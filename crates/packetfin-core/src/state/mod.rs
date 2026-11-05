//! Cross-packet decode state.
//!
//! [`DecodeSession`] decodes a capture's frames in order and owns the state
//! retained between them. State lives in [`StateStore`] tables under one
//! global byte budget; when a value cannot be retained the packet that needed
//! it gains a Warning/Sequence expert instead of aborting.
//!
//! TCP and UDP conversations, fragment buffers, templates and sequences live
//! in the store today; reassembly tables plug into the same ledger. Quoted
//! ICMP headers suspend analysis and reassembly state, but their transport
//! headers still create conversations and consume stream numbers.

mod annotations;
mod budget;
mod conversation;
mod dns;
mod fragment;
mod sequence;
mod snmp;
mod stream;
mod tcp;
mod template;

pub(crate) use stream::{PduAction, ReassembledPdu, ReassemblyReport, SegmentDataPiece, Ulp};
pub(crate) use tcp::{TcpAnalysisOptions, TcpObservation, TcpPacketState};

use std::sync::Arc;

use crate::capture::{Frame, Timestamp};
use crate::decode::tls::{ExportedKey, KeyLog, Secret, TlsFlow, TlsSecretCache};
use crate::decode::{DecodeOptions, Packet, decode_frame_inner};
use crate::names::NameResolver;
use std::net::IpAddr;

pub use annotations::{
    AnnotationStore, DEFAULT_ANNOTATION_BUDGET, FrameAnnotation, RenumberMap, apply_annotations,
    apply_dns_annotations, expert_label_only, expert_offending,
};
pub(crate) use annotations::{add_request_link, add_retransmission, add_time};
use budget::Budget;
pub use budget::{PutOutcome, StateStore, StateValue};
pub(crate) use conversation::{ConversationKey, StreamAssignment, TcpSegment};
use conversation::{ConversationState, ConversationStateKey};
pub(crate) use dns::{DnsTransaction, DnsTransactionKey};
pub(crate) use fragment::{
    Frag4Key, Frag6Key, FragmentKey, FragmentOutcome, FragmentPart, FragmentRecord, Reassembly,
};
use sequence::SequenceCache;
pub(crate) use sequence::{SequenceKey, SequenceState};
pub(crate) use snmp::{SnmpTransaction, SnmpTransactionKey};
use stream::{DnsConversation, HttpConversation, TlsConversation, TlsHandshake};
pub(crate) use stream::{
    DnsRequestOutcome, DnsResponseOutcome, HttpFrame, HttpRequestInfo, elapsed_nanos,
};
use template::TemplateCache;
pub(crate) use template::{
    ExporterAddress, MAX_TEMPLATE_FIELDS, TemplateEntry, TemplateField, TemplateKey, TemplateKind,
};

/// Packetfin's default state budget: 256 MiB, a ledger separate from
/// statistics and annotations.
pub const DEFAULT_STATE_BUDGET: usize = 256 * 1024 * 1024;

/// Capture metadata the decoders can read while a frame is decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameInfo {
    /// One-based frame number, continuous across pcapng sections.
    ///
    /// In a two-pass recording pass this is the renumbered position the read
    /// filter sees; [`Self::file_number`] stays the capture's own number.
    pub number: u64,
    /// The capture's own one-based frame number.
    ///
    /// Annotations and retransmission bookkeeping key on this value, which
    /// does not change when a pass renumbers displayed frames.
    pub file_number: u64,
    /// Capture time, absent for a pcapng Simple Packet Block.
    pub timestamp: Option<Timestamp>,
    /// Time since the session's first timestamped frame, in nanoseconds.
    pub time_relative: Option<i64>,
    /// Time since the previous timestamped frame, in nanoseconds.
    pub time_delta: Option<i64>,
}

impl FrameInfo {
    /// Frame information for a one-frame decode.
    ///
    /// A lone frame is its own reference, so its relative time is zero and it
    /// has no previous frame to measure a delta against.
    pub fn single(frame: &Frame) -> Self {
        Self {
            number: frame.number,
            file_number: frame.number,
            timestamp: frame.timestamp,
            time_relative: frame.timestamp.map(|_| 0),
            time_delta: None,
        }
    }
}

/// One endpoint of a followed transport stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamAddress {
    /// IPv4 address.
    Ipv4([u8; 4]),
    /// IPv6 address.
    Ipv6([u8; 16]),
}

/// A transport stream as the follow framework sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamKey {
    /// `tcp.stream` or `udp.stream` index.
    pub index: u32,
    /// Packet source address.
    pub source: StreamAddress,
    /// Packet source port.
    pub source_port: u16,
    /// Packet destination address.
    pub destination: StreamAddress,
    /// Packet destination port.
    pub destination_port: u16,
}

/// Receives the payload facts a follow statistic needs.
pub trait StreamObserver {
    /// One TCP segment payload, in arrival order.
    fn tcp_payload(
        &mut self,
        _key: StreamKey,
        _direction: u8,
        _sequence: u32,
        _acknowledgement: u32,
        _payload: &[u8],
    ) {
    }

    /// One UDP datagram payload, in arrival order.
    fn udp_payload(&mut self, _key: StreamKey, _direction: u8, _payload: &[u8]) {}

    /// One complete HTTP/1.x message (header block plus body).
    fn http_message(&mut self, _key: StreamKey, _direction: u8, _message: &[u8]) {}
}

/// A [`StreamObserver`] that ignores every event.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopObserver;

impl StreamObserver for NoopObserver {}

/// Which analysis pass a [`DecodeSession`] belongs to.
///
/// Single-pass runs use [`Self::One`]. Two-pass analysis uses [`Self::First`]
/// for the pass that records cross-frame state and [`Self::Second`] for the
/// pass that emits output; decoders and annotations read this value from the
/// session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassMode {
    /// The only pass of a normal read or live run.
    One,
    /// The recording pass of a two-pass run.
    First,
    /// The output pass of a two-pass run.
    Second,
}

/// Cross-packet state retained for one decode session.
///
/// The state tables and the least-recently-used ledger live together so one
/// global byte limit covers every table. Conversation stream counters are
/// monotonic for the session: an evicted conversation that reappears takes a
/// new stream number rather than reusing the old one.
#[derive(Debug)]
pub struct SessionState {
    budget: Budget,
    /// One table for TCP and UDP so a single LRU and byte budget cover both.
    conversations: StateStore<ConversationStateKey, ConversationState>,
    /// One table for IPv4 and IPv6 fragments so the global LRU covers both.
    fragments: StateStore<FragmentKey, fragment::FragmentBuffer>,
    templates: TemplateCache,
    sequences: SequenceCache,
    /// DNS transaction state for UDP-family messages, bounded by the ledger.
    dns: StateStore<DnsTransactionKey, DnsTransaction>,
    /// Pending SNMP requests, bounded by the same ledger.
    snmp: StateStore<SnmpTransactionKey, SnmpTransaction>,
    /// DNS-over-TCP transaction state.
    dns_tcp: StateStore<ConversationKey, DnsConversation>,
    /// HTTP request/response tail per TCP conversation.
    http: StateStore<ConversationKey, HttpConversation>,
    /// TLS session version per TCP conversation.
    tls: StateStore<ConversationKey, TlsConversation>,
    /// TLS record flows and decrypted plaintext streams.
    tls_flows: StateStore<ConversationKey, TlsFlow>,
    /// TLS handshake fragments carried across segments.
    tls_handshake: StateStore<stream::TlsHandshakeKey, TlsHandshake>,
    tls_plaintext: StateStore<stream::TlsPlaintextKey, stream::TlsPlaintext>,
    tls_secrets: TlsSecretCache,
    keylog: Option<Arc<KeyLog>>,
    export_tls_keys: bool,
    exported_tls_keys: Vec<ExportedKey>,
    /// Two-pass frame annotations under their own budget.
    annotations: AnnotationStore,
    next_tcp_stream: u32,
    next_udp_stream: u32,
    next_tls_stream: u32,
}

impl SessionState {
    /// Create empty session state with `limit` bytes of retained-state
    /// budget.
    ///
    /// Zero disables retention: every conversation is dropped immediately,
    /// so each packet starts a new stream.
    pub fn new(limit: usize) -> Self {
        Self::with_annotation_budget(limit, DEFAULT_ANNOTATION_BUDGET)
    }

    /// Create empty session state with explicit state and annotation budgets.
    pub fn with_annotation_budget(limit: usize, annotation_limit: usize) -> Self {
        Self::with_annotations(limit, AnnotationStore::with_budget(annotation_limit))
    }

    /// Create session state that reads a recording pass's annotations.
    pub fn with_annotations(limit: usize, annotations: AnnotationStore) -> Self {
        Self {
            budget: Budget::new(limit),
            conversations: StateStore::new(),
            fragments: StateStore::new(),
            templates: TemplateCache::new(),
            sequences: SequenceCache::new(),
            dns: StateStore::new(),
            snmp: StateStore::new(),
            dns_tcp: StateStore::new(),
            http: StateStore::new(),
            tls: StateStore::new(),
            tls_flows: StateStore::new(),
            tls_handshake: StateStore::new(),
            tls_plaintext: StateStore::new(),
            tls_secrets: TlsSecretCache::new(),
            keylog: None,
            export_tls_keys: false,
            exported_tls_keys: Vec::new(),
            annotations,
            next_tcp_stream: 0,
            next_udp_stream: 0,
            next_tls_stream: 0,
        }
    }

    /// The configured retention limit in bytes.
    pub fn limit(&self) -> usize {
        self.budget.limit()
    }

    /// The configured annotation limit in bytes.
    pub fn annotation_limit(&self) -> usize {
        self.annotations.limit()
    }

    /// Bytes currently retained by all state tables.
    pub fn used(&self) -> usize {
        self.budget.used()
    }

    /// Bytes currently reserved for annotations.
    pub fn annotations_used(&self) -> usize {
        self.annotations.used()
    }

    /// Read the annotation for a one-based file frame number.
    pub fn annotation(&self, frame: u64) -> Option<&FrameAnnotation> {
        self.annotations.get(frame)
    }

    /// Mutable annotations for the recording pass.
    pub(crate) fn annotations_mut(&mut self) -> &mut AnnotationStore {
        &mut self.annotations
    }

    /// Whether an annotation write was refused for lack of budget.
    ///
    /// The session consumes this once and reports the truncation on stderr.
    pub fn take_annotation_truncated(&mut self) -> bool {
        self.annotations.take_truncated()
    }

    /// Whether a state value has been dropped since the last check.
    ///
    /// The decoder that completes a frame consumes this once and reports the
    /// loss as an expert item on that frame.
    pub fn take_dropped(&mut self) -> bool {
        self.budget.take_dropped()
    }

    /// Install the loaded TLS key log for this session.
    ///
    /// The CLI reads the file once at startup; the decoder only receives the
    /// parsed, bounded map. Replacing the log does not clear existing TLS
    /// flow state.
    pub fn set_keylog(&mut self, keylog: KeyLog) {
        self.keylog = Some(Arc::new(keylog));
    }

    /// The installed key log, if any.
    pub(crate) fn keylog(&self) -> Option<Arc<KeyLog>> {
        self.keylog.clone()
    }

    /// Enable or disable collection of `--export-tls-session-keys` lines.
    ///
    /// Disabled by default: when no export file was requested, keys are never
    /// copied out of the TLS session state.
    pub fn set_tls_key_export(&mut self, enabled: bool) {
        self.export_tls_keys = enabled;
    }

    /// Whether TLS key export is enabled.
    pub(crate) fn tls_key_export(&self) -> bool {
        self.export_tls_keys
    }

    /// Take the key-export lines produced since the last call.
    pub fn take_export_keys(&mut self) -> Vec<ExportedKey> {
        std::mem::take(&mut self.exported_tls_keys)
    }

    pub(crate) fn push_exported_keys(&mut self, mut keys: Vec<ExportedKey>) {
        if self.export_tls_keys {
            self.exported_tls_keys.append(&mut keys);
        }
    }

    /// Take a TLS flow out of the state store for decoding one segment.
    pub(crate) fn take_tls_flow(&mut self, key: ConversationKey) -> Option<TlsFlow> {
        self.tls_flows.take_with(&mut self.budget, &key)
    }

    /// Return a TLS flow to the state store.
    pub(crate) fn put_tls_flow(&mut self, key: ConversationKey, flow: TlsFlow) {
        self.tls_flows.put_with(&mut self.budget, key, flow);
    }

    /// Copy a cached TLS master secret by session id or ticket.
    pub(crate) fn cached_tls_secret(&self, key: &[u8]) -> Option<Secret> {
        self.tls_secrets.get(key).and_then(Secret::duplicate)
    }

    /// Cache a TLS master secret by session id or ticket.
    pub(crate) fn cache_tls_secret(&mut self, key: &[u8], secret: &Secret) {
        self.tls_secrets.insert(key, secret);
    }

    /// Suspend or resume analysis/reassembly state retention.
    ///
    /// Quoted ICMP headers still create and count conversations, so stream
    /// numbers are consumed normally. Only the general state tables used by
    /// analysis and reassembly observe this switch; conversation accessors
    /// bypass it.
    pub(crate) fn set_suspended(&mut self, suspended: bool) -> bool {
        self.budget.set_suspended(suspended)
    }

    /// Take a DNS transaction out of its table.
    ///
    /// The caller updates it and puts it back, which keeps the table's
    /// least-recently-used order current without holding a borrow across the
    /// annotation writes.
    pub(crate) fn dns_take(&mut self, key: DnsTransactionKey) -> Option<DnsTransaction> {
        self.dns.take_with(&mut self.budget, &key)
    }

    /// Store or replace a DNS transaction.
    pub(crate) fn dns_put(&mut self, key: DnsTransactionKey, value: DnsTransaction) {
        let _ = self.dns.put_with(&mut self.budget, key, value);
    }

    /// Take a pending SNMP request out of its table.
    pub(crate) fn snmp_take(&mut self, key: SnmpTransactionKey) -> Option<SnmpTransaction> {
        self.snmp.take_with(&mut self.budget, &key)
    }

    /// Store a pending SNMP request.
    pub(crate) fn snmp_put(&mut self, key: SnmpTransactionKey, value: SnmpTransaction) {
        let _ = self.snmp.put_with(&mut self.budget, key, value);
    }

    /// Apply the final TLS version label to every frame of a conversation.
    fn finish_tls_versions(&mut self) {
        let Self {
            budget,
            tls,
            annotations,
            ..
        } = self;
        tls.drain_with(budget, |_, conversation| {
            let version = conversation
                .final_version
                .or(conversation.version)
                .unwrap_or(0);
            if version == 0 {
                return;
            }
            for frame in &conversation.frames {
                annotations.set_tls_version(u64::from(*frame), version);
            }
        });
    }

    /// Mark every query still waiting for a response at the end of a
    /// recording pass.
    fn finish_dns_transactions(&mut self) {
        let Self {
            budget,
            dns,
            annotations,
            ..
        } = self;
        dns.drain_with(budget, |_, value| {
            if value.pending_frame != 0 {
                for request in value.request_files() {
                    annotations.mark_response_missing(u64::from(*request));
                }
            }
        });
    }

    /// Add one IPv4 fragment to its datagram buffer and possibly reassemble.
    pub(crate) fn insert_fragment4(
        &mut self,
        key: Frag4Key,
        part: FragmentPart<'_>,
    ) -> FragmentOutcome {
        insert_fragment(
            &mut self.fragments,
            &mut self.budget,
            FragmentKey::Ipv4(key),
            part,
            fragment::MAX_IPV4_DATAGRAM,
        )
    }

    /// Add one IPv6 fragment to its datagram buffer and possibly reassemble.
    pub(crate) fn insert_fragment6(
        &mut self,
        key: Frag6Key,
        part: FragmentPart<'_>,
    ) -> FragmentOutcome {
        insert_fragment(
            &mut self.fragments,
            &mut self.budget,
            FragmentKey::Ipv6(key),
            part,
            fragment::MAX_ASSEMBLED,
        )
    }

    /// Return a template and mark it most recently used.
    pub(crate) fn lookup_template(&mut self, key: &TemplateKey) -> Option<TemplateEntry> {
        let Self {
            budget, templates, ..
        } = self;
        templates.lookup(budget, key)
    }

    /// Insert or replace a template in the bounded template cache.
    pub(crate) fn store_template(&mut self, key: TemplateKey, entry: TemplateEntry) -> PutOutcome {
        let Self {
            budget, templates, ..
        } = self;
        templates.insert(budget, key, entry)
    }

    /// Remove a withdrawn template.
    pub(crate) fn remove_template(&mut self, key: &TemplateKey) -> bool {
        let Self {
            budget, templates, ..
        } = self;
        templates.remove(budget, key)
    }

    /// Return the sequence expectation state for one exporter stream.
    pub(crate) fn lookup_sequence(&mut self, key: &SequenceKey) -> Option<SequenceState> {
        let Self {
            budget, sequences, ..
        } = self;
        sequences.lookup(budget, key)
    }

    /// Remember the last sequence number and frame for one exporter stream.
    pub(crate) fn store_sequence(&mut self, key: SequenceKey, state: SequenceState) -> PutOutcome {
        let Self {
            budget, sequences, ..
        } = self;
        sequences.insert(budget, key, state)
    }
}

/// Add a fragment to the shared table and retain or release its buffer.
fn insert_fragment(
    store: &mut StateStore<FragmentKey, fragment::FragmentBuffer>,
    budget: &mut Budget,
    key: FragmentKey,
    part: FragmentPart<'_>,
    max_len: usize,
) -> FragmentOutcome {
    let mut buffer = store.take_with(budget, &key).unwrap_or_default();
    let outcome = buffer.insert(part, max_len);
    if outcome.keep_buffer() && !buffer.is_empty() {
        let inserted = store.put_with(budget, key, buffer);
        if inserted.dropped {
            return FragmentOutcome::NotRetained;
        }
    }
    outcome
}

/// Decode a capture's frames in order with state shared between them.
///
/// One session belongs to one output run. Its options, budget and pass stay
/// fixed for the run, and the frame count in [`FrameInfo`] follows the
/// capture. An optional [`ObjectSink`](crate::export::ObjectSink) receives
/// HTTP message bodies when `--export-objects` is enabled.
pub struct DecodeSession {
    options: DecodeOptions,
    names: NameResolver,
    state: SessionState,
    pass: PassMode,
    names_notified: bool,
    objects: Option<Box<dyn crate::export::ObjectSink + 'static>>,
    first_timestamp: Option<Timestamp>,
    previous_timestamp: Option<Timestamp>,
}

impl std::fmt::Debug for DecodeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodeSession")
            .field("options", &self.options)
            .field("names", &self.names)
            .field("state", &self.state)
            .field("pass", &self.pass)
            .field("names_notified", &self.names_notified)
            .field("objects", &self.objects.as_ref().map(|_| "<sink>"))
            .finish()
    }
}

impl DecodeSession {
    /// Start a session with `options` and the default 256 MiB state budget.
    pub fn new(options: DecodeOptions) -> Self {
        Self::with_budget(options, DEFAULT_STATE_BUDGET)
    }

    /// Start a session with an explicit state budget in bytes.
    ///
    /// Zero disables retention; see [`SessionState::new`].
    pub fn with_budget(options: DecodeOptions, budget: usize) -> Self {
        Self::with_pass(options, budget, PassMode::One)
    }

    /// Start a session for one pass of a run with an explicit budget.
    pub fn with_pass(options: DecodeOptions, budget: usize, pass: PassMode) -> Self {
        Self::with_budgets(options, budget, DEFAULT_ANNOTATION_BUDGET, pass)
    }

    /// Start a session with explicit state and annotation budgets.
    pub fn with_budgets(
        options: DecodeOptions,
        budget: usize,
        annotation_budget: usize,
        pass: PassMode,
    ) -> Self {
        Self::with_budgets_and_annotations(
            options,
            budget,
            AnnotationStore::with_budget(annotation_budget),
            pass,
        )
    }

    /// Start an output pass over a recording pass's annotations.
    pub fn with_annotations(
        options: DecodeOptions,
        budget: usize,
        annotations: AnnotationStore,
        pass: PassMode,
    ) -> Self {
        Self::with_budgets_and_annotations(options, budget, annotations, pass)
    }

    fn with_budgets_and_annotations(
        options: DecodeOptions,
        budget: usize,
        annotations: AnnotationStore,
        pass: PassMode,
    ) -> Self {
        let mut options = options;
        let hosts = std::mem::take(&mut options.hosts);
        let names = NameResolver::new(options.preferences.nameres, hosts);
        Self {
            options,
            names,
            state: SessionState::with_annotations(budget, annotations),
            pass,
            names_notified: false,
            objects: None,
            first_timestamp: None,
            previous_timestamp: None,
        }
    }

    /// The pass this session belongs to.
    pub fn pass(&self) -> PassMode {
        self.pass
    }

    /// Install the sink that receives HTTP object bodies.
    pub fn set_object_sink(&mut self, sink: Box<dyn crate::export::ObjectSink + 'static>) {
        self.objects = Some(sink);
    }

    /// The session's annotations, for the two-pass driver.
    pub fn annotations(&self) -> &AnnotationStore {
        &self.state.annotations
    }

    /// Clear every table and counter, starting a new analysis session.
    ///
    /// `-M` uses this every N frames. Budgets stay as configured; stream
    /// counters restart at zero and no protocol state survives.
    pub fn reset_session(&mut self) {
        self.state =
            SessionState::with_annotation_budget(self.state.limit(), self.state.annotation_limit());
    }

    /// Finish the recording pass: queries left waiting are unanswered.
    ///
    /// Only [`PassMode::First`] records annotations, so other passes do
    /// nothing.
    pub fn finish_pass(&mut self) {
        if self.pass == PassMode::First {
            self.state.finish_dns_transactions();
            self.state.finish_tls_versions();
        }
    }

    /// Decode one frame, updating the state the following frames will see.
    pub fn decode(&mut self, frame: &Frame) -> Packet {
        self.decode_observed(frame, &mut NoopObserver)
    }

    /// Decode one frame with an explicit capture frame number.
    ///
    /// The recording pass gives the read filter a renumbered
    /// [`Frame::number`] while annotations stay keyed to `file_number`.
    pub fn decode_at(&mut self, frame: &Frame, file_number: u64) -> Packet {
        self.decode_inner(frame, file_number, &mut NoopObserver, false)
    }

    /// Decode one frame while forwarding stream payloads to `observer`.
    ///
    /// Statistics use this to see TCP and UDP payloads in arrival order
    /// without the decoders learning about any statistic.
    pub fn decode_observed(&mut self, frame: &Frame, observer: &mut dyn StreamObserver) -> Packet {
        self.decode_inner(frame, frame.number, observer, false)
    }

    /// Decode one frame for statistics with an explicit capture frame number.
    pub fn decode_observed_at(
        &mut self,
        frame: &Frame,
        file_number: u64,
        observer: &mut dyn StreamObserver,
    ) -> Packet {
        self.decode_inner(frame, file_number, observer, false)
    }

    /// Decode one frame only to advance cross-packet state.
    ///
    /// Used by the two-pass output pass for frames the read filter rejected:
    /// stream reassembly still needs their bytes, but link classification
    /// must ignore them.
    pub fn decode_observation(&mut self, frame: &Frame, file_number: u64) -> Packet {
        self.decode_inner(frame, file_number, &mut NoopObserver, true)
    }

    fn decode_inner(
        &mut self,
        frame: &Frame,
        file_number: u64,
        observer: &mut dyn StreamObserver,
        observe_only: bool,
    ) -> Packet {
        let time_relative = frame.timestamp.map(|timestamp| {
            let first = *self.first_timestamp.get_or_insert(timestamp);
            timestamp_delta(first, timestamp)
        });
        let time_delta = match (self.previous_timestamp, frame.timestamp) {
            (Some(previous), Some(timestamp)) => Some(timestamp_delta(previous, timestamp)),
            _ => None,
        };
        self.previous_timestamp = frame.timestamp;
        let info = FrameInfo {
            number: frame.number,
            file_number,
            timestamp: frame.timestamp,
            time_relative,
            time_delta,
        };
        let objects = self.objects.as_deref_mut();
        let mut packet = decode_frame_inner(
            frame,
            &self.options,
            &mut self.names,
            &mut self.state,
            info,
            objects,
            observer,
            self.pass,
            observe_only,
        );
        if self.state.take_dropped() {
            let expert = budget::state_dropped_expert();
            packet.tree.frame.add_expert(expert);
        }
        packet
    }

    /// Add pcapng name-resolution records learned since the previous frame.
    pub fn add_capture_names(&mut self, names: impl IntoIterator<Item = (IpAddr, String)>) {
        self.names.add_capture_names(names);
    }

    /// The name tables learned so far, for output formats that render names
    /// outside the decoded tree.
    pub fn names(&self) -> &NameResolver {
        &self.names
    }

    /// Whether a name table overflowed since the last call. The first
    /// overflow in a run returns `true` once, so the driver prints one note.
    pub fn take_name_drop(&mut self) -> bool {
        if self.names.take_dropped() && !self.names_notified {
            self.names_notified = true;
            return true;
        }
        false
    }

    /// Install a loaded TLS key log.
    pub fn set_keylog(&mut self, keylog: KeyLog) {
        self.state.set_keylog(keylog);
    }

    /// Enable collection of TLS session keys for `--export-tls-session-keys`.
    pub fn set_tls_key_export(&mut self, enabled: bool) {
        self.state.set_tls_key_export(enabled);
    }

    /// Take key-export lines produced since the last call.
    pub fn take_export_keys(&mut self) -> Vec<ExportedKey> {
        self.state.take_export_keys()
    }

    /// Bytes currently retained by the session's state tables.
    ///
    /// Never exceeds the budget the session was created with.
    pub fn budget_used(&self) -> usize {
        self.state.used()
    }

    /// Bytes currently reserved for annotations.
    pub fn annotations_used(&self) -> usize {
        self.state.annotations_used()
    }

    /// Report an annotation budget refusal once.
    pub fn take_annotation_truncated(&mut self) -> bool {
        self.state.take_annotation_truncated()
    }

    /// Read the annotation recorded for a one-based file frame number.
    pub fn annotation(&self, frame: u64) -> Option<&FrameAnnotation> {
        self.state.annotation(frame)
    }

    /// Move the annotation store out of a finished recording session.
    pub fn into_annotations(self) -> AnnotationStore {
        self.state.annotations
    }
}

pub(crate) fn timestamp_delta(earlier: Timestamp, later: Timestamp) -> i64 {
    let earlier = i128::from(earlier.seconds) * 1_000_000_000 + i128::from(earlier.nanos);
    let later = i128::from(later.seconds) * 1_000_000_000 + i128::from(later.nanos);
    let delta = later - earlier;
    i64::try_from(delta).unwrap_or(if delta < 0 { i64::MIN } else { i64::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Frame;
    use crate::tree::{Group, Severity};

    fn frame() -> Frame {
        Frame {
            number: 7,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 1,
            }),
            timestamp_precision: 6,
            captured: vec![0; 60],
            original_len: 60,
            link_type: 1,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: Some(0),
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: Default::default(),
        }
    }

    #[test]
    fn a_drop_before_a_frame_becomes_a_warning_on_that_frame() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        struct Key(u8);
        struct Value;

        impl StateValue for Value {
            fn state_bytes(&self) -> usize {
                0
            }
        }

        let mut session = DecodeSession::with_budget(DecodeOptions::default(), 1);
        let mut store = StateStore::<Key, Value>::new();
        let outcome = store.put(&mut session.state, Key(1), Value);
        assert!(outcome.dropped);

        let packet = session.decode(&frame());
        let experts = &packet.tree.frame.experts;
        assert_eq!(experts.len(), 1);
        if let Some(expert) = experts.first() {
            assert_eq!(expert.severity, Severity::Warning);
            assert_eq!(expert.group, Group::Sequence);
            assert!(!expert.message.is_empty());
        }
        assert!(!session.state.take_dropped());

        let next = session.decode(&frame());
        assert!(next.tree.frame.experts.is_empty());
    }

    #[test]
    fn a_fresh_session_reports_no_usage() {
        let session = DecodeSession::new(DecodeOptions::default());
        assert_eq!(session.budget_used(), 0);
        let zero = DecodeSession::with_budget(DecodeOptions::default(), 0);
        assert_eq!(zero.budget_used(), 0);
    }

    #[test]
    fn one_frame_wrappers_match_an_explicit_session() {
        let frame = frame();
        let wrapper = crate::decode::decode_frame_with_options(&frame, DecodeOptions::default());
        let mut session = DecodeSession::new(DecodeOptions::default());
        let explicit = session.decode(&frame);
        assert_eq!(wrapper, explicit);
    }
}
