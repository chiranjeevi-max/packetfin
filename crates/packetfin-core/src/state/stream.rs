//! Cross-packet state for the TCP application protocols.
//!
//! DNS over TCP and HTTP/1.x match responses to earlier requests. DNS state is
//! keyed by conversation and transaction id, HTTP state by conversation with
//! one "tail" exchange, because a response is associated with the most recent
//! request (RFC 9112 pipelining is not modeled). TLS remembers the session
//! version per conversation.
//! All tables live in the session store, so a drop caused by the global budget
//! surfaces as the session's warning expert.
//!
//! The same module owns bounded per-direction TCP stream reassembly. A
//! [`StreamBuffer`] keeps one contiguous byte window from the current PDU
//! onwards; segments are inserted in arrival order, the first copy of a byte
//! wins, and gaps stay gaps. Once the fixed header of the protocol is covered
//! the PDU length is known and the buffer repeatedly emits complete PDUs, so
//! several messages in one segment decode independently. The upper layer is
//! recognised by its transport port and framed by the rules each protocol
//! uses to delimit its messages: DNS prepends a two-byte length (RFC 1035
//! section 4.2.2), TLS records carry a five-byte header (RFC 8446 section
//! 5.1), BGP messages a nineteen-byte header whose length is at offset 16
//! (RFC 4271 section 4.1), and HTTP delimits a message by its header block
//! plus a content-length or chunked body (RFC 9112 sections 6.2 and 7.1).
//! A response without a delimiter runs to the direction's FIN, which completes
//! it (or a standalone message when the FIN segment carries the whole
//! response). Printable bytes that cannot begin a message after a completed
//! one are framed as continuation file data.
//!
//! TLS and DNS accept a first segment shorter than their fixed header and
//! reassemble once the header arrives; BGP needs the sixteen-octet marker in
//! the first segment, so a split at ten leaves the flow undecoded. Each
//! direction has its own limit: a non-HTTP PDU never exceeds [`MAX_PDU_BYTES`]
//! (1 MiB), while an HTTP/1.x message may reach the 64 MiB export-object cap
//! plus framing headroom ([`MAX_HTTP_MESSAGE_BYTES`]). A PDU never records
//! more than its protocol's contributing-segment cap, and retained segment
//! bytes stay within twice its PDU cap; exceeding a limit refuses the PDU
//! rather than aborting. The whole window is charged to the global state
//! ledger, which remains the real ceiling and evicts with an expert.

use std::mem::size_of;

use super::SessionState;
use super::budget::StateValue;
use super::conversation::ConversationKey;
use crate::capture::Timestamp;
use crate::http_syntax::{
    Answer, BodyPlan, ChunkScanner, ChunkStep, Framing, MAX_HEADER_BYTES, continuation,
    header_section_end, next_line,
};
use crate::tree::Bytes;

/// DNS's `dns.retransmission_timer` default in nanoseconds.
const RETRANSMISSION_WINDOW_NANOS: i128 = 5_000_000_000;

/// Most transactions retained per conversation.
///
/// A DNS stream that queries more names than this keeps the newest entries;
/// an evicted pending query makes its response look unsolicited.
const MAX_DNS_TRANSACTIONS: usize = 256;

/// One DNS over TCP transaction.
///
/// `response_frame` is zero while the response is outstanding.
#[derive(Clone, Debug)]
struct DnsTransaction {
    id: u16,
    request_frame: u64,
    request_file: u64,
    /// Capture frame numbers of the original request and retransmissions.
    request_files: Vec<u32>,
    response_frame: u64,
    request_time: Option<Timestamp>,
    multiple_responses: bool,
}

/// The DNS transactions of one conversation.
#[derive(Debug, Default)]
pub(crate) struct DnsConversation {
    transactions: Vec<DnsTransaction>,
}

impl DnsConversation {
    fn retained_bytes(&self) -> usize {
        self.transactions
            .capacity()
            .saturating_mul(size_of::<DnsTransaction>())
    }
}

impl StateValue for DnsConversation {
    fn state_bytes(&self) -> usize {
        self.retained_bytes().saturating_add(
            self.transactions
                .iter()
                .map(|transaction| transaction.request_files.capacity())
                .sum::<usize>()
                .saturating_mul(size_of::<u32>()),
        )
    }
}

/// Copy at most eight request file numbers into a fixed array.
fn files_array(files: &[u32]) -> [u32; 8] {
    let mut array = [0_u32; 8];
    for (slot, file) in array.iter_mut().zip(files.iter().take(8)) {
        *slot = *file;
    }
    array
}

/// What a DNS query did to the conversation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsRequestOutcome {
    /// The query opened a new transaction.
    New,
    /// The query repeats the outstanding transaction inside the retransmission
    /// window; the original request frame and time are kept.
    Retransmission { original_frame: u64 },
}

/// What a DNS response matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsResponseOutcome {
    /// The response answers a request; the elapsed time is absent when the
    /// capture has no timestamp for either frame.
    Matched {
        request_frame: u64,
        request_file: u64,
        request_files: [u32; 8],
        request_file_count: u8,
        elapsed_nanos: Option<i64>,
    },
    /// A second response to a transaction that accepts only one.
    Retransmission { response_frame: u64 },
    /// No transaction with this id was seen in the conversation.
    Unsolicited,
}

/// One HTTP request/response pairing slot.
#[derive(Clone, Debug, Default)]
struct HttpExchange {
    request_frame: u64,
    /// Capture frame number the request came from.
    request_file: u64,
    request_time: Option<Timestamp>,
    method: Option<String>,
    uri: Option<String>,
    full_uri: Option<String>,
    response_frame: u64,
    response_code: u16,
}

impl HttpExchange {
    fn state_bytes(&self) -> usize {
        self.method.as_ref().map_or(0, String::capacity)
            + self.uri.as_ref().map_or(0, String::capacity)
            + self.full_uri.as_ref().map_or(0, String::capacity)
    }
}

/// HTTP state for one conversation.
#[derive(Debug, Default)]
pub(crate) struct HttpConversation {
    tail: Option<HttpExchange>,
}

impl StateValue for HttpConversation {
    fn state_bytes(&self) -> usize {
        self.tail.as_ref().map_or(0, HttpExchange::state_bytes)
    }
}

/// Largest TLS handshake message retained across segments.
const MAX_TLS_HANDSHAKE: usize = 1024 * 1024;

/// Most frames remembered for the two-pass TLS version label per conversation.
const MAX_TLS_FRAMES: usize = 4096;

/// Direction-keyed identity for a TLS handshake fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TlsHandshakeKey {
    conversation: ConversationKey,
    /// Canonical direction of the sender.
    direction: usize,
}

/// An incomplete TLS handshake message carried across segments.
#[derive(Clone, Debug)]
pub(crate) struct TlsHandshake {
    /// Bytes of the message received so far.
    pub(crate) bytes: Vec<u8>,
    /// Handshake message name for the record label.
    pub(crate) name: &'static str,
    /// TCP sequence at the start of the segment that produced the fragment.
    pub(crate) sequence: Option<u32>,
    /// Capture frame where the handshake message started.
    pub(crate) first_file: u64,
}

impl StateValue for TlsHandshake {
    fn state_bytes(&self) -> usize {
        self.bytes.capacity()
    }
}

/// TLS session version remembered for a conversation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TlsConversation {
    /// Negotiated or record version, set once per session.
    pub(crate) version: Option<u16>,
    /// Last version seen in the conversation; the two-pass label.
    pub(crate) final_version: Option<u16>,
    /// Capture frames that carried TLS for this conversation.
    pub(crate) frames: Vec<u32>,
    /// Independent `tls.stream` index for this conversation.
    pub(crate) stream: Option<u32>,
}

impl StateValue for TlsConversation {
    fn state_bytes(&self) -> usize {
        self.frames.capacity().saturating_mul(size_of::<u32>())
    }
}

/// A frame's display and capture numbers for HTTP state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpFrame {
    /// Number the output pass prints.
    pub display: u64,
    /// One-based capture frame number.
    pub file: u64,
}

/// Identity of the decrypted byte stream of one TLS conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TlsPlaintextKey {
    conversation: ConversationKey,
}

/// Decrypted application-data streams awaiting or forming an HTTP message.
///
/// Record boundaries are invisible to HTTP/1.x (RFC 9112 section 3), so the
/// plaintext of every record is appended here and framed exactly like a
/// cleartext TCP stream. Sequence numbers are the plaintext offsets: records
/// are decrypted once, in wire order, so the stream is always contiguous.
#[derive(Debug, Default)]
pub(crate) struct TlsPlaintext {
    streams: ConversationStreams,
    next_sequence: [u32; 2],
    /// The direction's plaintext has been recognised as HTTP/1.x.
    http: [bool; 2],
}

impl StateValue for TlsPlaintext {
    fn state_bytes(&self) -> usize {
        self.streams.heap_bytes()
    }
}

/// The request a response matched, as the decoder needs it.
#[derive(Clone, Debug, Default)]
pub(crate) struct HttpRequestInfo {
    /// Display frame number of the request.
    pub frame: u64,
    /// Capture frame number of the request.
    pub file: u64,
    /// Capture time of the request.
    pub time: Option<Timestamp>,
    /// Request URI.
    pub uri: Option<String>,
    /// Absolute URI composed from the request and its Host header.
    pub full_uri: Option<String>,
}

/// The elapsed time between two capture timestamps in nanoseconds.
pub(crate) fn elapsed_nanos(request: Timestamp, response: Timestamp) -> i64 {
    let seconds = i128::from(response.seconds).saturating_sub(i128::from(request.seconds));
    let nanos = i128::from(response.nanos).saturating_sub(i128::from(request.nanos));
    i64::try_from(seconds.saturating_mul(1_000_000_000).saturating_add(nanos)).unwrap_or(i64::MAX)
}

impl SessionState {
    /// The TLS version already established for a conversation, if any.
    /// The TLS conversation's stream index.
    ///
    /// TLS conversations are numbered independently of `tcp.stream`: the
    /// first TLS conversation is `tls.stream` 0 even when it is TCP stream 1.
    pub(crate) fn tls_stream(&mut self, key: ConversationKey, quoted: bool) -> Option<u32> {
        if quoted {
            return None;
        }
        let mut conversation = self
            .tls
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        let stream = *conversation.stream.get_or_insert_with(|| {
            let stream = self.next_tls_stream;
            self.next_tls_stream = self.next_tls_stream.saturating_add(1);
            stream
        });
        self.tls.put_with(&mut self.budget, key, conversation);
        Some(stream)
    }

    pub(crate) fn tls_version(&mut self, key: ConversationKey) -> Option<u16> {
        if self.budget.suspended() {
            return None;
        }
        let conversation = self.tls.take_with(&mut self.budget, &key)?;
        let version = conversation.version;
        self.tls.put_with(&mut self.budget, key, conversation);
        version
    }

    /// Take an incomplete TLS handshake message for a conversation.
    pub(crate) fn take_tls_handshake(
        &mut self,
        conversation: ConversationKey,
        direction: usize,
        sequence: Option<u32>,
    ) -> Option<(Vec<u8>, &'static str, u64)> {
        if self.budget.suspended() {
            return None;
        }
        let key = TlsHandshakeKey {
            conversation,
            direction,
        };
        let handshake = self.tls_handshake.take_with(&mut self.budget, &key)?;
        // A retransmitted or restarted segment reuses an earlier sequence;
        // its handshake bytes are not a continuation of the stored fragment.
        if let (Some(current), Some(stored)) = (sequence, handshake.sequence)
            && current <= stored
        {
            return None;
        }
        Some((handshake.bytes, handshake.name, handshake.first_file))
    }

    /// Retain an incomplete TLS handshake message for the next segment.
    pub(crate) fn put_tls_handshake(
        &mut self,
        conversation: ConversationKey,
        direction: usize,
        sequence: Option<u32>,
        bytes: Vec<u8>,
        name: &'static str,
        first_file: u64,
    ) {
        if self.budget.suspended() || bytes.len() > MAX_TLS_HANDSHAKE {
            return;
        }
        let key = TlsHandshakeKey {
            conversation,
            direction,
        };
        self.tls_handshake.put_with(
            &mut self.budget,
            key,
            TlsHandshake {
                bytes,
                name,
                sequence,
                first_file,
            },
        );
    }

    /// Append decrypted application bytes and frame the complete HTTP PDUs.
    ///
    /// The returned actions carry a synthetic sequence equal to the plaintext
    /// offset; callers decode only the complete PDUs and ignore the TCP
    /// segment metadata those actions also describe.
    pub(crate) fn insert_tls_plaintext(
        &mut self,
        conversation: ConversationKey,
        direction: usize,
        frame: u64,
        bytes: &[u8],
        fin: bool,
        http2: bool,
    ) -> (ReassemblyReport, bool) {
        if self.budget.suspended() || (bytes.is_empty() && !fin) {
            return (ReassemblyReport::default(), false);
        }
        let key = TlsPlaintextKey { conversation };
        let mut plaintext = self
            .tls_plaintext
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        let direction = direction.min(1);
        {
            // ALPN `h2` fixes HTTP/2 for both directions: the client opens
            // with the connection preface, but the server's first record is a
            // SETTINGS frame with no marker of its own. Without ALPN, a
            // plaintext that starts with the preface still selects HTTP/2;
            // `set_ulp` keeps the direction's first value.
            let stream = plaintext.streams.direction_mut(direction);
            let ulp = if http2 || crate::decode::http2::looks_like_http2_prefix(bytes) {
                Ulp::Http2
            } else {
                Ulp::Http
            };
            stream.set_ulp(ulp);
        }
        let sequence = plaintext
            .next_sequence
            .get(direction)
            .copied()
            .unwrap_or_default();
        let report = plaintext
            .streams
            .direction_mut(direction)
            .insert_with_fin(sequence, bytes, frame, true, fin);
        plaintext
            .streams
            .observe_http_actions(direction, &report.actions);
        let buffered = plaintext.streams.direction(direction).buffered_prefix();
        let prefix = if buffered.is_empty() { bytes } else { buffered };
        let http = plaintext.http.get(direction).copied().unwrap_or(false)
            || crate::decode::looks_like_http_stream_prefix(prefix);
        if let Some(slot) = plaintext.http.get_mut(direction) {
            *slot = http;
        }
        if let Some(slot) = plaintext.next_sequence.get_mut(direction) {
            *slot = sequence.wrapping_add(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        }
        self.tls_plaintext
            .put_with(&mut self.budget, key, plaintext);
        (report, http)
    }

    /// Complete a close-delimited PDU at TCP FIN or TLS close_notify.
    pub(crate) fn finish_tls_plaintext(
        &mut self,
        conversation: ConversationKey,
        direction: usize,
        frame: u64,
    ) -> ReassemblyReport {
        if self.budget.suspended() {
            return ReassemblyReport::default();
        }
        let key = TlsPlaintextKey { conversation };
        let Some(mut plaintext) = self.tls_plaintext.take_with(&mut self.budget, &key) else {
            return ReassemblyReport::default();
        };
        let direction = direction.min(1);
        plaintext
            .streams
            .direction_mut(direction)
            .set_ulp(Ulp::Http);
        let sequence = plaintext
            .next_sequence
            .get(direction)
            .copied()
            .unwrap_or_default();
        let report = plaintext.streams.direction_mut(direction).insert_with_fin(
            sequence,
            &[],
            frame,
            true,
            true,
        );
        plaintext
            .streams
            .observe_http_actions(direction, &report.actions);
        self.tls_plaintext
            .put_with(&mut self.budget, key, plaintext);
        report
    }

    /// Remember the first version established for a TLS conversation.
    pub(crate) fn set_tls_version(&mut self, key: ConversationKey, version: u16) {
        if self.budget.suspended() {
            return;
        }
        let mut conversation = self
            .tls
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        // A version learned from a record before ServerHello is a guess: a
        // TLS 1.3 ServerHello may upgrade it. A later lower version never
        // downgrades the established one.
        if conversation.version.is_none_or(|current| version > current) {
            conversation.version = Some(version);
        }
        conversation.final_version = Some(version);
        self.tls.put_with(&mut self.budget, key, conversation);
    }

    /// Remember that a capture frame carried this TLS conversation.
    pub(crate) fn note_tls_frame(&mut self, key: ConversationKey, file: u64) {
        if self.budget.suspended() {
            return;
        }
        let mut conversation = self
            .tls
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        if let Ok(file) = u32::try_from(file)
            && conversation.frames.last() != Some(&file)
            && conversation.frames.len() < MAX_TLS_FRAMES
        {
            conversation.frames.push(file);
        }
        self.tls.put_with(&mut self.budget, key, conversation);
    }

    /// Record a DNS query and report whether it repeats the pending one.
    pub(crate) fn dns_tcp_request(
        &mut self,
        key: ConversationKey,
        id: u16,
        frame: u64,
        file: u64,
        time: Option<Timestamp>,
        multiple_responses: bool,
    ) -> DnsRequestOutcome {
        if self.budget.suspended() {
            return DnsRequestOutcome::New;
        }
        let mut conversation = self
            .dns_tcp
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        let outcome = match conversation
            .transactions
            .iter_mut()
            .rev()
            .find(|transaction| transaction.id == id)
        {
            Some(latest)
                if latest.response_frame == 0 && within_window(latest.request_time, time) =>
            {
                if let Ok(file) = u32::try_from(file)
                    && latest.request_files.len() < 8
                    && latest.request_files.last() != Some(&file)
                {
                    latest.request_files.push(file);
                }
                DnsRequestOutcome::Retransmission {
                    original_frame: latest.request_frame,
                }
            }
            _ => {
                push_transaction(
                    &mut conversation.transactions,
                    DnsTransaction {
                        id,
                        request_frame: frame,
                        request_file: file,
                        request_files: vec![u32::try_from(file).unwrap_or(u32::MAX)],
                        response_frame: 0,
                        request_time: time,
                        multiple_responses,
                    },
                );
                DnsRequestOutcome::New
            }
        };
        self.dns_tcp.put_with(&mut self.budget, key, conversation);
        outcome
    }

    /// Match a DNS response against the conversation's transactions.
    pub(crate) fn dns_tcp_response(
        &mut self,
        key: ConversationKey,
        id: u16,
        frame: u64,
        time: Option<Timestamp>,
    ) -> DnsResponseOutcome {
        if self.budget.suspended() {
            return DnsResponseOutcome::Unsolicited;
        }
        let mut conversation = self
            .dns_tcp
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        let outcome = match conversation
            .transactions
            .iter_mut()
            .rev()
            .find(|transaction| transaction.id == id)
        {
            None => DnsResponseOutcome::Unsolicited,
            Some(transaction) if transaction.response_frame == 0 => {
                transaction.response_frame = frame;
                let elapsed = match (transaction.request_time, time) {
                    (Some(request), Some(response)) => Some(elapsed_nanos(request, response)),
                    _ => None,
                };
                DnsResponseOutcome::Matched {
                    request_frame: transaction.request_frame,
                    request_file: transaction.request_file,
                    request_files: files_array(&transaction.request_files),
                    request_file_count: u8::try_from(transaction.request_files.len())
                        .unwrap_or(u8::MAX),
                    elapsed_nanos: elapsed,
                }
            }
            Some(transaction) if transaction.multiple_responses => {
                let elapsed = match (transaction.request_time, time) {
                    (Some(request), Some(response)) => Some(elapsed_nanos(request, response)),
                    _ => None,
                };
                DnsResponseOutcome::Matched {
                    request_frame: transaction.request_frame,
                    request_file: transaction.request_file,
                    request_files: files_array(&transaction.request_files),
                    request_file_count: u8::try_from(transaction.request_files.len())
                        .unwrap_or(u8::MAX),
                    elapsed_nanos: elapsed,
                }
            }
            Some(transaction) => DnsResponseOutcome::Retransmission {
                response_frame: transaction.response_frame,
            },
        };
        self.dns_tcp.put_with(&mut self.budget, key, conversation);
        outcome
    }

    /// Record an HTTP request as the conversation's most recent exchange.
    pub(crate) fn http_request(
        &mut self,
        key: ConversationKey,
        frame: HttpFrame,
        time: Option<Timestamp>,
        method: Option<&str>,
        uri: Option<&str>,
        full_uri: Option<&str>,
    ) {
        if self.budget.suspended() {
            return;
        }
        let mut conversation = self
            .http
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        conversation.tail = Some(HttpExchange {
            request_frame: frame.display,
            request_file: frame.file,
            request_time: time,
            method: method.map(str::to_string),
            uri: uri.map(str::to_string),
            full_uri: full_uri.map(str::to_string),
            response_frame: 0,
            response_code: 0,
        });
        self.http.put_with(&mut self.budget, key, conversation);
    }

    /// The method of the conversation's most recent request, if any.
    ///
    /// A response to HEAD carries no body, so the response parser needs the
    /// request method before it can delimit the message.
    pub(crate) fn http_pending_method(&mut self, key: ConversationKey) -> Option<String> {
        if self.budget.suspended() {
            return None;
        }
        let conversation = self.http.take_with(&mut self.budget, &key)?;
        let method = conversation
            .tail
            .as_ref()
            .and_then(|exchange| exchange.method.clone());
        self.http.put_with(&mut self.budget, key, conversation);
        method
    }

    /// Match an HTTP response against the conversation's most recent request.
    ///
    /// A response is matched unless the tail already carries a final response
    /// (code 200 or above); informational responses reuse the same exchange.
    /// An unmatched response opens an exchange of its own so a later response
    /// is not paired with an older request.
    pub(crate) fn http_response(
        &mut self,
        key: ConversationKey,
        frame: u64,
        code: u16,
    ) -> Option<HttpRequestInfo> {
        if self.budget.suspended() {
            return None;
        }
        let mut conversation = self
            .http
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        let reuse = conversation
            .tail
            .as_ref()
            .is_some_and(|exchange| exchange.response_frame == 0 || exchange.response_code < 200);
        let matched = if reuse {
            conversation
                .tail
                .as_ref()
                .filter(|exchange| exchange.request_frame != 0)
                .map(|exchange| HttpRequestInfo {
                    frame: exchange.request_frame,
                    file: exchange.request_file,
                    time: exchange.request_time,
                    uri: exchange.uri.clone(),
                    full_uri: exchange.full_uri.clone(),
                })
        } else {
            None
        };
        let exchange = if reuse {
            conversation.tail.get_or_insert_with(HttpExchange::default)
        } else {
            conversation.tail.insert(HttpExchange::default())
        };
        exchange.response_frame = frame;
        exchange.response_code = code;
        self.http.put_with(&mut self.budget, key, conversation);
        matched
    }
}

fn within_window(request: Option<Timestamp>, current: Option<Timestamp>) -> bool {
    match (request, current) {
        (Some(request), Some(current)) => {
            i128::from(elapsed_nanos(request, current)) < RETRANSMISSION_WINDOW_NANOS
        }
        _ => true,
    }
}

fn push_transaction(transactions: &mut Vec<DnsTransaction>, transaction: DnsTransaction) {
    if transactions.len() >= MAX_DNS_TRANSACTIONS {
        transactions.remove(0);
    }
    transactions.push(transaction);
}

// ---- Stream reassembly ----

/// Upper-layer protocol whose bytes the TCP stream reassembles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ulp {
    /// DNS over TCP: a two-byte length prefix and one message.
    Dns,
    /// TLS record layer: one record at a time.
    Tls,
    /// BGP: one message at a time.
    Bgp,
    /// HTTP/1.x: a header block and an optional declared body.
    Http,
    /// HTTP/2: the connection preface and one frame at a time.
    Http2,
}

impl Ulp {
    /// How many bytes the first segment must carry before reassembly starts.
    ///
    /// BGP refuses a first segment shorter than its sixteen-octet marker (a
    /// split at ten leaves only TCP), while DNS and TLS request the rest after
    /// any non-empty first segment.
    fn first_segment_minimum(self) -> usize {
        match self {
            Self::Bgp => 16,
            Self::Dns | Self::Tls | Self::Http | Self::Http2 => 1,
        }
    }

    /// Whether a PDU that fits one segment exposes `tcp.pdu.size`.
    ///
    /// DNS, BGP and HTTP/2 report a PDU length for every message; HTTP/1.x
    /// and TLS never do.
    fn standalone_pdu_size(self) -> bool {
        matches!(self, Self::Dns | Self::Bgp | Self::Http2)
    }

    /// Whether a reassembled PDU exposes `tcp.pdu.size`.
    ///
    /// The same rule as for a single-segment PDU: HTTP/1.x reports no length
    /// even for a reassembled message, although the buffer length is known.
    fn reassembled_pdu_size(self) -> bool {
        matches!(self, Self::Dns | Self::Bgp | Self::Http2)
    }

    /// The largest message this upper layer reassembles in one direction.
    fn pdu_limit(self) -> usize {
        match self {
            Self::Http => MAX_HTTP_MESSAGE_BYTES,
            Self::Http2 => MAX_HTTP2_FRAME_BYTES,
            Self::Dns | Self::Tls | Self::Bgp => MAX_PDU_BYTES,
        }
    }

    /// Where the oversized-PDU expert says the limit is.
    fn pdu_limit_label(self) -> &'static str {
        match self {
            Self::Http => "64 MiB HTTP",
            Self::Http2 => "16 MiB HTTP/2 frame",
            Self::Dns | Self::Tls | Self::Bgp => "1 MiB",
        }
    }

    /// The buffered window bound for this direction.
    ///
    /// A segment can carry the end of a capped message and the start of the
    /// next, so HTTP allows one trailing segment past the message cap. The
    /// allowance is at least one legacy 65,535-byte TCP payload, because a
    /// later small segment can follow data admitted by an earlier larger one
    /// through a hole; it grows with the observed segment for IPv6 jumbograms
    /// and large TSO frames.
    /// Other protocols keep their existing 1 MiB window bound unchanged.
    fn window_limit(self, trailing: usize) -> usize {
        match self {
            Self::Http => MAX_HTTP_MESSAGE_BYTES
                .saturating_add(trailing.max(65_535))
                .saturating_add(1),
            Self::Http2 => MAX_HTTP2_FRAME_BYTES
                .saturating_add(trailing.max(65_535))
                .saturating_add(1),
            Self::Dns | Self::Tls | Self::Bgp => MAX_PDU_BYTES,
        }
    }

    /// The most payload bytes all contributions to one PDU retain.
    ///
    /// A retransmission is listed even when it supplied no new byte, so a
    /// hostile stream can offer many full-size segments without growing the
    /// window. The cap refuses the PDU instead of letting that metadata grow
    /// without bound.
    fn contribution_limit(self) -> usize {
        self.pdu_limit().saturating_mul(2)
    }

    /// The most contributing segments one PDU records.
    ///
    /// A 64 MiB HTTP body normally spans about 44,000 segments at a 1,460-byte
    /// MSS, so HTTP gets a higher metadata cap than DNS/TLS/BGP while still
    /// bounding a one-byte-segment flood.
    fn segment_limit(self) -> usize {
        match self {
            Self::Http | Self::Http2 => 65_536,
            Self::Dns | Self::Tls | Self::Bgp => MAX_PDU_SEGMENTS,
        }
    }
}

/// The largest single non-HTTP PDU a direction reassembles (1 MiB).
pub(crate) const MAX_PDU_BYTES: usize = 1024 * 1024;

/// The largest HTTP/1.x message a direction reassembles.
///
/// Packetfin's export-object cap is 64 MiB. The message adds the header block
/// and, for a chunked body, chunk framing, so the reassembly window allows one
/// extra MiB above [`crate::export::MAX_EXPORT_OBJECT_BYTES`]. This limit
/// applies to plain and decrypted-TLS HTTP; every other upper layer keeps
/// [`MAX_PDU_BYTES`].
pub(crate) const MAX_HTTP_MESSAGE_BYTES: usize =
    crate::export::MAX_EXPORT_OBJECT_BYTES as usize + MAX_PDU_BYTES;

/// The largest HTTP/2 frame a direction reassembles.
///
/// RFC 9113 section 4.1 encodes the payload length in 24 bits, so a frame is
/// at most 16,777,215 payload octets plus its nine-octet header. The absolute
/// field width is the memory bound; SETTINGS_MAX_FRAME_SIZE is the protocol
/// limit the decoder checks.
pub(crate) const MAX_HTTP2_FRAME_BYTES: usize = crate::decode::http2::MAX_FRAME_BYTES;

/// The most contributing segments one non-HTTP PDU records.
///
/// Every contribution costs metadata beyond its bytes, so the cap keeps a
/// flood of one-byte segments from growing the bookkeeping without bound.
/// Exceeding this limit fails the PDU. HTTP raises the cap enough for a 64 MiB
/// body over a normal TCP MSS; see [`Ulp::segment_limit`].
const MAX_PDU_SEGMENTS: usize = 4096;

/// The most PDUs one segment/frame emits.
///
/// A 1 MiB window of tiny messages would otherwise create an unbounded action
/// list and Info string.
const MAX_PDUS_PER_INSERT: usize = 4096;

/// DNS's TCP length prefix.
const DNS_LENGTH_BYTES: usize = 2;

/// A TLS record's fixed header.
const TLS_HEADER_BYTES: usize = 5;

/// The all-ones BGP marker length.
const BGP_MARKER_BYTES: usize = 16;

/// A BGP message header: marker, length and type.
const BGP_HEADER_BYTES: usize = 19;

/// An HTTP/2 frame header: length, type, flags and stream identifier.
const HTTP2_HEADER_BYTES: usize = 9;

/// One segment's contribution to a reassembled PDU.
#[derive(Clone, Debug)]
pub(crate) struct PduSegment {
    /// Display frame number of the contributing segment.
    pub(crate) frame: u64,
    /// Capture frame number of the contributing segment.
    pub(crate) file: u64,
    /// Byte offset of the contribution within the PDU.
    pub(crate) offset: usize,
    /// Number of bytes the segment covers within the PDU.
    pub(crate) length: usize,
    /// The segment's own bytes for that range.
    pub(crate) data: Bytes,
    /// This segment overlapped bytes another segment supplied first.
    pub(crate) overlap: bool,
    /// The overlapping bytes differed.
    pub(crate) conflict: bool,
    /// This segment carried bytes past the declared PDU end.
    pub(crate) toolong: bool,
    /// This segment claimed the PDU's last byte after another one did.
    pub(crate) multipletails: bool,
}

/// A completed upper-layer PDU.
#[derive(Clone, Debug)]
pub(crate) struct ReassembledPdu {
    /// The PDU bytes, in order; a conflicting overlap takes the newer byte.
    pub(crate) data: Bytes,
    /// Contributing segments, ordered by their PDU offset.
    pub(crate) segments: Vec<PduSegment>,
    /// The upper protocol that framed the PDU.
    pub(crate) ulp: Ulp,
    /// Grouped attribution when the first segment lacked framing.
    pub(crate) grouped: Option<GroupedAttribution>,
}

/// Reassembly view when the first segment lacked the framing header.
#[derive(Clone, Debug)]
pub(crate) struct GroupedAttribution {
    /// The contiguous window reported as reassembled data.
    pub(crate) data: Bytes,
    /// Contributions clipped to that window.
    pub(crate) segments: Vec<PduSegment>,
}

/// One `tcp.segment_data` occurrence and its offset in the segment payload.
#[derive(Clone, Debug)]
pub(crate) struct SegmentDataPiece {
    /// Byte offset within the segment payload where this piece starts.
    pub(crate) offset: usize,
    /// The bytes belonging to this PDU.
    pub(crate) bytes: Vec<u8>,
    /// The bytes repeat an already consumed segment.
    pub(crate) retransmitted: bool,
}

/// What one segment did to one upper-layer PDU.
#[derive(Clone, Debug)]
pub(crate) enum PduAction {
    /// A complete PDU that lies inside this segment.
    Standalone {
        /// The upper protocol that framed the PDU.
        ulp: Ulp,
        /// The PDU bytes.
        data: Bytes,
        /// Offset of the PDU within the segment payload.
        offset: usize,
        /// `tcp.pdu.size` when the protocol exposes it for a direct decode.
        pdu_size: Option<u32>,
        /// The bytes are continuation file data, not a message.
        continuation: bool,
        /// The segment carries FIN.
        fin: bool,
    },
    /// A PDU completed from earlier segments and this one.
    Reassembled {
        /// The PDU and its contributing segments.
        pdu: ReassembledPdu,
        /// This segment's bytes that belong to the PDU.
        segment_data: SegmentDataPiece,
        /// `tcp.pdu.size` when the protocol exposes it.
        pdu_size: Option<u32>,
        /// The bytes are continuation file data, not a message.
        continuation: bool,
        /// The segment carries FIN.
        fin: bool,
    },
    /// This segment repeats stream bytes already consumed; it only carries
    /// `tcp.segment_data` and never decodes again.
    SegmentData {
        /// The repeated bytes.
        segment_data: SegmentDataPiece,
    },
    /// This segment's bytes belong to a PDU that is not complete yet.
    Partial {
        /// The upper protocol that framed the PDU.
        ulp: Ulp,
        /// This segment's bytes that belong to the PDU.
        segment_data: SegmentDataPiece,
        /// Offset of the PDU within the segment payload.
        offset: usize,
        /// The PDU began in this segment rather than an earlier one.
        started_here: bool,
        /// The first line of the buffered PDU, bounded to a kilobyte.
        pdu_start: Vec<u8>,
    },
}

/// Everything one segment did to the reassembly state.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReassemblyReport {
    /// PDU actions in wire order.
    pub(crate) actions: Vec<PduAction>,
    /// Reassembly failed for a PDU on this segment.
    pub(crate) error: bool,
    /// The segment that caused a reassembly failure, when known.
    pub(crate) error_frame: Option<u64>,
    /// A PDU exceeded this reassembly limit and was dropped.
    pub(crate) oversized: Option<&'static str>,
    /// The per-frame PDU limit was reached and the remainder dropped.
    pub(crate) limit_reached: bool,
    /// The fixed header was invalid for the protocol.
    pub(crate) malformed: Option<&'static str>,
}

/// One contribution to the buffered byte window.
#[derive(Clone, Debug)]
struct Contribution {
    frame: u64,
    file: u64,
    /// Offset within the buffered window.
    offset: usize,
    length: usize,
    data: Vec<u8>,
    overlap: bool,
    conflict: bool,
}

/// How a PDU's declared length was resolved.
enum FrameLength {
    /// The fixed header is not fully covered yet.
    NeedMore,
    /// The PDU ends at this many bytes from the window start.
    Complete(usize),
    /// The bytes are a continuation, ending at this many bytes.
    Continuation(usize),
    /// The declared length is invalid for the protocol.
    Invalid(&'static str),
    /// The declared length is larger than the reassembly limit.
    Oversized(usize),
    /// The header block exceeds the shared decoder cap; skip one capped
    /// window and keep the direction alive for later messages.
    HeaderOversized(usize),
    /// The message cannot be delimited within the limit; report and stop the
    /// direction rather than skipping into the middle of its body.
    FatalOversized(&'static str),
}

/// Per-insert facts shared by the PDU loop.
#[derive(Clone, Copy)]
struct InsertState {
    /// Contiguous covered bytes before this insert filled its segment.
    contiguous_before: usize,
    /// The segment carries FIN.
    fin: bool,
    /// Byte offset of the FIN stream end within the pending PDU.
    fin_end: Option<usize>,
}

/// One direction's reassembly buffer.
///
/// `start` is the sequence number of `data[0]`; every byte before `frontier`
/// has already been consumed as a complete PDU.
#[derive(Debug, Default)]
pub(crate) struct StreamBuffer {
    /// The upper protocol recognised for this direction.
    ulp: Option<Ulp>,
    /// Sequence number of the first buffered byte.
    start: Option<u32>,
    /// Sequence number where the next not-yet-seen PDU starts.
    frontier: Option<u32>,
    /// Buffered bytes from the original window start.
    data: Vec<u8>,
    /// Bytes already consumed from the front of `data` and `covered`.
    head: usize,
    /// Which buffered bytes have been supplied, in arrival order.
    covered: Vec<bool>,
    /// Length of the covered prefix at the front of `covered`.
    ///
    /// Maintained incrementally so a one-byte-segment flood stays linear
    /// instead of rescanning the whole window on every insert.
    contiguous: usize,
    /// Absolute index of the pending message's first LF, once found.
    first_newline: Option<usize>,
    /// Absolute prefix examined for `first_newline` with no match.
    newline_scan: usize,
    /// Absolute index of the first LF at or after the continuation probe.
    continuation_newline: Option<usize>,
    /// Absolute prefix examined for `continuation_newline`.
    continuation_scan: usize,
    /// Absolute end of the pending header block (`\r\n\r\n`).
    header_end: Option<usize>,
    /// Absolute prefix examined for `header_end` with no match.
    header_scan: usize,
    /// Parsed framing of the pending header block.
    header_framing: Option<Framing>,
    /// Cursor of the pending chunked-body parser.
    chunk_parse: Option<ChunkScanner>,
    /// The pending chunked body's framing was already found unusable.
    ///
    /// The scanner cannot continue past an unusable size line or a boundary
    /// that is not CRLF, and the message ends when the covered prefix or the
    /// stream does. Remembering that keeps a stream being finished from
    /// rescanning the body from its first chunk on every insert.
    chunk_invalid: bool,
    /// New chunked scanners built for the pending body (tests only).
    #[cfg(test)]
    chunk_scans: usize,
    /// Contributions from segments that supplied at least one new byte.
    contributions: Vec<Contribution>,
    /// Novel payload bytes retained outside the vectors above.
    heap: usize,
    /// A short first segment permanently disabled this direction.
    refused: bool,
    /// At least one PDU started in this direction.
    started_any: bool,
    /// Frame that supplied conflicting overlapping bytes to the pending PDU.
    conflict_frame: Option<u64>,
    /// The next response in this direction answers a HEAD request.
    head_pending: bool,
    /// The next response is a 2xx reply to CONNECT.
    connect_pending: bool,
    /// Sequence just past an oversized PDU that must be skipped.
    skip_until: Option<u32>,
    /// The pending PDU's first segment lacked its framing header.
    short_start: bool,
    /// The HTTP/2 connection preface has been consumed in this direction.
    http2_preface_done: bool,
}

impl StreamBuffer {
    /// Recognise one segment's upper protocol.
    ///
    /// A direction keeps the protocol of its first payload segment; later
    /// segments of the same flow cannot change it.
    pub(crate) fn set_ulp(&mut self, ulp: Ulp) {
        if self.ulp.is_none() {
            self.ulp = Some(ulp);
        }
    }

    /// Bytes retained for the pending PDU, for budget accounting.
    ///
    /// `Vec<bool>` is bit-packed, so its capacity counts elements (bits), not
    /// bytes. Contribution data is charged by allocation capacity because a
    /// compacted contribution keeps more bytes than its length.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.heap
            .saturating_add(self.data.capacity())
            .saturating_add(self.covered.capacity().div_ceil(8))
            .saturating_add(self.contributions.capacity() * size_of::<Contribution>())
    }

    /// Payload bytes buffered in this direction.
    #[cfg(test)]
    pub(crate) fn payload_bytes(&self) -> usize {
        self.data.len().saturating_sub(self.head)
    }

    /// The current contiguous window.
    fn window_data(&self) -> &[u8] {
        self.data.get(self.head..).unwrap_or_default()
    }

    /// Coverage bits for the current window.
    fn window_covered(&self) -> &[bool] {
        self.covered.get(self.head..).unwrap_or_default()
    }

    /// Move the consumed prefix out of the vectors once it is large enough.
    ///
    /// Consumption is a head pointer so a frame that emits thousands of
    /// small PDUs stays linear; compaction happens once per insertion.
    fn compact_if_needed(&mut self) {
        const COMPACT_BYTES: usize = 64 * 1024;
        if self.head >= COMPACT_BYTES {
            self.compact();
        }
    }

    fn compact(&mut self) {
        if self.head == 0 {
            return;
        }
        let head = self.head.min(self.data.len());
        self.data.drain(..head);
        self.covered.drain(..head.min(self.covered.len()));
        self.contiguous = self.contiguous.saturating_sub(head);
        self.reset_http_scan();
        for contribution in &mut self.contributions {
            if contribution.offset >= head {
                contribution.offset = contribution.offset.saturating_sub(head);
            } else {
                let dropped = head.saturating_sub(contribution.offset);
                contribution.offset = 0;
                contribution.length = contribution.length.saturating_sub(dropped);
                if contribution.length == 0 {
                    contribution.data.clear();
                } else {
                    let drop = dropped.min(contribution.data.len());
                    contribution.data.drain(..drop);
                }
            }
        }
        self.contributions
            .retain(|contribution| contribution.length > 0);
        self.heap = self
            .contributions
            .iter()
            .map(|contribution| contribution.data.capacity())
            .sum();
        self.head = 0;
    }

    /// The contiguous bytes retained from the pending PDU's start.
    fn buffered_prefix(&self) -> &[u8] {
        self.data.get(..self.covered_prefix()).unwrap_or_default()
    }

    /// Whether this direction has recognised an upper protocol.
    pub(crate) fn has_ulp(&self) -> bool {
        self.ulp.is_some()
    }

    /// Whether a PDU is pending.
    #[cfg(test)]
    pub(crate) fn has_pending(&self) -> bool {
        self.start.is_some()
    }

    /// Release the reassembly vectors when they no longer hold bytes.
    ///
    /// The state ledger charges capacity, so a completed large message must
    /// not leave a 64 MiB `data` buffer and its coverage/contribution vectors
    /// charged to an idle conversation. Small buffers are kept for reuse.
    fn release_large_buffers(&mut self) {
        const KEEP_CAPACITY: usize = 64 * 1024;
        if self.data.capacity() > KEEP_CAPACITY {
            self.data = Vec::new();
        } else {
            self.data.clear();
        }
        if self.covered.capacity() > KEEP_CAPACITY {
            self.covered = Vec::new();
        } else {
            self.covered.clear();
        }
        if self.contributions.capacity() > KEEP_CAPACITY / size_of::<Contribution>() {
            self.contributions = Vec::new();
        } else {
            self.contributions.clear();
        }
        self.heap = 0;
        self.head = 0;
        self.contiguous = 0;
        self.reset_http_scan();
    }

    /// Drop the pending bytes and release large allocations.
    ///
    /// Large allocations are released rather than kept for the next PDU: the
    /// state ledger counts `Vec` capacity, and a retained 65 MiB `data` plus
    /// `covered` pair would otherwise keep the conversation over its cap.
    pub(crate) fn clear(&mut self) {
        self.frontier = self.start.or(self.frontier);
        self.start = None;
        self.release_large_buffers();
        self.refused = false;
        self.conflict_frame = None;
        self.head_pending = false;
        self.connect_pending = false;
        self.skip_until = None;
        self.short_start = false;
    }

    /// Insert one segment payload and report every PDU it touched.
    ///
    /// `sequence` starts the payload and `frame` is its frame number. Bytes
    /// already supplied by an earlier segment are kept; only new bytes extend
    /// the window. A segment that begins after a hole still buffers, and the
    /// PDU completes when the hole is filled. `_reassemble` mirrors
    /// `tcp.reassemble_out_of_order`, but the buffer waits for the hole either
    /// way.
    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        sequence: u32,
        payload: &[u8],
        frame: u64,
        reassemble: bool,
    ) -> ReassemblyReport {
        self.insert_with_file_and_fin(sequence, payload, frame, frame, reassemble, false)
    }

    /// Insert one segment payload, retaining the capture frame number.
    ///
    /// The output pass renumbers displayed frames, while two-pass annotations
    /// are keyed by the capture's own numbers.
    /// Insert one segment payload, defaulting the capture frame to `frame`.
    pub(crate) fn insert_with_fin(
        &mut self,
        sequence: u32,
        payload: &[u8],
        frame: u64,
        reassemble: bool,
        fin: bool,
    ) -> ReassemblyReport {
        self.insert_with_file_and_fin(sequence, payload, frame, frame, reassemble, fin)
    }

    pub(crate) fn insert_with_file_and_fin(
        &mut self,
        mut sequence: u32,
        payload: &[u8],
        frame: u64,
        file: u64,
        _reassemble: bool,
        fin: bool,
    ) -> ReassemblyReport {
        let mut report = ReassemblyReport::default();
        let Some(ulp) = self.ulp else {
            return report;
        };
        if self.refused {
            return report;
        }
        // An insertion starts a fresh frame of work; reclaim any consumed
        // prefix once so the rest of this insert sees `data[0]` as the window.
        self.compact();

        // Drop bytes that belong to an oversized PDU whose body is not kept.
        let mut payload = payload;
        if let Some(skip) = self.skip_until {
            let difference = sequence.wrapping_sub(skip) as i32;
            if difference < 0 {
                let before = usize::try_from(-i64::from(difference)).unwrap_or(usize::MAX);
                if before >= payload.len() {
                    return report;
                }
                payload = payload.get(before..).unwrap_or_default();
                sequence = sequence.wrapping_add(u32::try_from(before).unwrap_or(u32::MAX));
            }
            self.skip_until = None;
        }
        if payload.is_empty() {
            if fin {
                self.finish_on_close(ulp, sequence, frame, &mut report);
            }
            return report;
        }

        // A segment below the completed frontier is one retransmitted piece;
        // it never reopens a PDU, even when it extends past the frontier with
        // new bytes.
        if let Some(frontier) = self.frontier
            && (sequence.wrapping_sub(frontier) as i32) < 0
        {
            report.actions.push(PduAction::SegmentData {
                segment_data: SegmentDataPiece {
                    offset: 0,
                    bytes: payload.to_vec(),
                    retransmitted: true,
                },
            });
            return report;
        }

        if self.start.is_none() {
            if payload.len() < ulp.first_segment_minimum() {
                // A short first segment only disables a direction that never
                // decoded a PDU; trailing bytes after a complete PDU may
                // still grow into the next message.
                if !self.started_any {
                    self.refused = true;
                }
                return report;
            }
            self.started_any = true;
            self.start = Some(sequence);
            self.short_start = !header_present(ulp, payload);
        }
        let start = self.start.unwrap_or(sequence);
        let difference = sequence.wrapping_sub(start) as i32;
        let mut payload_from = 0_usize;
        let offset = if difference >= 0 {
            usize::try_from(difference).unwrap_or(usize::MAX)
        } else {
            let before = usize::try_from(-i64::from(difference)).unwrap_or(usize::MAX);
            if before >= payload.len() {
                report.actions.push(PduAction::SegmentData {
                    segment_data: SegmentDataPiece {
                        offset: 0,
                        bytes: payload.to_vec(),
                        retransmitted: true,
                    },
                });
                return report;
            }
            payload_from = before;
            0
        };
        let dropped_prefix = payload.get(..payload_from).unwrap_or_default().to_vec();
        let payload = payload.get(payload_from..).unwrap_or_default();
        let sequence = sequence.wrapping_add(u32::try_from(payload_from).unwrap_or(u32::MAX));
        let end = offset.saturating_add(payload.len());
        let window_limit = ulp.window_limit(payload.len());
        if end > window_limit {
            // Keep the declared end and skip its body; a later message on the
            // same connection still decodes.
            report.oversized = Some(ulp.pdu_limit_label());
            report.error_frame = Some(frame);
            let skip = self
                .start
                .unwrap_or(sequence)
                .wrapping_add(u32::try_from(end).unwrap_or(u32::MAX));
            self.clear();
            self.skip_until = Some(skip);
            return report;
        }
        self.ensure(end, window_limit);
        let mut novel = false;
        let mut segment_overlap = false;
        let mut segment_conflict = false;
        let display = payload.to_vec();
        let contiguous_before = self.covered_prefix();
        for (index, byte) in payload.iter().copied().enumerate() {
            let position = offset.saturating_add(index);
            let Some(covered) = self.covered.get_mut(position) else {
                continue;
            };
            if *covered {
                segment_overlap = true;
                let previous = self.data.get(position).copied().unwrap_or_default();
                if previous != byte {
                    // First-arrived bytes win the reassembled data; the
                    // conflicting segment keeps its own bytes in the segment
                    // record and reports `tcp.segment.error`.
                    segment_conflict = true;
                    self.conflict_frame.get_or_insert(frame);
                }
            } else {
                novel = true;
                if let Some(slot) = self.data.get_mut(position) {
                    *slot = byte;
                }
                *covered = true;
            }
        }
        // Extend the cached prefix only over bytes this insert supplied. The
        // scan is amortised linear: each byte joins the prefix once.
        let mut contiguous = self.contiguous;
        while self.covered.get(contiguous).copied().unwrap_or(false) {
            contiguous = contiguous.saturating_add(1);
        }
        self.contiguous = contiguous;
        if novel || segment_overlap {
            // A retransmitted segment is listed in `tcp.segments` even
            // when every byte it repeats was already supplied; the segment
            // marks `tcp.segment.overlap` (and `tcp.segment.error` when the
            // bytes conflict). It contributes no new bytes to the PDU data.
            let contribution_bytes = self.heap.saturating_add(display.capacity());
            if contribution_bytes > ulp.contribution_limit()
                || self.contributions.len() >= ulp.segment_limit()
            {
                report.error = true;
                report.error_frame = Some(frame);
                self.clear();
                self.refused = true;
                return report;
            }
            self.contributions.push(Contribution {
                frame,
                file,
                offset,
                length: payload.len(),
                data: display,
                overlap: segment_overlap,
                conflict: segment_conflict,
            });
            self.heap = contribution_bytes;
        }

        let fin_end = if fin {
            let relative = sequence.wrapping_sub(start) as i32;
            (relative >= 0).then(|| {
                usize::try_from(relative)
                    .unwrap_or(usize::MAX)
                    .saturating_add(payload.len())
            })
        } else {
            None
        };
        self.emit_pdus(
            ulp,
            sequence,
            frame,
            payload,
            InsertState {
                contiguous_before,
                fin,
                fin_end,
            },
            &mut report,
        );
        prepend_dropped_prefix(&mut report.actions, &dropped_prefix);
        report
    }

    /// Finish a close-delimited HTTP response when the connection closes.
    ///
    /// A TCP FIN ends the stream, and the bytes that follow a response header
    /// without a length delimiter decode as the body. The empty FIN frame is
    /// named in the reassembly list, and the FIN sequence bounds the completed
    /// body.
    fn finish_on_close(
        &mut self,
        ulp: Ulp,
        segment_sequence: u32,
        frame: u64,
        report: &mut ReassemblyReport,
    ) {
        if self.start.is_none() || ulp != Ulp::Http {
            return;
        }
        let Some(start) = self.start else {
            return;
        };
        let relative = segment_sequence.wrapping_sub(start) as i32;
        if relative < 0 {
            return;
        }
        let fin_end = usize::try_from(relative).unwrap_or(usize::MAX);
        let contiguous = self.covered_prefix();
        if contiguous < fin_end {
            return;
        }
        let covered = contiguous.min(fin_end);
        let data = self.extract_prefix(covered);
        let Some(header_end) = header_section_end(&data) else {
            return;
        };
        let start_line_end = data
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index.saturating_add(1))
            .unwrap_or(0);
        if header_end.saturating_sub(start_line_end) > MAX_HEADER_BYTES {
            // The decoder cannot accept this close-delimited message; report
            // the header cap and do not emit partial framing at FIN.
            report.oversized = Some("1 MiB header");
            report.error_frame = Some(frame);
            self.clear();
            return;
        }
        let header = data.get(..header_end).unwrap_or_default();
        if !matches!(http_start(header), Some(HttpStart::Response(_))) {
            return;
        }
        // Only a response the rules delimit by the connection close belongs to
        // this path (RFC 9112 section 6.3 case 7); every other framing ends the
        // message earlier and was already emitted.
        if covered == 0
            || !matches!(
                Framing::of_block(header).body_plan(self.answer()),
                BodyPlan::CloseDelimited
            )
        {
            return;
        }
        let mut segments = self.segment_list(covered, &data);
        segments.push(PduSegment {
            frame,
            file: frame,
            offset: covered,
            length: 0,
            data: Bytes::default(),
            overlap: false,
            conflict: false,
            toolong: false,
            multipletails: false,
        });
        report.actions.push(PduAction::Reassembled {
            pdu: ReassembledPdu {
                data,
                segments,
                ulp: Ulp::Http,
                grouped: None,
            },
            segment_data: SegmentDataPiece {
                offset: 0,
                bytes: Vec::new(),
                retransmitted: false,
            },
            pdu_size: None,
            continuation: false,
            fin: true,
        });
        if let Some(conflict_frame) = self.conflict_frame.take() {
            report.error = true;
            report.error_frame = Some(conflict_frame);
        }
        self.consume(covered);
    }

    /// Emit every complete PDU starting at the window's front.
    fn emit_pdus(
        &mut self,
        ulp: Ulp,
        segment_sequence: u32,
        frame: u64,
        payload: &[u8],
        mut state: InsertState,
        report: &mut ReassemblyReport,
    ) {
        let mut emitted = 0_usize;
        let mut grouping_used = false;
        loop {
            if self.start.is_none() {
                return;
            }
            if emitted >= MAX_PDUS_PER_INSERT {
                report.error = true;
                report.error_frame = Some(frame);
                report.limit_reached = true;
                self.clear();
                self.refused = true;
                return;
            }
            let (length, continuation) = match self.frame_length(ulp, state.fin_end) {
                FrameLength::NeedMore => {
                    self.add_partial(
                        ulp,
                        segment_sequence,
                        payload,
                        None,
                        state.contiguous_before,
                        report,
                    );
                    return;
                }
                FrameLength::Invalid(message) => {
                    report.malformed = Some(message);
                    self.clear();
                    self.refused = true;
                    return;
                }
                FrameLength::Oversized(length) => {
                    report.oversized = Some(ulp.pdu_limit_label());
                    report.error_frame = Some(frame);
                    if length > 0 && self.covered_prefix() >= length {
                        // The declared end lies in this window; skip it and
                        // keep parsing the bytes that follow in this segment.
                        self.consume(length);
                        state.contiguous_before = state.contiguous_before.saturating_sub(length);
                        if let Some(end) = state.fin_end.as_mut() {
                            *end = end.saturating_sub(length);
                        }
                        continue;
                    }
                    let start = self.start.unwrap_or(segment_sequence);
                    let skip = start.wrapping_add(u32::try_from(length).unwrap_or(u32::MAX));
                    self.clear();
                    self.skip_until = Some(skip);
                    return;
                }
                FrameLength::HeaderOversized(length) => {
                    report.oversized = Some("1 MiB header");
                    report.error_frame = Some(frame);
                    if length > 0 && self.covered_prefix() >= length {
                        self.consume(length);
                        state.contiguous_before = state.contiguous_before.saturating_sub(length);
                        if let Some(end) = state.fin_end.as_mut() {
                            *end = end.saturating_sub(length);
                        }
                        continue;
                    }
                    let start = self.start.unwrap_or(segment_sequence);
                    let skip = start.wrapping_add(u32::try_from(length).unwrap_or(u32::MAX));
                    self.clear();
                    self.skip_until = Some(skip);
                    return;
                }
                FrameLength::FatalOversized(label) => {
                    report.oversized = Some(label);
                    report.error_frame = Some(frame);
                    self.clear();
                    self.refused = true;
                    return;
                }
                FrameLength::Complete(length) => (length, false),
                FrameLength::Continuation(length) => (length, true),
            };
            if length == 0 || self.covered_prefix() < length {
                self.add_partial(
                    ulp,
                    segment_sequence,
                    payload,
                    Some(length),
                    state.contiguous_before,
                    report,
                );
                return;
            }
            let grouped = self.short_start && !grouping_used && self.covered_prefix() > length;
            let data = self.extract_prefix(length);
            let segments = self.segment_list(length, &data);
            let pdu_start = self.start.unwrap_or(segment_sequence);
            let piece = if grouped {
                SegmentDataPiece {
                    offset: 0,
                    bytes: payload.to_vec(),
                    retransmitted: false,
                }
            } else {
                self.bounded_piece(segment_sequence, payload, Some(length), pdu_start, true)
                    .unwrap_or(SegmentDataPiece {
                        offset: 0,
                        bytes: Vec::new(),
                        retransmitted: false,
                    })
            };
            let standalone = segments.len() == 1
                && segments.first().is_some_and(|segment| {
                    segment.frame == frame && segment.offset == 0 && segment.length == length
                });
            let pdu_size =
                |exposed: bool| exposed.then(|| u32::try_from(length).unwrap_or(u32::MAX));
            if ulp == Ulp::Http
                && let Some(HttpStart::Response(code)) = http_start(&data)
                && code.is_none_or(|code| code >= 200)
            {
                self.head_pending = false;
                self.connect_pending = false;
            }
            if standalone {
                let difference = pdu_start.wrapping_sub(segment_sequence) as i32;
                let offset = usize::try_from(difference).unwrap_or(0);
                if let Some(bytes) = self.standalone_bytes(length, segment_sequence, payload) {
                    report.actions.push(PduAction::Standalone {
                        ulp,
                        data: Bytes::from(bytes),
                        offset,
                        pdu_size: pdu_size(ulp.standalone_pdu_size()),
                        continuation,
                        fin: state.fin,
                    });
                }
            } else {
                if grouped {
                    grouping_used = true;
                }
                let attribution = if grouped {
                    let attributed = self.covered_prefix();
                    let grouped_data = Bytes::from(
                        self.window_data()
                            .get(..attributed)
                            .unwrap_or_default()
                            .to_vec(),
                    );
                    let grouped_segments = self.segment_list(attributed, &grouped_data);
                    Some(GroupedAttribution {
                        data: grouped_data,
                        segments: grouped_segments,
                    })
                } else {
                    None
                };
                report.actions.push(PduAction::Reassembled {
                    pdu: ReassembledPdu {
                        data,
                        segments,
                        ulp,
                        grouped: attribution,
                    },
                    segment_data: piece,
                    pdu_size: pdu_size(ulp.reassembled_pdu_size()),
                    continuation,
                    fin: state.fin,
                });
            }
            if let Some(conflict_frame) = self.conflict_frame.take() {
                report.error = true;
                report.error_frame = Some(conflict_frame);
            }
            emitted = emitted.saturating_add(1);
            self.consume(length);
            state.contiguous_before = state.contiguous_before.saturating_sub(length);
            if let Some(end) = state.fin_end.as_mut() {
                *end = end.saturating_sub(length);
            }
            if let Some(next) = self.start {
                let difference = next.wrapping_sub(segment_sequence) as i32;
                if difference >= 0 {
                    let start = usize::try_from(difference).unwrap_or(usize::MAX);
                    if let Some(chunk) = payload.get(start..) {
                        self.short_start = !header_present(ulp, chunk);
                    }
                }
            }
            let head_after_consume = self.head;
            self.compact_if_needed();
            if self.head == 0 && head_after_consume > 0 {
                state.contiguous_before = state
                    .contiguous_before
                    .saturating_sub(head_after_consume.saturating_sub(length));
            }
        }
    }

    /// Forget the cached HTTP framing scans for the pending window.
    fn reset_http_scan(&mut self) {
        self.first_newline = None;
        self.newline_scan = 0;
        self.continuation_newline = None;
        self.continuation_scan = 0;
        self.header_end = None;
        self.header_scan = 0;
        self.header_framing = None;
        self.chunk_parse = None;
        self.chunk_invalid = false;
        // The bounded-rescan test counts the scanners each message builds.
        #[cfg(test)]
        let _ = std::mem::take(&mut self.chunk_scans);
    }

    /// Advance the HTTP framing scans to the covered prefix.
    ///
    /// A hostile stream of one-byte segments with no newline must not make
    /// every insert rescan the whole window; each byte is examined once per
    /// pending message.
    fn scan_http_prefix(&mut self) {
        if self.ulp != Some(Ulp::Http) {
            return;
        }
        let covered = self.covered_prefix();
        let end = self.head.saturating_add(covered);
        if self.first_newline.is_none() && self.newline_scan < end {
            let start = self.newline_scan.max(self.head);
            match self
                .data
                .get(start..end)
                .and_then(|window| window.iter().position(|byte| *byte == b'\n'))
            {
                Some(index) => self.first_newline = Some(start.saturating_add(index)),
                None => self.newline_scan = end,
            }
        }
        // The continuation probe skips one leading CRLF (see
        // `http_continuation_length`); invalidate a newline that belonged to
        // that prefix once both bytes are covered.
        let probe_start = if self
            .data
            .get(self.head..self.head.saturating_add(2))
            .is_some_and(|prefix| prefix == b"\r\n")
        {
            self.head.saturating_add(2)
        } else {
            self.head
        };
        if self
            .continuation_newline
            .is_some_and(|index| index < probe_start)
        {
            self.continuation_newline = None;
            self.continuation_scan = self.continuation_scan.max(probe_start);
        }
        if self.continuation_newline.is_none() {
            let start = self.continuation_scan.max(probe_start);
            if start < end {
                match self
                    .data
                    .get(start..end)
                    .and_then(|window| window.iter().position(|byte| *byte == b'\n'))
                {
                    Some(index) => {
                        self.continuation_newline = Some(start.saturating_add(index));
                    }
                    None => self.continuation_scan = end,
                }
            }
        }
        if self.header_end.is_none() && self.header_scan < end {
            // Keep the last three bytes so a CRLFCRLF split across inserts is
            // still found.
            let start = self.header_scan.saturating_sub(3).max(self.head);
            match self
                .data
                .get(start..end)
                .and_then(|window| window.windows(4).position(|w| w == b"\r\n\r\n"))
            {
                Some(index) => {
                    self.header_end = Some(start.saturating_add(index).saturating_add(4))
                }
                None => self.header_scan = end,
            }
        }
        if self.header_framing.is_none()
            && let Some(header_end) = self.header_end
        {
            let header_end = header_end.saturating_sub(self.head);
            let start_line = self
                .relative_first_newline()
                .map(|index| index.saturating_add(1))
                .unwrap_or(0);
            if header_end > start_line
                && let Some(header) = self.data.get(self.head..self.head + header_end)
            {
                self.header_framing = Some(Framing::of_block(header));
            }
        }
    }

    /// The cached first newline relative to the current window.
    fn relative_first_newline(&self) -> Option<usize> {
        self.first_newline
            .map(|index| index.saturating_sub(self.head))
    }

    /// The cached continuation newline relative to the current window.
    fn relative_continuation_newline(&self) -> Option<usize> {
        self.continuation_newline
            .map(|index| index.saturating_sub(self.head))
    }

    /// The cached header end relative to the current window.
    fn relative_header_end(&self) -> Option<usize> {
        self.header_end.map(|index| index.saturating_sub(self.head))
    }

    /// Whether the pending HTTP message has a Content-Length or chunked body.
    ///
    /// A close-delimited response is reassembled silently until FIN; its
    /// continuation segments show no HTTP start line.
    fn http_pending_has_body_delimiter(&self) -> bool {
        let Some(framing) = self.header_framing else {
            return false;
        };
        matches!(
            framing.body_plan(self.answer()),
            BodyPlan::Fixed(_) | BodyPlan::Chunked
        )
    }

    /// The peer-request facts the framing rules need (RFC 9112 section 6.3).
    fn answer(&self) -> Answer {
        Answer {
            head: self.head_pending,
            connect: self.connect_pending,
        }
    }

    /// The pending PDU's first line, when one is buffered.
    ///
    /// A continuation segment shows the start line even though it arrived in
    /// an earlier segment; the buffer supplies it.
    fn partial_start_line(&self) -> Vec<u8> {
        const MAX_START_LINE: usize = 1024;
        let Some(data) = self.data.get(..self.covered_prefix()) else {
            return Vec::new();
        };
        let end = self
            .relative_first_newline()
            .map(|index| index.saturating_add(1))
            .unwrap_or(data.len())
            .min(MAX_START_LINE)
            .min(data.len());
        data.get(..end).unwrap_or_default().to_vec()
    }

    /// Add the partial-PDU action for this segment, if it contributed bytes.
    fn add_partial(
        &mut self,
        ulp: Ulp,
        segment_sequence: u32,
        payload: &[u8],
        length: Option<usize>,
        contiguous_before: usize,
        report: &mut ReassemblyReport,
    ) {
        let Some(start) = self.start else {
            return;
        };
        let (offset, started_here) = self.pdu_placement(segment_sequence);
        let Some(piece) =
            self.bounded_piece(segment_sequence, payload, length, start, !started_here)
        else {
            return;
        };
        let segment_offset =
            usize::try_from(segment_sequence.wrapping_sub(start) as i32).unwrap_or(usize::MAX);
        if ulp == Ulp::Http2 {
            // The expected output buffers a split HTTP/2 frame without
            // `tcp.segment_data`; the frame decodes once, on the completing
            // segment.
            return;
        }
        let pdu_start = if !started_here
            && segment_offset == contiguous_before
            && ulp == Ulp::Http
            && self.http_pending_has_body_delimiter()
        {
            self.partial_start_line()
        } else {
            Vec::new()
        };
        report.actions.push(PduAction::Partial {
            ulp,
            segment_data: piece,
            offset,
            started_here,
            pdu_start,
        });
    }

    /// Where the pending PDU starts within this segment payload.
    fn pdu_placement(&self, segment_sequence: u32) -> (usize, bool) {
        let Some(start) = self.start else {
            return (0, false);
        };
        let difference = start.wrapping_sub(segment_sequence) as i32;
        if difference >= 0 {
            (usize::try_from(difference).unwrap_or(0), true)
        } else {
            (0, false)
        }
    }

    /// The bytes of this segment that form a standalone PDU.
    fn standalone_bytes(
        &self,
        length: usize,
        segment_sequence: u32,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let start = self.start?;
        let difference = start.wrapping_sub(segment_sequence) as i32;
        if difference < 0 {
            return None;
        }
        let payload_start = usize::try_from(difference).ok()?;
        payload
            .get(payload_start..payload_start.checked_add(length)?)
            .map(<[u8]>::to_vec)
    }

    /// This segment's bytes that belong to the PDU at the window front.
    fn bounded_piece(
        &self,
        segment_sequence: u32,
        payload: &[u8],
        length: Option<usize>,
        pdu_start: u32,
        include_prefix: bool,
    ) -> Option<SegmentDataPiece> {
        let bounded = length.unwrap_or(usize::MAX);
        let difference = segment_sequence.wrapping_sub(pdu_start) as i32;
        let (offset, available) = if difference >= 0 {
            let offset = usize::try_from(difference).unwrap_or(usize::MAX);
            (0_usize, bounded.saturating_sub(offset).min(payload.len()))
        } else if include_prefix {
            // A segment that starts before a PDU it continues also reports
            // its leading bytes as segment data.
            (0_usize, bounded.min(payload.len()))
        } else {
            let before = usize::try_from(-i64::from(difference)).unwrap_or(usize::MAX);
            (before, bounded.min(payload.len().saturating_sub(before)))
        };
        let bytes = payload
            .get(offset..offset.saturating_add(available))
            .unwrap_or_default();
        (!bytes.is_empty()).then(|| SegmentDataPiece {
            offset,
            bytes: bytes.to_vec(),
            retransmitted: false,
        })
    }

    /// The declared PDU length once its fixed header is covered.
    fn frame_length(&mut self, ulp: Ulp, fin_end: Option<usize>) -> FrameLength {
        let covered = self.covered_prefix();
        match ulp {
            Ulp::Dns => {
                if covered < DNS_LENGTH_BYTES {
                    return FrameLength::NeedMore;
                }
                match read_u16(self.window_data(), 0) {
                    Some(length) => FrameLength::Complete(2 + usize::from(length)),
                    None => FrameLength::NeedMore,
                }
            }
            Ulp::Tls => {
                if covered < TLS_HEADER_BYTES {
                    return FrameLength::NeedMore;
                }
                match read_u16(self.window_data(), 3) {
                    Some(length) => FrameLength::Complete(5 + usize::from(length)),
                    None => FrameLength::NeedMore,
                }
            }
            Ulp::Bgp => {
                if covered < BGP_HEADER_BYTES {
                    return FrameLength::NeedMore;
                }
                if !self
                    .window_data()
                    .get(..BGP_MARKER_BYTES)
                    .is_some_and(|marker| marker.iter().all(|byte| *byte == 0xff))
                {
                    return FrameLength::Invalid("BGP marker is invalid");
                }
                let Some(length) = read_u16(self.window_data(), 16).map(usize::from) else {
                    return FrameLength::NeedMore;
                };
                if length < BGP_HEADER_BYTES {
                    return FrameLength::Invalid("BGP message length is invalid");
                }
                // An over-long message keeps its header, length and
                // invalid-length expert; the body still has to arrive before
                // the PDU completes, like any other length.
                FrameLength::Complete(length)
            }
            Ulp::Http => self.http_length(covered, fin_end),
            Ulp::Http2 => self.http2_length(covered),
        }
    }

    /// HTTP/2: the connection preface, then one frame per PDU.
    ///
    /// RFC 9113 section 3.4 opens the connection with a fixed 24-octet
    /// preface, which the expected output reports as its own node. After it,
    /// frame is its nine-octet header plus the payload length that header
    /// declares. A stream that starts mid-connection (no preface) frames its
    /// first bytes as a frame.
    fn http2_length(&mut self, covered: usize) -> FrameLength {
        if !self.http2_preface_done {
            let prefix = self
                .window_data()
                .get(..covered.min(crate::decode::http2::PREFACE_BYTES))
                .unwrap_or_default();
            if crate::decode::http2::preface_prefix(prefix) {
                if covered < crate::decode::http2::PREFACE_BYTES {
                    return FrameLength::NeedMore;
                }
                self.http2_preface_done = true;
                return FrameLength::Complete(crate::decode::http2::PREFACE_BYTES);
            }
            self.http2_preface_done = true;
        }
        if covered < HTTP2_HEADER_BYTES {
            return FrameLength::NeedMore;
        }
        let Some(length) = read_u24(self.window_data(), 0).map(usize::try_from) else {
            return FrameLength::NeedMore;
        };
        let Ok(length) = length else {
            return FrameLength::Invalid("HTTP/2 frame length is invalid");
        };
        FrameLength::Complete(HTTP2_HEADER_BYTES.saturating_add(length))
    }

    /// HTTP/1.x: the header block plus its content-length or chunked body.
    fn http_length(&mut self, covered: usize, fin_end: Option<usize>) -> FrameLength {
        // Advance the incremental framing scans before borrowing the window.
        self.scan_http_prefix();
        let limit = Ulp::Http.pdu_limit();
        let continuation = {
            let window = self.window_data();
            let data = window.get(..covered).unwrap_or_default();
            continuation(data, self.relative_continuation_newline()).map(|_| data.len())
        };
        if let Some(length) = continuation {
            // Bytes that cannot begin a message are a "file data"
            // continuation. A complete first line is enough; the continuation
            // consumes the rest of the available bytes.
            return FrameLength::Continuation(length);
        }
        let start_line_end = self
            .relative_first_newline()
            .map(|index| index.saturating_add(1))
            .unwrap_or(0);
        let Some(header_end) = self.relative_header_end().filter(|end| *end <= covered) else {
            // The shared header cap counts the header lines after the start
            // line, like the decoder. Waiting past it could never produce a
            // header the decoder accepts.
            let header_area = covered.saturating_sub(start_line_end);
            if covered >= limit {
                // A header that never terminates cannot be resynchronised.
                return if header_area > MAX_HEADER_BYTES {
                    FrameLength::FatalOversized("1 MiB header")
                } else {
                    FrameLength::FatalOversized(Ulp::Http.pdu_limit_label())
                };
            }
            return FrameLength::NeedMore;
        };
        let Some(framing) = self.header_framing else {
            // `scan_http_prefix` installs the framing as soon as the header
            // block is complete.
            return FrameLength::Oversized(limit);
        };
        let plan = framing.body_plan(self.answer());
        let available = covered.saturating_sub(header_end);
        if header_end.saturating_sub(start_line_end) > MAX_HEADER_BYTES {
            // The decoder will not accept this header, but its framing still
            // says where the message ends. Skip the whole message; never hand
            // partial framing to the decoder.
            return match plan {
                // A bodyless status, or a response to HEAD, ends at the header
                // section: a declared length describes a body the message does
                // not carry. A CONNECT answer keeps its tunnel bytes.
                BodyPlan::Empty | BodyPlan::Answer => FrameLength::HeaderOversized(header_end),
                BodyPlan::Fixed(length) => {
                    FrameLength::HeaderOversized(header_end.saturating_add(length))
                }
                BodyPlan::Chunked => match self.chunked_body_end(header_end, covered, limit) {
                    ChunkedEnd::Complete(end) => FrameLength::HeaderOversized(end),
                    ChunkedEnd::NeedMore => {
                        if let Some(end) = fin_end {
                            if covered >= end {
                                return FrameLength::HeaderOversized(end);
                            }
                            return FrameLength::NeedMore;
                        }
                        if covered >= limit {
                            FrameLength::FatalOversized("1 MiB header")
                        } else {
                            FrameLength::NeedMore
                        }
                    }
                    ChunkedEnd::TooLarge | ChunkedEnd::Invalid => {
                        FrameLength::FatalOversized("1 MiB header")
                    }
                },
                // An unusable length has no declared end to skip over.
                BodyPlan::InvalidLength => FrameLength::FatalOversized("1 MiB header"),
                // A close-delimited response needs FIN to know its end.
                BodyPlan::CloseDelimited => {
                    if let Some(end) = fin_end {
                        if covered < end {
                            return FrameLength::NeedMore;
                        }
                        return FrameLength::HeaderOversized(end);
                    }
                    if covered >= limit {
                        return FrameLength::FatalOversized("1 MiB header");
                    }
                    return FrameLength::NeedMore;
                }
            };
        }
        match plan {
            BodyPlan::Empty => FrameLength::Complete(header_end),
            BodyPlan::Answer => {
                // A 2xx answer to CONNECT owns everything the segment carries:
                // the connection is a tunnel from here (RFC 9112 section
                // 9.3.6), so the bytes cannot reopen as another message.
                FrameLength::Complete(header_end.saturating_add(available))
            }
            BodyPlan::Fixed(length) => {
                let end = header_end.saturating_add(length);
                if end > limit {
                    // Skip to the declared end so a later message on the same
                    // connection still decodes.
                    FrameLength::Oversized(end)
                } else {
                    FrameLength::Complete(end)
                }
            }
            BodyPlan::Chunked => match self.chunked_body_end(header_end, covered, limit) {
                ChunkedEnd::Complete(end) => {
                    if end > limit {
                        FrameLength::Oversized(limit)
                    } else {
                        FrameLength::Complete(end)
                    }
                }
                ChunkedEnd::NeedMore => match fin_end {
                    Some(end) if covered < end => FrameLength::NeedMore,
                    Some(end) => FrameLength::Complete(end.min(covered)),
                    None if covered >= limit => {
                        FrameLength::FatalOversized(Ulp::Http.pdu_limit_label())
                    }
                    None => FrameLength::NeedMore,
                },
                ChunkedEnd::TooLarge => FrameLength::FatalOversized(Ulp::Http.pdu_limit_label()),
                ChunkedEnd::Invalid => match fin_end {
                    Some(end) if covered < end => FrameLength::NeedMore,
                    Some(end) => FrameLength::Complete(end.min(covered)),
                    None => FrameLength::Complete(covered),
                },
            },
            BodyPlan::InvalidLength => {
                // An unusable Content-Length leaves a response without a
                // declared boundary; the captured prefix is its body.
                FrameLength::Complete(covered)
            }
            BodyPlan::CloseDelimited => {
                // A response with no length is delimitable only by the
                // connection close; wait for FIN and require the contiguous
                // prefix to reach the FIN stream end (a gap exports nothing).
                let Some(end) = fin_end else {
                    return FrameLength::NeedMore;
                };
                if covered < end {
                    return FrameLength::NeedMore;
                }
                FrameLength::Complete(end.min(covered))
            }
        }
    }

    /// Parse and cache one chunked body incrementally.
    ///
    /// The cursor and the pending chunk size survive between inserts, so each
    /// chunk line is parsed once. Only the contiguous covered prefix is
    /// trusted; a gap leaves the cursor at the incomplete construct.
    fn chunked_body_end(&mut self, header_end: usize, covered: usize, limit: usize) -> ChunkedEnd {
        if self.chunk_invalid {
            // The body already failed its grammar; its end still depends on the
            // covered prefix or the stream end, and rescanning the chunks could
            // not produce a different answer.
            return ChunkedEnd::Invalid;
        }
        let covered_end = self.head.saturating_add(covered);
        let limit_end = self.head.saturating_add(limit);
        let mut scanner = match self.chunk_parse {
            Some(scanner) => scanner,
            None => {
                #[cfg(test)]
                {
                    self.chunk_scans = self.chunk_scans.saturating_add(1);
                }
                ChunkScanner::new(self.head.saturating_add(header_end))
            }
        };
        loop {
            match scanner.step(&self.data, covered_end) {
                ChunkStep::Data { boundary_ok, .. } => {
                    if !boundary_ok {
                        // RFC 9112 section 7.1 requires CRLF; a message that
                        // breaks the chunk framing cannot be delimited, so the
                        // available prefix completes it.
                        self.chunk_parse = None;
                        self.chunk_invalid = true;
                        return ChunkedEnd::Invalid;
                    }
                }
                ChunkStep::Last | ChunkStep::Trailer { .. } => {}
                ChunkStep::TrailerEnd { end, .. } => {
                    self.chunk_parse = None;
                    return if end > limit_end {
                        ChunkedEnd::TooLarge
                    } else {
                        ChunkedEnd::Complete(end.saturating_sub(self.head))
                    };
                }
                ChunkStep::Incomplete {
                    pending, restart, ..
                } => {
                    // A declared chunk that cannot fit the reassembly limit is
                    // refused before its bytes are buffered.
                    let over = pending.is_some_and(|pending| {
                        pending.data.saturating_add(pending.size).saturating_add(2) > limit_end
                    }) || restart > limit_end;
                    if over {
                        self.chunk_parse = None;
                        return ChunkedEnd::TooLarge;
                    }
                    self.chunk_parse = Some(scanner);
                    return ChunkedEnd::NeedMore;
                }
                ChunkStep::Invalid { .. } => {
                    self.chunk_parse = None;
                    self.chunk_invalid = true;
                    return ChunkedEnd::Invalid;
                }
            }
        }
    }

    /// The number of contiguous covered bytes from the window start.
    fn covered_prefix(&self) -> usize {
        self.contiguous
            .saturating_sub(self.head)
            .min(self.window_covered().len())
    }

    /// The contributing segments clipped to one PDU.
    fn segment_list(&self, length: usize, data: &Bytes) -> Vec<PduSegment> {
        let consumed = self.head;
        let last = length.saturating_sub(1);
        let mut segments: Vec<PduSegment> = self
            .contributions
            .iter()
            .filter_map(|contribution| {
                if contribution.offset.saturating_add(contribution.length) <= consumed {
                    return None;
                }
                let skip = consumed.saturating_sub(contribution.offset);
                let effective = contribution
                    .offset
                    .saturating_add(skip)
                    .saturating_sub(consumed);
                if effective >= length || skip >= contribution.length {
                    return None;
                }
                let clipped = contribution
                    .length
                    .saturating_sub(skip)
                    .min(length.saturating_sub(effective));
                let segment_data = if contribution.conflict {
                    Bytes::from(
                        contribution
                            .data
                            .get(skip..skip.saturating_add(clipped))
                            .unwrap_or_default()
                            .to_vec(),
                    )
                } else {
                    data.subslice(effective, clipped)
                };
                let covers_last =
                    effective <= last && effective.saturating_add(contribution.length) > last;
                let another_tail = covers_last
                    && self.contributions.iter().any(|other| {
                        !std::ptr::eq(other, contribution)
                            && other.offset < consumed.saturating_add(last)
                            && other.offset.saturating_add(other.length)
                                > consumed.saturating_add(last)
                    });
                Some(PduSegment {
                    frame: contribution.frame,
                    file: contribution.file,
                    offset: effective,
                    length: clipped,
                    data: segment_data,
                    overlap: contribution.overlap,
                    conflict: contribution.conflict,
                    toolong: false,
                    multipletails: another_tail,
                })
            })
            .collect();
        segments.sort_by_key(|segment| segment.offset);
        segments
    }

    /// Advance the window past a completed PDU.
    ///
    /// Consumption moves a head pointer; `compact_if_needed` reclaims the
    /// prefix later, so emitting many PDUs from one window stays linear.
    fn consume(&mut self, length: usize) {
        self.head = self.head.saturating_add(length);
        self.reset_http_scan();
        self.start = self
            .start
            .map(|start| start.wrapping_add(u32::try_from(length).unwrap_or(u32::MAX)));
        self.frontier = self.start;
        if self.head >= self.data.len() {
            self.start = None;
            // The window is empty: release a completed message's large
            // buffers so an idle conversation is not charged for capacity it
            // no longer holds.
            self.release_large_buffers();
        }
    }

    /// Take the window's contiguous prefix for a completed PDU.
    ///
    /// When the prefix is the whole window the vector moves into the shared
    /// [`Bytes`] instead of being copied, so the largest reassembled object
    /// has one allocation rather than two.
    fn extract_prefix(&mut self, length: usize) -> Bytes {
        let available = self.data.len().saturating_sub(self.head);
        if self.head == 0 && length == available {
            Bytes::new(std::mem::take(&mut self.data))
        } else {
            Bytes::from(
                self.window_data()
                    .get(..length)
                    .unwrap_or_default()
                    .to_vec(),
            )
        }
    }

    /// Grow the window to hold `length` bytes from its start.
    ///
    /// Growth is geometric but clamped to the direction's window bound, so a
    /// 64 MiB HTTP body never reserves twice its limit in `data` (the state
    /// ledger charges capacity, not length). `reserve_exact` to the clamped
    /// target keeps the charge equal to the bytes the direction can use.
    fn ensure(&mut self, length: usize, window_limit: usize) {
        let needed = self.head.saturating_add(length);
        if self.data.len() >= needed {
            return;
        }
        let limit = window_limit.max(needed);
        if self.data.capacity() < needed {
            let target = needed
                .max(self.data.capacity().saturating_mul(2))
                .min(limit);
            self.data
                .reserve_exact(target.saturating_sub(self.data.len()));
        }
        if self.covered.capacity() < needed {
            let target = needed
                .max(self.covered.capacity().saturating_mul(2))
                .min(limit);
            self.covered
                .reserve_exact(target.saturating_sub(self.covered.len()));
        }
        self.data.resize(needed, 0);
        self.covered.resize(needed, false);
    }
}

/// Prepend bytes a segment carried before the pending PDU start.
///
/// The whole segment is reported in `tcp.segment_data` when a segment
/// starts before the PDU it helps complete.
fn prepend_dropped_prefix(actions: &mut [PduAction], prefix: &[u8]) {
    if prefix.is_empty() {
        return;
    }
    for action in actions {
        match action {
            PduAction::Reassembled { segment_data, .. }
            | PduAction::Partial { segment_data, .. } => {
                let mut bytes = prefix.to_vec();
                bytes.extend_from_slice(&segment_data.bytes);
                segment_data.bytes = bytes;
                segment_data.offset = 0;
                return;
            }
            PduAction::SegmentData { .. } | PduAction::Standalone { .. } => {}
        }
    }
}

/// The first token of an HTTP message.
enum HttpStart<'a> {
    Request(&'a str),
    Response(Option<u16>),
}

/// Read an HTTP request method or recognise a response start line.
fn http_start(data: &[u8]) -> Option<HttpStart<'_>> {
    let (line, _) = next_line(data, 0)?;
    let line = crate::http_syntax::parse_start_line(line)?;
    if line.is_response() {
        return Some(HttpStart::Response(
            line.response_code()
                .and_then(|code| u16::try_from(code).ok()),
        ));
    }
    match line {
        crate::http_syntax::StartLine::Request { method, .. } => Some(HttpStart::Request(method)),
        crate::http_syntax::StartLine::Response { .. } => None,
    }
}

/// Whether a PDU's first segment carries the frame the protocol reads.
fn header_present(ulp: Ulp, chunk: &[u8]) -> bool {
    match ulp {
        Ulp::Dns => chunk.len() >= DNS_LENGTH_BYTES,
        Ulp::Tls => chunk.len() >= TLS_HEADER_BYTES,
        Ulp::Bgp => chunk.len() >= BGP_HEADER_BYTES,
        Ulp::Http => header_section_end(chunk).is_some(),
        Ulp::Http2 => chunk.len() >= HTTP2_HEADER_BYTES,
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

fn read_u24(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(3)?)?;
    Some(
        u32::from(*bytes.first()?) << 16
            | u32::from(*bytes.get(1)?) << 8
            | u32::from(*bytes.get(2)?),
    )
}

/// Where a chunked body ends.
enum ChunkedEnd {
    Complete(usize),
    NeedMore,
    Invalid,
    TooLarge,
}

/// Both directions of one conversation, each with its own reassembly limit.
#[derive(Debug, Default)]
pub(crate) struct ConversationStreams {
    directions: [StreamBuffer; 2],
}

impl ConversationStreams {
    pub(crate) fn direction(&self, direction: usize) -> &StreamBuffer {
        // The canonical direction is always zero or one.
        self.directions
            .get(direction.min(1))
            .unwrap_or_else(|| unreachable!("two directions are always present"))
    }

    /// Remember whether the next response in the other direction is bodyless.
    ///
    /// A response to HEAD carries no body even with Content-Length set
    /// (RFC 9112 section 6.3). The request method is the only framing fact the
    /// two directions share.
    pub(crate) fn observe_http_request(&mut self, direction: usize, payload: &[u8]) {
        let direction = direction.min(1);
        let (first, second) = self.directions.split_at_mut(1);
        let peer = if direction == 0 {
            second.first_mut()
        } else {
            first.first_mut()
        };
        let Some(peer) = peer else {
            return;
        };
        let line_end = payload.iter().position(|byte| *byte == b'\n');
        let Some(line_end) = line_end else {
            return;
        };
        let mut line = payload.get(..line_end).unwrap_or_default();
        if let Some(stripped) = line.strip_suffix(b"\r") {
            line = stripped;
        }
        if line.starts_with(b"HTTP/1.") {
            return;
        }
        let Some(space) = line.iter().position(|byte| *byte == b' ') else {
            return;
        };
        let method = line.get(..space).unwrap_or_default();
        peer.head_pending = method.eq_ignore_ascii_case(b"HEAD");
    }

    pub(crate) fn direction_mut(&mut self, direction: usize) -> &mut StreamBuffer {
        // The canonical direction is always zero or one.
        self.directions
            .get_mut(direction.min(1))
            .unwrap_or_else(|| unreachable!("two directions are always present"))
    }

    /// Bytes retained by both directions, including allocation capacity.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.directions.iter().map(StreamBuffer::heap_bytes).sum()
    }

    /// Payload bytes waiting in both direction buffers.
    ///
    /// Directions are bounded independently, so this is a diagnostic sum;
    /// the state ledger charges capacity through [`Self::heap_bytes`].
    #[cfg(test)]
    pub(crate) fn payload_bytes(&self) -> usize {
        self.directions
            .iter()
            .map(StreamBuffer::payload_bytes)
            .sum()
    }

    /// Track the request method for HTTP responses in the other direction.
    ///
    /// A response to HEAD has no body; the request method is the only
    /// body-framing fact the two directions share.
    pub(crate) fn observe_http_actions(&mut self, direction: usize, actions: &[PduAction]) {
        let direction = direction.min(1);
        let (first, second) = self.directions.split_at_mut(1);
        let (current, peer) = if direction == 0 {
            (first.first_mut(), second.first_mut())
        } else {
            (second.first_mut(), first.first_mut())
        };
        let (Some(current), Some(peer)) = (current, peer) else {
            return;
        };
        for action in actions {
            let (ulp, data) = match action {
                PduAction::Standalone { ulp, data, .. } => (ulp, data.as_slice()),
                PduAction::Reassembled { pdu, .. } => (&pdu.ulp, pdu.data.as_slice()),
                _ => continue,
            };
            if *ulp != Ulp::Http {
                continue;
            }
            match http_start(data) {
                Some(HttpStart::Request(method)) => {
                    peer.head_pending = method.eq_ignore_ascii_case("HEAD");
                    peer.connect_pending = method.eq_ignore_ascii_case("CONNECT");
                }
                Some(HttpStart::Response(code)) if code.is_none_or(|code| code >= 200) => {
                    current.head_pending = false;
                    current.connect_pending = false;
                }
                Some(HttpStart::Response(_)) | None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::DEFAULT_STATE_BUDGET;

    #[test]
    fn tls_version_round_trips_through_the_store() {
        let mut session = SessionState::new(DEFAULT_STATE_BUDGET);
        let (key, _) = ConversationKey::ipv4([192, 0, 2, 1], 40_000, [192, 0, 2, 2], 443);
        assert_eq!(session.tls_version(key), None);
        session.set_tls_version(key, 0x0304);
        assert_eq!(session.tls_version(key), Some(0x0304));
        session.set_tls_version(key, 0x0303);
        assert_eq!(session.tls_version(key), Some(0x0304));
    }

    #[test]
    fn tls_plaintext_frames_one_message_across_record_chunks() {
        let mut session = SessionState::new(DEFAULT_STATE_BUDGET);
        let (key, _) = ConversationKey::ipv4([192, 0, 2, 1], 40_000, [192, 0, 2, 2], 443);
        let request = b"GET /split HTTP/1.1\r\nHost: tls.test\r\n\r\n";
        let mut completed = Vec::new();
        for (frame, chunk) in [
            request.get(..5).unwrap_or_default(),
            request.get(5..20).unwrap_or_default(),
            request.get(20..).unwrap_or_default(),
        ]
        .into_iter()
        .enumerate()
        {
            let (report, _) = session.insert_tls_plaintext(
                key,
                0,
                u64::try_from(frame).unwrap_or(0),
                chunk,
                false,
                false,
            );
            for action in report.actions {
                if let PduAction::Reassembled { pdu, .. } = action {
                    completed.push(pdu.data);
                }
            }
        }
        assert_eq!(completed, vec![request.to_vec()]);
    }

    fn dns_pdu(message_len: u16) -> Vec<u8> {
        let mut pdu = message_len.to_be_bytes().to_vec();
        pdu.resize(2 + usize::from(message_len), 0x41);
        pdu
    }

    fn actions(report: &ReassemblyReport) -> Vec<&PduAction> {
        report.actions.iter().collect()
    }

    #[test]
    fn a_single_segment_pdu_reports_only_its_size() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let pdu = dns_pdu(6);
        let report = buffer.insert(100, &pdu, 1, false);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Standalone { .. })
        ));
        if let Some(PduAction::Standalone { pdu_size, data, .. }) = report.actions.first() {
            assert_eq!(*pdu_size, Some(8));
            assert_eq!(data, &pdu);
        }
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_split_pdu_reassembles_with_first_arrived_bytes() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let pdu = dns_pdu(6);
        let first_five = pdu.get(..5).unwrap_or_default();
        let first = buffer.insert(100, first_five, 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Partial { segment_data, .. }) if segment_data.bytes == first_five
        ));
        let junk = pdu.get(5..).unwrap_or_default();
        let completed = buffer.insert(105, junk, 2, false);
        assert_eq!(completed.actions.len(), 1, "{:?}", completed.actions);
        let Some(PduAction::Reassembled {
            pdu: reassembled, ..
        }) = completed.actions.first()
        else {
            return;
        };
        assert_eq!(reassembled.data, pdu, "the first copy of each byte wins");
        assert_eq!(reassembled.segments.len(), 2);
        assert_eq!(
            reassembled.segments.first().map(|segment| segment.frame),
            Some(1)
        );
        assert_eq!(
            reassembled.segments.get(1).map(|segment| segment.frame),
            Some(2)
        );
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_conflicting_overlap_keeps_the_first_byte_and_names_the_frame() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let pdu = dns_pdu(6);
        let first = buffer.insert(100, pdu.get(..5).unwrap_or_default(), 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        let mut junk = pdu.get(4..).unwrap_or_default().to_vec();
        if let Some(byte) = junk.first_mut() {
            *byte = 0xff;
        }
        let completed = buffer.insert(104, &junk, 2, false);
        let Some(PduAction::Reassembled {
            pdu: reassembled, ..
        }) = completed.actions.first()
        else {
            return;
        };
        assert_eq!(reassembled.data, pdu);
        assert_eq!(completed.error_frame, Some(2));
        let listed = reassembled
            .segments
            .iter()
            .find(|segment| segment.frame == 2);
        assert_eq!(
            listed.and_then(|segment| segment.data.first().copied()),
            Some(0xff)
        );
        assert!(listed.is_some_and(|segment| segment.conflict));
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_gap_keeps_the_pdu_incomplete_and_marks_partial_bytes() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let pdu = dns_pdu(10);
        buffer.insert(100, pdu.get(..4).unwrap_or_default(), 1, false);
        let tail_bytes = pdu.get(6..).unwrap_or_default();
        let tail = buffer.insert(106, tail_bytes, 2, false);
        assert!(matches!(
            tail.actions.first(),
            Some(PduAction::Partial { segment_data, .. }) if segment_data.bytes == tail_bytes
        ));
        let fill = buffer.insert(104, pdu.get(4..6).unwrap_or_default(), 3, false);
        let Some(PduAction::Reassembled {
            pdu: reassembled, ..
        }) = fill.actions.first()
        else {
            return;
        };
        assert_eq!(reassembled.data, pdu);
        assert_eq!(reassembled.segments.len(), 3);
    }

    #[test]
    fn several_pdus_in_one_segment_all_decode() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let mut payload = dns_pdu(4);
        payload.extend_from_slice(&dns_pdu(5));
        let report = buffer.insert(100, &payload, 1, false);
        let actions = actions(&report);
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            actions.first(),
            Some(PduAction::Standalone { .. })
        ));
        assert!(matches!(actions.get(1), Some(PduAction::Standalone { .. })));
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_completed_pdu_leaves_the_next_pdu_for_the_same_segment() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let first = dns_pdu(4);
        let first_part = buffer.insert(100, first.get(..3).unwrap_or_default(), 1, false);
        assert!(matches!(
            first_part.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        let mut payload = first.get(3..).unwrap_or_default().to_vec();
        payload.extend_from_slice(&first);
        let report = buffer.insert(103, &payload, 2, false);
        let actions = actions(&report);
        assert_eq!(actions.len(), 2);
        assert!(matches!(
            actions.first(),
            Some(PduAction::Reassembled { .. })
        ));
        assert!(matches!(actions.get(1), Some(PduAction::Standalone { .. })));
    }

    #[test]
    fn retransmitted_bytes_before_the_frontier_only_carry_segment_data() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let pdu = dns_pdu(4);
        let first = buffer.insert(100, &pdu, 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Standalone { .. })
        ));
        let repeat = buffer.insert(100, &pdu, 2, false);
        assert!(matches!(
            repeat.actions.first(),
            Some(PduAction::SegmentData { segment_data }) if segment_data.bytes == pdu
        ));
        assert!(repeat.actions.iter().all(|action| !matches!(
            action,
            PduAction::Standalone { .. } | PduAction::Reassembled { .. }
        )));
    }

    #[test]
    fn a_one_byte_segment_flood_stays_bounded() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        for sequence in 0..70_000_u32 {
            let _ = buffer.insert(sequence, &[0x41], u64::from(sequence), false);
        }
        // HTTP refuses at its segment-count cap long before the millionth
        // one-byte segment; the direction holds no retained bytes after it.
        assert!(
            buffer.heap_bytes() <= MAX_HTTP_MESSAGE_BYTES,
            "buffered {} bytes for a 64 MiB HTTP limit",
            buffer.heap_bytes()
        );
        assert!(!buffer.has_pending());
        assert!(buffer.refused);
    }

    #[test]
    fn an_overlap_flood_stays_bounded() {
        // Every retransmission is a segment in the reassembly list, so
        // the contribution table grows until the segment cap refuses the
        // PDU. The retained bytes stay bounded by the PDU limit either way.
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        for frame in 0..100_000_u64 {
            let _ = buffer.insert(100, b"AAAAAAAAAA", frame, false);
        }
        assert!(buffer.heap_bytes() <= MAX_PDU_BYTES);
        assert!(!buffer.has_pending());
        assert!(buffer.refused);
        assert_eq!(buffer.contributions.len(), 0);
    }

    #[test]
    fn a_large_overlap_flood_stays_bounded() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        // One MiB per repeated contribution reaches the byte cap long before
        // the 65,536-segment cap, so this exercises the contribution-byte
        // bound rather than only the metadata count. The header keeps the PDU
        // pending so the repeated bytes stay contributions.
        let mut payload = b"HTTP/1.1 200 OK\r\nContent-Length: 62914560\r\n\r\n".to_vec();
        payload.resize(MAX_PDU_BYTES, b'A');
        let mut last = ReassemblyReport::default();
        for frame in 0..(Ulp::Http.contribution_limit() / payload.len() + 2) {
            last = buffer.insert(
                100,
                &payload,
                u64::try_from(frame).unwrap_or(u64::MAX),
                false,
            );
            if buffer.refused {
                break;
            }
        }
        assert!(
            last.error,
            "the contribution-byte cap did not report an error"
        );
        assert!(
            buffer.heap_bytes()
                <= Ulp::Http
                    .contribution_limit()
                    .saturating_add(Ulp::Http.pdu_limit()),
            "retained {} bytes",
            buffer.heap_bytes()
        );
        assert!(!buffer.has_pending());
        assert!(buffer.refused);
    }

    #[test]
    fn a_long_split_pdu_reports_a_reassembly_error_instead_of_unbounded_metadata() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        for sequence in 0..(Ulp::Http.segment_limit() as u32 + 100) {
            let _ = buffer.insert(sequence, &[0x41], u64::from(sequence), false);
        }
        assert!(!buffer.has_pending());
        assert!(buffer.refused);
    }

    #[test]
    fn the_first_segment_must_carry_the_protocol_minimum() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Bgp);
        let outcome = buffer.insert(100, &[0xff; 10], 1, false);
        assert!(outcome.actions.is_empty());
        let later = buffer.insert(110, &[0xff; 10], 2, false);
        assert!(later.actions.is_empty());
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_short_first_segment_still_reassembles_dns() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let pdu = dns_pdu(6);
        let first = buffer.insert(100, pdu.get(..1).unwrap_or_default(), 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        let completed = buffer.insert(101, pdu.get(1..).unwrap_or_default(), 2, false);
        assert!(matches!(
            completed.actions.first(),
            Some(PduAction::Reassembled { .. })
        ));
    }

    #[test]
    fn a_short_segment_after_a_complete_pdu_does_not_refuse_the_direction() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Bgp);
        let mut payload = vec![0xff; 16];
        payload.extend_from_slice(&19_u16.to_be_bytes());
        payload.push(4);
        let first = buffer.insert(100, &payload, 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Standalone { .. })
        ));
        let short = buffer.insert(
            100_u32.saturating_add(u32::try_from(payload.len()).unwrap_or(0)),
            &[0xff; 10],
            2,
            false,
        );
        assert!(short.actions.is_empty());
        assert!(!buffer.refused);
    }

    #[test]
    fn a_close_delimited_response_completes_at_fin() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        let mut first = header.to_vec();
        first.extend_from_slice(b"close-");
        let report = buffer.insert(1000, &first, 1, false);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        assert!(buffer.has_pending());
        let sequence = 1000_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
        let report = buffer.insert_with_fin(sequence, b"body", 2, false, true);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Reassembled { .. })
        ));
        let Some(PduAction::Reassembled { pdu, .. }) = report.actions.first() else {
            return;
        };
        assert!(pdu.data.ends_with(b"close-body"));
        assert_eq!(
            pdu.segments
                .iter()
                .map(|segment| segment.frame)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(!buffer.has_pending());
    }

    #[test]
    fn an_empty_fin_is_named_in_the_reassembly_list() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let message = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclose-body";
        let report = buffer.insert(1000, message, 1, false);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        let sequence = 1000_u32.saturating_add(u32::try_from(message.len()).unwrap_or(0));
        let report = buffer.insert_with_fin(sequence, b"", 2, false, true);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Reassembled { .. })
        ));
        let Some(PduAction::Reassembled { pdu, .. }) = report.actions.first() else {
            return;
        };
        assert_eq!(pdu.segments.len(), 2);
        assert_eq!(pdu.segments.get(1).map(|segment| segment.length), Some(0));
        assert_eq!(pdu.segments.get(1).map(|segment| segment.frame), Some(2));
    }

    #[test]
    fn a_close_delimited_message_in_the_fin_segment_is_standalone() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let message = b"HTTP/1.1 200 OK\r\n\r\nclose-body";
        let report = buffer.insert_with_fin(1000, message, 1, false, true);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Standalone { .. })
        ));
        let Some(PduAction::Standalone { data, .. }) = report.actions.first() else {
            return;
        };
        assert!(data.ends_with(b"close-body"));
    }

    #[test]
    fn a_complete_http_request_leaves_the_next_partial_piece() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let payload = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGE";
        let report = buffer.insert(100, payload, 1, false);
        assert_eq!(report.actions.len(), 2, "{:?}", report.actions);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Standalone { .. })
        ));
        assert!(matches!(
            report.actions.get(1),
            Some(PduAction::Partial { .. })
        ));
        if let Some(PduAction::Partial { segment_data, .. }) = report.actions.get(1) {
            assert_eq!(segment_data.bytes, b"GE");
        }
    }

    #[test]
    fn an_unparseable_line_after_a_message_is_a_continuation() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let message = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc1.1 200 OK\r\nContent-Len";
        let report = buffer.insert(1000, message, 1, false);
        let data: Vec<&[u8]> = report
            .actions
            .iter()
            .filter_map(|action| match action {
                PduAction::Standalone { data, .. } => Some(data.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(data.len(), 2);
        assert_eq!(data.first().map(|data| data.len()), Some(41));
        assert_eq!(
            data.get(1).copied(),
            Some(b"1.1 200 OK\r\nContent-Len".as_slice())
        );
    }

    #[test]
    fn a_leading_crlf_before_a_request_is_not_a_continuation() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx\r\nGET /next HTTP/1.1\r\nHost: h\r\n\r\n";
        let report = buffer.insert(100, payload, 1, false);
        let requests: Vec<&[u8]> = report
            .actions
            .iter()
            .filter_map(|action| match action {
                PduAction::Standalone { data, .. }
                    if data.ends_with(b"GET /next HTTP/1.1\r\nHost: h\r\n\r\n") =>
                {
                    Some(data.as_slice())
                }
                _ => None,
            })
            .collect();
        // The leading CRLF belongs to the second PDU's bytes, but it must be
        // classified as a message rather than as continuation file data.
        assert_eq!(requests.len(), 1, "{} actions", report.actions.len());
    }

    #[test]
    fn a_close_delimited_response_does_not_complete_without_fin() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let message = b"HTTP/1.1 200 OK\r\n\r\nclose-body";
        let report = buffer.insert(1000, message, 1, false);
        assert!(matches!(
            report.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        assert!(buffer.has_pending());
    }

    #[test]
    fn a_window_of_tiny_pdus_is_capped() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let payload = vec![0_u8; 20_000];
        let report = buffer.insert(100, &payload, 1, false);
        assert!(report.limit_reached);
        assert!(report.actions.len() <= MAX_PDUS_PER_INSERT);
        assert!(buffer.refused);
    }

    #[test]
    fn a_chunked_http_body_waits_for_the_last_chunk() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let message =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n";
        let split = message.len() - 5;
        let first = buffer.insert(100, message.get(..split).unwrap_or_default(), 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        let completed = buffer.insert(
            100 + u32::try_from(split).unwrap_or(0),
            message.get(split..).unwrap_or_default(),
            2,
            false,
        );
        let Some(PduAction::Reassembled { pdu, .. }) = completed.actions.first() else {
            return;
        };
        assert_eq!(pdu.data, message);
    }

    #[test]
    fn a_header_block_split_across_segments_frames_the_message_once() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let message =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        // Split inside the Content-Length field name, so neither the framing
        // field nor the header terminator arrives whole.
        let cut = 50_usize;
        assert_eq!(
            message.get(cut..cut.saturating_add(8)),
            Some(b"-Length:".as_slice())
        );
        let first = buffer.insert(100, message.get(..cut).unwrap_or_default(), 1, false);
        assert!(matches!(
            first.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        assert!(buffer.has_pending());
        let completed = buffer.insert(
            100_u32.saturating_add(u32::try_from(cut).unwrap_or(u32::MAX)),
            message.get(cut..).unwrap_or_default(),
            2,
            false,
        );
        let Some(PduAction::Reassembled { pdu, .. }) = completed.actions.first() else {
            return;
        };
        assert_eq!(pdu.ulp, Ulp::Http);
        assert_eq!(pdu.data, message);
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_multi_mib_chunked_body_reassembles_across_many_segments() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let body = vec![b'A'; 2 * 1024 * 1024];
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for chunk in body.chunks(8192) {
            message.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            message.extend_from_slice(chunk);
            message.extend_from_slice(b"\r\n");
        }
        message.extend_from_slice(b"0\r\n\r\n");
        let expected = message.len();
        let mut sequence = 100_u32;
        let mut report = ReassemblyReport::default();
        for chunk in message.chunks(1460) {
            report = buffer.insert(sequence, chunk, 1, false);
            sequence = sequence.wrapping_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        }
        let Some(PduAction::Reassembled { pdu, .. }) = report.actions.first() else {
            return;
        };
        assert_eq!(pdu.data.len(), expected);
        assert_eq!(pdu.data, message);
    }

    #[test]
    fn a_chunked_message_beyond_the_cap_is_oversized() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        message.extend_from_slice(b"4600000\r\n");
        let outcome = buffer.insert(100, &message, 1, false);
        assert_eq!(outcome.oversized, Some("64 MiB HTTP"));
        assert!(!buffer.has_pending());
        assert!(buffer.refused);
    }

    #[test]
    fn a_header_over_the_shared_cap_is_oversized() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let mut message = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        message.resize(
            message
                .len()
                .saturating_add(MAX_HEADER_BYTES)
                .saturating_add(1),
            b'A',
        );
        message.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let outcome = buffer.insert(100, &message, 1, false);
        assert_eq!(outcome.oversized, Some("1 MiB header"));
        assert!(!buffer.has_pending());
        assert!(!buffer.refused);
    }

    #[test]
    fn a_pdu_over_the_limit_is_not_reassembled() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let declared = MAX_HTTP_MESSAGE_BYTES.saturating_add(1);
        let mut pdu = format!("POST / HTTP/1.1\r\nContent-Length: {declared}\r\n\r\n").into_bytes();
        pdu.resize(64, 0x41);
        let outcome = buffer.insert(100, &pdu, 1, false);
        assert_eq!(outcome.oversized, Some("64 MiB HTTP"));
        assert!(!buffer.has_pending());
    }

    #[test]
    fn a_non_http_pdu_over_one_mib_is_refused() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Dns);
        let mut pdu = 4_u16.to_be_bytes().to_vec();
        pdu.resize(MAX_PDU_BYTES.saturating_add(1), 0x41);
        let outcome = buffer.insert(100, &pdu, 1, false);
        assert_eq!(outcome.oversized, Some("1 MiB"));
        assert!(!buffer.has_pending());
        assert_eq!(outcome.actions.len(), 0);
    }

    #[test]
    fn http_messages_at_the_object_cap_reassemble() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let body_bytes = crate::export::MAX_EXPORT_OBJECT_BYTES as usize;
        let mut message = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {body_bytes}\r\n\r\n"
        )
        .into_bytes();
        message.resize(message.len().saturating_add(body_bytes), b'A');
        assert!(message.len() <= MAX_HTTP_MESSAGE_BYTES);
        let expected = message.len();
        let mut sequence = 100_u32;
        let mut report = ReassemblyReport::default();
        for chunk in message.chunks(MAX_PDU_BYTES) {
            report = buffer.insert(sequence, chunk, 1, false);
            sequence = sequence.wrapping_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        }
        let actions = report.actions.len();
        assert_eq!(actions, 1, "a 64 MiB body did not reassemble");
        let Some(PduAction::Reassembled { pdu, .. }) = report.actions.first() else {
            return;
        };
        assert_eq!(pdu.ulp, Ulp::Http);
        assert_eq!(pdu.data.len(), expected);
        // A completed message must not leave its large buffers charged; only
        // the small reuse-sized allocations may remain.
        assert!(
            buffer.heap_bytes() <= 64 * 1024,
            "retained {} bytes after completion",
            buffer.heap_bytes()
        );
    }

    #[test]
    fn directions_are_limited_independently() {
        let mut streams = ConversationStreams::default();
        streams.direction_mut(0).set_ulp(Ulp::Http);
        streams.direction_mut(1).set_ulp(Ulp::Dns);
        let body_bytes = 4 * 1024 * 1024;
        let mut message =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {body_bytes}\r\n\r\n").into_bytes();
        message.resize(message.len().saturating_add(body_bytes), b'A');
        let first = message.len().saturating_sub(body_bytes / 2);
        let http = streams.direction_mut(0).insert(
            100,
            message.get(..first).unwrap_or_default(),
            1,
            false,
        );
        assert!(matches!(
            http.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        let pdu = dns_pdu(65_000);
        let dns = streams
            .direction_mut(1)
            .insert(200, pdu.get(..2).unwrap_or_default(), 2, false);
        assert!(matches!(
            dns.actions.first(),
            Some(PduAction::Partial { .. })
        ));
        // Both directions together exceed the old shared 1 MiB cap, but each
        // is inside its own bound, so neither is trimmed or refused.
        assert!(streams.payload_bytes() > MAX_PDU_BYTES);
        assert!(streams.direction(0).has_pending());
        assert!(streams.direction(1).has_pending());
    }

    #[test]
    fn a_declared_body_over_the_cap_skips_to_its_declared_end() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let declared = MAX_HTTP_MESSAGE_BYTES.saturating_add(4096);
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n");
        let outcome = buffer.insert(100, header.as_bytes(), 1, false);
        assert_eq!(outcome.oversized, Some("64 MiB HTTP"));
        assert!(!buffer.has_pending());
        assert!(!buffer.refused);
        let next = 100_u32
            .wrapping_add(u32::try_from(header.len().saturating_add(declared)).unwrap_or(u32::MAX));
        let small = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let outcome = buffer.insert(next, small, 2, false);
        let Some(PduAction::Standalone { data, .. }) = outcome.actions.first() else {
            return;
        };
        assert_eq!(data, small);
    }

    #[test]
    fn an_oversized_header_keeps_the_direction_alive() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let mut message = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        message.resize(
            message
                .len()
                .saturating_add(MAX_HEADER_BYTES)
                .saturating_add(1),
            b'A',
        );
        message.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let small = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        message.extend_from_slice(small);
        let outcome = buffer.insert(100, &message, 1, false);
        assert_eq!(outcome.oversized, Some("1 MiB header"));
        assert!(!buffer.refused);
        let Some(PduAction::Standalone { data, .. }) = outcome
            .actions
            .iter()
            .find(|action| matches!(action, PduAction::Standalone { .. }))
        else {
            return;
        };
        assert_eq!(data, small);
    }

    #[test]
    fn a_far_segment_does_not_drop_a_pending_message() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        // A 60 KB tail admitted near the message cap, then a tiny header
        // segment. The admitted window must not be re-judged against the
        // later segment's smaller trailing allowance.
        let far = vec![b'A'; 60_000];
        let far_sequence = 100_u32.wrapping_add(
            u32::try_from(MAX_HTTP_MESSAGE_BYTES.saturating_sub(1)).unwrap_or(u32::MAX),
        );
        let outcome = buffer.insert(far_sequence, &far, 1, false);
        assert!(!outcome.oversized.is_some(), "{:?}", outcome.oversized);
        assert!(!buffer.refused);
        let header = b"HTTP/1.1 200 OK\r\nContent-Length: 62914560\r\n\r\n";
        let outcome = buffer.insert(100, header, 2, false);
        assert!(!outcome.oversized.is_some(), "{:?}", outcome.oversized);
        assert!(!buffer.refused);
        assert!(buffer.has_pending());
        let later = far_sequence.wrapping_add(61_000);
        let outcome = buffer.insert(later, b"GET /later HTTP/1.1\r\n\r\n", 3, false);
        assert!(!outcome.oversized.is_some(), "{:?}", outcome.oversized);
        assert!(!buffer.refused);
    }

    #[test]
    fn a_long_chunk_size_line_is_scanned_incrementally() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        message.extend(std::iter::repeat_n(b'0', 200_000));
        message.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        let expected = message.len();
        let mut sequence = 100_u32;
        let mut report = ReassemblyReport::default();
        for chunk in message.chunks(1460) {
            report = buffer.insert(sequence, chunk, 1, false);
            sequence = sequence.wrapping_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        }
        let Some(PduAction::Reassembled { pdu, .. }) = report.actions.first() else {
            return;
        };
        assert_eq!(pdu.data.len(), expected);
        assert_eq!(pdu.data, message);
    }

    #[test]
    fn an_unusable_chunk_body_is_not_scanned_again() {
        // Once the chunk grammar fails, the message can only end at the
        // covered prefix or at the stream close; rescanning the body from its
        // first chunk on every later insert would be quadratic on a hostile
        // stream.
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        message.extend_from_slice(b"1\r\naXX");
        let header_end = header_section_end(&message).unwrap_or_default();
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        buffer.data = message;
        buffer.covered = vec![true; buffer.data.len()];
        buffer.contiguous = buffer.data.len();
        let covered = buffer.data.len();
        assert!(matches!(
            buffer.chunked_body_end(header_end, covered, MAX_PDU_BYTES),
            ChunkedEnd::Invalid
        ));
        let scans = buffer.chunk_scans;
        assert_eq!(scans, 1, "the body must be scanned once");
        // A later call for the same pending message reuses the failed result.
        assert!(matches!(
            buffer.chunked_body_end(header_end, covered, MAX_PDU_BYTES),
            ChunkedEnd::Invalid
        ));
        assert_eq!(buffer.chunk_scans, scans, "the body was scanned again");
    }

    #[test]
    fn an_oversized_chunked_header_skips_the_whole_message() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Big: ".to_vec();
        message.resize(
            message
                .len()
                .saturating_add(MAX_HEADER_BYTES)
                .saturating_add(1),
            b'A',
        );
        message.extend_from_slice(b"\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
        let small = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        message.extend_from_slice(small);
        let mut sequence = 100_u32;
        let mut report = ReassemblyReport::default();
        for chunk in message.chunks(1460) {
            report = buffer.insert(sequence, chunk, 1, false);
            sequence = sequence.wrapping_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        }
        assert_eq!(report.oversized, Some("1 MiB header"));
        let responses: Vec<&[u8]> = report
            .actions
            .iter()
            .filter_map(|action| match action {
                PduAction::Reassembled { pdu, .. } => Some(pdu.data.as_slice()),
                PduAction::Standalone { data, .. } => Some(data.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(responses.len(), 1, "{:?}", report.actions.len());
        assert_eq!(responses.first().copied(), Some(small.as_slice()));
    }

    #[test]
    fn an_oversized_close_delimited_header_is_not_exported_at_fin() {
        let mut buffer = StreamBuffer::default();
        buffer.set_ulp(Ulp::Http);
        let mut message = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        message.resize(
            message
                .len()
                .saturating_add(MAX_HEADER_BYTES)
                .saturating_add(1),
            b'A',
        );
        message.extend_from_slice(b"\r\n\r\nbody");
        let first = buffer.insert(100, &message, 1, false);
        assert!(!first.oversized.is_some(), "{:?}", first.oversized);
        let sequence = 100_u32.wrapping_add(u32::try_from(message.len()).unwrap_or(u32::MAX));
        let fin = buffer.insert_with_fin(sequence, &[], 2, false, true);
        assert_eq!(fin.oversized, Some("1 MiB header"));
        assert!(fin.actions.is_empty(), "{:?}", fin.actions.len());
        assert!(!buffer.has_pending());
    }

    #[test]
    fn the_state_ledger_evicts_an_over_budget_reassembly() {
        let mut session = SessionState::new(4096);
        let (key, _) = ConversationKey::ipv4([192, 0, 2, 1], 40_000, [192, 0, 2, 2], 80);
        let chunk = vec![b'A'; 8192];
        let _ = session.insert_tls_plaintext(key, 0, 1, &chunk, false, false);
        assert!(session.take_dropped(), "the state ledger accepted 8 KiB");
    }
}
