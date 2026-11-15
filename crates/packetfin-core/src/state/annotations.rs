//! Per-frame cross-pass annotations and output renumbering.
//!
//! A two-pass run records links between frames in pass one and replays them
//! in pass two. Records are indexed by file frame number and hold both
//! directions of a link, because either counterpart may be hidden by the
//! read filter: a link to a frame that is not displayed is still printed,
//! mapped through the same renumbering rule as the displayed frames.
//!
//! The store grows in chunks so its resident memory stays inside the
//! annotation budget. When a new frame cannot be recorded, later annotations
//! are omitted and the session reports the truncation once; packets already
//! annotated keep their fields.

use std::collections::BTreeMap;
use std::mem::size_of;

use crate::decode::Packet;
use crate::fields;
use crate::tree::{ExpertInfo, Field, Group, Node, Range, Severity, Value};

/// Packetfin's default annotation budget: 64 MiB, a ledger separate from
/// state and statistics.
pub const DEFAULT_ANNOTATION_BUDGET: usize = 64 * 1024 * 1024;

/// Entries reserved per growth step.
///
/// Growing one entry at a time would reallocate (and copy) for every frame;
/// reserving a chunk keeps the amortised cost constant while capping the
/// final allocation at the budget.
const GROWTH_CHUNK: usize = 4096;

/// State recorded for one file frame.
///
/// Frame references are one-based file frame numbers; zero means "absent",
/// matching [`RenumberMap::output`]'s one-based output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameAnnotation {
    /// Frame whose request this frame answers, for responses.
    pub request_in: u32,
    /// Frame that answers this request, for queries.
    pub response_in: u32,
    /// Request-to-response delay in nanoseconds.
    pub time_ns: i64,
    /// Frame that completes a TCP PDU this frame started or continued.
    pub tcp_reassembled_in: u32,
    /// Frame that completes an IPv4 datagram this fragment belongs to.
    pub ip_reassembled_in: u32,
    /// Frame that completes an IPv6 datagram this fragment belongs to.
    pub ipv6_reassembled_in: u32,
    /// Frame that completes a TLS record this frame started.
    pub tls_reassembled_in: u32,
    /// Frame that completes a TLS handshake message this frame started.
    pub tls_handshake_reassembled_in: u32,
    /// Final TLS version that labels this conversation's records.
    pub tls_version: u16,
    flags: u8,
}

impl FrameAnnotation {
    /// The frame is an unanswered query in two-pass analysis.
    pub const RESPONSE_MISSING: u8 = 0x01;
    /// `time_ns` carries a measured delay (zero is a valid delay).
    pub const TIME_PRESENT: u8 = 0x04;

    /// Whether a two-pass query was never answered.
    pub const fn response_missing(self) -> bool {
        self.flags & Self::RESPONSE_MISSING != 0
    }

    /// Whether `time_ns` holds a measured delay.
    pub const fn time_present(self) -> bool {
        self.flags & Self::TIME_PRESENT != 0
    }
}

/// Links one HTTP/2 stream carries in one capture frame.
///
/// One capture frame can carry frames of several streams (RFC 9113 section
/// 5), each with its own request, response and body, so these links are kept
/// per frame and stream instead of once per frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Http2Links {
    /// Frame whose request this stream's response answers.
    pub request_in: u32,
    /// Frame that answers this stream's request.
    pub response_in: u32,
    /// Request-to-response delay in nanoseconds, when it was measured.
    pub time_ns: Option<i64>,
    /// Frame that completes the body this stream's DATA contributed to.
    pub body_reassembled_in: u32,
}

/// Bytes one HTTP/2 link entry is charged against the annotation budget.
///
/// A B-tree node holds up to eleven entries and stays at least about half
/// full, so two entry slots bound a link's share of its node and a third
/// covers the node bookkeeping.
const HTTP2_LINK_CHARGE: usize = 3 * size_of::<((u32, u32), Http2Links)>();

/// File-frame-indexed annotations under one byte budget.
#[derive(Debug)]
pub struct AnnotationStore {
    frames: Vec<FrameAnnotation>,
    /// HTTP/2 links by capture frame and stream identifier.
    http2: BTreeMap<(u32, u32), Http2Links>,
    limit: usize,
    truncated: bool,
}

impl AnnotationStore {
    /// Create an empty store with `limit` bytes of allowance.
    ///
    /// Zero disables recording: every attempt reports truncation without
    /// retaining a record.
    pub fn with_budget(limit: usize) -> Self {
        Self {
            frames: Vec::new(),
            http2: BTreeMap::new(),
            limit,
            truncated: false,
        }
    }

    /// The configured byte limit.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes currently reserved for records.
    pub fn used(&self) -> usize {
        self.frames
            .capacity()
            .saturating_mul(size_of::<FrameAnnotation>())
            .saturating_add(self.http2_bytes())
    }

    /// Bytes charged for the HTTP/2 links.
    fn http2_bytes(&self) -> usize {
        self.http2.len().saturating_mul(HTTP2_LINK_CHARGE)
    }

    /// Number of frames with a reserved record.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame has a record yet.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Whether a record was refused for lack of budget.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Report truncation once; later calls return `false`.
    pub fn take_truncated(&mut self) -> bool {
        std::mem::take(&mut self.truncated)
    }

    /// Borrow the record for a one-based file frame number.
    pub fn get(&self, frame: u64) -> Option<&FrameAnnotation> {
        let index = usize::try_from(frame.checked_sub(1)?).ok()?;
        self.frames.get(index)
    }

    /// Borrow the record for a frame, reserving it when needed.
    pub fn entry(&mut self, frame: u64) -> Option<&mut FrameAnnotation> {
        let index = usize::try_from(frame.checked_sub(1)?).ok()?;
        if !self.ensure(index) {
            return None;
        }
        self.frames.get_mut(index)
    }

    /// Record that a response answers an earlier request after `time_ns`.
    pub fn link_response(&mut self, response: u64, request: u64, time_ns: i64) -> bool {
        self.entry(response).is_some_and(|record| {
            record.request_in = u32::try_from(request).unwrap_or(u32::MAX);
            record.time_ns = time_ns;
            record.flags |= FrameAnnotation::TIME_PRESENT;
            true
        })
    }

    /// Record that `response` answers `request`.
    ///
    /// Both records get the link: the request points forward at its
    /// response and the response keeps the frame that asked, so the output
    /// pass prints `request_in` even when no delay could be measured. The
    /// delay itself is recorded only by [`Self::link_response`], and an
    /// existing response link is kept: a retransmitted query must not
    /// replace the request its response actually answered.
    ///
    /// Returns whether both records were reserved.
    pub fn link_response_in(&mut self, request: u64, response: u64) -> bool {
        let request_link = self.entry(request).is_some_and(|record| {
            record.response_in = u32::try_from(response).unwrap_or(u32::MAX);
            true
        });
        let response_link = self.entry(response).is_some_and(|record| {
            if record.request_in == 0 {
                record.request_in = u32::try_from(request).unwrap_or(u32::MAX);
            }
            true
        });
        request_link && response_link
    }

    /// Record that a query was never answered.
    pub fn mark_response_missing(&mut self, frame: u64) -> bool {
        self.entry(frame).is_some_and(|record| {
            record.flags |= FrameAnnotation::RESPONSE_MISSING;
            true
        })
    }

    /// Record that a TCP PDU this frame belongs to completes at `completing`.
    pub fn link_tcp_reassembled(&mut self, frame: u64, completing: u64) -> bool {
        self.entry(frame)
            .is_some_and(|record| set_link(&mut record.tcp_reassembled_in, completing))
    }

    /// Record that an IPv4 datagram this fragment belongs to completes later.
    pub fn link_ip_reassembled(&mut self, frame: u64, completing: u64) -> bool {
        self.entry(frame)
            .is_some_and(|record| set_link(&mut record.ip_reassembled_in, completing))
    }

    /// Record that an IPv6 datagram this fragment belongs to completes later.
    pub fn link_ipv6_reassembled(&mut self, frame: u64, completing: u64) -> bool {
        self.entry(frame)
            .is_some_and(|record| set_link(&mut record.ipv6_reassembled_in, completing))
    }

    /// Record that a TLS record this frame started completes later.
    pub fn link_tls_reassembled(&mut self, frame: u64, completing: u64) -> bool {
        self.entry(frame)
            .is_some_and(|record| set_link(&mut record.tls_reassembled_in, completing))
    }

    /// Record that a TLS handshake message this frame started completes later.
    pub fn link_tls_handshake_reassembled(&mut self, frame: u64, completing: u64) -> bool {
        self.entry(frame)
            .is_some_and(|record| set_link(&mut record.tls_handshake_reassembled_in, completing))
    }

    /// Record that the HTTP/2 response on `stream` in frame `response`
    /// answers the request the same stream carried in frame `request`,
    /// `time_ns` later when the delay was measured.
    ///
    /// The response keeps its request and delay; the request points at the
    /// latest response, so a final response replaces an interim 1xx one.
    /// Returns whether both links were reserved.
    pub fn link_http2_response(
        &mut self,
        request: u64,
        response: u64,
        stream: u32,
        time_ns: Option<i64>,
    ) -> bool {
        let request_link = self
            .http2_entry(request, stream)
            .is_some_and(|links| set_link(&mut links.response_in, response));
        let response_link = self.http2_entry(response, stream).is_some_and(|links| {
            links.time_ns = time_ns;
            set_link(&mut links.request_in, request)
        });
        request_link && response_link
    }

    /// Record that the HTTP/2 body `stream` carried in `frame` completes in
    /// `completing`.
    pub fn link_http2_body_reassembled(
        &mut self,
        frame: u64,
        stream: u32,
        completing: u64,
    ) -> bool {
        self.http2_entry(frame, stream)
            .is_some_and(|links| set_link(&mut links.body_reassembled_in, completing))
    }

    /// The HTTP/2 links one stream carries in one capture frame.
    pub fn http2_links(&self, frame: u64, stream: u32) -> Option<&Http2Links> {
        self.http2.get(&(u32::try_from(frame).ok()?, stream))
    }

    /// Borrow one stream's HTTP/2 links in a frame, reserving them when the
    /// budget allows.
    fn http2_entry(&mut self, frame: u64, stream: u32) -> Option<&mut Http2Links> {
        let key = (u32::try_from(frame).ok()?, stream);
        let fits = self.used().saturating_add(HTTP2_LINK_CHARGE) <= self.limit;
        match self.http2.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => Some(entry.into_mut()),
            std::collections::btree_map::Entry::Vacant(entry) if fits => {
                Some(entry.insert(Http2Links::default()))
            }
            std::collections::btree_map::Entry::Vacant(_) => {
                self.truncated = true;
                None
            }
        }
    }

    /// Record the conversation's final TLS version label for one frame.
    pub fn set_tls_version(&mut self, frame: u64, version: u16) -> bool {
        self.entry(frame).is_some_and(|record| {
            record.tls_version = version;
            true
        })
    }

    fn ensure(&mut self, index: usize) -> bool {
        let needed = index.saturating_add(1);
        if needed <= self.frames.len() {
            return true;
        }
        // The HTTP/2 links share the budget with the per-frame records.
        let available = self.limit.saturating_sub(self.http2_bytes());
        if available < size_of::<FrameAnnotation>() {
            self.truncated = true;
            return false;
        }
        let max_entries = available / size_of::<FrameAnnotation>();
        if needed > max_entries {
            self.truncated = true;
            return false;
        }
        if needed > self.frames.capacity() {
            let target = needed
                .max(self.frames.capacity().saturating_add(GROWTH_CHUNK))
                .min(max_entries);
            let additional = target.saturating_sub(self.frames.len());
            if self.frames.try_reserve_exact(additional).is_err() {
                self.truncated = true;
                return false;
            }
        }
        self.frames.resize(needed, FrameAnnotation::default());
        true
    }
}

/// Map a file frame number to the number pass two displays.
///
/// Frames that pass the read filter are numbered consecutively, so a
/// reference to a frame the filter did not accept still takes the position
/// it would have had (`1 + accepted frames before it`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RenumberMap {
    accepted: Vec<u32>,
}

impl RenumberMap {
    /// Build a map from sorted, deduplicated file frame numbers.
    ///
    /// Pass one already produces them in order; the two-pass driver uses this
    /// to keep the selection without a second copy.
    pub fn from_sorted(accepted: Vec<u32>) -> Self {
        Self { accepted }
    }

    /// Build a map from the file frame numbers pass one accepted.
    pub fn new(accepted: impl IntoIterator<Item = u64>) -> Self {
        let mut numbers: Vec<u32> = accepted
            .into_iter()
            .map(|number| u32::try_from(number).unwrap_or(u32::MAX))
            .collect();
        numbers.sort_unstable();
        numbers.dedup();
        Self { accepted: numbers }
    }

    /// The displayed number for a one-based file frame number.
    pub fn output(&self, file_frame: u32) -> u32 {
        let before = self.accepted.partition_point(|number| *number < file_frame);
        u32::try_from(before).unwrap_or(u32::MAX).saturating_add(1)
    }

    /// File frame numbers pass one accepted, in order.
    pub fn accepted(&self) -> &[u32] {
        &self.accepted
    }
}

/// Append every cross-pass link the file frame `file` carries.
///
/// DNS and HTTP links land at fixed positions inside their protocol nodes;
/// reassembly links name the frame that completed the PDU.
pub fn apply_annotations(
    packet: &mut Packet,
    annotations: &AnnotationStore,
    file: u64,
    renumber: &RenumberMap,
) {
    // HTTP/2 links are kept per stream, so a frame without a record of its
    // own can still carry them.
    apply_http2_annotations(packet, annotations, file, renumber);
    let Some(annotation) = annotations.get(file) else {
        return;
    };
    apply_dns_annotations(packet, annotation, renumber);
    apply_snmp_annotations(packet, annotation, renumber);
    apply_http_annotations(packet, annotation, renumber);
    if annotation.tcp_reassembled_in != 0 {
        // A segment whose PDU ends later is presented as plain TCP when the
        // segment did not already yield an upper-layer protocol; the
        // partial Info is dropped and only the reassembly suffix remains.
        // A complete HTTP message carried before the split tail keeps its
        // node and Info column.
        let has_upper = has_genuine_upper(&packet.tree.frame);
        if !has_upper {
            if let Some(tcp) = find_protocol_node_mut(&mut packet.tree.frame, "tcp") {
                tcp.children.clear();
            }
            if let Some(position) = packet
                .protocol_stack
                .iter()
                .position(|protocol| *protocol == "tcp")
            {
                packet.protocol_stack.truncate(position.saturating_add(1));
            }
            packet.columns.protocol = Some("TCP".to_string());
            packet.columns.info = Some(format!(
                "[TCP PDU reassembled in {}]",
                renumber.output(annotation.tcp_reassembled_in)
            ));
        }
    }
    apply_tcp_annotation(packet, annotation, renumber);
    apply_ip_annotation(packet, renumber, "ip", annotation.ip_reassembled_in);
    apply_ip_annotation(packet, renumber, "ipv6", annotation.ipv6_reassembled_in);
    if annotation.ip_reassembled_in != 0 {
        append_column_info(
            packet,
            format!(
                "[Reassembled in #{}]",
                renumber.output(annotation.ip_reassembled_in)
            ),
        );
    }
    apply_tls_annotations(packet, annotation, renumber);
}

/// Add SNMP request/response links to the frame's SNMP node.
fn apply_snmp_annotations(
    packet: &mut Packet,
    annotation: &FrameAnnotation,
    renumber: &RenumberMap,
) {
    let Some(node) = find_protocol_node_mut(&mut packet.tree.frame, "snmp") else {
        return;
    };
    let response = node.fields.iter().any(|field| {
        matches!(
            field.def.abbrev,
            "snmp.get_response_element" | "snmp.report_element"
        )
    });
    let base = node
        .fields
        .iter()
        .find(|field| field.def.abbrev == "snmp.data")
        .map_or(node.range.offset, |field| field.range.offset);
    if response {
        if annotation.request_in != 0 {
            node.add_field(
                &fields::SNMP_RESPONSE_TO,
                Range::new(base, 0),
                Value::Uint32(renumber.output(annotation.request_in)),
            );
        }
        if annotation.time_present() {
            node.add_field(
                &fields::SNMP_TIME,
                Range::new(base, 0),
                Value::RelativeTime(annotation.time_ns),
            );
        }
    } else if annotation.response_in != 0 {
        node.add_field(
            &fields::SNMP_RESPONSE_IN,
            Range::new(base, 0),
            Value::Uint32(renumber.output(annotation.response_in)),
        );
    }
}

/// Add HTTP request/response links to every HTTP message in the frame.
fn apply_http_annotations(
    packet: &mut Packet,
    annotation: &FrameAnnotation,
    renumber: &RenumberMap,
) {
    for_each_protocol_mut(&mut packet.tree.frame, "http", &mut |node| {
        let response = node
            .fields
            .iter()
            .any(|field| field.def.abbrev == "http.response");
        let request = node
            .fields
            .iter()
            .any(|field| field.def.abbrev == "http.request");
        let index = http_link_index(node);
        let base = node.range.offset;
        if response {
            if annotation.request_in != 0 {
                node.insert_field(
                    index,
                    &fields::HTTP_REQUEST_IN,
                    Range::new(base, 0),
                    Value::Uint32(renumber.output(annotation.request_in)),
                );
            }
        } else if request && annotation.response_in != 0 {
            node.insert_field(
                index,
                &fields::HTTP_RESPONSE_IN,
                Range::new(base, 0),
                Value::Uint32(renumber.output(annotation.response_in)),
            );
        }
        if response && annotation.time_present() {
            let index = index.saturating_add(usize::from(annotation.request_in != 0));
            node.insert_field(
                index,
                &fields::HTTP_TIME,
                Range::new(base, 0),
                Value::RelativeTime(annotation.time_ns),
            );
        }
    });
}

/// Whether a container or any of its descendants carries a field.
///
/// A curated header field sits inside its `http2.header` container, so the
/// role check has to look one level deeper than the stream container's
/// direct children.
fn field_in_container(field: &Field, abbrev: &str) -> bool {
    field.def.abbrev == abbrev
        || field
            .children
            .iter()
            .any(|child| field_in_container(child, abbrev))
}

/// Whether a stream container carries the fragment of a HEADERS or
/// PUSH_PROMISE frame, the only frames that open a header block.
fn opens_header_block(stream: &Field) -> bool {
    stream.children.iter().any(|field| {
        matches!(
            field.def.abbrev,
            "http2.headers" | "http2.push_promise.header"
        )
    })
}

/// A 32-bit field directly inside a stream container.
fn stream_number(stream: &Field, abbrev: &str) -> Option<u32> {
    stream
        .children
        .iter()
        .find(|field| field.def.abbrev == abbrev)
        .and_then(|field| match field.value {
            Value::Uint32(number) => Some(number),
            _ => None,
        })
}

/// The stream a frame's request is recorded on: the promised stream for a
/// PUSH_PROMISE (RFC 9113 section 6.6), else the frame's own stream.
fn request_stream(stream: &Field) -> Option<u32> {
    stream_number(stream, "http2.push_promise.promised_stream_id")
        .or_else(|| stream_number(stream, "http2.streamid"))
}

/// Add HTTP/2 request/response links and the body reassembly link.
///
/// The links live inside the frame's `http2.stream` container, before the
/// generated request URI and before the DATA field, which is the position the
/// reference prints them in. A capture frame can carry frames of several
/// streams, so each node reads the links recorded for its own stream.
///
/// A request is recorded against the capture frame whose HEADERS or
/// PUSH_PROMISE opened its header block (RFC 9113 section 6.10), never
/// against the CONTINUATION that ends it, although that frame shows the
/// method. One capture frame travels in one direction, so every header
/// block it opens on that stream (the request's and any trailers') is on the
/// request side and takes the forward link; a CONTINUATION or DATA frame
/// does not.
fn apply_http2_annotations(
    packet: &mut Packet,
    annotations: &AnnotationStore,
    file: u64,
    renumber: &RenumberMap,
) {
    for_each_protocol_mut(&mut packet.tree.frame, "http2", &mut |node| {
        let Some(stream) = node
            .fields
            .iter_mut()
            .find(|field| field.def.abbrev == "http2.stream")
        else {
            return;
        };
        let Some(id) = stream_number(stream, "http2.streamid") else {
            return;
        };
        let request_id = request_stream(stream).unwrap_or(id);
        let response = field_in_container(stream, "http2.headers.status");
        let request = opens_header_block(stream);
        let links = annotations
            .http2_links(file, id)
            .copied()
            .unwrap_or_default();
        let uri_index = stream
            .children
            .iter()
            .position(|field| field.def.abbrev == "http2.request.full_uri")
            .unwrap_or(stream.children.len());
        let response_in = annotations
            .http2_links(file, request_id)
            .map_or(0, |forward| forward.response_in);
        if response && links.request_in != 0 {
            stream.insert_field(
                uri_index,
                &fields::HTTP2_REQUEST_IN,
                Range::new(0, 0),
                Value::Uint32(renumber.output(links.request_in)),
            );
            if let Some(time_ns) = links.time_ns {
                stream.insert_field(
                    uri_index,
                    &fields::HTTP2_TIME,
                    Range::new(0, 0),
                    Value::RelativeTime(time_ns),
                );
            }
        } else if request && response_in != 0 {
            stream.insert_field(
                uri_index,
                &fields::HTTP2_RESPONSE_IN,
                Range::new(0, 0),
                Value::Uint32(renumber.output(response_in)),
            );
        }
        if links.body_reassembled_in != 0
            && let Some(data_index) = stream
                .children
                .iter()
                .position(|field| field.def.abbrev == "http2.data.data")
        {
            stream.insert_field(
                data_index,
                &fields::HTTP2_BODY_REASSEMBLED_IN,
                Range::new(0, 0),
                Value::Uint32(renumber.output(links.body_reassembled_in)),
            );
        }
    });
}

/// Where a response link or response timing goes in an HTTP message.
///
/// Both precede the generated request URI fields and the body.
fn http_link_index(node: &Node) -> usize {
    node.fields
        .iter()
        .position(|field| {
            matches!(
                field.def.abbrev,
                "http.request.uri"
                    | "http.request.full_uri"
                    | "http.file_data"
                    | "http.chunked_trailer_part"
                    | "http.chunk_boundary"
                    | "http.chunk_size"
                    | "http.chunk_data"
            )
        })
        .unwrap_or(node.fields.len())
}

/// Add `tcp.reassembled_in` before segment data on the TCP node.
fn apply_tcp_annotation(packet: &mut Packet, annotation: &FrameAnnotation, renumber: &RenumberMap) {
    if annotation.tcp_reassembled_in == 0 {
        return;
    }
    let Some(node) = find_protocol_node_mut(&mut packet.tree.frame, "tcp") else {
        return;
    };
    let index = node
        .fields
        .iter()
        .position(|field| {
            matches!(
                field.def.abbrev,
                "tcp.segment_data" | "tcp.segments" | "tcp.pdu.size"
            )
        })
        .unwrap_or(node.fields.len());
    let base = node.range.offset;
    node.insert_field(
        index,
        &fields::TCP_REASSEMBLED_IN,
        Range::new(base, 0),
        Value::Uint32(renumber.output(annotation.tcp_reassembled_in)),
    );
}

/// Add an IP fragment link at the end of the IP node's fields.
fn apply_ip_annotation(packet: &mut Packet, renumber: &RenumberMap, protocol: &str, frame: u32) {
    if frame == 0 {
        return;
    }
    let Some(node) = find_last_protocol_node_mut(&mut packet.tree.frame, protocol) else {
        return;
    };
    let def = if protocol == "ipv6" {
        &fields::IPV6_REASSEMBLED_IN
    } else {
        &fields::IP_REASSEMBLED_IN
    };
    let offset = if protocol == "ipv6" {
        node.children
            .first()
            .map_or(node.range.offset, |child| child.range.offset)
    } else {
        node.range.offset
    };
    node.add_field(
        def,
        Range::new(offset, 0),
        Value::Uint32(renumber.output(frame)),
    );
}

/// Add TLS record and handshake links to the TLS node.
fn apply_tls_annotations(
    packet: &mut Packet,
    annotation: &FrameAnnotation,
    renumber: &RenumberMap,
) {
    let record = annotation.tls_reassembled_in;
    let handshake = annotation.tls_handshake_reassembled_in;
    if record == 0 && handshake == 0 {
        return;
    }
    let Some(node) = find_protocol_node_mut(&mut packet.tree.frame, "tls") else {
        return;
    };
    if record != 0 {
        let index = node
            .fields
            .iter()
            .position(|field| field.def.abbrev == "tls.segment_data")
            .unwrap_or(node.fields.len());
        node.insert_field(
            index,
            &fields::TLS_REASSEMBLED_IN,
            Range::new(0, 0),
            Value::Uint32(renumber.output(record)),
        );
    }
    if handshake != 0 {
        // The link goes into the record that carried the first fragment,
        // after that record's handshake subtree.
        let fragment_index = node
            .fields
            .iter()
            .position(|field| field_contains(field, "tls.handshake.fragments"));
        let target = fragment_index.and_then(|index| index.checked_sub(1));
        if let Some(record) = target.and_then(|index| node.fields.get_mut(index)) {
            let offset = record.range.offset;
            record.add_field(
                &fields::TLS_HANDSHAKE_REASSEMBLED_IN,
                Range::new(offset, 0),
                Value::Uint32(renumber.output(handshake)),
            );
        } else {
            let offset = node.range.offset;
            node.add_field(
                &fields::TLS_HANDSHAKE_REASSEMBLED_IN,
                Range::new(offset, 0),
                Value::Uint32(renumber.output(handshake)),
            );
        }
    }
}

/// Whether a field or one of its descendants has `abbrev`.
fn field_contains(field: &Field, abbrev: &str) -> bool {
    field.def.abbrev == abbrev
        || field
            .children
            .iter()
            .any(|child| field_contains(child, abbrev))
}

/// Whether the frame carries a completed upper-layer protocol node.
///
/// A frame keeps its HTTP/TLS summary when the segment already held a
/// complete message before the split tail; the minimal TLS segment node that
/// only carries `tls.segment_data` is not such a message. An `http2` node is
/// a decoded HTTP/2 message, so it counts beside `http`.
fn has_genuine_upper(node: &Node) -> bool {
    match node.protocol.filter_name {
        "http" | "http2" | "dns" | "mdns" | "llmnr" | "bgp" => return true,
        "tls"
            if node
                .fields
                .iter()
                .any(|field| field.def.abbrev == "tls.record") =>
        {
            return true;
        }
        _ => {}
    }
    node.children.iter().any(has_genuine_upper)
}

/// Call `visit` for every protocol node named `protocol`, depth first.
fn for_each_protocol_mut(node: &mut Node, protocol: &str, visit: &mut impl FnMut(&mut Node)) {
    if node.protocol.filter_name == protocol {
        visit(node);
    }
    for child in &mut node.children {
        for_each_protocol_mut(child, protocol, visit);
    }
}

fn find_protocol_node_mut<'a>(node: &'a mut Node, protocol: &str) -> Option<&'a mut Node> {
    if node.protocol.filter_name == protocol {
        return Some(node);
    }
    node.children
        .iter_mut()
        .find_map(|child| find_protocol_node_mut(child, protocol))
}

fn find_last_protocol_node_mut<'a>(node: &'a mut Node, protocol: &str) -> Option<&'a mut Node> {
    let mut path = Vec::new();
    let path = last_protocol_path(node, protocol, &mut path)?;
    node_at_path_mut(node, &path)
}

fn last_protocol_path(node: &Node, protocol: &str, path: &mut Vec<usize>) -> Option<Vec<usize>> {
    let mut best = (node.protocol.filter_name == protocol).then(|| path.clone());
    for (index, child) in node.children.iter().enumerate() {
        path.push(index);
        if let Some(found) = last_protocol_path(child, protocol, path) {
            best = Some(found);
        }
        path.pop();
    }
    best
}

fn node_at_path_mut<'a>(node: &'a mut Node, path: &[usize]) -> Option<&'a mut Node> {
    let mut current = node;
    for index in path {
        current = current.children.get_mut(*index)?;
    }
    Some(current)
}

/// Append text to the Info column, keeping any earlier text.
fn append_column_info(packet: &mut Packet, suffix: String) {
    match &mut packet.columns.info {
        Some(info) if !info.is_empty() => {
            info.push(' ');
            info.push_str(&suffix);
        }
        _ => packet.columns.info = Some(suffix),
    }
}

/// Write a one-based link.
fn set_link(slot: &mut u32, completing: u64) -> bool {
    *slot = u32::try_from(completing).unwrap_or(u32::MAX);
    true
}

/// Append the links a two-pass record carries to the DNS node of a packet.
///
/// Returns whether a DNS-family node was present. The fields are added after
/// the decoded message, and expert references use the renumbered frame
/// number.
pub fn apply_dns_annotations(
    packet: &mut Packet,
    annotation: &FrameAnnotation,
    renumber: &RenumberMap,
) -> bool {
    let Some(node) = find_dns_node_mut(&mut packet.tree.frame) else {
        return false;
    };
    let Some(response) = dns_response_bit(node) else {
        return false;
    };
    let base = node.range.offset;
    let retransmission = dns_retransmission(node);
    if response {
        if !retransmission {
            if annotation.request_in != 0 {
                add_request_link(node, base, renumber.output(annotation.request_in));
            }
            if annotation.time_present() {
                add_time(node, base, annotation.time_ns);
            }
        }
    } else {
        if annotation.response_in != 0 && !retransmission {
            add_response_link(node, base, renumber.output(annotation.response_in));
        }
        if annotation.response_missing() && !retransmission {
            add_response_missing(node, base);
        }
    }
    true
}

/// Add the `[Response In: N]` link to a query node.
pub(crate) fn add_response_link(node: &mut Node, base: usize, display_frame: u32) {
    node.add_field(
        &fields::DNS_RESPONSE_IN,
        Range::new(base, 0),
        Value::Uint32(display_frame),
    );
}

/// Add the `[Request In: N]` link to a response node.
pub(crate) fn add_request_link(node: &mut Node, base: usize, display_frame: u32) {
    node.add_field(
        &fields::DNS_RESPONSE_TO,
        Range::new(base, 0),
        Value::Uint32(display_frame),
    );
}

/// Add the `[Time: ...]` request-to-response delay.
pub(crate) fn add_time(node: &mut Node, base: usize, time_ns: i64) {
    node.add_field(
        &fields::DNS_TIME,
        Range::new(base, 0),
        Value::RelativeTime(time_ns),
    );
}

/// Add the retransmission link, flag and expert entry for one DNS message.
pub(crate) fn add_retransmission(node: &mut Node, base: usize, response: bool, display_frame: u32) {
    let (link, label, message) = if response {
        (
            &fields::DNS_RETRANSMIT_RESPONSE_IN,
            &fields::DNS_RETRANSMIT_RESPONSE,
            format!("DNS response retransmission. Original response in frame {display_frame}"),
        )
    } else {
        (
            &fields::DNS_RETRANSMIT_REQUEST_IN,
            &fields::DNS_RETRANSMIT_REQUEST,
            format!("DNS query retransmission. Original request in frame {display_frame}"),
        )
    };
    node.add_field(link, Range::new(base, 0), Value::Uint32(display_frame));
    node.add_field(
        &fields::DNS_RETRANSMISSION,
        Range::new(base, 0),
        Value::Boolean(true),
    );
    // The expert's own field is also a tree occurrence: `-T fields` and
    // filters see it, while the full-tree formats render it only inside the
    // expert block.
    node.add_field(label, Range::new(0, 0), Value::None);
    add_expert_label(node, label, message);
}

/// Add the `dns.response_missing` expert entry for an unanswered query.
pub(crate) fn add_response_missing(node: &mut Node, base: usize) {
    node.add_field(
        &fields::DNS_RESPONSE_MISSING,
        Range::new(base, 0),
        Value::None,
    );
    add_expert_label(
        node,
        &fields::DNS_RESPONSE_MISSING,
        "DNS response missing".to_string(),
    );
}

/// Attach an expert to the transaction-id field and name its companion.
///
/// These entries go under `dns.id`; a message too short to carry an
/// id still keeps the direct field, so `-e dns.response_missing` works.
fn add_expert_label(node: &mut Node, label: &'static fields::FieldDef, message: String) {
    let Some(id) = node
        .fields
        .iter_mut()
        .find(|field| field.def.abbrev == "dns.id")
    else {
        return;
    };
    id.add_expert_for(
        ExpertInfo {
            severity: Severity::Warning,
            group: Group::Protocol,
            message,
        },
        label,
    );
}

/// Whether the output pass classified this message as a retransmission.
///
/// The pass-one request links are suppressed on a frame the output pass
/// again treats as a retransmission; the retransmission fields themselves are
/// recomputed live.
fn dns_retransmission(node: &Node) -> bool {
    node.fields.iter().any(|field| {
        field.def.abbrev == "dns.retransmission" && matches!(field.value, Value::Boolean(true))
    })
}

/// The value of `dns.flags.response` on a DNS-family node.
fn dns_response_bit(node: &Node) -> Option<bool> {
    node.fields.iter().find_map(|field| {
        (field.def.abbrev == "dns.flags.response")
            .then_some(matches!(field.value, Value::Boolean(true)))
    })
}

fn find_dns_node_mut(node: &mut Node) -> Option<&mut Node> {
    if matches!(node.protocol.filter_name, "dns" | "mdns" | "llmnr") {
        return Some(node);
    }
    node.children.iter_mut().find_map(find_dns_node_mut)
}

/// Whether a field is only an expert label and never a tree entry.
///
/// Output formats that render experts skip the direct occurrence; `-e` and
/// `-T fields` still see it.
pub fn expert_label_only(abbrev: &str) -> bool {
    matches!(
        abbrev,
        "dns.retransmit_request"
            | "dns.retransmit_response"
            | "dns.response_missing"
            | "ospf.lsa.invalid_length"
            | "ospf.reserved.not_zero"
            | "lldp.tlv_deprecated"
            | "lldp.excess_length"
            | "lldp.incorrect_length"
            | "lldp.excess_tlv"
            | "lldp.bad_type"
            | "bfd.auth.len.invalid"
            | "bfd.auth.no_data"
            | "vrrp.checksum_bad.expert"
    )
}

/// The field an expert block names as its offending item.
pub fn expert_offending(field: &Field) -> &'static fields::FieldDef {
    field.expert_field.unwrap_or(field.def)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Tree;

    #[test]
    fn growth_stays_within_the_budget_and_reports_overflow_once() {
        let entry = size_of::<FrameAnnotation>();
        let limit = entry.saturating_mul(3).saturating_add(entry / 2);
        let mut store = AnnotationStore::with_budget(limit);
        assert!(store.entry(1).is_some());
        assert!(store.entry(3).is_some());
        assert!(store.used() <= limit, "used {} limit {limit}", store.used());
        assert!(!store.truncated());

        assert!(store.entry(4).is_none());
        assert!(store.used() <= limit);
        assert!(store.truncated());
        assert!(store.take_truncated());
        assert!(!store.take_truncated());
    }

    #[test]
    fn zero_budget_records_nothing() {
        let mut store = AnnotationStore::with_budget(0);
        assert!(store.entry(1).is_none());
        assert!(store.truncated());
        assert!(store.is_empty());
        assert_eq!(store.used(), 0);
    }

    #[test]
    fn links_are_visible_from_both_sides_and_keep_zero_delays() {
        let mut store = AnnotationStore::with_budget(DEFAULT_ANNOTATION_BUDGET);
        assert!(store.link_response(2, 1, 0));
        assert!(store.link_response_in(1, 2));
        assert!(store.get(1).is_some());
        assert!(store.get(2).is_some());
        let request = store.get(1).copied().unwrap_or_default();
        let response = store.get(2).copied().unwrap_or_default();
        assert_eq!(request.response_in, 2);
        assert_eq!(response.request_in, 1);
        assert!(response.time_present());
        assert_eq!(response.time_ns, 0);
    }

    /// Find the first field with `abbrev` inside a node or its containers.
    fn field_named<'a>(node: &'a Node, abbrev: &str) -> Option<&'a Field> {
        fn in_field<'a>(field: &'a Field, abbrev: &str) -> Option<&'a Field> {
            if field.def.abbrev == abbrev {
                return Some(field);
            }
            field
                .children
                .iter()
                .find_map(|child| in_field(child, abbrev))
        }

        node.fields
            .iter()
            .find_map(|field| in_field(field, abbrev))
            .or_else(|| {
                node.children
                    .iter()
                    .find_map(|child| field_named(child, abbrev))
            })
    }

    /// An HTTP/2 packet whose stream 1 carries a response status.
    fn http2_response_packet() -> Packet {
        let mut frame = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 0));
        let mut http2 = Node::new(&fields::HTTP2_PROTOCOL, Range::new(0, 0));
        let stream = http2.add_container(&fields::HTTP2_STREAM, Range::new(0, 0), None);
        stream.add_field(&fields::HTTP2_STREAMID, Range::new(0, 0), Value::Uint32(1));
        stream.add_field(
            &fields::HTTP2_HEADERS_STATUS,
            Range::new(0, 0),
            Value::String("200".to_string()),
        );
        frame.add_child(http2);
        Packet {
            tree: Tree::new(frame),
            columns: crate::decode::Columns::default(),
            protocol_stack: Vec::new(),
            malformed: false,
            network: None,
            forced_data: false,
            resolution: crate::NameResolution::default(),
            data_sources: Vec::new(),
            data_source_kinds: Vec::new(),
        }
    }

    #[test]
    fn a_link_without_a_delay_still_renders_request_in() {
        let mut store = AnnotationStore::with_budget(DEFAULT_ANNOTATION_BUDGET);
        assert!(store.link_response_in(1, 2));
        assert_eq!(store.get(1).copied().unwrap_or_default().response_in, 2);
        let linked = store.get(2).copied().unwrap_or_default();
        assert_eq!(linked.request_in, 1);
        assert!(!linked.time_present());
        assert_eq!(linked.time_ns, 0);

        // A retransmitted query links forward as well, but the response
        // keeps the request it was first matched to.
        assert!(store.link_response_in(3, 2));
        assert_eq!(store.get(2).copied().unwrap_or_default().request_in, 1);

        // The output pass prints an HTTP/2 link without a timing field.
        let renumber = RenumberMap::new([1, 2, 3, 4]);
        assert!(store.link_http2_response(1, 2, 1, None));
        let mut packet = http2_response_packet();
        apply_annotations(&mut packet, &store, 2, &renumber);
        assert_eq!(
            field_named(&packet.tree.frame, "http2.request_in").map(|field| &field.value),
            Some(&Value::Uint32(1))
        );
        assert!(field_named(&packet.tree.frame, "http2.time").is_none());

        // A measured delay keeps both the link and its time.
        assert!(store.link_http2_response(3, 4, 1, Some(1_500_000_000)));
        let timed = store.http2_links(4, 1).copied().unwrap_or_default();
        assert_eq!(timed.request_in, 3);
        assert_eq!(timed.time_ns, Some(1_500_000_000));
        let mut packet = http2_response_packet();
        apply_annotations(&mut packet, &store, 4, &renumber);
        assert_eq!(
            field_named(&packet.tree.frame, "http2.request_in").map(|field| &field.value),
            Some(&Value::Uint32(3))
        );
        assert_eq!(
            field_named(&packet.tree.frame, "http2.time").map(|field| &field.value),
            Some(&Value::RelativeTime(1_500_000_000))
        );
    }

    #[test]
    fn http2_links_share_the_annotation_budget() {
        let limit = HTTP2_LINK_CHARGE.saturating_mul(3);
        let mut store = AnnotationStore::with_budget(limit);
        for stream in [1, 3, 5] {
            assert!(store.link_http2_body_reassembled(1, stream, 2));
        }
        assert!(store.used() <= limit, "used {} limit {limit}", store.used());
        assert!(!store.truncated());
        // An existing link is updated in place; a new one is refused.
        assert!(store.link_http2_body_reassembled(1, 3, 4));
        assert!(!store.link_http2_body_reassembled(1, 7, 2));
        assert!(store.truncated());
        assert!(store.used() <= limit);
        assert!(
            store.entry(1).is_none(),
            "the links left no room for a record"
        );
        assert_eq!(
            store
                .http2_links(1, 3)
                .map(|links| links.body_reassembled_in),
            Some(4)
        );
        assert!(store.http2_links(1, 7).is_none());
    }

    #[test]
    fn reassembly_links_are_stored_per_direction() {
        let mut store = AnnotationStore::with_budget(DEFAULT_ANNOTATION_BUDGET);
        assert!(store.link_tcp_reassembled(1, 4));
        assert!(store.link_ip_reassembled(2, 5));
        assert!(store.link_ipv6_reassembled(3, 6));
        assert!(store.link_tls_reassembled(4, 7));
        assert!(store.link_tls_handshake_reassembled(5, 8));
        let first = store.get(1).copied().unwrap_or_default();
        assert_eq!(first.tcp_reassembled_in, 4);
        assert_eq!(
            store.get(2).copied().unwrap_or_default().ip_reassembled_in,
            5
        );
        assert_eq!(
            store
                .get(3)
                .copied()
                .unwrap_or_default()
                .ipv6_reassembled_in,
            6
        );
        assert_eq!(
            store.get(4).copied().unwrap_or_default().tls_reassembled_in,
            7
        );
        assert_eq!(
            store
                .get(5)
                .copied()
                .unwrap_or_default()
                .tls_handshake_reassembled_in,
            8
        );
    }

    #[test]
    fn renumbering_counts_only_accepted_frames_before_the_reference() {
        let map = RenumberMap::new([2, 4]);
        assert_eq!(map.output(1), 1);
        assert_eq!(map.output(2), 1);
        assert_eq!(map.output(3), 2);
        assert_eq!(map.output(4), 2);
        assert_eq!(map.output(5), 3);
    }

    #[test]
    fn a_decoded_http2_node_counts_as_a_completed_upper_layer() {
        // A frame whose only upper node is HTTP/2 keeps its HTTP/2 summary
        // instead of being folded back into plain TCP.
        let mut frame = Node::new(&crate::fields::FRAME_PROTOCOL, Range::new(0, 0));
        let mut tcp = Node::new(&crate::fields::TCP_PROTOCOL, Range::new(0, 0));
        tcp.add_child(Node::new(&crate::fields::HTTP2_PROTOCOL, Range::new(0, 0)));
        frame.add_child(tcp);
        assert!(has_genuine_upper(&frame));
    }
}
