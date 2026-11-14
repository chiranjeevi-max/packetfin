//! Hypertext Transfer Protocol version 2 (RFC 9113) with HPACK (RFC 7541).
//!
//! Each frame is one protocol node under a `http2.stream` container whose
//! label is the frame summary the summary column abbreviates. Header blocks
//! are decompressed by [`hpack`] against the direction's dynamic table; a
//! block that spans HEADERS and CONTINUATION frames is buffered and decoded
//! once, when END_HEADERS arrives, and the decoded list is attached to that
//! completing frame (RFC 7541 section 2.2 makes a header block one unit).
//!
//! The decoder never trusts a declared length: the frame payload is sliced
//! only when the whole frame is present, the SETTINGS pair list is a multiple
//! of six, and every header, string and body is bounded by the caps in
//! [`hpack`] and [`crate::state`]. A frame that cannot be decoded keeps the
//! header fields it already produced and gains one expert item.

pub(crate) mod hpack;
mod hpack_tables;

use crate::decode::DecodeContext;
use crate::fields::{self, FieldDef};
use crate::state::{
    BlockFragment, BlockOrigin, BlockStart, BodyFragmentView, DataOutcome, Http2Data, Http2Key,
};
use crate::tree::{
    Bytes, ExpertInfo, Field, Group, Node, Range, RawField, RawSource, Severity, Value,
};

/// The client connection preface (RFC 9113 section 3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Every frame starts with a nine-octet header (RFC 9113 section 4.1).
const FRAME_HEADER_BYTES: usize = 9;

/// The largest payload the 24-bit length field can express.
const MAX_FRAME_PAYLOAD: usize = 0x00ff_ffff;

/// The default SETTINGS_MAX_FRAME_SIZE (RFC 9113 section 6.5.2).
pub(crate) const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest SETTINGS_MAX_FRAME_SIZE a peer may announce (RFC 9113 6.5.2).
pub(crate) const MAX_MAX_FRAME_SIZE: u32 = 0x00ff_ffff;

/// SETTINGS records or ORIGIN entries one frame adds to the tree at most.
///
/// A frame payload can reach 16 MiB, so an uncapped list would create
/// millions of containers; the bound matches the stream and fragment caps.
const MAX_FRAME_RECORDS: usize = 256;

/// Frames one payload may add to the tree.
///
/// The stream framer emits one frame per PDU and bounds its per-insert
/// actions to the same value, but a forced, decrypted or quoted payload can
/// reach this loop whole. One node per frame would then grow without bound,
/// so the loop stops at the bound and reports the frames it did not decode.
pub(crate) const MAX_FRAMES_PER_PAYLOAD: usize = 384;

/// DATA frame type.
const DATA: u8 = 0;
/// HEADERS frame type.
const HEADERS: u8 = 1;
/// PRIORITY frame type.
const PRIORITY: u8 = 2;
/// RST_STREAM frame type.
const RST_STREAM: u8 = 3;
/// SETTINGS frame type.
const SETTINGS: u8 = 4;
/// PUSH_PROMISE frame type.
const PUSH_PROMISE: u8 = 5;
/// PING frame type.
const PING: u8 = 6;
/// GOAWAY frame type.
const GOAWAY: u8 = 7;
/// WINDOW_UPDATE frame type.
const WINDOW_UPDATE: u8 = 8;
/// CONTINUATION frame type.
const CONTINUATION: u8 = 9;
/// ALTSVC frame type (RFC 7838).
const ALTSVC: u8 = 10;
/// ORIGIN frame type (RFC 8336).
const ORIGIN: u8 = 12;
/// PRIORITY_UPDATE frame type (RFC 9218).
const PRIORITY_UPDATE: u8 = 16;

/// END_STREAM flag (RFC 9113 section 6.1).
const FLAG_END_STREAM: u8 = 0x01;
/// END_HEADERS flag (RFC 9113 section 6.2).
pub(crate) const FLAG_END_HEADERS: u8 = 0x04;
/// PADDED flag (RFC 9113 section 6.1).
const FLAG_PADDED: u8 = 0x08;
/// PRIORITY flag on a HEADERS frame (RFC 9113 section 6.2).
const FLAG_PRIORITY: u8 = 0x20;
/// ACK flag on SETTINGS and PING (RFC 9113 sections 6.5 and 6.7).
const FLAG_ACK: u8 = 0x01;

/// Whether `data` starts with the connection preface or a prefix of it.
///
/// The heuristic needs four octets before it claims the flow: `PRI ` cannot
/// begin an HTTP/1.x start line whose method is followed by a space, so a
/// short segment of another protocol is not captured by mistake. A preface
/// split before its fourth octet stays TCP; the reassembly layer needs the
/// upper protocol before it can buffer.
pub(crate) fn looks_like_http2_prefix(data: &[u8]) -> bool {
    if data.starts_with(PREFACE) {
        return true;
    }
    data.len() >= 4 && data.len() < PREFACE.len() && PREFACE.starts_with(data)
}

/// Whether `data` begins with a plausible HTTP/2 frame header.
///
/// A server's first decrypted record is a SETTINGS frame with no preface of
/// its own (RFC 9113 section 3.4), so a key log without the ALPN selection
/// otherwise leaves the direction unidentified. The check is conservative:
/// the nine header octets must be present, the type must be one this module
/// knows, connection frames must name stream 0 and stream frames must name
/// another (section 6), and a SETTINGS payload must be whole six-octet
/// settings (section 6.5).
pub(crate) fn looks_like_frame_header(data: &[u8]) -> bool {
    if data.len() < FRAME_HEADER_BYTES {
        return false;
    }
    let Some(frame) = Frame::parse(data) else {
        return false;
    };
    if frame.length > u32::try_from(MAX_FRAME_PAYLOAD).unwrap_or(u32::MAX) {
        return false;
    }
    if frame_type_name(frame.kind).is_none() {
        return false;
    }
    let connection_frame = matches!(frame.kind, SETTINGS | PING | GOAWAY);
    let stream_frame = matches!(
        frame.kind,
        DATA | HEADERS | PRIORITY | RST_STREAM | PUSH_PROMISE | CONTINUATION
    );
    if (connection_frame && frame.stream_id != 0) || (stream_frame && frame.stream_id == 0) {
        return false;
    }
    frame.kind != SETTINGS || frame.length % 6 == 0
}

/// Whether `data` is a prefix of the connection preface.
///
/// The stream framer uses this to keep buffering a split preface; unlike the
/// dispatch heuristic it accepts a one-octet prefix, because the direction is
/// already known to be HTTP/2.
pub(crate) fn preface_prefix(data: &[u8]) -> bool {
    PREFACE.starts_with(data)
}

/// The preface length the framer emits as one PDU.
pub(crate) const PREFACE_BYTES: usize = PREFACE.len();

/// The largest complete frame the reassembly layer buffers.
pub(crate) const MAX_FRAME_BYTES: usize = FRAME_HEADER_BYTES + MAX_FRAME_PAYLOAD;

/// Decode every HTTP/2 frame in the bytes handed over by TCP.
///
/// The stream layer hands over one frame (or the preface) per call; a forced
/// `-d tcp.port==N,http2` entry hands over the whole payload, which may hold
/// several frames. Both shapes are framed here.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    if context.depth >= crate::decode::MAX_DECODE_DEPTH {
        context.mark_truncation(parent, "Decoding depth limit reached");
        return;
    }
    context.depth = context.depth.saturating_add(1);
    if context.protocol_stack.last() != Some(&fields::HTTP2_PROTOCOL.filter_name) {
        context
            .protocol_stack
            .push(fields::HTTP_PROTOCOL.filter_name);
        context
            .protocol_stack
            .push(fields::HTTP2_PROTOCOL.filter_name);
    }
    context.columns.protocol = Some("HTTP2".to_string());

    let key = state_key(context);
    let mut offset = 0_usize;
    let mut info = String::new();
    let mut decoded = false;
    let mut frames = 0_usize;
    if let Some(rest) = data.strip_prefix(PREFACE) {
        add_magic(parent, base);
        if let Some(key) = key {
            context.state.http2_mark(key);
        }
        decoded = true;
        info.push_str("Magic");
        offset = PREFACE.len();
        let _ = rest;
    }
    while offset < data.len() {
        if frames >= MAX_FRAMES_PER_PAYLOAD {
            // Every frame is a node, so a payload handed over whole must not
            // turn an uncapped frame list into unbounded tree growth. The
            // skipped frames are not decoded, so their HPACK mutations are
            // unknown (RFC 7541 section 2.2).
            parent.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Undecoded,
                message: format!(
                    "HTTP/2 payload exceeds {MAX_FRAMES_PER_PAYLOAD} frames; \
                     the remaining frames were not decoded"
                ),
            });
            if let Some(key) = key {
                context.state.http2_mark_table_lost(key);
                // Skipped DATA frames may have carried body bytes, so no
                // later END_STREAM may present the visible fragments as a
                // contiguous body.
                context.state.http2_abandon_bodies(key);
            }
            break;
        }
        let remaining = data.get(offset..).unwrap_or_default();
        let Some(frame) = Frame::parse(remaining) else {
            // Fewer than nine header octets remain. The frames already
            // decoded stay, and the fragment gets its own node so the
            // truncation is reported where it was found.
            add_truncated_header(context, parent, remaining, base.saturating_add(offset));
            break;
        };
        let frame_base = base.saturating_add(offset);
        let complete = frame.payload.len() == usize::try_from(frame.length).unwrap_or(usize::MAX);
        let payload = frame.payload;
        let summary = add_frame(context, parent, &frame, frame_base, key);
        frames = frames.saturating_add(1);
        if !summary.is_empty() {
            if !info.is_empty() {
                info.push_str(", ");
            }
            info.push_str(&summary);
        }
        decoded = true;
        offset = offset
            .saturating_add(FRAME_HEADER_BYTES)
            .saturating_add(payload.len());
        if !complete {
            // The header declared more bytes than the capture holds; the
            // header fields stay and one expert explains the truncation.
            if let Some(node) = parent.children.last_mut() {
                context.mark_malformed(node, "HTTP/2 frame is truncated");
            }
            break;
        }
    }
    if decoded {
        context.columns.info = Some(info);
    }
    context.depth = context.depth.saturating_sub(1);
}

/// Mark the packet malformed and attach the expert to a container field.
///
/// A header block or SETTINGS list that cannot be decoded keeps the fields
/// already added and reports the problem where it was found.
fn field_malformed(context: &mut DecodeContext<'_>, field: &mut Field, message: &'static str) {
    if context.quoted {
        return;
    }
    *context.malformed = true;
    field.add_expert(ExpertInfo {
        severity: Severity::Error,
        group: Group::Malformed,
        message: message.to_string(),
    });
}

/// Report a header-block sequencing error where the fragment was found.
///
/// RFC 9113 section 6.10 makes a header block uninterruptible: a frame that
/// breaks the sequence is a connection error, and the fragment it carried is
/// not decoded into the directional table.
fn block_protocol_expert(stream: &mut Field, message: &'static str) {
    stream.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Protocol,
        message: message.to_string(),
    });
}

/// The conversation and direction this frame belongs to.
fn state_key(context: &DecodeContext<'_>) -> Option<Http2Key> {
    if context.quoted {
        return None;
    }
    let (source, destination) = context.transport_ports?;
    let (conversation, direction) = context.conversation_key(source, destination)?;
    Some(Http2Key {
        conversation,
        direction: u8::try_from(direction).unwrap_or(0),
    })
}

/// The frame reference a header block records when it starts.
fn block_origin(context: &DecodeContext<'_>) -> BlockOrigin {
    BlockOrigin {
        frame: u32::try_from(context.frame.number).unwrap_or(u32::MAX),
        file: u32::try_from(context.frame.file_number).unwrap_or(u32::MAX),
        time: context.frame.timestamp,
    }
}

/// One parsed frame header and the payload bytes it declares.
struct Frame<'a> {
    length: u32,
    kind: u8,
    flags: u8,
    stream_id: u32,
    reserved: bool,
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parse the nine-octet header and slice the captured payload.
    fn parse(data: &'a [u8]) -> Option<Self> {
        let length = u32::from(*data.first()?) << 16
            | u32::from(*data.get(1)?) << 8
            | u32::from(*data.get(2)?);
        let kind = *data.get(3)?;
        let flags = *data.get(4)?;
        let word = u32::from_be_bytes([*data.get(5)?, *data.get(6)?, *data.get(7)?, *data.get(8)?]);
        let length_usize = usize::try_from(length).ok()?;
        let end = FRAME_HEADER_BYTES.checked_add(length_usize)?;
        let payload = data
            .get(FRAME_HEADER_BYTES..end.min(data.len()))
            .unwrap_or_default();
        Some(Self {
            length,
            kind,
            flags,
            stream_id: word & 0x7fff_ffff,
            reserved: word & 0x8000_0000 != 0,
            payload,
        })
    }
}

/// The registry name of a frame type.
fn frame_type_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        DATA => "DATA",
        HEADERS => "HEADERS",
        PRIORITY => "PRIORITY",
        RST_STREAM => "RST_STREAM",
        SETTINGS => "SETTINGS",
        PUSH_PROMISE => "PUSH_PROMISE",
        PING => "PING",
        GOAWAY => "GOAWAY",
        WINDOW_UPDATE => "WINDOW_UPDATE",
        CONTINUATION => "CONTINUATION",
        ALTSVC => "ALTSVC",
        ORIGIN => "ORIGIN",
        PRIORITY_UPDATE => "PRIORITY_UPDATE",
        _ => return None,
    })
}

/// Add the preface node and return nothing.
fn add_magic(parent: &mut Node, base: usize) {
    let mut node = Node::new(&fields::HTTP2_PROTOCOL, Range::new(base, PREFACE.len()));
    {
        let stream = node.add_container(
            &fields::HTTP2_STREAM,
            Range::new(base, PREFACE.len()),
            Some("Stream: Magic".to_string()),
        );
        stream.add_field(
            &fields::HTTP2_MAGIC,
            Range::new(base, PREFACE.len()),
            Value::String("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_string()),
        );
    }
    parent.add_child(node);
}

/// One frame's summary suffix for the detail label.
#[derive(Default)]
struct Suffix {
    text: String,
}

/// A rule RFC 9113 makes mandatory before a frame payload means anything.
enum FrameViolation {
    /// The payload is not interpreted; one malformed expert is reported.
    Fatal(&'static str),
    /// The payload still decodes, but a standards expert is reported.
    Protocol(&'static str),
}

/// Check the type-specific length and stream rules of RFC 9113 section 6.
///
/// HEADERS and CONTINUATION on stream zero are protocol errors, but the
/// expected output still decodes their payload, so they only gain an expert.
/// Every other violation stops the payload, keeping the frame header fields
/// already added and reporting one expert.
fn frame_violation(frame: &Frame<'_>) -> Option<FrameViolation> {
    let length = usize::try_from(frame.length).unwrap_or(usize::MAX);
    let on_stream_zero = frame.stream_id == 0;
    match frame.kind {
        DATA => on_stream_zero.then_some(FrameViolation::Fatal("HTTP/2 DATA frame is on stream 0")),
        HEADERS => on_stream_zero.then_some(FrameViolation::Protocol(
            "HTTP/2 HEADERS frame is on stream 0",
        )),
        PRIORITY => {
            if on_stream_zero {
                Some(FrameViolation::Fatal(
                    "HTTP/2 PRIORITY frame is on stream 0",
                ))
            } else if length != 5 {
                Some(FrameViolation::Fatal(
                    "HTTP/2 PRIORITY frame length is not 5",
                ))
            } else {
                None
            }
        }
        RST_STREAM => {
            if on_stream_zero {
                Some(FrameViolation::Fatal(
                    "HTTP/2 RST_STREAM frame is on stream 0",
                ))
            } else if length != 4 {
                Some(FrameViolation::Fatal(
                    "HTTP/2 RST_STREAM frame length is not 4",
                ))
            } else {
                None
            }
        }
        SETTINGS => {
            if !on_stream_zero {
                Some(FrameViolation::Fatal(
                    "HTTP/2 SETTINGS frame is not on stream 0",
                ))
            } else if frame.flags & FLAG_ACK != 0 && length != 0 {
                Some(FrameViolation::Fatal(
                    "HTTP/2 SETTINGS ACK frame carries a payload",
                ))
            } else {
                None
            }
        }
        PUSH_PROMISE => on_stream_zero.then_some(FrameViolation::Fatal(
            "HTTP/2 PUSH_PROMISE frame is on stream 0",
        )),
        PING => {
            // RFC 9113 section 6.7: PING is a connection-level frame, so a
            // stream identifier other than zero is a connection error.
            if !on_stream_zero {
                Some(FrameViolation::Fatal(
                    "HTTP/2 PING frame is not on stream 0",
                ))
            } else if length != 8 {
                Some(FrameViolation::Fatal("HTTP/2 PING frame length is not 8"))
            } else {
                None
            }
        }
        GOAWAY => {
            if !on_stream_zero {
                Some(FrameViolation::Fatal(
                    "HTTP/2 GOAWAY frame is not on stream 0",
                ))
            } else if length < 8 {
                Some(FrameViolation::Fatal(
                    "HTTP/2 GOAWAY frame is shorter than 8 octets",
                ))
            } else {
                None
            }
        }
        WINDOW_UPDATE => (length != 4).then_some(FrameViolation::Fatal(
            "HTTP/2 WINDOW_UPDATE frame length is not 4",
        )),
        CONTINUATION => on_stream_zero.then_some(FrameViolation::Protocol(
            "HTTP/2 CONTINUATION frame is on stream 0",
        )),
        _ => None,
    }
}

/// Add one frame node, returning its summary-column text.
fn add_frame(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
) -> String {
    let type_name = frame_type_name(frame.kind);
    let length = usize::try_from(frame.length).unwrap_or(usize::MAX);
    let full_length = length.min(frame.payload.len());
    let range = Range::new(base, FRAME_HEADER_BYTES.saturating_add(full_length));
    let mut node = Node::new(&fields::HTTP2_PROTOCOL, range);
    let mut suffix = Suffix::default();
    let mut summary = String::new();
    {
        let stream = node.add_container(&fields::HTTP2_STREAM, range, None);
        add_header_fields(&mut *stream, frame, base);
        // RFC 9113 section 6.10 makes a header block uninterruptible: any
        // other frame on the connection ends it as a connection error. The
        // state drops the buffered fragment and marks the dynamic table
        // lost, because the interrupted block's mutations are unknown; the
        // interrupting frame itself still decodes normally.
        if !matches!(frame.kind, HEADERS | PUSH_PROMISE | CONTINUATION)
            && let Some(key) = key
            && context.state.http2_interrupt_pending(key)
        {
            block_protocol_expert(&mut *stream, "HTTP/2 frame interrupts an open header block");
        }
        let mut blocked = false;
        // RFC 9113 section 4.2: a frame whose declared length exceeds the
        // SETTINGS_MAX_FRAME_SIZE the peer advertised for this direction is a
        // FRAME_SIZE_ERROR connection error (section 6.5.2). A frame without
        // conversation state still meets the protocol default.
        let limit = match key {
            Some(key) => context.state.http2_peer_max_frame_size(key),
            None => DEFAULT_MAX_FRAME_SIZE,
        };
        if frame.length > limit {
            field_malformed(
                context,
                &mut *stream,
                "HTTP/2 frame exceeds SETTINGS_MAX_FRAME_SIZE; FRAME_SIZE_ERROR",
            );
            if matches!(frame.kind, HEADERS | PUSH_PROMISE | CONTINUATION)
                && let Some(key) = key
            {
                // The skipped payload may have carried HPACK table mutations,
                // so later dynamic references cannot be resolved (RFC 7541
                // section 2.2).
                context.state.http2_mark_table_lost(key);
            }
            blocked = true;
        }
        if !blocked && let Some(violation) = frame_violation(frame) {
            match violation {
                FrameViolation::Fatal(message) => {
                    field_malformed(context, &mut *stream, message);
                    blocked = true;
                }
                FrameViolation::Protocol(message) => {
                    stream.add_expert(ExpertInfo {
                        severity: Severity::Warning,
                        group: Group::Protocol,
                        message: message.to_string(),
                    });
                }
            }
        }
        if !blocked {
            match frame.kind {
                HEADERS => decode_headers(context, &mut *stream, frame, base, key, &mut suffix),
                PUSH_PROMISE => {
                    decode_push_promise(context, &mut *stream, frame, base, key, &mut suffix)
                }
                CONTINUATION => {
                    decode_continuation(context, &mut *stream, frame, base, key, &mut suffix)
                }
                DATA => decode_data(context, &mut *stream, frame, base, key, &mut suffix),
                PRIORITY => decode_priority(&mut *stream, frame, base),
                RST_STREAM => decode_rst_stream(&mut *stream, frame, base),
                SETTINGS => decode_settings(context, &mut *stream, frame, base, key),
                PING => decode_ping(&mut *stream, frame, base),
                GOAWAY => decode_goaway(&mut *stream, frame, base),
                WINDOW_UPDATE => decode_window_update(context, &mut *stream, frame, base, key),
                ALTSVC => decode_altsvc(&mut *stream, frame, base),
                ORIGIN => decode_origin(&mut *stream, frame, base),
                PRIORITY_UPDATE => decode_priority_update(&mut *stream, frame, base),
                _ => decode_unknown(&mut *stream, frame, base),
            }
        }
        let mut label = String::new();
        match type_name {
            Some(name) => {
                label.push_str(name);
                label.push_str(", Stream ID: ");
                label.push_str(&frame.stream_id.to_string());
                label.push_str(", Length ");
                label.push_str(&frame.length.to_string());
            }
            None => {
                label.push_str("Unknown type (");
                label.push_str(&frame.kind.to_string());
                label.push_str("), Stream ID: ");
                label.push_str(&frame.stream_id.to_string());
                label.push_str(", Length ");
                label.push_str(&frame.length.to_string());
            }
        }
        label.push_str(&suffix.text);
        stream.showname = Some(format!("Stream: {label}"));
        summary.push_str(type_name.unwrap_or("Unknown type"));
        if type_name.is_none() {
            summary.push_str(" (");
            summary.push_str(&frame.kind.to_string());
            summary.push(')');
        }
        summary.push('[');
        summary.push_str(&frame.stream_id.to_string());
        summary.push(']');
        if let Some(column_suffix) = suffix.column() {
            summary.push_str(": ");
            summary.push_str(column_suffix);
        }
    }
    parent.add_child(node);
    summary
}

impl Suffix {
    /// The summary-column suffix, without the container-only body marker.
    fn column(&self) -> Option<&str> {
        let text = self.text.as_str();
        if text.is_empty() || text.starts_with(" (") {
            None
        } else {
            text.strip_prefix(", ")
        }
    }
}

/// Add the shared frame header fields: length, type, flags and stream id.
fn add_header_fields(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    add_length_field(stream, frame.length, base);
    add_type_field(stream, frame.kind, base);
    add_flag_fields(stream, frame.kind, frame.flags, base);
    add_stream_identifier(stream, frame, base);
}

/// Add the fields of a frame header cut short by the end of the payload.
///
/// The fields whose octets were captured stay, followed by one malformed
/// expert. The stream identifier ends the nine-octet header of RFC 9113
/// section 4.1, so a cut header never holds it.
fn add_truncated_header(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    fragment: &[u8],
    base: usize,
) {
    let range = Range::new(base, fragment.len());
    let mut node = Node::new(&fields::HTTP2_PROTOCOL, range);
    let stream = node.add_container(&fields::HTTP2_STREAM, range, None);
    if let [high, middle, low, ..] = *fragment {
        add_length_field(stream, u32::from_be_bytes([0, high, middle, low]), base);
    }
    if let Some(&kind) = fragment.get(3) {
        add_type_field(stream, kind, base);
        if let Some(&bits) = fragment.get(4) {
            add_flag_fields(stream, kind, bits, base);
        }
    }
    context.mark_malformed(&mut node, "HTTP/2 frame header is truncated");
    parent.add_child(node);
}

/// Add the 24-bit Length field.
fn add_length_field(stream: &mut Field, length: u32, base: usize) {
    stream.add_field(
        &fields::HTTP2_LENGTH,
        Range::new(base, 3),
        Value::Uint24(length),
    );
}

/// Add the Type field, named from the frame type registry.
fn add_type_field(stream: &mut Field, kind: u8, base: usize) {
    let type_field = stream.add_field(
        &fields::HTTP2_TYPE,
        Range::new(base.saturating_add(3), 1),
        Value::Uint8(kind),
    );
    type_field.showname = Some(match frame_type_name(kind) {
        Some(name) => format!("Type: {name} ({kind})"),
        None => format!("Type: Unknown ({kind})"),
    });
}

/// Add the Flags container and the flag bits the frame type defines.
fn add_flag_fields(stream: &mut Field, kind: u8, bits: u8, base: usize) {
    let flags_range = Range::new(base.saturating_add(4), 1);
    let flags = stream.add_field(&fields::HTTP2_FLAGS, flags_range, Value::Uint8(bits));
    flags.container = true;
    let mut label = format!("Flags: 0x{bits:02x}");
    for name in flag_names(kind, bits) {
        label.push_str(", ");
        label.push_str(name);
    }
    flags.showname = Some(label);
    let (unused, booleans): (&'static FieldDef, &[(&'static FieldDef, u8)]) = match kind {
        DATA => (
            &fields::HTTP2_FLAGS_UNUSED_DATA,
            &[
                (&fields::HTTP2_FLAGS_PADDED, FLAG_PADDED),
                (&fields::HTTP2_FLAGS_END_STREAM, FLAG_END_STREAM),
            ],
        ),
        HEADERS => (
            &fields::HTTP2_FLAGS_UNUSED_HEADERS,
            &[
                (&fields::HTTP2_FLAGS_PRIORITY, FLAG_PRIORITY),
                (&fields::HTTP2_FLAGS_PADDED, FLAG_PADDED),
                (&fields::HTTP2_FLAGS_EH, FLAG_END_HEADERS),
                (&fields::HTTP2_FLAGS_END_STREAM, FLAG_END_STREAM),
            ],
        ),
        SETTINGS => (
            &fields::HTTP2_FLAGS_UNUSED_SETTINGS,
            &[(&fields::HTTP2_FLAGS_ACK_SETTINGS, FLAG_ACK)],
        ),
        PUSH_PROMISE => (
            &fields::HTTP2_FLAGS_UNUSED_PUSH_PROMISE,
            &[
                (&fields::HTTP2_FLAGS_PADDED, FLAG_PADDED),
                (&fields::HTTP2_FLAGS_EH, FLAG_END_HEADERS),
            ],
        ),
        PING => (
            &fields::HTTP2_FLAGS_UNUSED_PING,
            &[(&fields::HTTP2_FLAGS_ACK_PING, FLAG_ACK)],
        ),
        CONTINUATION => (
            &fields::HTTP2_FLAGS_UNUSED_CONTINUATION,
            &[
                (&fields::HTTP2_FLAGS_PADDED, FLAG_PADDED),
                (&fields::HTTP2_FLAGS_EH, FLAG_END_HEADERS),
            ],
        ),
        _ => (&fields::HTTP2_FLAGS_UNUSED, &[]),
    };
    let mask = unused.bitmask.unwrap_or(0xff);
    let masked = u64::from(bits) & mask;
    let unused_value = u8::try_from(masked).unwrap_or(0);
    let unused_field = flags.add_field(unused, flags_range, Value::Uint8(unused_value));
    unused_field.showname = Some(format!(
        "{} = Unused: 0x{unused_value:02x}",
        bit_pattern(u64::from(bits), mask, 8)
    ));
    for (def, flag) in booleans {
        let flag = *flag;
        let set = bits & flag != 0;
        let boolean = flags.add_field(def, flags_range, Value::Boolean(set));
        boolean.showname = Some(format!(
            "{} = {}: {}",
            bit_pattern(u64::from(bits), u64::from(flag), 8),
            def.name,
            if set { "True" } else { "False" }
        ));
    }
}

/// Add the reserved bit and the 31-bit Stream Identifier.
fn add_stream_identifier(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let word_range = Range::new(base.saturating_add(5), 4);
    let word = (u32::from(frame.reserved) << 31) | frame.stream_id;
    let reserved = stream.add_field(
        &fields::HTTP2_R,
        word_range,
        Value::Uint32(u32::from(frame.reserved)),
    );
    reserved.showname = Some(format!(
        "{} = Reserved: 0x{}",
        bit_pattern(u64::from(word), 0x8000_0000, 32),
        u32::from(frame.reserved)
    ));
    let identifier = stream.add_field(
        &fields::HTTP2_STREAMID,
        word_range,
        Value::Uint32(frame.stream_id),
    );
    identifier.showname = Some(format!(
        "{} = Stream Identifier: {}",
        bit_pattern(u64::from(word), 0x7fff_ffff, 32),
        frame.stream_id
    ));
}

/// Render the bit pattern a masked field's detail line starts with.
///
/// Bits outside the mask print as `.`, so a reserved bit and the stream
/// identifier that share one 32-bit word each show their own positions.
fn bit_pattern(value: u64, mask: u64, bits: usize) -> String {
    let mut pattern = String::with_capacity(bits + bits / 4 + 1);
    for bit in (0..bits).rev() {
        let bit_mask = 1_u64 << bit;
        if mask & bit_mask == 0 {
            pattern.push('.');
        } else {
            pattern.push(if value & bit_mask != 0 { '1' } else { '0' });
        }
        if bit % 4 == 0 && bit != 0 {
            pattern.push(' ');
        }
    }
    pattern
}

/// The flag names a frame's summary lists, in bit order.
fn flag_names(kind: u8, flags: u8) -> Vec<&'static str> {
    let mut names = Vec::new();
    if kind == SETTINGS || kind == PING {
        if flags & FLAG_ACK != 0 {
            names.push("ACK");
        }
        return names;
    }
    if kind == DATA || kind == HEADERS || kind == PUSH_PROMISE || kind == CONTINUATION {
        if flags & FLAG_PRIORITY != 0 && kind == HEADERS {
            names.push("Priority");
        }
        if flags & FLAG_PADDED != 0 && kind != CONTINUATION {
            names.push("Padded");
        }
        if flags & FLAG_END_HEADERS != 0 && kind != DATA {
            names.push("End Headers");
        }
        if flags & FLAG_END_STREAM != 0 && (kind == DATA || kind == HEADERS) {
            names.push("End Stream");
        }
    }
    names
}

/// Decode the HEADERS payload, including an optional pad and priority block.
fn decode_headers(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
    suffix: &mut Suffix,
) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    // END_STREAM on a HEADERS frame ends the stream's body as well, which is
    // how trailers complete a message (RFC 9113 section 8.1). The expected
    // output prints the reassembled body there before the frame's fields.
    if frame.flags & FLAG_END_STREAM != 0
        && let Some(key) = key
    {
        let outcome = context.state.http2_data(
            key,
            Http2Data {
                stream_id: frame.stream_id,
                data: &[],
                flow_length: 0,
                end_stream: true,
                frame: context.frame.number,
                file: context.frame.file_number,
            },
        );
        report_body_truncation(stream, &outcome);
        if let Some(body) = outcome.data
            && !outcome.fragments.is_empty()
        {
            if outcome.fragments.len() > 1 {
                add_body_fragments(stream, &outcome.fragments, body.len(), &body);
            }
            stream.add_field(
                &fields::HTTP2_DATA_DATA,
                Range::new(0, body.len()),
                Value::bytes(body),
            );
        }
    }
    let mut offset = 0_usize;
    let pad = pad_length(frame, stream, payload_base, &mut offset);
    if frame.flags & FLAG_PRIORITY != 0 {
        // RFC 9113 section 6.2: the Priority field is five octets after the
        // Pad Length. A payload too short for it is a FRAME_SIZE_ERROR, and
        // the remainder cannot be a header block.
        let priority_end = offset.saturating_add(5);
        if frame.payload.get(offset..priority_end).is_none() {
            field_malformed(
                context,
                stream,
                "HTTP/2 HEADERS priority fields are truncated; FRAME_SIZE_ERROR",
            );
            return;
        }
        add_priority(
            stream,
            frame.payload.get(offset..),
            payload_base.saturating_add(offset),
        );
        offset = priority_end;
    }
    let (fragment, padding) = split_payload(frame.payload, offset, pad);
    let fragment_base = payload_base.saturating_add(offset);
    add_fragment(stream, &fields::HTTP2_HEADERS, fragment, fragment_base);
    let end_headers = frame.flags & FLAG_END_HEADERS != 0;
    if let Some(key) = key {
        let origin = block_origin(context);
        let result = context.state.http2_fragment(
            key,
            frame.stream_id,
            BlockFragment::Headers,
            origin,
            fragment,
            end_headers,
        );
        if result.overflow {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block exceeds the 1 MiB bound",
            );
        }
        if result.unexpected {
            block_protocol_expert(
                stream,
                "HTTP/2 header block is interrupted by another frame",
            );
        }
        if let (Some(block), Some(start)) = (result.block, result.start) {
            add_header_block(context, stream, &block, start, key, frame.stream_id, suffix);
        }
    }
    if let Some(padding) = padding {
        let index = uri_index(stream);
        stream.insert_field(
            index,
            &fields::HTTP2_HEADERS_PADDING,
            Range::new(
                payload_base.saturating_add(frame.payload.len().saturating_sub(padding.len())),
                padding.len(),
            ),
            Value::bytes(padding.to_vec()),
        );
    }
}

/// Decode a PUSH_PROMISE payload and record the promised request.
fn decode_push_promise(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
    suffix: &mut Suffix,
) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    let mut offset = 0_usize;
    let pad = pad_length(frame, stream, payload_base, &mut offset);
    let word = frame
        .payload
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes);
    if let Some(word) = word {
        let range = Range::new(payload_base.saturating_add(offset), 4);
        let reserved = stream.add_field(
            &fields::HTTP2_PUSH_PROMISE_R,
            range,
            Value::Uint32(word >> 31),
        );
        reserved.showname = Some(format!(
            "{} = Reserved: 0x{}",
            bit_pattern(u64::from(word), 0x8000_0000, 32),
            word >> 31
        ));
        let promised = stream.add_field(
            &fields::HTTP2_PUSH_PROMISE_PROMISED_STREAM_ID,
            range,
            Value::Uint32(word & 0x7fff_ffff),
        );
        promised.showname = Some(format!(
            "{} = Promised-Stream-ID: {}",
            bit_pattern(u64::from(word), 0x7fff_ffff, 32),
            word & 0x7fff_ffff
        ));
        offset = offset.saturating_add(4);
    } else {
        field_malformed(context, stream, "HTTP/2 PUSH_PROMISE is truncated");
    }
    let promised = word.map(|word| word & 0x7fff_ffff).unwrap_or(0);
    let (fragment, padding) = split_payload(frame.payload, offset, pad);
    let fragment_base = payload_base.saturating_add(offset);
    add_fragment(
        stream,
        &fields::HTTP2_PUSH_PROMISE_HEADER,
        fragment,
        fragment_base,
    );
    let end_headers = frame.flags & FLAG_END_HEADERS != 0;
    if let Some(key) = key {
        let origin = block_origin(context);
        let result = context.state.http2_fragment(
            key,
            frame.stream_id,
            BlockFragment::PushPromise { promised },
            origin,
            fragment,
            end_headers,
        );
        if result.overflow {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block exceeds the 1 MiB bound",
            );
        }
        if result.unexpected {
            block_protocol_expert(
                stream,
                "HTTP/2 header block is interrupted by another frame",
            );
        }
        if let (Some(block), Some(start)) = (result.block, result.start) {
            let request =
                add_header_block(context, stream, &block, start, key, frame.stream_id, suffix);
            // The promise's own stream keeps its request URI; the expected
            // output prints it after the promised request URI.
            add_stream_uri(context, stream, frame.stream_id, Some(key), false);
            if let Some(request) = request
                && start.push
                && start.promised != 0
                && !context.observe_only
            {
                context.state.http2_record_request(
                    key.conversation,
                    start.promised,
                    start.frame,
                    start.file,
                    start.time,
                    request.uri,
                );
            }
        }
    }
    if let Some(padding) = padding {
        stream.add_field(
            &fields::HTTP2_PUSH_PROMISE_PADDING,
            Range::new(
                payload_base.saturating_add(frame.payload.len().saturating_sub(padding.len())),
                padding.len(),
            ),
            Value::bytes(padding.to_vec()),
        );
    }
}

/// Decode a CONTINUATION payload.
fn decode_continuation(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
    suffix: &mut Suffix,
) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    let pad = pad_length(frame, stream, payload_base, &mut 0_usize);
    let (fragment, _padding) = split_payload(frame.payload, 0, pad);
    add_fragment(
        stream,
        &fields::HTTP2_CONTINUATION_HEADER,
        fragment,
        payload_base,
    );
    let end_headers = frame.flags & FLAG_END_HEADERS != 0;
    if let Some(key) = key {
        let origin = block_origin(context);
        let result = context.state.http2_fragment(
            key,
            frame.stream_id,
            BlockFragment::Continuation,
            origin,
            fragment,
            end_headers,
        );
        if result.overflow {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block exceeds the 1 MiB bound",
            );
        }
        if result.unexpected {
            block_protocol_expert(stream, "CONTINUATION without an open header block");
        }
        if let (Some(block), Some(start)) = (result.block, result.start) {
            let request =
                add_header_block(context, stream, &block, start, key, frame.stream_id, suffix);
            if start.push {
                // A completed PUSH_PROMISE block records the promised request
                // against the frame that opened it, not this continuation.
                add_stream_uri(context, stream, frame.stream_id, Some(key), false);
                if let Some(request) = request
                    && start.promised != 0
                    && !context.observe_only
                {
                    context.state.http2_record_request(
                        key.conversation,
                        start.promised,
                        start.frame,
                        start.file,
                        start.time,
                        request.uri,
                    );
                }
            }
        }
    }
}

/// Decode a DATA payload and account its flow-control and body state.
fn decode_data(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
    suffix: &mut Suffix,
) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    let mut offset = 0_usize;
    let pad = pad_length(frame, stream, payload_base, &mut offset);
    let (data, padding) = split_payload(frame.payload, offset, pad);
    let data_base = payload_base.saturating_add(offset);
    let end_stream = frame.flags & FLAG_END_STREAM != 0;
    // RFC 9113 section 6.1: the entire DATA frame payload is charged to flow
    // control, including the Pad Length and Padding fields, while the body
    // keeps only the unpadded octets.
    let flow_length = usize::try_from(frame.length).unwrap_or(usize::MAX);
    let mut assembled: Option<Vec<u8>> = None;
    let mut dropped = false;
    let mut windows = None;
    if let Some(key) = key {
        let outcome = context.state.http2_data(
            key,
            Http2Data {
                stream_id: frame.stream_id,
                data,
                flow_length,
                end_stream,
                frame: context.frame.number,
                file: context.frame.file_number,
            },
        );
        windows = Some((
            outcome.connection_before,
            outcome.connection_after,
            outcome.stream_before,
            outcome.stream_after,
        ));
        if outcome.evicted {
            stream.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Sequence,
                message: "HTTP/2 stream table full; oldest stream state dropped".to_string(),
            });
        }
        if outcome.dropped {
            dropped = true;
            add_marker(stream, &fields::HTTP2_REASSEMBLY_ERROR, "Reassembly failed");
            stream.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Reassemble,
                message: "HTTP/2 body exceeds the 1 MiB reassembly limit".to_string(),
            });
        }
        if end_stream && !outcome.dropped {
            report_body_truncation(stream, &outcome);
        }
        if let Some(body) = outcome.data {
            if outcome.fragments.len() > 1 {
                add_body_fragments(stream, &outcome.fragments, body.len(), &body);
            }
            assembled = Some(body);
        }
        if end_stream
            && context.pass == crate::state::PassMode::First
            && outcome.fragments.len() > 1
        {
            let completing = context.frame.file_number;
            let annotations = context.state.annotations_mut();
            for fragment in &outcome.fragments {
                if fragment.file != completing {
                    annotations.link_http2_body_reassembled(fragment.file, completing);
                }
            }
        }
    }
    let (value, range) = match &assembled {
        Some(body) => (body.clone(), Range::new(0, body.len())),
        None => (data.to_vec(), Range::new(data_base, data.len())),
    };
    let length = value.len();
    let data_field = stream.add_field(&fields::HTTP2_DATA_DATA, range, Value::bytes(value.clone()));
    if assembled.is_some() {
        data_field.raw = Some(raw_field(value, 0, length, 30, RawSource::Frame));
    }
    if let Some(padding) = padding {
        stream.add_field(
            &fields::HTTP2_DATA_PADDING,
            Range::new(
                payload_base.saturating_add(frame.payload.len().saturating_sub(padding.len())),
                padding.len(),
            ),
            Value::bytes(padding.to_vec()),
        );
    }
    if let Some((connection_before, connection_after, stream_before, stream_after)) = windows {
        add_connection_window(stream, connection_before, connection_after);
        add_stream_window(stream, stream_before, stream_after);
        add_stream_uri(context, stream, frame.stream_id, key, false);
    }
    if !end_stream && !dropped {
        suffix.text = " (partial entity body)".to_string();
    }
}

/// Report, once on the completing frame, that fragment metadata was capped.
///
/// The body itself stays whole; only the per-fragment frame and offset list is
/// bounded by [`crate::state::MAX_BODY_FRAGMENTS`], so the count here is the
/// number of DATA frames and the retained views are fewer.
fn report_body_truncation(stream: &mut Field, outcome: &DataOutcome) {
    if !outcome.truncated {
        return;
    }
    stream.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Reassemble,
        message: format!(
            "HTTP/2 body has {} DATA fragments; {} fragment views retained",
            outcome.fragment_count,
            outcome.fragments.len()
        ),
    });
}

/// Add the `N Body fragments` container the completing DATA frame carries.
fn add_body_fragments(
    stream: &mut Field,
    fragments: &[BodyFragmentView],
    total: usize,
    body: &[u8],
) {
    let mut label = String::with_capacity(32);
    label.push_str(&fragments.len().to_string());
    label.push_str(" Body fragments (");
    label.push_str(&total.to_string());
    label.push_str(" bytes): ");
    for (index, fragment) in fragments.iter().enumerate() {
        if index > 0 {
            label.push_str(", ");
        }
        label.push('#');
        label.push_str(&fragment.frame.to_string());
        label.push('(');
        label.push_str(&fragment.length.to_string());
        label.push(')');
    }
    let container = stream.add_container(
        &fields::HTTP2_BODY_FRAGMENTS,
        Range::new(0, total),
        Some(label),
    );
    for fragment in fragments {
        let end = fragment
            .offset
            .saturating_add(fragment.length)
            .saturating_sub(1);
        let field = container.add_field(
            &fields::HTTP2_BODY_FRAGMENT,
            Range::new(0, 0),
            Value::Uint32(u32::try_from(fragment.frame).unwrap_or(u32::MAX)),
        );
        field.showname = Some(format!(
            "Frame: {}, payload: {}-{} ({} bytes)",
            fragment.frame, fragment.offset, end, fragment.length
        ));
        field.raw = Some(raw_field(
            Vec::new(),
            fragment.offset,
            fragment.length,
            30,
            RawSource::Frame,
        ));
    }
    container.add_field(
        &fields::HTTP2_BODY_FRAGMENT_COUNT,
        Range::new(0, 0),
        Value::Uint32(u32::try_from(fragments.len()).unwrap_or(u32::MAX)),
    );
    container.add_field(
        &fields::HTTP2_BODY_REASSEMBLED_LENGTH,
        Range::new(0, 0),
        Value::Uint32(u32::try_from(total).unwrap_or(u32::MAX)),
    );
    let data = container.add_field(
        &fields::HTTP2_BODY_REASSEMBLED_DATA,
        Range::new(0, body.len()),
        Value::bytes(body.to_vec()),
    );
    data.raw = Some(raw_field(
        body.to_vec(),
        0,
        body.len(),
        30,
        RawSource::Frame,
    ));
}

/// Add the connection flow-control pair a DATA or WINDOW_UPDATE frame reports.
fn add_connection_window(stream: &mut Field, before: i32, after: i32) {
    stream.add_field(
        &fields::HTTP2_CALCULATED_CONNECTION_WINDOW_SIZE_BEFORE,
        Range::new(0, 0),
        Value::Int32(before),
    );
    stream.add_field(
        &fields::HTTP2_CALCULATED_CONNECTION_WINDOW_SIZE_AFTER,
        Range::new(0, 0),
        Value::Int32(after),
    );
}

/// Add the stream flow-control pair a DATA or WINDOW_UPDATE frame reports.
fn add_stream_window(stream: &mut Field, before: i32, after: i32) {
    stream.add_field(
        &fields::HTTP2_CALCULATED_STREAM_WINDOW_SIZE_BEFORE,
        Range::new(0, 0),
        Value::Int32(before),
    );
    stream.add_field(
        &fields::HTTP2_CALCULATED_STREAM_WINDOW_SIZE_AFTER,
        Range::new(0, 0),
        Value::Int32(after),
    );
}

/// Decode a PRIORITY payload.
fn decode_priority(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    add_priority(
        stream,
        Some(frame.payload),
        base.saturating_add(FRAME_HEADER_BYTES),
    );
}

/// Add the exclusive, dependency and weight fields.
fn add_priority(stream: &mut Field, payload: Option<&[u8]>, base: usize) {
    let Some(payload) = payload else {
        return;
    };
    let Some(word) = payload
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
    else {
        return;
    };
    let range = Range::new(base, 4);
    let exclusive = stream.add_field(
        &fields::HTTP2_EXCLUSIVE,
        range,
        Value::Boolean(word & 0x8000_0000 != 0),
    );
    exclusive.showname = Some(format!(
        "{} = Exclusive: {}",
        bit_pattern(u64::from(word), 0x8000_0000, 32),
        if word & 0x8000_0000 != 0 {
            "True"
        } else {
            "False"
        }
    ));
    let dependency = stream.add_field(
        &fields::HTTP2_STREAM_DEPENDENCY,
        range,
        Value::Uint32(word & 0x7fff_ffff),
    );
    dependency.showname = Some(format!(
        "{} = Stream Dependency: {}",
        bit_pattern(u64::from(word), 0x7fff_ffff, 32),
        word & 0x7fff_ffff
    ));
    if let Some(&weight) = payload.get(4) {
        stream.add_field(
            &fields::HTTP2_HEADERS_WEIGHT,
            Range::new(base.saturating_add(4), 1),
            Value::Uint8(weight),
        );
        stream.add_field(
            &fields::HTTP2_HEADERS_WEIGHT_REAL,
            Range::new(0, 0),
            Value::Uint8(weight.saturating_add(1)),
        );
    }
}

/// Decode an RST_STREAM payload.
fn decode_rst_stream(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let Some(error) = read_u32(frame.payload, 0) else {
        return;
    };
    let field = stream.add_field(
        &fields::HTTP2_RST_STREAM_ERROR,
        Range::new(base.saturating_add(FRAME_HEADER_BYTES), 4),
        Value::Uint32(error),
    );
    field.showname = Some(format!("Error: {} ({error})", error_name(error)));
}

/// Decode a SETTINGS payload.
fn decode_settings(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    if let Some(key) = key {
        // RFC 9113 section 6.5: a SETTINGS ACK acknowledges the oldest frame
        // the opposite direction sent; every other SETTINGS frame is queued
        // until that ACK arrives (section 6.5.3).
        if frame.flags & FLAG_ACK != 0 {
            context.state.http2_settings_ack(key);
        } else {
            context.state.http2_settings_frame(key);
        }
    }
    let mut offset = 0_usize;
    let mut records = 0_usize;
    let mut capped = false;
    while let (Some(id), Some(value)) = (
        read_u16(frame.payload, offset),
        read_u32(frame.payload, offset.saturating_add(2)),
    ) {
        if records >= MAX_FRAME_RECORDS {
            if !capped {
                capped = true;
                stream.add_expert(ExpertInfo {
                    severity: Severity::Warning,
                    group: Group::Undecoded,
                    message: format!(
                        "HTTP/2 SETTINGS frame carries more than {MAX_FRAME_RECORDS} \
                         settings; the rest are not shown"
                    ),
                });
            }
            // The values still change how later frames behave, so they are
            // applied even when their fields are not added to the tree.
            if let Some(key) = key {
                context.state.http2_settings(key, id, value);
            }
            offset = offset.saturating_add(6);
            records = records.saturating_add(1);
            continue;
        }
        let range = Range::new(payload_base.saturating_add(offset), 6);
        let name = settings_name(id);
        let mut label = String::new();
        label.push_str("Settings - ");
        if settings_name_known(id) {
            label.push_str(name);
        } else {
            label.push_str("Unknown (");
            label.push_str(&id.to_string());
            label.push(')');
        }
        label.push_str(" : ");
        label.push_str(&value.to_string());
        let container = stream.add_container(&fields::HTTP2_SETTINGS, range, Some(label));
        let identifier = container.add_field(
            &fields::HTTP2_SETTINGS_ID,
            Range::new(payload_base.saturating_add(offset), 2),
            Value::Uint16(id),
        );
        identifier.showname = Some(match settings_name_known(id) {
            true => format!("Settings Identifier: {name} ({id})"),
            false => format!("Settings Identifier: Unknown ({id})"),
        });
        let (value_field, showname) = match id {
            1 => (
                &fields::HTTP2_SETTINGS_HEADER_TABLE_SIZE,
                "Header table size",
            ),
            2 => (&fields::HTTP2_SETTINGS_ENABLE_PUSH, "Enable PUSH"),
            3 => (
                &fields::HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                "Max concurrent streams",
            ),
            4 => (
                &fields::HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                "Initial Window Size",
            ),
            5 => (&fields::HTTP2_SETTINGS_MAX_FRAME_SIZE, "Max frame size"),
            6 => (
                &fields::HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
                "Max header list size",
            ),
            8 => (&fields::HTTP2_SETTINGS_EXTENDED_CONNECT, "Extended CONNECT"),
            9 => (
                &fields::HTTP2_SETTINGS_NO_RFC7540_PRIORITIES,
                "No RFC7540 Priorities",
            ),
            16 => (
                &fields::HTTP2_SETTINGS_TLS_RENEG_PERMITTED,
                "TLS Renegotiation Permitted",
            ),
            _ => (&fields::HTTP2_SETTINGS_UNKNOWN, "Unknown Settings"),
        };
        let value_range = Range::new(payload_base.saturating_add(offset).saturating_add(2), 4);
        let value_field_ref = container.add_field(value_field, value_range, Value::Uint32(value));
        value_field_ref.showname = Some(format!("{showname}: {value}"));
        if id == 5 && !(DEFAULT_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
            container.add_expert(ExpertInfo {
                severity: Severity::Error,
                group: Group::Protocol,
                message: "SETTINGS_MAX_FRAME_SIZE outside 16384..=16777215".to_string(),
            });
        }
        if let Some(key) = key {
            context.state.http2_settings(key, id, value);
        }
        offset = offset.saturating_add(6);
        records = records.saturating_add(1);
    }
    if !frame.payload.len().is_multiple_of(6) {
        field_malformed(
            context,
            stream,
            "HTTP/2 SETTINGS payload is not a multiple of six",
        );
    }
}

/// The registry name of a SETTINGS identifier.
fn settings_name(id: u16) -> &'static str {
    match id {
        1 => "Header table size",
        2 => "Enable PUSH",
        3 => "Max concurrent streams",
        // The field registry spells this identifier "Windows"; the name is
        // part of the output contract.
        4 => "Initial Windows size",
        5 => "Max frame size",
        6 => "Max header list size",
        8 => "Extended CONNECT",
        9 => "No RFC7540 Priorities",
        16 => "TLS Renegotiation Permitted",
        _ => "Unknown",
    }
}

/// Whether a SETTINGS identifier has a registered name.
fn settings_name_known(id: u16) -> bool {
    matches!(id, 1 | 2 | 3 | 4 | 5 | 6 | 8 | 9 | 16)
}

/// Decode a PING payload.
fn decode_ping(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let range = Range::new(base.saturating_add(FRAME_HEADER_BYTES), frame.payload.len());
    let ack = frame.flags & FLAG_ACK != 0;
    if frame.payload.len() != 8 {
        return;
    }
    stream.add_field(
        if ack {
            &fields::HTTP2_PONG
        } else {
            &fields::HTTP2_PING
        },
        range,
        Value::bytes(frame.payload.to_vec()),
    );
}

/// Decode a GOAWAY payload.
fn decode_goaway(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    if let Some(word) = read_u32(frame.payload, 0) {
        let range = Range::new(payload_base, 4);
        let reserved = stream.add_field(&fields::HTTP2_GOAWAY_R, range, Value::Uint32(word >> 31));
        reserved.showname = Some(format!(
            "{} = Reserved: 0x{}",
            bit_pattern(u64::from(word), 0x8000_0000, 32),
            word >> 31
        ));
        let last = stream.add_field(
            &fields::HTTP2_GOAWAY_LAST_STREAM_ID,
            range,
            Value::Uint32(word & 0x7fff_ffff),
        );
        last.showname = Some(format!(
            "{} = Last-Stream-ID: {}",
            bit_pattern(u64::from(word), 0x7fff_ffff, 32),
            word & 0x7fff_ffff
        ));
    }
    if let Some(error) = read_u32(frame.payload, 4) {
        let field = stream.add_field(
            &fields::HTTP2_GOAWAY_ERROR,
            Range::new(payload_base.saturating_add(4), 4),
            Value::Uint32(error),
        );
        field.showname = Some(format!("Error: {} ({error})", error_name(error)));
    }
    if let Some(rest) = frame.payload.get(8..)
        && !rest.is_empty()
    {
        stream.add_field(
            &fields::HTTP2_GOAWAY_ADDATA,
            Range::new(payload_base.saturating_add(8), rest.len()),
            Value::bytes(rest.to_vec()),
        );
    }
}

/// The registry name of an HTTP/2 error code (RFC 9113 section 7).
fn error_name(code: u32) -> &'static str {
    match code {
        0 => "NO_ERROR",
        1 => "PROTOCOL_ERROR",
        2 => "INTERNAL_ERROR",
        3 => "FLOW_CONTROL_ERROR",
        4 => "SETTINGS_TIMEOUT",
        5 => "STREAM_CLOSED",
        6 => "FRAME_SIZE_ERROR",
        7 => "REFUSED_STREAM",
        8 => "CANCEL",
        9 => "COMPRESSION_ERROR",
        10 => "CONNECT_ERROR",
        11 => "ENHANCE_YOUR_CALM",
        12 => "INADEQUATE_SECURITY",
        13 => "HTTP_1_1_REQUIRED",
        _ => "Unknown",
    }
}

/// Decode a WINDOW_UPDATE payload.
fn decode_window_update(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    frame: &Frame<'_>,
    base: usize,
    key: Option<Http2Key>,
) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    let Some(word) = read_u32(frame.payload, 0) else {
        return;
    };
    let range = Range::new(payload_base, 4);
    let reserved = stream.add_field(
        &fields::HTTP2_WINDOW_UPDATE_R,
        range,
        Value::Uint32(word >> 31),
    );
    reserved.showname = Some(format!(
        "{} = Reserved: 0x{}",
        bit_pattern(u64::from(word), 0x8000_0000, 32),
        word >> 31
    ));
    let increment = word & 0x7fff_ffff;
    let increment_field = stream.add_field(
        &fields::HTTP2_WINDOW_UPDATE_WINDOW_SIZE_INCREMENT,
        range,
        Value::Uint32(increment),
    );
    increment_field.showname = Some(format!(
        "{} = Window Size Increment: {}",
        bit_pattern(u64::from(word), 0x7fff_ffff, 32),
        increment
    ));
    if increment == 0 && !context.quoted {
        // RFC 9113 section 6.9: a zero increment is a PROTOCOL_ERROR, a
        // stream error on a stream and a connection error on stream 0. The
        // window does not move, so the calculated pair below still holds. A
        // quoted copy is data, not a frame this connection received.
        increment_field.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Protocol,
            message: "HTTP/2 WINDOW_UPDATE increment is 0; PROTOCOL_ERROR".to_string(),
        });
    }
    if let Some(key) = key {
        let (before, after) = context.state.http2_window_update(
            key,
            frame.stream_id,
            increment,
            context.frame.file_number,
        );
        if frame.stream_id == 0 {
            add_connection_window(stream, before, after);
        } else {
            add_stream_window(stream, before, after);
        }
    }
}

/// Decode an ALTSVC payload (RFC 7838).
fn decode_altsvc(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    let Some(length) = read_u16(frame.payload, 0) else {
        return;
    };
    let length_usize = usize::from(length);
    stream.add_field(
        &fields::HTTP2_ALTSVC_ORIGIN_LEN,
        Range::new(payload_base, 2),
        Value::Uint16(length),
    );
    if let Some(origin) = frame.payload.get(2..2_usize.saturating_add(length_usize)) {
        stream.add_field(
            &fields::HTTP2_ALTSVC_ORIGIN,
            Range::new(payload_base.saturating_add(2), origin.len()),
            Value::String(String::from_utf8_lossy(origin).into_owned()),
        );
        if let Some(value) = frame.payload.get(2_usize.saturating_add(length_usize)..) {
            stream.add_field(
                &fields::HTTP2_ALTSVC_FIELD_VALUE,
                Range::new(
                    payload_base.saturating_add(2).saturating_add(length_usize),
                    value.len(),
                ),
                Value::String(String::from_utf8_lossy(value).into_owned()),
            );
        }
    }
}

/// Decode an ORIGIN payload (RFC 8336).
fn decode_origin(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    let mut offset = 0_usize;
    let mut records = 0_usize;
    while let Some(length) = read_u16(frame.payload, offset) {
        if records >= MAX_FRAME_RECORDS {
            stream.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Undecoded,
                message: format!(
                    "HTTP/2 ORIGIN frame carries more than {MAX_FRAME_RECORDS} \
                     origins; the rest are not shown"
                ),
            });
            break;
        }
        let length_usize = usize::from(length);
        let range = Range::new(payload_base.saturating_add(offset), 2);
        let container =
            stream.add_container(&fields::HTTP2_ORIGIN, range, Some("Origin".to_string()));
        container.add_field(
            &fields::HTTP2_ORIGIN_ORIGIN_LEN,
            range,
            Value::Uint16(length),
        );
        let Some(origin) = frame
            .payload
            .get(offset.saturating_add(2)..offset.saturating_add(2).saturating_add(length_usize))
        else {
            break;
        };
        container.add_field(
            &fields::HTTP2_ORIGIN_ORIGIN,
            Range::new(
                payload_base.saturating_add(offset).saturating_add(2),
                origin.len(),
            ),
            Value::String(String::from_utf8_lossy(origin).into_owned()),
        );
        offset = offset.saturating_add(2).saturating_add(length_usize);
        records = records.saturating_add(1);
    }
}

/// Decode a PRIORITY_UPDATE payload (RFC 9218).
fn decode_priority_update(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    let payload_base = base.saturating_add(FRAME_HEADER_BYTES);
    if let Some(stream_id) = read_u32(frame.payload, 0) {
        stream.add_field(
            &fields::HTTP2_PRIORITY_UPDATE_STREAM_ID,
            Range::new(payload_base, 4),
            Value::Uint64(u64::from(stream_id)),
        );
    }
    if let Some(value) = frame.payload.get(4..) {
        stream.add_field(
            &fields::HTTP2_PRIORITY_UPDATE_FIELD_VALUE,
            Range::new(payload_base.saturating_add(4), value.len()),
            Value::String(String::from_utf8_lossy(value).into_owned()),
        );
    }
}

/// Decode an unknown frame type's payload as opaque bytes.
fn decode_unknown(stream: &mut Field, frame: &Frame<'_>, base: usize) {
    stream.add_field(
        &fields::HTTP2_UNKNOWN,
        Range::new(base.saturating_add(FRAME_HEADER_BYTES), frame.payload.len()),
        Value::bytes(frame.payload.to_vec()),
    );
}

/// The Pad Length octet and its generated copy, returning the pad size.
fn pad_length(
    frame: &Frame<'_>,
    stream: &mut Field,
    payload_base: usize,
    offset: &mut usize,
) -> usize {
    let padded = frame.flags & FLAG_PADDED != 0 && frame.kind != CONTINUATION;
    let pad = if padded {
        frame.payload.first().copied().unwrap_or(0)
    } else {
        0
    };
    if padded {
        stream.add_field(
            &fields::HTTP2_PADDING,
            Range::new(payload_base, 1),
            Value::Uint8(pad),
        );
        *offset = 1;
    }
    stream.add_field(
        &fields::HTTP2_PAD_LENGTH,
        Range::new(0, 0),
        Value::Uint16(u16::from(pad)),
    );
    usize::from(pad)
}

/// Split the declared pad bytes off the end of a frame payload.
fn split_payload(payload: &[u8], offset: usize, pad: usize) -> (&[u8], Option<&[u8]>) {
    let Some(body) = payload.get(offset..) else {
        return (&[], None);
    };
    if pad == 0 || pad > body.len() {
        return (body, None);
    }
    let split = body.len().saturating_sub(pad);
    let (data, padding) = body.split_at(split);
    (data, Some(padding))
}

/// Add the header block fragment bytes field.
fn add_fragment(stream: &mut Field, def: &'static FieldDef, fragment: &[u8], base: usize) {
    if fragment.is_empty() {
        stream.add_field(def, Range::new(base, 0), Value::Missing);
    } else {
        stream.add_field(
            def,
            Range::new(base, fragment.len()),
            Value::bytes(fragment.to_vec()),
        );
    }
}

/// The request or response a header block carries.
#[derive(Default)]
struct HeaderSummary {
    method: Option<String>,
    path: Option<String>,
    uri: Option<String>,
    status: Option<u16>,
}

/// Add a decoded header block: length, count, items, URI and summary suffix.
fn add_header_block(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    block: &hpack::Block,
    start: BlockStart,
    key: Http2Key,
    stream_id: u32,
    suffix: &mut Suffix,
) -> Option<HeaderSummary> {
    let push = start.push;
    let mut summary = HeaderSummary::default();
    stream.add_field(
        &fields::HTTP2_HEADER_LENGTH,
        Range::new(0, 0),
        Value::Uint32(block.header_bytes),
    );
    stream.add_field(
        &fields::HTTP2_HEADER_COUNT,
        Range::new(0, 0),
        Value::Uint32(block.header_count),
    );
    for item in &block.items {
        match item {
            hpack::Item::TableSizeUpdate(size) => {
                let container = stream.add_container(
                    &fields::HTTP2_HEADER_TABLE_SIZE_UPDATE,
                    Range::new(0, 0),
                    Some("Header table size update".to_string()),
                );
                container.add_field(
                    &fields::HTTP2_HEADER_TABLE_SIZE_UPDATE_HEADER_TABLE_SIZE,
                    Range::new(0, 0),
                    Value::Uint32(*size),
                );
            }
            hpack::Item::Header(header) => {
                add_header(stream, header);
                match header.name.as_str() {
                    ":method" => summary.method = Some(header.value.clone()),
                    ":path" => summary.path = Some(header.value.clone()),
                    ":status" => summary.status = header.value.parse::<u16>().ok(),
                    _ => {}
                }
            }
        }
    }
    summary.uri = synthesize_uri(&summary, block);
    match block.stop {
        hpack::Stop::Complete => {}
        hpack::Stop::Invalid => {
            field_malformed(context, stream, "HTTP/2 header block is invalid");
        }
        hpack::Stop::SizeExceeded => {
            add_marker(
                stream,
                &fields::HTTP2_HEADER_SIZE_EXCEEDED,
                "Decompression stopped.",
            );
            field_malformed(
                context,
                stream,
                "HTTP/2 header list exceeds the 64 KiB bound",
            );
        }
        hpack::Stop::LinesExceeded => {
            add_marker(
                stream,
                &fields::HTTP2_HEADER_LINES_EXCEEDED,
                "Decompression stopped after 200 header lines.",
            );
            field_malformed(context, stream, "HTTP/2 header block exceeds 200 lines");
        }
        hpack::Stop::SizeUpdateAfterHeader => {
            field_malformed(
                context,
                stream,
                "HTTP/2 table size update after a header field",
            );
        }
        hpack::Stop::SizeUpdateRequired => {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block did not begin with the required table size update",
            );
        }
        hpack::Stop::Desynchronized => {
            // The block is valid; earlier damage left the decoder's table
            // out of step, so reporting the packet malformed would blame the
            // wrong frame.
            stream.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Undecoded,
                message: "HTTP/2 dynamic table lost after an earlier decoding error; \
                          indexed fields were not resolved"
                    .to_string(),
            });
        }
    }
    let conversation = key.conversation;
    if let Some(status) = summary.status {
        // A frame decoded only to advance reassembly must not create
        // request/response links: the output pass reports those solely for
        // displayed frames.
        if !context.observe_only {
            let info = context.state.http2_record_response(
                conversation,
                stream_id,
                u32::try_from(context.frame.number).unwrap_or(u32::MAX),
            );
            if let Some(info) = info {
                let delay = match (info.time, context.frame.timestamp) {
                    (Some(request), Some(response)) => {
                        Some(crate::state::elapsed_nanos(request, response))
                    }
                    _ => None,
                };
                if context.pass == crate::state::PassMode::First {
                    let annotations = context.state.annotations_mut();
                    if let Some(delay) = delay {
                        annotations.link_response(
                            context.frame.file_number,
                            u64::from(info.file),
                            delay,
                        );
                    }
                    annotations.link_response_in(u64::from(info.file), context.frame.file_number);
                }
                if context.pass != crate::state::PassMode::Second {
                    let index = uri_index(stream);
                    stream.insert_field(
                        index,
                        &fields::HTTP2_REQUEST_IN,
                        Range::new(0, 0),
                        Value::Uint32(info.frame),
                    );
                    if let Some(delay) = delay {
                        stream.insert_field(
                            index,
                            &fields::HTTP2_TIME,
                            Range::new(0, 0),
                            Value::RelativeTime(delay),
                        );
                    }
                }
            }
        }
        let reason = status_reason(status);
        suffix.text = format!(", {status} {reason}");
    } else if let (Some(method), Some(path)) = (&summary.method, &summary.path) {
        suffix.text = format!(", {method} {path}");
        if !push && !context.observe_only {
            let uri = summary.uri.clone();
            // RFC 9113 section 6.10 makes the block one unit: a request split
            // across CONTINUATION frames belongs to the frame that opened it,
            // not the one that completed it.
            context.state.http2_record_request(
                conversation,
                stream_id,
                start.frame,
                start.file,
                start.time,
                uri,
            );
        }
    }
    let uri = if let Some(uri) = summary.uri.clone() {
        Some(uri)
    } else if !push {
        context.state.http2_stream_uri(conversation, stream_id)
    } else {
        None
    };
    if let Some(uri) = uri
        && stream_id != 0
    {
        let field = stream.add_field(
            &fields::HTTP2_REQUEST_FULL_URI,
            Range::new(0, 0),
            Value::String(uri.clone()),
        );
        field.showname = Some(if push {
            format!("Full promised request URI: {uri}")
        } else {
            format!("Full request URI: {uri}")
        });
    }
    Some(summary)
}

/// Where a request link or response timing goes: before the generated URI.
fn uri_index(stream: &Field) -> usize {
    stream
        .children
        .iter()
        .position(|field| field.def.abbrev == "http2.request.full_uri")
        .unwrap_or(stream.children.len())
}

/// Build the request URI from the pseudo-header values.
fn synthesize_uri(summary: &HeaderSummary, block: &hpack::Block) -> Option<String> {
    let path = summary.path.as_deref()?;
    let scheme = block
        .headers()
        .find(|header| header.name == ":scheme")
        .map(|header| header.value.as_str())
        .unwrap_or("http");
    if path.starts_with("http://") || path.starts_with("https://") {
        return Some(path.to_string());
    }
    let authority = block
        .headers()
        .find(|header| header.name == ":authority")
        .map(|header| header.value.trim())
        .filter(|authority| !authority.is_empty())?;
    Some(format!("{scheme}://{authority}{path}"))
}

/// Add the request URI known for a stream, if any.
fn add_stream_uri(
    context: &mut DecodeContext<'_>,
    stream: &mut Field,
    stream_id: u32,
    key: Option<Http2Key>,
    push: bool,
) {
    if context.observe_only {
        // The URI is a cross-frame reference to a request recorded by another
        // frame, so a state-only decode must not add it.
        return;
    }
    let Some(key) = key else {
        return;
    };
    if stream_id == 0 {
        return;
    }
    let Some(uri) = context.state.http2_stream_uri(key.conversation, stream_id) else {
        return;
    };
    let field = stream.add_field(
        &fields::HTTP2_REQUEST_FULL_URI,
        Range::new(0, 0),
        Value::String(uri.clone()),
    );
    field.showname = Some(if push {
        format!("Full promised request URI: {uri}")
    } else {
        format!("Full request URI: {uri}")
    });
}

/// Add one decoded header field and its curated companion.
fn add_header(stream: &mut Field, header: &hpack::Header) {
    let mut label = String::new();
    label.push_str("Header: ");
    label.push_str(&header.name);
    label.push_str(": ");
    label.push_str(&header.value);
    if header.name == ":status"
        && let Ok(code) = header.value.parse::<u16>()
    {
        label.push(' ');
        label.push_str(status_reason(code));
    }
    let container = stream.add_container(&fields::HTTP2_HEADER, Range::new(0, 0), Some(label));
    container.add_field(
        &fields::HTTP2_HEADER_NAME_LENGTH,
        Range::new(0, 0),
        Value::Uint32(u32::try_from(header.name.len()).unwrap_or(u32::MAX)),
    );
    container.add_field(
        &fields::HTTP2_HEADER_NAME,
        Range::new(0, 0),
        Value::String(header.name.clone()),
    );
    container.add_field(
        &fields::HTTP2_HEADER_VALUE_LENGTH,
        Range::new(0, 0),
        Value::Uint32(u32::try_from(header.value.len()).unwrap_or(u32::MAX)),
    );
    container.add_field(
        &fields::HTTP2_HEADER_VALUE,
        Range::new(0, 0),
        Value::String(header.value.clone()),
    );
    if let Some(def) = curated_header(&header.name) {
        match def.field_type {
            fields::FieldType::Uint16 => {
                if let Ok(value) = header.value.parse::<u16>() {
                    container.add_field(def, Range::new(0, 0), Value::Uint16(value));
                }
            }
            fields::FieldType::Uint64 => {
                if let Ok(value) = header.value.parse::<u64>() {
                    container.add_field(def, Range::new(0, 0), Value::Uint64(value));
                }
            }
            _ => {
                container.add_field(def, Range::new(0, 0), Value::String(header.value.clone()));
            }
        }
    }
    container.add_field(
        &fields::HTTP2_HEADER_UNESCAPED,
        Range::new(0, 0),
        Value::String(header.value.clone()),
    );
    container.add_field(
        &fields::HTTP2_HEADER_REPR,
        Range::new(0, 0),
        Value::String(header.representation.name().to_string()),
    );
    if let Some(index) = header.index {
        container.add_field(
            &fields::HTTP2_HEADER_INDEX,
            Range::new(0, 0),
            Value::Uint32(index),
        );
    }
}

/// The curated `http2.headers.*` definition for a header name.
fn curated_header(name: &str) -> Option<&'static FieldDef> {
    Some(match name {
        ":authority" => &fields::HTTP2_HEADERS_AUTHORITY,
        ":status" => &fields::HTTP2_HEADERS_STATUS,
        ":path" => &fields::HTTP2_HEADERS_PATH,
        ":method" => &fields::HTTP2_HEADERS_METHOD,
        ":scheme" => &fields::HTTP2_HEADERS_SCHEME,
        ":protocol" => &fields::HTTP2_HEADERS_PROTOCOL,
        "accept" => &fields::HTTP2_HEADERS_ACCEPT,
        "accept-charset" => &fields::HTTP2_HEADERS_ACCEPT_CHARSET,
        "accept-encoding" => &fields::HTTP2_HEADERS_ACCEPT_ENCODING,
        "accept-language" => &fields::HTTP2_HEADERS_ACCEPT_LANGUAGE,
        "accept-ranges" => &fields::HTTP2_HEADERS_ACCEPT_RANGES,
        "access-control-allow-origin" => &fields::HTTP2_HEADERS_ACCESS_CONTROL_ALLOW_ORIGIN,
        "age" => &fields::HTTP2_HEADERS_AGE,
        "allow" => &fields::HTTP2_HEADERS_ALLOW,
        "authorization" => &fields::HTTP2_HEADERS_AUTHORIZATION,
        "cache-control" => &fields::HTTP2_HEADERS_CACHE_CONTROL,
        "content-disposition" => &fields::HTTP2_HEADERS_CONTENT_DISPOSITION,
        "content-encoding" => &fields::HTTP2_HEADERS_CONTENT_ENCODING,
        "content-language" => &fields::HTTP2_HEADERS_CONTENT_LANGUAGE,
        "content-length" => &fields::HTTP2_HEADERS_CONTENT_LENGTH,
        "content-location" => &fields::HTTP2_HEADERS_CONTENT_LOCATION,
        "content-range" => &fields::HTTP2_HEADERS_CONTENT_RANGE,
        "content-type" => &fields::HTTP2_HEADERS_CONTENT_TYPE,
        "cookie" => &fields::HTTP2_HEADERS_COOKIE,
        "date" => &fields::HTTP2_HEADERS_DATE,
        "etag" => &fields::HTTP2_HEADERS_ETAG,
        "expect" => &fields::HTTP2_HEADERS_EXPECT,
        "expires" => &fields::HTTP2_HEADERS_EXPIRES,
        "from" => &fields::HTTP2_HEADERS_FROM,
        "if-match" => &fields::HTTP2_HEADERS_IF_MATCH,
        "if-modified-since" => &fields::HTTP2_HEADERS_IF_MODIFIED_SINCE,
        "if-none-match" => &fields::HTTP2_HEADERS_IF_NONE_MATCH,
        "if-range" => &fields::HTTP2_HEADERS_IF_RANGE,
        "if-unmodified-since" => &fields::HTTP2_HEADERS_IF_UNMODIFIED_SINCE,
        "last-modified" => &fields::HTTP2_HEADERS_LAST_MODIFIED,
        "link" => &fields::HTTP2_HEADERS_LINK,
        "location" => &fields::HTTP2_HEADERS_LOCATION,
        "max-forwards" => &fields::HTTP2_HEADERS_MAX_FORWARDS,
        "proxy-authenticate" => &fields::HTTP2_HEADERS_PROXY_AUTHENTICATE,
        "proxy-authorization" => &fields::HTTP2_HEADERS_PROXY_AUTHORIZATION,
        "range" => &fields::HTTP2_HEADERS_RANGE,
        "referer" => &fields::HTTP2_HEADERS_REFERER,
        "refresh" => &fields::HTTP2_HEADERS_REFRESH,
        "retry-after" => &fields::HTTP2_HEADERS_RETRY_AFTER,
        "server" => &fields::HTTP2_HEADERS_SERVER,
        "set-cookie" => &fields::HTTP2_HEADERS_SET_COOKIE,
        "strict-transport-security" => &fields::HTTP2_HEADERS_STRICT_TRANSPORT_SECURITY,
        "user-agent" => &fields::HTTP2_HEADERS_USER_AGENT,
        "vary" => &fields::HTTP2_HEADERS_VARY,
        "via" => &fields::HTTP2_HEADERS_VIA,
        "www-authenticate" => &fields::HTTP2_HEADERS_WWW_AUTHENTICATE,
        _ => return None,
    })
}

/// The reason phrase for a status code.
fn status_reason(code: u16) -> &'static str {
    let text = crate::decode::http::status_description(u32::from(code));
    if text.is_empty() { "Unknown" } else { text }
}

/// Add a generated FT_NONE marker with no value.
fn add_marker(stream: &mut Field, def: &'static FieldDef, showname: &'static str) {
    let field = stream.add_field(def, Range::new(0, 0), Value::None);
    field.showname = Some(showname.to_string());
}

/// Read a big-endian 16-bit value.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes(<[u8; 2]>::try_from(bytes).ok()?))
}

/// Read a big-endian 32-bit value.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes(<[u8; 4]>::try_from(bytes).ok()?))
}

/// Build the raw span for a generated bytes value.
fn raw_field(
    bytes: Vec<u8>,
    start: usize,
    length: usize,
    field_type: u32,
    source: RawSource,
) -> RawField {
    RawField {
        bytes: Bytes::from(bytes),
        start,
        length,
        bitmask: 0,
        field_type,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preface_heuristic_requires_four_octets() {
        assert!(looks_like_http2_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
        assert!(looks_like_http2_prefix(b"PRI "));
        assert!(looks_like_http2_prefix(b"PRI * HTT"));
        assert!(!looks_like_http2_prefix(b"PRI"));
        assert!(!looks_like_http2_prefix(b"POST / HTTP/1.1"));
        assert!(!looks_like_http2_prefix(b"GET / HTTP/1.1"));
    }

    #[test]
    fn ping_is_legal_only_on_stream_zero() {
        let on_zero = [
            0x00, 0x00, 0x08, PING, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let frame = Frame::parse(&on_zero).unwrap_or_else(|| unreachable!("complete PING"));
        assert!(frame_violation(&frame).is_none());
        // RFC 9113 section 6.7: a non-zero stream identifier is a
        // connection error, the reverse of the other connection frames.
        let on_stream_one = [
            0x00, 0x00, 0x08, PING, 0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let frame = Frame::parse(&on_stream_one).unwrap_or_else(|| unreachable!("complete PING"));
        assert!(matches!(
            frame_violation(&frame),
            Some(FrameViolation::Fatal(_))
        ));
    }

    #[test]
    fn frame_parsing_reads_the_declared_length_and_stream_id() {
        let bytes = [
            0x00, 0x00, 0x03, 0x20, 0x05, 0x80, 0x00, 0x00, 0x01, 0xaa, 0xbb, 0xcc,
        ];
        let frame = match Frame::parse(&bytes) {
            Some(frame) => frame,
            None => unreachable!("the frame header is complete"),
        };
        assert_eq!(frame.length, 3);
        assert_eq!(frame.kind, 0x20);
        assert_eq!(frame.flags, 5);
        assert_eq!(frame.stream_id, 1);
        assert!(frame.reserved);
        assert_eq!(frame.payload, &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn a_short_frame_header_is_not_parsed() {
        assert!(Frame::parse(&[0x00, 0x00, 0x01]).is_none());
    }

    #[test]
    fn a_declared_payload_past_the_capture_keeps_the_prefix() {
        let bytes = [0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa];
        let frame = match Frame::parse(&bytes) {
            Some(frame) => frame,
            None => unreachable!("the frame header is complete"),
        };
        assert_eq!(frame.length, 16);
        assert_eq!(frame.payload, &[0xaa]);
    }

    #[test]
    fn padding_is_split_from_the_payload() {
        let payload = [0x02, 0x01, 0x02, 0x03, 0x00, 0x00];
        let (data, padding) = split_payload(&payload, 1, 2);
        assert_eq!(data, &[0x01, 0x02, 0x03]);
        assert_eq!(padding, Some(&[0x00, 0x00][..]));
        let (data, padding) = split_payload(&payload, 1, 9);
        assert_eq!(data, &[0x01, 0x02, 0x03, 0x00, 0x00]);
        assert!(padding.is_none());
    }

    #[test]
    fn the_uri_is_synthesized_from_pseudo_headers() {
        let mut table = hpack::DynamicTable::new();
        let block = hpack::decode_block(
            &[
                0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                0x90, 0xf4, 0xff,
            ],
            &mut table,
            hpack::DEFAULT_TABLE_SIZE,
        );
        let mut summary = HeaderSummary::default();
        for header in block.headers() {
            match header.name.as_str() {
                ":method" => summary.method = Some(header.value.clone()),
                ":path" => summary.path = Some(header.value.clone()),
                _ => {}
            }
        }
        assert_eq!(
            synthesize_uri(&summary, &block).as_deref(),
            Some("http://www.example.com/")
        );
    }

    /// One frame's wire bytes, header and payload.
    fn frame_pdu(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(payload.len()).unwrap_or(0);
        let mut out = Vec::with_capacity(FRAME_HEADER_BYTES.saturating_add(payload.len()));
        out.extend_from_slice(length.to_be_bytes().get(1..).unwrap_or_default());
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// One Ethernet/IPv4/TCP segment between the test endpoints.
    fn segment(
        number: u64,
        sequence: u32,
        from_client: bool,
        payload: &[u8],
    ) -> crate::capture::Frame {
        let (source, source_port, destination, destination_port) = if from_client {
            ([192, 0, 2, 1], 40_000_u16, [192, 0, 2, 2], 80_u16)
        } else {
            ([192, 0, 2, 2], 80_u16, [192, 0, 2, 1], 40_000_u16)
        };
        let mut tcp = Vec::with_capacity(20_usize.saturating_add(payload.len()));
        tcp.extend_from_slice(&source_port.to_be_bytes());
        tcp.extend_from_slice(&destination_port.to_be_bytes());
        tcp.extend_from_slice(&sequence.to_be_bytes());
        tcp.extend_from_slice(&1_u32.to_be_bytes());
        tcp.extend_from_slice(&[0x50, 0x18]);
        tcp.extend_from_slice(&65535_u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(payload);
        let total = u16::try_from(20_usize.saturating_add(tcp.len())).unwrap_or(u16::MAX);
        let mut datagram = vec![0x45, 0];
        datagram.extend_from_slice(&total.to_be_bytes());
        datagram.extend_from_slice(&0_u16.to_be_bytes());
        datagram.extend_from_slice(&0x4000_u16.to_be_bytes());
        datagram.push(64);
        datagram.push(6);
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(&source);
        datagram.extend_from_slice(&destination);
        datagram.extend_from_slice(&tcp);
        let mut captured = Vec::with_capacity(14_usize.saturating_add(datagram.len()));
        captured.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
        captured.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        captured.extend_from_slice(&0x0800_u16.to_be_bytes());
        captured.extend_from_slice(&datagram);
        crate::capture::Frame {
            number,
            timestamp: None,
            timestamp_precision: 6,
            captured,
            original_len: u32::try_from(14_usize.saturating_add(datagram.len()))
                .unwrap_or(u32::MAX),
            link_type: 1,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: None,
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: crate::capture::PacketOptions::default(),
        }
    }

    /// Decode one segment and advance its direction's TCP sequence.
    fn decode_segment(
        session: &mut crate::state::DecodeSession,
        number: u64,
        from_client: bool,
        payload: &[u8],
        sequences: &mut (u32, u32),
    ) -> crate::Packet {
        let sequence = if from_client {
            sequences.0
        } else {
            sequences.1
        };
        let packet = session.decode_at(&segment(number, sequence, from_client, payload), number);
        let next = sequence.saturating_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
        if from_client {
            sequences.0 = next;
        } else {
            sequences.1 = next;
        }
        packet
    }

    /// Decode one payload handed over whole and keep the resulting state.
    ///
    /// The stream framer normally cuts an HTTP/2 payload into one frame per
    /// call; a forced, decrypted or quoted path can hand over the whole
    /// payload, which is what this helper exercises.
    fn decode_payload(data: &[u8]) -> (Node, crate::state::SessionState) {
        let mut state = crate::state::SessionState::new(crate::state::DEFAULT_STATE_BUDGET);
        let options = crate::decode::DecodeOptions::default();
        let mut names = crate::names::NameResolver::new(options.preferences.nameres, Vec::new());
        let mut columns = crate::decode::Columns::default();
        let mut stack = Vec::new();
        let mut malformed = false;
        let mut network = Some(crate::decode::NetworkContext::Ipv4 {
            source: [192, 0, 2, 1],
            destination: [192, 0, 2, 2],
            protocol: 6,
            fragmented: false,
        });
        let mut transport = Some(crate::decode::TransportContext {
            source_port: 40_000,
            destination_port: 80,
            protocol: 6,
        });
        let mut forced_data = false;
        let mut observer = crate::state::NoopObserver;
        let mut data_sources = Vec::new();
        let mut data_source_kinds = Vec::new();
        let mut parent = Node::new(&fields::HTTP2_PROTOCOL, Range::new(0, data.len()));
        {
            let mut context = DecodeContext {
                frame: crate::state::FrameInfo {
                    number: 1,
                    file_number: 1,
                    timestamp: None,
                    time_relative: None,
                    time_delta: None,
                },
                state: &mut state,
                names: &mut names,
                columns: &mut columns,
                protocol_stack: &mut stack,
                malformed: &mut malformed,
                options: &options,
                network: &mut network,
                transport: &mut transport,
                forced_data: &mut forced_data,
                depth: 0,
                tls_plaintext: false,
                tls_record_source: None,
                pdu_bytes: None,
                observe_only: false,
                pass: crate::state::PassMode::One,
                udp_ports: None,
                quoted: false,
                transport_ports: Some((40_000, 80)),
                tcp_stream: None,
                tcp_sequence: None,
                reported_length: data.len(),
                frame_reported_length: data.len(),
                objects: None,
                observer: &mut observer,
                http_last_uri: None,
                http_pdu_offset: 0,
                http_continuation: false,
                http_fin: false,
                data_sources: &mut data_sources,
                data_source_kinds: &mut data_source_kinds,
            };
            decode(&mut context, &mut parent, data, 0);
        }
        (parent, state)
    }

    #[test]
    fn a_payload_above_the_frame_bound_stops_and_reports_once() {
        let mut data = PREFACE.to_vec();
        for _ in 0..MAX_FRAMES_PER_PAYLOAD.saturating_add(16) {
            data.extend_from_slice(&frame_pdu(0x20, 0, 0, &[]));
        }
        let (parent, mut state) = decode_payload(&data);
        assert_eq!(
            parent.children.len(),
            MAX_FRAMES_PER_PAYLOAD.saturating_add(1),
            "the preface node and the capped frames are all that is added"
        );
        assert_eq!(parent.experts.len(), 1, "one expert reports the cap");
        let expert = parent
            .experts
            .first()
            .unwrap_or_else(|| unreachable!("the cap expert"));
        assert_eq!(expert.group, Group::Undecoded);
        assert!(
            expert.message.contains(&MAX_FRAMES_PER_PAYLOAD.to_string()),
            "the message names the limit: {}",
            expert.message
        );
        assert!(
            parent.children.iter().all(|child| child.experts.is_empty()),
            "the frames themselves are decoded without an expert"
        );
        // The skipped frames may have carried table mutations, so the
        // direction's next dynamic reference cannot resolve.
        let (conversation, _) =
            crate::state::ConversationKey::ipv4([192, 0, 2, 1], 40_000, [192, 0, 2, 2], 80);
        let key = Http2Key {
            conversation,
            direction: 0,
        };
        let indexed = state.http2_fragment(
            key,
            1,
            BlockFragment::Headers,
            BlockOrigin {
                frame: 2,
                file: 2,
                time: None,
            },
            &[0xbe],
            true,
        );
        assert_eq!(
            indexed.block.map(|block| block.stop),
            Some(hpack::Stop::Desynchronized),
            "the skipped frames mark the table lost"
        );
    }

    #[test]
    fn a_frame_above_the_acknowledged_max_frame_size_is_malformed() {
        let mut session = crate::state::DecodeSession::new(crate::decode::DecodeOptions::default());
        let mut sequences = (1_u32, 1_u32);
        let mut first = PREFACE.to_vec();
        first.extend_from_slice(&frame_pdu(SETTINGS, 0, 0, &[]));
        let _ = decode_segment(&mut session, 1, true, &first, &mut sequences);
        // The server raises the limit for the frames the client sends.
        let raise = frame_pdu(SETTINGS, 0, 0, &[0, 5, 0, 0, 0x80, 0]);
        let _ = decode_segment(&mut session, 2, false, &raise, &mut sequences);
        let ack = frame_pdu(SETTINGS, FLAG_ACK, 0, &[]);
        let _ = decode_segment(&mut session, 3, true, &ack, &mut sequences);
        // The server lowers the limit again. A 20000-octet frame already in
        // flight stays valid until the client acknowledges the lowering
        // (RFC 9113 section 6.5.3).
        let lower = frame_pdu(SETTINGS, 0, 0, &[0, 5, 0, 0, 0x40, 0]);
        let _ = decode_segment(&mut session, 4, false, &lower, &mut sequences);
        let oversized_payload = [0x41_u8; 20_000];
        let oversized = frame_pdu(0x20, 0, 1, &oversized_payload);
        let in_flight = decode_segment(&mut session, 5, true, &oversized, &mut sequences);
        assert!(!in_flight.malformed, "the lower limit waits for its ACK");
        let ack = frame_pdu(SETTINGS, FLAG_ACK, 0, &[]);
        let _ = decode_segment(&mut session, 6, true, &ack, &mut sequences);
        let rejected = decode_segment(&mut session, 7, true, &oversized, &mut sequences);
        assert!(rejected.malformed, "the acknowledged limit now applies");
        assert!(
            rejected
                .tree
                .fields()
                .flat_map(|field| field.experts.iter())
                .any(|expert| expert.message.contains("FRAME_SIZE_ERROR")),
            "one expert names FRAME_SIZE_ERROR"
        );
    }

    #[test]
    fn a_skipped_oversized_header_frame_marks_the_table_lost() {
        let mut session = crate::state::DecodeSession::new(crate::decode::DecodeOptions::default());
        let mut sequences = (1_u32, 1_u32);
        let mut first = PREFACE.to_vec();
        first.extend_from_slice(&frame_pdu(SETTINGS, 0, 0, &[]));
        let _ = decode_segment(&mut session, 1, true, &first, &mut sequences);
        // A completed block inserts one entry at dynamic index 62.
        let inserted = frame_pdu(
            HEADERS,
            FLAG_END_HEADERS,
            1,
            &[0x40, 0x01, b'a', 0x01, b'1'],
        );
        let packet = decode_segment(&mut session, 2, true, &inserted, &mut sequences);
        assert_eq!(
            packet
                .tree
                .fields()
                .filter(|field| field.def.abbrev == "http2.header")
                .count(),
            1
        );
        // An oversized block that would insert a second entry is skipped
        // whole because its declared length exceeds SETTINGS_MAX_FRAME_SIZE.
        let mut skipped_payload = vec![0x40, 0x01, b'b', 0x01, b'2'];
        skipped_payload.resize(20_000, 0x41);
        let skipped = frame_pdu(HEADERS, FLAG_END_HEADERS, 3, &skipped_payload);
        let packet = decode_segment(&mut session, 3, true, &skipped, &mut sequences);
        assert!(packet.malformed);
        // Index 62 would resolve the first entry if the skip had not marked
        // the table lost; the block reports the desynchronized table instead.
        let indexed = frame_pdu(HEADERS, FLAG_END_HEADERS, 5, &[0xbe]);
        let packet = decode_segment(&mut session, 4, true, &indexed, &mut sequences);
        assert!(
            !packet.malformed,
            "a lost table is a warning, not malformed"
        );
        assert_eq!(
            packet
                .tree
                .fields()
                .filter(|field| field.def.abbrev == "http2.header")
                .count(),
            0,
            "the stale entry must not resolve"
        );
        assert!(
            packet
                .tree
                .fields()
                .flat_map(|field| field.experts.iter())
                .any(|expert| expert.group == Group::Undecoded
                    && expert.message.contains("dynamic table lost")),
            "the block reports the lost table"
        );
    }
}
