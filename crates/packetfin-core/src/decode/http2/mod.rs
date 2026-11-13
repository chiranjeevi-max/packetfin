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
use crate::state::{BodyFragmentView, Http2Key};
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
const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest SETTINGS_MAX_FRAME_SIZE a peer may announce (RFC 9113 6.5.2).
const MAX_MAX_FRAME_SIZE: u32 = 0x00ff_ffff;

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
const FLAG_END_HEADERS: u8 = 0x04;
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
        let remaining = data.get(offset..).unwrap_or_default();
        let Some(frame) = Frame::parse(remaining) else {
            // A frame header cut short: keep the frames already decoded and
            // stop, the way a truncated PDU is dropped by the stream layer.
            break;
        };
        let frame_base = base.saturating_add(offset);
        let complete = frame.payload.len() == usize::try_from(frame.length).unwrap_or(usize::MAX);
        let payload = frame.payload;
        let summary = add_frame(context, parent, &frame, frame_base, key);
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
    stream.add_field(
        &fields::HTTP2_LENGTH,
        Range::new(base, 3),
        Value::Uint24(frame.length),
    );
    let type_field = stream.add_field(
        &fields::HTTP2_TYPE,
        Range::new(base.saturating_add(3), 1),
        Value::Uint8(frame.kind),
    );
    type_field.showname = Some(match frame_type_name(frame.kind) {
        Some(name) => format!("Type: {name} ({})", frame.kind),
        None => format!("Type: Unknown ({})", frame.kind),
    });
    let flags_range = Range::new(base.saturating_add(4), 1);
    let flags = stream.add_field(&fields::HTTP2_FLAGS, flags_range, Value::Uint8(frame.flags));
    flags.container = true;
    let mut label = format!("Flags: 0x{:02x}", frame.flags);
    for name in flag_names(frame.kind, frame.flags) {
        label.push_str(", ");
        label.push_str(name);
    }
    flags.showname = Some(label);
    let (unused, booleans): (&'static FieldDef, &[(&'static FieldDef, u8)]) = match frame.kind {
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
    let masked = u64::from(frame.flags) & mask;
    let unused_value = u8::try_from(masked).unwrap_or(0);
    let unused_field = flags.add_field(unused, flags_range, Value::Uint8(unused_value));
    unused_field.showname = Some(format!(
        "{} = Unused: 0x{unused_value:02x}",
        bit_pattern(u64::from(frame.flags), mask, 8)
    ));
    for (def, flag) in booleans {
        let flag = *flag;
        let set = frame.flags & flag != 0;
        let boolean = flags.add_field(def, flags_range, Value::Boolean(set));
        boolean.showname = Some(format!(
            "{} = {}: {}",
            bit_pattern(u64::from(frame.flags), u64::from(flag), 8),
            def.name,
            if set { "True" } else { "False" }
        ));
    }
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
        && let outcome = context.state.http2_data(
            key,
            frame.stream_id,
            &[],
            true,
            context.frame.number,
            context.frame.file_number,
        )
        && let Some(body) = outcome.data
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
    let mut offset = 0_usize;
    let pad = pad_length(frame, stream, payload_base, &mut offset);
    if frame.flags & FLAG_PRIORITY != 0 {
        add_priority(
            stream,
            frame.payload.get(offset..),
            payload_base.saturating_add(offset),
        );
        offset = offset.saturating_add(5);
    }
    let (fragment, padding) = split_payload(frame.payload, offset, pad);
    let fragment_base = payload_base.saturating_add(offset);
    add_fragment(stream, &fields::HTTP2_HEADERS, fragment, fragment_base);
    let end_headers = frame.flags & FLAG_END_HEADERS != 0;
    if let Some(key) = key {
        let result =
            context
                .state
                .http2_fragment(key, frame.stream_id, false, fragment, end_headers);
        if result.overflow {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block exceeds the 1 MiB bound",
            );
        }
        if result.unexpected {
            stream.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: "CONTINUATION for a different stream".to_string(),
            });
        }
        if let Some(block) = result.block {
            add_header_block(context, stream, &block, key, frame.stream_id, false, suffix);
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
        let result =
            context
                .state
                .http2_fragment(key, frame.stream_id, true, fragment, end_headers);
        if result.overflow {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block exceeds the 1 MiB bound",
            );
        }
        if let Some(block) = result.block {
            let request =
                add_header_block(context, stream, &block, key, frame.stream_id, true, suffix);
            // The promise's own stream keeps its request URI; the expected
            // output prints it after the promised request URI.
            add_stream_uri(context, stream, frame.stream_id, Some(key), false);
            if let Some(request) = request
                && promised != 0
            {
                let conversation = key.conversation;
                context.state.http2_record_request(
                    conversation,
                    promised,
                    u32::try_from(context.frame.number).unwrap_or(u32::MAX),
                    u32::try_from(context.frame.file_number).unwrap_or(u32::MAX),
                    context.frame.timestamp,
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
        let result =
            context
                .state
                .http2_fragment(key, frame.stream_id, false, fragment, end_headers);
        if result.overflow {
            field_malformed(
                context,
                stream,
                "HTTP/2 header block exceeds the 1 MiB bound",
            );
        }
        if result.unexpected {
            stream.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: "CONTINUATION without an open header block".to_string(),
            });
        }
        if let Some(block) = result.block {
            add_header_block(context, stream, &block, key, frame.stream_id, false, suffix);
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
    let mut assembled: Option<Vec<u8>> = None;
    let mut dropped = false;
    let mut windows = None;
    if let Some(key) = key {
        let outcome = context.state.http2_data(
            key,
            frame.stream_id,
            data,
            end_stream,
            context.frame.number,
            context.frame.file_number,
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
    let mut offset = 0_usize;
    while let (Some(id), Some(value)) = (
        read_u16(frame.payload, offset),
        read_u32(frame.payload, offset.saturating_add(2)),
    ) {
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
    let increment = stream.add_field(
        &fields::HTTP2_WINDOW_UPDATE_WINDOW_SIZE_INCREMENT,
        range,
        Value::Uint32(word & 0x7fff_ffff),
    );
    increment.showname = Some(format!(
        "{} = Window Size Increment: {}",
        bit_pattern(u64::from(word), 0x7fff_ffff, 32),
        word & 0x7fff_ffff
    ));
    if let Some(key) = key {
        let (before, after) = context.state.http2_window_update(
            key,
            frame.stream_id,
            word & 0x7fff_ffff,
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
    while let Some(length) = read_u16(frame.payload, offset) {
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
    key: Http2Key,
    stream_id: u32,
    push: bool,
    suffix: &mut Suffix,
) -> Option<HeaderSummary> {
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
    }
    let conversation = key.conversation;
    if let Some(status) = summary.status {
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
        let reason = status_reason(status);
        suffix.text = format!(", {status} {reason}");
    } else if let (Some(method), Some(path)) = (&summary.method, &summary.path) {
        suffix.text = format!(", {method} {path}");
        if !push {
            let uri = summary.uri.clone();
            context.state.http2_record_request(
                conversation,
                stream_id,
                u32::try_from(context.frame.number).unwrap_or(u32::MAX),
                u32::try_from(context.frame.file_number).unwrap_or(u32::MAX),
                context.frame.timestamp,
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
}
