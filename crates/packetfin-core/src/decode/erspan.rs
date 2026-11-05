//! Cisco ERSPAN shim headers and frame dispatch.
//!
//! ERSPAN type I has no shim header: the GRE payload is an Ethernet frame.
//! Types II and III start with a version nibble that selects their layout
//! (Cisco ERSPAN draft-foschiano-erspan section 3). Type II (version 1) has
//! VLAN, COS/encapsulation/truncation/SPAN-ID, and reserved/INDEX words;
//! type III (version 2) has VLAN, COS/integrity/truncation/SPAN-ID, a
//! 32-bit timestamp, a security group tag and a flag word, followed by an
//! optional eight-octet platform sub-header. The version nibble is read
//! before any other field so a short or unknown header never reads past the
//! captured bytes.

use crate::decode::bytes::{read_u16_be, read_u32_be};
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const VERSION_OFFSET: usize = 0;
const TYPE_TWO_HEADER_LENGTH: usize = 8;
const TYPE_THREE_BASE_LENGTH: usize = 12;
const PLATFORM_SUBHEADER_LENGTH: usize = 8;

const FRAME_TYPE_ETHERNET: u16 = 0;

/// Decode an ERSPAN payload that starts with a shim header.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::ERSPAN_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::ERSPAN_PROTOCOL, Range::new(base, data.len()));

    let Some(version_word) = read_u16_be(data, VERSION_OFFSET) else {
        context.mark_malformed(&mut node, "ERSPAN header is shorter than its version");
        finish(context, parent, node);
        return;
    };
    let version = version_word >> 12;
    add_range_field(
        &mut node,
        &fields::ERSPAN_VERSION,
        base + VERSION_OFFSET,
        2,
        Value::Uint16(version),
    );

    let payload_offset = match version {
        1 => decode_type_two(context, &mut node, data, base),
        2 => decode_type_three(context, &mut node, data, base),
        _ => {
            // Repeat the version field ahead of the unknown-version marker.
            add_range_field(
                &mut node,
                &fields::ERSPAN_VERSION,
                base + VERSION_OFFSET,
                2,
                Value::Uint16(version),
            );
            node.add_field(
                &fields::ERSPAN_VERSION_UNKNOWN,
                Range::new(base, 0),
                Value::None,
            );
            node.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Undecoded,
                message: "Unknown version, please report or test to use fake ERSPAN preference"
                    .to_string(),
            });
            None
        }
    };

    if let Some((offset, frame_type)) = payload_offset
        && frame_type == FRAME_TYPE_ETHERNET
    {
        let payload = data.get(offset..).unwrap_or(&[]);
        decode::dispatch(
            context,
            &mut node,
            Some(fields::Protocol::Ethernet),
            payload,
            base + offset,
        );
    }

    finish(context, parent, node);
}

/// Decode an ERSPAN type I payload: the GRE payload is the Ethernet frame.
pub(crate) fn decode_type_one(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::ERSPAN_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::ERSPAN_PROTOCOL, Range::new(base, 0));
    decode::dispatch(
        context,
        &mut node,
        Some(fields::Protocol::Ethernet),
        data,
        base,
    );
    finish(context, parent, node);
}

/// Decode the type II (version 1) header. Returns the payload offset and
/// frame type.
fn decode_type_two(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
) -> Option<(usize, u16)> {
    let Some(vlan_word) = read_u16_be(data, 0) else {
        context.mark_malformed(node, "ERSPAN type II header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_VLAN,
        base,
        2,
        Value::Uint16(vlan_word & 0x0fff),
    );
    let Some(word) = read_u16_be(data, 2) else {
        context.mark_malformed(node, "ERSPAN type II header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_COS,
        base + 2,
        2,
        Value::Uint16((word >> 13) & 0x7),
    );
    add_range_field(
        node,
        &fields::ERSPAN_ENCAP,
        base + 2,
        2,
        Value::Uint16((word >> 11) & 0x3),
    );
    add_range_field(
        node,
        &fields::ERSPAN_TRUNCATED,
        base + 2,
        2,
        Value::Uint16((word >> 10) & 0x1),
    );
    add_range_field(
        node,
        &fields::ERSPAN_SPANID,
        base + 2,
        2,
        Value::Uint16(word & 0x03ff),
    );
    let Some(index_word) = read_u32_be(data, 4) else {
        context.mark_malformed(node, "ERSPAN type II header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_RESERVED,
        base + 4,
        4,
        Value::Uint32((index_word >> 20) & 0x0fff),
    );
    add_range_field(
        node,
        &fields::ERSPAN_INDEX,
        base + 4,
        4,
        Value::Uint32(index_word & 0x000f_ffff),
    );
    Some((TYPE_TWO_HEADER_LENGTH, FRAME_TYPE_ETHERNET))
}

/// Decode the type III (version 2) header and optional platform sub-header.
fn decode_type_three(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
) -> Option<(usize, u16)> {
    let Some(vlan_word) = read_u16_be(data, 0) else {
        context.mark_malformed(node, "ERSPAN type III header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_VLAN,
        base,
        2,
        Value::Uint16(vlan_word & 0x0fff),
    );
    let Some(word) = read_u16_be(data, 2) else {
        context.mark_malformed(node, "ERSPAN type III header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_COS,
        base + 2,
        2,
        Value::Uint16((word >> 13) & 0x7),
    );
    add_range_field(
        node,
        &fields::ERSPAN_BSO,
        base + 2,
        2,
        Value::Uint16((word >> 11) & 0x3),
    );
    add_range_field(
        node,
        &fields::ERSPAN_TRUNCATED,
        base + 2,
        2,
        Value::Uint16((word >> 10) & 0x1),
    );
    add_range_field(
        node,
        &fields::ERSPAN_SPANID,
        base + 2,
        2,
        Value::Uint16(word & 0x03ff),
    );
    let Some(timestamp) = read_u32_be(data, 4) else {
        context.mark_malformed(node, "ERSPAN type III header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_TIMESTAMP,
        base + 4,
        4,
        Value::Uint32(timestamp),
    );
    let Some(sgt) = read_u16_be(data, 8) else {
        context.mark_malformed(node, "ERSPAN type III header is truncated");
        return None;
    };
    add_range_field(node, &fields::ERSPAN_SGT, base + 8, 2, Value::Uint16(sgt));
    let Some(flags) = read_u16_be(data, 10) else {
        context.mark_malformed(node, "ERSPAN type III header is truncated");
        return None;
    };
    add_range_field(
        node,
        &fields::ERSPAN_P,
        base + 10,
        2,
        Value::Uint16((flags >> 15) & 0x1),
    );
    add_range_field(
        node,
        &fields::ERSPAN_FT,
        base + 10,
        2,
        Value::Uint16((flags >> 10) & 0x1f),
    );
    add_range_field(
        node,
        &fields::ERSPAN_HW,
        base + 10,
        2,
        Value::Uint16((flags >> 4) & 0x3f),
    );
    add_range_field(
        node,
        &fields::ERSPAN_DIRECTION,
        base + 10,
        2,
        Value::Boolean(flags & 0x0008 != 0),
    );
    add_range_field(
        node,
        &fields::ERSPAN_GRA,
        base + 10,
        2,
        Value::Uint16((flags >> 1) & 0x3),
    );
    add_range_field(
        node,
        &fields::ERSPAN_O,
        base + 10,
        2,
        Value::Uint16(flags & 0x1),
    );
    if flags & 0x1 != 0 {
        if !decode_platform_subheader(context, node, data, base, TYPE_THREE_BASE_LENGTH) {
            return None;
        }
        return Some((
            TYPE_THREE_BASE_LENGTH + PLATFORM_SUBHEADER_LENGTH,
            (flags >> 10) & 0x1f,
        ));
    }
    Some((TYPE_THREE_BASE_LENGTH, (flags >> 10) & 0x1f))
}

/// Decode the optional eight-octet platform sub-header selected by its
/// top six bits. Ids without a defined layout decode as reserved.
fn decode_platform_subheader(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
) -> bool {
    let Some(first) = read_u32_be(data, offset) else {
        context.mark_malformed(node, "ERSPAN platform sub-header is truncated");
        return false;
    };
    let platform = first >> 26;
    add_range_field(
        node,
        &fields::ERSPAN_PLATID,
        base + offset,
        4,
        Value::Uint32(platform),
    );
    match platform {
        1 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID1_RSVD1,
                base + offset,
                4,
                Value::Uint32((first >> 12) & 0x3fff),
            );
            add_range_field(
                node,
                &fields::ERSPAN_PID1_VSMID,
                base + offset,
                4,
                Value::Uint32(first & 0x0fff),
            );
        }
        3 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID3_RSVD1,
                base + offset,
                4,
                Value::Uint32((first >> 14) & 0xfff),
            );
            add_range_field(
                node,
                &fields::ERSPAN_PID3_PORT_INDEX,
                base + offset,
                4,
                Value::Uint32(first & 0x3fff),
            );
        }
        4 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID4_RSVD1,
                base + offset,
                4,
                Value::Uint32((first >> 14) & 0xfff),
            );
            add_range_field(
                node,
                &fields::ERSPAN_PID4_RSVD2,
                base + offset,
                4,
                Value::Uint32(first & 0x3fff),
            );
        }
        5 | 6 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID5_SWITCHID,
                base + offset,
                4,
                Value::Uint32((first >> 16) & 0x03ff),
            );
            add_range_field(
                node,
                &fields::ERSPAN_PID5_PORT_INDEX,
                base + offset,
                4,
                Value::Uint32(first & 0xffff),
            );
        }
        0 | 7 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID7_RSVD1,
                base + offset,
                4,
                Value::Uint32((first >> 20) & 0x3f),
            );
            add_range_field(
                node,
                &fields::ERSPAN_PID7_SOURCE_INDEX,
                base + offset,
                4,
                Value::Uint32(first & 0x000f_ffff),
            );
        }
        _ => {}
    }
    let Some(second) = read_u32_be(data, offset.saturating_add(4)) else {
        context.mark_malformed(node, "ERSPAN platform sub-header is truncated");
        return false;
    };
    match platform {
        1 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID1_PORT_INDEX,
                base + offset + 4,
                4,
                Value::Uint32(second),
            );
        }
        3 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID3_TIMESTAMP,
                base + offset + 4,
                4,
                Value::Uint32(second),
            );
        }
        4 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID4_RSVD3,
                base + offset + 4,
                4,
                Value::Uint32(second),
            );
        }
        5 | 6 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID5_TIMESTAMP,
                base + offset + 4,
                4,
                Value::Uint32(second),
            );
        }
        0 | 7 => {
            add_range_field(
                node,
                &fields::ERSPAN_PID7_TIMESTAMP,
                base + offset + 4,
                4,
                Value::Uint32(second),
            );
        }
        _ => {
            add_range_field(
                node,
                &fields::ERSPAN_PID_RSVD,
                base + offset,
                8,
                Value::Uint64(u64::from(second) & 0x03ff_ffff),
            );
        }
    }
    true
}

fn add_range_field(
    node: &mut Node,
    def: &'static fields::FieldDef,
    offset: usize,
    length: usize,
    value: Value,
) {
    node.add_field(def, Range::new(offset, length), value);
}

fn finish(context: &mut DecodeContext<'_>, parent: &mut Node, node: Node) {
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
