//! IEEE 802.3ad Link Aggregation Marker Protocol.
//!
//! The marker PDU shares the slow-protocol subtype and version header with
//! LACP. Its one-byte TLV length counts the sixteen content octets only
//! (IEEE 802.3-2018 clause 43.5.2), unlike LACP's length field.

use crate::decode::DecodeContext;
use crate::decode::bytes::{array, read_u16_be, read_u32_be};
use crate::fields;
use crate::tree::{Node, Range, Value};

const VERSION_OFFSET: usize = 0;
const TLV_OFFSET: usize = 1;
const TLV_HEADER_LENGTH: usize = 2;
/// TLV length including the type and length octets (IEEE 802.3-2018 43.5.2).
const MARKER_LENGTH: u8 = 16;
const MARKER_CONTENT_LENGTH: usize = 14;

/// Decode one marker PDU into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::MARKER_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::MARKER_PROTOCOL, Range::new(base, data.len()));
    let Some(version) = data.get(VERSION_OFFSET).copied() else {
        context.mark_malformed(&mut node, "Marker PDU is missing its version");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    node.add_field(
        &fields::MARKER_VERSION,
        Range::new(base.saturating_add(VERSION_OFFSET), 1),
        Value::Uint8(version),
    );

    let mut offset = TLV_OFFSET;
    while offset.saturating_add(TLV_HEADER_LENGTH) <= data.len() {
        let Some(kind) = data.get(offset).copied() else {
            break;
        };
        let Some(length) = data.get(offset.saturating_add(1)).copied() else {
            break;
        };
        let type_range = Range::new(base.saturating_add(offset), 1);
        node.add_field(&fields::MARKER_TLV_TYPE, type_range, Value::Uint8(kind));
        let length_range = Range::new(base.saturating_add(offset).saturating_add(1), 1);
        node.add_field(&fields::MARKER_TLV_LEN, length_range, Value::Uint8(length));
        if kind == 0 && length == 0 {
            break;
        }
        if !matches!(kind, 1 | 2) {
            node.add_field(&fields::MARKER_WRONG_TLV_TYPE, type_range, Value::None);
            break;
        }
        if length != MARKER_LENGTH {
            node.add_field(&fields::MARKER_WRONG_TLV_LENGTH, length_range, Value::None);
        }
        let content_start = offset.saturating_add(TLV_HEADER_LENGTH);
        let content_end = content_start
            .saturating_add(MARKER_CONTENT_LENGTH)
            .min(data.len());
        let Some(content) = data.get(content_start..content_end) else {
            context.mark_malformed(&mut node, "Marker TLV is truncated");
            break;
        };
        let complete = content.len() == MARKER_CONTENT_LENGTH;
        if !decode_marker_tlv(&mut node, content, base.saturating_add(content_start)) {
            context.mark_malformed(&mut node, "Marker TLV is truncated");
            break;
        }
        if !complete {
            context.mark_malformed(&mut node, "Marker TLV is truncated");
            break;
        }
        offset =
            content_start.saturating_add(usize::from(length).saturating_sub(TLV_HEADER_LENGTH));
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn decode_marker_tlv(node: &mut Node, content: &[u8], base: usize) -> bool {
    let Some(port) = read_u16_be(content, 0) else {
        return false;
    };
    node.add_field(
        &fields::MARKER_REQUESTER_PORT,
        Range::new(base, 2),
        Value::Uint16(port),
    );
    let Some(system) = array::<6>(content, 2) else {
        return false;
    };
    node.add_field(
        &fields::MARKER_REQUESTER_SYSTEM,
        Range::new(base.saturating_add(2), 6),
        Value::Ethernet(system),
    );
    let Some(transaction) = read_u32_be(content, 8) else {
        return false;
    };
    node.add_field(
        &fields::MARKER_REQUESTER_TRANS_ID,
        Range::new(base.saturating_add(8), 4),
        Value::Uint32(transaction),
    );
    let Some(pad) = read_u16_be(content, 12) else {
        return false;
    };
    node.add_field(
        &fields::MARKER_REQUESTER_PAD,
        Range::new(base.saturating_add(12), 2),
        Value::Uint32(u32::from(pad)),
    );
    if pad != 0 {
        node.add_field(
            &fields::MARKER_WRONG_PAD_VALUE,
            Range::new(base.saturating_add(12), 0),
            Value::None,
        );
    }
    true
}
