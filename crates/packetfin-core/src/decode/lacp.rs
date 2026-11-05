//! IEEE 802.3ad Link Aggregation Control Protocol.
//!
//! The slow-protocol header is followed by a one-byte version and a list of
//! TLVs (IEEE 802.3-2018 clause 43.4.2). The length of the actor, partner and
//! collector TLVs includes the type and length octets themselves, so a
//! valid actor or partner record holds 18 content octets and a collector
//! record holds 14. A zero type and zero length terminate the list.

use crate::decode::DecodeContext;
use crate::decode::bytes::{array, read_u16_be};
use crate::fields;
use crate::tree::{Node, Range, Value};

const VERSION_OFFSET: usize = 0;
const TLV_OFFSET: usize = 1;
const TLV_HEADER_LENGTH: usize = 2;
const ACTOR_LENGTH: u8 = 20;
const PARTNER_LENGTH: u8 = 20;
const COLLECTOR_LENGTH: u8 = 16;
const INFORMATION_LENGTH: usize = 18;
const COLLECTOR_CONTENT_LENGTH: usize = 14;

const STATE_ACTIVITY: u8 = 0x01;
const STATE_TIMEOUT: u8 = 0x02;
const STATE_AGGREGATION: u8 = 0x04;
const STATE_SYNCHRONIZATION: u8 = 0x08;
const STATE_COLLECTING: u8 = 0x10;
const STATE_DISTRIBUTING: u8 = 0x20;
const STATE_DEFAULTED: u8 = 0x40;
const STATE_EXPIRED: u8 = 0x80;

const ACTOR_STATE_BITS: [(&fields::FieldDef, u8); 8] = [
    (&fields::LACP_ACTOR_STATE_ACTIVITY, STATE_ACTIVITY),
    (&fields::LACP_ACTOR_STATE_TIMEOUT, STATE_TIMEOUT),
    (&fields::LACP_ACTOR_STATE_AGGREGATION, STATE_AGGREGATION),
    (
        &fields::LACP_ACTOR_STATE_SYNCHRONIZATION,
        STATE_SYNCHRONIZATION,
    ),
    (&fields::LACP_ACTOR_STATE_COLLECTING, STATE_COLLECTING),
    (&fields::LACP_ACTOR_STATE_DISTRIBUTING, STATE_DISTRIBUTING),
    (&fields::LACP_ACTOR_STATE_DEFAULTED, STATE_DEFAULTED),
    (&fields::LACP_ACTOR_STATE_EXPIRED, STATE_EXPIRED),
];

const PARTNER_STATE_BITS: [(&fields::FieldDef, u8); 8] = [
    (&fields::LACP_PARTNER_STATE_ACTIVITY, STATE_ACTIVITY),
    (&fields::LACP_PARTNER_STATE_TIMEOUT, STATE_TIMEOUT),
    (&fields::LACP_PARTNER_STATE_AGGREGATION, STATE_AGGREGATION),
    (
        &fields::LACP_PARTNER_STATE_SYNCHRONIZATION,
        STATE_SYNCHRONIZATION,
    ),
    (&fields::LACP_PARTNER_STATE_COLLECTING, STATE_COLLECTING),
    (&fields::LACP_PARTNER_STATE_DISTRIBUTING, STATE_DISTRIBUTING),
    (&fields::LACP_PARTNER_STATE_DEFAULTED, STATE_DEFAULTED),
    (&fields::LACP_PARTNER_STATE_EXPIRED, STATE_EXPIRED),
];

/// Decode one LACP PDU into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::LACP_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::LACP_PROTOCOL, Range::new(base, data.len()));
    let Some(version) = data.get(VERSION_OFFSET).copied() else {
        context.mark_malformed(&mut node, "LACP PDU is missing its version");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    node.add_field(
        &fields::LACP_VERSION,
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
        node.add_field(&fields::LACP_TLV_TYPE, type_range, Value::Uint8(kind));
        let length_range = Range::new(base.saturating_add(offset).saturating_add(1), 1);
        node.add_field(&fields::LACP_TLV_LENGTH, length_range, Value::Uint8(length));
        if kind == 0 && length == 0 {
            break;
        }
        let content_start = offset.saturating_add(TLV_HEADER_LENGTH);
        let content_length = usize::from(length).saturating_sub(TLV_HEADER_LENGTH);
        let expected = match kind {
            1 => Some((ACTOR_LENGTH, INFORMATION_LENGTH)),
            2 => Some((PARTNER_LENGTH, INFORMATION_LENGTH)),
            3 => Some((COLLECTOR_LENGTH, COLLECTOR_CONTENT_LENGTH)),
            _ => None,
        };
        let Some((expected_length, expected_content)) = expected else {
            node.add_field(&fields::LACP_WRONG_TLV_TYPE, type_range, Value::None);
            context.mark_field_malformed(&mut node, "LACP TLV has an unexpected type");
            break;
        };
        if length != expected_length || content_length != expected_content {
            node.add_field(&fields::LACP_WRONG_TLV_LENGTH, length_range, Value::None);
            context.mark_field_malformed(&mut node, "LACP TLV has an unexpected length");
            break;
        }
        let Some(content) = data.get(content_start..content_start.saturating_add(content_length))
        else {
            context.mark_malformed(&mut node, "LACP TLV is truncated");
            break;
        };
        let content_base = base.saturating_add(content_start);
        let parsed = match kind {
            1 => decode_information(&mut node, content, content_base, true),
            2 => decode_information(&mut node, content, content_base, false),
            3 => decode_collector(&mut node, content, content_base),
            _ => false,
        };
        if !parsed {
            context.mark_malformed(&mut node, "LACP TLV is truncated");
            break;
        }
        offset = content_start.saturating_add(content_length);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn decode_information(node: &mut Node, content: &[u8], base: usize, actor: bool) -> bool {
    let Some(system_priority) = read_u16_be(content, 0) else {
        return false;
    };
    let Some(system_id) = array::<6>(content, 2) else {
        return false;
    };
    let Some(key) = read_u16_be(content, 8) else {
        return false;
    };
    let Some(port_priority) = read_u16_be(content, 10) else {
        return false;
    };
    let Some(port) = read_u16_be(content, 12) else {
        return false;
    };
    let Some(state) = content.get(14).copied() else {
        return false;
    };
    let (bits, state_str) = if actor {
        (&ACTOR_STATE_BITS, &fields::LACP_ACTOR_STATE_STR)
    } else {
        (&PARTNER_STATE_BITS, &fields::LACP_PARTNER_STATE_STR)
    };
    let (priority_field, sysid_field, key_field, port_priority_field, port_field, state_field) =
        if actor {
            (
                &fields::LACP_ACTOR_SYS_PRIORITY,
                &fields::LACP_ACTOR_SYSID,
                &fields::LACP_ACTOR_KEY,
                &fields::LACP_ACTOR_PORT_PRIORITY,
                &fields::LACP_ACTOR_PORT,
                &fields::LACP_ACTOR_STATE,
            )
        } else {
            (
                &fields::LACP_PARTNER_SYS_PRIORITY,
                &fields::LACP_PARTNER_SYSID,
                &fields::LACP_PARTNER_KEY,
                &fields::LACP_PARTNER_PORT_PRIORITY,
                &fields::LACP_PARTNER_PORT,
                &fields::LACP_PARTNER_STATE,
            )
        };
    node.add_field(
        priority_field,
        Range::new(base, 2),
        Value::Uint16(system_priority),
    );
    node.add_field(
        sysid_field,
        Range::new(base.saturating_add(2), 6),
        Value::Ethernet(system_id),
    );
    node.add_field(
        key_field,
        Range::new(base.saturating_add(8), 2),
        Value::Uint16(key),
    );
    node.add_field(
        port_priority_field,
        Range::new(base.saturating_add(10), 2),
        Value::Uint16(port_priority),
    );
    node.add_field(
        port_field,
        Range::new(base.saturating_add(12), 2),
        Value::Uint16(port),
    );
    let state_range = Range::new(base.saturating_add(14), 1);
    node.add_field(state_field, state_range, Value::Uint8(state));
    for (field, mask) in bits {
        node.add_field(field, state_range, Value::Boolean(state & mask != 0));
    }
    node.add_field(state_str, state_range, Value::String(state_text(state)));
    let reserved = content.get(15..).unwrap_or(&[]);
    let reserved_field = if actor {
        &fields::LACP_ACTOR_RESERVED
    } else {
        &fields::LACP_PARTNER_RESERVED
    };
    node.add_field(
        reserved_field,
        Range::new(base.saturating_add(15), reserved.len()),
        Value::bytes(reserved.to_vec()),
    );
    true
}

fn decode_collector(node: &mut Node, content: &[u8], base: usize) -> bool {
    let Some(max_delay) = read_u16_be(content, 0) else {
        return false;
    };
    node.add_field(
        &fields::LACP_COLLECTOR_MAX_DELAY,
        Range::new(base, 2),
        Value::Uint16(max_delay),
    );
    let reserved = content.get(2..).unwrap_or(&[]);
    node.add_field(
        &fields::LACP_COLL_RESERVED,
        Range::new(base.saturating_add(2), reserved.len()),
        Value::bytes(reserved.to_vec()),
    );
    // The trailing reserved field is twelve octets; a short record is
    // truncated even when the leading fields were present.
    reserved.len() == COLLECTOR_CONTENT_LENGTH.saturating_sub(2)
}

/// Render the eight LACP state characters, from the most significant bit down.
fn state_text(state: u8) -> String {
    let mut text = String::with_capacity(8);
    text.push(if state & STATE_EXPIRED != 0 { 'E' } else { '*' });
    text.push(if state & STATE_DEFAULTED != 0 {
        'F'
    } else {
        '*'
    });
    text.push(if state & STATE_DISTRIBUTING != 0 {
        'D'
    } else {
        '*'
    });
    text.push(if state & STATE_COLLECTING != 0 {
        'C'
    } else {
        '*'
    });
    text.push(if state & STATE_SYNCHRONIZATION != 0 {
        'S'
    } else {
        '*'
    });
    text.push(if state & STATE_AGGREGATION != 0 {
        'G'
    } else {
        '*'
    });
    text.push(if state & STATE_TIMEOUT != 0 { 'S' } else { '*' });
    text.push(if state & STATE_ACTIVITY != 0 {
        'A'
    } else {
        '*'
    });
    text
}
