//! Virtual eXtensible Local Area Network.
//!
//! RFC 7348 section 5 defines the eight-octet VXLAN header: a flags word
//! whose I bit marks a valid VNI, a group-policy ID used by the GBP
//! extension, the 24-bit VNI and one reserved octet. The payload is always
//! an Ethernet frame. Both the IANA port 4789 and the Linux default port 8472
//! select this decoder.

use crate::decode::bytes::{read_u16_be, read_u24_be};
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const HEADER_LENGTH: usize = 8;
const FLAGS_OFFSET: usize = 0;
const GBP_OFFSET: usize = 2;
const VNI_OFFSET: usize = 4;
const RESERVED_OFFSET: usize = 7;

const FLAG_GBP_EXTENSION: u16 = 0x8000;
const FLAG_VNI_PRESENT: u16 = 0x0800;
const FLAG_DONT_LEARN: u16 = 0x0040;
const FLAG_POLICY_APPLIED: u16 = 0x0008;
const RESERVED_FLAGS_MASK: u16 = 0x77b7;

/// Decode one VXLAN header and its Ethernet payload.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::VXLAN_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::VXLAN_PROTOCOL, Range::new(base, data.len()));

    let Some(flags) = read_u16_be(data, FLAGS_OFFSET) else {
        context.mark_malformed(&mut node, "VXLAN header is shorter than its flags");
        finish(context, parent, node);
        return;
    };
    node.add_field(
        &fields::VXLAN_FLAGS,
        Range::new(base + FLAGS_OFFSET, 2),
        Value::Uint16(flags),
    );
    node.add_field(
        &fields::VXLAN_FLAGS_RESERVED,
        Range::new(base + FLAGS_OFFSET, 2),
        Value::Uint16(flags & RESERVED_FLAGS_MASK),
    );
    node.add_field(
        &fields::VXLAN_FLAG_G,
        Range::new(base + FLAGS_OFFSET, 2),
        Value::Boolean(flags & FLAG_GBP_EXTENSION != 0),
    );
    node.add_field(
        &fields::VXLAN_FLAG_I,
        Range::new(base + FLAGS_OFFSET, 2),
        Value::Boolean(flags & FLAG_VNI_PRESENT != 0),
    );
    node.add_field(
        &fields::VXLAN_FLAG_D,
        Range::new(base + FLAGS_OFFSET, 2),
        Value::Boolean(flags & FLAG_DONT_LEARN != 0),
    );
    node.add_field(
        &fields::VXLAN_FLAG_A,
        Range::new(base + FLAGS_OFFSET, 2),
        Value::Boolean(flags & FLAG_POLICY_APPLIED != 0),
    );

    if let Some(gbp) = read_u16_be(data, GBP_OFFSET) {
        node.add_field(
            &fields::VXLAN_GBP,
            Range::new(base + GBP_OFFSET, 2),
            Value::Uint16(gbp),
        );
    }
    if let Some(vni) = read_u24_be(data, VNI_OFFSET) {
        node.add_field(
            &fields::VXLAN_VNI,
            Range::new(base + VNI_OFFSET, 3),
            Value::Uint24(vni),
        );
    }
    if let Some(reserved) = data.get(RESERVED_OFFSET).copied() {
        node.add_field(
            &fields::VXLAN_RESERVED8,
            Range::new(base + RESERVED_OFFSET, 1),
            Value::Uint8(reserved),
        );
    }

    if data.len() < HEADER_LENGTH {
        context.mark_malformed(&mut node, "VXLAN header is truncated");
        finish(context, parent, node);
        return;
    }

    let payload = data.get(HEADER_LENGTH..).unwrap_or(&[]);
    decode::dispatch(
        context,
        &mut node,
        Some(fields::Protocol::Ethernet),
        payload,
        base + HEADER_LENGTH,
    );
    finish(context, parent, node);
}

fn finish(context: &mut DecodeContext<'_>, parent: &mut Node, node: Node) {
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
