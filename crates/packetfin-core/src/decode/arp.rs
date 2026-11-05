//! Address Resolution Protocol decoding.
//!
//! Every ARP packet starts with eight fixed bytes: hardware type, protocol
//! type, hardware address size, protocol address size and opcode. The four
//! addresses follow, each pair sized by the length fields. The decoder adds no
//! ARP fields when those eight bytes are incomplete, and adds only the fixed
//! fields when the address area is truncated.
//!
//! A six-byte hardware address is exposed as a MAC address (`arp.*.hw_mac`);
//! other lengths use the generic byte field. A protocol address of the IPv4
//! type with a four-byte size gets the IPv4 field; every other combination
//! stays a byte string. ARP addresses are values only: no network decoder is
//! dispatched.

use crate::decode::DecodeContext;
use crate::decode::bytes::read_u16_be;
use crate::fields;
use crate::tree::{Node, Range, Value};

const FIXED_LENGTH: usize = 8;
const HW_TYPE_OFFSET: usize = 0;
const PROTO_TYPE_OFFSET: usize = 2;
const HW_SIZE_OFFSET: usize = 4;
const PROTO_SIZE_OFFSET: usize = 5;
const OPCODE_OFFSET: usize = 6;
const ADDRESSES_OFFSET: usize = 8;
const MAC_LENGTH: usize = 6;
const PROTOCOL_IPV4: u16 = 0x0800;
const HW_TYPE_ETHERNET: u16 = 1;
const HW_TYPE_IEEE802: u16 = 6;

/// Decode one ARP packet into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::ARP_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::ARP_PROTOCOL, Range::new(base, data.len()));

    if let Some(value) = read_u16_be(data, HW_TYPE_OFFSET) {
        node.add_field(
            &fields::ARP_HW_TYPE,
            Range::new(base + HW_TYPE_OFFSET, 2),
            Value::Uint16(value),
        );
    }
    if let Some(value) = read_u16_be(data, PROTO_TYPE_OFFSET) {
        node.add_field(
            &fields::ARP_PROTO_TYPE,
            Range::new(base + PROTO_TYPE_OFFSET, 2),
            Value::Uint16(value),
        );
    }
    let hardware_size = data.get(HW_SIZE_OFFSET).copied().unwrap_or(0);
    let protocol_size = data.get(PROTO_SIZE_OFFSET).copied().unwrap_or(0);
    if data.get(HW_SIZE_OFFSET).is_some() {
        node.add_field(
            &fields::ARP_HW_SIZE,
            Range::new(base + HW_SIZE_OFFSET, 1),
            Value::Uint8(hardware_size),
        );
    }
    if data.get(PROTO_SIZE_OFFSET).is_some() {
        node.add_field(
            &fields::ARP_PROTO_SIZE,
            Range::new(base + PROTO_SIZE_OFFSET, 1),
            Value::Uint8(protocol_size),
        );
    }
    if let Some(value) = read_u16_be(data, OPCODE_OFFSET) {
        node.add_field(
            &fields::ARP_OPCODE,
            Range::new(base + OPCODE_OFFSET, 2),
            Value::Uint16(value),
        );
    }

    if data.len() < FIXED_LENGTH {
        context.mark_malformed(&mut node, "ARP packet shorter than its fixed header");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let hardware_size = usize::from(hardware_size);
    let protocol_size = usize::from(protocol_size);
    let Some(address_bytes) = hardware_size.checked_mul(2).and_then(|hardware| {
        protocol_size
            .checked_mul(2)
            .and_then(|protocol| hardware.checked_add(protocol))
    }) else {
        context.mark_malformed(&mut node, "ARP address sizes overflow");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let Some(required) = ADDRESSES_OFFSET.checked_add(address_bytes) else {
        context.mark_malformed(&mut node, "ARP address sizes overflow");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    if data.len() < required {
        context.mark_malformed(&mut node, "ARP packet shorter than its addresses");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let sender_hardware = ADDRESSES_OFFSET;
    let sender_protocol = sender_hardware.saturating_add(hardware_size);
    let target_hardware = sender_protocol.saturating_add(protocol_size);
    let target_protocol = target_hardware.saturating_add(hardware_size);

    let hardware_type = read_u16_be(data, HW_TYPE_OFFSET).unwrap_or(0);
    add_hardware_address(
        &mut node,
        data,
        base,
        sender_hardware,
        hardware_type,
        hardware_size,
        (&fields::ARP_SRC_HW, &fields::ARP_SRC_HW_MAC),
    );
    add_protocol_address(
        &mut node,
        data,
        base,
        sender_protocol,
        protocol_size,
        read_u16_be(data, PROTO_TYPE_OFFSET).unwrap_or(0),
        (&fields::ARP_SRC_PROTO, &fields::ARP_SRC_PROTO_IPV4),
    );
    add_hardware_address(
        &mut node,
        data,
        base,
        target_hardware,
        hardware_type,
        hardware_size,
        (&fields::ARP_DST_HW, &fields::ARP_DST_HW_MAC),
    );
    add_protocol_address(
        &mut node,
        data,
        base,
        target_protocol,
        protocol_size,
        read_u16_be(data, PROTO_TYPE_OFFSET).unwrap_or(0),
        (&fields::ARP_DST_PROTO, &fields::ARP_DST_PROTO_IPV4),
    );

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Add a hardware address, as a MAC address when it is six bytes long.
fn add_hardware_address(
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    hardware_type: u16,
    size: usize,
    defs: (&'static fields::FieldDef, &'static fields::FieldDef),
) {
    let (generic, mac) = defs;
    if size == 0 {
        return;
    }
    let Some(bytes) = address_bytes(data, offset, size) else {
        return;
    };
    if matches!(hardware_type, HW_TYPE_ETHERNET | HW_TYPE_IEEE802)
        && size == MAC_LENGTH
        && let Ok(address) = <[u8; MAC_LENGTH]>::try_from(bytes)
    {
        node.add_field(
            mac,
            Range::new(base + offset, MAC_LENGTH),
            Value::Ethernet(address),
        );
        return;
    }
    node.add_field(
        generic,
        Range::new(base + offset, bytes.len()),
        Value::bytes(bytes.to_vec()),
    );
}

/// Add a protocol address, as an IPv4 address for IPv4 ARP.
fn add_protocol_address(
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    size: usize,
    protocol_type: u16,
    defs: (&'static fields::FieldDef, &'static fields::FieldDef),
) {
    let (generic, ipv4) = defs;
    if size == 0 {
        return;
    }
    let Some(bytes) = address_bytes(data, offset, size) else {
        return;
    };
    if protocol_type == PROTOCOL_IPV4
        && size == 4
        && let Ok(address) = <[u8; 4]>::try_from(bytes)
    {
        node.add_field(ipv4, Range::new(base + offset, 4), Value::Ipv4(address));
        return;
    }
    node.add_field(
        generic,
        Range::new(base + offset, bytes.len()),
        Value::bytes(bytes.to_vec()),
    );
}

fn address_bytes(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    let end = offset.checked_add(size)?;
    data.get(offset..end)
}
