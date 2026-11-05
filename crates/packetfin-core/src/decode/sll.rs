//! Linux cooked-mode capture, versions 1 (link type 113) and 2 (276).
//!
//! Both versions share the `sll` filter name. Version 1 is a 16-byte header
//! with a packet type, link-layer address type and length, an eight-byte
//! address field and a protocol; version 2 moves the protocol to the front,
//! adds a reserved field and an interface index, and narrows the packet type
//! and address length to one byte each. The address length, not the address
//! type, selects which source address field is exposed.

use crate::decode::bytes::{read_u16_be, read_u32_be};
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const V1_ADDRESS_OFFSET: usize = 6;
const V1_PROTOCOL_OFFSET: usize = 14;
const V1_HEADER_LENGTH: usize = 16;
const V2_FIXED_LENGTH: usize = 12;
const V2_ADDRESS_OFFSET: usize = 12;
const V2_HEADER_LENGTH: usize = 20;
const ADDRESS_FIELD_LENGTH: usize = 8;
/// Largest protocol value reported as `sll.ltype`.
const MAX_LTYPE: u16 = 0x0600;
const LTYPE_LLC: u16 = 0x0004;

/// Decode one version-1 Linux cooked capture frame.
pub(crate) fn decode_v1(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::SLL_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::SLL_PROTOCOL, Range::new(base, data.len()));

    if data.len() >= 4 {
        if let Some(packet_type) = read_u16_be(data, 0) {
            node.add_field(
                &fields::SLL_PKTTYPE,
                Range::new(base, 2),
                Value::Uint16(packet_type),
            );
        }
        if let Some(address_type) = read_u16_be(data, 2) {
            node.add_field(
                &fields::SLL_HATYPE,
                Range::new(base + 2, 2),
                Value::Uint16(address_type),
            );
        }
    }

    let address_length = read_u16_be(data, 4);
    if let Some(address_length) = address_length {
        node.add_field(
            &fields::SLL_HALEN,
            Range::new(base + 4, 2),
            Value::Uint16(address_length),
        );
        add_address_fields(
            &mut node,
            data,
            V1_ADDRESS_OFFSET,
            base + V1_ADDRESS_OFFSET,
            address_length,
        );
        add_unused(
            &mut node,
            data,
            V1_ADDRESS_OFFSET,
            base + V1_ADDRESS_OFFSET,
            address_length,
        );
    }

    if data.len() < V1_HEADER_LENGTH {
        context.mark_malformed(
            &mut node,
            "Linux cooked capture header shorter than 16 bytes",
        );
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if let Some(protocol) = read_u16_be(data, V1_PROTOCOL_OFFSET) {
        add_protocol_field(&mut node, base, protocol, V1_PROTOCOL_OFFSET);
        dispatch_protocol(context, &mut node, data, base, protocol, V1_HEADER_LENGTH);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Decode one version-2 Linux cooked capture frame.
pub(crate) fn decode_v2(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::SLL_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::SLL_PROTOCOL, Range::new(base, data.len()));

    if data.len() < V2_FIXED_LENGTH {
        context.mark_malformed(
            &mut node,
            "Linux cooked capture v2 header shorter than 12 bytes",
        );
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let protocol = read_u16_be(data, 0);
    if let Some(protocol) = protocol {
        add_protocol_field(&mut node, base, protocol, 0);
    }
    if let Some(reserved) = data.get(2..4) {
        node.add_field(
            &fields::SLL_RESERVED,
            Range::new(base + 2, 2),
            Value::bytes(reserved.to_vec()),
        );
    }
    if let Some(interface_index) = read_u32_be(data, 4) {
        node.add_field(
            &fields::SLL_IFINDEX,
            Range::new(base + 4, 4),
            Value::Uint32(interface_index),
        );
    }
    if let Some(address_type) = read_u16_be(data, 8) {
        node.add_field(
            &fields::SLL_HATYPE,
            Range::new(base + 8, 2),
            Value::Uint16(address_type),
        );
    }
    if let Some(packet_type) = data.get(10).copied() {
        node.add_field(
            &fields::SLL_PKTTYPE,
            Range::new(base + 10, 1),
            Value::Uint16(u16::from(packet_type)),
        );
    }
    let address_length = data.get(11).copied().map(u16::from);
    if let Some(address_length) = address_length {
        node.add_field(
            &fields::SLL_HALEN,
            Range::new(base + 11, 1),
            Value::Uint16(address_length),
        );
        add_address_fields(
            &mut node,
            data,
            V2_ADDRESS_OFFSET,
            base + V2_ADDRESS_OFFSET,
            address_length,
        );
        add_unused(
            &mut node,
            data,
            V2_ADDRESS_OFFSET,
            base + V2_ADDRESS_OFFSET,
            address_length,
        );
    }

    if data.len() < V2_HEADER_LENGTH {
        context.mark_malformed(
            &mut node,
            "Linux cooked capture v2 header shorter than 20 bytes",
        );
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if let Some(protocol) = protocol {
        dispatch_protocol(context, &mut node, data, base, protocol, V2_HEADER_LENGTH);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Add the address field selected by the address length.
fn add_address_fields(
    node: &mut Node,
    data: &[u8],
    data_offset: usize,
    base: usize,
    address_length: u16,
) {
    if address_length == 0 {
        return;
    }
    let captured_length = usize::from(address_length).min(ADDRESS_FIELD_LENGTH);
    let end = match data_offset.checked_add(captured_length) {
        Some(end) => end,
        None => return,
    };
    let Some(bytes) = data.get(data_offset..end) else {
        return;
    };
    match address_length {
        4 => {
            if let Ok(address) = <[u8; 4]>::try_from(bytes) {
                node.add_field(
                    &fields::SLL_SRC_IPV4,
                    Range::new(base, 4),
                    Value::Ipv4(address),
                );
            }
        }
        6 => {
            if let Ok(address) = <[u8; 6]>::try_from(bytes) {
                node.add_field(
                    &fields::SLL_SRC_ETH,
                    Range::new(base, 6),
                    Value::Ethernet(address),
                );
            }
        }
        _ => {
            node.add_field(
                &fields::SLL_SRC_OTHER,
                Range::new(base, captured_length),
                Value::bytes(bytes.to_vec()),
            );
        }
    }
}

/// Add the bytes of the eight-byte address field that the length leaves
/// unused.
fn add_unused(node: &mut Node, data: &[u8], data_offset: usize, base: usize, address_length: u16) {
    let address_length = usize::from(address_length);
    if address_length >= ADDRESS_FIELD_LENGTH {
        return;
    }
    let start = match data_offset.checked_add(address_length) {
        Some(start) => start,
        None => return,
    };
    let end = match data_offset.checked_add(ADDRESS_FIELD_LENGTH) {
        Some(end) => end,
        None => return,
    };
    let Some(bytes) = data.get(start..end) else {
        return;
    };
    node.add_field(
        &fields::SLL_UNUSED,
        Range::new(base + address_length, bytes.len()),
        Value::bytes(bytes.to_vec()),
    );
}

/// Add the protocol field: `sll.ltype` for values at or below 0x0600 and
/// `sll.etype` above it.
fn add_protocol_field(node: &mut Node, base: usize, protocol: u16, protocol_offset: usize) {
    let protocol_range = Range::new(base + protocol_offset, 2);
    if protocol <= MAX_LTYPE {
        node.add_field(&fields::SLL_LTYPE, protocol_range, Value::Uint16(protocol));
    } else {
        node.add_field(&fields::SLL_ETYPE, protocol_range, Value::Uint16(protocol));
    }
}

/// Hand a complete cooked-capture payload to its decoder.
fn dispatch_protocol(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    protocol: u16,
    header_length: usize,
) {
    let payload = data.get(header_length..).unwrap_or(&[]);
    let payload_start = base + header_length;
    if protocol <= MAX_LTYPE {
        if protocol == LTYPE_LLC {
            decode::dispatch(
                context,
                node,
                Some(fields::Protocol::Llc),
                payload,
                payload_start,
            );
        }
    } else {
        decode::dispatch_ethertype(context, node, protocol, payload, payload_start);
    }
}
