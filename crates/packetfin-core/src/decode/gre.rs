//! Generic Routing Encapsulation.
//!
//! Registry layout follows RFC 2784 (base header) and RFC 2890 (key and
//! sequence extensions): a flags/version word, a protocol type, then the
//! optional checksum/offset, key and sequence fields in that order. RFC 1701
//! adds the source-route entries and the routing/checksum pair, and RFC 2637
//! gives version 1 its payload-length, call-ID and acknowledgment fields.
//! The routing list is followed until a zero address family and length pair,
//! with every entry bounded by the remaining captured bytes.
//!
//! The checksum covers the whole GRE header and payload with the checksum
//! field zeroed; it is verified only when the enclosing IP payload was fully
//! captured and is not a fragment, as in RFC 2784 section 2.3. A 0x88BE
//! payload carries an ERSPAN shim header only when the sequence bit is set
//! (Cisco ERSPAN types I and II); 0x22EB always carries one (type III).

use crate::decode::bytes::{read_u16_be, read_u32_be};
use crate::decode::checksum;
use crate::decode::{self, DecodeContext, NetworkContext};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const FLAGS_OFFSET: usize = 0;
const PROTOCOL_OFFSET: usize = 2;
const BASE_HEADER_LENGTH: usize = 4;
const CHECKSUM_OFFSET: usize = 4;

const FLAG_CHECKSUM: u16 = 0x8000;
const FLAG_ROUTING: u16 = 0x4000;
const FLAG_KEY: u16 = 0x2000;
const FLAG_SEQUENCE: u16 = 0x1000;
const FLAG_ACK: u16 = 0x0080;
const VERSION_MASK: u16 = 0x0007;

const PROTOCOL_PPP: u16 = 0x880b;
const PROTOCOL_CDMA2000_A10_UBS: u16 = 0x8881;

/// Deepest source-route list Packetfin follows in one GRE header.
///
/// RFC 1701 does not bound the list, but every entry costs at least four
/// octets, so the cap only stops a hostile capture from filling the tree.
const MAX_ROUTING_ENTRIES: usize = 64;

/// Decode one GRE header and dispatch its payload.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::GRE_PROTOCOL.filter_name);

    if data.len() < 2 {
        // One captured octet carries no complete field, so the enclosing IPv4
        // stays the last protocol; report the packet malformed without
        // creating an empty GRE node.
        context.mark_malformed(parent, "GRE header is shorter than its flags");
        context.depth = context.depth.saturating_sub(1);
        return;
    }
    let mut node = Node::new(&fields::GRE_PROTOCOL, Range::new(base, data.len()));
    let flags = read_u16_be(data, FLAGS_OFFSET).unwrap_or(0);
    let protocol = read_u16_be(data, PROTOCOL_OFFSET);
    let enhanced_ppp = protocol == Some(PROTOCOL_PPP) && flags & VERSION_MASK != 0;
    add_flag_fields(&mut node, base, flags, enhanced_ppp);

    let Some(protocol) = protocol else {
        context.mark_malformed(&mut node, "GRE header is shorter than its protocol type");
        finish(context, parent, node);
        return;
    };
    node.add_field(
        &fields::GRE_PROTO,
        Range::new(base + PROTOCOL_OFFSET, 2),
        Value::Uint16(protocol),
    );

    let mut offset = BASE_HEADER_LENGTH;

    if flags & (FLAG_CHECKSUM | FLAG_ROUTING) != 0 {
        let Some(stored) = read_u16_be(data, offset) else {
            mark_truncated(context, &mut node);
            finish(context, parent, node);
            return;
        };
        node.add_field(
            &fields::GRE_CHECKSUM,
            Range::new(base + offset, 2),
            Value::Uint16(stored),
        );
        report_checksum(
            context,
            &mut node,
            base + offset,
            stored,
            data,
            flags & FLAG_CHECKSUM != 0,
        );
        let Some(value) = read_u16_be(data, offset.saturating_add(2)) else {
            mark_truncated(context, &mut node);
            finish(context, parent, node);
            return;
        };
        node.add_field(
            &fields::GRE_OFFSET,
            Range::new(base + offset + 2, 2),
            Value::Uint16(value),
        );
        offset += 4;
    }

    if flags & FLAG_KEY != 0 {
        if enhanced_ppp && protocol != PROTOCOL_CDMA2000_A10_UBS {
            match (
                read_u16_be(data, offset),
                read_u16_be(data, offset.saturating_add(2)),
            ) {
                (Some(payload_length), Some(call_id)) => {
                    node.add_field(
                        &fields::GRE_KEY_PAYLOAD_LENGTH,
                        Range::new(base + offset, 2),
                        Value::Uint16(payload_length),
                    );
                    node.add_field(
                        &fields::GRE_KEY_CALL_ID,
                        Range::new(base + offset + 2, 2),
                        Value::Uint16(call_id),
                    );
                }
                _ => {
                    mark_truncated(context, &mut node);
                    finish(context, parent, node);
                    return;
                }
            }
        } else {
            match read_u32_be(data, offset) {
                Some(key) => {
                    node.add_field(
                        &fields::GRE_KEY,
                        Range::new(base + offset, 4),
                        Value::Uint32(key),
                    );
                }
                None => {
                    mark_truncated(context, &mut node);
                    finish(context, parent, node);
                    return;
                }
            }
        }
        offset += 4;
    }

    if flags & FLAG_SEQUENCE != 0 {
        match read_u32_be(data, offset) {
            Some(sequence) => {
                node.add_field(
                    &fields::GRE_SEQUENCE_NUMBER,
                    Range::new(base + offset, 4),
                    Value::Uint32(sequence),
                );
            }
            None => {
                mark_truncated(context, &mut node);
                finish(context, parent, node);
                return;
            }
        }
        offset += 4;
    }

    if enhanced_ppp && flags & FLAG_ACK != 0 {
        match read_u32_be(data, offset) {
            Some(acknowledgement) => {
                node.add_field(
                    &fields::GRE_ACK_NUMBER,
                    Range::new(base + offset, 4),
                    Value::Uint32(acknowledgement),
                );
            }
            None => {
                mark_truncated(context, &mut node);
                finish(context, parent, node);
                return;
            }
        }
        offset += 4;
    }

    if flags & FLAG_ROUTING != 0 && !decode_routing(context, &mut node, data, base, &mut offset) {
        finish(context, parent, node);
        return;
    }

    let Some(payload) = data.get(offset..) else {
        finish(context, parent, node);
        return;
    };
    if payload.is_empty() && flags & FLAG_SEQUENCE == 0 {
        // Without the S bit a header-only packet is legal (RFC 2784).
        finish(context, parent, node);
        return;
    }
    if !payload.is_empty() {
        dispatch_payload(context, &mut node, protocol, flags, payload, base + offset);
    }

    finish(context, parent, node);
}

/// Add the flags word and every flag bit, from the most significant bit down.
fn add_flag_fields(node: &mut Node, base: usize, flags: u16, enhanced_ppp: bool) {
    let range = Range::new(base + FLAGS_OFFSET, 2);
    node.add_field(&fields::GRE_FLAGS_AND_VERSION, range, Value::Uint16(flags));
    node.add_field(
        &fields::GRE_FLAGS_CHECKSUM,
        range,
        Value::Boolean(flags & FLAG_CHECKSUM != 0),
    );
    node.add_field(
        &fields::GRE_FLAGS_ROUTING,
        range,
        Value::Boolean(flags & FLAG_ROUTING != 0),
    );
    node.add_field(
        &fields::GRE_FLAGS_KEY,
        range,
        Value::Boolean(flags & FLAG_KEY != 0),
    );
    node.add_field(
        &fields::GRE_FLAGS_SEQUENCE_NUMBER,
        range,
        Value::Boolean(flags & FLAG_SEQUENCE != 0),
    );
    node.add_field(
        &fields::GRE_FLAGS_STRICT_SOURCE_ROUTE,
        range,
        Value::Boolean(flags & 0x0800 != 0),
    );
    node.add_field(
        &fields::GRE_FLAGS_RECURSION_CONTROL,
        range,
        Value::Uint16((flags >> 8) & 0x7),
    );
    if enhanced_ppp {
        node.add_field(
            &fields::GRE_FLAGS_ACK,
            range,
            Value::Boolean(flags & FLAG_ACK != 0),
        );
    }
    node.add_field(
        &fields::GRE_FLAGS_RESERVED,
        range,
        Value::Uint16((flags >> 3) & 0x1f),
    );
    node.add_field(
        &fields::GRE_FLAGS_VERSION,
        range,
        Value::Uint16(flags & VERSION_MASK),
    );
}

/// Add the checksum and its status, or the unverified status.
fn report_checksum(
    context: &DecodeContext<'_>,
    node: &mut Node,
    range_offset: usize,
    stored: u16,
    data: &[u8],
    verify: bool,
) {
    let fragmented = matches!(
        context.network,
        Some(
            NetworkContext::Ipv4 {
                fragmented: true,
                ..
            } | NetworkContext::Ipv6 {
                fragmented: true,
                ..
            }
        )
    );
    let calculated =
        (verify && !context.quoted && !fragmented && data.len() >= context.reported_length)
            .then(|| checksum::without_pseudo_header(data, CHECKSUM_OFFSET));
    let status = match calculated {
        None => checksum::STATUS_UNVERIFIED,
        Some(calculated) if calculated == stored => checksum::STATUS_GOOD,
        Some(_) => checksum::STATUS_BAD,
    };
    node.add_field(
        &fields::GRE_CHECKSUM_STATUS,
        Range::new(range_offset, 2),
        Value::Uint8(status),
    );
    if status == checksum::STATUS_BAD
        && let Some(calculated) = calculated
    {
        node.add_field(
            &fields::GRE_CHECKSUM_INCORRECT,
            Range::new(range_offset, 0),
            Value::None,
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Protocol,
            message: format!("Incorrect GRE Checksum [should be 0x{calculated:04x}]"),
        });
    }
}

/// Decode the RFC 1701 source-route list.
///
/// Returns `false` when decoding stopped on a malformed entry, so the caller
/// leaves the payload undecoded.
fn decode_routing(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: &mut usize,
) -> bool {
    for _ in 0..MAX_ROUTING_ENTRIES {
        let Some(family) = read_u16_be(data, *offset) else {
            mark_truncated(context, node);
            return false;
        };
        node.add_field(
            &fields::GRE_ROUTING,
            Range::new(base + *offset, data.len().saturating_sub(*offset)),
            Value::None,
        );
        node.add_field(
            &fields::GRE_ROUTING_ADDRESS_FAMILY,
            Range::new(base + *offset, 2),
            Value::Uint16(family),
        );
        let Some(sre_offset) = data.get(offset.saturating_add(2)).copied() else {
            mark_truncated(context, node);
            return false;
        };
        node.add_field(
            &fields::GRE_ROUTING_SRE_OFFSET,
            Range::new(base + *offset + 2, 1),
            Value::Uint8(sre_offset),
        );
        let Some(length) = data.get(offset.saturating_add(3)).copied() else {
            mark_truncated(context, node);
            return false;
        };
        node.add_field(
            &fields::GRE_ROUTING_SRC_LENGTH,
            Range::new(base + *offset + 3, 1),
            Value::Uint8(length),
        );
        *offset = offset.saturating_add(4);
        if family == 0 && length == 0 {
            return true;
        }
        let Some(information) = data.get(*offset..offset.saturating_add(usize::from(length)))
        else {
            mark_truncated(context, node);
            return false;
        };
        node.add_field(
            &fields::GRE_ROUTING_INFORMATION,
            Range::new(base + *offset, information.len()),
            Value::bytes(information.to_vec()),
        );
        *offset = offset.saturating_add(usize::from(length));
    }
    context.mark_malformed(node, "GRE routing list exceeds its entry limit");
    false
}

/// Hand a GRE payload to the decoder that its protocol type selects.
fn dispatch_payload(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    protocol: u16,
    flags: u16,
    payload: &[u8],
    base: usize,
) {
    let (protocol, decoder): (Option<fields::Protocol>, Option<fields::Decoder>) = match protocol {
        0x0800 => (Some(fields::Protocol::Ipv4), None),
        0x0806 => (Some(fields::Protocol::Arp), None),
        0x6558 => (Some(fields::Protocol::Ethernet), None),
        0x86dd => (Some(fields::Protocol::Ipv6), None),
        0x8847 | 0x8848 => (Some(fields::Protocol::Mpls), None),
        0x88be => (
            Some(fields::Protocol::Erspan),
            Some(if flags & FLAG_SEQUENCE != 0 {
                decode::erspan
            } else {
                decode::erspan_type_one
            }),
        ),
        0x22eb => (Some(fields::Protocol::Erspan), Some(decode::erspan)),
        _ => (None, None),
    };
    if let Some(decoder) = decoder {
        if let Some(protocol) = protocol {
            decode::dispatch_override(context, node, protocol, decoder, payload, base);
        }
        return;
    }
    decode::dispatch(context, node, protocol, payload, base);
}

fn mark_truncated(context: &mut DecodeContext<'_>, node: &mut Node) {
    context.mark_malformed(node, "GRE header is truncated");
}

fn finish(context: &mut DecodeContext<'_>, parent: &mut Node, node: Node) {
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
