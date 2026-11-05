//! Internet Control Message Protocol version 4.
//!
//! The decoder adds no ICMP field until six bytes are captured: the four-byte
//! base header plus the first two bytes of the message-specific area. Echo and
//! timestamp identifiers, error-message unused fields, the redirect gateway
//! and the parameter-problem pointer are then added as their bytes appear.
//! A capture that ends before the type's fixed area keeps those fields and
//! marks the packet malformed.
//!
//! Error messages quote the invoking datagram. The ordinary IPv4 or IPv6
//! decoder, selected by the quoted version nibble, decodes that copy, so the
//! address and transport fields repeat. RFC 4884's length byte bounds
//! the quoted copy to four bytes per unit. Quoted decoding never changes the
//! summary columns or the packet's network context, and truncation inside the
//! copy is not reported as a malformed packet.
//!
//! The checksum covers the captured ICMP message with no pseudo-header and is
//! always validated.

use crate::decode::bytes::{read_ipv4, read_u16_be, read_u32_be};
use crate::decode::{self, DecodeContext, checksum};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const MINIMUM_FIELDS_LENGTH: usize = 6;
const ECHO_MINIMUM_LENGTH: usize = 8;
const TIMESTAMP_MINIMUM_LENGTH: usize = 20;
const ADDRESS_MASK_MINIMUM_LENGTH: usize = 12;
const ERROR_MINIMUM_LENGTH: usize = 8;
const CHECKSUM_OFFSET: usize = 2;
const REST_OFFSET: usize = 4;
const QUOTED_OFFSET: usize = 8;

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_DESTINATION_UNREACHABLE: u8 = 3;
const TYPE_SOURCE_QUENCH: u8 = 4;
const TYPE_REDIRECT: u8 = 5;
const TYPE_ECHO_REQUEST: u8 = 8;
const TYPE_ROUTER_ADVERTISEMENT: u8 = 9;
const TYPE_ROUTER_SOLICITATION: u8 = 10;
const TYPE_TIME_EXCEEDED: u8 = 11;
const TYPE_PARAMETER_PROBLEM: u8 = 12;
const TYPE_TIMESTAMP_REQUEST: u8 = 13;
const TYPE_TIMESTAMP_REPLY: u8 = 14;
const TYPE_ADDRESS_MASK_REQUEST: u8 = 17;
const TYPE_ADDRESS_MASK_REPLY: u8 = 18;

const CODE_FRAGMENTATION_NEEDED: u8 = 4;

/// Decode one ICMP message into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::ICMP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::ICMP_PROTOCOL, Range::new(base, data.len()));
    let reported = context.reported_length;
    if data.len() < MINIMUM_FIELDS_LENGTH {
        if reported < MINIMUM_FIELDS_LENGTH {
            context.mark_malformed(&mut node, "ICMP header is truncated");
        }
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let message_type = data.first().copied().unwrap_or(0);
    let code = data.get(1).copied().unwrap_or(0);
    node.add_field(
        &fields::ICMP_TYPE,
        Range::new(base, 1),
        Value::Uint8(message_type),
    );
    if let Some(value) = data.get(1) {
        node.add_field(
            &fields::ICMP_CODE,
            Range::new(base + 1, 1),
            Value::Uint8(*value),
        );
    }
    if let Some(stored) = read_u16_be(data, CHECKSUM_OFFSET) {
        node.add_field(
            &fields::ICMP_CHECKSUM,
            Range::new(base + CHECKSUM_OFFSET, 2),
            Value::Uint16(stored),
        );
        let calculated = (!context.quoted && data.len() >= reported)
            .then(|| checksum::without_pseudo_header(data, CHECKSUM_OFFSET));
        checksum::report(
            &mut node,
            checksum::ChecksumFields {
                status: &fields::ICMP_CHECKSUM_STATUS,
                calculated: Some(&fields::ICMP_CHECKSUM_CALCULATED),
            },
            Range::new(base + CHECKSUM_OFFSET, 2),
            stored,
            calculated,
            checksum::ZeroChecksum::Validate,
            Severity::Warning,
            false,
        );
    }

    if is_error_type(message_type) {
        node.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Response,
            message: "Type indicates an error".to_string(),
        });
    }
    if matches!(
        message_type,
        TYPE_ADDRESS_MASK_REQUEST | TYPE_ADDRESS_MASK_REPLY
    ) {
        node.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Deprecated,
            message: "Type is deprecated".to_string(),
        });
    }

    let mut minimum_length = MINIMUM_FIELDS_LENGTH;
    match message_type {
        TYPE_ECHO_REPLY | TYPE_ECHO_REQUEST => {
            minimum_length = ECHO_MINIMUM_LENGTH;
            add_echo_fields(&mut node, data, base);
        }
        TYPE_TIMESTAMP_REQUEST | TYPE_TIMESTAMP_REPLY => {
            minimum_length = TIMESTAMP_MINIMUM_LENGTH;
            add_echo_identifiers(&mut node, data, base);
            if let Some(value) = read_u32_be(data, QUOTED_OFFSET) {
                node.add_field(
                    &fields::ICMP_ORIGINATE_TIMESTAMP,
                    Range::new(base + QUOTED_OFFSET, 4),
                    Value::Uint32(value),
                );
            }
            if let Some(value) = read_u32_be(data, 12) {
                node.add_field(
                    &fields::ICMP_RECEIVE_TIMESTAMP,
                    Range::new(base + 12, 4),
                    Value::Uint32(value),
                );
            }
            if let Some(value) = read_u32_be(data, 16) {
                node.add_field(
                    &fields::ICMP_TRANSMIT_TIMESTAMP,
                    Range::new(base + 16, 4),
                    Value::Uint32(value),
                );
            }
        }
        TYPE_ADDRESS_MASK_REQUEST | TYPE_ADDRESS_MASK_REPLY => {
            minimum_length = ADDRESS_MASK_MINIMUM_LENGTH;
            add_echo_identifiers(&mut node, data, base);
            if let Some(mask) = read_ipv4(data, QUOTED_OFFSET) {
                node.add_field(
                    &fields::ICMP_ADDRESS_MASK,
                    Range::new(base + QUOTED_OFFSET, 4),
                    Value::Ipv4(mask),
                );
            }
        }
        TYPE_DESTINATION_UNREACHABLE | TYPE_TIME_EXCEEDED | TYPE_PARAMETER_PROBLEM => {
            minimum_length = ERROR_MINIMUM_LENGTH;
            add_error_fields(&mut node, message_type, code, data, base);
        }
        TYPE_SOURCE_QUENCH => {
            minimum_length = ERROR_MINIMUM_LENGTH;
        }
        TYPE_REDIRECT => {
            minimum_length = ERROR_MINIMUM_LENGTH;
            if let Some(gateway) = read_ipv4(data, REST_OFFSET) {
                node.add_field(
                    &fields::ICMP_REDIR_GW,
                    Range::new(base + REST_OFFSET, 4),
                    Value::Ipv4(gateway),
                );
            }
        }
        TYPE_ROUTER_ADVERTISEMENT => {
            minimum_length = ERROR_MINIMUM_LENGTH;
            if let Some(count) = data.get(REST_OFFSET).copied() {
                node.add_field(
                    &fields::ICMP_NUM_ADDRS,
                    Range::new(base + REST_OFFSET, 1),
                    Value::Uint8(count),
                );
            }
            if let Some(size) = data.get(REST_OFFSET.saturating_add(1)).copied() {
                node.add_field(
                    &fields::ICMP_ADDR_ENTRY_SIZE,
                    Range::new(base + REST_OFFSET.saturating_add(1), 1),
                    Value::Uint8(size),
                );
            }
            if let Some(lifetime) = read_u16_be(data, MINIMUM_FIELDS_LENGTH) {
                node.add_field(
                    &fields::ICMP_LIFETIME,
                    Range::new(base + MINIMUM_FIELDS_LENGTH, 2),
                    Value::Uint16(lifetime),
                );
            }
        }
        TYPE_ROUTER_SOLICITATION => {}
        _ => {}
    }

    if reported < minimum_length {
        context.mark_malformed(&mut node, "ICMP message is truncated");
    }

    if is_error_type(message_type) && data.len() > QUOTED_OFFSET {
        let quoted = data.get(QUOTED_OFFSET..).unwrap_or(&[]);
        if !quoted.is_empty() {
            decode::dispatch_quoted(context, &mut node, quoted, base + QUOTED_OFFSET);
        }
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Whether a message type quotes the invoking datagram.
fn is_error_type(message_type: u8) -> bool {
    matches!(
        message_type,
        TYPE_DESTINATION_UNREACHABLE
            | TYPE_SOURCE_QUENCH
            | TYPE_REDIRECT
            | TYPE_TIME_EXCEEDED
            | TYPE_PARAMETER_PROBLEM
    )
}

/// Add the identifier and sequence fields shared by echo, timestamp and
/// address-mask messages.
fn add_echo_identifiers(node: &mut Node, data: &[u8], base: usize) {
    if let Some(ident) = read_u16_be(data, REST_OFFSET) {
        node.add_field(
            &fields::ICMP_IDENT,
            Range::new(base + REST_OFFSET, 2),
            Value::Uint16(ident),
        );
        node.add_field(
            &fields::ICMP_IDENT_LE,
            Range::new(base + REST_OFFSET, 2),
            Value::Uint16(ident.swap_bytes()),
        );
    }
    if let Some(seq) = read_u16_be(data, MINIMUM_FIELDS_LENGTH) {
        node.add_field(
            &fields::ICMP_SEQ,
            Range::new(base + MINIMUM_FIELDS_LENGTH, 2),
            Value::Uint16(seq),
        );
        node.add_field(
            &fields::ICMP_SEQ_LE,
            Range::new(base + MINIMUM_FIELDS_LENGTH, 2),
            Value::Uint16(seq.swap_bytes()),
        );
    }
}

/// Add the echo identifier, sequence and payload.
fn add_echo_fields(node: &mut Node, data: &[u8], base: usize) {
    add_echo_identifiers(node, data, base);
    if data.len() > ECHO_MINIMUM_LENGTH
        && let Some(payload) = data.get(ECHO_MINIMUM_LENGTH..)
        && !payload.is_empty()
    {
        node.add_field(
            &fields::ICMP_DATA,
            Range::new(base + ECHO_MINIMUM_LENGTH, payload.len()),
            Value::bytes(payload.to_vec()),
        );
    }
}

/// Add the type-specific four-byte area of an error message.
fn add_error_fields(node: &mut Node, message_type: u8, code: u8, data: &[u8], base: usize) {
    let length_byte = data
        .get(REST_OFFSET.saturating_add(1))
        .copied()
        .unwrap_or(0);
    let has_length = length_byte != 0;
    let fragmented =
        message_type == TYPE_DESTINATION_UNREACHABLE && code == CODE_FRAGMENTATION_NEEDED;

    if message_type == TYPE_PARAMETER_PROBLEM
        && let Some(pointer) = data.get(REST_OFFSET).copied()
    {
        node.add_field(
            &fields::ICMP_POINTER,
            Range::new(base + REST_OFFSET, 1),
            Value::Uint32(u32::from(pointer)),
        );
    }

    if has_length {
        if message_type != TYPE_PARAMETER_PROBLEM {
            add_unused(node, data, base, REST_OFFSET, 1);
        }
        node.add_field(
            &fields::ICMP_LENGTH,
            Range::new(base + REST_OFFSET.saturating_add(1), 1),
            Value::Uint8(length_byte),
        );
        node.add_field(
            &fields::ICMP_LENGTH_ORIGINAL,
            Range::new(base + REST_OFFSET.saturating_add(1), 1),
            Value::Uint16(u16::from(length_byte) * 4),
        );
        if !fragmented {
            add_unused(node, data, base, MINIMUM_FIELDS_LENGTH, 2);
        }
    } else if fragmented {
        add_unused(node, data, base, REST_OFFSET, 2);
    } else if message_type == TYPE_PARAMETER_PROBLEM {
        add_unused(node, data, base, REST_OFFSET.saturating_add(1), 3);
    } else {
        add_unused(node, data, base, REST_OFFSET, 4);
    }

    if fragmented && let Some(mtu) = read_u16_be(data, MINIMUM_FIELDS_LENGTH) {
        node.add_field(
            &fields::ICMP_MTU,
            Range::new(base + MINIMUM_FIELDS_LENGTH, 2),
            Value::Uint16(mtu),
        );
    }
}

/// Add an `icmp.unused` occurrence when the captured bytes cover it.
fn add_unused(node: &mut Node, data: &[u8], base: usize, offset: usize, length: usize) {
    let end = offset.saturating_add(length);
    if let Some(bytes) = data.get(offset..end)
        && !bytes.is_empty()
    {
        node.add_field(
            &fields::ICMP_UNUSED,
            Range::new(base + offset, bytes.len()),
            Value::bytes(bytes.to_vec()),
        );
    }
}
