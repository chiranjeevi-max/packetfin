//! Internet Control Message Protocol version 6 (RFC 4443) and the neighbor
//! discovery messages of RFC 4861.
//!
//! The fixed header is the four-byte type, code and checksum sequence; every
//! message type then has its own body. Echo requests and replies carry an
//! identifier and sequence number (RFC 4443 section 4.1). Destination
//! Unreachable, Packet Too Big, Time Exceeded and Parameter Problem carry a
//! four-byte type-specific area followed by as much of the invoking packet as
//! fits (RFC 4443 sections 3.1 to 3.4). The checksum covers an IPv6
//! pseudo-header and the message (RFC 4443 section 2.3) and is always
//! validated.
//!
//! Neighbor discovery uses six message codes from RFC 4861 section 4:
//! Router Solicitation, Router Advertisement, Neighbor Solicitation,
//! Neighbor Advertisement and Redirect. Options use a type, a length in
//! units of eight octets and type-specific data (RFC 4861 section 4.6).
//! Option decoding is bounded by the declared option length as well as by
//! the captured bytes, so a length that is too short is reported rather than
//! read past.
//!
//! Error messages quote the invoking IPv6 datagram. The quoted copy is decoded
//! only when its version nibble is six, which matches RFC 4443: an
//! ICMPv6 error can only quote an IPv6 packet. The copy repeats the network
//! and transport fields, never changes the outer summary columns or network
//! context, and is bounded by the global decode depth.

use crate::decode::bytes::{read_ipv6, read_u16_be, read_u32_be};
use crate::decode::{self, DecodeContext, NetworkContext, checksum};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const CHECKSUM_OFFSET: usize = 2;
const BODY_OFFSET: usize = 4;
const ERROR_QUOTED_OFFSET: usize = 8;
const ECHO_MINIMUM_LENGTH: usize = 8;
const ROUTER_SOLICITATION_MINIMUM_LENGTH: usize = 8;
const ROUTER_ADVERTISEMENT_MINIMUM_LENGTH: usize = 16;
const NEIGHBOR_MINIMUM_LENGTH: usize = 24;
const REDIRECT_MINIMUM_LENGTH: usize = 40;
const OPTION_HEADER_LENGTH: usize = 2;
const OPTION_UNIT: usize = 8;
const OPTION_RESERVED_LENGTH: usize = 6;
const PREFIX_BODY_LENGTH: usize = 30;
const MTU_BODY_LENGTH: usize = 6;
const LINK_LAYER_BODY_LENGTH: usize = 14;
const LINK_LAYER_PADDING_LENGTH: usize = 6;

const TYPE_DESTINATION_UNREACHABLE: u8 = 1;
const TYPE_PACKET_TOO_BIG: u8 = 2;
const TYPE_TIME_EXCEEDED: u8 = 3;
const TYPE_PARAMETER_PROBLEM: u8 = 4;
const TYPE_ECHO_REQUEST: u8 = 128;
const TYPE_ECHO_REPLY: u8 = 129;
const TYPE_ROUTER_SOLICITATION: u8 = 133;
const TYPE_ROUTER_ADVERTISEMENT: u8 = 134;
const TYPE_NEIGHBOR_SOLICITATION: u8 = 135;
const TYPE_NEIGHBOR_ADVERTISEMENT: u8 = 136;
const TYPE_REDIRECT: u8 = 137;

const OPTION_SOURCE_LINK_LAYER: u8 = 1;
const OPTION_TARGET_LINK_LAYER: u8 = 2;
const OPTION_PREFIX_INFORMATION: u8 = 3;
const OPTION_REDIRECTED_HEADER: u8 = 4;
const OPTION_MTU: u8 = 5;

const ICMPV6_PROTOCOL_NUMBER: u8 = 58;

/// Decode one ICMPv6 message into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::ICMPV6_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::ICMPV6_PROTOCOL, Range::new(base, data.len()));
    decode_message(context, &mut node, data, base);
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn decode_message(context: &mut DecodeContext<'_>, node: &mut Node, data: &[u8], base: usize) {
    let Some(&message_type) = data.first() else {
        return;
    };
    node.add_field(
        &fields::ICMPV6_TYPE,
        Range::new(base, 1),
        Value::Uint8(message_type),
    );
    if message_type < 0x80 {
        node.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Response,
            message: "Type indicates an error".to_string(),
        });
    }
    let Some(&code) = data.get(1) else {
        context.mark_malformed(node, "ICMPv6 header is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_CODE,
        Range::new(base + 1, 1),
        Value::Uint8(code),
    );

    let Some(stored) = read_u16_be(data, CHECKSUM_OFFSET) else {
        context.mark_malformed(node, "ICMPv6 header is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_CHECKSUM,
        Range::new(base + CHECKSUM_OFFSET, 2),
        Value::Uint16(stored),
    );
    let reported = context.reported_length;
    let calculated = if context.quoted || data.len() < reported {
        None
    } else {
        match context.network.as_ref() {
            Some(NetworkContext::Ipv6 {
                source,
                destination,
                ..
            }) => Some(checksum::ipv6_transport(
                *source,
                *destination,
                ICMPV6_PROTOCOL_NUMBER,
                u32::try_from(data.len()).unwrap_or(u32::MAX),
                data,
                CHECKSUM_OFFSET,
            )),
            _ => None,
        }
    };
    checksum::report(
        node,
        checksum::ChecksumFields {
            status: &fields::ICMPV6_CHECKSUM_STATUS,
            calculated: Some(&fields::ICMPV6_CHECKSUM_CALCULATED),
        },
        Range::new(base + CHECKSUM_OFFSET, 2),
        stored,
        calculated,
        checksum::ZeroChecksum::Validate,
        Severity::Warning,
        false,
    );

    match message_type {
        TYPE_ECHO_REQUEST | TYPE_ECHO_REPLY => add_echo(context, node, data, base, reported),
        TYPE_ROUTER_SOLICITATION => add_router_solicitation(context, node, data, base, reported),
        TYPE_ROUTER_ADVERTISEMENT => add_router_advertisement(context, node, data, base, reported),
        TYPE_NEIGHBOR_SOLICITATION => {
            add_neighbor_solicitation(context, node, data, base, reported)
        }
        TYPE_NEIGHBOR_ADVERTISEMENT => {
            add_neighbor_advertisement(context, node, data, base, reported)
        }
        TYPE_REDIRECT => add_redirect(context, node, data, base, reported),
        TYPE_DESTINATION_UNREACHABLE
        | TYPE_PACKET_TOO_BIG
        | TYPE_TIME_EXCEEDED
        | TYPE_PARAMETER_PROBLEM => add_error(context, node, data, base, message_type, reported),
        _ => {
            if data.len() > BODY_OFFSET
                && let Some(body) = data.get(BODY_OFFSET..)
            {
                node.add_field(
                    &fields::ICMPV6_DATA,
                    Range::new(base + BODY_OFFSET, body.len()),
                    Value::bytes(body.to_vec()),
                );
            }
        }
    }
}

/// Echo Request and Echo Reply body (RFC 4443 section 4.1).
fn add_echo(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    reported: usize,
) {
    let Some(identifier) = read_u16_be(data, BODY_OFFSET) else {
        if reported < BODY_OFFSET.saturating_add(2) {
            context.mark_malformed(node, "ICMPv6 Echo message is truncated");
        }
        return;
    };
    node.add_field(
        &fields::ICMPV6_ECHO_IDENTIFIER,
        Range::new(base + BODY_OFFSET, 2),
        Value::Uint16(identifier),
    );
    let Some(sequence) = read_u16_be(data, BODY_OFFSET.saturating_add(2)) else {
        if reported < ECHO_MINIMUM_LENGTH {
            context.mark_malformed(node, "ICMPv6 Echo message is truncated");
        }
        return;
    };
    node.add_field(
        &fields::ICMPV6_ECHO_SEQUENCE,
        Range::new(base + BODY_OFFSET.saturating_add(2), 2),
        Value::Uint16(sequence),
    );
    if reported < ECHO_MINIMUM_LENGTH {
        context.mark_malformed(node, "ICMPv6 Echo message is truncated");
    }
}

/// Router Solicitation body (RFC 4861 section 4.1).
fn add_router_solicitation(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    reported: usize,
) {
    if !add_reserved(context, node, data, base, BODY_OFFSET, 4, reported) {
        return;
    }
    if reported < ROUTER_SOLICITATION_MINIMUM_LENGTH {
        context.mark_malformed(node, "ICMPv6 Router Solicitation is truncated");
        return;
    }
    add_options(
        context,
        node,
        data,
        base,
        ROUTER_SOLICITATION_MINIMUM_LENGTH,
    );
}

/// Router Advertisement body (RFC 4861 section 4.2).
fn add_router_advertisement(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    reported: usize,
) {
    let Some(&hop_limit) = data.get(BODY_OFFSET) else {
        if reported < 5 {
            context.mark_malformed(node, "ICMPv6 Router Advertisement is truncated");
        }
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_RA_CUR_HOP_LIMIT,
        Range::new(base + BODY_OFFSET, 1),
        Value::Uint8(hop_limit),
    );

    let Some(&flags) = data.get(BODY_OFFSET.saturating_add(1)) else {
        if reported < 6 {
            context.mark_malformed(node, "ICMPv6 Router Advertisement is truncated");
        }
        return;
    };
    add_router_advertisement_flags(node, flags, base + BODY_OFFSET.saturating_add(1));

    let Some(router_lifetime) = read_u16_be(data, BODY_OFFSET.saturating_add(2)) else {
        context.mark_malformed(node, "ICMPv6 Router Advertisement is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_RA_ROUTER_LIFETIME,
        Range::new(base + BODY_OFFSET.saturating_add(2), 2),
        Value::Uint16(router_lifetime),
    );

    let Some(reachable_time) = read_u32_be(data, BODY_OFFSET.saturating_add(4)) else {
        context.mark_malformed(node, "ICMPv6 Router Advertisement is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_RA_REACHABLE_TIME,
        Range::new(base + BODY_OFFSET.saturating_add(4), 4),
        Value::Uint32(reachable_time),
    );

    let Some(retrans_timer) = read_u32_be(data, BODY_OFFSET.saturating_add(8)) else {
        context.mark_malformed(node, "ICMPv6 Router Advertisement is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_RA_RETRANS_TIMER,
        Range::new(base + BODY_OFFSET.saturating_add(8), 4),
        Value::Uint32(retrans_timer),
    );

    if reported < ROUTER_ADVERTISEMENT_MINIMUM_LENGTH {
        context.mark_malformed(node, "ICMPv6 Router Advertisement is truncated");
        return;
    }
    add_options(
        context,
        node,
        data,
        base,
        ROUTER_ADVERTISEMENT_MINIMUM_LENGTH,
    );
}

fn add_router_advertisement_flags(node: &mut Node, flags: u8, offset: usize) {
    node.add_field(
        &fields::ICMPV6_ND_RA_FLAG,
        Range::new(offset, 1),
        Value::Uint8(flags),
    );
    for (def, mask) in [
        (&fields::ICMPV6_ND_RA_FLAG_M, 0x80_u8),
        (&fields::ICMPV6_ND_RA_FLAG_O, 0x40),
        (&fields::ICMPV6_ND_RA_FLAG_H, 0x20),
        (&fields::ICMPV6_ND_RA_FLAG_P, 0x04),
        (&fields::ICMPV6_ND_RA_FLAG_S, 0x02),
    ] {
        node.add_field(
            def,
            Range::new(offset, 1),
            Value::Boolean(flags & mask != 0),
        );
    }
    node.add_field(
        &fields::ICMPV6_ND_RA_FLAG_PRF,
        Range::new(offset, 1),
        Value::Uint8((flags & 0x18) >> 3),
    );
    node.add_field(
        &fields::ICMPV6_ND_RA_FLAG_RSV,
        Range::new(offset, 1),
        Value::Uint8(flags & 0x01),
    );
}

/// Neighbor Solicitation body (RFC 4861 section 4.3).
fn add_neighbor_solicitation(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    reported: usize,
) {
    if !add_reserved(context, node, data, base, BODY_OFFSET, 4, reported) {
        return;
    }
    let Some(target) = read_ipv6(data, BODY_OFFSET.saturating_add(4)) else {
        context.mark_malformed(node, "ICMPv6 Neighbor Solicitation is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_NS_TARGET_ADDRESS,
        Range::new(base + BODY_OFFSET.saturating_add(4), 16),
        Value::Ipv6(target),
    );
    if reported < NEIGHBOR_MINIMUM_LENGTH {
        context.mark_malformed(node, "ICMPv6 Neighbor Solicitation is truncated");
        return;
    }
    add_options(context, node, data, base, NEIGHBOR_MINIMUM_LENGTH);
}

/// Neighbor Advertisement body (RFC 4861 section 4.4).
fn add_neighbor_advertisement(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    reported: usize,
) {
    let Some(flags) = read_u32_be(data, BODY_OFFSET) else {
        context.mark_malformed(node, "ICMPv6 Neighbor Advertisement is truncated");
        return;
    };
    let flag_offset = base + BODY_OFFSET;
    node.add_field(
        &fields::ICMPV6_ND_NA_FLAG,
        Range::new(flag_offset, 4),
        Value::Uint32(flags),
    );
    for (def, mask) in [
        (&fields::ICMPV6_ND_NA_FLAG_R, 0x8000_0000),
        (&fields::ICMPV6_ND_NA_FLAG_S, 0x4000_0000),
        (&fields::ICMPV6_ND_NA_FLAG_O, 0x2000_0000),
    ] {
        node.add_field(
            def,
            Range::new(flag_offset, 4),
            Value::Boolean(flags & mask != 0),
        );
    }
    node.add_field(
        &fields::ICMPV6_ND_NA_FLAG_RSV,
        Range::new(flag_offset, 4),
        Value::Uint32(flags & 0x1fff_ffff),
    );

    let Some(target) = read_ipv6(data, BODY_OFFSET.saturating_add(4)) else {
        context.mark_malformed(node, "ICMPv6 Neighbor Advertisement is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_NA_TARGET_ADDRESS,
        Range::new(base + BODY_OFFSET.saturating_add(4), 16),
        Value::Ipv6(target),
    );
    if reported < NEIGHBOR_MINIMUM_LENGTH {
        context.mark_malformed(node, "ICMPv6 Neighbor Advertisement is truncated");
        return;
    }
    add_options(context, node, data, base, NEIGHBOR_MINIMUM_LENGTH);
}

/// Redirect body (RFC 4861 section 4.5).
fn add_redirect(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    reported: usize,
) {
    if !add_reserved(context, node, data, base, BODY_OFFSET, 4, reported) {
        return;
    }
    let Some(target) = read_ipv6(data, BODY_OFFSET.saturating_add(4)) else {
        context.mark_malformed(node, "ICMPv6 Redirect is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_ND_RD_TARGET_ADDRESS,
        Range::new(base + BODY_OFFSET.saturating_add(4), 16),
        Value::Ipv6(target),
    );
    let Some(destination) = read_ipv6(data, BODY_OFFSET.saturating_add(20)) else {
        context.mark_malformed(node, "ICMPv6 Redirect is truncated");
        return;
    };
    node.add_field(
        &fields::ICMPV6_RD_NA_DESTINATION_ADDRESS,
        Range::new(base + BODY_OFFSET.saturating_add(20), 16),
        Value::Ipv6(destination),
    );
    if reported < REDIRECT_MINIMUM_LENGTH {
        context.mark_malformed(node, "ICMPv6 Redirect is truncated");
        return;
    }
    add_options(context, node, data, base, REDIRECT_MINIMUM_LENGTH);
}

/// Destination Unreachable, Packet Too Big, Time Exceeded and Parameter
/// Problem (RFC 4443 sections 3.1 to 3.4).
fn add_error(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    message_type: u8,
    reported: usize,
) {
    match message_type {
        TYPE_DESTINATION_UNREACHABLE | TYPE_TIME_EXCEEDED => {
            if !add_reserved(context, node, data, base, BODY_OFFSET, 4, reported) {
                return;
            }
        }
        TYPE_PACKET_TOO_BIG => {
            let Some(mtu) = read_u32_be(data, BODY_OFFSET) else {
                if reported < ERROR_QUOTED_OFFSET {
                    context.mark_malformed(node, "ICMPv6 Packet Too Big is truncated");
                }
                return;
            };
            node.add_field(
                &fields::ICMPV6_MTU,
                Range::new(base + BODY_OFFSET, 4),
                Value::Uint32(mtu),
            );
        }
        TYPE_PARAMETER_PROBLEM => {
            let Some(pointer) = read_u32_be(data, BODY_OFFSET) else {
                if reported < ERROR_QUOTED_OFFSET {
                    context.mark_malformed(node, "ICMPv6 Parameter Problem is truncated");
                }
                return;
            };
            node.add_field(
                &fields::ICMPV6_POINTER,
                Range::new(base + BODY_OFFSET, 4),
                Value::Uint32(pointer),
            );
        }
        _ => return,
    }

    // RFC 4443 section 3: an error message includes at least the first byte
    // of the invoking packet.
    if data.len() <= ERROR_QUOTED_OFFSET {
        if reported <= ERROR_QUOTED_OFFSET {
            context.mark_malformed(node, "ICMPv6 error message has no invoking packet");
        }
        return;
    }
    let Some(quoted) = data.get(ERROR_QUOTED_OFFSET..) else {
        return;
    };
    if quoted.first().is_some_and(|byte| byte >> 4 == 6) {
        decode::dispatch_quoted(context, node, quoted, base + ERROR_QUOTED_OFFSET);
    }
}

/// Add a four-byte reserved field when its first byte is captured.
fn add_reserved(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    length: usize,
    reported: usize,
) -> bool {
    let end = offset.saturating_add(length);
    let Some(bytes) = data.get(offset..end) else {
        if reported < end {
            context.mark_malformed(node, "ICMPv6 message is truncated");
        }
        return false;
    };
    if bytes.is_empty() {
        return false;
    }
    node.add_field(
        &fields::ICMPV6_RESERVED,
        Range::new(base + offset, bytes.len()),
        Value::bytes(bytes.to_vec()),
    );
    true
}

/// Add neighbor-discovery options starting at `offset`.
///
/// RFC 4861 section 4.6 gives every option a type, a length in eight-octet
/// units and a body. The option body is bounded by the declared length: a
/// field that would extend past it is reported as malformed instead of being
/// read from the bytes that follow.
fn add_options(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    mut offset: usize,
) {
    while offset < data.len() {
        let Some((&option_type, &length_units)) =
            data.get(offset).zip(data.get(offset.saturating_add(1)))
        else {
            context.mark_malformed(node, "ICMPv6 option is truncated");
            return;
        };
        let declared_length = usize::from(length_units).saturating_mul(OPTION_UNIT);
        let remaining = data.len().saturating_sub(offset);
        let option_range = Range::new(base + offset, declared_length.min(remaining));
        node.add_field(&fields::ICMPV6_OPT, option_range, Value::None);
        node.add_field(
            &fields::ICMPV6_OPT_TYPE,
            Range::new(base + offset, 1),
            Value::Uint8(option_type),
        );
        node.add_field(
            &fields::ICMPV6_OPT_LENGTH,
            Range::new(base + offset.saturating_add(1), 1),
            Value::Uint8(length_units),
        );
        if length_units == 0 {
            node.add_expert(ExpertInfo {
                severity: Severity::Error,
                group: Group::Malformed,
                message: "Invalid option length (Zero)".to_string(),
            });
            return;
        }

        let declared_end = offset.saturating_add(declared_length);
        let body_end = declared_end.min(data.len());
        let complete = decode_option_body(
            context,
            node,
            data,
            base,
            offset.saturating_add(OPTION_HEADER_LENGTH),
            option_type,
            length_units,
            body_end,
            declared_end,
        );
        if !complete || declared_end > data.len() {
            context.mark_malformed(node, "ICMPv6 option is truncated");
            return;
        }
        offset = declared_end;
    }
}

/// Decode one option body, bounded by `body_end`.
///
/// `declared_end` is the option's declared end in the message data and is
/// used to locate trailing bytes that are part of the option. Returns
/// whether every field the option type requires was present inside the
/// bound.
#[expect(
    clippy::too_many_arguments,
    reason = "the option decoder needs the message slice, its frame base and both option bounds"
)]
fn decode_option_body(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    body_start: usize,
    option_type: u8,
    length_units: u8,
    body_end: usize,
    declared_end: usize,
) -> bool {
    match option_type {
        OPTION_SOURCE_LINK_LAYER => {
            add_link_layer_option(node, data, base, body_start, body_end, length_units, false)
        }
        OPTION_TARGET_LINK_LAYER => {
            add_link_layer_option(node, data, base, body_start, body_end, length_units, true)
        }
        OPTION_PREFIX_INFORMATION => {
            add_prefix_option(node, data, base, body_start, body_end, length_units)
        }
        OPTION_REDIRECTED_HEADER => add_redirected_header_option(
            context,
            node,
            data,
            base,
            body_start,
            body_end,
            declared_end,
        ),
        OPTION_MTU => add_mtu_option(node, data, base, body_start, body_end, length_units),
        _ => {
            let body_length = usize::from(length_units)
                .saturating_mul(OPTION_UNIT)
                .saturating_sub(OPTION_HEADER_LENGTH);
            if body_end.saturating_sub(body_start) < body_length {
                return false;
            }
            let Some(body) = data.get(body_start..body_start.saturating_add(body_length)) else {
                return false;
            };
            node.add_field(
                &fields::ICMPV6_DATA,
                Range::new(base + body_start, body.len()),
                Value::bytes(body.to_vec()),
            );
            node.add_expert(ExpertInfo {
                severity: Severity::Note,
                group: Group::Undecoded,
                message: format!("Option type {option_type} is not decoded"),
            });
            true
        }
    }
}

/// Source and Target Link-Layer Address options (RFC 4861 section 4.6.1).
fn add_link_layer_option(
    node: &mut Node,
    data: &[u8],
    base: usize,
    body_start: usize,
    body_end: usize,
    length_units: u8,
    target: bool,
) -> bool {
    let body_length = body_end.saturating_sub(body_start);
    // A one-unit option carries a six-octet Ethernet address; report both the
    // generic and the specific field for this case.
    if length_units == 1 {
        let Some(address) = read_ethernet(data, body_start, body_end) else {
            return false;
        };
        node.add_field(
            &fields::ICMPV6_OPT_LINKADDR,
            Range::new(base + body_start, 6),
            Value::Ethernet(address),
        );
        let specific = if target {
            &fields::ICMPV6_OPT_TARGET_LINKADDR
        } else {
            &fields::ICMPV6_OPT_SRC_LINKADDR
        };
        node.add_field(
            specific,
            Range::new(base + body_start, 6),
            Value::Ethernet(address),
        );
        return true;
    }

    // A two-unit option whose last six octets are zero is an eight-octet
    // EUI-64 address followed by six padding octets.
    if length_units == 2
        && body_length >= LINK_LAYER_BODY_LENGTH
        && data
            .get(body_start.saturating_add(8)..body_start.saturating_add(LINK_LAYER_BODY_LENGTH))
            .is_some_and(|padding| padding.iter().all(|byte| *byte == 0))
    {
        let Some(bytes) = data.get(body_start..body_start.saturating_add(8)) else {
            return false;
        };
        let Ok(address) = <[u8; 8]>::try_from(bytes) else {
            return false;
        };
        node.add_field(
            &fields::ICMPV6_OPT_LINKADDR_EUI64,
            Range::new(base + body_start, 8),
            Value::Eui64(address),
        );
        if target {
            node.add_field(
                &fields::ICMPV6_OPT_TARGET_LINKADDR_EUI64,
                Range::new(base + body_start, 8),
                Value::Eui64(address),
            );
        } else {
            node.add_field(
                &fields::ICMPV6_OPT_SRC_LINKADDR_EUI64,
                Range::new(base + body_start, 8),
                Value::Eui64(address),
            );
            node.add_field(
                &fields::ICMPV6_OPT_LINKADDR,
                Range::new(base + body_start, 8),
                Value::bytes(address.to_vec()),
            );
            node.add_field(
                &fields::ICMPV6_OPT_SRC_LINKADDR,
                Range::new(base + body_start, 8),
                Value::bytes(address.to_vec()),
            );
        }
        node.add_field(
            &fields::ICMPV6_OPT_PADDING,
            Range::new(
                base + body_start.saturating_add(8),
                LINK_LAYER_PADDING_LENGTH,
            ),
            Value::None,
        );
        return true;
    }

    let body_length = usize::from(length_units)
        .saturating_mul(OPTION_UNIT)
        .saturating_sub(OPTION_HEADER_LENGTH);
    if body_end.saturating_sub(body_start) < body_length {
        return false;
    }
    let Some(bytes) = data.get(body_start..body_start.saturating_add(body_length)) else {
        return false;
    };
    node.add_field(
        &fields::ICMPV6_OPT_LINKADDR,
        Range::new(base + body_start, body_length),
        Value::bytes(bytes.to_vec()),
    );
    let specific = if target {
        &fields::ICMPV6_OPT_TARGET_LINKADDR
    } else {
        &fields::ICMPV6_OPT_SRC_LINKADDR
    };
    node.add_field(
        specific,
        Range::new(base + body_start, body_length),
        Value::bytes(bytes.to_vec()),
    );
    true
}

/// Prefix Information option (RFC 4861 section 4.6.2).
fn add_prefix_option(
    node: &mut Node,
    data: &[u8],
    base: usize,
    body_start: usize,
    body_end: usize,
    length_units: u8,
) -> bool {
    let body_length = body_end.saturating_sub(body_start);
    if body_length < 2 {
        return false;
    }
    let Some(&prefix_length) = data.get(body_start) else {
        return false;
    };
    node.add_field(
        &fields::ICMPV6_OPT_PREFIX_LENGTH,
        Range::new(base + body_start, 1),
        Value::Uint8(prefix_length),
    );

    let Some(&flags) = data.get(body_start.saturating_add(1)) else {
        return false;
    };
    let flag_offset = base + body_start.saturating_add(1);
    node.add_field(
        &fields::ICMPV6_OPT_PREFIX_FLAG,
        Range::new(flag_offset, 1),
        Value::Uint8(flags),
    );
    for (def, mask) in [
        (&fields::ICMPV6_OPT_PREFIX_FLAG_L, 0x80_u8),
        (&fields::ICMPV6_OPT_PREFIX_FLAG_A, 0x40),
        (&fields::ICMPV6_OPT_PREFIX_FLAG_R, 0x20),
        (&fields::ICMPV6_OPT_PREFIX_FLAG_P, 0x10),
    ] {
        node.add_field(
            def,
            Range::new(flag_offset, 1),
            Value::Boolean(flags & mask != 0),
        );
    }
    node.add_field(
        &fields::ICMPV6_OPT_PREFIX_FLAG_RESERVED,
        Range::new(flag_offset, 1),
        Value::Uint8(flags & 0x0f),
    );

    if body_length < 6 {
        return false;
    }
    let Some(valid_lifetime) = read_u32_be(data, body_start.saturating_add(2)) else {
        return false;
    };
    node.add_field(
        &fields::ICMPV6_OPT_PREFIX_VALID_LIFETIME,
        Range::new(base + body_start.saturating_add(2), 4),
        Value::Uint32(valid_lifetime),
    );
    if body_length < 10 {
        return false;
    }
    let Some(preferred_lifetime) = read_u32_be(data, body_start.saturating_add(6)) else {
        return false;
    };
    node.add_field(
        &fields::ICMPV6_OPT_PREFIX_PREFERRED_LIFETIME,
        Range::new(base + body_start.saturating_add(6), 4),
        Value::Uint32(preferred_lifetime),
    );

    let reserved_start = body_start.saturating_add(10);
    if reserved_start > body_end {
        return false;
    }
    let reserved_length = body_end.saturating_sub(reserved_start).min(4);
    node.add_field(
        &fields::ICMPV6_OPT_RESERVED,
        Range::new(base + reserved_start, reserved_length),
        Value::None,
    );

    let prefix_start = body_start.saturating_add(14);
    if body_length < PREFIX_BODY_LENGTH {
        return false;
    }
    let Some(prefix) = read_ipv6(data, prefix_start) else {
        return false;
    };
    node.add_field(
        &fields::ICMPV6_OPT_PREFIX,
        Range::new(base + prefix_start, 16),
        Value::Ipv6(prefix),
    );
    length_units == 4
}

/// MTU option (RFC 4861 section 4.6.4); its length is one eight-octet unit.
fn add_mtu_option(
    node: &mut Node,
    data: &[u8],
    base: usize,
    body_start: usize,
    body_end: usize,
    length_units: u8,
) -> bool {
    if body_start > body_end {
        return false;
    }
    let reserved_length = body_end.saturating_sub(body_start).min(2);
    node.add_field(
        &fields::ICMPV6_OPT_RESERVED,
        Range::new(base + body_start, reserved_length),
        Value::None,
    );
    let Some(mtu) = read_u32_be(data, body_start.saturating_add(2)) else {
        return false;
    };
    node.add_field(
        &fields::ICMPV6_OPT_MTU,
        Range::new(base + body_start.saturating_add(2), 4),
        Value::Uint32(mtu),
    );
    length_units == 1 && body_end.saturating_sub(body_start) >= MTU_BODY_LENGTH
}

/// Redirected Header option (RFC 4861 section 4.6.3).
fn add_redirected_header_option(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    body_start: usize,
    body_end: usize,
    declared_end: usize,
) -> bool {
    if body_start > body_end {
        return false;
    }
    let reserved_length = body_end
        .saturating_sub(body_start)
        .min(OPTION_RESERVED_LENGTH);
    node.add_field(
        &fields::ICMPV6_OPT_RESERVED,
        Range::new(base + body_start, reserved_length),
        Value::None,
    );
    let quoted_start = body_start.saturating_add(OPTION_RESERVED_LENGTH);
    if quoted_start > body_end {
        return false;
    }
    if declared_end.saturating_sub(body_start.saturating_sub(OPTION_HEADER_LENGTH)) <= OPTION_UNIT {
        return true;
    }
    node.add_field(
        &fields::ICMPV6_OPT_REDIRECTED_PACKET,
        Range::new(base + quoted_start, body_end.saturating_sub(quoted_start)),
        Value::None,
    );

    let Some(quoted) = data.get(quoted_start..body_end) else {
        return false;
    };
    let consumed = if quoted.first().is_some_and(|byte| byte >> 4 == 6) {
        decode::dispatch_quoted(context, node, quoted, base + quoted_start);
        ipv6_consumed_length(quoted)
    } else {
        quoted.len()
    };
    if declared_end > data.len() {
        return false;
    }
    let leftover_start = quoted_start.saturating_add(consumed).min(declared_end);
    if leftover_start < declared_end
        && let Some(leftover) = data.get(leftover_start..declared_end)
        && !leftover.is_empty()
    {
        node.add_field(
            &fields::ICMPV6_UNKNOWN_DATA,
            Range::new(base + leftover_start, leftover.len()),
            Value::bytes(leftover.to_vec()),
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Malformed,
            message: "Unknown Data (not interpreted)".to_string(),
        });
    }
    true
}

/// Number of bytes an IPv6 datagram consumes inside a redirected-header
/// option.
///
/// The quoted datagram is normally followed by padding inside the option;
/// RFC 4861 section 4.6.3 bounds the option by its length, so the padding is
/// reported as unknown data instead of being decoded.
fn ipv6_consumed_length(quoted: &[u8]) -> usize {
    if quoted.len() < 40 {
        return quoted.len();
    }
    let Some(payload_length) = read_u16_be(quoted, 4) else {
        return quoted.len();
    };
    let total = 40_usize.saturating_add(usize::from(payload_length));
    total.min(quoted.len())
}

/// Read a six-byte Ethernet address that must end at or before `body_end`.
fn read_ethernet(data: &[u8], offset: usize, body_end: usize) -> Option<[u8; 6]> {
    let end = offset.checked_add(6)?;
    if end > body_end {
        return None;
    }
    let bytes = data.get(offset..end)?;
    <[u8; 6]>::try_from(bytes).ok()
}
