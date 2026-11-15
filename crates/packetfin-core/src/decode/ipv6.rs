//! Internet Protocol version 6 and its extension headers.
//!
//! The fixed header is 40 bytes. Extension headers form a chain: each one
//! names the next header and measures itself in eight-byte units. The chain is
//! followed through hop-by-hop, routing, fragment and destination options
//! headers; the first value that is not an extension header goes through the
//! IP protocol table. The decode depth limit bounds the chain.
//!
//! Options in the hop-by-hop and destination options headers are read until
//! the declared header ends, and a trailing single byte that cannot carry an
//! option length marks the header malformed. A non-atomic fragment stops the
//! chain and joins its datagram buffer; the reassembled payload is decoded
//! from the completing frame's next header. Atomic fragments decode their
//! next header directly. The network context records the addresses, final
//! next header and fragmentation state for the transport slice.

use crate::decode::bytes::{read_ipv6, read_u16_be, read_u32_be};
use crate::decode::{self, DecodeContext, LayerType, MAX_DECODE_DEPTH, NetworkContext};
use crate::fields;
use crate::state::{Frag6Key, FragmentOutcome, FragmentPart, Reassembly};
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const FIXED_HEADER_LENGTH: usize = 40;
const IPV6_VERSION: u8 = 6;
const NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const NEXT_HEADER_ROUTING: u8 = 43;
const NEXT_HEADER_FRAGMENT: u8 = 44;
const NEXT_HEADER_NO_NEXT: u8 = 59;
const NEXT_HEADER_DESTINATION: u8 = 60;

/// Smallest jumbo payload length that can replace a zero IPv6 payload length.
const MIN_JUMBO_LENGTH: u32 = 65_536;

/// A datagram that completed while following the IPv6 extension chain.
struct FragmentCompletion {
    /// The completing frame's fragment-header next-header value.
    next_header: u8,
    /// The contiguous fragmentable payload and its records.
    reassembly: Reassembly,
}

const OPTION_PAD1: u8 = 0;
const OPTION_PADN: u8 = 1;
const OPTION_ROUTER_ALERT: u8 = 5;
const OPTION_JUMBO: u8 = 0xc2;

/// Decode one IPv6 datagram into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::IPV6_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::IPV6_PROTOCOL, Range::new(base, data.len()));

    let Some(first) = data.first().copied() else {
        context.mark_malformed(&mut node, "IPv6 packet is empty");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let version = first >> 4;
    node.add_field(
        &fields::IPV6_VERSION,
        Range::new(base, 1),
        Value::Uint8(version),
    );
    if version != IPV6_VERSION {
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Protocol,
            message: format!("Bogus IPv6 version {version}"),
        });
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if data.len() >= 4
        && let Some(tclass) = read_tclass(data)
    {
        let range = Range::new(base, 2);
        node.add_field(
            &fields::IPV6_TCLASS,
            range,
            Value::Uint32(u32::from(tclass)),
        );
        node.add_field(
            &fields::IPV6_TCLASS_DSCP,
            range,
            Value::Uint32(u32::from(tclass >> 2)),
        );
        node.add_field(
            &fields::IPV6_TCLASS_ECN,
            range,
            Value::Uint32(u32::from(tclass & 0x03)),
        );
    }
    if let Some(flow) = read_flow(data) {
        node.add_field(&fields::IPV6_FLOW, Range::new(base, 4), Value::Uint24(flow));
    }
    let payload_length = if data.len() >= 7 {
        read_u16_be(data, 4)
    } else {
        None
    };
    if let Some(payload_length) = payload_length {
        node.add_field(
            &fields::IPV6_PLEN,
            Range::new(base + 4, 2),
            Value::Uint16(payload_length),
        );
    }
    let next_header = data.get(6).copied();
    if let Some(next_header) = next_header {
        node.add_field(
            &fields::IPV6_NXT,
            Range::new(base + 6, 1),
            Value::Uint8(next_header),
        );
    }
    if let Some(hop_limit) = data.get(7).copied() {
        node.add_field(
            &fields::IPV6_HLIM,
            Range::new(base + 7, 1),
            Value::Uint8(hop_limit),
        );
    }
    let source = read_ipv6(data, 8);
    let destination = read_ipv6(data, 24);
    if let Some(source) = source {
        node.add_field(
            &fields::IPV6_SRC,
            Range::new(base + 8, 16),
            Value::Ipv6(source),
        );
        let address = std::net::IpAddr::V6(std::net::Ipv6Addr::from(source));
        let host = context
            .names
            .host_mut(&address)
            .map(str::to_string)
            .unwrap_or_else(|| Value::Ipv6(source).render(fields::Display::None));
        node.add_field(
            &fields::IPV6_SRC_HOST,
            Range::new(base + 8, 16),
            Value::String(host),
        );
        node.add_field(
            &fields::IPV6_ADDR,
            Range::new(base + 8, 16),
            Value::Ipv6(source),
        );
    }
    if let Some(destination) = destination {
        node.add_field(
            &fields::IPV6_DST,
            Range::new(base + 24, 16),
            Value::Ipv6(destination),
        );
        let address = std::net::IpAddr::V6(std::net::Ipv6Addr::from(destination));
        let host = context
            .names
            .host_mut(&address)
            .map(str::to_string)
            .unwrap_or_else(|| Value::Ipv6(destination).render(fields::Display::None));
        node.add_field(
            &fields::IPV6_DST_HOST,
            Range::new(base + 24, 16),
            Value::String(host),
        );
        node.add_field(
            &fields::IPV6_ADDR,
            Range::new(base + 24, 16),
            Value::Ipv6(destination),
        );
    }

    if data.len() < FIXED_HEADER_LENGTH {
        context.mark_truncation(&mut node, "IPv6 header must be exactly 40 bytes");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }
    let (Some(source), Some(destination), Some(next_header), Some(payload_length)) =
        (source, destination, next_header, payload_length)
    else {
        context.mark_truncation(&mut node, "IPv6 header must be exactly 40 bytes");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };

    *context.network = Some(NetworkContext::Ipv6 {
        source,
        destination,
        next_header,
        fragmented: false,
    });

    let payload = data.get(FIXED_HEADER_LENGTH..).unwrap_or(&[]);
    let captured_payload = payload.len();
    let jumbo = if next_header == NEXT_HEADER_HOP_BY_HOP {
        find_jumbo_payload(payload)
    } else {
        None
    };
    let payload_end = if payload_length == 0 {
        if next_header == NEXT_HEADER_HOP_BY_HOP {
            match jumbo {
                Some(value) if value >= MIN_JUMBO_LENGTH => {
                    let declared = usize::try_from(value).unwrap_or(usize::MAX);
                    FIXED_HEADER_LENGTH.saturating_add(declared).min(data.len())
                }
                _ => {
                    context.mark_malformed(
                        &mut node,
                        "IPv6 payload length equals 0 and Hop-By-Hop present and Jumbo Payload option missing",
                    );
                    parent.add_child(node);
                    context.depth = context.depth.saturating_sub(1);
                    return;
                }
            }
        } else {
            FIXED_HEADER_LENGTH
        }
    } else {
        let declared = FIXED_HEADER_LENGTH.saturating_add(usize::from(payload_length));
        if usize::from(payload_length) > captured_payload && !context.quoted {
            node.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: format!(
                    "IPv6 payload length exceeds framing length ({captured_payload} bytes)"
                ),
            });
        }
        declared.min(data.len())
    };

    let reported_payload = if payload_length == 0 {
        jumbo
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0)
    } else {
        usize::from(payload_length)
    };

    let completion = decode_next_header(
        context,
        &mut node,
        next_header,
        data,
        ChainBounds {
            base,
            end: payload_end,
            payload_length,
            reported_payload,
        },
        FIXED_HEADER_LENGTH,
    );
    if let Some(completion) = completion {
        if context.pass == crate::state::PassMode::First {
            let completing = context.frame.file_number;
            for part in &completion.reassembly.parts {
                if part.file != completing {
                    context
                        .state
                        .annotations_mut()
                        .link_ipv6_reassembled(part.file, completing);
                }
            }
        }
        decode::ipv6_fragment_fields(&mut node, base, &completion.reassembly);
        if let Some(NetworkContext::Ipv6 { fragmented, .. }) = context.network.as_mut() {
            *fragmented = false;
        }
        let child_start = node.children.len();
        let saved_reported = context.reported_length;
        let saved_frame_reported = context.frame_reported_length;
        context.reported_length = completion.reassembly.data.len();
        context.frame_reported_length = completion.reassembly.data.len();
        let reassembled = &completion.reassembly.data;
        let payload_end = reassembled.len();
        let _ = decode_next_header(
            context,
            &mut node,
            completion.next_header,
            reassembled,
            ChainBounds {
                base: 0,
                end: payload_end,
                payload_length: 0,
                reported_payload: payload_end,
            },
            0,
        );
        if let Some(children) = node.children.get_mut(child_start..) {
            decode::annotate_reassembled_fields(children, reassembled);
        }
        context.reported_length = saved_reported;
        context.frame_reported_length = saved_frame_reported;
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Frame position and declared bounds of one IPv6 payload segment.
#[derive(Clone, Copy)]
struct ChainBounds {
    /// Frame offset of the segment's first byte.
    base: usize,
    /// Offset one past the segment's last captured byte.
    end: usize,
    /// Payload Length field of the enclosing IPv6 header.
    payload_length: u16,
    /// Payload octets the enclosing header declares for this segment.
    reported_payload: usize,
}

/// Follow one next-header value from `offset`, creating extension nodes until
/// a protocol decoder or the end of the chain is reached.
fn decode_next_header(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    next_header: u8,
    data: &[u8],
    bounds: ChainBounds,
    offset: usize,
) -> Option<FragmentCompletion> {
    let ChainBounds {
        base,
        end: payload_end,
        payload_length,
        reported_payload,
    } = bounds;
    let offset = offset.min(payload_end);
    let available = data.get(offset..payload_end).unwrap_or(&[]);
    let forced = context
        .options
        .decode_as
        .lookup(LayerType::IpProto, &[u32::from(next_header)]);
    if let Some(protocol) = forced {
        if !context.options.policy.enabled(protocol) {
            return None;
        }
        match protocol {
            fields::Protocol::Ipv6Hopopts => {
                decode_hopopts(
                    context,
                    parent,
                    available,
                    base + offset,
                    offset == FIXED_HEADER_LENGTH,
                    payload_length,
                    reported_payload,
                );
                return None;
            }
            fields::Protocol::Ipv6Routing => {
                decode_routing(
                    context,
                    parent,
                    available,
                    base + offset,
                    payload_length,
                    reported_payload,
                );
                return None;
            }
            fields::Protocol::Ipv6Fraghdr => {
                decode_fraghdr(context, parent, available, base + offset, data, bounds);
                return None;
            }
            fields::Protocol::Ipv6Dstopts => {
                decode_dstopts(
                    context,
                    parent,
                    available,
                    base + offset,
                    payload_length,
                    reported_payload,
                );
                return None;
            }
            _ => {
                if let Some(decoder) =
                    decode::forced_decoder(protocol, LayerType::IpProto, available)
                {
                    decode::dispatch_override(
                        context,
                        parent,
                        protocol,
                        decoder,
                        available,
                        base + offset,
                    );
                    return None;
                }
            }
        }
    }
    match next_header {
        NEXT_HEADER_HOP_BY_HOP => decode_hopopts(
            context,
            parent,
            available,
            base + offset,
            offset == FIXED_HEADER_LENGTH,
            payload_length,
            reported_payload,
        ),
        NEXT_HEADER_ROUTING => decode_routing(
            context,
            parent,
            available,
            base + offset,
            payload_length,
            reported_payload,
        ),
        NEXT_HEADER_FRAGMENT => {
            decode_fraghdr(context, parent, available, base + offset, data, bounds)
        }
        NEXT_HEADER_DESTINATION => decode_dstopts(
            context,
            parent,
            available,
            base + offset,
            payload_length,
            reported_payload,
        ),
        NEXT_HEADER_NO_NEXT => {
            record_next_header(context, NEXT_HEADER_NO_NEXT);
            None
        }
        _ => {
            record_next_header(context, next_header);
            let declared_remaining = reported_payload;
            let frame_remaining = context
                .frame_reported_length
                .saturating_sub(base.saturating_add(offset));
            let saved_reported = context.reported_length;
            context.reported_length = if context.quoted {
                declared_remaining
            } else {
                declared_remaining.min(frame_remaining)
            };
            if reported_payload == 0 && matches!(next_header, 4 | 41 | 47) {
                // A zero-length payload cannot carry an inner IP header;
                // report the enclosing IPv6 header as malformed instead of
                // creating an empty inner node.
                context.mark_malformed(parent, "IPv6 payload length is zero");
            } else {
                decode::dispatch_ip_protocol(
                    context,
                    parent,
                    next_header,
                    available,
                    base + offset,
                );
            }
            context.reported_length = saved_reported;
            None
        }
    }
}

/// Decode a hop-by-hop options header.
fn decode_hopopts(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    available: &[u8],
    base: usize,
    first: bool,
    payload_length: u16,
    reported_payload: usize,
) -> Option<FragmentCompletion> {
    if !context
        .options
        .policy
        .enabled(fields::Protocol::Ipv6Hopopts)
    {
        return None;
    }
    let mut node = begin_extension(
        context,
        parent,
        &fields::IPV6_HOPOPTS_PROTOCOL,
        available,
        base,
    )?;
    if available.len() < 2 {
        context.mark_malformed(&mut node, "IPv6 hop-by-hop header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    }
    if !first {
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Protocol,
            message: "IPv6 Hop-by-Hop extension header must appear immediately after IPv6 header"
                .to_string(),
        });
    }
    let Some(header) = parse_extension_common(
        &mut node,
        available,
        base,
        &fields::IPV6_HOPOPTS_NXT,
        &fields::IPV6_HOPOPTS_LEN,
        &fields::IPV6_HOPOPTS_LEN_OCT,
    ) else {
        context.mark_malformed(&mut node, "IPv6 hop-by-hop header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    };
    record_next_header(context, header.next);
    let outcome = parse_options(context, &mut node, available, base, header.total_length);
    if let Some(jumbo) = outcome.jumbo {
        if payload_length != 0 {
            add_protocol_warning(
                &mut node,
                "When IPv6 payload length does not equal 0 a Jumbo Payload option must not be present"
                    .to_string(),
            );
        }
        if jumbo < MIN_JUMBO_LENGTH {
            add_protocol_warning(
                &mut node,
                "Jumbo Payload option present and jumbo length < 65536".to_string(),
            );
        }
    }
    parent.add_child(node);
    let completion = if outcome.chain_ok
        && available.len() >= header.total_length
        && let Some(child) = parent.children.last_mut()
    {
        decode_next_header(
            context,
            child,
            header.next,
            available,
            ChainBounds {
                base,
                end: available.len(),
                payload_length,
                reported_payload: reported_payload.saturating_sub(header.total_length),
            },
            header.total_length,
        )
    } else {
        None
    };
    context.depth = context.depth.saturating_sub(1);
    completion
}

/// Decode a destination options header.
fn decode_dstopts(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    available: &[u8],
    base: usize,
    payload_length: u16,
    reported_payload: usize,
) -> Option<FragmentCompletion> {
    if !context
        .options
        .policy
        .enabled(fields::Protocol::Ipv6Dstopts)
    {
        return None;
    }
    let mut node = begin_extension(
        context,
        parent,
        &fields::IPV6_DSTOPTS_PROTOCOL,
        available,
        base,
    )?;
    if available.len() < 2 {
        context.mark_malformed(&mut node, "IPv6 destination options header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    }
    let Some(header) = parse_extension_common(
        &mut node,
        available,
        base,
        &fields::IPV6_DSTOPTS_NXT,
        &fields::IPV6_DSTOPTS_LEN,
        &fields::IPV6_DSTOPTS_LEN_OCT,
    ) else {
        context.mark_malformed(&mut node, "IPv6 destination options header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    };
    record_next_header(context, header.next);
    let outcome = parse_options(context, &mut node, available, base, header.total_length);
    parent.add_child(node);
    let completion = if outcome.chain_ok
        && available.len() >= header.total_length
        && let Some(child) = parent.children.last_mut()
    {
        decode_next_header(
            context,
            child,
            header.next,
            available,
            ChainBounds {
                base,
                end: available.len(),
                payload_length,
                reported_payload: reported_payload.saturating_sub(header.total_length),
            },
            header.total_length,
        )
    } else {
        None
    };
    context.depth = context.depth.saturating_sub(1);
    completion
}

/// Decode a routing header.
fn decode_routing(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    available: &[u8],
    base: usize,
    payload_length: u16,
    reported_payload: usize,
) -> Option<FragmentCompletion> {
    if !context
        .options
        .policy
        .enabled(fields::Protocol::Ipv6Routing)
    {
        return None;
    }
    let mut node = begin_extension(
        context,
        parent,
        &fields::IPV6_ROUTING_PROTOCOL,
        available,
        base,
    )?;
    let Some(header) = parse_extension_common(
        &mut node,
        available,
        base,
        &fields::IPV6_ROUTING_NXT,
        &fields::IPV6_ROUTING_LEN,
        &fields::IPV6_ROUTING_LEN_OCT,
    ) else {
        context.mark_malformed(&mut node, "IPv6 routing header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    };
    record_next_header(context, header.next);
    let Some(&routing_type) = available.get(2) else {
        context.mark_malformed(&mut node, "IPv6 routing header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    };
    node.add_field(
        &fields::IPV6_ROUTING_TYPE,
        Range::new(base + 2, 1),
        Value::Uint8(routing_type),
    );
    let Some(&segments_left) = available.get(3) else {
        context.mark_malformed(&mut node, "IPv6 routing header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    };
    node.add_field(
        &fields::IPV6_ROUTING_SEGLEFT,
        Range::new(base + 3, 1),
        Value::Uint8(segments_left),
    );

    let end = header.total_length.min(available.len());
    let complete = available.len() >= header.total_length;
    match routing_type {
        0 => {
            add_routing_reserved(
                &mut node,
                available,
                base,
                &fields::IPV6_ROUTING_SRC_RESERVED,
            );
            let mut address_offset = 8_usize;
            while let Some(address) = read_ipv6_limited(available, address_offset, end) {
                node.add_field(
                    &fields::IPV6_ROUTING_SRC_ADDR,
                    Range::new(base + address_offset, 16),
                    Value::Ipv6(address),
                );
                address_offset = address_offset.saturating_add(16);
            }
            node.add_expert(ExpertInfo {
                severity: Severity::Note,
                group: Group::Deprecated,
                message: "Routing header type is deprecated".to_string(),
            });
        }
        2 => {
            add_routing_reserved(
                &mut node,
                available,
                base,
                &fields::IPV6_ROUTING_MIPV6_RESERVED,
            );
            if let Some(address) = read_ipv6_limited(available, 8, end) {
                node.add_field(
                    &fields::IPV6_ROUTING_MIPV6_HOME_ADDRESS,
                    Range::new(base + 8, 16),
                    Value::Ipv6(address),
                );
            }
        }
        4 => {
            if let Some(&last_entry) = available.get(4) {
                node.add_field(
                    &fields::IPV6_ROUTING_SRH_LAST_ENTRY,
                    Range::new(base + 4, 1),
                    Value::Uint8(last_entry),
                );
            }
            if let Some(&flags) = available.get(5) {
                node.add_field(
                    &fields::IPV6_ROUTING_SRH_FLAGS,
                    Range::new(base + 5, 1),
                    Value::Uint8(flags),
                );
            }
            if let Some(tag) = available.get(6..8) {
                node.add_field(
                    &fields::IPV6_ROUTING_SRH_TAG,
                    Range::new(base + 6, 2),
                    Value::bytes(tag.to_vec()),
                );
            }
            let mut address_offset = 8_usize;
            while let Some(address) = read_ipv6_limited(available, address_offset, end) {
                node.add_field(
                    &fields::IPV6_ROUTING_SRH_ADDR,
                    Range::new(base + address_offset, 16),
                    Value::Ipv6(address),
                );
                address_offset = address_offset.saturating_add(16);
            }
        }
        _ => {
            if complete
                && end > 4
                && let Some(data) = available.get(4..end)
            {
                node.add_field(
                    &fields::IPV6_ROUTING_UNKNOWN_DATA,
                    Range::new(base + 4, data.len()),
                    Value::bytes(data.to_vec()),
                );
            }
        }
    }

    if !complete {
        context.mark_malformed(&mut node, "IPv6 routing header is truncated");
    }
    parent.add_child(node);
    let completion = if complete && let Some(child) = parent.children.last_mut() {
        decode_next_header(
            context,
            child,
            header.next,
            available,
            ChainBounds {
                base,
                end: available.len(),
                payload_length,
                reported_payload: reported_payload.saturating_sub(header.total_length),
            },
            header.total_length,
        )
    } else {
        None
    };
    context.depth = context.depth.saturating_sub(1);
    completion
}

/// Decode a fragment header.
fn decode_fraghdr(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    available: &[u8],
    base: usize,
    data: &[u8],
    chain: ChainBounds,
) -> Option<FragmentCompletion> {
    let ChainBounds {
        base: datagram_base,
        end: payload_end,
        payload_length,
        reported_payload,
    } = chain;
    if !context
        .options
        .policy
        .enabled(fields::Protocol::Ipv6Fraghdr)
    {
        return None;
    }
    let mut node = begin_extension(
        context,
        parent,
        &fields::IPV6_FRAGHDR_PROTOCOL,
        available,
        base,
    )?;
    if available.len() < 8 {
        if let Some(&next_header) = available.first() {
            record_next_header(context, next_header);
        }
        context.mark_malformed(&mut node, "IPv6 fragment header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    }
    let Some(&next_header) = available.first() else {
        context.mark_malformed(&mut node, "IPv6 fragment header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return None;
    };
    node.add_field(
        &fields::IPV6_FRAGHDR_NXT,
        Range::new(base, 1),
        Value::Uint8(next_header),
    );
    if let Some(&reserved_octet) = available.get(1) {
        node.add_field(
            &fields::IPV6_FRAGHDR_RESERVED_OCTET,
            Range::new(base + 1, 1),
            Value::Uint8(reserved_octet),
        );
    }
    let word = read_u16_be(available, 2);
    if let Some(word) = word {
        node.add_field(
            &fields::IPV6_FRAGHDR_OFFSET,
            Range::new(base + 2, 2),
            Value::Uint16(word >> 3),
        );
        node.add_field(
            &fields::IPV6_FRAGHDR_RESERVED_BITS,
            Range::new(base + 2, 2),
            Value::Uint16((word >> 1) & 0x03),
        );
        node.add_field(
            &fields::IPV6_FRAGHDR_MORE,
            Range::new(base + 2, 2),
            Value::Boolean(word & 0x0001 != 0),
        );
    }
    if let Some(identification) = read_u32_be(available, 4) {
        node.add_field(
            &fields::IPV6_FRAGHDR_IDENT,
            Range::new(base + 4, 4),
            Value::Uint32(identification),
        );
    }
    let word = word.unwrap_or(0);
    let fragmented = word & 0x0001 != 0 || word >> 3 != 0;
    if let Some(NetworkContext::Ipv6 {
        next_header: recorded,
        fragmented: recorded_fragmented,
        ..
    }) = context.network.as_mut()
    {
        *recorded = next_header;
        *recorded_fragmented = fragmented;
    }

    if !fragmented {
        // An atomic fragment (offset 0, no more fragments) is not a
        // fragmented datagram: RFC 8200 section 4.5 hands its next header
        // straight to the transport decoder.
        parent.add_child(node);
        let field_offset = base.saturating_sub(datagram_base);
        let next_offset = field_offset.saturating_add(8);
        if let Some(child) = parent.children.last_mut() {
            let _ = decode_next_header(
                context,
                child,
                next_header,
                data,
                ChainBounds {
                    base: datagram_base,
                    end: payload_end,
                    payload_length,
                    reported_payload: reported_payload.saturating_sub(8),
                },
                next_offset,
            );
        }
        context.depth = context.depth.saturating_sub(1);
        return None;
    }

    let completion = if context.quoted || !context.options.preferences.ipv6_defragment {
        // A quoted header is not traffic, and defragmentation may be off.
        None
    } else if let (
        Some(identification),
        Some(NetworkContext::Ipv6 {
            source,
            destination,
            ..
        }),
    ) = (read_u32_be(available, 4), context.network.as_ref())
    {
        let (source, destination) = (*source, *destination);
        let fragment_payload = available.get(8..).unwrap_or(&[]);
        let outcome = context.state.insert_fragment6(
            Frag6Key {
                source,
                destination,
                identification,
            },
            FragmentPart {
                offset: usize::from(word >> 3).saturating_mul(8),
                data: fragment_payload,
                declared_len: reported_payload.saturating_sub(8),
                frame: context.frame.number,
                file: context.frame.file_number,
                more: word & 0x0001 != 0,
                timestamp: context.frame.timestamp,
            },
        );
        match outcome {
            FragmentOutcome::Complete(reassembly) => Some(FragmentCompletion {
                next_header,
                reassembly,
            }),
            FragmentOutcome::Malformed => {
                node.add_expert(ExpertInfo {
                    severity: Severity::Warning,
                    group: Group::Sequence,
                    message: "IPv6 non-final fragment is not a multiple of 8 octets".to_string(),
                });
                None
            }
            other => {
                if let Some(expert) = other.own_limit_expert() {
                    node.add_expert(expert);
                }
                None
            }
        }
    } else {
        None
    };
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
    completion
}

/// The extension fields shared by all extension headers.
struct ExtensionHeader {
    next: u8,
    total_length: usize,
}

/// What an options area contained.
struct OptionsOutcome {
    /// Whether the chain may follow the next header.
    chain_ok: bool,
    /// The value of the first jumbo payload option.
    jumbo: Option<u32>,
}

/// Add the next-header and length fields shared by extension headers.
fn parse_extension_common(
    node: &mut Node,
    available: &[u8],
    base: usize,
    next_def: &'static fields::FieldDef,
    length_def: &'static fields::FieldDef,
    length_octets_def: &'static fields::FieldDef,
) -> Option<ExtensionHeader> {
    let next = available.first().copied()?;
    node.add_field(next_def, Range::new(base, 1), Value::Uint8(next));
    let length = available.get(1).copied()?;
    node.add_field(length_def, Range::new(base + 1, 1), Value::Uint8(length));
    let total_length = (usize::from(length) + 1).saturating_mul(8);
    let octets = u16::try_from(total_length).unwrap_or(u16::MAX);
    node.add_field(
        length_octets_def,
        Range::new(base + 1, 1),
        Value::Uint16(octets),
    );
    Some(ExtensionHeader { next, total_length })
}

/// Parse the options area of a hop-by-hop or destination options header.
///
/// Returns whether the area was clean: a truncated option or a declared
/// length that runs past the captured bytes stops the chain.
fn parse_options(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    available: &[u8],
    base: usize,
    total_length: usize,
) -> OptionsOutcome {
    let data_limit = available.len();
    let option_limit = total_length.min(available.len().saturating_sub(1));
    let mut offset = 2_usize;
    let mut malformed = false;
    let mut chain_ok = true;
    let mut jumbo = None;
    while offset < option_limit {
        let Some(&option_type) = available.get(offset) else {
            malformed = true;
            break;
        };
        let type_range = Range::new(base + offset, 1);
        if option_type == OPTION_PAD1 {
            node.add_field(
                &fields::IPV6_OPT_TYPE,
                type_range,
                Value::Uint8(option_type),
            );
            node.add_field(&fields::IPV6_OPT_PAD1, type_range, Value::None);
            offset = offset.saturating_add(1);
            continue;
        }
        let Some(&length) = available.get(offset.saturating_add(1)) else {
            malformed = true;
            chain_ok = false;
            break;
        };
        node.add_field(
            &fields::IPV6_OPT_TYPE,
            type_range,
            Value::Uint8(option_type),
        );
        node.add_field(
            &fields::IPV6_OPT_TYPE_ACTION,
            type_range,
            Value::Uint8(option_type >> 6),
        );
        node.add_field(
            &fields::IPV6_OPT_TYPE_CHANGE,
            type_range,
            Value::Boolean(option_type & 0x20 != 0),
        );
        node.add_field(
            &fields::IPV6_OPT_TYPE_REST,
            type_range,
            Value::Uint8(option_type & 0x1f),
        );
        node.add_field(
            &fields::IPV6_OPT_LENGTH,
            Range::new(base + offset + 1, 1),
            Value::Uint8(length),
        );
        let data_offset = offset.saturating_add(2);
        let data_end = data_offset.saturating_add(usize::from(length));
        match option_type {
            OPTION_ROUTER_ALERT => {
                if let Some(value) = read_u16_be(available, data_offset) {
                    node.add_field(
                        &fields::IPV6_OPT_ROUTER_ALERT,
                        Range::new(base + data_offset, 2),
                        Value::Uint16(value),
                    );
                    offset = data_offset.saturating_add(usize::from(length).max(2));
                } else {
                    malformed = true;
                    chain_ok = false;
                    break;
                }
            }
            OPTION_JUMBO => {
                if let Some(value) = read_u32_be(available, data_offset) {
                    node.add_field(
                        &fields::IPV6_OPT_JUMBO,
                        Range::new(base + data_offset, 4),
                        Value::Uint32(value),
                    );
                    jumbo = Some(value);
                    offset = data_offset.saturating_add(usize::from(length).max(4));
                } else {
                    malformed = true;
                    chain_ok = false;
                    break;
                }
            }
            _ => {
                if data_end > data_limit {
                    malformed = true;
                    chain_ok = false;
                    break;
                }
                let data = available.get(data_offset..data_end).unwrap_or(&[]);
                if option_type == OPTION_PADN {
                    node.add_field(
                        &fields::IPV6_OPT_PADN,
                        Range::new(base + data_offset, data.len()),
                        Value::bytes(data.to_vec()),
                    );
                }
                offset = data_end;
            }
        }
    }
    if offset < total_length {
        malformed = true;
    }
    if malformed {
        context.mark_malformed(node, "IPv6 extension header is truncated");
    }
    OptionsOutcome { chain_ok, jumbo }
}

/// Record the last next-header value the chain reached.
fn record_next_header(context: &mut DecodeContext<'_>, next_header: u8) {
    if let Some(NetworkContext::Ipv6 {
        next_header: recorded,
        ..
    }) = context.network.as_mut()
    {
        *recorded = next_header;
    }
}

/// Scan the first hop-by-hop header for a jumbo payload option.
fn find_jumbo_payload(payload: &[u8]) -> Option<u32> {
    let length = payload.get(1).copied()?;
    let total = (usize::from(length) + 1).saturating_mul(8);
    let end = total.min(payload.len());
    let mut offset = 2_usize;
    while offset < end {
        let option_type = payload.get(offset).copied()?;
        if option_type == OPTION_PAD1 {
            offset = offset.saturating_add(1);
            continue;
        }
        let length = payload.get(offset.saturating_add(1)).copied()?;
        let data_offset = offset.saturating_add(2);
        let data_end = data_offset.saturating_add(usize::from(length));
        if data_end > end {
            return None;
        }
        if option_type == OPTION_JUMBO && length == 4 {
            return read_u32_be(payload, data_offset);
        }
        offset = data_end;
    }
    None
}

/// Create an extension node after checking the depth limit.
fn begin_extension(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    protocol: &'static fields::ProtocolDef,
    available: &[u8],
    base: usize,
) -> Option<Node> {
    if context.depth >= MAX_DECODE_DEPTH {
        context.mark_malformed(parent, "Decoding depth limit reached");
        return None;
    }
    context.depth = context.depth.saturating_add(1);
    context.protocol_stack.push(protocol.filter_name);
    Some(Node::new(protocol, Range::new(base, available.len())))
}

/// Add the four reserved bytes of a routing header.
fn add_routing_reserved(
    node: &mut Node,
    available: &[u8],
    base: usize,
    def: &'static fields::FieldDef,
) {
    if let Some(reserved) = available.get(4..8) {
        node.add_field(
            def,
            Range::new(base + 4, 4),
            Value::bytes(reserved.to_vec()),
        );
    }
}

/// Read a 16-byte address at `offset`, without reading beyond `end`.
fn read_ipv6_limited(data: &[u8], offset: usize, end: usize) -> Option<[u8; 16]> {
    let address_end = offset.checked_add(16)?;
    if address_end > end {
        return None;
    }
    read_ipv6(data, offset)
}

/// The traffic-class bits of the first 32-bit word.
fn read_tclass(data: &[u8]) -> Option<u8> {
    let first = data.first().copied()?;
    let second = data.get(1).copied()?;
    Some(((first & 0x0f) << 4) | (second >> 4))
}

/// The 20-bit flow label from bytes 1 through 3.
fn read_flow(data: &[u8]) -> Option<u32> {
    let first = data.get(1).copied()?;
    let second = data.get(2).copied()?;
    let third = data.get(3).copied()?;
    Some((u32::from(first & 0x0f) << 16) | (u32::from(second) << 8) | u32::from(third))
}

fn add_protocol_warning(node: &mut Node, message: String) {
    node.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Protocol,
        message,
    });
}

/// Decode a standalone hop-by-hop header, used when `-d ip.proto` forces one
/// outside an IPv6 chain.
pub(crate) fn decode_hopopts_standalone(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    let length = u16::try_from(data.len()).unwrap_or(u16::MAX);
    decode_hopopts(context, parent, data, base, true, length, data.len());
}

/// Decode a standalone destination-options header.
pub(crate) fn decode_dstopts_standalone(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    let length = u16::try_from(data.len()).unwrap_or(u16::MAX);
    decode_dstopts(context, parent, data, base, length, data.len());
}

/// Decode a standalone routing header.
pub(crate) fn decode_routing_standalone(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    let length = u16::try_from(data.len()).unwrap_or(u16::MAX);
    decode_routing(context, parent, data, base, length, data.len());
}

/// Decode a standalone fragment header.
pub(crate) fn decode_fraghdr_standalone(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    let length = u16::try_from(data.len()).unwrap_or(u16::MAX);
    decode_fraghdr(
        context,
        parent,
        data,
        base,
        data,
        ChainBounds {
            base,
            end: data.len(),
            payload_length: length,
            reported_payload: data.len(),
        },
    );
}
