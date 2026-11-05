//! Virtual Router Redundancy Protocol, versions 2 and 3.
//!
//! The eight-byte fixed header carries a four-bit version and type, the
//! virtual router identifier, priority, address count, and the checksum
//! (RFC 3768 section 5.1, RFC 5798 section 5.1). Version 2 follows the
//! header with authentication type and advertisement interval fields plus
//! eight bytes of authentication data (RFC 3768 section 5.1); version 3
//! replaces those four bytes with a reserved nibble and a twelve-bit
//! advertisement interval in centiseconds (RFC 5798 section 5.1).
//!
//! Addresses are four bytes over IPv4 and sixteen over IPv6. A version 2
//! checksum covers the VRRP message alone (RFC 3768 section 5.3.8); a
//! version 3 checksum over IPv4 is computed the same way, while IPv6
//! prepends the RFC 2460 section 8.1 pseudo-header (RFC 5798 section 5.2.8).

use crate::decode::bytes::{read_ipv4, read_ipv6, read_u16_be};
use crate::decode::checksum::{self, ChecksumFields, ZeroChecksum};
use crate::decode::{DecodeContext, NetworkContext};
use crate::fields;
use crate::tree::{Node, Range, Severity, Value};

const FIXED_HEADER_LENGTH: usize = 8;
const CHECKSUM_OFFSET: usize = 6;
const VERSION_3_HEADER: u8 = 3;
const ADDRESS_LENGTH_V4: usize = 4;
const ADDRESS_LENGTH_V6: usize = 16;

/// Decode one VRRP advertisement into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::VRRP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::VRRP_PROTOCOL, Range::new(base, data.len()));
    let Some(type_version) = data.first().copied() else {
        context.mark_malformed(&mut node, "VRRP header is empty");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let version = type_version >> 4;
    let message_type = type_version & 0x0f;
    let typever = node.add_container(
        &fields::VRRP_TYPEVER,
        Range::new(base, 1),
        Some(format!(
            "Version {version}, Packet type {message_type} ({})",
            fields::value_name("vrrp.type", u64::from(message_type)).unwrap_or("Unknown")
        )),
    );
    typever.value = Value::Uint8(type_version);
    let field = typever.add_field(
        &fields::VRRP_VERSION,
        Range::new(base, 1),
        Value::Uint8(version),
    );
    field.showname = Some(format!(
        "{} = VRRP protocol version: {version}",
        vrrp_bit_pattern(8, 0xf0, u64::from(type_version))
    ));
    let field = typever.add_field(
        &fields::VRRP_TYPE,
        Range::new(base, 1),
        Value::Uint8(message_type),
    );
    field.showname = Some(format!(
        "{} = VRRP packet type: {} ({message_type})",
        vrrp_bit_pattern(8, 0x0f, u64::from(type_version)),
        fields::value_name("vrrp.type", u64::from(message_type)).unwrap_or("Unknown")
    ));
    let Some(virtual_router_id) = data.get(1).copied() else {
        context.mark_malformed(&mut node, "VRRP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    node.add_field(
        &fields::VRRP_VIRT_RTR_ID,
        Range::new(base + 1, 1),
        Value::Uint8(virtual_router_id),
    );
    let Some(priority) = data.get(2).copied() else {
        context.mark_malformed(&mut node, "VRRP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let priority_field = node.add_field(
        &fields::VRRP_PRIO,
        Range::new(base + 2, 1),
        Value::Uint8(priority),
    );
    priority_field.showname = Some(format!(
        "Priority: {priority} ({})",
        match priority {
            255 => "Address owner (highest priority)",
            100 => "Default priority for a backup VRRP router",
            _ => "Non-default backup priority",
        }
    ));
    let Some(address_count) = data.get(3).copied() else {
        context.mark_malformed(&mut node, "VRRP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    node.add_field(
        &fields::VRRP_ADDR_COUNT,
        Range::new(base + 3, 1),
        Value::Uint8(address_count),
    );

    if version == VERSION_3_HEADER {
        if let (Some(reserved), Some(interval)) = (data.get(4).copied(), read_u16_be(data, 4)) {
            let field = node.add_field(
                &fields::VRRP_RESERVED_MBZ,
                Range::new(base + 4, 1),
                Value::Uint8(reserved >> 4),
            );
            field.showname = Some(format!(
                "{} = Reserved: {}",
                vrrp_bit_pattern(8, 0xf0, u64::from(reserved)),
                reserved >> 4
            ));
            let field = node.add_field(
                &fields::VRRP_SHORT_ADVER_INT,
                Range::new(base + 4, 2),
                Value::Uint16(interval & 0x0fff),
            );
            field.showname = Some(format!(
                "{} = Adver Int: {}",
                vrrp_bit_pattern(16, 0x0fff, u64::from(interval)),
                interval & 0x0fff
            ));
        }
    } else {
        if let Some(auth_type) = data.get(4).copied() {
            node.add_field(
                &fields::VRRP_AUTH_TYPE,
                Range::new(base + 4, 1),
                Value::Uint8(auth_type),
            );
        }
        if let Some(interval) = data.get(5).copied() {
            node.add_field(
                &fields::VRRP_ADVER_INT,
                Range::new(base + 5, 1),
                Value::Uint8(interval),
            );
        }
    }

    let Some(stored_checksum) = read_u16_be(data, CHECKSUM_OFFSET) else {
        context.mark_malformed(&mut node, "VRRP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let calculated = calculated_checksum(context, data, version);
    let checksum_text = match calculated {
        Some(expected) if expected == stored_checksum => {
            format!("Checksum: 0x{stored_checksum:04x} [correct]")
        }
        Some(expected) => {
            format!("Checksum: 0x{stored_checksum:04x} incorrect, should be 0x{expected:04x}")
        }
        None => format!("Checksum: 0x{stored_checksum:04x}"),
    };
    node.add_field(
        &fields::VRRP_CHECKSUM,
        Range::new(base + CHECKSUM_OFFSET, 2),
        Value::Uint16(stored_checksum),
    )
    .showname = Some(checksum_text);

    checksum::report(
        &mut node,
        ChecksumFields {
            status: &fields::VRRP_CHECKSUM_STATUS,
            calculated: None,
        },
        Range::new(base + CHECKSUM_OFFSET, 2),
        stored_checksum,
        calculated,
        ZeroChecksum::Validate,
        Severity::Warning,
        false,
    );
    if let Some(calculated) = calculated
        && calculated != stored_checksum
        && !(calculated == 0 && stored_checksum == 0xffff)
    {
        node.add_field(
            &fields::VRRP_CHECKSUM_BAD_EXPERT,
            Range::new(base + CHECKSUM_OFFSET, 2),
            Value::None,
        )
        .hide();
    }

    let family = address_family(context);
    let address_length = match family {
        AddressFamily::Ipv4 => ADDRESS_LENGTH_V4,
        AddressFamily::Ipv6 => ADDRESS_LENGTH_V6,
    };
    let mut offset = FIXED_HEADER_LENGTH;
    let mut truncated = false;
    for _ in 0..address_count {
        let range = Range::new(base + offset, address_length);
        match family {
            AddressFamily::Ipv4 => {
                let Some(address) = read_ipv4(data, offset) else {
                    truncated = true;
                    break;
                };
                node.add_field(&fields::VRRP_IP_ADDR, range, Value::Ipv4(address));
            }
            AddressFamily::Ipv6 => {
                let Some(address) = read_ipv6(data, offset) else {
                    truncated = true;
                    break;
                };
                node.add_field(&fields::VRRP_IPV6_ADDR, range, Value::Ipv6(address));
            }
        }
        offset = offset.saturating_add(address_length);
    }
    if truncated {
        context.mark_malformed(&mut node, "VRRP address list is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if version != VERSION_3_HEADER
        && let Some(auth_type) = data.get(4).copied()
    {
        decode_authentication(&mut node, data, offset, base, auth_type);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Address width selected by the enclosing IP header.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

fn address_family(context: &DecodeContext<'_>) -> AddressFamily {
    match context.network.as_ref() {
        Some(NetworkContext::Ipv6 { .. }) => AddressFamily::Ipv6,
        _ => AddressFamily::Ipv4,
    }
}

/// RFC 3768 section 5.3.8 checksum, with the RFC 5798 section 5.2.8
/// IPv6 pseudo-header for version 3.
fn calculated_checksum(context: &DecodeContext<'_>, data: &[u8], version: u8) -> Option<u16> {
    if version == VERSION_3_HEADER
        && let Some(NetworkContext::Ipv6 {
            source,
            destination,
            ..
        }) = context.network.as_ref()
    {
        let length = u32::try_from(data.len()).ok()?;
        return Some(checksum::ipv6_transport(
            *source,
            *destination,
            112,
            length,
            data,
            CHECKSUM_OFFSET,
        ));
    }
    Some(checksum::without_pseudo_header(data, CHECKSUM_OFFSET))
}

/// Version 2 authentication data: a simple password or raw bytes.
fn vrrp_bit_pattern(width: usize, mask: u64, raw: u64) -> String {
    let mut pattern = String::with_capacity(width + width / 4 + 2);
    for bit in (0..width).rev() {
        let bit_mask = 1_u64 << bit;
        if mask & bit_mask == 0 {
            pattern.push('.');
        } else {
            pattern.push(if raw & bit_mask != 0 { '1' } else { '0' });
        }
        if bit % 4 == 0 && bit != 0 {
            pattern.push(' ');
        }
    }
    pattern
}

fn decode_authentication(node: &mut Node, data: &[u8], offset: usize, base: usize, auth_type: u8) {
    let Some(authentication) = data.get(offset..offset.saturating_add(8)) else {
        return;
    };
    let range = Range::new(base + offset, authentication.len());
    match auth_type {
        1 => {
            let end = authentication
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(authentication.len());
            let text = authentication.get(..end).unwrap_or_default();
            node.add_field(
                &fields::VRRP_AUTH_STRING,
                range,
                Value::String(String::from_utf8_lossy(text).into_owned()),
            );
        }
        254 => {
            node.add_field(
                &fields::VRRP_MD5_AUTH_DATA,
                range,
                Value::bytes(authentication.to_vec()),
            );
        }
        _ => {}
    }
}
