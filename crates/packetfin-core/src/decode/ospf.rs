//! Open Shortest Path First, versions 2 and 3.
//!
//! Version 2 is RFC 2328: a 24-byte header (section A.3.1, with the
//! RFC 6549 instance identifier splitting the old 16-bit AuType field into
//! one instance byte and one authentication-type byte), the five packet
//! bodies of sections A.3.2 to A.3.6 and the LSA formats of section A.4.
//! Version 3 is RFC 5340: a 16-byte header (section A.3.1), the same five
//! packet types and the IPv6 LSA formats of section A.4. A packet is
//! version 3 when its version byte is 3; every other version uses the
//! version 2 layout.
//!
//! The version 3 checksum is the RFC 5340 section A.3.1 checksum: the
//! RFC 8200 section 8.1 IPv6 pseudo-header followed by the OSPF packet, with
//! the checksum field zeroed. The version 2 checksum excludes the 64-bit
//! authentication field (RFC 2328 section A.3.1). LSA lengths bound every
//! body field; a declared length below the header or the type's minimum, or
//! beyond the captured packet, stops that LSA after the fields already
//! decoded and marks the packet malformed.

use crate::decode::bytes::{read_ipv4, read_ipv6, read_u16_be, read_u24_be, read_u32_be};
use crate::decode::checksum::{self, InternetChecksum};
use crate::decode::{DecodeContext, NetworkContext};
use crate::fields;
use crate::tree::{ExpertInfo, Field, FieldParent, Group, Node, Range, Severity, Value};

const V2_HEADER_LENGTH: usize = 24;
const V3_HEADER_LENGTH: usize = 16;
const LSA_HEADER_LENGTH: usize = 20;
const V3_VERSION: u8 = 3;

/// Decode one OSPF packet into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::OSPF_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::OSPF_PROTOCOL, Range::new(base, data.len()));
    let Some(version) = data.first().copied() else {
        context.mark_malformed(&mut node, "OSPF packet is empty");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let header_length = if version == V3_VERSION {
        V3_HEADER_LENGTH
    } else {
        V2_HEADER_LENGTH
    };
    let mut header = node.add_container(
        &fields::OSPF_HEADER,
        Range::new(base, header_length.min(data.len())),
        Some("OSPF Header".to_string()),
    );
    header.add_field(
        &fields::OSPF_VERSION,
        Range::new(base, 1),
        Value::Uint8(version),
    );
    let Some(message_type) = data.get(1).copied() else {
        context.mark_malformed(&mut node, "OSPF header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    header.add_field(
        &fields::OSPF_MSG,
        Range::new(base + 1, 1),
        Value::Uint8(message_type),
    );
    let message_flag = match message_type {
        1 => Some(&fields::OSPF_MSG_HELLO),
        2 => Some(&fields::OSPF_MSG_DBDESC),
        3 => Some(&fields::OSPF_MSG_LSREQ),
        4 => Some(&fields::OSPF_MSG_LSUPDATE),
        5 => Some(&fields::OSPF_MSG_LSACK),
        _ => None,
    };
    if let Some(definition) = message_flag {
        header
            .add_field(definition, Range::new(base + 1, 1), Value::Boolean(true))
            .hide();
    }
    if let Some(packet_length) = read_u16_be(data, 2) {
        header.add_field(
            &fields::OSPF_PACKET_LENGTH,
            Range::new(base + 2, 2),
            Value::Uint16(packet_length),
        );
    }
    if let Some(source) = read_ipv4(data, 4) {
        header.add_field(
            &fields::OSPF_SRCROUTER,
            Range::new(base + 4, 4),
            Value::Ipv4(source),
        );
    }
    if let Some(area) = read_ipv4(data, 8) {
        let field = header.add_field(
            &fields::OSPF_AREA_ID,
            Range::new(base + 8, 4),
            Value::Ipv4(area),
        );
        if area == [0, 0, 0, 0] {
            field.showname = Some("Area ID: 0.0.0.0 (Backbone)".to_string());
        }
    }
    let declared_length_for_checksum = usize::from(read_u16_be(data, 2).unwrap_or(0));
    if let Some(checksum) = read_u16_be(data, 12) {
        let packet_end = if declared_length_for_checksum < header_length {
            header_length
        } else {
            declared_length_for_checksum.min(data.len())
        };
        let suffix = checksum_suffix(
            context,
            data,
            version,
            declared_length_for_checksum,
            packet_end,
            checksum,
        );
        let field = header.add_field(
            &fields::OSPF_CHECKSUM,
            Range::new(base + 12, 2),
            Value::Uint16(checksum),
        );
        field.showname = Some(format!("Checksum: 0x{checksum:04x}{suffix}"));
    }
    if version == V3_VERSION {
        if let Some(instance) = data.get(14).copied() {
            let field = header.add_field(
                &fields::OSPF_V3_INSTANCE_ID,
                Range::new(base + 14, 1),
                Value::Uint8(instance),
            );
            field.showname = Some(format!(
                "Instance ID: {} ({instance})",
                instance_v3_name(instance)
            ));
        }
        if let Some(reserved) = data.get(15..16) {
            header.add_field(
                &fields::OSPF_RESERVED,
                Range::new(base + 15, 1),
                Value::bytes(reserved.to_vec()),
            );
        }
    } else {
        if let Some(instance) = data.get(14).copied() {
            let field = header.add_field(
                &fields::OSPF_INSTANCE_ID,
                Range::new(base + 14, 1),
                Value::Uint8(instance),
            );
            field.showname = Some(format!(
                "Instance ID: {} ({instance})",
                instance_v2_name(instance)
            ));
        }
        if let Some(authentication_type) = data.get(15).copied() {
            let field = header.add_field(
                &fields::OSPF_AUTH_TYPE,
                Range::new(base + 15, 1),
                Value::Uint8(authentication_type),
            );
            field.showname = Some(format!(
                "Auth Type: {} ({authentication_type})",
                fields::value_name("ospf.auth.type", u64::from(authentication_type))
                    .unwrap_or("Unknown")
            ));
        }
    }

    let declared_length = usize::from(read_u16_be(data, 2).unwrap_or(0));
    let packet_end = if declared_length < header_length {
        header_length
    } else {
        declared_length.min(data.len())
    };
    if version != V3_VERSION {
        decode_v2_authentication(&mut header, data, base, declared_length, packet_end);
    }
    if data.len() < header_length {
        context.mark_malformed(&mut node, "OSPF header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }
    let mut packet_truncated = false;
    if declared_length < header_length {
        context.mark_malformed(&mut node, "OSPF packet length is shorter than its header");
        packet_truncated = true;
    } else if declared_length > data.len() {
        context.mark_malformed(&mut node, "OSPF packet length exceeds the captured packet");
        packet_truncated = true;
    }
    let body = data.get(header_length..packet_end).unwrap_or_default();
    let body_base = base + header_length;
    match message_type {
        1 => decode_hello(context, &mut node, body, body_base, version),
        2 => decode_database_description(context, &mut node, body, body_base, version),
        3 => decode_link_state_request(context, &mut node, body, body_base, version),
        4 => decode_link_state_update(context, &mut node, body, body_base, version),
        5 => decode_link_state_acknowledgement(context, &mut node, body, body_base, version),
        _ => {}
    }
    if packet_truncated && !node.protocol_exception {
        context.mark_malformed(&mut node, "OSPF packet is truncated");
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// The checksum suffix folded into the checksum showname.
///
/// A short capture or a declared length beyond it is left unverified, so no
/// suffix is printed. A mismatch names the value the packet should carry.
fn checksum_suffix(
    context: &DecodeContext<'_>,
    data: &[u8],
    version: u8,
    declared_length: usize,
    packet_end: usize,
    stored: u16,
) -> String {
    if declared_length != packet_end || packet_end < 16 {
        return String::new();
    }
    let calculated = if version == V3_VERSION {
        let Some(NetworkContext::Ipv6 {
            source,
            destination,
            ..
        }) = context.network.as_ref()
        else {
            return String::new();
        };
        let Some(length) = u32::try_from(packet_end).ok() else {
            return String::new();
        };
        let packet = data.get(..packet_end).unwrap_or_default();
        checksum::ipv6_transport(*source, *destination, 89, length, packet, 12)
    } else {
        if data.get(15).copied() == Some(2) && stored == 0 {
            return String::new();
        }
        let mut sum = InternetChecksum::new();
        sum.add(data.get(..12).unwrap_or_default());
        sum.add_u16(0);
        sum.add(data.get(14..16).unwrap_or_default());
        sum.add(data.get(24..packet_end).unwrap_or_default());
        sum.finish()
    };
    if calculated == stored || (calculated == 0 && stored == 0xffff) {
        " [correct]".to_string()
    } else {
        format!(" [incorrect, should be 0x{calculated:04x}]")
    }
}

/// The RFC 6549 instance name printed beside the numeric value.
fn instance_v2_name(value: u8) -> &'static str {
    match value {
        0 => "Base IPv4 Unicast Instance",
        1 => "Base IPv4 Multicast Instance",
        2 => "Base IPv4 In-band Management Instance",
        3..=127 => "Private Use",
        _ => "Unassigned",
    }
}

/// The RFC 5340 instance name printed beside the numeric value.
fn instance_v3_name(value: u8) -> &'static str {
    match value {
        0 => "Base IPv6 Unicast AF",
        1..=31 => "Base IPv6 Unicast AF (local policy)",
        32 => "Base IPv6 Multicast",
        33..=63 => "IPv6 Multicast AFs (local policy)",
        64 => "Base IPv4 Unicast AF",
        65..=95 => "IPv4 Unicast AFs (local policy)",
        96 => "Base IPv4 Multicast",
        97..=127 => "IPv4 Multicast AFs (local policy)",
        128..=191 => "Unassigned",
        _ => "Private Use",
    }
}

/// The 8-byte authentication field of an OSPFv2 header (RFC 2328 section
/// A.3.1, with the RFC 2328 appendix D cryptographic layout).
fn decode_v2_authentication(
    node: &mut impl FieldParent,
    data: &[u8],
    base: usize,
    declared_length: usize,
    packet_end: usize,
) {
    let Some(authentication_type) = data.get(15).copied() else {
        return;
    };
    let Some(authentication) = data.get(16..24) else {
        return;
    };
    match authentication_type {
        0 => {
            node.add_field(
                &fields::OSPF_AUTH_NONE,
                Range::new(base + 16, 8),
                Value::bytes(authentication.to_vec()),
            );
        }
        1 => {
            let end = authentication
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(authentication.len());
            let text = authentication.get(..end).unwrap_or_default();
            node.add_field(
                &fields::OSPF_AUTH_SIMPLE,
                Range::new(base + 16, 8),
                Value::String(String::from_utf8_lossy(text).into_owned()),
            );
        }
        2 => {
            let Some(key_id) = data.get(18).copied() else {
                return;
            };
            let Some(data_length) = data.get(19).copied() else {
                return;
            };
            let Some(sequence) = read_u32_be(data, 20) else {
                return;
            };
            node.add_field(
                &fields::OSPF_AUTH_CRYPT_KEY_ID,
                Range::new(base + 18, 1),
                Value::Uint8(key_id),
            );
            node.add_field(
                &fields::OSPF_AUTH_CRYPT_DATA_LENGTH,
                Range::new(base + 19, 1),
                Value::Uint8(data_length),
            );
            node.add_field(
                &fields::OSPF_AUTH_CRYPT_SEQ_NBR,
                Range::new(base + 20, 4),
                Value::Uint32(sequence),
            );
            let digest_start = declared_length.max(24);
            let digest_end = digest_start.saturating_add(usize::from(data_length));
            if let Some(digest) = data
                .get(digest_start..digest_end)
                .or_else(|| data.get(digest_start..packet_end))
            {
                node.add_field(
                    &fields::OSPF_AUTH_CRYPT_DATA,
                    Range::new(base + digest_start, digest.len()),
                    Value::bytes(digest.to_vec()),
                );
            }
        }
        _ => {
            node.add_field(
                &fields::OSPF_AUTH_UNKNOWN,
                Range::new(base + 16, 8),
                Value::bytes(authentication.to_vec()),
            );
        }
    }
}

fn decode_hello(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    body: &[u8],
    base: usize,
    version: u8,
) {
    let mut hello = node.add_container(
        &fields::OSPF_HELLO,
        Range::new(base, body.len()),
        Some("OSPF Hello Packet".to_string()),
    );
    let mut offset;
    if version == V3_VERSION {
        if let Some(interface_id) = read_u32_be(body, 0) {
            hello.add_field(
                &fields::OSPF_HELLO_INTERFACE_ID,
                Range::new(base, 4),
                Value::Uint32(interface_id),
            );
        }
        if let Some(priority) = body.get(4).copied() {
            hello.add_field(
                &fields::OSPF_HELLO_ROUTER_PRIORITY,
                Range::new(base + 4, 1),
                Value::Uint8(priority),
            );
        }
        if let Some(options) = read_u24_be(body, 5) {
            add_v3_options(&mut hello, options, base + 5);
        }
        if let Some(interval) = read_u16_be(body, 8) {
            hello.add_field(
                &fields::OSPF_HELLO_HELLO_INTERVAL,
                Range::new(base + 8, 2),
                Value::Uint32(u32::from(interval)),
            );
        }
        if let Some(interval) = read_u16_be(body, 10) {
            hello.add_field(
                &fields::OSPF_HELLO_ROUTER_DEAD_INTERVAL,
                Range::new(base + 10, 2),
                Value::Uint32(u32::from(interval)),
            );
        }
        if let Some(router) = read_ipv4(body, 12) {
            hello.add_field(
                &fields::OSPF_HELLO_DESIGNATED_ROUTER,
                Range::new(base + 12, 4),
                Value::Ipv4(router),
            );
        }
        if let Some(router) = read_ipv4(body, 16) {
            hello.add_field(
                &fields::OSPF_HELLO_BACKUP_DESIGNATED_ROUTER,
                Range::new(base + 16, 4),
                Value::Ipv4(router),
            );
        }
        offset = 20;
    } else {
        if let Some(mask) = read_ipv4(body, 0) {
            hello.add_field(
                &fields::OSPF_HELLO_NETWORK_MASK,
                Range::new(base, 4),
                Value::Ipv4(mask),
            );
        }
        if let Some(interval) = read_u16_be(body, 4) {
            hello.add_field(
                &fields::OSPF_HELLO_HELLO_INTERVAL,
                Range::new(base + 4, 2),
                Value::Uint32(u32::from(interval)),
            );
        }
        if let Some(options) = body.get(6).copied() {
            add_v2_options(&mut hello, options, base + 6);
        }
        if let Some(priority) = body.get(7).copied() {
            hello.add_field(
                &fields::OSPF_HELLO_ROUTER_PRIORITY,
                Range::new(base + 7, 1),
                Value::Uint8(priority),
            );
        }
        if let Some(interval) = read_u32_be(body, 8) {
            hello.add_field(
                &fields::OSPF_HELLO_ROUTER_DEAD_INTERVAL,
                Range::new(base + 8, 4),
                Value::Uint32(interval),
            );
        }
        if let Some(router) = read_ipv4(body, 12) {
            hello.add_field(
                &fields::OSPF_HELLO_DESIGNATED_ROUTER,
                Range::new(base + 12, 4),
                Value::Ipv4(router),
            );
        }
        if let Some(router) = read_ipv4(body, 16) {
            hello.add_field(
                &fields::OSPF_HELLO_BACKUP_DESIGNATED_ROUTER,
                Range::new(base + 16, 4),
                Value::Ipv4(router),
            );
        }
        offset = 20;
    }
    while let Some(neighbor) = read_ipv4(body, offset) {
        hello.add_field(
            &fields::OSPF_HELLO_ACTIVE_NEIGHBOR,
            Range::new(base + offset, 4),
            Value::Ipv4(neighbor),
        );
        offset += 4;
    }
    if body.len() < 20 || offset != body.len() {
        context.mark_malformed(node, "OSPF hello body length is invalid");
    }
}

fn decode_database_description(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    body: &[u8],
    base: usize,
    version: u8,
) {
    let mut description = node.add_unnamed(
        Range::new(base, body.len()),
        "OSPF DB Description".to_string(),
    );
    if version == V3_VERSION {
        if let Some(reserved) = body.get(0..1) {
            add_v3_reserved(&mut description, reserved, base);
        }
        if let Some(options) = read_u24_be(body, 1) {
            add_v3_options(&mut description, options, base + 1);
        }
        if let Some(mtu) = read_u16_be(body, 4) {
            description.add_field(
                &fields::OSPF_DB_INTERFACE_MTU,
                Range::new(base + 4, 2),
                Value::Uint16(mtu),
            );
        }
        if let Some(reserved) = body.get(6..7) {
            add_v3_reserved(&mut description, reserved, base + 6);
        }
        if let Some(flags) = body.get(7).copied() {
            add_dbd_flags(&mut description, flags, base + 7);
        }
        if let Some(sequence) = read_u32_be(body, 8) {
            description.add_field(
                &fields::OSPF_DB_DD_SEQUENCE,
                Range::new(base + 8, 4),
                Value::Uint32(sequence),
            );
        }
        if body.len() < 12 {
            context.mark_malformed(node, "OSPF database description body is truncated");
            return;
        }
        let headers = body.get(12..).unwrap_or_default();
        decode_lsa_headers(context, node, None, headers, base + 12, version, true);
    } else {
        if let Some(mtu) = read_u16_be(body, 0) {
            description.add_field(
                &fields::OSPF_DB_INTERFACE_MTU,
                Range::new(base, 2),
                Value::Uint16(mtu),
            );
        }
        if let Some(options) = body.get(2).copied() {
            add_v2_options(&mut description, options, base + 2);
        }
        if let Some(flags) = body.get(3).copied() {
            add_dbd_flags(&mut description, flags, base + 3);
        }
        if let Some(sequence) = read_u32_be(body, 4) {
            description.add_field(
                &fields::OSPF_DB_DD_SEQUENCE,
                Range::new(base + 4, 4),
                Value::Uint32(sequence),
            );
        }
        if body.len() < 8 {
            context.mark_malformed(node, "OSPF database description body is truncated");
            return;
        }
        let headers = body.get(8..).unwrap_or_default();
        decode_lsa_headers(context, node, None, headers, base + 8, version, true);
    }
}

fn add_dbd_flags(parent: &mut impl FieldParent, flags: u8, base: usize) {
    let range = Range::new(base, 1);
    let names = [
        (0x08_u8, "(R) OOBResync"),
        (0x04, "(I) Init"),
        (0x02, "(M) More"),
        (0x01, "(MS) Master"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_DBD, range, None);
    container.value = Value::Uint8(flags);
    container.showname = Some(options_showname(
        "DB Description",
        2,
        u64::from(flags),
        &visible,
    ));
    for (definition, bit, pattern, set, clear) in [
        (&fields::OSPF_DBD_R, 0x08, ".... 0...", "Set", "Not set"),
        (&fields::OSPF_DBD_I, 0x04, ".... .0..", "Set", "Not set"),
        (&fields::OSPF_DBD_M, 0x02, ".... ..0.", "Set", "Not set"),
        (&fields::OSPF_DBD_MS, 0x01, ".... ...0", "Yes", "No"),
    ] {
        let set_bit = flags & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            set,
            clear,
        );
    }
}

fn decode_link_state_request(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    body: &[u8],
    base: usize,
    version: u8,
) {
    if !body.len().is_multiple_of(12) {
        context.mark_malformed(node, "OSPF link state request body is truncated");
    }
    let mut offset = 0;
    while offset + 12 <= body.len() {
        let mut request = node.add_unnamed(
            Range::new(base + offset, 12),
            "Link State Request".to_string(),
        );
        if version == V3_VERSION {
            if let Some(reserved) = body.get(offset..offset + 2) {
                request.add_field(
                    &fields::OSPF_RESERVED,
                    Range::new(base + offset, 2),
                    Value::bytes(reserved.to_vec()),
                );
            }
            if let Some(ls_type) = read_u16_be(body, offset + 2) {
                add_v3_lsa_type(&mut request, ls_type, base + offset + 2, false);
            }
        } else if let Some(ls_type) = read_u32_be(body, offset) {
            let field = request.add_field(
                &fields::OSPF_LSA,
                Range::new(base + offset, 4),
                Value::Uint32(ls_type),
            );
            field.showname = Some(format!(
                "LS Type: {} ({ls_type})",
                fields::value_name("ospf.lsa", u64::from(ls_type)).unwrap_or("Unknown")
            ));
        }
        if let Some(link_state_id) = read_ipv4(body, offset + 4) {
            request.add_field(
                &fields::OSPF_LINK_STATE_ID,
                Range::new(base + offset + 4, 4),
                Value::Ipv4(link_state_id),
            );
        }
        if let Some(router) = read_ipv4(body, offset + 8) {
            request.add_field(
                &fields::OSPF_ADVROUTER,
                Range::new(base + offset + 8, 4),
                Value::Ipv4(router),
            );
        }
        offset += 12;
    }
}

fn decode_link_state_update(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    body: &[u8],
    base: usize,
    version: u8,
) {
    let Some(count) = read_u32_be(body, 0) else {
        context.mark_malformed(node, "OSPF link state update body is truncated");
        return;
    };
    let mut update = Field::container(
        &fields::UNNAMED_CONTAINER,
        Range::new(base, body.len()),
        Some("LS Update Packet".to_string()),
    );
    update.add_field(
        &fields::OSPF_LS_NUMBER_OF_LSAS,
        Range::new(base, 4),
        Value::Uint32(count),
    );
    let mut offset: usize = 4;
    for _ in 0..count {
        if offset
            .checked_add(LSA_HEADER_LENGTH)
            .is_none_or(|end| end > body.len())
        {
            context.mark_malformed(node, "OSPF link state update is truncated");
            node.fields.push(update);
            return;
        }
        match decode_lsa(
            context,
            node,
            Some(&mut update),
            body,
            offset,
            base,
            version,
            false,
        ) {
            Some(advance) => offset = offset.saturating_add(advance),
            None => {
                node.fields.push(update);
                return;
            }
        }
    }
    node.fields.push(update);
}

fn decode_link_state_acknowledgement(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    body: &[u8],
    base: usize,
    version: u8,
) {
    if !body.len().is_multiple_of(LSA_HEADER_LENGTH) {
        context.mark_malformed(node, "OSPF link state acknowledgement body is truncated");
    }
    let mut offset = 0;
    while offset + LSA_HEADER_LENGTH <= body.len() {
        if decode_lsa(context, node, None, body, offset, base, version, true).is_none() {
            return;
        }
        offset += LSA_HEADER_LENGTH;
    }
}

fn decode_lsa_headers(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    mut parent: Option<&mut Field>,
    body: &[u8],
    base: usize,
    version: u8,
    header_only: bool,
) {
    if !body.len().is_multiple_of(LSA_HEADER_LENGTH) {
        context.mark_malformed(node, "OSPF LSA header list is truncated");
    }
    let mut offset = 0;
    while offset + LSA_HEADER_LENGTH <= body.len() {
        if decode_lsa(
            context,
            node,
            parent.as_deref_mut(),
            body,
            offset,
            base,
            version,
            header_only,
        )
        .is_none()
        {
            return;
        }
        offset += LSA_HEADER_LENGTH;
    }
}

/// Decode one LSA starting at `offset`, returning the declared advance.
///
/// `header_only` is used inside database description and acknowledgement
/// packets, whose LSAs carry only the 20-byte header. The LSA group is built
/// locally and then appended, so the protocol node stays available for the
/// malformed marker without aliasing the group.
#[expect(
    clippy::too_many_arguments,
    reason = "the LSA decoder carries its data, base, version and header mode"
)]
fn decode_lsa(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: Option<&mut Field>,
    data: &[u8],
    offset: usize,
    base: usize,
    version: u8,
    header_only: bool,
) -> Option<usize> {
    let header = data.get(offset..offset.checked_add(LSA_HEADER_LENGTH)?)?;
    let header_base = base + offset;
    let available = data.len().saturating_sub(offset);
    let mut group = Field::container(
        &fields::UNNAMED_CONTAINER,
        Range::new(header_base, 0),
        Some(String::new()),
    );
    let (ls_type, length) = if version == V3_VERSION {
        add_lsa_header_v3(&mut group, header, header_base)
    } else {
        add_lsa_header_v2(&mut group, header, header_base)
    };
    let length_value = usize::from(length);
    let advance = length_value.max(LSA_HEADER_LENGTH);
    let group_length = if header_only {
        LSA_HEADER_LENGTH.min(available)
    } else {
        length_value.min(available)
    };
    group.range = Range::new(header_base, group_length);
    group.showname = Some(lsa_group_label(version, ls_type, length_value));
    if header_only {
        if length_value < LSA_HEADER_LENGTH {
            add_lsa_length_expert(&mut group, length_value, version, ls_type);
            append_lsa_group(node, parent, group);
            return None;
        }
        append_lsa_group(node, parent, group);
        return Some(advance);
    }
    let minimum = lsa_minimum_length(version, ls_type);
    if length_value < minimum {
        add_lsa_length_expert(&mut group, length_value, version, ls_type);
        append_lsa_group(node, parent, group);
        return None;
    }
    let body_start = offset + LSA_HEADER_LENGTH;
    let body_end = body_start.saturating_add(length_value - LSA_HEADER_LENGTH);
    let body_captured_end = body_end.min(data.len());
    let body = data.get(body_start..body_captured_end).unwrap_or_default();
    let body_base = header_base + LSA_HEADER_LENGTH;
    match version {
        V3_VERSION => decode_lsa_body_v3(context, node, &mut group, ls_type, body, body_base),
        _ => decode_lsa_body_v2(context, node, &mut group, ls_type, body, body_base),
    }
    if length_value > available {
        context.mark_malformed(node, "OSPF LSA length exceeds the captured packet");
        append_lsa_group(node, parent, group);
        return None;
    }
    append_lsa_group(node, parent, group);
    Some(length_value)
}

fn append_lsa_group(node: &mut Node, parent: Option<&mut Field>, group: Field) {
    match parent {
        Some(parent) => parent.children.push(group),
        None => node.fields.push(group),
    }
}

fn lsa_group_label(version: u8, ls_type: u32, length: usize) -> String {
    let (code, name) = if version == V3_VERSION {
        let code = ls_type & 0x1fff;
        (
            code,
            fields::value_name("ospf.v3.lsa.fc", u64::from(code)).unwrap_or("Unknown"),
        )
    } else {
        (
            ls_type,
            fields::value_name("ospf.lsa", u64::from(ls_type)).unwrap_or("Unknown"),
        )
    };
    format!("LSA-type {code} ({name}), len {length}")
}

fn add_lsa_length_expert(group: &mut Field, length: usize, version: u8, ls_type: u32) {
    let type_name = if version == V3_VERSION {
        fields::value_name("ospf.v3.lsa.fc", u64::from(ls_type & 0x1fff))
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown LSA type ({})", ls_type & 0x1fff))
    } else {
        fields::value_name("ospf.lsa", u64::from(ls_type))
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown LSA type ({ls_type})"))
    };
    let minimum = lsa_minimum_length(version, ls_type);
    let message =
        format!("Invalid LSA length ({length}) for type {type_name}, expected >= ({minimum})");
    if let Some(length_field) = group
        .children
        .iter_mut()
        .rev()
        .find(|field| field.def.abbrev == "ospf.lsa.length")
    {
        length_field.add_expert_for(
            ExpertInfo {
                severity: Severity::Error,
                group: Group::Malformed,
                message: message.clone(),
            },
            &fields::OSPF_LSA_INVALID_LENGTH,
        );
    }
    let marker = group.add_field(
        &fields::OSPF_LSA_INVALID_LENGTH,
        Range::new(0, 0),
        Value::None,
    );
    marker.hide();
    marker.showname = Some(message);
}

fn lsa_minimum_length(version: u8, ls_type: u32) -> usize {
    if version == V3_VERSION {
        match ls_type & 0x1fff {
            1 | 2 | 3 | 4 | 9 => LSA_HEADER_LENGTH + 4,
            8 => LSA_HEADER_LENGTH + 4,
            _ => LSA_HEADER_LENGTH,
        }
    } else {
        match ls_type {
            1 | 2 => LSA_HEADER_LENGTH + 4,
            3 | 4 => LSA_HEADER_LENGTH + 8,
            5 => LSA_HEADER_LENGTH + 16,
            _ => LSA_HEADER_LENGTH,
        }
    }
}

fn lsa_age_showname(age: u16) -> String {
    format!(
        "{} = LS Age (seconds): {}",
        bit_pattern(16, 0x7fff, u64::from(age)),
        age & 0x7fff
    )
}

fn add_lsa_header_v2(parent: &mut impl FieldParent, header: &[u8], base: usize) -> (u32, u16) {
    let age = read_u16_be(header, 0).unwrap_or(0);
    let options = header.get(2).copied().unwrap_or(0);
    let ls_type = u32::from(header.get(3).copied().unwrap_or(0));
    let field = parent.add_field(
        &fields::OSPF_LSA_AGE,
        Range::new(base, 2),
        Value::Uint16(age & 0x7fff),
    );
    field.showname = Some(lsa_age_showname(age));
    let field = parent.add_field(
        &fields::OSPF_LSA_DONOTAGE,
        Range::new(base, 2),
        Value::Uint16(u16::from(age & 0x8000 != 0)),
    );
    field.showname = Some(format!(
        "{} = Do Not Age Flag: {}",
        bit_pattern(16, 0x8000, u64::from(age)),
        u16::from(age & 0x8000 != 0)
    ));
    add_v2_options(parent, options, base + 2);
    let field = parent.add_field(
        &fields::OSPF_LSA,
        Range::new(base + 3, 1),
        Value::Uint32(ls_type),
    );
    field.showname = Some(format!(
        "LS Type: {} ({ls_type})",
        fields::value_name("ospf.lsa", u64::from(ls_type)).unwrap_or("Unknown")
    ));
    add_v2_lsa_type_boolean(parent, ls_type, base + 3);
    if let Some(link_state_id) = read_ipv4(header, 4) {
        parent.add_field(
            &fields::OSPF_LSA_ID,
            Range::new(base + 4, 4),
            Value::Ipv4(link_state_id),
        );
    }
    if let Some(router) = read_ipv4(header, 8) {
        parent.add_field(
            &fields::OSPF_ADVROUTER,
            Range::new(base + 8, 4),
            Value::Ipv4(router),
        );
    }
    if let Some(sequence) = read_u32_be(header, 12) {
        parent.add_field(
            &fields::OSPF_LSA_SEQNUM,
            Range::new(base + 12, 4),
            Value::Uint32(sequence),
        );
    }
    if let Some(checksum) = read_u16_be(header, 16) {
        parent.add_field(
            &fields::OSPF_LSA_CHKSUM,
            Range::new(base + 16, 2),
            Value::Uint16(checksum),
        );
    }
    let length = read_u16_be(header, 18).unwrap_or(0);
    parent.add_field(
        &fields::OSPF_LSA_LENGTH,
        Range::new(base + 18, 2),
        Value::Uint16(length),
    );
    (ls_type, length)
}

fn add_lsa_header_v3(parent: &mut impl FieldParent, header: &[u8], base: usize) -> (u32, u16) {
    let age = read_u16_be(header, 0).unwrap_or(0);
    let ls_type = u32::from(read_u16_be(header, 2).unwrap_or(0));
    let field = parent.add_field(
        &fields::OSPF_LSA_AGE,
        Range::new(base, 2),
        Value::Uint16(age & 0x7fff),
    );
    field.showname = Some(lsa_age_showname(age));
    let do_not_age = age & 0x8000 != 0;
    let field = parent.add_field(
        &fields::OSPF_V3_LSA_DO_NOT_AGE,
        Range::new(base, 2),
        Value::Boolean(do_not_age),
    );
    field.showname = Some(format!(
        "{} = Do Not Age: {}",
        bit_pattern(16, 0x8000, u64::from(age)),
        if do_not_age { "True" } else { "False" }
    ));
    add_v3_lsa_type(parent, ls_type as u16, base + 2, true);
    if let Some(link_state_id) = read_ipv4(header, 4) {
        parent.add_field(
            &fields::OSPF_LINK_STATE_ID,
            Range::new(base + 4, 4),
            Value::Ipv4(link_state_id),
        );
    }
    if let Some(router) = read_ipv4(header, 8) {
        parent.add_field(
            &fields::OSPF_ADVROUTER,
            Range::new(base + 8, 4),
            Value::Ipv4(router),
        );
    }
    if let Some(sequence) = read_u32_be(header, 12) {
        parent.add_field(
            &fields::OSPF_LSA_SEQNUM,
            Range::new(base + 12, 4),
            Value::Uint32(sequence),
        );
    }
    if let Some(checksum) = read_u16_be(header, 16) {
        parent.add_field(
            &fields::OSPF_LSA_CHKSUM,
            Range::new(base + 16, 2),
            Value::Uint16(checksum),
        );
    }
    let length = read_u16_be(header, 18).unwrap_or(0);
    parent.add_field(
        &fields::OSPF_LSA_LENGTH,
        Range::new(base + 18, 2),
        Value::Uint16(length),
    );
    (ls_type, length)
}

fn add_v2_lsa_type_boolean(parent: &mut impl FieldParent, ls_type: u32, base: usize) {
    if let Some(definition) = match ls_type {
        1 => Some(&fields::OSPF_LSA_ROUTER),
        2 => Some(&fields::OSPF_LSA_NETWORK),
        3 => Some(&fields::OSPF_LSA_SUMMARY),
        4 => Some(&fields::OSPF_LSA_ASBR),
        5 => Some(&fields::OSPF_LSA_ASEXT),
        _ => None,
    } {
        parent
            .add_field(definition, Range::new(base, 1), Value::Boolean(true))
            .hide();
    }
}

fn bit_pattern(width: usize, mask: u64, raw: u64) -> String {
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

fn add_v3_lsa_type(parent: &mut impl FieldParent, ls_type: u16, base: usize, with_boolean: bool) {
    let ls_type_u32 = u32::from(ls_type);
    let range = Range::new(base, 2);
    let container = parent.add_container(&fields::OSPF_V3_LSA, range, None);
    container.value = Value::Uint16(ls_type);
    container.showname = Some(format!("LS Type: 0x{ls_type:04x}"));
    let raw = u64::from(ls_type);
    let field = container.add_field(
        &fields::OSPF_V3_LSA_U,
        range,
        Value::Boolean(ls_type & 0x8000 != 0),
    );
    field.showname = Some(format!(
        "{} = LSA Handling: {}",
        bit_pattern(16, 0x8000, raw),
        if ls_type & 0x8000 != 0 {
            "Treat the LSA as if it had link-local flooding scope"
        } else {
            "Store and flood the LSA as if the type is understood"
        }
    ));
    let scope = u64::from((ls_type >> 13) & 0x3);
    let scope_name = fields::value_name("ospf.v3.lsa.s12", scope).unwrap_or("Reserved");
    let field = container.add_field(
        &fields::OSPF_V3_LSA_S12,
        range,
        Value::Uint16(u16::try_from(scope).unwrap_or(0)),
    );
    field.showname = Some(format!(
        "{} = Flooding Scope: {} (0x{scope:x})",
        bit_pattern(16, 0x6000, raw),
        scope_name
    ));
    let function = u64::from(ls_type & 0x1fff);
    let function_name = fields::value_name("ospf.v3.lsa.fc", function).unwrap_or("Unknown");
    let field = container.add_field(
        &fields::OSPF_V3_LSA_FC,
        range,
        Value::Uint16(ls_type & 0x1fff),
    );
    field.showname = Some(format!(
        "{} = Function Code: {} ({function})",
        bit_pattern(16, 0x1fff, raw),
        function_name
    ));
    if with_boolean
        && let Some(definition) = match ls_type & 0x1fff {
            1 => Some(&fields::OSPF_V3_LSA_ROUTER),
            2 => Some(&fields::OSPF_V3_LSA_NETWORK),
            3 => Some(&fields::OSPF_V3_LSA_INTERPREFIX),
            4 => Some(&fields::OSPF_V3_LSA_INTERROUTER),
            5 => Some(&fields::OSPF_V3_LSA_ASEXT),
            8 => Some(&fields::OSPF_V3_LSA_LINK),
            9 => Some(&fields::OSPF_V3_LSA_INTRAPREFIX),
            _ => None,
        }
    {
        parent
            .add_field(definition, range, Value::Boolean(ls_type_u32 & 0x1fff != 0))
            .hide();
    }
}

/// Add one boolean option/flag child with a bit-pattern showname.
fn add_flag_child(
    parent: &mut impl FieldParent,
    definition: &'static fields::FieldDef,
    range: Range,
    set: bool,
    pattern: &str,
    set_text: &str,
    clear_text: &str,
) {
    let field = parent.add_field(definition, range, Value::Boolean(set));
    field.showname = Some(format!(
        "{pattern} = {}: {}",
        definition.name,
        if set { set_text } else { clear_text }
    ));
}

fn options_showname(prefix: &str, width: usize, value: u64, names: &[(u64, &str)]) -> String {
    let mut text = format!("{prefix}: 0x{value:0width$x}");
    for (bit, name) in names {
        if value & bit != 0 {
            text.push_str(", ");
            text.push_str(name);
        }
    }
    text
}

fn add_v2_options(parent: &mut impl FieldParent, options: u8, base: usize) {
    let range = Range::new(base, 1);
    let names = [
        (0x80_u8, "DN"),
        (0x40, "(O) Opaque"),
        (0x20, "(DC) Demand Circuits"),
        (0x10, "(L) LLS Data block"),
        (0x08, "(N) NSSA"),
        (0x04, "(MC) Multicast"),
        (0x02, "(E) External Routing"),
        (0x01, "(MT) Multi-Topology Routing"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_V2_OPTIONS, range, None);
    container.value = Value::Uint8(options);
    container.showname = Some(options_showname("Options", 2, u64::from(options), &visible));
    for (definition, bit, pattern, set, clear) in [
        (
            &fields::OSPF_V2_OPTIONS_DN,
            0x80,
            "0... ....",
            "Set",
            "Not set",
        ),
        (
            &fields::OSPF_V2_OPTIONS_O,
            0x40,
            ".0.. ....",
            "Set",
            "Not set",
        ),
        (
            &fields::OSPF_V2_OPTIONS_DC,
            0x20,
            "..0. ....",
            "Supported",
            "Not supported",
        ),
        (
            &fields::OSPF_V2_OPTIONS_L,
            0x10,
            "...0 ....",
            "Present",
            "Not Present",
        ),
        (
            &fields::OSPF_V2_OPTIONS_N,
            0x08,
            ".... 0...",
            "Supported",
            "Not supported",
        ),
        (
            &fields::OSPF_V2_OPTIONS_MC,
            0x04,
            ".... .0..",
            "Capable",
            "Not capable",
        ),
        (
            &fields::OSPF_V2_OPTIONS_E,
            0x02,
            ".... ..0.",
            "Capable",
            "Not capable",
        ),
        (&fields::OSPF_V2_OPTIONS_MT, 0x01, ".... ...0", "Yes", "No"),
    ] {
        let set_bit = options & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            set,
            clear,
        );
    }
}

fn add_v3_reserved(parent: &mut impl FieldParent, reserved: &[u8], offset: usize) {
    let reserved_field = parent.add_field(
        &fields::OSPF_RESERVED,
        Range::new(offset, 1),
        Value::bytes(reserved.to_vec()),
    );
    if reserved.first().is_some_and(|byte| *byte != 0) {
        reserved_field.add_expert_for(
            ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: "incorrect, should be 0".to_string(),
            },
            &fields::OSPF_RESERVED_NOT_ZERO,
        );
        parent
            .add_field(
                &fields::OSPF_RESERVED_NOT_ZERO,
                Range::new(0, 0),
                Value::None,
            )
            .hide();
    }
}

fn add_v3_options(parent: &mut impl FieldParent, options: u32, base: usize) {
    let range = Range::new(base, 3);
    let names = [
        (0x400_u32, "AT"),
        (0x200, "L"),
        (0x100, "AF"),
        (0x20, "DC"),
        (0x10, "R"),
        (0x08, "N"),
        (0x04, "MC"),
        (0x02, "E"),
        (0x01, "V6"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_V3_OPTIONS, range, None);
    container.value = Value::Uint24(options);
    container.showname = Some(options_showname("Options", 6, u64::from(options), &visible));
    for (definition, bit, pattern) in [
        (
            &fields::OSPF_V3_OPTIONS_AT,
            0x400,
            ".... .... .... .0.. .... ....",
        ),
        (
            &fields::OSPF_V3_OPTIONS_L,
            0x200,
            ".... .... .... ..0. .... ....",
        ),
        (
            &fields::OSPF_V3_OPTIONS_AF,
            0x100,
            ".... .... .... ...0 .... ....",
        ),
        (
            &fields::OSPF_V3_OPTIONS_DC,
            0x20,
            ".... .... .... .... ..0. ....",
        ),
        (
            &fields::OSPF_V3_OPTIONS_R,
            0x10,
            ".... .... .... .... ...0 ....",
        ),
        (
            &fields::OSPF_V3_OPTIONS_N,
            0x08,
            ".... .... .... .... .... 0...",
        ),
        (
            &fields::OSPF_V3_OPTIONS_MC,
            0x04,
            ".... .... .... .... .... .0..",
        ),
        (
            &fields::OSPF_V3_OPTIONS_E,
            0x02,
            ".... .... .... .... .... ..0.",
        ),
        (
            &fields::OSPF_V3_OPTIONS_V6,
            0x01,
            ".... .... .... .... .... ...0",
        ),
    ] {
        let set_bit = options & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            "Set",
            "Not set",
        );
    }
}

fn add_v3_prefix_options(parent: &mut impl FieldParent, options: u8, base: usize) {
    let range = Range::new(base, 1);
    let names = [
        (0x08_u8, "(P) Propagate"),
        (0x04, "(MC) Multicast"),
        (0x02, "(LA) Local Address"),
        (0x01, "(NU) NoUnicast"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_V3_PREFIX_OPTIONS, range, None);
    container.value = Value::Uint8(options);
    container.showname = Some(options_showname(
        "PrefixOptions",
        2,
        u64::from(options),
        &visible,
    ));
    for (definition, bit, pattern) in [
        (&fields::OSPF_V3_PREFIX_OPTIONS_P, 0x08, ".... 0..."),
        (&fields::OSPF_V3_PREFIX_OPTIONS_MC, 0x04, ".... .0.."),
        (&fields::OSPF_V3_PREFIX_OPTIONS_LA, 0x02, ".... ..0."),
        (&fields::OSPF_V3_PREFIX_OPTIONS_NU, 0x01, ".... ...0"),
    ] {
        let set_bit = options & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            "Set",
            "Not set",
        );
    }
}

fn add_v2_router_flags(parent: &mut impl FieldParent, flags: u8, base: usize) {
    let range = Range::new(base, 1);
    let names = [
        (0x80_u8, "(H) Host"),
        (0x20, "(S) Shortcut-capable ABR"),
        (0x10, "(N) NSSA translation"),
        (0x08, "(W) Wild-card multicast receiver"),
        (0x04, "(V) Virtual link endpoint"),
        (0x02, "(E) AS boundary router"),
        (0x01, "(B) Area border router"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_V2_ROUTER_LSA_FLAGS, range, None);
    container.value = Value::Uint8(flags);
    container.showname = Some(options_showname("Flags", 2, u64::from(flags), &visible));
    for (definition, bit, pattern) in [
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_H, 0x80, "0... ...."),
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_S, 0x20, "..0. ...."),
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_N, 0x10, "...0 ...."),
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_W, 0x08, ".... 0..."),
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_V, 0x04, ".... .0.."),
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_E, 0x02, ".... ..0."),
        (&fields::OSPF_V2_ROUTER_LSA_FLAGS_B, 0x01, ".... ...0"),
    ] {
        let set_bit = flags & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            "Yes",
            "No",
        );
    }
}

fn add_v3_router_flags(parent: &mut impl FieldParent, flags: u8, base: usize) {
    let range = Range::new(base, 1);
    let names = [
        (0x08_u8, "(W) Wild-card multicast receiver"),
        (0x04, "(V) Virtual link endpoint"),
        (0x02, "(E) AS boundary router"),
        (0x01, "(B) Area border router"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_V3_ROUTER_LSA_FLAGS, range, None);
    container.value = Value::Uint8(flags);
    container.showname = Some(options_showname("Flags", 2, u64::from(flags), &visible));
    for (definition, bit, pattern) in [
        (&fields::OSPF_V3_ROUTER_LSA_FLAGS_W, 0x08, ".... 0..."),
        (&fields::OSPF_V3_ROUTER_LSA_FLAGS_V, 0x04, ".... .0.."),
        (&fields::OSPF_V3_ROUTER_LSA_FLAGS_E, 0x02, ".... ..0."),
        (&fields::OSPF_V3_ROUTER_LSA_FLAGS_B, 0x01, ".... ...0"),
    ] {
        let set_bit = flags & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            "Yes",
            "No",
        );
    }
}

fn add_v3_external_flags(parent: &mut impl FieldParent, flags: u8, base: usize) {
    let range = Range::new(base, 1);
    let names = [
        (0x04_u8, "(E) External Metric"),
        (0x02, "(F) Forwarding Address"),
        (0x01, "(T) External Route Tag"),
    ];
    let visible: Vec<(u64, &str)> = names
        .iter()
        .map(|(bit, name)| (u64::from(*bit), *name))
        .collect();
    let mut container = parent.add_container(&fields::OSPF_V3_AS_EXTERNAL_FLAGS, range, None);
    container.value = Value::Uint8(flags);
    container.showname = Some(options_showname("Flags", 2, u64::from(flags), &visible));
    for (definition, bit, pattern, set, clear) in [
        (
            &fields::OSPF_V3_AS_EXTERNAL_FLAGS_E,
            0x04,
            ".... .0..",
            "Type 2",
            "Type 1",
        ),
        (
            &fields::OSPF_V3_AS_EXTERNAL_FLAGS_F,
            0x02,
            ".... ..0.",
            "Present",
            "Absent",
        ),
        (
            &fields::OSPF_V3_AS_EXTERNAL_FLAGS_T,
            0x01,
            ".... ...0",
            "Present",
            "Not Present",
        ),
    ] {
        let set_bit = flags & bit != 0;
        let pattern = if set_bit {
            pattern.replace('0', "1")
        } else {
            pattern.to_string()
        };
        add_flag_child(
            &mut container,
            definition,
            range,
            set_bit,
            &pattern,
            set,
            clear,
        );
    }
}

fn decode_lsa_body_v2(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    ls_type: u32,
    body: &[u8],
    base: usize,
) {
    match ls_type {
        1 => decode_router_lsa_v2(context, node, parent, body, base),
        2 => decode_network_lsa_v2(context, node, parent, body, base),
        3 | 4 => decode_summary_lsa_v2(context, node, parent, body, base),
        5 => decode_external_lsa_v2(context, node, parent, body, base),
        _ => add_unknown_lsa(node, parent, ls_type, false),
    }
}

fn decode_router_lsa_v2(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    let Some(flags) = body.first().copied() else {
        context.mark_malformed(node, "OSPF router LSA body is truncated");
        return;
    };
    add_v2_router_flags(parent, flags, base);
    let Some(link_count) = read_u16_be(body, 2) else {
        context.mark_malformed(node, "OSPF router LSA body is truncated");
        return;
    };
    parent.add_field(
        &fields::OSPF_LSA_NUMBER_OF_LINKS,
        Range::new(base + 2, 2),
        Value::Uint16(link_count),
    );
    let mut offset = 4;
    for _ in 0..link_count {
        let Some(link_id) = read_ipv4(body, offset) else {
            context.mark_malformed(node, "OSPF router LSA link is truncated");
            return;
        };
        let Some(link_data) = read_ipv4(body, offset + 4) else {
            context.mark_malformed(node, "OSPF router LSA link is truncated");
            return;
        };
        let Some(link_type) = body.get(offset + 8).copied() else {
            context.mark_malformed(node, "OSPF router LSA link is truncated");
            return;
        };
        let Some(metrics) = body.get(offset + 9).copied() else {
            context.mark_malformed(node, "OSPF router LSA link is truncated");
            return;
        };
        let Some(metric) = read_u16_be(body, offset + 10) else {
            context.mark_malformed(node, "OSPF router LSA link is truncated");
            return;
        };
        let link = parent.add_unnamed(
            Range::new(base + offset, 12 + 4 * usize::from(metrics)),
            router_link_label(link_type, link_id, link_data, metric),
        );
        let field = link.add_field(
            &fields::OSPF_LSA_ROUTER_LINKID,
            Range::new(base + offset, 4),
            Value::Ipv4(link_id),
        );
        field.showname = Some(format!(
            "Link ID: {} - {}",
            ipv4_text(link_id),
            router_link_id_description(link_type)
        ));
        link.add_field(
            &fields::OSPF_LSA_ROUTER_LINKDATA,
            Range::new(base + offset + 4, 4),
            Value::Ipv4(link_data),
        );
        let field = link.add_field(
            &fields::OSPF_LSA_ROUTER_LINKTYPE,
            Range::new(base + offset + 8, 1),
            Value::Uint8(link_type),
        );
        field.showname = Some(format!(
            "Link Type: {link_type} - {}",
            router_link_type_name(link_type)
        ));
        let field = link.add_field(
            &fields::OSPF_LSA_ROUTER_NUMMETRICS,
            Range::new(base + offset + 9, 1),
            Value::Uint8(metrics),
        );
        field.showname = Some(format!("Number of Metrics: {metrics} - TOS"));
        let field = link.add_field(
            &fields::OSPF_LSA_ROUTER_METRIC0,
            Range::new(base + offset + 10, 2),
            Value::Uint16(metric),
        );
        field.showname = Some(format!("0 Metric: {metric}"));
        offset += 12;
        for _ in 0..metrics {
            let Some(tos_metric) = read_u16_be(body, offset + 2) else {
                context.mark_field_malformed(node, "OSPF router LSA TOS metric is truncated");
                return;
            };
            link.add_field(
                &fields::OSPF_LS_METRIC,
                Range::new(base + offset, 4),
                Value::Uint32(u32::from(tos_metric)),
            );
            offset += 4;
        }
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPF router LSA body has trailing bytes");
    }
}

fn decode_network_lsa_v2(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    let Some(mask) = read_ipv4(body, 0) else {
        context.mark_malformed(node, "OSPF network LSA body is truncated");
        return;
    };
    parent.add_field(
        &fields::OSPF_LSA_NETWORK_NETMASK,
        Range::new(base, 4),
        Value::Ipv4(mask),
    );
    let mut offset = 4;
    while let Some(router) = read_ipv4(body, offset) {
        parent.add_field(
            &fields::OSPF_LSA_NETWORK_ATTCHRTR,
            Range::new(base + offset, 4),
            Value::Ipv4(router),
        );
        offset += 4;
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPF network LSA body is truncated");
    }
}

fn decode_summary_lsa_v2(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    if let Some(mask) = read_ipv4(body, 0) {
        parent.add_field(
            &fields::OSPF_LSA_ASBR_NETMASK,
            Range::new(base, 4),
            Value::Ipv4(mask),
        );
    }
    let mut offset = 4;
    while offset + 4 <= body.len() {
        if let Some(tos) = body.get(offset).copied() {
            parent.add_field(
                &fields::OSPF_LSA_TOS,
                Range::new(base + offset, 1),
                Value::Uint8(tos),
            );
        }
        if let Some(metric) = read_u24_be(body, offset + 1) {
            parent.add_field(
                &fields::OSPF_METRIC,
                Range::new(base + offset + 1, 3),
                Value::Uint32(metric),
            );
        }
        offset += 4;
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPF summary LSA body is truncated");
    }
}

fn decode_external_lsa_v2(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    if let Some(mask) = read_ipv4(body, 0) {
        parent.add_field(
            &fields::OSPF_LSA_ASEXT_NETMASK,
            Range::new(base, 4),
            Value::Ipv4(mask),
        );
    }
    let mut offset = 4;
    while offset + 12 <= body.len() {
        let metric_word = read_u32_be(body, offset).unwrap_or(0);
        let type_byte = (metric_word >> 24) as u8;
        let external_type = metric_word & 0x8000_0000 != 0;
        let field = parent.add_field(
            &fields::OSPF_LSA_ASEXT_TYPE,
            Range::new(base + offset, 1),
            Value::Boolean(external_type),
        );
        field.showname = Some(format!(
            "{} = External Type: {}",
            bit_pattern(8, 0x80, u64::from(type_byte)),
            if external_type {
                "Type 2 (metric is larger than any other link state path)"
            } else {
                "Type 1 (metric is specified in the same units as interface cost)"
            }
        ));
        let field = parent.add_field(
            &fields::OSPF_LSA_TOS,
            Range::new(base + offset, 1),
            Value::Uint8(((metric_word >> 24) & 0x7f) as u8),
        );
        field.mask_override = Some(0x7f);
        field.showname = Some(format!(
            "{} = TOS: {}",
            bit_pattern(8, 0x7f, u64::from(type_byte)),
            (metric_word >> 24) & 0x7f
        ));
        parent.add_field(
            &fields::OSPF_METRIC,
            Range::new(base + offset + 1, 3),
            Value::Uint32(metric_word & 0x00ff_ffff),
        );
        if let Some(address) = read_ipv4(body, offset + 4) {
            parent.add_field(
                &fields::OSPF_LSA_ASEXT_FWDADDR,
                Range::new(base + offset + 4, 4),
                Value::Ipv4(address),
            );
        }
        if let Some(tag) = read_u32_be(body, offset + 8) {
            parent.add_field(
                &fields::OSPF_LSA_ASEXT_EXTRTTAG,
                Range::new(base + offset + 8, 4),
                Value::Uint32(tag),
            );
        }
        offset += 12;
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPF AS-external LSA body is truncated");
    }
}

fn decode_lsa_body_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    ls_type: u32,
    body: &[u8],
    base: usize,
) {
    match ls_type & 0x1fff {
        1 => decode_router_lsa_v3(context, node, parent, body, base),
        2 => decode_network_lsa_v3(context, node, parent, body, base),
        3 => decode_inter_area_prefix_lsa_v3(context, node, parent, body, base),
        4 => decode_inter_area_router_lsa_v3(context, node, parent, body, base),
        5 => decode_external_lsa_v3(context, node, parent, body, base),
        8 => decode_link_lsa_v3(context, node, parent, body, base),
        9 => decode_intra_area_prefix_lsa_v3(context, node, parent, body, base),
        _ => add_unknown_lsa(node, parent, ls_type, true),
    }
}

fn decode_router_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    let Some(flags) = body.first().copied() else {
        context.mark_malformed(node, "OSPFv3 router LSA body is truncated");
        return;
    };
    add_v3_router_flags(parent, flags, base);
    if let Some(options) = read_u24_be(body, 1) {
        add_v3_options(parent, options, base + 1);
    }
    let mut offset = 4;
    let mut interfaces = if offset + 16 <= body.len() {
        Some(parent.add_unnamed(
            Range::new(base + offset, body.len() - offset),
            "Router Interfaces".to_string(),
        ))
    } else {
        None
    };
    let mut entry_number = 1_u32;
    while offset + 16 <= body.len() {
        let Some(interfaces) = interfaces.as_mut() else {
            break;
        };
        let mut entry = interfaces.add_unnamed(
            Range::new(base + offset, 16),
            format!("Entry #{entry_number}"),
        );
        entry_number = entry_number.saturating_add(1);
        if let Some(link_type) = body.get(offset).copied() {
            add_v3_router_link_type(&mut entry, link_type, base + offset);
        }
        if let Some(reserved) = body.get(offset + 1..offset + 2) {
            entry.add_field(
                &fields::OSPF_RESERVED,
                Range::new(base + offset + 1, 1),
                Value::bytes(reserved.to_vec()),
            );
        }
        if let Some(metric) = read_u16_be(body, offset + 2) {
            entry.add_field(
                &fields::OSPF_METRIC,
                Range::new(base + offset + 2, 2),
                Value::Uint32(u32::from(metric)),
            );
        }
        if let Some(interface_id) = read_u32_be(body, offset + 4) {
            entry.add_field(
                &fields::OSPF_V3_LSA_INTERFACE_ID,
                Range::new(base + offset + 4, 4),
                Value::Uint32(interface_id),
            );
        }
        if let Some(interface_id) = read_u32_be(body, offset + 8) {
            entry.add_field(
                &fields::OSPF_V3_LSA_NEIGHBOR_INTERFACE_ID,
                Range::new(base + offset + 8, 4),
                Value::Uint32(interface_id),
            );
        }
        if let Some(router) = read_ipv4(body, offset + 12) {
            entry.add_field(
                &fields::OSPF_V3_LSA_NEIGHBOR_ROUTER_ID,
                Range::new(base + offset + 12, 4),
                Value::Ipv4(router),
            );
        }
        offset += 16;
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPFv3 router LSA body is truncated");
    }
}

fn add_v3_router_link_type(parent: &mut impl FieldParent, link_type: u8, base: usize) {
    let field = parent.add_field(
        &fields::OSPF_V3_LSA_TYPE,
        Range::new(base, 1),
        Value::Uint8(link_type),
    );
    field.showname = Some(format!(
        "Type: {} ({link_type})",
        fields::value_name("ospf.v3.lsa.type", u64::from(link_type)).unwrap_or("Unknown link type")
    ));
}

fn ipv4_text(address: [u8; 4]) -> String {
    std::net::Ipv4Addr::from(address).to_string()
}

fn router_link_type_name(link_type: u8) -> &'static str {
    match link_type {
        1 => "Point-to-point connection to another router",
        2 => "Connection to a transit network",
        3 => "Connection to a stub network",
        4 => "Virtual link",
        _ => "Unknown link type",
    }
}

fn router_link_short_name(link_type: u8) -> &'static str {
    match link_type {
        1 => "PTP",
        2 => "Transit",
        3 => "Stub",
        4 => "Virtual",
        _ => "Unknown",
    }
}

fn router_link_id_description(link_type: u8) -> &'static str {
    match link_type {
        1 => "Neighboring router's Router ID",
        2 => "IP address of Designated Router",
        3 => "IP network/subnet number",
        4 => "Router ID of virtual link neighbor",
        _ => "Link ID",
    }
}

fn router_link_label(link_type: u8, link_id: [u8; 4], link_data: [u8; 4], metric: u16) -> String {
    format!(
        "Type: {:<9}ID: {:<16}Data: {:<16}Metric: {metric}",
        router_link_short_name(link_type),
        ipv4_text(link_id),
        ipv4_text(link_data)
    )
}

fn decode_network_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    if let Some(reserved) = body.get(0..1) {
        parent.add_field(
            &fields::OSPF_RESERVED,
            Range::new(base, 1),
            Value::bytes(reserved.to_vec()),
        );
    }
    if let Some(options) = read_u24_be(body, 1) {
        add_v3_options(parent, options, base + 1);
    }
    let mut offset = 4;
    while let Some(router) = read_ipv4(body, offset) {
        parent.add_field(
            &fields::OSPF_V3_LSA_ATTACHED_ROUTER,
            Range::new(base + offset, 4),
            Value::Ipv4(router),
        );
        offset += 4;
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPFv3 network LSA body is truncated");
    }
}

fn decode_inter_area_prefix_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    if let Some(reserved) = body.get(0..1) {
        parent.add_field(
            &fields::OSPF_RESERVED,
            Range::new(base, 1),
            Value::bytes(reserved.to_vec()),
        );
    }
    if let Some(metric) = read_u24_be(body, 1) {
        parent.add_field(
            &fields::OSPF_METRIC,
            Range::new(base + 1, 3),
            Value::Uint32(metric),
        );
    }
    if body.len() < 8 {
        context.mark_malformed(node, "OSPFv3 inter-area prefix LSA body is truncated");
        return;
    }
    let Some(header) = decode_prefix_header(context, node, parent, body, 4, base + 4, true) else {
        return;
    };
    if let Some((address, address_length)) = header.address {
        add_prefix_address(parent, address, address_length, base + 4);
    } else if let Some(length) = header.invalid_length {
        add_invalid_prefix_group(parent, body, 4, base + 4, length, header.consumed - 4);
    }
}

fn decode_inter_area_router_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    if let Some(reserved) = body.get(0..1) {
        parent.add_field(
            &fields::OSPF_RESERVED,
            Range::new(base, 1),
            Value::bytes(reserved.to_vec()),
        );
    }
    if let Some(options) = read_u24_be(body, 1) {
        add_v3_options(parent, options, base + 1);
    }
    if let Some(reserved) = body.get(4..5) {
        parent.add_field(
            &fields::OSPF_RESERVED,
            Range::new(base + 4, 1),
            Value::bytes(reserved.to_vec()),
        );
    }
    if let Some(metric) = read_u24_be(body, 5) {
        parent.add_field(
            &fields::OSPF_METRIC,
            Range::new(base + 5, 3),
            Value::Uint32(metric),
        );
    }
    if let Some(router) = read_ipv4(body, 8) {
        parent.add_field(
            &fields::OSPF_V3_LSA_DESTINATION_ROUTER_ID,
            Range::new(base + 8, 4),
            Value::Ipv4(router),
        );
    } else {
        context.mark_malformed(node, "OSPFv3 inter-area router LSA body is truncated");
    }
}

fn decode_external_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    let Some(flags) = body.first().copied() else {
        context.mark_malformed(node, "OSPFv3 AS-external LSA body is truncated");
        return;
    };
    add_v3_external_flags(parent, flags, base);
    if let Some(metric) = read_u24_be(body, 1) {
        parent.add_field(
            &fields::OSPF_METRIC,
            Range::new(base + 1, 3),
            Value::Uint32(metric),
        );
    }
    let Some(referenced_type) = read_u16_be(body, 6) else {
        context.mark_malformed(node, "OSPFv3 AS-external LSA body is truncated");
        return;
    };
    let Some(header) = decode_prefix_header(context, node, parent, body, 4, base + 4, false) else {
        return;
    };
    add_referenced_ls_type(parent, referenced_type, base + 6);
    if let Some((address, address_length)) = header.address {
        add_prefix_address(parent, address, address_length, base + 4);
    } else if let Some(length) = header.invalid_length {
        add_invalid_prefix_group(parent, body, 4, base + 4, length, header.consumed - 4);
    }
    let mut offset = 4 + header.consumed;
    if flags & 0x02 != 0 {
        if let Some(address) = read_ipv6(body, offset) {
            parent.add_field(
                &fields::OSPF_V3_LSA_FORWARDING_ADDRESS_IPV6,
                Range::new(base + offset, 16),
                Value::Ipv6(address),
            );
        } else {
            context.mark_malformed(node, "OSPFv3 forwarding address is truncated");
            return;
        }
        offset += 16;
    }
    if flags & 0x01 != 0 {
        if let Some(tag) = read_u32_be(body, offset) {
            parent.add_field(
                &fields::OSPF_V3_LSA_EXTERNAL_ROUTE_TAG,
                Range::new(base + offset, 4),
                Value::Uint32(tag),
            );
        } else {
            context.mark_malformed(node, "OSPFv3 external route tag is truncated");
            return;
        }
        offset += 4;
    }
    if referenced_type != 0 {
        if let Some(link_state_id) = read_ipv4(body, offset) {
            parent.add_field(
                &fields::OSPF_V3_LSA_REFERENCED_LINK_STATE_ID,
                Range::new(base + offset, 4),
                Value::Ipv4(link_state_id),
            );
        } else {
            context.mark_malformed(node, "OSPFv3 referenced link state ID is truncated");
        }
    }
}

fn decode_link_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    if let Some(priority) = body.first().copied() {
        parent.add_field(
            &fields::OSPF_V3_LSA_ROUTER_PRIORITY,
            Range::new(base, 1),
            Value::Uint8(priority),
        );
    }
    if let Some(options) = read_u24_be(body, 1) {
        add_v3_options(parent, options, base + 1);
    }
    if let Some(address) = read_ipv6(body, 4) {
        parent.add_field(
            &fields::OSPF_V3_LSA_LINK_LOCAL_INTERFACE_ADDRESS_IPV6,
            Range::new(base + 4, 16),
            Value::Ipv6(address),
        );
    } else {
        context.mark_malformed(node, "OSPFv3 link LSA body is truncated");
        return;
    }
    let Some(prefix_count) = read_u32_be(body, 20) else {
        context.mark_malformed(node, "OSPFv3 link LSA body is truncated");
        return;
    };
    parent.add_field(
        &fields::OSPF_V3_LSA_NUM_PREFIXES,
        Range::new(base + 20, 4),
        Value::Uint32(prefix_count),
    );
    let mut offset = 24;
    for _ in 0..prefix_count {
        if body.len() < offset + 4 {
            context.mark_malformed(node, "OSPFv3 link LSA prefix is truncated");
            return;
        }
        let Some(header) =
            decode_prefix_header(context, node, parent, body, offset, base + offset, true)
        else {
            return;
        };
        if let Some((address, address_length)) = header.address {
            add_prefix_address(parent, address, address_length, base + offset);
        } else if let Some(length) = header.invalid_length {
            add_invalid_prefix_group(
                parent,
                body,
                offset,
                base + offset,
                length,
                header.consumed - 4,
            );
        }
        offset += header.consumed;
    }
}

fn decode_intra_area_prefix_lsa_v3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    base: usize,
) {
    let Some(prefix_count) = read_u16_be(body, 0) else {
        context.mark_malformed(node, "OSPFv3 intra-area prefix LSA body is truncated");
        return;
    };
    parent.add_field(
        &fields::OSPF_V3_LSA_NUM_PREFIXES,
        Range::new(base, 2),
        Value::Uint16(prefix_count),
    );
    if let Some(referenced_type) = read_u16_be(body, 2) {
        add_referenced_ls_type(parent, referenced_type, base + 2);
    }
    if let Some(link_state_id) = read_ipv4(body, 4) {
        parent.add_field(
            &fields::OSPF_V3_LSA_REFERENCED_LINK_STATE_ID,
            Range::new(base + 4, 4),
            Value::Ipv4(link_state_id),
        );
    }
    if let Some(router) = read_ipv4(body, 8) {
        parent.add_field(
            &fields::OSPF_V3_LSA_REFERENCED_ADVERTISING_ROUTER,
            Range::new(base + 8, 4),
            Value::Ipv4(router),
        );
    }
    if body.len() < 12 {
        context.mark_malformed(node, "OSPFv3 intra-area prefix LSA body is truncated");
        return;
    }
    let mut offset = 12;
    for _ in 0..prefix_count {
        if body.len() < offset + 4 {
            context.mark_malformed(node, "OSPFv3 intra-area prefix is truncated");
            return;
        }
        let Some(header) =
            decode_prefix_header(context, node, parent, body, offset, base + offset, false)
        else {
            return;
        };
        if let Some(metric) = read_u16_be(body, offset + 2) {
            parent.add_field(
                &fields::OSPF_METRIC,
                Range::new(base + offset + 2, 2),
                Value::Uint32(u32::from(metric)),
            );
        }
        if let Some((address, address_length)) = header.address {
            add_prefix_address(parent, address, address_length, base + offset);
        } else if let Some(length) = header.invalid_length {
            add_invalid_prefix_group(
                parent,
                body,
                offset,
                base + offset,
                length,
                header.consumed - 4,
            );
        }
        offset += header.consumed;
    }
    if offset != body.len() {
        context.mark_malformed(node, "OSPFv3 intra-area prefix LSA body has trailing bytes");
    }
}

/// Decode the four-byte OSPFv3 prefix header at `offset`.
///
/// Adds the prefix length, options and (unless the two bytes carry another
/// field) the reserved word, and returns the bytes consumed after the header,
/// the padded address and its captured length. The address occupies
/// `((length + 31) / 32) * 4` bytes (RFC 5340 section A.4.1). The caller adds
/// the address itself, because some LSAs place a metric or a referenced type
/// between the header and the address.
fn decode_prefix_header(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    parent: &mut impl FieldParent,
    body: &[u8],
    offset: usize,
    base: usize,
    reserved: bool,
) -> Option<PrefixHeader> {
    let Some(prefix_length) = body.get(offset).copied() else {
        context.mark_malformed(node, "OSPFv3 prefix header is truncated");
        return None;
    };
    let Some(options) = body.get(offset + 1).copied() else {
        context.mark_malformed(node, "OSPFv3 prefix header is truncated");
        return None;
    };
    parent.add_field(
        &fields::OSPF_PREFIX_LENGTH,
        Range::new(base, 1),
        Value::Uint8(prefix_length),
    );
    add_v3_prefix_options(parent, options, base + 1);
    if reserved && let Some(value) = body.get(offset + 2..offset + 4) {
        parent.add_field(
            &fields::OSPF_RESERVED,
            Range::new(base + 2, 2),
            Value::bytes(value.to_vec()),
        );
    }
    let words = usize::from(prefix_length).div_ceil(32);
    let Some(address_length) = words.checked_mul(4) else {
        context.mark_malformed(node, "OSPFv3 address prefix length is invalid");
        return None;
    };
    if prefix_length > 128 {
        context.mark_malformed(node, "OSPFv3 address prefix length exceeds 128 bits");
        return Some(PrefixHeader {
            consumed: 4 + address_length,
            address: None,
            invalid_length: Some(prefix_length),
        });
    }
    let Some(address) = body.get(offset + 4..offset + 4 + address_length) else {
        context.mark_malformed(node, "OSPFv3 address prefix is truncated");
        return None;
    };
    let mut padded = [0_u8; 16];
    let copy_length = address.len().min(16);
    let destination = padded.get_mut(..copy_length)?;
    destination.copy_from_slice(address.get(..copy_length)?);
    Some(PrefixHeader {
        consumed: 4 + address_length,
        address: Some((padded, address_length)),
        invalid_length: None,
    })
}

struct PrefixHeader {
    consumed: usize,
    address: Option<([u8; 16], usize)>,
    invalid_length: Option<u8>,
}

fn add_invalid_prefix_group(
    parent: &mut impl FieldParent,
    body: &[u8],
    offset: usize,
    base: usize,
    length: u8,
    padded_length: usize,
) {
    let start = offset.saturating_add(4);
    let rest = body.get(start..).unwrap_or_default();
    let remainder = rest
        .get(..padded_length.min(rest.len()))
        .unwrap_or_default();
    let message = format!("Address Prefix: length is invalid ({length}, should be <= 128)");
    let group = parent.add_unnamed(
        Range::new(base.saturating_add(4), remainder.len()),
        message.clone(),
    );
    group.add_expert_for(
        ExpertInfo {
            severity: Severity::Error,
            group: Group::Malformed,
            message: message.clone(),
        },
        &fields::OSPF_LSA_INVALID_LENGTH,
    );
    group
        .add_field(
            &fields::OSPF_LSA_INVALID_LENGTH,
            Range::new(0, 0),
            Value::None,
        )
        .hide();
}

fn add_referenced_ls_type(parent: &mut impl FieldParent, referenced_type: u16, base: usize) {
    let field = parent.add_field(
        &fields::OSPF_V3_LSA_REFERENCED_LS_TYPE,
        Range::new(base, 2),
        Value::Uint16(referenced_type),
    );
    let name =
        fields::value_name("ospf.v3.lsa.fc", u64::from(referenced_type)).unwrap_or("Unknown");
    field.showname = Some(format!(
        "Referenced LS type: {name} (0x{referenced_type:04x})"
    ));
}

fn add_prefix_address(
    parent: &mut impl FieldParent,
    address: [u8; 16],
    address_length: usize,
    prefix_base: usize,
) {
    parent.add_field(
        &fields::OSPF_V3_ADDRESS_PREFIX_IPV6,
        Range::new(prefix_base + 4, address_length),
        Value::Ipv6(address),
    );
}

fn add_unknown_lsa(node: &mut Node, parent: &mut impl FieldParent, ls_type: u32, version_3: bool) {
    parent.add_field(
        &fields::OSPF_LSA_UNKNOWN_TYPE,
        Range::new(0, 0),
        Value::None,
    );
    let message = if version_3 {
        format!("Unknown LSA Type {}", ls_type & 0x1fff)
    } else {
        "Unknown LSA Type".to_string()
    };
    node.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Protocol,
        message,
    });
}
