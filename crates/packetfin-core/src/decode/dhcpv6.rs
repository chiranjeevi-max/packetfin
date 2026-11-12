//! DHCPv6 over UDP.
//!
//! The message header, relay header and option TLV layout follow RFC 8415
//! sections 8 and 21: a one-octet message type, a three-octet transaction ID
//! (or, for Relay-forw/Relay-reply, a hop count and two 16-octet addresses),
//! then options with 16-bit type and length. Identity associations
//! (IA_NA/IA_TA/IA_PD), IA Address and IA Prefix nest further options; every
//! nested body is bounded by its declared length and the enclosing option.
//! A truncated option header or a body that runs past the message is skipped,
//! so the rest of the message still decodes.
//!
//! Each option is a `dhcpv6.option.type_str` container that holds its type,
//! length and decoded subfields.

use crate::decode::bytes::{
    ascii_lossy, hex_lower, link_layer_mac, link_layer_text, nul_terminated_text,
};
use crate::decode::{DecodeContext, MAX_DECODE_DEPTH};
use crate::fields;
use crate::tree::{ExpertInfo, FieldParent, Group, Node, Range, Severity, Value};

const MESSAGE_TYPE: usize = 0;
const TRANSACTION_ID: usize = 1;
const RELAY_HEADER: usize = 34;

const RELAY_FORWARD: u8 = 12;
const RELAY_REPLY: u8 = 13;

const OPTION_CLIENT_ID: u16 = 1;
const OPTION_SERVER_ID: u16 = 2;
const OPTION_IA_NA: u16 = 3;
const OPTION_IA_TA: u16 = 4;
const OPTION_IA_ADDRESS: u16 = 5;
const OPTION_ORO: u16 = 6;
const OPTION_PREFERENCE: u16 = 7;
const OPTION_ELAPSED_TIME: u16 = 8;
const OPTION_RELAY_MESSAGE: u16 = 9;
const OPTION_STATUS_CODE: u16 = 13;
const OPTION_INTERFACE_ID: u16 = 18;
const OPTION_RECONFIGURE_MESSAGE: u16 = 19;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_DOMAIN_LIST: u16 = 24;
const OPTION_IA_PD: u16 = 25;
const OPTION_IA_PREFIX: u16 = 26;

/// Seconds between 2000-01-01 and the Unix epoch; DUID times use that base.
const DUID_EPOCH_OFFSET: u32 = 946_684_800;

/// Decode one DHCPv6 message into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    decode_message(context, parent, data, base);
}

fn decode_message(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    if context.depth >= MAX_DECODE_DEPTH {
        context.mark_malformed(parent, "DHCPv6 relay nesting is too deep");
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::DHCPV6_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::DHCPV6_PROTOCOL, Range::new(base, data.len()));
    parse_message_into(&mut node, context, data, base);

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn parse_message_into(node: &mut Node, context: &mut DecodeContext<'_>, data: &[u8], base: usize) {
    let Some(message_type) = data.first().copied() else {
        return;
    };
    node.add_field(
        &fields::DHCPV6_MSGTYPE,
        Range::new(base + MESSAGE_TYPE, 1),
        Value::Uint8(message_type),
    );
    if message_type == RELAY_FORWARD || message_type == RELAY_REPLY {
        let Some(hop_count) = data.get(1).copied() else {
            context.mark_malformed(node, "DHCPv6 relay header is truncated");
            return;
        };
        node.add_field(
            &fields::DHCPV6_HOPCOUNT,
            Range::new(base + 1, 1),
            Value::Uint8(hop_count),
        );
        let Some(link) = data.get(2..18) else {
            context.mark_malformed(node, "DHCPv6 relay header is truncated");
            return;
        };
        node.add_field(
            &fields::DHCPV6_LINKADDR,
            Range::new(base + 2, 16),
            Value::Ipv6(ipv6(link)),
        );
        let Some(peer) = data.get(18..34) else {
            // Keep the link address and show the malformed line in the detail
            // view, but do not append the summary marker.
            node.protocol_exception = true;
            node.add_expert(ExpertInfo {
                severity: Severity::Error,
                group: Group::Malformed,
                message: "DHCPv6 relay header is truncated".to_string(),
            });
            return;
        };
        node.add_field(
            &fields::DHCPV6_PEERADDR,
            Range::new(base + 18, 16),
            Value::Ipv6(ipv6(peer)),
        );
        let mut malformed = None;
        let nested = parse_options(
            node,
            context,
            data,
            base,
            RELAY_HEADER,
            data.len(),
            &mut malformed,
        );
        if let Some(message) = malformed {
            context.mark_malformed(node, message);
        }
        if hop_count != 0 && !nested {
            node.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: format!(
                    "Hopcount of most inner message has to equal 0 instead of {hop_count}"
                ),
            });
        }
        return;
    }

    let Some(xid) = data.get(TRANSACTION_ID..TRANSACTION_ID + 3) else {
        context.mark_malformed(node, "DHCPv6 header is truncated");
        return;
    };
    let value = xid
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    node.add_field(
        &fields::DHCPV6_XID,
        Range::new(base + TRANSACTION_ID, 3),
        Value::Uint24(value),
    );
    let mut malformed = None;
    parse_options(node, context, data, base, 4, data.len(), &mut malformed);
    if let Some(message) = malformed {
        context.mark_malformed(node, message);
    }
}

fn parse_options(
    parent: &mut dyn FieldParent,
    context: &mut DecodeContext<'_>,
    data: &[u8],
    base: usize,
    start: usize,
    end: usize,
    malformed: &mut Option<&'static str>,
) -> bool {
    let end = end.min(data.len());
    let mut position = start;
    let mut relay_message = false;
    while position < end {
        let Some(header) = data.get(position..position + 4) else {
            break;
        };
        let Ok(header) = <[u8; 4]>::try_from(header) else {
            break;
        };
        let option_type = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let body_start = position + 4;
        let Some(body) = data.get(body_start..body_start + length) else {
            // Ignore an option whose declared body is not captured.
            break;
        };
        let name = option_name(option_type)
            .map(str::to_string)
            .unwrap_or_else(|| format!("DHCP option {option_type}"));
        let field = parent.add_container(
            &fields::DHCPV6_OPTION_TYPE_STR,
            Range::new(base + position, 4 + length),
            Some(name.clone()),
        );
        field.value = Value::String(name);
        let type_label = match option_name(option_type) {
            Some(name) => format!("Option: {name} ({option_type})"),
            None => format!("Option: Unknown ({option_type})"),
        };
        let type_field = field.add_field(
            &fields::DHCPV6_OPTION_TYPE,
            Range::new(base + position, 2),
            Value::Uint16(option_type),
        );
        type_field.showname = Some(type_label);
        field.add_field(
            &fields::DHCPV6_OPTION_LENGTH,
            Range::new(base + position + 2, 2),
            Value::Uint16(u16::try_from(length).unwrap_or(u16::MAX)),
        );
        if option_type == OPTION_RELAY_MESSAGE {
            relay_message = true;
        }
        decode_option(
            field,
            context,
            option_type,
            body,
            base + body_start,
            base + position,
            malformed,
        );
        position = body_start + length;
    }
    relay_message
}

/// Recurse into an option body with the shared decode-depth bound.
///
/// IA_NA, IA_TA, IA_PD, IA Address and IA Prefix bodies nest further options
/// and a hostile datagram can chain thousands of one-item IAs. The counter is
/// the same one used for relay nesting, so every recursive structure stops
/// deterministically and marks only the DHCPv6 node.
fn parse_nested_options(
    parent: &mut dyn FieldParent,
    context: &mut DecodeContext<'_>,
    data: &[u8],
    base: usize,
    start: usize,
    end: usize,
    malformed: &mut Option<&'static str>,
) {
    if context.depth >= MAX_DECODE_DEPTH {
        *malformed = Some("DHCPv6 option nesting is too deep");
        return;
    }
    context.depth = context.depth.saturating_add(1);
    parse_options(parent, context, data, base, start, end, malformed);
    context.depth = context.depth.saturating_sub(1);
}

fn decode_option(
    parent: &mut dyn FieldParent,
    context: &mut DecodeContext<'_>,
    option_type: u16,
    body: &[u8],
    offset: usize,
    option_offset: usize,
    malformed: &mut Option<&'static str>,
) {
    match option_type {
        OPTION_CLIENT_ID | OPTION_SERVER_ID => decode_duid(parent, body, offset, option_offset),
        OPTION_IA_NA => {
            if body.len() < 12 {
                malformed_option(parent, option_offset, "IA_NA: malformed option");
                return;
            }
            add_ia_header(parent, body, offset, true);
            parse_nested_options(parent, context, body, offset, 12, body.len(), malformed);
        }
        OPTION_IA_TA => {
            if body.len() < 4 {
                malformed_option(parent, option_offset, "IA_TA: malformed option");
                return;
            }
            let marker = parent.add_field(
                &fields::DHCPV6_OBSOLETED_OPTION,
                Range::new(option_offset, 0),
                Value::None,
            );
            marker.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Deprecated,
                message: "IA_TA: obsoleted option (RFC draft-ietf-dhc-rfc8415bis-12)".to_string(),
            });
            parent.add_field(
                &fields::DHCPV6_IATA,
                Range::new(offset, 4),
                Value::String(hex_lower(body.get(..4).unwrap_or(&[]))),
            );
            parse_nested_options(parent, context, body, offset, 4, body.len(), malformed);
        }
        OPTION_IA_PD => {
            if body.len() < 12 {
                malformed_option(parent, option_offset, "IA_PD: malformed option");
                return;
            }
            add_ia_header(parent, body, offset, true);
            parse_nested_options(parent, context, body, offset, 12, body.len(), malformed);
        }
        OPTION_IA_ADDRESS => {
            if body.len() < 24 {
                malformed_option(parent, option_offset, "IAA: malformed option");
                return;
            }
            if let Some(address) = body.get(..16) {
                parent.add_field(
                    &fields::DHCPV6_IAADDR_IP,
                    Range::new(offset, 16),
                    Value::Ipv6(ipv6(address)),
                );
            }
            add_u32(
                parent,
                &fields::DHCPV6_IAADDR_PREF_LIFETIME,
                body,
                16,
                offset,
            );
            add_u32(
                parent,
                &fields::DHCPV6_IAADDR_VALID_LIFETIME,
                body,
                20,
                offset,
            );
            parse_nested_options(parent, context, body, offset, 24, body.len(), malformed);
        }
        OPTION_IA_PREFIX => {
            if body.len() < 25 {
                malformed_option(parent, option_offset, "IAPREFIX: malformed option");
                return;
            }
            add_u32(
                parent,
                &fields::DHCPV6_IAPREFIX_PREF_LIFETIME,
                body,
                0,
                offset,
            );
            add_u32(
                parent,
                &fields::DHCPV6_IAPREFIX_VALID_LIFETIME,
                body,
                4,
                offset,
            );
            if let Some(&length) = body.get(8) {
                parent.add_field(
                    &fields::DHCPV6_IAPREFIX_PREF_LEN,
                    Range::new(offset + 8, 1),
                    Value::Uint8(length),
                );
            }
            if let Some(address) = body.get(9..25) {
                parent.add_field(
                    &fields::DHCPV6_IAPREFIX_PREF_ADDR,
                    Range::new(offset + 9, 16),
                    Value::Ipv6(ipv6(address)),
                );
            }
            parse_nested_options(parent, context, body, offset, 25, body.len(), malformed);
        }
        OPTION_ORO => {
            let mut index = 0;
            while index + 2 <= body.len() {
                let Some(code) = read_u16(body, index) else {
                    break;
                };
                parent.add_field(
                    &fields::DHCPV6_REQUESTED_OPTION_CODE,
                    Range::new(offset + index, 2),
                    Value::Uint16(code),
                );
                index += 2;
            }
            if !body.len().is_multiple_of(2) {
                *malformed = Some("DHCPv6 option request list has an odd length");
            }
        }
        OPTION_PREFERENCE => {
            if body.len() == 1 {
                if let Some(&value) = body.first() {
                    parent.add_field(
                        &fields::DHCPV6_OPTION_PREFERENCE,
                        Range::new(offset, 1),
                        Value::Uint8(value),
                    );
                }
            } else {
                malformed_option(parent, option_offset, "PREFERENCE: malformed option");
            }
        }
        OPTION_ELAPSED_TIME => {
            if body.len() == 2 {
                let raw = read_u16(body, 0).unwrap_or(0);
                parent.add_field(
                    &fields::DHCPV6_ELAPSED_TIME,
                    Range::new(offset, 2),
                    Value::Uint32(u32::from(raw) * 10),
                );
            } else {
                malformed_option(parent, option_offset, "ELAPSED-TIME: malformed option");
            }
        }
        OPTION_RELAY_MESSAGE => {
            if body.is_empty() {
                malformed_option(parent, option_offset, "RELAY-MSG: malformed option");
                return;
            }
            if context.depth >= MAX_DECODE_DEPTH {
                *malformed = Some("DHCPv6 relay nesting is too deep");
                return;
            }
            context.depth = context.depth.saturating_add(1);
            let mut inner = Node::new(&fields::DHCPV6_PROTOCOL, Range::new(offset, body.len()));
            parse_message_into(&mut inner, context, body, offset);
            parent.add_node(inner);
            context.depth = context.depth.saturating_sub(1);
        }
        OPTION_STATUS_CODE => {
            if body.len() < 2 {
                *malformed = Some("DHCPv6 status code is truncated");
                return;
            }
            if let Some(code) = read_u16(body, 0) {
                parent.add_field(
                    &fields::DHCPV6_STATUS_CODE,
                    Range::new(offset, 2),
                    Value::Uint16(code),
                );
            }
            if body.len() > 2
                && let Some(message) = body.get(2..)
            {
                // RFC 8415 §21.13 leaves the message a UTF-8 string; the
                // display follows the expected output: stop at the first NUL,
                // replace non-ASCII octets, and report any octet after the
                // terminator as stray. None of this changes the option bound.
                let (text, stray) = nul_terminated_text(message);
                let field = parent.add_field(
                    &fields::DHCPV6_STATUS_MSG,
                    Range::new(offset + 2, message.len()),
                    Value::String(text),
                );
                if stray {
                    field.add_expert_for(
                        ExpertInfo {
                            severity: Severity::Warning,
                            group: Group::Undecoded,
                            message: "Trailing stray characters".to_string(),
                        },
                        &fields::TRAILING_STRAY_CHARACTERS,
                    );
                }
            }
        }
        OPTION_INTERFACE_ID => {
            if body.is_empty() {
                malformed_option(parent, option_offset, "INTERFACE_ID: malformed option");
            } else {
                parent.add_field(
                    &fields::DHCPV6_INTERFACE_ID,
                    Range::new(offset, body.len()),
                    Value::bytes(body.to_vec()),
                );
            }
        }
        OPTION_RECONFIGURE_MESSAGE => {
            if body.len() == 1 {
                if let Some(&value) = body.first() {
                    parent.add_field(
                        &fields::DHCPV6_RECONF_MSG,
                        Range::new(offset, 1),
                        Value::Uint8(value),
                    );
                }
            } else {
                malformed_option(parent, option_offset, "RECONF_MSG: malformed option");
            }
        }
        OPTION_DNS_SERVERS => {
            if !body.len().is_multiple_of(16) {
                malformed_option(
                    parent,
                    option_offset,
                    "DNS servers address: malformed option",
                );
                return;
            }
            let mut index = 0;
            while index + 16 <= body.len() {
                if let Some(address) = body.get(index..index + 16) {
                    let field = parent.add_field(
                        &fields::DHCPV6_DNS_SERVER,
                        Range::new(offset + index, 16),
                        Value::Ipv6(ipv6(address)),
                    );
                    field.showname = Some(format!(
                        " {} DNS server address: {}",
                        index / 16 + 1,
                        Value::Ipv6(ipv6(address)).render(fields::Display::None)
                    ));
                }
                index += 16;
            }
        }
        OPTION_DOMAIN_LIST => decode_domain_list(parent, body, offset, option_offset),
        _ => {
            if !body.is_empty() {
                parent.add_field(
                    &fields::DHCPV6_OPTION_DATA,
                    Range::new(offset, body.len()),
                    Value::bytes(body.to_vec()),
                );
            }
        }
    }
}

fn add_ia_header(node: &mut dyn FieldParent, body: &[u8], offset: usize, with_times: bool) {
    if let Some(iaid) = body.get(..4) {
        node.add_field(
            &fields::DHCPV6_IAID,
            Range::new(offset, 4),
            Value::String(hex_lower(iaid)),
        );
    }
    if !with_times {
        return;
    }
    add_u32(node, &fields::DHCPV6_IAID_T1, body, 4, offset);
    add_u32(node, &fields::DHCPV6_IAID_T2, body, 8, offset);
}

fn add_u32(
    node: &mut dyn FieldParent,
    definition: &'static fields::FieldDef,
    body: &[u8],
    index: usize,
    offset: usize,
) {
    if let Some(value) = read_u32(body, index) {
        node.add_field(
            definition,
            Range::new(offset + index, 4),
            Value::Uint32(value),
        );
    }
}

fn decode_duid(node: &mut dyn FieldParent, body: &[u8], offset: usize, option_offset: usize) {
    if body.len() < 2 {
        malformed_option(node, option_offset, "DUID: malformed option");
        return;
    }
    node.add_field(
        &fields::DHCPV6_DUID_BYTES,
        Range::new(offset, body.len()),
        Value::bytes(body.to_vec()),
    );
    let Some(duid_type) = read_u16(body, 0) else {
        return;
    };
    node.add_field(
        &fields::DHCPV6_DUID_TYPE,
        Range::new(offset, 2),
        Value::Uint16(duid_type),
    );
    match duid_type {
        1 => {
            if body.len() < 8 {
                malformed_option(node, option_offset, "DUID: malformed option");
                return;
            }
            if let Some(hardware_type) = read_u16(body, 2) {
                node.add_field(
                    &fields::DHCPV6_DUIDLLT_HWTYPE,
                    Range::new(offset + 2, 2),
                    Value::Uint16(hardware_type),
                );
                if let Some(time) = read_u32(body, 4) {
                    let unix = i64::from(DUID_EPOCH_OFFSET.wrapping_add(time));
                    node.add_field(
                        &fields::DHCPV6_DUIDLLT_TIME,
                        Range::new(offset + 4, 4),
                        Value::AbsoluteTime(crate::Timestamp {
                            seconds: unix,
                            nanos: 0,
                        }),
                    );
                }
                add_link_layer_address(
                    node,
                    body.get(8..).unwrap_or(&[]),
                    offset + 8,
                    hardware_type,
                    true,
                );
            }
        }
        2 => {
            if body.len() < 6 {
                malformed_option(node, option_offset, "DUID: malformed option");
                return;
            }
            if let Some(enterprise) = read_u32(body, 2) {
                node.add_field(
                    &fields::DHCPV6_DUIDEN_ENTERPRISE,
                    Range::new(offset + 2, 4),
                    Value::Uint32(enterprise),
                );
            }
            if let Some(identifier) = body.get(6..).filter(|value| !value.is_empty()) {
                node.add_field(
                    &fields::DHCPV6_DUIDEN_IDENTIFIER,
                    Range::new(offset + 6, identifier.len()),
                    Value::bytes(identifier.to_vec()),
                );
            }
        }
        3 => {
            if body.len() < 4 {
                malformed_option(node, option_offset, "DUID: malformed option");
                return;
            }
            if let Some(hardware_type) = read_u16(body, 2) {
                node.add_field(
                    &fields::DHCPV6_DUIDLL_HWTYPE,
                    Range::new(offset + 2, 2),
                    Value::Uint16(hardware_type),
                );
                add_link_layer_address(
                    node,
                    body.get(4..).unwrap_or(&[]),
                    offset + 4,
                    hardware_type,
                    false,
                );
            }
        }
        4 => {
            if body.len() < 18 {
                malformed_option(node, option_offset, "DUID: malformed option");
                return;
            }
            if let Some(uuid) = body.get(2..18) {
                node.add_field(
                    &fields::DHCPV6_DUIDUUID_BYTES,
                    Range::new(offset + 2, 16),
                    Value::bytes(uuid.to_vec()),
                );
            }
        }
        _ => {}
    }
}

fn add_link_layer_address(
    node: &mut dyn FieldParent,
    address: &[u8],
    offset: usize,
    hardware_type: u16,
    llt: bool,
) {
    if address.is_empty() {
        return;
    }
    let string_definition = if llt {
        &fields::DHCPV6_DUIDLLT_LINK_LAYER_ADDR
    } else {
        &fields::DHCPV6_DUIDLL_LINK_LAYER_ADDR
    };
    node.add_field(
        string_definition,
        Range::new(offset, address.len()),
        Value::String(link_layer_text(hardware_type, address)),
    );
    if let Some(mac) = link_layer_mac(hardware_type, address) {
        let definition = if llt {
            &fields::DHCPV6_DUIDLLT_LINK_LAYER_ADDR_ETHER
        } else {
            &fields::DHCPV6_DUIDLL_LINK_LAYER_ADDR_ETHER
        };
        node.add_field(definition, Range::new(offset, 6), Value::Ethernet(mac));
    }
}

fn decode_domain_list(
    node: &mut dyn FieldParent,
    body: &[u8],
    offset: usize,
    option_offset: usize,
) {
    if body.is_empty() {
        return;
    }
    let group = node.add_unnamed(
        Range::new(offset, body.len()),
        "Domain name suffix search list".to_string(),
    );
    group.value = Value::bytes(body.to_vec());
    let node: &mut dyn FieldParent = group;
    let mut position = 0;
    while position < body.len() {
        let name_start = position;
        let mut labels = String::new();
        let mut complete = false;
        while let Some(&length) = body.get(position) {
            if length == 0 {
                position += 1;
                complete = true;
                break;
            }
            if length & 0xc0 != 0 {
                break;
            }
            let Some(label) = body.get(position + 1..position + 1 + usize::from(length)) else {
                break;
            };
            labels.push_str(&ascii_lossy(label));
            labels.push('.');
            position += 1 + usize::from(length);
        }
        if !complete {
            malformed_option(node, option_offset, "DOMAIN_LIST: malformed option");
            return;
        }
        if !labels.is_empty() {
            node.add_field(
                &fields::DHCPV6_SEARCH_LIST_ENTRY,
                Range::new(offset + name_start, position - name_start),
                Value::String(labels),
            );
        }
    }
}

fn malformed_option(node: &mut dyn FieldParent, option_offset: usize, message: &'static str) {
    let marker = node.add_field(
        &fields::DHCPV6_MALFORMED_OPTION,
        Range::new(option_offset, 0),
        Value::None,
    );
    marker.add_expert(ExpertInfo {
        severity: Severity::Error,
        group: Group::Malformed,
        message: message.to_string(),
    });
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_be_bytes)
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_be_bytes)
}

fn ipv6(data: &[u8]) -> [u8; 16] {
    data.get(..16)
        .and_then(|slice| <[u8; 16]>::try_from(slice).ok())
        .unwrap_or([0; 16])
}

/// The option code table from the IANA DHCPv6 option registry.
/// The registry name for a DHCPv6 option code.
pub fn option_name(code: u16) -> Option<&'static str> {
    OPTION_NAMES
        .get(usize::from(code))
        .copied()
        .filter(|name| !name.is_empty())
}

static OPTION_NAMES: &[&str] = &[
    "",
    "Client Identifier",
    "Server Identifier",
    "Identity Association for Non-temporary Address",
    "Identity Association for Temporary Address",
    "IA Address",
    "Option Request",
    "Preference",
    "Elapsed time",
    "Relay Message",
    "",
    "Authentication",
    "Server unicast",
    "Status code",
    "Rapid Commit",
    "User Class",
    "Vendor Class",
    "Vendor-specific Information",
    "Interface-Id",
    "Reconfigure Message",
    "Reconfigure Accept",
    "SIP Server Domain Name List",
    "SIP Servers IPv6 Address List",
    "DNS recursive name server",
    "Domain Search List",
    "Identity Association for Prefix Delegation",
    "IA Prefix",
    "Network Information Server",
    "Network Information Server V2",
    "Network Information Server Domain Name",
    "Network Information Server V2 Domain Name",
    "Simple Network Time Protocol Server",
    "Lifetime",
    "BCMCS Server Domain",
    "BCMCS Servers IPv6 Address List",
    "",
    "Geoconf Civic Address",
    "Remote Identifier",
    "Subscriber Identifier",
    "Client Fully Qualified Domain Name",
    "PANA Agents IPv6 Address List",
    "Time Zone",
    "Time Zone Database",
    "Echo Request Option",
    "Leasequery Query",
    "Leasequery Client Data",
    "Client Last Transaction Time",
    "Leasequery Relay Data",
    "Leasequery Client Link Address List",
    "Home Network Identifier FQDN",
    "Visited Home Network Information",
    "LoST Server",
    "CAPWAP Access Controllers",
    "Relay-ID",
    "MoS IPv6 Address",
    "MoS Domain Name List",
    "NTP Server",
    "Access Network Domain Name",
    "SIP User Agent Configuration Service Domains",
    "Boot File URL",
    "Boot File Parameters",
    "Client System Architecture Type",
    "Client Network Interface Identifier",
    "Geolocation",
    "Dual-Stack Lite AFTR Name",
    "ERP Local Domain Name",
    "Relay-Supplied Options",
    "Prefix Exclude",
    "Virtual Subnet Selection",
    "Identified Home Network Information",
    "Unrestricted Home Network Information",
    "Home Network Prefix",
    "Home Agent Address",
    "Home Agent FQDN",
    "RDNSS Selection",
    "Kerberos Principal Name",
    "Kerberos Realm Name",
    "Kerberos Default Realm Name",
    "Kerberos KDC",
    "Client Link-Layer Address",
    "Link Address",
    "RADIUS",
    "SOL_MAX_RT",
    "INF_MAX_RT",
    "Address Selection",
    "Address Selection table",
    "PCP Server",
    "DHCPv4 Message",
    "DHCP 4o6 Servers Address",
    "S46 Rule",
    "S46 BR",
    "S46 DMR",
    "S46 IPv4/IPv6 Address Binding",
    "S46 Port Parameters",
    "S46 MAP-E Container",
    "S46 MAP-T Container",
    "S46 Lightweight 4over6 Container",
    "4rd Options",
    "4rd Mapping Rule",
    "4rd Non-Mapping Rule",
    "LQ Server Base Time",
    "LQ Server Query Start Time",
    "LQ Server Query End Time",
    "Captive Portal",
    "MPL Parameter Configuration",
    "Access Technology Type",
    "Access Network Name",
    "Access Point Name",
    "Access Point BSSID",
    "Access Network Operator ID",
    "Access Network Operator Realm",
    "S46 Priority",
    "Manufacturer Usage Description",
    "IPv4/IPv6 Multicast Prefixes",
    "Failover Binding Status",
    "Failover Connect Flags",
    "Failover DNS Removal Info",
    "Failover DNS Hostname",
    "Failover DNS Zone Name",
    "Failover DNS Flags",
    "Failover Expiration Time",
    "Failover Maximum Number Unacked BNDUPD Messages",
    "Failover Maximum Client Lead Time (MCLT)",
    "Failover Partner Lifetime",
    "Failover Partner Lifetime Sent",
    "Failover Partner Down Time",
    "Failover Partner Raw Client Time",
    "Failover Protocol Version",
    "Failover Keepalive Time",
    "Failover Reconfigure Data",
    "Failover Relationship Name",
    "Failover Server Flags",
    "Failover Server State",
    "Failover Start Time of State",
    "Failover State Expiration Time",
    "Relay Source Port",
    "SZTP Redirect",
    "Softwire Source Binding Prefix Hint",
    "Identity Association for Link-Layer Addresses",
    "Link-Layer Address",
    "QUAD",
    "DOTS Reference Identifier",
    "DOTS Address",
    "ANDSF IPv6 Address",
    "Discovery of Network DNS Resolvers",
    "Registered Domain",
    "Forward Distribution Manager",
    "Reverse Distribution Manager",
    "Address Registration Enable",
    "Identity Association for SRv6 Locator",
    "IA SRv6 Locator",
];
