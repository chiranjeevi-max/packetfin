//! Border Gateway Protocol version 4.
//!
//! The message header is the 16-octet all-ones marker, a 16-bit total length
//! and a message type (RFC 4271 section 4.1). The decoder accepts a length
//! from 19 through 4096 octets and decodes each complete message in a segment;
//! a shorter declared length marks the packet malformed without a BGP node, and
//! a message that runs past the segment leaves its bytes for TCP reassembly. A
//! payload without a marker at its start is not BGP, which lets the HTTP
//! heuristic run afterwards.
//!
//! UPDATE path attributes follow RFC 4271 section 4.3 and the IANA path
//! attribute registry; NLRI prefixes are encoded as a length followed by the
//! high-order bits of the address (section 4.3).

use crate::decode::DecodeContext;
use crate::decode::bytes::{array, read_u16_be, read_u32_be};
use crate::fields;
use crate::tree::{ExpertInfo, Field, Group, Node, Range, Severity, Value};

const MARKER_LENGTH: usize = 16;
const HEADER_LENGTH: usize = 19;
const MAX_MESSAGE_LENGTH: usize = 4096;

const TYPE_OPEN: u8 = 1;
const TYPE_UPDATE: u8 = 2;
const TYPE_NOTIFICATION: u8 = 3;
const TYPE_KEEPALIVE: u8 = 4;
const TYPE_ROUTE_REFRESH: u8 = 5;

const ATTRIBUTE_ORIGIN: u8 = 1;
const ATTRIBUTE_AS_PATH: u8 = 2;
const ATTRIBUTE_NEXT_HOP: u8 = 3;
const ATTRIBUTE_MULTI_EXIT_DISC: u8 = 4;
const ATTRIBUTE_LOCAL_PREF: u8 = 5;
const ATTRIBUTE_AGGREGATOR: u8 = 7;
const ATTRIBUTE_COMMUNITIES: u8 = 8;

/// An unnamed per-prefix group, such as the `10.0.0.0/8` subtree.
///
/// The definition is deliberately outside the registry: it has no filter name
/// and no field name, so `-G fields`, `-e` and display filters must not see it.
static PREFIX_GROUP: fields::FieldDef = fields::FieldDef {
    abbrev: "",
    field_type: fields::FieldType::None,
    parent: "bgp",
    name: "",
    display: fields::Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// Decode the BGP messages carried by one TCP segment.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.len() < HEADER_LENGTH {
        // The 19-octet header must be in the first segment; TCP reassembly
        // joins the bytes that follow a complete header.
        return;
    }
    if !valid_marker(data) {
        return;
    }
    let Some(length) = read_u16_be(data, MARKER_LENGTH) else {
        return;
    };
    let length = usize::from(length);
    if length > MAX_MESSAGE_LENGTH {
        // An over-long declared length keeps the header and length field and
        // reports the length as invalid.
        let mut node = Node::new(&fields::BGP_PROTOCOL, Range::new(base, HEADER_LENGTH));
        node.add_field(
            &fields::BGP_MARKER,
            Range::new(base, MARKER_LENGTH),
            Value::bytes(data.get(..MARKER_LENGTH).unwrap_or(&[]).to_vec()),
        );
        node.add_field(
            &fields::BGP_LENGTH,
            Range::new(base.saturating_add(16), 2),
            Value::Uint16(u16::try_from(length).unwrap_or(u16::MAX)),
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Malformed,
            message: format!("Length is invalid {length}"),
        });
        if let Some(message_type) = data.get(18).copied() {
            context.columns.info = Some(message_info(message_type));
        }
        parent.add_child(node);
        return;
    }
    if length < HEADER_LENGTH {
        // A short declared length marks the packet malformed without adding a
        // BGP node.
        context.mark_malformed(parent, "BGP message length is invalid");
        return;
    }
    if length > data.len() {
        return;
    }

    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::BGP_PROTOCOL.filter_name);
    let mut offset = 0_usize;
    let mut infos: Vec<String> = Vec::new();
    while offset.saturating_add(HEADER_LENGTH) <= data.len() {
        let Some(declared) = read_u16_be(data, offset.saturating_add(MARKER_LENGTH)) else {
            break;
        };
        let declared = usize::from(declared);
        if declared > MAX_MESSAGE_LENGTH {
            if data.len().saturating_sub(offset) < declared {
                // The message runs past this segment; the remaining payload
                // waits for TCP reassembly.
                break;
            }
            let message_base = base.saturating_add(offset);
            let mut node = Node::new(
                &fields::BGP_PROTOCOL,
                Range::new(message_base, HEADER_LENGTH),
            );
            node.add_field(
                &fields::BGP_MARKER,
                Range::new(message_base, MARKER_LENGTH),
                Value::bytes(
                    data.get(offset..offset.saturating_add(MARKER_LENGTH))
                        .unwrap_or(&[])
                        .to_vec(),
                ),
            );
            node.add_field(
                &fields::BGP_LENGTH,
                Range::new(message_base.saturating_add(16), 2),
                Value::Uint16(u16::try_from(declared).unwrap_or(u16::MAX)),
            );
            node.add_expert(ExpertInfo {
                severity: Severity::Error,
                group: Group::Malformed,
                message: format!("Length is invalid {declared}"),
            });
            if let Some(message_type) = data.get(offset.saturating_add(18)).copied() {
                infos.push(message_info(message_type));
            }
            parent.add_child(node);
            break;
        }
        let Some(end) = offset.checked_add(declared) else {
            break;
        };
        if declared < HEADER_LENGTH || end > data.len() {
            break;
        }
        let Some(message) = data.get(offset..end) else {
            break;
        };
        if !valid_marker(message) {
            break;
        }
        let mut node = Node::new(
            &fields::BGP_PROTOCOL,
            Range::new(base.saturating_add(offset), declared),
        );
        let message_base = base.saturating_add(offset);
        node.add_field(
            &fields::BGP_MARKER,
            Range::new(message_base, MARKER_LENGTH),
            Value::bytes(message.get(..MARKER_LENGTH).unwrap_or(&[]).to_vec()),
        );
        node.add_field(
            &fields::BGP_LENGTH,
            Range::new(message_base.saturating_add(16), 2),
            Value::Uint16(u16::try_from(declared).unwrap_or(u16::MAX)),
        );
        let message_type = message.get(18).copied().unwrap_or(0);
        node.add_field(
            &fields::BGP_TYPE,
            Range::new(message_base.saturating_add(18), 1),
            Value::Uint8(message_type),
        );
        infos.push(message_info(message_type));
        let body = message.get(HEADER_LENGTH..).unwrap_or(&[]);
        match message_type {
            TYPE_OPEN => parse_open(&mut node, body, message_base.saturating_add(HEADER_LENGTH)),
            TYPE_UPDATE => {
                parse_update(&mut node, body, message_base.saturating_add(HEADER_LENGTH))
            }
            TYPE_NOTIFICATION => {
                parse_notification(&mut node, body, message_base.saturating_add(HEADER_LENGTH))
            }
            TYPE_ROUTE_REFRESH => {
                parse_route_refresh(&mut node, body, message_base.saturating_add(HEADER_LENGTH))
            }
            _ => {}
        }
        parent.add_child(node);
        offset = end;
    }
    if !infos.is_empty() {
        context.columns.info = Some(infos.join(", "));
    }
    context.depth = context.depth.saturating_sub(1);
}

/// The summary text for one BGP message type.
fn message_info(message_type: u8) -> String {
    match message_type {
        TYPE_OPEN => "OPEN Message".to_string(),
        TYPE_UPDATE => "UPDATE Message".to_string(),
        TYPE_NOTIFICATION => "NOTIFICATION Message".to_string(),
        TYPE_KEEPALIVE => "KEEPALIVE Message".to_string(),
        TYPE_ROUTE_REFRESH => "ROUTE-REFRESH Message".to_string(),
        6 => "CAPABILITY Message".to_string(),
        _ => format!("Unknown message type (0x{message_type:02x})"),
    }
}

fn valid_marker(data: &[u8]) -> bool {
    data.get(..MARKER_LENGTH)
        .is_some_and(|marker| marker.iter().all(|byte| *byte == 0xff))
}

fn add_value(
    node: &mut Node,
    def: &'static fields::FieldDef,
    base: usize,
    offset: usize,
    length: usize,
    value: Value,
) {
    node.add_field(def, Range::new(base.saturating_add(offset), length), value);
}

/// OPEN: version, my AS, hold time, identifier, optional parameters.
fn parse_open(node: &mut Node, body: &[u8], base: usize) {
    let Some(version) = body.first().copied() else {
        return;
    };
    add_value(
        node,
        &fields::BGP_OPEN_VERSION,
        base,
        0,
        1,
        Value::Uint8(version),
    );
    if let Some(myas) = read_u16_be(body, 1) {
        add_value(
            node,
            &fields::BGP_OPEN_MYAS,
            base,
            1,
            2,
            Value::Uint16(myas),
        );
    }
    if let Some(holdtime) = read_u16_be(body, 3) {
        add_value(
            node,
            &fields::BGP_OPEN_HOLDTIME,
            base,
            3,
            2,
            Value::Uint16(holdtime),
        );
    }
    if let Some(Some(identifier)) = array::<4>(body, 5).map(Some) {
        add_value(
            node,
            &fields::BGP_OPEN_IDENTIFIER,
            base,
            5,
            4,
            Value::Ipv4(identifier),
        );
    }
    let Some(parameters_length) = body.get(9).copied() else {
        return;
    };
    add_value(
        node,
        &fields::BGP_OPEN_OPT_LEN,
        base,
        9,
        1,
        Value::Uint8(parameters_length),
    );
    let parameters = body
        .get(10..10_usize.saturating_add(usize::from(parameters_length)))
        .unwrap_or(&[]);
    if parameters.is_empty() {
        return;
    }
    let parameters_field = node.add_container(
        &fields::BGP_OPEN_OPT,
        Range::new(base.saturating_add(10), parameters.len()),
        Some("Optional Parameters".to_string()),
    );
    let mut offset = 0_usize;
    while offset.saturating_add(2) <= parameters.len() {
        let Some(kind) = parameters.get(offset).copied() else {
            break;
        };
        let Some(length) = parameters.get(offset.saturating_add(1)).copied() else {
            break;
        };
        let length = usize::from(length);
        let Some(end) = offset
            .checked_add(2)
            .and_then(|start| start.checked_add(length))
        else {
            break;
        };
        if end > parameters.len() {
            break;
        }
        let parameter = parameters_field.add_container(
            &fields::BGP_OPEN_OPT_PARAM,
            Range::new(base.saturating_add(10).saturating_add(offset), 2 + length),
            Some("Optional Parameter".to_string()),
        );
        parameter.add_field(
            &fields::BGP_OPEN_OPT_PARAM_TYPE,
            Range::new(base.saturating_add(10).saturating_add(offset), 1),
            Value::Uint8(kind),
        );
        parameter.add_field(
            &fields::BGP_OPEN_OPT_PARAM_LEN,
            Range::new(
                base.saturating_add(10)
                    .saturating_add(offset)
                    .saturating_add(1),
                1,
            ),
            Value::Uint8(u8::try_from(length).unwrap_or(u8::MAX)),
        );
        let value = parameters.get(offset.saturating_add(2)..end).unwrap_or(&[]);
        if kind == 1 {
            parameter.add_field(
                &fields::BGP_OPEN_OPT_PARAM_AUTH,
                Range::new(
                    base.saturating_add(10)
                        .saturating_add(offset)
                        .saturating_add(2),
                    length,
                ),
                Value::bytes(value.to_vec()),
            );
        } else if !value.is_empty() {
            parameter.add_field(
                &fields::BGP_OPEN_OPT_PARAM_UNKNOWN,
                Range::new(
                    base.saturating_add(10)
                        .saturating_add(offset)
                        .saturating_add(2),
                    length,
                ),
                Value::bytes(value.to_vec()),
            );
        }
        offset = end;
    }
}

/// UPDATE: withdrawn routes, path attributes and NLRI.
fn parse_update(node: &mut Node, body: &[u8], base: usize) {
    let Some(withdrawn_length) = read_u16_be(body, 0) else {
        return;
    };
    add_value(
        node,
        &fields::BGP_UPDATE_WITHDRAWN_ROUTES_LENGTH,
        base,
        0,
        2,
        Value::Uint16(withdrawn_length),
    );
    let withdrawn_length = usize::from(withdrawn_length);
    let withdrawn = body
        .get(2..2_usize.saturating_add(withdrawn_length))
        .unwrap_or(&[]);
    if !withdrawn.is_empty() {
        let container = node.add_container(
            &fields::BGP_UPDATE_WITHDRAWN_ROUTES,
            Range::new(base.saturating_add(2), withdrawn.len()),
            Some("Withdrawn Routes".to_string()),
        );
        parse_prefixes(container, withdrawn, base.saturating_add(2), true);
    }

    let attributes_offset = 2_usize.saturating_add(withdrawn_length);
    let Some(attributes_length) = read_u16_be(body, attributes_offset) else {
        return;
    };
    add_value(
        node,
        &fields::BGP_UPDATE_PATH_ATTRIBUTES_LENGTH,
        base,
        attributes_offset,
        2,
        Value::Uint16(attributes_length),
    );
    let attributes_length = usize::from(attributes_length);
    let attributes_start = attributes_offset.saturating_add(2);
    let attributes = body
        .get(attributes_start..attributes_start.saturating_add(attributes_length))
        .unwrap_or(&[]);
    if !attributes.is_empty() {
        let container = node.add_container(
            &fields::BGP_UPDATE_PATH_ATTRIBUTES,
            Range::new(base.saturating_add(attributes_start), attributes.len()),
            Some("Path attributes".to_string()),
        );
        parse_attributes(container, attributes, base.saturating_add(attributes_start));
    }

    let nlri_start = attributes_start.saturating_add(attributes_length);
    if let Some(nlri) = body.get(nlri_start..)
        && !nlri.is_empty()
    {
        let container = node.add_container(
            &fields::BGP_UPDATE_NLRI,
            Range::new(base.saturating_add(nlri_start), nlri.len()),
            Some("Network Layer Reachability Information (NLRI)".to_string()),
        );
        parse_prefixes(container, nlri, base.saturating_add(nlri_start), false);
    }
}

/// One IPv4 prefix: a length then the high-order octets.
fn parse_prefixes(node: &mut Field, data: &[u8], base: usize, withdrawn: bool) {
    let mut offset = 0_usize;
    while let Some(&length) = data.get(offset) {
        let bits = usize::from(length);
        if bits > 32 {
            break;
        }
        let octets = bits.div_ceil(8);
        let Some(end) = offset
            .checked_add(1)
            .and_then(|start| start.checked_add(octets))
        else {
            break;
        };
        if end > data.len() {
            break;
        }
        let Some(bytes) = data.get(offset.saturating_add(1)..end) else {
            break;
        };
        let mut address = [0_u8; 4];
        address
            .get_mut(..bytes.len())
            .unwrap_or(&mut [])
            .copy_from_slice(bytes);
        let text = format!(
            "{}.{}.{}.{}/{bits}",
            address[0], address[1], address[2], address[3]
        );
        let group = node.add_container(
            &PREFIX_GROUP,
            Range::new(base.saturating_add(offset), end.saturating_sub(offset)),
            Some(text),
        );
        group.add_field(
            &fields::BGP_PREFIX_LENGTH,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(length),
        );
        let def = if withdrawn {
            &fields::BGP_WITHDRAWN_PREFIX
        } else {
            &fields::BGP_NLRI_PREFIX
        };
        group.add_field(
            def,
            Range::new(base.saturating_add(offset).saturating_add(1), octets),
            Value::Ipv4(address),
        );
        offset = end;
    }
}

/// One path attribute, bounded by its declared length (RFC 4271 4.3).
fn parse_attributes(node: &mut Field, data: &[u8], base: usize) {
    let mut offset = 0_usize;
    while offset.saturating_add(2) <= data.len() {
        let Some(&flags) = data.get(offset) else {
            break;
        };
        let Some(&type_code) = data.get(offset.saturating_add(1)) else {
            break;
        };
        let extended = flags & 0x10 != 0;
        let length_bytes = if extended { 2 } else { 1 };
        let length_offset = offset.saturating_add(2);
        let Some(length) = (if extended {
            read_u16_be(data, length_offset).map(usize::from)
        } else {
            data.get(length_offset).copied().map(usize::from)
        }) else {
            break;
        };
        let value_offset = length_offset.saturating_add(length_bytes);
        let Some(end) = value_offset.checked_add(length) else {
            break;
        };
        if end > data.len() {
            break;
        }
        let attribute = node.add_container(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE,
            Range::new(base.saturating_add(offset), end.saturating_sub(offset)),
            Some(attribute_showname(
                type_code,
                data.get(value_offset..end).unwrap_or(&[]),
            )),
        );
        let flags_field = attribute.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_FLAGS,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(flags),
        );
        let flags_range = Range::new(base.saturating_add(offset), 1);
        flags_field.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_OPTIONAL,
            flags_range,
            Value::Boolean(flags & 0x80 != 0),
        );
        flags_field.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_TRANSITIVE,
            flags_range,
            Value::Boolean(flags & 0x40 != 0),
        );
        flags_field.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_PARTIAL,
            flags_range,
            Value::Boolean(flags & 0x20 != 0),
        );
        flags_field.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_EXTENDED_LENGTH,
            flags_range,
            Value::Boolean(extended),
        );
        flags_field.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_UNUSED,
            flags_range,
            Value::Uint8(flags & 0x0f),
        );
        attribute.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_TYPE_CODE,
            Range::new(base.saturating_add(offset).saturating_add(1), 1),
            Value::Uint8(type_code),
        );
        if extended {
            attribute.add_field(
                &fields::BGP_UPDATE_PATH_ATTRIBUTE_LENGTH,
                Range::new(base.saturating_add(length_offset), 2),
                Value::Uint16(u16::try_from(length).unwrap_or(u16::MAX)),
            );
        } else {
            attribute.add_field(
                &fields::BGP_UPDATE_PATH_ATTRIBUTE_LENGTH,
                Range::new(base.saturating_add(length_offset), 1),
                Value::Uint16(u16::try_from(length).unwrap_or(u16::MAX)),
            );
        }
        let value = data.get(value_offset..end).unwrap_or(&[]);
        let value_base = base.saturating_add(value_offset);
        match type_code {
            ATTRIBUTE_ORIGIN => {
                if let Some(&origin) = value.first() {
                    attribute.add_field(
                        &fields::BGP_UPDATE_PATH_ATTRIBUTE_ORIGIN,
                        Range::new(value_base, 1),
                        Value::Uint8(origin),
                    );
                }
            }
            ATTRIBUTE_AS_PATH => parse_as_path(attribute, value, value_base),
            ATTRIBUTE_NEXT_HOP => {
                if let Some(address) = array::<4>(value, 0) {
                    attribute.add_field(
                        &fields::BGP_UPDATE_PATH_ATTRIBUTE_NEXT_HOP,
                        Range::new(value_base, 4),
                        Value::Ipv4(address),
                    );
                }
            }
            ATTRIBUTE_MULTI_EXIT_DISC => {
                if let Some(value) = read_u32_be(value, 0) {
                    attribute.add_field(
                        &fields::BGP_UPDATE_PATH_ATTRIBUTE_MULTI_EXIT_DISC,
                        Range::new(value_base, 4),
                        Value::Uint32(value),
                    );
                }
            }
            ATTRIBUTE_LOCAL_PREF => {
                if let Some(value) = read_u32_be(value, 0) {
                    attribute.add_field(
                        &fields::BGP_UPDATE_PATH_ATTRIBUTE_LOCAL_PREF,
                        Range::new(value_base, 4),
                        Value::Uint32(value),
                    );
                }
            }
            ATTRIBUTE_AGGREGATOR => {
                if let Some(value) = read_u32_be(value, 0) {
                    attribute.add_field(
                        &fields::BGP_UPDATE_PATH_ATTRIBUTE_AGGREGATOR_AS,
                        Range::new(value_base, 4),
                        Value::Uint32(value),
                    );
                }
                if let Some(address) = array::<4>(value, 4) {
                    attribute.add_field(
                        &fields::BGP_UPDATE_PATH_ATTRIBUTE_AGGREGATOR_ORIGIN,
                        Range::new(value_base.saturating_add(4), 4),
                        Value::Ipv4(address),
                    );
                }
            }
            ATTRIBUTE_COMMUNITIES => parse_communities(attribute, value, value_base),
            _ => {}
        }
        offset = end;
    }
}

/// The dynamic `Path Attribute - ...` label built for each attribute.
fn attribute_showname(type_code: u8, value: &[u8]) -> String {
    let name = match type_code {
        ATTRIBUTE_ORIGIN => "ORIGIN",
        ATTRIBUTE_AS_PATH => "AS_PATH",
        ATTRIBUTE_NEXT_HOP => "NEXT_HOP",
        ATTRIBUTE_MULTI_EXIT_DISC => "MULTI_EXIT_DISC",
        ATTRIBUTE_LOCAL_PREF => "LOCAL_PREF",
        ATTRIBUTE_AGGREGATOR => "AGGREGATOR",
        ATTRIBUTE_COMMUNITIES => "COMMUNITIES",
        _ => "Unknown",
    };
    let detail = match type_code {
        ATTRIBUTE_ORIGIN => match value.first() {
            Some(0) => ": IGP".to_string(),
            Some(1) => ": EGP".to_string(),
            Some(2) => ": INCOMPLETE".to_string(),
            Some(other) => format!(": Unknown ({other})"),
            None => String::new(),
        },
        ATTRIBUTE_NEXT_HOP => match array::<4>(value, 0) {
            Some([a, b, c, d]) => format!(": {a}.{b}.{c}.{d}"),
            None => String::new(),
        },
        ATTRIBUTE_COMMUNITIES => {
            let mut text = String::from(": ");
            let mut offset = 0_usize;
            while let Some([as_high, as_low, value_high, value_low]) = array::<4>(value, offset) {
                let _ = std::fmt::Write::write_fmt(
                    &mut text,
                    format_args!(
                        "{}:{} ",
                        u16::from_be_bytes([as_high, as_low]),
                        u16::from_be_bytes([value_high, value_low])
                    ),
                );
                offset = offset.saturating_add(4);
            }
            text
        }
        _ => String::new(),
    };
    format!("Path Attribute - {name}{detail}")
}

/// AS_PATH: a list of segments, each a type, a count and 2-octet AS numbers.
fn parse_as_path(attribute: &mut Field, data: &[u8], base: usize) {
    let mut offset = 0_usize;
    while offset.saturating_add(2) <= data.len() {
        let Some(&segment_type) = data.get(offset) else {
            break;
        };
        let Some(&count) = data.get(offset.saturating_add(1)) else {
            break;
        };
        let count = usize::from(count);
        let Some(end) = offset
            .checked_add(2)
            .and_then(|start| start.checked_add(count.saturating_mul(2)))
        else {
            break;
        };
        if end > data.len() {
            break;
        }
        let segment = attribute.add_container(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT,
            Range::new(base.saturating_add(offset), end.saturating_sub(offset)),
            Some("AS Path segment".to_string()),
        );
        segment.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_TYPE,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(segment_type),
        );
        segment.add_field(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_LENGTH,
            Range::new(base.saturating_add(offset).saturating_add(1), 1),
            Value::Uint8(u8::try_from(count).unwrap_or(u8::MAX)),
        );
        for index in 0..count {
            let position = offset
                .saturating_add(2)
                .saturating_add(index.saturating_mul(2));
            if let Some(value) = read_u16_be(data, position) {
                segment.add_field(
                    &fields::BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_AS2,
                    Range::new(base.saturating_add(position), 2),
                    Value::Uint16(value),
                );
            }
        }
        offset = end;
    }
}

/// COMMUNITIES: 4-octet values, split into AS and local number.
fn parse_communities(attribute: &mut Field, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    let communities = attribute.add_container(
        &fields::BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITIES,
        Range::new(base, data.len()),
        Some("Communities".to_string()),
    );
    let mut offset = 0_usize;
    while offset.saturating_add(4) <= data.len() {
        let Some([high, low, value_high, value_low]) = array::<4>(data, offset) else {
            break;
        };
        let community = communities.add_container(
            &fields::BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY,
            Range::new(base.saturating_add(offset), 4),
            Some(format!(
                "Community: {}:{} ",
                u16::from_be_bytes([high, low]),
                u16::from_be_bytes([value_high, value_low])
            )),
        );
        if high == 0xff && low == 0xff {
            community.add_field(
                &fields::BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_WELLKNOWN,
                Range::new(base.saturating_add(offset), 4),
                Value::Uint32(u32::from_be_bytes([high, low, value_high, value_low])),
            );
        } else {
            community.add_field(
                &fields::BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_AS,
                Range::new(base.saturating_add(offset), 2),
                Value::Uint16(u16::from_be_bytes([high, low])),
            );
            community.add_field(
                &fields::BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_VALUE,
                Range::new(base.saturating_add(offset).saturating_add(2), 2),
                Value::Uint16(u16::from_be_bytes([value_high, value_low])),
            );
        }
        offset = offset.saturating_add(4);
    }
}

/// NOTIFICATION: a major code, the code's minor field and optional data.
fn parse_notification(node: &mut Node, body: &[u8], base: usize) {
    let Some(major) = body.first().copied() else {
        return;
    };
    add_value(
        node,
        &fields::BGP_NOTIFY_MAJOR_ERROR,
        base,
        0,
        1,
        Value::Uint8(major),
    );
    let Some(minor) = body.get(1).copied() else {
        return;
    };
    let def = match major {
        1 => &fields::BGP_NOTIFY_MINOR_ERROR,
        2 => &fields::BGP_NOTIFY_MINOR_ERROR_OPEN,
        3 => &fields::BGP_NOTIFY_MINOR_ERROR_UPDATE,
        4 => &fields::BGP_NOTIFY_MINOR_ERROR_EXPIRED,
        5 => &fields::BGP_NOTIFY_MINOR_ERROR_STATE,
        6 => &fields::BGP_NOTIFY_MINOR_ERROR_CEASE,
        7 => &fields::BGP_NOTIFY_MINOR_ERROR_ROUTE_REFRESH,
        _ => &fields::BGP_NOTIFY_MINOR_ERROR_UNKNOWN,
    };
    add_value(node, def, base, 1, 1, Value::Uint8(minor));
    if let Some(data) = body.get(2..)
        && !data.is_empty()
    {
        add_value(
            node,
            &fields::BGP_NOTIFY_MINOR_DATA,
            base,
            2,
            data.len(),
            Value::bytes(data.to_vec()),
        );
    }
}

/// ROUTE-REFRESH: AFI, subtype and SAFI (RFC 2918, enhanced refresh drafts).
fn parse_route_refresh(node: &mut Node, body: &[u8], base: usize) {
    if let Some(afi) = read_u16_be(body, 0) {
        add_value(
            node,
            &fields::BGP_ROUTE_REFRESH_AFI,
            base,
            0,
            2,
            Value::Uint16(afi),
        );
    }
    if let Some(subtype) = body.get(2).copied() {
        add_value(
            node,
            &fields::BGP_ROUTE_REFRESH_SUBTYPE,
            base,
            2,
            1,
            Value::Uint8(subtype),
        );
    }
    if let Some(safi) = body.get(3).copied() {
        add_value(
            node,
            &fields::BGP_ROUTE_REFRESH_SAFI,
            base,
            3,
            1,
            Value::Uint8(safi),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attribute_longer_than_the_message_is_not_read_past_the_end() {
        let mut body = 0_u16.to_be_bytes().to_vec();
        body.extend_from_slice(&4_u16.to_be_bytes());
        body.extend_from_slice(&[0x40, 1, 0xff, 0xff, 0x00]);
        let mut node = Node::new(&fields::BGP_PROTOCOL, Range::new(0, 0));
        parse_update(&mut node, &body, 0);
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "bgp.update.path_attributes.length")
        );
    }

    #[test]
    fn a_prefix_longer_than_32_bits_stops_the_prefix_loop() {
        let mut node = Node::new(&fields::BGP_PROTOCOL, Range::new(0, 0));
        let container = node.add_container(
            &fields::BGP_UPDATE_NLRI,
            Range::new(0, 0),
            Some("NLRI".to_string()),
        );
        parse_prefixes(container, &[33, 1, 2, 3, 4, 5], 0, false);
        assert!(node.fields.iter().all(|field| {
            field
                .children
                .iter()
                .all(|child| child.def.abbrev != "bgp.prefix_length")
        }));
    }
}
