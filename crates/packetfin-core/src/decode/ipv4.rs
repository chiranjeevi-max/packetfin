//! Internet Protocol version 4.
//!
//! The fixed header is 20 bytes; the IHL nibble extends it by up to 40 bytes
//! of options, always a multiple of four. The decoder adds each fixed field
//! as soon as its bytes are present, then stops at the first semantic problem
//! (version, header length, total length) with a protocol expert entry. A
//! capture shorter than the header it declares keeps the fields decoded so
//! far and is marked malformed.
//!
//! A fragmented datagram is buffered by the session until its parts cover the
//! whole payload; the transport decoder runs on the completing frame with the
//! reassembled bytes at base zero. Earlier fragments keep only their IPv4
//! node and summary. The network context records the addresses, protocol and
//! fragmentation state for the transport slice. Options are parsed with
//! bounds checks; unknown options keep their type, length and data bytes.

use crate::decode::bytes::{read_ipv4, read_u16_be, read_u32_be};
use crate::decode::checksum;
use crate::decode::{self, DecodeContext, NetworkContext};
use crate::fields;
use crate::state::{Frag4Key, FragmentOutcome, FragmentPart};
use crate::tree::{ExpertInfo, Group, Node, Range, RawField, RawSource, Severity, Value};

const MIN_HEADER_LENGTH: usize = 20;
const MAX_HEADER_LENGTH: usize = 60;
const VERSION_OFFSET: usize = 0;
const DSFIELD_OFFSET: usize = 1;
const LENGTH_OFFSET: usize = 2;
const IDENTIFICATION_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 6;
const TTL_OFFSET: usize = 8;
const PROTOCOL_OFFSET: usize = 9;
const CHECKSUM_OFFSET: usize = 10;
const SOURCE_OFFSET: usize = 12;
const DESTINATION_OFFSET: usize = 16;
const OPTIONS_OFFSET: usize = 20;
const IPV4_VERSION: u8 = 4;
const CHECKSUM_WORD_OFFSET: usize = CHECKSUM_OFFSET;

const OPTION_EOL: u8 = 0;
const OPTION_NOP: u8 = 1;
const OPTION_RECORD_ROUTE: u8 = 7;
const OPTION_TIMESTAMP: u8 = 68;
const OPTION_ROUTER_ALERT: u8 = 148;

/// Decode one IPv4 datagram into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context.protocol_stack.push(fields::IP_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::IP_PROTOCOL, Range::new(base, data.len()));

    let Some(first) = data.get(VERSION_OFFSET).copied() else {
        context.mark_malformed(&mut node, "IPv4 packet is empty");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let version = first >> 4;
    node.add_field(
        &fields::IP_VERSION,
        Range::new(base + VERSION_OFFSET, 1),
        Value::Uint8(version),
    );
    if version != IPV4_VERSION {
        add_protocol_expert(&mut node, format!("Bogus IPv4 version {version}"));
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let header_length = usize::from(first & 0x0f) * 4;
    let header_length_field = u8::try_from(header_length).unwrap_or(u8::MAX);
    node.add_field(
        &fields::IP_HDR_LEN,
        Range::new(base + VERSION_OFFSET, 1),
        Value::Uint8(header_length_field),
    );
    if !(MIN_HEADER_LENGTH..=MAX_HEADER_LENGTH).contains(&header_length) {
        add_protocol_expert(
            &mut node,
            format!("Bogus IP header length ({header_length}, must be at least 20)"),
        );
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if let Some(dsfield) = data.get(DSFIELD_OFFSET).copied() {
        node.add_field(
            &fields::IP_DSFIELD,
            Range::new(base + DSFIELD_OFFSET, 1),
            Value::Uint8(dsfield),
        );
        node.add_field(
            &fields::IP_DSFIELD_DSCP,
            Range::new(base + DSFIELD_OFFSET, 1),
            Value::Uint8(dsfield >> 2),
        );
        node.add_field(
            &fields::IP_DSFIELD_ECN,
            Range::new(base + DSFIELD_OFFSET, 1),
            Value::Uint8(dsfield & 0x03),
        );
    }

    let raw_total_length = read_u16_be(data, LENGTH_OFFSET);
    // A zero total length is the TCP segmentation offload convention: the
    // frame's reported length carries the real datagram length, which can
    // exceed both the 16-bit field and a snaplen-truncated capture. That
    // length goes into `ip.len` and sets the transport slice; clamping it
    // would silently drop payload.
    let total_length = raw_total_length.map(|length| {
        if length == 0 {
            let reported = context
                .frame_reported_length
                .saturating_sub(base)
                .max(data.len());
            u32::try_from(reported).unwrap_or(u32::MAX)
        } else {
            u32::from(length)
        }
    });
    if let Some(total_length) = total_length {
        let total_length_usize = usize::try_from(total_length).unwrap_or(usize::MAX);
        if raw_total_length == Some(0) {
            let value = match u16::try_from(total_length) {
                Ok(small) => Value::Uint16(small),
                Err(_) => Value::Uint32(total_length),
            };
            let field = node.add_field(&fields::IP_LEN, Range::new(base + LENGTH_OFFSET, 2), value);
            field.generated = true;
            field.showname = Some(format!(
                "Total Length: {total_length} bytes (reported as 0, presumed to be because of \"TCP segmentation offload\" (TSO))"
            ));
            // `ip.len` stays FT_UINT16 even when the computed value is
            // wider; the raw bytes stay the on-wire zero.
            field.raw = Some(RawField {
                bytes: vec![0, 0].into(),
                start: base + LENGTH_OFFSET,
                length: 2,
                bitmask: 0,
                field_type: 5,
                source: RawSource::Field,
            });
        } else {
            node.add_field(
                &fields::IP_LEN,
                Range::new(base + LENGTH_OFFSET, 2),
                Value::Uint16(u16::try_from(total_length).unwrap_or(u16::MAX)),
            );
        }
        if raw_total_length != Some(0) && total_length_usize < header_length {
            add_protocol_expert(&mut node, "Bogus IP length".to_string());
            parent.add_child(node);
            context.depth = context.depth.saturating_sub(1);
            return;
        }
        if total_length_usize > data.len() && !context.quoted {
            add_protocol_expert(
                &mut node,
                format!(
                    "IPv4 total length exceeds packet length ({} bytes)",
                    data.len()
                ),
            );
        }
    }

    let identification = read_u16_be(data, IDENTIFICATION_OFFSET);
    if let Some(identification) = identification {
        node.add_field(
            &fields::IP_ID,
            Range::new(base + IDENTIFICATION_OFFSET, 2),
            Value::Uint16(identification),
        );
    }

    let flags = read_u16_be(data, FLAGS_OFFSET);
    if let Some(flags) = flags {
        let flag_bits = u8::try_from((flags >> 13) & 0x07).unwrap_or(0);
        node.add_field(
            &fields::IP_FLAGS,
            Range::new(base + FLAGS_OFFSET, 2),
            Value::Uint8(flag_bits),
        );
        node.add_field(
            &fields::IP_FLAGS_RB,
            Range::new(base + FLAGS_OFFSET, 2),
            Value::Boolean(flags & 0x8000 != 0),
        );
        node.add_field(
            &fields::IP_FLAGS_DF,
            Range::new(base + FLAGS_OFFSET, 2),
            Value::Boolean(flags & 0x4000 != 0),
        );
        node.add_field(
            &fields::IP_FLAGS_MF,
            Range::new(base + FLAGS_OFFSET, 2),
            Value::Boolean(flags & 0x2000 != 0),
        );
        node.add_field(
            &fields::IP_FRAG_OFFSET,
            Range::new(base + FLAGS_OFFSET, 2),
            Value::Uint16(flags & 0x1fff),
        );
    }

    if let Some(ttl) = data.get(TTL_OFFSET).copied() {
        node.add_field(
            &fields::IP_TTL,
            Range::new(base + TTL_OFFSET, 1),
            Value::Uint8(ttl),
        );
    }
    let protocol = data.get(PROTOCOL_OFFSET).copied();
    if let Some(protocol) = protocol {
        node.add_field(
            &fields::IP_PROTO,
            Range::new(base + PROTOCOL_OFFSET, 1),
            Value::Uint8(protocol),
        );
    }
    let checksum = read_u16_be(data, CHECKSUM_OFFSET);
    if let Some(checksum) = checksum {
        node.add_field(
            &fields::IP_CHECKSUM,
            Range::new(base + CHECKSUM_OFFSET, 2),
            Value::Uint16(checksum),
        );
        let calculated = data
            .get(..header_length)
            .filter(|_| context.options.preferences.ip_check_checksum)
            .map(header_checksum);
        checksum::report(
            &mut node,
            checksum::ChecksumFields {
                status: &fields::IP_CHECKSUM_STATUS,
                calculated: Some(&fields::IP_CHECKSUM_CALCULATED),
            },
            Range::new(base + CHECKSUM_OFFSET, 2),
            checksum,
            calculated,
            checksum::ZeroChecksum::Validate,
            Severity::Error,
            false,
        );
    }

    let source = read_ipv4(data, SOURCE_OFFSET);
    if let Some(source) = source {
        node.add_field(
            &fields::IP_SRC,
            Range::new(base + SOURCE_OFFSET, 4),
            Value::Ipv4(source),
        );
        let address = std::net::IpAddr::V4(std::net::Ipv4Addr::from(source));
        let host = context
            .names
            .host_mut(&address)
            .map(str::to_string)
            .unwrap_or_else(|| std::net::Ipv4Addr::from(source).to_string());
        node.add_field(
            &fields::IP_SRC_HOST,
            Range::new(base + SOURCE_OFFSET, 4),
            Value::String(host),
        );
    }

    let header_complete = data.len() >= header_length;
    let options_end = data.len().min(header_length);
    let captured_options = data.get(OPTIONS_OFFSET..options_end).unwrap_or(&[]);
    let mut option_scratch = Node::new(
        &fields::IP_PROTOCOL,
        Range::new(base + OPTIONS_OFFSET, captured_options.len()),
    );
    let clean_stop = parse_options(
        context,
        &mut option_scratch,
        captured_options,
        base + OPTIONS_OFFSET,
        header_length.saturating_sub(OPTIONS_OFFSET),
    );

    let destination = read_ipv4(data, DESTINATION_OFFSET);
    if header_complete || clean_stop {
        if let Some(destination) = destination {
            node.add_field(
                &fields::IP_DST,
                Range::new(base + DESTINATION_OFFSET, 4),
                Value::Ipv4(destination),
            );
            let address = std::net::IpAddr::V4(std::net::Ipv4Addr::from(destination));
            let host = context
                .names
                .host_mut(&address)
                .map(str::to_string)
                .unwrap_or_else(|| std::net::Ipv4Addr::from(destination).to_string());
            node.add_field(
                &fields::IP_DST_HOST,
                Range::new(base + DESTINATION_OFFSET, 4),
                Value::String(host),
            );
        }
        node.fields.append(&mut option_scratch.fields);
    }
    node.experts.append(&mut option_scratch.experts);

    if !header_complete {
        context.mark_malformed(&mut node, "IPv4 header shorter than its header length");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let flags_value = flags.unwrap_or(0);
    let fragmented = flags_value & 0x2000 != 0 || flags_value & 0x1fff != 0;
    if let (Some(source), Some(destination), Some(protocol)) = (source, destination, protocol) {
        *context.network = Some(NetworkContext::Ipv4 {
            source,
            destination,
            protocol,
            fragmented,
        });

        let declared = total_length.map_or(data.len(), |length| {
            usize::try_from(length).unwrap_or(usize::MAX)
        });
        let payload_end = if raw_total_length == Some(0) {
            data.len()
        } else {
            declared.min(data.len())
        };
        let captured_payload = data.get(header_length..payload_end).unwrap_or(&[]);
        let declared_payload = if raw_total_length == Some(0) {
            captured_payload.len()
        } else {
            declared.saturating_sub(header_length)
        };

        if !fragmented {
            let frame_remaining = context
                .frame_reported_length
                .saturating_sub(base.saturating_add(header_length));
            let declared_payload = if raw_total_length == Some(0) {
                frame_remaining
            } else {
                declared_payload
            };
            let saved_reported = context.reported_length;
            context.reported_length = if context.quoted {
                declared_payload
            } else {
                declared_payload.min(frame_remaining)
            };
            if declared_payload > 0 {
                decode::dispatch_ip_protocol(
                    context,
                    &mut node,
                    protocol,
                    captured_payload,
                    base + header_length,
                );
            }
            context.reported_length = saved_reported;
        } else if !context.quoted
            && context.options.preferences.ip_defragment
            && let Some(identification) = identification
        {
            // RFC 791 section 3.2: the identification, addresses and
            // protocol name the datagram; the offset counts eight-octet
            // units from the first byte of the payload.
            let outcome = context.state.insert_fragment4(
                Frag4Key {
                    source,
                    destination,
                    protocol,
                    identification,
                },
                FragmentPart {
                    offset: usize::from(flags_value & 0x1fff) * 8,
                    data: captured_payload,
                    declared_len: declared_payload,
                    frame: context.frame.number,
                    file: context.frame.file_number,
                    more: flags_value & 0x2000 != 0,
                    timestamp: context.frame.timestamp,
                },
            );
            match outcome {
                FragmentOutcome::Complete(reassembly) => {
                    if context.pass == crate::state::PassMode::First {
                        let completing = context.frame.file_number;
                        for part in &reassembly.parts {
                            if part.file != completing {
                                context
                                    .state
                                    .annotations_mut()
                                    .link_ip_reassembled(part.file, completing);
                            }
                        }
                    }
                    decode::ipv4_fragment_fields(&mut node, base, &reassembly);
                    *context.network = Some(NetworkContext::Ipv4 {
                        source,
                        destination,
                        protocol,
                        fragmented: false,
                    });
                    let child_start = node.children.len();
                    let saved_reported = context.reported_length;
                    let saved_frame_reported = context.frame_reported_length;
                    context.reported_length = reassembly.data.len();
                    context.frame_reported_length = reassembly.data.len();
                    if !reassembly.data.is_empty() {
                        decode::dispatch_ip_protocol(
                            context,
                            &mut node,
                            protocol,
                            &reassembly.data,
                            0,
                        );
                    }
                    if let Some(children) = node.children.get_mut(child_start..) {
                        decode::annotate_reassembled_fields(children, &reassembly.data);
                    }
                    context.reported_length = saved_reported;
                    context.frame_reported_length = saved_frame_reported;
                }
                FragmentOutcome::Malformed => node.add_expert(ExpertInfo {
                    severity: Severity::Warning,
                    group: Group::Sequence,
                    message: "IPv4 non-final fragment is not a multiple of 8 octets".to_string(),
                }),
                other => {
                    if let Some(expert) = other.own_limit_expert() {
                        node.add_expert(expert);
                    }
                }
            }
        }
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Sum the 16-bit header words with the checksum field treated as zero.
fn header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (words, _) = header.as_chunks::<2>();
    for (index, word) in words.iter().enumerate() {
        let offset = index.saturating_mul(2);
        if offset == CHECKSUM_WORD_OFFSET {
            continue;
        }
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*word)));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}

/// Parse the options area, which is `header_length - 20` bytes long.
fn parse_options(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    declared_length: usize,
) -> bool {
    let mut offset = 0_usize;
    while offset < data.len() {
        let Some(&option_type) = data.get(offset) else {
            return false;
        };
        if option_type == OPTION_EOL {
            add_option_type(node, base, offset, option_type);
            return true;
        }
        if option_type == OPTION_NOP {
            add_option_type(node, base, offset, option_type);
            offset = offset.saturating_add(1);
            continue;
        }

        let Some(&length_byte) = data.get(offset.saturating_add(1)) else {
            context.mark_malformed(node, "IPv4 option is truncated");
            return false;
        };
        let length = usize::from(length_byte);
        if length < 2 {
            add_option_warning(
                node,
                format!(
                    "{} (with too-short option length = {length} {})",
                    option_name(option_type),
                    if length == 1 { "byte" } else { "bytes" }
                ),
            );
            return true;
        }
        let Some(option_end) = offset.checked_add(length) else {
            context.mark_malformed(node, "IPv4 option length overflows");
            return true;
        };
        if option_end > declared_length {
            add_option_warning(
                node,
                format!(
                    "{} (option length = {length} bytes says option goes past end of options)",
                    option_name(option_type)
                ),
            );
            return true;
        }
        if option_end > data.len() {
            context.mark_malformed(node, "IPv4 option is truncated");
            return length >= 4;
        }

        add_option_type(node, base, offset, option_type);
        node.add_field(
            &fields::IP_OPT_LEN,
            Range::new(base + offset + 1, 1),
            Value::Uint8(length_byte),
        );
        let option_data = data
            .get(offset.saturating_add(2)..option_end)
            .unwrap_or(&[]);
        match option_type {
            OPTION_RECORD_ROUTE => {
                if !parse_record_route(context, node, option_data, base + offset + 2) {
                    return data.len() > option_end || data.len() >= declared_length;
                }
            }
            OPTION_TIMESTAMP => {
                if !parse_timestamp(context, node, option_data, base + offset + 2) {
                    return data.len() > option_end || data.len() >= declared_length;
                }
            }
            OPTION_ROUTER_ALERT => {
                if let Some(value) = read_u16_be(option_data, 0) {
                    node.add_field(
                        &fields::IP_OPT_RA,
                        Range::new(base + offset + 2, 2),
                        Value::Uint16(value),
                    );
                }
            }
            _ => {
                let range = Range::new(base + offset + 2, option_data.len());
                if option_data.is_empty() {
                    node.add_field(&fields::IP_OPT_DATA, range, Value::Missing);
                } else {
                    node.add_field(
                        &fields::IP_OPT_DATA,
                        range,
                        Value::bytes(option_data.to_vec()),
                    );
                }
            }
        }
        offset = option_end;
    }
    data.len() >= declared_length
}

/// Add the type byte and its bit fields for one option.
fn add_option_type(node: &mut Node, base: usize, offset: usize, option_type: u8) {
    let range = Range::new(base + offset, 1);
    node.add_field(&fields::IP_OPT_TYPE, range, Value::Uint8(option_type));
    node.add_field(
        &fields::IP_OPT_TYPE_COPY,
        range,
        Value::Boolean(option_type & 0x80 != 0),
    );
    node.add_field(
        &fields::IP_OPT_TYPE_CLASS,
        range,
        Value::Uint8((option_type >> 5) & 0x03),
    );
    node.add_field(
        &fields::IP_OPT_TYPE_NUMBER,
        range,
        Value::Uint8(option_type & 0x1f),
    );
}

/// Parse a record-route option's pointer and address slots.
///
/// The pointer is one-based from the option's first byte. Address slots before
/// the pointer are recorded routes and slots from it on are empty; an
/// out-of-range pointer raises a protocol warning instead of reading bytes.
fn parse_record_route(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    option_data: &[u8],
    base: usize,
) -> bool {
    let Some(&pointer) = option_data.first() else {
        context.mark_malformed(node, "Record Route option is too short");
        return false;
    };
    node.add_field(
        &fields::IP_OPT_PTR,
        Range::new(base, 1),
        Value::Uint8(pointer),
    );

    let pointer = usize::from(pointer);
    if pointer < 4 {
        add_option_warning(node, "Pointer points before first address".to_string());
        return true;
    }
    let next_slot = pointer - 4;
    if next_slot % 4 != 0 {
        add_option_warning(node, "Pointer points to middle of address".to_string());
        return true;
    }
    let recorded_slots = next_slot / 4;
    let mut slot = 0_usize;
    let mut address_offset = 1_usize;
    while let Some(address) = read_ipv4(option_data, address_offset) {
        let def = if slot < recorded_slots {
            &fields::IP_REC_RT
        } else {
            &fields::IP_EMPTY_RT
        };
        node.add_field(
            def,
            Range::new(base + address_offset, 4),
            Value::Ipv4(address),
        );
        slot = slot.saturating_add(1);
        address_offset = address_offset.saturating_add(4);
    }
    true
}

/// Parse a timestamp option's pointer, overflow and flag and its suboptions.
///
/// Flag 0 carries timestamps only, flag 1 an address before each timestamp,
/// and flag 3 prespecified addresses before each timestamp. A suboption that
/// does not fit raises a protocol warning and stops the option.
fn parse_timestamp(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    option_data: &[u8],
    base: usize,
) -> bool {
    let Some(&pointer) = option_data.first() else {
        context.mark_malformed(node, "Time stamp option is too short");
        return false;
    };
    node.add_field(
        &fields::IP_OPT_PTR,
        Range::new(base, 1),
        Value::Uint8(pointer),
    );
    let Some(&control) = option_data.get(1) else {
        context.mark_malformed(node, "Time stamp option is too short");
        return false;
    };
    node.add_field(
        &fields::IP_OPT_OVERFLOW,
        Range::new(base + 1, 1),
        Value::Uint8(control >> 4),
    );
    node.add_field(
        &fields::IP_OPT_FLAG,
        Range::new(base + 1, 1),
        Value::Uint8(control & 0x0f),
    );

    let flag = control & 0x0f;
    let suboptions = option_data.get(2..).unwrap_or(&[]);
    let mut offset = 0_usize;
    match flag {
        1 | 3 => {
            while offset < suboptions.len() {
                let (Some(address), Some(value)) = (
                    read_ipv4(suboptions, offset),
                    read_u32_be(suboptions, offset.saturating_add(4)),
                ) else {
                    add_option_warning(node, "Suboption would go past end of option".to_string());
                    break;
                };
                node.add_field(
                    &fields::IP_OPT_TIME_STAMP_ADDR,
                    Range::new(base + 2 + offset, 4),
                    Value::Ipv4(address),
                );
                node.add_field(
                    &fields::IP_OPT_TIME_STAMP,
                    Range::new(base + 2 + offset + 4, 4),
                    Value::Uint32(value),
                );
                offset = offset.saturating_add(8);
            }
        }
        _ => {
            while let Some(value) = read_u32_be(suboptions, offset) {
                node.add_field(
                    &fields::IP_OPT_TIME_STAMP,
                    Range::new(base + 2 + offset, 4),
                    Value::Uint32(value),
                );
                offset = offset.saturating_add(4);
            }
            if offset < suboptions.len() {
                add_option_warning(node, "Suboption would go past end of option".to_string());
            }
        }
    }
    true
}

fn option_name(option_type: u8) -> String {
    match option_type {
        OPTION_RECORD_ROUTE => "Record Route".to_string(),
        OPTION_TIMESTAMP => "Time stamp".to_string(),
        OPTION_ROUTER_ALERT => "Router Alert".to_string(),
        _ => format!("Unknown (0x{option_type:02x})"),
    }
}

fn add_option_warning(node: &mut Node, message: String) {
    node.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Protocol,
        message,
    });
}

fn add_protocol_expert(node: &mut Node, message: String) {
    node.add_expert(ExpertInfo {
        severity: Severity::Error,
        group: Group::Protocol,
        message,
    });
}
