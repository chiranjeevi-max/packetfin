//! Generic Network Virtualization Encapsulation.
//!
//! RFC 8926 section 3 defines the eight-octet base header: a two-bit version
//! and six-bit option length in four-octet units, one flag octet, the
//! protocol type of the encapsulated payload, a 24-bit VNI and one reserved
//! octet. Each option is a four-octet header (16-bit class, 8-bit type,
//! 8-bit length in four-octet units) followed by its data. The header's
//! declared option length bounds every option, so a length that overruns
//! the captured options stops this decoder and keeps the fields already
//! decoded.

use crate::decode::bytes::{read_u16_be, read_u24_be};
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const BASE_HEADER_LENGTH: usize = 8;
const VERSION_OFFSET: usize = 0;
const FLAGS_OFFSET: usize = 1;
const PROTOCOL_OFFSET: usize = 2;
const VNI_OFFSET: usize = 4;
const RESERVED_OFFSET: usize = 7;

const OPTION_HEADER_LENGTH: usize = 4;
/// The base header's six-bit option length, in four-octet units.
const HEADER_OPTION_LENGTH_MASK: u8 = 0x3f;
/// The option header's five-bit length, after three reserved bits; RFC 8926
/// section 3.5.
const OPTION_LENGTH_MASK: u8 = 0x1f;
const OPTION_CRITICAL_BIT: u8 = 0x80;

/// Decode one Geneve header, its bounded options and its payload.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::GENEVE_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::GENEVE_PROTOCOL, Range::new(base, data.len()));

    let Some(version_and_length) = data.get(VERSION_OFFSET).copied() else {
        context.mark_malformed(&mut node, "Geneve header is empty");
        finish(context, parent, node);
        return;
    };
    let version = version_and_length >> 6;
    let options_length =
        usize::from(version_and_length & HEADER_OPTION_LENGTH_MASK).saturating_mul(4);
    node.add_field(
        &fields::GENEVE_VERSION,
        Range::new(base + VERSION_OFFSET, 1),
        Value::Uint8(version),
    );
    node.add_field(
        &fields::GENEVE_OPTION_LENGTH,
        Range::new(base + VERSION_OFFSET, 1),
        Value::Uint8(u8::try_from(options_length).unwrap_or(u8::MAX)),
    );
    if version != 0 {
        node.add_field(
            &fields::GENEVE_VERSION_UNKNOWN,
            Range::new(base + VERSION_OFFSET, 0),
            Value::None,
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Undecoded,
            message: format!("Unknown version {version}"),
        });
    }

    let Some(flags) = data.get(FLAGS_OFFSET).copied() else {
        context.mark_malformed(&mut node, "Geneve header is truncated");
        finish(context, parent, node);
        return;
    };
    node.add_field(
        &fields::GENEVE_FLAGS,
        Range::new(base + FLAGS_OFFSET, 1),
        Value::Uint8(flags),
    );
    node.add_field(
        &fields::GENEVE_FLAGS_OAM,
        Range::new(base + FLAGS_OFFSET, 1),
        Value::Boolean(flags & 0x80 != 0),
    );
    node.add_field(
        &fields::GENEVE_FLAGS_CRITICAL,
        Range::new(base + FLAGS_OFFSET, 1),
        Value::Boolean(flags & 0x40 != 0),
    );
    node.add_field(
        &fields::GENEVE_FLAGS_RESERVED,
        Range::new(base + FLAGS_OFFSET, 1),
        Value::Boolean(flags & 0x3f != 0),
    );

    let Some(protocol_type) = read_u16_be(data, PROTOCOL_OFFSET) else {
        context.mark_malformed(&mut node, "Geneve header is truncated");
        finish(context, parent, node);
        return;
    };
    node.add_field(
        &fields::GENEVE_PROTO_TYPE,
        Range::new(base + PROTOCOL_OFFSET, 2),
        Value::Uint16(protocol_type),
    );
    if let Some(vni) = read_u24_be(data, VNI_OFFSET) {
        node.add_field(
            &fields::GENEVE_VNI,
            Range::new(base + VNI_OFFSET, 3),
            Value::Uint24(vni),
        );
    }
    if let Some(reserved) = data.get(RESERVED_OFFSET).copied() {
        node.add_field(
            &fields::GENEVE_RESERVED,
            Range::new(base + RESERVED_OFFSET, 1),
            Value::Uint8(reserved),
        );
    }
    if data.len() < BASE_HEADER_LENGTH {
        context.mark_malformed(&mut node, "Geneve header is truncated");
        finish(context, parent, node);
        return;
    }

    let available = data.len().saturating_sub(BASE_HEADER_LENGTH);
    if options_length > available {
        context.mark_malformed(&mut node, "Geneve options are truncated");
        finish(context, parent, node);
        return;
    }

    if options_length > 0 {
        let options = data.get(BASE_HEADER_LENGTH..BASE_HEADER_LENGTH + options_length);
        if let Some(options) = options {
            node.add_field(
                &fields::GENEVE_OPTIONS,
                Range::new(base + BASE_HEADER_LENGTH, options_length),
                Value::bytes(options.to_vec()),
            );
            if !decode_options(context, &mut node, options, base + BASE_HEADER_LENGTH) {
                finish(context, parent, node);
                return;
            }
        }
    }

    let payload_offset = BASE_HEADER_LENGTH + options_length;
    let payload = data.get(payload_offset..).unwrap_or(&[]);
    decode::dispatch_ethertype(
        context,
        &mut node,
        protocol_type,
        payload,
        base + payload_offset,
    );
    finish(context, parent, node);
}

/// Decode the option list. Returns `false` when an option overruns the
/// declared option area, so the payload is not decoded.
fn decode_options(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    options: &[u8],
    base: usize,
) -> bool {
    let mut offset = 0_usize;
    while offset < options.len() {
        let Some(header) = options.get(offset..offset.saturating_add(OPTION_HEADER_LENGTH)) else {
            context.mark_malformed(node, "Geneve option header is truncated");
            return false;
        };
        let (Some(class), Some(option_type), Some(length_byte)) = (
            read_u16_be(options, offset),
            header.get(2).copied(),
            header.get(3).copied(),
        ) else {
            context.mark_malformed(node, "Geneve option header is truncated");
            return false;
        };
        let option_length = OPTION_HEADER_LENGTH
            .saturating_add(usize::from(length_byte & OPTION_LENGTH_MASK).saturating_mul(4));
        let Some(option) = options.get(offset..offset.saturating_add(option_length)) else {
            node.add_field(
                &fields::GENEVE_OPTION_LENGTH_INVALID,
                Range::new(base + offset + 3, 0),
                Value::None,
            );
            context.mark_malformed(node, "Geneve option length is past the end of the options");
            return false;
        };
        node.add_field(
            &fields::GENEVE_OPTION,
            Range::new(base + offset, option_length),
            Value::bytes(option.to_vec()),
        );
        node.add_field(
            &fields::GENEVE_OPTION_CLASS,
            Range::new(base + offset, 2),
            Value::Uint16(class),
        );
        node.add_field(
            &fields::GENEVE_OPTION_TYPE,
            Range::new(base + offset + 2, 1),
            Value::Uint8(option_type),
        );
        node.add_field(
            &fields::GENEVE_OPTION_TYPE_CRITICAL,
            Range::new(base + offset + 2, 1),
            Value::Boolean(option_type & OPTION_CRITICAL_BIT != 0),
        );
        node.add_field(
            &fields::GENEVE_OPTION_FLAGS,
            Range::new(base + offset + 3, 1),
            Value::Uint8(length_byte >> 5),
        );
        node.add_field(
            &fields::GENEVE_OPTION_FLAGS_RESERVED,
            Range::new(base + offset + 3, 1),
            Value::Boolean(length_byte & 0xe0 != 0),
        );
        node.add_field(
            &fields::GENEVE_OPTION_LENGTH,
            Range::new(base + offset + 3, 1),
            Value::Uint8(u8::try_from(option_length).unwrap_or(u8::MAX)),
        );
        let data = option.get(OPTION_HEADER_LENGTH..).unwrap_or(&[]);
        node.add_field(
            &fields::GENEVE_OPTION_UNKNOWN_DATA,
            Range::new(base + offset + OPTION_HEADER_LENGTH, data.len()),
            if data.is_empty() {
                Value::Missing
            } else {
                Value::bytes(data.to_vec())
            },
        );
        offset = offset.saturating_add(option_length);
    }
    true
}

fn finish(context: &mut DecodeContext<'_>, parent: &mut Node, node: Node) {
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
