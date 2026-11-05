//! Cisco NetFlow version 5, version 9 and IPFIX (version 10) flow export.
//!
//! Version 5's header and 48-octet flow record are decoded here. Version 9
//! and IPFIX add template-set parsing and a per-exporter template cache in
//! the `netflow` submodule. The UDP dispatcher selects this decoder by port;
//! the version field itself then selects the layout (RFC 3954 section 5.1,
//! RFC 7011 section 3.1).

mod ie;
mod netflow;

use crate::decode::DecodeContext;
use crate::decode::bytes::{read_ipv4, read_u16_be, read_u32_be};
use crate::fields;
use crate::tree::{Node, Range, Value};

const HEADER_LENGTH: usize = 24;
const RECORD_LENGTH: usize = 48;
const VERSION_FIVE: u16 = 5;

/// Decode one NetFlow datagram into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::CFLOW_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::CFLOW_PROTOCOL, Range::new(base, data.len()));
    if !parse(context, &mut node, data, base) {
        context.mark_malformed(&mut node, "Malformed NetFlow message");
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Dispatch one datagram by its version field.
fn parse(context: &mut DecodeContext<'_>, node: &mut Node, data: &[u8], base: usize) -> bool {
    let Some(version) = read_u16_be(data, 0) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_VERSION,
        Range::new(base, 2),
        Value::Uint16(version),
    );
    match version {
        VERSION_FIVE => parse_version_five(node, data, base),
        9 => netflow::parse_v9(context, node, data, base),
        10 => netflow::parse_ipfix(context, node, data, base),
        _ => {
            let Some(count) = read_u16_be(data, 2) else {
                return false;
            };
            node.add_field(
                &fields::CFLOW_COUNT,
                Range::new(base + 2, 2),
                Value::Uint16(count),
            );
            data.len() >= HEADER_LENGTH
        }
    }
}

/// Parse the version-5 header and the records it declares.
fn parse_version_five(node: &mut Node, data: &[u8], base: usize) -> bool {
    let Some(count) = read_u16_be(data, 2) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_COUNT,
        Range::new(base + 2, 2),
        Value::Uint16(count),
    );
    let Some(uptime) = read_u32_be(data, 4) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_SYSUPTIME,
        Range::new(base + 4, 4),
        Value::RelativeTime(i64::from(uptime).saturating_mul(1_000_000)),
    );

    let (Some(unix_seconds), Some(unix_nanos)) = (read_u32_be(data, 8), read_u32_be(data, 12))
    else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_TIMESTAMP,
        Range::new(base + 8, 8),
        Value::AbsoluteTime(crate::capture::Timestamp {
            seconds: i64::from(unix_seconds),
            nanos: unix_nanos.min(999_999_999),
        }),
    );
    node.add_field(
        &fields::CFLOW_UNIX_SECS,
        Range::new(base + 8, 4),
        Value::Uint32(unix_seconds),
    );
    node.add_field(
        &fields::CFLOW_UNIX_NSECS,
        Range::new(base + 12, 4),
        Value::Uint32(unix_nanos),
    );

    let Some(sequence) = read_u32_be(data, 16) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_SEQUENCE,
        Range::new(base + 16, 4),
        Value::Uint32(sequence),
    );
    if let Some(engine_type) = data.get(20).copied() {
        node.add_field(
            &fields::CFLOW_ENGINE_TYPE,
            Range::new(base + 20, 1),
            Value::Uint8(engine_type),
        );
    }
    if let Some(engine_id) = data.get(21).copied() {
        node.add_field(
            &fields::CFLOW_ENGINE_ID,
            Range::new(base + 21, 1),
            Value::Uint8(engine_id),
        );
    }
    if let Some(sampling) = read_u16_be(data, 22) {
        node.add_field(
            &fields::CFLOW_SAMPLINGMODE,
            Range::new(base + 22, 2),
            Value::Uint16((sampling & 0xc000) >> 14),
        );
        node.add_field(
            &fields::CFLOW_SAMPLERATE,
            Range::new(base + 22, 2),
            Value::Uint16(sampling & 0x3fff),
        );
    }

    for index in 0..usize::from(count) {
        let Some(offset) = index
            .checked_mul(RECORD_LENGTH)
            .and_then(|offset| offset.checked_add(HEADER_LENGTH))
        else {
            break;
        };
        if offset.saturating_add(RECORD_LENGTH) > data.len() {
            break;
        }
        add_record(node, data, base, offset);
    }
    true
}

/// Add one 48-octet flow record.
fn add_record(node: &mut Node, data: &[u8], base: usize, offset: usize) {
    if let Some(address) = read_ipv4(data, offset) {
        node.add_field(
            &fields::CFLOW_SRCADDR,
            Range::new(base + offset, 4),
            Value::Ipv4(address),
        );
    }
    if let Some(address) = read_ipv4(data, offset + 4) {
        node.add_field(
            &fields::CFLOW_DSTADDR,
            Range::new(base + offset + 4, 4),
            Value::Ipv4(address),
        );
    }
    if let Some(address) = read_ipv4(data, offset + 8) {
        node.add_field(
            &fields::CFLOW_NEXTHOP,
            Range::new(base + offset + 8, 4),
            Value::Ipv4(address),
        );
    }
    if let Some(value) = read_u16_be(data, offset + 12) {
        node.add_field(
            &fields::CFLOW_INPUTINT,
            Range::new(base + offset + 12, 2),
            Value::Uint16(value),
        );
    }
    if let Some(value) = read_u16_be(data, offset + 14) {
        node.add_field(
            &fields::CFLOW_OUTPUTINT,
            Range::new(base + offset + 14, 2),
            Value::Uint16(value),
        );
    }
    if let Some(packets) = read_u32_be(data, offset + 16) {
        node.add_field(
            &fields::CFLOW_PACKETS,
            Range::new(base + offset + 16, 4),
            Value::Uint64(u64::from(packets)),
        );
    }
    if let Some(octets) = read_u32_be(data, offset + 20) {
        node.add_field(
            &fields::CFLOW_OCTETS,
            Range::new(base + offset + 20, 4),
            Value::Uint64(u64::from(octets)),
        );
    }
    let first = read_u32_be(data, offset + 24);
    let last = read_u32_be(data, offset + 28);
    if let (Some(first), Some(last)) = (first, last) {
        let duration = i64::from(last) - i64::from(first);
        node.add_field(
            &fields::CFLOW_TIMEDELTA,
            Range::new(base + offset + 24, 8),
            Value::RelativeTime(duration.saturating_mul(1_000_000)),
        );
        node.add_field(
            &fields::CFLOW_TIMESTART,
            Range::new(base + offset + 24, 4),
            Value::RelativeTime(i64::from(first).saturating_mul(1_000_000)),
        );
        node.add_field(
            &fields::CFLOW_TIMEEND,
            Range::new(base + offset + 28, 4),
            Value::RelativeTime(i64::from(last).saturating_mul(1_000_000)),
        );
    }
    if let Some(value) = read_u16_be(data, offset + 32) {
        node.add_field(
            &fields::CFLOW_SRCPORT,
            Range::new(base + offset + 32, 2),
            Value::Uint16(value),
        );
    }
    if let Some(value) = read_u16_be(data, offset + 34) {
        node.add_field(
            &fields::CFLOW_DSTPORT,
            Range::new(base + offset + 34, 2),
            Value::Uint16(value),
        );
    }
    if let Some(value) = data.get(offset + 36).copied() {
        node.add_field(
            &fields::CFLOW_PADDING,
            Range::new(base + offset + 36, 1),
            Value::bytes(vec![value]),
        );
    }
    if let Some(value) = data.get(offset + 37).copied() {
        node.add_field(
            &fields::CFLOW_TCPFLAGS,
            Range::new(base + offset + 37, 1),
            Value::Uint8(value),
        );
    }
    if let Some(value) = data.get(offset + 38).copied() {
        node.add_field(
            &fields::CFLOW_IP_PROTOCOL,
            Range::new(base + offset + 38, 1),
            Value::Uint8(value),
        );
    }
    if let Some(value) = data.get(offset + 39).copied() {
        node.add_field(
            &fields::CFLOW_TOS,
            Range::new(base + offset + 39, 1),
            Value::Uint8(value),
        );
    }
    if let Some(value) = read_u16_be(data, offset + 40) {
        node.add_field(
            &fields::CFLOW_SRCAS,
            Range::new(base + offset + 40, 2),
            Value::Uint16(value),
        );
    }
    if let Some(value) = read_u16_be(data, offset + 42) {
        node.add_field(
            &fields::CFLOW_DSTAS,
            Range::new(base + offset + 42, 2),
            Value::Uint16(value),
        );
    }
    if let Some(value) = data.get(offset + 44).copied() {
        node.add_field(
            &fields::CFLOW_SRCMASK,
            Range::new(base + offset + 44, 1),
            Value::Uint8(value),
        );
    }
    if let Some(value) = data.get(offset + 45).copied() {
        node.add_field(
            &fields::CFLOW_DSTMASK,
            Range::new(base + offset + 45, 1),
            Value::Uint8(value),
        );
    }
    if let Some(padding) = data.get(offset + 46..offset + 48) {
        node.add_field(
            &fields::CFLOW_PADDING,
            Range::new(base + offset + 46, 2),
            Value::bytes(padding.to_vec()),
        );
    }
}
