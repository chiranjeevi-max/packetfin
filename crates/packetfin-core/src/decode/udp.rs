//! User Datagram Protocol.
//!
//! The UDP header is eight bytes: source and destination ports, the length of
//! the datagram including the header, and a checksum over an IPv4 or IPv6
//! pseudo-header plus the datagram. The decoder adds each field as soon as its
//! bytes are captured, treats a length below eight as malformed and stops,
//! and marks a length beyond the captured payload while still keeping the
//! fields it already decoded.
//!
//! A zero checksum means "not present" over IPv4 and is illegal over IPv6;
//! both statuses are reported even when checksum validation is disabled.
//! Validation itself follows the `udp.check_checksum` preference.

use crate::decode;
use crate::decode::bytes::{byte_count_text, read_u16_be};
use crate::decode::checksum;
use crate::decode::{DecodeContext, NetworkContext};
use crate::fields;
use crate::state::{StreamAddress, StreamKey};
use crate::tree::{ExpertInfo, FieldParent, Group, Node, Range, Severity, Value};

const HEADER_LENGTH: usize = 8;
const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const LENGTH_OFFSET: usize = 4;
const CHECKSUM_OFFSET: usize = 6;

/// Decode one UDP datagram into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::UDP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::UDP_PROTOCOL, Range::new(base, data.len()));
    let (Some(source_port), Some(destination_port)) = (
        read_u16_be(data, SOURCE_PORT_OFFSET),
        read_u16_be(data, DESTINATION_PORT_OFFSET),
    ) else {
        context.mark_malformed(&mut node, "UDP header is shorter than its ports");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };

    node.add_field(
        &fields::UDP_SRC_PORT,
        Range::new(base + SOURCE_PORT_OFFSET, 2),
        Value::Uint16(source_port),
    );
    node.add_field(
        &fields::UDP_DST_PORT,
        Range::new(base + DESTINATION_PORT_OFFSET, 2),
        Value::Uint16(destination_port),
    );
    // Append both alias occurrences after the two real port fields.
    node.add_field(
        &fields::UDP_PORT,
        Range::new(base + SOURCE_PORT_OFFSET, 2),
        Value::Uint16(source_port),
    );
    node.add_field(
        &fields::UDP_PORT,
        Range::new(base + DESTINATION_PORT_OFFSET, 2),
        Value::Uint16(destination_port),
    );

    let length = read_u16_be(data, LENGTH_OFFSET);
    if data.len() < HEADER_LENGTH {
        if let Some(length) = length {
            node.add_field(
                &fields::UDP_LENGTH,
                Range::new(base + LENGTH_OFFSET, 2),
                Value::Uint16(length),
            );
        }
        context.mark_malformed(&mut node, "UDP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }
    let length = length.unwrap_or(0);
    let declared_length = usize::from(length);
    if declared_length < HEADER_LENGTH {
        node.add_field(
            &fields::UDP_LENGTH,
            Range::new(base + LENGTH_OFFSET, 2),
            Value::Uint16(length),
        );
        mark_malformed_message(context, &mut node, format!("Bad length value {length} < 8"));
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    node.add_field(
        &fields::UDP_LENGTH,
        Range::new(base + LENGTH_OFFSET, 2),
        Value::Uint16(length),
    );

    if declared_length > data.len() {
        mark_malformed_message(
            context,
            &mut node,
            format!("Bad length value {length} > IP payload length"),
        );
    }

    if let Some(stored) = read_u16_be(data, CHECKSUM_OFFSET) {
        node.add_field(
            &fields::UDP_CHECKSUM,
            Range::new(base + CHECKSUM_OFFSET, 2),
            Value::Uint16(stored),
        );
        let zero = if matches!(context.network.as_ref(), Some(NetworkContext::Ipv6 { .. })) {
            checksum::ZeroChecksum::Illegal
        } else {
            checksum::ZeroChecksum::NotPresent
        };
        checksum::report(
            &mut node,
            checksum::ChecksumFields {
                status: &fields::UDP_CHECKSUM_STATUS,
                calculated: Some(&fields::UDP_CHECKSUM_CALCULATED),
            },
            Range::new(base + CHECKSUM_OFFSET, 2),
            stored,
            calculated_checksum(context, data, length),
            zero,
            Severity::Error,
            true,
        );
    }

    // Add the stream fields after the fixed header and checksum:
    // the index points one byte past it and the packet number at its start.
    // A length above the captured payload still belongs to a stream.
    let mut stream_fact: Option<(StreamKey, u8)> = None;
    if let Some((key, direction)) = context.conversation_key(source_port, destination_port) {
        let (stream, times) =
            context
                .state
                .udp_stream_timed(key, context.quoted, context.frame.timestamp);
        if !context.quoted
            && let Some((source, destination)) = udp_stream_addresses(context)
        {
            stream_fact = Some((
                StreamKey {
                    index: stream.index,
                    source,
                    source_port,
                    destination,
                    destination_port,
                },
                u8::try_from(direction).unwrap_or(1),
            ));
        }
        node.add_field(
            &fields::UDP_STREAM,
            Range::new(base + HEADER_LENGTH, 0),
            Value::Uint32(stream.index),
        );
        if !context.quoted {
            node.add_field(
                &fields::UDP_STREAM_PNUM,
                Range::new(base, 0),
                Value::Uint32(stream.packet_number),
            );
            if context.options.udp_timestamps
                && let (Some(relative), Some(delta)) = (times.relative, times.delta)
            {
                let timestamps = node.add_unnamed(Range::new(base, 0), "Timestamps".to_string());
                timestamps.generated = true;
                timestamps
                    .add_field(
                        &fields::UDP_TIME_RELATIVE,
                        Range::new(base, 0),
                        Value::RelativeTime(relative),
                    )
                    .showname = Some(format!(
                    "Time since first frame: {}",
                    crate::time::delta_text(i128::from(relative))
                ));
                timestamps
                    .add_field(
                        &fields::UDP_TIME_DELTA,
                        Range::new(base, 0),
                        Value::RelativeTime(delta),
                    )
                    .showname = Some(format!(
                    "Time since previous frame: {}",
                    crate::time::delta_text(i128::from(delta))
                ));
            }
        }
    }

    if let Some(payload) = data.get(HEADER_LENGTH..)
        && !payload.is_empty()
        && declared_length > HEADER_LENGTH
    {
        node.add_field(
            &fields::UDP_PAYLOAD,
            Range::new(base + HEADER_LENGTH, payload.len()),
            Value::bytes(payload.to_vec()),
        )
        .showname = Some(format!("UDP payload ({})", byte_count_text(payload.len())));
    }

    let payload_length = declared_length
        .saturating_sub(HEADER_LENGTH)
        .min(data.len().saturating_sub(HEADER_LENGTH));
    if let Some(payload) = data.get(HEADER_LENGTH..HEADER_LENGTH.saturating_add(payload_length)) {
        if !payload.is_empty()
            && let Some((key, direction)) = stream_fact
        {
            context.observer.udp_payload(key, direction, payload);
        }
        // DNS transaction keys include the datagram's ports; nested
        // encapsulations restore the outer value when they return.
        let previous_ports = context.udp_ports;
        context.udp_ports = Some((source_port, destination_port));
        let saved = context.transport.replace(crate::decode::TransportContext {
            source_port,
            destination_port,
            protocol: 17,
        });
        decode::dispatch_udp_ports(
            context,
            &mut node,
            source_port,
            destination_port,
            payload,
            base + HEADER_LENGTH,
        );
        context.udp_ports = previous_ports;
        *context.transport = saved;
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// The IPv4 or IPv6 endpoints of a UDP datagram.
fn udp_stream_addresses(context: &DecodeContext<'_>) -> Option<(StreamAddress, StreamAddress)> {
    match context.network.as_ref()? {
        NetworkContext::Ipv4 {
            source,
            destination,
            ..
        } => Some((
            StreamAddress::Ipv4(*source),
            StreamAddress::Ipv4(*destination),
        )),
        NetworkContext::Ipv6 {
            source,
            destination,
            ..
        } => Some((
            StreamAddress::Ipv6(*source),
            StreamAddress::Ipv6(*destination),
        )),
    }
}

/// The checksum the datagram should carry, or `None` when validation is
/// disabled, the declared length is not captured or the network layer is
/// unknown.
fn calculated_checksum(context: &DecodeContext<'_>, data: &[u8], length: u16) -> Option<u16> {
    if !context.options.preferences.udp_check_checksum {
        return None;
    }
    let coverage = data.get(..usize::from(length))?;
    match context.network.as_ref()? {
        NetworkContext::Ipv4 {
            source,
            destination,
            ..
        } => Some(checksum::ipv4_transport(
            *source,
            *destination,
            17,
            u32::from(length),
            coverage,
            CHECKSUM_OFFSET,
        )),
        NetworkContext::Ipv6 {
            source,
            destination,
            ..
        } => Some(checksum::ipv6_transport(
            *source,
            *destination,
            17,
            u32::from(length),
            coverage,
            CHECKSUM_OFFSET,
        )),
    }
}

/// Mark the packet malformed with a message built at run time.
fn mark_malformed_message(context: &mut DecodeContext<'_>, node: &mut Node, message: String) {
    if context.quoted {
        return;
    }
    *context.malformed = true;
    node.protocol_exception = true;
    node.add_expert(ExpertInfo {
        severity: Severity::Error,
        group: Group::Malformed,
        message,
    });
}
