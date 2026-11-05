//! InMon sFlow version 5 datagrams.
//!
//! Layout, XDR encoding and the sample and record formats follow the sFlow
//! version 5 specification (sflow.org, July 2004), sections 5.1-5.3. Every
//! length is checked against the enclosing sample or record before it is
//! used; the sample and record loops are bounded by the bytes actually
//! present, and an unknown format keeps its bytes as `sflow.enterprise.data`
//! (standard enterprise) or as length plus data (a vendor enterprise).
//!
//! The sampled header is kept as bytes; this decoder does not decode it as the
//! protocol its `header_protocol` names.

use crate::decode::DecodeContext;
use crate::decode::bytes::{array, read_u32_be};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const VERSION_FIVE: u32 = 5;
const ADDRESS_IPV4: u32 = 1;
const ADDRESS_IPV6: u32 = 2;

const SAMPLE_FLOW: u32 = 1;
const SAMPLE_COUNTERS: u32 = 2;
const SAMPLE_EXPANDED_FLOW: u32 = 3;
const SAMPLE_EXPANDED_COUNTERS: u32 = 4;

const FLOW_RAW_HEADER: u32 = 1;
const FLOW_ETHERNET: u32 = 2;
const FLOW_IPV4: u32 = 3;
const FLOW_IPV6: u32 = 4;
const FLOW_EXTENDED_SWITCH: u32 = 1001;
const FLOW_EXTENDED_ROUTER: u32 = 1002;

const COUNTER_GENERIC: u32 = 1;
const COUNTER_ETHERNET: u32 = 2;
const COUNTER_TOKEN_RING: u32 = 3;
const COUNTER_VG: u32 = 4;
const COUNTER_VLAN: u32 = 5;
const COUNTER_PROCESSOR: u32 = 1001;

/// Decode one sFlow datagram into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    // Do not decode a datagram whose agent address type is neither IPv4 nor
    // IPv6.
    if data.len() >= 8 {
        let agent_type = read_u32_be(data, 4).unwrap_or(0);
        if agent_type != ADDRESS_IPV4 && agent_type != ADDRESS_IPV6 {
            return;
        }
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::SFLOW_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::SFLOW_PROTOCOL, Range::new(base, data.len()));
    if let Err(message) = parse(&mut node, data, base) {
        context.mark_malformed(&mut node, message);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// A cursor over XDR-encoded data that reports frame-absolute value offsets.
struct Xdr<'a> {
    data: &'a [u8],
    offset: usize,
    base: usize,
}

impl<'a> Xdr<'a> {
    fn at(data: &'a [u8], base: usize) -> Self {
        Self {
            data,
            offset: 0,
            base,
        }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    fn u32(&mut self) -> Result<(u32, usize), &'static str> {
        let offset = self.offset;
        let value = read_u32_be(self.data, offset).ok_or("Truncated sFlow field")?;
        self.offset = offset.checked_add(4).ok_or("sFlow field offset overflow")?;
        Ok((
            value,
            self.base
                .checked_add(offset)
                .ok_or("sFlow offset overflow")?,
        ))
    }

    fn u64(&mut self) -> Result<(u64, usize), &'static str> {
        let offset = self.offset;
        let bytes = array::<8>(self.data, offset).ok_or("Truncated sFlow field")?;
        self.offset = offset.checked_add(8).ok_or("sFlow field offset overflow")?;
        Ok((
            u64::from_be_bytes(bytes),
            self.base
                .checked_add(offset)
                .ok_or("sFlow offset overflow")?,
        ))
    }

    /// Read a length-prefixed opaque field and consume its padding.
    fn opaque(&mut self) -> Result<(&'a [u8], usize), &'static str> {
        let (length, _header_offset) = self.u32()?;
        let length = usize::try_from(length).map_err(|_| "sFlow length overflow")?;
        let offset = self.offset;
        let end = offset.checked_add(length).ok_or("sFlow length overflow")?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or("sFlow opaque field exceeds the sample")?;
        let padded = length
            .checked_add(3)
            .ok_or("sFlow length overflow")?
            .checked_div(4)
            .and_then(|words| words.checked_mul(4))
            .ok_or("sFlow length overflow")?;
        self.offset = offset.checked_add(padded).ok_or("sFlow length overflow")?;
        if end > self.data.len() {
            return Err("sFlow opaque field exceeds the sample");
        }
        Ok((
            bytes,
            self.base
                .checked_add(offset)
                .ok_or("sFlow offset overflow")?,
        ))
    }

    /// Take `length` bytes (and XDR padding) without a length prefix.
    fn take(&mut self, length: usize) -> Result<(&'a [u8], usize), &'static str> {
        let offset = self.offset;
        let end = offset.checked_add(length).ok_or("sFlow length overflow")?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or("sFlow element exceeds the sample")?;
        let padded = length
            .checked_add(3)
            .ok_or("sFlow length overflow")?
            .checked_div(4)
            .and_then(|words| words.checked_mul(4))
            .ok_or("sFlow length overflow")?;
        self.offset = offset.checked_add(padded).ok_or("sFlow length overflow")?;
        Ok((
            bytes,
            self.base
                .checked_add(offset)
                .ok_or("sFlow offset overflow")?,
        ))
    }
}

fn add_u32(node: &mut Node, field: &'static fields::FieldDef, value: u32, offset: usize) {
    node.add_field(field, Range::new(offset, 4), Value::Uint32(value));
}

fn add_u64(node: &mut Node, field: &'static fields::FieldDef, value: u64, offset: usize) {
    node.add_field(field, Range::new(offset, 8), Value::Uint64(value));
}

fn add_bool(node: &mut Node, field: &'static fields::FieldDef, value: bool, offset: usize) {
    node.add_field(field, Range::new(offset, 4), Value::Boolean(value));
}

fn note(node: &mut Node, message: &'static str) {
    node.add_expert(ExpertInfo {
        severity: Severity::Note,
        group: Group::Undecoded,
        message: message.to_string(),
    });
}

/// Parse the datagram header and every sample.
fn parse(node: &mut Node, data: &[u8], base: usize) -> Result<(), &'static str> {
    let mut reader = Xdr::at(data, base);
    let (version, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_VERSION, version, offset);
    let (agent_type, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_AGENTTYPE, agent_type, offset);
    match agent_type {
        ADDRESS_IPV4 => {
            let (address, offset) = reader.take(4)?;
            let Some(address) = <[u8; 4]>::try_from(address).ok() else {
                return Err("Truncated sFlow agent address");
            };
            node.add_field(
                &fields::SFLOW_245_AGENT,
                Range::new(offset, 4),
                Value::Ipv4(address),
            );
        }
        ADDRESS_IPV6 => {
            let (address, offset) = reader.take(16)?;
            let Some(address) = <[u8; 16]>::try_from(address).ok() else {
                return Err("Truncated sFlow agent address");
            };
            node.add_field(
                &fields::SFLOW_245_AGENT_V6,
                Range::new(offset, 16),
                Value::Ipv6(address),
            );
        }
        _ => return Err("Unknown sFlow agent address type"),
    }
    let (sub_agent, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_SUB_AGENT_ID, sub_agent, offset);
    let (sequence, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_SEQUENCE_NUMBER, sequence, offset);
    let (uptime, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_SYSUPTIME, uptime, offset);
    let (num_samples, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_NUMSAMPLES, num_samples, offset);
    if version != VERSION_FIVE {
        return Ok(());
    }

    let mut parsed = 0_u32;
    while parsed < num_samples && !reader.is_empty() {
        parse_sample(node, &mut reader)?;
        parsed = parsed.saturating_add(1);
    }
    if parsed < num_samples {
        return Err("sFlow datagram ends before its sample count");
    }
    Ok(())
}

/// Parse one sample record: type, declared length and sample body.
fn parse_sample(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (sample_type, type_offset) = reader.u32()?;
    let enterprise = sample_type >> 12;
    let format = sample_type & 0xfff;
    node.add_field(
        &fields::SFLOW_ENTERPRISE,
        Range::new(type_offset, 4),
        Value::Uint32(0),
    );
    if enterprise != 0 {
        // The format is vendor-defined; keep the body opaque and emit no
        // format or length fields.
        let (length, _) = reader.u32()?;
        let length = usize::try_from(length).map_err(|_| "sFlow length overflow")?;
        reader.take(length)?;
        return Ok(());
    }
    node.add_field(
        &fields::SFLOW_245_SAMPLETYPE,
        Range::new(type_offset, 4),
        Value::Uint32(format),
    );
    let (length, length_offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_5_SAMPLE_LENGTH, length, length_offset);
    let length = usize::try_from(length).map_err(|_| "sFlow length overflow")?;
    let (content, content_offset) = reader.take(length)?;

    match format {
        SAMPLE_FLOW => flow_sample(node, content, content_offset, false),
        SAMPLE_COUNTERS => counters_sample(node, content, content_offset, false),
        SAMPLE_EXPANDED_FLOW => flow_sample(node, content, content_offset, true),
        SAMPLE_EXPANDED_COUNTERS => counters_sample(node, content, content_offset, true),
        _ => {
            // Keep an unknown standard sample opaque without an expert
            // entry.
            Ok(())
        }
    }
}

/// Parse a compact or expanded flow sample.
fn flow_sample(
    node: &mut Node,
    content: &[u8],
    base: usize,
    expanded: bool,
) -> Result<(), &'static str> {
    let mut reader = Xdr::at(content, base);
    let (sequence, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_FLOW_SAMPLE_SEQUENCE_NUMBER,
        sequence,
        offset,
    );
    if expanded {
        let (source_type, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_SOURCE_ID_TYPE,
            source_type,
            offset,
        );
        let (source_index, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_SOURCE_ID_INDEX,
            source_index,
            offset,
        );
    } else {
        let (source, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_SOURCE_ID_CLASS,
            source >> 24,
            offset,
        );
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_INDEX,
            source & 0x00ff_ffff,
            offset,
        );
    }
    let (rate, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_FLOW_SAMPLE_SAMPLING_RATE, rate, offset);
    let (pool, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_FLOW_SAMPLE_SAMPLE_POOL, pool, offset);
    let (drops, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_FLOW_SAMPLE_DROPPED_PACKETS,
        drops,
        offset,
    );
    if expanded {
        let (input_format, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_INPUT_INTERFACE_FORMAT,
            input_format,
            offset,
        );
        let (input_value, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_INPUT_INTERFACE_VALUE,
            input_value,
            offset,
        );
        let (output_format, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_FORMAT,
            output_format,
            offset,
        );
        let (output_value, offset) = reader.u32()?;
        let output_field = match output_format {
            0 => &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_IFINDEX,
            1 => &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_VALUE_DISCARDED,
            2 => &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_NUMBER,
            _ => &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_VALUE,
        };
        add_u32(node, output_field, output_value, offset);
    } else {
        let (input, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_INPUT_INTERFACE,
            input,
            offset,
        );
        let (output, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE,
            output & 0x7fff_ffff,
            offset,
        );
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_FORMAT,
            (output >> 30) & 3,
            offset,
        );
        add_u32(
            node,
            &fields::SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_VALUE,
            output & 0x3fff_ffff,
            offset,
        );
    }
    let (record_count, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_FLOW_SAMPLE_FLOW_RECORD,
        record_count,
        offset,
    );
    let mut parsed = 0_u32;
    while parsed < record_count && !reader.is_empty() {
        parse_flow_record(node, &mut reader)?;
        parsed = parsed.saturating_add(1);
    }
    if parsed < record_count {
        return Err("sFlow flow sample ends before its record count");
    }
    Ok(())
}

/// Parse one flow record and its body.
fn parse_flow_record(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (format, format_offset) = reader.u32()?;
    let (length, length_offset) = reader.u32()?;
    let length = usize::try_from(length).map_err(|_| "sFlow length overflow")?;
    let (content, content_offset) = reader.take(length)?;
    let enterprise = format >> 12;
    let body = format & 0xfff;
    node.add_field(
        &fields::SFLOW_ENTERPRISE,
        Range::new(format_offset, 4),
        Value::Uint32(0),
    );
    if enterprise != 0 {
        node.add_field(
            &fields::SFLOW_ENTERPRISE_LENGTH,
            Range::new(length_offset, 4),
            Value::Uint32(u32::try_from(length).unwrap_or(u32::MAX)),
        );
        node.add_field(
            &fields::SFLOW_ENTERPRISE_DATA,
            Range::new(content_offset, content.len()),
            Value::bytes(content.to_vec()),
        );
        return Ok(());
    }
    node.add_field(
        &fields::SFLOW_245_FLOW_RECORD_FORMAT,
        Range::new(format_offset, 4),
        Value::Uint32(body),
    );
    add_u32(
        node,
        &fields::SFLOW_5_FLOW_DATA_LENGTH,
        u32::try_from(length).unwrap_or(u32::MAX),
        length_offset,
    );
    let mut body_reader = Xdr::at(content, content_offset);
    match body {
        FLOW_RAW_HEADER => parse_raw_header(node, &mut body_reader),
        FLOW_ETHERNET => parse_ethernet(node, &mut body_reader),
        FLOW_IPV4 => parse_ipv4(node, &mut body_reader),
        FLOW_IPV6 => parse_ipv6(node, &mut body_reader),
        FLOW_EXTENDED_SWITCH => parse_extended_switch(node, &mut body_reader),
        FLOW_EXTENDED_ROUTER => parse_extended_router(node, &mut body_reader),
        _ => {
            node.add_field(
                &fields::SFLOW_ENTERPRISE_DATA,
                Range::new(content_offset, content.len()),
                Value::bytes(content.to_vec()),
            );
            node.add_field(
                &fields::SFLOW_UNKNOWN_RECORD_FORMAT,
                Range::new(content_offset, 0),
                Value::None,
            );
            note(node, "Unknown/invalid record type");
            Ok(())
        }
    }
}

fn parse_raw_header(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (protocol, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_HEADER_PROTOCOL, protocol, offset);
    let (length, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_HEADER_FRAME_LENGTH, length, offset);
    let (stripped, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_HEADER_PAYLOAD_STRIPPED,
        stripped,
        offset,
    );
    let (header, offset) = reader.opaque()?;
    add_u32(
        node,
        &fields::SFLOW_245_HEADER_SAMPLED_HEADER_LENGTH,
        u32::try_from(header.len()).unwrap_or(u32::MAX),
        offset.checked_sub(4).ok_or("sFlow offset overflow")?,
    );
    node.add_field(
        &fields::SFLOW_245_HEADER,
        Range::new(offset, header.len()),
        Value::bytes(header.to_vec()),
    );
    Ok(())
}

fn parse_ethernet(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (length, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_ETHERNET_LENGTH, length, offset);
    let (source, offset) = reader.take(6)?;
    add_mac(
        node,
        &fields::SFLOW_245_ETHERNET_SOURCE_MAC_ADDRESS,
        source,
        offset,
    )?;
    let (destination, offset) = reader.take(6)?;
    add_mac(
        node,
        &fields::SFLOW_245_ETHERNET_DESTINATION_MAC_ADDRESS,
        destination,
        offset,
    )?;
    let (ether_type, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_ETHERNET_PACKET_TYPE,
        ether_type,
        offset,
    );
    Ok(())
}

fn add_mac(
    node: &mut Node,
    field: &'static fields::FieldDef,
    bytes: &[u8],
    offset: usize,
) -> Result<(), &'static str> {
    let Some(address) = <[u8; 6]>::try_from(bytes).ok() else {
        return Err("Truncated sFlow MAC address");
    };
    node.add_field(field, Range::new(offset, 6), Value::Ethernet(address));
    Ok(())
}

fn parse_ipv4(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (length, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IP_LENGTH, length, offset);
    let (protocol, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_IP_PROTOCOL, protocol, offset);
    let (source, offset) = reader.take(4)?;
    add_ipv4(node, &fields::SFLOW_245_IPV4_SRC, source, offset)?;
    let (destination, offset) = reader.take(4)?;
    add_ipv4(node, &fields::SFLOW_245_IPV4_DST, destination, offset)?;
    let (source_port, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IP_SOURCE_PORT, source_port, offset);
    let (destination_port, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_IP_DESTINATION_PORT,
        destination_port,
        offset,
    );
    let (flags, offset) = reader.u32()?;
    add_tcp_flags(node, flags, offset);
    let (tos, offset) = reader.u32()?;
    add_ipv4_tos(node, tos, offset);
    Ok(())
}

fn parse_ipv6(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (length, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IP_LENGTH, length, offset);
    let (protocol, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_IP_PROTOCOL, protocol, offset);
    let (source, offset) = reader.take(16)?;
    add_ipv6(node, &fields::SFLOW_245_IPV6_SRC, source, offset)?;
    let (destination, offset) = reader.take(16)?;
    add_ipv6(node, &fields::SFLOW_245_IPV6_DST, destination, offset)?;
    let (source_port, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IP_SOURCE_PORT, source_port, offset);
    let (destination_port, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_IP_DESTINATION_PORT,
        destination_port,
        offset,
    );
    let (flags, offset) = reader.u32()?;
    add_tcp_flags(node, flags, offset);
    let (priority, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IPV6_PRIORITY, priority, offset);
    Ok(())
}

fn add_ipv4(
    node: &mut Node,
    field: &'static fields::FieldDef,
    bytes: &[u8],
    offset: usize,
) -> Result<(), &'static str> {
    let Some(address) = <[u8; 4]>::try_from(bytes).ok() else {
        return Err("Truncated sFlow IPv4 address");
    };
    node.add_field(field, Range::new(offset, 4), Value::Ipv4(address));
    Ok(())
}

fn add_ipv6(
    node: &mut Node,
    field: &'static fields::FieldDef,
    bytes: &[u8],
    offset: usize,
) -> Result<(), &'static str> {
    let Some(address) = <[u8; 16]>::try_from(bytes).ok() else {
        return Err("Truncated sFlow IPv6 address");
    };
    node.add_field(field, Range::new(offset, 16), Value::Ipv6(address));
    Ok(())
}

fn add_tcp_flags(node: &mut Node, flags: u32, offset: usize) {
    for (mask, field) in [
        (0x80, &fields::SFLOW_245_IP_TCP_FLAG_CWR),
        (0x40, &fields::SFLOW_245_IP_TCP_FLAG_ECE),
        (0x20, &fields::SFLOW_245_IP_TCP_FLAG_URG),
        (0x10, &fields::SFLOW_245_IP_TCP_FLAG_ACK),
        (0x08, &fields::SFLOW_245_IP_TCP_FLAG_PSH),
        (0x04, &fields::SFLOW_245_IP_TCP_FLAG_RST),
        (0x02, &fields::SFLOW_245_IP_TCP_FLAG_SYN),
        (0x01, &fields::SFLOW_245_IP_TCP_FLAG_FIN),
    ] {
        add_bool(node, field, flags & mask != 0, offset);
    }
}

fn add_ipv4_tos(node: &mut Node, tos: u32, offset: usize) {
    add_u32(
        node,
        &fields::SFLOW_245_IPV4_PRECEDENCE_TYPE,
        (tos & 0xe0) >> 5,
        offset,
    );
    for (mask, field) in [
        (0x10, &fields::SFLOW_245_IPV4_DELAY),
        (0x08, &fields::SFLOW_245_IPV4_THROUGHPUT),
        (0x04, &fields::SFLOW_245_IPV4_RELIABILITY),
        (0x02, &fields::SFLOW_245_IPV4_COST),
    ] {
        add_bool(node, field, tos & mask != 0, offset);
    }
}

fn parse_extended_switch(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (source_vlan, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_VLAN_IN, source_vlan, offset);
    let (source_priority, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_PRI_IN, source_priority, offset);
    let (destination_vlan, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_VLAN_OUT, destination_vlan, offset);
    let (destination_priority, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_PRI_OUT,
        destination_priority,
        offset,
    );
    Ok(())
}

fn parse_extended_router(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (address_type, offset) = reader.u32()?;
    match address_type {
        ADDRESS_IPV4 => {
            let (address, offset) = reader.take(4)?;
            add_ipv4(node, &fields::SFLOW_245_NEXTHOP, address, offset)?;
        }
        ADDRESS_IPV6 => {
            let (address, offset) = reader.take(16)?;
            add_ipv6(node, &fields::SFLOW_245_NEXTHOP_V6, address, offset)?;
        }
        _ => {
            let _ = offset;
            node.add_field(
                &fields::SFLOW_INVALID_ADDRESS_TYPE,
                Range::new(reader.base, 0),
                Value::None,
            );
            return Err("Unknown sFlow address type");
        }
    }
    let (source_mask, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_NEXTHOP_SRC_MASK,
        source_mask,
        offset,
    );
    let (destination_mask, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_NEXTHOP_DST_MASK,
        destination_mask,
        offset,
    );
    Ok(())
}

/// Parse a compact or expanded counters sample.
fn counters_sample(
    node: &mut Node,
    content: &[u8],
    base: usize,
    expanded: bool,
) -> Result<(), &'static str> {
    let mut reader = Xdr::at(content, base);
    let (sequence, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_COUNTERS_SAMPLE_SEQUENCE_NUMBER,
        sequence,
        offset,
    );
    if expanded {
        let (source_type, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_COUNTERS_SAMPLE_SOURCE_ID_TYPE,
            source_type,
            offset,
        );
        let (source_index, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_COUNTERS_SAMPLE_SOURCE_ID_INDEX,
            source_index,
            offset,
        );
    } else {
        let (source, offset) = reader.u32()?;
        add_u32(
            node,
            &fields::SFLOW_COUNTERS_SAMPLE_SOURCE_ID_TYPE,
            source >> 24,
            offset,
        );
        add_u32(
            node,
            &fields::SFLOW_COUNTERS_SAMPLE_SOURCE_ID_INDEX,
            source & 0x00ff_ffff,
            offset,
        );
    }
    let (record_count, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_COUNTERS_SAMPLE_COUNTERS_RECORDS,
        record_count,
        offset,
    );
    let mut parsed = 0_u32;
    while parsed < record_count && !reader.is_empty() {
        parse_counter_record(node, &mut reader)?;
        parsed = parsed.saturating_add(1);
    }
    if parsed < record_count {
        return Err("sFlow counters sample ends before its record count");
    }
    Ok(())
}

fn parse_counter_record(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (format, format_offset) = reader.u32()?;
    let (length, length_offset) = reader.u32()?;
    let length = usize::try_from(length).map_err(|_| "sFlow length overflow")?;
    let (content, content_offset) = reader.take(length)?;
    let enterprise = format >> 12;
    let body = format & 0xfff;
    node.add_field(
        &fields::SFLOW_ENTERPRISE,
        Range::new(format_offset, 4),
        Value::Uint32(0),
    );
    if enterprise != 0 {
        node.add_field(
            &fields::SFLOW_ENTERPRISE_LENGTH,
            Range::new(length_offset, 4),
            Value::Uint32(u32::try_from(length).unwrap_or(u32::MAX)),
        );
        node.add_field(
            &fields::SFLOW_ENTERPRISE_DATA,
            Range::new(content_offset, content.len()),
            Value::bytes(content.to_vec()),
        );
        return Ok(());
    }
    node.add_field(
        &fields::SFLOW_245_COUNTERS_RECORD_FORMAT,
        Range::new(format_offset, 4),
        Value::Uint32(body),
    );
    add_u32(
        node,
        &fields::SFLOW_5_FLOW_DATA_LENGTH,
        u32::try_from(length).unwrap_or(u32::MAX),
        length_offset,
    );
    let mut body_reader = Xdr::at(content, content_offset);
    match body {
        COUNTER_GENERIC => parse_generic_counters(node, &mut body_reader),
        COUNTER_ETHERNET => parse_ethernet_counters(node, &mut body_reader),
        COUNTER_TOKEN_RING => parse_token_ring_counters(node, &mut body_reader),
        COUNTER_VG => parse_vg_counters(node, &mut body_reader),
        COUNTER_VLAN => parse_vlan_counters(node, &mut body_reader),
        COUNTER_PROCESSOR => parse_processor(node, &mut body_reader),
        _ => {
            node.add_field(
                &fields::SFLOW_ENTERPRISE_DATA,
                Range::new(content_offset, content.len()),
                Value::bytes(content.to_vec()),
            );
            node.add_field(
                &fields::SFLOW_UNKNOWN_RECORD_FORMAT,
                Range::new(content_offset, 0),
                Value::None,
            );
            note(node, "Unknown/invalid record type");
            Ok(())
        }
    }
}

fn parse_generic_counters(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (value, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IFINDEX, value, offset);
    let (value, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IFTYPE, value, offset);
    let (value, offset) = reader.u64()?;
    add_u64(node, &fields::SFLOW_245_IFSPEED, value, offset);
    let (value, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_IFDIRECTION, value, offset);
    let (status, offset) = reader.u32()?;
    add_bool(
        node,
        &fields::SFLOW_245_IFADMIN_STATUS,
        status & 1 != 0,
        offset,
    );
    add_bool(
        node,
        &fields::SFLOW_245_IFOPER_STATUS,
        status & 2 != 0,
        offset,
    );
    let (value, offset) = reader.u64()?;
    add_u64(node, &fields::SFLOW_245_IFINOCT, value, offset);
    for field in [
        &fields::SFLOW_245_IFINPKT,
        &fields::SFLOW_245_IFINMCAST,
        &fields::SFLOW_245_IFINBCAST,
        &fields::SFLOW_245_IFINDISC,
        &fields::SFLOW_245_IFINERR,
        &fields::SFLOW_245_IFINUNK,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    let (value, offset) = reader.u64()?;
    add_u64(node, &fields::SFLOW_245_IFOUTOCT, value, offset);
    for field in [
        &fields::SFLOW_245_IFOUTPKT,
        &fields::SFLOW_245_IFOUTMCAST,
        &fields::SFLOW_245_IFOUTBCAST,
        &fields::SFLOW_245_IFOUTDISC,
        &fields::SFLOW_245_IFOUTERR,
        &fields::SFLOW_245_IFPROMISC,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    Ok(())
}

fn parse_ethernet_counters(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    for field in [
        &fields::SFLOW_245_DOT3STATSALIGNMENTERRORS,
        &fields::SFLOW_245_DOT3STATSFCSERRORS,
        &fields::SFLOW_245_DOT3STATSSINGLECOLLISIONFRAMES,
        &fields::SFLOW_245_DOT3STATSMULTIPLECOLLISIONFRAMES,
        &fields::SFLOW_245_DOT3STATSSQETESTERRORS,
        &fields::SFLOW_245_DOT3STATSDEFERREDTRANSMISSIONS,
        &fields::SFLOW_245_DOT3STATSLATECOLLISIONS,
        &fields::SFLOW_245_DOT3STATSEXCESSIVECOLLISIONS,
        &fields::SFLOW_245_DOT3STATSINTERNALMACTRANSMITERRORS,
        &fields::SFLOW_245_DOT3STATSCARRIERSENSEERRORS,
        &fields::SFLOW_245_DOT3STATSFRAMETOOLONGS,
        &fields::SFLOW_245_DOT3STATSINTERNALMACRECEIVEERRORS,
        &fields::SFLOW_245_DOT3STATSSYMBOLERRORS,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    Ok(())
}

fn parse_token_ring_counters(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    for field in [
        &fields::SFLOW_245_DOT5STATSLINEERRORS,
        &fields::SFLOW_245_DOT5STATSBURSTERRORS,
        &fields::SFLOW_245_DOT5STATSACERRORS,
        &fields::SFLOW_245_DOT5STATSABORTTRANSERRORS,
        &fields::SFLOW_245_DOT5STATSINTERNALERRORS,
        &fields::SFLOW_245_DOT5STATSLOSTFRAMEERRORS,
        &fields::SFLOW_245_DOT5STATSRECEIVECONGESTIONS,
        &fields::SFLOW_245_DOT5STATSFRAMECOPIEDERRORS,
        &fields::SFLOW_245_DOT5STATSTOKENERRORS,
        &fields::SFLOW_245_DOT5STATSSOFTERRORS,
        &fields::SFLOW_245_DOT5STATSHARDERRORS,
        &fields::SFLOW_245_DOT5STATSSIGNALLOSS,
        &fields::SFLOW_245_DOT5STATSTRANSMITBEACONS,
        &fields::SFLOW_245_DOT5STATSRECOVERIES,
        &fields::SFLOW_245_DOT5STATSLOBEWIRES,
        &fields::SFLOW_245_DOT5STATSREMOVES,
        &fields::SFLOW_245_DOT5STATSSINGLES,
        &fields::SFLOW_245_DOT5STATSFREQERRORS,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    Ok(())
}

fn parse_vg_counters(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (value, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_DOT12INHIGHPRIORITYFRAMES,
        value,
        offset,
    );
    let (value, offset) = reader.u64()?;
    add_u64(
        node,
        &fields::SFLOW_245_DOT12INHIGHPRIORITYOCTETS,
        value,
        offset,
    );
    let (value, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_DOT12INNORMPRIORITYFRAMES,
        value,
        offset,
    );
    let (value, offset) = reader.u64()?;
    add_u64(
        node,
        &fields::SFLOW_245_DOT12INNORMPRIORITYOCTETS,
        value,
        offset,
    );
    for field in [
        &fields::SFLOW_245_DOT12INIPMERRORS,
        &fields::SFLOW_245_DOT12INOVERSIZEFRAMEERRORS,
        &fields::SFLOW_245_DOT12INDATAERRORS,
        &fields::SFLOW_245_DOT12INNULLADDRESSEDFRAMES,
        &fields::SFLOW_245_DOT12OUTHIGHPRIORITYFRAMES,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    let (value, offset) = reader.u64()?;
    add_u64(
        node,
        &fields::SFLOW_245_DOT12OUTHIGHPRIORITYOCTETS,
        value,
        offset,
    );
    let (value, offset) = reader.u32()?;
    add_u32(
        node,
        &fields::SFLOW_245_DOT12TRANSITIONINTOTRAININGS,
        value,
        offset,
    );
    let (value, offset) = reader.u64()?;
    add_u64(
        node,
        &fields::SFLOW_245_DOT12HCINHIGHPRIORITYOCTETS,
        value,
        offset,
    );
    let (value, offset) = reader.u64()?;
    add_u64(
        node,
        &fields::SFLOW_245_DOT12HCINNORMPRIORITYOCTETS,
        value,
        offset,
    );
    let (value, offset) = reader.u64()?;
    add_u64(
        node,
        &fields::SFLOW_245_DOT12HCOUTHIGHPRIORITYOCTETS,
        value,
        offset,
    );
    Ok(())
}

fn parse_vlan_counters(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    let (value, offset) = reader.u32()?;
    add_u32(node, &fields::SFLOW_245_VLAN_ID, value, offset);
    let (value, offset) = reader.u64()?;
    add_u64(node, &fields::SFLOW_245_OCTETS, value, offset);
    for field in [
        &fields::SFLOW_245_UCASTPKTS,
        &fields::SFLOW_245_MULTICASTPKTS,
        &fields::SFLOW_245_BROADCASTPKTS,
        &fields::SFLOW_245_DISCARDS,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    Ok(())
}

fn parse_processor(node: &mut Node, reader: &mut Xdr<'_>) -> Result<(), &'static str> {
    for field in [
        &fields::SFLOW_5_CPU_5S,
        &fields::SFLOW_5_CPU_1M,
        &fields::SFLOW_5_CPU_5M,
    ] {
        let (value, offset) = reader.u32()?;
        add_u32(node, field, value, offset);
    }
    let (value, offset) = reader.u64()?;
    add_u64(node, &fields::SFLOW_5_TOTAL_MEMORY, value, offset);
    let (value, offset) = reader.u64()?;
    add_u64(node, &fields::SFLOW_5_FREE_MEMORY, value, offset);
    Ok(())
}
