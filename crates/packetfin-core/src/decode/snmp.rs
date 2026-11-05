//! Simple Network Management Protocol version 1 and 2c.
//!
//! The message layout and PDU tags follow RFC 1157 section 4 for version 1
//! and RFC 3416 section 3 for version 2c; the values are X.690 BER encoded.
//! Only the definite-length form is accepted: an indefinite length, a long
//! form longer than four octets, a length past the enclosing element or a
//! value larger than eight octets stops the message. Nesting is bounded by
//! [`MAX_BER_DEPTH`] and every loop consumes at least one element, so a
//! hostile datagram cannot recurse or allocate without bound.
//!
//! Version 3 and the transport (TCP) framing are out of scope; a datagram
//! whose version is not 0 or 1 keeps the version field and stops.

use std::net::IpAddr;

use crate::decode::{DecodeContext, NetworkContext};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

/// Deepest constructed-element nesting the BER reader follows.
///
/// SNMP's own structures nest four levels; the limit is generous enough to
/// accept them and small enough that a crafted datagram cannot exhaust the
/// stack.
const MAX_BER_DEPTH: usize = 16;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_IP_ADDRESS: u8 = 0x40;
const TAG_COUNTER32: u8 = 0x41;
const TAG_GAUGE32: u8 = 0x42;
const TAG_TIMETICKS: u8 = 0x43;
const TAG_OPAQUE: u8 = 0x44;
const TAG_NSAP: u8 = 0x45;
const TAG_COUNTER64: u8 = 0x46;
const TAG_UNSIGNED32: u8 = 0x47;
const TAG_NO_SUCH_OBJECT: u8 = 0x80;
const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
const TAG_END_OF_MIB_VIEW: u8 = 0x82;

/// PDU tags, their `snmp.data` value and the field that marks the PDU.
const PDUS: &[(u8, u32, &fields::FieldDef)] = &[
    (0xa0, 0, &fields::SNMP_GET_REQUEST_ELEMENT),
    (0xa1, 1, &fields::SNMP_GET_NEXT_REQUEST_ELEMENT),
    (0xa2, 2, &fields::SNMP_GET_RESPONSE_ELEMENT),
    (0xa3, 3, &fields::SNMP_SET_REQUEST_ELEMENT),
    (0xa4, 4, &fields::SNMP_TRAP_ELEMENT),
    (0xa5, 5, &fields::SNMP_GETBULKREQUEST_ELEMENT),
    (0xa6, 6, &fields::SNMP_INFORMREQUEST_ELEMENT),
    (0xa7, 7, &fields::SNMP_SNMPV2_TRAP_ELEMENT),
    (0xa8, 8, &fields::SNMP_REPORT_ELEMENT),
];

/// One BER element with its position inside the decoder's input slice.
struct Element<'a> {
    tag: u8,
    /// Value octets, excluding the tag and length.
    content: &'a [u8],
    /// Offset of the value from the start of the decoder's input.
    content_offset: usize,
    /// Length of the whole element, tag and length included.
    total_length: usize,
}

/// A cursor over one BER element or over the elements of a constructed one.
struct BerReader<'a> {
    data: &'a [u8],
    offset: usize,
    /// Offset of `data[0]` from the start of the decoder's input slice.
    base_offset: usize,
}

impl<'a> BerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            base_offset: 0,
        }
    }

    fn at(data: &'a [u8], base_offset: usize) -> Self {
        Self {
            data,
            offset: 0,
            base_offset,
        }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Read one definite-length element.
    fn read(&mut self) -> Option<Element<'a>> {
        let tag = *self.data.get(self.offset)?;
        // A high-tag-number form has no use in SNMP and would need an
        // unbounded tag walk.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let first = *self.data.get(self.offset.checked_add(1)?)?;
        let (length, header_length) = if first < 0x80 {
            (usize::from(first), 2_usize)
        } else {
            let count = usize::from(first & 0x7f);
            // Indefinite length (0x80) is rejected, and the length must fit
            // this target's usize. RFC 3417 section 8(1) and X.690 8.1.3.5
            // NOTE 2 permit more length octets than the minimum, so leading
            // zero octets are not rejected.
            if count == 0 || count > std::mem::size_of::<usize>() {
                return None;
            }
            let mut length = 0_usize;
            for index in 0..count {
                let byte = *self
                    .data
                    .get(self.offset.checked_add(2)?.checked_add(index)?)?;
                length = length.checked_mul(256)?.checked_add(usize::from(byte))?;
            }
            (length, 2 + count)
        };
        let content_offset = self.offset.checked_add(header_length)?;
        let end = content_offset.checked_add(length)?;
        let content = self.data.get(content_offset..end)?;
        self.offset = end;
        Some(Element {
            tag,
            content,
            content_offset: self.base_offset.checked_add(content_offset)?,
            total_length: header_length.checked_add(length)?,
        })
    }

    fn read_expecting(&mut self, tag: u8) -> Option<Element<'a>> {
        let element = self.read()?;
        (element.tag == tag).then_some(element)
    }
}

/// Decode one SNMP message into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::SNMP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::SNMP_PROTOCOL, Range::new(base, data.len()));
    if !parse_message(&mut node, data, base) {
        context.mark_malformed(&mut node, "Malformed SNMP message");
    }
    record_state(context, &mut node);

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Record the request/response transaction and add the fields known in this
/// pass.
fn record_state(context: &mut DecodeContext<'_>, node: &mut Node) {
    if context.observe_only {
        return;
    }
    let Some(request_id) = node.fields.iter().find_map(|field| {
        (field.def.abbrev == "snmp.request_id").then(|| match field.value {
            Value::Int8(value) => Some(i64::from(value)),
            Value::Int16(value) => Some(i64::from(value)),
            Value::Int32(value) => Some(i64::from(value)),
            Value::Int64(value) => Some(value),
            Value::Uint32(value) => Some(i64::from(value)),
            Value::Uint64(value) => i64::try_from(value).ok(),
            _ => None,
        })?
    }) else {
        return;
    };
    let Some(pdu) = node.fields.iter().find_map(|field| {
        (field.def.abbrev == "snmp.data").then_some(match field.value {
            Value::Uint32(value) => Some(value),
            _ => None,
        })?
    }) else {
        return;
    };
    let response = pdu == 2;
    if !response && !matches!(pdu, 0 | 1 | 3 | 5 | 6) {
        return;
    }
    let Some((source, destination)) = network_addresses(context.network.as_ref()) else {
        return;
    };
    let Some((source_port, destination_port)) = context.udp_ports else {
        return;
    };
    let key = crate::state::SnmpTransactionKey::new(
        source,
        source_port,
        destination,
        destination_port,
        request_id,
        response,
    );
    let frame = context.frame.number;
    let file = context.frame.file_number;
    let time = context.frame.timestamp;
    let range = Range::new(0, 0);
    if response {
        let Some(transaction) = context.state.snmp_take(key) else {
            return;
        };
        let elapsed = match (transaction.pending_time_ns, time) {
            (request, Some(response)) if request != 0 => {
                let response_ns = response
                    .seconds
                    .saturating_mul(1_000_000_000)
                    .saturating_add(i64::from(response.nanos));
                Some(response_ns.saturating_sub(request))
            }
            _ => None,
        };
        if context.pass == crate::state::PassMode::First {
            let annotations = context.state.annotations_mut();
            annotations.link_response_in(u64::from(transaction.pending_file), file);
            if let Some(elapsed) = elapsed {
                annotations.link_response(file, u64::from(transaction.pending_file), elapsed);
            }
        }
        if context.pass != crate::state::PassMode::Second {
            node.add_field(
                &fields::SNMP_RESPONSE_TO,
                range,
                Value::Uint32(transaction.pending_frame),
            );
            if let Some(elapsed) = elapsed {
                node.add_field(&fields::SNMP_TIME, range, Value::RelativeTime(elapsed));
            }
        }
        return;
    }
    if context.pass == crate::state::PassMode::Second {
        return;
    }
    if context.state.snmp_take(key).is_none() {
        let pending_time_ns = time.map_or(0, |timestamp| {
            timestamp
                .seconds
                .saturating_mul(1_000_000_000)
                .saturating_add(i64::from(timestamp.nanos))
        });
        context.state.snmp_put(
            key,
            crate::state::SnmpTransaction {
                pending_frame: u32::try_from(frame).unwrap_or(u32::MAX),
                pending_file: u32::try_from(file).unwrap_or(u32::MAX),
                pending_time_ns,
            },
        );
    }
}

fn network_addresses(network: Option<&NetworkContext>) -> Option<(IpAddr, IpAddr)> {
    match network? {
        NetworkContext::Ipv4 {
            source,
            destination,
            ..
        } => Some((
            IpAddr::V4(std::net::Ipv4Addr::from(*source)),
            IpAddr::V4(std::net::Ipv4Addr::from(*destination)),
        )),
        NetworkContext::Ipv6 {
            source,
            destination,
            ..
        } => Some((
            IpAddr::V6(std::net::Ipv6Addr::from(*source)),
            IpAddr::V6(std::net::Ipv6Addr::from(*destination)),
        )),
    }
}

/// Parse the message envelope and one PDU. `false` means a hard error stopped
/// decoding; fields added before it stay in the node.
fn parse_message(node: &mut Node, data: &[u8], base: usize) -> bool {
    let mut reader = BerReader::new(data);
    let Some(message) = reader.read_expecting(TAG_SEQUENCE) else {
        return false;
    };
    let mut body = BerReader::at(message.content, message.content_offset);
    let Some(version_element) = body.read_expecting(TAG_INTEGER) else {
        return false;
    };
    let Some(version) = parse_signed(version_element.content) else {
        return false;
    };
    add_integer(node, &fields::SNMP_VERSION, &version_element, base, version);
    if version != 0 && version != 1 {
        // Version 3 has a different envelope and is out of scope.
        return true;
    }

    let Some(community) = body.read_expecting(TAG_OCTET_STRING) else {
        // Keep a header-only SNMP message without marking it malformed when
        // the community or the PDU is absent.
        return true;
    };
    node.add_field(
        &fields::SNMP_COMMUNITY,
        Range::new(base + community.content_offset, community.content.len()),
        Value::String(text(community.content)),
    );

    let Some(pdu_offset) = body.offset.checked_add(body.base_offset) else {
        return false;
    };
    let Some(pdu) = body.read() else {
        return true;
    };
    let Some((_, data_value, element_field)) =
        PDUS.iter().find(|(tag, _, _)| *tag == pdu.tag).copied()
    else {
        return false;
    };
    node.add_field(
        &fields::SNMP_DATA,
        Range::new(base + pdu_offset, pdu.total_length),
        Value::Uint32(data_value),
    );
    node.add_field(
        element_field,
        Range::new(base + pdu.content_offset, pdu.content.len()),
        Value::None,
    );

    parse_pdu(node, pdu, base, version == 0, 0)
}

/// Parse the PDU body. A version-1 trap has the RFC 1157 layout; every other
/// PDU has request-id, status/count, index/repetitions and a varbind list.
fn parse_pdu(
    node: &mut Node,
    pdu: Element<'_>,
    base: usize,
    version_one: bool,
    depth: usize,
) -> bool {
    if depth >= MAX_BER_DEPTH {
        return false;
    }
    let body = BerReader::at(pdu.content, pdu.content_offset);
    if pdu.tag == 0xa4 {
        if !version_one {
            return false;
        }
        return parse_trap(node, body, base, depth.saturating_add(1));
    }
    let mut body = body;
    let Some(request_id) = body.read_expecting(TAG_INTEGER) else {
        return false;
    };
    let Some(request_value) = parse_signed(request_id.content) else {
        return false;
    };
    add_integer(
        node,
        &fields::SNMP_REQUEST_ID,
        &request_id,
        base,
        request_value,
    );

    let Some(second) = body.read_expecting(TAG_INTEGER) else {
        return false;
    };
    let Some(second_value) = parse_signed(second.content) else {
        return false;
    };
    let second_field = if pdu.tag == 0xa5 {
        &fields::SNMP_NON_REPEATERS
    } else {
        &fields::SNMP_ERROR_STATUS
    };
    add_integer(node, second_field, &second, base, second_value);

    let Some(third) = body.read_expecting(TAG_INTEGER) else {
        return false;
    };
    let Some(third_value) = parse_signed(third.content) else {
        return false;
    };
    let third_field = if pdu.tag == 0xa5 {
        &fields::SNMP_MAX_REPETITIONS
    } else {
        &fields::SNMP_ERROR_INDEX
    };
    add_integer(node, third_field, &third, base, third_value);
    parse_varbinds(node, body, base, depth.saturating_add(1))
}

/// Parse a version-1 trap PDU.
fn parse_trap(node: &mut Node, mut body: BerReader<'_>, base: usize, depth: usize) -> bool {
    if depth >= MAX_BER_DEPTH {
        return false;
    }
    let Some(enterprise) = body.read_expecting(TAG_OID) else {
        return false;
    };
    add_oid(node, &fields::SNMP_ENTERPRISE, &enterprise, base);
    let Some(agent) = body.read_expecting(TAG_IP_ADDRESS) else {
        return false;
    };
    if agent.content.len() != 4 {
        return false;
    }
    let Some(address) = agent.content.try_into().ok() else {
        return false;
    };
    node.add_field(
        &fields::SNMP_AGENT_ADDR,
        Range::new(base + agent.content_offset, 4),
        Value::Ipv4(address),
    );
    let Some(generic) = body.read_expecting(TAG_INTEGER) else {
        return false;
    };
    let Some(generic_value) = parse_signed(generic.content) else {
        return false;
    };
    add_integer(
        node,
        &fields::SNMP_GENERIC_TRAP,
        &generic,
        base,
        generic_value,
    );
    let Some(specific) = body.read_expecting(TAG_INTEGER) else {
        return false;
    };
    let Some(specific_value) = parse_signed(specific.content) else {
        return false;
    };
    add_integer(
        node,
        &fields::SNMP_SPECIFIC_TRAP,
        &specific,
        base,
        specific_value,
    );
    let Some(stamp) = body.read_expecting(TAG_TIMETICKS) else {
        return false;
    };
    let Some(stamp_value) = parse_unsigned(stamp.content) else {
        return false;
    };
    let stored = u32::try_from(stamp_value).map_or(Value::Uint64(stamp_value), Value::Uint32);
    node.add_field(
        &fields::SNMP_TIME_STAMP,
        Range::new(base + stamp.content_offset, stamp.content.len()),
        stored,
    );
    parse_varbinds(node, body, base, depth.saturating_add(1))
}

/// Parse the varbind list that ends a PDU.
fn parse_varbinds(node: &mut Node, mut body: BerReader<'_>, base: usize, depth: usize) -> bool {
    if depth >= MAX_BER_DEPTH {
        return false;
    }
    let Some(list) = body.read_expecting(TAG_SEQUENCE) else {
        return false;
    };
    let mut scan = BerReader::at(list.content, list.content_offset);
    let mut count = 0_u32;
    while !scan.is_empty() {
        let Some(varbind) = scan.read_expecting(TAG_SEQUENCE) else {
            return false;
        };
        let _ = varbind;
        count = count.saturating_add(1);
    }
    node.add_field(
        &fields::SNMP_VARIABLE_BINDINGS,
        Range::new(base + list.content_offset, list.content.len()),
        Value::Uint32(count),
    );

    let mut bindings = BerReader::at(list.content, list.content_offset);
    while !bindings.is_empty() {
        let Some(varbind) = bindings.read_expecting(TAG_SEQUENCE) else {
            return false;
        };
        if !parse_varbind(node, varbind, base, depth.saturating_add(1)) {
            return false;
        }
    }
    true
}

/// Parse one `SEQUENCE { name OBJECT IDENTIFIER, value ANY }`.
fn parse_varbind(node: &mut Node, varbind: Element<'_>, base: usize, depth: usize) -> bool {
    if depth >= MAX_BER_DEPTH {
        return false;
    }
    let mut body = BerReader::at(varbind.content, varbind.content_offset);
    let Some(name) = body.read_expecting(TAG_OID) else {
        return false;
    };
    add_oid(node, &fields::SNMP_NAME, &name, base);
    let Some(value) = body.read() else {
        return false;
    };
    parse_value(node, &value, base)
}

/// Add the typed value of a varbind.
fn parse_value(node: &mut Node, value: &Element<'_>, base: usize) -> bool {
    let range = Range::new(base + value.content_offset, value.content.len());
    match value.tag {
        TAG_INTEGER => {
            if value.content.is_empty() {
                add_note(node, "Integral value is zero-length");
                return true;
            }
            match parse_signed(value.content) {
                Some(number) => {
                    node.add_field(&fields::SNMP_VALUE_INT, range, Value::Int64(number));
                    true
                }
                None => {
                    node.add_field(
                        &fields::SNMP_VAR_BIND_STR,
                        range,
                        Value::String(text(value.content)),
                    );
                    add_note(node, "Integral value too large or too small");
                    true
                }
            }
        }
        TAG_OCTET_STRING => {
            node.add_field(
                &fields::SNMP_VALUE_OCTETS,
                range,
                Value::bytes(value.content.to_vec()),
            );
            node.add_field(
                &fields::SNMP_VAR_BIND_STR,
                range,
                Value::String(text(value.content)),
            );
            true
        }
        TAG_OID => {
            let Some(ids) = parse_oid(value.content) else {
                return false;
            };
            node.add_field(&fields::SNMP_VALUE_OID, range, Value::Oid(ids));
            true
        }
        TAG_NULL => {
            node.add_field(&fields::SNMP_VALUE_NULL, range, Value::None);
            true
        }
        TAG_IP_ADDRESS => {
            add_address(node, value, base);
            true
        }
        TAG_UNSIGNED32 => match parse_signed(value.content) {
            Some(number) => {
                node.add_field(&fields::SNMP_VALUE_U32, range, Value::Int64(number));
                true
            }
            None => false,
        },
        TAG_GAUGE32 => match parse_signed(value.content) {
            Some(number) => {
                node.add_field(&fields::SNMP_VALUE_G32, range, Value::Int64(number));
                true
            }
            None => false,
        },
        TAG_COUNTER32 | TAG_COUNTER64 => match parse_unsigned(value.content) {
            Some(number) => {
                node.add_field(&fields::SNMP_VALUE_COUNTER, range, Value::Uint64(number));
                true
            }
            None => false,
        },
        TAG_TIMETICKS => match parse_unsigned(value.content) {
            Some(number) => {
                node.add_field(&fields::SNMP_VALUE_TIMETICKS, range, Value::Uint64(number));
                true
            }
            None => false,
        },
        TAG_NSAP => match parse_unsigned(value.content) {
            Some(number) => {
                node.add_field(&fields::SNMP_VALUE_NSAP, range, Value::Uint64(number));
                true
            }
            None => false,
        },
        TAG_OPAQUE => {
            node.add_field(
                &fields::SNMP_VALUE_OPAQUE,
                range,
                Value::bytes(value.content.to_vec()),
            );
            true
        }
        TAG_NO_SUCH_OBJECT => {
            node.add_field(&fields::SNMP_NOSUCHOBJECT, range, Value::None);
            add_note(node, "noSuchObject");
            true
        }
        TAG_NO_SUCH_INSTANCE => {
            node.add_field(&fields::SNMP_NOSUCHINSTANCE, range, Value::None);
            add_note(node, "noSuchInstance");
            true
        }
        TAG_END_OF_MIB_VIEW => {
            node.add_field(&fields::SNMP_ENDOFMIBVIEW, range, Value::None);
            add_note(node, "endOfMibView");
            true
        }
        0x83 => {
            node.add_field(
                &fields::SNMP_VARBIND_WRONG_TAG,
                Range::new(0, 0),
                Value::None,
            );
            node.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Malformed,
                message: "Wrong tag for SNMP VarBind error value".to_string(),
            });
            true
        }
        _ => {
            node.add_field(
                &fields::SNMP_VALUE_UNK,
                range,
                Value::bytes(value.content.to_vec()),
            );
            true
        }
    }
}

/// Add an `IpAddress` value in its 4-byte, 16-byte or opaque form.
fn add_address(node: &mut Node, value: &Element<'_>, base: usize) {
    let range = Range::new(base + value.content_offset, value.content.len());
    match value.content.len() {
        4 => {
            if let Ok(address) = <[u8; 4]>::try_from(value.content) {
                node.add_field(&fields::SNMP_VALUE_IPV4, range, Value::Ipv4(address));
            }
        }
        16 => {
            if let Ok(address) = <[u8; 16]>::try_from(value.content) {
                node.add_field(&fields::SNMP_VALUE_IPV6, range, Value::Ipv6(address));
            }
        }
        0 => {
            node.add_field(&fields::SNMP_VALUE_ADDR, range, Value::Missing);
        }
        _ => {
            node.add_field(
                &fields::SNMP_VALUE_ADDR,
                range,
                Value::bytes(value.content.to_vec()),
            );
        }
    }
}

fn add_integer(
    node: &mut Node,
    field: &'static fields::FieldDef,
    element: &Element<'_>,
    base: usize,
    value: i64,
) {
    let stored = match field.field_type {
        fields::FieldType::Int32 => i32::try_from(value).map_or(Value::Int64(value), Value::Int32),
        fields::FieldType::Uint32 => {
            u32::try_from(value).map_or(Value::Int64(value), Value::Uint32)
        }
        _ => Value::Int64(value),
    };
    node.add_field(
        field,
        Range::new(base + element.content_offset, element.content.len()),
        stored,
    );
}

fn add_oid(node: &mut Node, field: &'static fields::FieldDef, element: &Element<'_>, base: usize) {
    if let Some(ids) = parse_oid(element.content) {
        node.add_field(
            field,
            Range::new(base + element.content_offset, element.content.len()),
            Value::Oid(ids),
        );
    }
}

fn add_note(node: &mut Node, message: &'static str) {
    node.add_expert(ExpertInfo {
        severity: Severity::Note,
        group: Group::Undecoded,
        message: message.to_string(),
    });
}

/// Decode a two's-complement integer of at most eight octets.
fn parse_signed(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let mut value: i64 = if content.first().is_some_and(|first| first & 0x80 != 0) {
        -1
    } else {
        0
    };
    for byte in content {
        value = (value << 8) | i64::from(*byte);
    }
    Some(value)
}

/// Decode an unsigned integer of at most eight octets.
fn parse_unsigned(content: &[u8]) -> Option<u64> {
    if content.len() > 8 {
        return None;
    }
    let mut value = 0_u64;
    for byte in content {
        value = value.checked_shl(8)?.checked_add(u64::from(*byte))?;
    }
    Some(value)
}

/// Decode an object identifier into its sub-identifiers.
fn parse_oid(content: &[u8]) -> Option<Vec<u32>> {
    let mut ids = Vec::new();
    let mut value: u64 = 0;
    let mut in_progress = false;
    let mut first = true;
    for byte in content {
        value = value.checked_shl(7)?.checked_add(u64::from(byte & 0x7f))?;
        in_progress = byte & 0x80 != 0;
        if in_progress {
            continue;
        }
        if first {
            let (root, second) = if value < 40 {
                (0, value)
            } else if value < 80 {
                (1, value - 40)
            } else {
                (2, value - 80)
            };
            ids.push(u32::try_from(root).ok()?);
            ids.push(u32::try_from(second).ok()?);
            first = false;
        } else {
            ids.push(u32::try_from(value).ok()?);
        }
        value = 0;
    }
    if in_progress {
        return (!ids.is_empty()).then_some(ids);
    }
    Some(ids)
}

/// Decode an SNMP byte string for display: UTF-8 with invalid sequences
/// replaced, stopping at the first NUL like a C string.
fn text(content: &[u8]) -> String {
    let end = content
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(content.len());
    String::from_utf8_lossy(content.get(..end).unwrap_or_default()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_indefinite_and_overlong_lengths() {
        let mut reader = BerReader::new(&[0x30, 0x80, 0x00, 0x00]);
        assert!(reader.read().is_none());

        let mut reader = BerReader::new(&[0x30, 0x85, 0x01, 0, 0, 0, 0]);
        assert!(reader.read().is_none());

        let mut reader = BerReader::new(&[0x30, 0x81, 0x7f]);
        assert!(reader.read().is_none());
    }

    #[test]
    fn rejects_a_length_past_the_input() {
        let mut reader = BerReader::new(&[0x30, 0x05, 0x02, 0x01]);
        assert!(reader.read().is_none());
    }

    #[test]
    fn accepts_a_minimal_long_form() {
        let mut data = vec![0x30, 0x81, 0x80];
        data.resize(3 + 0x80, 0);
        let mut reader = BerReader::new(&data);
        let element = reader.read();
        assert!(element.is_some());
        assert_eq!(
            element.as_ref().map(|element| element.content.len()),
            Some(0x80)
        );
    }

    #[test]
    fn parses_signed_and_unsigned_integers() {
        assert_eq!(parse_signed(&[0x00]), Some(0));
        assert_eq!(parse_signed(&[0xff]), Some(-1));
        assert_eq!(parse_signed(&[0xd6]), Some(-42));
        assert_eq!(parse_signed(&[0x00, 0x80]), Some(128));
        assert_eq!(parse_signed(&[0xff; 9]), None);
        assert_eq!(parse_unsigned(&[0xff]), Some(255));
        assert_eq!(parse_unsigned(&[0xff; 8]), Some(u64::MAX));
    }

    #[test]
    fn parses_object_identifiers() {
        assert_eq!(parse_oid(&[0x2b, 0x06, 0x01]), Some(vec![1, 3, 6, 1]));
        assert_eq!(parse_oid(&[0x06, 0x01]), Some(vec![0, 6, 1]));
        assert_eq!(parse_oid(&[0x00]), Some(vec![0, 0]));
        assert_eq!(parse_oid(&[0x2b, 0x81]), Some(vec![1, 3]));
        assert_eq!(parse_oid(&[0x81]), None);
    }

    #[test]
    fn truncates_strings_at_nul_and_replaces_invalid_utf8() {
        assert_eq!(text(b"abc\0def"), "abc");
        assert_eq!(text(b"a\xffb"), "a\u{fffd}b");
    }
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, u8::try_from(body.len()).unwrap_or(0)];
        out.extend_from_slice(body);
        out
    }

    fn concat(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &concat(items))
    }

    fn integer(value: u8) -> Vec<u8> {
        tlv(0x02, &[value])
    }

    fn name_tlv() -> Vec<u8> {
        tlv(0x06, &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    }

    fn get_message(name: &[u8], value: &[u8]) -> Vec<u8> {
        let varbind = sequence(&[name.to_vec(), value.to_vec()]);
        let list = sequence(&[varbind]);
        let pdu = tlv(0xa0, &concat(&[integer(1), integer(0), integer(0), list]));
        sequence(&[integer(0), tlv(0x04, b"public"), pdu])
    }

    fn parse(data: &[u8]) -> (bool, Node) {
        let mut node = Node::new(&fields::SNMP_PROTOCOL, Range::new(0, data.len()));
        let parsed = parse_message(&mut node, data, 0);
        (parsed, node)
    }

    #[test]
    fn accepts_non_minimal_long_form_lengths() {
        let message = get_message(&name_tlv(), &tlv(0x05, &[]));
        let content = message.get(2..).unwrap_or_default();
        let mut data = vec![0x30, 0x81, u8::try_from(content.len()).unwrap_or(0)];
        data.extend_from_slice(content);
        let (parsed, node) = parse(&data);
        assert!(parsed);
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "snmp.version")
        );
    }

    #[test]
    fn accepts_a_non_minimal_length_with_more_than_four_octets() {
        let message = get_message(&name_tlv(), &tlv(0x05, &[]));
        let content = message.get(2..).unwrap_or_default();
        let mut data = vec![
            0x30,
            0x85,
            0,
            0,
            0,
            0,
            u8::try_from(content.len()).unwrap_or(0),
        ];
        data.extend_from_slice(content);
        let (parsed, node) = parse(&data);
        assert!(parsed);
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "snmp.version")
        );
    }

    #[test]
    fn rejects_indefinite_and_oversized_lengths() {
        for data in [
            vec![0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00],
            vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
            vec![0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
        ] {
            assert!(!parse(&data).0);
        }
    }

    #[test]
    fn rejects_a_deeply_nested_envelope() {
        let mut nested = integer(0);
        for _ in 0..40 {
            nested = tlv(0x30, &nested);
        }
        assert!(!parse(&nested).0);
    }

    #[test]
    fn keeps_partial_fields_and_ignores_trailing_bytes() {
        let mut message = get_message(&name_tlv(), &tlv(0x05, &[]));
        message.extend_from_slice(&[0xde, 0xad]);
        let (parsed, node) = parse(&message);
        assert!(parsed);
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "snmp.version")
        );

        let header_only = sequence(&[integer(0), tlv(0x04, b"public")]);
        let (parsed, node) = parse(&header_only);
        assert!(parsed);
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "snmp.version")
        );
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "snmp.community")
        );
    }

    #[test]
    fn zero_length_integer_adds_only_the_length_note() {
        let message = get_message(&name_tlv(), &tlv(0x02, &[]));
        let (parsed, node) = parse(&message);
        assert!(parsed);
        assert!(
            !node
                .fields
                .iter()
                .any(|field| matches!(field.def.abbrev, "snmp.value.int" | "snmp.var-bind_str"))
        );
        assert!(
            node.experts
                .iter()
                .any(|expert| expert.message == "Integral value is zero-length"
                    && expert.severity == Severity::Note)
        );
    }

    #[test]
    fn wrong_error_value_tag_adds_the_expert_and_marker() {
        let message = get_message(&name_tlv(), &tlv(0x83, &[]));
        let (parsed, node) = parse(&message);
        assert!(parsed);
        assert!(
            node.fields
                .iter()
                .any(|field| field.def.abbrev == "snmp.varbind.wrong_tag")
        );
        assert!(node.experts.iter().any(|expert| expert.message
            == "Wrong tag for SNMP VarBind error value"
            && expert.severity == Severity::Warning
            && expert.group == Group::Malformed));
    }

    #[test]
    fn partial_oid_keeps_the_decoded_prefix() {
        let message = get_message(&tlv(0x06, &[0x2b, 0x80]), &tlv(0x05, &[]));
        let (parsed, node) = parse(&message);
        assert!(parsed);
        assert!(node.fields.iter().any(|field| {
            field.def.abbrev == "snmp.name" && field.value == Value::Oid(vec![1, 3])
        }));
    }
}
