//! Syslog messages over UDP.
//!
//! The RFC 5424 header, structured data and message follow RFC 5424 sections
//! 6.1-6.3; the older header follows RFC 3164 section 4.1.3. The decoder
//! accepts both on the default UDP port 514, and presents the whole payload
//! as the message when neither header parses. Syslog over TCP (RFC 6587
//! framing) has no default TCP port entry; this decoder starts at the UDP
//! payload.
//!
//! Strings stop at the first NUL, like C strings.
//! A message that begins with `<` but has no PRI, or an RFC 3164 tag that
//! runs to the end of the datagram, stops the decoder; the PRI fields decoded
//! before that point stay in the tree.

use std::fmt::Write as _;

use crate::capture::Timestamp;
use crate::decode::DecodeContext;
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const MAX_PRIORITY_DIGITS: usize = 5;
const MAX_RFC5424_VERSION_DIGITS: usize = 2;

/// Decode one syslog datagram into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::SYSLOG_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::SYSLOG_PROTOCOL, Range::new(base, data.len()));
    let parsed = parse(&mut node, data, base);
    context.columns.info = summary_info(data);
    if !parsed {
        context.mark_malformed(&mut node, "Malformed Syslog message");
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn parse(node: &mut Node, data: &[u8], base: usize) -> bool {
    let Some(priority) = parse_priority(data) else {
        // Without a PRI the whole payload is the message (the non-conformant
        // fallback), unless it starts with an incomplete PRI.
        if data.first() == Some(&b'<') {
            return false;
        }
        add_message(node, data, base, 0, true);
        return true;
    };
    let (priority_value, priority_end) = priority;
    if data.len() <= priority_end {
        return false;
    }
    node.add_field(
        &fields::SYSLOG_FACILITY,
        Range::new(base, priority_end),
        Value::Uint16(u16::try_from((priority_value & 0x3f8) >> 3).unwrap_or(u16::MAX)),
    );
    node.add_field(
        &fields::SYSLOG_LEVEL,
        Range::new(base, priority_end),
        Value::Uint16(u16::try_from(priority_value & 0x7).unwrap_or(u16::MAX)),
    );

    let rest = data.get(priority_end..).unwrap_or_default();
    if parse_rfc5424(node, rest, base.saturating_add(priority_end)) {
        return true;
    }
    parse_rfc3164(node, rest, base.saturating_add(priority_end))
}

/// Parse `<PRI>` and return the numeric priority and the offset just past it.
fn parse_priority(data: &[u8]) -> Option<(u32, usize)> {
    if data.first() != Some(&b'<') {
        return None;
    }
    let mut value = 0_u32;
    for (index, byte) in data.iter().enumerate().skip(1) {
        let digits = index.saturating_sub(1);
        if *byte == b'>' {
            if digits == 0 {
                return None;
            }
            return Some((value, index.checked_add(1)?));
        }
        if !byte.is_ascii_digit() || digits >= MAX_PRIORITY_DIGITS {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    None
}

/// Parse an RFC 5424 header, structured data and message.
///
/// Returns false when the payload is not RFC 5424, in which case the caller
/// tries the RFC 3164 header. A structural failure after the version is
/// presented as a non-conformant trailing message.
fn parse_rfc5424(node: &mut Node, data: &[u8], base: usize) -> bool {
    let mut offset = 0;
    let version_start = offset;
    while data.get(offset).is_some_and(|byte| byte.is_ascii_digit())
        && offset - version_start < MAX_RFC5424_VERSION_DIGITS
    {
        offset += 1;
    }
    if offset == version_start || data.get(offset) != Some(&b' ') {
        return false;
    }
    let version_end = offset;
    offset += 1;

    let Some((timestamp, timestamp_offset)) = token(data, &mut offset) else {
        return false;
    };
    offset = timestamp_offset.saturating_add(timestamp.len());

    // A missing token makes the last parsed token the non-conformant message;
    // that token is not repeated as its own field.
    let Some((hostname, hostname_offset)) = next_token(data, &mut offset) else {
        add_version(node, data, base, version_start, version_end);
        add_message(node, timestamp, base, timestamp_offset, true);
        return true;
    };
    let timestamp_range = (timestamp_offset, timestamp.len());
    let Some((appname, appname_offset)) = next_token(data, &mut offset) else {
        add_version(node, data, base, version_start, version_end);
        add_timestamp(node, timestamp, base, timestamp_range);
        add_message(node, hostname, base, hostname_offset, true);
        return true;
    };
    let Some((procid, procid_offset)) = next_token(data, &mut offset) else {
        add_header_prefix(
            node,
            data,
            base,
            version_start,
            version_end,
            timestamp,
            timestamp_range,
        );
        add_name(
            node,
            &fields::SYSLOG_HOSTNAME,
            hostname,
            base,
            hostname_offset,
        );
        add_message(node, appname, base, appname_offset, true);
        return true;
    };
    let Some((msgid, msgid_offset)) = next_token(data, &mut offset) else {
        add_header_prefix(
            node,
            data,
            base,
            version_start,
            version_end,
            timestamp,
            timestamp_range,
        );
        add_name(
            node,
            &fields::SYSLOG_HOSTNAME,
            hostname,
            base,
            hostname_offset,
        );
        add_name(node, &fields::SYSLOG_APPNAME, appname, base, appname_offset);
        add_message(node, procid, base, procid_offset, true);
        return true;
    };

    // Structured data follows one space after MSGID.
    if data.get(offset) != Some(&b' ') {
        add_header_prefix(
            node,
            data,
            base,
            version_start,
            version_end,
            timestamp,
            timestamp_range,
        );
        add_name(
            node,
            &fields::SYSLOG_HOSTNAME,
            hostname,
            base,
            hostname_offset,
        );
        add_name(node, &fields::SYSLOG_APPNAME, appname, base, appname_offset);
        add_name(node, &fields::SYSLOG_PROCID, procid, base, procid_offset);
        add_message(node, msgid, base, msgid_offset, true);
        return true;
    }
    let sd_start = offset + 1;
    let Some(sd_length) = structured_data_length(data, sd_start) else {
        add_header_prefix(
            node,
            data,
            base,
            version_start,
            version_end,
            timestamp,
            timestamp_range,
        );
        add_name(
            node,
            &fields::SYSLOG_HOSTNAME,
            hostname,
            base,
            hostname_offset,
        );
        add_name(node, &fields::SYSLOG_APPNAME, appname, base, appname_offset);
        add_name(node, &fields::SYSLOG_PROCID, procid, base, procid_offset);
        add_name(node, &fields::SYSLOG_MSGID, msgid, base, msgid_offset);
        let rest = data.get(sd_start..).unwrap_or_default();
        add_message(node, rest, base, sd_start, true);
        return true;
    };

    add_header_prefix(
        node,
        data,
        base,
        version_start,
        version_end,
        timestamp,
        timestamp_range,
    );
    add_name(
        node,
        &fields::SYSLOG_HOSTNAME,
        hostname,
        base,
        hostname_offset,
    );
    add_name(node, &fields::SYSLOG_APPNAME, appname, base, appname_offset);
    add_name(node, &fields::SYSLOG_PROCID, procid, base, procid_offset);
    add_name(node, &fields::SYSLOG_MSGID, msgid, base, msgid_offset);

    let sd_end = sd_start.saturating_add(sd_length);
    if data.get(sd_end) == Some(&b' ') {
        let sd_bytes = data.get(sd_start..sd_end).unwrap_or_default();
        node.add_field(
            &fields::SYSLOG_SD,
            Range::new(base + sd_start, sd_bytes.len()),
            Value::None,
        );
        if sd_bytes != b"-".as_slice() {
            add_sd_elements(node, sd_bytes, base + sd_start);
        }
        let message_start = sd_end + 1;
        let message = data.get(message_start..).unwrap_or_default();
        add_message(node, message, base, message_start, false);
    } else if data.get(sd_end).is_none() {
        // RFC 5424 allows the structured data to end the message.
        let sd_bytes = data.get(sd_start..sd_end).unwrap_or_default();
        node.add_field(
            &fields::SYSLOG_SD,
            Range::new(base + sd_start, sd_bytes.len()),
            Value::None,
        );
        if sd_bytes != b"-".as_slice() {
            add_sd_elements(node, sd_bytes, base + sd_start);
        }
    } else {
        // Without the mandatory space, present the whole tail as
        // non-conformant data and do not decode the elements.
        let rest = data.get(sd_start..).unwrap_or_default();
        add_message(node, rest, base, sd_start, true);
    }
    true
}

fn add_version(
    node: &mut Node,
    data: &[u8],
    base: usize,
    version_start: usize,
    version_end: usize,
) {
    let version = data.get(version_start..version_end).unwrap_or_default();
    node.add_field(
        &fields::SYSLOG_VERSION,
        Range::new(base + version_start, version.len()),
        Value::String(text(version)),
    );
}

fn add_timestamp(node: &mut Node, timestamp: &[u8], base: usize, range: (usize, usize)) {
    node.add_field(
        &fields::SYSLOG_TIMESTAMP,
        Range::new(base + range.0, range.1),
        Value::AbsoluteTime(parse_timestamp(timestamp)),
    );
}

fn add_header_prefix(
    node: &mut Node,
    data: &[u8],
    base: usize,
    version_start: usize,
    version_end: usize,
    timestamp: &[u8],
    timestamp_range: (usize, usize),
) {
    add_version(node, data, base, version_start, version_end);
    add_timestamp(node, timestamp, base, timestamp_range);
}

/// Parse the RFC 3164 timestamp, hostname and tag after a PRI.
fn parse_rfc3164(node: &mut Node, data: &[u8], base: usize) -> bool {
    let Some(timestamp_end) = rfc3164_timestamp_length(data) else {
        add_message(node, data, base, 0, true);
        return true;
    };
    let timestamp = data.get(..timestamp_end).unwrap_or_default();
    let Some(hostname_start) = timestamp_end.checked_add(1) else {
        return false;
    };
    if data.get(timestamp_end) != Some(&b' ') || hostname_start >= data.len() {
        node.add_field(
            &fields::SYSLOG_TIMESTAMP_RFC3164,
            Range::new(base, timestamp.len()),
            Value::String(text(timestamp)),
        );
        add_message(node, timestamp, base, 0, true);
        return true;
    }
    let Some(hostname) = token(data, &mut { hostname_start }) else {
        return false;
    };
    let (hostname_bytes, hostname_offset) = hostname;
    let mut offset = hostname_offset.saturating_add(hostname_bytes.len());
    node.add_field(
        &fields::SYSLOG_TIMESTAMP_RFC3164,
        Range::new(base, timestamp.len()),
        Value::String(text(timestamp)),
    );
    add_name(
        node,
        &fields::SYSLOG_HOSTNAME,
        hostname_bytes,
        base,
        hostname_offset,
    );

    if data.get(offset) != Some(&b' ') {
        add_message(node, hostname_bytes, base, hostname_offset, true);
        return true;
    }
    offset += 1;
    let tag_start = offset;
    while data
        .get(offset)
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        offset += 1;
    }
    // Reject a tag that is empty or reaches the end of the datagram.
    if offset == tag_start || offset >= data.len() {
        return false;
    }
    let tag = data.get(tag_start..offset).unwrap_or_default();
    node.add_field(
        &fields::SYSLOG_PROCID,
        Range::new(base + tag_start, tag.len()),
        Value::String(text(tag)),
    );
    let message_start = offset + 1;
    let message = data.get(message_start..).unwrap_or_default();
    add_message(node, message, base, message_start, false);
    true
}

/// Length of an `Mmm dd hh:mm:ss` timestamp at the start of `data`.
fn rfc3164_timestamp_length(data: &[u8]) -> Option<usize> {
    const MONTHS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let month = data.get(..3)?;
    if !MONTHS.contains(&month) {
        return None;
    }
    let bytes = data.get(..15)?;
    let day = bytes.get(4..6)?;
    match day {
        [b' ', digit] if digit.is_ascii_digit() => {}
        [tens, ones] if tens.is_ascii_digit() && ones.is_ascii_digit() => {}
        _ => return None,
    }
    for (index, expected) in [(3, b' '), (6, b' '), (9, b':'), (12, b':')] {
        if bytes.get(index) != Some(&expected) {
            return None;
        }
    }
    for index in [7, 8, 10, 11, 13, 14] {
        if !bytes.get(index).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    Some(15)
}

/// The token at `offset`, leaving the offset on the separator.
fn token<'a>(data: &'a [u8], offset: &mut usize) -> Option<(&'a [u8], usize)> {
    let start = *offset;
    if start >= data.len() {
        return None;
    }
    let end = data
        .get(start..)?
        .iter()
        .position(|byte| *byte == b' ')
        .map_or(data.len(), |index| start.saturating_add(index));
    *offset = end;
    data.get(start..end).map(|token| (token, start))
}

/// Read one space-separated token and consume its separator.
fn next_token<'a>(data: &'a [u8], offset: &mut usize) -> Option<(&'a [u8], usize)> {
    if data.get(*offset) != Some(&b' ') {
        return None;
    }
    *offset = offset.checked_add(1)?;
    let token = token(data, offset)?;
    Some(token)
}

fn add_name(
    node: &mut Node,
    field: &'static fields::FieldDef,
    bytes: &[u8],
    base: usize,
    offset: usize,
) {
    node.add_field(
        field,
        Range::new(base + offset, bytes.len()),
        Value::String(text(bytes)),
    );
}

fn add_message(node: &mut Node, bytes: &[u8], base: usize, offset: usize, nonconformant: bool) {
    node.add_field(
        &fields::SYSLOG_MSG,
        Range::new(base + offset, bytes.len()),
        Value::String(text(bytes)),
    );
    if nonconformant {
        node.add_field(
            &fields::SYSLOG_MSG_NONCONFORMANT,
            Range::new(base + offset, 0),
            Value::None,
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Protocol,
            message: "Message conforms to neither RFC 5424 nor RFC 3164; trailing data appended"
                .to_string(),
        });
    }
}

/// One structured-data element and its parameters.
struct SdElement<'a> {
    range: Range,
    name: &'a [u8],
    name_range: Range,
    parameters: Vec<SdParameter<'a>>,
}

struct SdParameter<'a> {
    range: Range,
    name: &'a [u8],
    name_range: Range,
    value_range: Range,
    unescaped: Vec<u8>,
}

/// Length of the structured-data field starting at `offset`.
fn structured_data_length(data: &[u8], offset: usize) -> Option<usize> {
    if data.get(offset) == Some(&b'-') {
        return Some(1);
    }
    let mut length = 0_usize;
    let mut elements = 0_usize;
    while data.get(offset.checked_add(length)?) == Some(&b'[') {
        let element_length = element_length(data, offset.checked_add(length)?)?;
        length = length.checked_add(element_length)?;
        elements += 1;
    }
    (elements > 0).then_some(length)
}

/// Length of one `[...]` element.
fn element_length(data: &[u8], offset: usize) -> Option<usize> {
    let mut index = offset.checked_add(1)?;
    // Element name: SD-NAME, no space, '=' or ']'.
    let name_start = index;
    while let Some(byte) = data.get(index) {
        if matches!(*byte, b' ' | b'=' | b'"' | b']') {
            break;
        }
        index += 1;
    }
    if index == name_start {
        return None;
    }
    loop {
        match data.get(index)? {
            b']' => {
                index += 1;
                return index.checked_sub(offset);
            }
            b' ' => {
                index += 1;
                let parameter_start = index;
                while let Some(byte) = data.get(index) {
                    if matches!(*byte, b'=' | b' ' | b'"' | b']') {
                        break;
                    }
                    index += 1;
                }
                if index == parameter_start || data.get(index) != Some(&b'=') {
                    return None;
                }
                index += 1;
                if data.get(index) != Some(&b'"') {
                    return None;
                }
                index += 1;
                loop {
                    match data.get(index)? {
                        b'"' => {
                            index += 1;
                            break;
                        }
                        b'\\' => {
                            index = index.checked_add(2)?;
                        }
                        _ => index += 1,
                    }
                }
                match data.get(index)? {
                    b' ' | b']' => {}
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
}

/// Add the structured-data elements and parameters.
fn add_sd_elements(node: &mut Node, data: &[u8], base: usize) {
    let mut offset = 0_usize;
    while data.get(offset) == Some(&b'[') {
        let Some((element, length)) = parse_element(data, offset) else {
            return;
        };
        node.add_field(
            &fields::SYSLOG_SD_ELEMENT,
            Range::new(base + element.range.offset, element.range.length),
            Value::None,
        );
        node.add_field(
            &fields::SYSLOG_SD_ELEMENT_NAME,
            Range::new(base + element.name_range.offset, element.name_range.length),
            Value::String(text(element.name)),
        );
        for parameter in &element.parameters {
            node.add_field(
                &fields::SYSLOG_SD_PARAM,
                Range::new(base + parameter.range.offset, parameter.range.length),
                Value::None,
            );
            node.add_field(
                &fields::SYSLOG_SD_PARAM_NAME,
                Range::new(
                    base + parameter.name_range.offset,
                    parameter.name_range.length,
                ),
                Value::String(text(parameter.name)),
            );
            node.add_field(
                &fields::SYSLOG_SD_PARAM_VALUE,
                Range::new(
                    base + parameter.value_range.offset,
                    parameter.value_range.length,
                ),
                Value::String(String::from_utf8_lossy(&parameter.unescaped).into_owned()),
            );
        }
        offset = offset.saturating_add(length);
    }
}

fn parse_element(data: &[u8], offset: usize) -> Option<(SdElement<'_>, usize)> {
    let length = element_length(data, offset)?;
    let end = offset.checked_add(length)?;
    let mut index = offset.checked_add(1)?;
    let name_start = index;
    while let Some(byte) = data.get(index) {
        if matches!(*byte, b' ' | b'=' | b'"' | b']') {
            break;
        }
        index += 1;
    }
    let name = data.get(name_start..index)?;
    let mut parameters = Vec::new();
    while data.get(index) == Some(&b' ') {
        index += 1;
        let parameter_start = index;
        while let Some(byte) = data.get(index) {
            if matches!(*byte, b'=' | b' ' | b'"' | b']') {
                break;
            }
            index += 1;
        }
        let parameter_name = data.get(parameter_start..index)?;
        index += 1;
        index += 1;
        let value_start = index;
        let mut unescaped = Vec::new();
        loop {
            match data.get(index)? {
                b'"' => break,
                b'\\' => {
                    let escaped = data.get(index.checked_add(1)?)?;
                    unescaped.push(*escaped);
                    index = index.checked_add(2)?;
                }
                byte => {
                    unescaped.push(*byte);
                    index += 1;
                }
            }
        }
        let value = data.get(value_start..index)?;
        index += 1;
        parameters.push(SdParameter {
            range: Range::new(parameter_start, index.saturating_sub(parameter_start)),
            name: parameter_name,
            name_range: Range::new(parameter_start, parameter_name.len()),
            value_range: Range::new(value_start, value.len()),
            unescaped,
        });
    }
    Some((
        SdElement {
            range: Range::new(offset, length),
            name,
            name_range: Range::new(name_start, name.len()),
            parameters,
        },
        end.saturating_sub(offset),
    ))
}

/// Decode an RFC 3339 timestamp; an invalid value maps to the epoch.
fn parse_timestamp(text: &[u8]) -> Timestamp {
    parse_rfc3339(text).unwrap_or(Timestamp {
        seconds: 0,
        nanos: 0,
    })
}

fn parse_rfc3339(text: &[u8]) -> Option<Timestamp> {
    if text == b"-" {
        return Some(Timestamp {
            seconds: 0,
            nanos: 0,
        });
    }
    let year = digits(text, 0, 4)?;
    if text.get(4) != Some(&b'-') {
        return None;
    }
    let month = digits(text, 5, 2)?;
    if text.get(7) != Some(&b'-') {
        return None;
    }
    let day = digits(text, 8, 2)?;
    if !matches!(text.get(10), Some(b'T' | b't')) {
        return None;
    }
    let hour = digits(text, 11, 2)?;
    if text.get(13) != Some(&b':') {
        return None;
    }
    let minute = digits(text, 14, 2)?;
    if text.get(16) != Some(&b':') {
        return None;
    }
    let second = digits(text, 17, 2)?;
    let mut offset = 19_usize;
    let mut nanos = 0_u32;
    if text.get(offset) == Some(&b'.') {
        offset += 1;
        let fraction_start = offset;
        while text.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        let fraction = text.get(fraction_start..offset)?;
        if fraction.is_empty() {
            return None;
        }
        for index in 0..9 {
            let digit = fraction.get(index).copied().unwrap_or(b'0');
            nanos = nanos
                .checked_mul(10)?
                .checked_add(u32::from(digit - b'0'))?;
        }
    }
    let offset_seconds = match text.get(offset) {
        Some(b'Z' | b'z') => {
            offset += 1;
            0_i64
        }
        Some(sign @ (b'+' | b'-')) => {
            let hours = digits(text, offset + 1, 2)?;
            if text.get(offset + 3) != Some(&b':') {
                return None;
            }
            let minutes = digits(text, offset + 4, 2)?;
            offset += 6;
            let magnitude = i64::from(hours)
                .checked_mul(3_600)?
                .checked_add(i64::from(minutes).checked_mul(60)?)?;
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };
    if offset != text.len() {
        return None;
    }
    if !(1..=12).contains(&month)
        || day == 0
        || day > crate::capture::days_in_month(i64::from(year), month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = crate::capture::days_from_civil(i64::from(year), month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?
        .checked_sub(offset_seconds)?;
    Some(Timestamp { seconds, nanos })
}

fn digits(text: &[u8], offset: usize, length: usize) -> Option<u32> {
    let end = offset.checked_add(length)?;
    let bytes = text.get(offset..end)?;
    let mut value = 0_u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

/// Decode a syslog byte string for display: ASCII bytes stay, every other
/// byte becomes U+FFFD, and the text stops at the first NUL like a C string.
fn text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let mut text = String::with_capacity(end);
    for byte in bytes.get(..end).unwrap_or_default() {
        if byte.is_ascii() {
            text.push(char::from(*byte));
        } else {
            // Replace every non-ASCII byte in a field value with U+FFFD
            // rather than decoding a UTF-8 sequence.
            text.push('\u{fffd}');
        }
    }
    text
}

/// The one-line summary for a syslog datagram.
///
/// The text after the PRI is shown verbatim; a PRI that is incomplete or has
/// no message after it leaves the column empty so the malformed marker is the
/// whole entry.
fn summary_info(data: &[u8]) -> Option<String> {
    if data.first() != Some(&b'<') {
        return Some(escape_summary(data));
    }
    let (priority, end) = parse_priority(data)?;
    let rest = data.get(end..)?;
    if rest.is_empty() {
        return None;
    }
    let facility = (priority & 0x3ff) >> 3;
    let level = priority & 0x7;
    let mut text = String::new();
    text.push_str(facility_name(facility));
    text.push('.');
    text.push_str(level_name(level));
    text.push_str(": ");
    text.push_str(&escape_summary(rest));
    Some(text)
}

const FACILITIES: [&str; 24] = [
    "KERN", "USER", "MAIL", "DAEMON", "AUTH", "SYSLOG", "LPR", "NEWS", "UUCP", "CRON", "AUTHPRIV",
    "FTP", "NTP", "LOGAUDIT", "LOGALERT", "CRON", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4",
    "LOCAL5", "LOCAL6", "LOCAL7",
];

const LEVELS: [&str; 8] = [
    "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG",
];

fn facility_name(facility: u32) -> &'static str {
    usize::try_from(facility)
        .ok()
        .and_then(|index| FACILITIES.get(index))
        .copied()
        .unwrap_or("UNKNOWN")
}

fn level_name(level: u32) -> &'static str {
    usize::try_from(level)
        .ok()
        .and_then(|index| LEVELS.get(index))
        .copied()
        .unwrap_or("UNKNOWN")
}

/// Escape control characters for the summary column as C-style escapes.
fn escape_summary(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\u{7}' => escaped.push_str("\\a"),
            '\u{8}' => escaped.push_str("\\b"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\u{b}' => escaped.push_str("\\v"),
            '\u{c}' => escaped.push_str("\\f"),
            '\r' => escaped.push_str("\\r"),
            control if control.is_control() => {
                let _ = write!(escaped, "\\{:03o}", u32::from(control));
            }
            other => escaped.push(other),
        }
    }
    escaped
}
