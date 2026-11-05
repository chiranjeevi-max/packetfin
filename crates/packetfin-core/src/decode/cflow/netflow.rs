//! NetFlow version 9 and IPFIX (version 10).
//!
//! Header layouts follow RFC 3954 section 5.1 (v9, 20 octets) and RFC 7011
//! section 3.1 (IPFIX, 16 octets). Set IDs have the same meaning in both
//! versions: 0 v9 template, 1 v9 options template, 2 IPFIX template,
//! 3 IPFIX options template, 4-255 reserved, 256 and above data. v9's Count
//! field bounds how many sets the exporter declared, so extra bytes beyond
//! that count stay undecoded; IPFIX has no such guard.
//!
//! Templates are cached per exporter address, source port, transport and
//! observation domain (see `state::template`). A template carried by the
//! same datagram is used directly, so template and data may share one
//! datagram. Field counts and widths are checked against the set length
//! before any allocation.

use std::collections::HashMap;

use super::ie::{self, Element, Scope, TimeScale};
use crate::capture::{Timestamp, absolute_time_text, relative_time_text};
use crate::decode::DecodeContext;
use crate::decode::bytes::{read_ipv4, read_ipv6, read_u16_be, read_u32_be};
use crate::fields;
use crate::state::{
    ExporterAddress, MAX_TEMPLATE_FIELDS, SequenceKey, SequenceState, TemplateEntry, TemplateField,
    TemplateKey, TemplateKind,
};
use crate::tree::{ExpertInfo, Field, Group, Node, Range, Severity, Value};

const V9_HEADER_LENGTH: usize = 20;
const IPFIX_HEADER_LENGTH: usize = 16;

const SET_TEMPLATE_V9: u16 = 0;
const SET_OPTIONS_V9: u16 = 1;
const SET_TEMPLATE_IPFIX: u16 = 2;
const SET_OPTIONS_IPFIX: u16 = 3;
const FIRST_DATA_SET: u16 = 256;

/// Most data records decoded from one set before the rest stay opaque.
///
/// A 65535-octet set with one-octet records carries 65531 records; decoding
/// all of them would multiply a small datagram into tens of megabytes of
/// tree nodes on hostile input. Committed fixtures stay far below this cap.
const MAX_RECORDS_PER_SET: usize = 4096;

/// Most fields decoded from one datagram across all its data records.
const MAX_FIELDS_PER_MESSAGE: usize = 65_536;

/// Header fields shared by the set parser and the sequence analysis.
struct Message {
    version: u8,
    exporter: ExporterAddress,
    port: u16,
    transport: u8,
    domain: u32,
    frame: u64,
    sequence: u32,
}

/// One flow message payload and its frame offset.
#[derive(Clone, Copy)]
struct Datagram<'a> {
    data: &'a [u8],
    /// Frame offset of `data`'s first byte.
    base: usize,
}

/// One set's wire span and identity within a flow message.
#[derive(Clone, Copy)]
struct SetContext<'a> {
    datagram: Datagram<'a>,
    message: &'a Message,
    /// One-based position among the message's sets.
    index: usize,
    /// Offset of the set header inside the datagram.
    start: usize,
    /// Offset one past the set's last byte inside the datagram.
    end: usize,
}

impl SetContext<'_> {
    /// Declared set length in octets.
    fn set_length(self) -> usize {
        self.end - self.start
    }

    /// Offset of the set's first record octet inside the datagram.
    fn data_start(self) -> usize {
        self.start + 4
    }

    /// Octets between the set header and the set end.
    fn data_length(self) -> usize {
        self.set_length() - 4
    }
}

/// One rejected count field and the marker nested under it.
struct RejectedCount<'a> {
    /// Field definition for the count value.
    def: &'static crate::fields::FieldDef,
    /// Hidden marker that carries the rejection.
    marker: &'static crate::fields::FieldDef,
    value: u16,
    label: &'a str,
    message: String,
    group: Group,
}

/// Mutable bookkeeping for one datagram.
#[derive(Default)]
struct ParseState {
    malformed: bool,
    /// A set with ID 256 or above was seen, even if its template was
    /// missing or rejected.
    saw_data_set: bool,
    /// A template record was complete and accepted by the field cap.
    accepted_template: bool,
    decoded_fields: usize,
    /// Data records the templates describe, before the decode caps.
    sequence_records: usize,
}

/// Parse a complete v9 header and its sets.
pub(super) fn parse_v9(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
) -> bool {
    let Some(count) = read_u16_be(data, 2) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_COUNT,
        Range::new(base + 2, 2),
        Value::Uint16(count),
    );
    if data.len() < V9_HEADER_LENGTH {
        return false;
    }
    let (Some(uptime), Some(seconds), Some(sequence), Some(source_id)) = (
        read_u32_be(data, 4),
        read_u32_be(data, 8),
        read_u32_be(data, 12),
        read_u32_be(data, 16),
    ) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_SYSUPTIME,
        Range::new(base + 4, 4),
        Value::RelativeTime(i64::from(uptime).saturating_mul(1_000_000)),
    );
    add_header_timestamp(
        node,
        base + 8,
        Timestamp {
            seconds: i64::from(seconds),
            nanos: 0,
        },
        &fields::CFLOW_UNIX_SECS,
        Value::Uint32(seconds),
    );
    add_header_sequence(node, base + 12, sequence);
    node.add_field(
        &fields::CFLOW_SOURCE_ID,
        Range::new(base + 16, 4),
        Value::Uint32(source_id),
    );
    let message = Message {
        version: 9,
        exporter: exporter(context),
        port: context
            .transport
            .as_ref()
            .map_or(0, |transport| transport.source_port),
        transport: context
            .transport
            .as_ref()
            .map_or(17, |transport| transport.protocol),
        domain: source_id,
        frame: context.frame.number,
        sequence,
    };
    if count == 0 {
        if data.len() > V9_HEADER_LENGTH && !context.quoted {
            add_message_marker(
                node,
                base + V9_HEADER_LENGTH,
                data.len() - V9_HEADER_LENGTH,
                "FlowSets impossible - PDU Count is 0",
                &fields::CFLOW_FLOWSETS_IMPOSSIBLE,
            );
        }
        return true;
    }
    let mut state = ParseState::default();
    parse_sets(
        context,
        node,
        Datagram { data, base },
        V9_HEADER_LENGTH,
        &message,
        Some(count),
        &mut state,
    );
    finish_sequence(context, node, base, &message, &state);
    !state.malformed
}

/// Parse a complete IPFIX header and its sets.
pub(super) fn parse_ipfix(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
) -> bool {
    let Some(declared) = read_u16_be(data, 2) else {
        return false;
    };
    node.add_field(
        &fields::CFLOW_LEN,
        Range::new(base + 2, 2),
        Value::Uint16(declared),
    );
    if data.len() < IPFIX_HEADER_LENGTH {
        return false;
    }
    let (Some(export_time), Some(sequence), Some(domain)) = (
        read_u32_be(data, 4),
        read_u32_be(data, 8),
        read_u32_be(data, 12),
    ) else {
        return false;
    };
    add_header_timestamp(
        node,
        base + 4,
        Timestamp {
            seconds: i64::from(export_time),
            nanos: 0,
        },
        &fields::CFLOW_EXPORTTIME,
        Value::Uint32(export_time),
    );
    add_header_sequence(node, base + 8, sequence);
    node.add_field(
        &fields::CFLOW_OD_ID,
        Range::new(base + 12, 4),
        Value::Uint32(domain),
    );
    let message = Message {
        version: 10,
        exporter: exporter(context),
        port: context
            .transport
            .as_ref()
            .map_or(0, |transport| transport.source_port),
        transport: context
            .transport
            .as_ref()
            .map_or(17, |transport| transport.protocol),
        domain,
        frame: context.frame.number,
        sequence,
    };
    if declared == 0 {
        if data.len() > IPFIX_HEADER_LENGTH && !context.quoted {
            add_message_marker(
                node,
                base + IPFIX_HEADER_LENGTH,
                data.len() - IPFIX_HEADER_LENGTH,
                "FlowSets impossible - PDU Count is 0",
                &fields::CFLOW_FLOWSETS_IMPOSSIBLE,
            );
        }
        return true;
    }
    let mut state = ParseState::default();
    parse_sets(
        context,
        node,
        Datagram { data, base },
        IPFIX_HEADER_LENGTH,
        &message,
        None,
        &mut state,
    );
    finish_sequence(context, node, base, &message, &state);
    !state.malformed
}

/// Add the flow-sequence field as a value-bearing container.
///
/// The sequence expert and its marker nest under this field, and JSON/PDML
/// output keeps the value as a plain key until a marker exists.
fn add_header_sequence(node: &mut Node, offset: usize, sequence: u32) {
    let field = node.add_container(&fields::CFLOW_SEQUENCE, Range::new(offset, 4), None);
    field.value = Value::Uint32(sequence);
}

/// Add the absolute timestamp field and its header-specific child.
fn add_header_timestamp(
    node: &mut Node,
    offset: usize,
    timestamp: Timestamp,
    child_def: &'static crate::fields::FieldDef,
    child_value: Value,
) {
    let showname = format!("Timestamp: {}", absolute_time_text(timestamp));
    let field = node.add_container(
        &fields::CFLOW_TIMESTAMP,
        Range::new(offset, 4),
        Some(showname),
    );
    field.value = Value::AbsoluteTime(timestamp);
    field.add_field(child_def, Range::new(offset, 4), child_value);
}

/// Add an anonymous label container carrying one warning marker.
fn add_message_marker(
    node: &mut Node,
    offset: usize,
    length: usize,
    message: &str,
    marker: &'static crate::fields::FieldDef,
) {
    let container = node.add_container(
        &fields::CFLOW_MESSAGE,
        Range::new(offset, length),
        Some(message.to_string()),
    );
    let field = container.add_field(marker, Range::new(offset, 0), Value::None);
    field.showname = Some(message.to_string());
    field.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Malformed,
        message: message.to_string(),
    });
}

/// Append experts only when the datagram is not a quoted header.
fn add_expert(
    context: &DecodeContext<'_>,
    field: &mut Field,
    severity: Severity,
    group: Group,
    message: String,
) {
    if context.quoted {
        return;
    }
    field.add_expert(ExpertInfo {
        severity,
        group,
        message,
    });
}

/// Add a hidden marker field under a rejected count/length value.
///
/// The count/length stays visible and the offending marker nests in a warning
/// expert. A value-bearing container carries that detail and PDML shape while
/// leaving `-T fields` and display filters able to see the marker occurrence.
fn add_marker_field(
    context: &DecodeContext<'_>,
    field: &mut Field,
    def: &'static crate::fields::FieldDef,
    offset: usize,
    message: String,
    severity: Severity,
    group: Group,
) {
    let marker = field.add_field(def, Range::new(offset, 0), Value::None);
    marker.showname = Some(message.clone());
    add_expert(context, marker, severity, group, message);
}

/// Add a rejected count field: the value-bearing container plus its marker.
fn add_rejected_count_field(
    context: &DecodeContext<'_>,
    template: &mut Field,
    range: Range,
    count: RejectedCount<'_>,
) {
    let RejectedCount {
        def,
        marker,
        value,
        label,
        message,
        group,
    } = count;
    let field = template.add_container(def, range, Some(format!("{label}: {value}")));
    field.value = Value::Uint16(value);
    add_marker_field(
        context,
        field,
        marker,
        range.offset,
        message,
        Severity::Warning,
        group,
    );
}

/// Decode one datagram's flow sets.
fn parse_sets(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    datagram: Datagram<'_>,
    header_length: usize,
    message: &Message,
    max_sets: Option<u16>,
    state: &mut ParseState,
) {
    let data = datagram.data;
    let base = datagram.base;
    let mut offset = header_length;
    let mut set_index = 0_usize;
    let mut local: HashMap<u16, TemplateEntry> = HashMap::new();
    while offset.saturating_add(4) <= data.len() {
        if max_sets.is_some_and(|maximum| set_index >= usize::from(maximum)) {
            break;
        }
        let (Some(set_id), Some(set_length)) =
            (read_u16_be(data, offset), read_u16_be(data, offset + 2))
        else {
            break;
        };
        let set_length = usize::from(set_length);
        if set_length > data.len() - offset {
            // Stop silently when a set announces more bytes than the datagram
            // holds.
            break;
        }
        set_index += 1;
        if set_length < 4 {
            let flowset = node.add_container(
                &fields::CFLOW_FLOWSET,
                Range::new(base + offset, set_length),
                Some(format!("{} {set_index} [id={set_id}]", set_name(message))),
            );
            add_set_header(context, flowset, base, offset, set_id, set_length, true);
            break;
        }
        let set = SetContext {
            datagram,
            message,
            index: set_index,
            start: offset,
            end: offset + set_length,
        };
        match set_id {
            SET_TEMPLATE_V9 => {
                let flowset = node.add_container(
                    &fields::CFLOW_FLOWSET,
                    Range::new(base + offset, set_length),
                    None,
                );
                add_set_header(context, flowset, base, offset, set_id, set_length, false);
                let ids = parse_v9_templates(context, flowset, set, &mut local, state);
                flowset.showname = Some(format!(
                    "{} {set_index} [id={set_id}] (Data Template): {}",
                    set_name(message),
                    ids.join(",")
                ));
            }
            SET_OPTIONS_V9 => {
                let flowset = node.add_container(
                    &fields::CFLOW_FLOWSET,
                    Range::new(base + offset, set_length),
                    None,
                );
                add_set_header(context, flowset, base, offset, set_id, set_length, false);
                let ids = parse_v9_options_templates(context, flowset, set, &mut local, state);
                flowset.showname = Some(format!(
                    "{} {set_index} [id={set_id}] (Options Template): {}",
                    set_name(message),
                    ids.join(",")
                ));
            }
            SET_TEMPLATE_IPFIX => {
                let flowset = node.add_container(
                    &fields::CFLOW_FLOWSET,
                    Range::new(base + offset, set_length),
                    None,
                );
                add_set_header(context, flowset, base, offset, set_id, set_length, false);
                let ids = parse_ipfix_templates(context, flowset, set, &mut local, state);
                flowset.showname = Some(format!(
                    "{} {set_index} [id={set_id}] (Data Template): {}",
                    set_name(message),
                    ids.join(",")
                ));
            }
            SET_OPTIONS_IPFIX => {
                let flowset = node.add_container(
                    &fields::CFLOW_FLOWSET,
                    Range::new(base + offset, set_length),
                    None,
                );
                add_set_header(context, flowset, base, offset, set_id, set_length, false);
                let ids = parse_ipfix_options_templates(context, flowset, set, &mut local, state);
                flowset.showname = Some(format!(
                    "{} {set_index} [id={set_id}] (Options Template): {}",
                    set_name(message),
                    ids.join(",")
                ));
            }
            FIRST_DATA_SET..=u16::MAX => {
                decode_data_set(context, node, set, &local, state);
            }
            _ => {
                let flowset = node.add_container(
                    &fields::CFLOW_FLOWSET,
                    Range::new(base + offset, set_length),
                    Some(format!("{} {set_index} [id={set_id}]", set_name(message))),
                );
                add_set_header(context, flowset, base, offset, set_id, set_length, false);
            }
        }
        offset = offset.saturating_add(set_length);
    }
}

/// Add the flow-set ID and length fields.
fn add_set_header(
    context: &DecodeContext<'_>,
    flowset: &mut Field,
    base: usize,
    offset: usize,
    set_id: u16,
    set_length: usize,
    invalid_length: bool,
) {
    let id_field = flowset.add_field(
        &fields::CFLOW_FLOWSET_ID,
        Range::new(base + offset, 2),
        Value::Uint16(set_id),
    );
    id_field.showname = Some(format!("FlowSet Id: {} ({set_id})", set_kind_name(set_id)));
    let length = u16::try_from(set_length).unwrap_or(u16::MAX);
    if invalid_length {
        let field = flowset.add_container(
            &fields::CFLOW_FLOWSET_LENGTH,
            Range::new(base + offset + 2, 2),
            Some(format!("FlowSet Length: {length}")),
        );
        field.value = Value::Uint16(length);
        add_marker_field(
            context,
            field,
            &fields::CFLOW_FLOWSET_LENGTH_INVALID,
            base + offset + 2,
            format!("Flowset Length ({set_length}) too short"),
            Severity::Warning,
            Group::Malformed,
        );
    } else {
        flowset.add_field(
            &fields::CFLOW_FLOWSET_LENGTH,
            Range::new(base + offset + 2, 2),
            Value::Uint16(length),
        );
    }
}

/// The display name for a set ID.
fn set_kind_name(set_id: u16) -> &'static str {
    match set_id {
        SET_TEMPLATE_V9 => "Data Template (V9)",
        SET_OPTIONS_V9 => "Options Template(V9)",
        SET_TEMPLATE_IPFIX => "Data Template (V10 [IPFIX])",
        SET_OPTIONS_IPFIX => "Options Template (V10 [IPFIX])",
        FIRST_DATA_SET..=u16::MAX => "(Data)",
        _ => "(Reserved)",
    }
}

fn set_name(message: &Message) -> &'static str {
    if message.version == 10 {
        "Set"
    } else {
        "FlowSet"
    }
}

/// Parse the v9 template records in one set and cache the valid ones.
fn parse_v9_templates(
    context: &mut DecodeContext<'_>,
    flowset: &mut Field,
    set: SetContext<'_>,
    local: &mut HashMap<u16, TemplateEntry>,
    state: &mut ParseState,
) -> Vec<String> {
    let data = set.datagram.data;
    let base = set.datagram.base;
    let message = set.message;
    let end = set.end;
    let mut offset = set.data_start();
    let mut ids = Vec::new();
    while offset.saturating_add(4) <= end {
        let template_id = read_u16_be(data, offset).unwrap_or(0);
        let field_count = read_u16_be(data, offset + 2).unwrap_or(0);
        ids.push(template_id.to_string());
        let template = flowset.add_container(
            &fields::CFLOW_TEMPLATE,
            Range::new(base + offset, 4),
            Some(format!(
                "Template (Id = {template_id}, Count = {field_count})"
            )),
        );
        template.add_field(
            &fields::CFLOW_TEMPLATE_ID,
            Range::new(base + offset, 2),
            Value::Uint16(template_id),
        );
        let below_limit = usize::from(field_count) <= MAX_TEMPLATE_FIELDS;
        if below_limit {
            template.add_field(
                &fields::CFLOW_TEMPLATE_FIELD_COUNT,
                Range::new(base + offset + 2, 2),
                Value::Uint16(field_count),
            );
        } else {
            add_rejected_count_field(
                context,
                template,
                Range::new(base + offset + 2, 2),
                RejectedCount {
                    def: &fields::CFLOW_TEMPLATE_FIELD_COUNT,
                    marker: &fields::CFLOW_ENTRIES_TOO_MANY,
                    value: field_count,
                    label: "Field Count",
                    message: too_many_entries(field_count),
                    group: Group::Undecoded,
                },
            );
        }
        let fields_start = offset + 4;
        let mut fields = Vec::with_capacity(
            usize::from(field_count)
                .min(MAX_TEMPLATE_FIELDS)
                .min((end - fields_start) / 4),
        );
        let mut complete = true;
        let mut cursor = fields_start;
        for index in 0..usize::from(field_count) {
            if cursor.saturating_add(4) > end {
                complete = false;
                break;
            }
            let element = read_u16_be(data, cursor).unwrap_or(0);
            let length = read_u16_be(data, cursor + 2).unwrap_or(0);
            add_v9_field_description(template, base, cursor, element, length, index, field_count);
            fields.push(TemplateField {
                element,
                length,
                enterprise: None,
            });
            cursor += 4;
        }
        template.range.length = cursor.saturating_sub(offset);
        if !complete {
            state.malformed = true;
        }
        if complete && below_limit && field_count > 0 {
            state.accepted_template = true;
            let entry = TemplateEntry {
                kind: TemplateKind::Data,
                scope_count: 0,
                frame: message.frame,
                fields,
            };
            if entry.record_length().is_some() {
                local.insert(template_id, entry.clone());
                let key = template_key(message, template_id);
                context.state.store_template(key, entry);
            }
        }
        offset = cursor;
        if !complete {
            break;
        }
    }
    add_set_padding(flowset, data, base, offset, end);
    ids
}

/// Parse the v9 options template records in one set.
fn parse_v9_options_templates(
    context: &mut DecodeContext<'_>,
    flowset: &mut Field,
    set: SetContext<'_>,
    local: &mut HashMap<u16, TemplateEntry>,
    state: &mut ParseState,
) -> Vec<String> {
    let data = set.datagram.data;
    let base = set.datagram.base;
    let message = set.message;
    let end = set.end;
    let mut offset = set.data_start();
    let mut ids = Vec::new();
    while offset.saturating_add(6) <= end {
        let template_id = read_u16_be(data, offset).unwrap_or(0);
        let scope_length = read_u16_be(data, offset + 2).unwrap_or(0);
        let option_length = read_u16_be(data, offset + 4).unwrap_or(0);
        ids.push(template_id.to_string());
        let scope_count = usize::from(scope_length) / 4;
        let data_count = usize::from(option_length) / 4;
        let template = flowset.add_container(
            &fields::CFLOW_TEMPLATE,
            Range::new(base + offset, 6),
            Some(format!(
                "Options Template (Id = {template_id}) (Scope Count = {scope_count}; Data Count = {data_count})"
            )),
        );
        template.add_field(
            &fields::CFLOW_TEMPLATE_ID,
            Range::new(base + offset, 2),
            Value::Uint16(template_id),
        );
        let scope_over = scope_count > MAX_TEMPLATE_FIELDS;
        let data_over = data_count > MAX_TEMPLATE_FIELDS;
        let below_limit = scope_length.is_multiple_of(4)
            && option_length.is_multiple_of(4)
            && !scope_over
            && !data_over;
        template.add_field(
            &fields::CFLOW_OPTION_SCOPE_LENGTH,
            Range::new(base + offset + 2, 2),
            Value::Uint16(scope_length),
        );
        // Both "more scopes" and "more options" experts sit on Option Length,
        // the last of the two length fields.
        if scope_over || data_over {
            let field = template.add_container(
                &fields::CFLOW_OPTION_LENGTH,
                Range::new(base + offset + 4, 2),
                Some(format!("Option Length: {option_length}")),
            );
            field.value = Value::Uint16(option_length);
            if scope_over {
                add_marker_field(
                    context,
                    field,
                    &fields::CFLOW_SCOPES_TOO_MANY,
                    base + offset + 4,
                    too_many_scopes(scope_count),
                    Severity::Warning,
                    Group::Undecoded,
                );
            }
            if data_over {
                add_marker_field(
                    context,
                    field,
                    &fields::CFLOW_OPTIONS_TOO_MANY,
                    base + offset + 4,
                    too_many_options(data_count),
                    Severity::Warning,
                    Group::Undecoded,
                );
            }
        } else {
            template.add_field(
                &fields::CFLOW_OPTION_LENGTH,
                Range::new(base + offset + 4, 2),
                Value::Uint16(option_length),
            );
        }
        let mut complete = true;
        let mut cursor = offset + 6;
        let total_fields = scope_count.saturating_add(data_count);
        let mut fields = Vec::with_capacity(
            total_fields
                .min(MAX_TEMPLATE_FIELDS)
                .min((end - cursor) / 4),
        );
        for index in 0..total_fields {
            if cursor.saturating_add(4) > end {
                complete = false;
                break;
            }
            let element = read_u16_be(data, cursor).unwrap_or(0);
            let length = read_u16_be(data, cursor + 2).unwrap_or(0);
            if index < scope_count {
                add_v9_scope_description(
                    template,
                    base,
                    cursor,
                    element,
                    length,
                    index,
                    scope_count,
                );
            } else {
                add_v9_field_description(
                    template,
                    base,
                    cursor,
                    element,
                    length,
                    index - scope_count,
                    u16::try_from(data_count).unwrap_or(u16::MAX),
                );
            }
            fields.push(TemplateField {
                element,
                length,
                enterprise: None,
            });
            cursor += 4;
        }
        template.range.length = cursor.saturating_sub(offset);
        if !complete {
            state.malformed = true;
        }
        if complete && below_limit && total_fields > 0 {
            state.accepted_template = true;
            let entry = TemplateEntry {
                kind: TemplateKind::OptionsV9,
                scope_count: u16::try_from(scope_count).unwrap_or(u16::MAX),
                frame: message.frame,
                fields,
            };
            if entry.record_length().is_some() {
                local.insert(template_id, entry.clone());
                let key = template_key(message, template_id);
                context.state.store_template(key, entry);
            }
        }
        offset = cursor;
        if !complete {
            break;
        }
    }
    add_set_padding(flowset, data, base, offset, end);
    ids
}

/// Parse the IPFIX template records in one set and handle withdrawals.
fn parse_ipfix_templates(
    context: &mut DecodeContext<'_>,
    flowset: &mut Field,
    set: SetContext<'_>,
    local: &mut HashMap<u16, TemplateEntry>,
    state: &mut ParseState,
) -> Vec<String> {
    let data = set.datagram.data;
    let base = set.datagram.base;
    let message = set.message;
    let end = set.end;
    let mut offset = set.data_start();
    let mut ids = Vec::new();
    while offset.saturating_add(4) <= end {
        let template_id = read_u16_be(data, offset).unwrap_or(0);
        let field_count = read_u16_be(data, offset + 2).unwrap_or(0);
        ids.push(template_id.to_string());
        let template = flowset.add_container(
            &fields::CFLOW_TEMPLATE,
            Range::new(base + offset, 4),
            Some(format!(
                "Template (Id = {template_id}, Count = {field_count})"
            )),
        );
        template.add_field(
            &fields::CFLOW_TEMPLATE_ID,
            Range::new(base + offset, 2),
            Value::Uint16(template_id),
        );
        let below_limit = usize::from(field_count) <= MAX_TEMPLATE_FIELDS;
        if below_limit {
            template.add_field(
                &fields::CFLOW_TEMPLATE_FIELD_COUNT,
                Range::new(base + offset + 2, 2),
                Value::Uint16(field_count),
            );
        } else {
            add_rejected_count_field(
                context,
                template,
                Range::new(base + offset + 2, 2),
                RejectedCount {
                    def: &fields::CFLOW_TEMPLATE_FIELD_COUNT,
                    marker: &fields::CFLOW_ENTRIES_TOO_MANY,
                    value: field_count,
                    label: "Field Count",
                    message: too_many_entries(field_count),
                    group: Group::Undecoded,
                },
            );
        }
        let mut complete = true;
        let mut cursor = offset + 4;
        let mut fields = Vec::with_capacity(
            usize::from(field_count)
                .min(MAX_TEMPLATE_FIELDS)
                .min((end - cursor) / 4),
        );
        for index in 0..usize::from(field_count) {
            if cursor.saturating_add(4) > end {
                complete = false;
                break;
            }
            let field_offset = cursor;
            let raw_type = read_u16_be(data, field_offset).unwrap_or(0);
            let length = read_u16_be(data, field_offset + 2).unwrap_or(0);
            let enterprise = if raw_type & 0x8000 != 0 {
                let Some(pen) = read_u32_be(data, field_offset + 4) else {
                    complete = false;
                    break;
                };
                cursor = field_offset + 8;
                Some(pen)
            } else {
                cursor = field_offset + 4;
                None
            };
            let field = TemplateField {
                element: raw_type & 0x7fff,
                length,
                enterprise,
            };
            add_ipfix_field_description_scoped(
                template,
                Range::new(base + field_offset, 4),
                raw_type,
                field,
                index,
                field_count,
                false,
            );
            fields.push(field);
        }
        template.range.length = cursor.saturating_sub(offset);
        if !complete {
            state.malformed = true;
        }
        if field_count == 0 {
            // RFC 7011 section 8.1: a template record with no fields is a
            // withdrawal, so delete the cached template.
            local.remove(&template_id);
            let key = template_key(message, template_id);
            context.state.remove_template(&key);
        } else if complete && below_limit {
            state.accepted_template = true;
            let entry = TemplateEntry {
                kind: TemplateKind::Data,
                scope_count: 0,
                frame: message.frame,
                fields,
            };
            if entry.record_length().is_some() {
                local.insert(template_id, entry.clone());
                let key = template_key(message, template_id);
                context.state.store_template(key, entry);
            }
        }
        offset = cursor;
        if !complete {
            break;
        }
    }
    add_set_padding(flowset, data, base, offset, end);
    ids
}

/// Parse the IPFIX options template records in one set.
fn parse_ipfix_options_templates(
    context: &mut DecodeContext<'_>,
    flowset: &mut Field,
    set: SetContext<'_>,
    local: &mut HashMap<u16, TemplateEntry>,
    state: &mut ParseState,
) -> Vec<String> {
    let data = set.datagram.data;
    let base = set.datagram.base;
    let message = set.message;
    let end = set.end;
    let mut offset = set.data_start();
    let mut ids = Vec::new();
    while offset.saturating_add(6) <= end {
        let template_id = read_u16_be(data, offset).unwrap_or(0);
        let total_fields = read_u16_be(data, offset + 2).unwrap_or(0);
        let scope_fields = read_u16_be(data, offset + 4).unwrap_or(0);
        ids.push(template_id.to_string());
        let data_fields = total_fields.saturating_sub(scope_fields);
        let invalid_scope = scope_fields == 0 || scope_fields > total_fields;
        let scope_over = usize::from(scope_fields) > MAX_TEMPLATE_FIELDS;
        let data_over = usize::from(data_fields) > MAX_TEMPLATE_FIELDS;
        let showname = if invalid_scope {
            format!("Options Template (Id = {template_id})")
        } else {
            format!(
                "Options Template (Id = {template_id}) (Scope Count = {scope_fields}; Data Count = {data_fields})"
            )
        };
        let template = flowset.add_container(
            &fields::CFLOW_TEMPLATE,
            Range::new(base + offset, 6),
            Some(showname),
        );
        template.add_field(
            &fields::CFLOW_TEMPLATE_ID,
            Range::new(base + offset, 2),
            Value::Uint16(template_id),
        );
        if data_over {
            add_rejected_count_field(
                context,
                template,
                Range::new(base + offset + 2, 2),
                RejectedCount {
                    def: &fields::CFLOW_TEMPLATE_IPFIX_TOTAL_FIELD_COUNT,
                    marker: &fields::CFLOW_OPTIONS_TOO_MANY,
                    value: total_fields,
                    label: "Total Field Count",
                    message: too_many_options(usize::from(data_fields)),
                    group: Group::Undecoded,
                },
            );
        } else {
            template.add_field(
                &fields::CFLOW_TEMPLATE_IPFIX_TOTAL_FIELD_COUNT,
                Range::new(base + offset + 2, 2),
                Value::Uint16(total_fields),
            );
        }
        if scope_fields == 0 {
            add_rejected_count_field(
                context,
                template,
                Range::new(base + offset + 4, 2),
                RejectedCount {
                    def: &fields::CFLOW_TEMPLATE_IPFIX_SCOPE_FIELD_COUNT,
                    marker: &fields::CFLOW_IPFIX_SCOPE_NONE,
                    value: scope_fields,
                    label: "Scope Field Count",
                    message: "No scope fields".to_string(),
                    group: Group::Malformed,
                },
            );
        } else if scope_fields > total_fields {
            add_rejected_count_field(
                context,
                template,
                Range::new(base + offset + 4, 2),
                RejectedCount {
                    def: &fields::CFLOW_TEMPLATE_IPFIX_SCOPE_FIELD_COUNT,
                    marker: &fields::CFLOW_IPFIX_SCOPE_TOO_MANY,
                    value: scope_fields,
                    label: "Scope Field Count",
                    message: format!(
                        "More scope fields ({scope_fields}) than fields ({total_fields})"
                    ),
                    group: Group::Malformed,
                },
            );
        } else if scope_over {
            add_rejected_count_field(
                context,
                template,
                Range::new(base + offset + 4, 2),
                RejectedCount {
                    def: &fields::CFLOW_TEMPLATE_IPFIX_SCOPE_FIELD_COUNT,
                    marker: &fields::CFLOW_SCOPES_TOO_MANY,
                    value: scope_fields,
                    label: "Scope Field Count",
                    message: too_many_scopes(usize::from(scope_fields)),
                    group: Group::Undecoded,
                },
            );
        } else {
            template.add_field(
                &fields::CFLOW_TEMPLATE_IPFIX_SCOPE_FIELD_COUNT,
                Range::new(base + offset + 4, 2),
                Value::Uint16(scope_fields),
            );
        }
        let below_limit = !invalid_scope && !scope_over && !data_over;
        let mut complete = true;
        let mut cursor = offset + 6;
        let mut fields = Vec::with_capacity(
            usize::from(total_fields)
                .min(MAX_TEMPLATE_FIELDS)
                .min((end - cursor) / 4),
        );
        if invalid_scope {
            // Report the invalid scope count and show no field descriptions,
            // but still advance across the declared fields.
            let (next, ok) = skip_ipfix_fields(data, cursor, total_fields, end);
            cursor = next;
            complete = ok;
        } else {
            for index in 0..usize::from(total_fields) {
                if cursor.saturating_add(4) > end {
                    complete = false;
                    break;
                }
                let field_offset = cursor;
                let raw_type = read_u16_be(data, field_offset).unwrap_or(0);
                let length = read_u16_be(data, field_offset + 2).unwrap_or(0);
                let enterprise = if raw_type & 0x8000 != 0 {
                    let Some(pen) = read_u32_be(data, field_offset + 4) else {
                        complete = false;
                        break;
                    };
                    cursor = field_offset + 8;
                    Some(pen)
                } else {
                    cursor = field_offset + 4;
                    None
                };
                let field = TemplateField {
                    element: raw_type & 0x7fff,
                    length,
                    enterprise,
                };
                let range = Range::new(base + field_offset, 4);
                if index < usize::from(scope_fields) {
                    add_ipfix_field_description_scoped(
                        template,
                        range,
                        raw_type,
                        field,
                        index,
                        scope_fields,
                        true,
                    );
                } else {
                    add_ipfix_field_description_scoped(
                        template,
                        range,
                        raw_type,
                        field,
                        index - usize::from(scope_fields),
                        data_fields,
                        false,
                    );
                }
                fields.push(field);
            }
        }
        template.range.length = cursor.saturating_sub(offset);
        if !complete {
            state.malformed = true;
        }
        if invalid_scope {
            // Show no padding for an invalid options-template record and do
            // not parse later records in the same set.
            offset = end;
            break;
        }
        if total_fields == 0 {
            local.remove(&template_id);
            let key = template_key(message, template_id);
            context.state.remove_template(&key);
        } else if complete && below_limit {
            state.accepted_template = true;
            let entry = TemplateEntry {
                kind: TemplateKind::OptionsIpfix,
                scope_count: scope_fields,
                frame: message.frame,
                fields,
            };
            if entry.record_length().is_some() {
                local.insert(template_id, entry.clone());
                let key = template_key(message, template_id);
                context.state.store_template(key, entry);
            }
        }
        offset = cursor;
        if !complete {
            break;
        }
    }
    add_set_padding(flowset, data, base, offset, end);
    ids
}

/// Add one v9 data-template field description.
fn add_v9_field_description(
    template: &mut Field,
    base: usize,
    offset: usize,
    element: u16,
    length: u16,
    index: usize,
    count: u16,
) {
    let name = ie::element(element).map_or_else(
        || format!("Unknown({element})"),
        |spec| spec.name.to_string(),
    );
    let field = template.add_container(
        &fields::CFLOW_TEMPLATE_FIELD,
        Range::new(base + offset, 4),
        Some(format!(
            "Field ({}/{count}): {name}",
            index.saturating_add(1)
        )),
    );
    let type_field = field.add_field(
        &fields::CFLOW_TEMPLATE_FIELD_TYPE,
        Range::new(base + offset, 2),
        Value::Uint16(element),
    );
    type_field.showname = Some(format!(
        "Type: {} ({element})",
        ie::element(element).map_or("Unknown", |spec| spec.name)
    ));
    field.add_field(
        &fields::CFLOW_TEMPLATE_FIELD_LENGTH,
        Range::new(base + offset + 2, 2),
        Value::Uint16(length),
    );
}

/// Add one v9 options-template scope field description.
fn add_v9_scope_description(
    template: &mut Field,
    base: usize,
    offset: usize,
    element: u16,
    length: u16,
    index: usize,
    count: usize,
) {
    let field = template.add_container(
        &fields::CFLOW_TEMPLATE_FIELD,
        Range::new(base + offset, 4),
        Some(format!(
            "Field ({}/{count}) [Scope]: {}",
            index.saturating_add(1),
            ie::scope_name(element)
        )),
    );
    let type_field = field.add_field(
        &fields::CFLOW_SCOPE_FIELD_TYPE,
        Range::new(base + offset, 2),
        Value::Uint16(element),
    );
    type_field.showname = Some(format!(
        "Scope Type: {} ({element})",
        ie::scope_name(element)
    ));
    field.add_field(
        &fields::CFLOW_TEMPLATE_FIELD_LENGTH,
        Range::new(base + offset + 2, 2),
        Value::Uint16(length),
    );
}

/// Add one IPFIX data- or options-template field description.
fn add_ipfix_field_description_scoped(
    template: &mut Field,
    range: Range,
    raw_type: u16,
    field: TemplateField,
    index: usize,
    count: u16,
    scope: bool,
) {
    let TemplateField {
        element,
        length,
        enterprise,
    } = field;
    let name = if let Some(pen) = enterprise {
        if pen == 9 {
            format!("Unknown({element})")
        } else {
            format!("  {element} [pen: {}]", ie::enterprise_name(pen))
        }
    } else {
        ie::element(element).map_or_else(
            || format!("Unknown({element})"),
            |spec| spec.name.to_string(),
        )
    };
    let label = if scope {
        format!(
            "Field ({}/{count}) [Scope]: {name}",
            index.saturating_add(1)
        )
    } else {
        format!("Field ({}/{count}): {name}", index.saturating_add(1))
    };
    let container = template.add_container(&fields::CFLOW_TEMPLATE_FIELD, range, Some(label));
    let pen_field = container.add_field(
        &fields::CFLOW_TEMPLATE_IPFIX_PEN_PROVIDED,
        Range::new(range.offset, 2),
        Value::Boolean(enterprise.is_some()),
    );
    let pattern = bit_pattern(0x8000, raw_type, 16);
    pen_field.showname = Some(format!(
        "{pattern} = Pen provided: {}",
        if enterprise.is_some() { "Yes" } else { "No" }
    ));
    let type_def = if let Some(pen) = enterprise {
        if pen == 9 {
            &fields::CFLOW_TEMPLATE_CISCO_FIELD_TYPE
        } else {
            &fields::CFLOW_TEMPLATE_IPFIX_FIELD_TYPE_ENTERPRISE
        }
    } else {
        &fields::CFLOW_TEMPLATE_IPFIX_FIELD_TYPE
    };
    let type_field = container.add_field(
        type_def,
        Range::new(range.offset, 2),
        Value::Uint16(element),
    );
    let type_pattern = bit_pattern(0x7fff, raw_type, 16);
    let type_text = if let Some(pen) = enterprise {
        if pen == 9 {
            format!("Unknown ({element})")
        } else {
            format!("{element} [pen: {}]", ie::enterprise_name(pen))
        }
    } else {
        format!(
            "{} ({element})",
            ie::element(element).map_or("Unknown", |spec| spec.name)
        )
    };
    type_field.showname = Some(format!("{type_pattern} = Type: {type_text}"));
    container.add_field(
        &fields::CFLOW_TEMPLATE_FIELD_LENGTH,
        Range::new(range.offset + 2, 2),
        Value::Uint16(length),
    );
    if let Some(pen) = enterprise {
        let pen_field = container.add_field(
            &fields::CFLOW_TEMPLATE_IPFIX_FIELD_PEN,
            Range::new(range.offset + 4, 4),
            Value::Uint32(pen),
        );
        pen_field.showname = Some(format!("PEN: {} ({pen})", ie::enterprise_name(pen)));
    }
}

/// Render a 16-bit bit-field pattern in groups of four bits.
fn bit_pattern(mask: u16, value: u16, width: u32) -> String {
    let mut pattern = String::with_capacity(21);
    for bit in (0..width).rev() {
        let bit_mask = 1_u16 << bit;
        if mask & bit_mask == 0 {
            pattern.push('.');
        } else if value & bit_mask != 0 {
            pattern.push('1');
        } else {
            pattern.push('0');
        }
        if bit % 4 == 0 && bit != 0 {
            pattern.push(' ');
        }
    }
    pattern
}

/// Add any trailing bytes shorter than a template record as padding.
fn add_set_padding(flowset: &mut Field, data: &[u8], base: usize, start: usize, end: usize) {
    if start >= end {
        return;
    }
    if let Some(bytes) = data.get(start..end) {
        let field = flowset.add_field(
            &fields::CFLOW_PADDING,
            Range::new(base + start, bytes.len()),
            Value::bytes(bytes.to_vec()),
        );
        field.showname = Some(format!("Padding: {}", hex_text(bytes)));
    }
}

/// Decode one data set, with or without a matching template.
fn decode_data_set(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    set: SetContext<'_>,
    local: &HashMap<u16, TemplateEntry>,
    state: &mut ParseState,
) {
    let data = set.datagram.data;
    let base = set.datagram.base;
    let offset = set.start;
    let set_length = set.set_length();
    let data_start = set.data_start();
    let data_length = set.data_length();
    let set_index = set.index;
    let message = set.message;
    state.saw_data_set = true;
    let set_id = read_u16_be(data, offset).unwrap_or(0);
    let template = local.get(&set_id).cloned().or_else(|| {
        context
            .state
            .lookup_template(&template_key(message, set_id))
    });
    let Some(template) = template else {
        let flowset = node.add_container(
            &fields::CFLOW_FLOWSET,
            Range::new(base + offset, set_length),
            Some(format!("{} {set_index} [id={set_id}]", set_name(message))),
        );
        add_set_header(context, flowset, base, offset, set_id, set_length, false);
        if data_length == 0 {
            let marker = flowset.add_field(
                &fields::CFLOW_NO_FLOW_INFORMATION,
                Range::new(base + data_start, 0),
                Value::None,
            );
            marker.showname = Some("No flow information".to_string());
            add_expert(
                context,
                marker,
                Severity::Warning,
                Group::Malformed,
                "No flow information".to_string(),
            );
        }
        let empty = format!("Data ({data_length} bytes), no template found");
        let data_field = flowset.add_container(
            &fields::CFLOW_DATA,
            Range::new(base + data_start, data_length),
            Some(empty.clone()),
        );
        let marker = data_field.add_field(
            &fields::CFLOW_NO_TEMPLATE_FOUND,
            Range::new(base + data_start, 0),
            Value::None,
        );
        marker.showname = Some(empty.clone());
        add_expert(context, marker, Severity::Warning, Group::Malformed, empty);
        return;
    };
    let record_length = template.record_length();
    let available_records = record_length.map_or(0, |length| data_length / length);
    state.sequence_records = state.sequence_records.saturating_add(available_records);
    let record_count = available_records.min(MAX_RECORDS_PER_SET);
    let showname = if record_length.is_some() {
        format!(
            "{} {set_index} [id={set_id}] ({record_count} flows)",
            set_name(message)
        )
    } else {
        format!("{} {set_index} [id={set_id}]", set_name(message))
    };
    let flowset = node.add_container(
        &fields::CFLOW_FLOWSET,
        Range::new(base + offset, set_length),
        Some(showname),
    );
    add_set_header(context, flowset, base, offset, set_id, set_length, false);
    let Some(record_length) = record_length else {
        let marker = flowset.add_field(
            &fields::CFLOW_NO_FLOW_INFORMATION,
            Range::new(base + data_start, 0),
            Value::None,
        );
        marker.showname = Some("No flow information".to_string());
        add_expert(
            context,
            marker,
            Severity::Warning,
            Group::Malformed,
            "No flow information".to_string(),
        );
        return;
    };
    let template_frame = flowset.add_field(
        &fields::CFLOW_TEMPLATE_FRAME,
        Range::new(base.saturating_add(base).saturating_add(offset), 0),
        Value::Uint32(u32::try_from(template.frame).unwrap_or(u32::MAX)),
    );
    template_frame.showname = Some(format!("Template Frame: {}", template.frame));
    if available_records > record_count {
        let marker = flowset.add_field(
            &fields::CFLOW_ENTRIES_TOO_MANY,
            Range::new(base + data_start, 0),
            Value::None,
        );
        let message =
            format!("More records ({available_records}) than can be handled; decoding stopped");
        marker.showname = Some(message.clone());
        add_expert(
            context,
            marker,
            Severity::Warning,
            Group::Undecoded,
            message,
        );
    }
    let offsets = record_offsets(&template);
    let mut record_offset = data_start;
    let mut field_budget_stopped = false;
    for index in 0..record_count {
        if state.decoded_fields.saturating_add(template.fields.len()) > MAX_FIELDS_PER_MESSAGE {
            field_budget_stopped = true;
            break;
        }
        let flow = flowset.add_container(
            &fields::CFLOW_FLOW,
            Range::new(base + record_offset, record_length),
            Some(format!("Flow {}", index.saturating_add(1))),
        );
        decode_record(
            flow,
            data,
            base + record_offset,
            record_offset,
            &offsets,
            &template,
        );
        state.decoded_fields = state.decoded_fields.saturating_add(template.fields.len());
        record_offset += record_length;
    }
    if field_budget_stopped {
        let marker = flowset.add_field(
            &fields::CFLOW_ENTRIES_TOO_MANY,
            Range::new(base + data_start, 0),
            Value::None,
        );
        let message =
            format!("More fields ({MAX_FIELDS_PER_MESSAGE}) than can be handled; decoding stopped");
        marker.showname = Some(message.clone());
        add_expert(
            context,
            marker,
            Severity::Warning,
            Group::Undecoded,
            message,
        );
    }
    let decoded_bytes = record_count.saturating_mul(record_length);
    let padding_start = data_start.saturating_add(decoded_bytes);
    let padding_end = data_start.saturating_add(data_length);
    add_set_padding(flowset, data, base, padding_start, padding_end);
}

/// Byte offsets for every template field within one record.
fn record_offsets(template: &TemplateEntry) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(template.fields.len());
    let mut cursor = 0_usize;
    for field in &template.fields {
        offsets.push(cursor);
        cursor = cursor.saturating_add(usize::from(field.length));
    }
    offsets
}

/// Decode the fields of one data record.
fn decode_record(
    flow: &mut Field,
    data: &[u8],
    absolute: usize,
    record_start: usize,
    offsets: &[usize],
    template: &TemplateEntry,
) {
    let fields = &template.fields;
    let mut skip = vec![false; fields.len()];
    for index in 0..fields.len() {
        if skip.get(index).copied().unwrap_or(false) {
            continue;
        }
        let Some(field) = fields.get(index).copied() else {
            continue;
        };
        let offset = offsets.get(index).copied().unwrap_or(0);
        let length = usize::from(field.length);
        let bytes = record_bytes(data, record_start, offset, length);
        let range = Range::new(absolute + offset, length);
        if let Some((first, start, end, scale)) = duration_pair(fields, index) {
            if index == first
                && let (Some(start_field), Some(end_field)) = (fields.get(start), fields.get(end))
            {
                let start_offset = offsets.get(start).copied().unwrap_or(0);
                let end_offset = offsets.get(end).copied().unwrap_or(0);
                let start_bytes = record_bytes(
                    data,
                    record_start,
                    start_offset,
                    usize::from(start_field.length),
                );
                let end_bytes = record_bytes(
                    data,
                    record_start,
                    end_offset,
                    usize::from(end_field.length),
                );
                add_duration(
                    flow,
                    scale,
                    start_bytes,
                    end_bytes,
                    Range::new(absolute + start_offset, 0),
                    Range::new(absolute + start_offset, usize::from(start_field.length)),
                    Range::new(absolute + end_offset, usize::from(end_field.length)),
                );
                if let Some(slot) = skip.get_mut(if index == start { end } else { start }) {
                    *slot = true;
                }
            }
            continue;
        }
        add_record_field(flow, field, bytes, range, index, template);
    }
}

/// Slice one record field, returning only bytes that are actually present.
fn record_bytes(data: &[u8], record_start: usize, offset: usize, length: usize) -> &[u8] {
    let start = record_start.saturating_add(offset);
    let end = start.saturating_add(length);
    data.get(start..end).unwrap_or(&[])
}

/// The five duration pairs grouped for v9 and IPFIX flow records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurationScale {
    Switched,
    Seconds,
    Milliseconds,
    Microseconds,
    Nanoseconds,
}

/// Find the position and members of a duration pair.
fn duration_pair(
    fields: &[TemplateField],
    index: usize,
) -> Option<(usize, usize, usize, DurationScale)> {
    let element = fields.get(index)?.element;
    let (start_element, end_element, scale) = match element {
        21 | 22 => (22, 21, DurationScale::Switched),
        150 | 151 => (150, 151, DurationScale::Seconds),
        152 | 153 => (152, 153, DurationScale::Milliseconds),
        154 | 155 => (154, 155, DurationScale::Microseconds),
        156 | 157 => (156, 157, DurationScale::Nanoseconds),
        _ => return None,
    };
    let start = fields
        .iter()
        .position(|field| field.element == start_element)?;
    let end = fields
        .iter()
        .position(|field| field.element == end_element)?;
    Some((start.min(end), start, end, scale))
}

/// Add one data-record field.
fn add_record_field(
    flow: &mut Field,
    field: TemplateField,
    bytes: &[u8],
    range: Range,
    index: usize,
    template: &TemplateEntry,
) {
    if field.enterprise.is_some() {
        add_unknown_value(flow, field, bytes, range);
        return;
    }
    if template.kind == TemplateKind::OptionsV9 && index < usize::from(template.scope_count) {
        add_scope_value(flow, field.element, bytes, range);
        return;
    }
    let Some(spec) = ie::element(field.element) else {
        add_unknown_value(flow, field, bytes, range);
        return;
    };
    add_known_value(flow, spec.element, field, bytes, range);
}

/// Add one v9 options scope value.
fn add_scope_value(flow: &mut Field, element: u16, bytes: &[u8], range: Range) {
    match ie::scope(element) {
        Some(Scope::System) => {
            flow.add_field(
                &fields::CFLOW_SCOPE_SYSTEM,
                range,
                Value::bytes(bytes.to_vec()),
            );
        }
        Some(Scope::Interface) => {
            flow.add_field(
                &fields::CFLOW_SCOPE_INTERFACE,
                range,
                integer_value(bytes, 32),
            );
        }
        Some(Scope::LineCard) => {
            flow.add_field(
                &fields::CFLOW_SCOPE_LINECARD,
                range,
                integer_value(bytes, 32),
            );
        }
        Some(Scope::Cache) => {
            flow.add_field(
                &fields::CFLOW_SCOPE_CACHE,
                range,
                Value::bytes(bytes.to_vec()),
            );
        }
        Some(Scope::Template) => {
            flow.add_field(
                &fields::CFLOW_SCOPE_TEMPLATE,
                range,
                Value::bytes(bytes.to_vec()),
            );
        }
        None => add_unknown_value(
            flow,
            TemplateField {
                element,
                length: u16::try_from(bytes.len()).unwrap_or(u16::MAX),
                enterprise: None,
            },
            bytes,
            range,
        ),
    }
}

/// Add a known information element in record order.
fn add_known_value(
    flow: &mut Field,
    element: Element,
    field: TemplateField,
    bytes: &[u8],
    range: Range,
) {
    let width = bytes.len();
    let unsupported = |flow: &mut Field, field: TemplateField, bytes: &[u8], range: Range| {
        add_unknown_value(flow, field, bytes, range);
    };
    match element {
        Element::Octets => {
            flow.add_field(&fields::CFLOW_OCTETS, range, integer_value(bytes, 64));
        }
        Element::Packets => {
            flow.add_field(&fields::CFLOW_PACKETS, range, integer_value(bytes, 64));
        }
        Element::Protocol => {
            if width == 0 || width > 4 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let value = read_uint(bytes).unwrap_or(0);
            let showname = match fields::value_name("cflow.protocol", value) {
                Some(name) => format!("Protocol: {name} ({value})"),
                None => format!("Protocol: {value}"),
            };
            let added =
                flow.add_field(&fields::CFLOW_IP_PROTOCOL, range, Value::Uint8(value as u8));
            added.showname = Some(showname);
        }
        Element::SourcePort | Element::DestinationPort => {
            if width == 0 || width > 4 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let value = read_uint(bytes).unwrap_or(0);
            let def = if element == Element::SourcePort {
                &fields::CFLOW_SRCPORT
            } else {
                &fields::CFLOW_DSTPORT
            };
            let label = if element == Element::SourcePort {
                "SrcPort"
            } else {
                "DstPort"
            };
            let added = flow.add_field(def, range, Value::Uint16(value as u16));
            added.showname = Some(format!("{label}: {value} ({value})"));
        }
        Element::SourceIpv4 | Element::DestinationIpv4 => {
            if width != 4 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let Some(address) = read_ipv4(bytes, 0) else {
                unsupported(flow, field, bytes, range);
                return;
            };
            let def = if element == Element::SourceIpv4 {
                &fields::CFLOW_SRCADDR
            } else {
                &fields::CFLOW_DSTADDR
            };
            flow.add_field(def, range, Value::Ipv4(address));
        }
        Element::SourceIpv6 | Element::DestinationIpv6 => {
            if width != 16 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let Some(address) = read_ipv6(bytes, 0) else {
                unsupported(flow, field, bytes, range);
                return;
            };
            let def = if element == Element::SourceIpv6 {
                &fields::CFLOW_SRCADDRV6
            } else {
                &fields::CFLOW_DSTADDRV6
            };
            flow.add_field(def, range, Value::Ipv6(address));
        }
        Element::Tos => {
            if width == 0 || width > 2 {
                unsupported(flow, field, bytes, range);
                return;
            }
            if width == 1 {
                flow.add_field(
                    &fields::CFLOW_TOS,
                    range,
                    Value::Uint8(bytes.first().copied().unwrap_or(0)),
                );
            } else {
                flow.add_field(
                    &fields::CFLOW_TOS,
                    range,
                    Value::Uint16(read_uint(bytes).unwrap_or(0) as u16),
                );
            }
        }
        Element::TcpFlags => {
            if width == 0 || width > 2 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let value = read_uint(bytes).unwrap_or(0);
            let mut label = format!("TCP Flags: 0x{value:0width$x}", width = width * 2);
            let names = [
                (0x20_u64, "URG"),
                (0x10, "ACK"),
                (0x08, "PSH"),
                (0x04, "RST"),
                (0x02, "SYN"),
                (0x01, "FIN"),
            ];
            let set: Vec<&str> = names
                .iter()
                .filter(|(mask, _)| value & mask != 0)
                .map(|(_, name)| *name)
                .collect();
            if !set.is_empty() {
                label.push_str(", ");
                label.push_str(&set.join(", "));
            }
            let added = flow.add_container(&fields::CFLOW_TCPFLAGS, range, Some(label));
            added.value = if width == 1 {
                Value::Uint8(value as u8)
            } else {
                Value::Uint16(value as u16)
            };
            if width == 1 {
                add_flag_children(added, bytes.first().copied().unwrap_or(0), range);
            }
        }
        Element::InputInterface | Element::OutputInterface => {
            if width == 0 || width > 8 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let def = if element == Element::InputInterface {
                &fields::CFLOW_INPUTINT
            } else {
                &fields::CFLOW_OUTPUTINT
            };
            flow.add_field(def, range, integer_value(bytes, 32));
        }
        Element::NextHop | Element::BgpNextHop => {
            if width != 4 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let Some(address) = read_ipv4(bytes, 0) else {
                unsupported(flow, field, bytes, range);
                return;
            };
            let def = if element == Element::NextHop {
                &fields::CFLOW_NEXTHOP
            } else {
                &fields::CFLOW_BGPNEXTHOP
            };
            flow.add_field(def, range, Value::Ipv4(address));
        }
        Element::SourceAs | Element::DestinationAs => {
            if width == 0 || width > 8 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let def = if element == Element::SourceAs {
                &fields::CFLOW_SRCAS
            } else {
                &fields::CFLOW_DSTAS
            };
            flow.add_field(def, range, integer_value(bytes, 32));
        }
        Element::SourceMask | Element::DestinationMask => {
            if width == 0 || width > 8 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let def = if element == Element::SourceMask {
                &fields::CFLOW_SRCMASK
            } else {
                &fields::CFLOW_DSTMASK
            };
            flow.add_field(def, range, integer_value(bytes, 8));
        }
        Element::StartSwitched | Element::EndSwitched => {
            if width == 0 || width > 8 {
                unsupported(flow, field, bytes, range);
                return;
            }
            let def = if element == Element::StartSwitched {
                &fields::CFLOW_TIMESTART
            } else {
                &fields::CFLOW_TIMEEND
            };
            flow.add_field(
                def,
                range,
                Value::RelativeTime(
                    i64::try_from(read_uint(bytes).unwrap_or(0))
                        .unwrap_or(i64::MAX)
                        .saturating_mul(1_000_000),
                ),
            );
        }
        Element::AbsoluteStart(scale) | Element::AbsoluteEnd(scale) => {
            let Some(timestamp) = absolute_timestamp(bytes, scale) else {
                unsupported(flow, field, bytes, range);
                return;
            };
            let def = if matches!(element, Element::AbsoluteStart(_)) {
                &fields::CFLOW_ABSTIMESTART
            } else {
                &fields::CFLOW_ABSTIMEEND
            };
            flow.add_field(def, range, Value::AbsoluteTime(timestamp));
        }
    }
}

/// Add the TCP flag children for a one-octet control field.
fn add_flag_children(parent: &mut Field, value: u8, range: Range) {
    let flags = [
        (
            &fields::CFLOW_TCPFLAGS_RESERVED,
            (value & 0xc0) >> 6,
            "Reserved",
            true,
            0xc0_u16,
        ),
        (
            &fields::CFLOW_TCPFLAGS_URG,
            (value & 0x20) >> 5,
            "URG",
            false,
            0x20,
        ),
        (
            &fields::CFLOW_TCPFLAGS_ACK,
            (value & 0x10) >> 4,
            "ACK",
            false,
            0x10,
        ),
        (
            &fields::CFLOW_TCPFLAGS_PSH,
            (value & 0x08) >> 3,
            "PSH",
            false,
            0x08,
        ),
        (
            &fields::CFLOW_TCPFLAGS_RST,
            (value & 0x04) >> 2,
            "RST",
            false,
            0x04,
        ),
        (
            &fields::CFLOW_TCPFLAGS_SYN,
            (value & 0x02) >> 1,
            "SYN",
            false,
            0x02,
        ),
        (
            &fields::CFLOW_TCPFLAGS_FIN,
            value & 0x01,
            "FIN",
            false,
            0x01,
        ),
    ];
    for (def, bits, name, reserved, mask) in flags {
        let pattern = bit_pattern(mask, u16::from(value), 8);
        let (field, label) = if reserved {
            let field = parent.add_field(def, range, Value::Uint8(bits));
            (field, format!("{pattern} = {name}: 0x{bits:x}"))
        } else {
            let field = parent.add_field(def, range, Value::Boolean(bits != 0));
            let used = if bits != 0 { "Used" } else { "Not used" };
            (field, format!("{pattern} = {name}: {used}"))
        };
        field.showname = Some(label);
    }
}

/// Add the unknown-field fallback with a hex-bytes showname.
fn add_unknown_value(flow: &mut Field, field: TemplateField, bytes: &[u8], range: Range) {
    let showname = if let Some(pen) = field.enterprise {
        format!(
            "Enterprise Private entry: ({}) Type {}: Value (hex bytes): {}",
            ie::enterprise_name(pen),
            field.element,
            hex_space_text(bytes)
        )
    } else {
        format!(
            "Unknown Field Type: Type {}: Value (hex bytes): {}",
            field.element,
            hex_space_text(bytes)
        )
    };
    let added = flow.add_field(
        &fields::CFLOW_UNKNOWN_FIELD_TYPE,
        range,
        Value::bytes(bytes.to_vec()),
    );
    added.showname = Some(showname);
}

/// Add a duration container and its start/end children.
fn add_duration(
    flow: &mut Field,
    scale: DurationScale,
    start: &[u8],
    end: &[u8],
    range: Range,
    start_range: Range,
    end_range: Range,
) {
    let (start_value, start_def) = match scale {
        DurationScale::Switched => (
            Value::RelativeTime(
                i64::try_from(read_uint(start).unwrap_or(0))
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
            ),
            &fields::CFLOW_TIMESTART,
        ),
        DurationScale::Seconds => {
            let Some(timestamp) = absolute_timestamp(start, TimeScale::Seconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMESTART)
        }
        DurationScale::Milliseconds => {
            let Some(timestamp) = absolute_timestamp(start, TimeScale::Milliseconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMESTART)
        }
        DurationScale::Microseconds => {
            let Some(timestamp) = absolute_timestamp(start, TimeScale::Microseconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMESTART)
        }
        DurationScale::Nanoseconds => {
            let Some(timestamp) = absolute_timestamp(start, TimeScale::Nanoseconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMESTART)
        }
    };
    let (end_value, end_def) = match scale {
        DurationScale::Switched => (
            Value::RelativeTime(
                i64::try_from(read_uint(end).unwrap_or(0))
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000_000),
            ),
            &fields::CFLOW_TIMEEND,
        ),
        DurationScale::Seconds => {
            let Some(timestamp) = absolute_timestamp(end, TimeScale::Seconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMEEND)
        }
        DurationScale::Milliseconds => {
            let Some(timestamp) = absolute_timestamp(end, TimeScale::Milliseconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMEEND)
        }
        DurationScale::Microseconds => {
            let Some(timestamp) = absolute_timestamp(end, TimeScale::Microseconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMEEND)
        }
        DurationScale::Nanoseconds => {
            let Some(timestamp) = absolute_timestamp(end, TimeScale::Nanoseconds) else {
                return;
            };
            (Value::AbsoluteTime(timestamp), &fields::CFLOW_ABSTIMEEND)
        }
    };
    let duration = relative_value(&end_value).saturating_sub(relative_value(&start_value));
    let label = match scale {
        DurationScale::Switched => "switched",
        DurationScale::Seconds => "seconds",
        DurationScale::Milliseconds => "milliseconds",
        DurationScale::Microseconds => "microseconds",
        DurationScale::Nanoseconds => "nanoseconds",
    };
    let showname = format!("Duration: {} ({label})", relative_time_text(duration));
    let container = flow.add_container(
        &fields::CFLOW_TIMEDELTA,
        Range::new(range.offset, 0),
        Some(showname),
    );
    container.value = Value::RelativeTime(duration);
    container.generated = true;
    container.add_field(start_def, start_range, start_value);
    container.add_field(end_def, end_range, end_value);
}

/// A duration member's comparable nanosecond value.
fn relative_value(value: &Value) -> i64 {
    match value {
        Value::RelativeTime(nanos) => *nanos,
        Value::AbsoluteTime(timestamp) => i128::from(timestamp.seconds)
            .saturating_mul(1_000_000_000)
            .saturating_add(i128::from(timestamp.nanos))
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX))
            as i64,
        _ => 0,
    }
}

/// Convert an encoded absolute field value into a timestamp.
fn absolute_timestamp(bytes: &[u8], scale: TimeScale) -> Option<Timestamp> {
    match scale {
        TimeScale::Seconds => {
            if bytes.len() != 4 {
                return None;
            }
            let seconds = read_u32_be(bytes, 0)?;
            Some(Timestamp {
                seconds: i64::from(seconds),
                nanos: 0,
            })
        }
        TimeScale::Milliseconds => {
            if bytes.len() != 8 {
                return None;
            }
            let millis = read_uint(bytes)?;
            Some(Timestamp {
                seconds: i64::try_from(millis / 1_000).ok()?,
                nanos: u32::try_from((millis % 1_000) * 1_000_000).ok()?,
            })
        }
        TimeScale::Microseconds | TimeScale::Nanoseconds => {
            if bytes.len() != 8 {
                return None;
            }
            let raw = read_uint(bytes)?;
            let seconds = u32::try_from(raw >> 32).ok()?;
            let fraction = u32::try_from(raw & 0xffff_ffff).ok()?;
            // Convert the 32-bit NTP seconds to Unix time with a wrapping
            // subtraction: seconds below the epoch offset (NTP era 1, from
            // 2036) map to times after 2036 instead of negative values. The
            // 32-bit fraction is kept exact to the nanosecond.
            let unix = seconds.wrapping_sub(2_208_988_800) as i64;
            // Truncate a non-zero NTP fraction as (fraction * 1e9 - 1) >> 32,
            // so an exact nanosecond count comes out one lower; zero stays zero.
            let nanos = if fraction == 0 {
                0
            } else {
                ((u64::from(fraction) * 1_000_000_000 - 1) >> 32) as u32
            };
            Some(Timestamp {
                seconds: unix,
                nanos,
            })
        }
    }
}

/// Read a big-endian unsigned integer of up to eight octets.
fn read_uint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)),
    )
}

/// Build an integer value for a field of at most `bits` bits.
fn integer_value(bytes: &[u8], bits: u16) -> Value {
    let value = read_uint(bytes).unwrap_or(0);
    match bits {
        8 => Value::Uint8(value as u8),
        16 => Value::Uint16(value as u16),
        32 => Value::Uint32(u32::try_from(value).unwrap_or(u32::MAX)),
        _ => Value::Uint64(value),
    }
}

/// Hex text without separators.
fn hex_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Hex text with spaces between octets.
fn hex_space_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        use std::fmt::Write as _;
        if index > 0 {
            text.push(' ');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The exporter address for the current innermost network layer.
fn exporter(context: &DecodeContext<'_>) -> ExporterAddress {
    match *context.network {
        Some(crate::decode::NetworkContext::Ipv4 { source, .. }) => ExporterAddress::V4(source),
        Some(crate::decode::NetworkContext::Ipv6 { source, .. }) => ExporterAddress::V6(source),
        None => ExporterAddress::Unknown,
    }
}

fn template_key(message: &Message, template_id: u16) -> TemplateKey {
    TemplateKey {
        exporter: message.exporter,
        port: message.port,
        transport: message.transport,
        domain: message.domain,
        template_id,
    }
}

/// Advance over IPFIX fields without adding tree descriptions.
fn skip_ipfix_fields(data: &[u8], mut cursor: usize, count: u16, end: usize) -> (usize, bool) {
    for _ in 0..usize::from(count) {
        if cursor.saturating_add(4) > end {
            return (cursor, false);
        }
        let raw_type = read_u16_be(data, cursor).unwrap_or(0);
        if raw_type & 0x8000 != 0 {
            if cursor.saturating_add(8) > end {
                return (cursor, false);
            }
            cursor += 8;
        } else {
            cursor += 4;
        }
    }
    (cursor, true)
}

/// The "more scopes than we can handle" message.
fn too_many_scopes(count: usize) -> String {
    format!(
        "More scopes ({count}) than we can handle [template won't be used]. Maximum value can be adjusted in the protocol preferences."
    )
}

/// The "more options than we can handle" message.
fn too_many_options(count: usize) -> String {
    format!(
        "More options ({count}) than we can handle [template won't be used]. Maximum value can be adjusted in the protocol preferences."
    )
}

/// The "more entries than we can handle" message.
fn too_many_entries(count: u16) -> String {
    format!(
        "More entries ({count}) than we can handle [template won't be used]. Maximum value can be adjusted in the protocol preferences."
    )
}

/// Report and update sequence analysis after sets are decoded.
fn finish_sequence(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    base: usize,
    message: &Message,
    state: &ParseState,
) {
    // Check and update the expectation after every datagram whose header and
    // set loop were parsed, including template-only, header-only, short-set,
    // overrun, missing-template and rejected-template cases. The one
    // exception is an abort on an incomplete template with no data set in the
    // same datagram.
    if state.malformed && !state.saw_data_set {
        return;
    }
    let key = sequence_key(message);
    let previous = context.state.lookup_sequence(&key);
    // Establish the expectation only from an accepted template record. A
    // header-only, short, overrun, missing-template or rejected-template
    // datagram does not create state, though it checks and updates an
    // expectation that already exists.
    if previous.is_none() && !state.accepted_template {
        return;
    }
    if let Some(previous) = previous
        && previous.expected != message.sequence
        && !context.quoted
    {
        let expected = previous.expected;
        let message_text = format!(
            "Unexpected flow sequence for domain ID {} (expected {expected}, got {})",
            message.domain, message.sequence
        );
        if let Some(sequence_field) = node
            .fields
            .iter_mut()
            .find(|field| field.def.abbrev == "cflow.sequence")
        {
            sequence_field.showname = Some(format!(
                "FlowSequence: {} (expected {expected})",
                message.sequence
            ));
            let marker = sequence_field.add_field(
                &fields::CFLOW_UNEXPECTED_SEQUENCE,
                Range::new(sequence_field.range.offset, 0),
                Value::None,
            );
            marker.showname = Some(message_text.clone());
            marker.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Sequence,
                message: message_text,
            });
        }
        let expected_field = node.add_field(
            &fields::CFLOW_EXPECTED_SN,
            Range::new(base, 0),
            Value::Uint32(expected),
        );
        expected_field.showname = Some(format!("Expected Sequence Number: {expected}"));
        let previous_field = node.add_field(
            &fields::CFLOW_PREVIOUS_FRAME,
            Range::new(base, 0),
            Value::Uint32(u32::try_from(previous.previous_frame).unwrap_or(u32::MAX)),
        );
        previous_field.showname = Some(format!(
            "Previous Frame in Sequence: {}",
            previous.previous_frame
        ));
    }
    // v9's sequence counts PDUs, so any checked datagram advances it by one;
    // IPFIX advances by the data records its templates describe (zero for a
    // template-only or missing-template datagram).
    let increment = if message.version == 9 {
        1
    } else {
        u32::try_from(state.sequence_records).unwrap_or(u32::MAX)
    };
    context.state.store_sequence(
        key,
        SequenceState {
            expected: message.sequence.wrapping_add(increment),
            previous_frame: message.frame,
        },
    );
}

fn sequence_key(message: &Message) -> SequenceKey {
    SequenceKey {
        exporter: message.exporter,
        port: message.port,
        transport: message.transport,
        domain: message.domain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Frame;
    use crate::decode::DecodeOptions;
    use crate::state::DecodeSession;

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let (chunks, remainder) = data.as_chunks::<2>();
        for chunk in chunks {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*chunk)));
        }
        if let [last] = remainder {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let [_, _, high, low] = sum.to_be_bytes();
        !u16::from_be_bytes([high, low])
    }

    fn frame(number: u64, source: [u8; 4], source_port: u16, payload: &[u8]) -> Frame {
        let destination_port: u16 = if payload.get(..2) == Some(&10_u16.to_be_bytes()) {
            4739
        } else {
            2055
        };
        let mut captured = Vec::with_capacity(42 + payload.len());
        captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        captured.extend_from_slice(&0x0800_u16.to_be_bytes());
        let ip_start = captured.len();
        captured.extend_from_slice(&[0x45, 0]);
        let total = u16::try_from(20 + 8 + payload.len()).unwrap_or(u16::MAX);
        captured.extend_from_slice(&total.to_be_bytes());
        captured.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
        captured.extend_from_slice(&source);
        captured.extend_from_slice(&[198, 51, 100, 2]);
        let ip_checksum = checksum(captured.get(ip_start..ip_start + 20).unwrap_or(&[]));
        if let Some(bytes) = captured.get_mut(ip_start + 10..ip_start + 12) {
            bytes.copy_from_slice(&ip_checksum.to_be_bytes());
        }
        captured.extend_from_slice(&source_port.to_be_bytes());
        captured.extend_from_slice(&destination_port.to_be_bytes());
        let udp_length = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
        captured.extend_from_slice(&udp_length.to_be_bytes());
        captured.extend_from_slice(&[0, 0]);
        captured.extend_from_slice(payload);
        Frame {
            number,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000 + i64::try_from(number).unwrap_or(i64::MAX),
                nanos: 0,
            }),
            timestamp_precision: 6,
            captured,
            original_len: u32::try_from(42 + payload.len()).unwrap_or(u32::MAX),
            link_type: 1,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: None,
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: Default::default(),
        }
    }

    fn pad4(mut bytes: Vec<u8>) -> Vec<u8> {
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes
    }

    fn set(set_id: u16, body: Vec<u8>) -> Vec<u8> {
        let body = pad4(body);
        let mut out = set_id.to_be_bytes().to_vec();
        out.extend_from_slice(
            &u16::try_from(4 + body.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&body);
        out
    }

    fn v9_template(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut body = template_id.to_be_bytes().to_vec();
        body.extend_from_slice(
            &u16::try_from(fields.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for (element, length) in fields {
            body.extend_from_slice(&element.to_be_bytes());
            body.extend_from_slice(&length.to_be_bytes());
        }
        set(0, body)
    }

    fn ipfix_template(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
        let mut body = template_id.to_be_bytes().to_vec();
        body.extend_from_slice(
            &u16::try_from(fields.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        for (element, length) in fields {
            body.extend_from_slice(&element.to_be_bytes());
            body.extend_from_slice(&length.to_be_bytes());
        }
        set(2, body)
    }

    fn ipfix_withdrawal(template_id: u16) -> Vec<u8> {
        let mut body = template_id.to_be_bytes().to_vec();
        body.extend_from_slice(&0_u16.to_be_bytes());
        set(2, body)
    }

    fn v9_message(count: u16, sequence: u32, domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let mut out = 9_u16.to_be_bytes().to_vec();
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&1000_u32.to_be_bytes());
        out.extend_from_slice(&1_700_000_000_u32.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&domain.to_be_bytes());
        for set in sets {
            out.extend_from_slice(set);
        }
        out
    }

    fn ipfix_message(sequence: u32, domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let body_length: usize = sets.iter().map(Vec::len).sum();
        let length = u16::try_from(16 + body_length).unwrap_or(u16::MAX);
        let mut out = 10_u16.to_be_bytes().to_vec();
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&1_700_000_000_u32.to_be_bytes());
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&domain.to_be_bytes());
        for set in sets {
            out.extend_from_slice(set);
        }
        out
    }

    fn data_set(set_id: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = records.iter().flatten().copied().collect();
        set(set_id, body)
    }

    fn has_field(packet: &crate::decode::Packet, abbrev: &str) -> bool {
        packet.tree.fields().any(|field| field.def.abbrev == abbrev)
    }

    fn template_frame(packet: &crate::decode::Packet) -> Option<u64> {
        packet
            .tree
            .field_values("cflow.template_frame")
            .into_iter()
            .find_map(|value| match value {
                Value::Uint32(frame) => Some(u64::from(*frame)),
                Value::Uint64(frame) => Some(*frame),
                _ => None,
            })
    }

    #[test]
    fn v9_template_and_data_share_one_datagram() {
        let fields: &[(u16, u16)] = &[(8, 4), (12, 4)];
        let record = vec![10, 0, 0, 1, 10, 0, 0, 2];
        let payload = v9_message(
            2,
            1,
            7,
            &[
                v9_template(256, fields),
                data_set(256, std::slice::from_ref(&record)),
            ],
        );
        let mut session = DecodeSession::new(DecodeOptions::default());
        let packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &payload));
        assert!(!packet.malformed);
        assert!(has_field(&packet, "cflow.srcaddr"));
        assert!(has_field(&packet, "cflow.dstaddr"));
        assert_eq!(template_frame(&packet), Some(1));
    }

    #[test]
    fn v9_refresh_replaces_the_cached_template() {
        let first = v9_message(1, 1, 7, &[v9_template(256, &[(8, 4), (12, 4)])]);
        let data = v9_message(1, 2, 7, &[data_set(256, &[vec![10, 0, 0, 1, 10, 0, 0, 2]])]);
        let refreshed = v9_message(1, 3, 7, &[v9_template(256, &[(8, 4), (4, 1)])]);
        let refreshed_data = v9_message(1, 4, 7, &[data_set(256, &[vec![10, 0, 0, 3, 6]])]);
        let mut session = DecodeSession::new(DecodeOptions::default());
        session.decode(&frame(1, [192, 0, 2, 1], 40_000, &first));
        let second = session.decode(&frame(2, [192, 0, 2, 1], 40_000, &data));
        assert!(has_field(&second, "cflow.dstaddr"));
        session.decode(&frame(3, [192, 0, 2, 1], 40_000, &refreshed));
        let fourth = session.decode(&frame(4, [192, 0, 2, 1], 40_000, &refreshed_data));
        assert!(has_field(&fourth, "cflow.srcaddr"));
        assert!(has_field(&fourth, "cflow.protocol"));
        assert_eq!(template_frame(&fourth), Some(3));
    }

    #[test]
    fn ipfix_withdrawal_deletes_the_cached_template() {
        let template = ipfix_message(1, 42, &[ipfix_template(256, &[(8, 4), (12, 4)])]);
        let data = ipfix_message(2, 42, &[data_set(256, &[vec![10, 0, 0, 1, 10, 0, 0, 2]])]);
        let withdrawal = ipfix_message(3, 42, &[ipfix_withdrawal(256)]);
        let after = ipfix_message(4, 42, &[data_set(256, &[vec![10, 0, 0, 3, 10, 0, 0, 4]])]);
        let mut session = DecodeSession::new(DecodeOptions::default());
        session.decode(&frame(1, [192, 0, 2, 1], 40_000, &template));
        session.decode(&frame(2, [192, 0, 2, 1], 40_000, &data));
        session.decode(&frame(3, [192, 0, 2, 1], 40_000, &withdrawal));
        let fourth = session.decode(&frame(4, [192, 0, 2, 1], 40_000, &after));
        assert!(has_field(&fourth, "cflow.no_template_found"));
        assert!(!has_field(&fourth, "cflow.srcaddr"));
    }

    #[test]
    fn template_keys_separate_exporter_port_and_domain() {
        let payload = v9_message(1, 1, 7, &[v9_template(256, &[(8, 4), (12, 4)])]);
        let data = v9_message(1, 2, 7, &[data_set(256, &[vec![10, 0, 0, 1, 10, 0, 0, 2]])]);
        let other_port = v9_message(1, 3, 7, &[data_set(256, &[vec![10, 0, 0, 3, 10, 0, 0, 4]])]);
        let other_exporter =
            v9_message(1, 4, 7, &[data_set(256, &[vec![10, 0, 0, 5, 10, 0, 0, 6]])]);
        let other_domain = v9_message(1, 5, 8, &[data_set(256, &[vec![10, 0, 0, 7, 10, 0, 0, 8]])]);
        let mut session = DecodeSession::new(DecodeOptions::default());
        session.decode(&frame(1, [192, 0, 2, 1], 40_000, &payload));
        let same = session.decode(&frame(2, [192, 0, 2, 1], 40_000, &data));
        assert!(has_field(&same, "cflow.srcaddr"));
        for (index, (source, port, bytes)) in [
            ([192, 0, 2, 1], 40_001, &other_port),
            ([203, 0, 113, 9], 40_000, &other_exporter),
            ([192, 0, 2, 1], 40_000, &other_domain),
        ]
        .into_iter()
        .enumerate()
        {
            let packet = session.decode(&frame(
                u64::try_from(index).unwrap_or(0) + 3,
                source,
                port,
                bytes,
            ));
            assert!(has_field(&packet, "cflow.no_template_found"));
            assert!(!has_field(&packet, "cflow.srcaddr"));
        }
    }

    #[test]
    fn the_template_cache_evicts_the_oldest_entry() {
        let field: &[(u16, u16)] = &[(8, 4)];
        let mut payload = Vec::new();
        let mut sets = Vec::new();
        for index in 0..4097_u16 {
            sets.push(v9_template(256 + index, field));
        }
        payload.extend_from_slice(&9_u16.to_be_bytes());
        payload.extend_from_slice(&4097_u16.to_be_bytes());
        payload.extend_from_slice(&1000_u32.to_be_bytes());
        payload.extend_from_slice(&1_700_000_000_u32.to_be_bytes());
        payload.extend_from_slice(&1_u32.to_be_bytes());
        payload.extend_from_slice(&7_u32.to_be_bytes());
        for set in &sets {
            payload.extend_from_slice(set);
        }
        let mut session = DecodeSession::new(DecodeOptions::default());
        let packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &payload));
        assert!(!packet.malformed);
        let evicted = session.decode(&frame(
            2,
            [192, 0, 2, 1],
            40_000,
            &v9_message(1, 2, 7, &[data_set(256, &[vec![10, 0, 0, 1]])]),
        ));
        assert!(has_field(&evicted, "cflow.no_template_found"));
        let retained = session.decode(&frame(
            3,
            [192, 0, 2, 1],
            40_000,
            &v9_message(1, 3, 7, &[data_set(4352, &[vec![10, 0, 0, 2]])]),
        ));
        assert!(has_field(&retained, "cflow.srcaddr"));
    }

    fn expected_sequence(packet: &crate::decode::Packet) -> Option<u64> {
        packet
            .tree
            .field_values("cflow.sequence_analysis.expected_sn")
            .into_iter()
            .find_map(|value| match value {
                Value::Uint32(value) => Some(u64::from(*value)),
                Value::Uint64(value) => Some(*value),
                _ => None,
            })
    }

    #[test]
    fn sequence_state_starts_only_from_an_accepted_template() {
        let mut session = DecodeSession::new(DecodeOptions::default());
        let short = v9_message(1, 1, 7, &[vec![0, 0, 0, 3]]);
        session.decode(&frame(1, [192, 0, 2, 1], 40_000, &short));
        let header = session.decode(&frame(2, [192, 0, 2, 1], 40_000, &v9_message(1, 9, 7, &[])));
        assert_eq!(expected_sequence(&header), None);

        let template = v9_message(1, 3, 7, &[v9_template(256, &[(8, 4)])]);
        session.decode(&frame(3, [192, 0, 2, 1], 40_000, &template));
        let gap = session.decode(&frame(4, [192, 0, 2, 1], 40_000, &v9_message(1, 9, 7, &[])));
        assert_eq!(expected_sequence(&gap), Some(4));
        assert!(has_field(&gap, "cflow.unexpected_sequence_number"));
    }

    #[test]
    fn sixty_one_field_templates_are_rejected() {
        let fields: Vec<(u16, u16)> = std::iter::repeat_n((8, 4), 61).collect();
        let record = vec![10_u8; 61 * 4];
        let payload = v9_message(
            2,
            1,
            7,
            &[
                v9_template(256, &fields),
                data_set(256, std::slice::from_ref(&record)),
            ],
        );
        let mut session = DecodeSession::new(DecodeOptions::default());
        let packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &payload));
        assert!(has_field(&packet, "cflow.entries.too_many"));
        assert!(has_field(&packet, "cflow.no_template_found"));
        assert!(!has_field(&packet, "cflow.srcaddr"));
    }

    #[test]
    fn zero_scope_ipfix_options_templates_are_not_cached() {
        let mut body = 257_u16.to_be_bytes().to_vec();
        body.extend_from_slice(&1_u16.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&8_u16.to_be_bytes());
        body.extend_from_slice(&4_u16.to_be_bytes());
        let template = ipfix_message(1, 42, &[set(3, body)]);
        let data = ipfix_message(2, 42, &[data_set(257, &[vec![1, 2, 3, 4]])]);
        let mut session = DecodeSession::new(DecodeOptions::default());
        let template_packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &template));
        assert!(has_field(
            &template_packet,
            "cflow.template_ipfix_scope_field_count.none"
        ));
        let packet = session.decode(&frame(2, [192, 0, 2, 1], 40_000, &data));
        assert!(has_field(&packet, "cflow.no_template_found"));
        assert!(!has_field(&packet, "cflow.srcaddr"));
    }

    #[test]
    fn option_field_caps_emit_scopes_and_options_markers() {
        let scopes: Vec<(u16, u16)> = std::iter::repeat_n((1, 4), 61).collect();
        let options: Vec<(u16, u16)> = std::iter::repeat_n((1, 4), 61).collect();
        let mut v9_body = Vec::new();
        v9_body.extend_from_slice(&300_u16.to_be_bytes());
        v9_body.extend_from_slice(&(61_u16 * 4).to_be_bytes());
        v9_body.extend_from_slice(&(61_u16 * 4).to_be_bytes());
        for (element, length) in scopes.iter().chain(&options) {
            v9_body.extend_from_slice(&element.to_be_bytes());
            v9_body.extend_from_slice(&length.to_be_bytes());
        }
        let v9 = v9_message(1, 1, 7, &[set(1, v9_body)]);
        let mut session = DecodeSession::new(DecodeOptions::default());
        let packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &v9));
        assert!(has_field(&packet, "cflow.scopes.too_many"));
        assert!(has_field(&packet, "cflow.options.too_many"));

        let mut ipfix_body = 300_u16.to_be_bytes().to_vec();
        ipfix_body.extend_from_slice(&122_u16.to_be_bytes());
        ipfix_body.extend_from_slice(&61_u16.to_be_bytes());
        for (element, length) in scopes.iter().chain(&options) {
            ipfix_body.extend_from_slice(&element.to_be_bytes());
            ipfix_body.extend_from_slice(&length.to_be_bytes());
        }
        let ipfix = ipfix_message(1, 42, &[set(3, ipfix_body)]);
        let mut session = DecodeSession::new(DecodeOptions::default());
        let packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &ipfix));
        assert!(has_field(&packet, "cflow.scopes.too_many"));
        assert!(has_field(&packet, "cflow.options.too_many"));
    }

    #[test]
    fn ntp_fractions_truncate() {
        let start = u32::try_from(395_812_u64).unwrap_or(0);
        for (fraction, nanos) in [
            (0x2000_0000_u32, 124_999_999_u32),
            (0x4000_0000, 249_999_999),
            (0x8000_0000, 499_999_999),
            (0x8000_0001, 500_000_000),
            (0x7fff_ffff, 499_999_999),
        ] {
            let raw = (u64::from(start) << 32) | u64::from(fraction);
            let bytes = raw.to_be_bytes();
            let timestamp = absolute_timestamp(&bytes, TimeScale::Microseconds);
            assert!(timestamp.is_some(), "the NTP bytes are valid");
            if let Some(timestamp) = timestamp {
                assert_eq!(timestamp.nanos, nanos, "fraction {fraction:#x}");
            }
        }
        let zero = absolute_timestamp(&0_u64.to_be_bytes(), TimeScale::Nanoseconds);
        assert_eq!(zero.map(|timestamp| timestamp.nanos), Some(0));
    }

    #[test]
    fn a_zero_budget_session_still_decodes_one_datagram() {
        let fields: &[(u16, u16)] = &[(8, 4)];
        let record = vec![10, 0, 0, 1];
        let payload = v9_message(
            2,
            1,
            7,
            &[
                v9_template(256, fields),
                data_set(256, std::slice::from_ref(&record)),
            ],
        );
        let mut session = DecodeSession::with_budget(DecodeOptions::default(), 0);
        let packet = session.decode(&frame(1, [192, 0, 2, 1], 40_000, &payload));
        assert!(has_field(&packet, "cflow.srcaddr"));
        assert_eq!(session.budget_used(), 0);
        let second = session.decode(&frame(
            2,
            [192, 0, 2, 1],
            40_000,
            &v9_message(1, 2, 7, &[data_set(256, &[record])]),
        ));
        assert!(has_field(&second, "cflow.no_template_found"));
    }
}
