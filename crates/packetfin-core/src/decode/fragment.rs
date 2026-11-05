//! Reassembled fragment field containers.
//!
//! A completed datagram is reported as one container on the IP protocol:
//! the reassembled bytes, one record per fragment in offset order, the
//! fragment count, and the reassembled length and data. IPv4 uses a bytes
//! container; IPv6 uses a value-less container. A fragment with conflicting
//! overlap, several tails or data past the datagram end is reported through
//! `*.fragment.error` instead of `*.fragment`.

use crate::decode::hex_lower;
use crate::fields::{self, FieldDef, FieldType};
use crate::state::{FragmentRecord, Reassembly};
use crate::tree::{Bytes, Node, Range, RawField, RawSource, Value};

/// Numeric type code for `FT_BYTES` in raw arrays.
const FT_BYTES: u32 = 30;

/// Numeric type code for `FT_FRAMENUM` in raw arrays.
const FT_FRAMENUM: u32 = 35;

/// Numeric type code for `FT_UINT32` in raw arrays.
const FT_UINT32: u32 = 7;

struct FragmentDefs {
    container: &'static FieldDef,
    fragment: &'static FieldDef,
    error: &'static FieldDef,
    count: &'static FieldDef,
    length: &'static FieldDef,
    data: &'static FieldDef,
    overlap: &'static FieldDef,
    conflict: &'static FieldDef,
    multipletails: &'static FieldDef,
    toolongfragment: &'static FieldDef,
    family: &'static str,
}

static IPV4_DEFS: FragmentDefs = FragmentDefs {
    container: &fields::IP_FRAGMENTS,
    fragment: &fields::IP_FRAGMENT,
    error: &fields::IP_FRAGMENT_ERROR,
    count: &fields::IP_FRAGMENT_COUNT,
    length: &fields::IP_REASSEMBLED_LENGTH,
    data: &fields::IP_REASSEMBLED_DATA,
    overlap: &fields::IP_FRAGMENT_OVERLAP,
    conflict: &fields::IP_FRAGMENT_OVERLAP_CONFLICT,
    multipletails: &fields::IP_FRAGMENT_MULTIPLETAILS,
    toolongfragment: &fields::IP_FRAGMENT_TOOLONGFRAGMENT,
    family: "IPv4",
};

static IPV6_DEFS: FragmentDefs = FragmentDefs {
    container: &fields::IPV6_FRAGMENTS,
    fragment: &fields::IPV6_FRAGMENT,
    error: &fields::IPV6_FRAGMENT_ERROR,
    count: &fields::IPV6_FRAGMENT_COUNT,
    length: &fields::IPV6_REASSEMBLED_LENGTH,
    data: &fields::IPV6_REASSEMBLED_DATA,
    overlap: &fields::IPV6_FRAGMENT_OVERLAP,
    conflict: &fields::IPV6_FRAGMENT_OVERLAP_CONFLICT,
    multipletails: &fields::IPV6_FRAGMENT_MULTIPLETAILS,
    toolongfragment: &fields::IPV6_FRAGMENT_TOOLONGFRAGMENT,
    family: "IPv6",
};

/// Give every byte-backed field decoded from `data` its own raw source.
///
/// A transport (or inner IP) decoder only records frame-relative ranges.
/// Fields below `nodes` were decoded from the reassembled buffer at base
/// zero, so their bytes must not be read from the completing frame.
pub(crate) fn annotate_reassembled_fields(nodes: &mut [Node], data: &[u8]) {
    let source: std::sync::Arc<[u8]> = data.into();
    for node in nodes {
        annotate_node(node, &source);
    }
}

fn annotate_node(node: &mut Node, source: &std::sync::Arc<[u8]>) {
    node.source = Some(std::sync::Arc::clone(source));
    for child in &mut node.children {
        annotate_node(child, source);
    }
}

/// Add the IPv4 reassembly container to the `ip` node.
pub(crate) fn add_ipv4_fields(node: &mut Node, base: usize, reassembly: &Reassembly) {
    add_fields(node, base, reassembly, &IPV4_DEFS);
}

/// Add the IPv6 reassembly container to the `ipv6` node.
pub(crate) fn add_ipv6_fields(node: &mut Node, base: usize, reassembly: &Reassembly) {
    add_fields(node, base, reassembly, &IPV6_DEFS);
}

fn add_fields(node: &mut Node, base: usize, reassembly: &Reassembly, defs: &FragmentDefs) {
    let labels: Vec<String> = reassembly
        .parts
        .iter()
        .map(|part| format!("#{}({})", part.frame, part.data.len()))
        .collect();
    let container_label = format!(
        "{} {} Fragments ({} bytes): {}",
        reassembly.parts.len(),
        defs.family,
        reassembly.total_len,
        labels.join(", ")
    );
    let range = Range::new(base, reassembly.total_len);
    let container = node.add_container(defs.container, range, Some(container_label));
    let (value, field_type) = if defs.container.field_type == FieldType::None {
        (Value::None, 0)
    } else {
        (Value::bytes(reassembly.data.clone()), FT_BYTES)
    };
    container.value = value;
    container.raw = Some(raw(
        reassembly.data.clone(),
        0,
        reassembly.total_len,
        field_type,
    ));

    for part in &reassembly.parts {
        let label = part_label(part);
        let definition = if part.is_error() {
            defs.error
        } else {
            defs.fragment
        };
        let frame = u32::try_from(part.frame).unwrap_or(u32::MAX);
        let range = Range::new(part.offset, part.data.len());
        let has_flags = part.flags.overlap
            || part.flags.conflict
            || part.flags.multipletails
            || part.flags.toolongfragment;
        let entry = if has_flags {
            let entry = container.add_container(definition, range, Some(label));
            entry.value = Value::Uint32(frame);
            entry
        } else {
            let entry = container.add_field(definition, range, Value::Uint32(frame));
            entry.showname = Some(label);
            entry
        };
        entry.raw = Some(raw(
            record_bytes(part, reassembly),
            part.offset,
            part.data.len(),
            FT_FRAMENUM,
        ));
        if part.flags.overlap {
            add_flag(entry, defs.overlap, part.offset);
        }
        if part.flags.conflict {
            add_flag(entry, defs.conflict, part.offset);
        }
        if part.flags.multipletails {
            add_flag(entry, defs.multipletails, part.offset);
        }
        if part.flags.toolongfragment {
            add_flag(entry, defs.toolongfragment, part.offset);
        }
    }

    let count = u32::try_from(reassembly.parts.len()).unwrap_or(u32::MAX);
    let length = u32::try_from(reassembly.total_len).unwrap_or(u32::MAX);
    let count_field = container.add_field(defs.count, Range::default(), Value::Uint32(count));
    count_field.showname = Some(format!("Fragment count: {count}"));
    count_field.raw = Some(generated_raw(FT_UINT32));
    let length_field = container.add_field(defs.length, Range::default(), Value::Uint32(length));
    length_field.showname = Some(format!("Reassembled {} length: {length}", defs.family));
    length_field.raw = Some(generated_raw(FT_UINT32));
    let data_field = container.add_field(
        defs.data,
        Range::new(0, reassembly.total_len),
        Value::bytes(reassembly.data.clone()),
    );
    data_field.showname = Some(data_label(defs.family, &reassembly.data));
    data_field.raw = Some(raw(
        reassembly.data.clone(),
        0,
        reassembly.total_len,
        FT_BYTES,
    ));
}

/// A fragment record's bytes from the merged payload.
///
/// An overlapping record shows the first-arrived bytes. A record that extends
/// past the total keeps its own captured prefix, which full PDML output shows.
fn record_bytes(part: &FragmentRecord, reassembly: &Reassembly) -> Vec<u8> {
    let end = part
        .offset
        .saturating_add(part.data.len())
        .min(reassembly.total_len);
    match reassembly.data.get(part.offset..end) {
        Some(bytes) if bytes.len() == part.data.len() => bytes.to_vec(),
        _ => part.data.clone(),
    }
}

/// The reassembled-data label, which prints at most 105 bytes.
fn data_label(family: &str, data: &[u8]) -> String {
    const SHOWN: usize = 105;
    match data.get(..SHOWN) {
        Some(prefix) if data.len() > SHOWN => {
            format!("Reassembled {family} data […]: {}", hex_lower(prefix))
        }
        _ => format!("Reassembled {family} data: {}", hex_lower(data)),
    }
}

fn add_flag(entry: &mut crate::tree::Field, definition: &'static FieldDef, offset: usize) {
    entry.add_field(definition, Range::new(offset, 0), Value::Boolean(true));
}

fn part_label(part: &FragmentRecord) -> String {
    let length = part.data.len();
    if length == 0 {
        return format!("Frame: {}, payload: {} (0 bytes)", part.frame, part.offset);
    }
    let end = part.offset.saturating_add(length).saturating_sub(1);
    format!(
        "Frame: {}, payload: {}-{} ({} bytes)",
        part.frame, part.offset, end, length
    )
}

fn raw(bytes: Vec<u8>, start: usize, length: usize, field_type: u32) -> RawField {
    RawField {
        bytes: bytes.into(),
        start,
        length,
        bitmask: 0,
        field_type,
        source: RawSource::Frame,
    }
}

fn generated_raw(field_type: u32) -> RawField {
    RawField {
        bytes: Bytes::default(),
        start: 0,
        length: 0,
        bitmask: 0,
        field_type,
        source: RawSource::Frame,
    }
}
