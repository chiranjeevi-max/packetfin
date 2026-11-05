//! Trees shared by the output renderer unit tests.
//!
//! The definitions mirror decoder containers without adding
//! production fields; each renderer builds its packet from these.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{Columns, Packet};
use packetfin_core::fields::{self, Display, FieldDef, FieldType};
use packetfin_core::tree::{
    Bytes, ExpertInfo, Group, Node, Range, RawField, RawSource, Severity, Tree, Value,
};

pub(crate) static ANALYSIS: FieldDef = FieldDef {
    abbrev: "tcp.analysis",
    name: "SEQ/ACK analysis",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static ANALYSIS_ACKS_FRAME: FieldDef = FieldDef {
    abbrev: "tcp.analysis.acks_frame",
    name: "This is an ACK to the segment in frame",
    field_type: FieldType::Uint32,
    parent: "tcp.analysis",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static ANALYSIS_FLAGS: FieldDef = FieldDef {
    abbrev: "tcp.analysis.flags",
    name: "TCP Analysis Flags",
    field_type: FieldType::None,
    parent: "tcp.analysis",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static ANALYSIS_RTO: FieldDef = FieldDef {
    abbrev: "tcp.analysis.rto",
    name: "The RTO for this segment was",
    field_type: FieldType::Uint32,
    parent: "tcp.analysis",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static ANALYSIS_RETRANSMISSION: FieldDef = FieldDef {
    abbrev: "tcp.analysis.retransmission",
    name: "This frame is a (suspected) retransmission",
    field_type: FieldType::None,
    parent: "tcp.analysis",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static COMPLETENESS: FieldDef = FieldDef {
    abbrev: "tcp.completeness",
    name: "Conversation completeness",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static SEGMENTS: FieldDef = FieldDef {
    abbrev: "tcp.segments",
    name: "Reassembled TCP Segments",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static SEGMENT: FieldDef = FieldDef {
    abbrev: "tcp.segment",
    name: "TCP Segment",
    field_type: FieldType::Uint32,
    parent: "tcp.segments",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static SEGMENT_COUNT: FieldDef = FieldDef {
    abbrev: "tcp.segment.count",
    name: "Segment count",
    field_type: FieldType::Uint32,
    parent: "tcp.segments",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static IP_FRAGMENTS: FieldDef = FieldDef {
    abbrev: "ip.fragments",
    name: "IPv4 Fragments",
    field_type: FieldType::Bytes,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};
pub(crate) static IP_FRAGMENT: FieldDef = FieldDef {
    abbrev: "ip.fragment",
    name: "IPv4 Fragment",
    field_type: FieldType::Uint32,
    parent: "ip.fragments",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

fn raw(
    bytes: impl Into<Bytes>,
    start: usize,
    length: usize,
    field_type: u32,
    source: RawSource,
) -> RawField {
    RawField {
        bytes: bytes.into(),
        start,
        length,
        bitmask: 0,
        field_type,
        source,
    }
}

pub(crate) fn frame() -> Frame {
    Frame {
        number: 5,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_004,
            nanos: 0,
        }),
        timestamp_precision: 9,
        captured: vec![0_u8; 64],
        original_len: 64,
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: Some(0),
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: Default::default(),
    }
}

pub(crate) fn packet(tree: Tree) -> Packet {
    Packet {
        tree,
        columns: Columns::default(),
        protocol_stack: Vec::new(),
        malformed: false,
        network: None,
        forced_data: false,
        resolution: packetfin_core::NameResolution::default(),
        data_sources: Vec::new(),
        data_source_kinds: Vec::new(),
    }
}

pub(crate) fn tcp_tree(build: impl FnOnce(&mut Node)) -> Tree {
    let mut frame_node = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 64));
    frame_node.add_field(&fields::FRAME_NUMBER, Range::new(0, 0), Value::Uint32(5));
    let mut tcp = Node::new(&fields::TCP_PROTOCOL, Range::new(34, 20));
    tcp.add_field(&fields::TCP_SEQ, Range::new(38, 4), Value::Uint32(1));
    build(&mut tcp);
    frame_node.add_child(tcp);
    Tree::new(frame_node)
}

pub(crate) fn ip_tree(build: impl FnOnce(&mut Node)) -> Tree {
    let mut frame_node = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, 64));
    frame_node.add_field(&fields::FRAME_NUMBER, Range::new(0, 0), Value::Uint32(5));
    let mut ip = Node::new(&fields::IP_PROTOCOL, Range::new(14, 20));
    build(&mut ip);
    frame_node.add_child(ip);
    Tree::new(frame_node)
}

pub(crate) fn analysis_tree() -> Tree {
    tcp_tree(|tcp| {
        let container = tcp.add_container(
            &ANALYSIS,
            Range::new(34, 0),
            Some("SEQ/ACK analysis".to_string()),
        );
        container.raw = Some(raw(Vec::new(), 34, 0, 0, RawSource::Field));
        container.add_field(&ANALYSIS_ACKS_FRAME, Range::new(34, 0), Value::Uint32(1));
        let flags = container.add_container(
            &ANALYSIS_FLAGS,
            Range::new(34, 0),
            Some("TCP Analysis Flags".to_string()),
        );
        flags.raw = Some(raw(Vec::new(), 34, 0, 0, RawSource::Field));
        let retransmission =
            flags.add_field(&ANALYSIS_RETRANSMISSION, Range::new(34, 0), Value::None);
        retransmission.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Sequence,
            message: "This frame is a (suspected) retransmission".to_string(),
        });
        retransmission.raw = Some(raw(Vec::new(), 0, 0, 0, RawSource::None));
        flags.add_field(&ANALYSIS_RTO, Range::new(34, 0), Value::Uint32(1));
    })
}

pub(crate) fn completeness_tree() -> Tree {
    tcp_tree(|tcp| {
        let container = tcp.add_container(&COMPLETENESS, Range::new(34, 0), None);
        container.value = Value::Uint32(15);
        container.raw = Some(raw(Vec::new(), 0, 0, 4, RawSource::None));
    })
}

pub(crate) fn segments_tree() -> Tree {
    tcp_tree(|tcp| {
        let pdu: Vec<u8> = (0..31).map(|index| index as u8).collect();
        let container = tcp.add_container(
            &SEGMENTS,
            Range::new(0, 31),
            Some("2 Reassembled TCP Segments (31 bytes): #4(10), #5(21)".to_string()),
        );
        container.raw = Some(raw(pdu.clone(), 0, 31, 0, RawSource::Frame));
        let first = container.add_field(&SEGMENT, Range::new(0, 10), Value::Uint32(4));
        first.raw = Some(raw(
            pdu.get(..10).unwrap_or_default().to_vec(),
            0,
            10,
            35,
            RawSource::Frame,
        ));
        let second = container.add_field(&SEGMENT, Range::new(10, 21), Value::Uint32(5));
        second.raw = Some(raw(
            pdu.get(10..).unwrap_or_default().to_vec(),
            10,
            21,
            35,
            RawSource::Frame,
        ));
        let count = container.add_field(&SEGMENT_COUNT, Range::new(0, 0), Value::Uint32(2));
        count.raw = Some(raw(Vec::new(), 0, 0, 7, RawSource::Frame));
    })
}

pub(crate) fn fragments_tree() -> Tree {
    ip_tree(|ip| {
        let bytes: Vec<u8> = (0..32).map(|index| index as u8).collect();
        let container = ip.add_container(
            &IP_FRAGMENTS,
            Range::new(14, 32),
            Some("2 IPv4 Fragments (32 bytes): #1(16), #2(16)".to_string()),
        );
        container.value = Value::bytes(bytes.clone());
        container.raw = Some(raw(bytes.clone(), 0, 32, 30, RawSource::Frame));
        let first = container.add_field(&IP_FRAGMENT, Range::new(0, 16), Value::Uint32(1));
        first.raw = Some(raw(
            bytes.get(..16).unwrap_or_default().to_vec(),
            0,
            16,
            35,
            RawSource::Frame,
        ));
        let second = container.add_field(&IP_FRAGMENT, Range::new(16, 16), Value::Uint32(2));
        second.raw = Some(raw(
            bytes.get(16..).unwrap_or_default().to_vec(),
            16,
            16,
            35,
            RawSource::Frame,
        ));
    })
}
