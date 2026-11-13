//! HTTP/2 decoding behaviours the committed goldens cannot cover.
//!
//! A header block that spans HEADERS and CONTINUATION decodes once, at
//! END_HEADERS (RFC 7541 section 2.2), and a block that cannot be decompressed
//! keeps the fields already decoded and reports one malformed expert. Both
//! shapes differ from the recorded per-fragment output, so they are
//! asserted here instead of in a golden case.

use packetfin_core::DecodeSession;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{DecodeOptions, decode_frame};
use packetfin_core::tree::{Group, Node};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// One Ethernet/IPv4/TCP frame carrying `payload` to port 80.
fn frame(number: u64, sequence: u32, payload: &[u8]) -> Frame {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&40_000_u16.to_be_bytes());
    tcp.extend_from_slice(&80_u16.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&1_u32.to_be_bytes());
    tcp.extend_from_slice(&[0x50, 0x18]);
    tcp.extend_from_slice(&65535_u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(payload);
    let total = u16::try_from(20_usize.saturating_add(tcp.len())).unwrap_or(u16::MAX);
    let mut datagram = vec![0x45, 0];
    datagram.extend_from_slice(&total.to_be_bytes());
    datagram.extend_from_slice(&0_u16.to_be_bytes());
    datagram.extend_from_slice(&0x4000_u16.to_be_bytes());
    datagram.push(64);
    datagram.push(6);
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(&[192, 0, 2, 1]);
    datagram.extend_from_slice(&[192, 0, 2, 2]);
    datagram.extend_from_slice(&tcp);
    let mut captured = Vec::with_capacity(14 + datagram.len());
    captured.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
    captured.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    captured.extend_from_slice(&0x0800_u16.to_be_bytes());
    captured.extend_from_slice(&datagram);
    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured,
        original_len: u32::try_from(14_usize.saturating_add(datagram.len())).unwrap_or(u32::MAX),
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: None,
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: packetfin_core::capture::PacketOptions::default(),
    }
}

fn http2_nodes<'a>(node: &'a Node, collected: &mut Vec<&'a Node>) {
    if node.protocol.filter_name == "http2" {
        collected.push(node);
    }
    for child in &node.children {
        http2_nodes(child, collected);
    }
}

/// The `http2.stream` container of a node, when it has one.
fn stream_container(node: &Node) -> Option<&packetfin_core::tree::Field> {
    node.fields
        .iter()
        .find(|field| field.def.abbrev == "http2.stream")
}

fn has_child(node: &Node, abbrev: &str) -> bool {
    stream_container(node).is_some_and(|stream| {
        stream
            .children
            .iter()
            .any(|child| child.def.abbrev == abbrev)
    })
}

fn header_count(node: &Node) -> usize {
    stream_container(node).map_or(0, |stream| {
        stream
            .children
            .iter()
            .filter(|child| child.def.abbrev == "http2.header")
            .count()
    })
}

fn experts(node: &Node) -> usize {
    let mut count = node.experts.len();
    for field in &node.fields {
        count = count.saturating_add(field.experts.len());
        for child in &field.children {
            count = count.saturating_add(child.experts.len());
        }
    }
    for child in &node.children {
        count = count.saturating_add(experts(child));
    }
    count
}

#[test]
fn a_split_header_block_decodes_once_at_end_headers() {
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0, 1, &[0x82, 0x86, 0x84, 0x01, 0x0b]));
    let first_packet = session.decode_at(&frame(1, 1, &first), 1);
    let mut first_nodes = Vec::new();
    http2_nodes(&first_packet.tree.frame, &mut first_nodes);
    let headers = first_nodes
        .iter()
        .find(|node| has_child(node, "http2.headers"))
        .copied()
        .unwrap_or_else(|| unreachable!("the HEADERS frame decoded"));
    assert_eq!(header_count(headers), 0, "a partial block has no headers");
    assert_eq!(experts(headers), 0, "a buffered block is not an error");

    let mut second = h2_frame(9, 0x04, 1, b"example.com");
    second.extend_from_slice(&h2_frame(0, 0x01, 1, b"ok"));
    let sequence = 1_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
    let second_packet = session.decode_at(&frame(2, sequence, &second), 2);
    let mut second_nodes = Vec::new();
    http2_nodes(&second_packet.tree.frame, &mut second_nodes);
    let continuation = second_nodes
        .iter()
        .find(|node| has_child(node, "http2.continuation.header"))
        .copied()
        .unwrap_or_else(|| unreachable!("the CONTINUATION frame decoded"));
    assert_eq!(header_count(continuation), 4);
}

#[test]
fn an_invalid_huffman_code_keeps_the_fields_and_reports_one_expert() {
    let mut payload = PREFACE.to_vec();
    payload.extend_from_slice(&h2_frame(
        1,
        0x05,
        1,
        &[0x82, 0x86, 0x84, 0x00, 0x84, 0xff, 0xff, 0xff, 0xff],
    ));
    let packet = decode_frame(&frame(1, 1, &payload));
    assert!(packet.malformed);
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let headers = nodes
        .iter()
        .find(|node| has_child(node, "http2.headers"))
        .copied()
        .unwrap_or_else(|| unreachable!("HEADERS node"));
    assert_eq!(header_count(headers), 3, "headers before the error stay");
    assert_eq!(experts(headers), 1, "one expert explains the block");
    assert!(headers.has_expert(Group::Malformed));
}

#[test]
fn a_table_size_update_above_the_limit_is_malformed() {
    let mut payload = PREFACE.to_vec();
    // 0x3f 0xe1 0x3f encodes 8192, above the default 4096 limit.
    payload.extend_from_slice(&h2_frame(1, 0x05, 1, &[0x3f, 0xe1, 0x3f, 0x82]));
    let packet = decode_frame(&frame(1, 1, &payload));
    assert!(packet.malformed);
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let headers = nodes
        .iter()
        .find(|node| has_child(node, "http2.headers"))
        .copied()
        .unwrap_or_else(|| unreachable!("HEADERS node"));
    assert_eq!(header_count(headers), 0);
    assert_eq!(experts(headers), 1);
}

#[test]
fn two_pass_records_the_request_response_links() {
    let mut session = DecodeSession::with_pass(
        DecodeOptions::default(),
        packetfin_core::DEFAULT_STATE_BUDGET,
        packetfin_core::PassMode::First,
    );
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x82, 0x86, 0x84]));
    let _ = session.decode_at(&frame(1, 1, &first), 1);
    let mut second = h2_frame(1, 0x05, 1, &[0x88]);
    second.extend_from_slice(&h2_frame(7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]));
    let sequence = 1_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
    let _ = session.decode_at(&frame(2, sequence, &second), 2);
    let request = session
        .annotations()
        .get(1)
        .unwrap_or_else(|| unreachable!("request annotation"));
    assert_eq!(request.response_in, 2);
    let response = session
        .annotations()
        .get(2)
        .unwrap_or_else(|| unreachable!("response annotation"));
    assert_eq!(response.request_in, 1);
    assert!(response.time_present());
}

#[test]
fn a_continuation_on_another_stream_is_reported() {
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(1, 0, 1, &[0x82]));
    let _ = session.decode_at(&frame(1, 1, &first), 1);
    let second = h2_frame(9, 0x04, 3, &[0x86]);
    let sequence = 1_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
    let packet = session.decode_at(&frame(2, sequence, &second), 2);
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let continuation = nodes
        .iter()
        .find(|node| has_child(node, "http2.continuation.header"))
        .copied()
        .unwrap_or_else(|| unreachable!("CONTINUATION node"));
    assert!(continuation.has_expert(Group::Protocol));
    assert_eq!(header_count(continuation), 1);
}
