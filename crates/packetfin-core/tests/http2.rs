//! HTTP/2 decoding behaviours the committed goldens cannot cover.
//!
//! A header block that spans HEADERS and CONTINUATION decodes once, at
//! END_HEADERS (RFC 7541 section 2.2), and a block that cannot be decompressed
//! keeps the fields already decoded and reports one malformed expert. Both
//! shapes differ from the recorded per-fragment output, so they are
//! asserted here instead of in a golden case.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{DecodeOptions, decode_frame, parse_decode_as};
use packetfin_core::tree::{Group, Node};
use packetfin_core::{DecodeSession, KeyLog};

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
fn a_table_size_update_after_a_header_is_malformed() {
    let mut payload = PREFACE.to_vec();
    payload.extend_from_slice(&h2_frame(1, 0x05, 1, &[0x82, 0x20, 0x86, 0x84]));
    let packet = decode_frame(&frame(1, 1, &payload));
    assert!(packet.malformed);
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let headers = nodes
        .iter()
        .find(|node| has_child(node, "http2.headers"))
        .copied()
        .unwrap_or_else(|| unreachable!("HEADERS node"));
    assert_eq!(
        header_count(headers),
        1,
        "the header before the update stays"
    );
    assert_eq!(experts(headers), 1, "one expert explains the block");
    assert!(headers.has_expert(Group::Malformed));
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
    assert_eq!(
        header_count(continuation),
        0,
        "a fragment with no open block is not decoded"
    );
}

#[test]
fn a_frame_with_a_mandatory_length_violation_is_malformed() {
    let cases: [(&str, u8, u8, u32, &[u8]); 8] = [
        ("PING with six octets", 6, 0, 0, &[0; 6]),
        ("RST_STREAM with three octets", 3, 0, 1, &[0; 3]),
        ("SETTINGS ACK with a payload", 4, 0x01, 0, &[0; 6]),
        ("SETTINGS on a stream", 4, 0, 1, &[]),
        ("WINDOW_UPDATE with three octets", 8, 0, 0, &[0; 3]),
        ("PRIORITY with four octets", 2, 0, 1, &[0; 4]),
        ("GOAWAY with four octets", 7, 0, 0, &[0; 4]),
        ("DATA on stream zero", 0, 0, 0, &[]),
    ];
    for (name, kind, flags, stream, payload) in cases {
        let mut bytes = PREFACE.to_vec();
        bytes.extend_from_slice(&h2_frame(kind, flags, stream, payload));
        let packet = decode_frame(&frame(1, 1, &bytes));
        assert!(packet.malformed, "{name} must be malformed");
        let mut nodes = Vec::new();
        http2_nodes(&packet.tree.frame, &mut nodes);
        let node = nodes
            .last()
            .copied()
            .unwrap_or_else(|| unreachable!("frame node"));
        assert_eq!(experts(node), 1, "{name} reports one expert");
        assert!(
            has_child(node, "http2.length") && has_child(node, "http2.type"),
            "{name} keeps the frame header fields"
        );
    }
}

#[test]
fn headers_on_stream_zero_gets_a_protocol_expert() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&h2_frame(1, 0x04, 0, &[0x82]));
    let packet = decode_frame(&frame(1, 1, &bytes));
    assert!(
        !packet.malformed,
        "the frame keeps decoding, as the expected output does"
    );
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("frame node"));
    assert_eq!(header_count(node), 1, "the header block still decodes");
    assert_eq!(experts(node), 1, "one standards expert is reported");
    assert!(node.has_expert(Group::Protocol));
}

#[test]
fn a_continuation_on_stream_zero_keeps_the_orphan_diagnostic() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&h2_frame(9, 0x04, 0, &[0x82]));
    let packet = decode_frame(&frame(1, 1, &bytes));
    assert!(!packet.malformed, "a header-block violation is a warning");
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("frame node"));
    assert_eq!(
        header_count(node),
        0,
        "a fragment with no open block is not decoded"
    );
    assert_eq!(
        experts(node),
        2,
        "stream zero and the missing block each report once"
    );
    assert!(node.has_expert(Group::Protocol));
}

#[test]
fn an_orphan_continuation_does_not_reach_the_table() {
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(9, 0x04, 1, &[0x82]));
    let packet = session.decode_at(&frame(1, 1, &first), 1);
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let continuation = nodes
        .iter()
        .find(|node| has_child(node, "http2.continuation.header"))
        .copied()
        .unwrap_or_else(|| unreachable!("CONTINUATION node"));
    assert_eq!(
        header_count(continuation),
        0,
        "the orphan fragment is not decoded"
    );
    assert!(continuation.has_expert(Group::Protocol));
    // The missing block's mutations are unknown, so a later dynamic index
    // reports the desynchronized table instead of resolving an entry.
    let indexed = h2_frame(1, 0x04, 3, &[0xbe]);
    let sequence = 1_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
    let packet = session.decode_at(&frame(2, sequence, &indexed), 2);
    let mut later = Vec::new();
    http2_nodes(&packet.tree.frame, &mut later);
    let node = later
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("frame node"));
    assert_eq!(header_count(node), 0, "the dynamic index does not resolve");
    assert!(node.has_expert(Group::Undecoded));
}

#[test]
fn observe_only_frames_do_not_create_request_response_links() {
    // A request decoded only to advance reassembly must not answer a later
    // displayed response.
    let mut session = DecodeSession::with_pass(
        DecodeOptions::default(),
        packetfin_core::DEFAULT_STATE_BUDGET,
        packetfin_core::PassMode::First,
    );
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x82, 0x86, 0x84]));
    let _ = session.decode_observation(&frame(1, 1, &first), 1);
    let response = h2_frame(1, 0x04, 1, &[0x88]);
    let sequence = 1_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
    let packet = session.decode_at(&frame(2, sequence, &response), 2);
    assert!(
        stream_with(&packet, "http2.request_in").is_none(),
        "an observed request leaves the response unlinked"
    );
    assert!(
        session
            .annotations()
            .get(1)
            .is_none_or(|annotation| annotation.response_in == 0),
        "the observed request records no response"
    );

    // A response decoded only to advance reassembly must not link back to a
    // displayed request either.
    let mut session = DecodeSession::with_pass(
        DecodeOptions::default(),
        packetfin_core::DEFAULT_STATE_BUDGET,
        packetfin_core::PassMode::First,
    );
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x82, 0x86, 0x84]));
    let _ = session.decode_at(&frame(1, 1, &first), 1);
    let response = h2_frame(1, 0x04, 1, &[0x88]);
    let sequence = 1_u32.saturating_add(u32::try_from(first.len()).unwrap_or(0));
    let observed = session.decode_observation(&frame(2, sequence, &response), 2);
    assert!(
        stream_with(&observed, "http2.request_in").is_none(),
        "the observed response reports no request link"
    );
    assert!(
        session
            .annotations()
            .get(1)
            .is_none_or(|annotation| annotation.response_in == 0),
        "the displayed request records no response"
    );
    assert!(
        session
            .annotations()
            .get(2)
            .is_none_or(|annotation| annotation.request_in == 0),
        "the observed response records no request"
    );

    // Both PUSH_PROMISE completion paths: END_HEADERS on the PUSH_PROMISE
    // itself and END_HEADERS on a CONTINUATION.
    for fragmented in [false, true] {
        let mut session = DecodeSession::with_pass(
            DecodeOptions::default(),
            packetfin_core::DEFAULT_STATE_BUDGET,
            packetfin_core::PassMode::First,
        );
        let mut preface = PREFACE.to_vec();
        preface.extend_from_slice(&h2_frame(4, 0, 0, &[]));
        let mut sequence = 1_u32;
        let _ = session.decode_observation(&frame(1, sequence, &preface), 1);
        sequence = sequence.saturating_add(u32::try_from(preface.len()).unwrap_or(0));
        let mut promise = 2_u32.to_be_bytes().to_vec();
        if fragmented {
            promise.extend_from_slice(&[0x82]);
        } else {
            promise.extend_from_slice(&[0x82, 0x86, 0x84]);
        }
        let flags = if fragmented { 0 } else { 0x04 };
        let push = h2_frame(5, flags, 1, &promise);
        let _ = session.decode_observation(&frame(2, sequence, &push), 2);
        sequence = sequence.saturating_add(u32::try_from(push.len()).unwrap_or(0));
        if fragmented {
            let continuation = h2_frame(9, 0x04, 1, &[0x86, 0x84]);
            let _ = session.decode_observation(&frame(3, sequence, &continuation), 3);
            sequence = sequence.saturating_add(u32::try_from(continuation.len()).unwrap_or(0));
        }
        let response = h2_frame(1, 0x04, 2, &[0x88]);
        let packet = session.decode_at(&frame(4, sequence, &response), 4);
        assert!(
            stream_with(&packet, "http2.request_in").is_none(),
            "an observed PUSH_PROMISE ({fragmented}) records no promise"
        );
    }
}

#[test]
fn a_fragmented_push_promise_keeps_its_headers_and_promise() {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    let mut push = 2_u32.to_be_bytes().to_vec();
    push.extend_from_slice(&[0x82, 0x86]);
    first.extend_from_slice(&h2_frame(5, 0, 1, &push));
    let _ = session.decode_at(&frame_between(1, 1, client, server, &first), 1);

    let continuation = h2_frame(9, 0x04, 1, &[0x84]);
    let sequence = 1 + u32::try_from(first.len()).unwrap_or(0);
    let packet = session.decode_at(
        &frame_between(2, sequence, client, server, &continuation),
        2,
    );
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .iter()
        .find(|node| has_child(node, "http2.continuation.header"))
        .copied()
        .unwrap_or_else(|| unreachable!("CONTINUATION node"));
    assert_eq!(
        header_count(node),
        3,
        "the pending promise block stays whole"
    );
    assert_eq!(experts(node), 0, "the continuation belongs to the promise");

    let response = h2_frame(1, 0x04, 2, &[0x88]);
    let reply = session.decode_at(&frame_between(3, 1, server, client, &response), 3);
    let stream = stream_with(&reply, "http2.request_in")
        .unwrap_or_else(|| unreachable!("the response links to the promise"));
    assert_eq!(
        child_value(stream, "http2.request_in").as_deref(),
        Some("1"),
        "the promised request belongs to the PUSH_PROMISE frame"
    );
}

#[test]
fn a_forced_http2_port_reassembles_a_split_headers_frame() {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 8080);
    let mut options = DecodeOptions::default();
    parse_decode_as("tcp.port==8080,http2", &mut options.decode_as)
        .unwrap_or_else(|_| unreachable!("a valid decode-as entry"));
    let mut session = DecodeSession::new(options);

    let headers = h2_frame(
        1,
        0x05,
        1,
        &[
            0x82, 0x86, 0x84, 0x41, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm',
        ],
    );
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(headers.get(..14).unwrap_or_default());
    let first_packet = session.decode_at(&frame_between(1, 1, client, server, &first), 1);
    assert!(
        !first_packet.malformed,
        "a split forced frame is not malformed"
    );
    let mut first_nodes = Vec::new();
    http2_nodes(&first_packet.tree.frame, &mut first_nodes);
    assert!(
        first_nodes
            .iter()
            .all(|node| !has_child(node, "http2.headers")),
        "the header block waits for its last byte"
    );

    let second = headers.get(14..).unwrap_or_default().to_vec();
    let sequence = 1 + u32::try_from(first.len()).unwrap_or(0);
    let packet = session.decode_at(&frame_between(2, sequence, client, server, &second), 2);
    assert!(!packet.malformed, "the reassembled frame is valid");
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .iter()
        .find(|node| has_child(node, "http2.headers"))
        .copied()
        .unwrap_or_else(|| unreachable!("the reassembled HEADERS frame"));
    assert_eq!(header_count(node), 4);
}

/// One Ethernet/IPv4/TCP frame between explicit endpoints.
fn frame_between(
    number: u64,
    sequence: u32,
    source: ([u8; 4], u16),
    destination: ([u8; 4], u16),
    payload: &[u8],
) -> Frame {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&source.1.to_be_bytes());
    tcp.extend_from_slice(&destination.1.to_be_bytes());
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
    datagram.extend_from_slice(&source.0);
    datagram.extend_from_slice(&destination.0);
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

/// The rendered `http2.data.data` values of one packet, in frame order.
fn data_values(packet: &packetfin_core::Packet) -> Vec<String> {
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let mut values = Vec::new();
    for node in nodes {
        let Some(stream) = stream_container(node) else {
            continue;
        };
        for child in &stream.children {
            if child.def.abbrev == "http2.data.data" {
                values.push(child.value.render(child.def.display));
            }
        }
    }
    values
}

#[test]
fn request_and_response_bodies_do_not_merge() {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x82, 0x86, 0x84]));
    let _ = session.decode_at(&frame_between(1, 1, client, server, &first), 1);
    let mut response = h2_frame(4, 0, 0, &[]);
    response.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x88]));
    let _ = session.decode_at(&frame_between(2, 1, server, client, &response), 2);
    let request_data = h2_frame(0, 0, 1, b"A");
    let _ = session.decode_at(
        &frame_between(
            3,
            1 + u32::try_from(first.len()).unwrap_or(0),
            client,
            server,
            &request_data,
        ),
        3,
    );
    let response_data = h2_frame(0, 0, 1, b"B");
    let _ = session.decode_at(
        &frame_between(
            4,
            1 + u32::try_from(response.len()).unwrap_or(0),
            server,
            client,
            &response_data,
        ),
        4,
    );
    let end_request = h2_frame(0, 0x01, 1, b"C");
    let request = session.decode_at(
        &frame_between(
            5,
            1 + u32::try_from(first.len().saturating_add(request_data.len())).unwrap_or(0),
            client,
            server,
            &end_request,
        ),
        5,
    );
    let end_response = h2_frame(0, 0x01, 1, b"D");
    let reply = session.decode_at(
        &frame_between(
            6,
            1 + u32::try_from(response.len().saturating_add(response_data.len())).unwrap_or(0),
            server,
            client,
            &end_response,
        ),
        6,
    );
    assert_eq!(
        data_values(&request),
        vec!["4143"],
        "the request body is A and C"
    );
    assert_eq!(
        data_values(&reply),
        vec!["4244"],
        "the response body is B and D"
    );
}

#[test]
fn a_tiny_fragment_flood_keeps_the_body_and_bounds_the_views() {
    let frames = 300_usize;
    let mut payload = PREFACE.to_vec();
    payload.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    payload.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x82, 0x86, 0x84]));
    for index in 0..frames {
        let end = if index + 1 == frames { 0x01 } else { 0 };
        payload.extend_from_slice(&h2_frame(0, end, 1, b"x"));
    }
    let packet = decode_frame(&frame(1, 1, &payload));
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let completing = nodes
        .iter()
        .find(|node| has_child(node, "http2.body.fragments"))
        .copied()
        .unwrap_or_else(|| unreachable!("the completing frame carries the body"));
    let stream = stream_container(completing).unwrap_or_else(|| unreachable!("stream container"));
    let views = stream
        .children
        .iter()
        .find(|child| child.def.abbrev == "http2.body.fragments")
        .map_or(0, |container| {
            container
                .children
                .iter()
                .filter(|child| child.def.abbrev == "http2.body.fragment")
                .count()
        });
    assert_eq!(views, 256, "the 300 fragment views are capped at 256");
    let body = stream
        .children
        .iter()
        .find(|child| child.def.abbrev == "http2.data.data")
        .unwrap_or_else(|| unreachable!("the body is printed"));
    assert_eq!(body.value.render(body.def.display).len(), frames * 2);
    assert!(
        stream
            .experts
            .iter()
            .any(|expert| expert.message.contains("fragment views retained")),
        "truncation is reported once"
    );
}

/// Build the TLS 1.2 GCM records of a connection that negotiated `h2`.
///
/// The hello carries ALPN `h2`; the application records carry the connection
/// preface and frames in both directions, so the decrypted plaintext must be
/// framed as HTTP/2 rather than HTTP/1.x.
fn tls12_h2_records() -> (String, Vec<(bool, Vec<u8>)>) {
    let mut client_h2 = PREFACE.to_vec();
    client_h2.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    client_h2.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x82, 0x86, 0x84]));
    let mut server_h2 = h2_frame(4, 0, 0, &[]);
    server_h2.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x88]));
    server_h2.extend_from_slice(&h2_frame(0, 0x01, 1, b"hi"));
    let client_body = h2_frame(0, 0x01, 1, b"ok");
    tls12_alpn_records(
        vec![0, 3, 2, b'h', b'2'],
        vec![0, 3, 2, b'h', b'2'],
        &client_h2,
        &server_h2,
        &client_body,
    )
}

/// One TLS 1.2 exchange with the offered and selected ALPN protocol.
fn tls12_alpn_records(
    client_alpn: Vec<u8>,
    server_alpn: Vec<u8>,
    client_app: &[u8],
    server_app: &[u8],
    client_body: &[u8],
) -> (String, Vec<(bool, Vec<u8>)>) {
    use packetfin_testkit::tls;
    let mut writer = tls::Tls12Writer::new(0xc030, false);
    let client_extensions = vec![(16, client_alpn)];
    let client_hello = tls::client_hello(
        tls::TLS12_VERSION,
        writer.client_random(),
        &[],
        &[0xc030],
        &client_extensions,
    );
    // RFC 7301 section 3.2: the server's selection, not the client offer,
    // decides the application protocol.
    let server_hello = tls::server_hello(
        tls::TLS12_VERSION,
        writer.server_random(),
        &[],
        0xc030,
        &[(16, server_alpn)],
    );
    let records = vec![
        (
            true,
            tls::plain_record(tls::HANDSHAKE, 0x0301, &client_hello),
        ),
        (
            false,
            tls::plain_record(tls::HANDSHAKE, 0x0303, &server_hello),
        ),
        (
            false,
            tls::plain_record(tls::CHANGE_CIPHER_SPEC, 0x0303, &[1]),
        ),
        (
            false,
            writer.record(false, tls::HANDSHAKE, &tls::handshake(20, &[0xaa; 12])),
        ),
        (
            true,
            tls::plain_record(tls::CHANGE_CIPHER_SPEC, 0x0303, &[1]),
        ),
        (
            true,
            writer.record(true, tls::HANDSHAKE, &tls::handshake(20, &[0xbb; 12])),
        ),
        (true, writer.record(true, tls::APPLICATION_DATA, client_app)),
        (
            false,
            writer.record(false, tls::APPLICATION_DATA, server_app),
        ),
    ];
    let mut records = records;
    if !client_body.is_empty() {
        records.push((
            true,
            writer.record(true, tls::APPLICATION_DATA, client_body),
        ));
    }
    (writer.keylog(), records)
}

/// Decode one TLS record from `from_client` as its own frame.
fn tls_frame(number: u64, sequence: u32, from_client: bool, payload: &[u8]) -> Frame {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 443);
    if from_client {
        frame_between(number, sequence, client, server, payload)
    } else {
        frame_between(number, sequence, server, client, payload)
    }
}

/// Decode TLS records in order, each as its own frame of one connection.
fn decode_tls_records(keylog: &str, records: &[(bool, Vec<u8>)]) -> Vec<packetfin_core::Packet> {
    let mut session = DecodeSession::new(DecodeOptions::default());
    session.set_keylog(KeyLog::read(keylog.as_bytes()));
    let mut client_sequence = 1_u32;
    let mut server_sequence = 1_u32;
    let mut frames = Vec::new();
    for (index, (from_client, record)) in records.iter().enumerate() {
        let number = u64::try_from(index).unwrap_or(0) + 1;
        let sequence = if *from_client {
            client_sequence
        } else {
            server_sequence
        };
        let packet = session.decode_at(&tls_frame(number, sequence, *from_client, record), number);
        frames.push(packet);
        let next = sequence.saturating_add(u32::try_from(record.len()).unwrap_or(u32::MAX));
        if *from_client {
            client_sequence = next;
        } else {
            server_sequence = next;
        }
    }
    frames
}

/// One TLS 1.3 connection whose client sends an HTTP/2 preface as 0-RTT
/// data, then `client` and `server` as 1-RTT data, with the server's
/// EncryptedExtensions body `encrypted_extensions`. The early HEADERS block
/// inserts `x: y` as dynamic table entry 62, and a 0-RTT PING follows the
/// EncryptedExtensions.
fn early_data_exchange(
    encrypted_extensions: &[u8],
    client: &[u8],
    server: &[u8],
) -> Vec<packetfin_core::Packet> {
    use packetfin_testkit::tls;

    let mut writer = tls::Tls13Writer::new(0x1302);
    writer.with_early();
    let client_hello = tls::client_hello(
        tls::TLS12_VERSION,
        writer.client_random(),
        &[],
        &[0x1302, 0x1301],
        &[
            (16, vec![0, 3, 2, b'h', b'2']),
            (42, Vec::new()),
            (43, vec![4, 0x03, 0x04, 0x03, 0x03]),
        ],
    );
    let server_hello = tls::server_hello(
        tls::TLS12_VERSION,
        writer.server_random(),
        &[],
        0x1302,
        &[(43, vec![0x03, 0x04])],
    );
    let mut early = PREFACE.to_vec();
    early.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    early.extend_from_slice(&h2_frame(
        1,
        0x05,
        1,
        &[0x82, 0x86, 0x84, 0x40, 0x01, b'x', 0x01, b'y'],
    ));
    let records = vec![
        (
            true,
            tls::plain_record(tls::HANDSHAKE, 0x0301, &client_hello),
        ),
        (
            true,
            writer.record(true, tls::Epoch::Early, tls::APPLICATION_DATA, &early),
        ),
        (
            false,
            tls::plain_record(tls::HANDSHAKE, 0x0303, &server_hello),
        ),
        (
            false,
            writer.record(
                false,
                tls::Epoch::Handshake,
                tls::HANDSHAKE,
                &tls::handshake(8, encrypted_extensions),
            ),
        ),
        // The client is still sending early data while the server's flight
        // is in transit, so one more 0-RTT record follows EncryptedExtensions.
        (
            true,
            writer.record(
                true,
                tls::Epoch::Early,
                tls::APPLICATION_DATA,
                &h2_frame(6, 0, 0, &[0; 8]),
            ),
        ),
        (
            false,
            writer.record(
                false,
                tls::Epoch::Handshake,
                tls::HANDSHAKE,
                &tls::handshake(20, &[0xaa; 48]),
            ),
        ),
        (
            true,
            writer.record(
                true,
                tls::Epoch::Handshake,
                tls::HANDSHAKE,
                &tls::handshake(20, &[0xbb; 48]),
            ),
        ),
        (
            true,
            writer.record(true, tls::Epoch::Application, tls::APPLICATION_DATA, client),
        ),
        (
            false,
            writer.record(
                false,
                tls::Epoch::Application,
                tls::APPLICATION_DATA,
                server,
            ),
        ),
    ];
    decode_tls_records(&writer.keylog(), &records)
}

#[test]
fn rejected_early_data_leaves_the_negotiated_protocol_unpinned() {
    // The 0-RTT records open HTTP/2, but the server returns no "early_data"
    // extension and selects http/1.1. RFC 8446 section 4.2.10 lets the ALPN
    // selection change after a rejection, and the server never saw the early
    // records, so the 1-RTT records are HTTP/1.1.
    let mut encrypted_extensions = vec![0, 15, 0, 16, 0, 11, 0, 9, 8];
    encrypted_extensions.extend_from_slice(b"http/1.1");
    let frames = early_data_exchange(
        &encrypted_extensions,
        b"GET /again HTTP/1.1\r\nHost: h\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let early = frames
        .get(1)
        .unwrap_or_else(|| unreachable!("the early record"));
    assert!(
        stream_with(early, "http2.header").is_some(),
        "the early records themselves still decode as HTTP/2"
    );
    let request = frames
        .get(7)
        .unwrap_or_else(|| unreachable!("the 1-RTT request"));
    assert_eq!(
        tree_field(request, "http.request.uri").as_deref(),
        Some("/again")
    );
    let response = frames
        .get(8)
        .unwrap_or_else(|| unreachable!("the 1-RTT response"));
    assert_eq!(
        tree_field(response, "http.response.code").as_deref(),
        Some("200")
    );
}

#[test]
fn accepted_early_data_carries_its_http2_connection_on() {
    // The server returns "early_data", so the 1-RTT records continue the
    // connection the 0-RTT records opened, header compression included: the
    // 1-RTT block's index 62 is the entry the early block inserted.
    let encrypted_extensions = [0, 4, 0, 42, 0, 0];
    let frames = early_data_exchange(
        &encrypted_extensions,
        &h2_frame(1, 0x05, 3, &[0x82, 0x86, 0x84, 0xbe]),
        &h2_frame(4, 0, 0, &[]),
    );
    let request = frames
        .get(7)
        .unwrap_or_else(|| unreachable!("the 1-RTT request"));
    let stream = stream_with(request, "http2.header")
        .unwrap_or_else(|| unreachable!("the 1-RTT HEADERS decode as HTTP/2"));
    let headers = stream
        .children
        .iter()
        .filter(|child| child.def.abbrev == "http2.header")
        .count();
    assert_eq!(
        headers, 4,
        "the dynamic entry from the early block resolves"
    );
}

#[test]
fn application_only_keylog_infers_http2_for_the_server_direction() {
    use packetfin_testkit::tls;

    let mut writer = tls::Tls13Writer::new(0x1302);
    let client_hello = tls::client_hello(
        tls::TLS12_VERSION,
        writer.client_random(),
        &[],
        &[0x1302, 0x1301],
        &[
            (16, vec![0, 3, 2, b'h', b'2']),
            (43, vec![4, 0x03, 0x04, 0x03, 0x03]),
        ],
    );
    let server_hello = tls::server_hello(
        tls::TLS12_VERSION,
        writer.server_random(),
        &[],
        0x1302,
        &[(43, vec![0x03, 0x04])],
    );
    let mut client = PREFACE.to_vec();
    client.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    client.extend_from_slice(&h2_frame(1, 0x05, 1, &[0x82, 0x86, 0x84]));
    let mut server = h2_frame(4, 0, 0, &[]);
    server.extend_from_slice(&h2_frame(1, 0x04, 1, &[0x88]));
    server.extend_from_slice(&h2_frame(0, 0x01, 1, b"hi"));
    let records = [
        (
            true,
            tls::plain_record(tls::HANDSHAKE, 0x0301, &client_hello),
        ),
        (
            false,
            tls::plain_record(tls::HANDSHAKE, 0x0303, &server_hello),
        ),
        (
            true,
            writer.record(
                true,
                tls::Epoch::Application,
                tls::APPLICATION_DATA,
                &client,
            ),
        ),
        (
            false,
            writer.record(
                false,
                tls::Epoch::Application,
                tls::APPLICATION_DATA,
                &server,
            ),
        ),
    ];
    // Application traffic secrets alone cannot decrypt EncryptedExtensions,
    // so ALPN is unknown and the preface must settle the framing.
    let keylog = writer
        .keylog()
        .lines()
        .filter(|line| {
            line.starts_with("CLIENT_TRAFFIC_SECRET_0")
                || line.starts_with("SERVER_TRAFFIC_SECRET_0")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let frames = decode_tls_records(&keylog, &records);
    let server_app = frames
        .get(3)
        .unwrap_or_else(|| unreachable!("server app data"));
    let stream = stream_with(server_app, "http2.header")
        .unwrap_or_else(|| unreachable!("the server SETTINGS and HEADERS decode as HTTP/2"));
    assert_eq!(
        child_value(stream, "http2.headers.status").as_deref(),
        Some("200")
    );
    let client_app = frames
        .get(2)
        .unwrap_or_else(|| unreachable!("client app data"));
    assert!(
        stream_with(client_app, "http2.header").is_some(),
        "the preface and request frames decode as HTTP/2"
    );
}

/// The first value of `abbrev` anywhere in the packet tree.
fn tree_field(packet: &packetfin_core::Packet, abbrev: &str) -> Option<String> {
    packet
        .tree
        .fields()
        .find(|field| field.def.abbrev == abbrev)
        .map(|field| field.value.render(field.def.display))
}

#[test]
fn a_server_that_selects_http11_keeps_http11_plaintext() {
    // The client offers h2 first; the server selects http/1.1 (RFC 7301
    // section 3.2), so the plaintext must stay HTTP/1.x.
    let client_alpn = vec![
        0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
    ];
    let server_alpn = vec![0, 9, 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'];
    let (keylog, records) = tls12_alpn_records(
        client_alpn,
        server_alpn,
        b"GET /h1 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        b"",
    );
    let frames = decode_tls_records(&keylog, &records);
    let client = frames
        .get(6)
        .unwrap_or_else(|| unreachable!("client app data"));
    assert_eq!(
        tree_field(client, "http.request.method").as_deref(),
        Some("GET")
    );
    assert!(stream_with(client, "http2.header").is_none());
    let server = frames
        .get(7)
        .unwrap_or_else(|| unreachable!("server app data"));
    assert_eq!(
        tree_field(server, "http.response.code").as_deref(),
        Some("200")
    );
    assert!(stream_with(server, "http2.header").is_none());
}

/// The `http2.stream` container that carries `abbrev`, when one decoded.
fn stream_with<'a>(
    packet: &'a packetfin_core::Packet,
    abbrev: &str,
) -> Option<&'a packetfin_core::tree::Field> {
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    nodes.iter().find_map(|node| {
        stream_container(node).filter(|stream| {
            stream
                .children
                .iter()
                .any(|child| child.def.abbrev == abbrev)
        })
    })
}

/// A nested field's rendered value, matched by abbreviation.
fn child_value(field: &packetfin_core::tree::Field, abbrev: &str) -> Option<String> {
    for child in &field.children {
        if child.def.abbrev == abbrev {
            return Some(child.value.render(child.def.display));
        }
        if let Some(value) = child_value(child, abbrev) {
            return Some(value);
        }
    }
    None
}

#[test]
fn decrypted_http2_plaintext_is_framed_in_both_directions() {
    let (keylog, records) = tls12_h2_records();
    let frames = decode_tls_records(&keylog, &records);
    let server_app = frames
        .get(7)
        .unwrap_or_else(|| unreachable!("server app data"));
    let stream = stream_with(server_app, "http2.header")
        .unwrap_or_else(|| unreachable!("the decrypted server plaintext decodes as HTTP/2"));
    assert_eq!(
        child_value(stream, "http2.headers.status").as_deref(),
        Some("200")
    );
    let data_stream = stream_with(server_app, "http2.data.data")
        .unwrap_or_else(|| unreachable!("the response body decodes as HTTP/2"));
    assert_eq!(
        child_value(data_stream, "http2.data.data").as_deref(),
        Some("6869")
    );
    let client_app = frames
        .get(6)
        .unwrap_or_else(|| unreachable!("client app data"));
    let client_stream = stream_with(client_app, "http2.header")
        .unwrap_or_else(|| unreachable!("the decrypted client plaintext decodes as HTTP/2"));
    assert_eq!(
        child_value(client_stream, "http2.headers.method").as_deref(),
        Some("GET")
    );
}

#[test]
fn a_frame_between_header_fragments_interrupts_the_block() {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0, 1, &[0x82, 0x86]));
    let _ = session.decode_at(&frame_between(1, 1, client, server, &first), 1);

    // RFC 9113 section 6.10: PING is not a header-block frame, so it breaks
    // the open block and the CONTINUATION that follows has nothing to join.
    let mut second = h2_frame(6, 0, 0, &[0; 8]);
    second.extend_from_slice(&h2_frame(9, 0x04, 1, &[0x84]));
    let sequence = 1 + u32::try_from(first.len()).unwrap_or(0);
    let packet = session.decode_at(&frame_between(2, sequence, client, server, &second), 2);

    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let interrupting = nodes
        .iter()
        .find(|node| {
            stream_container(node).is_some_and(|stream| {
                stream.experts.iter().any(|expert| {
                    expert.group == Group::Protocol
                        && expert.message == "HTTP/2 frame interrupts an open header block"
                })
            })
        })
        .copied()
        .unwrap_or_else(|| unreachable!("the PING frame reports the interruption"));
    let stream = stream_container(interrupting)
        .unwrap_or_else(|| unreachable!("the interrupting frame has a stream container"));
    assert!(
        stream
            .showname
            .as_deref()
            .is_some_and(|name| name.starts_with("Stream: PING")),
        "the interruption is reported on the interrupting frame"
    );
    assert_eq!(
        nodes.iter().map(|node| header_count(node)).sum::<usize>(),
        0,
        "the interrupted block never decodes"
    );
}

#[test]
fn a_headers_priority_block_shorter_than_five_octets_is_malformed() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&h2_frame(1, 0x24, 1, &[]));
    let packet = decode_frame(&frame(1, 1, &bytes));
    assert!(packet.malformed, "a truncated priority field is an error");
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("HEADERS node"));
    let stream = stream_container(node)
        .unwrap_or_else(|| unreachable!("the HEADERS frame has a stream container"));
    assert!(stream.experts.iter().any(|expert| {
        expert.group == Group::Malformed && expert.message.contains("FRAME_SIZE_ERROR")
    }));
    assert!(
        !has_child(node, "http2.headers"),
        "no header block fragment is submitted"
    );
    assert_eq!(header_count(node), 0);

    // The fields are still decoded when the priority block is complete.
    let mut valid = PREFACE.to_vec();
    valid.extend_from_slice(&h2_frame(1, 0x24, 1, &[0, 0, 0, 1, 15, 0x82]));
    let packet = decode_frame(&frame(1, 1, &valid));
    assert!(!packet.malformed);
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("HEADERS node"));
    assert!(has_child(node, "http2.exclusive"));
    assert!(has_child(node, "http2.stream_dependency"));
    assert_eq!(header_count(node), 1, "the header block still decodes");
}

#[test]
fn a_fragmented_request_links_the_response_to_the_opening_headers() {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0, 1, &[0x82, 0x86]));
    let _ = session.decode_at(&frame_between(1, 1, client, server, &first), 1);

    // RFC 7541 section 2.2 makes the block one unit: the request belongs to
    // the HEADERS frame even though END_HEADERS arrived on the CONTINUATION.
    let continuation = h2_frame(9, 0x04, 1, &[0x84]);
    let sequence = 1 + u32::try_from(first.len()).unwrap_or(0);
    let _ = session.decode_at(
        &frame_between(2, sequence, client, server, &continuation),
        2,
    );

    let response = h2_frame(1, 0x04, 1, &[0x88]);
    let packet = session.decode_at(&frame_between(3, 1, server, client, &response), 3);
    let stream = stream_with(&packet, "http2.request_in")
        .unwrap_or_else(|| unreachable!("the response links to the request"));
    assert_eq!(
        child_value(stream, "http2.request_in").as_deref(),
        Some("1"),
        "the request belongs to the frame that opened the block"
    );
}

#[test]
fn an_acknowledged_table_reduction_requires_a_size_update() {
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    let _ = session.decode_at(&frame_between(1, 1, client, server, &first), 1);

    // The server lowers SETTINGS_HEADER_TABLE_SIZE to zero.
    let settings = h2_frame(4, 0, 0, &[0, 1, 0, 0, 0, 0]);
    let packet = session.decode_at(&frame_between(2, 1, server, client, &settings), 2);
    assert!(!packet.malformed, "a SETTINGS frame decodes normally");

    // The client acknowledges the reduction, so its next block must begin
    // with a dynamic table size update (RFC 9113 section 4.3.1).
    let ack = h2_frame(4, 0x01, 0, &[]);
    let sequence = 1 + u32::try_from(first.len()).unwrap_or(0);
    let _ = session.decode_at(&frame_between(3, sequence, client, server, &ack), 3);

    let headers = h2_frame(1, 0x05, 1, &[0x82, 0x86, 0x84]);
    let sequence = sequence.saturating_add(u32::try_from(ack.len()).unwrap_or(0));
    let packet = session.decode_at(&frame_between(4, sequence, client, server, &headers), 4);
    assert!(packet.malformed, "the missing update rejects the block");
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let node = nodes
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("HEADERS node"));
    assert_eq!(header_count(node), 0, "no field is decoded");
    let stream = stream_container(node)
        .unwrap_or_else(|| unreachable!("the HEADERS frame has a stream container"));
    assert!(stream.experts.iter().any(|expert| {
        expert.group == Group::Malformed && expert.message.contains("required table size update")
    }));
}

#[test]
fn a_frame_header_cut_short_is_reported_after_the_decoded_frames() {
    // Without desegmentation a forced port hands each segment to the decoder
    // whole, so a segment can end inside a frame header. The preface and the
    // complete SETTINGS frame stay; the eight octets left cannot hold the
    // nine-octet header of RFC 9113 section 4.1.
    let mut options = DecodeOptions::default();
    options.preferences.tcp_desegment_tcp_streams = false;
    parse_decode_as("tcp.port==8080,http2", &mut options.decode_as)
        .unwrap_or_else(|_| unreachable!("a valid decode-as entry"));
    let mut session = DecodeSession::new(options);
    let mut payload = PREFACE.to_vec();
    payload.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    payload.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0]);
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 8080);
    let packet = session.decode_at(&frame_between(1, 1, client, server, &payload), 1);
    assert!(packet.malformed, "the cut header is malformed");
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    assert_eq!(nodes.len(), 3, "Magic, SETTINGS and the cut fragment");
    assert!(
        nodes
            .get(1)
            .is_some_and(|node| has_child(node, "http2.streamid")),
        "the complete SETTINGS frame before the cut stays decoded"
    );
    let fragment = nodes
        .last()
        .copied()
        .unwrap_or_else(|| unreachable!("the cut fragment has its own node"));
    assert_eq!(fragment.range.length, 8);
    assert!(fragment.experts.iter().any(|expert| {
        expert.group == Group::Malformed && expert.message == "HTTP/2 frame header is truncated"
    }));
    // The captured Length, Type and Flags octets keep their fields; the
    // stream identifier would need the ninth octet.
    assert_eq!(
        child_value_of(fragment, "http2.length").as_deref(),
        Some("0")
    );
    assert_eq!(child_value_of(fragment, "http2.type").as_deref(), Some("4"));
    assert!(has_child(fragment, "http2.flags"));
    assert!(!has_child(fragment, "http2.streamid"));
}

/// A field's rendered value inside a node's stream container.
fn child_value_of(node: &Node, abbrev: &str) -> Option<String> {
    stream_container(node).and_then(|stream| child_value(stream, abbrev))
}

#[test]
fn a_zero_window_increment_is_a_protocol_error() {
    // RFC 9113 section 6.9 makes a zero increment a PROTOCOL_ERROR on the
    // connection (stream 0) and on a stream alike. The window does not move,
    // so the calculated pair still shows the same value twice.
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut payload = PREFACE.to_vec();
    payload.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    payload.extend_from_slice(&h2_frame(8, 0, 0, &[0, 0, 0, 0]));
    payload.extend_from_slice(&h2_frame(8, 0, 1, &[0, 0, 0, 0]));
    let packet = session.decode_at(&frame(1, 1, &payload), 1);
    assert!(
        !packet.malformed,
        "a zero increment breaks the protocol, not the framing"
    );
    let mut nodes = Vec::new();
    http2_nodes(&packet.tree.frame, &mut nodes);
    let increments: Vec<&packetfin_core::tree::Field> = nodes
        .iter()
        .filter_map(|node| stream_container(node))
        .flat_map(|stream| stream.children.iter())
        .filter(|field| field.def.abbrev == "http2.window_update.window_size_increment")
        .collect();
    assert_eq!(increments.len(), 2, "one increment per WINDOW_UPDATE frame");
    for increment in increments {
        assert!(increment.experts.iter().any(|expert| {
            expert.group == Group::Protocol && expert.message.ends_with("PROTOCOL_ERROR")
        }));
    }
    for scope in ["connection", "stream"] {
        let before = format!("http2.calculated.{scope}.window_size.before");
        let after = format!("http2.calculated.{scope}.window_size.after");
        let stream = stream_with(&packet, &before)
            .unwrap_or_else(|| unreachable!("the {scope} window pair is calculated"));
        assert_eq!(
            child_value(stream, &before),
            child_value(stream, &after),
            "the {scope} window does not move"
        );
    }
}

#[test]
fn a_split_request_shows_its_response_link_on_the_opening_headers() {
    // The request is recorded against the HEADERS frame that opened its
    // block (RFC 9113 section 6.10), but its method renders on the
    // CONTINUATION frame that ends the block. The output pass must still
    // print the forward link on the HEADERS frame.
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut opening = PREFACE.to_vec();
    opening.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    opening.extend_from_slice(&h2_frame(1, 0x01, 1, &[0x82, 0x86]));
    let continuation = h2_frame(9, 0x04, 1, &[0x84]);
    let response = h2_frame(1, 0x05, 1, &[0x88]);
    let continuation_sequence = 1 + u32::try_from(opening.len()).unwrap_or(0);
    let frames = [
        frame_between(1, 1, client, server, &opening),
        frame_between(2, continuation_sequence, client, server, &continuation),
        frame_between(3, 1, server, client, &response),
    ];
    assert_eq!(
        response_links(&frames),
        [vec![(1, 3)], vec![], vec![]],
        "only the opening HEADERS frame links forward to the response"
    );
}

#[test]
fn a_continuation_never_takes_the_link_of_a_block_opened_beside_it() {
    // The second segment ends stream 1's block, opened in the first segment,
    // and opens stream 3's block. Stream 3's request is recorded against the
    // second segment, so its link belongs on the HEADERS frame there, not on
    // the CONTINUATION that shows stream 1's method.
    let client = ([192, 0, 2, 1], 40_000);
    let server = ([192, 0, 2, 2], 80);
    let mut first = PREFACE.to_vec();
    first.extend_from_slice(&h2_frame(4, 0, 0, &[]));
    first.extend_from_slice(&h2_frame(1, 0x01, 1, &[0x82, 0x86]));
    let mut second = h2_frame(9, 0x04, 1, &[0x84]);
    second.extend_from_slice(&h2_frame(1, 0x01, 3, &[0x82, 0x86]));
    let third = h2_frame(9, 0x04, 3, &[0x84]);
    let first_response = h2_frame(1, 0x05, 1, &[0x88]);
    let second_response = h2_frame(1, 0x05, 3, &[0x88]);
    let second_sequence = 1 + u32::try_from(first.len()).unwrap_or(0);
    let third_sequence = second_sequence + u32::try_from(second.len()).unwrap_or(0);
    let response_sequence = 1 + u32::try_from(first_response.len()).unwrap_or(0);
    let frames = [
        frame_between(1, 1, client, server, &first),
        frame_between(2, second_sequence, client, server, &second),
        frame_between(3, third_sequence, client, server, &third),
        frame_between(4, 1, server, client, &first_response),
        frame_between(5, response_sequence, server, client, &second_response),
    ];
    assert_eq!(
        response_links(&frames),
        [vec![(1, 4)], vec![(3, 5)], vec![], vec![], vec![]],
    );
}

/// Run both passes over `frames` and list, per frame, the stream identifier
/// and the `http2.response_in` value of every HTTP/2 frame that links forward.
fn response_links(frames: &[Frame]) -> Vec<Vec<(u32, u32)>> {
    let mut recording = DecodeSession::with_pass(
        DecodeOptions::default(),
        packetfin_core::DEFAULT_STATE_BUDGET,
        packetfin_core::PassMode::First,
    );
    for (file, frame) in (1..).zip(frames) {
        let _ = recording.decode_at(frame, file);
    }
    let annotations = recording.into_annotations();

    let mut output = DecodeSession::with_pass(
        DecodeOptions::default(),
        packetfin_core::DEFAULT_STATE_BUDGET,
        packetfin_core::PassMode::Second,
    );
    let renumber = packetfin_core::RenumberMap::new(1..=u64::try_from(frames.len()).unwrap_or(0));
    let number = |stream: &packetfin_core::tree::Field, abbrev: &str| {
        child_value(stream, abbrev).and_then(|value| value.parse::<u32>().ok())
    };
    (1..)
        .zip(frames)
        .map(|(file, frame)| {
            let mut packet = output.decode_at(frame, file);
            if let Some(annotation) = annotations.get(file) {
                packetfin_core::apply_annotations(&mut packet, annotation, &renumber);
            }
            let mut nodes = Vec::new();
            http2_nodes(&packet.tree.frame, &mut nodes);
            nodes
                .iter()
                .filter_map(|node| stream_container(node))
                .filter_map(|stream| {
                    Some((
                        number(stream, "http2.streamid")?,
                        number(stream, "http2.response_in")?,
                    ))
                })
                .collect()
        })
        .collect()
}
