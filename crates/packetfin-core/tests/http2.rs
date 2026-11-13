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
    assert_eq!(header_count(continuation), 1);
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
    for (kind, fragment) in [(1_u8, &[0x82][..]), (9_u8, &[0x82][..])] {
        let mut bytes = PREFACE.to_vec();
        bytes.extend_from_slice(&h2_frame(kind, 0x04, 0, fragment));
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
        .filter(|child| child.def.abbrev == "http2.body.fragment")
        .count();
    assert!(views <= 256, "fragment views are bounded, got {views}");
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
