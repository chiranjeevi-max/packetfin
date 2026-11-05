//! ICMPv4 decoding tests: field layouts, checksum status, truncation
//! boundaries, RFC 4884 fields, quoted-header repetition and gating, and the
//! recursion limit.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{
    DecodeOptions, MAX_DECODE_DEPTH, NetworkContext, Preferences, decode_frame,
    decode_frame_with_options,
};
use packetfin_core::tree::{Group, Value};

const DESTINATION_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const SOURCE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const SOURCE: [u8; 4] = [192, 0, 2, 1];
const DESTINATION: [u8; 4] = [198, 51, 100, 2];

fn frame(captured: Vec<u8>) -> Frame {
    let original_len = u32::try_from(captured.len()).unwrap_or(u32::MAX);
    frame_with_original(captured, original_len)
}

fn frame_with_original(captured: Vec<u8>, original_len: u32) -> Frame {
    Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        timestamp_precision: 6,
        original_len,
        captured,
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

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*pair)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    let [high, low] = value.to_be_bytes();
    if let Some(byte) = bytes.get_mut(offset) {
        *byte = high;
    }
    if let Some(byte) = bytes.get_mut(offset.saturating_add(1)) {
        *byte = low;
    }
}

fn ipv4(protocol: u8, payload: &[u8], total_length: Option<u16>) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x45);
    header.push(0);
    header.extend_from_slice(
        &total_length
            .unwrap_or_else(|| u16::try_from(20 + payload.len()).unwrap_or(0))
            .to_be_bytes(),
    );
    header.extend_from_slice(&0x1c46_u16.to_be_bytes());
    header.extend_from_slice(&0x4000_u16.to_be_bytes());
    header.push(64);
    header.push(protocol);
    header.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&SOURCE);
    header.extend_from_slice(&DESTINATION);
    let value = checksum(&header);
    set_u16(&mut header, 10, value);
    header.extend_from_slice(payload);
    header
}

fn ipv6(next: u8, payload: &[u8], source: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    bytes.push(next);
    bytes.push(64);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(payload);
    bytes
}

fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&DESTINATION_MAC);
    bytes.extend_from_slice(&SOURCE_MAC);
    bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn icmp(message_type: u8, code: u8, rest: [u8; 4], payload: &[u8], bad: bool) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(message_type);
    message.push(code);
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(&rest);
    message.extend_from_slice(payload);
    let value = if bad { 0x1234 } else { checksum(&message) };
    set_u16(&mut message, 2, value);
    message
}

fn decode(message: &[u8]) -> packetfin_core::decode::Packet {
    decode_frame(&frame(ethernet(&ipv4(1, message, None))))
}

fn values(packet: &packetfin_core::decode::Packet, abbrev: &str) -> Vec<Value> {
    packet
        .tree
        .field_values(abbrev)
        .into_iter()
        .cloned()
        .collect()
}

fn u32_values(packet: &packetfin_core::decode::Packet, abbrev: &str) -> Vec<u32> {
    values(packet, abbrev)
        .into_iter()
        .filter_map(|value| match value {
            Value::Uint32(value) => Some(value),
            Value::Uint16(value) => Some(u32::from(value)),
            Value::Uint8(value) => Some(u32::from(value)),
            _ => None,
        })
        .collect()
}

#[test]
fn echo_fields_and_checksum() {
    let packet = decode(&icmp(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", false));
    assert!(!packet.malformed);
    assert_eq!(values(&packet, "icmp.ident"), vec![Value::Uint16(0x1234)]);
    assert_eq!(
        values(&packet, "icmp.ident_le"),
        vec![Value::Uint16(0x3412)]
    );
    assert_eq!(values(&packet, "icmp.seq"), vec![Value::Uint16(1)]);
    assert_eq!(values(&packet, "icmp.seq_le"), vec![Value::Uint16(0x0100)]);
    assert_eq!(
        values(&packet, "icmp.data"),
        vec![Value::bytes(b"abcdefgh".to_vec())]
    );
    assert_eq!(
        values(&packet, "icmp.checksum.status"),
        vec![Value::Uint8(1)]
    );
    assert!(!packet.tree.has_expert(Group::Checksum));
}

#[test]
fn bad_checksum_reports_status_zero_and_expert() {
    let packet = decode(&icmp(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", true));
    assert_eq!(
        values(&packet, "icmp.checksum.status"),
        vec![Value::Uint8(0)]
    );
    assert!(packet.tree.has_expert(Group::Checksum));
}

#[test]
fn fixed_header_truncation_boundaries() {
    let full = icmp(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", false);
    for length in [1_usize, 4, 5] {
        let packet = decode(full.get(..length).unwrap_or(&[]));
        assert!(packet.malformed, "length {length} must be malformed");
        assert!(values(&packet, "icmp.type").is_empty());
    }
    for length in [6_usize, 7] {
        let packet = decode(full.get(..length).unwrap_or(&[]));
        assert!(packet.malformed, "length {length} must be malformed");
        assert_eq!(values(&packet, "icmp.ident"), vec![Value::Uint16(0x1234)]);
        assert!(values(&packet, "icmp.seq").is_empty());
    }
    let packet = decode(full.get(..8).unwrap_or(&[]));
    assert!(!packet.malformed);
    assert!(values(&packet, "icmp.data").is_empty());
}

#[test]
fn error_fields_and_rfc4884_length() {
    let mut rest = [0_u8, 4, 0, 0];
    rest[2] = 0x05;
    rest[3] = 0xdc;
    let packet = decode(&icmp(3, 4, rest, b"", false));
    assert_eq!(values(&packet, "icmp.mtu"), vec![Value::Uint16(1500)]);
    assert_eq!(values(&packet, "icmp.unused"), vec![Value::bytes(vec![0])]);
    assert_eq!(values(&packet, "icmp.length"), vec![Value::Uint8(4)]);
    assert_eq!(
        values(&packet, "icmp.length.original_datagram"),
        vec![Value::Uint16(16)]
    );

    let packet = decode(&icmp(12, 0, [8, 0, 0, 0], b"", false));
    assert_eq!(values(&packet, "icmp.pointer"), vec![Value::Uint32(8)]);
    assert_eq!(
        values(&packet, "icmp.unused"),
        vec![Value::bytes(vec![0, 0, 0])]
    );

    let packet = decode(&icmp(5, 1, [10, 0, 0, 9], b"", false));
    assert_eq!(
        values(&packet, "icmp.redir_gw"),
        vec![Value::Ipv4([10, 0, 0, 9])]
    );
}

fn quoted_udp() -> Vec<u8> {
    let source = [10, 0, 0, 1];
    let destination = [10, 0, 0, 2];
    let mut segment = Vec::new();
    segment.extend_from_slice(&1234_u16.to_be_bytes());
    segment.extend_from_slice(&4321_u16.to_be_bytes());
    segment.extend_from_slice(&11_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(b"abc");
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&11_u16.to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let value = checksum(&pseudo);
    set_u16(&mut segment, 6, value);
    let mut datagram = ipv4(17, &segment, None);
    if let Some(address) = datagram.get_mut(12..16) {
        address.copy_from_slice(&source);
    }
    if let Some(address) = datagram.get_mut(16..20) {
        address.copy_from_slice(&destination);
    }
    set_u16(&mut datagram, 10, 0);
    let value = checksum(datagram.get(..20).unwrap_or(&[]));
    set_u16(&mut datagram, 10, value);
    datagram
}

#[test]
fn quoted_udp_fields_repeat_and_outer_context_survives() {
    let inner = quoted_udp();
    let packet = decode(&icmp(3, 3, [0, 0, 0, 0], &inner, false));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "ip.src"),
        vec![Value::Ipv4(SOURCE), Value::Ipv4([10, 0, 0, 1])]
    );
    assert_eq!(
        values(&packet, "ip.dst"),
        vec![Value::Ipv4(DESTINATION), Value::Ipv4([10, 0, 0, 2])]
    );
    assert_eq!(u32_values(&packet, "udp.srcport"), vec![1234]);
    assert_eq!(
        packet.network,
        Some(NetworkContext::Ipv4 {
            source: SOURCE,
            destination: DESTINATION,
            protocol: 1,
            fragmented: false,
        })
    );
    assert_eq!(packet.columns.source, Some("02:00:00:00:00:01".to_string()));
}

#[test]
fn quoted_checksums_follow_preferences_and_short_copy_is_not_malformed() {
    let inner = quoted_udp();
    let message = icmp(3, 3, [0, 0, 0, 0], &inner, false);
    let options = DecodeOptions {
        preferences: Preferences {
            ip_check_checksum: true,
            udp_check_checksum: true,
            ..Preferences::default()
        },
        ..DecodeOptions::default()
    };
    let packet =
        decode_frame_with_options(&frame(ethernet(&ipv4(1, &message, None))), options.clone());
    assert_eq!(u32_values(&packet, "ip.checksum.status"), vec![1, 1]);
    assert_eq!(u32_values(&packet, "udp.checksum.status"), vec![1]);

    let short = icmp(3, 3, [0, 0, 0, 0], inner.get(..16).unwrap_or(&[]), false);
    let packet =
        decode_frame_with_options(&frame(ethernet(&ipv4(1, &short, None))), options.clone());
    assert!(!packet.malformed);
    assert_eq!(u32_values(&packet, "ip.checksum.status"), vec![1, 2]);
    assert_eq!(values(&packet, "ip.src").len(), 2);
}

#[test]
fn quoted_ipv6_short_header_adds_expert_without_malformed_packet() {
    let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let quoted = ipv6(17, &[], source, destination);
    let short = quoted.get(..20).unwrap_or(&[]);
    let packet = decode(&icmp(3, 3, [0, 0, 0, 0], short, false));
    assert!(!packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    assert_eq!(values(&packet, "ipv6.version"), vec![Value::Uint8(6)]);
}

#[test]
fn quoted_icmp_is_unverified_and_nested_recursion_stops_at_the_limit() {
    let mut message = icmp(8, 0, [1, 2, 3, 4], b"", false);
    for _ in 0..(MAX_DECODE_DEPTH + 4) {
        message = icmp(3, 3, [0, 0, 0, 0], &ipv4(1, &message, None), false);
    }
    let packet = decode(&message);
    let statuses = u32_values(&packet, "icmp.checksum.status");
    assert!(statuses.len() > 1);
    assert!(statuses.iter().skip(1).all(|status| *status == 2));
    assert!(packet.tree.has_expert(Group::Malformed));
}

#[test]
fn capture_truncation_leaves_the_checksum_unverified_and_the_packet_well_formed() {
    let message = icmp(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", false);
    let full = ethernet(&ipv4(1, &message, None));
    let original = u32::try_from(full.len()).unwrap_or(u32::MAX);
    let captured = full
        .get(..full.len().saturating_sub(3))
        .unwrap_or(&[])
        .to_vec();
    let packet = decode_frame(&frame_with_original(captured, original));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmp.checksum.status"),
        vec![Value::Uint8(2)]
    );

    let captured = full
        .get(..full.len().saturating_sub(1))
        .unwrap_or(&[])
        .to_vec();
    let packet = decode_frame(&frame_with_original(captured, original));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmp.checksum.status"),
        vec![Value::Uint8(2)]
    );
}

#[test]
fn parameter_problem_length_byte_does_not_overlap_the_pointer() {
    let packet = decode(&icmp(12, 0, [8, 4, 0x11, 0x22], b"", false));
    assert_eq!(values(&packet, "icmp.pointer"), vec![Value::Uint32(8)]);
    assert_eq!(
        values(&packet, "icmp.unused"),
        vec![Value::bytes(vec![0x11, 0x22])]
    );
    assert_eq!(values(&packet, "icmp.length"), vec![Value::Uint8(4)]);
}

#[test]
fn original_datagram_length_is_not_truncated_to_a_byte() {
    for (length, expected) in [(64_u8, 256_u16), (255, 1020)] {
        let packet = decode(&icmp(3, 3, [0, length, 0, 0], b"", false));
        assert_eq!(
            values(&packet, "icmp.length.original_datagram"),
            vec![Value::Uint16(expected)],
            "length byte {length}"
        );
    }
}

#[test]
fn tso_total_length_zero_uses_the_frame_remaining_for_truncation() {
    let message = icmp(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", false);
    let full = ethernet(&ipv4(1, &message, Some(0)));
    let original = u32::try_from(full.len()).unwrap_or(u32::MAX);
    let captured = full
        .get(..full.len().saturating_sub(1))
        .unwrap_or(&[])
        .to_vec();
    let packet = decode_frame(&frame_with_original(captured, original));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmp.checksum.status"),
        vec![Value::Uint8(2)]
    );
}

#[test]
fn original_length_shorter_than_capture_is_not_malformed() {
    let message = icmp(8, 0, [0x12, 0x34, 0x00, 0x01], b"abcdefgh", false);
    let full = ethernet(&ipv4(1, &message, None));
    let original = u32::try_from(full.len().saturating_sub(14)).unwrap_or(u32::MAX);
    let packet = decode_frame(&frame_with_original(full, original));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmp.checksum.status"),
        vec![Value::Uint8(1)]
    );
}
