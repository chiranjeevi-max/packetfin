//! ICMPv6 decoding tests: RFC 4443 message layouts, checksum validation,
//! fixed-header truncation thresholds, RFC 4861 neighbor-discovery messages
//! and options, option length boundaries, quoted invoking packets, and the
//! recursion limit.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{MAX_DECODE_DEPTH, NetworkContext, decode_frame};
use packetfin_core::tree::{Group, Value};

const DESTINATION_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const SOURCE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const SOURCE: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DESTINATION: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const LINK_LOCAL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const INNER_SOURCE: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
];
const INNER_DESTINATION: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b,
];

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

fn ipv6_payload_length(payload: &[u8], declared: Option<u16>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    bytes.extend_from_slice(
        &declared
            .unwrap_or_else(|| u16::try_from(payload.len()).unwrap_or(0))
            .to_be_bytes(),
    );
    bytes.push(58);
    bytes.push(64);
    bytes.extend_from_slice(&SOURCE);
    bytes.extend_from_slice(&DESTINATION);
    bytes.extend_from_slice(payload);
    bytes
}

fn ethernet(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&DESTINATION_MAC);
    bytes.extend_from_slice(&SOURCE_MAC);
    bytes.extend_from_slice(&0x86dd_u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn icmpv6_checksum(source: [u8; 16], destination: [u8; 16], message: &[u8]) -> u16 {
    let mut data = Vec::new();
    data.extend_from_slice(&source);
    data.extend_from_slice(&destination);
    data.extend_from_slice(
        &u32::try_from(message.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    data.extend_from_slice(&[0, 0, 0, 58]);
    data.extend_from_slice(message);
    checksum(&data)
}

fn icmpv6(message_type: u8, code: u8, body: &[u8]) -> Vec<u8> {
    build_icmpv6(message_type, code, body, None)
}

fn build_icmpv6(message_type: u8, code: u8, body: &[u8], stored: Option<u16>) -> Vec<u8> {
    let mut message = Vec::new();
    message.push(message_type);
    message.push(code);
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(body);
    let value = stored.unwrap_or_else(|| icmpv6_checksum(SOURCE, DESTINATION, &message));
    set_u16(&mut message, 2, value);
    message
}

fn decode(message: &[u8]) -> packetfin_core::decode::Packet {
    decode_frame(&frame(ethernet(&ipv6_payload_length(message, None))))
}

fn decode_truncated(full: &[u8], length: usize) -> packetfin_core::decode::Packet {
    let payload = full.get(..length).unwrap_or(&[]);
    let declared = u16::try_from(full.len()).unwrap_or(0);
    decode_frame(&frame(ethernet(&ipv6_payload_length(
        payload,
        Some(declared),
    ))))
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

fn bool_values(packet: &packetfin_core::decode::Packet, abbrev: &str) -> Vec<bool> {
    values(packet, abbrev)
        .into_iter()
        .filter_map(|value| match value {
            Value::Boolean(value) => Some(value),
            _ => None,
        })
        .collect()
}

/// An IPv6 UDP datagram used as the invoking packet of an error message.
fn quoted_udp() -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&1234_u16.to_be_bytes());
    segment.extend_from_slice(&4321_u16.to_be_bytes());
    segment.extend_from_slice(&11_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(b"abc");
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&INNER_SOURCE);
    pseudo.extend_from_slice(&INNER_DESTINATION);
    pseudo.extend_from_slice(&11_u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&segment);
    let value = checksum(&pseudo);
    set_u16(&mut segment, 6, value);
    udp_inside_ipv6(&segment)
}

fn udp_inside_ipv6(segment: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    datagram.extend_from_slice(&u16::try_from(segment.len()).unwrap_or(0).to_be_bytes());
    datagram.push(17);
    datagram.push(64);
    datagram.extend_from_slice(&INNER_SOURCE);
    datagram.extend_from_slice(&INNER_DESTINATION);
    datagram.extend_from_slice(segment);
    datagram
}

fn quoted_tcp() -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&40_000_u16.to_be_bytes());
    segment.extend_from_slice(&443_u16.to_be_bytes());
    segment.extend_from_slice(&1_000_u32.to_be_bytes());
    segment.extend_from_slice(&0_u32.to_be_bytes());
    segment.push(0x50);
    segment.push(0x18);
    segment.extend_from_slice(&65_535_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(b"abc");
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&INNER_SOURCE);
    pseudo.extend_from_slice(&INNER_DESTINATION);
    pseudo.extend_from_slice(
        &u32::try_from(segment.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    pseudo.extend_from_slice(&segment);
    let value = checksum(&pseudo);
    set_u16(&mut segment, 16, value);
    let mut datagram = udp_inside_ipv6(&segment);
    if let Some(next) = datagram.get_mut(6) {
        *next = 6;
    }
    datagram
}

#[test]
fn echo_fields_and_checksum_status() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1234_u16.to_be_bytes());
    body.extend_from_slice(&5_u16.to_be_bytes());
    body.extend_from_slice(b"abcdefgh");
    let packet = decode(&icmpv6(128, 0, &body));

    assert!(!packet.malformed);
    assert_eq!(values(&packet, "icmpv6.type"), vec![Value::Uint8(128)]);
    assert_eq!(values(&packet, "icmpv6.code"), vec![Value::Uint8(0)]);
    assert_eq!(
        values(&packet, "icmpv6.echo.identifier"),
        vec![Value::Uint16(0x1234)]
    );
    assert_eq!(
        values(&packet, "icmpv6.echo.sequence_number"),
        vec![Value::Uint16(5)]
    );
    assert_eq!(
        values(&packet, "icmpv6.checksum.status"),
        vec![Value::Uint8(1)]
    );
    assert!(values(&packet, "icmpv6.data").is_empty());
    assert!(!packet.tree.has_expert(Group::Checksum));
}

#[test]
fn checksum_covers_the_ipv6_pseudo_header() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1234_u16.to_be_bytes());
    body.extend_from_slice(&5_u16.to_be_bytes());
    let message = icmpv6(128, 0, &body);

    let mut moved = ipv6_payload_length(&message, None);
    if let Some(address) = moved.get_mut(8) {
        *address ^= 0xff;
    }
    let packet = decode_frame(&frame(ethernet(&moved)));
    assert_eq!(
        values(&packet, "icmpv6.checksum.status"),
        vec![Value::Uint8(0)]
    );
    assert!(packet.tree.has_expert(Group::Checksum));
}

#[test]
fn bad_checksum_reports_status_zero_and_expert() {
    let packet = decode(&build_icmpv6(128, 0, &[0x12, 0x34, 0, 5], Some(0x1234)));
    assert_eq!(
        values(&packet, "icmpv6.checksum.status"),
        vec![Value::Uint8(0)]
    );
    assert!(packet.tree.has_expert(Group::Checksum));
}

#[test]
fn echo_fixed_header_truncation_boundaries() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1234_u16.to_be_bytes());
    body.extend_from_slice(&5_u16.to_be_bytes());
    let full = icmpv6(128, 0, &body);

    for length in [1_usize, 2, 3] {
        let packet = decode_truncated(&full, length);
        assert!(packet.malformed, "length {length}");
        assert!(values(&packet, "icmpv6.checksum.status").is_empty());
    }
    for length in [4_usize, 5] {
        let packet = decode_truncated(&full, length);
        assert!(packet.malformed, "length {length}");
        assert_eq!(
            values(&packet, "icmpv6.checksum.status"),
            vec![Value::Uint8(0)]
        );
        assert!(values(&packet, "icmpv6.echo.identifier").is_empty());
    }
    for length in [6_usize, 7] {
        let packet = decode_truncated(&full, length);
        assert!(packet.malformed, "length {length}");
        assert_eq!(
            values(&packet, "icmpv6.echo.identifier"),
            vec![Value::Uint16(0x1234)]
        );
        assert!(values(&packet, "icmpv6.echo.sequence_number").is_empty());
    }
    let packet = decode_truncated(&full, 8);
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.echo.sequence_number"),
        vec![Value::Uint16(5)]
    );
}

#[test]
fn neighbor_discovery_fixed_header_truncation_boundaries() {
    let router_solicitation = icmpv6(133, 0, &[0; 4]);
    for length in [4_usize, 7] {
        let packet = decode_truncated(&router_solicitation, length);
        assert!(packet.malformed, "RS length {length}");
        assert!(values(&packet, "icmpv6.reserved").is_empty());
    }
    let packet = decode_truncated(&router_solicitation, 8);
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.reserved"),
        vec![Value::bytes(vec![0, 0, 0, 0])]
    );

    let mut router_advertisement = Vec::new();
    router_advertisement.push(64);
    router_advertisement.push(0xc8);
    router_advertisement.extend_from_slice(&1800_u16.to_be_bytes());
    router_advertisement.extend_from_slice(&30_000_u32.to_be_bytes());
    router_advertisement.extend_from_slice(&1_000_u32.to_be_bytes());
    let full = icmpv6(134, 0, &router_advertisement);
    for length in [5_usize, 6, 7, 8, 12, 15] {
        let packet = decode_truncated(&full, length);
        assert!(packet.malformed, "RA length {length}");
    }
    let packet = decode_truncated(&full, 16);
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.nd.ra.retrans_timer"),
        vec![Value::Uint32(1_000)]
    );

    let mut neighbor = Vec::new();
    neighbor.extend_from_slice(&[0; 4]);
    neighbor.extend_from_slice(&LINK_LOCAL);
    let solicitation = icmpv6(135, 0, &neighbor);
    for length in [8_usize, 23] {
        let packet = decode_truncated(&solicitation, length);
        assert!(packet.malformed, "NS length {length}");
        assert!(values(&packet, "icmpv6.nd.ns.target_address").is_empty());
    }
    let packet = decode_truncated(&solicitation, 24);
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.nd.ns.target_address"),
        vec![Value::Ipv6(LINK_LOCAL)]
    );

    let mut redirect = Vec::new();
    redirect.extend_from_slice(&[0; 4]);
    redirect.extend_from_slice(&LINK_LOCAL);
    redirect.extend_from_slice(&DESTINATION);
    let full = icmpv6(137, 0, &redirect);
    for length in [24_usize, 39] {
        let packet = decode_truncated(&full, length);
        assert!(packet.malformed, "Redirect length {length}");
    }
    let packet = decode_truncated(&full, 40);
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.rd.na.destination_address"),
        vec![Value::Ipv6(DESTINATION)]
    );
}

#[test]
fn router_advertisement_and_neighbor_advertisement_flags() {
    let mut body = Vec::new();
    body.push(255);
    body.push(0xff);
    body.extend_from_slice(&1800_u16.to_be_bytes());
    body.extend_from_slice(&30_000_u32.to_be_bytes());
    body.extend_from_slice(&1_000_u32.to_be_bytes());
    let packet = decode(&icmpv6(134, 0, &body));
    assert_eq!(
        values(&packet, "icmpv6.nd.ra.flag"),
        vec![Value::Uint8(0xff)]
    );
    assert_eq!(u32_values(&packet, "icmpv6.nd.ra.flag.prf"), vec![3]);
    for field in [
        "icmpv6.nd.ra.flag.m",
        "icmpv6.nd.ra.flag.o",
        "icmpv6.nd.ra.flag.h",
        "icmpv6.nd.ra.flag.p",
        "icmpv6.nd.ra.flag.s",
    ] {
        assert_eq!(bool_values(&packet, field), vec![true], "{field}");
    }
    assert_eq!(u32_values(&packet, "icmpv6.nd.ra.flag.rsv"), vec![1]);

    let mut body = Vec::new();
    body.extend_from_slice(&0xffff_ffff_u32.to_be_bytes());
    body.extend_from_slice(&LINK_LOCAL);
    let packet = decode(&icmpv6(136, 0, &body));
    assert_eq!(
        values(&packet, "icmpv6.nd.na.flag"),
        vec![Value::Uint32(0xffff_ffff)]
    );
    for field in [
        "icmpv6.nd.na.flag.r",
        "icmpv6.nd.na.flag.s",
        "icmpv6.nd.na.flag.o",
    ] {
        assert_eq!(bool_values(&packet, field), vec![true], "{field}");
    }
    assert_eq!(
        u32_values(&packet, "icmpv6.nd.na.flag.rsv"),
        vec![0x1fff_ffff]
    );
    assert_eq!(
        values(&packet, "icmpv6.nd.na.target_address"),
        vec![Value::Ipv6(LINK_LOCAL)]
    );
}

fn option(option_type: u8, length: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(option_type);
    bytes.push(length);
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn link_layer_address_options_follow_the_declared_length() {
    let mac = [0x02, 0, 0, 0, 0, 0x01];

    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(1, 1, &mac));
    let packet = decode(&icmpv6(135, 0, &body));
    assert_eq!(
        values(&packet, "icmpv6.opt.linkaddr"),
        vec![Value::Ethernet(mac)]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.src_linkaddr"),
        vec![Value::Ethernet(mac)]
    );
    assert!(!packet.malformed);

    let fourteen = [
        0x02, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(1, 2, &fourteen));
    let packet = decode(&icmpv6(135, 0, &body));
    assert_eq!(
        values(&packet, "icmpv6.opt.linkaddr"),
        vec![Value::bytes(fourteen.to_vec())]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.src_linkaddr"),
        vec![Value::bytes(fourteen.to_vec())]
    );
    assert!(values(&packet, "icmpv6.opt.linkaddr_eui64").is_empty());
    assert!(values(&packet, "icmpv6.opt.padding").is_empty());
    assert!(!packet.malformed);
}

#[test]
fn eui64_link_layer_address_options_add_the_padding_node() {
    let mut eui = [0_u8; 14];
    eui[..8].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01, 0x02, 0x03]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(1, 2, &eui));
    let packet = decode(&icmpv6(135, 0, &body));
    let address = [0x02, 0, 0, 0, 0, 0x01, 0x02, 0x03];
    assert_eq!(
        values(&packet, "icmpv6.opt.linkaddr_eui64"),
        vec![Value::Eui64(address)]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.src_linkaddr_eui64"),
        vec![Value::Eui64(address)]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.linkaddr"),
        vec![Value::bytes(address.to_vec())]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.src_linkaddr"),
        vec![Value::bytes(address.to_vec())]
    );
    assert_eq!(values(&packet, "icmpv6.opt.padding"), vec![Value::None]);
    assert!(!packet.malformed);

    let mut body = Vec::new();
    body.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(2, 2, &eui));
    let packet = decode(&icmpv6(136, 0, &body));
    assert_eq!(
        values(&packet, "icmpv6.opt.target_linkaddr_eui64"),
        vec![Value::Eui64(address)]
    );
    assert!(values(&packet, "icmpv6.opt.linkaddr").is_empty());
    assert_eq!(values(&packet, "icmpv6.opt.padding"), vec![Value::None]);
}

#[test]
fn zero_option_length_stops_without_marking_the_packet_malformed() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    let mut bytes = option(1, 0, &[0x02, 0, 0, 0, 0, 0x01]);
    bytes.extend_from_slice(&option(1, 1, &[0x02, 0, 0, 0, 0, 0x02]));
    body.extend_from_slice(&bytes);
    let packet = decode(&icmpv6(135, 0, &body));
    assert!(!packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    assert_eq!(values(&packet, "icmpv6.opt.type"), vec![Value::Uint8(1)]);
    assert_eq!(values(&packet, "icmpv6.opt.length"), vec![Value::Uint8(0)]);
    assert!(values(&packet, "icmpv6.opt.linkaddr").is_empty());
}

#[test]
fn declared_option_length_beyond_capture_marks_the_packet_malformed() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(5, 1, &[0, 0, 0x05, 0xdc]));
    let packet = decode(&icmpv6(135, 0, &body));
    assert!(packet.malformed);
    assert_eq!(values(&packet, "icmpv6.opt.type"), vec![Value::Uint8(5)]);
    assert_eq!(values(&packet, "icmpv6.opt.length"), vec![Value::Uint8(1)]);
    assert_eq!(values(&packet, "icmpv6.opt.reserved"), vec![Value::None]);
    assert!(values(&packet, "icmpv6.opt.mtu").is_empty());
}

#[test]
fn trailing_option_byte_marks_the_packet_malformed() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(1, 1, &[0x02, 0, 0, 0, 0, 0x01]));
    body.push(0x01);
    let packet = decode(&icmpv6(135, 0, &body));
    assert!(packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.opt.linkaddr"),
        vec![Value::Ethernet([0x02, 0, 0, 0, 0, 0x01])]
    );
}

fn prefix_option(length: u8, prefix: [u8; 16]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(64);
    body.push(0xc0);
    body.extend_from_slice(&2_592_000_u32.to_be_bytes());
    body.extend_from_slice(&604_800_u32.to_be_bytes());
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&prefix);
    option(3, length, &body)
}

#[test]
fn prefix_option_requires_its_full_declared_length() {
    let prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut body = Vec::new();
    body.push(64);
    body.push(0xc8);
    body.extend_from_slice(&1800_u16.to_be_bytes());
    body.extend_from_slice(&30_000_u32.to_be_bytes());
    body.extend_from_slice(&1_000_u32.to_be_bytes());
    body.extend_from_slice(&prefix_option(4, prefix));
    let packet = decode(&icmpv6(134, 0, &body));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.opt.prefix"),
        vec![Value::Ipv6(prefix)]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.prefix.length"),
        vec![Value::Uint8(64)]
    );
    assert_eq!(
        values(&packet, "icmpv6.opt.prefix.flag"),
        vec![Value::Uint8(0xc0)]
    );
    assert_eq!(bool_values(&packet, "icmpv6.opt.prefix.flag.l"), vec![true]);
    assert_eq!(bool_values(&packet, "icmpv6.opt.prefix.flag.a"), vec![true]);
    assert_eq!(
        values(&packet, "icmpv6.opt.prefix.valid_lifetime"),
        vec![Value::Uint32(2_592_000)]
    );

    let short = prefix_option(3, prefix);
    let short = short.get(..24).unwrap_or(&[]).to_vec();
    let mut body = Vec::new();
    body.push(64);
    body.push(0xc8);
    body.extend_from_slice(&1800_u16.to_be_bytes());
    body.extend_from_slice(&30_000_u32.to_be_bytes());
    body.extend_from_slice(&1_000_u32.to_be_bytes());
    body.extend_from_slice(&short);
    let packet = decode(&icmpv6(134, 0, &body));
    assert!(packet.malformed);
    assert!(values(&packet, "icmpv6.opt.prefix").is_empty());
    assert_eq!(
        values(&packet, "icmpv6.opt.prefix.valid_lifetime"),
        vec![Value::Uint32(2_592_000)]
    );
    assert_eq!(values(&packet, "icmpv6.opt.reserved"), vec![Value::None]);
}

#[test]
fn option_fields_do_not_cross_the_declared_length() {
    let prefix = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let short = prefix_option(3, prefix);
    let mut body = Vec::new();
    body.push(64);
    body.push(0xc8);
    body.extend_from_slice(&1800_u16.to_be_bytes());
    body.extend_from_slice(&30_000_u32.to_be_bytes());
    body.extend_from_slice(&1_000_u32.to_be_bytes());
    body.extend_from_slice(short.get(..24).unwrap_or(&[]));
    // Bytes that would complete the prefix if reads crossed the option.
    body.extend_from_slice(&prefix[6..16]);
    let packet = decode(&icmpv6(134, 0, &body));
    assert!(packet.malformed);
    assert!(values(&packet, "icmpv6.opt.prefix").is_empty());
    assert_eq!(values(&packet, "icmpv6.opt.length"), vec![Value::Uint8(3)]);
}

#[test]
fn redirected_header_option_decodes_its_contained_packet() {
    let mut segment = Vec::new();
    segment.extend_from_slice(&1234_u16.to_be_bytes());
    segment.extend_from_slice(&4321_u16.to_be_bytes());
    segment.extend_from_slice(&8_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&INNER_SOURCE);
    pseudo.extend_from_slice(&INNER_DESTINATION);
    pseudo.extend_from_slice(&8_u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&segment);
    let value = checksum(&pseudo);
    set_u16(&mut segment, 6, value);
    let inner = udp_inside_ipv6(&segment);

    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&DESTINATION);
    let mut redirect_body = Vec::new();
    redirect_body.extend_from_slice(&[0; 6]);
    redirect_body.extend_from_slice(&inner);
    body.extend_from_slice(&option(4, 7, &redirect_body));
    let packet = decode(&icmpv6(137, 0, &body));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.opt.redirected_packet"),
        vec![Value::None]
    );
    assert_eq!(
        values(&packet, "ipv6.dst"),
        vec![Value::Ipv6(DESTINATION), Value::Ipv6(INNER_DESTINATION)]
    );
    assert_eq!(u32_values(&packet, "udp.srcport"), vec![1234]);
    assert!(values(&packet, "icmpv6.unknown_data").is_empty());
}

#[test]
fn one_unit_redirected_header_option_has_no_contained_packet_node() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&DESTINATION);
    body.extend_from_slice(&option(4, 1, &[0; 6]));
    let packet = decode(&icmpv6(137, 0, &body));
    assert!(!packet.malformed);
    assert_eq!(values(&packet, "icmpv6.opt.reserved"), vec![Value::None]);
    assert!(values(&packet, "icmpv6.opt.redirected_packet").is_empty());
}

#[test]
fn redirected_header_leftovers_become_unknown_data() {
    let mut segment = Vec::new();
    segment.extend_from_slice(&1234_u16.to_be_bytes());
    segment.extend_from_slice(&4321_u16.to_be_bytes());
    segment.extend_from_slice(&11_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(b"abc");
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&INNER_SOURCE);
    pseudo.extend_from_slice(&INNER_DESTINATION);
    pseudo.extend_from_slice(&11_u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&segment);
    let value = checksum(&pseudo);
    set_u16(&mut segment, 6, value);
    let inner = udp_inside_ipv6(&segment);

    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&DESTINATION);
    let mut redirect_body = Vec::new();
    redirect_body.extend_from_slice(&[0; 6]);
    redirect_body.extend_from_slice(&inner);
    redirect_body.extend_from_slice(&[0xbb; 5]);
    body.extend_from_slice(&option(4, 8, &redirect_body));
    let packet = decode(&icmpv6(137, 0, &body));
    assert!(!packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    assert_eq!(
        values(&packet, "icmpv6.unknown_data"),
        vec![Value::bytes(vec![0xbb; 5])]
    );
}

#[test]
fn quoted_udp_fields_repeat_and_outer_context_survives() {
    let inner = quoted_udp();
    let packet = decode(&icmpv6(
        1,
        3,
        &[0, 0, 0, 0]
            .iter()
            .copied()
            .chain(inner)
            .collect::<Vec<_>>(),
    ));

    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "ipv6.dst"),
        vec![Value::Ipv6(DESTINATION), Value::Ipv6(INNER_DESTINATION)]
    );
    assert_eq!(u32_values(&packet, "udp.srcport"), vec![1234]);
    assert_eq!(
        packet.network,
        Some(NetworkContext::Ipv6 {
            source: SOURCE,
            destination: DESTINATION,
            next_header: 58,
            fragmented: false,
        })
    );
    assert_eq!(packet.columns.source, Some("02:00:00:00:00:01".to_string()));
}

#[test]
fn quoted_tcp_fields_and_quoted_icmp_status() {
    let inner = quoted_tcp();
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&inner);
    let packet = decode(&icmpv6(1, 0, &body));
    assert!(values(&packet, "icmpv6.mtu").is_empty());
    assert_eq!(u32_values(&packet, "tcp.srcport"), vec![40_000]);

    let mut echo_body = Vec::new();
    echo_body.extend_from_slice(&0x1234_u16.to_be_bytes());
    echo_body.extend_from_slice(&5_u16.to_be_bytes());
    let quoted_echo = icmpv6(128, 0, &echo_body);
    let mut quoted_ipv6 = Vec::new();
    quoted_ipv6.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    quoted_ipv6.extend_from_slice(&u16::try_from(quoted_echo.len()).unwrap_or(0).to_be_bytes());
    quoted_ipv6.push(58);
    quoted_ipv6.push(64);
    quoted_ipv6.extend_from_slice(&INNER_SOURCE);
    quoted_ipv6.extend_from_slice(&INNER_DESTINATION);
    quoted_ipv6.extend_from_slice(&quoted_echo);
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&quoted_ipv6);
    let packet = decode(&icmpv6(3, 0, &body));
    assert_eq!(u32_values(&packet, "icmpv6.checksum.status"), vec![1, 2]);
    assert_eq!(
        values(&packet, "icmpv6.echo.identifier"),
        vec![Value::Uint16(0x1234)]
    );
}

#[test]
fn quoted_ipv4_payload_is_not_decoded_by_icmpv6() {
    let mut inner = Vec::new();
    inner.push(0x45);
    inner.push(0);
    inner.extend_from_slice(&20_u16.to_be_bytes());
    inner.extend_from_slice(&[0; 4]);
    inner.push(64);
    inner.push(17);
    inner.extend_from_slice(&[0; 4]);
    inner.extend_from_slice(&[10, 0, 0, 1]);
    inner.extend_from_slice(&[10, 0, 0, 2]);
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&inner);
    let packet = decode(&icmpv6(1, 0, &body));
    assert!(values(&packet, "ip.src").is_empty());
    assert_eq!(values(&packet, "ipv6.src").len(), 1);
}

#[test]
fn quoted_icmpv6_recursion_stops_at_the_decode_limit() {
    let mut message = icmpv6(128, 0, &[0x12, 0x34, 0, 1]);
    let mut packet_bytes = Vec::new();
    for _ in 0..(MAX_DECODE_DEPTH + 4) {
        let mut quoted = Vec::new();
        quoted.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
        quoted.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
        quoted.push(58);
        quoted.push(64);
        quoted.extend_from_slice(&INNER_SOURCE);
        quoted.extend_from_slice(&INNER_DESTINATION);
        quoted.extend_from_slice(&message);
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&quoted);
        message = icmpv6(1, 0, &body);
        packet_bytes = message.clone();
    }
    let packet = decode(&packet_bytes);
    let statuses = u32_values(&packet, "icmpv6.checksum.status");
    assert!(statuses.len() > 1);
    assert!(statuses.iter().skip(1).all(|status| *status == 2));
    assert!(packet.tree.has_expert(Group::Malformed));
}

#[test]
fn error_message_minimums_and_type_specific_fields() {
    let packet = decode_truncated(&icmpv6(1, 0, &[0, 0, 0, 0]), 8);
    assert!(packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.reserved"),
        vec![Value::bytes(vec![0, 0, 0, 0])]
    );

    let body = 1280_u32.to_be_bytes().to_vec();
    let packet = decode_truncated(&icmpv6(2, 0, &body), 8);
    assert!(packet.malformed);
    assert_eq!(values(&packet, "icmpv6.mtu"), vec![Value::Uint32(1280)]);

    let mut body = 7_u32.to_be_bytes().to_vec();
    body.extend_from_slice(&quoted_udp());
    let packet = decode(&icmpv6(4, 0, &body));
    assert!(!packet.malformed);
    assert_eq!(values(&packet, "icmpv6.pointer"), vec![Value::Uint32(7)]);
    assert_eq!(u32_values(&packet, "udp.srcport"), vec![1234]);

    let packet = decode_truncated(&icmpv6(4, 0, &body), 7);
    assert!(packet.malformed);
    assert!(values(&packet, "icmpv6.pointer").is_empty());
}

#[test]
fn unknown_message_type_data_starts_at_offset_four() {
    let packet = decode(&icmpv6(200, 0, b"abcd"));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.data"),
        vec![Value::bytes(b"abcd".to_vec())]
    );

    let full = icmpv6(200, 0, b"abcd");
    let packet = decode_truncated(&full, 4);
    assert!(!packet.malformed);
    assert!(values(&packet, "icmpv6.data").is_empty());
}

#[test]
fn unknown_option_type_keeps_its_declared_data() {
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&LINK_LOCAL);
    body.extend_from_slice(&option(
        99,
        2,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    ));
    let packet = decode(&icmpv6(135, 0, &body));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.data"),
        vec![Value::bytes(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
        ])]
    );
}

#[test]
fn capture_truncation_leaves_the_icmpv6_checksum_unverified() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1234_u16.to_be_bytes());
    body.extend_from_slice(&5_u16.to_be_bytes());
    let message = icmpv6(128, 0, &body);
    let full = ethernet(&ipv6_payload_length(&message, None));
    let original = u32::try_from(full.len()).unwrap_or(u32::MAX);
    let captured = full
        .get(..full.len().saturating_sub(3))
        .unwrap_or(&[])
        .to_vec();
    let packet = decode_frame(&frame_with_original(captured, original));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "icmpv6.checksum.status"),
        vec![Value::Uint8(2)]
    );
}

#[test]
fn quoted_ipv6_prefix_shorter_than_its_payload_length_keeps_transport_fields() {
    let mut segment = Vec::new();
    segment.extend_from_slice(&1234_u16.to_be_bytes());
    segment.extend_from_slice(&4321_u16.to_be_bytes());
    segment.extend_from_slice(&1008_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    let mut quoted = Vec::new();
    quoted.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    quoted.extend_from_slice(&1000_u16.to_be_bytes());
    quoted.push(17);
    quoted.push(64);
    quoted.extend_from_slice(&INNER_SOURCE);
    quoted.extend_from_slice(&INNER_DESTINATION);
    quoted.extend_from_slice(&segment);
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&quoted);
    let packet = decode(&icmpv6(1, 0, &body));
    assert!(!packet.malformed);
    assert_eq!(u32_values(&packet, "udp.srcport"), vec![1234]);
    assert_eq!(u32_values(&packet, "udp.dstport"), vec![4321]);
}

fn jumbogram(message: &[u8]) -> Vec<u8> {
    let mut hop = Vec::new();
    hop.push(58);
    hop.push(0);
    hop.extend_from_slice(&[0xc2, 0x04]);
    let jumbo = u32::try_from(8 + message.len()).unwrap_or(0);
    hop.extend_from_slice(&jumbo.to_be_bytes());
    let mut payload = hop;
    payload.extend_from_slice(message);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.push(0);
    bytes.push(64);
    bytes.extend_from_slice(&SOURCE);
    bytes.extend_from_slice(&DESTINATION);
    bytes.extend_from_slice(&payload);
    bytes
}

#[test]
fn jumbogram_reported_length_drives_the_checksum_status() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1234_u16.to_be_bytes());
    body.extend_from_slice(&5_u16.to_be_bytes());
    body.resize(65_524, 0);
    let message = icmpv6(128, 0, &body);
    let full = ethernet(&jumbogram(&message));
    let packet = decode_frame(&frame(full.clone()));
    assert_eq!(
        values(&packet, "icmpv6.checksum.status"),
        vec![Value::Uint8(1)]
    );
    assert!(!packet.malformed);

    let original = u32::try_from(full.len()).unwrap_or(u32::MAX);
    let captured = full.get(..1_100).unwrap_or(&[]).to_vec();
    let packet = decode_frame(&frame_with_original(captured, original));
    assert_eq!(
        values(&packet, "icmpv6.checksum.status"),
        vec![Value::Uint8(2)]
    );
    assert!(!packet.malformed);
}

#[test]
fn one_unit_prefix_option_does_not_read_the_following_option() {
    let mut body = Vec::new();
    body.push(64);
    body.push(0xc8);
    body.extend_from_slice(&1800_u16.to_be_bytes());
    body.extend_from_slice(&30_000_u32.to_be_bytes());
    body.extend_from_slice(&1_000_u32.to_be_bytes());
    body.extend_from_slice(&option(3, 1, &[64, 0xc0, 0, 0, 0, 0]));
    body.extend_from_slice(&option(1, 1, &[0x02, 0, 0, 0, 0, 0x01]));
    let packet = decode(&icmpv6(134, 0, &body));
    assert!(packet.malformed);
    assert!(values(&packet, "icmpv6.opt.prefix.preferred_lifetime").is_empty());
    assert!(values(&packet, "icmpv6.opt.prefix").is_empty());
}
