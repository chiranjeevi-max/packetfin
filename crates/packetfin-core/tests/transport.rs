//! Transport-layer decoding tests: UDP and TCP fields, options, checksum
//! statuses, length boundaries, fragmentation suppression and dispatch.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{
    DecodeOptions, NetworkContext, Preferences, decode_frame, decode_frame_with_options,
};
use packetfin_core::tree::{Group, Range, Value};

const DESTINATION_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SOURCE_ADDRESS: [u8; 4] = [192, 0, 2, 1];
const DESTINATION_ADDRESS: [u8; 4] = [198, 51, 100, 2];
const SOURCE_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DESTINATION_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const PAYLOAD: &[u8] = b"packetfin";

fn frame(link_type: u32, captured: Vec<u8>) -> Frame {
    Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        timestamp_precision: 6,
        original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
        captured,
        link_type,
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

fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&DESTINATION_MAC);
    bytes.extend_from_slice(&SOURCE_MAC);
    bytes.extend_from_slice(&ethertype.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn checksum(words: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (pairs, rest) = words.as_chunks::<2>();
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

fn ipv4(protocol: u8, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x45);
    header.push(0);
    header.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap_or(0).to_be_bytes());
    header.extend_from_slice(&0x1c46_u16.to_be_bytes());
    header.extend_from_slice(&flags.to_be_bytes());
    header.push(64);
    header.push(protocol);
    header.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&SOURCE_ADDRESS);
    header.extend_from_slice(&DESTINATION_ADDRESS);
    let value = checksum(&header);
    if let Some(bytes) = header.get_mut(10..12) {
        bytes.copy_from_slice(&value.to_be_bytes());
    }
    header.extend_from_slice(payload);
    header
}

fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    bytes.push(next);
    bytes.push(64);
    bytes.extend_from_slice(&SOURCE_IPV6);
    bytes.extend_from_slice(&DESTINATION_IPV6);
    bytes.extend_from_slice(payload);
    bytes
}

fn pseudo_checksum(ip_version: u8, protocol: u8, data: &[u8]) -> u16 {
    let mut bytes = Vec::new();
    if ip_version == 6 {
        bytes.extend_from_slice(&SOURCE_IPV6);
        bytes.extend_from_slice(&DESTINATION_IPV6);
        bytes.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, protocol]);
    } else {
        bytes.extend_from_slice(&SOURCE_ADDRESS);
        bytes.extend_from_slice(&DESTINATION_ADDRESS);
        bytes.extend_from_slice(&[0, protocol]);
        bytes.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
    }
    bytes.extend_from_slice(data);
    checksum(&bytes)
}

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    let [high, low] = value.to_be_bytes();
    if let Some(byte) = bytes.get_mut(offset) {
        *byte = high;
    }
    if let Some(byte) = bytes.get_mut(offset + 1) {
        *byte = low;
    }
}

fn udp(
    ip_version: u8,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    length: u16,
    checksum_override: Option<u16>,
) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&length.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let covered = segment.get(..usize::from(length)).unwrap_or(&segment);
    let value =
        checksum_override.unwrap_or_else(|| match pseudo_checksum(ip_version, 17, covered) {
            0 => 0xffff,
            other => other,
        });
    set_u16(&mut segment, 6, value);
    segment
}

/// TCP header fields written by the test helper.
#[derive(Clone, Copy, Debug, Default)]
struct TcpFields<'a> {
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    options: &'a [u8],
    payload: &'a [u8],
    data_offset: Option<u8>,
    checksum_override: Option<u16>,
}

fn tcp(ip_version: u8, fields: TcpFields<'_>) -> Vec<u8> {
    let offset = fields.data_offset.unwrap_or_else(|| {
        5_u8.saturating_add(u8::try_from(fields.options.len() / 4).unwrap_or(0))
    });
    let mut segment = Vec::new();
    segment.extend_from_slice(&40_000_u16.to_be_bytes());
    segment.extend_from_slice(&443_u16.to_be_bytes());
    segment.extend_from_slice(&fields.sequence.to_be_bytes());
    segment.extend_from_slice(&fields.acknowledgement.to_be_bytes());
    segment.push(offset << 4);
    segment.push(fields.flags);
    segment.extend_from_slice(&65_535_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(fields.options);
    segment.extend_from_slice(fields.payload);
    let value = fields
        .checksum_override
        .unwrap_or_else(|| pseudo_checksum(ip_version, 6, &segment));
    set_u16(&mut segment, 16, value);
    segment
}

fn values<'a>(packet: &'a packetfin_core::Packet, abbrev: &str) -> Vec<&'a Value> {
    packet.tree.field_values(abbrev)
}

fn transport_node<'a>(
    packet: &'a packetfin_core::Packet,
    name: &str,
) -> Option<&'a packetfin_core::Node> {
    packet
        .tree
        .frame
        .child("eth")
        .and_then(|eth| eth.child("ip").or_else(|| eth.child("ipv6")))
        .and_then(|ip| ip.child(name))
}

fn field_range(packet: &packetfin_core::Packet, abbrev: &str) -> Option<Range> {
    packet
        .tree
        .fields()
        .find(|field| field.def.abbrev == abbrev)
        .map(|field| field.range)
}

#[test]
fn udp_fields_ranges_and_ports() {
    let segment = udp(4, 12_345, 9_999, PAYLOAD, 17, None);
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &segment))));
    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "ip", "udp"]);
    assert_eq!(values(&packet, "udp.srcport"), vec![&Value::Uint16(12_345)]);
    assert_eq!(values(&packet, "udp.dstport"), vec![&Value::Uint16(9_999)]);
    assert_eq!(
        values(&packet, "udp.port"),
        vec![&Value::Uint16(12_345), &Value::Uint16(9_999)]
    );
    assert_eq!(values(&packet, "udp.length"), vec![&Value::Uint16(17)]);
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(2)]
    );
    assert!(values(&packet, "udp.checksum_calculated").is_empty());
    assert_eq!(
        values(&packet, "udp.payload"),
        vec![&Value::bytes(PAYLOAD.to_vec())]
    );
    assert_eq!(field_range(&packet, "udp.srcport"), Some(Range::new(34, 2)));
    assert_eq!(field_range(&packet, "udp.length"), Some(Range::new(38, 2)));
    assert_eq!(field_range(&packet, "udp.payload"), Some(Range::new(42, 9)));
    assert!(transport_node(&packet, "tcp").is_none());
}

#[test]
fn udp_checksum_statuses() {
    let validated = DecodeOptions {
        preferences: Preferences {
            udp_check_checksum: true,
            ..Preferences::default()
        },
        ..DecodeOptions::default()
    };
    let good = udp(4, 12_345, 9_999, PAYLOAD, 17, None);
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &good))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(1)]
    );
    assert_eq!(
        values(&packet, "udp.checksum_calculated"),
        values(&packet, "udp.checksum")
    );

    let bad = udp(4, 12_345, 9_999, PAYLOAD, 17, Some(0x1234));
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &bad))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(0)]
    );
    assert!(packet.tree.has_expert(Group::Checksum));

    let zero4 = udp(4, 12_345, 9_999, PAYLOAD, 17, Some(0));
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &zero4))));
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(3)]
    );
    assert!(values(&packet, "udp.checksum_calculated").is_empty());
    assert!(!packet.tree.has_expert(Group::Checksum));

    let zero6 = udp(6, 12_345, 9_999, PAYLOAD, 17, Some(0));
    let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(17, &zero6))));
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(4)]
    );
    assert!(packet.tree.has_expert(Group::Checksum));

    let good6 = udp(6, 12_345, 9_999, PAYLOAD, 17, None);
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x86dd, &ipv6(17, &good6))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(1)]
    );
}

#[test]
fn udp_length_boundaries_and_truncation() {
    let short = udp(4, 12_345, 9_999, PAYLOAD, 4, Some(0x1234));
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &short))));
    assert!(packet.malformed);
    assert_eq!(values(&packet, "udp.length"), vec![&Value::Uint16(4)]);
    assert!(values(&packet, "udp.checksum").is_empty());
    assert!(values(&packet, "udp.checksum.status").is_empty());
    assert!(values(&packet, "udp.payload").is_empty());
    assert!(packet.tree.has_expert(Group::Malformed));

    let long = udp(4, 12_345, 9_999, PAYLOAD, 20, Some(0x1234));
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &long))),
        DecodeOptions {
            preferences: Preferences {
                udp_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    assert!(packet.malformed);
    assert_eq!(
        values(&packet, "udp.checksum.status"),
        vec![&Value::Uint8(2)]
    );
    assert!(values(&packet, "udp.checksum_calculated").is_empty());
    assert_eq!(
        values(&packet, "udp.payload"),
        vec![&Value::bytes(PAYLOAD.to_vec())]
    );

    let padded = udp(4, 12_345, 9_999, PAYLOAD, 12, None);
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &padded))));
    assert!(!packet.malformed);
    assert_eq!(
        values(&packet, "udp.payload"),
        vec![&Value::bytes(PAYLOAD.to_vec())]
    );

    let no_payload = udp(4, 12_345, 9_999, PAYLOAD, 8, None);
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(17, 0x4000, &no_payload))));
    assert!(values(&packet, "udp.payload").is_empty());

    let four = udp(4, 12_345, 9_999, PAYLOAD, 17, None);
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(17, 0x4000, four.get(..4).unwrap_or(&[]))),
    ));
    assert!(packet.malformed);
    assert_eq!(values(&packet, "udp.srcport"), vec![&Value::Uint16(12_345)]);
    assert!(values(&packet, "udp.length").is_empty());

    let six = four.get(..6).unwrap_or(&[]);
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(17, 0x4000, six))));
    assert!(packet.malformed);
    assert_eq!(values(&packet, "udp.length"), vec![&Value::Uint16(17)]);
    assert!(values(&packet, "udp.checksum").is_empty());

    for prefix in 1_usize..=3 {
        let packet = decode_frame(&frame(
            1,
            ethernet(0x0800, &ipv4(17, 0x4000, four.get(..prefix).unwrap_or(&[]))),
        ));
        assert!(packet.malformed);
        assert!(transport_node(&packet, "udp").is_some());
        assert!(values(&packet, "udp.srcport").is_empty());
        assert!(values(&packet, "udp.port").is_empty());
        assert_eq!(packet.protocol_stack, vec!["eth", "ip", "udp"]);
    }
}

#[test]
fn tcp_fields_flags_and_ranges() {
    let options = [
        0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x01, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x11, 0x22, 0x33,
        0x44, 0x00, 0x00, 0x00, 0x00,
    ];
    let segment = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &options,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))));
    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "ip", "tcp"]);
    // A lone SYN prints sequence zero relative to its own ISN.
    assert_eq!(values(&packet, "tcp.seq"), vec![&Value::Uint32(0)]);
    assert_eq!(values(&packet, "tcp.seq_raw"), vec![&Value::Uint32(1_000)]);
    assert_eq!(values(&packet, "tcp.nxtseq"), vec![&Value::Uint32(1)]);
    assert_eq!(values(&packet, "tcp.hdr_len"), vec![&Value::Uint8(40)]);
    assert_eq!(values(&packet, "tcp.flags"), vec![&Value::Uint16(0x0002)]);
    assert_eq!(
        values(&packet, "tcp.flags.syn"),
        vec![&Value::Boolean(true)]
    );
    assert_eq!(
        values(&packet, "tcp.flags.fin"),
        vec![&Value::Boolean(false)]
    );
    assert_eq!(
        values(&packet, "tcp.flags.str"),
        vec![&Value::String("\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}S\u{00b7}".to_string())]
    );
    assert_eq!(
        values(&packet, "tcp.window_size_value"),
        vec![&Value::Uint16(65_535)]
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(2)]
    );
    assert_eq!(values(&packet, "tcp.len"), vec![&Value::Uint32(0)]);
    assert_eq!(
        values(&packet, "tcp.options.mss_val"),
        vec![&Value::Uint16(1_460)]
    );
    assert_eq!(
        values(&packet, "tcp.options.wscale.shift"),
        vec![&Value::Uint8(7)]
    );
    assert_eq!(
        values(&packet, "tcp.options.wscale.multiplier"),
        vec![&Value::Uint16(128)]
    );
    assert_eq!(
        values(&packet, "tcp.options.timestamp.tsval"),
        vec![&Value::Uint32(0x1122_3344)]
    );
    assert_eq!(
        values(&packet, "tcp.options.timestamp.tsecr"),
        vec![&Value::Uint32(0)]
    );
    assert_eq!(field_range(&packet, "tcp.seq"), Some(Range::new(38, 4)));
    assert_eq!(field_range(&packet, "tcp.hdr_len"), Some(Range::new(46, 1)));
    assert_eq!(field_range(&packet, "tcp.flags"), Some(Range::new(46, 2)));
}

#[test]
fn tcp_options_and_malformed_lengths() {
    let mut sack = Vec::new();
    sack.extend_from_slice(&[0x05, 0x12]);
    sack.extend_from_slice(&6_000_u32.to_be_bytes());
    sack.extend_from_slice(&7_000_u32.to_be_bytes());
    sack.extend_from_slice(&8_000_u32.to_be_bytes());
    sack.extend_from_slice(&9_000_u32.to_be_bytes());
    sack.extend_from_slice(&[0x01, 0x01]);
    let segment = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x18,
            options: &sack,
            payload: b"world",
            ..Default::default()
        },
    );
    let options = packetfin_core::decode::DecodeOptions {
        preferences: packetfin_core::decode::Preferences {
            tcp_relative_sequence_numbers: false,
            ..packetfin_core::decode::Preferences::default()
        },
        ..packetfin_core::decode::DecodeOptions::default()
    };
    let packet = packetfin_core::decode::decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))),
        options,
    );
    assert_eq!(
        values(&packet, "tcp.options.sack_le"),
        vec![&Value::Uint32(6_000), &Value::Uint32(8_000)]
    );
    assert_eq!(
        values(&packet, "tcp.options.sack_re"),
        vec![&Value::Uint32(7_000), &Value::Uint32(9_000)]
    );
    assert_eq!(
        values(&packet, "tcp.options.sack.count"),
        vec![&Value::Uint8(2)]
    );
    assert_eq!(
        values(&packet, "tcp.payload"),
        vec![&Value::bytes(b"world".to_vec())]
    );

    let invalid_mss = [0x02, 0x05, 0x05, 0xb4, 0x00, 0x00, 0x00, 0x00];
    let segment = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &invalid_mss,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))));
    assert_eq!(
        values(&packet, "tcp.option.len.invalid"),
        vec![&Value::None]
    );
    assert!(values(&packet, "tcp.options.mss_val").is_empty());
    assert_eq!(
        values(&packet, "tcp.option_kind"),
        vec![
            &Value::Uint8(2),
            &Value::Uint8(0),
            &Value::Uint8(0),
            &Value::Uint8(0)
        ]
    );

    let unknown = [0x1e, 0x04, 0xaa, 0xbb];
    let segment = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &unknown,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))));
    assert_eq!(values(&packet, "tcp.option_kind"), vec![&Value::Uint8(30)]);
    assert_eq!(values(&packet, "tcp.option_len"), vec![&Value::Uint8(4)]);
    assert!(values(&packet, "tcp.option.len.invalid").is_empty());
}

#[test]
fn tcp_header_length_and_capture_boundaries() {
    let short_header = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x10,
            data_offset: Some(4),
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &short_header))));
    assert_eq!(values(&packet, "tcp.hdr_len"), vec![&Value::Uint8(16)]);
    assert_eq!(values(&packet, "tcp.len"), vec![&Value::Uint32(4)]);
    assert!(values(&packet, "tcp.ack").is_empty());
    assert!(values(&packet, "tcp.flags").is_empty());
    assert!(packet.tree.has_expert(Group::Protocol));

    let long_header = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x10,
            data_offset: Some(15),
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &long_header))));
    assert_eq!(values(&packet, "tcp.hdr_len"), vec![&Value::Uint8(60)]);
    assert!(values(&packet, "tcp.len").is_empty());
    assert_eq!(values(&packet, "tcp.options"), vec![&Value::Missing]);
    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));

    let full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x18,
            payload: b"hello",
            ..Default::default()
        },
    );
    for count in [4_usize, 13] {
        let packet = decode_frame(&frame(
            1,
            ethernet(0x0800, &ipv4(6, 0x4000, full.get(..count).unwrap_or(&[]))),
        ));
        assert!(packet.malformed);
        assert_eq!(values(&packet, "tcp.srcport"), vec![&Value::Uint16(40_000)]);
        assert!(values(&packet, "tcp.seq").is_empty());
    }
    for count in [14_usize, 16, 18, 19] {
        let packet = decode_frame(&frame(
            1,
            ethernet(0x0800, &ipv4(6, 0x4000, full.get(..count).unwrap_or(&[]))),
        ));
        assert!(values(&packet, "tcp.seq").len() == 1);
        assert_eq!(
            values(&packet, "tcp.window_size_value").len(),
            usize::from(count >= 16)
        );
        assert_eq!(
            values(&packet, "tcp.checksum").len(),
            usize::from(count >= 18)
        );
        assert!(values(&packet, "tcp.urgent_pointer").is_empty());
        assert!(packet.malformed);
        assert!(packet.tree.has_expert(Group::Malformed));
    }

    let options_full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &[0x02, 0x04, 0x05, 0xb4],
            ..Default::default()
        },
    );
    let cut = options_full.get(..22).unwrap_or(&[]);
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, cut))));
    assert_eq!(
        values(&packet, "tcp.options"),
        vec![&Value::bytes(vec![0x02, 0x04])]
    );
    assert_eq!(values(&packet, "tcp.option_kind"), vec![&Value::Uint8(2)]);
    assert_eq!(values(&packet, "tcp.option_len"), vec![&Value::Uint8(4)]);
    assert!(values(&packet, "tcp.options.mss_val").is_empty());
    assert!(packet.malformed);
}

#[test]
fn tcp_shorter_than_its_ports_owns_the_expert() {
    let segment = tcp(
        4,
        TcpFields {
            flags: 0x10,
            ..Default::default()
        },
    );
    for length in 1_usize..=3 {
        let packet = decode_frame(&frame(
            1,
            ethernet(
                0x0800,
                &ipv4(6, 0x4000, segment.get(..length).unwrap_or(&[])),
            ),
        ));
        assert!(packet.malformed);
        assert_eq!(packet.protocol_stack, vec!["eth", "ip", "tcp"]);
        let tcp = transport_node(&packet, "tcp");
        assert_eq!(tcp.map(|node| node.experts.len()), Some(1));
        assert_eq!(
            tcp.and_then(|node| node.experts.first())
                .map(|expert| expert.group),
            Some(Group::Malformed)
        );
        assert_eq!(
            tcp.and_then(|node| node.experts.first())
                .map(|expert| expert.message.as_str()),
            Some("TCP header is shorter than its ports")
        );
        let ip = packet
            .tree
            .frame
            .child("eth")
            .and_then(|eth| eth.child("ip"));
        assert_eq!(ip.map(|node| node.experts.len()), Some(0));
    }
}

#[test]
fn tcp_checksum_statuses() {
    let validated = DecodeOptions {
        preferences: Preferences {
            tcp_check_checksum: true,
            ..Preferences::default()
        },
        ..DecodeOptions::default()
    };
    let good = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x18,
            payload: b"hello",
            ..Default::default()
        },
    );
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &good))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(1)]
    );
    assert_eq!(
        values(&packet, "tcp.checksum_calculated"),
        values(&packet, "tcp.checksum")
    );

    let bad = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x10,
            checksum_override: Some(0x1234),
            ..Default::default()
        },
    );
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &bad))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(0)]
    );
    assert!(packet.tree.has_expert(Group::Checksum));

    let zero4 = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x10,
            checksum_override: Some(0),
            ..Default::default()
        },
    );
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &zero4))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(0)]
    );

    let good6 = tcp(
        6,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x18,
            payload: b"hello",
            ..Default::default()
        },
    );
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x86dd, &ipv6(6, &good6))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(1)]
    );

    let zero6 = tcp(
        6,
        TcpFields {
            sequence: 1_000,
            acknowledgement: 2_000,
            flags: 0x10,
            checksum_override: Some(0),
            ..Default::default()
        },
    );
    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x86dd, &ipv6(6, &zero6))),
        validated.clone(),
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(0)]
    );
}

#[test]
fn fragments_do_not_decode_transport() {
    let udp_datagram = udp(4, 12_345, 9_999, PAYLOAD, 17, None);
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(17, 0x2000, &udp_datagram)),
    ));
    assert!(transport_node(&packet, "udp").is_none());
    assert!(matches!(
        packet.network,
        Some(NetworkContext::Ipv4 {
            protocol: 17,
            fragmented: true,
            ..
        })
    ));

    let tcp = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x2000 | 10, &tcp))));
    assert!(transport_node(&packet, "tcp").is_none());

    let udp6 = udp(6, 12_345, 9_999, PAYLOAD, 17, None);
    let mut fragment = Vec::new();
    fragment.extend_from_slice(&[17, 0]);
    fragment.extend_from_slice(&0x0008_u16.to_be_bytes());
    fragment.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
    fragment.extend_from_slice(&udp6);
    let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(44, &fragment))));
    assert!(transport_node(&packet, "udp").is_none());
    assert!(matches!(
        packet.network,
        Some(NetworkContext::Ipv6 {
            next_header: 17,
            fragmented: true,
            ..
        })
    ));
}

#[test]
fn tcp_rst_keeps_len_without_payload() {
    for flags in [0x04_u8, 0x14] {
        let segment = tcp(
            4,
            TcpFields {
                sequence: 1_000,
                acknowledgement: 2_000,
                flags,
                payload: b"rst!!",
                ..Default::default()
            },
        );
        let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))));
        assert_eq!(values(&packet, "tcp.len"), vec![&Value::Uint32(5)]);
        assert!(values(&packet, "tcp.payload").is_empty());
        assert_eq!(
            transport_node(&packet, "tcp").map(|node| node.children.len()),
            Some(0)
        );
    }
}

#[test]
fn udp_ports_appear_atomically() {
    let segment = udp(4, 12_345, 9_999, PAYLOAD, 17, None);
    for prefix in 1_usize..=8 {
        let packet = decode_frame(&frame(
            1,
            ethernet(
                0x0800,
                &ipv4(17, 0x4000, segment.get(..prefix).unwrap_or(&[])),
            ),
        ));
        assert!(packet.malformed, "prefix {prefix}");
        assert!(transport_node(&packet, "udp").is_some(), "prefix {prefix}");
        if prefix < 4 {
            assert!(values(&packet, "udp.srcport").is_empty(), "prefix {prefix}");
            assert!(values(&packet, "udp.dstport").is_empty(), "prefix {prefix}");
            assert!(values(&packet, "udp.port").is_empty(), "prefix {prefix}");
        } else {
            assert_eq!(
                values(&packet, "udp.srcport"),
                vec![&Value::Uint16(12_345)],
                "prefix {prefix}"
            );
            assert_eq!(
                values(&packet, "udp.dstport"),
                vec![&Value::Uint16(9_999)],
                "prefix {prefix}"
            );
            assert_eq!(values(&packet, "udp.port").len(), 2, "prefix {prefix}");
        }
        if prefix < 6 {
            assert!(values(&packet, "udp.length").is_empty(), "prefix {prefix}");
        } else {
            assert_eq!(
                values(&packet, "udp.length"),
                vec![&Value::Uint16(17)],
                "prefix {prefix}"
            );
        }
        if prefix < 8 {
            assert!(
                values(&packet, "udp.checksum").is_empty(),
                "prefix {prefix}"
            );
        } else {
            assert_eq!(values(&packet, "udp.checksum").len(), 1, "prefix {prefix}");
        }
    }
}

#[test]
fn sack_without_complete_block_stops_option_area() {
    for length in 2_u8..=9 {
        let mut options = Vec::new();
        options.push(0x05);
        options.push(length);
        for index in 0..usize::from(length.saturating_sub(2)) {
            options.push(u8::try_from(index).unwrap_or(0));
        }
        options.extend_from_slice(&[0x02, 0x04, 0x05, 0xb4]);
        options.resize(16, 0);
        let segment = tcp(
            4,
            TcpFields {
                sequence: 1_000,
                flags: 0x02,
                options: &options,
                ..Default::default()
            },
        );
        let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))));
        assert_eq!(
            values(&packet, "tcp.option_kind"),
            vec![&Value::Uint8(5)],
            "length {length}"
        );
        assert_eq!(
            values(&packet, "tcp.options.sack.count"),
            vec![&Value::Uint8(0)],
            "length {length}"
        );
        assert!(
            values(&packet, "tcp.options.mss_val").is_empty(),
            "length {length}"
        );
    }
}

#[test]
fn truncated_options_keep_present_values() {
    let mut timestamps = Vec::new();
    timestamps.extend_from_slice(&[0x08, 0x0a]);
    timestamps.extend_from_slice(&0x1122_3344_u32.to_be_bytes());
    timestamps.extend_from_slice(&0x5566_7788_u32.to_be_bytes());
    timestamps.extend_from_slice(&[0x01, 0x01]);
    let full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &timestamps,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(6, 0x4000, full.get(..26).unwrap_or(&[]))),
    ));
    assert_eq!(
        values(&packet, "tcp.options.timestamp.tsval"),
        vec![&Value::Uint32(0x1122_3344)]
    );
    assert!(values(&packet, "tcp.options.timestamp.tsecr").is_empty());
    assert!(packet.malformed);

    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(6, 0x4000, full.get(..30).unwrap_or(&[]))),
    ));
    assert_eq!(
        values(&packet, "tcp.options.timestamp.tsecr"),
        vec![&Value::Uint32(0x5566_7788)]
    );

    let mut sack = Vec::new();
    sack.extend_from_slice(&[0x05, 0x0a]);
    sack.extend_from_slice(&2_000_u32.to_be_bytes());
    sack.extend_from_slice(&3_000_u32.to_be_bytes());
    sack.extend_from_slice(&[0x01, 0x01]);
    let full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &sack,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(6, 0x4000, full.get(..26).unwrap_or(&[]))),
    ));
    assert_eq!(
        values(&packet, "tcp.options.sack_le"),
        vec![&Value::Uint32(2_000)]
    );
    assert!(values(&packet, "tcp.options.sack_re").is_empty());
    assert!(values(&packet, "tcp.options.sack.count").is_empty());
    assert!(packet.malformed);

    let window_scale = [0x03, 0x04, 0x07, 0x00];
    let full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &window_scale,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(6, 0x4000, full.get(..23).unwrap_or(&[]))),
    ));
    assert_eq!(
        values(&packet, "tcp.option.len.invalid"),
        vec![&Value::None]
    );
    assert!(values(&packet, "tcp.options.wscale.shift").is_empty());
    assert!(packet.malformed);

    let mss_six = [0x02, 0x06, 0x05, 0xb4, 0x00, 0x00, 0x00, 0x00];
    let full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &mss_six,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(6, 0x4000, full.get(..25).unwrap_or(&[]))),
    ));
    assert_eq!(
        values(&packet, "tcp.option.len.invalid"),
        vec![&Value::None]
    );
    assert!(values(&packet, "tcp.options.mss_val").is_empty());
    assert!(packet.malformed);
}

#[test]
fn nxtseq_counts_syn_or_fin_once() {
    let options = packetfin_core::decode::DecodeOptions {
        preferences: packetfin_core::decode::Preferences {
            tcp_relative_sequence_numbers: false,
            ..packetfin_core::decode::Preferences::default()
        },
        ..packetfin_core::decode::DecodeOptions::default()
    };
    for (payload, expected) in [(&[][..], 1_001_u32), (&b"hello"[..], 1_006)] {
        let segment = tcp(
            4,
            TcpFields {
                sequence: 1_000,
                acknowledgement: 2_000,
                flags: 0x03,
                payload,
                ..Default::default()
            },
        );
        let packet = packetfin_core::decode::decode_frame_with_options(
            &frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &segment))),
            options.clone(),
        );
        assert_eq!(
            values(&packet, "tcp.nxtseq"),
            vec![&Value::Uint32(expected)]
        );
    }
}

#[test]
fn lone_option_kind_at_complete_end_is_invalid() {
    let complete = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &[0x01, 0x01, 0x01, 0x02],
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(6, 0x4000, &complete))));
    assert_eq!(
        values(&packet, "tcp.option.len.invalid"),
        vec![&Value::None]
    );

    let options = [0x01, 0x01, 0x01, 0x02, 0x04, 0x05, 0xb4, 0x00];
    let full = tcp(
        4,
        TcpFields {
            sequence: 1_000,
            flags: 0x02,
            options: &options,
            ..Default::default()
        },
    );
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(6, 0x4000, full.get(..24).unwrap_or(&[]))),
    ));
    assert!(values(&packet, "tcp.option.len.invalid").is_empty());
    assert!(packet.malformed);
}

#[test]
fn jumbogram_checksum_folds_carries() {
    let mut segment = vec![0xff_u8; 140_020];
    for (offset, value) in [(0_usize, 40_000_u16), (2, 443), (14, 65_535)] {
        set_u16(&mut segment, offset, value);
    }
    if let Some(byte) = segment.get_mut(12) {
        *byte = 0x50;
    }
    if let Some(byte) = segment.get_mut(13) {
        *byte = 0x18;
    }
    set_u16(&mut segment, 16, 0);
    let checksum = folded_pseudo_checksum(&segment);
    set_u16(&mut segment, 16, checksum);

    let jumbo_length = u32::try_from(16 + segment.len()).unwrap_or(u32::MAX);
    let mut hopopts = Vec::new();
    hopopts.extend_from_slice(&[6, 1]);
    hopopts.push(0xc2);
    hopopts.push(4);
    hopopts.extend_from_slice(&jumbo_length.to_be_bytes());
    hopopts.extend_from_slice(&[0x00; 8]);
    let mut payload = hopopts;
    payload.extend_from_slice(&segment);

    let mut ipv6_header = Vec::new();
    ipv6_header.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
    ipv6_header.extend_from_slice(&0_u16.to_be_bytes());
    ipv6_header.push(0);
    ipv6_header.push(64);
    ipv6_header.extend_from_slice(&SOURCE_IPV6);
    ipv6_header.extend_from_slice(&DESTINATION_IPV6);
    ipv6_header.extend_from_slice(&payload);

    let packet = decode_frame_with_options(
        &frame(1, ethernet(0x86dd, &ipv6_header)),
        DecodeOptions {
            preferences: Preferences {
                tcp_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    assert_eq!(
        values(&packet, "tcp.checksum.status"),
        vec![&Value::Uint8(1)]
    );
    assert_eq!(
        values(&packet, "tcp.checksum_calculated"),
        vec![&Value::Uint16(checksum)]
    );
}

fn folded_pseudo_checksum(segment: &[u8]) -> u16 {
    let mut data = Vec::new();
    data.extend_from_slice(&SOURCE_IPV6);
    data.extend_from_slice(&DESTINATION_IPV6);
    data.extend_from_slice(&u32::try_from(segment.len()).unwrap_or(0).to_be_bytes());
    data.extend_from_slice(&[0, 0, 0, 6]);
    data.extend_from_slice(segment);
    let mut sum = 0_u32;
    let (words, rest) = data.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
        if sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    if let [last] = rest {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
        if sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}
