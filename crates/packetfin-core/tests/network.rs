//! Network-layer decoding tests: ARP, IPv4 options, IPv6 extension headers,
//! fragmentation context, truncation and dispatch from every link type.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{
    DecodeOptions, MAX_DECODE_DEPTH, NetworkContext, Preferences, decode_frame,
    decode_frame_with_options,
};
use packetfin_core::tree::{Group, Value};

const DESTINATION_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SOURCE_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DESTINATION_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

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
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}

fn ipv4(protocol: u8, flags: u16, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let header_length = 20 + options.len();
    let mut header = Vec::new();
    header.push(u8::try_from((4 << 4) | (header_length / 4)).unwrap_or(0x45));
    header.push(0);
    header.extend_from_slice(
        &u16::try_from(header_length + payload.len())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    header.extend_from_slice(&0x1c46_u16.to_be_bytes());
    header.extend_from_slice(&flags.to_be_bytes());
    header.push(64);
    header.push(protocol);
    header.extend_from_slice(&[0, 0]);
    header.extend_from_slice(&[192, 0, 2, 1]);
    header.extend_from_slice(&[198, 51, 100, 2]);
    header.extend_from_slice(options);
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

#[test]
fn arp_request_has_expected_fields_and_ranges() {
    let mut arp = Vec::new();
    arp.extend_from_slice(&1_u16.to_be_bytes());
    arp.extend_from_slice(&0x0800_u16.to_be_bytes());
    arp.extend_from_slice(&[6, 4]);
    arp.extend_from_slice(&1_u16.to_be_bytes());
    arp.extend_from_slice(&SOURCE_MAC);
    arp.extend_from_slice(&[192, 0, 2, 1]);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&[198, 51, 100, 2]);

    let packet = decode_frame(&frame(1, ethernet(0x0806, &arp)));
    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "arp"]);
    assert_eq!(
        packet.tree.field_values("arp.hw.type"),
        vec![&Value::Uint16(1)]
    );
    assert_eq!(
        packet.tree.field_values("arp.proto.type"),
        vec![&Value::Uint16(0x0800)]
    );
    assert_eq!(
        packet.tree.field_values("arp.src.proto_ipv4"),
        vec![&Value::Ipv4([192, 0, 2, 1])]
    );
    assert_eq!(
        packet.tree.field_values("arp.dst.proto_ipv4"),
        vec![&Value::Ipv4([198, 51, 100, 2])]
    );
    assert_eq!(
        packet.tree.field_values("arp.src.hw_mac"),
        vec![&Value::Ethernet(SOURCE_MAC)]
    );
    assert!(packet.tree.child("ip").is_none());
    assert!(packet.tree.child("ipv6").is_none());
}

#[test]
fn ipv4_options_and_checksum_status() {
    let options = [0x01, 0x01, 0x00, 0x00];
    let captured = ethernet(0x0800, &ipv4(253, 0x4000, &options, &[0xaa, 0xbb]));
    let packet = decode_frame(&frame(1, captured.clone()));
    assert!(!packet.malformed);
    assert_eq!(
        packet.tree.field_values("ip.hdr_len"),
        vec![&Value::Uint8(24)]
    );
    assert_eq!(
        packet.tree.field_values("ip.opt.type"),
        vec![&Value::Uint8(1), &Value::Uint8(1), &Value::Uint8(0)]
    );
    assert_eq!(
        packet.tree.field_values("ip.checksum.status"),
        vec![&Value::Uint8(2)]
    );
    assert!(
        packet
            .tree
            .field_values("ip.checksum_calculated")
            .is_empty()
    );
    assert!(packet.tree.child("udp").is_none());

    let validated = decode_frame_with_options(
        &frame(1, captured.clone()),
        DecodeOptions {
            preferences: Preferences {
                ip_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    assert_eq!(
        validated.tree.field_values("ip.checksum.status"),
        vec![&Value::Uint8(1)]
    );
    assert_eq!(
        validated.tree.field_values("ip.checksum_calculated"),
        validated.tree.field_values("ip.checksum")
    );

    let mut bad = captured;
    if let Some(bytes) = bad.get_mut(24..26) {
        bytes.copy_from_slice(&0x1234_u16.to_be_bytes());
    }
    let bad_packet = decode_frame_with_options(
        &frame(1, bad),
        DecodeOptions {
            preferences: Preferences {
                ip_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    assert_eq!(
        bad_packet.tree.field_values("ip.checksum.status"),
        vec![&Value::Uint8(0)]
    );
    assert!(bad_packet.tree.has_expert(Group::Checksum));
}

#[test]
fn ipv4_fragmentation_sets_context_and_skips_transport() {
    let packet = decode_frame(&frame(
        1,
        ethernet(0x0800, &ipv4(17, 0x2000 | 100, &[], &[0; 8])),
    ));
    assert_eq!(
        packet.tree.field_values("ip.flags.mf"),
        vec![&Value::Boolean(true)]
    );
    assert_eq!(
        packet.tree.field_values("ip.frag_offset"),
        vec![&Value::Uint16(100)]
    );
    assert!(matches!(
        packet.network,
        Some(NetworkContext::Ipv4 {
            protocol: 17,
            fragmented: true,
            ..
        })
    ));
    assert_eq!(packet.protocol_stack, vec!["eth", "ip"]);
}

#[test]
fn ipv6_extension_chain_and_context() {
    let hopopts = [0x2b, 0x00, 0x00, 0x00, 0x01, 0x02, 0xaa, 0xbb];
    let mut routing = vec![0x2c, 0x02, 0x02, 0x00, 0, 0, 0, 0];
    routing.extend_from_slice(&DESTINATION_IPV6);
    let fragment = [0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07];
    let mut payload = Vec::new();
    payload.extend_from_slice(&hopopts);
    payload.extend_from_slice(&routing);
    payload.extend_from_slice(&fragment);

    let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(0, &payload))));
    assert!(!packet.malformed);
    assert_eq!(
        packet.protocol_stack,
        vec![
            "eth",
            "ipv6",
            "ipv6.hopopts",
            "ipv6.routing",
            "ipv6.fraghdr"
        ]
    );
    assert_eq!(
        packet.tree.field_values("ipv6.opt.type"),
        vec![&Value::Uint8(0), &Value::Uint8(0), &Value::Uint8(1)]
    );
    assert_eq!(
        packet.tree.field_values("ipv6.routing.type"),
        vec![&Value::Uint8(2)]
    );
    assert_eq!(
        packet.tree.field_values("ipv6.fraghdr.ident"),
        vec![&Value::Uint32(7)]
    );
    assert!(matches!(
        packet.network,
        Some(NetworkContext::Ipv6 {
            next_header: 59,
            fragmented: false,
            ..
        })
    ));
}

#[test]
fn ipv6_extension_depth_is_bounded() {
    let mut payload = Vec::new();
    for index in 0..20 {
        let next = if index == 19 { 59 } else { 0 };
        payload.extend_from_slice(&[next, 0x00, 0x00, 0x00, 0x01, 0x02, 0xaa, 0xbb]);
    }
    let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(0, &payload))));
    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    assert_eq!(packet.protocol_stack.len(), MAX_DECODE_DEPTH);
}

#[test]
fn ipv4_and_ipv6_truncation_keeps_complete_fields() {
    let full_v4 = ethernet(0x0800, &ipv4(253, 0, &[], &[0xaa, 0xbb]));
    let full_v6 = ethernet(0x86dd, &ipv6(59, &[0xde, 0xad]));
    for length in 0..full_v4.len() {
        let mut captured = full_v4.clone();
        captured.truncate(length);
        let packet = decode_frame(&frame(1, captured));
        if length < 34 {
            assert!(packet.malformed, "IPv4 length {length}");
        }
    }
    for length in 0..full_v6.len() {
        let mut captured = full_v6.clone();
        captured.truncate(length);
        let packet = decode_frame(&frame(1, captured));
        if length < 54 {
            assert!(packet.malformed, "IPv6 length {length}");
        }
    }
}

#[test]
fn network_dispatches_from_every_link_type() {
    let v4 = ipv4(253, 0, &[], &[0xaa, 0xbb]);
    let v6 = ipv6(59, &[0xde, 0xad]);

    let ethernet_packet = decode_frame(&frame(1, ethernet(0x0800, &v4)));
    assert!(matches!(
        ethernet_packet.network,
        Some(NetworkContext::Ipv4 { .. })
    ));

    let mut raw = frame(101, v4.clone());
    raw.link_type = 101;
    assert!(matches!(
        decode_frame(&raw).network,
        Some(NetworkContext::Ipv4 { .. })
    ));

    let mut null = Vec::new();
    null.extend_from_slice(&2_u32.to_le_bytes());
    null.extend_from_slice(&v4);
    assert!(matches!(
        decode_frame(&frame(0, null)).network,
        Some(NetworkContext::Ipv4 { .. })
    ));

    let mut loopback = Vec::new();
    loopback.extend_from_slice(&24_u32.to_be_bytes());
    loopback.extend_from_slice(&v6);
    assert!(matches!(
        decode_frame(&frame(108, loopback)).network,
        Some(NetworkContext::Ipv6 { .. })
    ));

    let mut sll = Vec::new();
    sll.extend_from_slice(&0_u16.to_be_bytes());
    sll.extend_from_slice(&1_u16.to_be_bytes());
    sll.extend_from_slice(&6_u16.to_be_bytes());
    sll.extend_from_slice(&[0; 8]);
    sll.extend_from_slice(&0x0800_u16.to_be_bytes());
    sll.extend_from_slice(&v4);
    assert!(matches!(
        decode_frame(&frame(113, sll)).network,
        Some(NetworkContext::Ipv4 { .. })
    ));

    let mut sll2 = Vec::new();
    sll2.extend_from_slice(&0x86dd_u16.to_be_bytes());
    sll2.extend_from_slice(&[0, 0]);
    sll2.extend_from_slice(&3_u32.to_be_bytes());
    sll2.extend_from_slice(&1_u16.to_be_bytes());
    sll2.extend_from_slice(&[0, 6]);
    sll2.extend_from_slice(&[0; 8]);
    sll2.extend_from_slice(&v6);
    assert!(matches!(
        decode_frame(&frame(276, sll2)).network,
        Some(NetworkContext::Ipv6 { .. })
    ));

    let mut vlan = Vec::new();
    vlan.extend_from_slice(&100_u16.to_be_bytes());
    vlan.extend_from_slice(&0x0800_u16.to_be_bytes());
    vlan.extend_from_slice(&v4);
    assert!(matches!(
        decode_frame(&frame(1, ethernet(0x8100, &vlan))).network,
        Some(NetworkContext::Ipv4 { .. })
    ));
}

#[test]
fn ipv4_zero_total_length_treats_the_capture_as_the_datagram() {
    let mut datagram = ipv4(253, 0x4000, &[], &[0xaa; 40]);
    if let Some(bytes) = datagram.get_mut(2..4) {
        bytes.copy_from_slice(&0_u16.to_be_bytes());
    }
    if let Some(bytes) = datagram.get_mut(10..12) {
        bytes.copy_from_slice(&[0, 0]);
    }
    let value = checksum(datagram.get(..20).unwrap_or(&[]));
    if let Some(bytes) = datagram.get_mut(10..12) {
        bytes.copy_from_slice(&value.to_be_bytes());
    }
    let captured = ethernet(0x0800, &datagram);
    let packet = decode_frame(&frame(1, captured.clone()));
    assert_eq!(packet.tree.field_values("ip.len"), vec![&Value::Uint16(60)]);
    assert_eq!(
        packet.tree.field_values("ip.proto"),
        vec![&Value::Uint8(253)]
    );
    assert_eq!(
        packet.tree.field_values("ip.src"),
        vec![&Value::Ipv4([192, 0, 2, 1])]
    );
    assert_eq!(
        packet.tree.field_values("ip.dst"),
        vec![&Value::Ipv4([198, 51, 100, 2])]
    );
    let validated = decode_frame_with_options(
        &frame(1, captured),
        DecodeOptions {
            preferences: Preferences {
                ip_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    assert_eq!(
        validated.tree.field_values("ip.checksum.status"),
        vec![&Value::Uint8(1)]
    );
}

#[test]
fn arp_hardware_family_selects_mac_or_generic_bytes() {
    let mut arp = Vec::new();
    arp.extend_from_slice(&15_u16.to_be_bytes());
    arp.extend_from_slice(&0x0800_u16.to_be_bytes());
    arp.extend_from_slice(&[6, 4]);
    arp.extend_from_slice(&1_u16.to_be_bytes());
    arp.extend_from_slice(&SOURCE_MAC);
    arp.extend_from_slice(&[192, 0, 2, 1]);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&[198, 51, 100, 2]);
    let packet = decode_frame(&frame(1, ethernet(0x0806, &arp)));
    assert!(packet.tree.field_values("arp.src.hw_mac").is_empty());
    assert_eq!(
        packet.tree.field_values("arp.src.hw"),
        vec![&Value::bytes(SOURCE_MAC.to_vec())]
    );

    let mut iv6 = arp.clone();
    if let Some(bytes) = iv6.get_mut(0..2) {
        bytes.copy_from_slice(&5829_u16.to_be_bytes());
    }
    let other = decode_frame(&frame(1, ethernet(0x0806, &iv6)));
    assert!(other.tree.field_values("arp.src.hw_mac").is_empty());
    assert_eq!(
        other.tree.field_values("arp.src.hw"),
        vec![&Value::bytes(SOURCE_MAC.to_vec())]
    );

    let mut atmarp = arp.clone();
    if let Some(bytes) = atmarp.get_mut(0..2) {
        bytes.copy_from_slice(&19_u16.to_be_bytes());
    }
    let atmarp_packet = decode_frame(&frame(1, ethernet(0x0806, &atmarp)));
    assert!(atmarp_packet.tree.field_values("arp.src.hw_mac").is_empty());
    assert_eq!(
        atmarp_packet.tree.field_values("arp.src.hw"),
        vec![&Value::bytes(SOURCE_MAC.to_vec())]
    );

    let mut ethernet_type = arp;
    if let Some(bytes) = ethernet_type.get_mut(0..2) {
        bytes.copy_from_slice(&1_u16.to_be_bytes());
    }
    let mac = decode_frame(&frame(1, ethernet(0x0806, &ethernet_type)));
    assert_eq!(
        mac.tree.field_values("arp.src.hw_mac"),
        vec![&Value::Ethernet(SOURCE_MAC)]
    );
    assert!(mac.tree.field_values("arp.src.hw").is_empty());
}

#[test]
fn ipv6_fixed_header_fields_appear_at_prefix_thresholds() {
    let full = ipv6(59, &[0xde, 0xad]);
    for length in 0..=40_usize {
        let mut payload = full.clone();
        payload.truncate(length);
        let packet = decode_frame(&frame(1, ethernet(0x86dd, &payload)));
        assert_eq!(
            !packet.tree.field_values("ipv6.tclass").is_empty(),
            length >= 4,
            "tclass at {length}"
        );
        assert_eq!(
            !packet.tree.field_values("ipv6.plen").is_empty(),
            length >= 7,
            "plen at {length}"
        );
        assert_eq!(
            !packet.tree.field_values("ipv6.hlim").is_empty(),
            length >= 8,
            "hlim at {length}"
        );
        assert_eq!(
            !packet.tree.field_values("ipv6.src").is_empty(),
            length >= 24,
            "src at {length}"
        );
        assert_eq!(
            !packet.tree.field_values("ipv6.dst").is_empty(),
            length >= 40,
            "dst at {length}"
        );
    }
}

#[test]
fn ipv6_extension_fields_appear_at_prefix_thresholds() {
    let hop = ipv6(0, &[59]);
    let hop_one = decode_frame(&frame(1, ethernet(0x86dd, &hop)));
    assert!(hop_one.tree.field_values("ipv6.hopopts.nxt").is_empty());

    let hop = ipv6(0, &[59, 0]);
    let hop_two = decode_frame(&frame(1, ethernet(0x86dd, &hop)));
    assert_eq!(
        hop_two.tree.field_values("ipv6.hopopts.nxt"),
        vec![&Value::Uint8(59)]
    );
    assert_eq!(
        hop_two.tree.field_values("ipv6.hopopts.len"),
        vec![&Value::Uint8(0)]
    );

    for (length, has_type) in [(1_usize, false), (2, false), (3, true), (4, true)] {
        let mut payload = vec![59_u8, 2, 0, 0];
        payload.truncate(length);
        let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(43, &payload))));
        assert_eq!(
            !packet.tree.field_values("ipv6.routing.type").is_empty(),
            has_type,
            "routing type at {length}"
        );
    }
}

#[test]
fn ipv6_short_option_values_are_read_from_option_data_start() {
    let cases: &[(&[u8], u16)] = &[
        (&[0x05, 0x00, 0x11, 0x22, 0x01, 0x02, 0xaa, 0xbb], 0x1122),
        (&[0x05, 0x01, 0x11, 0x01, 0x02, 0xaa, 0xbb, 0x00], 0x1101),
        (&[0x05, 0x02, 0x11, 0x22, 0x01, 0x02, 0xaa, 0xbb], 0x1122),
    ];
    for (options, expected) in cases {
        let mut payload = vec![59_u8, 0];
        payload.extend_from_slice(options);
        let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(0, &payload))));
        assert_eq!(
            packet.tree.field_values("ipv6.opt.router_alert"),
            vec![&Value::Uint16(*expected)]
        );
    }
    for length in 0_u8..=8 {
        let mut header = vec![59_u8, 2, 0xc2, length];
        header.extend_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);
        header.resize(24, 0);
        let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(0, &header))));
        assert_eq!(
            packet.tree.field_values("ipv6.opt.jumbo"),
            vec![&Value::Uint32(0x1011_1213)],
            "jumbo length {length}"
        );
    }
}

#[test]
fn ipv4_timestamp_flags_other_than_one_and_three_use_timestamps_only() {
    for flag in [0_u8, 2, 4] {
        let options = [0x44, 0x0c, 0x05, flag, 0, 0, 0x03, 0xe8, 0, 0, 0x07, 0xd0];
        let packet = decode_frame(&frame(
            1,
            ethernet(0x0800, &ipv4(253, 0, &options, &[0xaa])),
        ));
        assert_eq!(
            packet.tree.field_values("ip.opt.time_stamp"),
            vec![&Value::Uint32(1000), &Value::Uint32(2000)],
            "flag {flag}"
        );
    }
}

#[test]
fn ipv6_unknown_routing_truncation_omits_type_specific_data() {
    let mut routing = vec![59_u8, 2, 99, 0];
    routing.extend(0x10_u8..=0x23);
    for length in [8_usize, 9, 16, 17, 20, 23, 24] {
        let mut payload = routing.clone();
        payload.truncate(length);
        let packet = decode_frame(&frame(1, ethernet(0x86dd, &ipv6(43, &payload))));
        let values = packet.tree.field_values("ipv6.routing.unknown_data");
        if length == 24 {
            assert_eq!(values.len(), 1, "length {length}");
        } else {
            assert!(values.is_empty(), "length {length}");
        }
    }
}

#[test]
fn ipv4_truncated_header_keeps_destination_after_a_clean_option_stop() {
    let options = [0x01, 0x01, 0x00, 0x00];
    let mut datagram = ipv4(253, 0x4000, &options, &[0xaa]);
    datagram.truncate(23);
    let packet = decode_frame(&frame(1, ethernet(0x0800, &datagram)));
    assert_eq!(
        packet.tree.field_values("ip.dst"),
        vec![&Value::Ipv4([198, 51, 100, 2])]
    );
    assert_eq!(
        packet.tree.field_values("ip.opt.type"),
        vec![&Value::Uint8(1), &Value::Uint8(1), &Value::Uint8(0)]
    );
}

#[test]
fn zero_length_ip_option_data_renders_missing() {
    let options = [0x9e, 0x02, 0x00, 0x00];
    let packet = decode_frame(&frame(1, ethernet(0x0800, &ipv4(253, 0, &options, &[]))));
    assert_eq!(
        packet.tree.field_values("ip.opt.data"),
        vec![&Value::Missing]
    );
    assert_eq!(
        Value::Missing.render(packetfin_core::fields::Display::None),
        "<MISSING>"
    );
}
