//! Tunnel decoding tests: GRE, ERSPAN, VXLAN, Geneve, MPLS, IP-in-IP and
//! 6in4, including every truncated field boundary and the depth bound.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{MAX_DECODE_DEPTH, Packet, decode_frame};
use packetfin_core::tree::{Group, Node, Value};

const DESTINATION_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SOURCE_ADDRESS: [u8; 4] = [192, 0, 2, 1];
const DESTINATION_ADDRESS: [u8; 4] = [198, 51, 100, 2];

fn frame(captured: Vec<u8>) -> Frame {
    Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        timestamp_precision: 6,
        original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
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

fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap_or(0).to_be_bytes());
    header.extend_from_slice(&0x1c46_u16.to_be_bytes());
    header.extend_from_slice(&0x4000_u16.to_be_bytes());
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
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    bytes.push(next);
    bytes.push(64);
    bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(payload);
    bytes
}

fn udp(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&source.to_be_bytes());
    bytes.extend_from_slice(&destination.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(0).to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

fn decode(captured: Vec<u8>) -> Packet {
    decode_frame(&frame(captured))
}

fn find<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    if node.protocol.filter_name == name {
        return Some(node);
    }
    node.children.iter().find_map(|child| find(child, name))
}

fn value(node: &Node, abbrev: &str) -> Option<u64> {
    node.fields
        .iter()
        .find(|field| field.def.abbrev == abbrev)
        .and_then(|field| match field.value {
            Value::Uint8(value) => Some(u64::from(value)),
            Value::Uint16(value) => Some(u64::from(value)),
            Value::Uint24(value) => Some(u64::from(value)),
            Value::Uint32(value) => Some(u64::from(value)),
            Value::Uint64(value) => Some(value),
            Value::Boolean(value) => Some(u64::from(value)),
            _ => None,
        })
}

fn occurrence_count(node: &Node, abbrev: &str) -> usize {
    node.fields
        .iter()
        .filter(|field| field.def.abbrev == abbrev)
        .count()
}

fn count_fields(node: &Node, abbrev: &str) -> usize {
    occurrence_count(node, abbrev)
        + node
            .children
            .iter()
            .map(|child| count_fields(child, abbrev))
            .sum::<usize>()
}

fn malformed(node: &Node) -> bool {
    node.has_expert(Group::Malformed)
}

fn node_or_exit<'a>(packet: &'a Packet, name: &str) -> &'a Node {
    match find(&packet.tree.frame, name) {
        Some(node) => node,
        None => {
            eprintln!("no {name} protocol node");
            std::process::exit(1);
        }
    }
}

fn gre(flags: u16, protocol: u16, extra: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(extra);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn gre_key_and_sequence_fields_are_decoded() {
    let mut packet = gre(0xb000, 0x0800, &[0, 0, 0, 0], &[]);
    packet.extend_from_slice(&0xdead_beef_u32.to_be_bytes());
    packet.extend_from_slice(&7_u32.to_be_bytes());
    packet.extend_from_slice(&ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    // The checksum covers the complete header and payload.
    let expected = checksum(&packet);
    if let Some(bytes) = packet.get_mut(4..6) {
        bytes.copy_from_slice(&expected.to_be_bytes());
    }
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "gre");
    assert_eq!(value(node, "gre.flags_and_version"), Some(0xb000));
    assert_eq!(value(node, "gre.key"), Some(0xdead_beef));
    assert_eq!(value(node, "gre.sequence_number"), Some(7));
    assert_eq!(value(node, "gre.checksum.status"), Some(1));
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn gre_bad_checksum_is_reported_without_stopping_the_payload() {
    let mut packet = gre(0x8000, 0x0800, &[0x12, 0x34, 0, 0], &[]);
    packet.extend_from_slice(&ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "gre");
    assert_eq!(value(node, "gre.checksum"), Some(0x1234));
    assert_eq!(value(node, "gre.checksum.status"), Some(0));
    assert_eq!(occurrence_count(node, "gre.checksum.incorrect"), 1);
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn gre_source_route_entries_are_bounded_and_decoded() {
    let mut extra = vec![0, 0, 0, 0];
    // One SRE with four octets of routing information.
    extra.extend_from_slice(&0x0800_u16.to_be_bytes());
    extra.extend_from_slice(&[0, 4]);
    extra.extend_from_slice(&[1, 2, 3, 4]);
    // Terminating zero address family and length.
    extra.extend_from_slice(&[0, 0, 0, 0]);
    let payload = ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]);
    let packet = gre(0x4000, 0x0800, &extra, &payload);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "gre");
    assert_eq!(value(node, "gre.routing.address_family"), Some(0x0800));
    assert_eq!(value(node, "gre.routing.src_length"), Some(4));
    assert_eq!(occurrence_count(node, "gre.routing"), 2);
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn gre_enhanced_ppp_uses_payload_length_and_call_id() {
    let extra = [0x12, 0x34, 0xab, 0xcd, 0, 0, 0, 7, 0, 0, 0, 9];
    let packet = gre(0x3081, 0x880b, &extra, &[0xfe, 0xfe, 0x03]);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "gre");
    assert_eq!(value(node, "gre.key.payload_length"), Some(0x1234));
    assert_eq!(value(node, "gre.key.call_id"), Some(0xabcd));
    assert_eq!(value(node, "gre.sequence_number"), Some(7));
    assert_eq!(value(node, "gre.ack_number"), Some(9));
}

#[test]
fn gre_truncated_key_keeps_the_decoded_fields() {
    let packet = [0x20, 0x00, 0x08, 0x00, 0xde, 0xad];
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "gre");
    assert_eq!(value(node, "gre.proto"), Some(0x0800));
    assert_eq!(occurrence_count(node, "gre.key"), 0);
    assert!(malformed(node));
    assert!(decoded.malformed);
}

#[test]
fn erspan_type_one_has_no_shim_header() {
    let inner = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let packet = gre(0x0000, 0x88be, &[], &inner);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(node.range.length, 0);
    assert_eq!(occurrence_count(node, "erspan.version"), 0);
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn erspan_type_two_fields_are_decoded() {
    let mut shim = Vec::new();
    shim.extend_from_slice(&((1_u16 << 12) | 100).to_be_bytes());
    shim.extend_from_slice(&((3_u16 << 13) | (1 << 10) | 0x22).to_be_bytes());
    shim.extend_from_slice(&0x05f5_e100_u32.to_be_bytes());
    let inner = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let packet = gre(0x1000, 0x88be, &[0, 0, 0, 7], &[shim, inner].concat());
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(value(node, "erspan.version"), Some(1));
    assert_eq!(value(node, "erspan.vlan"), Some(100));
    assert_eq!(value(node, "erspan.cos"), Some(3));
    assert_eq!(value(node, "erspan.encap"), Some(0));
    assert_eq!(value(node, "erspan.truncated"), Some(1));
    assert_eq!(value(node, "erspan.spanid"), Some(0x22));
    assert_eq!(value(node, "erspan.reserved"), Some(0x5f));
    assert_eq!(value(node, "erspan.index"), Some(0x0005_e100));
    assert_eq!(occurrence_count(node, "erspan.timestamp"), 0);
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn erspan_type_three_fields_and_subheader_are_decoded() {
    let mut shim = Vec::new();
    shim.extend_from_slice(&((2_u16 << 12) | 100).to_be_bytes());
    shim.extend_from_slice(&((3_u16 << 13) | (1 << 10) | 0x22).to_be_bytes());
    shim.extend_from_slice(&0x05f5_e100_u32.to_be_bytes());
    shim.extend_from_slice(&0x1234_u16.to_be_bytes());
    let flags: u16 = (1 << 15) | (2 << 10) | (5 << 4) | (1 << 3) | (2 << 1) | 1;
    shim.extend_from_slice(&flags.to_be_bytes());
    shim.extend_from_slice(&((7_u32 << 26) | 0x0012_3456).to_be_bytes());
    shim.extend_from_slice(&0x89ab_cdef_u32.to_be_bytes());
    let inner = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let packet = gre(0x0000, 0x22eb, &[], &[shim, inner].concat());
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(value(node, "erspan.version"), Some(2));
    assert_eq!(value(node, "erspan.bso"), Some(0));
    assert_eq!(value(node, "erspan.timestamp"), Some(0x05f5_e100));
    assert_eq!(value(node, "erspan.sgt"), Some(0x1234));
    assert_eq!(value(node, "erspan.p"), Some(1));
    assert_eq!(value(node, "erspan.ft"), Some(2));
    assert_eq!(value(node, "erspan.hw"), Some(5));
    assert_eq!(value(node, "erspan.direction"), Some(1));
    assert_eq!(value(node, "erspan.gra"), Some(2));
    assert_eq!(value(node, "erspan.o"), Some(1));
    assert_eq!(value(node, "erspan.platid"), Some(7));
    assert_eq!(value(node, "erspan.pid7.rsvd1"), Some(1));
    assert_eq!(value(node, "erspan.pid7.source_index"), Some(0x2_3456));
    assert_eq!(value(node, "erspan.pid7.timestamp"), Some(0x89ab_cdef));
    // Frame type 2 is not Ethernet, so no payload dissector runs.
    assert!(find(&decoded.tree.frame, "icmp").is_none());
}

#[test]
fn erspan_unknown_version_is_duplicated_and_marked() {
    let shim = [0x30, 0x64];
    let packet = gre(0x0000, 0x22eb, &[], &shim);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(occurrence_count(node, "erspan.version"), 2);
    assert_eq!(occurrence_count(node, "erspan.version.unknown"), 1);
    assert!(
        node.experts
            .iter()
            .any(|expert| expert.group == Group::Undecoded)
    );
}

#[test]
fn erspan_truncated_type_three_keeps_prior_fields() {
    let shim = [0x20, 0x64, 0x60, 0x22, 0, 0, 0, 0];
    let packet = gre(0x0000, 0x22eb, &[], &shim);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(value(node, "erspan.vlan"), Some(100));
    assert_eq!(value(node, "erspan.timestamp"), Some(0));
    assert_eq!(occurrence_count(node, "erspan.sgt"), 0);
    assert!(malformed(node));
}

#[test]
fn vxlan_fields_and_inner_ethernet_are_decoded() {
    let mut header = Vec::new();
    header.extend_from_slice(&0x0800_u16.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&[0, 0, 100]);
    header.push(0);
    let inner = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let packet = ipv4(17, &udp(12_345, 4789, &[header, inner].concat()));
    let decoded = decode(ethernet(0x0800, &packet));
    let node = node_or_exit(&decoded, "vxlan");
    assert_eq!(value(node, "vxlan.flags"), Some(0x0800));
    assert_eq!(value(node, "vxlan.flags_reserved"), Some(0));
    assert_eq!(value(node, "vxlan.flag_i"), Some(1));
    assert_eq!(value(node, "vxlan.vni"), Some(100));
    assert_eq!(value(node, "vxlan.gbp"), Some(0));
    assert_eq!(value(node, "vxlan.reserved8"), Some(0));
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn vxlan_truncated_header_keeps_decoded_fields() {
    let header = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    let packet = ipv4(17, &udp(12_345, 4789, &header));
    let decoded = decode(ethernet(0x0800, &packet));
    let node = node_or_exit(&decoded, "vxlan");
    assert_eq!(value(node, "vxlan.flags"), Some(0x0800));
    assert_eq!(occurrence_count(node, "vxlan.vni"), 0);
    assert!(malformed(node));
}

#[test]
fn geneve_header_and_options_are_bounded_by_the_declared_length() {
    let mut header = vec![0x02, 0x00];
    header.extend_from_slice(&0x6558_u16.to_be_bytes());
    header.extend_from_slice(&[0, 0, 200, 0]);
    let mut option = Vec::new();
    option.extend_from_slice(&0x0100_u16.to_be_bytes());
    option.extend_from_slice(&[0x80, 0x01]);
    option.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    let inner = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let packet = ipv4(17, &udp(12_345, 6081, &[header, option, inner].concat()));
    let decoded = decode(ethernet(0x0800, &packet));
    let node = node_or_exit(&decoded, "geneve");
    assert_eq!(value(node, "geneve.version"), Some(0));
    assert_eq!(value(node, "geneve.proto_type"), Some(0x6558));
    assert_eq!(value(node, "geneve.vni"), Some(200));
    assert_eq!(value(node, "geneve.option.class"), Some(0x0100));
    assert_eq!(value(node, "geneve.option.type"), Some(0x80));
    assert_eq!(value(node, "geneve.option.type.critical"), Some(1));
    assert_eq!(value(node, "geneve.option.length"), Some(8));
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn geneve_option_overrun_marks_the_header_and_stops() {
    let mut header = vec![0x02, 0x00];
    header.extend_from_slice(&0x6558_u16.to_be_bytes());
    header.extend_from_slice(&[0, 0, 200, 0]);
    let mut option = Vec::new();
    option.extend_from_slice(&0x0100_u16.to_be_bytes());
    option.extend_from_slice(&[0x00, 0x03]);
    option.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    let inner = ethernet(0x0800, &ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]));
    let packet = ipv4(17, &udp(12_345, 6081, &[header, option, inner].concat()));
    let decoded = decode(ethernet(0x0800, &packet));
    let node = node_or_exit(&decoded, "geneve");
    assert_eq!(occurrence_count(node, "geneve.option.class"), 0);
    assert_eq!(occurrence_count(node, "geneve.option.length.invalid"), 1);
    assert!(malformed(node));
    assert!(find(&decoded.tree.frame, "icmp").is_none());
}

#[test]
fn mpls_stack_decodes_each_label_and_dispatches_ipv4() {
    let mut labels = Vec::new();
    labels.extend_from_slice(&(((200_u32) << 12) | (2 << 9) | 63).to_be_bytes());
    labels.extend_from_slice(&(((100_u32) << 12) | (5 << 9) | (1 << 8) | 64).to_be_bytes());
    let packet = ethernet(
        0x8847,
        &[labels, ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0])].concat(),
    );
    let decoded = decode(packet);
    let node = node_or_exit(&decoded, "mpls");
    assert_eq!(value(node, "mpls.label"), Some(200));
    assert_eq!(value(node, "mpls.exp"), Some(2));
    assert_eq!(value(node, "mpls.bottom"), Some(0));
    assert_eq!(count_fields(&decoded.tree.frame, "mpls.label"), 2);
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn mpls_without_bottom_of_stack_is_malformed() {
    let label = ((100_u32) << 12) | (5 << 9) | 64;
    let packet = ethernet(0x8847, &label.to_be_bytes());
    let decoded = decode(packet);
    let node = node_or_exit(&decoded, "mpls");
    assert_eq!(value(node, "mpls.label"), Some(100));
    assert!(malformed(node));
    assert!(decoded.malformed);
}

#[test]
fn mpls_bottom_label_without_payload_is_malformed() {
    let label = ((100_u32) << 12) | (5 << 9) | (1 << 8) | 64;
    let packet = ethernet(0x8847, &label.to_be_bytes());
    let decoded = decode(packet);
    let node = node_or_exit(&decoded, "mpls");
    assert!(malformed(node));
}

#[test]
fn ip_in_ip_and_six_in_four_dispatch_inner_network_layers() {
    let inner = ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]);
    let decoded = decode(ethernet(0x0800, &ipv4(4, &inner)));
    assert_eq!(
        decoded
            .protocol_stack
            .iter()
            .filter(|name| **name == "ip")
            .count(),
        2
    );
    assert!(find(&decoded.tree.frame, "icmp").is_some());

    let decoded = decode(ethernet(0x0800, &ipv4(41, &ipv6(59, &[]))));
    assert!(find(&decoded.tree.frame, "ipv6").is_some());
}

#[test]
fn nested_ip_in_ip_stops_at_the_decode_depth_limit() {
    let mut datagram = ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]);
    for _ in 0..(MAX_DECODE_DEPTH + 4) {
        datagram = ipv4(4, &datagram);
    }
    let decoded = decode(ethernet(0x0800, &datagram));
    assert_eq!(decoded.protocol_stack.len(), MAX_DECODE_DEPTH);
    assert!(decoded.malformed);
}

#[test]
fn gre_in_gre_dispatches_the_inner_gre_header() {
    let inner = ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]);
    let mut inner_gre = Vec::new();
    inner_gre.extend_from_slice(&0_u16.to_be_bytes());
    inner_gre.extend_from_slice(&0x0800_u16.to_be_bytes());
    inner_gre.extend_from_slice(&inner);
    let mut outer_gre = Vec::new();
    outer_gre.extend_from_slice(&0_u16.to_be_bytes());
    outer_gre.extend_from_slice(&0x0800_u16.to_be_bytes());
    outer_gre.extend_from_slice(&ipv4(47, &inner_gre));
    let decoded = decode(ethernet(0x0800, &ipv4(47, &outer_gre)));
    assert_eq!(count_fields(&decoded.tree.frame, "gre.proto"), 2);
    let outer_gre = node_or_exit(&decoded, "gre");
    let Some(inner_gre_node) = outer_gre
        .children
        .iter()
        .find_map(|child| find(child, "gre"))
    else {
        eprintln!("no inner GRE node");
        std::process::exit(1);
    };
    assert_eq!(value(inner_gre_node, "gre.proto"), Some(0x0800));
    assert!(find(&decoded.tree.frame, "icmp").is_some());
}

#[test]
fn mpls_label_stack_is_capped() {
    let mut payload = Vec::new();
    for _ in 0..65 {
        payload.extend_from_slice(&mpls_label_word(100, 5, false, 64));
    }
    let decoded = decode(ethernet(0x8847, &payload));
    assert_eq!(count_fields(&decoded.tree.frame, "mpls.label"), 64);
    assert!(decoded.malformed);
}

#[test]
fn gre_source_route_list_is_capped() {
    let mut extra = vec![0, 0, 0, 0];
    for _ in 0..65 {
        extra.extend_from_slice(&0x0800_u16.to_be_bytes());
        extra.extend_from_slice(&[0, 0]);
    }
    let mut gre = Vec::new();
    gre.extend_from_slice(&0x4000_u16.to_be_bytes());
    gre.extend_from_slice(&0x0800_u16.to_be_bytes());
    gre.extend_from_slice(&extra);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &gre)));
    assert_eq!(
        count_fields(&decoded.tree.frame, "gre.routing.address_family"),
        64
    );
    assert!(decoded.malformed);
}

fn mpls_label_word(label: u32, exp: u32, bottom: bool, ttl: u8) -> [u8; 4] {
    ((label << 12) | (exp << 9) | (u32::from(bottom) << 8) | u32::from(ttl)).to_be_bytes()
}

#[test]
fn erspan_type_two_boundary_keeps_vlan_and_cos_words() {
    for (shim, cos, spanid) in [
        (vec![0x10, 0x64], None, None),
        (vec![0x10, 0x64, 0x60, 0x22], Some(3), Some(0x22)),
    ] {
        let packet = gre(0x1000, 0x88be, &[0, 0, 0, 7], &shim);
        let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
        let node = node_or_exit(&decoded, "erspan");
        assert_eq!(value(node, "erspan.vlan"), Some(100));
        assert_eq!(value(node, "erspan.cos"), cos);
        assert_eq!(value(node, "erspan.spanid"), spanid);
        assert!(malformed(node));
    }
}

#[test]
fn erspan_type_three_boundary_keeps_sgt_before_flags() {
    let mut shim = Vec::new();
    shim.extend_from_slice(&((2_u16 << 12) | 100).to_be_bytes());
    shim.extend_from_slice(&((3_u16 << 13) | 0x22).to_be_bytes());
    shim.extend_from_slice(&0x05f5_e100_u32.to_be_bytes());
    shim.extend_from_slice(&0x1234_u16.to_be_bytes());
    let packet = gre(0x0000, 0x22eb, &[], &shim);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(value(node, "erspan.sgt"), Some(0x1234));
    assert_eq!(occurrence_count(node, "erspan.p"), 0);
    assert!(malformed(node));
}

#[test]
fn erspan_platform_boundary_keeps_the_first_word() {
    let mut shim = Vec::new();
    shim.extend_from_slice(&((2_u16 << 12) | 100).to_be_bytes());
    shim.extend_from_slice(&((3_u16 << 13) | 0x22).to_be_bytes());
    shim.extend_from_slice(&0x05f5_e100_u32.to_be_bytes());
    shim.extend_from_slice(&0x1234_u16.to_be_bytes());
    shim.extend_from_slice(&((1_u16 << 15) | 1).to_be_bytes());
    shim.extend_from_slice(&((7_u32 << 26) | 0x0012_3456).to_be_bytes());
    let packet = gre(0x0000, 0x22eb, &[], &shim);
    let decoded = decode(ethernet(0x0800, &ipv4(47, &packet)));
    let node = node_or_exit(&decoded, "erspan");
    assert_eq!(value(node, "erspan.platid"), Some(7));
    assert_eq!(value(node, "erspan.pid7.source_index"), Some(0x2_3456));
    assert_eq!(occurrence_count(node, "erspan.pid7.timestamp"), 0);
    assert!(malformed(node));
}
