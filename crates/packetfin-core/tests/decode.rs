//! Registry, tree, formatting and Ethernet decoding tests.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{MAX_DECODE_DEPTH, decode_frame};
use packetfin_core::fields::{self, Display, FieldType};
use packetfin_core::tree::{Field, FieldSelection, Group, Node, Range, Severity, Value};

const DESTINATION_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SOURCE_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DESTINATION_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const TIMESTAMP: Timestamp = Timestamp {
    seconds: 1_700_000_000,
    nanos: 123_456_000,
};

fn captured_frame(number: u64, captured: Vec<u8>) -> Frame {
    let original_len = u32::try_from(captured.len()).unwrap_or(u32::MAX);
    Frame {
        number,
        timestamp: Some(TIMESTAMP),
        timestamp_precision: 6,
        captured,
        original_len,
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

fn ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&DESTINATION_MAC);
    bytes.extend_from_slice(&SOURCE_MAC);
    bytes.extend_from_slice(&ethertype.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn frame_field<'a>(node: &'a Node, abbrev: &str) -> Option<&'a Field> {
    node.fields
        .iter()
        .find_map(|field| frame_field_in(field, abbrev))
}

fn frame_field_in<'a>(field: &'a Field, abbrev: &str) -> Option<&'a Field> {
    if field.def.abbrev == abbrev {
        return Some(field);
    }
    field
        .children
        .iter()
        .find_map(|child| frame_field_in(child, abbrev))
}

fn child_node<'a>(node: &'a Node, filter_name: &str) -> Option<&'a Node> {
    if node.protocol.filter_name == filter_name {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| child_node(child, filter_name))
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (words, remainder) = data.as_chunks::<2>();
    for word in words {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*word)));
    }
    if let [last] = remainder {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}

fn ospf_v2_packet(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![2, message_type];
    let length = u16::try_from(24 + body.len()).unwrap_or(0);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[1, 1, 1, 1]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&[0; 8]);
    packet.extend_from_slice(body);
    let mut covered = packet.get(..16).unwrap_or_default().to_vec();
    covered.extend_from_slice(packet.get(24..).unwrap_or_default());
    let checksum = internet_checksum(&covered);
    if let Some(slot) = packet.get_mut(12..14) {
        slot.copy_from_slice(&checksum.to_be_bytes());
    }
    packet
}

fn ospf_ipv4_frame(packet: &[u8]) -> Vec<u8> {
    let mut header = vec![0x45, 0];
    let total = u16::try_from(20 + packet.len()).unwrap_or(0);
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&[0, 1, 0x40, 0, 64, 89, 0, 0]);
    header.extend_from_slice(&[192, 0, 2, 1]);
    header.extend_from_slice(&[198, 51, 100, 2]);
    let checksum = internet_checksum(&header);
    if let Some(slot) = header.get_mut(10..12) {
        slot.copy_from_slice(&checksum.to_be_bytes());
    }
    header.extend_from_slice(packet);
    ethernet_frame(0x0800, &header)
}

fn ospf_v3_packet(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![3, message_type];
    let length = u16::try_from(16 + body.len()).unwrap_or(0);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[192, 0, 2, 1]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(body);
    packet
}

fn ospf_ipv6_frame(packet: &[u8]) -> Vec<u8> {
    let mut header = vec![0x60, 0, 0, 0];
    let payload_length = u16::try_from(packet.len()).unwrap_or(0);
    header.extend_from_slice(&payload_length.to_be_bytes());
    header.extend_from_slice(&[89, 64]);
    header.extend_from_slice(&SOURCE_IPV6);
    header.extend_from_slice(&DESTINATION_IPV6);
    header.extend_from_slice(packet);
    ethernet_frame(0x86dd, &header)
}

#[test]
fn registry_indexes_frame_and_ethernet_fields() {
    let registry = fields::registry();
    assert_eq!(registry.fields().len(), 1690);
    assert_eq!(fields::protocols().len(), 46);
    assert_eq!(
        fields::protocols()
            .iter()
            .map(|protocol| protocol.filter_name)
            .collect::<Vec<_>>(),
        vec![
            "frame",
            "eth",
            "llc",
            "vlan",
            "ieee8021ad",
            "sll",
            "null",
            "arp",
            "ip",
            "ipv6",
            "ipv6.hopopts",
            "ipv6.dstopts",
            "ipv6.routing",
            "ipv6.fraghdr",
            "tcp",
            "udp",
            "dns",
            "mdns",
            "llmnr",
            "dhcp",
            "dhcpv6",
            "ntp",
            "icmp",
            "icmpv6",
            "erspan",
            "geneve",
            "gre",
            "mpls",
            "vxlan",
            "bfd",
            "bfd_echo",
            "ospf",
            "vrrp",
            "lacp",
            "lldp",
            "marker",
            "slow",
            "stp",
            "cflow",
            "sflow",
            "snmp",
            "syslog",
            "bgp",
            "http",
            "http2",
            "tls",
        ]
    );

    let number = fields::field_by_abbrev("frame.number");
    assert!(number.is_some());
    if let Some(number) = number {
        assert_eq!(number.field_type, FieldType::Uint32);
        assert_eq!(number.display, Display::Decimal);
        assert_eq!(number.parent, "frame");
        assert!(number.generated);
    }

    let eth_type = fields::field_by_abbrev("eth.type");
    assert!(eth_type.is_some());
    if let Some(eth_type) = eth_type {
        assert_eq!(eth_type.field_type, FieldType::Uint16);
        assert_eq!(eth_type.display, Display::Hex);
        assert_eq!(eth_type.parent, "eth");
        assert!(!eth_type.generated);
    }

    assert!(fields::field_by_abbrev("eth.addr").is_some());
    assert!(fields::field_by_abbrev("frame.interface_name").is_some());
    assert!(fields::field_by_abbrev("frame.bogus").is_none());
    assert!(fields::field_by_abbrev("eth").is_none());
    assert!(fields::field_by_abbrev("").is_none());

    for protocol in fields::protocols() {
        for field in protocol.fields {
            assert_eq!(field.parent, protocol.filter_name);
            let looked_up = fields::field_by_abbrev(field.abbrev);
            assert!(looked_up.is_some());
            if let Some(looked_up) = looked_up {
                assert_eq!(looked_up.abbrev, field.abbrev);
            }
        }
    }
}

#[test]
fn values_render_in_display_formats() {
    assert_eq!(
        Value::Ethernet(DESTINATION_MAC).render(Display::None),
        "02:00:00:00:00:02"
    );
    assert_eq!(Value::Uint16(0x0800).render(Display::Hex), "0x0800");
    assert_eq!(Value::Uint16(0x0012).render(Display::Hex), "0x0012");
    assert_eq!(Value::Uint16(0x0012).render(Display::Decimal), "18");
    assert_eq!(Value::Uint8(0x12).render(Display::Hex), "0x12");
    assert_eq!(
        Value::Uint32(0x1234_5678).render(Display::Hex),
        "0x12345678"
    );
    assert_eq!(
        Value::AbsoluteTime(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        })
        .render(Display::None),
        "1700000000.123456000"
    );
    assert_eq!(Value::Boolean(true).render(Display::None), "True");
    assert_eq!(Value::Boolean(false).render(Display::None), "False");
    assert_eq!(
        Value::Ipv4([192, 0, 2, 1]).render(Display::None),
        "192.0.2.1"
    );
    assert_eq!(Value::bytes(vec![0x01, 0xab]).render(Display::None), "01ab");
    assert_eq!(
        Value::String("eth0".to_string()).render(Display::None),
        "eth0"
    );
    assert_eq!(Value::Int16(-2).render(Display::Decimal), "-2");
    assert_eq!(Value::Int16(-2).render(Display::Hex), "0xfffe");
}

#[test]
fn ipv6_uses_canonical_compression() {
    let mut all_zero = [0_u8; 16];
    assert_eq!(Value::Ipv6(all_zero).render(Display::None), "::");

    all_zero[15] = 1;
    assert_eq!(Value::Ipv6(all_zero).render(Display::None), "::1");

    let mut mixed = [0_u8; 16];
    mixed[0] = 0x20;
    mixed[1] = 0x01;
    mixed[2] = 0x0d;
    mixed[3] = 0xb8;
    mixed[15] = 1;
    assert_eq!(Value::Ipv6(mixed).render(Display::None), "2001:db8::1");

    let no_run: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x01,
    ];
    assert_eq!(
        Value::Ipv6(no_run).render(Display::None),
        "2001:db8:0:1:1:1:1:1"
    );
}

#[test]
fn unknown_ethertype_decodes_ethernet_fields_and_columns() {
    let packet = decode_frame(&captured_frame(7, ethernet_frame(0x1234, &[0xab, 0xcd])));
    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth"]);
    assert_eq!(packet.columns.number, Some(7));
    assert_eq!(packet.columns.time, Some(TIMESTAMP));
    assert_eq!(packet.columns.length, Some(16));
    assert_eq!(packet.columns.source.as_deref(), Some("02:00:00:00:00:01"));
    assert_eq!(
        packet.columns.destination.as_deref(),
        Some("02:00:00:00:00:02")
    );
    assert_eq!(packet.columns.protocol.as_deref(), Some("0x1234"));
    assert_eq!(packet.columns.info.as_deref(), Some("Ethernet II"));

    let frame_number = frame_field(&packet.tree.frame, "frame.number");
    assert!(frame_number.is_some());
    if let Some(field) = frame_number {
        assert_eq!(field.value, Value::Uint32(7));
        assert_eq!(field.range, Range::new(0, 0));
        assert!(field.generated);
    }
    assert_eq!(
        frame_field(&packet.tree.frame, "frame.time_epoch").map(|field| &field.value),
        Some(&Value::AbsoluteTime(TIMESTAMP))
    );
    assert_eq!(
        frame_field(&packet.tree.frame, "frame.len").map(|field| &field.value),
        Some(&Value::Uint32(16))
    );
    assert_eq!(
        frame_field(&packet.tree.frame, "frame.cap_len").map(|field| &field.value),
        Some(&Value::Uint32(16))
    );
    assert_eq!(
        frame_field(&packet.tree.frame, "frame.interface_id").map(|field| &field.value),
        Some(&Value::Uint32(0))
    );

    let ethernet = packet.tree.child("eth");
    assert!(ethernet.is_some());
    if let Some(ethernet) = ethernet {
        assert_eq!(ethernet.range, Range::new(0, 16));
        assert!(ethernet.experts.is_empty());
        assert_eq!(
            frame_field(ethernet, "eth.dst").map(|field| (&field.range, &field.value)),
            Some((&Range::new(0, 6), &Value::Ethernet(DESTINATION_MAC)))
        );
        assert_eq!(
            frame_field(ethernet, "eth.src").map(|field| (&field.range, &field.value)),
            Some((&Range::new(6, 6), &Value::Ethernet(SOURCE_MAC)))
        );
        assert_eq!(
            frame_field(ethernet, "eth.type").map(|field| (&field.range, &field.value)),
            Some((&Range::new(12, 2), &Value::Uint16(0x1234)))
        );
        let addresses: Vec<_> = ethernet
            .fields
            .iter()
            .filter(|field| field.def.abbrev == "eth.addr")
            .map(|field| (&field.range, &field.value))
            .collect();
        assert_eq!(
            addresses,
            vec![
                (&Range::new(0, 6), &Value::Ethernet(DESTINATION_MAC)),
                (&Range::new(6, 6), &Value::Ethernet(SOURCE_MAC)),
            ]
        );
    }

    let values = packet.tree.field_values("eth.addr");
    assert_eq!(
        values,
        vec![
            &Value::Ethernet(DESTINATION_MAC),
            &Value::Ethernet(SOURCE_MAC)
        ]
    );
}

#[test]
fn thirteen_byte_frame_keeps_mac_fields_and_reports_malformed() {
    let mut captured = ethernet_frame(0x1234, &[]);
    captured.truncate(13);
    let packet = decode_frame(&captured_frame(1, captured));

    assert!(packet.malformed);
    assert_eq!(packet.columns.protocol.as_deref(), Some("Ethernet"));
    assert_eq!(packet.columns.info.as_deref(), Some("[Malformed Packet]"));
    assert_eq!(packet.columns.source.as_deref(), Some("02:00:00:00:00:01"));
    assert_eq!(
        packet.columns.destination.as_deref(),
        Some("02:00:00:00:00:02")
    );
    assert!(packet.tree.has_expert(Group::Malformed));

    let ethernet = packet.tree.child("eth");
    assert!(ethernet.is_some());
    if let Some(ethernet) = ethernet {
        assert_eq!(ethernet.range, Range::new(0, 13));
        assert!(frame_field(ethernet, "eth.dst").is_some());
        assert!(frame_field(ethernet, "eth.src").is_some());
        assert!(frame_field(ethernet, "eth.type").is_none());
        assert_eq!(
            ethernet
                .fields
                .iter()
                .filter(|field| field.def.abbrev == "eth.addr")
                .count(),
            2
        );
        assert_eq!(ethernet.experts.len(), 1);
        if let Some(expert) = ethernet.experts.first() {
            assert_eq!(expert.severity, Severity::Error);
            assert_eq!(expert.group, Group::Malformed);
            assert!(!expert.message.is_empty());
        }
    }
}

#[test]
fn eleven_byte_frame_has_no_ethernet_fields() {
    let mut captured = ethernet_frame(0x1234, &[]);
    captured.truncate(11);
    let packet = decode_frame(&captured_frame(1, captured));

    assert!(packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth"]);
    assert_eq!(packet.columns.protocol.as_deref(), Some("Ethernet"));
    assert_eq!(packet.columns.info.as_deref(), Some("[Malformed Packet]"));
    assert_eq!(
        packet.columns.destination.as_deref(),
        Some("02:00:00:00:00:02")
    );
    assert_eq!(packet.columns.source, None);
    assert!(packet.tree.has_expert(Group::Malformed));

    let ethernet = packet.tree.child("eth");
    assert!(ethernet.is_some());
    if let Some(ethernet) = ethernet {
        assert_eq!(ethernet.range, Range::new(0, 11));
        assert!(ethernet.fields.is_empty());
        assert_eq!(ethernet.experts.len(), 1);
    }
}

#[test]
fn pruning_keeps_selected_fields_and_needed_protocol_nodes() {
    let mut packet = decode_frame(&captured_frame(1, ethernet_frame(0x1234, &[0xab, 0xcd])));
    packet.tree.prune(&FieldSelection::from_abbreviations(&[
        "frame.number",
        "eth.addr",
    ]));

    let abbreviations: Vec<_> = packet.tree.fields().map(|field| field.def.abbrev).collect();
    assert_eq!(abbreviations, vec!["frame.number", "eth.addr", "eth.addr"]);
    assert!(packet.tree.child("eth").is_some());
    assert!(packet.tree.field_values("eth.dst").is_empty());

    packet
        .tree
        .prune(&FieldSelection::from_abbreviations(&["frame.number"]));
    let abbreviations: Vec<_> = packet.tree.fields().map(|field| field.def.abbrev).collect();
    assert_eq!(abbreviations, vec!["frame.number"]);
    assert!(packet.tree.child("eth").is_none());
}

#[test]
fn pruning_retains_every_occurrence_of_a_repeated_selection() {
    let mut packet = decode_frame(&captured_frame(1, ethernet_frame(0x1234, &[0xab, 0xcd])));
    packet.tree.prune(&FieldSelection::new(&[
        &fields::ETH_ADDR,
        &fields::FRAME_NUMBER,
        &fields::ETH_ADDR,
    ]));

    let abbreviations: Vec<_> = packet.tree.fields().map(|field| field.def.abbrev).collect();
    assert_eq!(abbreviations, vec!["frame.number", "eth.addr", "eth.addr"]);
}

#[test]
fn pruning_retains_a_malformed_protocol_node() {
    let mut captured = ethernet_frame(0x1234, &[]);
    captured.truncate(11);
    let mut packet = decode_frame(&captured_frame(1, captured));
    packet
        .tree
        .prune(&FieldSelection::from_abbreviations(&["frame.number"]));

    assert!(packet.tree.child("eth").is_some());
    assert!(packet.tree.has_expert(Group::Malformed));
    let abbreviations: Vec<_> = packet.tree.fields().map(|field| field.def.abbrev).collect();
    assert_eq!(abbreviations, vec!["frame.number"]);
}

#[test]
fn missing_timestamp_omits_the_epoch_field() {
    let mut frame = captured_frame(1, ethernet_frame(0x1234, &[]));
    frame.timestamp = None;
    let packet = decode_frame(&frame);

    assert_eq!(packet.columns.time, None);
    assert!(packet.tree.field_values("frame.time_epoch").is_empty());
    assert!(!packet.malformed);
}

#[test]
fn interface_name_is_emitted_when_present() {
    let mut frame = captured_frame(1, ethernet_frame(0x1234, &[]));
    frame.interface_name = Some("eth0".to_string());
    let packet = decode_frame(&frame);

    let name = frame_field(&packet.tree.frame, "frame.interface_name");
    assert!(name.is_some());
    if let Some(name) = name {
        assert_eq!(name.value, Value::String("eth0".to_string()));
        assert!(name.generated);
        assert_eq!(name.range, Range::new(0, 0));
    }
}

#[test]
fn unregistered_link_type_still_produces_frame_fields() {
    let mut frame = captured_frame(1, vec![0x45, 0x00]);
    frame.link_type = 999;
    let packet = decode_frame(&frame);

    assert!(!packet.malformed);
    assert!(packet.protocol_stack.is_empty());
    assert!(packet.tree.child("eth").is_none());
    assert_eq!(packet.columns.protocol, None);
    assert_eq!(packet.columns.info, None);
    assert!(frame_field(&packet.tree.frame, "frame.number").is_some());
    assert_eq!(MAX_DECODE_DEPTH, 16);
}

#[test]
fn raw_ip_link_type_dispatches_by_version_without_a_link_node() {
    let mut frame = captured_frame(1, ipv4_prefix());
    frame.link_type = 101;
    let packet = decode_frame(&frame);

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["ip"]);
    assert_eq!(packet.tree.frame.children.len(), 1);
}

fn link_frame(link_type: u32, captured: Vec<u8>) -> Frame {
    let mut frame = captured_frame(1, captured);
    frame.link_type = link_type;
    frame
}

fn ethernet_8023(length: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&DESTINATION_MAC);
    frame.extend_from_slice(&SOURCE_MAC);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn tci(priority: u16, dei: bool, id: u16) -> u16 {
    let dei_bit = if dei { 0x1000 } else { 0 };
    (priority << 13) | dei_bit | (id & 0x0fff)
}

fn tag(control: u16, inner: u16) -> Vec<u8> {
    let mut tag = Vec::new();
    tag.extend_from_slice(&control.to_be_bytes());
    tag.extend_from_slice(&inner.to_be_bytes());
    tag
}

fn padded_snap() -> Vec<u8> {
    let mut pdu = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
    pdu.extend_from_slice(&ipv4_prefix());
    pdu.resize(46, 0);
    pdu
}

fn sll_v1(
    packet_type: u16,
    address_type: u16,
    address_length: u16,
    address: [u8; 8],
    protocol: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&packet_type.to_be_bytes());
    frame.extend_from_slice(&address_type.to_be_bytes());
    frame.extend_from_slice(&address_length.to_be_bytes());
    frame.extend_from_slice(&address);
    frame.extend_from_slice(&protocol.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

struct TestSll2Address {
    address_type: u16,
    packet_type: u8,
    address_length: u8,
    address: [u8; 8],
}

fn sll_v2(
    protocol: u16,
    reserved: u16,
    interface_index: u32,
    address: TestSll2Address,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&protocol.to_be_bytes());
    frame.extend_from_slice(&reserved.to_be_bytes());
    frame.extend_from_slice(&interface_index.to_be_bytes());
    frame.extend_from_slice(&address.address_type.to_be_bytes());
    frame.push(address.packet_type);
    frame.push(address.address_length);
    frame.extend_from_slice(&address.address);
    frame.extend_from_slice(payload);
    frame
}

fn ipv4_prefix() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x14, 0x1c, 0x46, 0x40, 0x00, 0x40, 0xfd, 0x31, 0x70, 0xc0, 0x00, 0x02,
        0x01, 0xc6, 0x33, 0x64, 0x02,
    ]
}

#[test]
fn llc_snap_fields_have_exact_ranges() {
    let mut llc = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
    llc.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(1, ethernet_8023(28, &llc)));

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "llc", "ip"]);

    let ethernet = packet.tree.child("eth");
    assert!(ethernet.is_some());
    let Some(ethernet) = ethernet else {
        return;
    };
    assert!(frame_field(ethernet, "eth.type").is_none());
    assert_eq!(
        frame_field(ethernet, "eth.len").map(|field| (&field.range, &field.value)),
        Some((&Range::new(12, 2), &Value::Uint16(28)))
    );

    let llc_node = ethernet.child("llc");
    assert!(llc_node.is_some());
    let Some(llc_node) = llc_node else {
        return;
    };
    assert_eq!(llc_node.range, Range::new(14, 28));
    assert_eq!(
        frame_field(llc_node, "llc.dsap").map(|field| (&field.range, &field.value)),
        Some((&Range::new(14, 1), &Value::Uint8(0xaa)))
    );
    assert_eq!(
        frame_field(llc_node, "llc.ssap").map(|field| (&field.range, &field.value)),
        Some((&Range::new(15, 1), &Value::Uint8(0xaa)))
    );
    assert_eq!(
        frame_field(llc_node, "llc.control").map(|field| (&field.range, &field.value)),
        Some((&Range::new(16, 1), &Value::Uint16(0x0003)))
    );
    assert_eq!(
        frame_field(llc_node, "llc.oui").map(|field| (&field.range, &field.value)),
        Some((&Range::new(17, 3), &Value::Uint32(0)))
    );
    assert_eq!(
        frame_field(llc_node, "llc.type").map(|field| (&field.range, &field.value)),
        Some((&Range::new(20, 2), &Value::Uint16(0x0800)))
    );
    assert!(frame_field(llc_node, "llc.pid").is_none());
}

#[test]
fn snap_with_a_vendor_oui_exposes_pid_instead_of_type() {
    let llc = [0xaa, 0xaa, 0x03, 0x12, 0x34, 0x56, 0x99, 0x99, 0xde, 0xad];
    let packet = decode_frame(&link_frame(1, ethernet_8023(10, &llc)));

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "llc"]);
    let llc_node = packet.tree.child("eth").and_then(|eth| eth.child("llc"));
    assert!(llc_node.is_some());
    let Some(llc_node) = llc_node else {
        return;
    };
    assert_eq!(
        frame_field(llc_node, "llc.oui").map(|field| &field.value),
        Some(&Value::Uint32(0x12_34_56))
    );
    assert_eq!(
        frame_field(llc_node, "llc.pid").map(|field| &field.value),
        Some(&Value::Uint16(0x9999))
    );
    assert!(frame_field(llc_node, "llc.type").is_none());
}

#[test]
fn two_byte_llc_control_is_read_little_endian() {
    let llc = [0x42, 0x42, 0x01, 0x00, 0xde, 0xad];
    let packet = decode_frame(&link_frame(1, ethernet_8023(6, &llc)));

    // An S-format control (first byte low bits 01) has no information field,
    // so it stays LLC even on the STP service access point.
    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "llc"]);
    let llc_node = packet.tree.child("eth").and_then(|eth| eth.child("llc"));
    assert!(llc_node.is_some());
    let Some(llc_node) = llc_node else {
        return;
    };
    assert_eq!(
        frame_field(llc_node, "llc.control").map(|field| (&field.range, &field.value)),
        Some((&Range::new(16, 2), &Value::Uint16(0x0001)))
    );
}

#[test]
fn truncated_llc_keeps_its_service_access_points() {
    let packet = decode_frame(&link_frame(1, ethernet_8023(10, &[0x42, 0x42])));

    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    let llc_node = packet.tree.child("eth").and_then(|eth| eth.child("llc"));
    assert!(llc_node.is_some());
    let Some(llc_node) = llc_node else {
        return;
    };
    assert!(frame_field(llc_node, "llc.dsap").is_some());
    assert!(frame_field(llc_node, "llc.ssap").is_some());
    assert!(frame_field(llc_node, "llc.control").is_none());
}

#[test]
fn vlan_tag_fields_and_nested_dispatch() {
    let mut body = tag(tci(5, false, 100), 0x0800);
    body.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x8100, &body)));

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "vlan", "ip"]);
    let vlan = packet.tree.child("eth").and_then(|eth| eth.child("vlan"));
    assert!(vlan.is_some());
    let Some(vlan) = vlan else {
        return;
    };
    assert_eq!(
        frame_field(vlan, "vlan.priority").map(|field| (&field.range, &field.value)),
        Some((&Range::new(14, 2), &Value::Uint16(5)))
    );
    assert_eq!(
        frame_field(vlan, "vlan.dei").map(|field| &field.value),
        Some(&Value::Boolean(false))
    );
    assert_eq!(
        frame_field(vlan, "vlan.id").map(|field| &field.value),
        Some(&Value::Uint16(100))
    );
    assert_eq!(
        frame_field(vlan, "vlan.etype").map(|field| (&field.range, &field.value)),
        Some((&Range::new(16, 2), &Value::Uint16(0x0800)))
    );
}

#[test]
fn stacked_vlan_tags_repeat_each_field() {
    let mut body = tag(tci(2, false, 300), 0x8100);
    body.extend_from_slice(&tag(tci(3, true, 400), 0x0800));
    body.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x9100, &body)));

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["eth", "vlan", "vlan", "ip"]);
    assert_eq!(
        packet.tree.field_values("vlan.priority"),
        vec![&Value::Uint16(2), &Value::Uint16(3)]
    );
    assert_eq!(
        packet.tree.field_values("vlan.dei"),
        vec![&Value::Boolean(false), &Value::Boolean(true)]
    );
    assert_eq!(
        packet.tree.field_values("vlan.id"),
        vec![&Value::Uint16(300), &Value::Uint16(400)]
    );
    assert_eq!(
        packet.tree.field_values("vlan.etype"),
        vec![&Value::Uint16(0x8100), &Value::Uint16(0x0800)]
    );
}

#[test]
fn provider_bridge_uses_ieee8021ad_fields() {
    let mut body = tag(tci(1, true, 100), 0x8100);
    body.extend_from_slice(&tag(tci(5, false, 200), 0x0800));
    body.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x88a8, &body)));

    assert!(!packet.malformed);
    assert_eq!(
        packet.protocol_stack,
        vec!["eth", "ieee8021ad", "vlan", "ip"]
    );
    let provider = packet
        .tree
        .child("eth")
        .and_then(|eth| eth.child("ieee8021ad"));
    assert!(provider.is_some());
    let Some(provider) = provider else {
        return;
    };
    assert_eq!(
        frame_field(provider, "ieee8021ad.priority").map(|field| &field.value),
        Some(&Value::Uint16(1))
    );
    assert_eq!(
        frame_field(provider, "ieee8021ad.dei").map(|field| &field.value),
        Some(&Value::Uint16(1))
    );
    assert_eq!(
        frame_field(provider, "ieee8021ad.id").map(|field| &field.value),
        Some(&Value::Uint16(100))
    );
    assert_eq!(
        packet.tree.field_values("vlan.id"),
        vec![&Value::Uint16(200)]
    );
}

#[test]
fn double_provider_tags_expose_svid_and_cvid() {
    let mut body = tag(tci(1, false, 10), 0x88a8);
    body.extend_from_slice(&tag(tci(2, true, 20), 0x8100));
    body.extend_from_slice(&tag(tci(3, false, 30), 0x0800));
    body.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x88a8, &body)));

    assert!(!packet.malformed);
    assert_eq!(
        packet.protocol_stack,
        vec!["eth", "ieee8021ad", "vlan", "ip"]
    );
    assert_eq!(
        packet.tree.field_values("ieee8021ad.svid"),
        vec![&Value::Uint16(10)]
    );
    assert_eq!(
        packet.tree.field_values("ieee8021ad.cvid"),
        vec![&Value::Uint16(20)]
    );
    assert!(packet.tree.field_values("ieee8021ad.id").is_empty());
    assert_eq!(
        packet.tree.field_values("vlan.id"),
        vec![&Value::Uint16(30)]
    );
}

#[test]
fn truncated_vlan_tag_reports_malformed() {
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x8100, &[0x00])));

    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    let vlan = packet.tree.child("eth").and_then(|eth| eth.child("vlan"));
    assert!(vlan.is_some());
    if let Some(vlan) = vlan {
        assert!(vlan.fields.is_empty());
        assert_eq!(vlan.experts.len(), 1);
    }
}

#[test]
fn sll_v1_fields_and_address_kinds() {
    let packet = decode_frame(&link_frame(
        113,
        sll_v1(
            0,
            1,
            6,
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
            0x0800,
            &ipv4_prefix(),
        ),
    ));

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["sll", "ip"]);
    let sll = packet.tree.child("sll");
    assert!(sll.is_some());
    let Some(sll) = sll else {
        return;
    };
    assert_eq!(
        frame_field(sll, "sll.pkttype").map(|field| &field.value),
        Some(&Value::Uint16(0))
    );
    assert_eq!(
        frame_field(sll, "sll.hatype").map(|field| &field.value),
        Some(&Value::Uint16(1))
    );
    assert_eq!(
        frame_field(sll, "sll.halen").map(|field| &field.value),
        Some(&Value::Uint16(6))
    );
    assert_eq!(
        frame_field(sll, "sll.src.eth").map(|field| (&field.range, &field.value)),
        Some((
            &Range::new(6, 6),
            &Value::Ethernet([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        ))
    );
    assert_eq!(
        frame_field(sll, "sll.unused").map(|field| &field.value),
        Some(&Value::bytes(vec![0x00, 0x00]))
    );
    assert_eq!(
        frame_field(sll, "sll.etype").map(|field| &field.value),
        Some(&Value::Uint16(0x0800))
    );

    let ipv4 = decode_frame(&link_frame(
        113,
        sll_v1(4, 2, 4, [192, 0, 2, 1, 0, 0, 0, 0], 0x0800, &ipv4_prefix()),
    ));
    assert!(
        ipv4.tree
            .field_values("sll.src.ipv4")
            .contains(&&Value::Ipv4([192, 0, 2, 1]))
    );

    let other = decode_frame(&link_frame(
        113,
        sll_v1(1, 6, 8, [1, 2, 3, 4, 5, 6, 7, 8], 0x1234, &[]),
    ));
    assert!(
        other
            .tree
            .field_values("sll.src.other")
            .contains(&&Value::bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]))
    );
    assert!(other.tree.field_values("sll.unused").is_empty());

    let no_address = decode_frame(&link_frame(
        113,
        sll_v1(2, 1, 0, [0; 8], 0x0800, &ipv4_prefix()),
    ));
    assert!(!no_address.malformed);
    assert!(no_address.tree.field_values("sll.src.eth").is_empty());
    assert!(no_address.tree.field_values("sll.src.ipv4").is_empty());
    assert!(no_address.tree.field_values("sll.src.other").is_empty());
    assert_eq!(
        no_address.tree.field_values("sll.unused"),
        vec![&Value::bytes(vec![0; 8])]
    );
}

#[test]
fn sll_v1_truncated_header_reports_malformed() {
    let mut captured = sll_v1(0, 1, 6, [0; 8], 0x0800, &[]);
    captured.truncate(4);
    let packet = decode_frame(&link_frame(113, captured));

    assert!(packet.malformed);
    let sll = packet.tree.child("sll");
    assert!(sll.is_some());
    let Some(sll) = sll else {
        return;
    };
    assert!(frame_field(sll, "sll.pkttype").is_some());
    assert!(frame_field(sll, "sll.hatype").is_some());
    assert!(frame_field(sll, "sll.halen").is_none());
    assert_eq!(sll.experts.len(), 1);
}

#[test]
fn sll_ltype_four_dispatches_llc() {
    let payload = [0x42, 0x42, 0x03, 0xde, 0xad];
    let packet = decode_frame(&link_frame(113, sll_v1(0, 1, 6, [0; 8], 0x0004, &payload)));

    assert!(packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["sll", "llc", "stp"]);
    assert_eq!(
        packet.tree.field_values("sll.ltype"),
        vec![&Value::Uint16(0x0004)]
    );
    assert!(packet.tree.field_values("sll.etype").is_empty());
    assert_eq!(
        packet.tree.field_values("llc.dsap"),
        vec![&Value::Uint8(0x42)]
    );
}

#[test]
fn sll_v2_fields_include_interface_and_reserved() {
    let packet = decode_frame(&link_frame(
        276,
        sll_v2(
            0x0800,
            0xbeef,
            3,
            TestSll2Address {
                address_type: 1,
                packet_type: 0,
                address_length: 6,
                address: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00],
            },
            &ipv4_prefix(),
        ),
    ));

    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["sll", "ip"]);
    assert_eq!(
        packet.tree.field_values("sll.pkttype"),
        vec![&Value::Uint16(0)]
    );
    assert_eq!(
        packet.tree.field_values("sll.halen"),
        vec![&Value::Uint16(6)]
    );
    assert_eq!(
        packet.tree.field_values("sll.ifindex"),
        vec![&Value::Uint32(3)]
    );
    assert_eq!(
        packet.tree.field_values("sll.reserved"),
        vec![&Value::bytes(vec![0xbe, 0xef])]
    );
    assert_eq!(
        packet.tree.field_values("sll.etype"),
        vec![&Value::Uint16(0x0800)]
    );
}

#[test]
fn sll_v2_truncated_fixed_header_reports_malformed() {
    let mut captured = sll_v2(
        0x8100,
        0,
        3,
        TestSll2Address {
            address_type: 1,
            packet_type: 0,
            address_length: 6,
            address: [0; 8],
        },
        &[],
    );
    captured.truncate(12);
    let packet = decode_frame(&link_frame(276, captured));

    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    assert_eq!(
        packet.tree.field_values("sll.etype"),
        vec![&Value::Uint16(0x8100)]
    );
    assert!(packet.tree.field_values("sll.src.eth").is_empty());
    assert!(packet.tree.child("vlan").is_none());
    let sll = packet.tree.child("sll");
    assert!(sll.is_some());
    if let Some(sll) = sll {
        assert!(sll.children.is_empty());
        assert_eq!(sll.experts.len(), 1);
    }
}

#[test]
fn null_and_loopback_decode_their_family_byte_order() {
    let mut little = Vec::new();
    little.extend_from_slice(&2_u32.to_le_bytes());
    little.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(0, little));
    assert!(!packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["null", "ip"]);
    assert_eq!(
        packet.tree.field_values("null.family"),
        vec![&Value::Uint32(2)]
    );
    assert!(packet.tree.field_values("null.type").is_empty());

    let mut network_order = Vec::new();
    network_order.extend_from_slice(&2_u32.to_be_bytes());
    network_order.extend_from_slice(&ipv4_prefix());
    let detected = decode_frame(&link_frame(0, network_order));
    assert_eq!(
        detected.tree.field_values("null.family"),
        vec![&Value::Uint32(2)]
    );

    let mut loopback = Vec::new();
    loopback.extend_from_slice(&24_u32.to_be_bytes());
    loopback.extend_from_slice(&[0x60, 0, 0, 0]);
    let loop_packet = decode_frame(&link_frame(108, loopback));
    assert_eq!(
        loop_packet.tree.field_values("null.family"),
        vec![&Value::Uint32(24)]
    );

    let mut loop_little = Vec::new();
    loop_little.extend_from_slice(&2_u32.to_le_bytes());
    loop_little.extend_from_slice(&ipv4_prefix());
    let loop_little_packet = decode_frame(&link_frame(108, loop_little));
    assert_eq!(
        loop_little_packet.tree.field_values("null.family"),
        vec![&Value::Uint32(33_554_432)]
    );
}

#[test]
fn truncated_null_header_reports_malformed() {
    let packet = decode_frame(&link_frame(0, vec![0x02, 0x00, 0x00]));

    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    let node = packet.tree.child("null");
    assert!(node.is_some());
    if let Some(node) = node {
        assert!(node.fields.is_empty());
        assert_eq!(node.experts.len(), 1);
    }
}

#[test]
fn raw_ip_versions_and_empty_frames() {
    let ipv6 = {
        let mut datagram = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        datagram.extend_from_slice(&SOURCE_IPV6);
        datagram.extend_from_slice(&DESTINATION_IPV6);
        datagram
    };
    for (version, payload, stack) in [
        (4_u8, ipv4_prefix(), vec!["ip"]),
        (6_u8, ipv6, vec!["ipv6"]),
        (7_u8, vec![0x70, 0, 0, 0], Vec::new()),
    ] {
        let packet = decode_frame(&link_frame(101, payload));
        assert!(!packet.malformed, "version {version}");
        assert_eq!(packet.protocol_stack, stack, "version {version}");
        assert_eq!(
            packet.tree.frame.children.len(),
            usize::from(version != 7),
            "version {version}"
        );
    }

    let empty = decode_frame(&link_frame(101, Vec::new()));
    assert!(empty.malformed);
    assert!(empty.tree.frame.has_expert(Group::Malformed));
    assert!(empty.tree.frame.children.is_empty());
}

#[test]
fn vlan_stacking_stops_at_the_depth_limit() {
    let mut body = Vec::new();
    for index in 0..20_u16 {
        let inner = if index == 19 { 0x0800 } else { 0x8100 };
        body.extend_from_slice(&tag(tci(0, false, index), inner));
    }
    body.extend_from_slice(&ipv4_prefix());
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x8100, &body)));

    assert!(packet.malformed);
    assert!(packet.tree.has_expert(Group::Malformed));
    assert_eq!(packet.protocol_stack.len(), MAX_DECODE_DEPTH);
    assert_eq!(
        packet
            .protocol_stack
            .iter()
            .filter(|name| **name == "vlan")
            .count(),
        MAX_DECODE_DEPTH - 1
    );
}

#[test]
fn ethernet_type_length_boundaries_pick_type_or_length() {
    let padded = padded_snap();

    let zero = decode_frame(&link_frame(1, ethernet_frame(0, &padded)));
    assert!(!zero.malformed);
    assert_eq!(
        zero.tree.field_values("eth.type"),
        vec![&Value::Uint16(0x0000)]
    );
    assert!(zero.tree.field_values("eth.len").is_empty());
    assert!(
        zero.tree
            .child("eth")
            .and_then(|eth| eth.child("llc"))
            .is_none()
    );

    let one = decode_frame(&link_frame(1, ethernet_frame(1, &padded)));
    assert!(one.malformed);
    assert_eq!(one.tree.field_values("eth.len"), vec![&Value::Uint16(1)]);
    let one_llc = one.tree.child("eth").and_then(|eth| eth.child("llc"));
    assert!(one_llc.is_some());
    if let Some(llc) = one_llc {
        assert_eq!(llc.range, Range::new(14, 1));
        assert_eq!(
            frame_field(llc, "llc.dsap").map(|field| &field.value),
            Some(&Value::Uint8(0xaa))
        );
        assert!(frame_field(llc, "llc.ssap").is_none());
        assert!(frame_field(llc, "llc.control").is_none());
    }

    let four = decode_frame(&link_frame(1, ethernet_frame(4, &padded)));
    assert!(four.malformed);
    let four_llc = four.tree.child("eth").and_then(|eth| eth.child("llc"));
    assert!(four_llc.is_some());
    if let Some(llc) = four_llc {
        assert_eq!(llc.range, Range::new(14, 4));
        assert_eq!(
            frame_field(llc, "llc.control").map(|field| &field.value),
            Some(&Value::Uint16(0x0003))
        );
        assert!(frame_field(llc, "llc.oui").is_none());
        assert!(frame_field(llc, "llc.type").is_none());
    }

    for value in [1_501_u16, 1_535] {
        let packet = decode_frame(&link_frame(1, ethernet_frame(value, &padded)));
        assert!(!packet.malformed, "value {value}");
        assert!(packet.tree.field_values("eth.len").is_empty());
        assert!(packet.tree.field_values("eth.type").is_empty());
        assert!(
            packet
                .tree
                .child("eth")
                .and_then(|eth| eth.child("llc"))
                .is_none()
        );
        let eth = packet.tree.child("eth");
        assert!(eth.is_some());
        if let Some(eth) = eth {
            assert_eq!(eth.experts.len(), 1);
            if let Some(expert) = eth.experts.first() {
                assert_eq!(expert.severity, Severity::Warning);
                assert_eq!(expert.group, Group::Protocol);
                assert!(expert.message.contains("Invalid length/type"));
            }
        }
    }

    let ethertype = decode_frame(&link_frame(1, ethernet_frame(1_536, &padded)));
    assert!(!ethertype.malformed);
    assert_eq!(
        ethertype.tree.field_values("eth.type"),
        vec![&Value::Uint16(0x0600)]
    );
    assert!(ethertype.tree.field_values("eth.len").is_empty());
    assert!(
        ethertype
            .tree
            .child("eth")
            .and_then(|eth| eth.child("llc"))
            .is_none()
    );
}

#[test]
fn vlan_inner_length_bounds_llc() {
    let padded = padded_snap();

    let mut four_body = tag(tci(1, false, 10), 4);
    four_body.extend_from_slice(&padded);
    let four = decode_frame(&link_frame(1, ethernet_frame(0x8100, &four_body)));
    assert!(four.malformed);
    assert_eq!(four.tree.field_values("vlan.len"), vec![&Value::Uint16(4)]);
    let four_llc = four
        .tree
        .child("eth")
        .and_then(|eth| eth.child("vlan"))
        .and_then(|vlan| vlan.child("llc"));
    assert!(four_llc.is_some());
    if let Some(llc) = four_llc {
        assert_eq!(llc.range, Range::new(18, 4));
        assert_eq!(
            frame_field(llc, "llc.control").map(|field| &field.value),
            Some(&Value::Uint16(0x0003))
        );
        assert!(frame_field(llc, "llc.oui").is_none());
    }

    let mut zero_body = tag(tci(2, false, 20), 0);
    zero_body.extend_from_slice(&padded);
    let zero = decode_frame(&link_frame(1, ethernet_frame(0x8100, &zero_body)));
    assert!(zero.malformed);
    assert_eq!(zero.tree.field_values("vlan.len"), vec![&Value::Uint16(0)]);
    let zero_llc = zero
        .tree
        .child("eth")
        .and_then(|eth| eth.child("vlan"))
        .and_then(|vlan| vlan.child("llc"));
    assert!(zero_llc.is_some());
    if let Some(llc) = zero_llc {
        assert_eq!(llc.range, Range::new(18, 0));
        assert!(llc.fields.is_empty());
    }

    for value in [1_501_u16, 1_536] {
        let mut body = tag(tci(3, false, 30), value);
        body.extend_from_slice(&padded);
        let packet = decode_frame(&link_frame(1, ethernet_frame(0x8100, &body)));
        assert!(!packet.malformed, "value {value}");
        assert_eq!(
            packet.tree.field_values("vlan.etype"),
            vec![&Value::Uint16(value)]
        );
        assert!(packet.tree.field_values("vlan.len").is_empty());
        assert!(
            packet
                .tree
                .child("eth")
                .and_then(|eth| eth.child("vlan"))
                .and_then(|vlan| vlan.child("llc"))
                .is_none()
        );
    }
}

#[test]
fn provider_inner_value_is_always_an_ethertype() {
    let padded = padded_snap();
    for value in [4_u16, 1_500, 1_501, 1_536] {
        let mut body = tag(tci(1, false, 10), value);
        body.extend_from_slice(&padded);
        let packet = decode_frame(&link_frame(1, ethernet_frame(0x88a8, &body)));
        assert!(!packet.malformed, "value {value}");
        assert_eq!(
            packet.tree.field_values("ieee8021ad.id"),
            vec![&Value::Uint16(10)]
        );
        assert!(packet.tree.field_values("vlan.len").is_empty());
        assert!(
            packet
                .tree
                .child("eth")
                .and_then(|eth| eth.child("ieee8021ad"))
                .and_then(|provider| provider.child("vlan"))
                .is_none()
        );
    }
}

#[test]
fn double_provider_truncation_limits_decoded_fields() {
    let first = tag(tci(1, false, 10), 0x88a8);
    let second = tci(2, true, 20);

    for extra in [&[][..], &[0x00][..]] {
        let mut body = first.clone();
        body.extend_from_slice(extra);
        let packet = decode_frame(&link_frame(1, ethernet_frame(0x88a8, &body)));
        assert!(packet.malformed);
        assert!(packet.tree.has_expert(Group::Malformed));
        assert!(packet.tree.field_values("ieee8021ad.priority").is_empty());
        assert!(packet.tree.field_values("ieee8021ad.svid").is_empty());
    }

    let mut six = first.clone();
    six.extend_from_slice(&second.to_be_bytes());
    let six_packet = decode_frame(&link_frame(1, ethernet_frame(0x88a8, &six)));
    assert!(six_packet.malformed);
    assert_eq!(
        six_packet.tree.field_values("ieee8021ad.priority"),
        vec![&Value::Uint16(1), &Value::Uint16(2)]
    );
    assert_eq!(
        six_packet.tree.field_values("ieee8021ad.svid"),
        vec![&Value::Uint16(10)]
    );
    assert_eq!(
        six_packet.tree.field_values("ieee8021ad.cvid"),
        vec![&Value::Uint16(20)]
    );
    assert!(six_packet.tree.field_values("ieee8021ad.id").is_empty());
}

#[test]
fn sll_v2_complete_header_opens_dispatch() {
    let packet = decode_frame(&link_frame(
        276,
        sll_v2(
            0x8100,
            0,
            3,
            TestSll2Address {
                address_type: 1,
                packet_type: 0,
                address_length: 6,
                address: [0; 8],
            },
            &[],
        ),
    ));

    assert!(packet.malformed);
    assert_eq!(packet.protocol_stack, vec!["sll", "vlan"]);
    assert!(
        packet
            .tree
            .child("sll")
            .and_then(|sll| sll.child("vlan"))
            .is_some()
    );
}

#[test]
fn raw_link_types_force_ip_version() {
    let mut ipv6_shaped = vec![0x60]; // version nibble 6
    ipv6_shaped.resize(40, 0);
    let forced_v4 = decode_frame(&link_frame(228, ipv6_shaped));
    assert!(forced_v4.protocol_stack.contains(&"ip"));
    assert!(!forced_v4.protocol_stack.contains(&"ipv6"));

    let mut ipv4_shaped = vec![0x45]; // version nibble 4
    ipv4_shaped.resize(40, 0);
    let forced_v6 = decode_frame(&link_frame(229, ipv4_shaped));
    assert!(forced_v6.protocol_stack.contains(&"ipv6"));
    assert!(!forced_v6.protocol_stack.contains(&"ip"));
}

#[test]
#[expect(clippy::panic, reason = "the fixture guarantees the Ethernet node")]
fn field_level_malformed_keeps_protocol_exception_clear() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&DESTINATION_MAC);
    frame.extend_from_slice(&SOURCE_MAC);
    frame.extend_from_slice(&100_u16.to_be_bytes());
    let packet = decode_frame(&captured_frame(1, frame));
    let ethernet = packet
        .tree
        .child("eth")
        .unwrap_or_else(|| panic!("Ethernet node"));
    assert!(!ethernet.protocol_exception);
    assert!(
        ethernet
            .experts
            .iter()
            .any(|expert| expert.group == Group::Malformed)
    );

    let short = decode_frame(&captured_frame(1, vec![0]));
    let ethernet = short
        .tree
        .child("eth")
        .unwrap_or_else(|| panic!("short Ethernet node"));
    assert!(ethernet.protocol_exception);
}

#[test]
fn ospf_v3_db_description_attaches_reserved_experts_to_each_field() {
    for (first, second, expected) in [(1, 0, 1_usize), (0, 1, 1), (1, 1, 2), (0, 0, 0)] {
        let mut body = vec![first, 0, 0, 0x01, 0x05, 0xdc, second, 0];
        body.extend_from_slice(&[0, 0, 0, 1]);
        let packet = decode_frame(&captured_frame(
            1,
            ospf_ipv6_frame(&ospf_v3_packet(2, &body)),
        ));
        let reserved: Vec<&Field> = packet
            .tree
            .fields()
            .filter(|field| field.def.abbrev == "ospf.reserved")
            .collect();
        assert_eq!(reserved.len(), 3, "header and both DBD reserved bytes");
        let anchored = reserved
            .iter()
            .filter(|field| !field.experts.is_empty())
            .count();
        assert_eq!(anchored, expected, "anchored reserved experts");
        let markers: Vec<&Field> = packet
            .tree
            .fields()
            .filter(|field| field.def.abbrev == "ospf.reserved.not_zero")
            .collect();
        assert_eq!(markers.len(), expected, "hidden expert markers");
        for marker in markers {
            assert!(marker.hidden);
            assert_eq!(marker.value, Value::None);
        }
    }
}

#[test]
#[expect(clippy::panic, reason = "the fixture guarantees the OSPF node")]
fn ospf_valid_packet_has_no_checksum_expert() {
    let hello = [
        255, 255, 255, 0, 0, 10, 0x02, 1, 0, 0, 0, 40, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    ];
    let packet = decode_frame(&captured_frame(
        1,
        ospf_ipv4_frame(&ospf_v2_packet(1, &hello)),
    ));
    let ospf = child_node(&packet.tree.frame, "ospf").unwrap_or_else(|| panic!("OSPF node"));
    assert!(!packet.malformed);
    assert!(
        !ospf
            .experts
            .iter()
            .any(|expert| expert.group == Group::Checksum)
    );
    assert_eq!(
        frame_field(ospf, "ospf.hello.router_dead_interval").map(|f| &f.value),
        Some(&Value::Uint32(40))
    );
}

#[test]
#[expect(clippy::panic, reason = "the fixture guarantees the OSPF node")]
fn ospf_v2_router_flag_bits_match_the_field_masks() {
    for (bit, expected) in [
        (0x01, "b"),
        (0x02, "e"),
        (0x04, "v"),
        (0x08, "w"),
        (0x10, "n"),
        (0x20, "s"),
        (0x80, "h"),
    ] {
        let mut lsa = vec![0_u8, 0, 0x22, 1];
        lsa.extend_from_slice(&[1, 1, 1, 1]);
        lsa.extend_from_slice(&[1, 1, 1, 1]);
        lsa.extend_from_slice(&0x8000_0001_u32.to_be_bytes());
        lsa.extend_from_slice(&[0, 0]);
        lsa.extend_from_slice(&24_u16.to_be_bytes());
        lsa.extend_from_slice(&[bit, 0, 0, 0]);
        let mut update = 1_u32.to_be_bytes().to_vec();
        update.extend_from_slice(&lsa);
        let packet = decode_frame(&captured_frame(
            1,
            ospf_ipv4_frame(&ospf_v2_packet(4, &update)),
        ));
        let ospf = child_node(&packet.tree.frame, "ospf").unwrap_or_else(|| panic!("OSPF node"));
        let flag = |suffix: &str| {
            frame_field(ospf, &format!("ospf.v2.router.lsa.flags.{suffix}"))
                .map(|field| field.value == Value::Boolean(true))
                .unwrap_or(false)
        };
        for suffix in ["b", "e", "v", "w", "n", "s", "h"] {
            assert_eq!(
                flag(suffix),
                suffix == expected,
                "flags 0x{bit:02x} field {suffix}"
            );
        }
    }
}

#[test]
#[expect(clippy::panic, reason = "the fixture guarantees the OSPF node")]
fn ospf_bad_checksum_reports_the_expected_value() {
    let hello = [
        255, 255, 255, 0, 0, 10, 0x02, 1, 0, 0, 0, 40, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    ];
    let mut ospf = ospf_v2_packet(1, &hello);
    let expected = ospf
        .get(12..14)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0);
    if let Some(slot) = ospf.get_mut(12..14) {
        slot.copy_from_slice(&0x1234_u16.to_be_bytes());
    }
    let packet = decode_frame(&captured_frame(1, ospf_ipv4_frame(&ospf)));
    let ospf = child_node(&packet.tree.frame, "ospf").unwrap_or_else(|| panic!("OSPF node"));
    let checksum = frame_field(ospf, "ospf.checksum").unwrap_or_else(|| panic!("checksum"));
    assert_eq!(
        checksum.showname.as_deref(),
        Some(format!("Checksum: 0x1234 [incorrect, should be 0x{expected:04x}]").as_str())
    );
    assert!(
        !ospf
            .experts
            .iter()
            .any(|expert| expert.group == Group::Checksum)
    );
}

fn lldp_tlv(kind: u16, content: &[u8]) -> Vec<u8> {
    let header = ((kind & 0x01ff) << 9) | u16::try_from(content.len()).unwrap_or(0);
    let mut tlv = header.to_be_bytes().to_vec();
    tlv.extend_from_slice(content);
    tlv
}

fn lldp_mandatory() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&lldp_tlv(1, &[4, 0, 0x11, 0x22, 0x33, 0x44, 0x55]));
    payload.extend_from_slice(&lldp_tlv(2, &[5, b'e', b't', b'h', b'0']));
    payload.extend_from_slice(&lldp_tlv(3, &[0x00, 0x78]));
    payload
}

#[test]
fn lldp_field_ranges_follow_the_tlv_offsets() {
    let mut payload = lldp_mandatory();
    payload.extend_from_slice(&lldp_tlv(0, &[]));
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x88cc, &payload)));
    let Some(lldp) = packet.tree.child("eth").and_then(|eth| eth.child("lldp")) else {
        return;
    };
    let range = |abbrev: &str| frame_field(lldp, abbrev).map(|field| field.range);
    assert_eq!(range("lldp.chassis.subtype"), Some(Range::new(16, 1)));
    assert_eq!(range("lldp.chassis.id.mac"), Some(Range::new(17, 6)));
    assert_eq!(range("lldp.port.subtype"), Some(Range::new(25, 1)));
    assert_eq!(range("lldp.port.id"), Some(Range::new(26, 4)));
    assert_eq!(range("lldp.time_to_live"), Some(Range::new(32, 2)));
    assert_eq!(lldp.range, Range::new(14, payload.len()));
}

#[test]
fn one_byte_lldp_payload_is_malformed() {
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x88cc, &[0x02])));
    assert!(packet.malformed);
}

#[test]
fn unknown_base_lldp_tlv_is_skipped_by_its_declared_length() {
    let mut payload = lldp_mandatory();
    payload.extend_from_slice(&lldp_tlv(9, b"abc"));
    payload.extend_from_slice(&lldp_tlv(5, b"switch"));
    payload.extend_from_slice(&lldp_tlv(0, &[]));
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x88cc, &payload)));
    let Some(lldp) = packet.tree.child("eth").and_then(|eth| eth.child("lldp")) else {
        return;
    };
    assert_eq!(
        frame_field(lldp, "lldp.tlv.system.name").map(|field| &field.value),
        Some(&Value::String("switch".to_string()))
    );
}

#[test]
fn zero_length_lldp_management_address_is_malformed() {
    let mut payload = lldp_mandatory();
    payload.extend_from_slice(&lldp_tlv(8, &[0, 1, 2, 0, 0, 0, 1, 0]));
    payload.extend_from_slice(&lldp_tlv(0, &[]));
    let packet = decode_frame(&link_frame(1, ethernet_frame(0x88cc, &payload)));
    assert!(packet.malformed);
    let Some(lldp) = packet.tree.child("eth").and_then(|eth| eth.child("lldp")) else {
        return;
    };
    assert!(frame_field(lldp, "lldp.mgn.interface.number").is_none());
}

/// Wrap one payload in an IPv4 and UDP header for transport tests.
fn services_udp_frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&destination_port.to_be_bytes());
    let length = u16::try_from(8_usize.saturating_add(payload.len())).unwrap_or(u16::MAX);
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let total = u16::try_from(20_usize.saturating_add(udp.len())).unwrap_or(u16::MAX);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&0_u16.to_be_bytes());
    ip.extend_from_slice(&0x4000_u16.to_be_bytes());
    ip.push(64);
    ip.push(17);
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&[192, 0, 2, 1]);
    ip.extend_from_slice(&[198, 51, 100, 2]);
    ip.extend_from_slice(&udp);
    ethernet_frame(0x0800, &ip)
}

/// Wrap one payload in an IPv4 and TCP header for payload-label tests.
fn one_byte_tcp_frame() -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&40_000_u16.to_be_bytes());
    tcp.extend_from_slice(&80_u16.to_be_bytes());
    tcp.extend_from_slice(&1_u32.to_be_bytes());
    tcp.extend_from_slice(&0_u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(0x18);
    tcp.extend_from_slice(&65_535_u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(&0_u16.to_be_bytes());
    tcp.push(0x78);
    let total = u16::try_from(20_usize.saturating_add(tcp.len())).unwrap_or(u16::MAX);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&0_u16.to_be_bytes());
    ip.extend_from_slice(&0x4000_u16.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&[192, 0, 2, 1]);
    ip.extend_from_slice(&[198, 51, 100, 2]);
    ip.extend_from_slice(&tcp);
    ethernet_frame(0x0800, &ip)
}

#[test]
#[expect(
    clippy::panic,
    reason = "the generated frames contain UDP and TCP nodes"
)]
fn one_byte_payload_labels_are_singular() {
    let packet = decode_frame(&captured_frame(1, services_udp_frame(1234, 5678, &[0x78])));
    let udp = child_node(&packet.tree.frame, "udp").unwrap_or_else(|| panic!("UDP node"));
    assert_eq!(
        frame_field(udp, "udp.payload").and_then(|field| field.showname.as_deref()),
        Some("UDP payload (1 byte)")
    );

    let packet = decode_frame(&captured_frame(1, one_byte_tcp_frame()));
    let tcp = child_node(&packet.tree.frame, "tcp").unwrap_or_else(|| panic!("TCP node"));
    assert_eq!(
        frame_field(tcp, "tcp.payload").and_then(|field| field.showname.as_deref()),
        Some("TCP payload (1 byte)")
    );
}

fn option_container(node: &Node, code: u8) -> Option<&Field> {
    node.fields.iter().find(|field| {
        field.def.abbrev == "dhcp.option.type"
            && matches!(field.value, Value::Uint8(value) if value == code)
    })
}

#[test]
fn dhcp_options_are_containers_with_hidden_values() {
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&dhcp_option_bytes(12, b"host"));
    let mut agent = Vec::new();
    agent.extend_from_slice(&[1, 2, 0xaa, 0xbb]);
    main.extend_from_slice(&dhcp_option_bytes(82, &agent));
    main.push(255);
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());

    let flags = dhcp
        .fields
        .iter()
        .find(|field| field.def.abbrev == "dhcp.flags")
        .unwrap_or_else(|| unreachable!());
    assert!(flags.is_container());
    assert!(
        flags
            .children
            .iter()
            .any(|field| field.def.abbrev == "dhcp.flags.bc")
    );

    let message_type = option_container(dhcp, 53).unwrap_or_else(|| unreachable!());
    assert!(message_type.is_container());
    let length = message_type
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.length")
        .unwrap_or_else(|| unreachable!());
    assert_eq!(length.value, Value::Uint8(1));
    let value = message_type
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.value")
        .unwrap_or_else(|| unreachable!());
    assert!(value.hidden);
    assert!(
        message_type
            .children
            .iter()
            .any(|field| field.def.abbrev == "dhcp.option.dhcp")
    );

    let agent = option_container(dhcp, 82).unwrap_or_else(|| unreachable!());
    let suboption = agent
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.agent_information_option.suboption")
        .unwrap_or_else(|| unreachable!());
    assert!(suboption.is_container());
    assert!(
        suboption.children.iter().any(
            |field| field.def.abbrev == "dhcp.option.agent_information_option.agent_circuit_id"
        )
    );
}

#[test]
fn dhcp_agent_suboptions_hide_only_handled_values() {
    let mut agent = Vec::new();
    agent.extend_from_slice(&[1, 2, 0xaa, 0xbb]);
    agent.extend_from_slice(&[0, 1, 0xcc]);
    agent.extend_from_slice(&[3, 1, 0xdd]);
    agent.extend_from_slice(&[14, 1, 0xee]);
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&dhcp_option_bytes(82, &agent));
    main.push(255);
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let option = option_container(dhcp, 82).unwrap_or_else(|| unreachable!());
    let suboptions: Vec<&Field> = option
        .children
        .iter()
        .filter(|field| field.def.abbrev == "dhcp.option.agent_information_option.suboption")
        .collect();
    assert_eq!(suboptions.len(), 4);
    let hidden = |field: &Field| {
        field
            .children
            .iter()
            .find(|child| child.def.abbrev == "dhcp.option.agent_information_option.value")
            .is_some_and(|child| child.hidden)
    };
    // Codes 1-13 have a typed decode, so their generic value line is hidden;
    // padding and the unregistered codes keep it visible.
    assert!(hidden(
        suboptions
            .first()
            .copied()
            .unwrap_or_else(|| unreachable!())
    ));
    assert!(!hidden(
        suboptions.get(1).copied().unwrap_or_else(|| unreachable!())
    ));
    assert!(hidden(
        suboptions.get(2).copied().unwrap_or_else(|| unreachable!())
    ));
    assert!(!hidden(
        suboptions.get(3).copied().unwrap_or_else(|| unreachable!())
    ));
}

#[test]
fn dhcp_agent_missing_suboption_length_keeps_its_value_hidden() {
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&dhcp_option_bytes(82, &[1]));
    main.push(255);
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let option = option_container(dhcp, 82).unwrap_or_else(|| unreachable!());
    let value = option
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.value")
        .unwrap_or_else(|| unreachable!());
    assert!(value.hidden);
    let marker = option
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.missing_subopt_length")
        .unwrap_or_else(|| unreachable!());
    assert_eq!(marker.range.offset, option.range.offset);
    let expert = marker.experts.first().unwrap_or_else(|| unreachable!());
    assert_eq!(expert.group, Group::Protocol);
    assert_eq!(
        expert.message,
        "Suboption 1: no room left in option for suboption length"
    );
}

fn dhcp_overload_payload(overload: &[u8], file: &[u8], sname: &[u8]) -> Vec<u8> {
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&dhcp_option_bytes(52, overload));
    main.push(255);
    bootp_test_payload(sname, file, &main)
}

fn assert_malformed_group_follows_main_end(payload: &[u8], showname_prefix: &str) {
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let display: Vec<&Field> = dhcp.display_fields().collect();
    let group = display
        .iter()
        .position(|field| {
            field
                .showname_text()
                .is_some_and(|name| name == showname_prefix)
        })
        .unwrap_or_else(|| unreachable!());
    let cookie = display
        .iter()
        .position(|field| field.def.abbrev == "dhcp.cookie")
        .unwrap_or_else(|| unreachable!());
    let last_end = display
        .iter()
        .rposition(|field| field.def.abbrev == "dhcp.option.end")
        .unwrap_or(0);
    assert!(group > cookie, "group before cookie: {group} <= {cookie}");
    assert!(
        group > last_end,
        "group before main End: {group} <= {last_end}"
    );
}

#[test]
fn dhcp_malformed_file_overload_stays_after_the_main_end() {
    let payload = dhcp_overload_payload(&[1], &[12, 255], &[]);
    assert_malformed_group_follows_main_end(&payload, "Boot file name option overload");
}

#[test]
fn dhcp_malformed_sname_overload_stays_after_the_main_end() {
    let payload = dhcp_overload_payload(&[2], &[], &[12, 255]);
    assert_malformed_group_follows_main_end(&payload, "Server host name option overload");
}

#[test]
fn dhcp_malformed_sname_with_file_group_keeps_file_group_moved() {
    let mut file = dhcp_option_bytes(12, b"file");
    file.push(255);
    let payload = dhcp_overload_payload(&[3], &file, &[12, 255]);
    assert_malformed_group_follows_main_end(&payload, "Server host name option overload");
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let display: Vec<&Field> = dhcp.display_fields().collect();
    let file_group = display
        .iter()
        .position(|field| {
            field
                .showname_text()
                .is_some_and(|name| name == "Boot file name option overload")
        })
        .unwrap_or_else(|| unreachable!());
    let sname_marker = display
        .iter()
        .position(|field| {
            field
                .showname_text()
                .is_some_and(|name| name.starts_with("Server name option overloaded"))
        })
        .unwrap_or_else(|| unreachable!());
    assert!(file_group > sname_marker);
}

#[test]
fn dhcp_rfc3396_blocks_mark_and_decode_the_last_block() {
    let mut main = dhcp_option_bytes(12, b"ab");
    main.extend_from_slice(&dhcp_option_bytes(12, b"cd"));
    main.push(255);
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let blocks: Vec<&Field> = dhcp
        .fields
        .iter()
        .filter(|field| {
            field.def.abbrev == "dhcp.option.type" && matches!(field.value, Value::Uint8(12))
        })
        .collect();
    assert_eq!(blocks.len(), 2);
    let first = blocks.first().copied().unwrap_or_else(|| unreachable!());
    let marker = first
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.rfc_3396_detected")
        .unwrap_or_else(|| unreachable!());
    assert!(marker.is_container());
    assert!(
        marker
            .children
            .iter()
            .any(|field| field.def.abbrev == "dhcp.option.refer_last_option")
    );
    let last = blocks.get(1).copied().unwrap_or_else(|| unreachable!());
    let hostname = last
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.hostname")
        .unwrap_or_else(|| unreachable!());
    assert!(matches!(&hostname.value, Value::String(text) if text == "abcd"));
    assert_eq!(hostname.range.length, 4);
    assert!(hostname.raw.is_some());
}

#[test]
fn dhcp_truncated_option_keeps_its_container_and_bounds() {
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&[12, 8, b'a']);
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    assert!(packet.malformed);
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let truncated = option_container(dhcp, 12).unwrap_or_else(|| unreachable!());
    assert_eq!(truncated.range.length, 10);
    assert!(
        truncated
            .children
            .iter()
            .all(|field| field.def.abbrev != "dhcp.option.value")
    );
}

fn dhcpv6_option(code: u16, body: &[u8]) -> Vec<u8> {
    let mut option = Vec::new();
    option.extend_from_slice(&code.to_be_bytes());
    option.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
    option.extend_from_slice(body);
    option
}

#[test]
fn dhcpv6_ia_options_nest_inside_the_parent_option() {
    let mut address = Vec::new();
    address.extend_from_slice(&SOURCE_IPV6);
    address.extend_from_slice(&300_u32.to_be_bytes());
    address.extend_from_slice(&600_u32.to_be_bytes());
    let mut ia = Vec::new();
    ia.extend_from_slice(&1_u32.to_be_bytes());
    ia.extend_from_slice(&100_u32.to_be_bytes());
    ia.extend_from_slice(&200_u32.to_be_bytes());
    ia.extend_from_slice(&dhcpv6_option(5, &address));
    let mut message = vec![1, 0x12, 0x34, 0x56];
    message.extend_from_slice(&dhcpv6_option(3, &ia));
    let packet = decode_frame(&captured_frame(1, services_udp_frame(546, 547, &message)));
    let dhcpv6 = child_node(&packet.tree.frame, "dhcpv6").unwrap_or_else(|| unreachable!());
    let ia_na = dhcpv6
        .fields
        .iter()
        .find(|field| {
            field.def.abbrev == "dhcpv6.option.type_str"
                && matches!(&field.value, Value::String(name) if name == "Identity Association for Non-temporary Address")
        })
        .unwrap_or_else(|| unreachable!());
    assert!(ia_na.is_container());
    let nested = ia_na
        .children
        .iter()
        .find(|field| {
            field.def.abbrev == "dhcpv6.option.type_str"
                && matches!(&field.value, Value::String(name) if name == "IA Address")
        })
        .unwrap_or_else(|| unreachable!());
    assert!(nested.is_container());
    assert!(
        nested
            .children
            .iter()
            .any(|field| field.def.abbrev == "dhcpv6.iaaddr.ip")
    );
}

#[test]
fn dhcpv6_relay_message_nests_the_inner_protocol() {
    let mut inner = vec![1, 0x12, 0x34, 0x56];
    inner.extend_from_slice(&dhcpv6_option(6, &[0, 23]));
    let mut relay = vec![12, 0];
    relay.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    relay.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    relay.extend_from_slice(&dhcpv6_option(9, &inner));
    let packet = decode_frame(&captured_frame(1, services_udp_frame(547, 546, &relay)));
    let dhcpv6 = child_node(&packet.tree.frame, "dhcpv6").unwrap_or_else(|| unreachable!());
    let relay_option = dhcpv6
        .fields
        .iter()
        .find(|field| {
            field.def.abbrev == "dhcpv6.option.type_str"
                && matches!(&field.value, Value::String(name) if name == "Relay Message")
        })
        .unwrap_or_else(|| unreachable!());
    assert_eq!(relay_option.nodes.len(), 1);
    let inner = relay_option.nodes.first().unwrap_or_else(|| unreachable!());
    assert_eq!(inner.protocol.filter_name, "dhcpv6");
    assert!(
        inner
            .fields
            .iter()
            .any(|field| field.def.abbrev == "dhcpv6.msgtype")
    );
}

/// Build a DHCPv6 Solicit whose IA_TA options nest `levels` deep.
fn nested_ia_ta_message(levels: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for level in 0..levels {
        let mut option = Vec::new();
        option.extend_from_slice(&4_u16.to_be_bytes());
        let length = u16::try_from(4_usize.saturating_add(body.len())).unwrap_or(u16::MAX);
        option.extend_from_slice(&length.to_be_bytes());
        let iaid = u32::try_from(level).unwrap_or(0);
        option.extend_from_slice(&iaid.to_be_bytes());
        option.extend_from_slice(&body);
        body = option;
    }
    let mut message = vec![1];
    message.extend_from_slice(&[0x12, 0x34, 0x56]);
    message.extend_from_slice(&body);
    message
}

#[test]
#[expect(clippy::panic, reason = "the fixture guarantees the DHCPv6 node")]
fn dhcpv6_nested_ia_options_stop_at_the_depth_limit() {
    let payload = nested_ia_ta_message(32);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(546, 547, &payload)));
    assert!(packet.malformed);
    let node = child_node(&packet.tree.frame, "dhcpv6").unwrap_or_else(|| panic!("DHCPv6 node"));
    assert!(
        node.experts
            .iter()
            .any(|expert| expert.message.contains("option nesting is too deep")),
        "missing depth expert: {:?}",
        node.experts
    );
}

#[test]
fn dhcpv6_deep_ia_payload_survives_a_one_mebibyte_stack() {
    let payload = nested_ia_ta_message(8_185);
    assert!(payload.len() > 65_000);
    let frame = captured_frame(1, services_udp_frame(546, 547, &payload));
    let Ok(handle) = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            let packet = decode_frame(&frame);
            assert!(packet.malformed);
        })
    else {
        return;
    };
    assert!(handle.join().is_ok(), "decoder thread must not panic");
}

fn bootp_test_payload(server_name: &[u8], boot_file: &[u8], options: &[u8]) -> Vec<u8> {
    let mut payload = vec![2, 1, 6, 0];
    payload.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
    payload.extend_from_slice(&0_u16.to_be_bytes());
    payload.extend_from_slice(&0x8000_u16.to_be_bytes());
    payload.extend_from_slice(&[0; 16]);
    payload.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    payload.extend_from_slice(&[0; 10]);
    let mut name = vec![0_u8; 64];
    for (slot, byte) in name.iter_mut().zip(server_name.iter()) {
        *slot = *byte;
    }
    payload.extend_from_slice(&name);
    let mut file = vec![0_u8; 128];
    for (slot, byte) in file.iter_mut().zip(boot_file.iter()) {
        *slot = *byte;
    }
    payload.extend_from_slice(&file);
    payload.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    payload.extend_from_slice(options);
    payload
}

fn dhcp_option_bytes(code: u8, body: &[u8]) -> Vec<u8> {
    let mut option = vec![code, u8::try_from(body.len()).unwrap_or(0)];
    option.extend_from_slice(body);
    option
}

#[test]
fn dhcp_concatenated_fields_stay_before_the_last_end() {
    let sname = {
        let mut options = dhcp_option_bytes(12, b"sname-host");
        options.push(255);
        options
    };
    let file = {
        let mut options = dhcp_option_bytes(12, b"file-");
        options.push(255);
        options
    };
    let main = {
        let mut options = dhcp_option_bytes(53, &[2]);
        options.extend_from_slice(&dhcp_option_bytes(52, &[3]));
        options.extend_from_slice(&dhcp_option_bytes(12, b"main-"));
        options.push(255);
        options
    };
    let payload = bootp_test_payload(&sname, &file, &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(67, 68, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| {
        // The node must exist for this well-formed packet.
        unreachable!()
    });
    let mut collected: Vec<&packetfin_core::Field> = Vec::new();
    for field in &dhcp.fields {
        field.for_each_in_subtree(&mut |candidate| collected.push(candidate));
    }
    let hostname = collected
        .iter()
        .position(|field| field.def.abbrev == "dhcp.option.hostname")
        .unwrap_or(usize::MAX);
    let last_end = collected
        .iter()
        .rposition(|field| field.def.abbrev == "dhcp.option.end")
        .unwrap_or(0);
    assert!(hostname < last_end, "typed field moved after the last End");
}

#[test]
fn dhcp_repeated_untyped_option_adds_concatenated_value() {
    let main = {
        let mut options = dhcp_option_bytes(53, &[1]);
        options.extend_from_slice(&dhcp_option_bytes(224, b"abcd"));
        options.extend_from_slice(&dhcp_option_bytes(224, b"ef"));
        options.push(255);
        options
    };
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let mut collected: Vec<&packetfin_core::Field> = Vec::new();
    for field in &dhcp.fields {
        field.for_each_in_subtree(&mut |candidate| collected.push(candidate));
    }
    let values: Vec<&[u8]> = collected
        .iter()
        .filter(|field| field.def.abbrev == "dhcp.option.value")
        .filter_map(|field| match &field.value {
            Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(
        values,
        vec![
            &[1_u8][..],
            b"abcd".as_slice(),
            b"ef".as_slice(),
            b"abcdef".as_slice()
        ]
    );
    let concatenated = collected
        .iter()
        .position(|field| matches!(&field.value, Value::Bytes(bytes) if bytes == b"abcdef"))
        .unwrap_or(usize::MAX);
    let last_end = collected
        .iter()
        .rposition(|field| field.def.abbrev == "dhcp.option.end")
        .unwrap_or(0);
    assert!(concatenated < last_end);
}

/// Decode one DHCP message whose only option besides the type and End is the
/// agent information option with the given payload.
fn decode_agent_payload(agent: &[u8]) -> packetfin_core::Packet {
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&dhcp_option_bytes(82, agent));
    main.push(255);
    let payload = bootp_test_payload(&[], &[], &main);
    decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)))
}

fn agent_suboptions(agent: &[u8]) -> Vec<Field> {
    let packet = decode_agent_payload(agent);
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let option = option_container(dhcp, 82).unwrap_or_else(|| unreachable!());
    option
        .children
        .iter()
        .filter(|field| field.def.abbrev == "dhcp.option.agent_information_option.suboption")
        .cloned()
        .collect()
}

fn suboption_field<'a>(suboption: &'a Field, abbrev: &str) -> Option<&'a Field> {
    suboption
        .children
        .iter()
        .find(|field| field.def.abbrev == abbrev)
}

#[test]
fn dhcp_agent_typed_suboptions_match_the_registry_layout() {
    let mut agent = Vec::new();
    agent.extend_from_slice(&[3, 2, 0x01, 0x02]);
    agent.extend_from_slice(&[7, 1, 0x01]);
    agent.extend_from_slice(&[8, 1, 0x02]);
    agent.extend_from_slice(&[10, 1, 0x05]);
    agent.extend_from_slice(&[11, 4, 198, 51, 100, 10]);
    agent.extend_from_slice(&[12, 1, 0x03]);
    agent.extend_from_slice(&[13, 2, 0x0a, 0xa0]);
    let suboptions = agent_suboptions(&agent);
    assert_eq!(suboptions.len(), 7);

    let reserved = suboption_field(
        suboptions.first().unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.reserved",
    )
    .unwrap_or_else(|| unreachable!());
    assert!(matches!(&reserved.value, Value::Bytes(bytes) if bytes == &[0x01, 0x02]));

    let radius = suboption_field(
        suboptions.get(1).unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.radius_attributes",
    )
    .unwrap_or_else(|| unreachable!());
    assert!(matches!(&radius.value, Value::Bytes(bytes) if bytes == &[0x01]));

    let authentication = suboption_field(
        suboptions.get(2).unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.authentication",
    )
    .unwrap_or_else(|| unreachable!());
    assert!(matches!(&authentication.value, Value::Bytes(bytes) if bytes == &[0x02]));

    let flags = suboption_field(
        suboptions.get(3).unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.flags",
    )
    .unwrap_or_else(|| unreachable!());
    assert_eq!(flags.value, Value::Uint8(5));

    // The server identifier override labels the suboption with its address.
    assert_eq!(
        suboptions
            .get(4)
            .unwrap_or_else(|| unreachable!())
            .showname_text()
            .as_deref(),
        Some("Option 82 Suboption: (11) Server ID Override (198.51.100.10)")
    );
    let override_field = suboption_field(
        suboptions.get(4).unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.server_id_override",
    )
    .unwrap_or_else(|| unreachable!());
    assert_eq!(override_field.value, Value::Ipv4([198, 51, 100, 10]));

    let relay = suboption_field(
        suboptions.get(5).unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.relay_agent_id",
    )
    .unwrap_or_else(|| unreachable!());
    assert!(matches!(&relay.value, Value::Bytes(bytes) if bytes == &[0x03]));

    let access = suboption_field(
        suboptions.get(6).unwrap_or_else(|| unreachable!()),
        "dhcp.option.agent_information_option.ani_att",
    )
    .unwrap_or_else(|| unreachable!());
    assert_eq!(access.value, Value::Uint8(0xa0));
    assert_eq!(access.range.length, 1);

    // Every typed suboption replaces the generic value line.
    for suboption in &suboptions {
        let generic = suboption_field(suboption, "dhcp.option.agent_information_option.value")
            .unwrap_or_else(|| unreachable!());
        assert!(generic.hidden);
    }
}

#[test]
fn dhcp_agent_wrong_length_suboptions_report_a_protocol_expert() {
    let mut agent = Vec::new();
    agent.extend_from_slice(&[10, 2, 0x05, 0x06]);
    agent.extend_from_slice(&[11, 3, 0xc6, 0x33, 0x64]);
    let suboptions = agent_suboptions(&agent);
    assert_eq!(suboptions.len(), 2);
    for (suboption, expected) in suboptions.iter().zip(["length isn't 1", "length isn't 4"]) {
        assert!(suboption.children.iter().all(|field| field.def.abbrev
            != "dhcp.option.agent_information_option.value"
            || field.hidden));
        let marker = suboption
            .children
            .iter()
            .find(|field| field.def.abbrev == "dhcp.bad_length")
            .unwrap_or_else(|| unreachable!());
        let expert = marker.experts.first().unwrap_or_else(|| unreachable!());
        assert_eq!(expert.group, Group::Protocol);
        assert_eq!(expert.message, expected);
    }
    // A wrong length on these suboptions is not a packet-level failure.
    let packet = decode_agent_payload(&[10, 2, 0x05, 0x06]);
    assert!(!packet.malformed);
}

#[test]
fn dhcp_agent_access_technology_reads_the_att_octet() {
    // RFC 7839 §4.2: a Reserved octet the receiver ignores, then the ATT.
    let packet = decode_agent_payload(&[13, 2, 0xff, 0x06]);
    assert!(!packet.malformed);
    let suboptions = agent_suboptions(&[13, 2, 0xff, 0x06]);
    let suboption = suboptions.first().unwrap_or_else(|| unreachable!());
    let access = suboption_field(suboption, "dhcp.option.agent_information_option.ani_att")
        .unwrap_or_else(|| unreachable!());
    assert_eq!(access.value, Value::Uint8(6));
    assert_eq!(access.range.length, 1);
}

#[test]
fn dhcp_agent_access_technology_rejects_other_lengths() {
    for value in [
        &[][..],
        &[0x01][..],
        &[0x01, 0x02, 0x03][..],
        &[0x01, 0x02, 0x03, 0x04, 0x05][..],
    ] {
        let mut agent = vec![13, u8::try_from(value.len()).unwrap_or(u8::MAX)];
        agent.extend_from_slice(value);
        let suboptions = agent_suboptions(&agent);
        let suboption = suboptions.first().unwrap_or_else(|| unreachable!());
        assert!(
            suboption
                .children
                .iter()
                .all(|field| field.def.abbrev != "dhcp.option.agent_information_option.ani_att"),
            "length {} decoded an ATT: {suboption:?}",
            value.len()
        );
        let marker =
            suboption_field(suboption, "dhcp.bad_length").unwrap_or_else(|| unreachable!());
        let expert = marker.experts.first().unwrap_or_else(|| unreachable!());
        assert_eq!(expert.severity, Severity::Error);
        assert_eq!(expert.group, Group::Protocol);
        assert_eq!(expert.message, "length isn't 2");
        // An absent value stops the decoder; a present but wrong-sized
        // value leaves the remaining options decodable.
        assert_eq!(decode_agent_payload(&agent).malformed, value.is_empty());
    }
}

#[test]
fn dhcp_agent_vendor_blocks_nest_the_data_length_under_the_enterprise() {
    let mut agent = Vec::new();
    // Two blocks: one with data, one with an empty value.
    agent.extend_from_slice(&[9, 12]);
    agent.extend_from_slice(&32473_u32.to_be_bytes());
    agent.extend_from_slice(&[2, 0xaa, 0xbb]);
    agent.extend_from_slice(&32473_u32.to_be_bytes());
    agent.extend_from_slice(&[0]);
    let suboptions = agent_suboptions(&agent);
    assert_eq!(suboptions.len(), 1);
    let suboption = suboptions.first().unwrap_or_else(|| unreachable!());
    let enterprises: Vec<&Field> = suboption
        .children
        .iter()
        .filter(|field| field.def.abbrev == "dhcp.option.agent_information_option.vi.enterprise")
        .collect();
    assert_eq!(enterprises.len(), 2);
    assert_eq!(
        enterprises.first().unwrap_or_else(|| unreachable!()).value,
        Value::Uint32(32473)
    );
    let length = enterprises
        .first()
        .unwrap_or_else(|| unreachable!())
        .children
        .first()
        .unwrap_or_else(|| unreachable!());
    assert_eq!(
        length.def.abbrev,
        "dhcp.option.agent_information_option.vi.data_length"
    );
    assert_eq!(length.value, Value::Uint8(2));
    assert_eq!(
        enterprises
            .get(1)
            .unwrap_or_else(|| unreachable!())
            .children
            .first()
            .map(|field| field.value.clone()),
        Some(Value::Uint8(0))
    );
    // Each block's data is a visible sibling of its enterprise number.
    let values: Vec<&Field> = suboption
        .children
        .iter()
        .filter(|field| {
            field.def.abbrev == "dhcp.option.agent_information_option.value" && !field.hidden
        })
        .collect();
    assert_eq!(values.len(), 2);
    assert!(
        matches!(&values.first().unwrap_or_else(|| unreachable!()).value, Value::Bytes(bytes) if bytes == &[0xaa, 0xbb])
    );
    assert_eq!(
        values.get(1).unwrap_or_else(|| unreachable!()).value,
        Value::Missing
    );
    assert_eq!(
        packetfin_core::decode::enterprise_name(32473),
        Some("Example Enterprise Number for Documentation Use")
    );
}

#[test]
fn dhcp_zero_length_typed_option_keeps_the_generic_value_line() {
    let mut main = dhcp_option_bytes(53, &[1]);
    main.extend_from_slice(&dhcp_option_bytes(12, b""));
    main.push(255);
    let payload = bootp_test_payload(&[], &[], &main);
    let packet = decode_frame(&captured_frame(1, services_udp_frame(68, 67, &payload)));
    let dhcp = child_node(&packet.tree.frame, "dhcp").unwrap_or_else(|| unreachable!());
    let host = option_container(dhcp, 12).unwrap_or_else(|| unreachable!());
    let value = host
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.value")
        .unwrap_or_else(|| unreachable!());
    assert!(!value.hidden);
    assert_eq!(value.value, Value::Missing);
    let hostname = host
        .children
        .iter()
        .find(|field| field.def.abbrev == "dhcp.option.hostname")
        .unwrap_or_else(|| unreachable!());
    assert!(matches!(&hostname.value, Value::String(text) if text.is_empty()));
}

#[test]
fn dhcpv6_status_message_stops_at_the_nul_and_reports_trailing_octets() {
    let mut message = vec![7, 0x01, 0x02, 0x03];
    message.extend_from_slice(&dhcpv6_option(13, &[0x00, 0x00, b'h', b'i', 0x00, b'x']));
    let packet = decode_frame(&captured_frame(1, services_udp_frame(547, 546, &message)));
    let dhcpv6 = child_node(&packet.tree.frame, "dhcpv6").unwrap_or_else(|| unreachable!());
    let option = dhcpv6
        .fields
        .iter()
        .find(|field| field.def.abbrev == "dhcpv6.option.type_str")
        .unwrap_or_else(|| unreachable!());
    let status = suboption_field(option, "dhcpv6.status_msg").unwrap_or_else(|| unreachable!());
    assert!(matches!(&status.value, Value::String(text) if text == "hi"));
    let expert = status.experts.first().unwrap_or_else(|| unreachable!());
    assert_eq!(expert.severity, Severity::Warning);
    assert_eq!(expert.group, Group::Undecoded);
    assert_eq!(expert.message, "Trailing stray characters");
    assert_eq!(
        status
            .expert_field
            .map(|definition| definition.abbrev)
            .unwrap_or(""),
        "_ws.string.trailing_stray_characters"
    );
    // The option is still whole: the trailing octet is a display concern.
    assert!(!packet.malformed);
}

#[test]
fn dhcpv6_status_message_keeps_an_empty_terminated_value() {
    let mut message = vec![7, 0x01, 0x02, 0x03];
    message.extend_from_slice(&dhcpv6_option(13, &[0x00, 0x00, 0x00]));
    let packet = decode_frame(&captured_frame(1, services_udp_frame(547, 546, &message)));
    let dhcpv6 = child_node(&packet.tree.frame, "dhcpv6").unwrap_or_else(|| unreachable!());
    let option = dhcpv6
        .fields
        .iter()
        .find(|field| field.def.abbrev == "dhcpv6.option.type_str")
        .unwrap_or_else(|| unreachable!());
    let status = suboption_field(option, "dhcpv6.status_msg").unwrap_or_else(|| unreachable!());
    assert!(matches!(&status.value, Value::String(text) if text.is_empty()));
    // A terminator in the last octet leaves nothing stray to report.
    assert!(status.experts.is_empty());
}

#[test]
fn dhcpv6_truncated_status_code_stays_malformed() {
    // RFC 8415 §21.13 defines a 16-bit status code; one octet cannot supply it
    // and reading the next option would cross the declared option bound.
    let mut message = vec![7, 0x01, 0x02, 0x03];
    message.extend_from_slice(&dhcpv6_option(13, &[0x00]));
    message.extend_from_slice(&dhcpv6_option(9, &[0x00, 0x01]));
    let packet = decode_frame(&captured_frame(1, services_udp_frame(547, 546, &message)));
    assert!(packet.malformed);
    let dhcpv6 = child_node(&packet.tree.frame, "dhcpv6").unwrap_or_else(|| unreachable!());
    assert!(dhcpv6.protocol_exception);
    let option = dhcpv6
        .fields
        .iter()
        .find(|field| field.def.abbrev == "dhcpv6.option.type_str")
        .unwrap_or_else(|| unreachable!());
    assert!(
        option
            .children
            .iter()
            .all(|field| field.def.abbrev != "dhcpv6.status_code")
    );
}

#[test]
fn dhcp_relay_suboption_names_follow_the_registry() {
    // RFC 6607 §3.2 and §3.3 assign 151 to VSS and 152 to VSS-Control.
    assert_eq!(
        packetfin_core::decode::dhcp_agent_suboption_name(151),
        "VSS"
    );
    assert_eq!(
        packetfin_core::decode::dhcp_agent_suboption_name(152),
        "VSS-Control"
    );
}
