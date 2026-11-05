//! IPv4 and IPv6 fragment reassembly through a decode session.
//!
//! Fragments are buffered between frames; the transport decoder runs on the
//! frame that completes the datagram and only then. These tests pin the
//! completion rule, the measured overlap/conflict/error taxonomy, the
//! per-datagram bounds and the state budget.

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{DecodeOptions, Packet};
use packetfin_core::state::{DEFAULT_STATE_BUDGET, DecodeSession};
use packetfin_core::tree::{Group, Value};

const SOURCE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DESTINATION_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SOURCE_ADDRESS: [u8; 4] = [10, 0, 0, 1];
const DESTINATION_ADDRESS: [u8; 4] = [10, 0, 0, 2];
const SOURCE_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const DESTINATION_IPV6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn frame(number: u64, captured: Vec<u8>) -> Frame {
    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: u32::try_from(number).unwrap_or(0) * 1_000,
        }),
        timestamp_precision: 6,
        original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
        captured,
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        interface_name: None,
        timestamp_units: None,
        source_offset: 0,
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

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (pairs, rest) = bytes.as_chunks::<2>();
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

fn ipv4(identification: u16, flags_offset: u16, payload: &[u8]) -> Vec<u8> {
    ipv4_protocol(17, identification, flags_offset, payload)
}

fn ipv4_protocol(protocol: u8, identification: u16, flags_offset: u16, payload: &[u8]) -> Vec<u8> {
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap_or(0).to_be_bytes());
    header.extend_from_slice(&identification.to_be_bytes());
    header.extend_from_slice(&flags_offset.to_be_bytes());
    header.extend_from_slice(&[64, protocol, 0, 0]);
    header.extend_from_slice(&SOURCE_ADDRESS);
    header.extend_from_slice(&DESTINATION_ADDRESS);
    let value = checksum(&header);
    if let Some(slot) = header.get_mut(10..12) {
        slot.copy_from_slice(&value.to_be_bytes());
    }
    header.extend_from_slice(payload);
    header
}

fn udp(payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&1_u16.to_be_bytes());
    segment.extend_from_slice(&515_u16.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(0).to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    segment
}

fn ipv6_fragment(identification: u32, offset_units: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    let word = (offset_units << 3) | u16::from(more);
    let mut fragment = vec![17, 0];
    fragment.extend_from_slice(&word.to_be_bytes());
    fragment.extend_from_slice(&identification.to_be_bytes());
    fragment.extend_from_slice(payload);
    let mut datagram = Vec::new();
    let word = 6_u32 << 28;
    datagram.extend_from_slice(&word.to_be_bytes());
    datagram.extend_from_slice(
        &u16::try_from(fragment.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    datagram.push(44);
    datagram.push(64);
    datagram.extend_from_slice(&SOURCE_IPV6);
    datagram.extend_from_slice(&DESTINATION_IPV6);
    datagram.extend_from_slice(&fragment);
    datagram
}

fn decode(session: &mut DecodeSession, frames: &[Vec<u8>]) -> Vec<Packet> {
    frames
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let number = u64::try_from(index).unwrap_or(0) + 1;
            session.decode(&frame(number, bytes.clone()))
        })
        .collect()
}

fn head(data: &[u8]) -> &[u8] {
    data.get(..80).unwrap_or(&[])
}

fn from(data: &[u8], start: usize) -> &[u8] {
    data.get(start..).unwrap_or(&[])
}

fn part(data: &[u8], start: usize, end: usize) -> &[u8] {
    data.get(start..end).unwrap_or(&[])
}

fn conflicting(first: &[u8]) -> Vec<u8> {
    let mut conflict = from(first, 72).to_vec();
    if let Some(prefix) = conflict.get_mut(..8) {
        prefix.fill(0xee);
    }
    conflict
}

fn fragment_container<'a>(packet: &'a Packet, abbrev: &str) -> Option<&'a packetfin_core::Field> {
    packet
        .tree
        .fields()
        .find(|field| field.def.abbrev == abbrev && field.is_container())
}

fn field_u32(field: &packetfin_core::Field) -> u32 {
    match field.value {
        Value::Uint32(value) => value,
        _ => u32::MAX,
    }
}

fn child<'a>(field: &'a packetfin_core::Field, abbrev: &str) -> Option<&'a packetfin_core::Field> {
    field
        .children
        .iter()
        .find(|child| child.def.abbrev == abbrev)
}

fn fragment_frames(container: &packetfin_core::Field) -> Vec<u32> {
    container
        .children
        .iter()
        .filter(|child| child.def.abbrev == "ip.fragment")
        .map(field_u32)
        .collect()
}

fn error_frames(container: &packetfin_core::Field) -> Vec<u32> {
    container
        .children
        .iter()
        .filter(|child| child.def.abbrev == "ip.fragment.error")
        .map(field_u32)
        .collect()
}

fn protocol<'a>(packet: &'a Packet, name: &str) -> Option<&'a packetfin_core::Node> {
    fn walk<'a>(node: &'a packetfin_core::Node, name: &str) -> Option<&'a packetfin_core::Node> {
        if node.protocol.filter_name == name {
            return Some(node);
        }
        node.children.iter().find_map(|child| walk(child, name))
    }
    walk(&packet.tree.frame, name)
}

fn container_value(container: &packetfin_core::Field) -> Option<&[u8]> {
    match &container.value {
        Value::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

#[test]
fn ipv4_ordered_fragments_decode_only_on_the_completing_frame() {
    let segment = udp(&(0_u8..92).collect::<Vec<_>>());
    let mut session = DecodeSession::new(DecodeOptions::default());
    let first_packet = session.decode(&frame(
        1,
        ethernet(0x0800, &ipv4(0x1234, 0x2000, head(&segment))),
    ));
    assert!(
        fragment_container(&first_packet, "ip.fragments").is_none(),
        "an incomplete datagram has no container"
    );
    assert!(
        protocol(&first_packet, "udp").is_none(),
        "transport decodes only on the completing frame"
    );
    assert!(session.budget_used() > 0, "the part is retained");
    let second_packet = session.decode(&frame(
        2,
        ethernet(0x0800, &ipv4(0x1234, 10, from(&segment, 80))),
    ));

    let container = fragment_container(&second_packet, "ip.fragments");
    assert!(container.is_some(), "the second fragment completes");
    let Some(container) = container else {
        return;
    };
    assert_eq!(container_value(container), Some(segment.as_slice()));
    assert_eq!(fragment_frames(container), vec![1, 2]);
    assert_eq!(
        child(container, "ip.fragment.count").map(field_u32),
        Some(2)
    );
    assert_eq!(
        child(container, "ip.reassembled.length").map(field_u32),
        Some(100)
    );
    let data = child(container, "ip.reassembled.data");
    assert_eq!(
        data.map(|field| field.value.clone()),
        Some(Value::bytes(segment))
    );

    let udp_node = protocol(&second_packet, "udp");
    assert!(udp_node.is_some(), "transport decoded on completion");
    assert_eq!(udp_node.map(|node| node.range.offset), Some(0));
    assert!(
        session.budget_used() > 0,
        "the completed transport creates conversation state"
    );
}

#[test]
fn ipv4_out_of_order_fragments_complete_on_the_first_fragment() {
    let segment = udp(&[0x11; 92]);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x0800, &ipv4(0x2222, 10, from(&segment, 80))),
            ethernet(0x0800, &ipv4(0x2222, 0x2000, head(&segment))),
        ],
    );
    let Some(packet) = packets.get(1) else {
        return;
    };
    let container = fragment_container(packet, "ip.fragments");
    assert_eq!(container.map(fragment_frames), Some(vec![2, 1]));
}

#[test]
fn ipv4_overlap_keeps_first_bytes_and_marks_the_error_fragment() {
    let first = udp(&(0_u8..156).collect::<Vec<_>>());
    let conflict = conflicting(&first);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x0800, &ipv4(0x3333, 0x2000, head(&first))),
            ethernet(0x0800, &ipv4(0x3333, 72 / 8, &conflict)),
        ],
    );
    let Some(packet) = packets.get(1) else {
        return;
    };
    let container = fragment_container(packet, "ip.fragments");
    assert!(container.is_some(), "the conflicting overlap completes");
    let Some(container) = container else {
        return;
    };
    assert_eq!(fragment_frames(container), vec![1]);
    assert_eq!(error_frames(container), vec![2]);
    let error = container
        .children
        .iter()
        .find(|child| child.def.abbrev == "ip.fragment.error");
    assert!(error.is_some(), "the overlapping fragment is an error");
    if let Some(error) = error {
        assert!(child(error, "ip.fragment.overlap").is_some());
        assert!(child(error, "ip.fragment.overlap.conflict").is_some());
    }
    let bytes = container_value(container);
    assert_eq!(bytes.map(head), Some(head(&first)));
    assert_eq!(
        bytes.map(|bytes| from(bytes, 80)),
        Some(part(&conflict, 8, conflict.len()))
    );
}

#[test]
fn a_duplicate_first_fragment_is_reported_as_an_error_not_a_fragment() {
    let segment = udp(&[0x22; 92]);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x0800, &ipv4(0x4444, 0x2000, head(&segment))),
            ethernet(0x0800, &ipv4(0x4444, 0x2000, &[0xee; 40])),
            ethernet(0x0800, &ipv4(0x4444, 10, from(&segment, 80))),
        ],
    );
    let Some(packet) = packets.get(2) else {
        return;
    };
    let container = fragment_container(packet, "ip.fragments");
    assert!(container.is_some(), "the last fragment completes");
    let Some(container) = container else {
        return;
    };
    assert_eq!(
        child(container, "ip.fragment.count").map(field_u32),
        Some(3)
    );
    assert_eq!(fragment_frames(container), vec![1, 3]);
    assert_eq!(error_frames(container), vec![2]);
}

#[test]
fn a_gap_keeps_buffering_until_a_filling_fragment_arrives() {
    let segment = udp(&[0x33; 108]);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x0800, &ipv4(0x5555, 0x2000, head(&segment))),
            ethernet(0x0800, &ipv4(0x5555, 12, from(&segment, 96))),
            ethernet(0x0800, &ipv4(0x5555, 0x2000 | 10, part(&segment, 80, 96))),
        ],
    );
    assert!(
        packets
            .get(1)
            .is_some_and(|packet| fragment_container(packet, "ip.fragments").is_none()),
        "the gap keeps the datagram buffered"
    );
    assert!(
        packets
            .get(1)
            .is_some_and(|packet| protocol(packet, "udp").is_none()),
        "no transport decode while a gap remains"
    );
    let container = packets
        .get(2)
        .and_then(|packet| fragment_container(packet, "ip.fragments"));
    assert_eq!(container.map(fragment_frames), Some(vec![1, 3, 2]));
}

#[test]
fn a_non_multiple_of_eight_non_final_fragment_never_completes() {
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x0800, &ipv4(0x6666, 0x2000, &[0x44; 79])),
            ethernet(0x0800, &ipv4(0x6666, 10, &[0x45; 20])),
        ],
    );
    let packet = packets.get(1);
    assert!(
        packet.is_some_and(|packet| fragment_container(packet, "ip.fragments").is_none()),
        "an invalid non-final fragment never completes"
    );
    assert!(
        packet.is_some_and(|packet| protocol(packet, "udp").is_none()),
        "no transport decode for an incomplete datagram"
    );
    let ip = packets.first().and_then(|packet| protocol(packet, "ip"));
    assert!(
        ip.is_some_and(|ip| ip
            .experts
            .iter()
            .any(|expert| expert.group == Group::Sequence)),
        "the rejected fragment keeps an explicit marker"
    );
}

#[test]
fn ipv6_fragments_reassemble_and_atomic_fragments_decode_directly() {
    let segment = udp(&[0x55; 92]);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x86dd, &ipv6_fragment(1, 0, true, head(&segment))),
            ethernet(0x86dd, &ipv6_fragment(1, 10, false, from(&segment, 80))),
            ethernet(0x86dd, &ipv6_fragment(2, 0, false, &udp(&[0x66; 5]))),
        ],
    );
    let container = packets
        .get(1)
        .and_then(|packet| fragment_container(packet, "ipv6.fragments"));
    assert!(container.is_some(), "the IPv6 datagram completes");
    let Some(container) = container else {
        return;
    };
    assert_eq!(
        child(container, "ipv6.fragment.count").map(field_u32),
        Some(2)
    );
    assert_eq!(
        child(container, "ipv6.reassembled.length").map(field_u32),
        Some(100)
    );
    assert!(
        packets
            .get(1)
            .is_some_and(|packet| protocol(packet, "udp").is_some()),
        "the reassembled transport decodes"
    );
    assert_eq!(
        packets
            .get(1)
            .and_then(|packet| protocol(packet, "udp"))
            .map(|node| node.range.offset),
        Some(0)
    );
    assert!(
        packets
            .get(2)
            .is_some_and(|packet| fragment_container(packet, "ipv6.fragments").is_none()),
        "an atomic fragment has no fragment container"
    );
    assert!(
        packets
            .get(2)
            .is_some_and(|packet| protocol(packet, "udp").is_some()),
        "an atomic fragment decodes its next header directly"
    );
}

#[test]
fn ipv6_overlap_marks_an_error_fragment() {
    let first = udp(&(0_u8..156).collect::<Vec<_>>());
    let conflict = conflicting(&first);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x86dd, &ipv6_fragment(3, 0, true, head(&first))),
            ethernet(0x86dd, &ipv6_fragment(3, 9, false, &conflict)),
        ],
    );
    let container = packets
        .get(1)
        .and_then(|packet| fragment_container(packet, "ipv6.fragments"));
    assert!(container.is_some(), "the IPv6 overlap completes");
    let Some(container) = container else {
        return;
    };
    let errors: Vec<u32> = container
        .children
        .iter()
        .filter(|child| child.def.abbrev == "ipv6.fragment.error")
        .map(field_u32)
        .collect();
    assert_eq!(errors, vec![2]);
    assert_eq!(
        child(container, "ipv6.reassembled.length").map(field_u32),
        Some(164)
    );
}

#[test]
fn a_fragment_flood_cannot_exceed_the_state_budget() {
    let budget = 4096;
    let mut session = DecodeSession::with_budget(DecodeOptions::default(), budget);
    let segment = udp(&[0x77; 92]);
    for identifier in 0_u16..2000 {
        let packet = session.decode(&frame(
            u64::from(identifier) + 1,
            ethernet(0x0800, &ipv4(identifier, 0x2000, head(&segment))),
        ));
        assert!(session.budget_used() <= budget);
        assert!(fragment_container(&packet, "ip.fragments").is_none());
    }
}

#[test]
fn too_many_fragments_drop_the_datagram_with_an_expert() {
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut last = None;
    for index in 0_u16..129 {
        let packet = session.decode(&frame(
            u64::from(index) + 1,
            ethernet(0x0800, &ipv4(0x7777, 0x2000 | (index * 8), &[0x88; 8])),
        ));
        assert!(fragment_container(&packet, "ip.fragments").is_none());
        last = Some(packet);
    }
    let ip = last.as_ref().and_then(|packet| protocol(packet, "ip"));
    assert!(
        ip.is_some_and(|ip| ip
            .experts
            .iter()
            .any(|expert| expert.message.contains("fragment reassembly limit reached"))),
        "the over-limit frame is reported"
    );
    assert!(session.budget_used() < DEFAULT_STATE_BUDGET);
}

#[test]
fn fragmented_tcp_decodes_only_on_completion() {
    let mut segment = vec![0x04, 0xd2, 0x00, 0x50];
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.push(5 << 4);
    segment.push(0x10);
    segment.extend_from_slice(&8192_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(&[0x5a; 60]);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let first = session.decode(&frame(
        1,
        ethernet(0x0800, &ipv4_protocol(6, 0x9999, 0x2000, head(&segment))),
    ));
    assert!(
        protocol(&first, "tcp").is_none(),
        "a fragmented TCP header waits for reassembly"
    );
    let second = session.decode(&frame(
        2,
        ethernet(0x0800, &ipv4_protocol(6, 0x9999, 10, from(&segment, 80))),
    ));
    assert!(
        protocol(&second, "tcp").is_some(),
        "the completing frame decodes TCP"
    );
}

#[test]
fn one_pass_never_emits_reassembled_in() {
    let segment = udp(&[0x99; 92]);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packets = decode(
        &mut session,
        &[
            ethernet(0x0800, &ipv4(0x8888, 0x2000, head(&segment))),
            ethernet(0x0800, &ipv4(0x8888, 10, from(&segment, 80))),
        ],
    );
    for packet in &packets {
        assert!(
            !packet
                .tree
                .fields()
                .any(|field| field.def.abbrev == "ip.reassembled_in"),
            "the two-pass annotation is absent in one pass"
        );
    }
    assert!(
        packets
            .get(1)
            .is_some_and(|packet| packet.tree.frame.experts.is_empty()),
        "a successful reassembly reports no sequence expert"
    );
}
