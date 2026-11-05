//! Cross-packet state through the public decode session.
//!
//! The expected stream numbers come from the committed `tcp-streams` and
//! `udp-streams` fixtures and their expected output.

use std::fs;

use packetfin_core::capture::{CaptureReader, Frame};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::{DecodeSession, Group, Node, Value};
use packetfin_testkit::fixtures;
use packetfin_testkit::golden;

fn frames(name: &str) -> Result<Vec<Frame>, String> {
    let fixture = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| format!("fixture {name} is not registered"))?;
    let path = golden::fixtures_dir().join(fixture.file_name());
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut reader = CaptureReader::new(std::io::Cursor::new(bytes))
        .map_err(|error| format!("CaptureReader::new failed: {error}"))?;
    let mut frames = Vec::new();
    while let Some(frame) = reader
        .next_frame()
        .map_err(|error| format!("next_frame failed: {error}"))?
    {
        frames.push(frame);
    }
    Ok(frames)
}

fn find_node<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    if node.protocol.filter_name == name {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_node(child, name))
}

fn u32_values(packet: &packetfin_core::Packet, abbrev: &str) -> Vec<u32> {
    packet
        .tree
        .field_values(abbrev)
        .into_iter()
        .filter_map(|value| match value {
            Value::Uint32(number) => Some(*number),
            _ => None,
        })
        .collect()
}

fn assert_no_stream_fields(packet: &packetfin_core::Packet) {
    assert!(u32_values(packet, "tcp.stream").is_empty());
    assert!(u32_values(packet, "tcp.stream.pnum").is_empty());
    assert!(u32_values(packet, "udp.stream").is_empty());
    assert!(u32_values(packet, "udp.stream.pnum").is_empty());
}

#[test]
fn tcp_stream_fixture_numbers_conversations() -> Result<(), String> {
    let frames = frames("tcp-streams")?;
    let expected_streams: [Option<u32>; 17] = [
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        Some(1),
        Some(0),
        Some(2),
        Some(1),
        Some(2),
        Some(2),
        Some(3),
        Some(3),
        Some(4),
        Some(4),
        Some(2),
        None,
    ];
    let expected_packets: [Option<u32>; 17] = [
        Some(1),
        Some(2),
        Some(3),
        Some(4),
        Some(5),
        Some(1),
        Some(6),
        Some(1),
        Some(2),
        Some(2),
        Some(3),
        Some(1),
        Some(2),
        Some(1),
        Some(2),
        Some(4),
        None,
    ];
    let mut session = DecodeSession::new(DecodeOptions::default());
    for (index, frame) in frames.iter().enumerate() {
        let packet = session.decode(frame);
        assert_eq!(
            u32_values(&packet, "tcp.stream").first().copied(),
            expected_streams.get(index).copied().flatten(),
            "frame {} stream",
            index + 1
        );
        assert_eq!(
            u32_values(&packet, "tcp.stream.pnum").first().copied(),
            expected_packets.get(index).copied().flatten(),
            "frame {} packet number",
            index + 1
        );
        assert!(session.budget_used() <= packetfin_core::DEFAULT_STATE_BUDGET);
    }
    assert!(session.budget_used() > 0);
    Ok(())
}

#[test]
fn udp_stream_fixture_numbers_conversations() -> Result<(), String> {
    let frames = frames("udp-streams")?;
    let expected_streams: [Option<u32>; 10] = [
        Some(0),
        Some(0),
        Some(1),
        Some(0),
        Some(2),
        Some(3),
        Some(0),
        Some(4),
        Some(4),
        None,
    ];
    let expected_packets: [Option<u32>; 10] = [
        Some(1),
        Some(2),
        Some(1),
        Some(3),
        Some(1),
        Some(1),
        Some(4),
        Some(1),
        Some(2),
        None,
    ];
    let mut session = DecodeSession::new(DecodeOptions::default());
    for (index, frame) in frames.iter().enumerate() {
        let packet = session.decode(frame);
        assert_eq!(
            u32_values(&packet, "udp.stream").first().copied(),
            expected_streams.get(index).copied().flatten(),
            "frame {} stream",
            index + 1
        );
        assert_eq!(
            u32_values(&packet, "udp.stream.pnum").first().copied(),
            expected_packets.get(index).copied().flatten(),
            "frame {} packet number",
            index + 1
        );
    }
    assert!(session.budget_used() > 0);
    Ok(())
}

#[test]
fn quoted_transports_consume_stream_numbers() -> Result<(), String> {
    let quoted_tcp = frames("icmp-error-tcp")?
        .into_iter()
        .next()
        .ok_or_else(|| "icmp-error-tcp is empty".to_string())?;
    let real_tcp = frames("tcp-streams")?
        .into_iter()
        .next()
        .ok_or_else(|| "tcp-streams is empty".to_string())?;
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packet = session.decode(&quoted_tcp);
    assert_eq!(u32_values(&packet, "tcp.stream"), vec![0]);
    assert_eq!(u32_values(&packet, "tcp.stream.pnum"), vec![1]);
    assert!(session.budget_used() > 0, "the quote must retain a stream");
    let packet = session.decode(&real_tcp);
    assert_eq!(u32_values(&packet, "tcp.stream"), vec![1]);
    assert_eq!(u32_values(&packet, "tcp.stream.pnum"), vec![1]);

    let quoted_udp = frames("icmp-error-udp")?
        .into_iter()
        .next()
        .ok_or_else(|| "icmp-error-udp is empty".to_string())?;
    let real_udp = frames("udp-streams")?
        .into_iter()
        .next()
        .ok_or_else(|| "udp-streams is empty".to_string())?;
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packet = session.decode(&quoted_udp);
    assert_eq!(u32_values(&packet, "udp.stream"), vec![0]);
    assert!(
        u32_values(&packet, "udp.stream.pnum").is_empty(),
        "a quoted UDP header is not a stream packet"
    );
    let packet = session.decode(&real_udp);
    assert_eq!(u32_values(&packet, "udp.stream"), vec![1]);
    assert_eq!(u32_values(&packet, "udp.stream.pnum"), vec![1]);
    Ok(())
}

#[test]
fn fragmented_transports_do_not_create_conversations() -> Result<(), String> {
    let frames = frames("ipv4-fragmented")?;
    let mut session = DecodeSession::new(DecodeOptions::default());
    for frame in frames.iter().take(3) {
        let packet = session.decode(frame);
        assert_no_stream_fields(&packet);
    }
    assert!(
        session.budget_used() > 0,
        "the incomplete tail fragment is retained"
    );
    // The fixture ends with an unfragmented datagram, which is ordinary
    // traffic and does get a conversation.
    let frame = frames
        .get(3)
        .ok_or_else(|| "fragment fixture lost its fourth frame".to_string())?;
    let packet = session.decode(frame);
    assert_eq!(u32_values(&packet, "udp.stream"), vec![0]);
    Ok(())
}

#[test]
fn a_zero_budget_starts_a_stream_for_every_packet() -> Result<(), String> {
    let frames = frames("tcp-streams")?;
    let mut session = DecodeSession::with_budget(DecodeOptions::default(), 0);
    let mut tcp_packets = 0_u32;
    let mut udp_packets = 0_u32;
    for frame in &frames {
        let packet = session.decode(frame);
        if let Some(stream) = u32_values(&packet, "tcp.stream").first() {
            assert_eq!(*stream, tcp_packets);
            assert_eq!(u32_values(&packet, "tcp.stream.pnum"), vec![1]);
            tcp_packets = tcp_packets.saturating_add(1);
        }
        if let Some(stream) = u32_values(&packet, "udp.stream").first() {
            assert_eq!(*stream, udp_packets);
            assert_eq!(u32_values(&packet, "udp.stream.pnum"), vec![1]);
            udp_packets = udp_packets.saturating_add(1);
        }
        assert!(packet.tree.frame.experts.is_empty());
        assert_eq!(session.budget_used(), 0);
    }
    Ok(())
}

#[test]
fn an_unfittable_conversation_reports_a_frame_expert() -> Result<(), String> {
    let frames = frames("tcp-streams")?;
    let mut session = DecodeSession::with_budget(DecodeOptions::default(), 1);
    for frame in frames.iter().take(2) {
        let packet = session.decode(frame);
        assert_eq!(session.budget_used(), 0);
        assert!(
            packet
                .tree
                .frame
                .experts
                .iter()
                .any(
                    |expert| expert.severity == packetfin_core::Severity::Warning
                        && expert.group == Group::Sequence
                ),
            "frame {} has no state-loss expert",
            frame.number
        );
    }
    Ok(())
}

#[test]
fn udp_stream_fields_follow_the_checksum_with_zero_length_ranges() -> Result<(), String> {
    let frame = frames("udp-streams")?
        .into_iter()
        .next()
        .ok_or_else(|| "udp-streams is empty".to_string())?;
    let mut session = DecodeSession::new(DecodeOptions::default());
    let packet = session.decode(&frame);
    let udp =
        find_node(&packet.tree.frame, "udp").ok_or_else(|| "frame has no UDP node".to_string())?;
    let names: Vec<&str> = udp.fields.iter().map(|field| field.def.abbrev).collect();
    let position = |name: &str| names.iter().position(|candidate| *candidate == name);
    let length = position("udp.length").ok_or_else(|| "missing udp.length".to_string())?;
    let checksum = position("udp.checksum").ok_or_else(|| "missing udp.checksum".to_string())?;
    let status =
        position("udp.checksum.status").ok_or_else(|| "missing udp.checksum.status".to_string())?;
    let stream = position("udp.stream").ok_or_else(|| "missing udp.stream".to_string())?;
    let packet_number =
        position("udp.stream.pnum").ok_or_else(|| "missing udp.stream.pnum".to_string())?;
    assert!(
        length < checksum && checksum < status && status < stream && stream < packet_number,
        "UDP field order: {names:?}"
    );

    let stream_field = udp
        .fields
        .get(stream)
        .ok_or_else(|| "missing stream field".to_string())?;
    let number_field = udp
        .fields
        .get(packet_number)
        .ok_or_else(|| "missing packet-number field".to_string())?;
    assert_eq!(
        stream_field.range.offset,
        udp.range.offset.saturating_add(8)
    );
    assert_eq!(stream_field.range.length, 0);
    assert_eq!(number_field.range.offset, udp.range.offset);
    assert_eq!(number_field.range.length, 0);
    Ok(())
}
