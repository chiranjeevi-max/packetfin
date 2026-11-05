//! Integration tests for the first-party pcap and pcapng reader.
//!
//! The expected values are written out in each test and checked against the
//! committed fixtures; no test runs an external program.

use std::fs;
use std::io::{self, Read};

use packetfin_core::capture::{CaptureError, CaptureReader, Frame, MAX_FRAME_SIZE, Timestamp};
use packetfin_testkit::fixtures;
use packetfin_testkit::golden;
use packetfin_testkit::pcap;
use packetfin_testkit::pcapng;
use packetfin_testkit::{ByteOrder, Timestamp as BuilderTimestamp, TimestampResolution};

fn committed(name: &str) -> Result<Vec<u8>, String> {
    let fixture = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| format!("fixture {name} is not registered"))?;
    let path = golden::fixtures_dir().join(fixture.file_name());
    fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn read_frames(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    let mut reader =
        CaptureReader::new(bytes).map_err(|error| format!("CaptureReader::new failed: {error}"))?;
    drain(&mut reader)
}

fn drain<R: Read>(reader: &mut CaptureReader<R>) -> Result<Vec<Frame>, String> {
    let mut frames = Vec::new();
    loop {
        match reader.next_frame() {
            Ok(Some(frame)) => frames.push(frame),
            Ok(None) => return Ok(frames),
            Err(error) => return Err(format!("next_frame failed: {error}")),
        }
    }
}

fn single_frame(bytes: &[u8]) -> Result<Frame, String> {
    let mut frames = read_frames(bytes)?.into_iter();
    let frame = frames
        .next()
        .ok_or_else(|| "expected one frame, got none".to_string())?;
    if frames.next().is_some() {
        return Err("expected one frame, got more".to_string());
    }
    Ok(frame)
}

fn new_error(bytes: &[u8], label: &str) -> Result<CaptureError, String> {
    match CaptureReader::new(bytes) {
        Ok(_) => Err(format!(
            "{label}: CaptureReader::new unexpectedly succeeded"
        )),
        Err(error) => Ok(error),
    }
}

fn next_error(bytes: &[u8], label: &str) -> Result<CaptureError, String> {
    let mut reader =
        CaptureReader::new(bytes).map_err(|error| format!("{label}: new failed: {error}"))?;
    match reader.next_frame() {
        Ok(Some(_)) => Err(format!("{label}: expected an error, got a frame")),
        Ok(None) => Err(format!("{label}: expected an error, got end of file")),
        Err(error) => Ok(error),
    }
}

fn timestamp(seconds: i64, nanos: u32) -> Option<Timestamp> {
    Some(Timestamp { seconds, nanos })
}

#[test]
fn pcap_reads_all_endiannesses_and_resolutions() -> Result<(), String> {
    let cases = [
        (
            ByteOrder::Little,
            TimestampResolution::Microsecond,
            123_456,
            123_456_000,
        ),
        (
            ByteOrder::Little,
            TimestampResolution::Nanosecond,
            123_456_789,
            123_456_789,
        ),
        (
            ByteOrder::Big,
            TimestampResolution::Microsecond,
            123_456,
            123_456_000,
        ),
        (
            ByteOrder::Big,
            TimestampResolution::Nanosecond,
            123_456_789,
            123_456_789,
        ),
    ];

    for (order, resolution, fraction, nanos) in cases {
        let data = vec![0x11, 0x22, 0x33, 0x44];
        let mut file = pcap::Pcap::new(order, resolution);
        file.push(BuilderTimestamp::new(1_700_000_000, fraction), data.clone())?;
        let bytes = file.to_bytes()?;
        let frame = single_frame(&bytes)?;
        assert_eq!(frame.number, 1);
        assert_eq!(frame.timestamp, timestamp(1_700_000_000, nanos));
        assert_eq!(frame.captured, data);
        assert_eq!(frame.original_len, 4);
        assert_eq!(frame.link_type, 1);
        assert_eq!(frame.interface_id, 0);
        assert_eq!(frame.interface_name, None);
        assert!(frame.comments.is_empty());
    }
    Ok(())
}

#[test]
fn committed_pcap_fixtures_read_the_expected_fields() -> Result<(), String> {
    let little = single_frame(&committed("ethernet-udp-le-us")?)?;
    assert_eq!(little.timestamp, timestamp(1_700_000_000, 123_456_000));
    assert_eq!(little.captured.len(), 51);
    assert_eq!(little.original_len, 51);
    assert_eq!(little.link_type, 1);
    assert_eq!(little.interface_id, 0);
    assert_eq!(little.interface_name, None);

    let big = single_frame(&committed("ethernet-udp-be-ns")?)?;
    assert_eq!(big.timestamp, timestamp(1_700_000_000, 123_456_789));
    assert_eq!(big.captured.len(), 51);
    assert_eq!(big.original_len, 51);
    assert_eq!(big.link_type, 1);

    let truncation = next_error(&committed("truncated")?, "truncated.pcap")?;
    assert!(matches!(&truncation, CaptureError::Truncated));
    Ok(())
}

#[test]
fn committed_pcapng_fixtures_read_interfaces_and_comments() -> Result<(), String> {
    let two_interfaces = read_frames(&committed("two-interfaces")?)?;
    assert_eq!(two_interfaces.len(), 2);

    let first = two_interfaces.first().ok_or("missing first frame")?;
    assert_eq!(first.number, 1);
    assert_eq!(first.timestamp, timestamp(1_700_000_000, 100_000_000));
    assert_eq!(first.captured.len(), 51);
    assert_eq!(first.original_len, 51);
    assert_eq!(first.link_type, 1);
    assert_eq!(first.interface_id, 0);
    assert_eq!(first.interface_name.as_deref(), Some("eth0"));
    assert!(first.comments.is_empty());

    let second = two_interfaces.get(1).ok_or("missing second frame")?;
    assert_eq!(second.number, 2);
    assert_eq!(second.timestamp, timestamp(1_700_000_000, 200_000_001));
    assert_eq!(second.interface_id, 1);
    assert_eq!(second.interface_name.as_deref(), Some("eth1"));
    assert_eq!(second.comments, vec!["second".to_string()]);

    let simple = single_frame(&committed("simple-packet")?)?;
    assert_eq!(simple.number, 1);
    assert_eq!(simple.timestamp, None);
    assert_eq!(simple.captured.len(), 51);
    assert_eq!(simple.original_len, 51);
    assert_eq!(simple.link_type, 1);
    assert_eq!(simple.interface_id, 0);
    assert_eq!(simple.interface_name, None);
    assert!(simple.comments.is_empty());
    Ok(())
}

#[test]
fn advanced_fixture_covers_sections_blocks_and_options() -> Result<(), String> {
    let frames = read_frames(&committed("advanced")?)?;
    assert_eq!(frames.len(), 6);

    let expected = [
        (
            timestamp(1_700_000_000, 123_456_000),
            51_u32,
            51_u32,
            0,
            "eth0",
        ),
        (timestamp(1_700_000_001, 200_000_001), 51, 51, 1, "eth1"),
        (timestamp(1_700_000_001, 300_000_000), 48, 60, 1, "eth1"),
        (None, 51, 51, 0, "eth0"),
        (
            timestamp(1_700_000_001, 400_000_000),
            51,
            51,
            0,
            "section-two",
        ),
        (timestamp(1_700_000_001, 500_000_000), 51, 51, 0, "be-eth"),
    ];
    let comments = [
        vec!["hello".to_string()],
        Vec::new(),
        vec!["obsolete".to_string()],
        Vec::new(),
        vec!["second-section".to_string()],
        vec!["be-section".to_string()],
    ];

    for (index, (frame, expected)) in frames.iter().zip(expected.iter()).enumerate() {
        let number =
            u64::try_from(index).map_err(|_| "frame index does not fit u64".to_string())? + 1;
        assert_eq!(frame.number, number);
        assert_eq!(frame.timestamp, expected.0);
        assert_eq!(
            frame.captured.len(),
            usize::try_from(expected.1).map_err(|_| "caplen")?
        );
        assert_eq!(frame.original_len, expected.2);
        assert_eq!(frame.interface_id, expected.3);
        assert_eq!(frame.interface_name.as_deref(), Some(expected.4));
        assert_eq!(frame.link_type, 1);
    }
    for (frame, expected) in frames.iter().zip(comments.iter()) {
        assert_eq!(&frame.comments, expected);
    }

    let first = frames.first().ok_or("missing first frame")?;
    let simple = frames.get(3).ok_or("missing simple packet frame")?;
    assert_eq!(simple.captured, first.captured);
    Ok(())
}

#[test]
fn snaplen_truncated_pcap_preserves_both_lengths() -> Result<(), String> {
    let frame = single_frame(&committed("snaplen-truncated")?)?;
    assert_eq!(frame.timestamp, timestamp(1_700_000_000, 123_456_000));
    assert_eq!(frame.captured.len(), 60);
    assert_eq!(frame.original_len, 1_500);
    assert_eq!(frame.link_type, 1);
    Ok(())
}

#[test]
fn garbage_is_unrecognized_but_empty_and_short_non_magic_are_empty() -> Result<(), String> {
    let garbage = new_error(&committed("garbage")?, "garbage.bin")?;
    assert!(matches!(&garbage, CaptureError::Unrecognized));

    let empty = read_frames(&committed("empty")?)?;
    assert!(empty.is_empty());

    for length in 1..=7 {
        let bytes = vec![0x41_u8; length];
        let frames = read_frames(&bytes)?;
        assert!(frames.is_empty(), "length {length} produced frames");
    }
    Ok(())
}

#[test]
fn a_recognized_magic_with_a_short_header_is_malformed() -> Result<(), String> {
    let cases: [(&str, Vec<u8>); 6] = [
        ("pcap magic only", vec![0xd4, 0xc3, 0xb2, 0xa1]),
        (
            "pcap magic and version only",
            vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0],
        ),
        ("pcapng magic only", vec![0x0a, 0x0d, 0x0d, 0x0a]),
        (
            "pcapng magic and length only",
            vec![0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0],
        ),
        (
            "pcapng truncated section header",
            vec![0x0a, 0x0d, 0x0d, 0x0a, 32, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a],
        ),
        (
            "pcap truncated global header",
            vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0],
        ),
    ];

    for (label, bytes) in cases {
        let error = new_error(&bytes, label)?;
        assert!(
            matches!(&error, CaptureError::Malformed(_)),
            "{label}: expected Malformed, got {error}"
        );
    }

    let mut valid = committed("two-interfaces")?;
    let byte_order = valid
        .get_mut(8..12)
        .ok_or_else(|| "fixture is too short to corrupt its byte-order magic".to_string())?;
    byte_order.copy_from_slice(&[0, 0, 0, 0]);
    let error = new_error(&valid, "bad byte-order magic")?;
    assert!(matches!(&error, CaptureError::Malformed(_)));
    Ok(())
}

#[test]
fn truncation_is_reported_only_after_a_complete_header() -> Result<(), String> {
    let pcap_truncation = next_error(&committed("truncated")?, "truncated.pcap")?;
    assert!(matches!(&pcap_truncation, CaptureError::Truncated));

    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(pcapng::Interface::ethernet())?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 123_456),
        vec![0xaa; 8],
    ))?;
    let complete = file.to_bytes()?;

    let mut cut_trailer = complete.clone();
    cut_trailer.truncate(complete.len().saturating_sub(4));
    let trailer_error = next_error(&cut_trailer, "pcapng cut trailer")?;
    assert!(matches!(&trailer_error, CaptureError::Truncated));

    let mut partial_block = complete.clone();
    partial_block.extend_from_slice(&[0x06, 0, 0, 0]);
    let mut reader = CaptureReader::new(partial_block.as_slice())
        .map_err(|error| format!("partial block: {error}"))?;
    let first = reader
        .next_frame()
        .map_err(|error| format!("partial block first frame: {error}"))?;
    assert!(first.is_some());
    match reader.next_frame() {
        Err(CaptureError::Truncated) => {}
        Err(error) => return Err(format!("partial block: unexpected error {error}")),
        Ok(_) => return Err("partial block: expected Truncated".to_string()),
    }

    let mut pcap_file = pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond);
    pcap_file.push(BuilderTimestamp::new(1_700_000_000, 1), vec![0xbb; 4])?;
    let mut pcap_bytes = pcap_file.to_bytes()?;
    pcap_bytes.extend_from_slice(&[1, 2, 3, 4]);
    let mut pcap_reader = CaptureReader::new(pcap_bytes.as_slice())
        .map_err(|error| format!("partial record: {error}"))?;
    assert!(
        pcap_reader
            .next_frame()
            .map_err(|error| format!("partial record first frame: {error}"))?
            .is_some()
    );
    match pcap_reader.next_frame() {
        Err(CaptureError::Truncated) => {}
        Err(error) => return Err(format!("partial record: unexpected error {error}")),
        Ok(_) => return Err("partial record: expected Truncated".to_string()),
    }
    Ok(())
}

#[test]
fn a_global_header_without_packets_is_a_clean_end() -> Result<(), String> {
    let pcap_bytes =
        pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond).to_bytes()?;
    assert!(read_frames(&pcap_bytes)?.is_empty());

    let mut pcapng_file = pcapng::PcapNg::new(ByteOrder::Big);
    pcapng_file.add_interface(pcapng::Interface::ethernet())?;
    let pcapng_bytes = pcapng_file.to_bytes()?;
    assert!(read_frames(&pcapng_bytes)?.is_empty());
    Ok(())
}

#[test]
fn oversized_declarations_are_limited_before_allocation() -> Result<(), String> {
    let mut pcap_file = pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond);
    pcap_file.push_packet(pcap::Packet {
        timestamp: BuilderTimestamp::new(1_700_000_000, 0),
        captured_len: u32::MAX,
        original_len: u32::MAX,
        data: Vec::new(),
    })?;
    let pcap_bytes = pcap_file.to_bytes()?;
    assert!(pcap_bytes.len() < 100);
    let pcap_error = next_error(&pcap_bytes, "pcap huge caplen")?;
    assert!(matches!(&pcap_error, CaptureError::FrameTooLarge));

    let mut base = pcapng::PcapNg::new(ByteOrder::Little);
    base.add_interface(pcapng::Interface::ethernet())?;
    let mut huge_block = base.to_bytes()?;
    huge_block.extend_from_slice(&[0x06, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    assert!(huge_block.len() < 100);
    let block_error = next_error(&huge_block, "pcapng huge block")?;
    assert!(matches!(
        &block_error,
        CaptureError::LimitExceeded("pcapng block length")
    ));

    let mut huge_frame = base.to_bytes()?;
    huge_frame.extend_from_slice(&raw_epb_le(u32::MAX)?);
    assert!(huge_frame.len() < 100);
    let frame_error = next_error(&huge_frame, "pcapng huge caplen")?;
    assert!(matches!(
        &frame_error,
        CaptureError::LimitExceeded("frame captured length")
    ));
    Ok(())
}

#[test]
fn a_frame_at_the_size_limit_is_read_at_its_declared_size() -> Result<(), String> {
    let size = u32::try_from(MAX_FRAME_SIZE)
        .map_err(|_| "MAX_FRAME_SIZE does not fit a pcap length".to_string())?;
    let mut file =
        pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond).with_snap_len(size);
    file.push(
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0x5a; MAX_FRAME_SIZE],
    )?;
    let bytes = file.to_bytes()?;
    let full_len = bytes.len();

    let frames = read_frames(&bytes)?;
    assert_eq!(frames.len(), 1);
    let frame = frames
        .first()
        .ok_or_else(|| "expected one maximum-size frame".to_string())?;
    assert_eq!(frame.captured.len(), MAX_FRAME_SIZE);
    assert!(frame.captured.iter().all(|byte| *byte == 0x5a));

    let mut truncated = bytes;
    truncated.truncate(full_len.saturating_sub(1));
    let error = next_error(&truncated, "truncated maximum frame")?;
    assert!(matches!(error, CaptureError::Truncated));

    let mut oversized =
        pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond).with_snap_len(size);
    oversized.push_packet(pcap::Packet {
        timestamp: BuilderTimestamp::new(1_700_000_000, 1),
        captured_len: size + 1,
        original_len: size + 1,
        data: Vec::new(),
    })?;
    let error = next_error(&oversized.to_bytes()?, "oversized frame")?;
    assert!(matches!(error, CaptureError::FrameTooLarge));
    Ok(())
}

fn raw_epb_le(captured_length: u32) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    for value in [0_u32, 0, 0, captured_length, u32::MAX] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let body_len =
        u32::try_from(body.len()).map_err(|_| "test block body does not fit u32".to_string())?;
    let total_len = body_len
        .checked_add(12)
        .ok_or_else(|| "test block length overflow".to_string())?;
    let mut block = Vec::new();
    block.extend_from_slice(&6_u32.to_le_bytes());
    block.extend_from_slice(&total_len.to_le_bytes());
    block.extend_from_slice(&body);
    block.extend_from_slice(&total_len.to_le_bytes());
    Ok(block)
}

#[test]
fn a_one_byte_reader_streams_both_formats() -> Result<(), String> {
    let pcapng_bytes = committed("advanced")?;
    let mut pcapng_reader = CaptureReader::new(Dribble::new(&pcapng_bytes))
        .map_err(|error| format!("one-byte pcapng: {error}"))?;
    let pcapng_frames = drain(&mut pcapng_reader)?;
    assert_eq!(pcapng_frames.len(), 6);
    assert_eq!(
        pcapng_frames.first().and_then(|frame| frame.timestamp),
        timestamp(1_700_000_000, 123_456_000)
    );

    let pcap_bytes = committed("snaplen-truncated")?;
    let mut pcap_reader = CaptureReader::new(Dribble::new(&pcap_bytes))
        .map_err(|error| format!("one-byte pcap: {error}"))?;
    let pcap_frames = drain(&mut pcap_reader)?;
    assert_eq!(pcap_frames.len(), 1);
    assert_eq!(
        pcap_frames
            .first()
            .and_then(|frame| frame.original_len.checked_sub(1_500)),
        Some(0)
    );
    Ok(())
}

struct Dribble<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Dribble<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
}

impl Read for Dribble<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(byte) = self.data.get(self.position) else {
            return Ok(0);
        };
        let Some(slot) = buffer.first_mut() else {
            return Ok(0);
        };
        *slot = *byte;
        self.position += 1;
        Ok(1)
    }
}

#[test]
fn pcapng_link_type_and_snaplen_are_per_interface() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let raw = file.add_interface(pcapng::Interface {
        link_type: 101,
        snap_len: 4,
        ..pcapng::Interface::ethernet()
    })?;
    let ipv4 = file.add_interface(pcapng::Interface {
        link_type: 228,
        snap_len: 65_535,
        ..pcapng::Interface::ethernet()
    })?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        raw,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0x01; 8],
    ))?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        ipv4,
        BuilderTimestamp::new(1_700_000_000, 2),
        vec![0x02; 8],
    ))?;
    file.add_simple_packet(pcapng::SimplePacket::new(vec![0x03; 4]).original_len(8))?;
    let bytes = file.to_bytes()?;
    let frames = read_frames(&bytes)?;
    assert_eq!(frames.len(), 3);
    let first = frames.first().ok_or("missing first frame")?;
    let second = frames.get(1).ok_or("missing second frame")?;
    let simple = frames.get(2).ok_or("missing simple frame")?;
    assert_eq!(first.link_type, 101);
    assert_eq!(first.interface_id, 0);
    assert_eq!(second.link_type, 228);
    assert_eq!(second.interface_id, 1);
    assert_eq!(simple.link_type, 101);
    assert_eq!(simple.captured.len(), 4);
    assert_eq!(simple.original_len, 8);
    assert_eq!(simple.timestamp, None);
    Ok(())
}

#[test]
fn pcapng_options_are_padded_and_tsoffset_is_applied() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(
        pcapng::Interface::ethernet()
            .with_name("x")
            .with_timestamp_resolution(TimestampResolution::Nanosecond)
            .with_timestamp_offset(100),
    )?;
    file.add_enhanced_packet(
        pcapng::EnhancedPacket::new(
            interface,
            BuilderTimestamp::new(1_700_000_000, 123_456_789),
            vec![0xcc; 4],
        )
        .comment("hi"),
    )?;
    let bytes = file.to_bytes()?;
    let frame = single_frame(&bytes)?;
    assert_eq!(frame.timestamp, timestamp(1_700_000_100, 123_456_789));
    assert_eq!(frame.interface_name.as_deref(), Some("x"));
    assert_eq!(frame.comments, vec!["hi".to_string()]);
    Ok(())
}

#[test]
fn pcapng_default_timestamp_resolution_is_microseconds() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(pcapng::Interface::ethernet())?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 123_456),
        vec![0xdd; 4],
    ))?;
    let bytes = file.to_bytes()?;
    let frame = single_frame(&bytes)?;
    assert_eq!(frame.timestamp, timestamp(1_700_000_000, 123_456_000));
    Ok(())
}

#[test]
fn pcapng_skips_unknown_blocks_and_accepts_nrb_and_isb() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Big);
    let interface = file.add_interface(
        pcapng::Interface::ethernet()
            .with_name("be0")
            .with_timestamp_resolution(TimestampResolution::Microsecond),
    )?;
    file.add_name_resolution(
        pcapng::NameResolution::new()
            .add_ipv4([192, 0, 2, 1], &["host.example"])
            .add_other(99, vec![1, 2, 3])
            .comment("nrb"),
    )?;
    file.add_interface_statistics(
        pcapng::InterfaceStatistics::new(interface, BuilderTimestamp::new(1_700_000_000, 500_000))
            .with_received(7)
            .with_dropped(2),
    )?;
    file.add_unknown_block(pcapng::UnknownBlock::new(0xdead_beef, vec![9, 8, 7]))?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 123_456),
        vec![0xaa; 6],
    ))?;
    let bytes = file.to_bytes()?;
    let frame = single_frame(&bytes)?;
    assert_eq!(frame.number, 1);
    assert_eq!(frame.timestamp, timestamp(1_700_000_000, 123_456_000));
    assert_eq!(frame.interface_name.as_deref(), Some("be0"));
    assert_eq!(frame.captured, vec![0xaa; 6]);
    Ok(())
}
