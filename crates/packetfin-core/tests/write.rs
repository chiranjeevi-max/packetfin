//! Integration tests for the capture writer: byte layouts, round trips,
//! option ordering, lazy opening and compression.

use std::fs;
use std::io::{self, BufWriter, Read, Write};

use packetfin_core::capture::{
    CaptureEvent, CaptureReader, CaptureWriter, Compression, Frame, InterfaceInfo, InterfaceOption,
    MAX_PACKET_SIZE, OutputFormat, PacketOption, PacketOptions, PacketRecord, Resolution,
    SectionInfo, SectionOption, Timestamp, TimestampResolution, WriteError, WriterOptions,
};
use packetfin_testkit::pcapng;
use packetfin_testkit::{
    ByteOrder, Timestamp as BuilderTimestamp, TimestampResolution as BuilderResolution,
};
use packetfin_testkit::{fixtures, golden, pcap};

fn committed(name: &str) -> Result<Vec<u8>, String> {
    let fixture = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| format!("fixture {name} is not registered"))?;
    let path = golden::fixtures_dir().join(fixture.file_name());
    fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn rewrite_with(
    bytes: &[u8],
    format: OutputFormat,
    application: &str,
    capture_comments: &[String],
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format,
                compression: Compression::None,
                application,
                capture_comments,
            },
        );
        let mut reader = CaptureReader::new(bytes).map_err(|error| error.to_string())?;
        loop {
            match reader.next_event() {
                Ok(Some(event)) => writer.observe(&event).map_err(|error| error.to_string())?,
                Ok(None) => break,
                Err(error) => return Err(error.to_string()),
            }
        }
        writer.finish().map_err(|error| error.to_string())?;
    }
    Ok(out)
}

fn rewrite(bytes: &[u8], format: OutputFormat) -> Result<Vec<u8>, String> {
    rewrite_with(bytes, format, "test", &[])
}

fn try_rewrite(
    bytes: &[u8],
    format: OutputFormat,
) -> Result<(Vec<u8>, Option<WriteError>), String> {
    let mut out = Vec::new();
    let mut error = None;
    {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format,
                compression: Compression::None,
                application: "test",
                capture_comments: &[],
            },
        );
        let mut reader = CaptureReader::new(bytes).map_err(|error| error.to_string())?;
        loop {
            match reader.next_event() {
                Ok(Some(event)) => {
                    if let Err(failure) = writer.observe(&event) {
                        error = Some(failure);
                        break;
                    }
                }
                Ok(None) => break,
                Err(failure) => return Err(failure.to_string()),
            }
        }
        if error.is_none()
            && let Err(failure) = writer.finish()
        {
            error = Some(failure);
        }
    }
    Ok((out, error))
}

fn events(bytes: &[u8]) -> Result<Vec<CaptureEvent>, String> {
    let mut reader = CaptureReader::new(bytes).map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    loop {
        match reader.next_event() {
            Ok(Some(event)) => events.push(event),
            Ok(None) => return Ok(events),
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn frames(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    Ok(events(bytes)?
        .into_iter()
        .filter_map(|event| match event {
            CaptureEvent::Frame(frame) => Some(frame),
            CaptureEvent::Section(_)
            | CaptureEvent::Interface(_)
            | CaptureEvent::NameResolution(_) => None,
        })
        .collect())
}

fn expected(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn ethernet_interface(global_index: u32) -> InterfaceInfo {
    InterfaceInfo {
        global_index,
        link_type: 1,
        snap_len: 262_144,
        options: Vec::new(),
    }
}

#[test]
fn pcap_global_and_record_headers_are_byte_exact() -> Result<(), String> {
    let data = [1_u8, 2, 3, 4];
    let mut file = pcap::Pcap::new(ByteOrder::Little, BuilderResolution::Microsecond);
    file.push(BuilderTimestamp::new(1_700_000_000, 123_456), data)?;
    let output = rewrite(
        &file.to_bytes()?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;

    let expected = expected(&[
        &[0xd4, 0xc3, 0xb2, 0xa1],
        &[2, 0, 4, 0],
        &[0, 0, 0, 0],
        &[0, 0, 0, 0],
        &262_144_u32.to_le_bytes(),
        &1_u32.to_le_bytes(),
        &1_700_000_000_u32.to_le_bytes(),
        &123_456_u32.to_le_bytes(),
        &4_u32.to_le_bytes(),
        &4_u32.to_le_bytes(),
        &data,
    ]);
    assert_eq!(output, expected);

    let nsec = rewrite(&file.to_bytes()?, OutputFormat::NsecPcap)?;
    assert_eq!(nsec.get(..4), Some(&[0x4d, 0x3c, 0xb2, 0xa1][..]));
    assert_eq!(nsec.get(28..32), Some(&123_456_000_u32.to_le_bytes()[..]));
    Ok(())
}

#[test]
fn pcapng_section_interface_and_packet_headers_are_byte_exact() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(pcapng::Interface::ethernet().with_name("eth0"))?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 123_456),
        vec![0xaa, 0xbb, 0xcc, 0xdd],
    ))?;
    let output = rewrite_with(&file.to_bytes()?, OutputFormat::PcapNg, "app", &[])?;

    let timestamp_units = 1_700_000_000_u64 * 1_000_000 + 123_456;
    let expected = expected(&[
        // Section header block: 40 bytes, one userappl option and end.
        &[0x0a, 0x0d, 0x0d, 0x0a],
        &40_u32.to_le_bytes(),
        &[0x4d, 0x3c, 0x2b, 0x1a],
        &[1, 0, 0, 0],
        &(-1_i64).to_le_bytes(),
        &[4, 0, 3, 0],
        b"app",
        &[0],
        &[0, 0, 0, 0],
        &40_u32.to_le_bytes(),
        // Interface description block: 32 bytes.
        &[1, 0, 0, 0],
        &32_u32.to_le_bytes(),
        &[1, 0],
        &[0, 0],
        &262_144_u32.to_le_bytes(),
        &[2, 0, 4, 0],
        b"eth0",
        &[0, 0, 0, 0],
        &32_u32.to_le_bytes(),
        // Enhanced packet block: 36 bytes.
        &[6, 0, 0, 0],
        &36_u32.to_le_bytes(),
        &[0, 0, 0, 0],
        &((timestamp_units >> 32) as u32).to_le_bytes(),
        &(timestamp_units as u32).to_le_bytes(),
        &[4, 0, 0, 0],
        &[4, 0, 0, 0],
        &[0xaa, 0xbb, 0xcc, 0xdd],
        &36_u32.to_le_bytes(),
    ]);
    assert_eq!(output, expected);
    Ok(())
}

#[test]
fn advanced_capture_round_trips_with_sections_blocks_and_options() -> Result<(), String> {
    let input = committed("advanced")?;
    let original_frames = frames(&input)?;
    let original_nrb: Vec<Vec<u8>> = events(&input)?
        .into_iter()
        .filter_map(|event| match event {
            CaptureEvent::NameResolution(body) => Some(body),
            _ => None,
        })
        .collect();
    let original_interfaces: Vec<InterfaceInfo> = events(&input)?
        .into_iter()
        .filter_map(|event| match event {
            CaptureEvent::Interface(interface) => Some(interface),
            _ => None,
        })
        .collect();

    let output = rewrite(&input, OutputFormat::PcapNg)?;
    let output_events = events(&output)?;
    let output_frames = frames(&output)?;
    assert_eq!(output_frames.len(), original_frames.len());
    assert_eq!(original_nrb.len(), 1);
    assert_eq!(
        output_events
            .iter()
            .filter(|event| matches!(event, CaptureEvent::Section(_)))
            .count(),
        1
    );
    let output_nrb: Vec<Vec<u8>> = output_events
        .iter()
        .filter_map(|event| match event {
            CaptureEvent::NameResolution(body) => Some(body.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(output_nrb, original_nrb);
    let output_interfaces: Vec<InterfaceInfo> = output_events
        .into_iter()
        .filter_map(|event| match event {
            CaptureEvent::Interface(interface) => Some(interface),
            _ => None,
        })
        .collect();
    assert_eq!(output_interfaces, original_interfaces);

    for (original, rewritten) in original_frames.iter().zip(output_frames.iter()) {
        assert_eq!(original.timestamp, rewritten.timestamp);
        assert_eq!(original.timestamp_units, rewritten.timestamp_units);
        assert_eq!(original.captured, rewritten.captured);
        assert_eq!(original.original_len, rewritten.original_len);
        assert_eq!(original.link_type, rewritten.link_type);
        assert_eq!(original.global_interface, rewritten.global_interface);
        assert_eq!(rewritten.interface_id, rewritten.global_interface);
        assert_eq!(original.interface_name, rewritten.interface_name);
        assert_eq!(rewritten.section_number, Some(1));
    }
    Ok(())
}

#[test]
fn section_and_interface_options_keep_source_order() -> Result<(), String> {
    let section = SectionInfo {
        number: 1,
        options: vec![
            SectionOption::Hardware("hw".to_string()),
            SectionOption::UserApplication("source".to_string()),
            SectionOption::Comment("first".to_string()),
            SectionOption::Os("os".to_string()),
        ],
    };
    let interface = InterfaceInfo {
        global_index: 0,
        link_type: 1,
        snap_len: 1_000,
        options: vec![
            InterfaceOption::Name("ethX".to_string()),
            InterfaceOption::Description("my desc".to_string()),
            InterfaceOption::Speed(1_000_000),
            InterfaceOption::TimestampResolution(TimestampResolution::PowerOfTen(6)),
            InterfaceOption::Os("my os".to_string()),
            InterfaceOption::FcsLength(4),
            InterfaceOption::TimestampOffset(3_600),
            InterfaceOption::Hardware("hw".to_string()),
        ],
    };
    let packet_options = PacketOptions {
        options: vec![
            PacketOption::Comment("pkt".to_string()),
            PacketOption::Flags(1),
            PacketOption::Hash(vec![2, 0, 1, 0, 0xaa, 0xbb]),
            PacketOption::DropCount(7),
            PacketOption::PacketId(99),
            PacketOption::Queue(3),
            PacketOption::Verdict(vec![2, 0, 0, 0]),
        ],
    };
    let mut out = Vec::new();
    {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression: Compression::None,
                application: "app",
                capture_comments: &["capture".to_string()],
            },
        );
        writer
            .observe(&CaptureEvent::Section(section.clone()))
            .map_err(|error| error.to_string())?;
        writer
            .observe(&CaptureEvent::Interface(interface.clone()))
            .map_err(|error| error.to_string())?;
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 123_456_000,
                }),
                timestamp_units: Some(1_700_000_000_123_456),
                interface: 0,
                captured: &[1, 2, 3, 4],
                original_len: 4,
                options: &packet_options,
            })
            .map_err(|error| error.to_string())?;
        writer.finish().map_err(|error| error.to_string())?;
    }

    let parsed = events(&out)?;
    let parsed_section = parsed
        .iter()
        .find_map(|event| match event {
            CaptureEvent::Section(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| "output has no section".to_string())?;
    let mut expected_section = section.options.clone();
    expected_section.push(SectionOption::Comment("capture".to_string()));
    assert_eq!(parsed_section.options, expected_section);

    let parsed_interface = parsed
        .iter()
        .find_map(|event| match event {
            CaptureEvent::Interface(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| "output has no interface".to_string())?;
    assert_eq!(parsed_interface.options, interface.options);

    let parsed_frame = parsed
        .iter()
        .find_map(|event| match event {
            CaptureEvent::Frame(frame) => Some(frame),
            _ => None,
        })
        .ok_or_else(|| "output has no frame".to_string())?;
    assert_eq!(parsed_frame.options, packet_options);
    Ok(())
}

#[test]
fn obsolete_packets_gain_a_drop_count_and_simple_packets_stay_simple() -> Result<(), String> {
    let input = committed("advanced")?;
    let output = rewrite(&input, OutputFormat::PcapNg)?;
    let frames = frames(&output)?;
    let obsolete = frames
        .get(2)
        .ok_or_else(|| "missing rewritten obsolete frame".to_string())?;
    assert_eq!(obsolete.comments, vec!["obsolete".to_string()]);
    assert_eq!(obsolete.options.drop_count(), Some(0));
    assert_eq!(
        obsolete.timestamp,
        Some(Timestamp {
            seconds: 1_700_000_001,
            nanos: 300_000_000,
        })
    );

    let simple = frames
        .get(3)
        .ok_or_else(|| "missing rewritten simple frame".to_string())?;
    assert_eq!(simple.timestamp, None);
    assert_eq!(simple.timestamp_units, None);
    assert_eq!(simple.captured.len(), 51);
    assert!(simple.options.options.is_empty());
    Ok(())
}

#[test]
fn timestamp_conversion_truncates_microseconds_and_scales_nanoseconds() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(
        pcapng::Interface::ethernet().with_timestamp_resolution(BuilderResolution::Nanosecond),
    )?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 999_999_999),
        vec![0; 4],
    ))?;
    let input = file.to_bytes()?;

    let micro = rewrite(&input, OutputFormat::Pcap(Resolution::Microsecond))?;
    let micro_frame = frames(&micro)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing microsecond frame".to_string())?;
    assert_eq!(
        micro_frame.timestamp,
        Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 999_999_000,
        })
    );

    let nano = rewrite(&input, OutputFormat::NsecPcap)?;
    let nano_frame = frames(&nano)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing nanosecond frame".to_string())?;
    assert_eq!(
        nano_frame.timestamp,
        Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 999_999_999,
        })
    );
    Ok(())
}

#[test]
fn a_second_that_does_not_fit_pcap_is_rejected_after_the_header() -> Result<(), String> {
    let mut out = Vec::new();
    let error = {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format: OutputFormat::Pcap(Resolution::Microsecond),
                compression: Compression::None,
                application: "test",
                capture_comments: &[],
            },
        );
        writer
            .open_live(&[ethernet_interface(0)])
            .map_err(|error| error.to_string())?;
        let options = PacketOptions::default();
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 4_294_967_296,
                    nanos: 0,
                }),
                timestamp_units: Some(4_294_967_296_000_000),
                interface: 0,
                captured: &[0; 4],
                original_len: 4,
                options: &options,
            })
            .err()
    };
    assert!(matches!(error, Some(WriteError::TimestampOutOfRange)));
    assert_eq!(out.len(), 24);
    Ok(())
}

#[test]
fn an_oversized_packet_is_rejected_before_it_is_encoded() -> Result<(), String> {
    let data = vec![0_u8; MAX_PACKET_SIZE + 1];
    let options = PacketOptions::default();
    let mut out = Vec::new();
    let error = {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression: Compression::None,
                application: "test",
                capture_comments: &[],
            },
        );
        writer
            .open_live(&[ethernet_interface(0)])
            .map_err(|error| error.to_string())?;
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                timestamp_units: Some(1_000_000),
                interface: 0,
                captured: &data,
                original_len: MAX_PACKET_SIZE as u32 + 1,
                options: &options,
            })
            .err()
    };
    assert!(matches!(error, Some(WriteError::PacketTooLarge { .. })));
    Ok(())
}

#[test]
fn mixed_link_types_split_before_and_after_opening() -> Result<(), String> {
    let mut before = pcapng::PcapNg::new(ByteOrder::Little);
    before.add_interface(pcapng::Interface::ethernet())?;
    before.add_interface(pcapng::Interface {
        link_type: 101,
        ..pcapng::Interface::ethernet()
    })?;
    let (bytes, error) = try_rewrite(
        &before.to_bytes()?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;
    assert!(matches!(error, Some(WriteError::Incompatible(_))));
    assert!(bytes.is_empty());

    let mut late = pcapng::PcapNg::new(ByteOrder::Little);
    let first = late.add_interface(pcapng::Interface::ethernet())?;
    late.add_enhanced_packet(pcapng::EnhancedPacket::new(
        first,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0; 4],
    ))?;
    late.add_section(ByteOrder::Little)?;
    let second = late.add_interface(pcapng::Interface {
        link_type: 101,
        ..pcapng::Interface::ethernet()
    })?;
    late.add_enhanced_packet(pcapng::EnhancedPacket::new(
        second,
        BuilderTimestamp::new(1_700_000_001, 1),
        vec![0; 4],
    ))?;
    let (bytes, error) = try_rewrite(
        &late.to_bytes()?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;
    assert!(matches!(error, Some(WriteError::IncompatibleLater(_))));
    assert!(bytes.len() > 24);
    assert_eq!(bytes.get(..4), Some(&[0xd4, 0xc3, 0xb2, 0xa1][..]));

    let mut same = pcapng::PcapNg::new(ByteOrder::Little);
    let first = same.add_interface(pcapng::Interface::ethernet())?;
    same.add_enhanced_packet(pcapng::EnhancedPacket::new(
        first,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0; 4],
    ))?;
    same.add_section(ByteOrder::Little)?;
    let second = same.add_interface(pcapng::Interface::ethernet())?;
    same.add_enhanced_packet(pcapng::EnhancedPacket::new(
        second,
        BuilderTimestamp::new(1_700_000_001, 1),
        vec![0; 4],
    ))?;
    let output = rewrite(
        &same.to_bytes()?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;
    assert_eq!(frames(&output)?.len(), 2);
    Ok(())
}

#[test]
fn empty_sources_write_header_only_files() -> Result<(), String> {
    let pcapng_output = rewrite_with(&[], OutputFormat::PcapNg, "app", &[])?;
    let ng_expected = expected(&[
        &[0x0a, 0x0d, 0x0d, 0x0a],
        &40_u32.to_le_bytes(),
        &[0x4d, 0x3c, 0x2b, 0x1a],
        &[1, 0, 0, 0],
        &(-1_i64).to_le_bytes(),
        &[4, 0, 3, 0],
        b"app",
        &[0],
        &[0, 0, 0, 0],
        &40_u32.to_le_bytes(),
        &[1, 0, 0, 0],
        &32_u32.to_le_bytes(),
        &[0xc5, 0],
        &[0, 0],
        &262_144_u32.to_le_bytes(),
        &[9, 0, 1, 0],
        &[9, 0, 0, 0],
        &[0, 0, 0, 0],
        &32_u32.to_le_bytes(),
    ]);
    assert_eq!(pcapng_output, ng_expected);

    let pcap_output = rewrite(&[], OutputFormat::Pcap(Resolution::Microsecond))?;
    let pcap_expected = expected(&[
        &[0xd4, 0xc3, 0xb2, 0xa1],
        &[2, 0, 4, 0],
        &[0, 0, 0, 0],
        &[0, 0, 0, 0],
        &262_144_u32.to_le_bytes(),
        &197_u32.to_le_bytes(),
    ]);
    assert_eq!(pcap_output, pcap_expected);
    Ok(())
}

#[test]
fn a_section_without_interfaces_is_pcap_incompatible() -> Result<(), String> {
    let shb_only = expected(&[
        &[0x0a, 0x0d, 0x0d, 0x0a],
        &28_u32.to_le_bytes(),
        &[0x4d, 0x3c, 0x2b, 0x1a],
        &[1, 0, 0, 0],
        &(-1_i64).to_le_bytes(),
        &28_u32.to_le_bytes(),
    ]);
    let (output, error) = try_rewrite(&shb_only, OutputFormat::Pcap(Resolution::Microsecond))?;
    assert!(matches!(error, Some(WriteError::Incompatible(_))));
    assert!(output.is_empty());

    let pcapng_output = rewrite_with(&shb_only, OutputFormat::PcapNg, "app", &[])?;
    let sections = events(&pcapng_output)?
        .into_iter()
        .filter(|event| matches!(event, CaptureEvent::Section(_)))
        .count();
    let interfaces = events(&pcapng_output)?
        .into_iter()
        .filter(|event| matches!(event, CaptureEvent::Interface(_)))
        .count();
    assert_eq!(sections, 1);
    assert_eq!(interfaces, 0);
    Ok(())
}

#[test]
fn binary_resolution_and_tsoffset_survive_a_pcapng_rewrite() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(
        pcapng::Interface::ethernet()
            .with_timestamp_resolution(BuilderResolution::PowerOfTwo(10))
            .with_timestamp_offset(100),
    )?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(3, 512),
        vec![0; 4],
    ))?;
    let input = file.to_bytes()?;

    let original = frames(&input)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing original frame".to_string())?;
    assert_eq!(
        original.timestamp,
        Some(Timestamp {
            seconds: 103,
            nanos: 500_000_000,
        })
    );
    assert_eq!(original.timestamp_units, Some(3 * 1_024 + 512));

    let output = rewrite(&input, OutputFormat::PcapNg)?;
    let parsed = events(&output)?;
    let interface_info = parsed
        .iter()
        .find_map(|event| match event {
            CaptureEvent::Interface(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| "missing interface".to_string())?;
    assert_eq!(
        interface_info.timestamp_resolution(),
        Some(TimestampResolution::PowerOfTwo(10))
    );
    assert_eq!(interface_info.timestamp_offset(), Some(100));
    let rewritten = parsed
        .into_iter()
        .find_map(|event| match event {
            CaptureEvent::Frame(frame) => Some(frame),
            _ => None,
        })
        .ok_or_else(|| "missing rewritten frame".to_string())?;
    assert_eq!(rewritten.timestamp_units, Some(3 * 1_024 + 512));
    assert_eq!(rewritten.timestamp, original.timestamp);

    let pcap = rewrite(&input, OutputFormat::Pcap(Resolution::Microsecond))?;
    let pcap_frame = frames(&pcap)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing pcap frame".to_string())?;
    assert_eq!(
        pcap_frame.timestamp,
        Some(Timestamp {
            seconds: 103,
            nanos: 500_000_000,
        })
    );
    Ok(())
}

#[test]
fn gzip_and_lz4_output_is_deterministic_and_counts_logical_bytes() -> Result<(), String> {
    let mut file = pcap::Pcap::new(ByteOrder::Little, BuilderResolution::Microsecond);
    file.push(BuilderTimestamp::new(1_700_000_000, 1), vec![0x5a; 64])?;
    let input = file.to_bytes()?;
    let plain = rewrite(&input, OutputFormat::PcapNg)?;

    let compressed = |compression| -> Result<(Vec<u8>, u64), String> {
        let mut writer = CaptureWriter::new(
            Vec::new(),
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression,
                application: "test",
                capture_comments: &[],
            },
        );
        let mut reader = CaptureReader::new(input.as_slice()).map_err(|error| error.to_string())?;
        loop {
            match reader.next_event() {
                Ok(Some(event)) => writer.observe(&event).map_err(|error| error.to_string())?,
                Ok(None) => break,
                Err(error) => return Err(error.to_string()),
            }
        }
        writer.finish().map_err(|error| error.to_string())?;
        let logical = writer.logical_bytes();
        let bytes = writer.into_inner().map_err(|error| error.to_string())?;
        Ok((bytes, logical))
    };

    let (gzip_one, gzip_logical) = compressed(Compression::Gzip)?;
    let (gzip_two, _) = compressed(Compression::Gzip)?;
    assert_eq!(gzip_one, gzip_two);
    assert_eq!(gzip_logical, plain.len() as u64);
    assert_eq!(gzip_one.get(..2), Some(&[0x1f, 0x8b][..]));
    assert_eq!(gzip_one.get(4..8), Some(&[0, 0, 0, 0][..]));
    let mut decoded = Vec::new();
    flate2::read::MultiGzDecoder::new(gzip_one.as_slice())
        .read_to_end(&mut decoded)
        .map_err(|error| error.to_string())?;
    assert_eq!(decoded, plain);

    let (lz4_one, lz4_logical) = compressed(Compression::Lz4)?;
    let (lz4_two, _) = compressed(Compression::Lz4)?;
    assert_eq!(lz4_one, lz4_two);
    assert_eq!(lz4_logical, plain.len() as u64);
    assert_eq!(lz4_one.get(..4), Some(&[0x04, 0x22, 0x4d, 0x18][..]));
    let mut decoded = Vec::new();
    lz4_flex::frame::FrameDecoder::new(lz4_one.as_slice())
        .read_to_end(&mut decoded)
        .map_err(|error| error.to_string())?;
    assert_eq!(decoded, plain);
    Ok(())
}

#[test]
fn later_section_options_are_dropped_and_interfaces_are_renumbered() -> Result<(), String> {
    let first = SectionInfo {
        number: 1,
        options: vec![SectionOption::Hardware("hw".to_string())],
    };
    let second = SectionInfo {
        number: 2,
        options: vec![SectionOption::Os("later".to_string())],
    };
    let mut out = Vec::new();
    {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression: Compression::None,
                application: "app",
                capture_comments: &[],
            },
        );
        writer
            .observe(&CaptureEvent::Section(first.clone()))
            .map_err(|error| error.to_string())?;
        writer
            .observe(&CaptureEvent::Interface(InterfaceInfo {
                global_index: 0,
                link_type: 1,
                snap_len: 1_000,
                options: vec![InterfaceOption::Name("one".to_string())],
            }))
            .map_err(|error| error.to_string())?;
        let options = PacketOptions::default();
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                timestamp_units: Some(1_000_000),
                interface: 0,
                captured: &[0; 4],
                original_len: 4,
                options: &options,
            })
            .map_err(|error| error.to_string())?;
        writer
            .observe(&CaptureEvent::Section(second))
            .map_err(|error| error.to_string())?;
        writer
            .observe(&CaptureEvent::Interface(InterfaceInfo {
                global_index: 1,
                link_type: 1,
                snap_len: 1_000,
                options: vec![InterfaceOption::Name("two".to_string())],
            }))
            .map_err(|error| error.to_string())?;
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 2,
                    nanos: 0,
                }),
                timestamp_units: Some(2_000_000),
                interface: 1,
                captured: &[1; 4],
                original_len: 4,
                options: &options,
            })
            .map_err(|error| error.to_string())?;
        writer.finish().map_err(|error| error.to_string())?;
    }

    let parsed = events(&out)?;
    let sections: Vec<&SectionInfo> = parsed
        .iter()
        .filter_map(|event| match event {
            CaptureEvent::Section(info) => Some(info),
            _ => None,
        })
        .collect();
    assert_eq!(sections.len(), 1);
    let section = sections
        .first()
        .ok_or_else(|| "missing section".to_string())?;
    assert_eq!(
        section.options,
        vec![
            SectionOption::Hardware("hw".to_string()),
            SectionOption::UserApplication("app".to_string()),
        ]
    );
    let interfaces: Vec<&InterfaceInfo> = parsed
        .iter()
        .filter_map(|event| match event {
            CaptureEvent::Interface(info) => Some(info),
            _ => None,
        })
        .collect();
    assert_eq!(interfaces.len(), 2);
    assert_eq!(interfaces.get(1).map(|info| info.global_index), Some(1));
    let frames = frames(&out)?;
    assert_eq!(frames.get(1).map(|frame| frame.global_interface), Some(1));
    assert_eq!(frames.get(1).map(|frame| frame.interface_id), Some(1));
    Ok(())
}

#[test]
fn pcap_snaplen_is_copied_to_the_output_interface() -> Result<(), String> {
    let mut file =
        pcap::Pcap::new(ByteOrder::Little, BuilderResolution::Microsecond).with_snap_len(1_000);
    file.push(BuilderTimestamp::new(1_700_000_000, 1), vec![0; 4])?;
    let output = rewrite(&file.to_bytes()?, OutputFormat::PcapNg)?;
    let interface = events(&output)?
        .into_iter()
        .find_map(|event| match event {
            CaptureEvent::Interface(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| "missing interface".to_string())?;
    assert_eq!(interface.snap_len, 1_000);
    Ok(())
}

#[test]
fn open_live_writes_identity_and_interfaces_eagerly() -> Result<(), String> {
    let mut out = Vec::new();
    let interfaces = [
        InterfaceInfo {
            global_index: 0,
            link_type: 1,
            snap_len: 524_288,
            options: vec![InterfaceOption::Name("eth0".to_string())],
        },
        InterfaceInfo {
            global_index: 1,
            link_type: 1,
            snap_len: 524_288,
            options: vec![InterfaceOption::Name("eth1".to_string())],
        },
    ];
    {
        let mut writer = CaptureWriter::new(
            &mut out,
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression: Compression::None,
                application: "packetfin",
                capture_comments: &[],
            },
        );
        writer
            .open_live(&interfaces)
            .map_err(|error| error.to_string())?;
        let options = PacketOptions::default();
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 1,
                }),
                timestamp_units: Some(1_000_000),
                interface: 1,
                captured: &[0; 4],
                original_len: 4,
                options: &options,
            })
            .map_err(|error| error.to_string())?;
        writer.finish().map_err(|error| error.to_string())?;
    }

    let parsed = events(&out)?;
    let section = parsed
        .iter()
        .find_map(|event| match event {
            CaptureEvent::Section(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| "missing section".to_string())?;
    assert_eq!(
        section.options,
        vec![SectionOption::UserApplication("packetfin".to_string())]
    );
    let interfaces = parsed
        .iter()
        .filter(|event| matches!(event, CaptureEvent::Interface(_)))
        .count();
    assert_eq!(interfaces, 2);
    let frame = frames(&out)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing frame".to_string())?;
    assert_eq!(frame.global_interface, 1);
    assert_eq!(frame.interface_id, 1);
    Ok(())
}

#[test]
fn a_first_section_truncated_spb_becomes_an_enhanced_block() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    file.add_interface(pcapng::Interface {
        snap_len: 4,
        ..pcapng::Interface::ethernet()
    })?;
    file.add_simple_packet(pcapng::SimplePacket::new(vec![0xaa; 4]).original_len(51))?;
    let output = rewrite(&file.to_bytes()?, OutputFormat::PcapNg)?;
    let frame = frames(&output)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing converted simple packet".to_string())?;
    assert_eq!(frame.global_interface, 0);
    assert_eq!(
        frame.timestamp,
        Some(Timestamp {
            seconds: 0,
            nanos: 0
        })
    );
    assert_eq!(frame.timestamp_units, Some(0));
    assert_eq!(frame.captured, vec![0xaa; 4]);
    assert_eq!(frame.original_len, 51);
    Ok(())
}

#[test]
fn a_later_section_untruncated_spb_stays_simple() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    file.add_interface(pcapng::Interface::ethernet())?;
    file.add_section(ByteOrder::Little)?;
    file.add_interface(pcapng::Interface::ethernet())?;
    file.add_simple_packet(pcapng::SimplePacket::new(vec![0xbb; 4]))?;
    let output = rewrite(&file.to_bytes()?, OutputFormat::PcapNg)?;
    let frame = frames(&output)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing simple packet".to_string())?;
    assert_eq!(frame.global_interface, 0);
    assert_eq!(frame.interface_id, 0);
    assert_eq!(frame.timestamp, None);
    assert_eq!(frame.timestamp_units, None);
    assert_eq!(frame.captured, vec![0xbb; 4]);
    assert_eq!(frame.original_len, 4);
    Ok(())
}

#[test]
fn a_truncated_later_section_simple_packet_becomes_an_enhanced_block() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    file.add_interface(pcapng::Interface::ethernet())?;
    file.add_section(ByteOrder::Little)?;
    file.add_interface(pcapng::Interface {
        snap_len: 4,
        ..pcapng::Interface::ethernet()
    })?;
    file.add_simple_packet(pcapng::SimplePacket::new(vec![0xaa; 4]).original_len(51))?;
    let output = rewrite(&file.to_bytes()?, OutputFormat::PcapNg)?;
    let frame = frames(&output)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing converted simple packet".to_string())?;
    assert_eq!(frame.global_interface, 1);
    assert_eq!(frame.interface_id, 1);
    assert_eq!(
        frame.timestamp,
        Some(Timestamp {
            seconds: 0,
            nanos: 0
        })
    );
    assert_eq!(frame.timestamp_units, Some(0));
    assert_eq!(frame.captured, vec![0xaa; 4]);
    assert_eq!(frame.original_len, 51);
    Ok(())
}

#[test]
fn source_offsets_are_decompressed_offsets() -> Result<(), String> {
    let mut file = pcap::Pcap::new(ByteOrder::Little, BuilderResolution::Microsecond);
    file.push(BuilderTimestamp::new(1_700_000_000, 1), vec![0; 4])?;
    file.push(BuilderTimestamp::new(1_700_000_001, 1), vec![0; 4])?;
    let plain = file.to_bytes()?;
    let expected: Vec<u64> = frames(&plain)?
        .into_iter()
        .map(|frame| frame.source_offset)
        .collect();
    assert_eq!(expected, vec![24, 44]);

    for compressed in [
        packetfin_testkit::compress::gzip_member(&plain)?,
        packetfin_testkit::compress::lz4_frame(&plain)?,
    ] {
        let offsets: Vec<u64> = frames(&compressed)?
            .into_iter()
            .map(|frame| frame.source_offset)
            .collect();
        assert_eq!(offsets, expected);
        let output = rewrite(&compressed, OutputFormat::PcapNg)?;
        assert_eq!(frames(&output)?.len(), 2);
    }
    Ok(())
}

#[test]
fn source_offsets_point_at_each_record_and_block() -> Result<(), String> {
    let mut file = pcap::Pcap::new(ByteOrder::Little, BuilderResolution::Microsecond);
    file.push(BuilderTimestamp::new(1_700_000_000, 1), vec![0; 4])?;
    file.push(BuilderTimestamp::new(1_700_000_001, 1), vec![0; 4])?;
    let pcap_frames = frames(&file.to_bytes()?)?;
    assert_eq!(
        pcap_frames.first().map(|frame| frame.source_offset),
        Some(24)
    );
    assert_eq!(
        pcap_frames.get(1).map(|frame| frame.source_offset),
        Some(44)
    );

    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(pcapng::Interface::ethernet())?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0; 4],
    ))?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_001, 1),
        vec![0; 4],
    ))?;
    let pcapng_frames = frames(&file.to_bytes()?)?;
    assert_eq!(
        pcapng_frames.first().map(|frame| frame.source_offset),
        Some(56)
    );
    assert_eq!(
        pcapng_frames.get(1).map(|frame| frame.source_offset),
        Some(96)
    );
    Ok(())
}

#[test]
fn unused_interfaces_keep_their_global_number() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    file.add_interface(pcapng::Interface::ethernet().with_name("unused"))?;
    let used = file.add_interface(pcapng::Interface::ethernet().with_name("used"))?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        used,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0; 4],
    ))?;
    let input = file.to_bytes()?;
    let original = frames(&input)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing frame".to_string())?;
    assert_eq!(original.interface_id, 1);
    assert_eq!(original.global_interface, 1);

    let output = rewrite(&input, OutputFormat::PcapNg)?;
    let rewritten = frames(&output)?
        .into_iter()
        .next()
        .ok_or_else(|| "missing rewritten frame".to_string())?;
    assert_eq!(rewritten.interface_id, 1);
    assert_eq!(rewritten.global_interface, 1);
    Ok(())
}

fn name_resolution_body(bytes: &[u8]) -> Result<Vec<u8>, String> {
    events(bytes)?
        .into_iter()
        .find_map(|event| match event {
            CaptureEvent::NameResolution(body) => Some(body),
            _ => None,
        })
        .ok_or_else(|| "missing name resolution block".to_string())
}

#[test]
fn big_endian_name_resolution_is_normalised_to_little_endian() -> Result<(), String> {
    let build = |order: ByteOrder| -> Result<Vec<u8>, String> {
        let mut file = pcapng::PcapNg::new(order);
        let interface = file.add_interface(pcapng::Interface::ethernet())?;
        file.add_name_resolution(
            pcapng::NameResolution::new()
                .add_ipv4([10, 0, 0, 1], &["host.example"])
                .comment("nrb"),
        )?;
        file.add_enhanced_packet(pcapng::EnhancedPacket::new(
            interface,
            BuilderTimestamp::new(1_700_000_000, 1),
            vec![0; 4],
        ))?;
        file.to_bytes()
    };

    let big = rewrite(&build(ByteOrder::Big)?, OutputFormat::PcapNg)?;
    let little = rewrite(&build(ByteOrder::Little)?, OutputFormat::PcapNg)?;
    let big_body = name_resolution_body(&big)?;
    let little_body = name_resolution_body(&little)?;
    assert_eq!(big_body, little_body);
    assert_eq!(big_body.get(..4), Some(&[1, 0, 17, 0][..]));
    assert!(big_body.windows(4).any(|window| window == [1, 0, 3, 0]));
    assert_eq!(frames(&big)?.len(), 1);
    Ok(())
}

#[test]
fn obsolete_packet_options_keep_order_and_suppress_the_field_drop_count() -> Result<(), String> {
    for (order, big_endian) in [(ByteOrder::Little, false), (ByteOrder::Big, true)] {
        let mut file = pcapng::PcapNg::new(order);
        let interface = file.add_interface(pcapng::Interface::ethernet())?;
        let flags = if big_endian {
            1_u32.to_be_bytes()
        } else {
            1_u32.to_le_bytes()
        };
        let drop_count = if big_endian {
            7_u64.to_be_bytes()
        } else {
            7_u64.to_le_bytes()
        };
        let packet_id = if big_endian {
            99_u64.to_be_bytes()
        } else {
            99_u64.to_le_bytes()
        };
        let queue = if big_endian {
            3_u32.to_be_bytes()
        } else {
            3_u32.to_le_bytes()
        };
        file.add_obsolete_packet(
            pcapng::ObsoletePacket::new(
                interface,
                BuilderTimestamp::new(1_700_000_000, 1),
                vec![0; 4],
            )
            .with_drop_count(5)
            .with_raw_option(2, flags)
            .with_raw_option(3, vec![1, 0, 0, 0])
            .with_raw_option(4, drop_count)
            .with_raw_option(5, packet_id)
            .with_raw_option(6, queue)
            .with_raw_option(7, vec![0, 0]),
        )?;
        let input = file.to_bytes()?;
        let expected = vec![
            PacketOption::Flags(1),
            PacketOption::Hash(vec![1, 0, 0, 0]),
            PacketOption::DropCount(7),
            PacketOption::PacketId(99),
            PacketOption::Queue(3),
            PacketOption::Verdict(vec![0, 0]),
        ];
        let original = frames(&input)?
            .into_iter()
            .next()
            .ok_or_else(|| "missing original obsolete frame".to_string())?;
        assert_eq!(original.options.options, expected);

        let output = rewrite(&input, OutputFormat::PcapNg)?;
        let rewritten = frames(&output)?
            .into_iter()
            .next()
            .ok_or_else(|| "missing rewritten obsolete frame".to_string())?;
        assert_eq!(rewritten.options.options, expected);
    }
    Ok(())
}

#[test]
fn pcap_output_copies_classic_source_snaplen() -> Result<(), String> {
    let truncated = rewrite(
        &committed("snaplen-truncated")?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;
    assert_eq!(truncated.get(16..20), Some(&64_u32.to_le_bytes()[..]));

    let mut zero =
        pcap::Pcap::new(ByteOrder::Little, BuilderResolution::Microsecond).with_snap_len(0);
    zero.push(BuilderTimestamp::new(1_700_000_000, 1), vec![0; 4])?;
    let zero = rewrite(
        &zero.to_bytes()?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;
    assert_eq!(zero.get(16..20), Some(&262_144_u32.to_le_bytes()[..]));

    let mut pcapng_file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = pcapng_file.add_interface(pcapng::Interface {
        snap_len: 1_000,
        ..pcapng::Interface::ethernet()
    })?;
    pcapng_file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0; 4],
    ))?;
    let from_pcapng = rewrite(
        &pcapng_file.to_bytes()?,
        OutputFormat::Pcap(Resolution::Microsecond),
    )?;
    assert_eq!(
        from_pcapng.get(16..20),
        Some(&262_144_u32.to_le_bytes()[..])
    );
    Ok(())
}

#[test]
fn compressed_sinks_flush_a_buffered_writer() -> Result<(), String> {
    for compression in [Compression::None, Compression::Gzip, Compression::Lz4] {
        let mut writer = CaptureWriter::new(
            BufWriter::with_capacity(8_192, Vec::new()),
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression,
                application: "test",
                capture_comments: &[],
            },
        );
        writer
            .open_live(&[ethernet_interface(0)])
            .map_err(|error| error.to_string())?;
        let options = PacketOptions::default();
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                timestamp_units: Some(1_000_000),
                interface: 0,
                captured: &[0; 4],
                original_len: 4,
                options: &options,
            })
            .map_err(|error| error.to_string())?;
        writer.finish().map_err(|error| error.to_string())?;
        let buffered = writer.into_inner().map_err(|error| error.to_string())?;
        assert_eq!(buffered.buffer().len(), 0);
        let bytes = buffered.into_inner().map_err(|error| error.to_string())?;
        assert!(!bytes.is_empty());
    }
    Ok(())
}

#[test]
fn compressed_sinks_report_flush_failures() -> Result<(), String> {
    for compression in [Compression::Gzip, Compression::Lz4] {
        let mut writer = CaptureWriter::new(
            FlushFailure,
            WriterOptions {
                format: OutputFormat::PcapNg,
                compression,
                application: "test",
                capture_comments: &[],
            },
        );
        writer
            .open_live(&[ethernet_interface(0)])
            .map_err(|error| error.to_string())?;
        let options = PacketOptions::default();
        writer
            .write_packet(PacketRecord {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                timestamp_units: Some(1_000_000),
                interface: 0,
                captured: &[0; 4],
                original_len: 4,
                options: &options,
            })
            .map_err(|error| error.to_string())?;
        assert!(matches!(writer.finish(), Err(WriteError::Io(_))));
    }
    Ok(())
}

#[test]
fn a_timestamp_without_units_is_not_silently_a_simple_packet() -> Result<(), String> {
    let mut writer = CaptureWriter::new(
        Vec::new(),
        WriterOptions {
            format: OutputFormat::PcapNg,
            compression: Compression::None,
            application: "test",
            capture_comments: &[],
        },
    );
    writer
        .open_live(&[ethernet_interface(0)])
        .map_err(|error| error.to_string())?;
    let options = PacketOptions::default();
    let error = writer
        .write_packet(PacketRecord {
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_000,
            }),
            timestamp_units: None,
            interface: 0,
            captured: &[0; 4],
            original_len: 4,
            options: &options,
        })
        .err();
    assert!(matches!(error, Some(WriteError::MissingTimestampUnits)));
    Ok(())
}

#[test]
fn interface_filter_option_round_trips() -> Result<(), String> {
    let filter = vec![0, b'l', b'i', b'b', b'p', b'c', b'a', b'p'];
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = file.add_interface(
        pcapng::Interface::ethernet()
            .with_name("eth0")
            .with_raw_option(11, filter.clone()),
    )?;
    file.add_enhanced_packet(pcapng::EnhancedPacket::new(
        interface,
        BuilderTimestamp::new(1_700_000_000, 1),
        vec![0; 4],
    ))?;
    let output = rewrite(&file.to_bytes()?, OutputFormat::PcapNg)?;
    let info = events(&output)?
        .into_iter()
        .find_map(|event| match event {
            CaptureEvent::Interface(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| "missing interface".to_string())?;
    assert_eq!(
        info.options,
        vec![
            InterfaceOption::Name("eth0".to_string()),
            InterfaceOption::Filter(filter),
        ]
    );
    Ok(())
}

#[test]
fn an_empty_interface_filter_is_rejected() -> Result<(), String> {
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    file.add_interface(pcapng::Interface::ethernet().with_raw_option(11, Vec::new()))?;
    match events(&file.to_bytes()?) {
        Err(error) => {
            assert!(error.contains("if_filter"), "unexpected error: {error}");
            Ok(())
        }
        Ok(_) => Err("empty if_filter was accepted".to_string()),
    }
}

#[test]
fn empty_source_interface_names_are_dropped_on_rewrite() -> Result<(), String> {
    let output = rewrite(&committed("field-output")?, OutputFormat::PcapNg)?;
    let interfaces: Vec<InterfaceInfo> = events(&output)?
        .into_iter()
        .filter_map(|event| match event {
            CaptureEvent::Interface(info) => Some(info),
            _ => None,
        })
        .collect();
    assert_eq!(interfaces.len(), 3);
    let empty = interfaces
        .get(1)
        .ok_or_else(|| "missing empty-name interface".to_string())?;
    assert_eq!(empty.name(), None);
    assert!(
        empty
            .options
            .iter()
            .all(|option| !matches!(option, InterfaceOption::Name(_)))
    );
    Ok(())
}

struct FlushFailure;

impl Write for FlushFailure {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

#[test]
fn live_pcap_header_keeps_the_activated_snapshot_length() -> Result<(), String> {
    for snap_len in [40_u32, 524_288] {
        let mut out = Vec::new();
        let interface = InterfaceInfo {
            global_index: 0,
            link_type: 0,
            snap_len,
            options: Vec::new(),
        };
        {
            let mut writer = CaptureWriter::new(
                &mut out,
                WriterOptions {
                    format: OutputFormat::Pcap(Resolution::Microsecond),
                    compression: Compression::None,
                    application: "test",
                    capture_comments: &[],
                },
            );
            writer
                .open_live(&[interface])
                .map_err(|error| error.to_string())?;
            writer.finish().map_err(|error| error.to_string())?;
        }
        assert_eq!(out.len(), 24, "open_live must write only the global header");
        assert_eq!(
            out.get(16..20),
            Some(&snap_len.to_le_bytes()[..]),
            "snap {snap_len}"
        );
    }
    Ok(())
}
