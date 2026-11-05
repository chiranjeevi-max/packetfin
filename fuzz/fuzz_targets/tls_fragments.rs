#![no_main]

//! Fuzz cross-segment TLS handshake fragments and direction changes.
//!
//! The selector chooses whether the second segment is the reverse direction;
//! the rest becomes a handshake record split over two TCP segments. The input
//! is decoded through one session so the fragment buffer is exercised.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::{DecodeSession, DEFAULT_STATE_BUDGET};

const CLIENT: [u8; 4] = [192, 0, 2, 1];
const SERVER: [u8; 4] = [192, 0, 2, 2];

fn frame(number: u64, source: [u8; 4], destination: [u8; 4], source_port: u16, destination_port: u16, sequence: u32, payload: &[u8]) -> Frame {
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&(sequence as u32).to_be_bytes());
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.push(0x50);
    segment.push(0x18);
    segment.extend_from_slice(&65_535_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);

    let total = u16::try_from(20_usize.saturating_add(segment.len())).unwrap_or(u16::MAX);
    let mut datagram = vec![0x45, 0];
    datagram.extend_from_slice(&total.to_be_bytes());
    datagram.extend_from_slice(&0_u16.to_be_bytes());
    datagram.extend_from_slice(&0x4000_u16.to_be_bytes());
    datagram.push(64);
    datagram.push(6);
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(&source);
    datagram.extend_from_slice(&destination);
    datagram.extend_from_slice(&segment);

    let mut captured = Vec::with_capacity(14 + datagram.len());
    captured.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
    captured.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    captured.extend_from_slice(&0x0800_u16.to_be_bytes());
    captured.extend_from_slice(&datagram);
    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured,
        original_len: u32::try_from(14_usize.saturating_add(datagram.len())).unwrap_or(u32::MAX),
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: None,
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: packetfin_core::capture::PacketOptions::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    if payload.is_empty() {
        return;
    }
    let body_length = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&body_length.to_be_bytes());
    record.extend_from_slice(payload);
    let split = (record.len() / 2).max(1).min(record.len());
    let first = record.get(..split).unwrap_or(&[]);
    let second = record.get(split..).unwrap_or(&[]);
    let reverse = selector & 1 != 0;
    let first_frame = frame(
        1,
        CLIENT,
        SERVER,
        40_000,
        443,
        1000,
        first,
    );
    let second_frame = if reverse {
        frame(2, SERVER, CLIENT, 443, 40_000, 5000, second)
    } else {
        frame(
            2,
            CLIENT,
            SERVER,
            40_000,
            443,
            1000_u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            second,
        )
    };
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut rendered = 0_usize;
    for frame in [first_frame, second_frame] {
        let packet = session.decode(&frame);
        for field in packet.tree.fields() {
            rendered =
                rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
        }
    }
    assert!(session.budget_used() <= DEFAULT_STATE_BUDGET);
    let _ = (rendered, session);
});
