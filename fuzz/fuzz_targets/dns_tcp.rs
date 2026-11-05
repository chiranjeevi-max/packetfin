#![no_main]

//! Fuzz DNS over TCP framing and its transaction state.
//!
//! The selector picks the service port; the rest is the TCP payload. Two
//! frames are decoded through one session so retransmission and response
//! matching state sees a second message.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{DecodeOptions, decode_frame_with_options};
use packetfin_core::{DecodeSession, DEFAULT_STATE_BUDGET};

const PORTS: [u16; 4] = [53, 5353, 853, 9999];

fn frame(number: u64, payload: &[u8], destination_port: u16) -> Frame {
    let length = u16::try_from(8_usize.saturating_add(payload.len())).unwrap_or(u16::MAX);
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&40_000_u16.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&length.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);

    let total = u16::try_from(20_usize.saturating_add(segment.len())).unwrap_or(u16::MAX);
    let mut datagram = vec![0x45, 0];
    datagram.extend_from_slice(&total.to_be_bytes());
    datagram.extend_from_slice(&0_u16.to_be_bytes());
    datagram.extend_from_slice(&0x4000_u16.to_be_bytes());
    datagram.push(64);
    datagram.push(6);
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(&[192, 0, 2, 1]);
    datagram.extend_from_slice(&[192, 0, 2, 2]);
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
    let port = PORTS
        .get(usize::from(*selector) % PORTS.len())
        .copied()
        .unwrap_or(53);
    let first = frame(1, payload, port);
    let second = frame(2, payload, port);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut rendered = 0_usize;
    for frame in [first, second] {
        let packet = session.decode(&frame);
        for field in packet.tree.fields() {
            rendered =
                rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
        }
        let validated = decode_frame_with_options(
            &frame,
            DecodeOptions {
                preferences: packetfin_core::decode::Preferences {
                    tcp_check_checksum: true,
                    ..packetfin_core::decode::Preferences::default()
                },
                ..DecodeOptions::default()
            },
        );
        for field in validated.tree.fields() {
            rendered =
                rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
        }
    }
    assert!(session.budget_used() <= DEFAULT_STATE_BUDGET);
    let _ = (rendered, session);
});
