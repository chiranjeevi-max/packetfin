#![no_main]

//! Fuzz the HTTP/2 frame and HPACK decoders.
//!
//! Input is raw connection bytes: the client preface followed by any number of
//! frames, exactly as they appear on the wire. The bytes ride one TCP segment
//! to port 80, so the stream layer frames them and the connection state is
//! exercised across every frame in the input.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{DecodeOptions, Preferences, decode_frame, decode_frame_with_options};

/// Port the cleartext heuristic is registered on.
const PORT: u16 = 80;

fn frame(payload: &[u8]) -> Frame {
    let length = u16::try_from(8_usize.saturating_add(payload.len())).unwrap_or(u16::MAX);
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&40_000_u16.to_be_bytes());
    segment.extend_from_slice(&PORT.to_be_bytes());
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
        number: 1,
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
    let frame = frame(data);
    let mut rendered = 0_usize;
    let packet = decode_frame(&frame);
    for field in packet.tree.fields() {
        rendered =
            rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
    }
    // The same bytes with checksum validation on cover the second decode path.
    let validated = decode_frame_with_options(
        &frame,
        DecodeOptions {
            preferences: Preferences {
                tcp_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    std::hint::black_box((rendered, validated.tree.fields().count()));
});
