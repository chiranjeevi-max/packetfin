#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::Filter;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode_frame;

/// Ethernet/IPv4/UDP frame with a one-byte payload.
///
/// The target parses arbitrary bytes as a display filter and evaluates the
/// result against this decoded packet. Malformed expressions must return an
/// error; a valid expression must never panic or hang.
const CAPTURED: [u8; 43] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 0, 2, 1, 198, 51, 100, 2,
    0x30, 0x39, 0x27, 0x0f, 0x00, 0x09, 0x00, 0x00, 0xde,
];

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let frame = Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured: CAPTURED.to_vec(),
        original_len: u32::try_from(CAPTURED.len()).unwrap_or(u32::MAX),
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: None,
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: Default::default(),
    };
    let packet = decode_frame(&frame);
    if let Ok(filter) = Filter::parse(text) {
        let _ = filter.matches(&packet.tree);
    }
});
