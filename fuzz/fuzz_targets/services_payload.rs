#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{
    DecodeOptions, Preferences, decode_frame, decode_frame_with_options,
};

/// Service port pairs dispatched to DHCP, NTP and DHCPv6.
const PORTS: [(u16, u16); 5] = [
    (67, 68),
    (68, 67),
    (123, 123),
    (546, 547),
    (547, 546),
];

fuzz_target!(|data: &[u8]| {
    let (selector, payload) = match data.split_first() {
        Some((selector, rest)) => (*selector, rest),
        None => (0, data),
    };
    let (source_port, destination_port) = PORTS
        .get(usize::from(selector) % PORTS.len())
        .copied()
        .unwrap_or((123, 123));

    let mut udp = Vec::with_capacity(8 + payload.len());
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

    let mut frame_bytes = Vec::with_capacity(14 + ip.len());
    frame_bytes.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame_bytes.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame_bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame_bytes.extend_from_slice(&ip);

    let frame = Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured: frame_bytes.clone(),
        original_len: u32::try_from(frame_bytes.len()).unwrap_or(u32::MAX),
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
    let mut rendered = 0_usize;
    for field in packet.tree.fields() {
        rendered =
            rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
    }
    let validated = decode_frame_with_options(
        &frame,
        DecodeOptions {
            preferences: Preferences {
                udp_check_checksum: true,
                ..Preferences::default()
            },
            ..DecodeOptions::default()
        },
    );
    let _ = (
        rendered,
        validated.malformed,
        packet.malformed,
        packet.columns,
        packet.protocol_stack,
    );
});
