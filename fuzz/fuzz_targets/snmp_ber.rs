#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::decode_frame;

/// UDP ports that dispatch to the SNMP decoder.
const PORTS: [u16; 3] = [161, 162, 8161];

fuzz_target!(|data: &[u8]| {
    // The first byte selects the SNMP port; the rest is the UDP payload
    // carried in a minimal Ethernet/IPv4 datagram. The BER reader is reached
    // through the same dispatch path as a captured packet, so its length,
    // depth and element bounds are exercised end to end.
    let (selector, payload) = data
        .split_first()
        .map_or((0, &data[..]), |(selector, rest)| (*selector, rest));
    let port = PORTS
        .get(usize::from(selector) % PORTS.len())
        .copied()
        .unwrap_or(161);
    let Ok(udp_length) = u16::try_from(8_usize.saturating_add(payload.len())) else {
        return;
    };
    let Some(total_length) = u16::try_from(20_usize.saturating_add(usize::from(udp_length)))
        .ok()
    else {
        return;
    };
    if payload.len() > 60_000 {
        return;
    }

    let mut frame = Vec::with_capacity(14 + 20 + usize::from(udp_length));
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&total_length.to_be_bytes());
    frame.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, 17, 0, 0]);
    frame.extend_from_slice(&[192, 0, 2, 1]);
    frame.extend_from_slice(&[198, 51, 100, 2]);
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&udp_length.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);

    let captured = frame;
    let packet = decode_frame(&Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        timestamp_precision: 6,
        original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
        captured,
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: None,
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: Default::default(),
    });
    let mut rendered = 0_usize;
    for field in packet.tree.fields() {
        rendered =
            rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
    }
    let _ = (
        rendered,
        packet.malformed,
        packet.columns,
        packet.protocol_stack,
    );
});
