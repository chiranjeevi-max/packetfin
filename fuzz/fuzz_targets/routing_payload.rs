#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::decode_frame;

/// Routing payload selectors: OSPFv2, OSPFv3, VRRP over IPv4, VRRP over
/// IPv6, BFD control over UDP and BFD echo over UDP.
const SELECTORS: usize = 6;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let selector = usize::from(*selector) % SELECTORS;
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    match selector {
        0 | 2 => {
            frame.extend_from_slice(&0x0800_u16.to_be_bytes());
            let protocol = if selector == 0 { 89 } else { 112 };
            let total = 20_u16
                .saturating_add(u16::try_from(payload.len()).unwrap_or(u16::MAX));
            let header = [
                0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, protocol, 0, 0, 192, 0, 2, 1, 198, 51,
                100, 2,
            ];
            frame.extend_from_slice(&header);
            set_u16(&mut frame, 16, total);
            frame.extend_from_slice(payload);
        }
        1 | 3 => {
            frame.extend_from_slice(&0x86dd_u16.to_be_bytes());
            let next_header = if selector == 1 { 89 } else { 112 };
            let length = u16::try_from(payload.len()).unwrap_or(u16::MAX);
            frame.extend_from_slice(&0x6000_0000_u32.to_be_bytes());
            frame.extend_from_slice(&length.to_be_bytes());
            frame.push(next_header);
            frame.push(64);
            frame.extend_from_slice(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]);
            frame.extend_from_slice(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            ]);
            frame.extend_from_slice(payload);
        }
        _ => {
            frame.extend_from_slice(&0x0800_u16.to_be_bytes());
            let port: u16 = if selector == 4 { 3784 } else { 3785 };
            let mut udp = Vec::new();
            udp.extend_from_slice(&49_152_u16.to_be_bytes());
            udp.extend_from_slice(&port.to_be_bytes());
            udp.extend_from_slice(
                &u16::try_from(8_usize.saturating_add(payload.len()))
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            udp.extend_from_slice(&[0, 0]);
            udp.extend_from_slice(payload);
            let total = 20_u16
                .saturating_add(u16::try_from(udp.len()).unwrap_or(u16::MAX));
            let header = [
                0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100,
                2,
            ];
            frame.extend_from_slice(&header);
            set_u16(&mut frame, 16, total);
            frame.extend_from_slice(&udp);
        }
    }
    let frame = Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        original_len: u32::try_from(frame.len()).unwrap_or(u32::MAX),
        captured: frame,
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
    let _ = (packet.columns, packet.malformed, packet.protocol_stack);
});

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    let value = value.to_be_bytes();
    if let Some(slot) = bytes.get_mut(offset..offset + 2) {
        slot.copy_from_slice(&value);
    }
}
