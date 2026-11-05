#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::decode_frame;

/// The encapsulations this target feeds with arbitrary payload bytes.
const WRAPPERS: [Wrapper; 7] = [
    Wrapper::Ip(47),
    Wrapper::Ip(4),
    Wrapper::Ip(41),
    Wrapper::Ether(0x8847),
    Wrapper::Ether(0x8848),
    Wrapper::Udp(4789),
    Wrapper::Udp(6081),
];

#[derive(Clone, Copy)]
enum Wrapper {
    Ip(u8),
    Ether(u16),
    Udp(u16),
}

fuzz_target!(|data: &[u8]| {
    let (selector, payload) = data
        .split_first()
        .map_or((0, &data[..]), |(selector, rest)| (*selector, rest));
    let wrapper = WRAPPERS
        .get(usize::from(selector) % WRAPPERS.len())
        .copied()
        .unwrap_or(Wrapper::Ip(47));
    if payload.len() > 60_000 {
        return;
    }
    let inner = match wrapper {
        Wrapper::Udp(port) => {
            let Some(udp_length) = u16::try_from(8_usize.saturating_add(payload.len())).ok() else {
                return;
            };
            let mut segment = Vec::with_capacity(usize::from(udp_length));
            segment.extend_from_slice(&12_345_u16.to_be_bytes());
            segment.extend_from_slice(&port.to_be_bytes());
            segment.extend_from_slice(&udp_length.to_be_bytes());
            segment.extend_from_slice(&[0, 0]);
            segment.extend_from_slice(payload);
            (17, segment, 0x0800)
        }
        Wrapper::Ip(protocol) => (protocol, payload.to_vec(), 0x0800),
        Wrapper::Ether(ethertype) => (0, payload.to_vec(), ethertype),
    };
    let (protocol, payload, ethertype) = inner;
    let mut frame = Vec::with_capacity(14 + 20 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    let Some(total_length) = u16::try_from(20_usize.saturating_add(payload.len())).ok() else {
        return;
    };
    if ethertype == 0x0800 {
        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&total_length.to_be_bytes());
        frame.extend_from_slice(&[0x12, 0x34, 0x40, 0x00, 64, protocol, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[198, 51, 100, 2]);
    }
    frame.extend_from_slice(&payload);

    let frame = Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured: frame,
        original_len: u32::try_from(14 + 20 + payload.len()).unwrap_or(u32::MAX),
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
    let _ = (
        packet.protocol_stack,
        packet.malformed,
        packet.columns,
        packet.tree.fields().count(),
    );
});
