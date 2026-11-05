#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::FieldSelection;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::decode_frame;

/// Wrap one link-layer control payload in an Ethernet frame.
const DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
const SOURCE: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let mut captured = Vec::with_capacity(14 + payload.len() + 3);
    captured.extend_from_slice(&DESTINATION);
    captured.extend_from_slice(&SOURCE);
    match selector % 3 {
        0 => {
            captured.extend_from_slice(&0x88cc_u16.to_be_bytes());
            captured.extend_from_slice(payload);
        }
        1 => {
            captured.extend_from_slice(&0x8809_u16.to_be_bytes());
            captured.extend_from_slice(payload);
        }
        _ => {
            let length = u16::try_from(payload.len().saturating_add(3)).unwrap_or(u16::MAX);
            captured.extend_from_slice(&length.to_be_bytes());
            captured.extend_from_slice(&[0x42, 0x42, 0x03]);
            captured.extend_from_slice(payload);
        }
    }
    let frame = Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
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
    };
    let mut packet = decode_frame(&frame);
    let mut rendered = 0_usize;
    for field in packet.tree.fields() {
        rendered =
            rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
    }
    packet
        .tree
        .prune(&FieldSelection::new(packetfin_core::fields::registry().fields()));
    let _ = (rendered, packet.columns, packet.malformed, packet.protocol_stack);
});
