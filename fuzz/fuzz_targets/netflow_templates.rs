#![no_main]

//! Fuzz the NetFlow v9 and IPFIX template parser and its bounded cache.
//!
//! Input starts with an exporter selector, followed by length-prefixed
//! datagram payloads. Each payload is wrapped in Ethernet/IPv4/UDP and
//! decoded through one session, so templates defined by one datagram are
//! visible to the next datagrams of the same exporter, while the selector
//! changes the exporter address and source port to exercise cache misses.

use libfuzzer_sys::fuzz_target;
use packetfin_core::DEFAULT_STATE_BUDGET;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::DecodeSession;

const MAX_FRAMES: usize = 64;
const SMALL_BUDGET: usize = 4 * 1024;

const EXPORTERS: [([u8; 4], u16); 4] = [
    ([192, 0, 2, 1], 40_000),
    ([192, 0, 2, 1], 40_001),
    ([203, 0, 113, 9], 40_000),
    ([203, 0, 113, 10], 40_002),
];

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let (source, source_port) = EXPORTERS[usize::from(*selector) % EXPORTERS.len()];

    let mut frames = Vec::new();
    let mut offset = 0;
    while frames.len() < MAX_FRAMES && offset + 2 <= rest.len() {
        let Some(prefix) = rest.get(offset..offset + 2) else {
            break;
        };
        let Ok(prefix) = <[u8; 2]>::try_from(prefix) else {
            break;
        };
        let length = usize::from(u16::from_be_bytes(prefix));
        offset += 2;
        if length == 0 || offset + length > rest.len() {
            break;
        }
        let Some(payload) = rest.get(offset..offset + length) else {
            break;
        };
        offset += length;
        let version = payload
            .get(..2)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(u16::from_be_bytes);
        let destination_port = if version == Some(10) { 4739 } else { 2055 };
        frames.push((source, source_port, destination_port, payload.to_vec()));
    }

    let mut default_session = DecodeSession::new(DecodeOptions::default());
    let mut small_session = DecodeSession::with_budget(DecodeOptions::default(), SMALL_BUDGET);
    for (index, (source, source_port, destination_port, payload)) in frames.iter().enumerate() {
        let frame = frame(
            u64::try_from(index).unwrap_or(u64::MAX) + 1,
            *source,
            *source_port,
            *destination_port,
            payload,
        );
        let mut packet = default_session.decode(&frame);
        for field in packet.tree.fields() {
            let _ = field.value.formatted(field.def.display).to_string();
        }
        packet.tree.prune(&packetfin_core::FieldSelection::new(
            packetfin_core::fields::registry().fields(),
        ));
        let small = small_session.decode(&frame);
        for field in small.tree.fields() {
            let _ = field.value.formatted(field.def.display).to_string();
        }
        assert!(small_session.budget_used() <= SMALL_BUDGET);
        assert!(default_session.budget_used() <= DEFAULT_STATE_BUDGET);
    }
});

fn frame(
    number: u64,
    source: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Frame {
    let mut captured = Vec::with_capacity(42 + payload.len());
    captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    captured.extend_from_slice(&0x0800_u16.to_be_bytes());

    let ip_start = captured.len();
    captured.extend_from_slice(&[0x45, 0]);
    let total = u16::try_from(20 + 8 + payload.len()).unwrap_or(u16::MAX);
    captured.extend_from_slice(&total.to_be_bytes());
    captured.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    captured.extend_from_slice(&source);
    captured.extend_from_slice(&[198, 51, 100, 2]);
    let checksum = internet_checksum(captured.get(ip_start..ip_start + 20).unwrap_or(&[]));
    captured[ip_start + 10..ip_start + 12].copy_from_slice(&checksum.to_be_bytes());

    captured.extend_from_slice(&source_port.to_be_bytes());
    captured.extend_from_slice(&destination_port.to_be_bytes());
    let udp_length = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    captured.extend_from_slice(&udp_length.to_be_bytes());
    captured.extend_from_slice(&[0, 0]);
    captured.extend_from_slice(payload);

    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured,
        original_len: u32::try_from(42 + payload.len()).unwrap_or(u32::MAX),
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: None,
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: Default::default(),
    }
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*chunk)));
    }
    if let [last] = remainder {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}
