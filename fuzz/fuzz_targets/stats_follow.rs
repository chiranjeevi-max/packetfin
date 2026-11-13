#![no_main]

//! Fuzz the follow sink with arbitrary TCP and UDP payloads.
//!
//! Payloads are fed in arrival order with a wrapping sequence number, so
//! out-of-order fragments, gaps and repeated bytes are all exercised. The
//! target must never panic, hang or exceed the statistics budget.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::stats::{StatsOptions, StatsSet, parse_spec};
use packetfin_core::DecodeSession;

const BUDGET: usize = 64 * 1024;
const MAX_FRAMES: usize = 64;

fn ethernet(payload: &[u8], ethertype: u16) -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ipv4(payload: &[u8], protocol: u8) -> Vec<u8> {
    let mut header = vec![0x45, 0];
    let total = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX);
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&[0, 1, 0x40, 0, 64, protocol, 0, 0]);
    header.extend_from_slice(&[192, 0, 2, 1]);
    header.extend_from_slice(&[198, 51, 100, 2]);
    header.extend_from_slice(payload);
    header
}

fn tcp(sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&40000_u16.to_be_bytes());
    segment.extend_from_slice(&80_u16.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.extend_from_slice(&[0x50, 0x18]);
    segment.extend_from_slice(&65535_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    segment
}

fn udp(payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&6000_u16.to_be_bytes());
    segment.extend_from_slice(&7000_u16.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(u16::MAX).to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    segment
}

fn frame(number: u64, captured: Vec<u8>) -> Frame {
    Frame {
        number,
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
    }
}

fuzz_target!(|data: &[u8]| {
    let specs = [
        "follow,tcp,ascii,0",
        "follow,tcp,hex,0",
        "follow,tcp,raw,0",
        "follow,udp,ascii,0",
        "follow,http,ascii,0",
        "follow,http,raw,0",
    ]
        .into_iter()
        .filter_map(|spec| parse_spec(spec).ok())
        .collect::<Vec<_>>();
    let options = StatsOptions {
        specs,
        budget: BUDGET,
    };
    let mut stats = StatsSet::new(&options);
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut sequence = 1_u32;
    for (index, chunk) in data.chunks(64).take(MAX_FRAMES).enumerate() {
        let number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        let captured = if index % 3 == 0 {
            ethernet(&ipv4(&udp(chunk), 17), 0x0800)
        } else {
            let segment = tcp(sequence, chunk);
            sequence = sequence.wrapping_add(u32::try_from(chunk.len()).unwrap_or(0));
            if index % 5 == 0 {
                sequence = sequence.wrapping_add(chunk.len() as u32);
            }
            ethernet(&ipv4(&segment, 6), 0x0800)
        };
        let frame = frame(number, captured);
        let packet = session.decode_observed(&frame, stats.stream_observer());
        stats.observe(&frame, &packet);
    }
    assert!(stats.budget_used() <= BUDGET);
    let mut output = String::new();
    let _ = stats.finish(&mut output);
    assert!(output.len() < 16 * 1024 * 1024);
});
