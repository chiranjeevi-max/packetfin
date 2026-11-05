#![no_main]

//! Fuzz the DNS and HTTP stat trees with arbitrary payload bytes.
//!
//! The bytes become DNS messages on UDP port 53 and HTTP messages on TCP
//! port 80. The trees must never panic, hang or grow without bound, and the
//! rendered tables stay below the statistics budget.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::stats::{StatsOptions, StatsSet, parse_spec};
use packetfin_core::DecodeSession;

const BUDGET: usize = 64 * 1024;

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

fn udp(payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&40000_u16.to_be_bytes());
    segment.extend_from_slice(&53_u16.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap_or(u16::MAX).to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    segment
}

fn tcp(payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&40001_u16.to_be_bytes());
    segment.extend_from_slice(&80_u16.to_be_bytes());
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.extend_from_slice(&1_u32.to_be_bytes());
    segment.extend_from_slice(&[0x50, 0x18]);
    segment.extend_from_slice(&65535_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    segment
}

fn frame(number: u64, captured: Vec<u8>) -> Frame {
    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000 + i64::try_from(number).unwrap_or(i64::MAX),
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
    let specs = ["dns,tree", "http,tree", "dns,tree,dns.qry.type==1", "http,tree,http.response.code>=400"]
        .into_iter()
        .filter_map(|spec| parse_spec(spec).ok())
        .collect::<Vec<_>>();
    let options = StatsOptions {
        specs,
        budget: BUDGET,
    };
    let mut stats = StatsSet::new(&options);
    let mut session = DecodeSession::new(DecodeOptions::default());
    for (index, chunk) in data.chunks(128).take(64).enumerate() {
        let number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        let captured = if index % 2 == 0 {
            ethernet(&ipv4(&udp(chunk), 17), 0x0800)
        } else {
            ethernet(&ipv4(&tcp(chunk), 6), 0x0800)
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
