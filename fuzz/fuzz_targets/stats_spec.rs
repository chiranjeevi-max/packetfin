#![no_main]

//! Fuzz `-z` specification parsing and one bounded statistics run.
//!
//! A parsed specification is fed two frames through a [`StatsSet`] with a
//! tiny budget, then every table is rendered into a discarded string. The
//! target must never panic, exceed the budget, or print an unbounded table.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::decode_frame;
use packetfin_core::stats::{StatsOptions, StatsSet, parse_spec};

const BUDGET: usize = 4 * 1024;

fn frame(number: u64, nanos: u32) -> Frame {
    let mut captured = Vec::new();
    captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    captured.extend_from_slice(&0x0800_u16.to_be_bytes());
    captured.extend_from_slice(&[0x45, 0, 0, 36, 0, 1, 0x40, 0, 64, 17, 0, 0]);
    captured.extend_from_slice(&[192, 0, 2, 1]);
    captured.extend_from_slice(&[198, 51, 100, 2]);
    captured.extend_from_slice(&[0x04, 0xd2, 0x08, 0xae]);
    captured.extend_from_slice(&8_u16.to_be_bytes());
    captured.extend_from_slice(&[0, 0]);
    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos,
        }),
        timestamp_precision: 6,
        captured,
        original_len: 42,
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
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Some(text) = text.get(..text.len().min(4096)) else {
        return;
    };
    let Ok(spec) = parse_spec(text) else {
        return;
    };
    let options = StatsOptions {
        specs: vec![spec],
        budget: BUDGET,
    };
    let mut statistics = StatsSet::new(&options);
    for (index, nanos) in [0_u32, 10_000_000].into_iter().enumerate() {
        let number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        let frame = frame(number, nanos);
        let packet = decode_frame(&frame);
        statistics.observe(&frame, &packet);
    }
    assert!(statistics.budget_used() <= BUDGET);
    let mut output = String::new();
    let _ = statistics.finish(&mut output);
    assert!(output.len() < 16 * 1024 * 1024);
});
