#![no_main]

//! Fuzz one capture's frames through one stateful decode session.
//!
//! Input is a link-type selector followed by length-prefixed frames. The same
//! frames are decoded under the default budget and under a 4 KiB budget; the
//! 4 KiB session must never exceed its limit, and neither session may panic.

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::stats::{StatsOptions, StatsSet, parse_spec};
use packetfin_core::{
    DecodeSession, PassMode, RenumberMap, DEFAULT_STATE_BUDGET, apply_annotations,
};

/// Link types the decoder registers, plus one unknown value.
const LINK_TYPES: [u32; 7] = [1, 0, 108, 101, 113, 276, 999];
const SMALL_BUDGET: usize = 4 * 1024;
const SMALL_ANNOTATION_BUDGET: usize = 4 * 1024;
const MAX_FRAMES: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let link_type = LINK_TYPES
        .get(usize::from(*selector) % LINK_TYPES.len())
        .copied()
        .unwrap_or(1);

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
        let Some(captured) = rest.get(offset..offset + length) else {
            break;
        };
        offset += length;
        frames.push(captured.to_vec());
    }

    let stats_specs = [
        "io,phs",
        "io,stat,1",
        "conv,tcp",
        "conv,udp",
        "conv,eth",
        "endpoints,ip",
        "expert",
        "dns,tree",
        "http,tree",
        "follow,tcp,ascii,0",
        "follow,udp,hex,0",
        "follow,http,raw,0",
    ]
        .into_iter()
        .filter_map(|spec| parse_spec(spec).ok())
        .collect::<Vec<_>>();
    let stats_options = StatsOptions {
        specs: stats_specs,
        budget: SMALL_BUDGET,
    };
    let mut statistics = StatsSet::new(&stats_options);

    let mut default_session = DecodeSession::new(DecodeOptions::default());
    let mut small_session = DecodeSession::with_budget(DecodeOptions::default(), SMALL_BUDGET);
    let mut rendered = 0_usize;
    for (index, captured) in frames.iter().enumerate() {
        let frame = Frame {
            number: u64::try_from(index).unwrap_or(u64::MAX) + 1,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_000,
            }),
            timestamp_precision: 6,
            captured: captured.clone(),
            original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
            link_type,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: None,
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: Default::default(),
        };
        let packet = default_session.decode_observed(&frame, statistics.stream_observer());
        statistics.observe(&frame, &packet);
        for field in packet.tree.fields() {
            rendered =
                rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
        }
        let small = small_session.decode(&frame);
        for field in small.tree.fields() {
            rendered =
                rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
        }
        assert!(small_session.budget_used() <= SMALL_BUDGET);
    }

    assert!(default_session.budget_used() <= DEFAULT_STATE_BUDGET);
    assert!(statistics.budget_used() <= SMALL_BUDGET);
    let mut stats_output = String::new();
    let _ = statistics.finish(&mut stats_output);
    assert!(stats_output.len() < 16 * 1024 * 1024);
    let _ = (rendered, default_session, small_session, statistics);

    replay_two_pass(link_type, &frames);
});

/// Replay the same frames as a two-pass run with a small annotation budget.
///
/// The recording pass must stay inside its budget, the output pass must
/// accept every annotation without panicking, and a zero annotation budget
/// must simply produce no links.
fn replay_two_pass(link_type: u32, frames: &[Vec<u8>]) {
    for annotation_budget in [0, SMALL_ANNOTATION_BUDGET] {
        let mut recording = DecodeSession::with_budgets(
            DecodeOptions::default(),
            DEFAULT_STATE_BUDGET,
            annotation_budget,
            PassMode::First,
        );
        for (index, captured) in frames.iter().enumerate() {
            let frame = captured_frame(link_type, index, captured);
            let _ = recording.decode(&frame);
        }
        recording.finish_pass();
        assert!(recording.annotations_used() <= annotation_budget);
        let annotations = recording.into_annotations();
        let renumber = RenumberMap::new(1..=u64::try_from(frames.len()).unwrap_or(u64::MAX));

        let mut output = DecodeSession::with_budgets(
            DecodeOptions::default(),
            DEFAULT_STATE_BUDGET,
            annotation_budget,
            PassMode::Second,
        );
        for (index, captured) in frames.iter().enumerate() {
            let mut frame = captured_frame(link_type, index, captured);
            frame.number = u64::try_from(index).unwrap_or(u64::MAX) + 1;
            let file_number = frame.number;
            let mut packet = output.decode(&frame);
            if let Some(annotation) = annotations.get(file_number) {
                apply_annotations(&mut packet, annotation, &renumber);
            }
            for field in packet.tree.fields() {
                let _ = field.value.formatted(field.def.display).to_string();
            }
        }
        assert!(output.annotations_used() <= annotation_budget);
    }
}

fn captured_frame(link_type: u32, index: usize, captured: &[u8]) -> Frame {
    Frame {
        number: u64::try_from(index).unwrap_or(u64::MAX) + 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured: captured.to_vec(),
        original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
        link_type,
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
