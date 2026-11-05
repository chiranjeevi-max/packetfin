#![no_main]

//! Fuzz HTTP body discovery, object naming and the sink contract.
//!
//! The input is one TCP payload placed on port 80 in both directions through
//! one decode session, so requests, responses and their association all run.
//! The recording sink rejects a name that is not exactly one safe path
//! component and a body above the export cap.

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::DecodeOptions;
use packetfin_core::export::{
    MAX_EXPORT_OBJECT_BYTES, MAX_OBJECT_NAME_BYTES, ObjectName, ObjectSink,
};
use packetfin_core::{DEFAULT_STATE_BUDGET, DecodeSession};

#[derive(Default)]
struct RecordingSink {
    written: u64,
    committed: u64,
    aborted: u64,
}

impl ObjectSink for RecordingSink {
    fn begin(&mut self, name: &ObjectName, _expected: Option<u64>) -> bool {
        let text = name.as_str();
        assert!(!text.is_empty());
        assert!(text.len() <= MAX_OBJECT_NAME_BYTES);
        assert!(text.bytes().all(|byte| byte.is_ascii()));
        assert!(!text.contains('/'));
        assert!(!text.contains('\\'));
        assert!(!text.contains('\0'));
        assert_ne!(text, ".");
        assert_ne!(text, "..");
        assert_eq!(Path::new(text).components().count(), 1);
        true
    }

    fn write(&mut self, data: &[u8]) {
        self.written = self.written.saturating_add(data.len() as u64);
        assert!(self.written <= MAX_EXPORT_OBJECT_BYTES);
    }

    fn commit(&mut self) {
        self.committed = self.committed.saturating_add(1);
    }

    fn abort(&mut self) {
        self.aborted = self.aborted.saturating_add(1);
    }
}

fn frame(number: u64, sequence: u32, payload: &[u8], to_server: bool, fin: bool) -> Frame {
    let (source, destination, source_port, destination_port) = if to_server {
        ([10, 0, 0, 1], [10, 0, 0, 2], 40_000_u16, 80_u16)
    } else {
        ([10, 0, 0, 2], [10, 0, 0, 1], 80_u16, 40_000_u16)
    };
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&0_u32.to_be_bytes());
    segment.extend_from_slice(&[0x50, 0x18 | u8::from(fin)]);
    segment.extend_from_slice(&0xffff_u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);

    let total = u16::try_from(20_usize.saturating_add(segment.len())).unwrap_or(u16::MAX);
    let mut datagram = vec![0x45, 0];
    datagram.extend_from_slice(&total.to_be_bytes());
    datagram.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
    datagram.extend_from_slice(&source);
    datagram.extend_from_slice(&destination);
    datagram.extend_from_slice(&segment);

    let mut captured = Vec::with_capacity(14 + datagram.len());
    captured.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    captured.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    captured.extend_from_slice(&0x0800_u16.to_be_bytes());
    captured.extend_from_slice(&datagram);

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
        options: packetfin_core::capture::PacketOptions::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut session = DecodeSession::with_budget(DecodeOptions::default(), DEFAULT_STATE_BUDGET);
    session.set_object_sink(Box::new(RecordingSink::default()));
    // A request direction and a response direction over the same tuple let
    // the state-based naming path run with arbitrary message bodies. The
    // selector splits each payload into 1-4 sequential segments, so message
    // headers and bodies exercise cross-segment reassembly and continuation
    // handling as well as the single-segment path.
    let (selector, payload) = data.split_first().unwrap_or((&0, &[]));
    let parts = 1 + usize::from(*selector % 4);
    let fin_last = *selector & 0x08 != 0;
    let mut number = 1_u64;
    for to_server in [true, false] {
        let mut sequence = 1000_u32;
        for part in 0..parts {
            let start = payload.len().saturating_mul(part) / parts;
            let end = payload.len().saturating_mul(part + 1) / parts;
            let chunk = payload.get(start..end).unwrap_or_default();
            let fin = fin_last && part + 1 == parts;
            let _ = session.decode(&frame(number, sequence, chunk, to_server, fin));
            number = number.saturating_add(1);
            sequence = sequence.saturating_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        }
    }
});
