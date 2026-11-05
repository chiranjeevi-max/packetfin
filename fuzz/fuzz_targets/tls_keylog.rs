#![no_main]

//! Fuzz the NSS key-log parser.
//!
//! Every input is a whole key-log file prefix. The loader is bounded, so the
//! target additionally exercises the line and entry caps with large inputs.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packetfin_core::KeyLog;

fuzz_target!(|data: &[u8]| {
    let log = KeyLog::read(Cursor::new(data));
    let _ = (log.len(), log.truncated(), log.skipped(), log.bytes_read());
});
