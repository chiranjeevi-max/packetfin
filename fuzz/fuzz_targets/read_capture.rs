#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::CaptureReader;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = CaptureReader::new(data) else {
        return;
    };
    while let Ok(Some(_frame)) = reader.next_frame() {}
});
