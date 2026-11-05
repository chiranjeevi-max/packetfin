#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::CaptureReader;

// Drive the gzip, zstd or lz4 source with arbitrary bytes.
//
// The first byte selects the container and the rest is the compressed stream
// after its magic, so every run enters a decompressor even when the fuzzer
// has not yet discovered a valid magic number.
fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let mut stream = Vec::with_capacity(rest.len().saturating_add(4));
    match selector % 3 {
        0 => stream.extend_from_slice(&[0x1f, 0x8b]),
        1 => stream.extend_from_slice(&[0x28, 0xb5, 0x2f, 0xfd]),
        _ => stream.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18]),
    }
    stream.extend_from_slice(rest);
    let Ok(mut reader) = CaptureReader::new(&stream[..]) else {
        return;
    };
    while let Ok(Some(_frame)) = reader.next_frame() {}
});
