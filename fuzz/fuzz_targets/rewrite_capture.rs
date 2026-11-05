#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::capture::{
    CaptureReader, CaptureWriter, Compression, OutputFormat, Resolution, WriterOptions,
};

fuzz_target!(|data: &[u8]| {
    // Every CLI-independent writer path: the three formats, the two
    // compression sinks and a capture comment. The reader below sniffs the
    // compressed output, so this also exercises decompression.
    let comments = ["fuzz comment".to_string()];
    let cases = [
        (OutputFormat::PcapNg, Compression::None),
        (OutputFormat::Pcap(Resolution::Microsecond), Compression::None),
        (OutputFormat::NsecPcap, Compression::None),
        (OutputFormat::PcapNg, Compression::Gzip),
        (OutputFormat::PcapNg, Compression::Lz4),
    ];
    for (format, compression) in cases {
        let Ok(mut reader) = CaptureReader::new(data) else {
            continue;
        };
        let mut writer = CaptureWriter::new(
            Vec::new(),
            WriterOptions {
                format,
                compression,
                application: "packetfin-fuzz",
                capture_comments: &comments,
            },
        );
        let mut complete = true;
        while let Ok(Some(event)) = reader.next_event() {
            if writer.observe(&event).is_err() {
                complete = false;
                break;
            }
        }
        if complete {
            complete = writer.finish().is_ok();
        } else {
            let _ = writer.finish();
        }
        let Ok(output) = writer.into_inner() else {
            continue;
        };
        if complete {
            let mut round_trip = CaptureReader::new(output.as_slice())
                .expect("a completed rewrite must have a readable header");
            loop {
                match round_trip.next_frame() {
                    Ok(Some(_frame)) => {}
                    Ok(None) => break,
                    Err(error) => panic!("completed rewrite is unreadable: {error}"),
                }
            }
        }
    }
});
