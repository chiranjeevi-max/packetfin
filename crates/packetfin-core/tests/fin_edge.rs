//! FIN completion boundary cases: gaps, tails and illegal-segment tags.
//!
//! The `http-objects-fin-edge` fixture is the generated reference capture for
//! these shapes; the export manifest pins the names and bodies.

use std::fs;

use packetfin_core::decode::DecodeOptions;
use packetfin_core::{DecodeSession, Value};
use packetfin_testkit::fixtures;
use packetfin_testkit::golden;

fn frames(name: &str) -> Result<Vec<packetfin_core::capture::Frame>, String> {
    let fixture = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| format!("fixture {name} is not registered"))?;
    let path = golden::fixtures_dir().join(fixture.file_name());
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut reader = packetfin_core::capture::CaptureReader::new(std::io::Cursor::new(bytes))
        .map_err(|error| format!("CaptureReader::new failed: {error}"))?;
    let mut frames = Vec::new();
    while let Some(frame) = reader
        .next_frame()
        .map_err(|error| format!("next_frame failed: {error}"))?
    {
        frames.push(frame);
    }
    Ok(frames)
}

#[test]
fn only_a_conflicting_overlap_marks_illegal_segments() -> Result<(), String> {
    let frames = frames("http-objects-fin-edge")?;
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut tagged = Vec::new();
    let mut errors = Vec::new();
    for frame in &frames {
        let packet = session.decode(frame);
        let error_fields = packet
            .tree
            .field_values("tcp.segment.error")
            .into_iter()
            .filter(|value| matches!(value, Value::Uint32(_)))
            .count();
        if error_fields > 0 {
            errors.push((packet.columns.number, error_fields));
        }
        if packet
            .columns
            .info
            .as_deref()
            .is_some_and(|info| info.contains("[Illegal Segments]"))
        {
            tagged.push(packet.columns.number);
        }
    }
    assert_eq!(
        errors.len(),
        1,
        "exactly the conflicting overlap carries tcp.segment.error: {errors:?}"
    );
    assert_eq!(
        tagged.len(),
        1,
        "exactly the conflicting overlap is tagged: {tagged:?}"
    );
    assert_eq!(tagged.first(), errors.first().map(|(number, _)| number));
    Ok(())
}

#[test]
fn a_truncated_chunk_still_exports_its_complete_prefix() -> Result<(), String> {
    let frames = frames("http-objects-fin-edge")?;
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut bodies = Vec::new();
    for frame in &frames {
        let packet = session.decode(frame);
        for value in packet.tree.field_values("http.file_data") {
            if let Value::Bytes(bytes) = value {
                bodies.push(bytes.clone());
            }
        }
    }
    assert!(
        bodies.iter().any(|body| body == b"hello"),
        "the complete chunk prefix is file data"
    );
    assert!(
        !bodies.iter().any(|body| body == b"hel"),
        "the incomplete chunk is not exported"
    );
    Ok(())
}
