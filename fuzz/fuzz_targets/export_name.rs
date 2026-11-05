#![no_main]

//! Fuzz the measured object naming rules directly.
//!
//! The selector picks a URI, a Content-Type fallback, or a missing
//! Content-Type; the rest of the input is the name bytes. Every result must
//! be one ASCII path component, at most 255 bytes, never `.` or `..`, and
//! every collision candidate must keep those invariants.

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use packetfin_core::export::{MAX_OBJECT_NAME_BYTES, ObjectName};

fn check(name: &ObjectName) {
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
    for index in [1, 2, 9, 999] {
        let candidate = name.with_collision(index);
        assert!(!candidate.is_empty());
        assert!(candidate.len() <= MAX_OBJECT_NAME_BYTES);
        assert!(candidate.bytes().all(|byte| byte.is_ascii()));
        assert!(!candidate.contains('/'));
        assert!(!candidate.contains('\\'));
        assert!(!candidate.contains('\0'));
        assert_eq!(Path::new(&candidate).components().count(), 1);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    match selector % 4 {
        0 => check(&ObjectName::from_request_uri(&text)),
        1 => {
            let frame = u64::from_le_bytes([
                rest.first().copied().unwrap_or(0),
                rest.get(1).copied().unwrap_or(0),
                rest.get(2).copied().unwrap_or(0),
                rest.get(3).copied().unwrap_or(0),
                rest.get(4).copied().unwrap_or(0),
                rest.get(5).copied().unwrap_or(0),
                rest.get(6).copied().unwrap_or(0),
                rest.get(7).copied().unwrap_or(0),
            ]);
            check(&ObjectName::fallback(frame, Some(&text)));
        }
        2 => check(&ObjectName::fallback(0, None)),
        _ => {
            if let Ok(text) = std::str::from_utf8(rest) {
                check(&ObjectName::from_request_uri(text));
            }
        }
    }
});
