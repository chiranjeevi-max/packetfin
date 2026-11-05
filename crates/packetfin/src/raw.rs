//! Byte lookup for protocol-tree ranges.
//!
//! Most ranges refer to the captured frame. Decrypted TLS content uses a
//! one-based data-source index carried by `Range::source`; the buffers live in
//! `Packet::data_sources`. PDML, JSON and EK share this lookup so all three
//! report the same plaintext bytes.

use packetfin_core::tree::Bytes;
use packetfin_core::{Frame, Range};

/// The buffer a range source refers to.
pub(crate) fn source_bytes<'a>(frame: &'a Frame, sources: &'a [Bytes], source: u32) -> &'a [u8] {
    if source == 0 {
        return frame.captured.as_slice();
    }
    sources
        .get(
            usize::try_from(source)
                .unwrap_or(usize::MAX)
                .saturating_sub(1),
        )
        .map_or(&[][..], |bytes| bytes.as_slice())
}

/// The bytes a range covers in its own data source.
pub(crate) fn raw_bytes<'a>(frame: &'a Frame, sources: &'a [Bytes], range: Range) -> &'a [u8] {
    let bytes = source_bytes(frame, sources, range.source);
    let end = range.offset.saturating_add(range.length).min(bytes.len());
    bytes.get(range.offset..end).unwrap_or(&[])
}

/// The buffer a source refers to when the frame bytes are already borrowed.
pub(crate) fn source_len(captured: &[u8], sources: &[Bytes], source: u32) -> usize {
    if source == 0 {
        captured.len()
    } else {
        sources
            .get(
                usize::try_from(source)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(1),
            )
            .map_or(0, Bytes::len)
    }
}

/// The bytes a range covers without borrowing a `Frame`.
pub(crate) fn raw_bytes_from<'a>(
    captured: &'a [u8],
    sources: &'a [Bytes],
    range: Range,
) -> &'a [u8] {
    let bytes = if range.source == 0 {
        captured
    } else {
        sources
            .get(
                usize::try_from(range.source)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(1),
            )
            .map_or(&[][..], |bytes| bytes.as_slice())
    };
    let end = range.offset.saturating_add(range.length).min(bytes.len());
    bytes.get(range.offset..end).unwrap_or(&[])
}

/// Bytes from an explicit source, start and length without a `Frame`.
pub(crate) fn range_bytes_from<'a>(
    captured: &'a [u8],
    sources: &'a [Bytes],
    source: u32,
    start: usize,
    length: usize,
) -> Option<&'a [u8]> {
    let bytes = if source == 0 {
        captured
    } else {
        sources
            .get(
                usize::try_from(source)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(1),
            )
            .map_or(&[][..], |bytes| bytes.as_slice())
    };
    let end = start.checked_add(length)?;
    bytes.get(start..end)
}

/// Bytes for a field, preferring its explicit source and falling back to the
/// enclosing node's reassembled source (used by fragment reassembly).
pub(crate) fn raw_bytes_with_node<'a>(
    frame: &'a Frame,
    sources: &'a [Bytes],
    node_source: Option<&'a [u8]>,
    range: Range,
) -> &'a [u8] {
    if range.source == 0
        && let Some(bytes) = node_source
    {
        let end = range.offset.saturating_add(range.length).min(bytes.len());
        return bytes.get(range.offset..end).unwrap_or(&[]);
    }
    raw_bytes(frame, sources, range)
}
