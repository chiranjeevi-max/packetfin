//! Deterministic compression helpers for generated fixtures.
//!
//! gzip and lz4 use their pure-Rust encoders. zstd frames are assembled by
//! hand from RFC 8878 raw and RLE blocks so the fixture builder stays
//! dependency-free and can produce exact edge cases (an oversized window
//! descriptor, an RLE bomb) that an encoder would not emit.

use std::io::Write as _;

use flate2::{Compression, GzBuilder};

/// zstd's frame magic, little-endian on the wire.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
/// Largest zstd block: 128 KiB, independent of the frame window.
const ZSTD_BLOCK: usize = 128 * 1024;

/// One complete gzip member containing `data`.
///
/// The header carries mtime 0 so repeated builds are byte-identical.
pub fn gzip_member(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .map_err(|error| format!("gzip member: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("gzip member: {error}"))
}

/// One gzip member whose payload is `prefix` followed by `zero_bytes` zero
/// bytes, written without materialising the expansion.
pub fn gzip_bomb(prefix: &[u8], zero_bytes: u64) -> Result<Vec<u8>, String> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder
        .write_all(prefix)
        .map_err(|error| format!("gzip bomb: {error}"))?;
    write_zeros(&mut encoder, zero_bytes, "gzip bomb")?;
    encoder
        .finish()
        .map_err(|error| format!("gzip bomb: {error}"))
}

/// One complete lz4 frame containing `data`.
pub fn lz4_frame(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
    encoder
        .write_all(data)
        .map_err(|error| format!("lz4 frame: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("lz4 frame: {error}"))
}

/// One skippable frame with an opaque payload.
///
/// RFC 8878 section 3.1.2 and the lz4 frame format share the magic range
/// `0x184D2A50`–`0x184D2A5F`; `id` selects the low nibble and the size is the
/// little-endian payload length.
pub fn skippable_frame(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.push(0x50 | (id & 0x0f));
    frame.extend_from_slice(&[0x2a, 0x4d, 0x18]);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// One complete zstd frame containing `data` as raw blocks.
///
/// The frame has no content size and no checksum, so it stays readable as a
/// pure stream. A 128 KiB window matches the maximum block size.
pub fn zstd_frame(data: &[u8]) -> Vec<u8> {
    zstd_frame_with_checksum(data, false)
}

/// A zstd frame carrying the RFC 8878 content checksum: the low 32 bits of
/// XXH64(seed 0) over the uncompressed payload.
pub fn zstd_frame_with_checksum(data: &[u8], checksum: bool) -> Vec<u8> {
    zstd_frame_inner(data, checksum, None)
}

/// A zstd frame whose header declares a four-byte Frame_Content_Size.
///
/// `declared` is written verbatim; pass a different value from `data.len()` to
/// build a frame that must be rejected at end of frame.
pub fn zstd_frame_with_content_size(data: &[u8], declared: u32) -> Vec<u8> {
    zstd_frame_inner(data, false, Some(declared))
}

fn zstd_frame_inner(data: &[u8], checksum: bool, declared: Option<u32>) -> Vec<u8> {
    let block_count = data.len().div_ceil(ZSTD_BLOCK).max(1);
    let mut out = zstd_header(0x38, checksum, declared);
    for index in 0..block_count {
        let start = index.saturating_mul(ZSTD_BLOCK);
        let end = start.saturating_add(ZSTD_BLOCK).min(data.len());
        let block = data.get(start..end).unwrap_or(&[]);
        push_block(&mut out, 0, block.len(), index + 1 == block_count);
        out.extend_from_slice(block);
    }
    if checksum {
        out.extend_from_slice(&zstd_content_checksum(data).to_le_bytes());
    }
    out
}

/// Low 32 bits of XXH64(seed 0), the zstd content checksum.
fn zstd_content_checksum(data: &[u8]) -> u32 {
    use std::hash::Hasher as _;
    let mut hasher = twox_hash::XxHash64::with_seed(0);
    hasher.write(data);
    hasher.finish() as u32
}

/// A zstd frame with `prefix` then `zero_bytes` zero bytes, encoded as one
/// raw block and RLE blocks so the compressed form stays tiny.
pub fn zstd_bomb(prefix: &[u8], zero_bytes: u64) -> Vec<u8> {
    let prefix_blocks = usize::from(!prefix.is_empty());
    let zero_blocks = usize::try_from(zero_bytes.div_ceil(ZSTD_BLOCK as u64)).unwrap_or(0);
    let total = prefix_blocks.saturating_add(zero_blocks).max(1);
    let mut out = zstd_header(0x38, false, None);
    let mut block = 0_usize;
    if !prefix.is_empty() {
        block += 1;
        push_block(&mut out, 0, prefix.len(), block == total);
        out.extend_from_slice(prefix);
    }
    let mut remaining = zero_bytes;
    while remaining > 0 {
        block += 1;
        let take = remaining.min(ZSTD_BLOCK as u64);
        remaining = remaining.saturating_sub(take);
        let size = usize::try_from(take).unwrap_or(ZSTD_BLOCK);
        push_block(&mut out, 1, size, block == total);
        out.push(0);
    }
    if total == 1 && prefix.is_empty() {
        push_block(&mut out, 0, 0, true);
    }
    out
}

/// A zstd frame header that declares `window_descriptor`, followed by an
/// empty final block.
///
/// RFC 8878 section 3.1.1.2: windowLog is `10 + (descriptor >> 3)` and the
/// mantissa adds `(1 << windowLog) / 8 * (descriptor & 7)`; descriptor 0xff
/// therefore asks for a window far above Packetfin's 128 MiB bound.
pub fn zstd_window_frame(window_descriptor: u8) -> Vec<u8> {
    let mut out = zstd_header(window_descriptor, false, None);
    push_block(&mut out, 0, 0, true);
    out
}

/// zstd magic, a frame header descriptor, the window descriptor and an
/// optional four-byte Frame_Content_Size.
fn zstd_header(window_descriptor: u8, checksum: bool, content_size: Option<u32>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ZSTD_MAGIC);
    let mut descriptor = if checksum { 0x04 } else { 0x00 };
    if content_size.is_some() {
        // FCS flag 2 selects a four-byte field.
        descriptor |= 0x80;
    }
    out.push(descriptor);
    out.push(window_descriptor);
    if let Some(size) = content_size {
        out.extend_from_slice(&size.to_le_bytes());
    }
    out
}

/// Append a three-byte zstd block header (RFC 8878 section 3.1.1.3).
fn push_block(out: &mut Vec<u8>, block_type: u32, size: usize, last: bool) {
    let header = (u32::from(last)) | (block_type << 1) | (u32::try_from(size).unwrap_or(0) << 3);
    let bytes = header.to_le_bytes();
    if let Some(prefix) = bytes.get(..3) {
        out.extend_from_slice(prefix);
    }
}

/// One complete lz4 frame carrying a content checksum.
pub fn lz4_frame_with_content_checksum(data: &[u8]) -> Result<Vec<u8>, String> {
    let info = lz4_flex::frame::FrameInfo::new().content_checksum(true);
    let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::new());
    encoder
        .write_all(data)
        .map_err(|error| format!("lz4 frame: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("lz4 frame: {error}"))
}

/// One complete lz4 frame whose payload is `prefix` followed by `zero_bytes`
/// zero bytes, encoded without materialising the expansion.
pub fn lz4_bomb(prefix: &[u8], zero_bytes: u64) -> Result<Vec<u8>, String> {
    let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
    encoder
        .write_all(prefix)
        .map_err(|error| format!("lz4 bomb: {error}"))?;
    write_zeros(&mut encoder, zero_bytes, "lz4 bomb")?;
    encoder
        .finish()
        .map_err(|error| format!("lz4 bomb: {error}"))
}

/// Write `zero_bytes` zero bytes through `writer` in bounded chunks.
fn write_zeros<W: std::io::Write>(
    writer: &mut W,
    zero_bytes: u64,
    label: &str,
) -> Result<(), String> {
    let zeros = [0_u8; 64 * 1024];
    let mut remaining = zero_bytes;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(zeros.len() as u64))
            .map_err(|_| format!("{label} chunk"))?;
        let Some(chunk) = zeros.get(..take) else {
            return Err(format!("{label} chunk exceeds its buffer"));
        };
        writer
            .write_all(chunk)
            .map_err(|error| format!("{label}: {error}"))?;
        remaining = remaining.saturating_sub(take as u64);
    }
    Ok(())
}
