//! Compressed capture sources: gzip (RFC 1952), zstd (RFC 8878) and lz4
//! frames.
//!
//! Detection is by content magic, never by file name, so `-r -` and every
//! other caller behave alike. Each format decodes into one continuous byte
//! stream: concatenated gzip members, zstd frames and lz4 frames are joined
//! exactly as if their payloads had been written back to back, so a second
//! capture header in a concatenated stream is parsed as record data.
//!
//! Bounds: the compressed input buffer is 32 KiB for every format, an lz4
//! block is at most 4 MiB (the largest frame header value) and a zstd window
//! is at most 128 MiB (libzstd's default). Decompression is incremental: a
//! stream that expands to far more bytes than its file size is decoded one
//! caller-sized chunk at a time, never materialised.
//!
//! Failure taxonomy: a decoder failure before the capture format header is
//! [`CompressionError`] with exit 3. After at least one frame was delivered,
//! gzip deflate/trailer and lz4 payload/checksum corruption, truncation and
//! trailing data are [`super::CaptureError::Truncated`] (exit 14); a
//! header-only stream and a damaged gzip or lz4 frame header stay exit 3.
//! zstd keeps exit 3 for payload corruption. The gzip FHCRC check follows
//! RFC 1952 and the 128 KiB FNAME/FCOMMENT bound is a Packetfin safety limit.
//!
//! lz4 read-ahead: `lz4_flex` decompresses one block (up to 4 MiB) before the
//! caller sees it and validates the frame's content checksum only at the end
//! marker. A bad content checksum can therefore surface after earlier blocks
//! and their capture frames were delivered, which is why lz4 payload damage
//! after a frame is exit 14 rather than a pre-capture failure.
//!
//! Skippable frames (magic `0x184D2A50`–`0x184D2A5F`, a four-byte
//! little-endian payload size, then opaque bytes) are metadata in both the
//! zstd and lz4 frame formats. They are consumed at any frame boundary,
//! including before the capture format is sniffed, so a seekable zstd archive
//! whose seek table is a trailing skippable frame decodes like the plain
//! stream.

use std::fmt;
use std::io::{self, Read};

use super::CaptureError;
use super::bytes;

/// zstd's default window bound, matching libzstd.
pub(crate) const MAX_ZSTD_WINDOW: u64 = 128 * 1024 * 1024;

/// Buffer used for compressed input. Also the gzip decoder's working set.
const INPUT_BUFFER: usize = 32 * 1024;

/// Largest gzip member header accepted, including optional fields. RFC 1952
/// allows a 65535-byte extra field before the name and comment, so 128 KiB
/// admits any legal FEXTRA while still bounding a hostile header.
const MAX_GZIP_HEADER: u64 = 128 * 1024;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const LZ4_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];

/// Why a compressed capture could not be decompressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionError {
    /// The stream ended inside a member, frame, header or trailer.
    Truncated,
    /// A decoder rejected the stream: bad header, payload, checksum or length.
    Corrupt,
    /// A gzip or lz4 frame header failed validation.
    ///
    /// Header damage is "cannot be decompressed" (exit 3) even when earlier
    /// frames were decoded. The gzip FHCRC check follows RFC 1952 and the
    /// 128 KiB FNAME/FCOMMENT bound is a Packetfin safety limit.
    HeaderCorrupt,
    /// Bytes after the last complete member or frame are not another one.
    Trailing,
    /// A frame asks for a window larger than the 128 MiB decoder limit.
    LimitExceeded,
    /// A frame header sets a reserved or unsupported parameter.
    Unsupported,
}

impl fmt::Display for CompressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(formatter, "the compressed stream is truncated"),
            Self::Corrupt => write!(formatter, "the compressed stream is corrupt"),
            Self::HeaderCorrupt => write!(formatter, "the compressed frame header is corrupt"),
            Self::Trailing => write!(formatter, "the compressed stream has trailing data"),
            Self::LimitExceeded => {
                write!(
                    formatter,
                    "the compressed stream needs more memory than allowed"
                )
            }
            Self::Unsupported => {
                write!(formatter, "unsupported compressed-stream frame parameter")
            }
        }
    }
}

impl std::error::Error for CompressionError {}

/// Marker stored inside an `io::Error` so the capture reader can recover the
/// decompression failure without exposing decoder text.
#[derive(Debug)]
struct CompressedFailure(CompressionError);

impl fmt::Display for CompressedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for CompressedFailure {}

fn failure(error: CompressionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, CompressedFailure(error))
}

/// Recover a decompression failure from an error raised by [`Source`].
pub(super) fn compression_error(error: &io::Error) -> Option<CompressionError> {
    error
        .get_ref()?
        .downcast_ref::<CompressedFailure>()
        .map(|failure| failure.0)
}

fn truncated() -> io::Error {
    failure(CompressionError::Truncated)
}

fn corrupt() -> io::Error {
    failure(CompressionError::Corrupt)
}

fn header_corrupt() -> io::Error {
    failure(CompressionError::HeaderCorrupt)
}

fn trailing() -> io::Error {
    failure(CompressionError::Trailing)
}

/// Retry an interrupted read so decoders never observe `EINTR` mid-stream.
///
/// `bytes::fill` retries at the capture layer, but by then a decoder may have
/// consumed part of a member or produced part of the caller's buffer; keeping
/// the retry here makes the state machine restartable.
fn read_retrying<R: Read>(inner: &mut R, out: &mut [u8]) -> io::Result<usize> {
    loop {
        match inner.read(out) {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Whether a four-byte magic starts a skippable frame.
///
/// RFC 8878 section 3.1.2 and the lz4 frame format share the range
/// `0x184D2A50`–`0x184D2A5F`; the low nibble of the first byte is the
/// application-defined identifier and carries no structure.
fn is_skippable_magic(magic: &[u8; 4]) -> bool {
    magic[0] & 0xf0 == 0x50 && magic[1..] == [0x2a, 0x4d, 0x18]
}

/// Read exactly `out.len()` bytes, retrying interrupted reads.
fn read_exact_retrying<R: Read>(inner: &mut R, out: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < out.len() {
        let Some(target) = out.get_mut(offset..) else {
            return Ok(());
        };
        let read = read_retrying(inner, target)?;
        if read == 0 {
            return Err(truncated());
        }
        offset = offset.saturating_add(read);
    }
    Ok(())
}

/// Discard exactly `length` bytes without allocating for the payload.
fn skip_exact<R: Read>(inner: &mut R, mut length: u64) -> io::Result<()> {
    let mut scratch = [0_u8; 8 * 1024];
    while length > 0 {
        let wanted = usize::try_from(length.min(scratch.len() as u64)).unwrap_or(scratch.len());
        let Some(target) = scratch.get_mut(..wanted) else {
            return Err(truncated());
        };
        let read = read_retrying(inner, target)?;
        if read == 0 {
            return Err(truncated());
        }
        length = length.saturating_sub(read as u64);
    }
    Ok(())
}

/// The decompressed byte stream of a capture.
pub(super) enum Source<R: Read> {
    /// No compression magic was found; the sniffed prefix is replayed.
    Plain(Prefix<R>),
    /// One or more concatenated gzip members.
    Gzip(Gzip<R>),
    /// One or more concatenated zstd frames.
    Zstd(Box<Zstd<R>>),
    /// One or more concatenated lz4 frames.
    Lz4(Box<Lz4<R>>),
}

impl<R: Read> Source<R> {
    /// Read the first four bytes, consume any leading skippable frames,
    /// detect a compression magic and build the corresponding streaming
    /// source. Unknown bytes are replayed unchanged.
    ///
    /// A skippable frame carries only metadata (a seek table, for example),
    /// so it can precede the first zstd or lz4 data frame, or a plain
    /// capture. Consuming it before format detection keeps the capture
    /// sniff independent of the compression container.
    pub(super) fn new(mut inner: R) -> Result<Self, CaptureError> {
        let mut sniff = [0_u8; 4];
        let mut got = bytes::fill(&mut inner, &mut sniff)?;
        loop {
            let available = sniff.get(..got).unwrap_or(&[]);
            if available.starts_with(&GZIP_MAGIC) {
                return Ok(Self::Gzip(Gzip::new(Prefix::new(sniff, got, inner))));
            }
            if got == sniff.len() && is_skippable_magic(&sniff) {
                let mut size = [0_u8; 4];
                read_exact_retrying(&mut inner, &mut size).map_err(initial_failure)?;
                skip_exact(&mut inner, u64::from(u32::from_le_bytes(size)))
                    .map_err(initial_failure)?;
                got = bytes::fill(&mut inner, &mut sniff)?;
                continue;
            }
            if available == ZSTD_MAGIC.as_slice() {
                return Ok(Self::Zstd(Box::new(Zstd::new(Prefix::new(
                    sniff, got, inner,
                )))));
            }
            if available == LZ4_MAGIC.as_slice() {
                return Ok(Self::Lz4(Box::new(Lz4::new(Prefix::new(
                    sniff, got, inner,
                )))));
            }
            return Ok(Self::Plain(Prefix::new(sniff, got, inner)));
        }
    }
}

/// Report a skippable-prefix read failure as a decompression failure, not a
/// generic I/O error.
fn initial_failure(error: io::Error) -> CaptureError {
    match compression_error(&error) {
        Some(compression) => CaptureError::Compressed(compression),
        None => CaptureError::Io(error),
    }
}

impl<R: Read> Source<R> {
    /// Whether this source decodes lz4 frames. Used to apply lz4's
    /// payload-corruption exit code after a capture header (see
    /// `map_stream_error`).
    pub(super) fn is_lz4(&self) -> bool {
        matches!(self, Self::Lz4(_))
    }

    /// Whether this source decodes gzip members.
    pub(super) fn is_gzip(&self) -> bool {
        matches!(self, Self::Gzip(_))
    }
}

impl<R: Read> Read for Source<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(inner) => inner.read(out),
            Self::Gzip(inner) => inner.read(out),
            Self::Zstd(inner) => inner.read(out),
            Self::Lz4(inner) => inner.read(out),
        }
    }
}

/// Replays a small prefix read during magic detection, then the rest of the
/// stream. Avoids allocating for the four sniffed bytes.
pub(super) struct Prefix<R> {
    bytes: [u8; 4],
    length: usize,
    position: usize,
    inner: R,
}

impl<R> Prefix<R> {
    fn new(bytes: [u8; 4], length: usize, inner: R) -> Self {
        Self {
            bytes,
            length,
            position: 0,
            inner,
        }
    }
}

impl<R: Read> Read for Prefix<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let start = self.position;
        let end = self.length.min(start.saturating_add(out.len()));
        let Some(prefix) = self.bytes.get(start..end) else {
            return Ok(0);
        };
        if !prefix.is_empty() {
            let Some(target) = out.get_mut(..prefix.len()) else {
                return Ok(0);
            };
            target.copy_from_slice(prefix);
            self.position = end;
            return Ok(prefix.len());
        }
        read_retrying(&mut self.inner, out)
    }
}

/// A fixed-size, non-allocating-after-construction input buffer.
///
/// [`Self::ensure`] reads until the requested prefix is available or the
/// stream ends, so a short read from a pipe cannot be mistaken for a frame
/// boundary. The decoders read through [`Read`]; when the buffer is empty the
/// read goes straight to the inner stream, avoiding a second copy.
struct Buffered<R> {
    inner: R,
    buffer: Box<[u8]>,
    position: usize,
    filled: usize,
    eof: bool,
}

impl<R: Read> Buffered<R> {
    fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            buffer: vec![0_u8; capacity].into_boxed_slice(),
            position: 0,
            filled: 0,
            eof: false,
        }
    }

    fn buffered(&self) -> &[u8] {
        self.buffer.get(self.position..self.filled).unwrap_or(&[])
    }

    fn consume(&mut self, count: usize) {
        self.position = self.position.saturating_add(count).min(self.filled);
    }

    fn compact(&mut self) {
        if self.position == 0 {
            return;
        }
        let remaining = self.filled.saturating_sub(self.position);
        self.buffer.copy_within(self.position..self.filled, 0);
        self.position = 0;
        self.filled = remaining;
    }

    /// Ensure at least `wanted` bytes are buffered, unless the stream ends.
    fn ensure(&mut self, wanted: usize) -> io::Result<&[u8]> {
        let wanted = wanted.min(self.buffer.len());
        if self.filled.saturating_sub(self.position) < wanted && !self.eof {
            self.compact();
            while self.filled < wanted && !self.eof {
                let read = read_retrying(
                    &mut self.inner,
                    self.buffer.get_mut(self.filled..).unwrap_or(&mut []),
                )?;
                if read == 0 {
                    self.eof = true;
                } else {
                    self.filled = self.filled.saturating_add(read);
                }
            }
        }
        Ok(self.buffered())
    }

    /// Discard exactly `length` buffered or incoming bytes.
    ///
    /// The skippable-frame payload is opaque metadata, so it is consumed
    /// through the existing input buffer instead of being materialised.
    fn skip(&mut self, mut length: u64) -> io::Result<()> {
        while length > 0 {
            let available = self.buffered().len();
            if available == 0 {
                if self.ensure(1)?.is_empty() {
                    return Err(truncated());
                }
                continue;
            }
            let take = usize::try_from(length.min(available as u64)).unwrap_or(available);
            self.consume(take);
            length = length.saturating_sub(take as u64);
        }
        Ok(())
    }
}

impl<R: Read> Read for Buffered<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let available = self.filled.saturating_sub(self.position);
        if available > 0 {
            let count = available.min(out.len());
            let Some(source) = self.buffer.get(self.position..self.position + count) else {
                return Ok(0);
            };
            let Some(target) = out.get_mut(..count) else {
                return Ok(0);
            };
            target.copy_from_slice(source);
            self.position += count;
            return Ok(count);
        }
        self.position = 0;
        self.filled = 0;
        if self.eof {
            return Ok(0);
        }
        let read = read_retrying(&mut self.inner, out)?;
        if read == 0 {
            self.eof = true;
        }
        Ok(read)
    }
}

/// What a frame-boundary peek found.
enum Peek {
    /// No bytes remain; the stream ended cleanly between frames.
    End,
    /// The stream ended inside the next magic.
    Short,
    /// A complete magic number.
    Magic([u8; 4]),
}

fn peek(reader: &mut Buffered<impl Read>) -> io::Result<Peek> {
    let available = reader.ensure(4)?;
    if available.is_empty() {
        return Ok(Peek::End);
    }
    if available.len() < 4 {
        return Ok(Peek::Short);
    }
    let Some(magic) = available.get(..4) else {
        return Ok(Peek::Short);
    };
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(magic);
    Ok(Peek::Magic(bytes))
}

/// Consume one skippable frame whose magic is already at the reader's cursor.
///
/// The caller has checked [`is_skippable_magic`]. The payload size is the
/// four-byte little-endian field that follows the magic; a size that reaches
/// past the end of the stream is a truncation, never an allocation.
fn skip_skippable_frame(reader: &mut Buffered<impl Read>) -> io::Result<()> {
    let header = reader.ensure(8)?;
    if header.len() < 8 {
        return Err(truncated());
    }
    let Some(size) = header.get(4..8) else {
        return Err(truncated());
    };
    let mut size_bytes = [0_u8; 4];
    size_bytes.copy_from_slice(size);
    reader.consume(8);
    reader.skip(u64::from(u32::from_le_bytes(size_bytes)))
}

/// Wrap a reader so a decode that reaches the underlying end of file is
/// distinguishable from a frame that ended cleanly.
///
/// The lz4 and zstd streaming decoders return `Ok(0)` for both cases (lz4 even
/// at block boundaries); the flag turns the former into a truncation.
struct EofProbe<R> {
    inner: R,
    eof: bool,
}

impl<R> EofProbe<R> {
    fn new(inner: R) -> Self {
        Self { inner, eof: false }
    }

    fn reset(&mut self) {
        self.eof = false;
    }

    fn past_end(&self) -> bool {
        self.eof
    }

    fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read> Read for EofProbe<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(out)?;
        if read == 0 && !out.is_empty() {
            self.eof = true;
        }
        Ok(read)
    }
}

// ---------------------------------------------------------------------------
// gzip

#[derive(Clone, Copy, PartialEq, Eq)]
enum GzipPhase {
    Header,
    Body,
    Trailer,
    Finished,
}

/// One or more gzip members decoded into a continuous byte stream.
pub(super) struct Gzip<R> {
    reader: Buffered<Prefix<R>>,
    phase: GzipPhase,
    inflate: flate2::Decompress,
    crc: flate2::Crc,
    member_size: u64,
}

impl<R: Read> Gzip<R> {
    fn new(inner: Prefix<R>) -> Self {
        Self {
            reader: Buffered::with_capacity(INPUT_BUFFER, inner),
            phase: GzipPhase::Header,
            inflate: flate2::Decompress::new(false),
            crc: flate2::Crc::new(),
            member_size: 0,
        }
    }

    fn start_member(&mut self) -> io::Result<()> {
        let magic = {
            let available = self.reader.ensure(2)?;
            if available.is_empty() {
                self.phase = GzipPhase::Finished;
                return Ok(());
            }
            let Some(magic) = available.get(..2) else {
                return Err(trailing());
            };
            let mut copy = [0_u8; 2];
            copy.copy_from_slice(magic);
            copy
        };
        if magic != GZIP_MAGIC {
            return Err(trailing());
        }
        self.read_header()?;
        self.inflate.reset(false);
        self.crc = flate2::Crc::new();
        self.member_size = 0;
        self.phase = GzipPhase::Body;
        Ok(())
    }

    /// Parse the RFC 1952 member header, including optional fields.
    fn read_header(&mut self) -> io::Result<()> {
        let mut base = [0_u8; 10];
        self.read_exact(&mut base)?;
        let method = base.get(2).copied().unwrap_or(0);
        let flags = base.get(3).copied().unwrap_or(0xff);
        if base.get(..2) != Some(&GZIP_MAGIC[..]) || method != 8 || flags & 0xe0 != 0 {
            return Err(header_corrupt());
        }
        let mut header_crc = flate2::Crc::new();
        header_crc.update(&base);
        let mut consumed = 10_u64;

        if flags & 0x04 != 0 {
            // FEXTRA
            let mut extra_length = [0_u8; 2];
            self.read_exact(&mut extra_length)?;
            header_crc.update(&extra_length);
            let length = u64::from(u16::from_le_bytes(extra_length));
            consumed = consumed.saturating_add(2);
            self.skip_header_bytes(&mut header_crc, &mut consumed, length)?;
        }
        if flags & 0x08 != 0 {
            // FNAME, NUL-terminated
            self.skip_header_string(&mut header_crc, &mut consumed)?;
        }
        if flags & 0x10 != 0 {
            // FCOMMENT, NUL-terminated
            self.skip_header_string(&mut header_crc, &mut consumed)?;
        }
        if flags & 0x02 != 0 {
            // FHCRC: low 16 bits of the CRC-32 of the header so far.
            let mut stored = [0_u8; 2];
            self.read_exact(&mut stored)?;
            let expected = u16::from_le_bytes(stored);
            let actual = (header_crc.sum() & 0xffff) as u16;
            if expected != actual {
                return Err(header_corrupt());
            }
        }
        Ok(())
    }

    fn skip_header_bytes(
        &mut self,
        header_crc: &mut flate2::Crc,
        consumed: &mut u64,
        mut length: u64,
    ) -> io::Result<()> {
        while length > 0 {
            *consumed = consumed.saturating_add(length.min(INPUT_BUFFER as u64));
            if *consumed > MAX_GZIP_HEADER {
                return Err(header_corrupt());
            }
            let wanted = usize::try_from(length.min(INPUT_BUFFER as u64)).unwrap_or(INPUT_BUFFER);
            let available = self.reader.ensure(wanted)?;
            if available.is_empty() {
                return Err(truncated());
            }
            let take = available.len().min(wanted);
            let Some(chunk) = available.get(..take) else {
                return Err(corrupt());
            };
            header_crc.update(chunk);
            self.reader.consume(take);
            length = length.saturating_sub(take as u64);
        }
        Ok(())
    }

    fn skip_header_string(
        &mut self,
        header_crc: &mut flate2::Crc,
        consumed: &mut u64,
    ) -> io::Result<()> {
        loop {
            let available = self.reader.ensure(1)?;
            if available.is_empty() {
                return Err(truncated());
            }
            let end = available
                .iter()
                .position(|byte| *byte == 0)
                .map_or(available.len(), |position| position.saturating_add(1));
            *consumed = consumed.saturating_add(end as u64);
            if *consumed > MAX_GZIP_HEADER {
                return Err(header_corrupt());
            }
            let Some(chunk) = available.get(..end) else {
                return Err(header_corrupt());
            };
            header_crc.update(chunk);
            let terminated = chunk.last() == Some(&0);
            self.reader.consume(end);
            if terminated {
                return Ok(());
            }
        }
    }

    fn read_exact(&mut self, target: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < target.len() {
            let available = self.reader.ensure(target.len().saturating_sub(offset))?;
            if available.is_empty() {
                return Err(truncated());
            }
            let take = available.len().min(target.len().saturating_sub(offset));
            let Some(chunk) = available.get(..take) else {
                return Err(truncated());
            };
            let Some(destination) = target.get_mut(offset..offset + take) else {
                return Err(corrupt());
            };
            destination.copy_from_slice(chunk);
            self.reader.consume(take);
            offset += take;
        }
        Ok(())
    }

    /// Inflate until the output fills, the member ends, or the stream fails.
    fn pump(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        loop {
            if written == out.len() {
                return Ok(written);
            }
            let available = self.reader.ensure(1)?;
            // At end of input flate2 may still hold decoded bytes it could
            // not write into the previous output slice; an empty-input call
            // drains them before the stream is declared truncated.
            let at_end = available.is_empty();
            let input_before = self.inflate.total_in();
            let output_before = self.inflate.total_out();
            let status = {
                let Some(target) = out.get_mut(written..) else {
                    return Ok(written);
                };
                self.inflate
                    .decompress(available, target, flate2::FlushDecompress::None)
                    .map_err(|_| corrupt())?
            };
            let consumed = self.inflate.total_in().saturating_sub(input_before);
            let produced = self.inflate.total_out().saturating_sub(output_before);
            self.reader
                .consume(usize::try_from(consumed).unwrap_or(usize::MAX));
            if produced > 0 {
                let produced_usize = usize::try_from(produced).unwrap_or(usize::MAX);
                let end = written.saturating_add(produced_usize).min(out.len());
                if let Some(chunk) = out.get(written..end) {
                    self.crc.update(chunk);
                }
                self.member_size = self.member_size.wrapping_add(produced);
                written = end;
            }
            match status {
                flate2::Status::StreamEnd => {
                    self.phase = GzipPhase::Trailer;
                    return Ok(written);
                }
                flate2::Status::Ok | flate2::Status::BufError => {
                    if consumed == 0 && produced == 0 {
                        return Err(if at_end { truncated() } else { corrupt() });
                    }
                }
            }
        }
    }

    fn finish_member(&mut self) -> io::Result<()> {
        let mut trailer = [0_u8; 8];
        self.read_exact(&mut trailer)?;
        let [crc0, crc1, crc2, crc3, size0, size1, size2, size3] = trailer;
        let expected_crc = u32::from_le_bytes([crc0, crc1, crc2, crc3]);
        let expected_size = u32::from_le_bytes([size0, size1, size2, size3]);
        if self.crc.sum() != expected_crc {
            return Err(corrupt());
        }
        let actual_size = (self.member_size & 0xffff_ffff) as u32;
        if actual_size != expected_size {
            return Err(corrupt());
        }
        self.phase = GzipPhase::Header;
        Ok(())
    }
}

impl<R: Read> Read for Gzip<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.phase {
                GzipPhase::Finished => return Ok(0),
                GzipPhase::Header => self.start_member()?,
                GzipPhase::Body => {
                    let written = self.pump(out)?;
                    if written > 0 {
                        return Ok(written);
                    }
                }
                GzipPhase::Trailer => self.finish_member()?,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// zstd

/// One or more zstd frames decoded into a continuous byte stream.
pub(super) struct Zstd<R: Read> {
    reader: Option<EofProbe<Buffered<Prefix<R>>>>,
    decoder: Option<
        ruzstd::decoding::StreamingDecoder<
            EofProbe<Buffered<Prefix<R>>>,
            ruzstd::decoding::FrameDecoder,
        >,
    >,
    frame_output: u64,
    frame_declares_content_size: bool,
    finished: bool,
}

impl<R: Read> Zstd<R> {
    fn new(inner: Prefix<R>) -> Self {
        Self {
            reader: Some(EofProbe::new(Buffered::with_capacity(INPUT_BUFFER, inner))),
            decoder: None,
            frame_output: 0,
            frame_declares_content_size: false,
            finished: false,
        }
    }

    fn start_frame(&mut self) -> io::Result<bool> {
        loop {
            let Some(reader) = self.reader.as_mut() else {
                self.finished = true;
                return Ok(false);
            };
            let inner = reader.get_mut();
            match peek(inner)? {
                Peek::End => {
                    self.finished = true;
                    return Ok(false);
                }
                Peek::Short => return Err(trailing()),
                Peek::Magic(magic) => {
                    if is_skippable_magic(&magic) {
                        skip_skippable_frame(inner)?;
                        continue;
                    }
                    if magic != ZSTD_MAGIC {
                        return Err(trailing());
                    }
                    // RFC 8878 section 3.1.1.1.1: the reserved bit (bit 3 of
                    // the Frame_Header_Descriptor) must be zero. ruzstd 0.9.1
                    // does not check it, so validate the byte before handing
                    // over the frame.
                    let header = inner.ensure(5)?;
                    let descriptor = header.get(4).copied();
                    if descriptor.is_some_and(|descriptor| descriptor & 0x08 != 0) {
                        return Err(failure(CompressionError::Unsupported));
                    }
                    // RFC 8878 section 3.1.1.4: the content-size field is
                    // present when the flag is nonzero or the single-segment
                    // bit is set. `content_size()` cannot distinguish an
                    // absent field from a declared zero, so remember which
                    // shape this frame declared.
                    let declares_content_size = descriptor
                        .is_some_and(|descriptor| descriptor & 0xc0 != 0 || descriptor & 0x20 != 0);
                    let Some(mut source) = self.reader.take() else {
                        self.finished = true;
                        return Ok(false);
                    };
                    source.reset();
                    return match ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                        source,
                        MAX_ZSTD_WINDOW,
                    ) {
                        Ok(decoder) => {
                            self.decoder = Some(decoder);
                            self.frame_output = 0;
                            self.frame_declares_content_size = declares_content_size;
                            Ok(true)
                        }
                        Err(error) => Err(classify_zstd(&error)),
                    };
                }
            }
        }
    }
}

/// Map a ruzstd error to Packetfin's taxonomy without exposing decoder text.
fn classify_zstd(error: &ruzstd::decoding::errors::FrameDecoderError) -> io::Error {
    use ruzstd::decoding::errors::{FrameDecoderError, FrameHeaderError};
    match error {
        FrameDecoderError::FrameHeaderError(FrameHeaderError::WindowTooBig { .. })
        | FrameDecoderError::WindowSizeTooBig { .. } => failure(CompressionError::LimitExceeded),
        _ => {
            if error_chain_is_short(error) {
                truncated()
            } else {
                corrupt()
            }
        }
    }
}

/// True when any error in the chain is an unexpected end of file.
fn error_chain_is_short(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(io) = error.downcast_ref::<io::Error>()
            && io.kind() == io::ErrorKind::UnexpectedEof
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Classify a zstd decoder error, preserving a window-limit rejection.
fn classify_zstd_io(error: &io::Error, past_end: bool) -> io::Error {
    use ruzstd::decoding::errors::{FrameDecoderError, FrameHeaderError};
    if past_end {
        return truncated();
    }
    let Some(inner) = error.get_ref() else {
        return corrupt();
    };
    if let Some(
        FrameDecoderError::FrameHeaderError(FrameHeaderError::WindowTooBig { .. })
        | FrameDecoderError::WindowSizeTooBig { .. },
    ) = inner.downcast_ref::<FrameDecoderError>()
    {
        return failure(CompressionError::LimitExceeded);
    }
    if error_chain_is_short(inner) {
        truncated()
    } else {
        corrupt()
    }
}

/// ruzstd records the frame checksum and the calculated hash but leaves the
/// comparison to the caller; a frame that carries a checksum must match it.
fn zstd_checksum_mismatch(
    decoder: &ruzstd::decoding::StreamingDecoder<
        EofProbe<Buffered<Prefix<impl Read>>>,
        ruzstd::decoding::FrameDecoder,
    >,
) -> bool {
    let frame = &decoder.decoder;
    match (
        frame.get_checksum_from_data(),
        frame.get_calculated_checksum(),
    ) {
        (Some(stored), Some(calculated)) => stored != calculated,
        _ => false,
    }
}

impl<R: Read> Read for Zstd<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.finished {
                return Ok(0);
            }
            if self.decoder.is_none() && !self.start_frame()? {
                return Ok(0);
            }
            let Some(decoder) = self.decoder.as_mut() else {
                self.finished = true;
                return Ok(0);
            };
            match decoder.read(out) {
                Ok(0) => {
                    let past_end = decoder.get_ref().past_end();
                    if !past_end {
                        // ruzstd records the declared Frame_Content_Size but
                        // does not compare it with the decoded byte count. A
                        // declared zero with data is also a mismatch.
                        if self.frame_declares_content_size
                            && decoder.decoder.content_size() != self.frame_output
                        {
                            return Err(corrupt());
                        }
                        if zstd_checksum_mismatch(decoder) {
                            return Err(corrupt());
                        }
                    }
                    let Some(decoder) = self.decoder.take() else {
                        self.finished = true;
                        return Ok(0);
                    };
                    let source = decoder.into_inner();
                    if past_end {
                        return Err(truncated());
                    }
                    self.reader = Some(source);
                }
                Ok(read) => {
                    self.frame_output = self.frame_output.saturating_add(read as u64);
                    return Ok(read);
                }
                Err(error) => {
                    let past_end = decoder.get_ref().past_end();
                    return Err(classify_zstd_io(&error, past_end));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// lz4

/// One or more lz4 frames decoded into a continuous byte stream.
///
/// The frame header's block size field bounds a block at 4 MiB; the decoder
/// reads at most one block (plus its checksum) at a time.
pub(super) struct Lz4<R: Read> {
    reader: Option<EofProbe<Buffered<Prefix<R>>>>,
    decoder: Option<lz4_flex::frame::FrameDecoder<EofProbe<Buffered<Prefix<R>>>>>,
    finished: bool,
}

impl<R: Read> Lz4<R> {
    fn new(inner: Prefix<R>) -> Self {
        Self {
            reader: Some(EofProbe::new(Buffered::with_capacity(INPUT_BUFFER, inner))),
            decoder: None,
            finished: false,
        }
    }

    fn start_frame(&mut self) -> io::Result<bool> {
        loop {
            let Some(reader) = self.reader.as_mut() else {
                self.finished = true;
                return Ok(false);
            };
            match peek(reader.get_mut())? {
                Peek::End => {
                    self.finished = true;
                    return Ok(false);
                }
                Peek::Short => return Err(trailing()),
                Peek::Magic(magic) => {
                    if is_skippable_magic(&magic) {
                        skip_skippable_frame(reader.get_mut())?;
                        continue;
                    }
                    if magic != LZ4_MAGIC {
                        return Err(trailing());
                    }
                    let Some(mut source) = self.reader.take() else {
                        self.finished = true;
                        return Ok(false);
                    };
                    source.reset();
                    self.decoder = Some(lz4_flex::frame::FrameDecoder::new(source));
                    return Ok(true);
                }
            }
        }
    }
}

/// Classify an lz4 decoder error, keeping a damaged frame header separate
/// from damaged payload or checksum bytes.
fn classify_lz4(error: &io::Error, past_end: bool) -> io::Error {
    if past_end || error.kind() == io::ErrorKind::UnexpectedEof {
        return truncated();
    }
    use lz4_flex::frame::Error as FrameError;
    let header = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<FrameError>())
        .is_some_and(|error| {
            matches!(
                error,
                FrameError::WrongMagicNumber
                    | FrameError::UnsupportedBlocksize(_)
                    | FrameError::UnsupportedVersion(_)
                    | FrameError::ReservedBitsSet
                    | FrameError::HeaderChecksumError
                    | FrameError::DictionaryNotSupported
            )
        });
    if header { header_corrupt() } else { corrupt() }
}

impl<R: Read> Read for Lz4<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.finished {
                return Ok(0);
            }
            if self.decoder.is_none() && !self.start_frame()? {
                return Ok(0);
            }
            let Some(decoder) = self.decoder.as_mut() else {
                self.finished = true;
                return Ok(0);
            };
            match decoder.read(out) {
                Ok(0) => {
                    let past_end = decoder.get_ref().past_end();
                    let Some(decoder) = self.decoder.take() else {
                        self.finished = true;
                        return Ok(0);
                    };
                    let source = decoder.into_inner();
                    if past_end {
                        return Err(truncated());
                    }
                    self.reader = Some(source);
                }
                Ok(read) => return Ok(read),
                Err(error) => {
                    let past_end = decoder.get_ref().past_end();
                    return Err(classify_lz4(&error, past_end));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    type TestSource = Source<Cursor<Vec<u8>>>;

    fn open_source(data: impl Into<Vec<u8>>) -> Result<TestSource, String> {
        Source::new(Cursor::new(data.into())).map_err(|error| error.to_string())
    }

    fn read_all(source: &mut TestSource) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        source
            .read_to_end(&mut out)
            .map_err(|error| error.to_string())?;
        Ok(out)
    }

    /// Read to the end, expecting a decompression failure; return the bytes
    /// produced before it and the failure kind.
    fn read_failure(source: &mut TestSource) -> Result<(Vec<u8>, CompressionError), String> {
        let mut out = Vec::new();
        match source.read_to_end(&mut out) {
            Ok(_) => Err("the stream decoded without an error".to_string()),
            Err(error) => match compression_error(&error) {
                Some(compression) => Ok((out, compression)),
                None => Err(format!("the error is not a decompression failure: {error}")),
            },
        }
    }

    /// A prefix shorter than the container magic is replayed as plain bytes;
    /// every longer prefix of one complete member or frame must report a
    /// truncation rather than end silently.
    fn truncated_failure(
        source: &mut TestSource,
        length: usize,
        detected_at: usize,
        format: &str,
    ) -> Result<(), String> {
        let mut out = Vec::new();
        match source.read_to_end(&mut out) {
            Ok(_) if length < detected_at => Ok(()),
            Ok(_) => Err(format!(
                "{format} prefix of {length} bytes decoded cleanly after detection"
            )),
            Err(error) if compression_error(&error) == Some(CompressionError::Truncated) => Ok(()),
            Err(error) => Err(format!(
                "{format} prefix of {length} bytes produced {error}"
            )),
        }
    }

    #[test]
    fn plain_source_replays_the_sniffed_prefix() -> Result<(), String> {
        let data = b"\xd4\xc3\xb2\xa1tail";
        let mut source = open_source(data.to_vec())?;
        assert_eq!(read_all(&mut source)?, data);
        Ok(())
    }

    #[test]
    fn gzip_decodes_and_joins_members() -> Result<(), String> {
        let first = packetfin_testkit::compress::gzip_member(b"hello ")?;
        let second = packetfin_testkit::compress::gzip_member(b"world")?;
        let mut data = first;
        data.extend_from_slice(&second);
        let mut source = open_source(data)?;
        assert_eq!(read_all(&mut source)?, b"hello world");
        Ok(())
    }

    #[test]
    fn gzip_bad_crc_is_corrupt() -> Result<(), String> {
        let mut data = packetfin_testkit::compress::gzip_member(b"payload")?;
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xff;
        }
        let mut source = open_source(data)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::Corrupt);
        Ok(())
    }

    #[test]
    fn gzip_truncation_at_every_boundary_is_bounded() -> Result<(), String> {
        let data = packetfin_testkit::compress::gzip_member(b"some capture bytes")?;
        for length in 0..data.len() {
            let prefix = data.get(..length).unwrap_or_default();
            let mut source = open_source(prefix.to_vec())?;
            truncated_failure(&mut source, length, GZIP_MAGIC.len(), "gzip")?;
        }
        Ok(())
    }

    #[test]
    fn source_stops_at_a_clean_member_end() -> Result<(), String> {
        let mut data = packetfin_testkit::compress::gzip_member(b"first")?;
        data.extend_from_slice(b"trailing");
        let mut source = open_source(data)?;
        let (out, failure) = read_failure(&mut source)?;
        assert_eq!(out, b"first");
        assert_eq!(failure, CompressionError::Trailing);
        Ok(())
    }

    #[test]
    fn gzip_optional_header_fields_are_validated() -> Result<(), String> {
        let payload = b"optional header payload";
        for flags in 0_u8..32 {
            let flags = flags & 0x1f;
            let member = gzip_optional(payload, flags)?;
            let mut source = open_source(member)?;
            let decoded = read_all(&mut source)?;
            assert_eq!(decoded, payload, "flags 0x{flags:02x}");
        }

        let mut broken = gzip_optional(payload, 0x04)?;
        let Some(flag) = broken.get_mut(3) else {
            return Err("short gzip header".to_string());
        };
        *flag |= 0x20;
        let mut source = open_source(broken)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::HeaderCorrupt);
        Ok(())
    }

    /// Raw deflate body for a test payload.
    fn deflate_body(payload: &[u8]) -> Result<Vec<u8>, String> {
        use std::io::Write as _;
        let mut deflate =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        deflate
            .write_all(payload)
            .map_err(|error| error.to_string())?;
        deflate.finish().map_err(|error| error.to_string())
    }

    /// Wrap a header and raw deflate body in the gzip trailer.
    fn gzip_member_from(header: Vec<u8>, payload: &[u8], body: Vec<u8>) -> Vec<u8> {
        let mut member = header;
        member.extend_from_slice(&body);
        let mut crc = flate2::Crc::new();
        crc.update(payload);
        member.extend_from_slice(&crc.sum().to_le_bytes());
        member.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        member
    }

    /// Build a gzip member with the requested optional header fields around a
    /// raw deflate payload.
    fn gzip_optional(payload: &[u8], flags: u8) -> Result<Vec<u8>, String> {
        let body = deflate_body(payload)?;
        let mut header = vec![0x1f, 0x8b, 8, flags];
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.push(0);
        header.push(0xff);
        if flags & 0x04 != 0 {
            header.extend_from_slice(&4_u16.to_le_bytes());
            header.extend_from_slice(b"abcd");
        }
        if flags & 0x08 != 0 {
            header.extend_from_slice(b"name\0");
        }
        if flags & 0x10 != 0 {
            header.extend_from_slice(b"comment\0");
        }
        if flags & 0x02 != 0 {
            let mut crc = flate2::Crc::new();
            crc.update(&header);
            header.extend_from_slice(&((crc.sum() & 0xffff) as u16).to_le_bytes());
        }
        Ok(gzip_member_from(header, payload, body))
    }

    #[test]
    fn gzip_header_crc_mismatch_is_corrupt() -> Result<(), String> {
        let payload = b"header crc";
        let mut member = gzip_optional(payload, 0x02)?;
        // With no optional fields the stored CRC16 occupies bytes 10 and 11.
        if let Some(byte) = member.get_mut(10) {
            *byte ^= 0xff;
        }
        let mut source = open_source(member)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::HeaderCorrupt);
        Ok(())
    }

    #[test]
    fn gzip_extra_field_bound_accepts_the_rfc_maximum() -> Result<(), String> {
        let payload = b"fextra";
        let body = deflate_body(payload)?;
        let mut header = vec![0x1f, 0x8b, 8, 0x04];
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.push(0);
        header.push(0xff);
        header.extend_from_slice(&u16::MAX.to_le_bytes());
        header.extend_from_slice(&vec![0x5a_u8; usize::from(u16::MAX)]);
        let member = gzip_member_from(header, payload, body);
        let mut source = open_source(member)?;
        assert_eq!(read_all(&mut source)?, payload);
        Ok(())
    }

    #[test]
    fn gzip_header_above_the_bound_is_corrupt() -> Result<(), String> {
        let payload = b"long name";
        let body = deflate_body(payload)?;
        let mut header = vec![0x1f, 0x8b, 8, 0x08];
        header.extend_from_slice(&0_u32.to_le_bytes());
        header.push(0);
        header.push(0xff);
        header.extend_from_slice(&vec![b'a'; MAX_GZIP_HEADER as usize]);
        header.push(0);
        let member = gzip_member_from(header, payload, body);
        let mut source = open_source(member)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::HeaderCorrupt);
        Ok(())
    }

    #[test]
    fn zstd_content_size_is_verified() -> Result<(), String> {
        let payload = b"content sized";
        let valid = packetfin_testkit::compress::zstd_frame_with_content_size(
            payload,
            u32::try_from(payload.len()).map_err(|error| error.to_string())?,
        );
        let mut source = open_source(valid)?;
        assert_eq!(read_all(&mut source)?, payload);

        let mut broken = packetfin_testkit::compress::zstd_frame_with_content_size(
            payload,
            u32::try_from(payload.len() + 1).map_err(|error| error.to_string())?,
        );
        let mut source = open_source(std::mem::take(&mut broken))?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::Corrupt);
        Ok(())
    }

    #[test]
    fn zstd_declared_zero_content_size_is_valid_only_without_data() -> Result<(), String> {
        // A one-byte FCS field may legitimately declare an empty frame.
        let empty = packetfin_testkit::compress::zstd_frame_with_content_size(&[], 0);
        let mut source = open_source(empty)?;
        assert_eq!(read_all(&mut source)?, b"");

        // The same declaration with decoded bytes is a size mismatch.
        let broken = packetfin_testkit::compress::zstd_frame_with_content_size(b"payload", 0);
        let mut source = open_source(broken)?;
        let (out, failure) = read_failure(&mut source)?;
        assert_eq!(out, b"payload");
        assert_eq!(failure, CompressionError::Corrupt);
        Ok(())
    }

    #[test]
    fn zstd_reserved_descriptor_bit_is_unsupported() -> Result<(), String> {
        let mut frame = packetfin_testkit::compress::zstd_frame(b"reserved");
        if let Some(descriptor) = frame.get_mut(4) {
            *descriptor |= 0x08;
        }
        let mut source = open_source(frame)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::Unsupported);
        Ok(())
    }

    #[test]
    fn zstd_content_checksum_is_verified() -> Result<(), String> {
        let data = packetfin_testkit::compress::zstd_frame_with_checksum(b"checksummed", true);
        let mut source = open_source(data.clone())?;
        assert_eq!(read_all(&mut source)?, b"checksummed");

        let mut broken = data;
        if let Some(byte) = broken.last_mut() {
            *byte ^= 0xff;
        }
        let mut source = open_source(broken)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::Corrupt);
        Ok(())
    }

    #[test]
    fn gzip_each_trailer_byte_is_checked() -> Result<(), String> {
        let member = packetfin_testkit::compress::gzip_member(b"trailer")?;
        for index in member.len().saturating_sub(8)..member.len() {
            let mut broken = member.clone();
            if let Some(byte) = broken.get_mut(index) {
                *byte ^= 0xff;
            }
            let mut source = open_source(broken)?;
            let (_, failure) = read_failure(&mut source)?;
            assert_eq!(failure, CompressionError::Corrupt, "trailer byte {index}");
        }
        Ok(())
    }

    #[test]
    fn skippable_frames_are_consumed_around_zstd_and_lz4_frames() -> Result<(), String> {
        use packetfin_testkit::compress::skippable_frame;

        let zstd_first = packetfin_testkit::compress::zstd_frame(b"first ");
        let zstd_second = packetfin_testkit::compress::zstd_frame(b"second");
        let mut zstd_leading = skippable_frame(14, b"seek table");
        zstd_leading.extend_from_slice(&zstd_first);
        let mut zstd_middle = zstd_first.clone();
        zstd_middle.extend_from_slice(&skippable_frame(0, b""));
        zstd_middle.extend_from_slice(&zstd_second);
        let mut zstd_trailing = zstd_second.clone();
        zstd_trailing.extend_from_slice(&skippable_frame(15, b"trailer"));
        for (label, data, expected) in [
            ("leading", zstd_leading, b"first ".as_slice()),
            ("middle", zstd_middle, b"first second".as_slice()),
            ("trailing", zstd_trailing, b"second".as_slice()),
        ] {
            let mut source = open_source(data)?;
            assert_eq!(read_all(&mut source)?, expected, "zstd {label}");
        }

        let lz4_first = packetfin_testkit::compress::lz4_frame(b"first ")?;
        let lz4_second = packetfin_testkit::compress::lz4_frame(b"second")?;
        let mut lz4_leading = skippable_frame(14, b"seek table");
        lz4_leading.extend_from_slice(&lz4_first);
        let mut lz4_middle = lz4_first.clone();
        lz4_middle.extend_from_slice(&skippable_frame(0, b""));
        lz4_middle.extend_from_slice(&lz4_second);
        let mut lz4_trailing = lz4_second.clone();
        lz4_trailing.extend_from_slice(&skippable_frame(15, b"trailer"));
        for (label, data, expected) in [
            ("leading", lz4_leading, b"first ".as_slice()),
            ("middle", lz4_middle, b"first second".as_slice()),
            ("trailing", lz4_trailing, b"second".as_slice()),
        ] {
            let mut source = open_source(data)?;
            assert_eq!(read_all(&mut source)?, expected, "lz4 {label}");
        }
        Ok(())
    }

    #[test]
    fn skippable_prefix_before_plain_bytes_is_consumed() -> Result<(), String> {
        let mut data = packetfin_testkit::compress::skippable_frame(3, b"metadata");
        data.extend_from_slice(b"plain capture bytes");
        let mut source = open_source(data)?;
        assert_eq!(read_all(&mut source)?, b"plain capture bytes");
        Ok(())
    }

    #[test]
    fn malformed_skippable_frames_are_truncated() -> Result<(), String> {
        use packetfin_testkit::compress::skippable_frame;

        let complete = skippable_frame(14, b"payload");
        let cases: [(&str, Vec<u8>); 3] = [
            (
                "short header",
                complete.get(..6).unwrap_or_default().to_vec(),
            ),
            (
                "short payload",
                complete
                    .get(..complete.len().saturating_sub(2))
                    .unwrap_or_default()
                    .to_vec(),
            ),
            ("oversized payload", {
                let mut frame = vec![0x5e, 0x2a, 0x4d, 0x18];
                frame.extend_from_slice(&u32::MAX.to_le_bytes());
                frame.extend_from_slice(b"abc");
                frame
            }),
        ];
        for (label, data) in cases {
            match Source::new(Cursor::new(data)) {
                Ok(_) => return Err(format!("{label} decoded as a capture")),
                Err(CaptureError::Compressed(CompressionError::Truncated)) => {}
                Err(error) => return Err(format!("{label} produced {error}")),
            }
        }

        let mut source = open_source(skippable_frame(14, b"only metadata"))?;
        assert_eq!(read_all(&mut source)?, b"");
        Ok(())
    }

    #[test]
    fn zstd_decodes_and_joins_frames() -> Result<(), String> {
        let first = packetfin_testkit::compress::zstd_frame(b"first ");
        let second = packetfin_testkit::compress::zstd_frame(b"second");
        let mut data = first.clone();
        data.extend_from_slice(&second);
        let mut source = open_source(data)?;
        assert_eq!(read_all(&mut source)?, b"first second");

        let mut source = open_source(first)?;
        assert_eq!(read_all(&mut source)?, b"first ");
        Ok(())
    }

    #[test]
    fn zstd_truncation_at_every_boundary_is_bounded() -> Result<(), String> {
        let data = packetfin_testkit::compress::zstd_frame(
            b"a zstd frame with enough bytes to cross a boundary",
        );
        for length in 0..data.len() {
            let prefix = data.get(..length).unwrap_or_default();
            let mut source = open_source(prefix.to_vec())?;
            truncated_failure(&mut source, length, ZSTD_MAGIC.len(), "zstd")?;
        }
        Ok(())
    }

    #[test]
    fn zstd_window_limit_is_reported() -> Result<(), String> {
        // 0x89 is a ~144 MiB window, just above the 128 MiB cap; 0xff asks
        // for far more. Both must be rejected before allocating.
        for descriptor in [0x89_u8, 0xff] {
            let data = packetfin_testkit::compress::zstd_window_frame(descriptor);
            let mut source = open_source(data)?;
            let (_, failure) = read_failure(&mut source)?;
            assert_eq!(
                failure,
                CompressionError::LimitExceeded,
                "descriptor 0x{descriptor:02x}"
            );
        }
        Ok(())
    }

    #[test]
    fn lz4_decodes_and_joins_frames() -> Result<(), String> {
        let first = packetfin_testkit::compress::lz4_frame(b"first ")?;
        let second = packetfin_testkit::compress::lz4_frame(b"second")?;
        let mut data = first.clone();
        data.extend_from_slice(&second);
        let mut source = open_source(data)?;
        assert_eq!(read_all(&mut source)?, b"first second");

        let mut source = open_source(first)?;
        assert_eq!(read_all(&mut source)?, b"first ");
        Ok(())
    }

    #[test]
    fn lz4_truncation_at_every_boundary_is_bounded() -> Result<(), String> {
        let data = packetfin_testkit::compress::lz4_frame(b"an lz4 frame")?;
        for length in 0..data.len() {
            let prefix = data.get(..length).unwrap_or_default();
            let mut source = open_source(prefix.to_vec())?;
            truncated_failure(&mut source, length, LZ4_MAGIC.len(), "lz4")?;
        }
        Ok(())
    }

    #[test]
    fn lz4_trailing_and_corrupt_are_distinct() -> Result<(), String> {
        let mut data = packetfin_testkit::compress::lz4_frame(b"payload")?;
        data.extend_from_slice(b"junk");
        let mut source = open_source(data)?;
        let (out, failure) = read_failure(&mut source)?;
        assert_eq!(out, b"payload");
        assert_eq!(failure, CompressionError::Trailing);

        let mut data = packetfin_testkit::compress::lz4_frame(b"payload")?;
        if let Some(byte) = data.last_mut() {
            *byte ^= 0xff;
        }
        let mut source = open_source(data)?;
        let (_, failure) = read_failure(&mut source)?;
        assert_eq!(failure, CompressionError::Corrupt);
        Ok(())
    }

    /// Deterministic incompressible bytes for read-ahead tests.
    fn noise(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = 0x9e37_79b9_u32;
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
        }
        out
    }

    /// A compressed stream whose remaining bytes are incompressible must not
    /// be read past the frames the caller asked for.
    #[test]
    fn source_does_not_read_past_the_needed_frames() -> Result<(), String> {
        use std::cell::Cell;
        use std::rc::Rc;

        struct Counting<R> {
            inner: R,
            read: Rc<Cell<usize>>,
        }

        impl<R: Read> Read for Counting<R> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let count = self.inner.read(out)?;
                self.read.set(self.read.get().saturating_add(count));
                Ok(count)
            }
        }

        let header = packetfin_testkit::pcap::Pcap::new(
            packetfin_testkit::ByteOrder::Little,
            packetfin_testkit::TimestampResolution::Microsecond,
        )
        .to_bytes()?;
        let mut payload = header;
        payload.extend(std::iter::repeat_n(0_u8, 100 * 16));
        payload.extend_from_slice(&noise(2 * 1024 * 1024));

        // lz4 buffers one compressed block, so use 64 KiB blocks to keep the
        // first block (and therefore the read for 100 frames) small.
        let mut lz4 = {
            use std::io::Write as _;
            let info =
                lz4_flex::frame::FrameInfo::new().block_size(lz4_flex::frame::BlockSize::Max64KB);
            let mut encoder = lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::new());
            encoder
                .write_all(&payload)
                .map_err(|error| error.to_string())?;
            encoder.finish().map_err(|error| error.to_string())?
        };
        let gzip = packetfin_testkit::compress::gzip_member(&payload)?;
        let zstd = packetfin_testkit::compress::zstd_frame(&payload);
        let streams = [gzip, zstd, std::mem::take(&mut lz4)];
        for stream in streams {
            let consumed = Rc::new(Cell::new(0));
            let source = Counting {
                inner: Cursor::new(stream),
                read: Rc::clone(&consumed),
            };
            let mut reader =
                super::super::CaptureReader::new(source).map_err(|error| error.to_string())?;
            for _ in 0..100 {
                reader
                    .next_frame()
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "stream ended before the requested frames".to_string())?;
            }
            let input = consumed.get();
            assert!(
                input < 512 * 1024,
                "{input} compressed bytes were consumed for 100 frames"
            );
        }
        Ok(())
    }

    /// A reader that returns one byte at a time and injects `Interrupted` must
    /// decode exactly like an ordinary reader; this exercises compaction and
    /// the decoder's short-read paths.
    #[test]
    fn source_handles_short_and_interrupted_reads() -> Result<(), String> {
        struct Awkward<R> {
            inner: R,
            calls: usize,
        }

        impl<R: Read> Read for Awkward<R> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.calls = self.calls.saturating_add(1);
                if self.calls.is_multiple_of(5) {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                let take = out.len().min(1);
                let Some(small) = out.get_mut(..take) else {
                    return Ok(0);
                };
                self.inner.read(small)
            }
        }

        let payload = noise(256 * 1024);
        let data = packetfin_testkit::compress::gzip_member(&payload)?;
        let source = Awkward {
            inner: Cursor::new(data),
            calls: 0,
        };
        let mut source = Source::new(source).map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        source
            .read_to_end(&mut out)
            .map_err(|error| error.to_string())?;
        assert_eq!(out, payload);
        Ok(())
    }

    /// A tiny compressed stream that expands to 64 MiB must produce frames
    /// after a bounded amount of input, not be materialised up front.
    #[test]
    fn bomb_streams_are_decoded_incrementally() -> Result<(), String> {
        use std::cell::Cell;
        use std::rc::Rc;

        struct Counting<R> {
            inner: R,
            read: Rc<Cell<usize>>,
        }

        impl<R: Read> Read for Counting<R> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let count = self.inner.read(out)?;
                self.read.set(self.read.get().saturating_add(count));
                Ok(count)
            }
        }

        let header = packetfin_testkit::pcap::Pcap::new(
            packetfin_testkit::ByteOrder::Little,
            packetfin_testkit::TimestampResolution::Microsecond,
        )
        .to_bytes()?;
        let zeros = 64 * 1024 * 1024_u64;
        let streams = [
            packetfin_testkit::compress::gzip_bomb(&header, zeros)?,
            packetfin_testkit::compress::zstd_bomb(&header, zeros),
            packetfin_testkit::compress::lz4_bomb(&header, zeros)?,
        ];
        for stream in streams {
            let consumed = Rc::new(Cell::new(0));
            let source = Counting {
                inner: Cursor::new(stream),
                read: Rc::clone(&consumed),
            };
            let mut reader =
                super::super::CaptureReader::new(source).map_err(|error| error.to_string())?;
            for expected in 1..=100 {
                let frame = reader
                    .next_frame()
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "bomb stream ended early".to_string())?;
                assert_eq!(frame.number, expected);
            }
            let input = consumed.get();
            assert!(
                input < 128 * 1024,
                "{input} compressed bytes were consumed for 100 frames"
            );
        }
        Ok(())
    }
}
