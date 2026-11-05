//! Bounded byte order, cursor and stream helpers shared by the capture
//! readers.

use std::io::{self, Read};

use super::CaptureError;

/// Byte order of a pcap file or pcapng section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Endian {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl Endian {
    pub(crate) fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    pub(crate) fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    pub(crate) fn u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            Self::Little => u64::from_le_bytes(bytes),
            Self::Big => u64::from_be_bytes(bytes),
        }
    }

    pub(crate) fn i64(self, bytes: [u8; 8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

/// Fill `buffer` until it is full or the reader reports end of file.
///
/// Returns the number of bytes read. Interrupted reads are retried, matching
/// `Read::read_exact`'s behaviour.
pub(crate) fn fill<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<usize, CaptureError> {
    let needed = buffer.len();
    let mut got = 0;
    while got < needed {
        let Some(rest) = buffer.get_mut(got..) else {
            break;
        };
        match reader.read(rest) {
            Ok(0) => break,
            Ok(read) if read <= rest.len() => got += read,
            Ok(_) => {
                return Err(CaptureError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reader reported more bytes than the buffer can hold",
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(CaptureError::Io(error)),
        }
    }
    Ok(got)
}

/// Read exactly `buffer.len()` bytes or fail with [`CaptureError::Truncated`].
pub(crate) fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), CaptureError> {
    let needed = buffer.len();
    match fill(reader, buffer)? {
        got if got == needed => Ok(()),
        _ => Err(CaptureError::Truncated),
    }
}

/// Read exactly `buffer.len()` bytes or report the short header as malformed.
///
/// The capture format sniff and the first global header must map a short read
/// to the "unrecognized or malformed" exit code, never to the truncated-file
/// code: the stream never contained a complete header.
pub(crate) fn read_exact_initial<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    context: &'static str,
) -> Result<(), CaptureError> {
    let needed = buffer.len();
    match fill(reader, buffer)? {
        got if got == needed => Ok(()),
        got => Err(CaptureError::Malformed(format!(
            "{context} ended after {got} of {needed} bytes"
        ))),
    }
}

/// Read a fixed-size header, distinguishing a clean end of file from a record
/// cut short.
///
/// Returns `false` only when the reader returned no bytes before the first
/// byte of the header. A partial header is [`CaptureError::Truncated`].
pub(crate) fn read_full_or_eof<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<bool, CaptureError> {
    let needed = buffer.len();
    match fill(reader, buffer)? {
        0 => Ok(false),
        got if got == needed => Ok(true),
        _ => Err(CaptureError::Truncated),
    }
}

/// Read `len` bytes into a vector allocated at the declared size.
///
/// The caller validates `len` against [`super::MAX_FRAME_SIZE`] before this
/// call, so one exact allocation replaces the former chunked growth and copy.
pub(crate) fn read_bounded<R: Read>(reader: &mut R, len: usize) -> Result<Vec<u8>, CaptureError> {
    read_bounded_with(reader, len, |reader, buffer| read_exact(reader, buffer))
}

/// Like [`read_bounded`], but a short read is reported as a malformed header,
/// for use while the first section header is being consumed.
pub(crate) fn read_bounded_initial<R: Read>(
    reader: &mut R,
    len: usize,
    context: &'static str,
) -> Result<Vec<u8>, CaptureError> {
    read_bounded_with(reader, len, |reader, buffer| {
        read_exact_initial(reader, buffer, context)
    })
}

fn read_bounded_with<R, F>(reader: &mut R, len: usize, mut read: F) -> Result<Vec<u8>, CaptureError>
where
    R: Read,
    F: FnMut(&mut R, &mut [u8]) -> Result<(), CaptureError>,
{
    let mut out = vec![0_u8; len];
    read(reader, &mut out)?;
    Ok(out)
}

/// Discard `len` bytes without allocating a buffer for them.
pub(crate) fn skip_bounded<R: Read>(reader: &mut R, len: usize) -> Result<(), CaptureError> {
    let mut remaining = len;
    let mut chunk = [0_u8; 8192];
    while remaining > 0 {
        let take = remaining.min(chunk.len());
        let Some(part) = chunk.get_mut(..take) else {
            return Err(CaptureError::Malformed(
                "internal skip chunk exceeds its buffer".to_string(),
            ));
        };
        read_exact(reader, part)?;
        remaining -= take;
    }
    Ok(())
}

/// A bounded view over one pcapng block body or pcap header.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], CaptureError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| {
                CaptureError::Malformed(
                    "a field extends past the end of its capture structure".to_string(),
                )
            })?;
        let slice = self.data.get(self.position..end).ok_or_else(|| {
            CaptureError::Malformed(
                "a field extends past the end of its capture structure".to_string(),
            )
        })?;
        self.position = end;
        Ok(slice)
    }

    pub(crate) fn skip(&mut self, len: usize) -> Result<(), CaptureError> {
        self.take(len).map(|_| ())
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], CaptureError> {
        let bytes = self.take(N)?;
        bytes
            .try_into()
            .map_err(|_| CaptureError::Malformed("a fixed field has the wrong length".to_string()))
    }

    pub(crate) fn u16(&mut self, endian: Endian) -> Result<u16, CaptureError> {
        Ok(endian.u16(self.array()?))
    }

    pub(crate) fn u32(&mut self, endian: Endian) -> Result<u32, CaptureError> {
        Ok(endian.u32(self.array()?))
    }

    pub(crate) fn i64(&mut self, endian: Endian) -> Result<i64, CaptureError> {
        Ok(endian.i64(self.array()?))
    }
}
