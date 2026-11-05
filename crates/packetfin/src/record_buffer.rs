//! A bounded text buffer for one output record.
//!
//! Output formats build one packet's record before writing it. A 64 MiB
//! object rendered as hex is hundreds of MiB of text, which must not become
//! resident just to be written to stdout. This buffer keeps small records in
//! memory and spills a record above [`SPILL_BYTES`] to a temporary file; the
//! caller copies the file to the real writer when the record is complete.
//! The rendered bytes are identical either way.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Text retained in memory before a record spills to its temporary file.
const SPILL_BYTES: usize = 256 * 1024;

/// Bytes rendered per direct write when a huge byte value is streamed.
const HEX_CHUNK_BYTES: usize = 16 * 1024;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

/// One output record, in memory until it grows past [`SPILL_BYTES`].
pub struct RecordBuffer {
    text: String,
    file: Option<File>,
    path: Option<PathBuf>,
    error: Option<io::Error>,
}

impl Default for RecordBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordBuffer {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self {
            text: String::new(),
            file: None,
            path: None,
            error: None,
        }
    }

    /// Drop the record and its temporary file.
    pub fn clear(&mut self) {
        if self.text.capacity() > SPILL_BYTES {
            self.text = String::new();
        } else {
            self.text.clear();
        }
        self.file = None;
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
        self.error = None;
    }

    /// Append text.
    pub fn push_str(&mut self, text: &str) {
        self.text.push_str(text);
        self.spill_if_needed();
    }

    /// Append one character.
    pub fn push(&mut self, character: char) {
        self.text.push(character);
        self.spill_if_needed();
    }

    /// Append one ASCII byte without UTF-8 re-encoding.
    pub fn push_byte(&mut self, byte: u8) {
        self.push(char::from(byte));
    }

    /// Append `bytes` as lowercase hex, optionally colon-separated.
    ///
    /// Small values stay in the record text; a multi-MiB value is written
    /// straight to the spill file in bounded chunks, so its hex text never
    /// exists as one allocation.
    pub fn write_hex(&mut self, bytes: &[u8], colon: bool) {
        let rendered = bytes.len().saturating_mul(if colon { 3 } else { 2 });
        if rendered <= SPILL_BYTES {
            push_hex_str(&mut self.text, bytes, colon);
            self.spill_if_needed();
            return;
        }
        if let Err(error) = self.spill_all() {
            self.error = Some(error);
            return;
        }
        if !self.ensure_file() {
            return;
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let mut buffer = Vec::with_capacity(HEX_CHUNK_BYTES * 3 + 1);
        let mut first = true;
        for chunk in bytes.chunks(HEX_CHUNK_BYTES) {
            buffer.clear();
            for byte in chunk {
                if colon && !first {
                    buffer.push(b':');
                }
                first = false;
                push_hex_byte(&mut buffer, *byte);
            }
            if let Err(error) = file.write_all(&buffer) {
                self.error = Some(error);
                return;
            }
        }
    }

    /// Finish the record, copying any spilled text to `writer`.
    pub fn emit(&mut self, writer: &mut impl Write) -> io::Result<()> {
        if let Some(error) = self.error.take() {
            self.clear();
            return Err(error);
        }
        if self.file.is_none() {
            writer.write_all(self.text.as_bytes())?;
            self.clear();
            return Ok(());
        }
        self.spill_all()?;
        if let Some(mut file) = self.file.take() {
            file.flush()?;
            file.seek(io::SeekFrom::Start(0))?;
            io::copy(&mut file, writer)?;
        }
        self.clear();
        Ok(())
    }

    fn spill_if_needed(&mut self) {
        if self.text.len() < SPILL_BYTES || self.error.is_some() {
            return;
        }
        if let Err(error) = self.spill_all() {
            self.error = Some(error);
        }
    }

    fn spill_all(&mut self) -> io::Result<()> {
        if self.text.is_empty() {
            return Ok(());
        }
        if !self.ensure_file() {
            return Err(self
                .error
                .take()
                .unwrap_or_else(|| io::Error::other("cannot create a record spill file")));
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        file.write_all(self.text.as_bytes())?;
        if self.text.capacity() > SPILL_BYTES {
            self.text = String::new();
        } else {
            self.text.clear();
        }
        Ok(())
    }

    fn ensure_file(&mut self) -> bool {
        if self.file.is_some() {
            return true;
        }
        for _ in 0..32 {
            let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "packetfin-record-{}-{sequence}",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    self.file = Some(file);
                    // Unix keeps the open handle usable after unlinking, so
                    // an interrupted process cannot leave the record behind.
                    #[cfg(unix)]
                    {
                        let _ = fs::remove_file(&path);
                    }
                    #[cfg(not(unix))]
                    {
                        self.path = Some(path);
                    }
                    return true;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    self.error = Some(error);
                    return false;
                }
            }
        }
        self.error = Some(io::Error::other("cannot create a unique record spill file"));
        false
    }
}

impl Drop for RecordBuffer {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

impl fmt::Write for RecordBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_str(text);
        Ok(())
    }
}

/// Append `bytes` as lowercase hex to a string.
pub fn push_hex_str(text: &mut String, bytes: &[u8], colon: bool) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.iter().enumerate() {
        if colon && index > 0 {
            text.push(':');
        }
        text.push(char::from(
            DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'),
        ));
        text.push(char::from(
            DIGITS
                .get(usize::from(byte & 0x0f))
                .copied()
                .unwrap_or(b'0'),
        ));
    }
}

fn push_hex_byte(buffer: &mut Vec<u8>, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    buffer.push(DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
    buffer.push(
        DIGITS
            .get(usize::from(byte & 0x0f))
            .copied()
            .unwrap_or(b'0'),
    );
}
