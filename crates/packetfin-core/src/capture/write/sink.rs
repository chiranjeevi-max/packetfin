//! Output sinks: plain bytes, deterministic gzip and lz4 frames.
//!
//! Logical byte accounting happens before compression so live `-a filesize`
//! and ring limits see the uncompressed capture size.

use std::io::{self, Write};

use flate2::write::GzEncoder;
use flate2::{Compression as GzipLevel, GzBuilder};
use lz4_flex::frame::FrameEncoder;

use super::WriteError;

/// Compression applied to a capture output stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// No compression.
    None,
    /// gzip with a zero modification time, so identical input produces
    /// identical bytes.
    Gzip,
    /// One lz4 frame.
    Lz4,
}

pub(crate) struct Output<W: Write> {
    sink: Option<Sink<W>>,
    finished: Option<W>,
    logical_bytes: u64,
}

impl<W: Write> Output<W> {
    pub(crate) fn new(inner: W, compression: Compression) -> Self {
        let sink = match compression {
            Compression::None => Sink::Plain(inner),
            Compression::Gzip => {
                Sink::Gzip(GzBuilder::new().mtime(0).write(inner, GzipLevel::default()))
            }
            Compression::Lz4 => Sink::Lz4(FrameEncoder::new(inner)),
        };
        Self {
            sink: Some(sink),
            finished: None,
            logical_bytes: 0,
        }
    }

    /// Write uncompressed bytes and account for them.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
        let sink = self.sink.as_mut().ok_or(WriteError::Finished)?;
        match sink {
            Sink::Plain(inner) => inner.write_all(bytes),
            Sink::Gzip(encoder) => encoder.write_all(bytes),
            Sink::Lz4(encoder) => encoder.write_all(bytes),
        }
        .map_err(WriteError::Io)?;
        self.logical_bytes = self.logical_bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }

    pub(crate) fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Push already-written bytes to the underlying writer without ending the
    /// compression stream.
    pub(crate) fn flush(&mut self) -> Result<(), WriteError> {
        let sink = self.sink.as_mut().ok_or(WriteError::Finished)?;
        match sink {
            Sink::Plain(inner) => inner.flush(),
            Sink::Gzip(encoder) => encoder.flush(),
            Sink::Lz4(encoder) => encoder.flush(),
        }
        .map_err(WriteError::Io)
    }

    /// Finish the compression stream and flush the underlying writer.
    pub(crate) fn finish(&mut self) -> Result<(), WriteError> {
        let Some(sink) = self.sink.take() else {
            return Ok(());
        };
        let inner = match sink {
            Sink::Plain(mut inner) => {
                inner.flush().map_err(WriteError::Io)?;
                inner
            }
            Sink::Gzip(encoder) => {
                let mut inner = encoder.finish().map_err(WriteError::Io)?;
                inner.flush().map_err(WriteError::Io)?;
                inner
            }
            Sink::Lz4(encoder) => {
                let mut inner = encoder
                    .finish()
                    .map_err(io::Error::from)
                    .map_err(WriteError::Io)?;
                inner.flush().map_err(WriteError::Io)?;
                inner
            }
        };
        self.finished = Some(inner);
        Ok(())
    }

    /// Finish the stream, if needed, and return the wrapped writer.
    pub(crate) fn into_inner(mut self) -> Result<W, WriteError> {
        self.finish()?;
        self.finished.ok_or(WriteError::Finished)
    }
}

enum Sink<W: Write> {
    Plain(W),
    Gzip(GzEncoder<W>),
    Lz4(FrameEncoder<W>),
}
