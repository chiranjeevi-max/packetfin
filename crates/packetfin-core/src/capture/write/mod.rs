//! Streaming capture writer for pcap, nsecpcap and pcapng.
//!
//! The writer consumes the same [`CaptureEvent`] stream the reader produces,
//! so a rewrite forwards section, interface, name-resolution and packet
//! metadata without a second parser. Output is written incrementally; no
//! frame or block is buffered beyond the one being encoded.
//!
//! Opening is lazy for both formats. For pcap that separates a link-type
//! conflict discovered before the first packet (open-time failure) from one
//! discovered after packets were written ([`WriteError::IncompatibleLater`]).
//! pcapng opens on the first metadata or packet event, and at
//! [`CaptureWriter::finish`] for an empty source.

mod options;
mod pcap;
mod pcapng;
mod sink;

use std::fmt;
use std::io::{self, Write};

use crate::capture::{CaptureEvent, Frame, InterfaceInfo, PacketOptions, Resolution, Timestamp};

pub use sink::Compression;

/// Largest captured frame the writer stores, in bytes.
///
/// The value is libpcap's maximum snapshot length; a reader built on that
/// limit treats a larger frame as damaged. Packetfin's reader accepts up to
/// [`crate::capture::MAX_FRAME_SIZE`] for robustness, but the writer never
/// stores a frame above this limit.
pub const MAX_PACKET_SIZE: usize = 262_144;

/// Capture file format to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// pcapng, little-endian, version 1.0, unspecified section length.
    PcapNg,
    /// Classic pcap with the given timestamp precision.
    Pcap(Resolution),
    /// Classic pcap with nanosecond timestamps.
    NsecPcap,
}

/// Construction options for [`CaptureWriter`].
#[derive(Clone, Copy, Debug)]
pub struct WriterOptions<'a> {
    /// Container format.
    pub format: OutputFormat,
    /// Output compression.
    pub compression: Compression,
    /// Value written to `shb_userappl` when the source does not provide one.
    pub application: &'a str,
    /// `--capture-comment` values, appended to section comments.
    pub capture_comments: &'a [String],
}

/// One packet to write.
///
/// `timestamp_units` drives pcapng output verbatim so `if_tsoffset` survives
/// a rewrite; `None` selects a simple packet block unless the packet is
/// truncated, in which case it becomes an enhanced block with zero timestamp.
/// An absolute `timestamp` with no units is rejected rather than silently
/// dropping the time.
/// `timestamp` drives pcap output, where the offset has to be folded into the
/// absolute time.
#[derive(Clone, Copy, Debug)]
pub struct PacketRecord<'a> {
    /// Absolute capture time; absent for a pcapng simple packet.
    pub timestamp: Option<Timestamp>,
    /// Raw timestamp units in the interface's declared resolution.
    pub timestamp_units: Option<u64>,
    /// Global interface index.
    pub interface: u32,
    /// Captured bytes.
    pub captured: &'a [u8],
    /// Length of the packet on the wire.
    pub original_len: u32,
    /// Packet options, in source order.
    pub options: &'a PacketOptions,
}

/// Why a capture could not be written.
///
/// [`Self::Incompatible`] covers failures discovered before the output is
/// opened (read-mode exit 9); [`Self::IncompatibleLater`] covers the same
/// class of failure after writing started (exit 15).
#[derive(Debug)]
pub enum WriteError {
    /// The underlying writer failed.
    Io(io::Error),
    /// The capture cannot be represented in the chosen format. Nothing has
    /// been written.
    Incompatible(&'static str),
    /// The capture stopped being representable after output began; earlier
    /// bytes remain in the sink.
    IncompatibleLater(&'static str),
    /// A captured frame is larger than [`MAX_PACKET_SIZE`].
    PacketTooLarge {
        /// Captured length that was rejected.
        length: usize,
    },
    /// A timestamp does not fit the target format's seconds field.
    TimestampOutOfRange,
    /// A packet has an absolute timestamp but no raw units, so a pcapng
    /// writer cannot tell whether the caller meant an enhanced or simple
    /// packet block.
    MissingTimestampUnits,
    /// A packet references an interface the writer never described.
    InvalidInterface(u32),
    /// A metadata value does not fit a pcapng option length field.
    OptionTooLong {
        /// Option code.
        code: u16,
        /// Rejected value length.
        length: usize,
    },
    /// The caller supplied structurally invalid block data.
    InvalidBlock(&'static str),
    /// A link type does not fit pcapng's 16-bit field.
    LinkTypeTooLarge {
        /// Rejected link type.
        link_type: u32,
    },
    /// The writer was already finished.
    Finished,
}

impl fmt::Display for WriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error while writing capture: {error}"),
            Self::Incompatible(reason) => {
                write!(
                    formatter,
                    "the capture cannot be written in this format: {reason}"
                )
            }
            Self::IncompatibleLater(reason) => {
                write!(
                    formatter,
                    "the capture became unwritable after output began: {reason}"
                )
            }
            Self::PacketTooLarge { length } => write!(
                formatter,
                "captured frame is {length} bytes; the maximum is {MAX_PACKET_SIZE}"
            ),
            Self::TimestampOutOfRange => {
                write!(formatter, "timestamp does not fit the output format")
            }
            Self::MissingTimestampUnits => write!(
                formatter,
                "packet has a timestamp but no raw pcapng timestamp units"
            ),
            Self::InvalidInterface(index) => {
                write!(formatter, "packet references unknown interface {index}")
            }
            Self::OptionTooLong { code, length } => write!(
                formatter,
                "pcapng option {code} is {length} bytes; the maximum is 65535"
            ),
            Self::InvalidBlock(detail) => write!(formatter, "invalid capture block: {detail}"),
            Self::LinkTypeTooLarge { link_type } => {
                write!(formatter, "link type {link_type} does not fit pcapng")
            }
            Self::Finished => write!(formatter, "capture writer is already finished"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for WriteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Streaming capture writer.
pub struct CaptureWriter<W: Write> {
    inner: Inner<W>,
    finished: bool,
}

enum Inner<W: Write> {
    PcapNg(pcapng::Writer<W>),
    Pcap(pcap::Writer<W>),
}

impl<W: Write> CaptureWriter<W> {
    /// Create a writer over `sink`.
    pub fn new(sink: W, options: WriterOptions<'_>) -> Self {
        let output = sink::Output::new(sink, options.compression);
        let inner = match options.format {
            OutputFormat::PcapNg => Inner::PcapNg(pcapng::Writer::new(
                output,
                options.application,
                options.capture_comments,
            )),
            OutputFormat::Pcap(resolution) => Inner::Pcap(pcap::Writer::new(output, resolution)),
            OutputFormat::NsecPcap => {
                Inner::Pcap(pcap::Writer::new(output, Resolution::Nanosecond))
            }
        };
        Self {
            inner,
            finished: false,
        }
    }

    /// Forward one reader event.
    ///
    /// Section, interface and name-resolution events update output metadata;
    /// a frame event is written immediately. A caller that filters frames can
    /// instead call this for metadata and [`Self::write_packet`] for the
    /// selected frames.
    pub fn observe(&mut self, event: &CaptureEvent) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        match (&mut self.inner, event) {
            (Inner::PcapNg(writer), CaptureEvent::Section(section)) => {
                writer.observe_section(section)
            }
            (Inner::PcapNg(writer), CaptureEvent::Interface(interface)) => {
                writer.observe_interface(interface)
            }
            (Inner::PcapNg(writer), CaptureEvent::NameResolution(body)) => {
                writer.observe_name_resolution(body)
            }
            (Inner::PcapNg(writer), CaptureEvent::Frame(frame)) => {
                writer.write_packet(&record(frame))
            }
            (Inner::Pcap(writer), CaptureEvent::Section(_)) => {
                writer.observe_section();
                Ok(())
            }
            (Inner::Pcap(writer), CaptureEvent::Interface(interface)) => {
                writer.observe_interface(interface)
            }
            (Inner::Pcap(writer), CaptureEvent::NameResolution(_)) => {
                writer.observe_name_resolution();
                Ok(())
            }
            (Inner::Pcap(writer), CaptureEvent::Frame(frame)) => {
                writer.write_packet(&record(frame))
            }
        }
    }

    /// Write a live capture's interfaces and open the output eagerly.
    ///
    /// Interface ids are assigned by slice order; later [`PacketRecord`]
    /// values must use those indices. A pcap output keeps 262144 as its
    /// snapshot length because live capture has no classic-pcap source.
    pub fn open_live(&mut self, interfaces: &[InterfaceInfo]) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        match &mut self.inner {
            Inner::PcapNg(writer) => writer.open_live(interfaces),
            Inner::Pcap(writer) => writer.open_live(interfaces),
        }
    }

    /// Write one packet.
    pub fn write_packet(&mut self, record: PacketRecord<'_>) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        match &mut self.inner {
            Inner::PcapNg(writer) => writer.write_packet(&record),
            Inner::Pcap(writer) => writer.write_packet(&record),
        }
    }

    /// Flush the current output without finishing the compression stream.
    pub fn flush(&mut self) -> Result<(), WriteError> {
        if self.finished {
            return Err(WriteError::Finished);
        }
        match &mut self.inner {
            Inner::PcapNg(writer) => writer.flush(),
            Inner::Pcap(writer) => writer.flush(),
        }
    }

    /// Uncompressed output bytes written so far.
    pub fn logical_bytes(&self) -> u64 {
        match &self.inner {
            Inner::PcapNg(writer) => writer.logical_bytes(),
            Inner::Pcap(writer) => writer.logical_bytes(),
        }
    }

    /// Finish the output, including any compression stream.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        if self.finished {
            return Ok(());
        }
        let result = match &mut self.inner {
            Inner::PcapNg(writer) => writer.finish(),
            Inner::Pcap(writer) => writer.finish(),
        };
        self.finished = true;
        result
    }

    /// Finish the output and return the wrapped writer.
    pub fn into_inner(mut self) -> Result<W, WriteError> {
        self.finish()?;
        match self.inner {
            Inner::PcapNg(writer) => writer.into_output().into_inner(),
            Inner::Pcap(writer) => writer.into_output().into_inner(),
        }
    }
}

fn record(frame: &Frame) -> PacketRecord<'_> {
    PacketRecord {
        timestamp: frame.timestamp,
        timestamp_units: frame.timestamp_units,
        interface: frame.global_interface,
        captured: &frame.captured,
        original_len: frame.original_len,
        options: &frame.options,
    }
}
