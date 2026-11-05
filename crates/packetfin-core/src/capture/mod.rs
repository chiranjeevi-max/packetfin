//! Streaming readers for pcap and pcapng capture files, including gzip, zstd
//! and lz4 compressed input.
//!
//! [`CaptureReader`] works over any [`std::io::Read`] and yields one
//! [`Frame`] at a time; it never loads the whole capture. Compression is
//! detected from the input's magic bytes, so a regular file and `-r -` behave
//! alike. The reader is first-party, so the error
//! taxonomy and allocation bounds stay under Packetfin's control.
//!
//! Allocation rules: a declared length is validated against
//! [`MAX_FRAME_SIZE`] before it drives an allocation, a record buffer is
//! allocated once at its validated size, and options, interfaces and name
//! records have entry limits. Arithmetic on timestamps uses checked `u128`
//! operations.

mod bytes;
mod compressed;
mod pcap;
mod pcapng;

pub mod write;

pub use write::{
    CaptureWriter, Compression, MAX_PACKET_SIZE, OutputFormat, PacketRecord, WriteError,
    WriterOptions,
};

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read};

use bytes::Endian;
use compressed::Source;

pub use compressed::CompressionError;

/// Largest captured frame or pcapng block this reader accepts, in bytes.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Timestamp precision of a classic pcap file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Fractions of a second are millionths.
    Microsecond,
    /// Fractions of a second are billionths.
    Nanosecond,
}

/// A captured timestamp at nanosecond precision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch.
    pub seconds: i64,
    /// Nanoseconds within the second; always below one billion.
    pub nanos: u32,
}

/// pcapng timestamp resolution declared by the `if_tsresol` option.
///
/// `if_tsresol` is one octet: bit 7 selects a power-of-two fraction and the
/// remaining seven bits are the exponent. Without the option the pcapng
/// default is 10^-6 seconds (RFC 4.1, "Interface Description Block").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampResolution {
    /// Fractions of a second are 10^-exponent seconds.
    PowerOfTen(u8),
    /// Fractions of a second are 2^-exponent seconds.
    PowerOfTwo(u8),
}

impl Default for TimestampResolution {
    fn default() -> Self {
        Self::PowerOfTen(6)
    }
}

impl TimestampResolution {
    /// Fractional-second digits the resolution implies, capped at nine.
    pub(crate) fn precision(self) -> u8 {
        match self {
            Self::PowerOfTen(exponent) => exponent.min(9),
            // floor(exponent * log10(2)) without floating point:
            // 30103 / 100000 is log10(2) to five places.
            Self::PowerOfTwo(exponent) => u8::try_from(u32::from(exponent) * 30103 / 100_000)
                .unwrap_or(9)
                .min(9),
        }
    }
}

/// One section header option, in the order the capture stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionOption {
    /// `shb_hardware` (code 2).
    Hardware(String),
    /// `shb_os` (code 3).
    Os(String),
    /// `shb_userappl` (code 4).
    UserApplication(String),
    /// `opt_comment` (code 1).
    Comment(String),
}

/// Metadata from one pcapng section header block.
///
/// Options are kept in source order because a rewritten section must emit
/// them in that order. Unknown option codes are not represented, so a
/// rewritten section drops them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionInfo {
    /// One-based section number within the capture.
    pub number: u32,
    /// Known section options, in source order.
    pub options: Vec<SectionOption>,
}

impl SectionInfo {
    /// First `shb_hardware` value.
    pub fn hardware(&self) -> Option<&str> {
        self.first_text(|option| match option {
            SectionOption::Hardware(text) => Some(text),
            _ => None,
        })
    }

    /// First `shb_os` value.
    pub fn os(&self) -> Option<&str> {
        self.first_text(|option| match option {
            SectionOption::Os(text) => Some(text),
            _ => None,
        })
    }

    /// First `shb_userappl` value.
    pub fn user_application(&self) -> Option<&str> {
        self.first_text(|option| match option {
            SectionOption::UserApplication(text) => Some(text),
            _ => None,
        })
    }

    /// All `shb_comment` values, in source order.
    pub fn comments(&self) -> impl Iterator<Item = &str> {
        self.options.iter().filter_map(|option| match option {
            SectionOption::Comment(text) => Some(text.as_str()),
            _ => None,
        })
    }

    fn first_text<'a>(
        &'a self,
        select: impl Fn(&'a SectionOption) -> Option<&'a String>,
    ) -> Option<&'a str> {
        self.options
            .iter()
            .find_map(|option| select(option).map(String::as_str))
    }
}

/// One interface description option, in the order the capture stores it.
///
/// Only options Packetfin's writer preserves are represented. Interface
/// addresses, time zones and tx/rx speeds are dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceOption {
    /// `opt_comment` (code 1).
    Comment(String),
    /// `if_name` (code 2).
    Name(String),
    /// `if_description` (code 3).
    Description(String),
    /// `if_speed` (code 8).
    Speed(u64),
    /// `if_tsresol` (code 9).
    TimestampResolution(TimestampResolution),
    /// `if_os` (code 12).
    Os(String),
    /// `if_filter` (code 11), including its filter-type octet.
    Filter(Vec<u8>),
    /// `if_fcslen` (code 13).
    FcsLength(u8),
    /// `if_tsoffset` (code 14), in seconds.
    TimestampOffset(i64),
    /// `if_hardware` (code 15).
    Hardware(String),
}

/// Metadata from one pcapng interface description block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Zero-based interface index across the whole capture, in encounter
    /// order. Unused interfaces still consume an index. Writers assign output
    /// ids by event order and ignore this field; a direct caller must pass
    /// interface events in that same order.
    pub global_index: u32,
    /// Link type of packets on this interface.
    pub link_type: u32,
    /// Maximum captured bytes per packet; zero means no limit.
    pub snap_len: u32,
    /// Known interface options, in source order.
    pub options: Vec<InterfaceOption>,
}

impl InterfaceInfo {
    /// First `if_name` value.
    pub fn name(&self) -> Option<&str> {
        self.options.iter().find_map(|option| match option {
            InterfaceOption::Name(text) => Some(text.as_str()),
            _ => None,
        })
    }

    /// First `if_description` value.
    pub fn description(&self) -> Option<&str> {
        self.options.iter().find_map(|option| match option {
            InterfaceOption::Description(text) => Some(text.as_str()),
            _ => None,
        })
    }

    /// Last `if_tsresol` value, or `None` when the capture leaves the
    /// pcapng default (microseconds) in force.
    pub fn timestamp_resolution(&self) -> Option<TimestampResolution> {
        self.options.iter().rev().find_map(|option| match option {
            InterfaceOption::TimestampResolution(resolution) => Some(*resolution),
            _ => None,
        })
    }

    /// Last `if_tsoffset` value, in seconds.
    pub fn timestamp_offset(&self) -> Option<i64> {
        self.options.iter().rev().find_map(|option| match option {
            InterfaceOption::TimestampOffset(offset) => Some(*offset),
            _ => None,
        })
    }
}

/// One packet option, in the order the capture stores it.
///
/// Binary values (`epb_hash`, `epb_verdict`) are kept verbatim; `epb_hash` is
/// never truncated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketOption {
    /// `opt_comment` (code 1).
    Comment(String),
    /// `epb_flags` (code 2).
    Flags(u32),
    /// `epb_hash` (code 3), including its leading algorithm octet.
    Hash(Vec<u8>),
    /// `epb_dropcount` (code 4).
    DropCount(u64),
    /// `epb_packetid` (code 5).
    PacketId(u64),
    /// `epb_queue` (code 6).
    Queue(u32),
    /// `epb_verdict` (code 7).
    Verdict(Vec<u8>),
}

/// Packet-level options from an enhanced or obsolete packet block.
///
/// Options are significant in the order the source stored them. Obsolete
/// packet blocks gain the 16-bit drop-count field as a trailing
/// `epb_dropcount` only when they did not already carry one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketOptions {
    /// Known packet options, in source order.
    pub options: Vec<PacketOption>,
}

impl PacketOptions {
    /// All `opt_comment` values, in source order.
    pub fn comments(&self) -> impl Iterator<Item = &str> {
        self.options.iter().filter_map(|option| match option {
            PacketOption::Comment(text) => Some(text.as_str()),
            _ => None,
        })
    }

    /// Last `epb_flags` value.
    pub fn flags(&self) -> Option<u32> {
        self.options.iter().rev().find_map(|option| match option {
            PacketOption::Flags(flags) => Some(*flags),
            _ => None,
        })
    }

    /// Last `epb_hash` value, including its algorithm octet.
    pub fn hash(&self) -> Option<&[u8]> {
        self.options.iter().rev().find_map(|option| match option {
            PacketOption::Hash(hash) => Some(hash.as_slice()),
            _ => None,
        })
    }

    /// Last `epb_dropcount` value.
    pub fn drop_count(&self) -> Option<u64> {
        self.options.iter().rev().find_map(|option| match option {
            PacketOption::DropCount(count) => Some(*count),
            _ => None,
        })
    }

    /// Last `epb_packetid` value.
    pub fn packet_id(&self) -> Option<u64> {
        self.options.iter().rev().find_map(|option| match option {
            PacketOption::PacketId(id) => Some(*id),
            _ => None,
        })
    }

    /// Last `epb_queue` value.
    pub fn queue(&self) -> Option<u32> {
        self.options.iter().rev().find_map(|option| match option {
            PacketOption::Queue(queue) => Some(*queue),
            _ => None,
        })
    }

    /// Last `epb_verdict` value.
    pub fn verdict(&self) -> Option<&[u8]> {
        self.options.iter().rev().find_map(|option| match option {
            PacketOption::Verdict(verdict) => Some(verdict.as_slice()),
            _ => None,
        })
    }
}

/// One item produced by [`CaptureReader::next_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureEvent {
    /// A pcapng section header block.
    Section(SectionInfo),
    /// A pcapng interface description block, or the single synthetic
    /// interface of a pcap file.
    Interface(InterfaceInfo),
    /// A packet block.
    Frame(Frame),
    /// A name resolution block body (without the block header, trailer or
    /// padding), validated and normalised to little-endian headers so the
    /// single output section can forward it.
    NameResolution(Vec<u8>),
}

/// Convert seconds since the Unix epoch into a UTC Gregorian date and time.
///
/// The conversion uses the proleptic Gregorian calendar, matching the date
/// arithmetic RFC 5424 uses for absolute times.
pub fn civil_time(seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = u32::try_from(second_of_day / 3_600).unwrap_or(0);
    let minute = u32::try_from((second_of_day % 3_600) / 60).unwrap_or(0);
    let second = u32::try_from(second_of_day % 60).unwrap_or(0);
    (year, month, day, hour, minute, second)
}

/// Render an absolute time as the human-readable `-V` text.
///
/// The `-T fields` and JSON writers keep the ISO 8601 form; this form is the
/// one detail output and field labels use, for example
/// `Nov 14, 2023 22:13:20.000000000 UTC`.
pub fn absolute_time_text(timestamp: Timestamp) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day, hour, minute, second) = civil_time(timestamp.seconds);
    let month_name = MONTHS
        .get(usize::try_from(month).unwrap_or(1).saturating_sub(1))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{month_name} {day:>2}, {year:04} {hour:02}:{minute:02}:{second:02}.{:09} UTC",
        timestamp.nanos
    )
}

/// Render a signed nanosecond interval as human-readable relative-time text.
///
/// Days, hours and minutes are named when non-zero. A whole-second remainder
/// stays integral; sub-second values print as milliseconds with microsecond
/// detail. Negative values keep their sign.
pub fn relative_time_text(nanos: i64) -> String {
    use std::fmt::Write as _;

    let magnitude = nanos.unsigned_abs();
    if magnitude == 0 {
        return "0.000000000 seconds".to_string();
    }
    let mut text = String::new();
    if nanos < 0 {
        text.push('-');
    }
    let seconds = magnitude / 1_000_000_000;
    let fraction = magnitude % 1_000_000_000;
    if seconds == 0 {
        let millis = magnitude / 1_000_000;
        // Six fractional digits carry nanosecond precision for the
        // sub-millisecond remainder.
        let fraction = magnitude % 1_000_000;
        let _ = write!(text, "{millis}.{fraction:06} milliseconds");
        return text;
    }
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let remainder = seconds % 60;
    let mut parts: Vec<String> = Vec::new();
    for (value, unit) in [(days, "day"), (hours, "hour"), (minutes, "minute")] {
        if value > 0 {
            parts.push(format!(
                "{value} {unit}{}",
                if value == 1 { "" } else { "s" }
            ));
        }
    }
    if fraction > 0 {
        parts.push(format!("{}.{:09} seconds", remainder, fraction));
    } else if remainder > 0 || parts.is_empty() {
        parts.push(format!(
            "{remainder} second{}",
            if remainder == 1 { "" } else { "s" }
        ));
    }
    text.push_str(&parts.join(", "));
    text
}

/// Convert days since 1970-01-01 into a Gregorian date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days.saturating_add(719_468);
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    if month <= 2 {
        year += 1;
    }
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// Convert a UTC Gregorian date into days since 1970-01-01.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Number of days in a Gregorian month, or zero for an invalid month.
pub fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// One captured frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// One-based frame number, continuous across pcapng sections.
    pub number: u64,
    /// Capture time; absent for a pcapng Simple Packet Block.
    pub timestamp: Option<Timestamp>,
    /// Fractional-second digits the capture declares, capped at nine.
    pub timestamp_precision: u8,
    /// Captured bytes, exactly as stored in the file.
    pub captured: Vec<u8>,
    /// Original length of the packet on the wire.
    pub original_len: u32,
    /// Link type of the interface the frame was captured on.
    pub link_type: u32,
    /// Interface id within its pcapng section; zero for pcap.
    pub interface_id: u32,
    /// Zero-based interface index across the whole capture. The writer uses
    /// this id so sections merge without renumbering.
    pub global_interface: u32,
    /// Raw timestamp units in the interface's declared resolution; absent
    /// for a pcapng Simple Packet Block. Preserved verbatim on a pcapng
    /// rewrite so `if_tsoffset` is not applied twice.
    pub timestamp_units: Option<u64>,
    /// Decompressed source bytes before this frame's block or record.
    ///
    /// This is the offset `-a filesize:N` compares in read mode; for pcap it
    /// includes the 24-byte global header.
    pub source_offset: u64,
    /// `if_name` of the interface, when the capture supplies one.
    pub interface_name: Option<String>,
    /// One-based pcapng section number; absent for pcap.
    pub section_number: Option<u32>,
    /// Packet comments, in file order.
    pub comments: Vec<String>,
    /// Packet options, in source order.
    pub options: PacketOptions,
}

/// Why a capture could not be read.
///
/// The variants map to process exit codes: [`Self::Unrecognized`],
/// [`Self::Malformed`], [`Self::LimitExceeded`] and [`Self::Compressed`] are
/// exit 3, and [`Self::Truncated`] and [`Self::FrameTooLarge`] are exit 14.
/// [`Self::Io`] is reported by the caller.
#[derive(Debug)]
pub enum CaptureError {
    /// The underlying reader failed.
    Io(io::Error),
    /// The input is not a pcap or pcapng file.
    Unrecognized,
    /// The stream ended after a valid header, inside a record or block body.
    Truncated,
    /// A pcap record declares more captured frame bytes than the reader
    /// supports. Such a file counts as damaged (exit 14).
    FrameTooLarge,
    /// A recognized capture has an invalid structure.
    Malformed(String),
    /// A declared size or entry count exceeds a supported limit.
    LimitExceeded(&'static str),
    /// A compressed input could not be decompressed before a capture header
    /// was available, or a zstd stream is corrupt. Payload corruption in a
    /// gzip member or lz4 frame after at least one frame was delivered is
    /// [`Self::Truncated`]; header-only streams and damaged gzip or lz4 frame
    /// headers stay here. The gzip FHCRC check follows RFC 1952 and the
    /// 128 KiB header bound is a Packetfin safety limit.
    Compressed(CompressionError),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error while reading capture: {error}"),
            Self::Unrecognized => {
                write!(formatter, "input is not a pcap or pcapng capture")
            }
            Self::Truncated => {
                write!(
                    formatter,
                    "capture ended in the middle of a record or block"
                )
            }
            Self::FrameTooLarge => {
                write!(
                    formatter,
                    "frame captured length exceeds the supported limit"
                )
            }
            Self::Malformed(detail) => write!(formatter, "malformed capture: {detail}"),
            Self::LimitExceeded(what) => {
                write!(formatter, "{what} exceeds the supported limit")
            }
            Self::Compressed(error) => write!(formatter, "compressed capture: {error}"),
        }
    }
}

impl std::error::Error for CaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CaptureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A frame before the reader stamps its number.
pub(crate) struct FrameData {
    pub(crate) timestamp: Option<Timestamp>,
    pub(crate) timestamp_precision: u8,
    pub(crate) captured: Vec<u8>,
    pub(crate) original_len: u32,
    pub(crate) link_type: u32,
    pub(crate) interface_id: u32,
    pub(crate) global_interface: u32,
    pub(crate) timestamp_units: Option<u64>,
    pub(crate) source_offset: u64,
    pub(crate) interface_name: Option<String>,
    pub(crate) section_number: Option<u32>,
    pub(crate) options: PacketOptions,
}

/// A source reader that counts the decompressed bytes it has delivered.
///
/// The counter drives [`Frame::source_offset`] and therefore read-mode
/// `-a filesize`; it sits above [`compressed::Source`], so the offset is a
/// decompressed-stream offset.
pub(crate) struct CountingReader<R> {
    inner: R,
    position: u64,
}

impl<R: Read> CountingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner, position: 0 }
    }

    pub(crate) fn position(&self) -> u64 {
        self.position
    }

    pub(crate) fn get_ref(&self) -> &R {
        &self.inner
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.position = self.position.saturating_add(read as u64);
        Ok(read)
    }
}

/// One event before the reader stamps a frame number.
pub(crate) enum RawEvent {
    Frame(FrameData),
    Event(CaptureEvent),
}

enum Format {
    Empty,
    Pcap(pcap::State),
    PcapNg(pcapng::State),
}

/// Streaming capture reader.
///
/// `R` is any byte source: a file, standard input or an in-memory slice. The
/// reader reads only as far as the next frame, so a caller can stop early
/// without consuming the rest of the capture.
pub struct CaptureReader<R: Read> {
    /// Decompressed bytes, counted for [`Frame::source_offset`].
    source: CountingReader<Source<R>>,
    format: Format,
    pending: VecDeque<CaptureEvent>,
    next_number: u64,
    /// Whether any frame has been delivered. gzip/lz4 payload corruption is a
    /// damaged capture (exit 14) only after at least one frame was emitted; a
    /// header-only stream stays "cannot be decompressed" (exit 3).
    frames_decoded: bool,
    finished: bool,
    pending_names: Vec<(std::net::IpAddr, String)>,
}

impl<R: Read> CaptureReader<R> {
    /// Sniff compression and the capture format, then consume the first
    /// global header.
    ///
    /// gzip (`1f 8b`, two bytes are enough), zstd (`28 b5 2f fd`) and lz4
    /// (`04 22 4d 18`) are decompressed into the same streaming reader, so
    /// every caller gets compressed input without a separate path. An empty
    /// input, or one with fewer than eight non-magic bytes, is treated as an
    /// empty capture: [`Self::next_frame`] returns `Ok(None)` and the exit
    /// status is 0. Those 1–7 bytes are not decoded as a raw frame. Eight or
    /// more non-magic bytes are [`CaptureError::Unrecognized`]. A recognized
    /// magic followed by a short header is [`CaptureError::Malformed`], never
    /// [`CaptureError::Truncated`]: the stream never contained a complete
    /// header. A decompression failure before the capture header is
    /// [`CaptureError::Compressed`].
    ///
    /// The first section header or the pcap interface is queued as the first
    /// [`CaptureEvent`] so a writer can reproduce the source metadata before
    /// it sees a frame.
    pub fn new(inner: R) -> Result<Self, CaptureError> {
        let mut source = CountingReader::new(Source::new(inner)?);
        let mut pending = VecDeque::new();
        let (format, section) = Self::read_format(&mut source).map_err(map_initial_error)?;
        if let Some(section) = section {
            pending.push_back(CaptureEvent::Section(section));
        }

        if let Format::Pcap(state) = &format {
            // A pcap file has one interface and no section metadata. A
            // nanosecond source declares if_tsresol=9; the microsecond
            // default is written without the option.
            let options = match state.resolution {
                Resolution::Nanosecond => vec![InterfaceOption::TimestampResolution(
                    TimestampResolution::PowerOfTen(9),
                )],
                Resolution::Microsecond => Vec::new(),
            };
            pending.push_back(CaptureEvent::Interface(InterfaceInfo {
                global_index: 0,
                link_type: state.link_type,
                snap_len: state.snap_len,
                options,
            }));
        }

        Ok(Self {
            source,
            format,
            pending,
            next_number: 1,
            frames_decoded: false,
            finished: false,
            pending_names: Vec::new(),
        })
    }

    /// Sniff the capture format from the decompressed stream and consume its
    /// first global header.
    ///
    /// A pcapng file also returns its first section metadata so the caller can
    /// queue it as the first [`CaptureEvent`].
    fn read_format(
        source: &mut CountingReader<Source<R>>,
    ) -> Result<(Format, Option<SectionInfo>), CaptureError> {
        let mut magic = [0_u8; 4];
        let got = bytes::fill(source, &mut magic)?;
        if got < magic.len() {
            return Ok((Format::Empty, None));
        }

        match magic {
            [0xa1, 0xb2, 0xc3, 0xd4] => Ok((
                Format::Pcap(pcap::read_header(
                    source,
                    Endian::Big,
                    Resolution::Microsecond,
                )?),
                None,
            )),
            [0xd4, 0xc3, 0xb2, 0xa1] => Ok((
                Format::Pcap(pcap::read_header(
                    source,
                    Endian::Little,
                    Resolution::Microsecond,
                )?),
                None,
            )),
            [0xa1, 0xb2, 0x3c, 0x4d] => Ok((
                Format::Pcap(pcap::read_header(
                    source,
                    Endian::Big,
                    Resolution::Nanosecond,
                )?),
                None,
            )),
            [0x4d, 0x3c, 0xb2, 0xa1] => Ok((
                Format::Pcap(pcap::read_header(
                    source,
                    Endian::Little,
                    Resolution::Nanosecond,
                )?),
                None,
            )),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                let (state, section) = pcapng::read_first_section(source)?;
                Ok((Format::PcapNg(state), Some(section)))
            }
            _ => {
                // A non-magic file of eight or more bytes is not a capture.
                // Fewer than eight bytes is treated as empty, so that input
                // exits with status zero.
                let mut extra = [0_u8; 4];
                let extra_got = bytes::fill(source, &mut extra)?;
                if magic.len() + extra_got < 8 {
                    return Ok((Format::Empty, None));
                }
                Err(CaptureError::Unrecognized)
            }
        }
    }

    /// Take the pcapng name-resolution records read since the last call.
    ///
    /// The records apply to the frames that follow them; the driver calls
    /// this after reading a frame and before decoding it.
    pub fn take_name_records(&mut self) -> Vec<(std::net::IpAddr, String)> {
        std::mem::take(&mut self.pending_names)
    }

    /// Read the next capture event, or `Ok(None)` at a clean end of file.
    ///
    /// Section, interface and name-resolution events precede the frames they
    /// describe. [`Self::next_frame`] skips them and keeps its old
    /// one-frame-at-a-time contract.
    ///
    /// After an error the reader is finished; the caller should stop.
    pub fn next_event(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(Some(event));
        }
        if self.finished {
            return Ok(None);
        }

        let result = match &mut self.format {
            Format::Empty => Ok(None),
            Format::Pcap(state) => {
                pcap::next(&mut self.source, state).map(|data| data.map(RawEvent::Frame))
            }
            Format::PcapNg(state) => pcapng::next_event(&mut self.source, state),
        };

        if let Format::PcapNg(state) = &mut self.format {
            self.pending_names.append(&mut state.take_names());
        }

        match result {
            Ok(Some(RawEvent::Frame(data))) => Ok(Some(CaptureEvent::Frame(self.stamp(data)))),
            Ok(Some(RawEvent::Event(event))) => Ok(Some(event)),
            Ok(None) => {
                self.finished = true;
                Ok(None)
            }
            Err(error) => {
                self.finished = true;
                Err(self.map_stream_error(error))
            }
        }
    }

    /// Read the next frame, or `Ok(None)` at a clean end of file.
    ///
    /// Metadata events are consumed and discarded; frame numbering and every
    /// existing [`Frame`] field keep their previous meaning.
    ///
    /// After an error the reader is finished; the caller should stop.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        loop {
            match self.next_event()? {
                Some(CaptureEvent::Frame(frame)) => return Ok(Some(frame)),
                Some(
                    CaptureEvent::Section(_)
                    | CaptureEvent::Interface(_)
                    | CaptureEvent::NameResolution(_),
                ) => {}
                None => return Ok(None),
            }
        }
    }

    fn stamp(&mut self, data: FrameData) -> Frame {
        let number = self.next_number;
        self.next_number = self.next_number.saturating_add(1);
        self.frames_decoded = true;
        let comments = data.options.comments().map(str::to_string).collect();
        Frame {
            number,
            timestamp: data.timestamp,
            timestamp_precision: data.timestamp_precision,
            captured: data.captured,
            original_len: data.original_len,
            link_type: data.link_type,
            interface_id: data.interface_id,
            global_interface: data.global_interface,
            timestamp_units: data.timestamp_units,
            source_offset: data.source_offset,
            interface_name: data.interface_name,
            section_number: data.section_number,
            comments,
            options: data.options,
        }
    }

    /// Translate a decompression failure into the capture-file taxonomy.
    ///
    /// Once a capture header is parsed, truncation and trailing bytes are a
    /// cut-short capture (exit 14). Payload corruption is also exit 14 for
    /// gzip and lz4, but only after at least one frame was delivered: a
    /// header-only stream with a bad gzip CRC or lz4 content checksum is
    /// "cannot be decompressed" (exit 3). zstd keeps exit 3 for payload
    /// corruption. A gzip or lz4 frame header that fails validation stays
    /// exit 3 even after frames were decoded. Before a header every
    /// decompression failure is exit 3.
    fn map_stream_error(&self, error: CaptureError) -> CaptureError {
        let CaptureError::Io(io) = &error else {
            return error;
        };
        let Some(compression) = compressed::compression_error(io) else {
            return error;
        };
        let header_parsed = !matches!(self.format, Format::Empty);
        let source = self.source.get_ref();
        match compression {
            CompressionError::Truncated | CompressionError::Trailing if header_parsed => {
                CaptureError::Truncated
            }
            CompressionError::Corrupt
                if self.frames_decoded && (source.is_gzip() || source.is_lz4()) =>
            {
                CaptureError::Truncated
            }
            other => CaptureError::Compressed(other),
        }
    }
}

/// A decompression failure while the capture header was being sniffed can
/// never be a truncated capture: no capture was recognized yet.
fn map_initial_error(error: CaptureError) -> CaptureError {
    match &error {
        CaptureError::Io(io) => match compressed::compression_error(io) {
            Some(compression) => CaptureError::Compressed(compression),
            None => error,
        },
        _ => error,
    }
}
