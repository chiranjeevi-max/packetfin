use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufReader, Write as _};
use std::path::{Path, PathBuf};

use packetfin_core::decode::{
    DecodeOptions, LayerType, PrefError, apply_preference, heuristic, nameres_from_flags,
};
use packetfin_core::fields::protocol_by_name;
use packetfin_core::stats::{self, StatsOptions};
use packetfin_core::{
    Compression, DEFAULT_ANNOTATION_BUDGET, DEFAULT_STATE_BUDGET, DEFAULT_STATS_BUDGET, FieldDef,
    Filter, FilterError, OutputFormat, Resolution, field_by_abbrev, protocols,
};
use packetfin_pcap::{Linktype, buffer_bytes_from_mib};

use crate::detail::DetailOptions;
use crate::fields::{FieldOutputOptions, Occurrence, Quote};
use crate::hexdump::HexdumpOptions;
use crate::json::{JsonMode, ProtocolFilter};
use crate::summary::{SummaryStyle, TimeFormat, TimeOptions};

/// A `-G` glossary report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// The field registry.
    Fields,
    /// The protocol registry.
    Protocols,
    /// The `-G` help text.
    Help,
    /// The heuristic-decoder registry.
    HeuristicDecodes,
}

/// Where the frames come from.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// A capture file, or `-` for standard input.
    Read(PathBuf),
    /// A live capture on one or more interfaces.
    Live(Box<LiveOptions>),
}

impl Input {
    /// The capture path used by output headers, empty for a live capture.
    #[must_use]
    pub fn capture_path(&self) -> &Path {
        match self {
            Self::Read(path) => path,
            Self::Live(_) => Path::new(""),
        }
    }
}

/// Live-capture settings from `-i`, `-f`, `-s`, `-p`, `-I`, `-B`, `-y`,
/// `--time-stamp-type` and `-Q`.
///
/// Interface selectors stay unresolved so an invalid name is reported by the
/// live session, which exits 5 for an unknown name, not by the parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveOptions {
    /// `-i` selectors in command-line order; empty means the default device.
    pub interfaces: Vec<String>,
    /// `-f` capture filter; the last value wins.
    pub capture_filter: Option<String>,
    /// `-s` snapshot length; `Some(0)` asks libpcap for its own limit.
    pub snaplen: Option<u32>,
    /// Promiscuous mode; `-p` clears it.
    pub promisc: bool,
    /// Monitor (rfmon) mode from `-I`.
    pub monitor: bool,
    /// `-B` kernel capture buffer size in bytes.
    pub buffer_bytes: Option<u32>,
    /// `-y` link type, resolved from its libpcap name.
    pub link_type: Option<Linktype>,
    /// `--time-stamp-type` name, resolved when the interface is opened.
    pub tstamp_type: Option<String>,
    /// `-Q`: suppress the capture start, drop and count messages.
    pub suppress_messages: bool,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            capture_filter: None,
            snaplen: None,
            promisc: true,
            monitor: false,
            buffer_bytes: None,
            link_type: None,
            tstamp_type: None,
            suppress_messages: false,
        }
    }
}

/// Which capability reports a `-L` or `--list-time-stamp-types` run prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListModes {
    /// Print the data link types (`-L`).
    pub link_types: bool,
    /// Print the timestamp types (`--list-time-stamp-types`).
    pub timestamp_types: bool,
}

/// What the command line asks packetfin to do.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Print the own-wording help text and exit 0.
    Help,
    /// Print the own-wording version banner and exit 0.
    Version,
    /// Print the numbered interface list and exit (`-D`).
    ListDevices,
    /// Print interface capabilities and exit (`-L`, `--list-time-stamp-types`).
    ListCaptureModes {
        /// Interfaces and capture options the listing opens.
        options: Box<LiveOptions>,
        /// Which reports to print.
        modes: ListModes,
    },
    /// An option packetfin does not recognise.
    Unknown(String),
    /// A positional argument, which packetfin does not accept yet.
    Argument(String),
    /// A malformed command line: print the message and usage, exit 1.
    Usage(String),
    /// A recognised command line that cannot run: print the message, exit 1.
    Error(String),
    /// Print the `-z` statistics list and exit zero.
    StatsHelp,
    /// A statistics name, filter or budget diagnostic.
    StatsError(String),
    /// A warning that ends the run (an unknown `--compress` mode): print the
    /// message and exit 0 without output.
    ExitZero(String),
    /// Print selected fields from a capture file.
    Fields(Box<FieldsOptions>),
    /// Print JSON or JSONraw packets.
    Json(Box<JsonOptions>),
    /// Print PDML packets.
    Pdml(Box<PdmlOptions>),
    /// Print PSML packets.
    Psml(Box<PsmlOptions>),
    /// Print Elasticsearch bulk documents.
    Ek(Box<EkOptions>),
    /// Print PostScript pages.
    Ps(Box<PsOptions>),
    /// Print the default packet summary.
    Summary(Box<SummaryOptions>),
    /// Print a glossary report and exit.
    Report(Report),
    /// Print the `--hexdump` help text and exit 0.
    HexdumpHelp,
    /// A `-Y` expression that does not parse: print it and exit 4.
    DisplayFilter { filter: String, error: FilterError },
}

/// One `--export-objects PROTOCOL,DIR` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportObjects {
    /// Export-object protocol; only HTTP has a decoder here.
    pub protocol: ExportProtocol,
    /// Destination directory, created at startup.
    pub directory: PathBuf,
}

/// Export-object protocols listed for `--export-objects`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportProtocol {
    /// HTTP/1.x message bodies.
    Http,
    /// Internet Message Format bodies (no decoder yet).
    Imf,
    /// SMB file data (no decoder yet).
    Smb,
    /// DICOM data (no decoder yet).
    Dicom,
    /// TFTP data (no decoder yet).
    Tftp,
    /// FTP data channel (no decoder yet).
    FtpData,
    /// X.509 attribute certificates (no decoder yet).
    X509af,
}

impl ExportProtocol {
    /// Match a case-sensitive protocol name.
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "http" => Self::Http,
            "imf" => Self::Imf,
            "smb" => Self::Smb,
            "dicom" => Self::Dicom,
            "tftp" => Self::Tftp,
            "ftp-data" => Self::FtpData,
            "x509af" => Self::X509af,
            _ => return None,
        })
    }

    /// The name printed and accepted on the command line.
    fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Imf => "imf",
            Self::Smb => "smb",
            Self::Dicom => "dicom",
            Self::Tftp => "tftp",
            Self::FtpData => "ftp-data",
            Self::X509af => "x509af",
        }
    }
}

/// TLS key-log and key-export options shared by every output mode.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsOptions {
    /// `-o tls.keylog_file:PATH`, loaded once before the first frame.
    pub keylog_file: Option<PathBuf>,
    /// `--export-tls-session-keys PATH`.
    pub export_session_keys: Option<PathBuf>,
}

/// Validated options for the default summary and `-T text`.
#[derive(Debug, Clone, PartialEq)]
pub struct SummaryOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// `-t` and `-u` time options.
    pub time: TimeOptions,
    /// Column layout: spaces for `-T text`, tabs for `-T tabs`.
    pub style: SummaryStyle,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Whether packet lines are printed. `-q` and `-Q` suppress the implicit
    /// summary, but not an explicit `-T text`.
    pub print: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `-V`/`-O` detail output, or `None` for the summary line.
    pub detail: Option<DetailOptions>,
    /// `-x`/`--hexdump` packet-bytes output.
    pub hexdump: Option<HexdumpOptions>,
    /// `-P`: print the summary line even when another output mode is active.
    pub print_summary: bool,
    /// `-S` line separator bytes printed after each detail or hexdump block.
    pub separator: Vec<u8>,
    /// `--color`: colorise summary lines on a terminal.
    pub color: bool,
    /// `--pf-terminal-color`: force the summary-colour path for tests.
    pub force_terminal_color: bool,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Validated options for `-T json` and `-T jsonraw`.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// JSON flavour selected by `-T`.
    pub mode: JsonMode,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `-e` fields; empty means the whole decoded tree.
    pub fields: Vec<&'static FieldDef>,
    /// `-j`/`-J` protocol selection, when one was supplied.
    pub protocol_filter: Option<ProtocolFilter>,
    /// `--no-duplicate-keys`: merge repeated keys into arrays.
    pub merge_keys: bool,
    /// `-x`/`--hexdump`: emit each display value's raw array as well.
    pub print_hex: bool,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Validated options for `-T pdml`.
#[derive(Debug, Clone, PartialEq)]
pub struct PdmlOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `-e` fields; empty means the whole decoded tree.
    pub fields: Vec<&'static FieldDef>,
    /// `-j`/`-J` protocol selection, when one was supplied.
    pub protocol_filter: Option<ProtocolFilter>,
    /// `--color`: add foreground/background attributes to each packet.
    pub color: bool,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Validated options for `-T psml`.
#[derive(Debug, Clone, PartialEq)]
pub struct PsmlOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// `-t` and `-u` time options for the Time column.
    pub time: TimeOptions,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `--color`: add foreground/background attributes to each packet.
    pub color: bool,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Validated options for `-T ek`.
#[derive(Debug, Clone, PartialEq)]
pub struct EkOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// `-t` and `-u` time options for `-P` summary bodies.
    pub time: TimeOptions,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `-e` fields; empty means the whole decoded tree.
    pub fields: Vec<&'static FieldDef>,
    /// `-j`/`-J` protocol selection, when one was supplied.
    pub protocol_filter: Option<ProtocolFilter>,
    /// `-x`/`--hexdump`: emit each field's raw value.
    pub print_hex: bool,
    /// `-P`: write summary columns instead of `layers`.
    pub print_summary: bool,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Validated options for `-T ps`.
#[derive(Debug, Clone, PartialEq)]
pub struct PsOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// `-t` and `-u` time options for summary lines.
    pub time: TimeOptions,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `-V`/`-O` detail text, or `None` for summary lines.
    pub detail: Option<DetailOptions>,
    /// `-x`/`--hexdump` packet bytes.
    pub hexdump: Option<HexdumpOptions>,
    /// `--color`: colorise summary pages.
    pub color: bool,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Validated options for `-T fields`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldsOptions {
    /// Capture source: a file, standard input or live interfaces.
    pub input: Input,
    /// Fields to print, in command-line order.
    pub fields: Vec<&'static FieldDef>,
    /// Decoder preferences from `-o`.
    pub decode_options: DecodeOptions,
    /// TLS key-log and key-export options.
    pub tls: TlsOptions,
    /// Global cross-packet state budget in bytes (`--pf-state-budget`).
    pub state_budget: usize,
    /// Statistics selected by repeatable `-z` options.
    pub stats: StatsOptions,
    /// Field output options from `-E`.
    pub output: FieldOutputOptions,
    /// Stop after this many packets (`-c`).
    pub packet_count: Option<u64>,
    /// Flush standard output after each packet (`-l`).
    pub flush: bool,
    /// Parsed `-Y` display filter.
    pub display_filter: Option<Filter>,
    /// Capture writing from `-w`.
    pub write: WriteOptions,
    /// `--export-objects` requests.
    pub exports: Vec<ExportObjects>,
}

/// Limits from `-a` that stop a capture run.
///
/// Each condition is independent; the first one reached stops the run. A
/// repeated category replaces the earlier value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AutostopOptions {
    /// Stop after this many selected packets (`-a packets`).
    pub packets: Option<u64>,
    /// Read mode: stop after the first frame whose pre-frame source offset
    /// reaches this many bytes (`-a filesize`). Live: output bytes in KiB.
    pub filesize: Option<u64>,
    /// Stop after this much wall-clock time (`-a duration`).
    pub duration: Option<std::time::Duration>,
    /// Stop after this many ring files are finished (`-a files`).
    pub files: Option<u64>,
}

/// Ring-buffer rotation from `-b`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RingOptions {
    /// Rotate after this many packets (`-b packets`).
    pub packets: Option<u64>,
    /// Live: rotate after this many uncompressed output KiB (`-b filesize`).
    pub filesize: Option<u64>,
    /// Rotate after this much wall-clock time (`-b duration`).
    pub duration: Option<std::time::Duration>,
    /// Keep at most this many files (`-b files`).
    pub files: Option<u64>,
    /// Write each opened file name to this path (`-b printname`).
    pub printname: Option<PathBuf>,
}

impl RingOptions {
    /// Whether any condition rotates the output or retains ring files.
    pub fn rotates(&self) -> bool {
        self.packets.is_some()
            || self.filesize.is_some()
            || self.duration.is_some()
            || self.files.is_some()
    }
}

/// Capture output requested by `-w`, `-F`, `-a`, `-b`, `--compress`,
/// `--capture-comment`, `-R` and `-2`.
#[derive(Clone, Debug, PartialEq)]
pub struct WriteOptions {
    /// `-w` path; `-` writes the capture to standard output.
    pub file: Option<PathBuf>,
    /// `-F` format; pcapng unless requested.
    pub format: OutputFormat,
    /// Resolved compression from `--compress` or the output extension.
    pub compression: Compression,
    /// Repeatable `--capture-comment` values.
    pub comments: Vec<String>,
    /// `-a` autostop conditions.
    pub autostop: AutostopOptions,
    /// `-b` ring conditions.
    pub ring: RingOptions,
    /// `-2`: analyse in two passes so the read filter sees the whole capture.
    pub two_pass: bool,
    /// `-R` read filter, evaluated against file frame numbers.
    pub read_filter: Option<Filter>,
    /// `-M`: start a new analysis session every this many frames.
    pub reset_interval: Option<u32>,
    /// `--pf-annotation-budget`: bytes reserved for two-pass annotations.
    pub annotation_budget: usize,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            file: None,
            format: OutputFormat::PcapNg,
            compression: Compression::None,
            comments: Vec::new(),
            autostop: AutostopOptions::default(),
            ring: RingOptions::default(),
            two_pass: false,
            read_filter: None,
            reset_interval: None,
            annotation_budget: DEFAULT_ANNOTATION_BUDGET,
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Packetfin's identity string in XML `creator` attributes.
pub const CREATOR: &str = concat!("packetfin/", env!("CARGO_PKG_VERSION"));

/// Parse command-line arguments left to right.
///
/// Help and version act as soon as they are reached; `-G`
/// records the report and is validated after the whole command line, so a
/// later unknown option still fails. A malformed or unsupported combination
/// is reported as [`Action::Usage`] or [`Action::Error`]; an unrecognised
/// option stops parsing with [`Action::Unknown`], and `--` ends option
/// parsing before [`Action::Argument`] reports a positional argument.
/// Whether an output can observe UDP's per-stream timestamp fields.
fn wants_udp_timestamps(
    full_tree: bool,
    fields: &[&'static FieldDef],
    filter_text: Option<&str>,
) -> bool {
    full_tree
        || fields
            .iter()
            .any(|field| matches!(field.abbrev, "udp.time_relative" | "udp.time_delta"))
        || filter_text.is_some_and(|text| {
            text.contains("udp.time_relative") || text.contains("udp.time_delta")
        })
}

pub fn parse(args: &[OsString]) -> Action {
    let mut read_file: Option<PathBuf> = None;
    let mut field_names: Vec<String> = Vec::new();
    let mut fields_requested = false;
    let mut json_mode: Option<JsonMode> = None;
    let mut pdml_requested = false;
    let mut psml_requested = false;
    let mut ek_requested = false;
    let mut ps_requested = false;
    let mut tabs_requested = false;
    let mut protocol_tokens: Vec<(String, bool)> = Vec::new();
    let mut merge_keys = false;
    let mut decode_options = DecodeOptions::default();
    let mut tls_options = TlsOptions::default();
    let mut state_budget = DEFAULT_STATE_BUDGET;
    let mut stats = StatsOptions::default();
    let mut deferred_stats_error: Option<String> = None;
    let mut output = FieldOutputOptions::default();
    let mut packet_count: Option<u64> = None;
    let mut flush = false;
    let mut text_requested = false;
    let mut output_requested = false;
    let mut time = TimeOptions::default();
    let mut quiet = false;
    let mut verbose = false;
    let mut protocol_filter: Option<String> = None;
    let mut hexdump: Option<HexdumpOptions> = None;
    let mut print_summary = false;
    let mut separator: Vec<u8> = Vec::new();
    let mut report: Option<String> = None;
    let mut display_filter_text: Option<String> = None;
    let mut color = false;
    let mut force_terminal_color = false;
    let mut external_requested = false;
    let mut write_file: Option<PathBuf> = None;
    let mut output_format: Option<OutputFormat> = None;
    let mut compression_mode: Option<Compression> = None;
    let mut capture_comments: Vec<String> = Vec::new();
    let mut autostop = AutostopOptions::default();
    let mut ring = RingOptions::default();
    let mut two_pass = false;
    let mut read_filter_text: Option<String> = None;
    let mut live = LiveOptions::default();
    let mut list_link_types = false;
    let mut list_timestamp_types = false;
    let mut exports: Vec<ExportObjects> = Vec::new();
    let mut reset_interval: Option<u32> = None;
    let mut annotation_budget = DEFAULT_ANNOTATION_BUDGET;
    let mut end_of_options = false;
    let mut index = 1;

    while let Some(argument) = args.get(index) {
        index += 1;
        if end_of_options {
            // Words after `--` are capture-filter arguments; a
            // glossary report exits before they are validated.
            if report.is_some() {
                continue;
            }
            return Action::Argument(argument.to_string_lossy().into_owned());
        }
        let Some(argument_text) = argument.to_str() else {
            if argument
                .as_encoded_bytes()
                .starts_with(b"--pf-state-budget=")
            {
                return Action::Error("the --pf-state-budget value is not valid UTF-8".to_string());
            }
            if let Some(value) = attached_field_output(argument) {
                if let Err(message) = apply_field_output_option(value, &mut output) {
                    return Action::Error(message);
                }
                continue;
            }
            if attached_display_filter(argument) {
                return Action::Error("the -Y value is not valid UTF-8".to_string());
            }
            if attached_protocol_filter(argument) {
                protocol_filter = Some(String::new());
                continue;
            }
            if let Some(value) = attached_separator(argument) {
                separator = value.to_vec();
                continue;
            }
            if let Some(value) = attached_export_objects(argument) {
                if let Err(message) = apply_export_objects(value, &mut exports) {
                    return Action::Error(message);
                }
                continue;
            }
            match attached_read_file(argument) {
                Some(path) => {
                    read_file = Some(path);
                    continue;
                }
                None => return Action::Unknown(argument.to_string_lossy().into_owned()),
            }
        };
        match argument_text {
            "--" => end_of_options = true,
            "-h" | "--help" => return Action::Help,
            "--export-tls-session-keys" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    tls_options.export_session_keys = Some(PathBuf::from(value.as_os_str()));
                }
                None => {
                    return Action::Usage(
                        "option --export-tls-session-keys requires a value".to_string(),
                    );
                }
            },
            "--pf-state-budget" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    match parse_state_budget(value) {
                        Ok(budget) => state_budget = budget,
                        Err(message) => return Action::Error(message),
                    }
                }
                None => {
                    return Action::Usage("option --pf-state-budget requires a value".to_string());
                }
            },
            "-z" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -z value is not valid UTF-8".to_string());
                    };
                    if value == "help" {
                        return Action::StatsHelp;
                    }
                    if !stats::name_supported(value) {
                        return Action::StatsError(stats::unsupported(value));
                    }
                    match stats::parse_spec(value) {
                        Ok(spec) => stats.specs.push(spec),
                        Err(message) => {
                            if deferred_stats_error.is_none() {
                                deferred_stats_error = Some(message);
                            }
                        }
                    }
                }
                None => return Action::Usage("option -z requires a value".to_string()),
            },
            "--pf-stats-budget" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    match parse_stats_budget(value) {
                        Ok(budget) => stats.budget = budget,
                        Err(message) => return Action::Error(message),
                    }
                }
                None => {
                    return Action::Usage("option --pf-stats-budget requires a value".to_string());
                }
            },
            "-v" | "--version" => return Action::Version,
            "-n" => {
                decode_options.preferences.nameres = nameres_from_flags("").unwrap_or_default();
            }
            "-N" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -N value is not valid UTF-8".to_string());
                    };
                    if let Err(message) = apply_nameres(value, &mut decode_options) {
                        return Action::Error(message);
                    }
                    external_requested |= value.contains('N');
                }
                None => return Action::Usage("option -N requires a value".to_string()),
            },
            "-H" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    if let Err(message) = add_hosts_file(Path::new(value), &mut decode_options) {
                        return Action::Error(message);
                    }
                }
                None => return Action::Usage("option -H requires a value".to_string()),
            },
            "-d" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -d value is not valid UTF-8".to_string());
                    };
                    if let Err(message) = apply_decode_as(value, &mut decode_options) {
                        return Action::Error(message);
                    }
                }
                None => return Action::Usage("option -d requires a value".to_string()),
            },
            "--enable-protocol" | "--disable-protocol" | "--only-protocols" => {
                match args.get(index) {
                    Some(value) => {
                        index += 1;
                        let Some(value) = value.to_str() else {
                            return Action::Error(format!(
                                "the {argument_text} value is not valid UTF-8"
                            ));
                        };
                        let result = match argument_text {
                            "--enable-protocol" => {
                                apply_protocol_list(value, true, &mut decode_options)
                            }
                            "--disable-protocol" => {
                                apply_protocol_list(value, false, &mut decode_options)
                            }
                            _ => apply_only_protocols(value, &mut decode_options),
                        };
                        if let Err(message) = result {
                            return Action::Error(message);
                        }
                    }
                    None => {
                        return Action::Usage(format!("option {argument_text} requires a value"));
                    }
                }
            }
            "--enable-heuristic" | "--disable-heuristic" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error(format!(
                            "the {argument_text} value is not valid UTF-8"
                        ));
                    };
                    if let Err(message) = apply_heuristic(
                        value,
                        argument_text == "--enable-heuristic",
                        &mut decode_options,
                    ) {
                        return Action::Error(message);
                    }
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "--color" => color = true,
            "--pf-terminal-color" => force_terminal_color = true,
            "-r" | "--read-file" => match args.get(index) {
                Some(value) => {
                    read_file = Some(PathBuf::from(value.as_os_str()));
                    index += 1;
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-i" | "--interface" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -i value is not valid UTF-8".to_string());
                    };
                    live.interfaces.push(value.to_string());
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-D" | "--list-interfaces" => {
                // Print the list as soon as -D is seen, without validating
                // the options that follow.
                return Action::ListDevices;
            }
            "-L" | "--list-data-link-types" => {
                list_link_types = true;
            }
            "--list-time-stamp-types" => {
                list_timestamp_types = true;
            }
            "-f" | "--capture-filter" => {
                match args.get(index) {
                    Some(value) => {
                        index += 1;
                        let Some(value) = value.to_str() else {
                            return Action::Error("the -f value is not valid UTF-8".to_string());
                        };
                        // The last capture filter wins.
                        live.capture_filter = Some(value.to_string());
                    }
                    None => {
                        return Action::Usage(format!("option {argument_text} requires a value"));
                    }
                }
            }
            "-s" | "--snapshot-length" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -s value is not valid UTF-8".to_string());
                    };
                    match parse_snaplen(value) {
                        Ok(snaplen) => live.snaplen = Some(snaplen),
                        Err(message) => return Action::Error(message),
                    }
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-p" | "--no-promiscuous-mode" => {
                live.promisc = false;
            }
            "-I" | "--monitor-mode" => {
                live.monitor = true;
            }
            "-B" | "--buffer-size" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -B value is not valid UTF-8".to_string());
                    };
                    match parse_buffer_size(value) {
                        Ok(buffer) => live.buffer_bytes = Some(buffer),
                        Err(message) => return Action::Error(message),
                    }
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-y" | "--link-type" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -y value is not valid UTF-8".to_string());
                    };
                    match link_type_from_name(value) {
                        Ok(link_type) => live.link_type = Some(link_type),
                        Err(action) => return action,
                    }
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "--time-stamp-type" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error(
                            "the --time-stamp-type value is not valid UTF-8".to_string(),
                        );
                    };
                    live.tstamp_type = Some(value.to_string());
                }
                None => {
                    return Action::Usage("option --time-stamp-type requires a value".to_string());
                }
            },
            "-Y" | "--display-filter" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -Y value is not valid UTF-8".to_string());
                    };
                    display_filter_text = Some(value.to_string());
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-w" | "--write-file" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    write_file = Some(PathBuf::from(value.as_os_str()));
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-F" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    match output_format_from_os(value) {
                        Ok(format) => output_format = Some(format),
                        Err(message) => return Action::Error(message),
                    }
                }
                None => return Action::Usage("option -F requires a value".to_string()),
            },
            "--compress" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    match compression_from_os(value) {
                        Ok(mode) => compression_mode = Some(mode),
                        Err(action) => return action,
                    }
                }
                None => {
                    return Action::Usage("option --compress requires a value".to_string());
                }
            },
            "--capture-comment" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error(
                            "the --capture-comment value is not valid UTF-8".to_string(),
                        );
                    };
                    capture_comments.push(value.to_string());
                }
                None => {
                    return Action::Usage("option --capture-comment requires a value".to_string());
                }
            },
            "-a" | "--autostop" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -a value is not valid UTF-8".to_string());
                    };
                    if let Err(message) = apply_autostop(value, &mut autostop) {
                        return Action::Error(message);
                    }
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-b" | "--ring-buffer" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -b value is not valid UTF-8".to_string());
                    };
                    if let Err(message) = apply_ring(value, &mut ring) {
                        return Action::Error(message);
                    }
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "-2" | "--two-pass" => {
                if reset_interval.is_some() {
                    return Action::Usage("-2 does not support auto session reset.".to_string());
                }
                two_pass = true;
            }
            "-M" => {
                if two_pass {
                    return Action::Usage("-M does not support two-pass analysis.".to_string());
                }
                match args.get(index) {
                    Some(value) => {
                        index += 1;
                        match parse_reset_count(value) {
                            Ok(count) => reset_interval = Some(count),
                            Err(message) => return Action::Usage(message),
                        }
                    }
                    None => {
                        return Action::Usage("option -M requires a value".to_string());
                    }
                }
            }
            "--pf-annotation-budget" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error(
                            "the --pf-annotation-budget value is not valid UTF-8".to_string(),
                        );
                    };
                    match parse_budget(value, "--pf-annotation-budget") {
                        Ok(budget) => annotation_budget = budget,
                        Err(message) => return Action::Error(message),
                    }
                }
                None => {
                    return Action::Usage(
                        "option --pf-annotation-budget requires a value".to_string(),
                    );
                }
            },
            "-R" | "--read-filter" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -R value is not valid UTF-8".to_string());
                    };
                    read_filter_text = Some(value.to_string());
                }
                None => {
                    return Action::Usage(format!("option {argument_text} requires a value"));
                }
            },
            "--export-objects" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = os_str_bytes(value) else {
                        return Action::Error(
                            "the --export-objects value is not valid UTF-8".to_string(),
                        );
                    };
                    if let Err(message) = apply_export_objects(value, &mut exports) {
                        return Action::Error(message);
                    }
                }
                None => {
                    return Action::Usage("option --export-objects requires a value".to_string());
                }
            },
            "-T" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -T value is not valid UTF-8".to_string());
                    };
                    if output_requested {
                        return Action::Error("Multiple -T parameters are unsupported".to_string());
                    }
                    output_requested = true;
                    match value {
                        "fields" => fields_requested = true,
                        "text" => text_requested = true,
                        "json" => json_mode = Some(JsonMode::Json),
                        "jsonraw" => json_mode = Some(JsonMode::JsonRaw),
                        "pdml" => pdml_requested = true,
                        "psml" => psml_requested = true,
                        "ek" => ek_requested = true,
                        "ps" => ps_requested = true,
                        "tabs" => tabs_requested = true,
                        _ => return unsupported_output(value),
                    }
                }
                None => return Action::Usage("option -T requires a value".to_string()),
            },
            "-e" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -e value is not valid UTF-8".to_string());
                    };
                    field_names.push(value.to_string());
                }
                None => return Action::Usage("option -e requires a value".to_string()),
            },
            "-o" => match args.get(index) {
                Some(value) => {
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -o value is not valid UTF-8".to_string());
                    };
                    index += 1;
                    if let Some((name, setting)) = value.split_once(':')
                        && name.eq_ignore_ascii_case("tls.keylog_file")
                    {
                        tls_options.keylog_file = Some(PathBuf::from(setting));
                    } else {
                        match apply_preference(value, &mut decode_options.preferences) {
                            Ok(()) => external_requested |= requests_external(value),
                            Err(error) => {
                                return Action::Error(format_preference_error(value, error));
                            }
                        }
                    }
                }
                None => return Action::Usage("option -o requires a value".to_string()),
            },
            "-E" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    match apply_field_output_os(value.as_os_str(), &mut output) {
                        Ok(()) => {}
                        Err(message) => return Action::Error(message),
                    }
                }
                None => return Action::Usage("option -E requires a value".to_string()),
            },
            "-t" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -t value is not valid UTF-8".to_string());
                    };
                    match apply_time_format(value, &mut time) {
                        Ok(()) => {}
                        Err(message) => return Action::Error(message),
                    }
                }
                None => return Action::Usage("option -t requires a value".to_string()),
            },
            "-u" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -u value is not valid UTF-8".to_string());
                    };
                    match value {
                        "s" => time.hours_minutes_seconds = false,
                        "hms" => time.hours_minutes_seconds = true,
                        _ => {
                            return Action::Error("invalid seconds type; use s or hms".to_string());
                        }
                    }
                }
                None => return Action::Usage("option -u requires a value".to_string()),
            },
            "-c" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -c value is not valid UTF-8".to_string());
                    };
                    match parse_packet_count(value) {
                        Ok(count) => packet_count = Some(count),
                        Err(message) => return Action::Error(message),
                    }
                }
                None => return Action::Usage("option -c requires a value".to_string()),
            },
            "-V" => {
                verbose = true;
            }
            "-x" => {
                hexdump.get_or_insert_with(HexdumpOptions::default);
            }
            "-P" | "--print" => {
                print_summary = true;
            }
            "-S" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    separator = os_str_bytes(value)
                        .map(<[u8]>::to_vec)
                        .unwrap_or_else(|| value.to_string_lossy().as_bytes().to_vec());
                }
                None => return Action::Usage("option -S requires a value".to_string()),
            },
            "--hexdump" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    let option = value.to_string_lossy();
                    if option == "help" {
                        return Action::HexdumpHelp;
                    }
                    let options = hexdump.get_or_insert_with(HexdumpOptions::default);
                    if !options.apply(&option) {
                        return Action::Error(format!("invalid --hexdump option: {option}"));
                    }
                }
                None => {
                    return Action::Usage("option --hexdump requires a value".to_string());
                }
            },
            "-O" => {
                match args.get(index) {
                    Some(value) => {
                        index += 1;
                        // A protocol list that matches nothing is treated
                        // as unknown and parsing keeps going; a non-UTF-8
                        // list therefore selects nothing.
                        protocol_filter = Some(match value.to_str() {
                            Some(value) => value.to_string(),
                            None => String::new(),
                        });
                    }
                    None => return Action::Usage("option -O requires a value".to_string()),
                }
            }
            "-j" | "-J" => {
                let include_children = argument_text == "-J";
                match args.get(index) {
                    Some(value) => {
                        index += 1;
                        let Some(value) = value.to_str() else {
                            return Action::Error(format!(
                                "the {argument_text} value is not valid UTF-8"
                            ));
                        };
                        add_protocol_tokens(value, include_children, &mut protocol_tokens);
                    }
                    None => {
                        return Action::Usage(format!("option {argument_text} requires a value"));
                    }
                }
            }
            "--no-duplicate-keys" => {
                merge_keys = true;
            }
            "-l" => {
                flush = true;
            }
            "-q" => {
                quiet = true;
            }
            "-Q" => {
                quiet = true;
                live.suppress_messages = true;
            }
            "-G" => match args.get(index) {
                Some(value) => {
                    index += 1;
                    if report.is_some() {
                        return multiple_reports();
                    }
                    let Some(value) = value.to_str() else {
                        return Action::Error("the -G value is not valid UTF-8".to_string());
                    };
                    report = Some(value.to_string());
                }
                None => return Action::Usage("option -G requires an argument".to_string()),
            },
            token => {
                if let Some(value) = token.strip_prefix("-S") {
                    separator = value.as_bytes().to_vec();
                } else if let Some(value) = token.strip_prefix("--hexdump=") {
                    if value == "help" {
                        return Action::HexdumpHelp;
                    }
                    let options = hexdump.get_or_insert_with(HexdumpOptions::default);
                    if !options.apply(value) {
                        return Action::Error(format!("invalid --hexdump option: {value}"));
                    }
                } else if let Some(value) = token.strip_prefix("--interface=") {
                    live.interfaces.push(value.to_string());
                } else if let Some(value) = token.strip_prefix("-i") {
                    if value.is_empty() {
                        return Action::Usage("option -i requires a value".to_string());
                    }
                    live.interfaces.push(value.to_string());
                } else if let Some(value) = token.strip_prefix("--capture-filter=") {
                    live.capture_filter = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("-f") {
                    if value.is_empty() {
                        return Action::Usage("option -f requires a value".to_string());
                    }
                    live.capture_filter = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("--snapshot-length=") {
                    match parse_snaplen(value) {
                        Ok(snaplen) => live.snaplen = Some(snaplen),
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("-s") {
                    if value.is_empty() {
                        return Action::Usage("option -s requires a value".to_string());
                    }
                    match parse_snaplen(value) {
                        Ok(snaplen) => live.snaplen = Some(snaplen),
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("--buffer-size=") {
                    match parse_buffer_size(value) {
                        Ok(buffer) => live.buffer_bytes = Some(buffer),
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("-B") {
                    if value.is_empty() {
                        return Action::Usage("option -B requires a value".to_string());
                    }
                    match parse_buffer_size(value) {
                        Ok(buffer) => live.buffer_bytes = Some(buffer),
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("--link-type=") {
                    match link_type_from_name(value) {
                        Ok(link_type) => live.link_type = Some(link_type),
                        Err(action) => return action,
                    }
                } else if let Some(value) = token.strip_prefix("-y") {
                    if value.is_empty() {
                        return Action::Usage("option -y requires a value".to_string());
                    }
                    match link_type_from_name(value) {
                        Ok(link_type) => live.link_type = Some(link_type),
                        Err(action) => return action,
                    }
                } else if let Some(value) = token.strip_prefix("--time-stamp-type=") {
                    live.tstamp_type = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("--display-filter=") {
                    display_filter_text = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("-Y") {
                    if value.is_empty() {
                        return Action::Usage("option -Y requires a value".to_string());
                    }
                    display_filter_text = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("--write-file=") {
                    write_file = Some(PathBuf::from(value));
                } else if let Some(value) = token.strip_prefix("-w") {
                    if value.is_empty() {
                        return Action::Usage("option -w requires a value".to_string());
                    }
                    write_file = Some(PathBuf::from(value));
                } else if let Some(value) = token.strip_prefix("-F") {
                    if value.is_empty() {
                        return Action::Usage("option -F requires a value".to_string());
                    }
                    match output_format_from_os(OsStr::new(value)) {
                        Ok(format) => output_format = Some(format),
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("--compress=") {
                    match compression_from_os(OsStr::new(value)) {
                        Ok(mode) => compression_mode = Some(mode),
                        Err(action) => return action,
                    }
                } else if let Some(value) = token.strip_prefix("--capture-comment=") {
                    capture_comments.push(value.to_string());
                } else if let Some(value) = token.strip_prefix("--autostop=") {
                    if let Err(message) = apply_autostop(value, &mut autostop) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("-a") {
                    if value.is_empty() {
                        return Action::Usage("option -a requires a value".to_string());
                    }
                    if let Err(message) = apply_autostop(value, &mut autostop) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--ring-buffer=") {
                    if let Err(message) = apply_ring(value, &mut ring) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("-b") {
                    if value.is_empty() {
                        return Action::Usage("option -b requires a value".to_string());
                    }
                    if let Err(message) = apply_ring(value, &mut ring) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--read-filter=") {
                    read_filter_text = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("-R") {
                    if value.is_empty() {
                        return Action::Usage("option -R requires a value".to_string());
                    }
                    read_filter_text = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("--pf-stats-budget=") {
                    match parse_stats_budget(OsStr::new(value)) {
                        Ok(budget) => stats.budget = budget,
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("--pf-state-budget=") {
                    match parse_state_budget(OsStr::new(value)) {
                        Ok(budget) => state_budget = budget,
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("--export-objects=") {
                    if let Err(message) = apply_export_objects(value.as_bytes(), &mut exports) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--pf-annotation-budget=") {
                    match parse_budget(value, "--pf-annotation-budget") {
                        Ok(budget) => annotation_budget = budget,
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("-M") {
                    if value.is_empty() {
                        return Action::Usage("option -M requires a value".to_string());
                    }
                    if two_pass {
                        return Action::Usage("-M does not support two-pass analysis.".to_string());
                    }
                    match parse_reset_count(OsStr::new(value)) {
                        Ok(count) => reset_interval = Some(count),
                        Err(message) => return Action::Usage(message),
                    }
                } else if let Some(value) = token.strip_prefix("--read-file=") {
                    read_file = Some(PathBuf::from(value));
                } else if let Some(value) = token.strip_prefix("-r") {
                    if value.is_empty() {
                        return Action::Usage("option -r requires a value".to_string());
                    }
                    read_file = Some(PathBuf::from(value));
                } else if let Some(value) = token.strip_prefix("-T") {
                    if value.is_empty() {
                        return Action::Usage("option -T requires a value".to_string());
                    }
                    if output_requested {
                        return Action::Error("Multiple -T parameters are unsupported".to_string());
                    }
                    output_requested = true;
                    match value {
                        "fields" => fields_requested = true,
                        "text" => text_requested = true,
                        "json" => json_mode = Some(JsonMode::Json),
                        "jsonraw" => json_mode = Some(JsonMode::JsonRaw),
                        "pdml" => pdml_requested = true,
                        "psml" => psml_requested = true,
                        "ek" => ek_requested = true,
                        "ps" => ps_requested = true,
                        "tabs" => tabs_requested = true,
                        _ => return unsupported_output(value),
                    }
                } else if let Some(value) = token.strip_prefix("-e") {
                    if value.is_empty() {
                        return Action::Usage("option -e requires a value".to_string());
                    }
                    field_names.push(value.to_string());
                } else if let Some(value) = token.strip_prefix("-o") {
                    if value.is_empty() {
                        return Action::Usage("option -o requires a value".to_string());
                    }
                    if let Some((name, setting)) = value.split_once(':')
                        && name.eq_ignore_ascii_case("tls.keylog_file")
                    {
                        tls_options.keylog_file = Some(PathBuf::from(setting));
                    } else {
                        match apply_preference(value, &mut decode_options.preferences) {
                            Ok(()) => external_requested |= requests_external(value),
                            Err(error) => {
                                return Action::Error(format_preference_error(value, error));
                            }
                        }
                    }
                } else if let Some(value) = token.strip_prefix("-E") {
                    if value.is_empty() {
                        return Action::Usage("option -E requires a value".to_string());
                    }
                    match apply_field_output_option(value.as_bytes(), &mut output) {
                        Ok(()) => {}
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("-c") {
                    if value.is_empty() {
                        return Action::Usage("option -c requires a value".to_string());
                    }
                    match parse_packet_count(value) {
                        Ok(count) => packet_count = Some(count),
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("-t") {
                    if value.is_empty() {
                        return Action::Usage("option -t requires a value".to_string());
                    }
                    match apply_time_format(value, &mut time) {
                        Ok(()) => {}
                        Err(message) => return Action::Error(message),
                    }
                } else if let Some(value) = token.strip_prefix("-u") {
                    if value.is_empty() {
                        return Action::Usage("option -u requires a value".to_string());
                    }
                    match value {
                        "s" => time.hours_minutes_seconds = false,
                        "hms" => time.hours_minutes_seconds = true,
                        _ => {
                            return Action::Error("invalid seconds type; use s or hms".to_string());
                        }
                    }
                } else if let Some(value) = token.strip_prefix("--no-duplicate-keys") {
                    if !value.is_empty() {
                        return Action::Unknown(token.to_string());
                    }
                    merge_keys = true;
                } else if let Some(value) = token.strip_prefix("-j") {
                    if value.is_empty() {
                        return Action::Usage("option -j requires a value".to_string());
                    }
                    add_protocol_tokens(value, false, &mut protocol_tokens);
                } else if let Some(value) = token.strip_prefix("-J") {
                    if value.is_empty() {
                        return Action::Usage("option -J requires a value".to_string());
                    }
                    add_protocol_tokens(value, true, &mut protocol_tokens);
                } else if let Some(value) = token.strip_prefix("-O") {
                    if value.is_empty() {
                        return Action::Usage("option -O requires a value".to_string());
                    }
                    protocol_filter = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("-G") {
                    if value.is_empty() {
                        return Action::Usage("option -G requires an argument".to_string());
                    }
                    if report.is_some() {
                        return multiple_reports();
                    }
                    report = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("--enable-protocol=") {
                    if let Err(message) = apply_protocol_list(value, true, &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--disable-protocol=") {
                    if let Err(message) = apply_protocol_list(value, false, &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--only-protocols=") {
                    if let Err(message) = apply_only_protocols(value, &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--enable-heuristic=") {
                    if let Err(message) = apply_heuristic(value, true, &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("--disable-heuristic=") {
                    if let Err(message) = apply_heuristic(value, false, &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("-N") {
                    if value.is_empty() {
                        return Action::Usage("option -N requires a value".to_string());
                    }
                    if let Err(message) = apply_nameres(value, &mut decode_options) {
                        return Action::Error(message);
                    }
                    external_requested |= value.contains('N');
                } else if let Some(value) = token.strip_prefix("-H") {
                    if value.is_empty() {
                        return Action::Usage("option -H requires a value".to_string());
                    }
                    if let Err(message) = add_hosts_file(Path::new(value), &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if let Some(value) = token.strip_prefix("-d") {
                    if value.is_empty() {
                        return Action::Usage("option -d requires a value".to_string());
                    }
                    if let Err(message) = apply_decode_as(value, &mut decode_options) {
                        return Action::Error(message);
                    }
                } else if token == "--color" {
                    color = true;
                } else if token == "--pf-terminal-color" {
                    force_terminal_color = true;
                } else {
                    return Action::Unknown(token.to_string());
                }
            }
        }
    }

    decode_options.policy.finalize();
    if external_requested
        && decode_options
            .preferences
            .nameres
            .use_external_name_resolver
    {
        decode_options.notices.push(
            "external name resolution (-N N) is not implemented; addresses stay numeric"
                .to_string(),
        );
    }

    let invalid: Vec<String> = protocol_tokens
        .iter()
        .filter_map(|(name, _)| {
            if Filter::parse(name).is_err() && !synthetic_protocol_name(name) {
                Some(name.clone())
            } else {
                None
            }
        })
        .fold(Vec::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        });
    if !invalid.is_empty() {
        return Action::Error(format!(
            "invalid protocol filter field(s): {}",
            invalid.join(", ")
        ));
    }

    if list_link_types || list_timestamp_types {
        if read_file.is_some() {
            return Action::Error(
                "interface capability lists cannot be combined with a capture file to read"
                    .to_string(),
            );
        }
        // A list still validates the rest of the command line;
        // capture-time options (-w, -a duration/filesize, -f) are ignored.
        if let Err(action) = compile_display_filter(&display_filter_text) {
            return action;
        }
        if read_filter_text.is_some() && !two_pass {
            return Action::Error("-R requires -2; use -Y for single-pass filtering".to_string());
        }
        if let Err(action) = compile_display_filter(&read_filter_text) {
            return action;
        }
        if autostop.files.is_some() || ring.rotates() || ring.printname.is_some() {
            return Action::Error(
                "a ring buffer or files limit requires a capture to be running".to_string(),
            );
        }
        if fields_requested && field_names.is_empty() {
            return Action::Usage("-T fields requires at least one -e FIELD".to_string());
        }
        if !fields_requested && !field_names.is_empty() {
            if json_mode == Some(JsonMode::JsonRaw) {
                return Action::Error(
                    "output fields (-e) cannot be printed with -T jsonraw".to_string(),
                );
            }
            if !(json_mode.is_some() || pdml_requested || psml_requested || ek_requested) {
                return Action::Usage(
                    "-e requires -T fields, -T json, -T pdml, -T psml or -T ek".to_string(),
                );
            }
        }
        if let Err(action) = resolve_fields(&field_names) {
            return action;
        }
        if merge_keys && !matches!(json_mode, Some(JsonMode::Json | JsonMode::JsonRaw)) {
            return Action::Error(
                "--no-duplicate-keys can only be used with -T json or -T jsonraw".to_string(),
            );
        }
        if hexdump.is_some() && (fields_requested || pdml_requested || psml_requested) {
            return Action::Error(
                "raw packet hex data cannot be printed with -T fields, -T pdml or -T psml"
                    .to_string(),
            );
        }
        if psml_requested && protocol_filter.is_some() {
            return Action::Error("-O can only be used with -V".to_string());
        }
        return Action::ListCaptureModes {
            options: Box::new(live),
            modes: ListModes {
                link_types: list_link_types,
                timestamp_types: list_timestamp_types,
            },
        };
    }

    let write = match resolve_write_options(
        write_file,
        output_format,
        compression_mode,
        capture_comments,
        autostop,
        ring,
        two_pass,
        read_filter_text,
        reset_interval,
        annotation_budget,
        read_file.is_some(),
        live.capture_filter.as_deref(),
        display_filter_text.as_deref(),
        output_requested
            || verbose
            || protocol_filter.is_some()
            || hexdump.is_some()
            || print_summary,
    ) {
        Ok(write) => write,
        Err(action) => return action,
    };

    let input = match read_file {
        Some(path) => Input::Read(path),
        None => Input::Live(Box::new(live)),
    };

    if let Some(value) = report {
        if fields_requested {
            if field_names.is_empty() {
                return Action::Usage("-T fields requires at least one -e FIELD".to_string());
            }
            if let Err(action) = resolve_fields(&field_names) {
                return action;
            }
        } else if !field_names.is_empty() && json_mode.is_none() {
            return Action::Usage("-e requires -T fields".to_string());
        }
        return report_action(&value);
    }

    if let Some(mode) = json_mode {
        if mode == JsonMode::JsonRaw && !field_names.is_empty() {
            return Action::Error(
                "output fields (-e) cannot be printed with -T jsonraw".to_string(),
            );
        }
        let fields = if field_names.is_empty() {
            Vec::new()
        } else {
            match resolve_fields(&field_names) {
                Ok(fields) => fields,
                Err(action) => return action,
            }
        };
        let display_filter = match compile_display_filter_deferred(
            &display_filter_text,
            &mut deferred_stats_error,
        ) {
            Ok(filter) => filter,
            Err(action) => return action,
        };
        let mut decode_options = decode_options;
        decode_options.udp_timestamps =
            wants_udp_timestamps(fields.is_empty(), &fields, display_filter_text.as_deref());
        return Action::Json(Box::new(JsonOptions {
            input,
            mode,
            decode_options,
            tls: tls_options.clone(),
            state_budget,
            stats: stats.clone(),
            packet_count,
            flush,
            display_filter,
            fields,
            protocol_filter: ProtocolFilter::new(&protocol_tokens),
            merge_keys,
            print_hex: hexdump.is_some(),
            write,
            exports,
        }));
    }

    if merge_keys {
        return Action::Error(
            "--no-duplicate-keys can only be used with \"-T json\" or \"-T jsonraw\"".to_string(),
        );
    }

    if pdml_requested || psml_requested {
        if hexdump.is_some() {
            return Action::Error(
                "raw packet hex data cannot be printed with -T pdml or -T psml".to_string(),
            );
        }
        if psml_requested && protocol_filter.is_some() {
            return Action::Error("-O can only be used with -V".to_string());
        }
        let fields = match resolve_fields(&field_names) {
            Ok(fields) => fields,
            Err(action) => return action,
        };
        let display_filter = match compile_display_filter_deferred(
            &display_filter_text,
            &mut deferred_stats_error,
        ) {
            Ok(filter) => filter,
            Err(action) => return action,
        };
        if pdml_requested {
            let mut decode_options = decode_options;
            decode_options.udp_timestamps =
                wants_udp_timestamps(fields.is_empty(), &fields, display_filter_text.as_deref());
            return Action::Pdml(Box::new(PdmlOptions {
                input,
                decode_options,
                tls: tls_options.clone(),
                state_budget,
                stats: stats.clone(),
                packet_count,
                flush,
                display_filter,
                fields,
                protocol_filter: ProtocolFilter::new(&protocol_tokens),
                write,
                color,
                exports,
            }));
        }
        let mut decode_options = decode_options;
        decode_options.udp_timestamps =
            wants_udp_timestamps(false, &[], display_filter_text.as_deref());
        return Action::Psml(Box::new(PsmlOptions {
            input,
            time,
            decode_options,
            tls: tls_options.clone(),
            state_budget,
            stats: stats.clone(),
            packet_count,
            flush,
            display_filter,
            write,
            color,
            exports,
        }));
    }

    if ek_requested {
        let fields = match resolve_fields(&field_names) {
            Ok(fields) => fields,
            Err(action) => return action,
        };
        let display_filter = match compile_display_filter_deferred(
            &display_filter_text,
            &mut deferred_stats_error,
        ) {
            Ok(filter) => filter,
            Err(action) => return action,
        };
        let mut decode_options = decode_options;
        decode_options.udp_timestamps = wants_udp_timestamps(
            !print_summary && fields.is_empty(),
            &fields,
            display_filter_text.as_deref(),
        );
        return Action::Ek(Box::new(EkOptions {
            input,
            time,
            decode_options,
            tls: tls_options.clone(),
            state_budget,
            stats: stats.clone(),
            packet_count,
            flush,
            display_filter,
            fields,
            protocol_filter: ProtocolFilter::new(&protocol_tokens),
            print_hex: hexdump.is_some(),
            print_summary,
            write,
            exports,
        }));
    }

    if ps_requested {
        if !field_names.is_empty() {
            return Action::Error("output fields (-e) cannot be printed with -T ps".to_string());
        }
        let display_filter = match compile_display_filter_deferred(
            &display_filter_text,
            &mut deferred_stats_error,
        ) {
            Ok(filter) => filter,
            Err(action) => return action,
        };
        let detail = if verbose || protocol_filter.is_some() {
            Some(DetailOptions {
                protocols: protocol_filter
                    .map(|list| list.split(',').map(str::to_string).collect()),
            })
        } else {
            None
        };
        let mut decode_options = decode_options;
        decode_options.udp_timestamps =
            wants_udp_timestamps(detail.is_some(), &[], display_filter_text.as_deref());
        return Action::Ps(Box::new(PsOptions {
            input,
            time,
            decode_options,
            tls: tls_options.clone(),
            state_budget,
            stats: stats.clone(),
            packet_count,
            flush,
            display_filter,
            detail,
            hexdump,
            write,
            color,
            exports,
        }));
    }

    if !fields_requested {
        if !field_names.is_empty() {
            if tabs_requested {
                return Action::Error(
                    "output fields (-e) cannot be printed with -T tabs".to_string(),
                );
            }
            return Action::Usage("-e requires -T fields".to_string());
        }
        let display_filter = match compile_display_filter_deferred(
            &display_filter_text,
            &mut deferred_stats_error,
        ) {
            Ok(filter) => filter,
            Err(action) => return action,
        };
        let detail = if verbose || protocol_filter.is_some() {
            Some(DetailOptions {
                protocols: protocol_filter
                    .map(|list| list.split(',').map(str::to_string).collect()),
            })
        } else {
            None
        };
        // `-w` suppresses only the implicit summary; an explicit `-T text`
        // or `-T tabs` still prints, and `-P` forces the line.
        let implicit_summary = write.file.is_none();
        let mut decode_options = decode_options;
        decode_options.udp_timestamps = wants_udp_timestamps(
            detail.is_some() || !stats.specs.is_empty(),
            &[],
            display_filter_text.as_deref(),
        );
        return Action::Summary(Box::new(SummaryOptions {
            input,
            time,
            style: if tabs_requested {
                SummaryStyle::Tabs
            } else {
                SummaryStyle::Text
            },
            decode_options,
            tls: tls_options.clone(),
            state_budget,
            stats: stats.clone(),
            packet_count,
            flush,
            print: tabs_requested || text_requested || (!quiet && implicit_summary),
            display_filter,
            detail,
            hexdump,
            print_summary,
            separator,
            write,
            color,
            force_terminal_color,
            exports,
        }));
    }

    if hexdump.is_some() {
        return Action::Error("raw packet hex data cannot be printed with -T fields".to_string());
    }

    if field_names.is_empty() {
        return Action::Usage("-T fields requires at least one -e FIELD".to_string());
    }

    let fields = match resolve_fields(&field_names) {
        Ok(fields) => fields,
        Err(action) => return action,
    };
    let display_filter =
        match compile_display_filter_deferred(&display_filter_text, &mut deferred_stats_error) {
            Ok(filter) => filter,
            Err(action) => return action,
        };

    decode_options.udp_timestamps =
        wants_udp_timestamps(false, &fields, display_filter_text.as_deref());
    Action::Fields(Box::new(FieldsOptions {
        input,
        fields,
        decode_options,
        tls: tls_options.clone(),
        state_budget,
        stats: stats.clone(),
        output,
        packet_count,
        flush,
        display_filter,
        write,
        exports,
    }))
}

/// Accepted names for items Packetfin synthesises outside its field
/// registry: the data node, packet comments and expert pseudo-protocols.
fn synthetic_protocol_name(name: &str) -> bool {
    matches!(
        name,
        "data" | "pkt_comment" | "frame.comment" | "_ws.expert" | "_ws.malformed" | "_ws.short"
    )
}

/// Append the space-separated names in one `-j` or `-J` value.
///
/// Only a literal space splits names; consecutive spaces add no names.
fn add_protocol_tokens(value: &str, include_children: bool, tokens: &mut Vec<(String, bool)>) {
    for name in value.split(' ') {
        if !name.is_empty() {
            tokens.push((name.to_string(), include_children));
        }
    }
}

/// Resolve every `-e` value to a registry field, in command-line order.
fn resolve_fields(field_names: &[String]) -> Result<Vec<&'static FieldDef>, Action> {
    let mut fields = Vec::with_capacity(field_names.len());
    for name in field_names {
        match field_by_abbrev(name) {
            Some(field) => fields.push(field),
            None => return Err(Action::Error(format!("unknown output field: {name}"))),
        }
    }
    Ok(fields)
}

/// Parse a `-Y` expression, if one was supplied.
fn compile_display_filter_deferred(
    text: &Option<String>,
    deferred: &mut Option<String>,
) -> Result<Option<Filter>, Action> {
    let filter = compile_display_filter(text)?;
    if let Some(message) = deferred.take() {
        return Err(Action::StatsError(message));
    }
    Ok(filter)
}

fn compile_display_filter(text: &Option<String>) -> Result<Option<Filter>, Action> {
    match text {
        Some(text) => match Filter::parse(text) {
            Ok(filter) => Ok(Some(filter)),
            Err(error) => Err(Action::DisplayFilter {
                filter: text.clone(),
                error,
            }),
        },
        None => Ok(None),
    }
}

/// Apply one `-t FORMAT[.N]` argument.
fn apply_time_format(value: &str, options: &mut TimeOptions) -> Result<(), String> {
    let has_dot = value.contains('.');
    let (format, precision) = match value.split_once('.') {
        Some((format, digits)) => {
            let precision = if digits.is_empty() {
                None
            } else {
                let parsed = digits.parse::<u8>().map_err(|_| {
                    format!("invalid time stamp precision {digits:?}; use 0 through 9 or none")
                })?;
                if parsed > 9 {
                    return Err(format!(
                        "invalid time stamp precision {digits:?}; use 0 through 9 or none"
                    ));
                }
                Some(parsed)
            };
            (format, precision)
        }
        None => (value, None),
    };
    let selected = match format {
        "r" => TimeFormat::Relative,
        "a" => TimeFormat::Absolute,
        "ad" => TimeFormat::AbsoluteWithDate,
        "adoy" => TimeFormat::AbsoluteWithDayOfYear,
        "d" => TimeFormat::Delta,
        "dd" => TimeFormat::DeltaDisplayed,
        "e" => TimeFormat::Epoch,
        "u" => TimeFormat::Utc,
        "ud" => TimeFormat::UtcWithDate,
        "udoy" => TimeFormat::UtcWithDayOfYear,
        "" if has_dot => options.format,
        other => {
            return Err(format!(
                "invalid time stamp type {other:?}; use a, ad, adoy, d, dd, e, r, u, ud or udoy"
            ));
        }
    };
    options.format = selected;
    if precision.is_some() {
        options.precision = precision;
    }
    Ok(())
}

fn multiple_reports() -> Action {
    Action::Error("multiple glossary reports (-G) are not supported".to_string())
}

/// Split a non-UTF-8 argument that carries a capture path.
///
/// Only the attached value is inspected as bytes; option names are ASCII.
#[cfg(unix)]
fn attached_read_file(argument: &OsStr) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    const LONG: &[u8] = b"--read-file=";
    const SHORT: &[u8] = b"-r";
    let bytes = argument.as_bytes();
    let value = bytes
        .strip_prefix(LONG)
        .or_else(|| bytes.strip_prefix(SHORT))?;
    Some(PathBuf::from(OsStr::from_bytes(value)))
}

#[cfg(not(unix))]
fn attached_read_file(_: &OsStr) -> Option<PathBuf> {
    None
}

/// Bytes after an attached `--export-objects=` on a non-UTF-8 argument.
#[cfg(unix)]
fn attached_export_objects(argument: &OsStr) -> Option<&[u8]> {
    use std::os::unix::ffi::OsStrExt;

    argument.as_bytes().strip_prefix(b"--export-objects=")
}

#[cfg(not(unix))]
fn attached_export_objects(_: &OsStr) -> Option<&[u8]> {
    None
}

/// Parse `PROTOCOL,DESTDIR` and append it to the export list.
///
/// Only the first comma splits: the destination may itself contain
/// commas (`http,out,extra` writes into `out,extra`). Protocol names are
/// case-sensitive; a repeated protocol is an error.
fn apply_export_objects(bytes: &[u8], exports: &mut Vec<ExportObjects>) -> Result<(), String> {
    const FORM: &str = "\"--export-objects\" are specified as: <protocol>,<destdir>";
    let Some(comma) = bytes.iter().position(|byte| *byte == b',') else {
        return Err(FORM.to_string());
    };
    let protocol_bytes = bytes.get(..comma).unwrap_or(&[]);
    let directory_bytes = bytes.get(comma.saturating_add(1)..).unwrap_or(&[]);
    let Some(protocol_name) = std::str::from_utf8(protocol_bytes).ok() else {
        return Err(FORM.to_string());
    };
    let Some(protocol) = ExportProtocol::parse(protocol_name) else {
        return Err(FORM.to_string());
    };
    if exports.iter().any(|export| export.protocol == protocol) {
        return Err(format!(
            "\"--export-objects\" already specified protocol '{}'",
            protocol.name()
        ));
    }
    exports.push(ExportObjects {
        protocol,
        directory: path_from_bytes(directory_bytes),
    });
    Ok(())
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

/// Bytes after an attached `-S` on a non-UTF-8 argument.
#[cfg(unix)]
fn attached_separator(argument: &OsStr) -> Option<&[u8]> {
    use std::os::unix::ffi::OsStrExt;

    argument
        .as_bytes()
        .strip_prefix(b"-S")
        .filter(|value| !value.is_empty())
}

#[cfg(not(unix))]
fn attached_separator(_: &OsStr) -> Option<&[u8]> {
    None
}

/// Whether a non-UTF-8 argument is an attached `-O` protocol list.
#[cfg(unix)]
fn attached_protocol_filter(argument: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    argument.as_bytes().starts_with(b"-O")
}

#[cfg(not(unix))]
fn attached_protocol_filter(_: &OsStr) -> bool {
    false
}

/// Whether a non-UTF-8 argument is an attached `-Y` or `--display-filter`.
#[cfg(unix)]
fn attached_display_filter(argument: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    const LONG: &[u8] = b"--display-filter=";
    const SHORT: &[u8] = b"-Y";
    let bytes = argument.as_bytes();
    bytes.starts_with(LONG)
        || bytes
            .strip_prefix(SHORT)
            .is_some_and(|value| !value.is_empty())
}

#[cfg(not(unix))]
fn attached_display_filter(_: &OsStr) -> bool {
    false
}

/// Whether a `-o` value explicitly requests the external resolver.
fn requests_external(value: &str) -> bool {
    let Some((name, setting)) = value.split_once(':') else {
        return false;
    };
    let Some((protocol, preference)) = name.split_once('.') else {
        return false;
    };
    protocol.eq_ignore_ascii_case("nameres")
        && preference == "use_external_name_resolver"
        && setting.trim_start_matches(' ').eq_ignore_ascii_case("TRUE")
}

/// Format a rejected `-o` value.
fn format_preference_error(value: &str, error: PrefError) -> String {
    match error {
        PrefError::MissingColon => {
            format!("option -o needs NAME:VALUE, not {value:?}")
        }
        PrefError::UnknownName => {
            let names: Vec<&str> = packetfin_core::decode::PREF_DEFS
                .iter()
                .map(|definition| definition.name)
                .collect();
            format!(
                "-o flag {value:?} specifies an unknown preference; Packetfin implements {}",
                names.join(", ")
            )
        }
        PrefError::InvalidValue => format!("invalid -o flag {value:?}"),
    }
}

/// Apply one `-N` resolver flag string, replacing the whole `nameres` set.
fn apply_nameres(flags: &str, options: &mut DecodeOptions) -> Result<(), String> {
    match nameres_from_flags(flags) {
        Some(prefs) => {
            options.preferences.nameres = prefs;
            Ok(())
        }
        None => Err(format!(
            "-N specifies an unknown resolving option {flags:?}; valid options are \
             d, g, m, n, N, s, t and v"
        )),
    }
}

/// Add one `-H` hosts file.
fn add_hosts_file(path: &Path, options: &mut DecodeOptions) -> Result<(), String> {
    let file = File::open(path).map_err(|error| {
        format!(
            "cannot read host entries from {:?}: {error}",
            path.display()
        )
    })?;
    let parsed = packetfin_core::names::parse_hosts(BufReader::new(file))
        .map_err(|error| format!("cannot read host entries: {error}"))?;
    let remaining = packetfin_core::names::HOSTS_MAX_ENTRIES.saturating_sub(options.hosts.len());
    let dropped = parsed.entries.len().saturating_sub(remaining);
    options
        .hosts
        .extend(parsed.entries.into_iter().take(remaining));
    if parsed.truncated || dropped > 0 {
        options.notices.push(format!(
            "host entries from {:?} were truncated at Packetfin's limit",
            path.display()
        ));
    }
    Ok(())
}

/// Apply one protocol list, treating `ALL` as every protocol.
fn apply_protocol_list(
    value: &str,
    enable: bool,
    options: &mut DecodeOptions,
) -> Result<(), String> {
    for name in value.split(',') {
        if name == "ALL" {
            if enable {
                options.policy.enable_all();
            } else {
                options.policy.disable_all();
            }
            continue;
        }
        let protocol = protocol_by_name(name).ok_or_else(|| format!("No such protocol {name}"))?;
        if enable {
            options.policy.enable(protocol);
        } else {
            options.policy.disable(protocol);
        }
    }
    Ok(())
}

/// `--only-protocols`: disable every protocol, then enable the list.
fn apply_only_protocols(value: &str, options: &mut DecodeOptions) -> Result<(), String> {
    options.policy.disable_all();
    if value.is_empty() {
        return Ok(());
    }
    apply_protocol_list(value, true, options)
}

/// Enable or disable one heuristic by its short name.
fn apply_heuristic(name: &str, enable: bool, options: &mut DecodeOptions) -> Result<(), String> {
    let heuristic = heuristic(name).ok_or_else(|| format!("No such protocol {name}"))?;
    if enable {
        options.policy.enable_heuristic(heuristic);
    } else {
        options.policy.disable_heuristic(heuristic);
    }
    Ok(())
}

/// Parse one `-d <layer>==<selector>,<protocol>` argument.
fn apply_decode_as(value: &str, options: &mut DecodeOptions) -> Result<(), String> {
    packetfin_core::decode::parse_decode_as(value, &mut options.decode_as).map_err(|error| {
        match error {
            packetfin_core::decode::DecodeAsError::Template => {
                format!("parameter {value:?} does not follow <layer_type>==<selector>,<protocol>")
            }
            packetfin_core::decode::DecodeAsError::UnknownLayer(layer) => format!(
                "unknown layer type {layer:?}; valid layer types are {}",
                LayerType::ALL
                    .iter()
                    .map(|layer| layer.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            packetfin_core::decode::DecodeAsError::InvalidSelector(message) => message,
            packetfin_core::decode::DecodeAsError::UnknownProtocol { layer, protocol } => format!(
                "unknown protocol {protocol:?}; valid protocols for {} are {}",
                layer.name(),
                valid_protocol_names(layer)
            ),
            packetfin_core::decode::DecodeAsError::InvalidForLayer { layer, protocol } => format!(
                "protocol {protocol:?} is not valid for layer type {:?}; valid protocols are {}",
                layer.name(),
                valid_protocol_names(layer)
            ),
        }
    })
}

fn valid_protocol_names(layer: LayerType) -> String {
    layer
        .valid_protocols()
        .iter()
        .map(|protocol| {
            let definition = protocols()
                .iter()
                .find(|definition| definition.filter_name == protocol.filter_name());
            match definition {
                Some(definition) => {
                    format!("{} ({})", protocol.filter_name(), definition.long_name)
                }
                None => protocol.filter_name().to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Apply one `-E OPTION=VALUE` value supplied as an operating-system string.
fn apply_field_output_os(value: &OsStr, options: &mut FieldOutputOptions) -> Result<(), String> {
    match os_str_bytes(value) {
        Some(bytes) => apply_field_output_option(bytes, options),
        None => Err("the -E value is not valid UTF-8".to_string()),
    }
}

/// Apply one `-E OPTION=VALUE` field output option.
///
/// The option name is ASCII and the value is bytes: enumerated values match
/// on their first byte and the rest is ignored, including invalid UTF-8.
/// Unknown options and malformed values are command-line errors.
fn apply_field_output_option(value: &[u8], options: &mut FieldOutputOptions) -> Result<(), String> {
    let Some(equal) = value.iter().position(|&byte| byte == b'=') else {
        return Err(format!(
            "option -E needs OPTION=VALUE, not {:?}",
            String::from_utf8_lossy(value)
        ));
    };
    let name = value.get(..equal).unwrap_or_default();
    let setting = value.get(equal + 1..).unwrap_or_default();
    match name {
        b"bom" => options.bom = field_output_switch(setting)?,
        b"header" => options.header = field_output_switch(setting)?,
        b"separator" => options.separator = field_output_separator(setting)?,
        b"occurrence" => {
            options.occurrence = match setting.first() {
                Some(b'f') => Occurrence::First,
                Some(b'l') => Occurrence::Last,
                Some(b'a') => Occurrence::All,
                _ => {
                    return Err(format!(
                        "invalid -E occurrence value: {:?}; use f, l or a",
                        String::from_utf8_lossy(setting)
                    ));
                }
            };
        }
        b"aggregator" => options.aggregator = field_output_aggregator(setting)?,
        b"quote" => {
            options.quote = match setting.first() {
                Some(b'd') => Quote::Double,
                Some(b's') => Quote::Single,
                Some(b'n') => Quote::None,
                _ => {
                    return Err(format!(
                        "invalid -E quote value: {:?}; use d, s or n",
                        String::from_utf8_lossy(setting)
                    ));
                }
            };
        }
        b"escape" => options.escape = field_output_switch(setting)?,
        _ => {
            return Err(format!(
                "unknown -E option: {}",
                String::from_utf8_lossy(name)
            ));
        }
    }
    Ok(())
}

/// Parse a `-E y|n` value; only the first byte counts.
fn field_output_switch(value: &[u8]) -> Result<bool, String> {
    match value.first() {
        Some(b'y') => Ok(true),
        Some(b'n') => Ok(false),
        _ => Err(format!(
            "invalid -E switch value: {:?}; use y or n",
            String::from_utf8_lossy(value)
        )),
    }
}

/// Map a `-E separator` value to its output byte.
///
/// `/t` and `/s` select tab and space. Every other value beginning with `/`
/// selects a backslash; any other value contributes
/// its first byte, even when it is multi-byte or longer than one character.
fn field_output_separator(value: &[u8]) -> Result<u8, String> {
    match value {
        [] => Err("a -E separator cannot be empty".to_string()),
        [b'/', b't', ..] => Ok(b'\t'),
        [b'/', b's', ..] => Ok(b' '),
        [b'/', ..] => Ok(b'\\'),
        [first, ..] => Ok(*first),
    }
}

/// Map a `-E aggregator` value to its output byte.
///
/// Only `/s` is special for the aggregator: it selects a space. Any
/// other value beginning with `/`, including `/t`, selects a backslash; any
/// other value contributes its first byte.
fn field_output_aggregator(value: &[u8]) -> Result<u8, String> {
    match value {
        [] => Err("a -E aggregator cannot be empty".to_string()),
        [b'/', b's', ..] => Ok(b' '),
        [b'/', ..] => Ok(b'\\'),
        [first, ..] => Ok(*first),
    }
}

/// Bytes of an operating-system string on Unix; UTF-8 elsewhere.
#[cfg(unix)]
fn os_str_bytes(value: &OsStr) -> Option<&[u8]> {
    use std::os::unix::ffi::OsStrExt;

    Some(value.as_bytes())
}

#[cfg(not(unix))]
fn os_str_bytes(value: &OsStr) -> Option<&[u8]> {
    value.to_str().map(str::as_bytes)
}

/// Split an attached `-Evalue` argument that is not valid UTF-8.
#[cfg(unix)]
fn attached_field_output(argument: &OsStr) -> Option<&[u8]> {
    use std::os::unix::ffi::OsStrExt;

    argument.as_bytes().strip_prefix(b"-E")
}

#[cfg(not(unix))]
fn attached_field_output(argument: &OsStr) -> Option<&[u8]> {
    argument
        .to_str()
        .and_then(|text| text.strip_prefix("-E").map(str::as_bytes))
}

/// Parse the `--pf-state-budget` byte count.
///
/// Unlike the other numeric options, `--pf-state-budget` accepts plain
/// decimal bytes only: no suffixes, signs or grouping.
fn parse_state_budget(value: &OsStr) -> Result<usize, String> {
    parse_byte_budget(value, "--pf-state-budget")
}

fn parse_stats_budget(value: &OsStr) -> Result<usize, String> {
    parse_byte_budget(value, "--pf-stats-budget")
}

fn parse_byte_budget(value: &OsStr, option: &str) -> Result<usize, String> {
    let Some(text) = value.to_str() else {
        return Err(format!("the {option} value is not valid UTF-8"));
    };
    parse_budget(text, option)
}

/// Parse a Packetfin-only byte-count option.
fn parse_budget(text: &str, option: &str) -> Result<usize, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "invalid {option} value {text:?}; use a decimal byte count"
        ));
    }
    text.parse::<usize>().map_err(|_| {
        format!(
            "{option} value {text:?} is too large; the maximum is {}",
            usize::MAX
        )
    })
}

/// Parse the `-M` session reset count.
///
/// Leading white space and an optional sign are accepted, a negative value
/// is reported before its magnitude is checked, and the count is capped at
/// the largest 32-bit signed integer. Trailing characters, a zero count and
/// values above the cap are rejected.
fn parse_reset_count(value: &OsStr) -> Result<u32, String> {
    let Some(text) = value.to_str() else {
        return Err("the -M value is not valid UTF-8".to_string());
    };
    let trimmed = text.trim_start_matches(|character: char| character.is_ascii_whitespace());
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, trimmed.get(1..).unwrap_or_default()),
        Some(b'+') => (false, trimmed.get(1..).unwrap_or_default()),
        _ => (false, trimmed),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "The specified session reset count {text:?} isn't a decimal number"
        ));
    }
    if negative {
        if digits.bytes().all(|byte| byte == b'0') {
            return Err("The specified session reset count is zero".to_string());
        }
        return Err(format!(
            "The specified session reset count {text:?} is a negative number"
        ));
    }
    let count = digits.parse::<u64>().unwrap_or(u64::MAX);
    if count > u64::from(i32::MAX as u32) {
        return Err(format!(
            "The specified session reset count {text:?} is too large (greater than 2147483647)"
        ));
    }
    if count == 0 {
        return Err("The specified session reset count is zero".to_string());
    }
    u32::try_from(count).map_err(|_| {
        format!("The specified session reset count {text:?} is too large (greater than 2147483647)")
    })
}

/// Map a `-F` value to a format Packetfin can write.
///
/// Packetfin writes pcapng, pcap and nsecpcap and rejects any other type
/// with the list of supported ones.
fn output_format_from_os(value: &OsStr) -> Result<OutputFormat, String> {
    let Some(value) = value.to_str() else {
        return Err("the -F value is not valid UTF-8".to_string());
    };
    match value {
        "pcap" => Ok(OutputFormat::Pcap(Resolution::Microsecond)),
        "nsecpcap" => Ok(OutputFormat::NsecPcap),
        "pcapng" => Ok(OutputFormat::PcapNg),
        _ => Err(format!(
            "\"{value}\" isn't a supported capture file type; Packetfin writes pcap, pcapng and nsecpcap"
        )),
    }
}

/// Map a `--compress` value to a sink compression.
///
/// An unknown name prints a diagnostic and exits 0 without creating a file.
/// zstd is a hard error because Packetfin does not write it.
fn compression_from_os(value: &OsStr) -> Result<Compression, Action> {
    let Some(value) = value.to_str() else {
        return Err(Action::Error(
            "the --compress value is not valid UTF-8".to_string(),
        ));
    };
    match value {
        "gzip" => Ok(Compression::Gzip),
        "lz4" => Ok(Compression::Lz4),
        "zstd" => Err(Action::Error(
            "output files can't be written as zstd compressed".to_string(),
        )),
        _ => Err(Action::ExitZero(format!(
            "\"{value}\" isn't a valid output compression mode; use gzip or lz4"
        ))),
    }
}

/// Apply one `-a` condition, replacing an earlier value in the same category.
fn apply_autostop(value: &str, autostop: &mut AutostopOptions) -> Result<(), String> {
    let Some((kind, value)) = value.split_once(':') else {
        return Err(format!("invalid -a argument {value:?}"));
    };
    match kind {
        "packets" => {
            autostop.packets = Some(parse_packet_count(value)?);
        }
        "filesize" => {
            autostop.filesize = Some(parse_packet_count(value)?);
        }
        "files" => {
            autostop.files = Some(parse_packet_count(value)?);
        }
        "duration" => {
            autostop.duration = Some(parse_duration(value)?);
        }
        _ => return Err(format!("invalid -a argument {kind:?}")),
    }
    Ok(())
}

/// Apply one `-b` condition, replacing an earlier value in the same category.
fn apply_ring(value: &str, ring: &mut RingOptions) -> Result<(), String> {
    let Some((kind, value)) = value.split_once(':') else {
        return Err(format!("invalid -b argument {value:?}"));
    };
    match kind {
        "packets" => {
            ring.packets = Some(parse_packet_count(value)?);
        }
        "filesize" => {
            ring.filesize = Some(parse_packet_count(value)?);
        }
        "files" => {
            ring.files = Some(parse_packet_count(value)?);
        }
        "duration" => {
            ring.duration = Some(parse_duration(value)?);
        }
        "printname" => {
            if value.is_empty() {
                return Err("invalid -b argument \"printname:\"".to_string());
            }
            ring.printname = Some(PathBuf::from(value));
        }
        _ => return Err(format!("invalid -b argument {kind:?}")),
    }
    Ok(())
}

/// Parse a `-a duration` or `-b duration` value as seconds.
///
/// Zero and decimal fractions are accepted; a negative or non-decimal
/// value is rejected by the caller with exit 1.
fn parse_duration(value: &str) -> Result<std::time::Duration, String> {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "the specified duration {value:?} is not a decimal number"
        ));
    }
    let seconds = whole
        .parse::<u64>()
        .map_err(|_| format!("the specified duration {value:?} is too large"))?;
    let nanos = match fraction {
        None => 0,
        Some(fraction) => {
            if fraction.is_empty()
                || fraction.len() > 9
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(format!(
                    "the specified duration {value:?} is not a decimal number"
                ));
            }
            let digits = fraction
                .parse::<u32>()
                .map_err(|_| format!("the specified duration {value:?} is not a decimal number"))?;
            digits * 10_u32.pow(9 - u32::try_from(fraction.len()).unwrap_or(9))
        }
    };
    Ok(std::time::Duration::new(seconds, nanos))
}

/// Parse a `-s` snapshot length.
///
/// Zero is valid and asks libpcap for its own limit; a negative or
/// non-decimal value exits 1 before any interface is opened.
fn parse_snaplen(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "the specified snapshot length {value:?} is not a decimal number"
        ));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("the specified snapshot length {value:?} is too large"))?;
    if parsed > u64::from(i32::MAX as u32) {
        return Err(format!(
            "the specified snapshot length {value:?} is too large"
        ));
    }
    u32::try_from(parsed)
        .map_err(|_| format!("the specified snapshot length {value:?} is too large"))
}

/// Parse `-B` mebibytes into a byte count.
fn parse_buffer_size(value: &str) -> Result<u32, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "the specified buffer size {value:?} is not a decimal number"
        ));
    }
    let mib = value
        .parse::<u64>()
        .map_err(|_| format!("the specified buffer size {value:?} is too large"))?;
    if mib == 0 {
        return Err("the specified buffer size is zero".to_string());
    }
    buffer_bytes_from_mib(mib).map_err(|error| error.to_string())
}

/// Resolve a `-y` link-type name through libpcap.
fn link_type_from_name(value: &str) -> Result<Linktype, Action> {
    Linktype::from_name(value).map_err(|error| Action::Error(error.to_string()))
}

/// Validate and assemble the capture-output settings.
///
/// The read-filter shape, live restrictions, capture-comment rules and the
/// output extension are checked in that order before a run starts. Each
/// failure maps to a fixed exit status.
#[expect(
    clippy::too_many_arguments,
    reason = "the parser has one local per option"
)]
fn resolve_write_options(
    write_file: Option<PathBuf>,
    output_format: Option<OutputFormat>,
    compression_mode: Option<Compression>,
    capture_comments: Vec<String>,
    autostop: AutostopOptions,
    ring: RingOptions,
    two_pass: bool,
    read_filter_text: Option<String>,
    reset_interval: Option<u32>,
    annotation_budget: usize,
    has_read_file: bool,
    capture_filter: Option<&str>,
    display_filter: Option<&str>,
    stdout_conflict: bool,
) -> Result<WriteOptions, Action> {
    if two_pass && reset_interval.is_some() {
        return Err(Action::Usage(
            "-M does not support two-pass analysis.".to_string(),
        ));
    }
    if read_filter_text.is_some() && !two_pass {
        return Err(Action::Error(
            "-R requires -2; use -Y for single-pass filtering".to_string(),
        ));
    }
    if two_pass && !has_read_file {
        return Err(Action::Error(
            "live captures do not support two-pass analysis".to_string(),
        ));
    }
    if has_read_file {
        if capture_filter.is_some() {
            return Err(Action::Error(
                "a capture filter can only be used when capturing live traffic".to_string(),
            ));
        }
    } else if display_filter.is_some() && write_file.is_some() {
        return Err(Action::Error(
            "display filters cannot be used while capturing and saving packets".to_string(),
        ));
    }
    let read_filter = compile_display_filter(&read_filter_text)?;

    if write_file
        .as_deref()
        .is_some_and(|path| path == Path::new("-"))
        && stdout_conflict
    {
        return Err(Action::Error(
            "you can't write both raw packet data and dissected packets to the standard output"
                .to_string(),
        ));
    }

    if !capture_comments.is_empty() && write_file.is_none() {
        return Err(Action::Error(
            "capture comments were specified, but no capture file is being written".to_string(),
        ));
    }
    let rotation_condition =
        ring.packets.is_some() || ring.filesize.is_some() || ring.duration.is_some();
    if (ring.files.is_some() || ring.printname.is_some() || autostop.files.is_some())
        && !rotation_condition
    {
        return Err(Action::Error(
            "a files limit or file-name log requires a packet, size or duration rotation condition"
                .to_string(),
        ));
    }
    if has_read_file {
        if autostop.duration.is_some() {
            return Err(Action::Error(
                "a maximum capture time was specified, but a capture isn't being done".to_string(),
            ));
        }
        if autostop.files.is_some() || ring.rotates() || ring.printname.is_some() {
            return Err(Action::Error(
                "multiple capture files were requested, but a capture isn't being done".to_string(),
            ));
        }
    } else {
        let writes_ring = autostop.files.is_some() || ring.rotates() || ring.printname.is_some();
        let writes_stdout = write_file
            .as_deref()
            .is_some_and(|path| path == Path::new("-"));
        if writes_ring && write_file.is_none() {
            return Err(Action::Error(
                "multiple capture files were requested, but no capture file is being written"
                    .to_string(),
            ));
        }
        if writes_ring && writes_stdout {
            return Err(Action::Error(
                "multiple capture files were requested, but the capture is being written to the standard output"
                    .to_string(),
            ));
        }
        if autostop.filesize.is_some() && write_file.is_none() {
            return Err(Action::Error(
                "a maximum capture file size was specified, but no capture file is being written"
                    .to_string(),
            ));
        }
    }

    let format = output_format.unwrap_or(OutputFormat::PcapNg);
    if !capture_comments.is_empty()
        && matches!(format, OutputFormat::Pcap(_) | OutputFormat::NsecPcap)
    {
        return Err(Action::Error(
            "capture comments can only be written to pcapng files".to_string(),
        ));
    }

    let compression = match compression_mode {
        Some(mode) => mode,
        None => output_extension_compression(write_file.as_deref())?,
    };

    Ok(WriteOptions {
        file: write_file,
        format,
        compression,
        comments: capture_comments,
        autostop,
        ring,
        two_pass,
        read_filter,
        reset_interval,
        annotation_budget,
    })
}

/// Select compression from the output name's case-sensitive extension.
fn output_extension_compression(path: Option<&Path>) -> Result<Compression, Action> {
    let Some(path) = path.filter(|path| *path != Path::new("-")) else {
        return Ok(Compression::None);
    };
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return Ok(Compression::None);
    };
    if name.ends_with(".gz") {
        Ok(Compression::Gzip)
    } else if name.ends_with(".lz4") {
        Ok(Compression::Lz4)
    } else if name.ends_with(".zst") {
        Err(Action::Error(
            "output files can't be written as zstd compressed".to_string(),
        ))
    } else {
        Ok(Compression::None)
    }
}

/// Parse a `-c` packet count.
///
/// Leading ASCII whitespace and an optional sign are accepted; the rest must
/// be decimal digits with no trailing characters. The value must be between
/// 1 and `i32::MAX`.
fn parse_packet_count(value: &str) -> Result<u64, String> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while matches!(
        bytes.get(index),
        Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
    ) {
        index += 1;
    }
    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };
    let digits_start = index;
    while bytes.get(index).is_some_and(u8::is_ascii_digit) {
        index += 1;
    }
    if index == digits_start || index != bytes.len() {
        return Err(format!(
            "the specified packet count {value:?} is not a decimal number"
        ));
    }
    let magnitude = value[digits_start..].parse::<u64>().unwrap_or(u64::MAX);
    if magnitude == 0 {
        return Err("the specified packet count is zero".to_string());
    }
    if negative {
        return Err(format!("the specified packet count {value:?} is negative"));
    }
    if magnitude > u64::from(i32::MAX as u32) {
        return Err(format!(
            "the specified packet count {value:?} is greater than 2147483647"
        ));
    }
    Ok(magnitude)
}

fn report_action(value: &str) -> Action {
    match value {
        "fields" => Action::Report(Report::Fields),
        "protocols" => Action::Report(Report::Protocols),
        "heuristic-decodes" => Action::Report(Report::HeuristicDecodes),
        "help" => Action::Report(Report::Help),
        _ => Action::Error(format!(
            "unknown -G report: {value}; try '-G help' for the available reports"
        )),
    }
}

fn unsupported_output(value: &str) -> Action {
    Action::Usage(format!(
        "unsupported output format: {value}; use 'fields', 'json', 'jsonraw', 'pdml', 'psml', 'ek', 'ps', 'tabs' or 'text'"
    ))
}

/// Print the own-wording help text to stdout.
pub fn print_help() {
    let mut handle = io::stdout().lock();
    let _ = writeln!(handle, "Usage: packetfin [options]");
    let _ = writeln!(handle);
    let _ = writeln!(handle, "Options:");
    let _ = writeln!(handle, "  -h, --help      Print this help text and exit.");
    let _ = writeln!(
        handle,
        "  -v, --version   Print the version banner and exit."
    );
    let _ = writeln!(
        handle,
        "  -n              Disable name resolution (by default only MAC"
    );
    let _ = writeln!(handle, "                  vendor names are resolved).");
    let _ = writeln!(
        handle,
        "  -N FLAGS        Enable name resolution flags: m MAC, n network,"
    );
    let _ = writeln!(
        handle,
        "                  t transport, d DNS packet addresses, s TLS SNI,"
    );
    let _ = writeln!(
        handle,
        "                  v VLAN, N external resolver, g MaxMind GeoIP; each"
    );
    let _ = writeln!(handle, "                  -N replaces the whole set.");
    let _ = writeln!(
        handle,
        "  -H FILE         Read IPv4/IPv6 host entries from FILE for name"
    );
    let _ = writeln!(
        handle,
        "                  resolution (repeatable; hosts-file syntax)."
    );
    let _ = writeln!(handle, "  -d LAYER==SELECTOR,PROTOCOL");
    let _ = writeln!(
        handle,
        "                  Decode as PROTOCOL when LAYER matches SELECTOR"
    );
    let _ = writeln!(
        handle,
        "                  (port, range or length; repeatable, a later entry"
    );
    let _ = writeln!(handle, "                  with the same selector wins).");
    let _ = writeln!(
        handle,
        "  --enable-protocol LIST   Enable the comma-separated protocols"
    );
    let _ = writeln!(
        handle,
        "                  (ALL enables every protocol; repeatable)."
    );
    let _ = writeln!(
        handle,
        "  --disable-protocol LIST  Disable the comma-separated protocols."
    );
    let _ = writeln!(
        handle,
        "  --only-protocols LIST    Disable every protocol, then enable LIST."
    );
    let _ = writeln!(
        handle,
        "  --enable-heuristic NAME  Enable one heuristic decoder by short name."
    );
    let _ = writeln!(
        handle,
        "  --disable-heuristic NAME Disable one heuristic decoder by short name."
    );
    let _ = writeln!(handle, "  -r, --read-file FILE");
    let _ = writeln!(
        handle,
        "                  Read packets from FILE ('-' reads standard input,"
    );
    let _ = writeln!(
        handle,
        "                  which must be a pipe or a regular file). Without -r,"
    );
    let _ = writeln!(
        handle,
        "                  capture live from the first non-loopback interface."
    );
    let _ = writeln!(handle, "  -i, --interface NAME|INDEX");
    let _ = writeln!(
        handle,
        "                  Capture from an interface by name or 1-based index"
    );
    let _ = writeln!(
        handle,
        "                  (repeatable; the default interface otherwise)."
    );
    let _ = writeln!(handle, "  -D, --list-interfaces");
    let _ = writeln!(
        handle,
        "                  Print the numbered capture interfaces and exit."
    );
    let _ = writeln!(handle, "  -L, --list-data-link-types");
    let _ = writeln!(
        handle,
        "                  Print each interface's data link types and exit."
    );
    let _ = writeln!(handle, "  --list-time-stamp-types");
    let _ = writeln!(
        handle,
        "                  Print each interface's timestamp types and exit."
    );
    let _ = writeln!(handle, "  -f, --capture-filter FILTER");
    let _ = writeln!(
        handle,
        "                  Capture only packets matching the BPF filter"
    );
    let _ = writeln!(handle, "                  (the last -f wins).");
    let _ = writeln!(handle, "  -s, --snapshot-length BYTES");
    let _ = writeln!(
        handle,
        "                  Capture at most BYTES per packet (0 is no limit)."
    );
    let _ = writeln!(handle, "  -p, --no-promiscuous-mode");
    let _ = writeln!(
        handle,
        "                  Do not put the interface in promiscuous mode."
    );
    let _ = writeln!(handle, "  -I, --monitor-mode");
    let _ = writeln!(handle, "                  Capture in monitor mode.");
    let _ = writeln!(handle, "  -B, --buffer-size MiB");
    let _ = writeln!(
        handle,
        "                  Set the kernel capture buffer size."
    );
    let _ = writeln!(handle, "  -y, --link-type TYPE");
    let _ = writeln!(
        handle,
        "                  Set the data link type by libpcap name."
    );
    let _ = writeln!(handle, "  --time-stamp-type TYPE");
    let _ = writeln!(
        handle,
        "                  Select the interface timestamp type."
    );
    let _ = writeln!(
        handle,
        "  -G REPORT       Print a glossary report and exit. REPORT is fields,"
    );
    let _ = writeln!(
        handle,
        "                  protocols, heuristic-decodes or help."
    );
    let _ = writeln!(handle, "  -T fields|text|json|jsonraw|pdml|psml|ek|ps|tabs");
    let _ = writeln!(
        handle,
        "                  Select field output, the summary, JSON, raw JSON,"
    );
    let _ = writeln!(
        handle,
        "                  PDML, PSML, Elasticsearch, PostScript or tabs."
    );
    let _ = writeln!(
        handle,
        "  -t FORMAT[.N]   Time stamp format: a, ad, adoy, d, dd, e,"
    );
    let _ = writeln!(
        handle,
        "                  r, u, ud or udoy, with an optional precision."
    );
    let _ = writeln!(
        handle,
        "  -u s|hms        Seconds format for relative and delta times."
    );
    let _ = writeln!(
        handle,
        "  -V              Print the packet detail tree instead of summary lines."
    );
    let _ = writeln!(
        handle,
        "  -O PROTOCOLS    In detail output, expand only these comma-separated"
    );
    let _ = writeln!(
        handle,
        "                  protocol names; others show their header line."
    );
    let _ = writeln!(
        handle,
        "  -P, --print     Print the summary line even when another output mode runs."
    );
    let _ = writeln!(
        handle,
        "  --color         Color matching packets in the summary (on a terminal)"
    );
    let _ = writeln!(
        handle,
        "                  and in PostScript, PSML and PDML output."
    );
    let _ = writeln!(
        handle,
        "  -S SEPARATOR    Line printed after each detail or hexdump packet block."
    );
    let _ = writeln!(
        handle,
        "  -x              Print the captured frame bytes as hex and ASCII."
    );
    let _ = writeln!(
        handle,
        "  --hexdump OPT   Configure the byte dump: all, frames, ascii, delimit,"
    );
    let _ = writeln!(
        handle,
        "                  noascii, time, notime, help. Repeat to combine."
    );
    let _ = writeln!(handle, "  -w, --write-file FILE");
    let _ = writeln!(
        handle,
        "                  Write the capture to FILE ('-' writes raw capture"
    );
    let _ = writeln!(
        handle,
        "                  bytes to standard output). Defaults to pcapng."
    );
    let _ = writeln!(
        handle,
        "  -F TYPE         Output format: pcap, pcapng or nsecpcap."
    );
    let _ = writeln!(handle, "  --compress gzip|lz4");
    let _ = writeln!(
        handle,
        "                  Compress the output; .gz and .lz4 select it too."
    );
    let _ = writeln!(handle, "  --capture-comment TEXT");
    let _ = writeln!(
        handle,
        "                  Append a section comment (pcapng only, repeatable)."
    );
    let _ = writeln!(
        handle,
        "  -a CONDITION    Autostop: packets:N, filesize:N, files:N or"
    );
    let _ = writeln!(
        handle,
        "                  duration:N. Read mode accepts packets and filesize."
    );
    let _ = writeln!(
        handle,
        "  -b CONDITION    Ring buffer: packets:N, filesize:N, duration:N,"
    );
    let _ = writeln!(
        handle,
        "                  files:N or printname:FILE (live capture only)."
    );
    let _ = writeln!(
        handle,
        "  -2, --two-pass  Analyse in two passes so -R sees the whole capture."
    );
    let _ = writeln!(
        handle,
        "  -M COUNT        Start a new analysis session every COUNT frames"
    );
    let _ = writeln!(handle, "                  (auto session reset).");
    let _ = writeln!(
        handle,
        "  -R FILTER       Read filter, applied against file frame numbers"
    );
    let _ = writeln!(handle, "                  (--read-filter; requires -2).");
    let _ = writeln!(
        handle,
        "  -l              Flush standard output after each packet."
    );
    let _ = writeln!(
        handle,
        "  -q, -Q          Suppress the implicit summary and packet counts."
    );
    let _ = writeln!(handle, "  --export-objects PROTOCOL,DIR");
    let _ = writeln!(
        handle,
        "                  Export object bodies (http is implemented) into DIR."
    );
    let _ = writeln!(handle, "  -c COUNT        Stop after COUNT packets.");
    let _ = writeln!(
        handle,
        "  -e FIELD        Add FIELD to -T fields or -T json output (repeatable)."
    );
    let _ = writeln!(
        handle,
        "  -j PROTOCOLS    In JSON output, show only these space-separated layers."
    );
    let _ = writeln!(
        handle,
        "  -J PROTOCOLS    In JSON output, show these layers and all their children."
    );
    let _ = writeln!(handle, "  --no-duplicate-keys");
    let _ = writeln!(
        handle,
        "                  Merge repeated JSON object keys into arrays."
    );
    let _ = writeln!(
        handle,
        "  -Y FILTER       Only process packets matching the display filter"
    );
    let _ = writeln!(
        handle,
        "                  (--display-filter); the last -Y wins."
    );
    let _ = writeln!(
        handle,
        "  -E OPTION=VALUE Set a -T fields output option (repeatable):"
    );
    let _ = writeln!(handle, "                  bom=y|n, header=y|n, escape=y|n,");
    let _ = writeln!(
        handle,
        "                  separator=/t|/s|CHAR, aggregator=CHAR|/s,"
    );
    let _ = writeln!(handle, "                  occurrence=f|l|a, quote=d|s|n.");
    let _ = writeln!(
        handle,
        "  -o NAME:VALUE   Set a preference. Boolean values are TRUE or FALSE."
    );
    let _ = writeln!(
        handle,
        "                  Supported: ip.check_checksum, udp.check_checksum,"
    );
    let _ = writeln!(
        handle,
        "                  tcp.check_checksum, tcp.relative_sequence_numbers,"
    );
    let _ = writeln!(
        handle,
        "                  tcp.analyze_sequence_numbers, ip.defragment,"
    );
    let _ = writeln!(
        handle,
        "                  ipv6.defragment, tcp.desegment_tcp_streams,"
    );
    let _ = writeln!(handle, "                  tcp.reassemble_out_of_order,");
    let _ = writeln!(handle, "                  tcp.track_bytes_in_flight,");
    let _ = writeln!(handle, "                  tcp.calculate_timestamps,");
    let _ = writeln!(handle, "                  tcp.fastrt_supersedes_ooo,");
    let _ = writeln!(handle, "                  tcp.default_window_scaling,");
    let _ = writeln!(handle, "                  tls.keylog_file");
    let _ = writeln!(handle, "  -o tls.keylog_file:PATH");
    let _ = writeln!(
        handle,
        "                  Decrypt TLS 1.2/1.3 from an NSS key-log file."
    );
    let _ = writeln!(handle, "  --export-tls-session-keys PATH");
    let _ = writeln!(
        handle,
        "                  Write decrypted TLS session keys to PATH."
    );
    let _ = writeln!(
        handle,
        "  -z STAT         Run a statistic such as io,stat, io,phs, conv,tcp,"
    );
    let _ = writeln!(
        handle,
        "                  endpoints,ip, expert or follow,tcp,ascii,0"
    );
    let _ = writeln!(
        handle,
        "                  (repeatable; '-z help' lists every supported name)."
    );
    let _ = writeln!(handle, "  --pf-stats-budget BYTES");
    let _ = writeln!(
        handle,
        "                  Bound memory retained by -z statistics (default"
    );
    let _ = writeln!(
        handle,
        "                  {DEFAULT_STATS_BUDGET}; 0 disables retention)."
    );
    let _ = writeln!(handle, "  --pf-state-budget BYTES");
    let _ = writeln!(
        handle,
        "                  Bound memory retained between packets (default"
    );
    let _ = writeln!(
        handle,
        "                  {DEFAULT_STATE_BUDGET}; 0 disables retention)."
    );
    let _ = writeln!(handle, "  --pf-annotation-budget BYTES");
    let _ = writeln!(
        handle,
        "                  Bound memory for two-pass annotations (default"
    );
    let _ = writeln!(
        handle,
        "                  {DEFAULT_ANNOTATION_BUDGET}; 0 disables links)."
    );
}

/// Print the version banner to stdout.
pub fn print_version() {
    let mut handle = io::stdout().lock();
    let _ = writeln!(
        handle,
        "packetfin {VERSION} — a command-line packet analyzer."
    );
}

/// Print the usage line to the given writer.
pub fn print_usage(writer: &mut impl io::Write) {
    let _ = writeln!(writer, "Usage: packetfin [options]");
    let _ = writeln!(writer, "Try 'packetfin --help' for more information.");
}

/// Print the `--hexdump` option help and exit 0.
pub fn print_hexdump_help() {
    let mut handle = io::stdout().lock();
    let _ = writeln!(handle, "packetfin --hexdump options:");
    let _ = writeln!(handle);
    let _ = writeln!(handle, "Data source options:");
    let _ = writeln!(
        handle,
        "  all                      dump every available data source (-x default)"
    );
    let _ = writeln!(
        handle,
        "  frames                   dump only the frame data source"
    );
    let _ = writeln!(handle);
    let _ = writeln!(handle, "ASCII options:");
    let _ = writeln!(
        handle,
        "  ascii                    include ASCII dump text (-x default)"
    );
    let _ = writeln!(
        handle,
        "  delimit                  wrap ASCII dump text in '|' characters"
    );
    let _ = writeln!(handle, "  noascii                  exclude ASCII dump text");
    let _ = writeln!(handle);
    let _ = writeln!(handle, "Timestamp options:");
    let _ = writeln!(
        handle,
        "  time                     include a timestamp preamble (uses -t)"
    );
    let _ = writeln!(
        handle,
        "  notime                   omit the timestamp preamble (-x default)"
    );
    let _ = writeln!(handle);
    let _ = writeln!(handle, "Miscellaneous:");
    let _ = writeln!(
        handle,
        "  help                     display this help and exit"
    );
    let _ = writeln!(handle);
    let _ = writeln!(
        handle,
        "Example: packetfin --hexdump frames --hexdump delimit -r FILE"
    );
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Action, FieldsOptions, Input, ListModes, Report, SummaryOptions};
    use crate::fields::{FieldOutputOptions, Occurrence, Quote};
    use crate::summary::TimeFormat;

    fn parse(args: &[&str]) -> Action {
        let mut arguments = vec![OsString::from("packetfin")];
        arguments.extend(args.iter().map(OsString::from));
        super::parse(&arguments)
    }

    fn fields(args: &[&str]) -> FieldsOptions {
        match parse(args) {
            Action::Fields(options) => *options,
            other => {
                eprintln!("expected a fields action, got {other:?}");
                std::process::exit(1);
            }
        }
    }

    fn summary(args: &[&str]) -> SummaryOptions {
        match parse(args) {
            Action::Summary(options) => *options,
            other => {
                eprintln!("expected a summary action, got {other:?}");
                std::process::exit(1);
            }
        }
    }

    const BASE: &[&str] = &["-T", "fields", "-e", "frame.number", "-r", "capture.pcap"];

    fn with_options(options: &[&str]) -> FieldsOptions {
        let mut args = BASE.to_vec();
        args.extend_from_slice(options);
        fields(&args)
    }

    #[test]
    fn display_filters_are_accepted_in_every_option_form() {
        let expected = super::Filter::parse("ip.src == 192.0.2.1").ok();
        assert!(expected.is_some());
        for extra in [
            vec!["-Y", "ip.src == 192.0.2.1"],
            vec!["-Yip.src == 192.0.2.1"],
            vec!["--display-filter", "ip.src == 192.0.2.1"],
            vec!["--display-filter=ip.src == 192.0.2.1"],
        ] {
            assert_eq!(with_options(&extra).display_filter, expected, "{extra:?}");
        }
    }

    #[test]
    fn the_last_display_filter_wins() {
        let expected = super::Filter::parse("udp").ok();
        assert!(expected.is_some());
        assert_eq!(
            with_options(&["-Y", "ip", "-Y", "udp"]).display_filter,
            expected
        );
    }

    #[test]
    fn empty_display_filters_are_accepted() {
        let options = with_options(&["-Y", ""]);
        assert!(options.display_filter.is_some());
        let options = with_options(&["-Y", "   "]);
        assert!(options.display_filter.is_some());
    }

    #[test]
    fn invalid_display_filters_are_reported() {
        assert!(matches!(
            parse(&[
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-r",
                "capture.pcap",
                "-Y",
                "ip.nope"
            ]),
            Action::DisplayFilter { .. }
        ));
    }

    #[test]
    fn display_filter_validation_follows_the_command_line_order() {
        assert!(matches!(parse(&["-h", "-Y", "ip.nope"]), Action::Help));
        assert!(matches!(
            parse(&["-G", "fields", "-Y", "ip.nope"]),
            Action::Report(Report::Fields)
        ));
        assert!(matches!(
            parse(&[
                "-T",
                "fields",
                "-e",
                "not.a.field",
                "-r",
                "capture.pcap",
                "-Y",
                "ip.nope"
            ]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-Y", "ip.nope"]),
            Action::DisplayFilter { .. }
        ));
        assert!(matches!(parse(&["-Y"]), Action::Usage(_)));
    }

    #[test]
    fn summary_options_carry_the_display_filter() {
        assert!(
            summary(&["-r", "capture.pcap", "-Y", "ip"])
                .display_filter
                .is_some()
        );
    }

    #[test]
    fn field_output_has_expected_defaults() {
        let options = fields(BASE);
        assert_eq!(options.output, FieldOutputOptions::default());
        assert_eq!(options.output.separator, b'\t');
        assert_eq!(options.output.aggregator, b',');
        assert_eq!(options.output.occurrence, Occurrence::All);
        assert_eq!(options.output.quote, Quote::None);
        assert!(options.output.escape);
        assert!(!options.output.bom);
        assert!(!options.output.header);
        assert_eq!(options.packet_count, None);
        assert!(!options.flush);
    }

    #[test]
    fn field_output_options_accept_attached_and_detached_values() {
        let options = with_options(&[
            "-Eheader=y",
            "-E",
            "separator=,",
            "-Equote=d",
            "-E",
            "occurrence=l",
            "-Eaggregator=/s",
            "-E",
            "escape=n",
        ]);
        assert!(options.output.header);
        assert_eq!(options.output.separator, b',');
        assert_eq!(options.output.quote, Quote::Double);
        assert_eq!(options.output.occurrence, Occurrence::Last);
        assert_eq!(options.output.aggregator, b' ');
        assert!(!options.output.escape);
    }

    #[test]
    fn enumerated_values_use_their_first_byte() {
        let options = with_options(&[
            "-E",
            "header=yes",
            "-E",
            "bom=yes",
            "-E",
            "escape=nonsense",
            "-E",
            "quote=double",
            "-E",
            "occurrence=first",
        ]);
        assert!(options.output.header);
        assert!(options.output.bom);
        assert!(!options.output.escape);
        assert_eq!(options.output.quote, Quote::Double);
        assert_eq!(options.output.occurrence, Occurrence::First);
    }

    #[test]
    fn separator_follows_byte_rules() {
        for (value, expected) in [
            ("/t", b'\t'),
            ("/s", b' '),
            ("/T", b'\\'),
            ("/x", b'\\'),
            ("/", b'\\'),
            ("/tX", b'\t'),
            ("/sX", b' '),
            ("ab", b'a'),
            ("=", b'='),
            ("é", 0xc3),
            (" ", b' '),
        ] {
            let separator = format!("separator={value}");
            assert_eq!(
                with_options(&["-E", &separator]).output.separator,
                expected,
                "separator {value:?}"
            );
        }
    }

    #[test]
    fn aggregator_only_special_cases_slash_s() {
        for (value, expected) in [
            ("/s", b' '),
            ("/t", b'\\'),
            ("/T", b'\\'),
            ("/x", b'\\'),
            ("/", b'\\'),
            ("/tX", b'\\'),
            ("/sX", b' '),
            ("ab", b'a'),
            ("=", b'='),
            ("é", 0xc3),
            (" ", b' '),
        ] {
            let aggregator = format!("aggregator={value}");
            assert_eq!(
                with_options(&["-E", &aggregator]).output.aggregator,
                expected,
                "aggregator {value:?}"
            );
        }
    }

    #[test]
    fn later_field_output_options_override_earlier_ones() {
        let options = with_options(&[
            "-E",
            "header=y",
            "-E",
            "header=n",
            "-E",
            "separator=x",
            "-E",
            "separator=,",
            "-E",
            "quote=s",
            "-E",
            "quote=d",
        ]);
        assert!(!options.output.header);
        assert_eq!(options.output.separator, b',');
        assert_eq!(options.output.quote, Quote::Double);
    }

    #[test]
    fn invalid_field_output_options_are_errors() {
        for option in [
            "bogus=y",
            "quote=x",
            "occurrence=z",
            "header=Y",
            "escape=TRUE",
            "bom=",
            "separator=",
            "aggregator=",
            "header",
            "header =y",
        ] {
            let action = parse(&[
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-r",
                "capture.pcap",
                "-E",
                option,
            ]);
            assert!(
                matches!(action, Action::Error(_)),
                "expected an error for {option:?}, got {action:?}"
            );
        }
    }

    #[test]
    fn missing_field_output_value_is_a_usage_error() {
        assert!(matches!(
            parse(&[
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-r",
                "capture.pcap",
                "-E",
            ]),
            Action::Usage(_)
        ));
    }

    #[test]
    fn field_output_is_validated_before_later_help() {
        assert!(matches!(parse(&["-E", "bogus=y", "-h"]), Action::Error(_)));
        assert!(matches!(parse(&["-h", "-E", "bogus=y"]), Action::Help));
    }

    #[test]
    fn field_output_is_validated_for_glossary_reports() {
        assert!(matches!(
            parse(&["-E", "bogus=y", "-G", "fields"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-E", "header=y", "-G", "fields"]),
            Action::Report(Report::Fields)
        ));
    }

    #[test]
    fn field_output_without_field_output_format_is_accepted() {
        assert!(summary(&["-E", "header=y", "-r", "capture.pcap"]).print);
    }

    #[test]
    fn time_formats_parse_with_optional_precision() {
        let options = summary(&["-r", "capture.pcap", "-t", "r.3"]);
        assert_eq!(options.time.format, TimeFormat::Relative);
        assert_eq!(options.time.precision, Some(3));
        for (value, format) in [
            ("a", TimeFormat::Absolute),
            ("ad", TimeFormat::AbsoluteWithDate),
            ("adoy", TimeFormat::AbsoluteWithDayOfYear),
            ("d", TimeFormat::Delta),
            ("dd", TimeFormat::DeltaDisplayed),
            ("e", TimeFormat::Epoch),
            ("u", TimeFormat::Utc),
            ("ud", TimeFormat::UtcWithDate),
            ("udoy", TimeFormat::UtcWithDayOfYear),
        ] {
            assert_eq!(
                summary(&["-r", "capture.pcap", "-t", value]).time.format,
                format
            );
        }
        let options = summary(&["-r", "capture.pcap", "-t", ".6"]);
        assert_eq!(options.time.format, TimeFormat::Relative);
        assert_eq!(options.time.precision, Some(6));
    }

    #[test]
    fn invalid_time_options_are_errors() {
        for value in ["z", "r.10", "r.-1", "r.x", "udon"] {
            assert!(matches!(
                parse(&["-r", "capture.pcap", "-t", value]),
                Action::Error(_)
            ));
        }
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-u", "minutes"]),
            Action::Error(_)
        ));
    }

    #[test]
    fn quiet_flags_suppress_only_the_implicit_summary() {
        assert!(matches!(
            parse(&["-r", "capture.pcap"]),
            Action::Summary(options) if options.print
        ));
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-q"]),
            Action::Summary(options) if !options.print
        ));
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-Q"]),
            Action::Summary(options) if !options.print
        ));
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-T", "text", "-q"]),
            Action::Summary(options) if options.print
        ));
    }

    #[test]
    fn empty_time_format_is_rejected_but_precision_only_is_accepted() {
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-t", ""]),
            Action::Error(_)
        ));
        assert_eq!(
            summary(&["-r", "capture.pcap", "-t", ".6"]).time.precision,
            Some(6)
        );
    }

    #[test]
    fn attached_time_and_seconds_options_are_accepted() {
        let options = summary(&["-r", "capture.pcap", "-tr.3"]);
        assert_eq!(options.time.format, TimeFormat::Relative);
        assert_eq!(options.time.precision, Some(3));
        assert!(
            summary(&["-r", "capture.pcap", "-uhms"])
                .time
                .hours_minutes_seconds
        );
    }

    #[test]
    fn multiple_output_formats_are_rejected() {
        for args in [
            vec!["-T", "fields", "-e", "frame.number", "-T", "fields"],
            vec!["-T", "text", "-T", "text"],
            vec!["-T", "fields", "-e", "frame.number", "-T", "text"],
        ] {
            let mut values = args.clone();
            values.extend_from_slice(&["-r", "capture.pcap"]);
            assert!(matches!(parse(&values), Action::Error(_)), "{args:?}");
        }
    }

    #[test]
    fn hms_seconds_format_is_accepted() {
        assert!(
            summary(&["-r", "capture.pcap", "-u", "hms"])
                .time
                .hours_minutes_seconds
        );
    }

    #[test]
    fn packet_count_accepts_decimal_forms() {
        assert_eq!(with_options(&["-c", "1"]).packet_count, Some(1));
        assert_eq!(with_options(&["-c2"]).packet_count, Some(2));
        assert_eq!(with_options(&["-c", "0002"]).packet_count, Some(2));
        assert_eq!(with_options(&["-c", " 1"]).packet_count, Some(1));
        assert_eq!(with_options(&["-c", "\t1"]).packet_count, Some(1));
        assert_eq!(with_options(&["-c", "+1"]).packet_count, Some(1));
        assert_eq!(with_options(&["-c", "1", "-c", "2"]).packet_count, Some(2));
        assert_eq!(
            with_options(&["-c", "2147483647"]).packet_count,
            Some(2_147_483_647)
        );
    }

    #[test]
    fn invalid_packet_counts_are_errors() {
        for value in [
            "0",
            "-0",
            "-1",
            "abc",
            "1x",
            "1.5",
            " 1 ",
            "",
            "+",
            "2147483648",
            "999999999999999999999",
        ] {
            let action = parse(&[
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-r",
                "capture.pcap",
                "-c",
                value,
            ]);
            assert!(
                matches!(action, Action::Error(_)),
                "expected an error for count {value:?}, got {action:?}"
            );
        }
    }

    #[test]
    fn packet_count_is_validated_for_glossary_reports() {
        assert!(matches!(
            parse(&["-c", "0", "-G", "fields"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-c", "1", "-G", "fields"]),
            Action::Report(Report::Fields)
        ));
    }

    #[cfg(unix)]
    fn parse_os(args: &[OsString]) -> Action {
        let mut arguments = vec![OsString::from("packetfin")];
        arguments.extend_from_slice(args);
        super::parse(&arguments)
    }

    #[cfg(unix)]
    #[test]
    fn field_output_accepts_non_utf8_values_on_unix() {
        use std::os::unix::ffi::OsStringExt;

        fn os(bytes: &[u8]) -> OsString {
            OsString::from_vec(bytes.to_vec())
        }

        fn fields(action: Action) -> FieldsOptions {
            match action {
                Action::Fields(options) => *options,
                other => {
                    eprintln!("expected a fields action, got {other:?}");
                    std::process::exit(1);
                }
            }
        }

        let base: Vec<OsString> = BASE.iter().map(OsString::from).collect();
        let detached = |value: &[u8]| {
            let mut args = base.clone();
            args.push(OsString::from("-E"));
            args.push(os(value));
            fields(parse_os(&args))
        };
        let attached = |value: &[u8]| {
            let mut args = base.clone();
            args.push(os(value));
            fields(parse_os(&args))
        };

        assert!(!detached(b"header=n\xff").output.header);
        assert_eq!(detached(b"quote=d\xff").output.quote, Quote::Double);
        assert_eq!(detached(b"separator=\xff").output.separator, 0xff);
        assert_eq!(detached(b"aggregator=\xff").output.aggregator, 0xff);

        assert!(!attached(b"-Eheader=n\xff").output.header);
        assert_eq!(attached(b"-Equote=d\xff").output.quote, Quote::Double);
        assert_eq!(attached(b"-Eseparator=\xff").output.separator, 0xff);

        for value in [b"header=\xff".as_slice(), b"bogus=\xff".as_slice()] {
            let mut args = base.clone();
            args.push(OsString::from("-E"));
            args.push(os(value));
            assert!(
                matches!(parse_os(&args), Action::Error(_)),
                "expected an error for {value:?}"
            );
        }
    }

    #[test]
    fn flush_and_quiet_flags_are_accepted() {
        let options = with_options(&["-l", "-q", "-Q"]);
        assert!(options.flush);
        assert!(matches!(
            with_options(&["-q", "-Q"]),
            FieldsOptions { flush: false, .. }
        ));
    }

    #[test]
    fn write_defaults_to_pcapng_and_no_compression() {
        let options = with_options(&[]);
        assert!(options.write.file.is_none());
        assert_eq!(options.write.format, super::OutputFormat::PcapNg);
        assert_eq!(options.write.compression, super::Compression::None);
        assert!(!options.write.two_pass);
    }

    #[test]
    fn write_format_and_path_accept_attached_and_detached_forms() {
        for extra in [
            vec!["-w", "out.pcap"],
            vec!["-wout.pcap"],
            vec!["--write-file", "out.pcap"],
            vec!["--write-file=out.pcap"],
        ] {
            let options = with_options(&extra);
            assert_eq!(
                options.write.file.as_deref(),
                Some(std::path::Path::new("out.pcap"))
            );
        }
        for (extra, expected) in [
            (
                vec!["-F", "pcap"],
                super::OutputFormat::Pcap(super::Resolution::Microsecond),
            ),
            (vec!["-Fpcapng"], super::OutputFormat::PcapNg),
            (vec!["-F", "nsecpcap"], super::OutputFormat::NsecPcap),
        ] {
            let options = with_options(&extra);
            assert_eq!(options.write.format, expected);
        }
    }

    #[test]
    fn compression_comes_from_the_option_then_the_extension() {
        let options = with_options(&["-w", "out.gz"]);
        assert_eq!(options.write.compression, super::Compression::Gzip);
        let options = with_options(&["-w", "out.lz4"]);
        assert_eq!(options.write.compression, super::Compression::Lz4);
        let options = with_options(&["-w", "out.GZ"]);
        assert_eq!(options.write.compression, super::Compression::None);
        let options = with_options(&["-w", "out.gz", "--compress", "lz4"]);
        assert_eq!(options.write.compression, super::Compression::Lz4);
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-w", "out.zst"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-r", "capture.pcap", "--compress", "zstd"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-r", "capture.pcap", "--compress", "NOPE"]),
            Action::ExitZero(_)
        ));
    }

    #[test]
    fn autostop_and_ring_conditions_replace_the_same_category() {
        let options = with_options(&["-a", "packets:2", "-a", "packets:3", "-a", "filesize:100"]);
        assert_eq!(options.write.autostop.packets, Some(3));
        assert_eq!(options.write.autostop.filesize, Some(100));
        let mut ring = super::RingOptions::default();
        assert!(super::apply_ring("packets:4", &mut ring).is_ok());
        assert!(super::apply_ring("packets:5", &mut ring).is_ok());
        assert!(super::apply_ring("files:2", &mut ring).is_ok());
        assert!(super::apply_ring("printname:names.txt", &mut ring).is_ok());
        assert_eq!(ring.packets, Some(5));
        assert_eq!(ring.files, Some(2));
        assert_eq!(
            ring.printname.as_deref(),
            Some(std::path::Path::new("names.txt"))
        );
        // Read mode rejects ring buffers before the action is returned.
        assert!(matches!(
            parse(&[
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-r",
                "capture.pcap",
                "-b",
                "packets:5",
            ]),
            Action::Error(_)
        ));
    }

    #[test]
    fn two_pass_requires_a_read_file_and_a_seekable_filter() {
        let options = with_options(&["-2", "-R", "tcp.flags.syn==1", "-r", "capture.pcap"]);
        assert!(options.write.two_pass);
        assert!(options.write.read_filter.is_some());
        assert!(matches!(
            parse(&["-r", "capture.pcap", "-R", "tcp.flags.syn==1"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-2", "-T", "fields", "-e", "frame.number"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&[
                "-2",
                "-R",
                "bogus.field==1",
                "-r",
                "capture.pcap",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ]),
            Action::DisplayFilter { .. }
        ));
    }

    #[test]
    fn capture_comments_repeat_and_require_an_output_file() {
        let options = with_options(&[
            "-w",
            "out.pcapng",
            "--capture-comment",
            "one",
            "--capture-comment=two",
        ]);
        assert_eq!(options.write.comments, ["one", "two"]);
        assert!(matches!(
            parse(&[
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-r",
                "capture.pcap",
                "--capture-comment",
                "one",
            ]),
            Action::Error(_)
        ));
    }

    #[test]
    fn write_suppresses_only_the_implicit_summary() {
        let options = summary(&["-r", "capture.pcap", "-w", "out.pcapng"]);
        assert!(!options.print);
        let options = summary(&["-r", "capture.pcap"]);
        assert!(options.print);
        let options = summary(&["-r", "capture.pcap", "-w", "out.pcapng", "-q"]);
        assert!(!options.print);
    }

    #[test]
    fn write_stdout_conflicts_with_dissected_output() {
        let cases: &[&[&str]] = &[
            &[
                "-r",
                "capture.pcap",
                "-w",
                "-",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ],
            &["-r", "capture.pcap", "-w", "-", "-V"],
            &["-r", "capture.pcap", "-w", "-", "-x"],
            &["-r", "capture.pcap", "-w", "-", "-P"],
            &["-r", "capture.pcap", "-w", "-", "-O", "tcp"],
        ];
        for arguments in cases {
            assert!(
                matches!(parse(arguments), Action::Error(_)),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn no_arguments_select_the_live_default_input() {
        let options = summary(&[]);
        let Input::Live(live) = options.input else {
            eprintln!("expected a live input");
            std::process::exit(1);
        };
        assert!(live.interfaces.is_empty());
        assert!(live.promisc);
        assert!(!live.monitor);
        assert!(live.capture_filter.is_none());
    }

    #[test]
    fn live_options_parse_in_order_and_the_last_filter_wins() {
        let options = summary(&[
            "-i",
            "lo0",
            "-i8",
            "-s40",
            "-p",
            "-I",
            "-B",
            "4",
            "-y",
            "NULL",
            "--time-stamp-type=host",
            "-f",
            "icmp",
            "-fudp port 9",
            "-c",
            "3",
        ]);
        let Input::Live(live) = options.input else {
            eprintln!("expected live input");
            std::process::exit(1);
        };
        assert_eq!(live.interfaces, ["lo0", "8"]);
        assert_eq!(live.snaplen, Some(40));
        assert!(!live.promisc);
        assert!(live.monitor);
        assert_eq!(live.buffer_bytes, Some(4 * 1_048_576));
        assert_eq!(live.link_type.map(|link| link.value()), Some(0));
        assert_eq!(live.tstamp_type.as_deref(), Some("host"));
        assert_eq!(live.capture_filter.as_deref(), Some("udp port 9"));
        assert_eq!(options.packet_count, Some(3));
    }

    #[test]
    fn invalid_live_values_exit_one_at_parse_time() {
        for arguments in [
            &["-s", "-1"][..],
            &["-s", "abc"],
            &["-B", "0"],
            &["-B", "abc"],
            &["-y", "BOGUS"],
        ] {
            assert!(
                matches!(parse(arguments), Action::Error(_)),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn live_validation_follows_the_exit_matrix() {
        let error = |arguments: &[&str]| matches!(parse(arguments), Action::Error(_));
        assert!(error(&["-2"]));
        assert!(error(&["-R", "frame.number==1"]));
        assert!(error(&["-Y", "icmp", "-w", "out.pcapng"]));
        assert!(error(&["-w", "/nonexistent/out.pcapng", "-Y", "icmp"]));
        assert!(error(&["-b", "packets:2"]));
        assert!(error(&["-b", "packets:2", "-w", "-"]));
        assert!(error(&["-a", "files:2", "-b", "packets:2"]));
        assert!(error(&["-a", "files:2", "-b", "packets:2", "-w", "-"]));
        assert!(error(&["-a", "filesize:1"]));
        assert!(error(&["-f", "icmp", "-r", "capture.pcap"]));
        assert!(!error(&["-a", "filesize:1", "-w", "-"]));
        assert!(!error(&["-a", "duration:1", "-w", "out.pcapng"]));
        assert!(!error(&["-b", "packets:2", "-w", "out.pcapng"]));
    }

    #[test]
    fn capability_lists_validate_the_rest_of_the_command_line() {
        assert!(matches!(
            parse(&["-L", "-Y", "bogus"]),
            Action::DisplayFilter { .. }
        ));
        assert!(matches!(
            parse(&["-L", "-R", "frame.number==1"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-L", "-2", "-R", "bogus"]),
            Action::DisplayFilter { .. }
        ));
        assert!(matches!(
            parse(&["-L", "-b", "packets:2"]),
            Action::Error(_)
        ));
        assert!(matches!(parse(&["-L", "-a", "files:2"]), Action::Error(_)));
        assert!(matches!(
            parse(&["-L", "-T", "fields", "-e", "bogus"]),
            Action::Error(_)
        ));
        assert!(matches!(parse(&["-L", "-T", "fields"]), Action::Usage(_)));
        assert!(matches!(
            parse(&["-L", "-e", "frame.number"]),
            Action::Usage(_)
        ));
        assert!(matches!(
            parse(&["-L", "-a", "duration:1"]),
            Action::ListCaptureModes { .. }
        ));
        assert!(matches!(
            parse(&["-L", "-f", "not a filter"]),
            Action::ListCaptureModes { .. }
        ));
        // The rest of the output-mode grammar matches a normal run.
        assert!(matches!(
            parse(&["-L", "-T", "psml", "-e", "frame.number"]),
            Action::ListCaptureModes { .. }
        ));
        assert!(matches!(
            parse(&[
                "-L",
                "-T",
                "json",
                "-e",
                "frame.number",
                "--no-duplicate-keys"
            ]),
            Action::ListCaptureModes { .. }
        ));
        assert!(matches!(
            parse(&["-L", "-T", "jsonraw", "-e", "frame.number"]),
            Action::Error(_)
        ));
        assert!(matches!(
            parse(&["-L", "--no-duplicate-keys"]),
            Action::Error(_)
        ));
        for arguments in [
            &["-L", "-T", "fields", "-e", "frame.number", "-x"][..],
            &["-L", "-T", "pdml", "-e", "frame.number", "-x"],
            &["-L", "-T", "psml", "-e", "frame.number", "-x"],
            &["-L", "-O", "tcp", "-T", "psml"],
        ] {
            assert!(
                matches!(parse(arguments), Action::Error(_)),
                "{arguments:?}"
            );
        }
        assert!(matches!(
            parse(&["-L", "-O", "tcp"]),
            Action::ListCaptureModes { .. }
        ));
    }

    #[test]
    fn device_listing_is_immediate_and_capability_lists_are_not() {
        assert!(matches!(parse(&["-D", "--bogus"]), Action::ListDevices));
        assert!(matches!(parse(&["--bogus", "-D"]), Action::Unknown(_)));
        assert!(matches!(parse(&["-L", "--bogus"]), Action::Unknown(_)));
        assert!(matches!(
            parse(&["-L", "-r", "capture.pcap"]),
            Action::Error(_)
        ));
        match parse(&["-i", "lo0", "-i", "en0", "-L", "--list-time-stamp-types"]) {
            Action::ListCaptureModes { options, modes } => {
                assert_eq!(options.interfaces, ["lo0", "en0"]);
                assert_eq!(
                    modes,
                    ListModes {
                        link_types: true,
                        timestamp_types: true
                    }
                );
            }
            other => {
                eprintln!("expected a list action, got {other:?}");
                std::process::exit(1);
            }
        }
    }
}
