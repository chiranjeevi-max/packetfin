//! `packetfin-core` is the decoding heart of packetfin.
//!
//! It contains no I/O of its own: it works over the `std::io::Read` values the
//! caller passes in. Capture readers, protocol decoders, the field registry,
//! the packet tree, summary columns and expert info live here; command-line
//! parsing and output formatting live in the `packetfin` binary.

pub mod capture;
pub mod decode;
pub mod export;
pub mod fields;
pub mod filter;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_support;
mod http_syntax;
pub mod names;
pub mod state;
pub mod stats;
pub mod time;
pub mod tree;

pub use capture::{
    CaptureError, CaptureEvent, CaptureReader, CaptureWriter, Compression, Frame, InterfaceInfo,
    InterfaceOption, MAX_FRAME_SIZE, MAX_PACKET_SIZE, OutputFormat, PacketOption, PacketOptions,
    PacketRecord, Resolution, SectionInfo, SectionOption, Timestamp, TimestampResolution,
    WriteError, WriterOptions, civil_time, days_from_civil, days_in_month,
};
pub use decode::{
    Columns, DecodeAsTable, DecodeContext, DecodeOptions, LayerType, MAX_DECODE_DEPTH, Packet,
    Preferences, ProtocolPolicy, decode_frame,
};
pub use decode::{DataSourceKind, ExportedKey, KeyLog};
pub use fields::{
    Decoder, Display, FieldDef, FieldType, Protocol, ProtocolDef, Registry, field_by_abbrev,
    protocol_by_name, protocols, registry,
};
pub use filter::{Filter, FilterError};
pub use names::{
    NameResPrefs, NameResolver, Resolution as NameResolution, client_hello_sni, mac_organization,
    mac_short_label, service_name,
};
pub use state::{
    AnnotationStore, DEFAULT_ANNOTATION_BUDGET, DEFAULT_STATE_BUDGET, DecodeSession,
    FrameAnnotation, FrameInfo, PassMode, PutOutcome, RenumberMap, SessionState, StateStore,
    StateValue, apply_annotations, apply_dns_annotations, expert_label_only, expert_offending,
};
pub use stats::{
    ConvKind, DEFAULT_STATS_BUDGET, StatsFilter, StatsOptions, StatsSet, StatsSpec,
    help_text as stats_help_text, parse_spec as parse_stats_spec, unsupported as unsupported_stat,
};
pub use tree::{
    ExpertInfo, Field, FieldSelection, FormattedValue, Group, Node, ProtocolSelection, Range,
    Severity, Tree, Value,
};
