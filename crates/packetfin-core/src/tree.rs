//! The per-packet protocol tree and field values.
//!
//! A decoder adds typed fields with a frame-relative [`Range`] to the node
//! for its protocol. The root node is the frame pseudo-protocol; protocol
//! nodes nest beneath it. Values are typed so output formats and display
//! filters can work from the tree without reparsing packet bytes.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

use crate::capture::Timestamp;
use crate::fields::{Display, FieldDef, FieldType, ProtocolDef};
use crate::time;

/// A byte range within the captured frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    /// Byte offset from the start of the frame or data source.
    pub offset: usize,
    /// Number of bytes in the range.
    pub length: usize,
    /// Zero for the captured frame, otherwise a one-based decrypted data
    /// source index carried by [`crate::decode::Packet::data_sources`].
    pub source: u32,
}

impl Range {
    /// Build a frame-relative range.
    pub const fn new(offset: usize, length: usize) -> Self {
        Self {
            offset,
            length,
            source: 0,
        }
    }

    /// Build a range relative to a decrypted data source.
    pub const fn in_source(source: u32, offset: usize, length: usize) -> Self {
        Self {
            offset,
            length,
            source,
        }
    }
}

/// An immutable byte string that can be shared without copying.
///
/// Reassembled PDUs, chunk bodies and raw field arrays are slices of one
/// larger buffer. A [`Bytes`] keeps the buffer alive and points at a
/// subrange, so copying a field value or attaching the same bytes as a raw
/// source costs one reference, not another multi-MiB allocation.
#[derive(Clone)]
pub struct Bytes {
    storage: Arc<Vec<u8>>,
    start: usize,
    end: usize,
}

impl Bytes {
    /// Take ownership of `data`.
    pub fn new(data: Vec<u8>) -> Self {
        let end = data.len();
        Self {
            storage: Arc::new(data),
            start: 0,
            end,
        }
    }

    /// A subrange of this value, clamped to its bounds.
    pub fn subslice(&self, start: usize, length: usize) -> Self {
        let start = start.min(self.len());
        let end = start.saturating_add(length).min(self.len());
        Self {
            storage: Arc::clone(&self.storage),
            start: self.start.saturating_add(start),
            end: self.start.saturating_add(end),
        }
    }

    /// The bytes this value points at.
    pub fn as_slice(&self) -> &[u8] {
        self.storage.get(self.start..self.end).unwrap_or_default()
    }

    /// Number of bytes this value points at.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether this value points at no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy the bytes into an owned vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl PartialEq<Vec<u8>> for Bytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Bytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Bytes {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<&[u8]> for Bytes {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl PartialOrd for Bytes {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bytes {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("Bytes")
            .field(&self.as_slice())
            .finish()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Bytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Bytes {
    fn from(data: &[u8; N]) -> Self {
        Self::new(data.to_vec())
    }
}

/// One typed field value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Unsigned 8-bit integer.
    Uint8(u8),
    /// Unsigned 16-bit integer.
    Uint16(u16),
    /// Unsigned 24-bit integer.
    Uint24(u32),
    /// Unsigned 32-bit integer.
    Uint32(u32),
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Signed 8-bit integer.
    Int8(i8),
    /// Signed 16-bit integer.
    Int16(i16),
    /// Signed 32-bit integer.
    Int32(i32),
    /// Signed 64-bit integer.
    Int64(i64),
    /// Boolean.
    Boolean(bool),
    /// A field that is present but carries no value (`FT_NONE`).
    None,
    /// A bytes field present with zero declared length, rendered as
    /// `<MISSING>`.
    Missing,
    /// IEEE 802 MAC address.
    Ethernet([u8; 6]),
    /// 64-bit IEEE EUI-64 address.
    Eui64([u8; 8]),
    /// IPv4 address.
    Ipv4([u8; 4]),
    /// IPv6 address.
    Ipv6([u8; 16]),
    /// UTF-8 string.
    String(String),
    /// Uninterpreted bytes.
    Bytes(Bytes),
    /// Absolute capture time.
    AbsoluteTime(Timestamp),
    /// Object identifier sub-identifiers.
    Oid(Vec<u32>),
    /// Relative time in nanoseconds.
    RelativeTime(i64),
}

/// A [`Value`] rendered with a field's display base.
///
/// The adapter implements [`fmt::Display`], so callers can write a value
/// straight into an output sink without an intermediate `String`.
#[derive(Clone, Copy, Debug)]
pub struct FormattedValue<'a> {
    value: &'a Value,
    display: Display,
}

impl Value {
    /// Build a bytes value from any byte storage, sharing without a copy
    /// when the caller already owns a [`Bytes`].
    pub fn bytes(data: impl Into<Bytes>) -> Self {
        Self::Bytes(data.into())
    }

    /// Numeric field type for this value, as JSON raw arrays encode it.
    pub fn raw_field_type(&self) -> u32 {
        match self {
            Self::None | Self::Missing => 0,
            Self::Boolean(_) => 2,
            Self::Uint8(_) => 4,
            Self::Uint16(_) => 5,
            Self::Uint24(_) => 6,
            Self::Uint32(_) => 7,
            Self::Uint64(_) => 11,
            Self::Int8(_) => 12,
            Self::Int16(_) => 13,
            Self::Int32(_) => 15,
            Self::Int64(_) => 19,
            Self::AbsoluteTime(_) => 24,
            Self::RelativeTime(_) => 25,
            Self::String(_) => 26,
            Self::Ethernet(_) => 29,
            Self::Bytes(_) => 30,
            Self::Ipv4(_) => 32,
            Self::Ipv6(_) => 33,
            Self::Oid(_) => 37,
            Self::Eui64(_) => 38,
        }
    }

    /// Render this value with the field's display base.
    pub fn formatted(&self, display: Display) -> FormattedValue<'_> {
        FormattedValue {
            value: self,
            display,
        }
    }

    /// Render this value into an owned string.
    pub fn render(&self, display: Display) -> String {
        self.formatted(display).to_string()
    }
}

impl fmt::Display for FormattedValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value {
            Value::Uint8(value) => write_integer(formatter, u64::from(*value), 2, self.display),
            Value::Uint16(value) => write_integer(formatter, u64::from(*value), 4, self.display),
            Value::Uint24(value) => write_integer(formatter, u64::from(*value), 6, self.display),
            Value::Uint32(value) => write_integer(formatter, u64::from(*value), 8, self.display),
            Value::Uint64(value) => write_integer(formatter, *value, 16, self.display),
            Value::Int8(value) => write_signed(formatter, i64::from(*value), 2, self.display),
            Value::Int16(value) => write_signed(formatter, i64::from(*value), 4, self.display),
            Value::Int32(value) => write_signed(formatter, i64::from(*value), 8, self.display),
            Value::Int64(value) => write_signed(formatter, *value, 16, self.display),
            Value::Boolean(value) => formatter.write_str(if *value { "True" } else { "False" }),
            Value::None => formatter.write_str("1"),
            Value::Missing => formatter.write_str("<MISSING>"),
            Value::Ethernet(address) => write_ethernet(formatter, address),
            Value::Eui64(address) => write_eui64(formatter, address),
            Value::Ipv4(address) => write_ipv4(formatter, address),
            Value::Ipv6(address) => formatter.write_str(&format_ipv6(address)),
            Value::String(text) => formatter.write_str(text),
            Value::Bytes(bytes) => write_bytes(formatter, bytes),
            Value::AbsoluteTime(timestamp) => match self.display {
                Display::IsoTime => formatter.write_str(&time::iso_time(
                    timestamp.seconds,
                    timestamp.nanos,
                    "+0000",
                )),
                Display::IsoTimeZ => {
                    formatter.write_str(&time::iso_time(timestamp.seconds, timestamp.nanos, "Z"))
                }
                _ => write!(formatter, "{}.{:09}", timestamp.seconds, timestamp.nanos),
            },
            Value::Oid(ids) => {
                for (index, id) in ids.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(".")?;
                    }
                    write!(formatter, "{id}")?;
                }
                Ok(())
            }
            Value::RelativeTime(nanos) => {
                let negative = *nanos < 0;
                let magnitude = nanos.unsigned_abs();
                let seconds = magnitude / 1_000_000_000;
                let fraction = magnitude % 1_000_000_000;
                if negative {
                    formatter.write_str("-")?;
                }
                write!(formatter, "{seconds}.{fraction:09}")
            }
        }
    }
}

fn write_integer(
    formatter: &mut fmt::Formatter<'_>,
    value: u64,
    width: usize,
    display: Display,
) -> fmt::Result {
    match display {
        Display::Hex | Display::HexDec => write!(formatter, "0x{value:0width$x}", width = width),
        Display::Seconds256 => formatter.write_str(&render_seconds_256(value)),
        Display::MaskedHex => write!(formatter, "0x{value:08x}"),
        Display::RelativeTime => formatter.write_str(&format_relative_time(value)),
        // BASE_OUI values print numerically and the boolean bit-width markers
        // carry no numeric base.
        Display::Decimal
        | Display::DecHex
        | Display::Oui
        | Display::PortTcp
        | Display::PortUdp
        | Display::Boolean0
        | Display::Boolean6
        | Display::Boolean8
        | Display::Boolean12
        | Display::Boolean16
        | Display::Boolean24
        | Display::Boolean32
        | Display::None
        | Display::BaseNone
        | Display::Custom
        | Display::IsoTime
        | Display::IsoTimeZ => {
            write!(formatter, "{value}")
        }
    }
}

/// Render a 16-bit STP timer held in 1/256-second units.
///
/// The fraction terminates within eight decimal digits; trailing zeros are
/// trimmed. `stp.msg_age` and its siblings use this form.
pub fn render_seconds_256(value: u64) -> String {
    let whole = value / 256;
    let fraction = value % 256;
    if fraction == 0 {
        return whole.to_string();
    }
    let scaled = fraction * 390_625;
    let mut text = format!("{whole}.{scaled:08}");
    while text.ends_with('0') {
        text.pop();
    }
    text
}

/// Render a nanosecond interval as `-T fields` and JSON print an
/// `FT_RELATIVE_TIME` field: seconds with nine fractional digits.
pub fn format_relative_time(nanos: u64) -> String {
    format!("{}.{:09}", nanos / 1_000_000_000, nanos % 1_000_000_000)
}

fn write_signed(
    formatter: &mut fmt::Formatter<'_>,
    value: i64,
    width: usize,
    display: Display,
) -> fmt::Result {
    match display {
        Display::Hex | Display::HexDec => {
            let mask = match width {
                2 => 0xff_u64,
                4 => 0xffff,
                8 => 0xffff_ffff,
                _ => u64::MAX,
            };
            let unsigned = (value as u64) & mask;
            write!(formatter, "0x{unsigned:0width$x}", width = width)
        }
        Display::RelativeTime => formatter.write_str(&format_relative_time(
            u64::try_from(value).unwrap_or_default(),
        )),
        Display::Decimal
        | Display::DecHex
        | Display::Oui
        | Display::PortTcp
        | Display::PortUdp
        | Display::Boolean0
        | Display::Boolean6
        | Display::Boolean8
        | Display::Boolean12
        | Display::Boolean16
        | Display::Boolean24
        | Display::Boolean32
        | Display::None
        | Display::BaseNone
        | Display::Custom
        | Display::IsoTime
        | Display::IsoTimeZ
        | Display::MaskedHex
        | Display::Seconds256 => {
            write!(formatter, "{value}")
        }
    }
}

fn write_ethernet(formatter: &mut fmt::Formatter<'_>, address: &[u8; 6]) -> fmt::Result {
    for (index, byte) in address.iter().enumerate() {
        if index > 0 {
            formatter.write_str(":")?;
        }
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

fn write_eui64(formatter: &mut fmt::Formatter<'_>, address: &[u8; 8]) -> fmt::Result {
    for (index, byte) in address.iter().enumerate() {
        if index > 0 {
            formatter.write_str(":")?;
        }
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

fn write_ipv4(formatter: &mut fmt::Formatter<'_>, address: &[u8; 4]) -> fmt::Result {
    for (index, byte) in address.iter().enumerate() {
        if index > 0 {
            formatter.write_str(".")?;
        }
        write!(formatter, "{byte}")?;
    }
    Ok(())
}

/// Format an IPv6 address in RFC 5952 canonical form: lowercase hexadecimal,
/// the longest run of two or more zero groups replaced by `::`.
pub(crate) fn format_ipv6(address: &[u8; 16]) -> String {
    if let Some(embedded) = embedded_ipv4(address) {
        return embedded;
    }
    let mut groups = [0_u16; 8];
    let (chunks, _) = address.as_chunks::<2>();
    for (group, chunk) in groups.iter_mut().zip(chunks) {
        *group = u16::from_be_bytes(*chunk);
    }

    let run = longest_zero_run(&groups);
    let mut parts: Vec<String> = Vec::with_capacity(8);
    let mut index = 0;
    while index < groups.len() {
        if let Some((start, length)) = run
            && index == start
        {
            parts.push(String::new());
            index += length;
            continue;
        }
        parts.push(format!("{:x}", groups.get(index).copied().unwrap_or(0)));
        index += 1;
    }

    let mut text = parts.join(":");
    if let Some((start, length)) = run {
        if start == 0 {
            text.insert(0, ':');
        }
        if start + length == groups.len() {
            text.push(':');
        }
    }
    text
}

fn embedded_ipv4(address: &[u8; 16]) -> Option<String> {
    let suffix: [u8; 4] = address.get(12..16)?.try_into().ok()?;
    let [first, second, third, fourth] = suffix;
    let dotted = format!("{first}.{second}.{third}.{fourth}");
    if address.iter().take(10).all(|byte| *byte == 0)
        && address.get(10..12) == Some(&[0xff, 0xff][..])
    {
        return Some(format!("::ffff:{dotted}"));
    }
    if address.iter().take(12).all(|byte| *byte == 0) && u32::from_be_bytes(suffix) > 0xffff {
        return Some(format!("::{dotted}"));
    }
    None
}

fn longest_zero_run(groups: &[u16; 8]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut index = 0;
    while let Some(group) = groups.get(index) {
        if *group == 0 {
            let start = index;
            while groups.get(index) == Some(&0) {
                index += 1;
            }
            let length = index - start;
            if length >= 2 && best.is_none_or(|(_, best_length)| length > best_length) {
                best = Some((start, length));
            }
        } else {
            index += 1;
        }
    }
    best
}

/// Render an object identifier as dotted decimal.
pub fn oid_text(ids: &[u32]) -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            text.push('.');
        }
        let _ = write!(text, "{id}");
    }
    text
}

/// Render an object identifier with its resolved root label.
///
/// An OID under the `iso` root (first sub-identifier 1) prints as `iso`
/// followed by the remaining sub-identifiers, the alternate form shown for
/// `snmp.enterprise` and SNMP value names.
pub fn oid_resolved_text(ids: &[u32]) -> String {
    let dotted = oid_text(ids);
    match (ids.first(), dotted.strip_prefix('1')) {
        (Some(1), Some(rest)) => format!("iso{rest}"),
        _ => dotted,
    }
}

fn write_bytes(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    if bytes.is_empty() {
        return formatter.write_str("<none>");
    }
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Severity of an expert-info entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// A capture comment, the least serious entry.
    Comment,
    /// Conversational information.
    Chat,
    /// A notable event.
    Note,
    /// A possible problem.
    Warning,
    /// A definite problem.
    Error,
}

/// Group of an expert-info entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// Malformed or truncated data.
    Malformed,
    /// A checksum failure.
    Checksum,
    /// A sequence-number problem.
    Sequence,
    /// A protocol violation.
    Protocol,
    /// Use of a deprecated feature.
    Deprecated,
    /// A response problem.
    Response,
    /// A request problem.
    Request,
    /// Data that was not decoded.
    Undecoded,
    /// Reassembly information.
    Reassemble,
    /// A capture or packet comment.
    Comment,
}

impl Group {
    /// The group label the expert statistics table prints.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::Checksum => "Checksum",
            Self::Sequence => "Sequence",
            Self::Protocol => "Protocol",
            Self::Deprecated => "Deprecated",
            Self::Response => "Response",
            Self::Request => "Request",
            Self::Undecoded => "Undecoded",
            Self::Reassemble => "Reassemble",
            Self::Comment => "Comment",
        }
    }
}

/// One expert-info entry raised while decoding a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpertInfo {
    /// How serious the entry is.
    pub severity: Severity,
    /// Which kind of problem it reports.
    pub group: Group,
    /// Human-readable explanation.
    pub message: String,
}

/// Where a raw value array came from, and its code in JSON raw arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawSource {
    /// Bytes of a field's own value (`0`).
    Field,
    /// Bytes of a reassembled or generated record (`1`).
    Frame,
    /// Decrypted TLS plaintext (`2`).
    Plaintext,
    /// A computed value with no source (`null`).
    None,
}

/// The exact raw span reported for a field.
///
/// Container values and generated records are not always a slice of the
/// captured frame, so `Range` alone cannot describe their raw array or PDML
/// value. Decoders set this alongside the typed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawField {
    /// Bytes the raw value renders.
    pub bytes: Bytes,
    /// Offset reported as the raw array's start.
    pub start: usize,
    /// Length reported for the raw value and PDML `size`.
    pub length: usize,
    /// Bit mask reported for the raw value.
    pub bitmask: u64,
    /// Numeric field type for the raw array.
    pub field_type: u32,
    /// Where the raw value came from.
    pub source: RawSource,
}

/// A showname whose hex text is generated only when an output format
/// renders it.
///
/// A chunked HTTP body can hold tens of thousands of chunk data fields; the
/// hex label of each is twice its byte length and would otherwise be retained
/// for the whole frame. The bytes are already shared with the reassembly
/// buffer, so the label costs nothing until printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexShowname {
    /// Text before the lowercase hex bytes.
    pub prefix: &'static str,
    /// Bytes rendered as lowercase hex.
    pub bytes: Bytes,
}

/// One field occurrence in a protocol node.
///
/// A container field carries children: the tree attaches generated
/// state, option lists and reassembly records this way. The container is
/// still one occurrence of its definition, so display filters and `-e`
/// selection see it beside its descendants rather than instead of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The registry definition this occurrence instantiates.
    pub def: &'static FieldDef,
    /// Bytes the value came from; zero-length for generated values.
    pub range: Range,
    /// The typed value.
    pub value: Value,
    /// Whether the value was computed rather than read from the frame.
    pub generated: bool,
    /// Complete `showname` label for this occurrence, including any
    /// count or value text. Decoders set it for containers and for the
    /// generated records inside them.
    pub showname: Option<String>,
    /// A showname generated from bytes when output needs it.
    pub showname_hex: Option<HexShowname>,
    /// Nested field occurrences, in decoder order.
    pub children: Vec<Field>,
    /// Protocol nodes nested inside this field, after its child fields.
    ///
    /// A field item can carry a whole protocol subtree: a DHCPv6
    /// Relay Message option holds the inner DHCPv6 message this way. Output
    /// writers emit these nodes after the field's child fields, in order.
    pub nodes: Vec<Node>,
    /// Expert-info entries attached to this field.
    pub experts: Vec<ExpertInfo>,
    /// Field named as the expert entry's offending item.
    ///
    /// Some expert entries attach to a visible field but label the entry with
    /// a zero-length companion field (`dns.response_missing` under `dns.id`).
    /// When set, output formats use this definition for the expert block's
    /// child field instead of `def`.
    pub expert_field: Option<&'static FieldDef>,
    /// Whether this occurrence was added as a container.
    ///
    /// Container identity survives pruning a container's children away, so
    /// it cannot be inferred from `children` alone.
    pub container: bool,
    /// Whether this occurrence is hidden from the detail view and marked
    /// `hide="yes"` in PDML. JSON and EK still emit hidden fields, and
    /// display filters and `-e` selection see them.
    pub hidden: bool,
    /// A mask for this occurrence when it differs from the registry entry.
    ///
    /// The OSPF TOS byte reports mask `0x7f` in the packet tree while
    /// `-G fields` keeps the field maskless; the occurrence override keeps
    /// both reports exact.
    pub mask_override: Option<u64>,
    /// Exact raw span when it cannot be derived from `range` and `value`.
    pub raw: Option<RawField>,
}

impl Field {
    /// The label an output format prints for this field.
    ///
    /// A lazy hex label is rendered here rather than during decoding.
    pub fn showname_text(&self) -> Option<Cow<'_, str>> {
        if let Some(text) = &self.showname {
            return Some(Cow::Borrowed(text));
        }
        let lazy = self.showname_hex.as_ref()?;
        let mut text = String::with_capacity(
            lazy.prefix
                .len()
                .saturating_add(lazy.bytes.len().saturating_mul(2)),
        );
        text.push_str(lazy.prefix);
        for byte in lazy.bytes.as_slice() {
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!("{byte:02x}"));
        }
        Some(Cow::Owned(text))
    }

    fn occurrence(def: &'static FieldDef, range: Range, value: Value) -> Self {
        Self {
            def,
            range,
            value,
            generated: def.generated,
            showname: None,
            showname_hex: None,
            children: Vec::new(),
            nodes: Vec::new(),
            experts: Vec::new(),
            expert_field: None,
            container: false,
            hidden: false,
            mask_override: None,
            raw: None,
        }
    }

    pub(crate) fn container(
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> Self {
        let value = match def.field_type {
            FieldType::Bytes => Value::bytes(Bytes::default()),
            _ => Value::None,
        };
        Self {
            def,
            range,
            value,
            generated: def.generated,
            showname,
            showname_hex: None,
            children: Vec::new(),
            nodes: Vec::new(),
            experts: Vec::new(),
            expert_field: None,
            container: true,
            hidden: false,
            mask_override: None,
            raw: None,
        }
    }

    /// Mark this field, its children and its nested protocol nodes as
    /// belonging to a data source.
    pub fn set_range_source(&mut self, source: u32) {
        self.range.source = source;
        for child in &mut self.children {
            child.set_range_source(source);
        }
        for node in &mut self.nodes {
            node.set_range_source(source);
        }
    }

    /// Whether this occurrence is a container rather than a leaf.
    pub fn is_container(&self) -> bool {
        self.container
    }

    /// Hide this occurrence from the detail view and mark it hidden in PDML.
    ///
    /// Synthetic companion fields use this, such as the
    /// `ospf.msg.*` message-type flags: `-V` omits them, PDML keeps them with
    /// `hide="yes"`, and JSON/EK/filters still see them.
    pub fn hide(&mut self) -> &mut Self {
        self.hidden = true;
        self
    }

    /// Whether this container sits at packet scope.
    ///
    /// `tcp.segments` is built through a protocol-scope helper node, so its
    /// label starts at column zero and JSON/PDML place it beside `tcp`
    /// instead of inside it. Every other container stays inline.
    pub fn packet_scoped(&self) -> bool {
        self.container && self.def.abbrev == "tcp.segments"
    }

    /// Add a child field occurrence and return it for expert attachment.
    pub fn add_field(&mut self, def: &'static FieldDef, range: Range, value: Value) -> &mut Field {
        self.children.push(Self::occurrence(def, range, value));
        let Some(field) = self.children.last_mut() else {
            unreachable!("a child field was just pushed")
        };
        field
    }

    /// Add a nested container and return it for child insertion.
    pub fn add_container(
        &mut self,
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> &mut Field {
        self.children.push(Self::container(def, range, showname));
        let Some(field) = self.children.last_mut() else {
            unreachable!("a nested container was just pushed")
        };
        field
    }

    /// Add a protocol node nested inside this field.
    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    /// Add an expert-info entry attached to this field.
    pub fn add_expert(&mut self, expert: ExpertInfo) {
        self.experts.push(expert);
    }

    /// Add an expert that names a zero-length companion field as its
    /// offending item, as DNS state expert entries do.
    pub fn add_expert_for(&mut self, expert: ExpertInfo, field: &'static FieldDef) {
        self.expert_field = Some(field);
        self.experts.push(expert);
    }

    fn has_expert(&self, group: Group) -> bool {
        self.experts.iter().any(|expert| expert.group == group)
            || self.children.iter().any(|child| child.has_expert(group))
            || self
                .nodes
                .iter()
                .any(|node| node.has_expert_in_subtree(group))
    }

    fn collect<'a>(&'a self, collected: &mut Vec<&'a Field>) {
        self.for_each_in_subtree(&mut |field| collected.push(field));
    }

    /// Call `visit` for this field and its field descendants in preorder.
    pub fn for_each_in_subtree<'a>(&'a self, visit: &mut impl FnMut(&'a Field)) {
        let _ = self.try_for_each_in_subtree(&mut |field| {
            visit(field);
            Ok::<(), ()>(())
        });
    }

    fn try_for_each_in_subtree<'a, E>(
        &'a self,
        visit: &mut impl FnMut(&'a Field) -> Result<(), E>,
    ) -> Result<(), E> {
        visit(self)?;
        for child in &self.children {
            child.try_for_each_in_subtree(visit)?;
        }
        if !self.nodes.is_empty() {
            for node in &self.nodes {
                node.try_for_each_field_in(visit)?;
            }
        }
        Ok(())
    }

    fn prune(&mut self, selection: &FieldSelection, protocols: &ProtocolSelection) -> bool {
        self.children
            .retain_mut(|child| child.prune(selection, protocols));
        for node in &mut self.nodes {
            node.prune(selection, protocols);
        }
        self.nodes
            .retain(|node| !node.is_empty() || protocols.contains(node.protocol));
        selection.contains(self.def) || !self.children.is_empty() || !self.nodes.is_empty()
    }
}

/// A place fields can be appended to: a protocol node or a container field.
///
/// Decoders that populate a named container or an unnamed group write through
/// this trait, so the same insertion code serves the flat and nested layouts.
pub trait FieldParent {
    /// Add a field occurrence and return it for expert attachment.
    fn add_field(&mut self, def: &'static FieldDef, range: Range, value: Value) -> &mut Field;

    /// Add a container occurrence and return it for child insertion.
    fn add_container(
        &mut self,
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> &mut Field;

    /// Add a protocol node nested inside the current container.
    fn add_node(&mut self, node: Node);

    /// Add an unnamed synthetic group (`name=""` in PDML).
    fn add_unnamed(&mut self, range: Range, showname: String) -> &mut Field {
        self.add_container(&crate::fields::UNNAMED_CONTAINER, range, Some(showname))
    }
}

impl FieldParent for Node {
    fn add_field(&mut self, def: &'static FieldDef, range: Range, value: Value) -> &mut Field {
        Node::add_field(self, def, range, value)
    }

    fn add_container(
        &mut self,
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> &mut Field {
        Node::add_container(self, def, range, showname)
    }

    fn add_node(&mut self, node: Node) {
        Node::add_child(self, node);
    }
}

impl FieldParent for Field {
    fn add_field(&mut self, def: &'static FieldDef, range: Range, value: Value) -> &mut Field {
        Field::add_field(self, def, range, value)
    }

    fn add_container(
        &mut self,
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> &mut Field {
        Field::add_container(self, def, range, showname)
    }

    fn add_node(&mut self, node: Node) {
        Field::add_node(self, node);
    }
}

impl<T: FieldParent + ?Sized> FieldParent for &mut T {
    fn add_field(&mut self, def: &'static FieldDef, range: Range, value: Value) -> &mut Field {
        (**self).add_field(def, range, value)
    }

    fn add_container(
        &mut self,
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> &mut Field {
        (**self).add_container(def, range, showname)
    }

    fn add_node(&mut self, node: Node) {
        (**self).add_node(node);
    }
}

/// The field definitions an output selects.
///
/// A selection is built once from the requested definitions and then checked
/// for every occurrence while the tree is pruned. Definitions are the
/// registry's `'static` entries, so their addresses identify them without
/// comparing abbreviation strings. Definitions that share an abbreviation
/// (mDNS reuses DNS names for some fields) expand to every identity the
/// registry assigns that abbreviation, so a selected name keeps all of its
/// occurrences.
#[derive(Clone, Debug, Default)]
pub struct FieldSelection {
    selected: HashSet<usize, BuildHasherDefault<FastHasher>>,
}

impl FieldSelection {
    /// Select every definition in `fields`. Duplicates are harmless.
    pub fn new(fields: &[&'static FieldDef]) -> Self {
        let mut selected = HashSet::with_capacity_and_hasher(
            fields.len(),
            BuildHasherDefault::<FastHasher>::default(),
        );
        let registry = crate::fields::registry();
        for field in fields {
            selected.insert(field.identity());
            if let Some(canonical) = registry.field(field.abbrev) {
                selected.insert(canonical.identity());
            }
            for shared in registry.shared_abbrev_fields(field.abbrev) {
                selected.insert(shared.identity());
            }
        }
        Self { selected }
    }

    /// Select the definitions the registry assigns to `abbreviations`.
    ///
    /// An unknown abbreviation selects nothing, so a caller that has already
    /// rejected unknown fields sees the same behaviour here.
    pub fn from_abbreviations(abbreviations: &[&str]) -> Self {
        let registry = crate::fields::registry();
        let mut selected = HashSet::with_capacity_and_hasher(
            abbreviations.len(),
            BuildHasherDefault::<FastHasher>::default(),
        );
        for abbreviation in abbreviations {
            if let Some(field) = registry.field(abbreviation) {
                selected.insert(field.identity());
            }
            for shared in registry.shared_abbrev_fields(abbreviation) {
                selected.insert(shared.identity());
            }
        }
        Self { selected }
    }

    fn contains(&self, field: &'static FieldDef) -> bool {
        self.selected.contains(&field.identity())
    }
}

/// A hasher for the address identities the selection sets hold.
///
/// Address lookups never hash strings, so a multiply-rotate hash is enough;
/// it keeps the per-occurrence prune check to a few instructions. Hash quality
/// only affects probe length, never what a selection contains.
#[derive(Clone, Copy, Debug, Default)]
struct FastHasher(u64);

impl FastHasher {
    const PRIME: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    fn mix(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(Self::PRIME);
    }
}

impl Hasher for FastHasher {
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = 0_u64;
            for (index, byte) in chunk.iter().enumerate() {
                word |= u64::from(*byte) << (index * 8);
            }
            self.mix(word);
        }
    }

    fn write_usize(&mut self, value: usize) {
        self.mix(value as u64);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// The protocol definitions a filter-aware prune must keep.
///
/// A protocol node kept by this selection survives even when no selected
/// field, child or expert keeps it alive, so a display filter's protocol
/// existence test still sees it.
#[derive(Clone, Debug, Default)]
pub struct ProtocolSelection {
    selected: HashSet<usize>,
}

impl ProtocolSelection {
    /// Select every definition in `protocols`. Duplicates are harmless.
    pub fn new(protocols: &[&'static ProtocolDef]) -> Self {
        let mut selected = HashSet::with_capacity(protocols.len());
        for protocol in protocols {
            selected.insert(protocol.identity());
        }
        Self { selected }
    }

    fn contains(&self, protocol: &'static ProtocolDef) -> bool {
        self.selected.contains(&protocol.identity())
    }
}

/// One protocol in the packet tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The protocol this node represents.
    pub protocol: &'static ProtocolDef,
    /// Bytes this protocol covers within the frame.
    pub range: Range,
    /// Field occurrences, in decoder order.
    pub fields: Vec<Field>,
    /// Nested protocol nodes, in decode order.
    pub children: Vec<Node>,
    /// Expert-info entries raised while decoding this protocol.
    pub experts: Vec<ExpertInfo>,
    /// Whether a protocol exception reached this node. Field-level malformed
    /// experts leave it false so the detail view does not invent a
    /// `[Malformed Packet]` line.
    pub protocol_exception: bool,
    /// Whether this node belongs to a datagram quoted inside another packet.
    ///
    /// Statistics (`io,phs`, expert, conversations, endpoints) skip quoted
    /// copies, while display filters and `io,stat` field counts still see
    /// them.
    pub quoted: bool,
    /// Bytes this node was decoded from when they are not the captured frame.
    ///
    /// A protocol decoded from a reassembled buffer keeps the whole buffer
    /// here so output formats can map its frame-relative ranges back to the
    /// bytes that produced them.
    pub source: Option<Arc<[u8]>>,
    /// Field order for full-tree output, after any item moves.
    ///
    /// Items move only when the full tree is built; selected-field output
    /// (`-e`) walks the insertion order instead. `None` means the field list
    /// is already in display order. Pruning clears it because the indices no
    /// longer address the retained occurrences.
    display_order: Option<Vec<u32>>,
}

impl Node {
    /// Create an empty protocol node.
    pub fn new(protocol: &'static ProtocolDef, range: Range) -> Self {
        Self {
            protocol,
            range,
            fields: Vec::new(),
            children: Vec::new(),
            experts: Vec::new(),
            protocol_exception: false,
            quoted: false,
            source: None,
            display_order: None,
        }
    }

    /// Mark every range in this subtree as belonging to a decrypted data
    /// source. Container offsets are set by the caller when they stay
    /// frame-relative, as TLS handshake containers do.
    pub fn set_range_source(&mut self, source: u32) {
        self.range.source = source;
        for field in &mut self.fields {
            field.set_range_source(source);
        }
        for child in &mut self.children {
            child.set_range_source(source);
        }
    }

    /// Mark this node and its descendants as a quoted datagram.
    pub fn mark_quoted(&mut self) {
        self.quoted = true;
        for field in &mut self.fields {
            for node in &mut field.nodes {
                node.mark_quoted();
            }
        }
        for child in &mut self.children {
            child.mark_quoted();
        }
    }

    /// Add a field occurrence and return it for expert attachment. Its
    /// `generated` flag comes from the definition.
    pub fn add_field(&mut self, def: &'static FieldDef, range: Range, value: Value) -> &mut Field {
        self.fields.push(Field::occurrence(def, range, value));
        let Some(field) = self.fields.last_mut() else {
            unreachable!("a field was just pushed")
        };
        field
    }

    /// Insert a field occurrence at a position in the decoder-ordered list.
    ///
    /// Cross-pass links arrive after decoding but take a fixed position
    /// among the decoded fields (before generated URIs or segment data), so
    /// they cannot simply be appended.
    pub fn insert_field(
        &mut self,
        index: usize,
        def: &'static FieldDef,
        range: Range,
        value: Value,
    ) -> &mut Field {
        let index = index.min(self.fields.len());
        self.fields
            .insert(index, Field::occurrence(def, range, value));
        let Some(field) = self.fields.get_mut(index) else {
            unreachable!("a field was just inserted")
        };
        field
    }

    /// Add a container field occurrence and return it for child insertion.
    ///
    /// `showname` is the complete label for the container. A bytes
    /// container starts with an empty value; the decoder fills it before
    /// adding the records it describes.
    pub fn add_container(
        &mut self,
        def: &'static FieldDef,
        range: Range,
        showname: Option<String>,
    ) -> &mut Field {
        self.fields.push(Field::container(def, range, showname));
        let Some(field) = self.fields.last_mut() else {
            unreachable!("a container was just pushed")
        };
        field
    }

    /// Add a child protocol node.
    pub fn add_child(&mut self, child: Node) {
        self.children.push(child);
    }

    /// Add an expert-info entry.
    pub fn add_expert(&mut self, expert: ExpertInfo) {
        self.experts.push(expert);
    }

    /// The first child for a protocol filter name.
    pub fn child(&self, filter_name: &str) -> Option<&Node> {
        self.children
            .iter()
            .find(|child| child.protocol.filter_name == filter_name)
    }

    /// Whether an expert entry in this node, its fields or a descendant node
    /// has the group.
    pub fn has_expert(&self, group: Group) -> bool {
        self.experts.iter().any(|expert| expert.group == group)
            || self.fields.iter().any(|field| field.has_expert(group))
            || self.children.iter().any(|child| child.has_expert(group))
    }

    pub(crate) fn has_expert_in_subtree(&self, group: Group) -> bool {
        self.has_expert(group)
    }

    /// Set the sibling order full-tree writers use.
    ///
    /// `order` must be a permutation of `0..fields.len()`. Items move only
    /// while a full tree is built, so this order stays separate from the
    /// insertion order selected fields use.
    pub fn set_display_order(&mut self, order: Vec<u32>) {
        debug_assert_eq!(order.len(), self.fields.len());
        debug_assert!({
            let mut seen = vec![false; order.len()];
            order.iter().all(|&index| {
                let index = usize::try_from(index).unwrap_or(usize::MAX);
                if let Some(slot) = seen.get_mut(index) {
                    if *slot {
                        return false;
                    }
                    *slot = true;
                    true
                } else {
                    false
                }
            })
        });
        self.display_order = Some(order);
    }

    /// Fields in full-tree display order.
    pub fn display_fields(&self) -> impl Iterator<Item = &Field> {
        let fields = &self.fields;
        let mut explicit = self.display_order.as_ref().map(|order| order.iter());
        let mut insertion = fields.iter();
        std::iter::from_fn(move || {
            if let Some(order) = explicit.as_mut() {
                for &index in order.by_ref() {
                    if let Some(field) = fields.get(usize::try_from(index).ok()?) {
                        return Some(field);
                    }
                }
                None
            } else {
                insertion.next()
            }
        })
    }

    fn collect_fields<'a>(&'a self, collected: &mut Vec<&'a Field>) {
        for field in &self.fields {
            field.collect(collected);
        }
        for child in &self.children {
            child.collect_fields(collected);
        }
    }

    /// Call `visit` for every field in this node and its descendants, in
    /// preorder. Stops at the first error.
    pub fn try_for_each_field<E>(
        &self,
        visit: &mut impl FnMut(&Field) -> Result<(), E>,
    ) -> Result<(), E> {
        self.try_for_each_field_in(visit)
    }

    fn try_for_each_field_in<'a, E>(
        &'a self,
        visit: &mut impl FnMut(&'a Field) -> Result<(), E>,
    ) -> Result<(), E> {
        for field in &self.fields {
            field.try_for_each_in_subtree(visit)?;
        }
        for child in &self.children {
            child.try_for_each_field_in(visit)?;
        }
        Ok(())
    }

    fn prune(&mut self, selection: &FieldSelection, protocols: &ProtocolSelection) {
        self.fields
            .retain_mut(|field| field.prune(selection, protocols));
        self.display_order = None;
        for child in &mut self.children {
            child.prune(selection, protocols);
        }
        self.children
            .retain(|child| !child.is_empty() || protocols.contains(child.protocol));
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.children.is_empty() && self.experts.is_empty()
    }
}

/// The packet tree. The root node is the frame pseudo-protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
    /// The frame node; protocol nodes are its descendants.
    pub frame: Node,
}

impl Tree {
    /// Wrap a frame node in a tree.
    pub fn new(frame: Node) -> Self {
        Self { frame }
    }

    /// Every field occurrence in preorder: each field (and its container
    /// descendants), then each child protocol's fields.
    pub fn fields(&self) -> std::vec::IntoIter<&Field> {
        let mut collected = Vec::new();
        self.frame.collect_fields(&mut collected);
        collected.into_iter()
    }

    /// Every value of a field, in tree order.
    pub fn field_values(&self, abbrev: &str) -> Vec<&Value> {
        self.fields()
            .filter(|field| field.def.abbrev == abbrev)
            .map(|field| &field.value)
            .collect()
    }

    /// Call `visit` for every field occurrence in preorder: the frame's
    /// fields, then each protocol's fields, then its children's. Stops at the
    /// first error.
    pub fn try_for_each_field<E>(
        &self,
        visit: &mut impl FnMut(&Field) -> Result<(), E>,
    ) -> Result<(), E> {
        self.frame.try_for_each_field(visit)
    }

    /// Drop fields that the requested output does not select, then drop
    /// protocol nodes that no longer carry fields, children or expert info.
    pub fn prune(&mut self, selection: &FieldSelection) {
        self.prune_keeping(selection, &ProtocolSelection::default());
    }

    /// Prune fields and protocols while keeping every protocol node a
    /// display filter references, even when it has no selected fields.
    pub fn prune_keeping(&mut self, selection: &FieldSelection, protocols: &ProtocolSelection) {
        self.frame.prune(selection, protocols);
    }

    /// The first child for a protocol filter name.
    pub fn child(&self, filter_name: &str) -> Option<&Node> {
        self.frame.child(filter_name)
    }

    /// Whether any node carries an expert entry in the group.
    pub fn has_expert(&self, group: Group) -> bool {
        self.frame.has_expert(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static CONTAINER: FieldDef = FieldDef {
        abbrev: "tcp.analysis",
        name: "SEQ/ACK analysis",
        field_type: FieldType::None,
        parent: "tcp",
        display: Display::None,
        bitmask: None,
        blurb: "",
        generated: true,
    };
    static CHILD_ONE: FieldDef = FieldDef {
        abbrev: "tcp.analysis.acks_frame",
        name: "This is an ACK to the segment in frame",
        field_type: FieldType::Uint32,
        parent: "tcp.analysis",
        display: Display::Decimal,
        bitmask: None,
        blurb: "",
        generated: true,
    };
    static CHILD_TWO: FieldDef = FieldDef {
        abbrev: "tcp.analysis.rto",
        name: "The RTO for this segment was",
        field_type: FieldType::Uint32,
        parent: "tcp.analysis",
        display: Display::Decimal,
        bitmask: None,
        blurb: "",
        generated: true,
    };
    static BYTES_CONTAINER: FieldDef = FieldDef {
        abbrev: "ip.fragments",
        name: "IPv4 Fragments",
        field_type: FieldType::Bytes,
        parent: "ip",
        display: Display::None,
        bitmask: None,
        blurb: "",
        generated: true,
    };
    static FLAT_ONE: FieldDef = FieldDef {
        abbrev: "tcp.seq",
        name: "Sequence Number",
        field_type: FieldType::Uint32,
        parent: "tcp",
        display: Display::Decimal,
        bitmask: None,
        blurb: "",
        generated: false,
    };
    static FLAT_TWO: FieldDef = FieldDef {
        abbrev: "tcp.ack",
        name: "Acknowledgment Number",
        field_type: FieldType::Uint32,
        parent: "tcp",
        display: Display::Decimal,
        bitmask: None,
        blurb: "",
        generated: false,
    };
    static SEGMENTS: FieldDef = FieldDef {
        abbrev: "tcp.segments",
        name: "Reassembled TCP Segments",
        field_type: FieldType::None,
        parent: "tcp",
        display: Display::None,
        bitmask: None,
        blurb: "",
        generated: true,
    };
    static PROTOCOL: ProtocolDef = ProtocolDef {
        filter_name: "tcp",
        long_name: "Transmission Control Protocol",
        short_name: "TCP",
        fields: &[&CONTAINER, &FLAT_ONE],
    };

    fn node(fields: impl FnOnce(&mut Node)) -> Node {
        let mut node = Node::new(&PROTOCOL, Range::new(0, 0));
        fields(&mut node);
        node
    }

    #[test]
    fn containers_start_with_the_value_their_type_declares() {
        let node = node(|node| {
            node.add_container(&CONTAINER, Range::new(0, 0), Some("label".to_string()));
            node.add_container(&BYTES_CONTAINER, Range::new(0, 0), None);
        });
        let values: Vec<&Value> = node.fields.iter().map(|field| &field.value).collect();
        assert_eq!(values, [&Value::None, &Value::bytes(Vec::new())]);
        assert_eq!(node.fields.len(), 2);
        let (Some(analysis), Some(bytes)) = (node.fields.first(), node.fields.get(1)) else {
            return;
        };
        assert_eq!(analysis.showname.as_deref(), Some("label"));
        assert!(analysis.is_container());
        assert!(bytes.is_container());
    }

    #[test]
    fn field_preorder_visits_a_container_before_its_children() {
        let frame = node(|node| {
            node.add_field(&FLAT_ONE, Range::new(0, 4), Value::Uint32(1));
            let container =
                node.add_container(&CONTAINER, Range::new(4, 0), Some("SEQ/ACK".to_string()));
            container.add_field(&CHILD_ONE, Range::new(4, 0), Value::Uint32(1));
            container.add_field(&CHILD_TWO, Range::new(4, 0), Value::Uint32(2));
            node.add_field(&FLAT_TWO, Range::new(8, 4), Value::Uint32(3));
        });
        let tree = Tree::new(frame);
        let abbreviations: Vec<&str> = tree.fields().map(|field| field.def.abbrev).collect();
        assert_eq!(
            abbreviations,
            [
                "tcp.seq",
                "tcp.analysis",
                "tcp.analysis.acks_frame",
                "tcp.analysis.rto",
                "tcp.ack"
            ]
        );

        let mut visited = Vec::new();
        assert!(
            tree.try_for_each_field(&mut |field| {
                visited.push(field.def.abbrev);
                Ok::<(), ()>(())
            })
            .is_ok()
        );
        assert_eq!(visited, abbreviations);
    }

    #[test]
    fn pruning_keeps_a_container_only_with_a_selection_or_surviving_child() {
        fn tree() -> Tree {
            Tree::new(node(|node| {
                node.add_field(&FLAT_ONE, Range::new(0, 4), Value::Uint32(1));
                let container =
                    node.add_container(&CONTAINER, Range::new(4, 0), Some("SEQ/ACK".to_string()));
                container.add_field(&CHILD_ONE, Range::new(4, 0), Value::Uint32(1));
                container.add_field(&CHILD_TWO, Range::new(4, 0), Value::Uint32(2));
                node.add_field(&FLAT_TWO, Range::new(8, 4), Value::Uint32(3));
            }))
        }

        let mut child_only = tree();
        child_only.prune(&FieldSelection::new(&[&CHILD_TWO]));
        let fields: Vec<&str> = child_only.fields().map(|field| field.def.abbrev).collect();
        assert_eq!(fields, ["tcp.analysis", "tcp.analysis.rto"]);

        let mut container_only = tree();
        container_only.prune(&FieldSelection::new(&[&CONTAINER]));
        let fields: Vec<&str> = container_only
            .fields()
            .map(|field| field.def.abbrev)
            .collect();
        assert_eq!(fields, ["tcp.analysis"]);

        let mut flat_only = tree();
        flat_only.prune(&FieldSelection::new(&[&FLAT_TWO]));
        let fields: Vec<&str> = flat_only.fields().map(|field| field.def.abbrev).collect();
        assert_eq!(fields, ["tcp.ack"]);

        let mut nothing = tree();
        nothing.prune(&FieldSelection::default());
        assert!(nothing.fields().next().is_none());
    }

    #[test]
    fn selection_keeps_every_definition_sharing_an_abbreviation() {
        use crate::fields::{
            DNS_RR_UDP_PAYLOAD_SIZE, DNS_RR_UDP_PAYLOAD_SIZE_MDNS, FRAME_PROTOCOL,
        };

        fn tree() -> Tree {
            let mut frame = Node::new(&FRAME_PROTOCOL, Range::new(0, 0));
            frame.add_field(
                &DNS_RR_UDP_PAYLOAD_SIZE,
                Range::new(0, 2),
                Value::Uint16(512),
            );
            frame.add_field(
                &DNS_RR_UDP_PAYLOAD_SIZE_MDNS,
                Range::new(2, 2),
                Value::Uint16(1400),
            );
            Tree::new(frame)
        }

        let mut from_name = tree();
        from_name.prune(&FieldSelection::from_abbreviations(&[
            "dns.rr.udp_payload_size",
        ]));
        assert_eq!(
            from_name.field_values("dns.rr.udp_payload_size"),
            [&Value::Uint16(512), &Value::Uint16(1400)]
        );

        let mut from_definition = tree();
        from_definition.prune(&FieldSelection::new(&[&DNS_RR_UDP_PAYLOAD_SIZE]));
        assert_eq!(
            from_definition.field_values("dns.rr.udp_payload_size"),
            [&Value::Uint16(512), &Value::Uint16(1400)]
        );
    }

    #[test]
    fn only_tcp_segments_is_at_packet_scope() {
        let node = node(|node| {
            node.add_container(&CONTAINER, Range::new(0, 0), None);
            node.add_container(&SEGMENTS, Range::new(0, 0), None);
        });
        assert_eq!(node.fields.len(), 2);
        let (Some(analysis), Some(segments)) = (node.fields.first(), node.fields.get(1)) else {
            return;
        };
        assert!(!analysis.packet_scoped());
        assert!(segments.packet_scoped());
    }

    #[test]
    fn unnamed_groups_have_no_abbreviation_and_prune_with_children() {
        let mut tree = Tree::new(node(|node| {
            let group = node.add_unnamed(Range::new(4, 0), "Unnamed label".to_string());
            group.add_field(&CHILD_ONE, Range::new(4, 0), Value::Uint32(1));
            group.add_field(&CHILD_TWO, Range::new(8, 4), Value::Uint32(2));
            node.add_field(&FLAT_TWO, Range::new(12, 4), Value::Uint32(3));
        }));
        let fields: Vec<&str> = tree.fields().map(|field| field.def.abbrev).collect();
        assert_eq!(
            fields,
            ["", "tcp.analysis.acks_frame", "tcp.analysis.rto", "tcp.ack"]
        );
        let Some(group) = tree.fields().next() else {
            return;
        };
        assert_eq!(group.def.abbrev, "");
        assert_eq!(group.showname.as_deref(), Some("Unnamed label"));
        assert!(group.is_container());

        tree.prune(&FieldSelection::new(&[&CHILD_TWO]));
        let fields: Vec<&str> = tree.fields().map(|field| field.def.abbrev).collect();
        assert_eq!(fields, ["", "tcp.analysis.rto"]);

        tree.prune(&FieldSelection::default());
        assert!(tree.fields().next().is_none());
    }

    #[test]
    fn hidden_occurrences_remain_selected_and_survive_pruning() {
        let mut tree = Tree::new(node(|node| {
            node.add_field(&FLAT_ONE, Range::new(0, 4), Value::Uint32(1))
                .hide();
        }));
        let Some(field) = tree.fields().next() else {
            return;
        };
        assert!(field.hidden);
        tree.prune(&FieldSelection::new(&[&FLAT_ONE]));
        let field = tree.fields().next().cloned();
        assert!(field.is_some_and(|field| field.hidden));
    }

    #[test]
    fn deep_and_empty_unnamed_groups_survive_selected_descendants() {
        let tree = Tree::new(node(|node| {
            let outer = node.add_unnamed(Range::new(0, 0), "outer".to_string());
            let inner = outer.add_unnamed(Range::new(0, 0), "inner".to_string());
            inner.add_field(&CHILD_ONE, Range::new(0, 0), Value::Uint32(1));
            node.add_unnamed(Range::new(4, 0), "empty".to_string());
        }));
        let names: Vec<&str> = tree
            .fields()
            .map(|field| field.showname.as_deref().unwrap_or(field.def.abbrev))
            .collect();
        assert_eq!(
            names,
            ["outer", "inner", "tcp.analysis.acks_frame", "empty"]
        );
    }

    #[test]
    fn has_expert_walks_field_and_container_experts() {
        let tree = Tree::new(node(|node| {
            let container = node.add_container(&CONTAINER, Range::new(0, 0), None);
            container
                .add_field(&CHILD_ONE, Range::new(0, 0), Value::Uint32(1))
                .add_expert(ExpertInfo {
                    severity: Severity::Note,
                    group: Group::Sequence,
                    message: "field expert".to_string(),
                });
        }));
        assert!(tree.has_expert(Group::Sequence));
        assert!(!tree.has_expert(Group::Malformed));

        let tree = Tree::new(node(|node| {
            node.add_field(&FLAT_ONE, Range::new(0, 0), Value::Uint32(1))
                .add_expert(ExpertInfo {
                    severity: Severity::Warning,
                    group: Group::Protocol,
                    message: "leaf expert".to_string(),
                });
        }));
        assert!(tree.has_expert(Group::Protocol));
    }
}
