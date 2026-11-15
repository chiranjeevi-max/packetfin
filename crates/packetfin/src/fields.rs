//! `-T fields` output.
//!
//! The packet tree is pruned to the selected fields, then formatted in a
//! single walk. A [`Formatter`] holds the requested columns and their buffers
//! for the whole invocation, so each occurrence is written once instead of
//! scanning every occurrence for every requested field.

use std::collections::HashMap;
use std::io::{self, Write};

use packetfin_core::fields::FieldType;
use packetfin_core::{FieldDef, Tree};

use crate::record_buffer::RecordBuffer;

/// Which occurrences of a repeated field are printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Occurrence {
    /// The first occurrence.
    First,
    /// The last occurrence.
    Last,
    /// Every occurrence, joined by the aggregator.
    All,
}

/// The quote character placed around field values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quote {
    /// No quoting.
    None,
    /// Double quotes, with embedded double quotes duplicated.
    Double,
    /// Single quotes, with embedded single quotes duplicated.
    Single,
}

impl Quote {
    /// The quote byte, or `None` when values are not quoted.
    fn byte(self) -> Option<u8> {
        match self {
            Self::None => None,
            Self::Double => Some(b'"'),
            Self::Single => Some(b'\''),
        }
    }
}

/// Parsed `-E` output options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldOutputOptions {
    /// Print the UTF-8 byte-order mark before any other output.
    pub bom: bool,
    /// Print the field abbreviations as the first line.
    pub header: bool,
    /// Byte written between columns.
    pub separator: u8,
    /// Which occurrences of a repeated field to print.
    pub occurrence: Occurrence,
    /// Byte written between occurrences of one field.
    pub aggregator: u8,
    /// Quoting style for field values.
    pub quote: Quote,
    /// Escape control characters, the backslash and the separator with
    /// C-style backslash sequences.
    pub escape: bool,
}

impl Default for FieldOutputOptions {
    fn default() -> Self {
        Self {
            bom: false,
            header: false,
            separator: b'\t',
            occurrence: Occurrence::All,
            aggregator: b',',
            quote: Quote::None,
            escape: true,
        }
    }
}

/// The formatted occurrences of one selected field.
#[derive(Default)]
struct FieldValues {
    bytes: Vec<u8>,
    /// A byte field's rendering, spilled once it grows past the record bound.
    spill: Option<RecordBuffer>,
    written: bool,
    /// Whether this field's rendering may contain an escapable byte.
    ///
    /// Fixed for the invocation by the field type and `-E` options.
    scan: bool,
}

impl FieldValues {
    fn clear(&mut self) {
        if let Some(spill) = self.spill.as_mut() {
            spill.clear();
        } else {
            self.bytes.clear();
        }
        self.written = false;
    }

    fn push_aggregator(&mut self, byte: u8) {
        if let Some(spill) = self.spill.as_mut() {
            spill.push_byte(byte);
        } else {
            self.bytes.push(byte);
        }
    }

    fn format_occurrence(
        &mut self,
        value: &packetfin_core::tree::Value,
        display: packetfin_core::Display,
    ) -> io::Result<()> {
        if let Some(spill) = self.spill.as_mut() {
            use std::fmt::Write as _;
            write!(spill, "{}", value.formatted(display))
                .map_err(|_| io::Error::other("field value buffer failed"))
        } else {
            write!(&mut self.bytes, "{}", value.formatted(display))
        }
    }
}

/// Prepared `-T fields` formatting for one invocation.
pub struct Formatter {
    /// Requested columns as indexes into `values`, in command-line order.
    ///
    /// A duplicate `-e` request keeps its own header column but prints no
    /// value: only the last column that requests a field is filled.
    columns: Vec<Option<usize>>,
    /// One rendered buffer per unique selected definition.
    values: Vec<FieldValues>,
    /// Definition identity to its index in `values`.
    positions: HashMap<usize, usize>,
    /// Field abbreviation to its index in `values`, so definitions that share
    /// an abbreviation report one column.
    by_abbrev: HashMap<&'static str, usize>,
    /// Field abbreviations in command-line order, for the header line.
    headers: Vec<&'static str>,
    /// `-E` output options.
    options: FieldOutputOptions,
    /// Holds an escaped value while the occurrence buffer is swapped out.
    scratch: Vec<u8>,
}

impl Formatter {
    /// Prepare one rendered buffer per unique selected field. Duplicate `-e`
    /// requests share it and keep their header columns, but only the last
    /// request prints the value.
    pub fn new(fields: &[&'static FieldDef], options: FieldOutputOptions) -> Self {
        let mut columns = Vec::with_capacity(fields.len());
        let mut values = Vec::new();
        let mut positions = HashMap::with_capacity(fields.len());
        let mut by_abbrev = HashMap::with_capacity(fields.len());
        let mut headers = Vec::with_capacity(fields.len());
        let scan_fixed_values =
            fixed_values_may_contain(options.separator) || escapes(options.aggregator, &options);
        for field in fields {
            let next = values.len();
            let index = *by_abbrev.entry(field.abbrev).or_insert_with(|| {
                let scan = scan_fixed_values
                    || matches!(field.field_type, FieldType::String | FieldType::StringZ);
                let spill = (field.field_type == FieldType::Bytes
                    && !scan
                    && options.aggregator.is_ascii())
                .then(RecordBuffer::new);
                values.push(FieldValues {
                    scan,
                    spill,
                    ..FieldValues::default()
                });
                next
            });
            positions.entry(field.identity()).or_insert(index);
            columns.push(Some(index));
            headers.push(field.abbrev);
        }
        let mut last_column = vec![0_usize; values.len()];
        for (position, column) in columns.iter().enumerate() {
            if let Some(index) = column
                && let Some(slot) = last_column.get_mut(*index)
            {
                *slot = position;
            }
        }
        for (position, column) in columns.iter_mut().enumerate() {
            if let Some(index) = *column
                && last_column.get(index).copied() != Some(position)
            {
                *column = None;
            }
        }
        Self {
            columns,
            values,
            positions,
            by_abbrev,
            headers,
            options,
            scratch: Vec::new(),
        }
    }

    /// Write the optional byte-order mark and header line.
    ///
    /// The header is printed even when the capture holds no packets. It uses
    /// the same separator as the field values and is never quoted or escaped.
    pub fn write_prefix(&self, writer: &mut impl Write) -> io::Result<()> {
        if self.options.bom {
            writer.write_all(&[0xef, 0xbb, 0xbf])?;
        }
        if self.options.header {
            for (position, header) in self.headers.iter().enumerate() {
                if position > 0 {
                    writer.write_all(&[self.options.separator])?;
                }
                writer.write_all(header.as_bytes())?;
            }
            writer.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Write one packet as fields followed by a newline.
    ///
    /// A field with no value prints as an empty column. Two adjacent empty
    /// fields therefore leave two adjacent separators; a trailing empty field
    /// leaves a separator at the end of the line. Occurrences are selected by
    /// `-E occurrence`, joined with `-E aggregator`, escaped, and quoted as
    /// `-E quote` requests.
    pub fn write_packet(&mut self, writer: &mut impl Write, tree: &Tree) -> io::Result<()> {
        let Self {
            columns,
            values,
            positions,
            by_abbrev,
            options,
            scratch,
            ..
        } = self;
        let options = *options;
        for values in values.iter_mut() {
            values.clear();
        }
        tree.try_for_each_field(&mut |field| -> io::Result<()> {
            let Some(&index) = by_abbrev
                .get(field.def.abbrev)
                .or_else(|| positions.get(&field.def.identity()))
            else {
                return Ok(());
            };
            let Some(values) = values.get_mut(index) else {
                return Ok(());
            };
            match options.occurrence {
                Occurrence::First if values.written => return Ok(()),
                Occurrence::First => values.written = true,
                Occurrence::Last => {
                    values.clear();
                    values.written = true;
                }
                Occurrence::All => {
                    if values.written {
                        values.push_aggregator(options.aggregator);
                    }
                    values.written = true;
                }
            }
            values.format_occurrence(&field.value, field.def.display)?;
            Ok(())
        })?;
        for values in values.iter_mut() {
            if values.written && values.scan && values.spill.is_none() {
                escape_value(values, scratch, &options);
            }
        }

        for (position, column) in columns.iter().enumerate() {
            if position > 0 {
                writer.write_all(&[options.separator])?;
            }
            if let Some(index) = *column
                && let Some(values) = values.get_mut(index)
                && values.written
            {
                if let Some(spill) = values.spill.as_mut() {
                    if let Some(quote) = options.quote.byte() {
                        writer.write_all(&[quote])?;
                    }
                    spill.emit(writer)?;
                    if let Some(quote) = options.quote.byte() {
                        writer.write_all(&[quote])?;
                    }
                } else {
                    write_value(writer, &values.bytes, options.quote)?;
                }
            }
        }
        writer.write_all(b"\n")
    }
}

/// Escape a joined field value if it contains an escapable byte.
///
/// Values are formatted straight into their occurrence buffer, as before the
/// `-E` work. Only a value that actually contains a byte needing an escape is
/// copied through `scratch`, so the common numeric and address values pay one
/// scan and no copy.
fn escape_value(values: &mut FieldValues, scratch: &mut Vec<u8>, options: &FieldOutputOptions) {
    if !values.bytes.iter().any(|&byte| escapes(byte, options)) {
        return;
    }
    scratch.clear();
    scratch.reserve(values.bytes.len());
    for &byte in &values.bytes {
        push_escaped_byte(scratch, byte, options);
    }
    std::mem::swap(&mut values.bytes, scratch);
}

/// Whether a non-string value's rendered bytes can contain `separator`.
///
/// The fixed renderings use only decimal and lowercase hexadecimal digits,
/// `0x`, address and timestamp punctuation, and the words `True`, `False`,
/// `<MISSING>` and `<none>`. The ISO time renderings add the `+` offset
/// sign and the `Z` zone suffix (`IsoTime` and `IsoTimeZ`). String values
/// are always scanned for escapes, and a separator outside this set cannot
/// occur in any other rendering, so those values skip the scan entirely.
fn fixed_values_may_contain(separator: u8) -> bool {
    matches!(
        separator,
        b'0'..=b'9'
            | b'a'..=b'f'
            | b'x'
            | b':'
            | b'.'
            | b'-'
            | b'+'
            | b'Z'
            | b'<'
            | b'>'
            | b'M'
            | b'I'
            | b'S'
            | b'N'
            | b'G'
            | b'T'
            | b'F'
            | b'r'
            | b'u'
            | b'l'
            | b's'
            | b'o'
            | b'n'
    )
}

/// Whether a rendered byte needs a backslash escape.
///
/// `-E escape=y` escapes the C control characters. A backslash is doubled
/// whenever escaping is on or values are unquoted; with `-E escape=n` and a
/// quote character it stays literal. The separator is escaped whenever
/// values are unquoted.
fn escapes(byte: u8, options: &FieldOutputOptions) -> bool {
    (options.escape
        && matches!(
            byte,
            b'\x07' | b'\x08' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'
        ))
        || (byte == b'\\' && (options.escape || options.quote == Quote::None))
        || (byte == options.separator && options.quote == Quote::None)
}

/// Append one byte to `out`, applying the field-output escaping rules.
fn push_escaped_byte(out: &mut Vec<u8>, byte: u8, options: &FieldOutputOptions) {
    if options.escape {
        let code = match byte {
            b'\x07' => Some(b'a'),
            b'\x08' => Some(b'b'),
            b'\t' => Some(b't'),
            b'\n' => Some(b'n'),
            b'\x0b' => Some(b'v'),
            b'\x0c' => Some(b'f'),
            b'\r' => Some(b'r'),
            _ => None,
        };
        if let Some(code) = code {
            out.push(b'\\');
            out.push(code);
            return;
        }
    }
    if byte == b'\\' && (options.escape || options.quote == Quote::None) {
        out.push(b'\\');
        out.push(byte);
        return;
    }
    if byte == options.separator && options.quote == Quote::None {
        out.push(b'\\');
        out.push(byte);
        return;
    }
    out.push(byte);
}

/// Write one field value, duplicating any quote byte it contains.
fn write_value(writer: &mut impl Write, bytes: &[u8], quote: Quote) -> io::Result<()> {
    let Some(quote) = quote.byte() else {
        return writer.write_all(bytes);
    };
    writer.write_all(&[quote])?;
    let mut parts = bytes.split(|&byte| byte == quote);
    if let Some(first) = parts.next() {
        writer.write_all(first)?;
    }
    for part in parts {
        writer.write_all(&[quote, quote])?;
        writer.write_all(part)?;
    }
    writer.write_all(&[quote])
}

#[cfg(test)]
mod tests {
    use super::{
        FieldOutputOptions, Formatter, Occurrence, Quote, escapes, fixed_values_may_contain,
    };
    use packetfin_core::fields::{
        Display, ETH_ADDR, ETH_PROTOCOL, FRAME_INTERFACE_NAME, FRAME_LEN, FRAME_NUMBER,
        FRAME_PROTOCOL, FieldDef, FieldType,
    };
    use packetfin_core::{Node, Range, Tree, Value};

    fn tree_with_name(number: u64, name: &str, with_ethernet: bool) -> Tree {
        let mut frame = Node::new(&FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(&FRAME_NUMBER, Range::new(0, 8), Value::Uint64(number));
        frame.add_field(
            &FRAME_INTERFACE_NAME,
            Range::new(0, 0),
            Value::String(name.to_string()),
        );
        if with_ethernet {
            let mut ethernet = Node::new(&ETH_PROTOCOL, Range::new(0, 14));
            ethernet.add_field(
                &ETH_ADDR,
                Range::new(0, 6),
                Value::Ethernet([0x02, 0, 0, 0, 0, 2]),
            );
            ethernet.add_field(
                &ETH_ADDR,
                Range::new(6, 6),
                Value::Ethernet([0x02, 0, 0, 0, 0, 1]),
            );
            frame.add_child(ethernet);
        }
        Tree::new(frame)
    }

    fn tree(number: u64, with_ethernet: bool) -> Tree {
        tree_with_name(number, "", with_ethernet)
    }

    fn requested() -> [&'static packetfin_core::FieldDef; 6] {
        [
            &FRAME_NUMBER,
            &FRAME_LEN,
            &FRAME_INTERFACE_NAME,
            &ETH_ADDR,
            &ETH_ADDR,
            &FRAME_NUMBER,
        ]
    }

    fn format(
        fields: &[&'static packetfin_core::FieldDef],
        options: FieldOutputOptions,
        tree: &Tree,
    ) -> Vec<u8> {
        let mut formatter = Formatter::new(fields, options);
        let mut output = Vec::new();
        assert!(formatter.write_packet(&mut output, tree).is_ok());
        output
    }

    #[test]
    fn duplicates_missing_fields_and_occurrences_keep_command_order() {
        let output = format(&requested(), FieldOutputOptions::default(), &tree(7, true));
        assert_eq!(
            output,
            b"\t\t\t\t02:00:00:00:00:02,02:00:00:00:00:01\t7\n".to_vec()
        );
    }

    #[test]
    fn duplicate_columns_keep_their_position_but_print_nothing() {
        let formatter = Formatter::new(&requested(), FieldOutputOptions::default());
        assert_eq!(formatter.values.len(), 4);
        assert_eq!(formatter.positions.len(), 4);
        assert_eq!(
            formatter.columns,
            vec![None, Some(1), Some(2), None, Some(3), Some(0)]
        );
        assert_eq!(
            formatter.headers,
            vec![
                "frame.number",
                "frame.len",
                "frame.interface_name",
                "eth.addr",
                "eth.addr",
                "frame.number",
            ]
        );
    }

    #[test]
    fn reused_formatter_clears_values_between_packets() {
        let mut formatter = Formatter::new(&requested(), FieldOutputOptions::default());
        let mut output = Vec::new();
        assert!(formatter.write_packet(&mut output, &tree(7, true)).is_ok());
        output.clear();
        assert!(formatter.write_packet(&mut output, &tree(8, false)).is_ok());
        assert_eq!(output, b"\t\t\t\t\t8\n".to_vec());
    }

    #[test]
    fn escapes_controls_backslash_and_separator() {
        let tree = tree_with_name(
            1,
            "tab\tline\ncarriage\rform\x0cvertical\x0bback\x08bel\x07slash\\",
            true,
        );
        let output = format(
            &[&FRAME_NUMBER, &FRAME_INTERFACE_NAME],
            FieldOutputOptions::default(),
            &tree,
        );
        assert_eq!(
            output,
            b"1\ttab\\tline\\ncarriage\\rform\\fvertical\\vback\\bbel\\aslash\\\\\n".to_vec()
        );
    }

    #[test]
    fn separator_is_escaped_only_without_quotes() {
        let tree = tree_with_name(1, "comma,inside", true);
        let fields = [&FRAME_NUMBER, &FRAME_INTERFACE_NAME];
        let mut options = FieldOutputOptions {
            separator: b',',
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(&fields, options, &tree),
            b"1,comma\\,inside\n".to_vec()
        );

        options.quote = Quote::Double;
        assert_eq!(
            format(&fields, options, &tree),
            b"\"1\",\"comma,inside\"\n".to_vec()
        );
    }

    #[test]
    fn quote_doubles_embedded_quotes_and_quotes_empty_values() {
        let fields = [&FRAME_NUMBER, &FRAME_INTERFACE_NAME];
        let options = FieldOutputOptions {
            quote: Quote::Double,
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(&fields, options, &tree_with_name(1, "say \"hi\"", true)),
            b"\"1\"\t\"say \"\"hi\"\"\"\n".to_vec()
        );
        assert_eq!(
            format(&fields, options, &tree_with_name(1, "", true)),
            b"\"1\"\t\"\"\n".to_vec()
        );

        let single = FieldOutputOptions {
            quote: Quote::Single,
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(&fields, single, &tree_with_name(1, "it's", false)),
            b"'1'\t'it''s'\n".to_vec()
        );
    }

    #[test]
    fn missing_fields_stay_empty_when_quoted() {
        let options = FieldOutputOptions {
            quote: Quote::Double,
            ..FieldOutputOptions::default()
        };
        let mut formatter = Formatter::new(&[&FRAME_NUMBER, &ETH_ADDR], options);
        let mut output = Vec::new();
        assert!(
            formatter
                .write_packet(&mut output, &tree_with_name(1, "", false))
                .is_ok()
        );
        assert_eq!(output, b"\"1\"\t\n".to_vec());
    }

    #[test]
    fn occurrence_selects_first_last_or_all() {
        let mut frame = Node::new(&FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(&FRAME_NUMBER, Range::new(0, 8), Value::Uint64(1));
        for octet in [1, 2, 3] {
            frame.add_field(
                &ETH_ADDR,
                Range::new(0, 6),
                Value::Ethernet([0x02, 0, 0, 0, 0, octet]),
            );
        }
        let tree = Tree::new(frame);
        let fields = [&FRAME_NUMBER, &ETH_ADDR];

        for (occurrence, expected) in [
            (Occurrence::First, b"1\t02:00:00:00:00:01\n".to_vec()),
            (Occurrence::Last, b"1\t02:00:00:00:00:03\n".to_vec()),
            (
                Occurrence::All,
                b"1\t02:00:00:00:00:01,02:00:00:00:00:02,02:00:00:00:00:03\n".to_vec(),
            ),
        ] {
            let options = FieldOutputOptions {
                occurrence,
                ..FieldOutputOptions::default()
            };
            let mut formatter = Formatter::new(&fields, options);
            let mut output = Vec::new();
            assert!(formatter.write_packet(&mut output, &tree).is_ok());
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn quoted_values_keep_backslashes_literal_when_escaping_is_off() {
        let options = FieldOutputOptions {
            escape: false,
            quote: Quote::Double,
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(
                &[&FRAME_NUMBER, &FRAME_INTERFACE_NAME],
                options,
                &tree_with_name(1, "back\\slash", true)
            ),
            b"\"1\"\t\"back\\slash\"\n".to_vec()
        );

        let mut formatter = Formatter::new(
            &[&ETH_ADDR],
            FieldOutputOptions {
                escape: false,
                quote: Quote::Double,
                aggregator: b'\\',
                ..FieldOutputOptions::default()
            },
        );
        let mut output = Vec::new();
        assert!(formatter.write_packet(&mut output, &tree(1, true)).is_ok());
        assert_eq!(
            output,
            b"\"02:00:00:00:00:02\\02:00:00:00:00:01\"\n".to_vec()
        );
    }

    #[test]
    fn aggregator_is_escaped_with_the_joined_value() {
        let tree = tree_with_name(1, "unused", true);
        let mut formatter = Formatter::new(
            &[&ETH_ADDR],
            FieldOutputOptions {
                aggregator: b'\t',
                ..FieldOutputOptions::default()
            },
        );
        let mut output = Vec::new();
        assert!(formatter.write_packet(&mut output, &tree).is_ok());
        assert_eq!(output, b"02:00:00:00:00:02\\t02:00:00:00:00:01\n".to_vec());
    }

    #[test]
    fn fixed_values_escape_a_matching_separator() {
        let options = FieldOutputOptions {
            escape: false,
            separator: b':',
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(&[&ETH_ADDR], options, &tree(1, true)),
            b"02\\:00\\:00\\:00\\:00\\:02,02\\:00\\:00\\:00\\:00\\:01\n".to_vec()
        );
    }

    #[test]
    fn absolute_time_separators_are_escaped() {
        let timestamp = packetfin_core::capture::Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_789,
        };
        let mut frame = Node::new(&FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(&FRAME_NUMBER, Range::new(0, 8), Value::Uint64(1));
        frame.add_field(
            &packetfin_core::fields::NTP_XMT,
            Range::new(0, 8),
            Value::AbsoluteTime(timestamp),
        );
        frame.add_field(
            &packetfin_core::fields::DHCPV6_DUIDLLT_TIME,
            Range::new(0, 8),
            Value::AbsoluteTime(timestamp),
        );
        let tree = Tree::new(frame);

        // `IsoTimeZ` ends in `Z`; a `Z` separator must not look like the end
        // of the time value.
        let z = FieldOutputOptions {
            escape: false,
            separator: b'Z',
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(&[&FRAME_NUMBER, &packetfin_core::fields::NTP_XMT], z, &tree),
            b"1Z2023-11-14T22:13:20.123456789\\Z\n".to_vec()
        );

        // `IsoTime` carries a `+0000` offset suffix.
        let plus = FieldOutputOptions {
            escape: false,
            separator: b'+',
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(
                &[&FRAME_NUMBER, &packetfin_core::fields::DHCPV6_DUIDLLT_TIME],
                plus,
                &tree
            ),
            b"1+2023-11-14T22:13:20.123456789\\+0000\n".to_vec()
        );
    }

    #[test]
    fn fixed_value_renderings_only_need_scans_for_listed_separators() {
        use packetfin_core::Timestamp;
        use packetfin_core::fields::Display;

        let values = [
            Value::Uint8(0xab),
            Value::Uint16(0),
            Value::Uint24(0xabc),
            Value::Uint32(u32::MAX),
            Value::Uint64(u64::MAX),
            Value::Int8(-1),
            Value::Int16(i16::MIN),
            Value::Int32(-123),
            Value::Int64(i64::MIN),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::None,
            Value::Missing,
            Value::Ethernet([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Value::Eui64([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 1]),
            Value::Ipv4([1, 2, 3, 4]),
            Value::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Value::Ipv6([0xff; 16]),
            Value::bytes(vec![]),
            Value::bytes(vec![0xab, 0xcd]),
            Value::AbsoluteTime(Timestamp {
                seconds: -1,
                nanos: 999_999_999,
            }),
        ];
        let displays = [
            Display::Decimal,
            Display::DecHex,
            Display::Hex,
            Display::HexDec,
            Display::Oui,
            Display::PortTcp,
            Display::PortUdp,
            Display::Boolean8,
            Display::Boolean12,
            Display::Boolean16,
            Display::Boolean32,
            Display::None,
            Display::BaseNone,
            Display::IsoTime,
            Display::IsoTimeZ,
        ];
        for value in &values {
            for display in displays {
                let rendered = value.formatted(display).to_string();
                for separator in 0..=u8::MAX {
                    if fixed_values_may_contain(separator) {
                        continue;
                    }
                    let options = FieldOutputOptions {
                        separator,
                        ..FieldOutputOptions::default()
                    };
                    assert!(
                        !rendered.bytes().any(|byte| escapes(byte, &options)),
                        "{value:?} as {display:?} contains an unlisted separator {separator}"
                    );
                }
            }
        }
    }

    #[test]
    fn escape_disabled_only_keeps_separator_and_backslash_escapes() {
        let options = FieldOutputOptions {
            escape: false,
            ..FieldOutputOptions::default()
        };
        assert_eq!(
            format(
                &[&FRAME_NUMBER, &FRAME_INTERFACE_NAME],
                options,
                &tree_with_name(1, "a\tb\\c,d", true)
            ),
            b"1\ta\\\tb\\\\c,d\n".to_vec()
        );
    }

    #[test]
    fn header_and_bom_prefix_keep_command_order() {
        let fields = [&FRAME_NUMBER, &ETH_ADDR, &FRAME_NUMBER];
        let options = FieldOutputOptions {
            bom: true,
            header: true,
            ..FieldOutputOptions::default()
        };
        let formatter = Formatter::new(&fields, options);
        let mut output = Vec::new();
        assert!(formatter.write_prefix(&mut output).is_ok());
        assert_eq!(
            output,
            b"\xef\xbb\xbfframe.number\teth.addr\tframe.number\n".to_vec()
        );
    }

    #[test]
    fn flat_fields_keep_their_output_when_a_container_is_present() {
        use packetfin_core::FieldSelection;
        use packetfin_core::fields::TCP_SEQ;

        let mut tree = crate::test_support::tcp_tree(|tcp| {
            let container = tcp.add_container(
                &crate::test_support::ANALYSIS,
                Range::new(34, 0),
                Some("SEQ/ACK analysis".to_string()),
            );
            container.add_field(
                &crate::test_support::ANALYSIS_ACKS_FRAME,
                Range::new(34, 0),
                Value::Uint32(1),
            );
        });

        let flat_selection = FieldSelection::new(&[&FRAME_NUMBER, &TCP_SEQ]);
        tree.prune(&flat_selection);
        assert_eq!(
            format(
                &[&FRAME_NUMBER, &TCP_SEQ],
                FieldOutputOptions::default(),
                &tree
            ),
            b"5\t1\n".to_vec()
        );

        let mut tree = crate::test_support::tcp_tree(|tcp| {
            let container = tcp.add_container(
                &crate::test_support::ANALYSIS,
                Range::new(34, 0),
                Some("SEQ/ACK analysis".to_string()),
            );
            container.add_field(
                &crate::test_support::ANALYSIS_ACKS_FRAME,
                Range::new(34, 0),
                Value::Uint32(1),
            );
        });
        let child_selection = FieldSelection::new(&[
            &FRAME_NUMBER,
            &TCP_SEQ,
            &crate::test_support::ANALYSIS_ACKS_FRAME,
        ]);
        tree.prune(&child_selection);
        assert_eq!(
            format(
                &[
                    &FRAME_NUMBER,
                    &TCP_SEQ,
                    &crate::test_support::ANALYSIS_ACKS_FRAME
                ],
                FieldOutputOptions::default(),
                &tree
            ),
            b"5\t1\t1\n".to_vec()
        );
        let mut tree = crate::test_support::tcp_tree(|tcp| {
            let container = tcp.add_container(
                &crate::test_support::ANALYSIS,
                Range::new(34, 0),
                Some("SEQ/ACK analysis".to_string()),
            );
            container.add_field(
                &crate::test_support::ANALYSIS_ACKS_FRAME,
                Range::new(34, 0),
                Value::Uint32(1),
            );
        });
        let container_selection = FieldSelection::new(&[&crate::test_support::ANALYSIS]);
        tree.prune(&container_selection);
        assert_eq!(
            format(
                &[&crate::test_support::ANALYSIS],
                FieldOutputOptions::default(),
                &tree
            ),
            b"1\n".to_vec()
        );
    }

    #[test]
    fn z_strings_escape_like_plain_strings() {
        static STRINGZ: FieldDef = FieldDef {
            abbrev: "test.stringz",
            name: "Z String",
            field_type: FieldType::StringZ,
            parent: "test",
            display: Display::None,
            bitmask: None,
            blurb: "",
            generated: false,
        };
        let mut frame = Node::new(&FRAME_PROTOCOL, Range::new(0, 0));
        frame.add_field(
            &STRINGZ,
            Range::new(0, 0),
            Value::String("a\\b\tc\nd,e".to_string()),
        );
        let output = format(
            &[&STRINGZ],
            FieldOutputOptions::default(),
            &Tree::new(frame),
        );
        assert_eq!(output, b"a\\\\b\\tc\\nd,e\n".to_vec());
    }
}
