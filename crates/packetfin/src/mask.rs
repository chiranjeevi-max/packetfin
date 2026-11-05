//! Bit-field display metadata shared by PDML and EK.
//!
//! A masked field prints with a bit pattern, the masked value, the
//! parent byte window it came from, and sometimes an `unmaskedvalue`. The
//! window is derived from the mask, not from Packetfin's field range: some
//! decoders store a 16-bit flags word for an 8-bit mask, and IPv6 traffic
//! class masks span four bytes while the tree range covers two.

use packetfin_core::tree::Field;
use packetfin_core::{Display, FieldType, Frame, Value};

/// The display attributes of one masked field occurrence.
pub struct MaskedField {
    /// The bit pattern with `.` for bits outside the mask.
    pub pattern: String,
    /// The parent byte window size.
    pub size: usize,
    /// The frame offset of that window.
    pub pos: usize,
    /// The raw window bytes as lowercase hex.
    pub unmasked: String,
    /// The masked value as uppercase hex without a prefix.
    pub value: String,
}

/// Whether a field gets a bit-pattern prefix but no masked value attributes.
///
/// These fields print as bit fields while their `value` stays the raw
/// byte, matching their maskless `-G fields` entry.
pub fn pattern_only(abbrev: &str) -> bool {
    matches!(abbrev, "ip.version" | "ip.hdr_len" | "ipv6.version")
}

/// Compute a masked field's display attributes, or `None` when the field has
/// no mask (or is one of the groups printed without a bit pattern).
pub fn masked_field(field: &Field, frame: &Frame, source: Option<&[u8]>) -> Option<MaskedField> {
    let (width, mask) = match field.def.abbrev {
        "ip.version" | "ipv6.version" => (8, 0xf0_u64),
        "ip.hdr_len" => (8, 0x0f_u64),
        // BFD version 1 puts the Demand bit at 0x02; the version-0 layout
        // moves it to 0x40, while the registry keeps the 0x40 -G mask for
        // both.
        "bfd.flags.d" => {
            let version = field
                .range
                .offset
                .checked_sub(1)
                .and_then(|offset| source_byte(field, source, frame, offset))
                .map_or(1, |byte| byte >> 5);
            (8, if version == 0 { 0x40 } else { 0x02 })
        }
        _ => {
            let mask = field.mask_override.or(field.def.bitmask)?;
            let width = display_width(field.def.display)
                .unwrap_or_else(|| type_width(field.def.field_type));
            (width, mask)
        }
    };
    if width == 0 || mask == 0 {
        return None;
    }
    let value = integer_value(&field.value)?;
    let (window, size, pos, pattern_raw) =
        if matches!(field.def.abbrev, "syslog.facility" | "syslog.level") {
            // The window spans the whole decimal `<PRI>` token and the bit
            // pattern comes from the parsed value shifted into the mask.
            let window = read_window(source, frame, field.range.offset, field.range.length);
            let pattern_raw = value.checked_shl(mask.trailing_zeros()).unwrap_or(0);
            (window, field.range.length, field.range.offset, pattern_raw)
        } else if field.def.display == Display::Boolean12 {
            let raw = read_window(source, frame, field.range.offset, 2);
            let byte_index = if mask.trailing_zeros() >= 8 { 0 } else { 1 };
            let byte = raw.get(byte_index).copied().unwrap_or(0);
            let pattern_raw = raw
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
                & 0xfff;
            (
                vec![byte],
                1,
                field.range.offset.saturating_add(byte_index),
                pattern_raw,
            )
        } else {
            let bytes = storage_size(field.def.display, field.def.field_type);
            let offset = field
                .range
                .offset
                .saturating_add(window_offset(field.def.abbrev));
            let raw = read_window(source, frame, offset, bytes);
            let pattern_raw = raw
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
            (raw, bytes, offset, pattern_raw)
        };
    let mut pattern = String::with_capacity(width + width / 4 + 3);
    for bit in (0..width).rev() {
        let bit_mask = 1_u64 << bit;
        if mask & bit_mask == 0 {
            pattern.push('.');
        } else {
            pattern.push(if pattern_raw & bit_mask != 0 {
                '1'
            } else {
                '0'
            });
        }
        if bit % 4 == 0 && bit != 0 {
            pattern.push(' ');
        }
    }
    Some(MaskedField {
        pattern,
        size,
        pos,
        unmasked: hex_lower(&window),
        value: format!("{value:X}"),
    })
}

/// The byte window for a masked field: the parent display or storage
/// width, not the mask's highest bit. DNS flag subfields are 16-bit booleans,
/// and the IPv6 traffic-class family is a 32-bit word.
fn storage_size(display: Display, field_type: FieldType) -> usize {
    let bits = display_width(display).unwrap_or_else(|| type_width(field_type));
    bits.div_ceil(8).max(1)
}

fn window_offset(abbrev: &str) -> usize {
    if abbrev == "ipv6.flow" { 1 } else { 0 }
}

fn source_byte(field: &Field, source: Option<&[u8]>, frame: &Frame, offset: usize) -> Option<u8> {
    source
        .and_then(|bytes| bytes.get(offset).copied())
        .or_else(|| {
            let raw = field.raw.as_ref()?;
            raw.bytes.get(offset.checked_sub(raw.start)?).copied()
        })
        .or_else(|| frame.captured.get(offset).copied())
}

fn read_window(source: Option<&[u8]>, frame: &Frame, offset: usize, length: usize) -> Vec<u8> {
    let bytes = source.unwrap_or(&frame.captured);
    let end = offset.saturating_add(length).min(bytes.len());
    if let Some(bytes) = bytes.get(offset..end) {
        return bytes.to_vec();
    }
    let end = offset.saturating_add(length).min(frame.captured.len());
    frame
        .captured
        .get(offset..end)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn integer_value(value: &Value) -> Option<u64> {
    Some(match value {
        Value::Uint8(value) => u64::from(*value),
        Value::Uint16(value) => u64::from(*value),
        Value::Uint24(value) => u64::from(*value),
        Value::Uint32(value) => u64::from(*value),
        Value::Uint64(value) => *value,
        Value::Int8(value) => u64::try_from(*value).ok()?,
        Value::Int16(value) => u64::try_from(*value).ok()?,
        Value::Int32(value) => u64::try_from(*value).ok()?,
        Value::Int64(value) => u64::try_from(*value).ok()?,
        Value::Boolean(value) => u64::from(*value),
        _ => return None,
    })
}

fn display_width(display: Display) -> Option<usize> {
    match display {
        Display::Boolean0 => Some(0),
        Display::Boolean6 => Some(6),
        Display::Boolean8 => Some(8),
        Display::Boolean12 => Some(12),
        Display::Boolean16 => Some(16),
        Display::Boolean24 => Some(24),
        Display::Boolean32 => Some(32),
        _ => None,
    }
}

fn type_width(field_type: FieldType) -> usize {
    match field_type {
        FieldType::Uint8 | FieldType::Int8 | FieldType::Boolean => 8,
        FieldType::Uint16 | FieldType::Int16 => 16,
        FieldType::Uint24 => 24,
        FieldType::Uint32 | FieldType::FrameNumber | FieldType::Int32 => 32,
        FieldType::Uint64 | FieldType::Int64 => 64,
        _ => 8,
    }
}
