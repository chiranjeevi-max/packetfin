//! Formatting helpers shared by the statistics tables.

/// Format a byte count with SI size units.
///
/// Values below ten kilobytes print as plain bytes; larger values use the
/// first metric prefix whose scaled value is at least ten, so 1,484 prints
/// `1484 bytes` and 3,200,000 prints `3200 kB`.
pub(crate) fn format_size(bytes: u64) -> String {
    const PREFIXES: [(&str, u64); 4] = [
        (" T", 1_000_000_000_000),
        (" G", 1_000_000_000),
        (" M", 1_000_000),
        (" k", 1_000),
    ];
    for (prefix, power) in PREFIXES {
        if bytes / power >= 10 {
            return format!("{}{prefix}B", bytes / power);
        }
    }
    format!("{bytes} bytes")
}

/// Decimal digit count of a value, capped at fifteen digits.
pub(crate) fn magnitude(mut value: u64) -> u32 {
    let mut digits = 0;
    for _ in 0..15 {
        digits += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    digits
}

/// Centre a column label over a value column.
///
/// The result includes the label's trailing column separator. `width` is the
/// value width without the surrounding spaces; each side of the label gets
/// half the spare width plus one space.
pub(crate) fn print_center(label: &str, width: usize) -> String {
    let label_len = label.len() as i64;
    let width = width as i64;
    let len = 6 - ((width - label_len) / 2 + 1);
    if len > 0 && len < 6 {
        let spaces = "      ";
        let suffix = spaces.get(len as usize..).unwrap_or("");
        if (width - label_len) % 2 == 0 {
            format!("{suffix}{label}{suffix}|")
        } else {
            // An odd spare width puts the extra space before the label.
            format!(" {suffix}{label}{suffix}|")
        }
    } else if len > 0 && len <= 15 {
        format!("{label}|")
    } else {
        String::new()
    }
}
