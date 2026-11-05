//! ISO 8601 rendering for displayed timestamps.
//!
//! The Gregorian conversion itself lives in [`crate::capture`], which also
//! owns the date arithmetic used by capture readers and display filters.

pub use crate::capture::civil_time;

/// Render a timestamp as ISO 8601 with the given zone suffix.
pub fn iso_time(seconds: i64, nanos: u32, suffix: &str) -> String {
    let (year, month, day, hour, minute, second) = civil_time(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}{suffix}")
}

/// Render a signed nanosecond interval with detail-view units.
///
/// Whole days, hours and minutes are named; the remainder uses seconds,
/// milliseconds, microseconds or nanoseconds, whichever reads exactly. A
/// zero interval is `0.000000000 seconds`.
pub fn delta_text(nanos: i128) -> String {
    let mut total = nanos;
    let mut text = String::new();
    if total < 0 {
        text.push('-');
        total = -total;
    }
    let total = u128::try_from(total).unwrap_or(0);
    if total == 0 {
        return "0.000000000 seconds".to_string();
    }
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    const NANOS_PER_MINUTE: u128 = 60 * NANOS_PER_SECOND;
    const NANOS_PER_HOUR: u128 = 60 * NANOS_PER_MINUTE;
    const NANOS_PER_DAY: u128 = 24 * NANOS_PER_HOUR;
    let days = total / NANOS_PER_DAY;
    let hours = (total % NANOS_PER_DAY) / NANOS_PER_HOUR;
    let minutes = (total % NANOS_PER_HOUR) / NANOS_PER_MINUTE;
    let remainder = total % NANOS_PER_MINUTE;
    let mut parts: Vec<String> = Vec::with_capacity(4);
    if days > 0 {
        parts.push(format!("{days} day{}", plural(days)));
    }
    if hours > 0 {
        parts.push(format!("{hours} hour{}", plural(hours)));
    }
    if minutes > 0 {
        parts.push(format!("{minutes} minute{}", plural(minutes)));
    }
    if remainder > 0 {
        parts.push(delta_remainder(remainder));
    }
    text.push_str(&parts.join(", "));
    text
}

fn plural(value: u128) -> &'static str {
    if value == 1 { "" } else { "s" }
}

fn delta_remainder(nanos: u128) -> String {
    if nanos >= 1_000_000_000 {
        let seconds = nanos / 1_000_000_000;
        if nanos.is_multiple_of(1_000_000_000) {
            format!("{seconds} second{}", plural(seconds))
        } else {
            format!("{}.{:09} seconds", seconds, nanos % 1_000_000_000)
        }
    } else if nanos >= 1_000_000 {
        format!(
            "{}.{:06} milliseconds",
            nanos / 1_000_000,
            nanos % 1_000_000
        )
    } else if nanos >= 1_000 {
        format!("{}.{:03} microseconds", nanos / 1_000, nanos % 1_000)
    } else {
        format!("{nanos} nanosecond{}", plural(nanos))
    }
}
