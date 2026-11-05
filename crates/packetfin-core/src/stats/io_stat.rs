//! `io,stat`: interval buckets with computed columns.
//!
//! The table layout is driven by the values that were actually seen, so its
//! width changes with the capture. Layout rules:
//! interval 0 and intervals at least as long as the capture collapse to one
//! row whose duration precision follows the duration magnitude; integer
//! intervals print the last row end as `Dur`; fractional intervals keep their
//! own precision; expression columns only see fields the column's display
//! filter references.

use std::fmt;

use crate::fields::{FieldDef, FieldType, ProtocolDef};
use crate::tree::Value;

use super::facts::FrameFacts;
use super::render::{magnitude, print_center};
use super::{Budget, Clock, Notices, StatsFilter};

/// The statistic one `io,stat` column computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCalc {
    /// Count frames and their bytes (a plain filter column).
    FramesAndBytes,
    /// Count occurrences of a field or protocol.
    Count,
    /// Sum a numeric field.
    Sum,
    /// Smallest numeric value.
    Min,
    /// Largest numeric value.
    Max,
    /// Arithmetic mean of a numeric field.
    Avg,
    /// Queue depth of a relative-time field.
    Load,
}

impl IoCalc {
    /// The printed column heading.
    fn name(self) -> &'static str {
        match self {
            Self::FramesAndBytes => "Frames and bytes",
            Self::Count => "COUNT",
            Self::Sum => "SUM",
            Self::Min => "MIN",
            Self::Max => "MAX",
            Self::Avg => "AVG",
            Self::Load => "LOAD",
        }
    }
}

/// The field or protocol an `io,stat` expression reads.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IoArgument {
    /// A registered field occurrence.
    Field(&'static FieldDef),
    /// A protocol presence occurrence, valid only for `COUNT`.
    Protocol(&'static ProtocolDef),
}

impl IoArgument {
    fn name(self) -> &'static str {
        match self {
            Self::Field(field) => field.abbrev,
            Self::Protocol(protocol) => protocol.filter_name,
        }
    }

    fn field_type(self) -> Option<FieldType> {
        match self {
            Self::Field(field) => Some(field.field_type),
            Self::Protocol(_) => None,
        }
    }
}

/// One `io,stat` column.
#[derive(Clone, Debug, PartialEq)]
pub struct IoColumnSpec {
    /// What the column computes.
    pub kind: IoCalc,
    /// The token as typed, printed after `Col N:`; `None` for the default
    /// frame/byte column.
    pub label: Option<String>,
    /// Field or protocol read by the expression.
    pub argument: Option<IoArgument>,
    /// Display filter that both selects packets and makes the expression's
    /// field visible to the tap.
    pub filter: StatsFilter,
    /// Whether the filter references the expression's field or protocol.
    pub available: bool,
}

/// One `io,stat` specification.
#[derive(Clone, Debug, PartialEq)]
pub struct IoStatSpec {
    /// Interval in microseconds; zero means the whole capture.
    pub interval_micros: u64,
    /// Decimal places the interval argument implies.
    pub precision: u32,
    /// Columns in command-line order.
    pub columns: Vec<IoColumnSpec>,
}

pub(crate) const MAX_BUCKETS: usize = 1_000_000;
/// Vector growth and map bookkeeping the row's own size does not cover.
const ROW_OVERHEAD: usize = std::mem::size_of::<Row>();
const INTERVAL_ERROR: &str =
    "\"-z\" interval must be >=0.000001 seconds or \"0\" for the entire capture duration.";
const ARGUMENT_ERROR: &str = "invalid \"-z io,stat,<interval>[,<filter>][,<filter>]...\" argument";

/// Parse `io,stat,<interval>[,<column>...]`.
pub(crate) fn parse(text: &str) -> Result<IoStatSpec, String> {
    if text.ends_with(',') {
        return Err(ARGUMENT_ERROR.to_string());
    }
    let Some(rest) = text.strip_prefix("io,stat,") else {
        return Err(ARGUMENT_ERROR.to_string());
    };
    let (interval_text, columns_text) = rest
        .split_once(',')
        .map_or((rest, None), |(interval, columns)| {
            (interval, Some(columns))
        });
    let interval_text = interval_text.trim_start();
    if interval_text.is_empty() {
        return Err(ARGUMENT_ERROR.to_string());
    }
    let Some(interval_float) = parse_c_double(interval_text) else {
        return Err(ARGUMENT_ERROR.to_string());
    };
    // `-0` and `-0.0` are zero intervals, exactly as C's comparison sees
    // them; only strictly negative values are rejected.
    if interval_float.is_nan() || interval_float < 0.0 {
        return Err(INTERVAL_ERROR.to_string());
    }
    let mut interval_micros = 0_u64;
    let mut precision = 0_u32;
    if interval_float != 0.0 {
        if interval_float.is_infinite() {
            // An infinite interval exceeds any capture duration; the draw
            // clamps it.
            interval_micros = u64::MAX;
        } else {
            let rounded = interval_float * 1_000_000.0 + 0.5;
            if rounded < 1.0 {
                return Err(INTERVAL_ERROR.to_string());
            }
            interval_micros = if rounded >= u64::MAX as f64 {
                u64::MAX
            } else {
                rounded as u64
            };
        }
        precision = 6;
        for divisor in [10_u64, 100, 1_000, 10_000, 100_000, 1_000_000] {
            if !interval_micros.is_multiple_of(divisor) {
                break;
            }
            precision -= 1;
        }
        if precision == 0
            && let Some(dot) = interval_text.find('.')
        {
            let fraction = interval_text
                .get(dot + 1..)
                .unwrap_or_default()
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .count();
            precision = u32::try_from(fraction.min(6)).unwrap_or(0);
        }
    }

    let mut columns = Vec::new();
    match columns_text {
        None => columns.push(IoColumnSpec {
            kind: IoCalc::FramesAndBytes,
            label: None,
            argument: None,
            filter: StatsFilter::none(),
            available: true,
        }),
        Some("") => columns.push(IoColumnSpec {
            kind: IoCalc::FramesAndBytes,
            label: None,
            argument: None,
            filter: StatsFilter::none(),
            available: true,
        }),
        Some(text) => {
            let tokens: Vec<&str> = text.split(',').collect();
            let mut index = 0;
            while index < tokens.len() {
                let mut candidate = tokens
                    .get(index)
                    .copied()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                loop {
                    match parse_column(&candidate) {
                        Ok(column) => {
                            columns.push(column);
                            index += 1;
                            break;
                        }
                        Err(error) => {
                            let Some(next) = tokens.get(index + 1) else {
                                return Err(error);
                            };
                            candidate.push(',');
                            candidate.push_str(next.trim());
                            index += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(IoStatSpec {
        interval_micros,
        precision,
        columns,
    })
}

/// Parse a C `strtod`-style number for the interval argument.
///
/// Handles decimal and hexadecimal floats plus `inf`/`infinity`/`nan`, with
/// the whole token required to be consumed.
fn parse_c_double(text: &str) -> Option<f64> {
    let (negative, rest) = match text.as_bytes().first() {
        Some(b'-') => (true, text.get(1..)?),
        Some(b'+') => (false, text.get(1..)?),
        _ => (false, text),
    };
    let lower = rest.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" {
        return Some(if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    if lower == "nan" {
        return Some(f64::NAN);
    }
    if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        return parse_hex_float(hex, negative);
    }
    let value = text.parse::<f64>().ok()?;
    Some(value)
}

fn parse_hex_float(text: &str, negative: bool) -> Option<f64> {
    let mut value = 0.0_f64;
    let mut digits = 0_usize;
    let mut index = 0_usize;
    let bytes = text.as_bytes();
    while let Some(digit) = bytes
        .get(index)
        .and_then(|byte| (*byte as char).to_digit(16))
    {
        value = value * 16.0 + f64::from(digit);
        digits += 1;
        index += 1;
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let mut scale = 1.0 / 16.0;
        while let Some(digit) = bytes
            .get(index)
            .and_then(|byte| (*byte as char).to_digit(16))
        {
            value += f64::from(digit) * scale;
            scale /= 16.0;
            digits += 1;
            index += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    let mut exponent = 0_i32;
    if matches!(bytes.get(index), Some(b'p' | b'P')) {
        index += 1;
        let (exp_negative, remaining) = bytes.get(index).map(|byte| match byte {
            b'-' => (true, index + 1),
            b'+' => (false, index + 1),
            _ => (false, index),
        })?;
        let start = remaining;
        let mut end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return None;
        }
        let exponent_text = text.get(start..end)?;
        exponent = exponent_text.parse::<i32>().ok()?;
        if exp_negative {
            exponent = -exponent;
        }
        index = end;
    }
    if index != bytes.len() {
        return None;
    }
    let value = value * 2_f64.powi(exponent);
    Some(if negative { -value } else { value })
}

fn parse_column(candidate: &str) -> Result<IoColumnSpec, String> {
    if candidate.is_empty() {
        return Ok(IoColumnSpec {
            kind: IoCalc::FramesAndBytes,
            label: None,
            argument: None,
            filter: StatsFilter::none(),
            available: true,
        });
    }
    for (name, kind) in [
        ("COUNT", IoCalc::Count),
        ("SUM", IoCalc::Sum),
        ("MIN", IoCalc::Min),
        ("MAX", IoCalc::Max),
        ("AVG", IoCalc::Avg),
        ("LOAD", IoCalc::Load),
    ] {
        let Some(after_name) = candidate.strip_prefix(name) else {
            continue;
        };
        let Some(rest) = after_name.strip_prefix('(') else {
            continue;
        };
        let Some(close) = rest.find(')') else {
            return Err("Closing parenthesis missing from calculated expression.".to_string());
        };
        let argument = rest.get(..close).unwrap_or_default();
        if argument.is_empty() {
            return Err(format!("You didn't specify a field name for {name}(*)."));
        }
        let filter_text = rest.get(close + 1..).unwrap_or_default();
        let Some(argument) = super::field_or_protocol(argument) else {
            return Err(format!("There is no field named '{argument}'."));
        };
        validate_argument(kind, argument)?;
        let filter = compile_io_filter(filter_text)?;
        let available = match argument {
            IoArgument::Field(field) => filter
                .referenced_fields()
                .iter()
                .any(|referenced| referenced.abbrev == field.abbrev),
            IoArgument::Protocol(protocol) => filter
                .referenced_protocols()
                .iter()
                .any(|referenced| referenced.filter_name == protocol.filter_name),
        };
        return Ok(IoColumnSpec {
            kind,
            label: Some(candidate.to_string()),
            argument: Some(argument),
            filter,
            available,
        });
    }
    let filter = compile_io_filter(candidate)?;
    Ok(IoColumnSpec {
        kind: IoCalc::FramesAndBytes,
        label: Some(candidate.to_string()),
        argument: None,
        filter,
        available: true,
    })
}

fn compile_io_filter(text: &str) -> Result<StatsFilter, String> {
    StatsFilter::compile(text, "Couldn't register io,stat tap: ", "")
}

fn validate_argument(kind: IoCalc, argument: IoArgument) -> Result<(), String> {
    if kind == IoCalc::Count {
        return Ok(());
    }
    if kind == IoCalc::Load {
        if matches!(argument, IoArgument::Protocol(_)) {
            return Err(format!(
                "{} doesn't have integral values, so LOAD(*) calculations are not supported on it.",
                argument.name()
            ));
        }
        // A non-relative field is accepted here and reported when a matching
        // packet arrives; the column then stays zero.
        return Ok(());
    }
    let name = argument.name();
    let Some(field_type) = argument.field_type() else {
        return Err(format!(
            "{name} doesn't have integral values, so {}(*) calculations are not supported on it.",
            kind.name()
        ));
    };
    let supported = matches!(
        field_type,
        FieldType::Uint8
            | FieldType::Uint16
            | FieldType::Uint24
            | FieldType::Uint32
            | FieldType::Uint64
            | FieldType::Int8
            | FieldType::Int16
            | FieldType::Int32
            | FieldType::Int64
            | FieldType::Double
            | FieldType::RelativeTime
            | FieldType::FrameNumber
    );
    if supported {
        return Ok(());
    }
    Err(format!(
        "{name} doesn't have integral values, so {}(*) calculations are not supported on it.",
        kind.name()
    ))
}

/// Accumulated values for one bucket of one column.
#[derive(Clone, Default)]
struct Row {
    frames: u64,
    counter: u64,
    double_counter: f64,
    num: u64,
}

struct Column {
    kind: IoCalc,
    label: Option<String>,
    argument: Option<IoArgument>,
    filter: StatsFilter,
    available: bool,
    rows: Vec<Row>,
    max_vals: u64,
    max_frame: u64,
    load_error_reported: bool,
}

/// Aggregation state for one `io,stat` specification.
pub(crate) struct State {
    columns: Vec<Column>,
    last_relative_us: u64,
    capped: bool,
}

impl State {
    pub(crate) fn new(spec: &IoStatSpec) -> Self {
        Self {
            columns: spec
                .columns
                .iter()
                .map(|column| Column {
                    kind: column.kind,
                    label: column.label.clone(),
                    argument: column.argument,
                    filter: column.filter.clone(),
                    available: column.available,
                    rows: Vec::new(),
                    max_vals: 0,
                    max_frame: 0,
                    load_error_reported: false,
                })
                .collect(),
            last_relative_us: 0,
            capped: false,
        }
    }

    pub(crate) fn observe(
        &mut self,
        spec: &IoStatSpec,
        facts: &FrameFacts<'_>,
        clock: &Clock,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        let interval = if spec.interval_micros == 0 {
            u64::MAX
        } else {
            spec.interval_micros
        };
        let relative_us = if clock.relative_ns >= 0 {
            let relative = super::micros_from_nanos(clock.relative_ns);
            self.last_relative_us = relative;
            relative
        } else {
            self.last_relative_us
        };
        let bucket = if interval == u64::MAX {
            0
        } else {
            relative_us
                .checked_div(interval)
                .unwrap_or(0)
                .min(u64::try_from(MAX_BUCKETS - 1).unwrap_or(u64::MAX)) as usize
        };
        let mut capped = std::mem::take(&mut self.capped);
        for index in 0..self.columns.len() {
            let Some(column) = self.columns.get_mut(index) else {
                continue;
            };
            if !column.filter.matches(facts.tree) {
                continue;
            }
            if column.kind == IoCalc::Load && !column.available_load() {
                if !column.load_error_reported {
                    column.load_error_reported = true;
                    notices.once(
                        "io-stat-load",
                        "LOAD() is only supported for relative-time fields such as smb.time",
                    );
                }
                continue;
            }
            let was_capped = capped;
            let Some(row_index) = column.ensure_rows(bucket, budget, &mut capped) else {
                if !capped {
                    notices.once(
                        "io-stat-buckets",
                        "statistics budget reached; io,stat buckets were capped",
                    );
                    capped = true;
                }
                continue;
            };
            if capped && !was_capped {
                notices.once(
                    "io-stat-buckets",
                    "statistics budget reached; io,stat buckets were capped",
                );
            }
            if let Some(row) = column.rows.get_mut(row_index) {
                row.frames = row.frames.saturating_add(1);
            }
            update_column(column, row_index, facts, interval);
            update_max(column, row_index);
        }
        self.capped = capped;
    }

    pub(crate) fn finish(
        &mut self,
        spec: &IoStatSpec,
        duration_micros: u64,
        output: &mut dyn fmt::Write,
    ) -> fmt::Result {
        let requested = spec.interval_micros;
        let original_duration = duration_micros;
        let mut duration = duration_micros;
        let mut interval = if requested > duration || requested == 0 {
            duration
        } else {
            requested
        };
        let clamped = requested > duration_micros || requested == 0;
        let mut dur_mag = magnitude(duration / 1_000_000);
        let invl_mag = magnitude(interval / 1_000_000);
        let (precision, mut borderlen) = if interval == duration {
            let precision = if dur_mag >= 2 {
                1
            } else if dur_mag == 1 {
                3
            } else {
                6
            };
            let border = 30 + dur_mag + if precision == 0 { 0 } else { precision + 1 };
            (precision, border as usize)
        } else {
            let precision = spec.precision;
            let border =
                25 + dur_mag.max(invl_mag) + if precision == 0 { 0 } else { precision + 1 };
            (precision, border as usize)
        };

        // Round the duration to the precision that will be printed, then let
        // a clamped interval follow the rounded value.
        let mut divisor = 1_000_000_u64;
        for _ in 0..precision {
            divisor /= 10;
        }
        if divisor > 0 && duration % divisor > 5 * (divisor / 10) {
            duration = duration.saturating_add(5 * (divisor / 10));
            duration = (duration / divisor) * divisor;
            dur_mag = magnitude(duration / 1_000_000);
        }
        if clamped {
            interval = duration;
        }

        let dur_w = dur_mag + if precision == 0 { 0 } else { precision + 1 };
        // Widen the printed span by one space and keep at least three
        // characters for "Dur".
        let time_width = (dur_w + 1).max(3) as usize;
        let invl_col_w = 2 * (time_width + 3);

        let mut widths = Vec::with_capacity(self.columns.len());
        let mut tabrow_w = invl_col_w;
        for column in &self.columns {
            let width = column_width(column, interval);
            tabrow_w += width + 3;
            widths.push(width);
        }
        // Frames-and-bytes columns contribute a second value width.
        for column in &self.columns {
            if column.kind == IoCalc::FramesAndBytes {
                tabrow_w += bytes_width(column.max_vals) + 3;
            }
        }
        borderlen = borderlen.max(tabrow_w);

        let mut max_filter_w = 0_usize;
        for column in &self.columns {
            let width = match &column.label {
                Some(label) => label.len() + 11,
                None => 26,
            };
            max_filter_w = max_filter_w.max(width);
        }
        if max_filter_w > borderlen && borderlen < 102 {
            borderlen = max_filter_w.min(102);
        }
        if borderlen == tabrow_w + 1 {
            borderlen += 1;
        }

        write_header(
            output,
            borderlen,
            original_duration,
            interval,
            precision,
            spec,
        )?;
        write_column_header(output, borderlen, tabrow_w, invl_col_w, spec, &widths, self)?;

        let computed_rows = if interval == 0 || duration == 0 {
            0
        } else {
            duration / interval + u64::from(!duration.is_multiple_of(interval))
        };
        // A hostile interval cannot make the renderer print unbounded rows.
        // When the budget capped storage, print only rows that exist; an
        // uncapped run keeps zero-filled gaps.
        let mut num_rows = computed_rows.min(MAX_BUCKETS as u64);
        if self.capped {
            let stored = self
                .columns
                .iter()
                .map(|column| column.rows.len())
                .max()
                .unwrap_or(0);
            num_rows = num_rows.min(u64::try_from(stored).unwrap_or(0));
        }
        let truncated = num_rows < computed_rows;
        let dur_w = time_width;
        let mut row_start = 0_u64;
        for row_index in 0..num_rows {
            let last = row_index + 1 == num_rows;
            let start = time_text(row_index.saturating_mul(interval), precision);
            let end = if precision == 0 && last && !truncated {
                "Dur".to_string()
            } else {
                time_text((row_index + 1).saturating_mul(interval), precision)
            };
            let _ = row_start;
            row_start += interval;
            write!(output, "|{start:>dur_w$} <")?;
            write!(output, "> {end:<dur_w$}|")?;
            for (index, column) in self.columns.iter().enumerate() {
                let row = column
                    .rows
                    .get(usize::try_from(row_index).unwrap_or(usize::MAX));
                let value = column_value(
                    column,
                    row,
                    interval,
                    widths.get(index).copied().unwrap_or(2),
                );
                write!(output, " {value} |")?;
            }
            if tabrow_w < borderlen {
                write_filler(output, borderlen - tabrow_w)?;
            }
            writeln!(output)?;
        }
        for _ in 0..borderlen {
            write!(output, "=")?;
        }
        writeln!(output)?;
        Ok(())
    }
}

impl Column {
    fn available_load(&self) -> bool {
        matches!(
            self.argument,
            Some(IoArgument::Field(field)) if field.field_type == FieldType::RelativeTime
        )
    }

    fn ensure_rows(
        &mut self,
        bucket: usize,
        budget: &mut Budget,
        capped: &mut bool,
    ) -> Option<usize> {
        if self.rows.is_empty() {
            if !budget.reserve(std::mem::size_of::<Row>() + ROW_OVERHEAD) {
                return None;
            }
            self.rows.push(Row::default());
        }
        if bucket < self.rows.len() {
            return Some(self.rows.len() - 1);
        }
        while self.rows.len() <= bucket {
            if self.rows.len() >= MAX_BUCKETS
                || !budget.reserve(std::mem::size_of::<Row>() + ROW_OVERHEAD)
            {
                *capped = true;
                return Some(self.rows.len() - 1);
            }
            self.rows.push(Row::default());
        }
        Some(self.rows.len() - 1)
    }
}

fn update_column(column: &mut Column, row_index: usize, facts: &FrameFacts<'_>, interval: u64) {
    match column.kind {
        IoCalc::FramesAndBytes => {
            if let Some(row) = column.rows.get_mut(row_index) {
                row.counter = row
                    .counter
                    .saturating_add(u64::from(facts.frame.original_len));
            }
        }
        IoCalc::Count => {
            if !column.available {
                return;
            }
            let count = match column.argument {
                Some(IoArgument::Field(field)) => facts.field_values(field.abbrev).count(),
                Some(IoArgument::Protocol(protocol)) => facts.protocol_count(protocol.filter_name),
                None => 0,
            };
            if let Some(row) = column.rows.get_mut(row_index) {
                row.counter = row
                    .counter
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
        }
        IoCalc::Sum | IoCalc::Min | IoCalc::Max | IoCalc::Avg => {
            if !column.available {
                return;
            }
            let Some(IoArgument::Field(field)) = column.argument else {
                return;
            };
            let mut values = Vec::new();
            for (_, value) in facts.field_values(field.abbrev) {
                if let Some(numeric) = numeric_value(field.field_type, value) {
                    values.push(numeric);
                }
            }
            let Some(row) = column.rows.get_mut(row_index) else {
                return;
            };
            for (occurrence, value) in values.into_iter().enumerate() {
                match value {
                    Numeric::Integer(value) => match column.kind {
                        IoCalc::Sum | IoCalc::Avg => {
                            row.counter = row.counter.wrapping_add(value);
                            if column.kind == IoCalc::Avg {
                                row.num = row.num.saturating_add(1);
                            }
                        }
                        IoCalc::Min
                            if (row.frames == 1 && occurrence == 0)
                                || compare_integer(field.field_type, value, row.counter) =>
                        {
                            row.counter = value;
                        }
                        IoCalc::Max
                            if compare_integer_max(field.field_type, value, row.counter) =>
                        {
                            row.counter = value;
                        }
                        _ => {}
                    },
                    Numeric::Double(value) => match column.kind {
                        IoCalc::Sum => row.double_counter += value,
                        IoCalc::Avg => {
                            row.double_counter += value;
                            row.num = row.num.saturating_add(1);
                        }
                        IoCalc::Min
                            if (row.frames == 1 && occurrence == 0)
                                || value < row.double_counter =>
                        {
                            row.double_counter = value;
                        }
                        IoCalc::Max if value > row.double_counter => {
                            row.double_counter = value;
                        }
                        _ => {}
                    },
                }
            }
        }
        IoCalc::Load => {
            if !column.available {
                return;
            }
            let Some(IoArgument::Field(field)) = column.argument else {
                return;
            };
            let mut samples = Vec::new();
            for (_, value) in facts.field_values(field.abbrev) {
                if let Value::RelativeTime(nanos) = value {
                    let magnitude = nanos.unsigned_abs();
                    samples.push(if *nanos < 0 { 0 } else { magnitude / 1_000 });
                }
            }
            for val in samples {
                let tival = if interval == u64::MAX {
                    val
                } else {
                    val % interval
                };
                if let Some(row) = column.rows.get_mut(row_index) {
                    row.counter = row.counter.saturating_add(tival);
                }
                let mut remaining = val.saturating_sub(tival);
                let mut previous = row_index;
                while remaining > 0 {
                    let Some(index) = previous.checked_sub(1) else {
                        break;
                    };
                    let Some(target) = column.rows.get_mut(index) else {
                        break;
                    };
                    if interval == u64::MAX || remaining < interval {
                        target.counter = target.counter.saturating_add(remaining);
                        break;
                    }
                    target.counter = target.counter.saturating_add(interval);
                    remaining -= interval;
                    previous = index;
                }
            }
        }
    }
}

fn update_max(column: &mut Column, row_index: usize) {
    let Some(row) = column.rows.get(row_index) else {
        return;
    };
    match column.kind {
        IoCalc::FramesAndBytes => {
            column.max_frame = column.max_frame.max(row.frames);
            column.max_vals = column.max_vals.max(row.counter);
        }
        IoCalc::Count | IoCalc::Load => {
            column.max_vals = column.max_vals.max(row.counter);
        }
        IoCalc::Sum | IoCalc::Min | IoCalc::Max => {
            if let Some(IoArgument::Field(field)) = column.argument {
                if field.field_type == FieldType::Double {
                    column.max_vals = column
                        .max_vals
                        .max((row.double_counter + 0.5).max(0.0) as u64);
                } else {
                    column.max_vals = column.max_vals.max(row.counter);
                }
            }
        }
        IoCalc::Avg => {
            if row.num == 0 {
                return;
            }
            if let Some(IoArgument::Field(field)) = column.argument {
                let average = match field.field_type {
                    FieldType::Double => row.double_counter / row.num as f64,
                    FieldType::RelativeTime => {
                        let mean = row.counter / row.num;
                        (mean.saturating_add(500_000_000) / 1_000_000_000) as f64
                    }
                    _ => (row.counter / row.num) as f64,
                };
                column.max_vals = column.max_vals.max(average as u64);
            }
        }
    }
}

enum Numeric {
    Integer(u64),
    Double(f64),
}

fn numeric_value(field_type: FieldType, value: &Value) -> Option<Numeric> {
    Some(match field_type {
        FieldType::Uint8
        | FieldType::Uint16
        | FieldType::Uint24
        | FieldType::Uint32
        | FieldType::Uint64 => match value {
            Value::Uint8(value) => Numeric::Integer(u64::from(*value)),
            Value::Uint16(value) => Numeric::Integer(u64::from(*value)),
            Value::Uint24(value) => Numeric::Integer(u64::from(*value)),
            Value::Uint32(value) => Numeric::Integer(u64::from(*value)),
            Value::Uint64(value) => Numeric::Integer(*value),
            _ => return None,
        },
        FieldType::Int8 | FieldType::Int16 | FieldType::Int32 | FieldType::Int64 => match value {
            Value::Int8(value) => Numeric::Integer(i64::from(*value) as u64),
            Value::Int16(value) => Numeric::Integer(i64::from(*value) as u64),
            Value::Int32(value) => Numeric::Integer(i64::from(*value) as u64),
            Value::Int64(value) => Numeric::Integer(*value as u64),
            _ => return None,
        },
        FieldType::Double => match value {
            Value::Uint16(value) => Numeric::Double(f64::from(*value) / 256.0),
            Value::Uint32(value) => Numeric::Double(f64::from(*value) / 256.0),
            Value::RelativeTime(_) => return None,
            _ => return None,
        },
        FieldType::RelativeTime => match value {
            Value::RelativeTime(nanos) => Numeric::Integer(nanos.unsigned_abs()),
            _ => return None,
        },
        FieldType::FrameNumber => match value {
            Value::Uint32(value) => Numeric::Integer(u64::from(*value)),
            _ => return None,
        },
        _ => return None,
    })
}

fn compare_integer(field_type: FieldType, candidate: u64, current: u64) -> bool {
    if is_signed(field_type) {
        (candidate as i64) < (current as i64)
    } else {
        candidate < current
    }
}

fn compare_integer_max(field_type: FieldType, candidate: u64, current: u64) -> bool {
    if is_signed(field_type) {
        (candidate as i64) > (current as i64)
    } else {
        candidate > current
    }
}

fn is_signed(field_type: FieldType) -> bool {
    matches!(
        field_type,
        FieldType::Int8 | FieldType::Int16 | FieldType::Int32 | FieldType::Int64
    )
}

fn column_width(column: &Column, interval: u64) -> usize {
    match column.kind {
        IoCalc::FramesAndBytes => column.max_frame.max(1).to_string().len().max(6),
        IoCalc::Count => bytes_width(column.max_vals),
        IoCalc::Sum | IoCalc::Min | IoCalc::Max | IoCalc::Avg | IoCalc::Load => {
            let Some(argument) = column.argument else {
                return 2;
            };
            match argument.field_type() {
                Some(FieldType::Double) => {
                    let mag = magnitude(column.max_vals) as usize;
                    mag + 7
                }
                Some(FieldType::RelativeTime) => {
                    let scaled = match column.kind {
                        IoCalc::Load => column.max_vals.checked_div(interval).unwrap_or(0),
                        IoCalc::Avg => column.max_vals,
                        _ => (column.max_vals.saturating_add(500_000_000)) / 1_000_000_000,
                    };
                    magnitude(scaled) as usize + 7
                }
                _ => {
                    let name = column.kind.name().len();
                    name.max(magnitude(column.max_vals) as usize)
                }
            }
        }
    }
}

fn bytes_width(value: u64) -> usize {
    magnitude(value).max(5) as usize
}

fn column_value(column: &Column, row: Option<&Row>, interval: u64, width: usize) -> String {
    let zero = Row::default();
    let row = row.unwrap_or(&zero);
    match column.kind {
        IoCalc::FramesAndBytes => {
            let bytes_width = bytes_width(column.max_vals);
            format!(
                "{:>frame_width$} | {:>bytes_width$}",
                row.frames,
                row.counter,
                frame_width = width
            )
        }
        IoCalc::Count => format!("{:>width$}", row.counter),
        IoCalc::Sum | IoCalc::Min | IoCalc::Max => {
            let Some(argument) = column.argument else {
                return format!("{:>width$}", 0);
            };
            match argument.field_type() {
                Some(FieldType::Double) => format!("{:>width$.6}", row.double_counter),
                Some(FieldType::RelativeTime) => {
                    let micros = row.counter.saturating_add(500) / 1_000;
                    format!(
                        "{:>mag$}.{:06}",
                        micros / 1_000_000,
                        micros % 1_000_000,
                        mag = width.saturating_sub(7)
                    )
                }
                Some(field_type) if is_signed(field_type) => {
                    format!("{:>width$}", row.counter as i64)
                }
                _ => format!("{:>width$}", row.counter),
            }
        }
        IoCalc::Avg => {
            let Some(argument) = column.argument else {
                return format!("{:>width$}", 0);
            };
            let num = row.num.max(1);
            match argument.field_type() {
                Some(FieldType::Double) => {
                    format!("{:>width$.6}", row.double_counter / num as f64)
                }
                Some(FieldType::RelativeTime) => {
                    let micros = (row.counter / num).saturating_add(500) / 1_000;
                    format!(
                        "{:>mag$}.{:06}",
                        micros / 1_000_000,
                        micros % 1_000_000,
                        mag = width.saturating_sub(7)
                    )
                }
                _ => format!("{:>width$}", row.counter / num),
            }
        }
        IoCalc::Load => {
            let relative = matches!(
                column.argument,
                Some(IoArgument::Field(field)) if field.field_type == FieldType::RelativeTime
            );
            if !relative {
                return format!("{:>width$}", row.counter);
            }
            if interval == 0 {
                return format!("{:>width$}", 0);
            }
            let seconds = row.counter / interval;
            let micros = (row.counter % interval).saturating_mul(1_000_000) / interval;
            format!(
                "{:>mag$}.{:06}",
                seconds,
                micros,
                mag = width.saturating_sub(7)
            )
        }
    }
}

/// Round a microsecond value to the printed decimal precision.
fn round_micros(micros: u64, precision: u32) -> u64 {
    let precision = precision.min(6);
    let divisor = 10_u64.pow(6 - precision);
    let half = divisor / 2;
    micros.saturating_add(half) / divisor * divisor
}

fn time_text(micros: u64, precision: u32) -> String {
    let seconds = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    let precision = precision.min(6);
    if precision == 0 {
        return seconds.to_string();
    }
    let divisor = 10_u64.pow(6 - precision);
    format!(
        "{seconds}.{:0width$}",
        fraction / divisor,
        width = precision as usize
    )
}

fn write_header(
    output: &mut dyn fmt::Write,
    borderlen: usize,
    duration: u64,
    interval: u64,
    precision: u32,
    spec: &IoStatSpec,
) -> fmt::Result {
    let dur_precision = if precision == 0 { 6 } else { precision };
    let duration = round_micros(duration, dur_precision);
    writeln!(output)?;
    for _ in 0..borderlen {
        write!(output, "=")?;
    }
    writeln!(output)?;
    write_padded(output, " IO Statistics", borderlen)?;
    write_padded(output, "", borderlen)?;

    let dur_mag = magnitude(duration / 1_000_000);
    let header_width = (dur_mag + if precision == 0 { 0 } else { precision + 1 }) as usize;
    let duration_text = time_text(duration, dur_precision);
    let mut line = String::from("| Duration: ");
    line.push_str(&format!("{duration_text:>header_width$} secs"));
    write_padded(output, &line, borderlen)?;

    let interval_text = time_text(interval, precision);
    let mut line = String::from("| Interval: ");
    line.push_str(&format!("{interval_text:>header_width$} secs"));
    write_padded(output, &line, borderlen)?;

    write_padded(output, "", borderlen)?;
    for (index, column) in spec.columns.iter().enumerate() {
        let mut prefix = if index == 0 {
            String::from("| Col ")
        } else {
            String::from("|     ")
        };
        prefix.push_str(&format!("{:>2}: ", index + 1));
        let label = column.label.as_deref().unwrap_or("Frames and bytes");
        let max_width = borderlen.saturating_sub(11);
        let mut remaining = label;
        while max_width > 0 && remaining.len() > max_width {
            let mut split = max_width.min(remaining.len());
            while split > 0 && !remaining.is_char_boundary(split) {
                split -= 1;
            }
            if split == 0 {
                // The width falls inside the first character; move to the
                // next boundary so the loop always makes progress.
                split = max_width.min(remaining.len());
                while split < remaining.len() && !remaining.is_char_boundary(split) {
                    split += 1;
                }
            }
            let split = remaining[..split].rfind(' ').unwrap_or(split);
            let (chunk, rest) = remaining.split_at(split);
            write_padded(output, &format!("{prefix}{chunk}"), borderlen)?;
            prefix = String::from("|         ");
            remaining = rest.strip_prefix(' ').unwrap_or(rest);
        }
        write_padded(output, &format!("{prefix}{remaining}"), borderlen)?;
    }
    write!(output, "|-")?;
    for _ in 0..borderlen.saturating_sub(3) {
        write!(output, "-")?;
    }
    writeln!(output, "|")?;
    Ok(())
}

fn write_column_header(
    output: &mut dyn fmt::Write,
    borderlen: usize,
    tabrow_w: usize,
    invl_col_w: usize,
    spec: &IoStatSpec,
    widths: &[usize],
    state: &State,
) -> fmt::Result {
    write!(output, "|")?;
    for _ in 0..invl_col_w.saturating_sub(2) {
        write!(output, " ")?;
    }
    write!(output, "|")?;
    for (index, column) in spec.columns.iter().enumerate() {
        let width = widths.get(index).copied().unwrap_or(2);
        let padding = if column.kind == IoCalc::FramesAndBytes {
            width + bytes_width(state.columns.get(index).map_or(0, |c| c.max_vals)) + 3
        } else {
            width
        };
        write!(output, "{:<2}", index + 1)?;
        for _ in 0..padding {
            write!(output, " ")?;
        }
        write!(output, "|")?;
    }
    if tabrow_w < borderlen {
        write_filler(output, borderlen - tabrow_w)?;
    }
    writeln!(output)?;

    let mut line = String::from("| Interval");
    while line.len() + 1 < invl_col_w {
        line.push(' ');
    }
    write!(output, "{line}|")?;
    for (index, column) in spec.columns.iter().enumerate() {
        let width = widths.get(index).copied().unwrap_or(2);
        match column.kind {
            IoCalc::FramesAndBytes => {
                let bytes = bytes_width(state.columns.get(index).map_or(0, |c| c.max_vals));
                write!(output, "{}", print_center("Frames", width))?;
                write!(output, "{}", print_center("Bytes", bytes))?;
            }
            _ => {
                write!(output, "{}", print_center(column.kind.name(), width))?;
            }
        }
    }
    if tabrow_w < borderlen {
        write_filler(output, borderlen - tabrow_w)?;
    }
    writeln!(output)?;
    write!(output, "|-")?;
    for _ in 0..tabrow_w.saturating_sub(3) {
        write!(output, "-")?;
    }
    write!(output, "|")?;
    if tabrow_w < borderlen {
        write_filler(output, borderlen - tabrow_w)?;
    }
    writeln!(output)?;
    Ok(())
}

fn write_filler(output: &mut dyn fmt::Write, width: usize) -> fmt::Result {
    if width == 0 {
        return Ok(());
    }
    for _ in 0..width.saturating_sub(1) {
        write!(output, " ")?;
    }
    write!(output, "|")
}

fn write_padded(output: &mut dyn fmt::Write, line: &str, borderlen: usize) -> fmt::Result {
    if line.starts_with('|') {
        write!(output, "{line}")?;
    } else {
        write!(output, "|{line}")?;
    }
    let written = line.len() + usize::from(!line.starts_with('|'));
    for _ in written..borderlen.saturating_sub(1) {
        write!(output, " ")?;
    }
    writeln!(output, "|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::Display;

    static FRAME_REFERENCE: FieldDef = FieldDef {
        abbrev: "test.frame_reference",
        name: "Frame Reference",
        field_type: FieldType::FrameNumber,
        parent: "frame",
        display: Display::Decimal,
        bitmask: None,
        blurb: "",
        generated: true,
    };

    #[test]
    fn framenum_fields_support_numeric_calculations() {
        assert!(validate_argument(IoCalc::Sum, IoArgument::Field(&FRAME_REFERENCE)).is_ok());
        assert!(matches!(
            numeric_value(FieldType::FrameNumber, &Value::Uint32(7)),
            Some(Numeric::Integer(7))
        ));
    }

    #[test]
    fn load_rejects_protocol_arguments_but_accepts_fields() {
        assert!(
            validate_argument(
                IoCalc::Load,
                IoArgument::Protocol(&crate::fields::FRAME_PROTOCOL)
            )
            .is_err()
        );
        let unknown = crate::fields::field_by_abbrev("frame.len");
        assert!(unknown.is_some());
        if let Some(field) = unknown {
            assert!(validate_argument(IoCalc::Load, IoArgument::Field(field)).is_ok());
        }
    }

    #[test]
    fn c_double_interval_grammar_matches_strtod() {
        assert_eq!(parse_c_double("0x1"), Some(1.0));
        assert_eq!(parse_c_double("0X1.8"), Some(1.5));
        assert_eq!(parse_c_double("0x1p4"), Some(16.0));
        assert_eq!(parse_c_double("0x1.8p1"), Some(3.0));
        assert_eq!(parse_c_double("Infinity"), Some(f64::INFINITY));
        assert_eq!(parse_c_double("-inf"), Some(f64::NEG_INFINITY));
        assert!(parse_c_double("nan").is_some_and(f64::is_nan));
        assert_eq!(parse_c_double("1e999"), Some(f64::INFINITY));
        assert_eq!(parse_c_double("1.2.3"), None);
        assert_eq!(parse_c_double("-0"), Some(-0.0));
        assert_eq!(parse_c_double("-0.0"), Some(-0.0));
        assert!(parse("io,stat,-0").is_ok());
        assert!(parse("io,stat,-0.0").is_ok());
        assert!(parse("io,stat,-0.000001").is_err());
    }

    #[test]
    fn max_starts_at_zero_for_all_negative_values() {
        let spec = parse("io,stat,0,MAX(ntp.precision)ntp.precision");
        assert!(spec.is_ok());
    }
}
