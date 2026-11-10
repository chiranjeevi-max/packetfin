//! Default text output: one summary line per packet.
//!
//! The default columns are number, time, source,
//! destination, protocol, length and info. Addresses and protocol names are
//! read from the decoded tree so field output and summary output share one
//! decode. Time formats mirror `-t`; `-u hms` changes relative and delta
//! seconds to hours, minutes and seconds.
//!
//! UTC times without a date (`-t u`) have at most seven fractional digits,
//! and only the seven-digit form ends in `Z`.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::io::{self, Write};

use packetfin_core::NameResolution as Resolution;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{NetworkContext, Packet};
use packetfin_core::fields::{self, value_name};
use packetfin_core::names::service_name;
use packetfin_core::tree::{Node, Severity, Value};

use crate::color;

/// A `-t` time stamp format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeFormat {
    /// Seconds since the first captured frame.
    Relative,
    /// Local time without a date; rendered as UTC without a time-zone database.
    Absolute,
    /// Local date and time; rendered as UTC.
    AbsoluteWithDate,
    /// Local date as year and day of year; rendered as UTC.
    AbsoluteWithDayOfYear,
    /// Seconds since the previous captured frame.
    Delta,
    /// Seconds since the previous displayed frame.
    DeltaDisplayed,
    /// Seconds since the Unix epoch.
    Epoch,
    /// UTC time without a date.
    Utc,
    /// UTC date and time.
    UtcWithDate,
    /// UTC year and day of year.
    UtcWithDayOfYear,
}

/// How the seven summary columns are laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryStyle {
    /// Single spaces between columns, as `-T text` and the default summary.
    Text,
    /// Tabs between columns, as `-T tabs`.
    Tabs,
}

/// Parsed `-t` and `-u` options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeOptions {
    /// Selected `-t` format.
    pub format: TimeFormat,
    /// Fractional digits from `-t FORMAT.N`; `None` uses the capture's own.
    pub precision: Option<u8>,
    /// Whether `-u hms` asks for hours, minutes and seconds.
    pub hours_minutes_seconds: bool,
}

impl Default for TimeOptions {
    fn default() -> Self {
        Self {
            format: TimeFormat::Relative,
            precision: None,
            hours_minutes_seconds: false,
        }
    }
}

/// The seven summary columns for one displayed frame.
pub struct Columns {
    /// `No.` column: the frame number.
    pub number: u64,
    /// `Time` column, already rendered with the selected `-t`/`-u` format.
    pub time: String,
    /// `Source` column.
    pub source: String,
    /// `Destination` column.
    pub destination: String,
    /// `Protocol` column.
    pub protocol: String,
    /// `Length` column: the original frame length.
    pub length: u32,
    /// `Info` column.
    pub info: String,
}

/// Renders summary lines and keeps the state the time formats need.
pub struct SummaryWriter {
    options: TimeOptions,
    style: SummaryStyle,
    first_timestamp: Option<Timestamp>,
    previous_captured: Option<Timestamp>,
    previous_displayed: Option<Timestamp>,
    echo_requests: EchoBook,
    /// The next `-t d` delta is blank after a session reset.
    suppress_captured_delta: bool,
    line: String,
    color: bool,
}

impl SummaryWriter {
    /// Create a writer for the selected time options.
    pub fn new(options: TimeOptions) -> Self {
        Self {
            options,
            style: SummaryStyle::Text,
            first_timestamp: None,
            previous_captured: None,
            previous_displayed: None,
            echo_requests: EchoBook::default(),
            suppress_captured_delta: false,
            line: String::with_capacity(160),
            color: false,
        }
    }

    /// Restart the state `-M` resets.
    ///
    /// The first file frame becomes the delta reference again and the first
    /// `-t d` delta of the new session is blank; the following delta is
    /// therefore measured from the first file frame. `-t dd` deltas continue
    /// from the previous displayed frame.
    pub fn reset_session(&mut self) {
        if self.options.format == TimeFormat::Delta {
            self.previous_captured = self.first_timestamp;
            self.suppress_captured_delta = true;
        }
    }

    /// Seed the time baseline from a frame that will not be displayed.
    ///
    /// The relative summary time is measured from the first file frame,
    /// even when a read filter skips every earlier frame.
    pub fn observe_capture_time(&mut self, frame: &Frame) {
        if self.first_timestamp.is_none() {
            self.first_timestamp = frame.timestamp;
        }
        if frame.timestamp.is_some() {
            self.previous_captured = frame.timestamp;
        }
    }

    /// Select the column layout.
    pub fn with_style(mut self, style: SummaryStyle) -> Self {
        self.style = style;
        self
    }

    /// Colourise displayed summary lines.
    ///
    /// The caller decides whether colour applies (a terminal or the test
    /// hook); this writer only renders the escape sequence.
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// Write one summary line. `displayed` is false when quiet mode suppresses
    /// the line or a display filter rejects the frame; the frame still
    /// advances the captured-time state. `observe_hidden` keeps echo-request
    /// state for a frame the filter hides, so a later reply's `(request in N)`
    /// annotation can name a request that was not displayed.
    pub fn write_packet(
        &mut self,
        output: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
        displayed: bool,
        observe_hidden: bool,
    ) -> io::Result<()> {
        if !displayed {
            self.observe_hidden(frame, packet, observe_hidden);
            return Ok(());
        }

        let columns = self.columns(frame, packet);
        self.line.clear();
        match self.style {
            SummaryStyle::Text => {
                let _ = writeln!(
                    self.line,
                    "{:>5} {:>10} {:>12} \u{2192} {:<12} {} {} {}",
                    columns.number,
                    columns.time,
                    columns.source,
                    columns.destination,
                    columns.protocol,
                    columns.length,
                    columns.info
                );
            }
            SummaryStyle::Tabs => {
                let _ = writeln!(
                    self.line,
                    "{:>5}\t{:>10}\t{:>12}\t\u{2192}\t{:<12}\t{}\t{}\t{}",
                    columns.number,
                    columns.time,
                    columns.source,
                    columns.destination,
                    columns.protocol,
                    columns.length,
                    columns.info
                );
            }
        }
        if self.color
            && let Some(rule) = color::rule_for(&packet.tree)
        {
            let prefix = color::terminal_prefix(&rule);
            let line = self.line.strip_suffix('\n').unwrap_or(&self.line);
            output.write_all(prefix.as_bytes())?;
            output.write_all(line.as_bytes())?;
            output.write_all(b"\x1b[K\r\n\x1b[0m")?;
        } else {
            output.write_all(self.line.as_bytes())?;
        }
        Ok(())
    }

    /// Advance the captured-time and echo state for a frame that is not
    /// printed.
    ///
    /// Echo state is the only output-visible state a hidden frame can
    /// contribute. Skip the chain and address strings when the packet has no
    /// ICMP layer at all.
    pub fn observe_hidden(&mut self, frame: &Frame, packet: &Packet, observe_hidden: bool) {
        if self.first_timestamp.is_none() {
            self.first_timestamp = frame.timestamp;
        }
        let suppress_delta = std::mem::take(&mut self.suppress_captured_delta);
        if !suppress_delta {
            self.previous_captured = frame.timestamp;
        }
        if observe_hidden
            && packet
                .protocol_stack
                .iter()
                .any(|name| matches!(*name, "icmp" | "icmpv6"))
        {
            let chain = outer_chain(packet);
            let (source, destination) = addresses(packet, &chain);
            let _ = observe_echo(
                frame.number,
                chain.last().copied(),
                &source,
                &destination,
                &mut self.echo_requests,
            );
        }
    }

    /// Render the seven summary columns for a displayed frame.
    ///
    /// This is the summary line's data without its fixed-width layout, so
    /// XML summary output can reuse the exact same time, address, protocol
    /// and info values.
    pub fn columns(&mut self, frame: &Frame, packet: &Packet) -> Columns {
        if self.first_timestamp.is_none() {
            self.first_timestamp = frame.timestamp;
        }
        let suppress_delta = std::mem::take(&mut self.suppress_captured_delta);
        let time = if suppress_delta {
            String::new()
        } else {
            self.render_time(frame)
        };
        if !suppress_delta {
            self.previous_captured = frame.timestamp;
        }
        self.previous_displayed = frame.timestamp;
        let chain = outer_chain(packet);
        let (source, destination) = addresses(packet, &chain);
        let (protocol, info) = protocol_and_info(
            frame,
            packet,
            &chain,
            &source,
            &destination,
            &mut self.echo_requests,
        );
        Columns {
            number: frame.number,
            time,
            source,
            destination,
            protocol,
            length: frame.original_len,
            info,
        }
    }

    fn render_time(&self, frame: &Frame) -> String {
        let Some(timestamp) = frame.timestamp else {
            return String::new();
        };
        let precision =
            u32::from(self.options.precision.unwrap_or(frame.timestamp_precision)).min(9);
        match self.options.format {
            TimeFormat::Relative => {
                let Some(first) = self.first_timestamp else {
                    return String::new();
                };
                self.render_difference(difference(timestamp, Some(first)), precision)
            }
            TimeFormat::Delta | TimeFormat::DeltaDisplayed => {
                let previous = if self.options.format == TimeFormat::Delta {
                    self.previous_captured
                } else {
                    self.previous_displayed
                };
                self.render_difference(difference(timestamp, previous), precision)
            }
            TimeFormat::Epoch => render_epoch(timestamp, precision),
            TimeFormat::Absolute | TimeFormat::Utc => {
                render_time_of_day(timestamp, precision, self.options.format == TimeFormat::Utc)
            }
            TimeFormat::AbsoluteWithDate | TimeFormat::UtcWithDate => render_date_time(
                timestamp,
                precision,
                false,
                self.options.format == TimeFormat::UtcWithDate,
            ),
            TimeFormat::AbsoluteWithDayOfYear | TimeFormat::UtcWithDayOfYear => render_date_time(
                timestamp,
                precision,
                true,
                self.options.format == TimeFormat::UtcWithDayOfYear,
            ),
        }
    }

    fn render_difference(&self, difference: Option<SignedTime>, precision: u32) -> String {
        let Some(value) = difference else {
            return String::new();
        };
        let mut text = String::with_capacity(32);
        if self.options.hours_minutes_seconds {
            render_hms(&mut text, value, precision);
        } else {
            render_signed_seconds(&mut text, value, precision);
        }
        text
    }
}

type EchoKey = (bool, String, String, u64, u64);

/// Maximum unmatched ICMP echo requests kept for `(request in N)`.
const MAX_ECHO_REQUESTS: usize = 4096;

/// A bounded store of unmatched echo requests.
///
/// Entries are evicted oldest first and the insertion queue is compacted
/// when it outgrows twice the entry cap. A reply to an evicted request simply
/// loses the annotation; the summary never grows without bound.
#[derive(Default)]
struct EchoBook {
    entries: HashMap<EchoKey, (u64, u64)>,
    order: VecDeque<(EchoKey, u64)>,
    next_order: u64,
}

impl EchoBook {
    fn remember(&mut self, key: EchoKey, frame: u64) {
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.0 = frame;
            return;
        }
        self.next_order = self.next_order.wrapping_add(1);
        let order = self.next_order;
        self.entries.insert(key.clone(), (frame, order));
        self.order.push_back((key, order));
        if self.order.len() > MAX_ECHO_REQUESTS * 2 {
            self.compact();
        }
        while self.entries.len() > MAX_ECHO_REQUESTS {
            let Some((old_key, old_order)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&old_key)
                .is_some_and(|(_, current)| *current == old_order)
            {
                self.entries.remove(&old_key);
            }
        }
    }

    fn reply(&mut self, key: &EchoKey) -> Option<u64> {
        let frame = self.entries.remove(key)?.0;
        self.order.retain(|(stored, _)| stored != key);
        Some(frame)
    }

    fn compact(&mut self) {
        let Self { entries, order, .. } = self;
        order.retain(|(key, stored)| {
            entries
                .get(key)
                .is_some_and(|(_, current)| current == stored)
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.order.len()
    }
}

/// A signed second/nanosecond difference.
#[derive(Clone, Copy, Debug)]
struct SignedTime {
    negative: bool,
    seconds: u64,
    nanos: u32,
}

fn difference(later: Timestamp, earlier: Option<Timestamp>) -> Option<SignedTime> {
    let earlier = earlier?;
    let total_nanos = i128::from(later.seconds)
        .saturating_sub(i128::from(earlier.seconds))
        .saturating_mul(1_000_000_000)
        .saturating_add(i128::from(later.nanos))
        .saturating_sub(i128::from(earlier.nanos));
    let negative = total_nanos < 0;
    let magnitude = total_nanos.unsigned_abs();
    Some(SignedTime {
        negative,
        seconds: u64::try_from(magnitude / 1_000_000_000).unwrap_or(u64::MAX),
        nanos: u32::try_from(magnitude % 1_000_000_000).unwrap_or(0),
    })
}

fn render_signed_seconds(text: &mut String, value: SignedTime, precision: u32) {
    if value.negative {
        text.push('-');
    }
    let _ = write!(text, "{}", value.seconds);
    append_fraction(text, value.nanos, precision);
}

fn render_hms(text: &mut String, value: SignedTime, precision: u32) {
    if value.negative {
        text.push_str("- ");
    }
    if value.seconds >= 3_600 {
        let _ = write!(
            text,
            "{}h {:2}m {:2}",
            value.seconds / 3_600,
            (value.seconds / 60) % 60,
            value.seconds % 60
        );
    } else if value.seconds >= 60 {
        let _ = write!(text, "{}m {:2}", value.seconds / 60, value.seconds % 60);
    } else {
        let _ = write!(text, "{}", value.seconds);
    }
    append_fraction(text, value.nanos, precision);
    text.push('s');
}

fn append_fraction(text: &mut String, nanos: u32, precision: u32) {
    if precision == 0 {
        return;
    }
    let precision = precision.min(9);
    let divisor = 10_u32.pow(9 - precision);
    let fraction = nanos / divisor;
    let _ = write!(text, ".{fraction:0width$}", width = precision as usize);
}

fn render_epoch(timestamp: Timestamp, precision: u32) -> String {
    let mut text = String::with_capacity(32);
    let _ = write!(text, "{}", timestamp.seconds);
    append_fraction(&mut text, timestamp.nanos, precision);
    text
}

fn render_time_of_day(timestamp: Timestamp, precision: u32, utc: bool) -> String {
    let (_year, _month, _day, hour, minute, second) = civil_time(timestamp.seconds);
    let mut text = String::with_capacity(32);
    let _ = write!(text, "{hour:02}:{minute:02}:{second:02}");
    if utc {
        // The UTC time-only column holds seven fractional digits at most and
        // marks only that wider form with `Z`.
        if precision >= 7 {
            let fraction = timestamp.nanos / 100;
            let _ = write!(text, ".{fraction:07}");
            text.push('Z');
        } else {
            append_fraction(&mut text, timestamp.nanos, precision);
        }
    } else {
        append_fraction(&mut text, timestamp.nanos, precision);
    }
    text
}

fn render_date_time(timestamp: Timestamp, precision: u32, day_of_year: bool, utc: bool) -> String {
    let (year, month, day, hour, minute, second) = civil_time(timestamp.seconds);
    let mut text = String::with_capacity(40);
    if day_of_year {
        let _ = write!(
            text,
            "{year:04}/{:03} {hour:02}:{minute:02}:{second:02}",
            day_of_year_number(year, month, day)
        );
    } else {
        let _ = write!(
            text,
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
        );
    }
    append_fraction(&mut text, timestamp.nanos, precision);
    if utc {
        text.push('Z');
    }
    text
}

/// Render the `--hexdump time` preamble.
///
/// The preamble uses the `-t` format and timestamp precision, but its default
/// precision is three fractional digits rather than the capture's. `-u` does
/// not change it. Delta formats print an empty line for a frame with no
/// predecessor.
pub(crate) fn hexdump_time_text(
    options: TimeOptions,
    timestamp: Timestamp,
    first: Timestamp,
    previous_captured: Option<Timestamp>,
    previous_displayed: Option<Timestamp>,
    default_precision: u8,
) -> String {
    let precision = u32::from(options.precision.unwrap_or(default_precision)).min(9);
    match options.format {
        TimeFormat::Relative => {
            let mut text = String::new();
            if let Some(value) = difference(timestamp, Some(first)) {
                render_signed_seconds(&mut text, value, precision);
            }
            text
        }
        TimeFormat::Delta | TimeFormat::DeltaDisplayed => {
            let previous = if options.format == TimeFormat::Delta {
                previous_captured
            } else {
                previous_displayed
            };
            let mut text = String::new();
            if let Some(value) = difference(timestamp, previous) {
                if options.hours_minutes_seconds {
                    render_hms(&mut text, value, precision);
                } else {
                    render_signed_seconds(&mut text, value, precision);
                }
            }
            text
        }
        TimeFormat::Epoch => render_epoch(timestamp, precision),
        TimeFormat::Absolute | TimeFormat::Utc => {
            render_time_of_day(timestamp, precision, options.format == TimeFormat::Utc)
        }
        TimeFormat::AbsoluteWithDate | TimeFormat::UtcWithDate => render_date_time(
            timestamp,
            precision,
            false,
            options.format == TimeFormat::UtcWithDate,
        ),
        TimeFormat::AbsoluteWithDayOfYear | TimeFormat::UtcWithDayOfYear => render_date_time(
            timestamp,
            precision,
            true,
            options.format == TimeFormat::UtcWithDayOfYear,
        ),
    }
}

/// Convert seconds since the epoch into a UTC civil date and time.
pub(crate) use packetfin_core::time::civil_time;

fn day_of_year_number(year: i64, month: u32, day: u32) -> u32 {
    const MONTH_DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mut total = day;
    for (index, days) in MONTH_DAYS.iter().enumerate() {
        if index + 1 < month as usize {
            total += days;
            if index == 1 && leap {
                total += 1;
            }
        }
    }
    total
}

/// The summary source and destination, read from the innermost address-
/// bearing layer. A tunnel's inner Ethernet/IPv4/IPv6 supplies the columns,
/// not the outer tunnel endpoints; the inner Ethernet decoder already put its
/// addresses in `packet.columns`.
fn addresses(packet: &Packet, chain: &[&Node]) -> (String, String) {
    let mut source = None;
    let mut destination = chain
        .iter()
        .rev()
        .find(|node| node.protocol.filter_name == "eth")
        .filter(|node| node.range.length >= 6)
        .filter(|node| {
            !node
                .fields
                .iter()
                .any(|field| field.def.abbrev == "eth.dst")
        })
        .and_then(|_| packet.columns.destination.clone());
    let mut routed_destination = None;
    for node in chain.iter().rev() {
        match node.protocol.filter_name {
            "ip" => {
                if source.is_none() {
                    source = field_text(node, "ip.src_host").or_else(|| field_text(node, "ip.src"));
                }
                if destination.is_none() {
                    destination =
                        field_text(node, "ip.dst_host").or_else(|| field_text(node, "ip.dst"));
                }
            }
            "ipv6" => {
                if source.is_none() {
                    source =
                        field_text(node, "ipv6.src_host").or_else(|| field_text(node, "ipv6.src"));
                }
                if destination.is_none() {
                    destination =
                        field_text(node, "ipv6.dst_host").or_else(|| field_text(node, "ipv6.dst"));
                }
            }
            "ipv6.routing" => {
                // A type-0 source route still to be processed replaces the
                // destination column with the final address in its list.
                if field_u64(node, "ipv6.routing.type") == Some(0)
                    && field_u64(node, "ipv6.routing.segleft").is_some_and(|left| left > 0)
                {
                    routed_destination = field_text_last(node, "ipv6.routing.src.addr");
                }
            }
            "eth" => {
                if source.is_none() {
                    source = field_text(node, "eth.src_resolved")
                        .or_else(|| field_text(node, "eth.src"));
                }
                if destination.is_none() {
                    destination = field_text(node, "eth.dst_resolved")
                        .or_else(|| field_text(node, "eth.dst"));
                }
            }
            _ => {}
        }
        if source.is_some() && destination.is_some() {
            break;
        }
    }
    if let Some(value) = routed_destination {
        destination = Some(value);
    }
    (
        source
            .or_else(|| packet.columns.source.clone())
            .unwrap_or_default(),
        destination
            .or_else(|| packet.columns.destination.clone())
            .unwrap_or_default(),
    )
}

/// The outermost protocol chain: link, then each protocol's first child.
///
/// A datagram quoted inside an ICMP error is a child of the ICMP node, not
/// the outer IP node, so it never appears here.
fn outer_chain(packet: &Packet) -> Vec<&Node> {
    let mut chain = Vec::new();
    let mut current = packet.tree.frame.children.first();
    while let Some(node) = current {
        chain.push(node);
        if matches!(node.protocol.filter_name, "icmp" | "icmpv6") {
            break;
        }
        current = next_layer(node);
    }
    chain
}

/// The layer a protocol hands its payload to.
///
/// IPv6 extension headers are subtree items. An ordinary packet keeps one
/// child chain, while a completed reassembly decodes its payload after the
/// fragment header, so the newly decoded chain is the last child.
fn next_layer(node: &Node) -> Option<&Node> {
    if node.protocol.filter_name == "ipv6" && node.children.len() > 1 {
        return node.children.last();
    }
    node.children.first()
}

/// Record echo-request state, or find the request a reply answers.
///
/// The caller passes every visible frame and, while a display filter is
/// active, every hidden frame too: a reply's annotation can refer to a
/// request the filter did not display.
fn observe_echo(
    frame_number: u64,
    top: Option<&Node>,
    source: &str,
    destination: &str,
    echo_requests: &mut EchoBook,
) -> Option<u64> {
    let top = top?;
    let (family, message_type, identifier, sequence) = match top.protocol.filter_name {
        "icmp" => (
            false,
            field_u64(top, "icmp.type"),
            field_u64(top, "icmp.ident"),
            field_u64(top, "icmp.seq"),
        ),
        "icmpv6" => (
            true,
            field_u64(top, "icmpv6.type"),
            field_u64(top, "icmpv6.echo.identifier"),
            field_u64(top, "icmpv6.echo.sequence_number"),
        ),
        _ => return None,
    };
    let (Some(message_type), Some(identifier), Some(sequence)) =
        (message_type, identifier, sequence)
    else {
        return None;
    };
    if !matches!(message_type, 0 | 8 | 128 | 129) {
        return None;
    }
    if matches!(message_type, 8 | 128) {
        echo_requests.remember(
            (
                family,
                source.to_string(),
                destination.to_string(),
                identifier,
                sequence,
            ),
            frame_number,
        );
        return None;
    }
    echo_requests
        .reply(&(
            family,
            source.to_string(),
            destination.to_string(),
            identifier,
            sequence,
        ))
        .or_else(|| {
            echo_requests.reply(&(
                family,
                destination.to_string(),
                source.to_string(),
                identifier,
                sequence,
            ))
        })
}

/// Collect every protocol node with `name`, in tree preorder.
fn collect_protocol_nodes<'a>(node: &'a Node, name: &str, out: &mut Vec<&'a Node>) {
    if node.protocol.filter_name == name {
        out.push(node);
    }
    for child in &node.children {
        collect_protocol_nodes(child, name, out);
    }
}

fn protocol_and_info(
    frame: &Frame,
    packet: &Packet,
    chain: &[&Node],
    source: &str,
    destination: &str,
    echo_requests: &mut EchoBook,
) -> (String, String) {
    let mut protocol = String::new();
    let mut info = String::new();

    let top = chain
        .last()
        .copied()
        .filter(|node| match node.protocol.filter_name {
            "udp" => {
                field_u64(node, "udp.srcport").is_some() && field_u64(node, "udp.dstport").is_some()
            }
            "tcp" => {
                field_u64(node, "tcp.srcport").is_some() && field_u64(node, "tcp.dstport").is_some()
            }
            _ => true,
        });
    let top = top.or_else(|| {
        chain
            .len()
            .checked_sub(2)
            .and_then(|index| chain.get(index))
            .copied()
    });

    if let Some(top) = top {
        match top.protocol.filter_name {
            "udp" => {
                protocol.push_str("UDP");
                info = udp_info(top, packet, chain);
            }
            "syslog" => {
                protocol.push_str("Syslog");
                info = packet.columns.info.clone().unwrap_or_default();
            }
            "sflow" => {
                protocol.push_str("sFlow");
                info = sflow_info(top);
            }
            "cflow" => {
                protocol.push_str("CFLOW");
                info = cflow_info(top);
            }
            "snmp" => {
                protocol.push_str("SNMP");
                info = if packet.malformed {
                    String::new()
                } else {
                    snmp_info(top).unwrap_or_else(|| {
                        chain
                            .iter()
                            .rev()
                            .find(|node| node.protocol.filter_name == "udp")
                            .map(|node| udp_info(node, packet, chain))
                            .unwrap_or_default()
                    })
                };
            }
            name @ ("dns" | "mdns" | "llmnr") => {
                protocol.push_str(match name {
                    "dns" => "DNS",
                    "mdns" => "MDNS",
                    _ => "LLMNR",
                });
                if name == "dns" {
                    // One TCP segment may carry several DNS messages, each a
                    // sibling protocol node; their summaries join with commas.
                    let mut nodes = Vec::new();
                    collect_protocol_nodes(&packet.tree.frame, "dns", &mut nodes);
                    let multiple = nodes.len() > 1;
                    info = nodes
                        .iter()
                        .filter(|node| {
                            !multiple
                                || !node.protocol_exception
                                    && node
                                        .fields
                                        .iter()
                                        .any(|field| field.def.abbrev == "dns.count.queries")
                        })
                        .map(|node| dns_info(node, false))
                        .filter(|text| !text.is_empty())
                        .collect::<Vec<_>>()
                        .join(", ");
                } else {
                    info = dns_info(top, name == "mdns");
                }
                if let Some(tcp) = chain
                    .iter()
                    .rev()
                    .find(|node| node.protocol.filter_name == "tcp")
                {
                    if let Some(tags) = tcp_analysis_tags(tcp) {
                        // An upper-layer summary completed on a reassembled
                        // segment keeps the TCP tag first, separated by ` , `.
                        info = format!("{tags} , {info}");
                    }
                    if tcp_has_segment_error(tcp) {
                        info.push_str("[Illegal Segments]");
                    }
                }
            }
            "http" => {
                protocol.push_str("HTTP");
                info = packet.columns.info.clone().unwrap_or_default();
            }
            "http2" => {
                protocol.push_str("HTTP2");
                info = packet.columns.info.clone().unwrap_or_default();
            }
            "tls" => {
                protocol.push_str(packet.columns.protocol.as_deref().unwrap_or("TLS"));
                info = packet.columns.info.clone().unwrap_or_default();
            }
            "bgp" => {
                protocol.push_str("BGP");
                info = packet.columns.info.clone().unwrap_or_default();
            }
            "tcp" => {
                protocol.push_str("TCP");
                // The HTTP decoder fills the Info column from the
                // start line before the message is complete, while the
                // protocol column still says TCP.
                info = match packet.columns.info.as_deref() {
                    Some(candidate) if candidate.is_empty() || is_http_start_line(candidate) => {
                        candidate.to_string()
                    }
                    _ => tcp_info(top, packet.resolution),
                };
                if let Some(tags) = tcp_analysis_tags(top) {
                    info = format!("{tags} {info}");
                }
                if let Some(suffix) = packet
                    .columns
                    .info
                    .as_deref()
                    .filter(|info| info.starts_with("[TCP PDU reassembled in "))
                {
                    info.push(' ');
                    info.push_str(suffix);
                }
            }
            "icmp" => {
                protocol.push_str("ICMP");
                info = icmp_info(top, chain);
            }
            "icmpv6" => {
                protocol.push_str("ICMPv6");
                info = icmpv6_info(top, chain);
            }
            "dhcp" => {
                let (name, text) = dhcp_info(top);
                protocol.push_str(name);
                info = text;
            }
            "dhcpv6" => {
                protocol.push_str("DHCPv6");
                info = dhcpv6_info(chain);
            }
            "ntp" => {
                protocol.push_str("NTP");
                info = ntp_info(top);
            }
            "ospf" => {
                protocol.push_str("OSPF");
                info = ospf_info(top);
            }
            "vrrp" => {
                protocol.push_str("VRRP");
                info = vrrp_info(top);
            }
            "bfd" => {
                protocol.push_str("BFD Control");
                info = bfd_info(top);
            }
            "bfd_echo" => {
                protocol.push_str("BFD Echo");
                info.push_str("Originator specific content");
            }
            "arp" => {
                protocol.push_str("ARP");
                info = arp_info(top);
            }
            "lldp" => {
                protocol.push_str("LLDP");
                info = lldp_info(frame, top);
            }
            "lacp" => {
                protocol.push_str("LACP");
                info = lacp_info(top);
            }
            "marker" => {
                protocol.push_str("Marker");
                info = marker_info(top);
            }
            "slow" => {
                protocol.push_str("Slow Protocols");
                info = slow_info(top);
            }
            "stp" => {
                protocol.push_str("STP");
                info = stp_info(top);
            }
            "vlan" => {
                if let Some(ethertype) = field_u64(top, "vlan.etype") {
                    if ethertype == 0x0600 {
                        protocol.push_str("IDP");
                    } else {
                        protocol = format!("0x{ethertype:04x}");
                        info = vlan_info(top);
                    }
                } else {
                    protocol.push_str("VLAN");
                }
            }
            "llc" => {
                protocol.push_str("LLC");
                info = llc_info(top);
            }
            "sll" => {
                protocol = field_u64(top, "sll.ltype")
                    .or_else(|| field_u64(top, "sll.etype"))
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_default();
                if field_u64(top, "sll.ifindex").is_some() {
                    info = sll2_info(top);
                } else {
                    info = sll_info(top);
                }
            }
            "sll2" => {
                protocol = field_u64(top, "sll2.etype")
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_default();
                info = sll2_info(top);
            }
            "ip" => {
                protocol.push_str("IPv4");
                info = ipv4_info(top, packet.forced_data);
                if let Some(suffix) = packet
                    .columns
                    .info
                    .as_deref()
                    .filter(|info| info.starts_with("[Reassembled in #"))
                {
                    info.push(' ');
                    info.push_str(suffix);
                }
            }
            "ipv6" => {
                protocol.push_str("IPv6");
                info = ipv6_info(top, packet.forced_data);
            }
            "gre" => {
                protocol.push_str("GRE");
                info = encapsulated_info(top, "gre.proto", true);
            }
            "erspan" => {
                protocol.push_str("ERSPAN");
                info.push_str("ERSPAN:");
            }
            "geneve" => {
                protocol.push_str("Geneve");
                info = encapsulated_info(top, "geneve.proto_type", false);
            }
            "mpls" => {
                protocol.push_str("MPLS");
                info.push_str("MPLS Label Switched Packet");
            }
            "vxlan" => {
                protocol.push_str("VxLAN");
            }
            name if name.starts_with("ipv6.") => {
                protocol.push_str("IPv6");
                let malformed = top
                    .experts
                    .iter()
                    .any(|expert| expert.group == packetfin_core::tree::Group::Malformed);
                if name == "ipv6.fraghdr" {
                    if !malformed {
                        let completed = chain.iter().any(|node| {
                            subtree_field_u64(node, "ipv6.reassembled.length").is_some()
                        });
                        let next = field_u64(top, "ipv6.fraghdr.nxt").unwrap_or(0);
                        if completed {
                            if next == 59 && top.children.is_empty() {
                                info.push_str("IPv6 no next header");
                            } else if !is_registered_ip_protocol(next) {
                                info = format!("Unknown IP Protocol: Unknown ({next})");
                            }
                        } else if next == 59 && top.children.is_empty() {
                            info.push_str("IPv6 no next header");
                        } else {
                            info = fragment_info(top);
                        }
                    }
                } else if !malformed && field_u64(top, ext_next_header(name)) == Some(59) {
                    info.push_str("IPv6 no next header");
                } else {
                    info = ipv6_extension_info(name);
                }
            }
            name => {
                protocol.push_str(display_protocol(name));
            }
        }
    }

    let captured = frame.captured.len();
    let original = usize::try_from(frame.original_len).unwrap_or(usize::MAX);
    let cut = captured < original;
    let force_malformed = chain.last().is_some_and(|node| {
        (node.protocol.filter_name == "udp"
            && matches!(
                (field_u64(node, "udp.length"), network_payload_length(chain)),
                (Some(length), Some(payload)) if length > payload && payload <= 8
            ))
            || (node.protocol.filter_name == "icmpv6"
                && field_u64(node, "icmpv6.type") == Some(200)
                && node.range.length == 4)
    });

    if let Some(number) = observe_echo(frame.number, top, source, destination, echo_requests) {
        let _ = write!(info, " (request in {number})");
    }

    if let Some(fragment) = chain
        .iter()
        .find(|node| node.protocol.filter_name == "ipv6.fraghdr")
        && !fragment
            .experts
            .iter()
            .any(|expert| expert.group == packetfin_core::tree::Group::Malformed)
        && !chain
            .iter()
            .any(|node| subtree_field_u64(node, "ipv6.reassembled.length").is_some())
        && !chain
            .iter()
            .skip_while(|node| node.protocol.filter_name != "ipv6.fraghdr")
            .skip(1)
            .any(|node| !node.protocol.filter_name.starts_with("ipv6."))
    {
        if info == "IPv6 no next header" {
            // The innermost extension already reported the final header.
        } else if field_u64(fragment, "ipv6.fraghdr.nxt") == Some(59)
            && fragment.children.is_empty()
        {
            info = "IPv6 no next header".to_string();
        } else {
            info = fragment_info(fragment);
        }
    }

    // Append [Illegal Segments] to the upper-layer Info when the
    // completing TCP segment carried a conflicting overlap.
    if top.is_some_and(|top| matches!(top.protocol.filter_name, "http" | "tls" | "bgp"))
        && !info.contains("[Illegal Segments]")
        && let Some(tcp) = chain
            .iter()
            .rev()
            .find(|node| node.protocol.filter_name == "tcp")
        && tcp_has_segment_error(tcp)
    {
        if !info.is_empty() && !info.ends_with(' ') {
            info.push(' ');
        }
        info.push_str("[Illegal Segments]");
    }

    if protocol == "Ethernet" || chain.is_empty() {
        let innermost_eth = chain
            .iter()
            .rposition(|node| node.protocol.filter_name == "eth");
        if let Some(index) = innermost_eth
            && let Some(node) = chain.get(index).copied()
        {
            if let Some(ethertype) = field_u64(node, "eth.type") {
                if ethertype == 0x0600 {
                    protocol = "IDP".to_string();
                    info.clear();
                } else if packet.forced_data {
                    protocol = "Ethernet".to_string();
                    info.clear();
                    info.push_str("Ethernet II");
                } else {
                    protocol = format!("0x{ethertype:04x}");
                    info.clear();
                    info.push_str(packet.columns.info.as_deref().unwrap_or("Ethernet II"));
                }
            } else {
                if let Some(value) = &packet.columns.protocol {
                    protocol.clone_from(value);
                }
                if let Some(caption) = tunnel_caption(chain, index) {
                    info = caption;
                } else if chain
                    .get(index.checked_sub(1).unwrap_or(usize::MAX))
                    .is_some_and(|parent| {
                        parent.protocol.filter_name == "eth"
                            && field_u64(parent, "eth.type") == Some(0x6558)
                    })
                {
                    info.push_str("Ethernet II");
                } else if !cut && let Some(value) = &packet.columns.info {
                    info.clone_from(value);
                }
            }
        } else {
            if let Some(value) = &packet.columns.protocol {
                protocol.clone_from(value);
            }
            if let Some(value) = &packet.columns.info {
                info.clone_from(value);
            }
        }
    }

    // A capture cut short is not the same as malformed data. The summary
    // still reports a capture limit when a decoder needed bytes that were
    // not stored, and ICMP decoders do so even when the IP payload is cut.
    let malformed_reported = chain.last().is_some_and(|node| {
        node.experts.iter().any(|expert| {
            expert.group == packetfin_core::tree::Group::Malformed
                && !expert.message.starts_with("Bad length value")
        })
    });
    if (packet.malformed || force_malformed) && !info.contains("[Malformed Packet") {
        if let Some(detail) = malformed_detail(chain) {
            let _ = write!(info, "[Malformed Packet: {detail}]");
        } else if force_malformed || (!cut && malformed_reported) {
            info.push_str("[Malformed Packet]");
        }
    }
    let capture_limited = capture_limited(frame, packet);
    if cut && capture_limited && !info.ends_with("[Packet size limited during capture]") {
        info.push_str("[Packet size limited during capture]");
    }

    if protocol.is_empty() {
        protocol.push_str("Packet");
    }

    (protocol, info)
}

fn malformed_detail(chain: &[&Node]) -> Option<&'static str> {
    for node in chain.iter().rev() {
        if node.protocol.filter_name != "ip"
            && node.protocol.filter_name != "ipv6.routing"
            && node.protocol.filter_name != "tcp"
            && node.protocol.filter_name != "lldp"
        {
            continue;
        }
        for expert in &node.experts {
            if expert.group != packetfin_core::tree::Group::Malformed {
                continue;
            }
            let routing_detail = node.protocol.filter_name == "ipv6.routing"
                && field_u64(node, "ipv6.routing.type") == Some(0)
                && field_u64(node, "ipv6.routing.segleft").is_some();
            let tcp_detail = node.protocol.filter_name == "tcp"
                && expert.message.contains("TCP option is truncated")
                && !node
                    .fields
                    .iter()
                    .any(|field| field.def.abbrev == "tcp.option.len.invalid")
                && field_u64(node, "tcp.option_len").is_some_and(|declared| {
                    u64::try_from(node.range.length.saturating_sub(20)).unwrap_or(0) < declared
                });
            let ip_detail = node.protocol.filter_name == "ip"
                && (expert.message.contains("option is truncated")
                    || expert.message.contains("option length overflows"));
            let lldp_detail = node.protocol.filter_name == "lldp"
                && expert
                    .message
                    .contains("length of contained item exceeds length of containing item");
            if routing_detail || tcp_detail || ip_detail || lldp_detail {
                return Some("length of contained item exceeds length of containing item");
            }
        }
    }
    None
}

/// Whether this frame is reported as cut short by the capture-size limit.
pub(crate) fn capture_limited(frame: &Frame, packet: &Packet) -> bool {
    let captured = frame.captured.len();
    let original = usize::try_from(frame.original_len).unwrap_or(usize::MAX);
    if captured >= original {
        return false;
    }
    let chain = outer_chain(packet);
    let network_end = network_end_offset(&chain);
    network_end.is_none_or(|end| end < captured)
        || matches!(
            chain.last().map(|node| node.protocol.filter_name),
            Some("icmpv6" | "dns" | "mdns" | "llmnr")
        )
}

/// Offset just past the outermost IP datagram, in frame bytes.
fn network_end_offset(chain: &[&Node]) -> Option<usize> {
    for node in chain {
        match node.protocol.filter_name {
            "ip" => {
                let total = field_u64(node, "ip.len")?;
                return node.range.offset.checked_add(usize::try_from(total).ok()?);
            }
            "ipv6" => {
                let payload = field_u64(node, "ipv6.plen")?;
                return node
                    .range
                    .offset
                    .checked_add(40)?
                    .checked_add(usize::try_from(payload).ok()?);
            }
            _ => {}
        }
    }
    None
}

fn vlan_info(node: &Node) -> String {
    format!(
        "PRI: {}  DEI: {}  ID: {}",
        field_u64(node, "vlan.priority").unwrap_or(0),
        u8::from(field_bool(node, "vlan.dei")),
        field_u64(node, "vlan.id").unwrap_or(0)
    )
}

fn llc_info(node: &Node) -> String {
    let mut info = match field_u64(node, "llc.control") {
        Some(0x0003) => "U, func=UI".to_string(),
        Some(control) => format!("control 0x{control:04x}"),
        None => String::new(),
    };
    if let Some(oui) = field_u64(node, "llc.oui") {
        let pid = field_u64(node, "llc.pid").or_else(|| field_u64(node, "llc.cisco_pid"));
        if let Some(pid) = pid {
            if oui == 0x00000c {
                let _ = write!(
                    info,
                    "; SNAP, OUI 0x{oui:06X} (Cisco Systems, Inc), PID 0x{pid:04x}"
                );
            } else {
                let _ = write!(info, "; SNAP, OUI 0x{oui:06x} (Unknown), PID 0x{pid:04x}");
            }
        }
    }
    if field_u64(node, "llc.dsap") == Some(0x42) && field_u64(node, "llc.ssap") == Some(0x42) {
        info.push_str("; DSAP Spanning Tree BPDU Individual, SSAP Spanning Tree BPDU Command");
    }
    info
}

fn stp_info(node: &Node) -> String {
    let Some(bpdu_type) = field_u64(node, "stp.type") else {
        return String::new();
    };
    match bpdu_type {
        0 => stp_configuration_info(node, "Conf."),
        2 => {
            let prefix = if field_u64(node, "stp.version") == Some(3) {
                "MST."
            } else {
                "RST."
            };
            stp_configuration_info(node, prefix)
        }
        0x80 => "Topology Change Notification".to_string(),
        value => format!("Unknown BPDU type ({value})"),
    }
}

fn stp_configuration_info(node: &Node, prefix: &str) -> String {
    let (Some(priority), Some(extension), Some(cost), Some(port)) = (
        field_u64(node, "stp.root.prio"),
        field_u64(node, "stp.root.ext"),
        field_u64(node, "stp.root.cost"),
        field_u64(node, "stp.port"),
    ) else {
        return String::new();
    };
    let Some(address) = field_text(node, "stp.root.hw") else {
        return String::new();
    };
    let topology_change = if field_bool(node, "stp.flags.tc") {
        " TC +"
    } else {
        ""
    };
    format!(
        "{prefix}{topology_change} Root = {priority}/{extension}/{address}  Cost = {cost}  Port = 0x{port:04x}"
    )
}

fn lldp_info(frame: &Frame, node: &Node) -> String {
    let malformed = node.experts.iter().any(|expert| {
        expert.group == packetfin_core::tree::Group::Malformed && expert.severity == Severity::Error
    });
    let Some(chassis_subtype) = field_u64(node, "lldp.chassis.subtype") else {
        return if malformed {
            String::new()
        } else {
            "Invalid Chassis ID TLV".to_string()
        };
    };
    let Some(chassis) = lldp_chassis_text(node, chassis_subtype) else {
        return if malformed {
            String::new()
        } else {
            "Invalid Chassis ID TLV".to_string()
        };
    };
    let chassis_count = field_count(node, "lldp.chassis.subtype");
    let port_count = field_count(node, "lldp.port.subtype");
    let ttl_count = field_count(node, "lldp.time_to_live");
    if chassis_count > 1 && port_count >= 1 && ttl_count >= 1 {
        return "Duplicate Chassis ID TLV".to_string();
    }
    if port_count > 1 {
        return "Duplicate Port ID TLV".to_string();
    }
    if ttl_count > 1 {
        return "Duplicate Time-To-Live TLV".to_string();
    }
    let mut info = chassis;
    let Some(port_subtype) = field_u64(node, "lldp.port.subtype") else {
        return partial_lldp_info(info, malformed, "Invalid Port ID TLV");
    };
    let Some(port) = lldp_port_text(frame, node, port_subtype) else {
        return partial_lldp_info(info, malformed, "Invalid Port ID TLV");
    };
    info.push(' ');
    info.push_str(&port);
    let Some(time_to_live) = field_u64(node, "lldp.time_to_live") else {
        return partial_lldp_info(info, malformed, "Invalid Time-to-Live TLV");
    };
    let _ = write!(info, " {time_to_live}");
    if time_to_live == 0 {
        info.push_str(" (Shutdown LLDPDU)");
    }
    if let Some(name) = field_text(node, "lldp.tlv.system.name") {
        info.push_str(" SysN=");
        info.push_str(&name);
    }
    if let Some(description) = field_text(node, "lldp.tlv.system.desc") {
        info.push_str(" SysD=");
        info.push_str(&description);
    }
    info.push(' ');
    info
}

fn partial_lldp_info(mut info: String, malformed: bool, missing: &str) -> String {
    if malformed {
        info.push(' ');
        info
    } else {
        missing.to_string()
    }
}

fn lldp_chassis_text(node: &Node, subtype: u64) -> Option<String> {
    let (prefix, value) = match subtype {
        1 => ("CC", lldp_bytes_text(node, "lldp.chassis.id")?),
        2 => ("IA", lldp_bytes_text(node, "lldp.chassis.id")?),
        3 => ("PC", lldp_bytes_hex(node, "lldp.chassis.id")?),
        4 => ("MA", field_text(node, "lldp.chassis.id.mac")?),
        5 => (
            "NA",
            field_text(node, "lldp.chassis.id.ip4")
                .or_else(|| field_text(node, "lldp.chassis.id.ip6"))?,
        ),
        6 => ("IN", lldp_bytes_text(node, "lldp.chassis.id")?),
        7 => ("LA", lldp_bytes_text(node, "lldp.chassis.id")?),
        _ => return Some("Rs/Reserved".to_string()),
    };
    Some(format!("{prefix}/{value}"))
}

fn lldp_port_text(frame: &Frame, node: &Node, subtype: u64) -> Option<String> {
    let (prefix, value) = match subtype {
        1 => ("IA", field_text(node, "lldp.port.id")?),
        2 => ("PC", lldp_range_hex(frame, node, "lldp.port.id")?),
        3 => ("MA", field_text(node, "lldp.port.id.mac")?),
        4 => (
            "NA",
            field_text(node, "lldp.port.id.ip4")
                .or_else(|| field_text(node, "lldp.port.id.ip6"))?,
        ),
        5 => ("IN", field_text(node, "lldp.port.id")?),
        6 => ("AC", field_text(node, "lldp.port.id")?),
        7 => ("LA", field_text(node, "lldp.port.id")?),
        _ => return Some("Rs/Reserved".to_string()),
    };
    Some(format!("{prefix}/{value}"))
}

fn lldp_bytes_text(node: &Node, abbrev: &str) -> Option<String> {
    let bytes = field_bytes(node, abbrev)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn lldp_bytes_hex(node: &Node, abbrev: &str) -> Option<String> {
    let bytes = field_bytes(node, abbrev)?;
    Some(hex_string(&bytes))
}

fn lldp_range_hex(frame: &Frame, node: &Node, abbrev: &str) -> Option<String> {
    let field = find_field(node, abbrev)?;
    let bytes = frame
        .captured
        .get(field.range.offset..field.range.offset.saturating_add(field.range.length))?;
    Some(hex_string(bytes))
}

fn field_count(node: &Node, abbrev: &str) -> usize {
    let mut count = 0;
    let mut visit = |field: &packetfin_core::tree::Field| {
        if field.def.abbrev == abbrev {
            count += 1;
        }
    };
    for field in &node.fields {
        field.for_each_in_subtree(&mut visit);
    }
    count
}

fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn lacp_info(node: &Node) -> String {
    let version = field_u64(node, "lacp.version").unwrap_or(0);
    let mut info = format!("v{version}");
    if let (Some(system), Some(port), Some(key)) = (
        field_text(node, "lacp.actor.sysid"),
        field_u64(node, "lacp.actor.port"),
        field_u64(node, "lacp.actor.key"),
    ) {
        let flags = field_text(node, "lacp.actor.state_str").unwrap_or_default();
        let _ = write!(info, " ACTOR {system} P: {port} K: {key} {flags}");
    }
    if let (Some(system), Some(port), Some(key)) = (
        field_text(node, "lacp.partner.sysid"),
        field_u64(node, "lacp.partner.port"),
        field_u64(node, "lacp.partner.key"),
    ) {
        let flags = field_text(node, "lacp.partner.state_str").unwrap_or_default();
        let _ = write!(info, " PARTNER {system} P: {port} K: {key} {flags}");
    }
    info
}

fn marker_info(node: &Node) -> String {
    let label = match field_u64(node, "marker.tlvType") {
        Some(1) => "Information",
        Some(2) => "Response",
        _ => return "Marker Protocol".to_string(),
    };
    let (Some(system), Some(port), Some(transaction)) = (
        field_text(node, "marker.requesterSystem"),
        field_u64(node, "marker.requesterPort"),
        field_u64(node, "marker.requesterTransId"),
    ) else {
        return label.to_string();
    };
    format!("{label} SysId={system}, P={port}, TId={transaction}")
}

fn slow_info(node: &Node) -> String {
    field_u64(node, "slow.subtype")
        .map(|subtype| format!("Subtype = {subtype}"))
        .unwrap_or_default()
}

fn sll_info(node: &Node) -> String {
    match field_u64(node, "sll.pkttype") {
        Some(0) => "Host".to_string(),
        Some(1) => "Broadcast".to_string(),
        Some(2) => "Multicast".to_string(),
        Some(3) => "Otherhost".to_string(),
        Some(4) => "Outgoing".to_string(),
        _ => String::new(),
    }
}

fn sll2_info(node: &Node) -> String {
    // The unknown protocol value is read from the two bytes at
    // offset 10 (packet type and address length in this header revision).
    match (field_u64(node, "sll.pkttype"), field_u64(node, "sll.halen")) {
        (Some(packet_type), Some(address_length)) => {
            format!("Unknown ({})", (packet_type << 8) | address_length)
        }
        _ => String::new(),
    }
}

/// The enclosing tunnel's information-column caption for a short inner
/// Ethernet frame; the caption stays while the Ethernet decoder reports the
/// malformed payload.
fn tunnel_caption(chain: &[&Node], eth_index: usize) -> Option<String> {
    let parent = chain.get(eth_index.checked_sub(1)?)?;
    match parent.protocol.filter_name {
        "geneve" => Some(encapsulated_info(parent, "geneve.proto_type", false)),
        "gre" => Some(encapsulated_info(parent, "gre.proto", true)),
        "erspan" => Some("ERSPAN:".to_string()),
        "vxlan" => Some(String::new()),
        _ => None,
    }
}

fn display_protocol(filter_name: &str) -> &'static str {
    match filter_name {
        "eth" => "Ethernet",
        "llc" => "LLC",
        "stp" => "STP",
        "lldp" => "LLDP",
        "lacp" => "LACP",
        "marker" => "Marker",
        "slow" => "Slow Protocols",
        "vlan" => "VLAN",
        "ieee8021ad" => "IEEE 802.1AD",
        "sll" => "SLL",
        "null" => "Null",
        "arp" => "ARP",
        "ip" => "IPv4",
        "ipv6" => "IPv6",
        "udp" => "UDP",
        "tcp" => "TCP",
        "icmp" => "ICMP",
        "icmpv6" => "ICMPv6",
        "erspan" => "ERSPAN",
        "geneve" => "Geneve",
        "gre" => "GRE",
        "mpls" => "MPLS",
        "vxlan" => "VxLAN",
        "ospf" => "OSPF",
        "vrrp" => "VRRP",
        "bfd" => "BFD Control",
        "bfd_echo" => "BFD Echo",
        "syslog" => "Syslog",
        "sflow" => "sFlow",
        "cflow" => "CFLOW",
        "snmp" => "SNMP",
        _ => "",
    }
}

/// The tunnel summary for an encapsulated protocol type.
fn encapsulated_info(node: &Node, abbrev: &str, uppercase: bool) -> String {
    let Some(value) = field_u64(node, abbrev) else {
        return String::new();
    };
    match value_name(abbrev, value) {
        Some(name) => format!("Encapsulated {name}"),
        None if uppercase => format!("Encapsulated 0x{value:04X} (unknown)"),
        None => format!("Encapsulated 0x{value:04x} (unknown)"),
    }
}

fn arp_info(node: &Node) -> String {
    let Some(opcode) = field_u64(node, "arp.opcode") else {
        return String::new();
    };
    let source = field_text(node, "arp.src.proto_ipv4").unwrap_or_default();
    let target = field_text(node, "arp.dst.proto_ipv4").unwrap_or_default();
    match opcode {
        1 => format!("Who has {target}? Tell {source}"),
        2 => format!(
            "{source} is at {}",
            field_text(node, "arp.src.hw_mac").unwrap_or_default()
        ),
        _ => String::new(),
    }
}

fn ospf_info(node: &Node) -> String {
    let Some(message_type) = field_u64(node, "ospf.msg") else {
        return String::new();
    };
    match packetfin_core::fields::value_name("ospf.msg", message_type) {
        Some(name) => name.to_string(),
        None => format!("Unknown ({message_type})"),
    }
}

fn vrrp_info(node: &Node) -> String {
    let Some(version) = field_u64(node, "vrrp.version") else {
        return String::new();
    };
    format!("Announcement (v{version})")
}

fn bfd_info(node: &Node) -> String {
    let Some(flags) = field_u64(node, "bfd.flags") else {
        return String::new();
    };
    let version = field_u64(node, "bfd.version").unwrap_or(1);
    let diagnostic = field_u64(node, "bfd.diag").unwrap_or(0);
    let diagnostic_name = packetfin_core::fields::value_name("bfd.diag", diagnostic)
        .map(str::to_string)
        .unwrap_or_else(|| "Unknown".to_string());
    if version == 0 {
        return format!("Diag: {diagnostic_name}, Flags: 0x{flags:02x}");
    }
    let state = field_u64(node, "bfd.sta").unwrap_or(0);
    let state_name = packetfin_core::fields::value_name("bfd.sta", state)
        .map(str::to_string)
        .unwrap_or_else(|| "Unknown".to_string());
    format!(
        "Diag: {diagnostic_name}, State: {state_name}, Flags: 0x{:02x}",
        flags & 0x3f
    )
}

fn ipv4_info(node: &Node, forced_data: bool) -> String {
    let captured = u64::try_from(node.range.length).unwrap_or(u64::MAX);
    let header = field_u64(node, "ip.hdr_len");
    if let Some(header) = header
        && header < 20
        && captured >= header
    {
        return format!("Bogus IP header length ({header}, must be at least 20)");
    }
    let Some(header) = header else {
        return String::new();
    };
    if captured < header {
        return String::new();
    }
    let Some(total) = field_u64(node, "ip.len") else {
        return String::new();
    };
    if total < header {
        return format!("Bogus IP length ({total}, less than header length {header})");
    }
    let protocol = field_u64(node, "ip.proto").unwrap_or(0);
    let completed = subtree_field_u64(node, "ip.reassembled.length").is_some();
    let fragmented = field_bool(node, "ip.flags.mf")
        || field_u64(node, "ip.frag_offset").is_some_and(|offset| offset > 0);
    if fragmented && !completed {
        let offset = field_u64(node, "ip.frag_offset").unwrap_or(0) * 8;
        let id = field_u64(node, "ip.id").unwrap_or(0);
        return format!(
            "Fragmented IP protocol (proto={} {protocol}, off={offset}, ID={id:04x})",
            ip_protocol_name(protocol)
        );
    }
    if !is_registered_transport(protocol) && total > header {
        return format!("Unknown ({protocol})");
    }
    if !forced_data
        && is_registered_transport(protocol)
        && node.children.is_empty()
        && total > header
    {
        return format!("{} ({protocol})", ip_protocol_name(protocol));
    }
    String::new()
}

fn is_registered_transport(protocol: u64) -> bool {
    matches!(protocol, 1 | 4 | 6 | 17 | 41 | 47 | 58)
}

fn ip_protocol_name(protocol: u64) -> &'static str {
    match protocol {
        1 => "ICMP",
        4 => "IPIP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        47 => "Generic Routing Encapsulation",
        58 => "ICMPv6",
        _ => "Unknown",
    }
}

fn ipv6_info(node: &Node, forced_data: bool) -> String {
    let captured = u64::try_from(node.range.length).unwrap_or(u64::MAX);
    if captured == 0 {
        return String::new();
    }
    if captured < 40 {
        return format!("Invalid IPv6 header ({captured} bytes, need exactly 40)");
    }
    if node
        .experts
        .iter()
        .any(|expert| expert.group == packetfin_core::tree::Group::Malformed)
    {
        return String::new();
    }
    if let Some(next) = field_u64(node, "ipv6.nxt") {
        if next == 59 {
            return "IPv6 no next header".to_string();
        }
        if !is_registered_ip_protocol(next)
            && field_u64(node, "ipv6.plen").is_some_and(|len| len > 0)
        {
            return format!("Unknown IP Protocol: Unknown ({next})");
        }
    }
    let next_header = field_u64(node, "ipv6.nxt").unwrap_or(0);
    if !forced_data && is_registered_transport(next_header) && node.children.is_empty() {
        return format!(
            "Unknown IP Protocol: {} ({next_header})",
            ip_protocol_name(next_header)
        );
    }
    String::new()
}

/// Whether a next-header value has a decoder or is an IPv6 extension.
fn is_registered_ip_protocol(protocol: u64) -> bool {
    matches!(
        protocol,
        0 | 1 | 4 | 6 | 17 | 41 | 43 | 44 | 47 | 58 | 59 | 60 | 89 | 112
    )
}

fn ext_next_header(filter_name: &str) -> &str {
    match filter_name {
        "ipv6.hopopts" => "ipv6.hopopts.nxt",
        "ipv6.dstopts" => "ipv6.dstopts.nxt",
        "ipv6.routing" => "ipv6.routing.nxt",
        "ipv6.fraghdr" => "ipv6.fraghdr.nxt",
        _ => "ipv6.nxt",
    }
}

fn ipv6_extension_info(filter_name: &str) -> String {
    match filter_name {
        "ipv6.hopopts" => "IPv6 hop-by-hop options".to_string(),
        "ipv6.dstopts" => "IPv6 destination options".to_string(),
        "ipv6.routing" => "IPv6 routing".to_string(),
        "ipv6.fraghdr" => "IPv6 fragment header".to_string(),
        _ => String::new(),
    }
}

#[derive(Default)]
struct DnsQuestion {
    name: Option<String>,
    rtype: Option<u64>,
    qu: bool,
}

#[derive(Default)]
struct DnsRecord {
    rtype: u64,
    cache_flush: bool,
    data: Option<String>,
    preference: Option<u64>,
    exchange: Option<String>,
    mname: Option<String>,
    srv: [Option<String>; 3],
    srv_target: Option<String>,
}

impl DnsRecord {
    fn data_text(&self) -> Option<String> {
        match self.rtype {
            1 | 28 => self.data.clone(),
            2 | 5 | 12 => self.data.clone(),
            15 => Some(format!(
                "{} {}",
                self.preference?,
                self.exchange.as_deref()?
            )),
            6 => self.mname.clone(),
            33 => Some(format!(
                "{} {} {} {}",
                self.srv[0].as_deref()?,
                self.srv[1].as_deref()?,
                self.srv[2].as_deref()?,
                self.srv_target.as_deref()?
            )),
            _ => None,
        }
    }
}

/// One-line sFlow description, built from the decoded header.
fn sflow_info(node: &Node) -> String {
    let mut info = String::new();
    if let Some(version) = field_u64(node, "sflow_245.version") {
        let _ = write!(info, "V{version}");
    }
    if let Some(agent) =
        field_text(node, "sflow_245.agent").or_else(|| field_text(node, "sflow_245.agent.v6"))
    {
        let _ = write!(info, ", agent {agent}");
    }
    if let Some(sub_agent) = field_u64(node, "sflow_245.sub_agent_id") {
        let _ = write!(info, ", sub-agent ID {sub_agent}");
    }
    if let Some(sequence) = field_u64(node, "sflow_245.sequence_number") {
        let _ = write!(info, ", seq {sequence}");
    }
    if let Some(samples) = field_u64(node, "sflow_245.numsamples") {
        let _ = write!(info, ", {samples} samples");
    }
    info
}

/// One-line NetFlow description.
///
/// v9 prints the header's flow-set count and source ID; IPFIX uses the
/// declared PDU length and observation domain. Either form appends one
/// bracketed descriptor per parsed set, in wire order.
fn cflow_info(node: &Node) -> String {
    let Some(version) = field_u64(node, "cflow.version") else {
        return String::new();
    };
    let mut info = String::new();
    match version {
        9 => {
            let Some(count) = field_u64(node, "cflow.count") else {
                return String::new();
            };
            let plural = if count == 1 { "" } else { "s" };
            let _ = write!(info, "total: {count} (v9) record{plural}");
            if let Some(source_id) = field_u64(node, "cflow.source_id") {
                let _ = write!(info, " Obs-Domain-ID={source_id:>5}");
            }
        }
        10 => {
            let actual = node.range.length;
            let Some(declared) = field_u64(node, "cflow.len") else {
                // A 2- or 3-octet IPFIX datagram has no length field; the
                // summary shows only its malformed marker.
                return String::new();
            };
            if declared == actual as u64 {
                let _ = write!(info, "IPFIX flow ({actual:4} bytes)");
            } else {
                let _ = write!(info, "IPFIX partial flow ({actual}/{declared} bytes)");
            }
            if let Some(domain) = field_u64(node, "cflow.od_id") {
                let _ = write!(info, " Obs-Domain-ID={domain:>5}");
            }
        }
        _ => {
            let Some(count) = field_u64(node, "cflow.count") else {
                return String::new();
            };
            let plural = if count == 1 { "" } else { "s" };
            let _ = write!(info, "total: {count} (v{version}) flow{plural}");
        }
    }
    append_cflow_set_descriptors(node, &mut info);
    info
}

/// Append the `[Data-Template:...]`, `[Options-Template:...]` and
/// `[Data:...]` descriptors for every parsed set.
fn append_cflow_set_descriptors(node: &Node, info: &mut String) {
    for field in &node.fields {
        if !std::ptr::eq(field.def, &fields::CFLOW_FLOWSET) {
            continue;
        }
        let Some(set_id) = field
            .children
            .iter()
            .find(|child| child.def.abbrev == "cflow.flowset_id")
            .and_then(field_value_u64)
        else {
            continue;
        };
        // A set whose declared length is below the four-byte header gets a
        // detail node and an expert but no summary descriptor.
        let set_length = field
            .children
            .iter()
            .find(|child| child.def.abbrev == "cflow.flowset_length")
            .and_then(field_value_u64)
            .unwrap_or(0);
        if set_length < 4 {
            continue;
        }
        match set_id {
            0 | 2 => {
                let ids = cflow_template_ids(field);
                let _ = write!(info, " [Data-Template:{}]", ids.join(","));
            }
            1 | 3 => {
                let ids = cflow_template_ids(field);
                let _ = write!(info, " [Options-Template:{}]", ids.join(","));
            }
            256.. => {
                let _ = write!(info, " [Data:{set_id}]");
            }
            _ => {}
        }
    }
}

/// Template IDs in one template set, in wire order.
fn cflow_template_ids(flowset: &packetfin_core::tree::Field) -> Vec<String> {
    flowset
        .children
        .iter()
        .filter(|child| std::ptr::eq(child.def, &fields::CFLOW_TEMPLATE))
        .filter_map(|template| {
            template
                .children
                .iter()
                .find(|child| child.def.abbrev == "cflow.template_id")
                .and_then(field_value_u64)
        })
        .map(|id| id.to_string())
        .collect()
}

/// One-line SNMP description: the PDU name and its varbind names.
///
/// A version-1 trap also names its enterprise, prefixed with `iso.`.
fn snmp_info(node: &Node) -> Option<String> {
    const PDUS: [(&str, &str); 9] = [
        ("snmp.get_request_element", "get-request"),
        ("snmp.get_next_request_element", "get-next-request"),
        ("snmp.get_response_element", "get-response"),
        ("snmp.set_request_element", "set-request"),
        ("snmp.trap_element", "trap"),
        ("snmp.getBulkRequest_element", "getBulkRequest"),
        ("snmp.informRequest_element", "informRequest"),
        ("snmp.snmpV2_trap_element", "snmpV2-trap"),
        ("snmp.report_element", "report"),
    ];
    let (abbrev, name) = PDUS
        .iter()
        .find(|(abbrev, _)| node.fields.iter().any(|field| field.def.abbrev == *abbrev))
        .copied()?;
    let mut info = name.to_string();
    if abbrev == "snmp.trap_element"
        && let Some(enterprise) = oid_field_text(node, "snmp.enterprise")
    {
        let _ = write!(info, " {enterprise}");
    }
    let mut names: Vec<String> = Vec::new();
    for field in &node.fields {
        match field.def.abbrev {
            "snmp.name" => {
                if let Value::Oid(ids) = &field.value {
                    names.push(packetfin_core::tree::oid_text(ids));
                }
            }
            "snmp.varbind.wrong_tag" => {
                // The failing varbind is omitted from the summary; varbinds
                // after it still decode and appear.
                names.pop();
            }
            _ => {}
        }
    }
    for name in names {
        let _ = write!(info, " {name}");
    }
    Some(info)
}

fn oid_field_text(node: &Node, abbrev: &str) -> Option<String> {
    node.fields.iter().find_map(|field| {
        if field.def.abbrev == abbrev
            && let Value::Oid(ids) = &field.value
        {
            return Some(packetfin_core::tree::oid_resolved_text(ids));
        }
        None
    })
}

/// The protocol name and one-line description of a DHCP or BOOTP message.
fn dhcp_info(node: &Node) -> (&'static str, String) {
    if let Some(message_type) = packetfin_core::decode::dhcp_main_area_message_type(node) {
        let name = match packetfin_core::fields::value_name("dhcp.option.dhcp", message_type) {
            Some(name) => format!("{name:<8}"),
            None => format!("Unknown Message Type (0x{message_type:02x})"),
        };
        let transaction = field_u64(node, "dhcp.id").unwrap_or(0);
        return (
            "DHCP",
            format!("DHCP {name} - Transaction ID 0x{transaction:08x}"),
        );
    }
    let Some(op) = field_u64(node, "dhcp.type") else {
        return ("BOOTP", String::new());
    };
    let text = match op {
        1 => {
            let address = if let Some(mac) = field_text(node, "dhcp.hw.mac_addr") {
                format!("{mac} ({mac})")
            } else if let Some(raw) = field_text(node, "dhcp.hw.addr") {
                raw
            } else {
                "<No address>".to_string()
            };
            format!("Boot Request from {address}")
        }
        2 => "Boot Reply".to_string(),
        other => format!("Unknown BOOTP message type ({other})"),
    };
    ("BOOTP", text)
}

/// One-line DHCPv6 description, built from the chain's first `dhcpv6` node.
fn dhcpv6_info(chain: &[&Node]) -> String {
    let Some(node) = chain
        .iter()
        .copied()
        .find(|node| node.protocol.filter_name == "dhcpv6")
    else {
        return String::new();
    };
    dhcpv6_segment(&dhcpv6_segments(node))
}

struct Dhcpv6Segment {
    name: String,
    relay: bool,
    link: Option<String>,
    xid: Option<u64>,
    client_id: Option<String>,
    addresses: Vec<String>,
}

fn dhcpv6_segments(node: &Node) -> Vec<Dhcpv6Segment> {
    let mut segments: Vec<Dhcpv6Segment> = Vec::new();
    let mut current_option = None;
    let _ = node.try_for_each_field(&mut |field| -> Result<(), ()> {
        match field.def.abbrev {
            "dhcpv6.msgtype" => {
                let message_type = field_value_u64(field).unwrap_or(0);
                let name = packetfin_core::fields::value_name("dhcpv6.msgtype", message_type)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("Message Type {message_type}"));
                segments.push(Dhcpv6Segment {
                    name,
                    relay: matches!(message_type, 12 | 13),
                    link: None,
                    xid: None,
                    client_id: None,
                    addresses: Vec::new(),
                });
            }
            "dhcpv6.linkaddr" => {
                if let Some(segment) = segments.last_mut()
                    && segment.relay
                {
                    segment.link = field_text_value(field);
                }
            }
            "dhcpv6.xid" => {
                if let Some(segment) = segments.last_mut() {
                    segment.xid = field_value_u64(field);
                }
            }
            "dhcpv6.option.type" => current_option = field_value_u64(field),
            "dhcpv6.duid.bytes" if current_option == Some(1) => {
                if let Some(segment) = segments.last_mut()
                    && segment.client_id.is_none()
                    && let Value::Bytes(bytes) = &field.value
                {
                    segment.client_id = Some(packetfin_core::decode::hex_lower(bytes));
                }
            }
            "dhcpv6.iaaddr.ip" => {
                if let Some(segment) = segments.last_mut()
                    && let Some(text) = field_text_value(field)
                {
                    segment.addresses.push(text);
                }
            }
            _ => {}
        }
        Ok(())
    });
    segments
}

fn dhcpv6_segment(segments: &[Dhcpv6Segment]) -> String {
    let Some(first) = segments.first() else {
        return String::new();
    };
    if first.relay {
        let mut text = first.name.clone();
        if let Some(link) = &first.link {
            let _ = write!(text, " L: {link}");
        }
        if let Some(client_id) = &first.client_id {
            let _ = write!(text, " CID: {client_id}");
        }
        text.push(' ');
        if segments.len() > 1 {
            text.push_str(&dhcpv6_segment(segments.get(1..).unwrap_or(&[])));
        }
        return text;
    }
    let mut text = match first.xid {
        Some(xid) => format!("{} XID: 0x{xid:06x}", first.name),
        None => first.name.clone(),
    };
    if let Some(client_id) = &first.client_id {
        let _ = write!(text, " CID: {client_id}");
    }
    for address in &first.addresses {
        let _ = write!(text, " IAA: {address}");
    }
    text.push(' ');
    if segments.len() > 1 {
        text.push_str(&dhcpv6_segment(segments.get(1..).unwrap_or(&[])));
    }
    text
}

fn ntp_info(node: &Node) -> String {
    let Some(flags) = field_u64(node, "ntp.flags") else {
        return String::new();
    };
    ntp_status_text(flags)
}

/// The `NTP Version N, mode` text used by the summary and detail header.
pub(crate) fn ntp_status_text(flags: u64) -> String {
    let version = packetfin_core::fields::value_name("ntp.flags.vn", (flags >> 3) & 0x7)
        .unwrap_or("reserved");
    let mode = match flags & 0x7 {
        6 => "control",
        7 => "private",
        other => packetfin_core::fields::value_name("ntp.flags.mode", other).unwrap_or("reserved"),
    };
    format!("{version}, {mode}")
}

fn dns_info(node: &Node, mdns: bool) -> String {
    let mut info = String::new();
    if let Some(flags) = field_u64(node, "dns.flags") {
        let response = field_bool(node, "dns.flags.response");
        let opcode = field_u64(node, "dns.flags.opcode").unwrap_or(flags >> 11 & 0xf);
        info.push_str(&packetfin_core::decode::opcode_text(
            u16::try_from(opcode).unwrap_or(0),
        ));
        if response {
            info.push_str(" response");
        }
        if let Some(id) = field_u64(node, "dns.id") {
            let _ = write!(info, " 0x{id:04x}");
        }
        if response && let Some(rcode) = field_u64(node, "dns.flags.rcode") {
            let rcode = u16::try_from(rcode).unwrap_or(0);
            if rcode != 0 {
                let text = packetfin_core::decode::rcode_text(rcode).map_or_else(
                    || format!("Unknown error ({rcode})"),
                    |name| name.to_string(),
                );
                let _ = write!(info, " {text}");
            }
        }
    }

    let mut questions: Vec<DnsQuestion> = Vec::new();
    let mut records: Vec<DnsRecord> = Vec::new();
    let mut question: Option<DnsQuestion> = None;
    let mut record: Option<DnsRecord> = None;
    for field in &node.fields {
        match field.def.abbrev {
            "dns.qry.name" => {
                questions.extend(question.take());
                question = Some(DnsQuestion {
                    name: field_text_value(field),
                    ..DnsQuestion::default()
                });
            }
            "dns.qry.type" => {
                if let Some(question) = question.as_mut() {
                    question.rtype = field_value_u64(field);
                }
            }
            "dns.qry.qu" => {
                if let Some(question) = question.as_mut() {
                    question.qu = matches!(field.value, Value::Boolean(true));
                }
            }
            "dns.resp.type" => {
                records.extend(record.take());
                record = Some(DnsRecord {
                    rtype: field_value_u64(field).unwrap_or(0),
                    ..DnsRecord::default()
                });
            }
            "dns.resp.cache_flush" => {
                if let Some(record) = record.as_mut() {
                    record.cache_flush = matches!(field.value, Value::Boolean(true));
                }
            }
            "dns.a" | "dns.aaaa" | "dns.cname" | "dns.ns" | "dns.ptr.domain_name" => {
                if let Some(record) = record.as_mut() {
                    record.data = field_text_value(field);
                }
            }
            "dns.mx.preference" => {
                if let Some(record) = record.as_mut() {
                    record.preference = field_value_u64(field);
                }
            }
            "dns.mx.mail_exchange" => {
                if let Some(record) = record.as_mut() {
                    record.exchange = field_text_value(field);
                }
            }
            "dns.soa.mname" => {
                if let Some(record) = record.as_mut() {
                    record.mname = field_text_value(field);
                }
            }
            "dns.srv.priority" => set_srv(&mut record, 0, field),
            "dns.srv.weight" => set_srv(&mut record, 1, field),
            "dns.srv.port" => set_srv(&mut record, 2, field),
            "dns.srv.target" => {
                if let Some(record) = record.as_mut() {
                    record.srv_target = field_text_value(field);
                }
            }
            _ => {}
        }
    }
    questions.extend(question);
    records.extend(record);

    for question in &questions {
        if let Some(rtype) = question.rtype {
            let _ = write!(info, " {}", packetfin_core::decode::type_text(rtype as u16));
        }
        if let Some(name) = &question.name {
            let _ = write!(info, " {name}");
        }
        if mdns {
            info.push_str(if question.qu {
                ", \"QU\" question"
            } else {
                ", \"QM\" question"
            });
        }
    }
    for record in &records {
        let _ = write!(
            info,
            " {}",
            packetfin_core::decode::type_text(u16::try_from(record.rtype).unwrap_or(0))
        );
        if mdns && record.cache_flush {
            info.push_str(", cache flush");
        }
        if let Some(data) = record.data_text() {
            let _ = write!(info, " {data}");
        }
    }
    info
}

fn set_srv(record: &mut Option<DnsRecord>, index: usize, field: &packetfin_core::tree::Field) {
    if let Some(record) = record.as_mut()
        && let Some(slot) = record.srv.get_mut(index)
    {
        *slot = field_text_value(field);
    }
}

fn udp_info(node: &Node, packet: &Packet, chain: &[&Node]) -> String {
    let (Some(source), Some(destination)) = (
        field_u64(node, "udp.srcport"),
        field_u64(node, "udp.dstport"),
    ) else {
        return String::new();
    };
    let mut info = format!(
        "{} \u{2192} {}",
        port_text(source, false, packet.resolution),
        port_text(destination, false, packet.resolution)
    );
    if let Some(length) = field_u64(node, "udp.length") {
        if length < 8 {
            let _ = write!(info, " [BAD UDP LENGTH {length} < 8]");
            return info;
        }
        let payload = network_payload_length(chain).unwrap_or(length);
        if length > payload {
            let _ = write!(info, " [BAD UDP LENGTH {length} > IP PAYLOAD LENGTH]");
        }
        let _ = write!(info, " Len={}", length - 8);
    }
    if field_u64(node, "udp.checksum") == Some(0)
        && matches!(packet.network, Some(NetworkContext::Ipv6 { .. }))
    {
        info.push_str(" [ILLEGAL CHECKSUM (0)]");
    }
    info
}

/// The summary form of a transport port: `name(port)` when transport names
/// are enabled and the registry knows the port, otherwise the number.
fn port_text(port: u64, tcp: bool, resolution: Resolution) -> String {
    if resolution.transport
        && let Ok(port) = u16::try_from(port)
        && let Some(name) = service_name(port, tcp)
    {
        return format!("{name}({port})");
    }
    port.to_string()
}

/// The outer IP payload length, when the network header carries one.
fn network_payload_length(chain: &[&Node]) -> Option<u64> {
    // A transport decoded from a reassembled datagram belongs to the
    // innermost IP layer, which may sit below a tunnel header whose payload
    // is only one fragment.
    let mut reassembled = None;
    for node in chain {
        if let Some(length) = subtree_field_u64(node, "ip.reassembled.length")
            .or_else(|| subtree_field_u64(node, "ipv6.reassembled.length"))
        {
            reassembled = Some(length);
        }
    }
    if let Some(length) = reassembled {
        return Some(length);
    }
    for node in chain {
        match node.protocol.filter_name {
            "ip" => {
                if let (Some(total), Some(header)) =
                    (field_u64(node, "ip.len"), field_u64(node, "ip.hdr_len"))
                {
                    return Some(total.saturating_sub(header));
                }
            }
            "ipv6" => {
                if let Some(length) = field_u64(node, "ipv6.plen") {
                    return Some(length);
                }
            }
            _ => {}
        }
    }
    None
}

/// The first numeric occurrence of a field anywhere below `node`.
fn subtree_field_u64(node: &Node, abbrev: &str) -> Option<u64> {
    node.fields
        .iter()
        .find_map(|field| field_subtree_u64(field, abbrev))
}

fn field_subtree_u64(field: &packetfin_core::tree::Field, abbrev: &str) -> Option<u64> {
    if field.def.abbrev == abbrev {
        return field_value_u64(field);
    }
    field
        .children
        .iter()
        .find_map(|child| field_subtree_u64(child, abbrev))
}

fn tcp_has_segment_error(node: &Node) -> bool {
    let mut found = false;
    let _ = node.try_for_each_field::<()>(&mut |field| {
        if field.def.abbrev == "tcp.segment.error" {
            found = true;
        }
        Ok(())
    });
    found
}

/// The TCP analysis tags, in the order the Info column shows them.
///
/// The flags live inside the `tcp.analysis` and `tcp.analysis.flags`
/// containers, so the walk covers the node's field subtree. Of the
/// retransmission family, only the most specific tag is shown.
fn tcp_analysis_tags(node: &Node) -> Option<String> {
    let mut present: Vec<&str> = Vec::new();
    let mut duplicate: Option<(u64, u64)> = None;
    let mut number = None;
    let mut frame = None;
    let _ = node.try_for_each_field::<()>(&mut |field| {
        present.push(field.def.abbrev);
        match field.def.abbrev {
            "tcp.analysis.duplicate_ack_num" => {
                if let Value::Uint32(value) = field.value {
                    number = Some(u64::from(value));
                }
            }
            "tcp.analysis.duplicate_ack_frame" => {
                if let Value::Uint32(value) = field.value {
                    frame = Some(u64::from(value));
                }
            }
            _ => {}
        }
        Ok(())
    });
    if let (Some(number), Some(frame)) = (number, frame) {
        duplicate = Some((number, frame));
    }
    let flag = |abbrev: &str| present.contains(&abbrev);
    let mut tags: Vec<String> = Vec::with_capacity(4);
    if flag("tcp.analysis.zero_window_probe_ack") {
        tags.push("[TCP ZeroWindowProbeAck]".to_string());
    }
    if flag("tcp.analysis.zero_window") {
        tags.push("[TCP ZeroWindow]".to_string());
    }
    if flag("tcp.analysis.zero_window_probe") {
        tags.push("[TCP ZeroWindowProbe]".to_string());
    }
    if let Some((number, frame)) = duplicate {
        tags.push(format!("[TCP Dup ACK {frame}#{number}]"));
    }
    if flag("tcp.analysis.keep_alive_ack") {
        tags.push("[TCP Keep-Alive ACK]".to_string());
    }
    if flag("tcp.analysis.keep_alive") {
        tags.push("[TCP Keep-Alive]".to_string());
    }
    if flag("tcp.analysis.window_update") {
        tags.push("[TCP Window Update]".to_string());
    }
    if flag("tcp.analysis.ack_lost_segment") {
        tags.push("[TCP ACKed unseen segment]".to_string());
    }
    if flag("tcp.analysis.lost_segment") {
        tags.push("[TCP Previous segment not captured]".to_string());
    }
    if flag("tcp.analysis.out_of_order") {
        tags.push("[TCP Out-Of-Order]".to_string());
    }
    if flag("tcp.analysis.spurious_retransmission") {
        tags.push("[TCP Spurious Retransmission]".to_string());
    } else if flag("tcp.analysis.fast_retransmission") {
        tags.push("[TCP Fast Retransmission]".to_string());
    } else if flag("tcp.analysis.retransmission") {
        tags.push("[TCP Retransmission]".to_string());
    }
    if flag("tcp.analysis.reused_ports") {
        tags.push("[TCP Port numbers reused]".to_string());
    }
    (!tags.is_empty()).then(|| tags.join(" "))
}

/// Whether text is an HTTP/1.x request or status line.
fn is_http_start_line(text: &str) -> bool {
    if text.starts_with("HTTP/1.") {
        return true;
    }
    let mut parts = text.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(uri) = parts.next() else {
        return false;
    };
    !method.is_empty()
        && !uri.is_empty()
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
        && parts
            .next()
            .is_some_and(|version| version.starts_with("HTTP/1."))
}

fn tcp_info(node: &Node, resolution: Resolution) -> String {
    let (Some(source), Some(destination)) = (
        field_u64(node, "tcp.srcport"),
        field_u64(node, "tcp.dstport"),
    ) else {
        return String::new();
    };
    let mut info = format!(
        "{} \u{2192} {}",
        port_text(source, true, resolution),
        port_text(destination, true, resolution)
    );
    let mut details = String::new();
    let flags = tcp_flags(node);
    if !flags.is_empty() {
        let _ = write!(details, " [{}]", flags.join(", "));
    }
    if let Some(sequence) = field_u64(node, "tcp.seq") {
        let _ = write!(details, " Seq={sequence}");
    }
    if field_bool(node, "tcp.flags.ack")
        && let Some(acknowledgement) = field_u64(node, "tcp.ack")
    {
        let _ = write!(details, " Ack={acknowledgement}");
    }
    // The summary shows the scaled window; the raw value is a separate
    // field. A raw window of 4096 with a scale factor of 128 prints Win=524288.
    if let Some(window) =
        field_u64(node, "tcp.window_size").or_else(|| field_u64(node, "tcp.window_size_value"))
    {
        let _ = write!(details, " Win={window}");
    }
    let header_length = field_u64(node, "tcp.hdr_len");
    if let Some(length) = field_u64(node, "tcp.len")
        && !header_length.is_some_and(|header| header < 20)
    {
        let _ = write!(details, " Len={length}");
    }
    // SACK edges are already relative to the acknowledgement base when
    // relative numbering is active (see `parse_sack`).
    for field in &node.fields {
        match field.def.abbrev {
            "tcp.options.sack_le" => {
                if let Value::Uint32(left) = field.value {
                    let _ = write!(details, " SLE={left}");
                }
            }
            "tcp.options.sack_re" => {
                if let Value::Uint32(right) = field.value {
                    let _ = write!(details, " SRE={right}");
                }
            }
            _ => {}
        }
    }
    if let Some(mss) = field_u64(node, "tcp.options.mss_val") {
        let _ = write!(details, " MSS={mss}");
    }
    if tcp_has_option_kind(node, 4) {
        details.push_str(" SACK_PERM");
    }
    if let Some(multiplier) = field_u64(node, "tcp.options.wscale.multiplier") {
        let _ = write!(details, " WS={multiplier}");
    }
    if let (Some(tsval), Some(tsecr)) = (
        field_u64(node, "tcp.options.timestamp.tsval"),
        field_u64(node, "tcp.options.timestamp.tsecr"),
    ) {
        let _ = write!(details, " TSval={tsval} TSecr={tsecr}");
    }
    if let Some(header) = header_length
        && header < 20
    {
        let _ = write!(
            details,
            ", bogus TCP header length ({header}, must be at least 20)"
        );
    }
    info.push_str(&details);
    info
}

fn tcp_has_option_kind(node: &Node, kind: u64) -> bool {
    node.fields.iter().any(|field| {
        field.def.abbrev == "tcp.option_kind"
            && matches!(field.value, Value::Uint8(value) if u64::from(value) == kind)
    })
}

fn tcp_flags(node: &Node) -> Vec<&'static str> {
    let mut flags = Vec::with_capacity(8);
    for (abbrev, name) in [
        ("tcp.flags.fin", "FIN"),
        ("tcp.flags.syn", "SYN"),
        ("tcp.flags.reset", "RST"),
        ("tcp.flags.push", "PSH"),
        ("tcp.flags.ack", "ACK"),
        ("tcp.flags.urg", "URG"),
        ("tcp.flags.ece", "ECE"),
        ("tcp.flags.cwr", "CWR"),
    ] {
        if field_bool(node, abbrev) {
            flags.push(name);
        }
    }
    flags
}

fn icmp_info(node: &Node, chain: &[&Node]) -> String {
    let Some(message_type) = field_u64(node, "icmp.type") else {
        return String::new();
    };
    let code = field_u64(node, "icmp.code").unwrap_or(0);
    let ttl = outer_network_hop_limit(chain);
    match message_type {
        0 | 8 => echo_info(node, message_type == 8, ttl),
        13 | 14 => timestamp_info(node, message_type == 13, ttl),
        9 => format!("Mobile IP Advertisement ({})", icmp_code_name(9, code)),
        10 => "Router solicitation ".to_string(),
        42 | 43 => format!(
            "Extended Echo {} ({})",
            if message_type == 42 {
                "Request"
            } else {
                "Reply"
            },
            icmp_code_name(42, code)
        ),
        3 => format!(
            "{:<20} ({})",
            "Destination unreachable",
            icmp_code_name(3, code)
        ),
        5 => format!("{:<20} ({})", "Redirect", icmp_code_name(5, code)),
        11 => format!(
            "{:<20} ({})",
            "Time-to-live exceeded",
            icmp_code_name(11, code)
        ),
        12 => format!("{:<20} ({})", "Parameter problem", icmp_code_name(12, code)),
        other => format!("Type {other}"),
    }
}

fn echo_info(node: &Node, request: bool, ttl: Option<u64>) -> String {
    let name = if request { "request" } else { "reply" };
    let mut info = format!("Echo (ping) {name:<7} ");
    let identifier = field_u64(node, "icmp.ident");
    let sequence = field_u64(node, "icmp.seq");
    let sequence_le = field_u64(node, "icmp.seq_le");
    if let (Some(identifier), Some(sequence), Some(sequence_le), Some(ttl)) =
        (identifier, sequence, sequence_le, ttl)
    {
        let _ = write!(
            info,
            " id=0x{identifier:04x}, seq={sequence}/{sequence_le}, ttl={ttl}"
        );
    }
    info
}

fn timestamp_info(node: &Node, request: bool, ttl: Option<u64>) -> String {
    let name = if request {
        "Timestamp request"
    } else {
        "Timestamp reply"
    };
    let mut info = format!("{name:<20} ");
    let identifier = field_u64(node, "icmp.ident");
    let sequence = field_u64(node, "icmp.seq");
    let sequence_le = field_u64(node, "icmp.seq_le");
    if let (Some(identifier), Some(sequence), Some(sequence_le), Some(ttl)) =
        (identifier, sequence, sequence_le, ttl)
    {
        let _ = write!(
            info,
            "id=0x{identifier:04x}, seq={sequence}/{sequence_le}, ttl={ttl}"
        );
    }
    info
}

fn icmp_code_name(message_type: u64, code: u64) -> String {
    let name = match (message_type, code) {
        (3, 0) => "Network unreachable",
        (3, 1) => "Host unreachable",
        (3, 2) => "Protocol unreachable",
        (3, 3) => "Port unreachable",
        (3, 4) => "Fragmentation needed",
        (3, 5) => "Source route failed",
        (3, 6) => "Destination network unknown",
        (3, 7) => "Destination host unknown",
        (3, 8) => "Source host isolated",
        (3, 9) => "Network administratively prohibited",
        (3, 10) => "Host administratively prohibited",
        (3, 11) => "Network unreachable for TOS",
        (3, 12) => "Host unreachable for TOS",
        (3, 13) => "Communication administratively filtered",
        (3, 14) => "Host precedence violation",
        (3, 15) => "Precedence cutoff in effect",
        (5, 0) => "Redirect for network",
        (5, 1) => "Redirect for host",
        (5, 2) => "Redirect for TOS and network",
        (5, 3) => "Redirect for TOS and host",
        (9, 0) => "Normal router advertisement",
        (9, 16) => "Does not route common traffic",
        (11, 0) => "Time to live exceeded in transit",
        (11, 1) => "Fragment reassembly time exceeded",
        (12, 0) => "Pointer indicates the error",
        (12, 1) => "Missing a required option",
        (12, 2) => "Bad length",
        (42, 0) => "No error",
        (42, 1) => "Malformed query",
        (42, 2) => "No such interface",
        (42, 3) => "No such table entry",
        (42, 4) => "Multiple interfaces satisfy query",
        _ => return format!("Unknown code: {code}"),
    };
    name.to_string()
}

fn icmpv6_info(node: &Node, chain: &[&Node]) -> String {
    let Some(message_type) = field_u64(node, "icmpv6.type") else {
        return String::new();
    };
    let code = field_u64(node, "icmpv6.code").unwrap_or(0);
    match message_type {
        128 | 129 => {
            let name = if message_type == 128 {
                "request"
            } else {
                "reply"
            };
            let mut info = format!("Echo (ping) {name}");
            if let (Some(identifier), Some(sequence), Some(hop_limit)) = (
                field_u64(node, "icmpv6.echo.identifier"),
                field_u64(node, "icmpv6.echo.sequence_number"),
                outer_network_hop_limit(chain),
            ) {
                let _ = write!(
                    info,
                    " id=0x{identifier:04x}, seq={sequence}, hop limit={hop_limit}"
                );
            }
            info
        }
        1 => format!("Destination Unreachable ({})", icmpv6_code_name(1, code)),
        2 => "Packet Too Big".to_string(),
        3 => format!("Time Exceeded ({})", icmpv6_code_name(3, code)),
        4 => format!("Parameter Problem ({})", icmpv6_code_name(4, code)),
        133 => "Router Solicitation".to_string(),
        134 => match link_address_with_kind(node, "icmpv6.opt.src_linkaddr")
            .map(|(address, _)| address)
        {
            Some(address) => format!("Router Advertisement from {address}"),
            None => "Router Advertisement".to_string(),
        },
        135 => {
            let mut info = "Neighbor Solicitation".to_string();
            if let Some(target) = field_text(node, "icmpv6.nd.ns.target_address") {
                let _ = write!(info, " for {target}");
            }
            if let Some((address, _)) = link_address_with_kind(node, "icmpv6.opt.src_linkaddr") {
                let _ = write!(info, " from {address}");
            }
            info
        }
        136 => {
            let Some(target) = field_text(node, "icmpv6.nd.na.target_address") else {
                return "Neighbor Advertisement".to_string();
            };
            let mut info = format!("Neighbor Advertisement {target}");
            let mut flags = Vec::new();
            if field_bool(node, "icmpv6.nd.na.flag.s") {
                flags.push("sol");
            }
            if field_bool(node, "icmpv6.nd.na.flag.o") {
                flags.push("ovr");
            }
            let _ = write!(info, " ({})", flags.join(", "));
            if let Some((address, eui64)) = link_address_with_kind(node, "icmpv6.opt.linkaddr") {
                let _ = write!(info, " {} {address}", if eui64 { "from" } else { "is at" });
            }
            info
        }
        137 => "Redirect".to_string(),
        100 | 101 | 200 | 201 => "Private experimentation".to_string(),
        other => format!("Type {other}"),
    }
}

fn link_address_with_kind(node: &Node, plain: &str) -> Option<(String, bool)> {
    let eui64 = format!("{plain}_eui64");
    if let Some(address) = field_text(node, &eui64) {
        return Some((address, true));
    }
    let field = find_field(node, plain)?;
    let bytes = match &field.value {
        Value::Ethernet(bytes) => bytes.as_slice(),
        Value::Bytes(bytes) if bytes.len() == 6 => bytes.as_slice(),
        _ => return None,
    };
    Some((
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
        false,
    ))
}

fn fragment_info(node: &Node) -> String {
    // The summary prints the fragment offset in octets, while the
    // fragment-header field counts eight-octet units.
    let offset = field_u64(node, "ipv6.fraghdr.offset").unwrap_or(0) * 8;
    let more = field_bool(node, "ipv6.fraghdr.more");
    let ident = field_u64(node, "ipv6.fraghdr.ident").unwrap_or(0);
    let next = field_u64(node, "ipv6.fraghdr.nxt").unwrap_or(0);
    let mut info = format!(
        "IPv6 fragment (off={offset} more={} ident=0x{ident:08x} nxt={next})",
        if more { "y" } else { "n" }
    );
    if let Some(child) = node.children.first() {
        let child_info = if child.protocol.filter_name.starts_with("ipv6.") {
            ipv6_extension_info(child.protocol.filter_name)
        } else {
            display_protocol(child.protocol.filter_name).to_string()
        };
        if !child_info.is_empty() {
            let _ = write!(info, " , {child_info}");
        }
    }
    info
}

fn icmpv6_code_name(message_type: u64, code: u64) -> &'static str {
    match (message_type, code) {
        (1, 0) => "No route to destination",
        (1, 1) => "Communication with destination administratively prohibited",
        (1, 2) => "Beyond scope of source address",
        (1, 3) => "Address unreachable",
        (1, 4) => "Port unreachable",
        (1, 5) => "Source address failed ingress/egress policy",
        (1, 6) => "Reject route to destination",
        (1, 7) => "Error in Source Routing Header",
        (3, 0) => "Hop limit exceeded in transit",
        (3, 1) => "Fragment reassembly time exceeded",
        (4, 0) => "Erroneous header field encountered",
        (4, 1) => "Unrecognized Next Header type encountered",
        (4, 2) => "Unrecognized IPv6 option encountered",
        _ => "Unknown",
    }
}

fn outer_network_hop_limit(chain: &[&Node]) -> Option<u64> {
    for node in chain {
        match node.protocol.filter_name {
            "ip" => return field_u64(node, "ip.ttl"),
            "ipv6" => return field_u64(node, "ipv6.hlim"),
            _ => {}
        }
    }
    None
}

fn field_bool(node: &Node, abbrev: &str) -> bool {
    find_field(node, abbrev).is_some_and(|field| matches!(field.value, Value::Boolean(true)))
}

fn find_field<'a>(node: &'a Node, abbrev: &str) -> Option<&'a packetfin_core::tree::Field> {
    node.fields
        .iter()
        .find_map(|field| find_field_in(field, abbrev))
}

fn find_field_in<'a>(
    field: &'a packetfin_core::tree::Field,
    abbrev: &str,
) -> Option<&'a packetfin_core::tree::Field> {
    if field.def.abbrev == abbrev {
        return Some(field);
    }
    field
        .children
        .iter()
        .find_map(|child| find_field_in(child, abbrev))
}

fn field_u64(node: &Node, abbrev: &str) -> Option<u64> {
    find_field(node, abbrev).and_then(field_value_u64)
}

fn field_value_u64(field: &packetfin_core::tree::Field) -> Option<u64> {
    match field.value {
        Value::Uint8(value) => Some(u64::from(value)),
        Value::Uint16(value) => Some(u64::from(value)),
        Value::Uint24(value) | Value::Uint32(value) => Some(u64::from(value)),
        Value::Uint64(value) => Some(value),
        Value::Int8(value) => Some(value as u64),
        Value::Int16(value) => Some(value as u64),
        Value::Int32(value) => Some(value as u64),
        Value::Int64(value) => Some(value as u64),
        _ => None,
    }
}

fn field_text_last(node: &Node, abbrev: &str) -> Option<String> {
    let mut found = None;
    let mut visit = |field: &packetfin_core::tree::Field| {
        if field.def.abbrev == abbrev {
            found = field_text_value(field);
        }
    };
    for field in &node.fields {
        field.for_each_in_subtree(&mut visit);
    }
    found
}

fn field_text_value(field: &packetfin_core::tree::Field) -> Option<String> {
    match &field.value {
        Value::Ethernet(address) => Some(
            address
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        ),
        Value::Ipv4(address) => Some(
            address
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("."),
        ),
        Value::Ipv6(_) => Some(field.value.formatted(field.def.display).to_string()),
        Value::String(value) => Some(value.clone()),
        Value::Uint8(value) => Some(value.to_string()),
        Value::Uint16(value) => Some(value.to_string()),
        _ => Some(field.value.formatted(field.def.display).to_string()),
    }
}

fn field_bytes(node: &Node, abbrev: &str) -> Option<Vec<u8>> {
    let field = find_field(node, abbrev)?;
    match &field.value {
        Value::Bytes(bytes) => Some(bytes.to_vec()),
        _ => None,
    }
}

fn field_text(node: &Node, abbrev: &str) -> Option<String> {
    let field = find_field(node, abbrev)?;
    field_text_value(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn summary_text_does_not_gain_container_output() {
        let frame = test_support::frame();
        let packet = test_support::packet(test_support::analysis_tree());
        let mut writer = SummaryWriter::new(TimeOptions::default());
        let mut output = Vec::new();
        assert!(
            writer
                .write_packet(&mut output, &frame, &packet, true, false)
                .is_ok()
        );
        let text = String::from_utf8(output).unwrap_or_default();
        assert!(!text.contains("SEQ/ACK"), "{text}");
        assert!(!text.contains("TCP Analysis Flags"), "{text}");
    }
}

#[cfg(test)]
mod echo_tests {
    use super::{EchoBook, EchoKey, MAX_ECHO_REQUESTS, ntp_status_text};

    fn key(index: u64) -> EchoKey {
        (
            false,
            "192.0.2.1".to_string(),
            "198.51.100.2".to_string(),
            1,
            index,
        )
    }

    #[test]
    fn repeated_echo_requests_keep_one_queue_entry() {
        let mut book = EchoBook::default();
        for frame in 0..400_000 {
            book.remember(key(0), frame);
        }
        assert_eq!(book.len(), 1);
        assert_eq!(book.order_len(), 1);
        assert_eq!(book.reply(&key(0)), Some(399_999));
        assert_eq!(book.order_len(), 0);
    }

    #[test]
    fn matched_echo_pairs_leave_no_queue_entries() {
        let mut book = EchoBook::default();
        for frame in 0..400_000 {
            book.remember(key(frame), frame);
            assert!(book.reply(&key(frame)).is_some());
        }
        assert_eq!(book.len(), 0);
        assert_eq!(book.order_len(), 0);
    }

    #[test]
    fn unmatched_echo_requests_stay_bounded() {
        let mut book = EchoBook::default();
        for frame in 0..400_000 {
            book.remember(key(frame), frame);
        }
        assert_eq!(book.len(), MAX_ECHO_REQUESTS);
        assert!(book.order_len() <= MAX_ECHO_REQUESTS * 2);
        assert_eq!(book.reply(&key(0)), None);
        assert_eq!(book.reply(&key(399_999)), Some(399_999));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "RSS probe; run explicitly with --ignored --nocapture"]
    fn echo_state_rss_probe() {
        let mut book = EchoBook::default();
        let before = rss_kb();
        for frame in 0..200_000 {
            book.remember(key(frame), frame);
        }
        let after_200k = rss_kb();
        for frame in 200_000..400_000 {
            book.remember(key(frame), frame);
        }
        let after_400k = rss_kb();
        println!(
            "rss_kb before={before:?} after_200k={after_200k:?} after_400k={after_400k:?} entries={} order={}",
            book.len(),
            book.order_len()
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "RSS probe; run explicitly with --ignored --nocapture"]
    fn echo_pairs_rss_probe() {
        let mut book = EchoBook::default();
        let before = rss_kb();
        for frame in 0..200_000 {
            book.remember(key(frame), frame);
            assert!(book.reply(&key(frame)).is_some());
        }
        let after_200k = rss_kb();
        for frame in 200_000..400_000 {
            book.remember(key(frame), frame);
            assert!(book.reply(&key(frame)).is_some());
        }
        let after_400k = rss_kb();
        println!(
            "rss_kb before={before:?} after_200k={after_200k:?} after_400k={after_400k:?} entries={} order={}",
            book.len(),
            book.order_len()
        );
    }

    #[cfg(unix)]
    fn rss_kb() -> Option<u64> {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    }

    #[test]
    fn ntp_summary_uses_short_control_mode_text() {
        assert_eq!(ntp_status_text(0x26), "NTP Version 4, control");
        assert_eq!(ntp_status_text(0x27), "NTP Version 4, private");
        assert_eq!(ntp_status_text(0x24), "NTP Version 4, server");
    }
}
