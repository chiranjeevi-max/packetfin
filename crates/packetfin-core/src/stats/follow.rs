//! `-z follow,*`: reconstruct a transport stream and print its chunks.
//!
//! The output rules:
//! the header names the protocol, the stream filter and the two endpoints;
//! ASCII chunks print `\t?<length>` then the bytes with non-printable octets
//! replaced by `.`; raw chunks print lowercase hex; hex chunks print a
//! classic dump whose offsets are per direction and never reset at a chunk
//! boundary. TCP follows the sequence stream, keeps out-of-order segments
//! until the gap fills or the peer acknowledges it, and inserts a
//! `[N bytes missing in capture file]` record (including its trailing NUL)
//! when an ACK proves the bytes were captured elsewhere. HTTP follows the
//! message chunks its dissector produces; with desegmentation disabled it
//! rejoins a start line split across segments from a bounded probe. TLS
//! follows decrypted application data, which Packetfin cannot decrypt yet,
//! so a TLS follow prints an empty table.
//!
//! Every list is bounded: one follow specification retains at most
//! [`SPEC_LIMIT`] bytes of chunk data and all of them together at most the
//! statistics budget, capped at [`TOTAL_LIMIT`] (64 MiB by default). A cap
//! drops the record that would cross it, keeps the chunks already collected
//! and reports one notice, so hostile payloads cannot exhaust memory.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::http_syntax::{
    Answer, BodyPlan, ChunkScanner, ChunkStep, Framing, StartLine, header_section_end, next_line,
    parse_start_line,
};
use crate::state::{StreamAddress, StreamKey};

/// Per-follow-specification retained chunk bytes.
pub(crate) const SPEC_LIMIT: usize = 16 * 1024 * 1024;

/// Total retained chunk bytes across every follow specification.
pub(crate) const TOTAL_LIMIT: usize = 64 * 1024 * 1024;

/// Per-record bookkeeping: the direction byte, the chunk vector and its
/// allocator slack are charged alongside the chunk bytes so a flood of tiny
/// records cannot grow the table without bound.
const RECORD_OVERHEAD: usize = std::mem::size_of::<Record>() + 32;

/// Per-fragment bookkeeping for out-of-order TCP data.
const FRAGMENT_OVERHEAD: usize = std::mem::size_of::<Fragment>() + 32;

/// Bytes of a split HTTP start line the no-desegmentation probe may retain.
const HTTP_PREFIX_LIMIT: usize = 8 * 1024;

/// Segments of a split HTTP start line the probe may retain.
const HTTP_PREFIX_PARTS: usize = 16;

/// Separator rule printed above and below a follow stream.
const SEPARATOR: &str = "===================================================================\n";

/// One upper protocol a follow statistic understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FollowProto {
    /// `follow,tcp`.
    Tcp,
    /// `follow,udp`.
    Udp,
    /// `follow,tls`.
    Tls,
    /// `follow,http`.
    Http,
}

impl FollowProto {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "tls" => Self::Tls,
            "http" => Self::Http,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Tls => "tls",
            Self::Http => "http",
        }
    }

    /// The field whose stream index selects the conversation.
    fn stream_field(self) -> &'static str {
        match self {
            Self::Udp => "udp.stream",
            Self::Tcp | Self::Http => "tcp.stream",
            Self::Tls => "tls.stream",
        }
    }

    /// The transport whose ports the address filter names.
    fn port_field(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp | Self::Tls | Self::Http => "tcp",
        }
    }
}

/// How one chunk is rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FollowMode {
    /// Length-prefixed text with non-printable octets replaced by `.`.
    Ascii,
    /// Classic offset/hex/ASCII dump.
    Hex,
    /// Lowercase hexadecimal digits.
    Raw,
}

impl FollowMode {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "ascii" => Self::Ascii,
            "hex" => Self::Hex,
            "raw" => Self::Raw,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Hex => "hex",
            Self::Raw => "raw",
        }
    }
}

/// One endpoint named on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FollowEndpoint {
    /// Address text as the user wrote it.
    pub address: StreamAddress,
    /// Transport port.
    pub port: u16,
}

/// How the stream is selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FollowSelector {
    /// A `tcp.stream`, `udp.stream` or `tls.stream` index.
    Stream(u32),
    /// Two address/port endpoints, in either direction.
    Address {
        /// First endpoint from the command line.
        first: FollowEndpoint,
        /// Second endpoint from the command line.
        second: FollowEndpoint,
    },
}

/// One parsed `follow,` specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FollowSpec {
    /// Upper protocol.
    pub proto: FollowProto,
    /// Rendering mode.
    pub mode: FollowMode,
    /// Stream selector.
    pub selector: FollowSelector,
    /// First and last chunk printed, one-based and inclusive.
    pub range: (u32, u32),
}

/// Parse `follow,<proto>,<mode>,<selector>[,<range>]`.
pub(crate) fn parse(text: &str) -> Result<FollowSpec, String> {
    let rest = text.strip_prefix("follow,").unwrap_or(text);
    let Some((proto_text, rest)) = rest.split_once(',') else {
        if FollowProto::parse(rest).is_some() {
            // A protocol without a mode reports both the mode error and
            // the address error.
            return Err("Invalid display mode.\nInvalid address.".to_string());
        }
        return Err(super::unsupported(text));
    };
    let Some(proto) = FollowProto::parse(proto_text) else {
        return Err(super::unsupported(text));
    };
    let (mode_text, rest) = rest.split_once(',').unwrap_or((rest, ""));
    let Some(mode) = FollowMode::parse(mode_text) else {
        return Err(
            "Invalid display mode.\nInvalid address.\nInvalid range.\nInvalid parameter."
                .to_string(),
        );
    };
    let Some((selector, rest)) = parse_selector(rest) else {
        return Err("Invalid address.".to_string());
    };
    if let FollowSelector::Address { first, second } = &selector
        && std::mem::discriminant(&first.address) != std::mem::discriminant(&second.address)
    {
        return Err("Mismatched IP address types.".to_string());
    }
    let range = if rest.is_empty() {
        parse_range(None)?
    } else {
        let Some(range_text) = rest.strip_prefix(',') else {
            return Err("Invalid parameter.".to_string());
        };
        if range_text.contains(',') {
            return Err("Invalid parameter.".to_string());
        }
        parse_range(Some(range_text))?
    };
    Ok(FollowSpec {
        proto,
        mode,
        selector,
        range,
    })
}

fn parse_selector(text: &str) -> Option<(FollowSelector, &str)> {
    if text.is_empty() {
        return None;
    }
    let numeric_end = text.find(',').unwrap_or(text.len());
    let numeric = text.get(..numeric_end)?;
    if !numeric.is_empty() && numeric.bytes().all(|byte| byte.is_ascii_digit()) {
        let index: u32 = numeric.parse().ok()?;
        return Some((FollowSelector::Stream(index), text.get(numeric_end..)?));
    }
    let (first, rest) = parse_endpoint(text)?;
    let rest = rest.strip_prefix(',')?;
    let (second, rest) = parse_endpoint(rest)?;
    Some((FollowSelector::Address { first, second }, rest))
}

/// Parse one endpoint and return the remaining text.
fn parse_endpoint(text: &str) -> Option<(FollowEndpoint, &str)> {
    if let Some(rest) = text.strip_prefix('[') {
        let close = rest.find(']')?;
        let address: Ipv6Addr = rest.get(..close)?.parse().ok()?;
        let after = rest.get(close + 1..)?;
        let after = after.strip_prefix(':')?;
        let port_end = after.find(',').unwrap_or(after.len());
        let port: u16 = after.get(..port_end)?.parse().ok()?;
        let consumed = 1 + close + 1 + 1 + port_end;
        return Some((
            FollowEndpoint {
                address: StreamAddress::Ipv6(address.octets()),
                port,
            },
            text.get(consumed..)?,
        ));
    }
    let colon = text.find(':')?;
    let address: Ipv4Addr = text.get(..colon)?.parse().ok()?;
    let after = text.get(colon + 1..)?;
    let port_end = after.find(',').unwrap_or(after.len());
    let port: u16 = after.get(..port_end)?.parse().ok()?;
    let consumed = colon + 1 + port_end;
    Some((
        FollowEndpoint {
            address: StreamAddress::Ipv4(address.octets()),
            port,
        },
        text.get(consumed..)?,
    ))
}

fn parse_range(text: Option<&str>) -> Result<(u32, u32), String> {
    let Some(text) = text else {
        return Ok((1, u32::MAX));
    };
    if text.is_empty() {
        return Err("Invalid range.\nInvalid parameter.".to_string());
    }
    let (first, last) = match text.split_once('-') {
        Some((first, last)) => (first, Some(last)),
        None => (text, None),
    };
    if first.is_empty()
        && let Some(last) = last
        && parse_chunk(last).is_some()
    {
        // A range with no first chunk (`-N`) is valid and prints the table
        // with no chunks, which a zero chunk range produces.
        return Ok((0, 0));
    }
    if last.is_some_and(|last| last.is_empty() || last.contains('-')) {
        return Err("Invalid parameter.".to_string());
    }
    let Some(first) = parse_chunk(first) else {
        return Err("Invalid range.\nInvalid parameter.".to_string());
    };
    let last = match last {
        Some(last) => match parse_chunk(last) {
            Some(last) => last,
            None => return Err("Invalid range.\nInvalid parameter.".to_string()),
        },
        None => first,
    };
    if first < 1 || first > last {
        return Err("Invalid range value.".to_string());
    }
    Ok((first, last))
}

fn parse_chunk(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// One output chunk.
struct Record {
    direction: u8,
    data: Vec<u8>,
}

/// One direction of a followed TCP stream.
#[derive(Default)]
struct TcpHalf {
    expected: Option<u32>,
    fragments: Vec<Fragment>,
}

struct Fragment {
    sequence: u32,
    data: Vec<u8>,
}

/// Aggregation state for one `follow,` specification.
pub(crate) struct State {
    spec: FollowSpec,
    records: Vec<Record>,
    endpoints: Option<(StreamAddress, u16, StreamAddress, u16)>,
    tcp: [TcpHalf; 2],
    retained: usize,
    limit: usize,
    http_desegment: bool,
    http_started: bool,
    /// Leading segments of an HTTP stream whose first start line is split
    /// across segments, in arrival order. Only the no-desegmentation path
    /// uses the probe, because reassembly hands the tap a whole message.
    http_prefix: Vec<Vec<u8>>,
    /// Bytes held by `http_prefix`, segment bytes only.
    http_prefix_bytes: usize,
    /// The connection and direction whose start line the probe continues.
    http_probe: Option<StreamKey>,
    /// The peer request each direction last carried, for the HEAD and CONNECT
    /// framing rules (RFC 9112 section 6.3 cases 1 and 2).
    answers: [Answer; 2],
    truncated: bool,
}

impl State {
    /// Create empty follow state with the default per-specification cap.
    #[cfg(test)]
    pub(crate) fn new(spec: FollowSpec) -> Self {
        Self::with_limit(spec, SPEC_LIMIT)
    }

    /// Create empty follow state capped by the statistics budget share.
    pub(crate) fn with_limit(spec: FollowSpec, limit: usize) -> Self {
        Self {
            spec,
            records: Vec::new(),
            endpoints: None,
            tcp: Default::default(),
            retained: 0,
            limit: limit.min(SPEC_LIMIT),
            http_desegment: true,
            http_started: false,
            http_prefix: Vec::new(),
            http_prefix_bytes: 0,
            http_probe: None,
            answers: [Answer::default(); 2],
            truncated: false,
        }
    }

    /// Bytes retained by this state.
    pub(crate) fn retained(&self) -> usize {
        self.retained
    }

    /// Whether a cap dropped a record.
    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    /// Lower this state's cap so the whole run stays inside `remaining`.
    pub(crate) fn allow(&mut self, remaining: usize) {
        self.limit = self.retained.saturating_add(remaining).min(SPEC_LIMIT);
    }

    /// Feed one TCP segment.
    pub(crate) fn tcp_event(
        &mut self,
        key: StreamKey,
        _direction: u8,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) {
        if self.spec.proto == FollowProto::Http && !self.http_desegment {
            self.http_segment(key, payload);
            return;
        }
        if self.spec.proto != FollowProto::Tcp || !self.selects(key) {
            return;
        }
        self.establish(key);
        let is_server = self.direction_of(key);
        let peer = usize::from(is_server) ^ 1;
        // An ACK on this segment can prove bytes in the other direction were
        // captured elsewhere even when this segment carries no data.
        while self.fill_from_ack(peer, acknowledgement, true) {}
        self.tcp_segment(is_server, sequence, payload);
    }

    /// Apply one un-reassembled HTTP segment.
    ///
    /// The follow begins at the first complete start line. A start line split
    /// across segments leaves the earlier segments unparsable one at a time,
    /// so the probe retains them and replays them once the concatenation
    /// carries a start line. The probe belongs to the connection and
    /// direction that opened it: bytes from another key cannot continue that
    /// line, so they are ignored until the probe completes or its bounds
    /// clear it.
    fn http_segment(&mut self, key: StreamKey, payload: &[u8]) {
        if !self.selects(key) || payload.is_empty() {
            return;
        }
        if !self.http_started {
            if self.http_probe.is_some_and(|probe| probe != key) {
                return;
            }
            if self.http_prefix.is_empty() {
                if starts_with_http_start_line(payload) {
                    self.start_http(key, None, payload);
                    return;
                }
                if next_line(payload, 0).is_some() {
                    // The first line is complete but cannot start an HTTP
                    // message (for example a capture starting mid-body). Do
                    // not retain it: a later valid message must be free to
                    // begin the follow.
                    self.take_http_prefix();
                    return;
                }
                self.retain_http_prefix(key, payload);
                return;
            }
            let mut combined =
                Vec::with_capacity(self.http_prefix_bytes.saturating_add(payload.len()));
            for part in &self.http_prefix {
                combined.extend_from_slice(part);
            }
            combined.extend_from_slice(payload);
            if !starts_with_http_start_line(&combined) {
                if next_line(&combined, 0).is_some() {
                    // The joined first line is complete but invalid; release
                    // the probe so a later message can start the follow.
                    self.take_http_prefix();
                    return;
                }
                self.retain_http_prefix(key, payload);
                return;
            }
            self.start_http(key, Some(combined), payload);
            return;
        }
        self.establish(key);
        let direction = self.direction_of(key);
        let records = split_http_segments(payload, direction, &mut self.answers);
        for data in records {
            self.push(direction, data);
        }
    }

    /// Begin the HTTP follow and replay the start-line probe.
    ///
    /// `combined` holds the retained segments joined with `payload`; it is
    /// `None` when the segment carries the start line by itself. No retained
    /// segment parses as a start line alone, so the joined request line
    /// records the method (and with it the HEAD and CONNECT rules of RFC 9112
    /// section 6.3) before the segments are replayed in arrival order.
    fn start_http(&mut self, key: StreamKey, combined: Option<Vec<u8>>, payload: &[u8]) {
        self.http_started = true;
        self.establish(key);
        let direction = self.direction_of(key);
        if let Some(combined) = &combined {
            note_http_message(combined, direction, &mut self.answers);
        }
        let prefix = self.take_http_prefix();
        for part in &prefix {
            for data in split_http_segments(part, direction, &mut self.answers) {
                self.push(direction, data);
            }
        }
        let records = split_http_segments(payload, direction, &mut self.answers);
        for data in records {
            self.push(direction, data);
        }
    }

    /// Retain one segment of a split HTTP start line.
    ///
    /// The probe keeps at most [`HTTP_PREFIX_LIMIT`] bytes in at most
    /// [`HTTP_PREFIX_PARTS`] segments, charged against the specification cap
    /// as a record is. A segment that would cross a bound releases what the
    /// probe kept and leaves the stream not started, so a first line that
    /// never completes cannot grow the table.
    fn retain_http_prefix(&mut self, key: StreamKey, payload: &[u8]) {
        let charge = payload.len().saturating_add(RECORD_OVERHEAD);
        let parts = self.http_prefix.len();
        if payload.len() > HTTP_PREFIX_LIMIT.saturating_sub(self.http_prefix_bytes)
            || parts >= HTTP_PREFIX_PARTS
            || self.retained.saturating_add(charge) > self.limit
        {
            self.take_http_prefix();
            return;
        }
        self.http_prefix_bytes = self.http_prefix_bytes.saturating_add(payload.len());
        self.retained = self.retained.saturating_add(charge);
        self.http_prefix.push(payload.to_vec());
        self.http_probe = Some(key);
    }

    /// Release the retained start-line segments in arrival order.
    fn take_http_prefix(&mut self) -> Vec<Vec<u8>> {
        let prefix = std::mem::take(&mut self.http_prefix);
        let charge = self
            .http_prefix_bytes
            .saturating_add(prefix.len().saturating_mul(RECORD_OVERHEAD));
        self.retained = self.retained.saturating_sub(charge);
        self.http_prefix_bytes = 0;
        self.http_probe = None;
        prefix
    }

    /// Apply one segment to a direction's TCP stream.
    fn tcp_segment(&mut self, direction: u8, sequence: u32, payload: &[u8]) {
        let index = usize::from(direction.min(1));
        let Some(half) = self.tcp.get(index) else {
            return;
        };
        let Some(expected) = half.expected else {
            if let Some(half) = self.tcp.get_mut(index) {
                half.expected = Some(sequence);
            }
            if payload.is_empty() {
                return;
            }
            self.push_tcp_data(direction, sequence, payload);
            return;
        };
        if payload.is_empty() {
            return;
        }
        let mut sequence = sequence;
        let mut data = payload;
        if lt_seq(sequence, expected) {
            let end = sequence.wrapping_add(length_u32(data.len()));
            if !gt_seq(end, expected) {
                return;
            }
            let skip = usize::try_from(expected.wrapping_sub(sequence))
                .unwrap_or(usize::MAX)
                .min(data.len());
            data = data.get(skip..).unwrap_or_default();
            sequence = expected;
        }
        if data.is_empty() || lt_seq(sequence, expected) {
            return;
        }
        self.push_tcp_data(direction, sequence, data);
    }

    fn push_tcp_data(&mut self, direction: u8, sequence: u32, data: &[u8]) {
        let index = usize::from(direction.min(1));
        let Some(half) = self.tcp.get(index) else {
            return;
        };
        let expected = half.expected.unwrap_or(sequence);
        if eq_seq(sequence, expected) {
            self.push(direction, data.to_vec());
            if let Some(half) = self.tcp.get_mut(index) {
                half.expected = Some(expected.wrapping_add(length_u32(data.len())));
            }
            while self.fill_from_ack(index, 0, false) {}
            return;
        }
        let Some(half) = self.tcp.get_mut(index) else {
            return;
        };
        let charge = data.len().saturating_add(FRAGMENT_OVERHEAD);
        if self.retained.saturating_add(charge) > self.limit {
            self.truncated = true;
            return;
        }
        self.retained += charge;
        half.fragments.push(Fragment {
            sequence,
            data: data.to_vec(),
        });
        if half.fragments.len() > 4096
            && let Some(fragment) = half.fragments.first()
        {
            self.retained = self
                .retained
                .saturating_sub(fragment.data.len().saturating_add(FRAGMENT_OVERHEAD));
            half.fragments.remove(0);
        }
    }

    /// Feed one UDP datagram.
    pub(crate) fn udp_event(&mut self, key: StreamKey, payload: &[u8]) {
        if self.spec.proto != FollowProto::Udp || !self.selects(key) {
            return;
        }
        self.establish(key);
        let direction = self.direction_of(key);
        self.push(direction, payload.to_vec());
    }

    /// Feed one complete HTTP message.
    pub(crate) fn http_event(&mut self, key: StreamKey, message: &[u8]) {
        if self.spec.proto != FollowProto::Http || !self.http_desegment || !self.selects(key) {
            return;
        }
        self.establish(key);
        let direction = self.direction_of(key);
        let records = if self.http_desegment {
            split_http_records(message, direction, &mut self.answers)
        } else {
            split_http_segments(message, direction, &mut self.answers)
        };
        for data in records {
            self.push(direction, data);
        }
    }

    /// Whether HTTP messages were reassembled by the TCP dissector.
    pub(crate) fn set_http_desegment(&mut self, desegment: bool) {
        self.http_desegment = desegment;
    }

    /// Whether this specification follows `key`.
    fn selects(&self, key: StreamKey) -> bool {
        match &self.spec.selector {
            // A stream index names one connection per capture pass, because
            // each pass numbers its streams from zero. Endpoints are not an
            // identity: a restarted pass reuses index N for its own stream,
            // so the index alone selects the followed conversation the same
            // way the stream field does.
            FollowSelector::Stream(index) => key.index == *index,
            FollowSelector::Address { first, second } => {
                endpoint_matches(key.source, key.source_port, *first)
                    && endpoint_matches(key.destination, key.destination_port, *second)
                    || endpoint_matches(key.source, key.source_port, *second)
                        && endpoint_matches(key.destination, key.destination_port, *first)
            }
        }
    }

    fn establish(&mut self, key: StreamKey) {
        self.endpoints.get_or_insert((
            key.source,
            key.source_port,
            key.destination,
            key.destination_port,
        ));
    }

    fn direction_of(&self, key: StreamKey) -> u8 {
        match self.endpoints {
            Some((source, port, _, _))
                if endpoint_matches(
                    key.source,
                    key.source_port,
                    FollowEndpoint {
                        address: source,
                        port,
                    },
                ) =>
            {
                0
            }
            _ => 1,
        }
    }

    fn push(&mut self, direction: u8, data: Vec<u8>) -> bool {
        let charge = data.len().saturating_add(RECORD_OVERHEAD);
        if self.retained.saturating_add(charge) > self.limit {
            self.truncated = true;
            return false;
        }
        self.retained += charge;
        self.records.push(Record { direction, data });
        true
    }

    /// Apply every fragment an acknowledgement unlocks.
    fn fill_from_ack(&mut self, direction: usize, acknowledged: u32, use_ack: bool) -> bool {
        let half = self.tcp.get_mut(direction.min(1));
        let Some(half) = half else {
            return false;
        };
        let Some(expected) = half.expected else {
            return false;
        };
        let mut lowest: Option<u32> = None;
        let mut apply: Option<(usize, usize, bool)> = None;
        for (index, fragment) in half.fragments.iter().enumerate() {
            if lowest.is_none_or(|lowest| gt_seq(lowest, fragment.sequence)) {
                lowest = Some(fragment.sequence);
            }
            if lt_seq(fragment.sequence, expected) {
                let end = fragment
                    .sequence
                    .wrapping_add(length_u32(fragment.data.len()));
                if gt_seq(end, expected) {
                    let seen = usize::try_from(expected.wrapping_sub(fragment.sequence))
                        .unwrap_or(usize::MAX)
                        .min(fragment.data.len());
                    apply = Some((index, seen, true));
                    break;
                }
                apply = Some((index, 0, false));
                break;
            }
            if eq_seq(fragment.sequence, expected) {
                apply = Some((index, 0, true));
                break;
            }
        }
        if let Some((index, offset, append)) = apply {
            let fragment = half.fragments.remove(index);
            self.retained = self
                .retained
                .saturating_sub(fragment.data.len().saturating_add(FRAGMENT_OVERHEAD));
            if append {
                let data = fragment.data.get(offset..).unwrap_or_default().to_vec();
                let length = length_u32(data.len());
                self.push(u8::try_from(direction).unwrap_or(1), data);
                if let Some(half) = self.tcp.get_mut(direction.min(1)) {
                    half.expected = Some(expected.wrapping_add(length));
                }
            }
            return true;
        }
        if use_ack
            && let Some(lowest) = lowest
            && gt_seq(acknowledged, lowest)
        {
            let missing = lowest.wrapping_sub(expected);
            let text = format!("[{missing} bytes missing in capture file]");
            let mut data = text.into_bytes();
            // The record includes the terminating NUL byte.
            data.push(0);
            self.push(u8::try_from(direction).unwrap_or(1), data);
            if let Some(half) = self.tcp.get_mut(direction.min(1)) {
                half.expected = Some(lowest);
            }
            return true;
        }
        false
    }

    /// Render the stream table.
    pub(crate) fn finish(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        write!(output, "\n{SEPARATOR}")?;
        writeln!(
            output,
            "Follow: {},{}",
            self.spec.proto.name(),
            self.spec.mode.name()
        )?;
        writeln!(output, "Filter: {}", filter_text(&self.spec))?;
        let (node0, node1) = self
            .endpoints
            .map(|(source, source_port, destination, destination_port)| {
                (
                    format_endpoint(source, source_port),
                    format_endpoint(destination, destination_port),
                )
            })
            .unwrap_or_else(|| (":0".to_string(), ":0".to_string()));
        writeln!(output, "Node 0: {node0}")?;
        writeln!(output, "Node 1: {node1}")?;
        let (first, last) = self.spec.range;
        let mut hex_offsets = [0_u32; 2];
        for (index, record) in self.records.iter().enumerate() {
            let chunk = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
            let direction = usize::from(record.direction.min(1));
            if chunk < first || chunk > last {
                if let Some(slot) = hex_offsets.get_mut(direction) {
                    *slot = slot.wrapping_add(length_u32(record.data.len()));
                }
                continue;
            }
            match self.spec.mode {
                FollowMode::Ascii => {
                    if record.direction != 0 {
                        output.write_char('\t')?;
                    }
                    writeln!(output, "{}", record.data.len())?;
                    write_ascii(output, &record.data)?;
                    output.write_char('\n')?;
                }
                FollowMode::Raw => {
                    if record.direction != 0 {
                        output.write_char('\t')?;
                    }
                    write_hex_digits(output, &record.data)?;
                    output.write_char('\n')?;
                }
                FollowMode::Hex => {
                    let offset = hex_offsets.get(direction).copied().unwrap_or(0);
                    write_hex_dump(output, record.direction != 0, offset, &record.data)?;
                    if let Some(slot) = hex_offsets.get_mut(direction) {
                        *slot = offset.wrapping_add(length_u32(record.data.len()));
                    }
                }
            }
        }
        write!(output, "{SEPARATOR}")
    }
}

fn endpoint_matches(address: StreamAddress, port: u16, endpoint: FollowEndpoint) -> bool {
    address == endpoint.address && port == endpoint.port
}

fn lt_seq(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

fn gt_seq(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) > 0
}

fn eq_seq(left: u32, right: u32) -> bool {
    left == right
}

fn length_u32(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

/// The `Filter:` line a follow specification prints.
pub(crate) fn filter_text(spec: &FollowSpec) -> String {
    match &spec.selector {
        FollowSelector::Stream(index) => {
            format!("{} eq {index}", spec.proto.stream_field())
        }
        FollowSelector::Address { first, second } => {
            let version = match first.address {
                StreamAddress::Ipv6(_) => "v6",
                StreamAddress::Ipv4(_) => "",
            };
            let ports = spec.proto.port_field();
            format!(
                "((ip{version}.src eq {a} and {ports}.srcport eq {ap}) and (ip{version}.dst eq {b} and {ports}.dstport eq {bp})) or ((ip{version}.src eq {b} and {ports}.srcport eq {bp}) and (ip{version}.dst eq {a} and {ports}.dstport eq {ap}))",
                a = address_text(first.address),
                ap = first.port,
                b = address_text(second.address),
                bp = second.port,
            )
        }
    }
}

fn address_text(address: StreamAddress) -> String {
    match address {
        StreamAddress::Ipv4(bytes) => Ipv4Addr::from(bytes).to_string(),
        StreamAddress::Ipv6(bytes) => Ipv6Addr::from(bytes).to_string(),
    }
}

fn format_endpoint(address: StreamAddress, port: u16) -> String {
    match address {
        StreamAddress::Ipv4(bytes) => format!("{}:{port}", Ipv4Addr::from(bytes)),
        StreamAddress::Ipv6(bytes) => format!("[{}]:{port}", Ipv6Addr::from(bytes)),
    }
}

/// Render bytes in ASCII follow mode.
fn write_ascii(output: &mut dyn fmt::Write, data: &[u8]) -> fmt::Result {
    for byte in data {
        let rendered = match byte {
            b'\r' | b'\n' => char::from(*byte),
            0x20..=0x7e => char::from(*byte),
            _ => '.',
        };
        output.write_char(rendered)?;
    }
    Ok(())
}

fn write_hex_digits(output: &mut dyn fmt::Write, data: &[u8]) -> fmt::Result {
    for byte in data {
        write!(output, "{byte:02x}")?;
    }
    Ok(())
}

/// Render one classic hex dump line group.
fn write_hex_dump(
    output: &mut dyn fmt::Write,
    prefix_tab: bool,
    offset: u32,
    data: &[u8],
) -> fmt::Result {
    let mut start = 0_usize;
    while start < data.len() {
        if prefix_tab {
            output.write_char('\t')?;
        }
        let end = start.saturating_add(16).min(data.len());
        let line = data.get(start..end).unwrap_or_default();
        let line_offset = offset.saturating_add(u32::try_from(start).unwrap_or(u32::MAX));
        write!(output, "{line_offset:08X}  ")?;
        for index in 0..16 {
            if index == 8 {
                output.write_char(' ')?;
            }
            match line.get(index) {
                Some(byte) => write!(output, "{byte:02x} ")?,
                None => output.write_str("   ")?,
            }
        }
        output.write_char(' ')?;
        let mut text = String::new();
        for (index, byte) in line.iter().enumerate() {
            if index == 8 {
                text.push(' ');
            }
            text.push(if (0x20..=0x7e).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            });
        }
        // Trim the ASCII column's trailing space.
        while text.ends_with(' ') {
            text.pop();
        }
        output.write_str(&text)?;
        output.write_char('\n')?;
        start = start.saturating_add(16);
    }
    Ok(())
}

/// Whether a segment begins with a complete HTTP/1.x start line.
///
/// Any method token RFC 9110 section 9 defines is acceptable, so a request
/// whose method is not one of the common ones still starts the follow. A
/// segment that stops before its first LF is not a start line yet.
fn starts_with_http_start_line(bytes: &[u8]) -> bool {
    let Some((line, _)) = next_line(bytes, 0) else {
        return false;
    };
    parse_start_line(line).is_some()
}

/// Split one un-reassembled HTTP segment into follow records.
///
/// With `tcp.desegment_tcp_streams` disabled the dissector sees one segment
/// at a time. A request segment is queued whole, while a response header
/// queues the header and an empty body when the framing announces one. A
/// body-only segment queues its bytes unchanged. Pipelined start lines are
/// still separate records, and the body bounds come from the shared
/// [`Framing::body_plan`] so the tap cannot disagree with the dissector.
fn split_http_segments(message: &[u8], direction: u8, answers: &mut [Answer; 2]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < message.len() {
        let rest = message.get(offset..).unwrap_or_default();
        let Some(header_length) = header_section_end(rest) else {
            records.push(rest.to_vec());
            break;
        };
        let header = rest.get(..header_length).unwrap_or_default();
        let plan = Framing::of_block(header).body_plan(
            answers
                .get(direction_of_answer(direction))
                .copied()
                .unwrap_or_default(),
        );
        records.push(header.to_vec());
        note_http_message(header, direction, answers);
        let body = rest.get(header_length..).unwrap_or_default();
        if body.is_empty() {
            if announces_body(plan) {
                // Without reassembly the tap queues an empty body when a
                // header announces one but its body is in another segment.
                records.push(Vec::new());
            }
            break;
        }
        if plan == BodyPlan::Chunked {
            // The body segment keeps its chunk framing; only a dissected,
            // reassembled message is de-chunked.
            records.push(body.to_vec());
            break;
        }
        let take = match plan {
            BodyPlan::Fixed(length) => length.min(body.len()),
            BodyPlan::Empty => 0,
            BodyPlan::Answer | BodyPlan::InvalidLength | BodyPlan::CloseDelimited => body.len(),
            BodyPlan::Chunked => body.len(),
        };
        if take > 0 {
            records.push(body.get(..take).unwrap_or_default().to_vec());
        }
        offset = offset.saturating_add(header_length).saturating_add(take);
        // A zero-length body ends at its header section, so the following
        // bytes are another message; the header already advanced the offset.
        // Every other zero-take plan cannot make progress, so the loop ends
        // rather than rescanning the same bytes.
        if take == 0 && !matches!(plan, BodyPlan::Empty | BodyPlan::Fixed(0)) {
            break;
        }
    }
    records
}

/// The direction that answers `direction`: a response in one direction
/// answers the request in the other.
fn direction_of_answer(direction: u8) -> usize {
    usize::from(direction.min(1)) ^ 1
}

/// Record the request method a later response answers.
///
/// A request replaces the answer its own direction carries; a final response
/// consumes the other direction's, because it answered that request (a 1xx
/// answer leaves it pending).
fn note_http_message(header: &[u8], direction: u8, answers: &mut [Answer; 2]) {
    let Some((line, _)) = next_line(header, 0) else {
        return;
    };
    let index = usize::from(direction.min(1));
    match parse_start_line(line) {
        Some(StartLine::Request { method, .. }) => {
            if let Some(answer) = answers.get_mut(index) {
                *answer = Answer {
                    head: method.eq_ignore_ascii_case("HEAD"),
                    connect: method.eq_ignore_ascii_case("CONNECT"),
                };
            }
        }
        Some(StartLine::Response { code, .. }) => {
            if code >= 200
                && let Some(answer) = answers.get_mut(index ^ 1)
            {
                *answer = Answer::default();
            }
        }
        None => {}
    }
}

/// Whether the header announces a body its segment does not carry.
fn announces_body(plan: BodyPlan) -> bool {
    match plan {
        BodyPlan::Chunked => true,
        BodyPlan::Fixed(length) => length > 0,
        BodyPlan::Empty | BodyPlan::Answer | BodyPlan::InvalidLength | BodyPlan::CloseDelimited => {
            false
        }
    }
}

/// Split one HTTP byte run into follow records.
///
/// A message contributes its header lines as one record and its body as a
/// second; a chunked body is de-chunked into one record even when it is
/// empty. Pipelined messages in one delivery are split at each complete
/// header, so a desegmented segment that carries two requests still prints
/// two records. The body bounds come from the shared [`Framing::body_plan`].
fn split_http_records(message: &[u8], direction: u8, answers: &mut [Answer; 2]) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < message.len() {
        let rest = message.get(offset..).unwrap_or_default();
        let Some(header_length) = header_section_end(rest) else {
            records.push(rest.to_vec());
            break;
        };
        let header = rest.get(..header_length).unwrap_or_default();
        records.push(header.to_vec());
        let body = rest.get(header_length..).unwrap_or_default();
        if body.is_empty() {
            note_http_message(header, direction, answers);
            break;
        }
        let plan = Framing::of_block(header).body_plan(
            answers
                .get(direction_of_answer(direction))
                .copied()
                .unwrap_or_default(),
        );
        note_http_message(header, direction, answers);
        match plan {
            BodyPlan::Chunked => {
                let (data, consumed) = dechunk(body);
                records.push(data);
                if consumed == 0 {
                    break;
                }
                offset = offset
                    .saturating_add(header_length)
                    .saturating_add(consumed);
            }
            BodyPlan::Empty => {
                // The header section is the whole message; the following bytes
                // are the next message or a continuation record.
                offset = offset.saturating_add(header_length);
            }
            BodyPlan::Fixed(length) => {
                let take = length.min(body.len());
                if take > 0 {
                    records.push(body.get(..take).unwrap_or_default().to_vec());
                }
                offset = offset.saturating_add(header_length).saturating_add(take);
            }
            BodyPlan::Answer | BodyPlan::InvalidLength | BodyPlan::CloseDelimited => {
                // Every remaining byte belongs to this message.
                records.push(body.to_vec());
                offset = message.len();
            }
        }
    }
    records
}

/// Concatenate one chunked body's data and report the bytes consumed.
///
/// The de-chunked body is one record, not one per chunk, so a two-chunk
/// response prints a single data block. An empty chunked body still queues
/// an empty record. An incomplete size line ends the record where it starts;
/// an incomplete trailer section consumes the bytes the segment carries, so
/// the record after it does not reprint trailer text as a message. A malformed
/// chunk boundary keeps the data read so far and consumes the supplied
/// remainder, because RFC 9112 section 7.1 gives nothing after it a frame.
fn dechunk(body: &[u8]) -> (Vec<u8>, usize) {
    let mut data = Vec::new();
    let mut scanner = ChunkScanner::new(0);
    loop {
        match scanner.step(body, body.len()) {
            ChunkStep::Data {
                bytes, boundary_ok, ..
            } => {
                data.extend_from_slice(bytes);
                if !boundary_ok {
                    // RFC 9112 section 7.1 requires CRLF after the chunk data.
                    // Nothing after a malformed boundary can be framed, so the
                    // bytes read so far stay and the supplied remainder is
                    // consumed, matching the reassembled parser.
                    return (data, body.len());
                }
            }
            ChunkStep::Last | ChunkStep::Trailer { .. } => {}
            ChunkStep::TrailerEnd { end, .. } => return (data, end),
            ChunkStep::Incomplete {
                restart, trailers, ..
            } => {
                return (data, if trailers { body.len() } else { restart });
            }
            ChunkStep::Invalid { at, .. } => return (data, at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u32, source: u8, destination: u8) -> StreamKey {
        StreamKey {
            index,
            source: StreamAddress::Ipv4([10, 0, 0, source]),
            source_port: 1000,
            destination: StreamAddress::Ipv4([10, 0, 0, destination]),
            destination_port: 2000,
        }
    }

    fn reverse_key(index: u32, source: u8, destination: u8) -> StreamKey {
        StreamKey {
            index,
            source: StreamAddress::Ipv4([10, 0, 0, source]),
            source_port: 2000,
            destination: StreamAddress::Ipv4([10, 0, 0, destination]),
            destination_port: 1000,
        }
    }

    fn follow(text: &str) -> State {
        match parse(text) {
            Ok(spec) => State::new(spec),
            Err(error) => {
                eprintln!("follow spec {text}: {error}");
                std::process::exit(1);
            }
        }
    }

    #[test]
    fn a_stream_index_selects_only_its_own_connection() {
        let mut state = follow("follow,tcp,ascii,0");
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"first");
        // Another connection with the same endpoints but a different index is
        // not the followed stream.
        state.tcp_event(key(1, 1, 2), 0, 1, 1, b"other");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(output.contains("first"), "{output}");
        assert!(!output.contains("other"), "{output}");
    }

    #[test]
    fn tcp_follow_fills_a_gap_from_the_peer_ack() {
        let mut state = follow("follow,tcp,ascii,0");
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"BBBB");
        state.tcp_event(key(0, 1, 2), 0, 9, 1, b"CCCC");
        state.tcp_event(reverse_key(0, 2, 1), 1, 1, 13, b"");
        state.tcp_event(key(0, 1, 2), 0, 13, 1, b"DDDD");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(
            output.contains(
                "4
BBBB"
            ),
            "{output}"
        );
        assert!(
            output.contains(
                "34
[4 bytes missing in capture file]."
            ),
            "{output}"
        );
        assert!(
            output.contains(
                "4
CCCC"
            ),
            "{output}"
        );
        assert!(
            output.contains(
                "4
DDDD"
            ),
            "{output}"
        );
    }

    #[test]
    fn a_follow_respects_the_head_request_it_answers() {
        // RFC 9112 section 6.3 case 1: a response to HEAD ends at the header
        // section. The tap must split the trailing bytes as one record, not
        // as the declared length plus the rest.
        let mut state = follow("follow,http,ascii,0");
        state.set_http_desegment(false);
        state.tcp_event(
            key(0, 1, 2),
            0,
            1,
            1,
            b"HEAD /head HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        state.tcp_event(
            reverse_key(0, 2, 1),
            1,
            1,
            33,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\njunk\r\n",
        );
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(
            output.contains("6\njunk\r\n"),
            "the trailing bytes must be one record: {output}"
        );
        assert!(
            !output.contains("4\njunk"),
            "the declared length must not split a HEAD answer: {output}"
        );
    }

    #[test]
    fn a_zero_length_body_keeps_the_next_message_in_the_segment() {
        // RFC 9112 section 6.3 case 6: Content-Length: 0 ends the message at
        // its header section. The header advances the offset by itself, so a
        // pipelined request in the same segment is still a second record.
        let segment = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nGET /next HTTP/1.1\r\n\r\n";
        let mut answers = [Answer::default(); 2];
        let records = split_http_segments(segment, 0, &mut answers);
        assert_eq!(
            records,
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                b"GET /next HTTP/1.1\r\n\r\n".to_vec(),
            ]
        );
    }

    #[test]
    fn a_malformed_chunk_boundary_ends_the_dechunk() {
        // RFC 9112 section 7.1 requires CRLF after the chunk data. Nothing
        // after a malformed boundary can be framed, so only the first chunk's
        // data is kept and every supplied byte is consumed, as the
        // reassembled parser does.
        let body = b"1\r\naXX1\r\nb\r\n0\r\n\r\n";
        let (data, consumed) = dechunk(body);
        assert_eq!(data, b"a");
        assert_eq!(consumed, body.len());
    }

    #[test]
    fn a_split_start_line_replays_both_segments() {
        // The first segment stops before its LF, so neither segment carries a
        // start line by itself. The probe retains the first and replays both
        // once the second completes the line.
        let mut state = follow("follow,http,ascii,0");
        state.set_http_desegment(false);
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"GET /split");
        state.tcp_event(key(0, 1, 2), 0, 11, 1, b" HTTP/1.1\r\nHost: h\r\n\r\n");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(output.contains("10\nGET /split\n"), "{output}");
        assert!(
            output.contains("22\n HTTP/1.1\r\nHost: h\r\n\r\n\n"),
            "the second segment must follow the retained one: {output}"
        );
    }

    #[test]
    fn a_split_head_request_answers_bodyless() {
        // The split request line only parses once joined, so the probe records
        // its method before replaying the segments. RFC 9112 section 6.3 case
        // 1 then ends the answer at its header section.
        let mut state = follow("follow,http,ascii,0");
        state.set_http_desegment(false);
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"HEAD /split");
        state.tcp_event(key(0, 1, 2), 0, 11, 1, b" HTTP/1.1\r\nHost: h\r\n\r\n");
        state.tcp_event(
            reverse_key(0, 2, 1),
            1,
            1,
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\njunkMORE",
        );
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(
            output.contains("\t8\njunkMORE\n"),
            "the answer to HEAD must carry no body: {output}"
        );
        assert!(
            !output.contains("4\njunk"),
            "the declared length must not split a HEAD answer: {output}"
        );
    }

    #[test]
    fn an_invalid_complete_first_line_does_not_block_the_follow() {
        // A capture can start mid-body: `tail\r\n` is a complete line but
        // no HTTP start line. It must not be retained as a probe, or every
        // later valid message would be prefixed by it and ignored.
        let mut state = follow("follow,http,ascii,0");
        state.set_http_desegment(false);
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"tail\r\n");
        assert!(
            state.http_prefix.is_empty(),
            "an invalid line is not a probe"
        );
        assert!(state.http_probe.is_none());
        state.tcp_event(reverse_key(0, 2, 1), 1, 1, 1, b"HTTP/1.1 200 OK\r\n\r\n");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(
            output.contains("HTTP/1.1 200 OK"),
            "the later message must start the follow: {output}"
        );
    }

    #[test]
    fn an_incomplete_start_line_stops_at_the_probe_caps() {
        let mut state = follow("follow,http,ascii,0");
        state.set_http_desegment(false);
        for _ in 0..HTTP_PREFIX_PARTS {
            state.tcp_event(key(0, 1, 2), 0, 1, 1, b"x");
        }
        assert_eq!(state.http_prefix.len(), HTTP_PREFIX_PARTS);
        assert!(state.retained() > HTTP_PREFIX_PARTS);
        // One more segment cannot join the part list, so the probe releases
        // everything it kept and the stream stays not started.
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"y");
        assert!(state.http_prefix.is_empty());
        assert!(state.http_probe.is_none());
        assert!(!state.http_started);
        assert_eq!(state.retained(), 0);
        // A segment that cannot fit the byte bound clears the probe the same
        // way.
        let large = vec![b'x'; HTTP_PREFIX_LIMIT.saturating_add(1)];
        state.tcp_event(key(0, 1, 2), 0, 1, 1, &large);
        assert!(state.http_prefix.is_empty());
        assert!(!state.http_started);
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(!output.contains("xx"), "{output}");
    }

    #[test]
    fn tcp_follow_ignores_fully_seen_retransmissions() {
        let mut state = follow("follow,tcp,raw,0");
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"abcdef");
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"abcdef");
        state.tcp_event(key(0, 1, 2), 0, 4, 1, b"defghi");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert_eq!(output.matches("616263646566").count(), 1, "{output}");
        assert!(output.contains("676869"), "{output}");
    }

    #[test]
    fn a_specification_cap_truncates_after_sixteen_mibibytes() {
        let mut state = follow("follow,udp,raw,0");
        let block = vec![0x41_u8; 1024 * 1024];
        for _ in 0..17 {
            state.udp_event(key(0, 1, 2), &block);
        }
        assert!(state.truncated());
        assert!(state.retained() <= SPEC_LIMIT);
    }

    #[test]
    fn retained_bytes_include_record_bookkeeping() {
        let mut state = follow("follow,udp,raw,0");
        state.udp_event(key(0, 1, 2), b"x");
        assert!(
            state.retained() > 1,
            "a one-byte record charges its chunk vector: {}",
            state.retained()
        );
    }

    #[test]
    fn address_selection_matches_either_direction() {
        let mut state = follow("follow,udp,raw,10.0.0.1:1000,10.0.0.2:2000");
        state.udp_event(reverse_key(4, 2, 1), b"reply");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(output.contains("Filter: ((ip.src eq 10.0.0.1"), "{output}");
        assert!(output.contains("7265706c79"), "{output}");
    }

    #[test]
    fn ranges_skip_records_but_keep_per_direction_hex_offsets() {
        let mut state = follow("follow,tcp,hex,0,2-2");
        state.tcp_event(key(0, 1, 2), 0, 1, 1, b"aaaa");
        state.tcp_event(reverse_key(0, 2, 1), 1, 1, 5, b"bbbb");
        let mut output = String::new();
        state.finish(&mut output).unwrap_or(());
        assert!(!output.contains("aaaa"), "{output}");
        assert!(output.contains("\t00000000  62 62 62 62"), "{output}");
    }

    #[test]
    fn hex_dump_uses_the_fixed_layout() {
        let mut text = String::new();
        write_hex_dump(&mut text, false, 0, b"one\ntwo\n").unwrap_or(());
        assert_eq!(
            text,
            "00000000  6f 6e 65 0a 74 77 6f 0a                           one.two.\n"
        );
    }
}
