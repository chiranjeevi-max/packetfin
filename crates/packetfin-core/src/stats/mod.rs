//! `-z` statistics.
//!
//! One [`StatsSet`] belongs to one capture run. It builds a [`FrameFacts`]
//! snapshot once per decoded frame from the full protocol tree, before any
//! output filter prunes it, and feeds every registered specification from that
//! snapshot. The decoder therefore never learns about statistics and no
//! statistic re-walks the tree for a second decoder pass.
//!
//! Bounds: statistics live under one byte budget ([`DEFAULT_STATS_BUDGET`]).
//! Conversation and endpoint rows are evicted oldest-activity first; expert
//! keys and `io,stat` buckets have their own caps. A capped run prints one
//! notice per cause on standard error and keeps producing the rows it has,
//! so a hostile capture cannot exhaust memory or abort output.

mod conv;
mod dns_tree;
mod expert;
mod facts;
mod follow;
mod http_tree;
mod io_phs;
mod io_stat;
mod render;
mod stat_tree;

use std::collections::HashSet;
use std::fmt;

use crate::capture::{Frame, Timestamp};
use crate::decode::Packet;
use crate::fields::{FieldDef, ProtocolDef, field_by_abbrev, protocols};
use crate::filter::Filter;
use crate::tree::Severity;

pub use facts::{ConvKind, FrameFacts};
pub use follow::{FollowEndpoint, FollowMode, FollowProto, FollowSelector, FollowSpec};
pub use io_stat::{IoArgument, IoCalc, IoColumnSpec, IoStatSpec};

use facts::Interests;

/// Packetfin's default statistics budget: 64 MiB, a ledger separate from
/// state and two-pass annotations.
pub const DEFAULT_STATS_BUDGET: usize = 64 * 1024 * 1024;

/// The heading printed before the `-z` name list.
pub const STATS_HELP_HEADING: &str = "The available statistics for the \"-z\" option are:";

/// The `-z` statistics Packetfin implements, in report order.
pub const SUPPORTED: &[&str] = &[
    "conv,eth",
    "conv,ip",
    "conv,ipv6",
    "conv,sll",
    "conv,tcp",
    "conv,udp",
    "endpoints,eth",
    "endpoints,ip",
    "endpoints,ipv6",
    "endpoints,sll",
    "endpoints,tcp",
    "endpoints,udp",
    "dns,tree",
    "expert",
    "follow,http",
    "follow,tcp",
    "follow,tls",
    "follow,udp",
    "http,tree",
    "io,phs",
    "io,stat",
];

/// A display filter attached to one statistic, together with the text that
/// the table header prints.
///
/// A statistic with no filter (`-z io,phs`) has neither; an explicit empty
/// filter (`-z conv,tcp,`) keeps an empty expression that matches every
/// packet and prints an empty `Filter:` value.
#[derive(Clone, Debug, PartialEq)]
pub struct StatsFilter {
    /// The compiled expression, or `None` when no filter was given.
    pub filter: Option<Filter>,
    /// The original expression text, or `None` when no filter was given.
    pub text: Option<String>,
}

impl StatsFilter {
    /// No filter: every packet is counted and the table prints its default.
    pub fn none() -> Self {
        Self {
            filter: None,
            text: None,
        }
    }

    /// Compile an expression for a statistic.
    fn compile(text: &str, error_prefix: &str, error_suffix: &str) -> Result<Self, String> {
        let filter = Filter::parse(text).map_err(|error| {
            let reason = filter_error_reason(text, &error);
            format!("{error_prefix}Filter \"{text}\" is invalid - {reason}{error_suffix}")
        })?;
        Ok(Self {
            filter: Some(filter),
            text: Some(text.to_string()),
        })
    }

    /// Whether the frame represented by `tree` passes this filter.
    pub fn matches(&self, tree: &crate::tree::Tree) -> bool {
        self.filter
            .as_ref()
            .is_none_or(|filter| filter.matches(tree))
    }

    /// The text the `Filter:` header prints, if any.
    pub fn header_text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    /// Fields the filter references. Only these field occurrences are visible
    /// to an `io,stat` expression.
    fn referenced_fields(&self) -> Vec<&'static FieldDef> {
        self.filter
            .as_ref()
            .map(|filter| filter.references().0)
            .unwrap_or_default()
    }

    /// Protocols the filter references, for `COUNT(protocol)` expressions.
    fn referenced_protocols(&self) -> Vec<&'static ProtocolDef> {
        self.filter
            .as_ref()
            .map(|filter| filter.references().1)
            .unwrap_or_default()
    }
}

/// Render the reason part of a `-z` filter error.
///
/// An unknown symbol and an expression that ends early get fixed wording, so
/// scripts that check `-z` validation messages see stable text. Other syntax
/// errors keep the parser's own message with a trailing period.
fn filter_error_reason(text: &str, error: &crate::filter::FilterError) -> String {
    let message = error.message();
    if let Some(quoted) = message.strip_suffix(" is not a registered protocol or field") {
        return format!("{quoted} is not a valid protocol or protocol field.");
    }
    if message.contains("\"\" is not a valid integer")
        || message == "a closing parenthesis is missing"
        || error.offset() >= text.len()
    {
        return "Unexpected end of filter expression.".to_string();
    }
    if message.trim_end_matches('.') == "unexpected token in the display filter"
        && let Some(character) = text
            .get(error.offset()..)
            .and_then(|rest| rest.chars().next())
    {
        return format!("\"{character}\" was unexpected in this context.");
    }
    if message.ends_with('.') {
        message.to_string()
    } else {
        format!("{message}.")
    }
}

/// One statistic selected by `-z`.
#[derive(Clone, Debug, PartialEq)]
pub enum StatsSpec {
    /// `io,stat`: interval buckets and computed columns.
    IoStat(IoStatSpec),
    /// `io,phs`: protocol hierarchy.
    IoPhs {
        /// Optional frame filter.
        filter: StatsFilter,
    },
    /// `endpoints,<family>`.
    Endpoints {
        /// Address family and ports.
        kind: ConvKind,
        /// Optional frame filter.
        filter: StatsFilter,
    },
    /// `conv,<family>`.
    Conversations {
        /// Address family and ports.
        kind: ConvKind,
        /// Optional frame filter.
        filter: StatsFilter,
    },
    /// `expert`: aggregated expert-info frequencies.
    Expert {
        /// Lowest severity included in the table.
        min_severity: Severity,
        /// Optional frame filter.
        filter: StatsFilter,
    },
    /// `dns,tree`: the DNS packet counter tree.
    DnsTree {
        /// Optional frame filter.
        filter: StatsFilter,
    },
    /// `http,tree`: the HTTP packet counter tree.
    HttpTree {
        /// Optional frame filter.
        filter: StatsFilter,
    },
    /// `follow,<proto>,<mode>,<selector>[,<range>]`.
    Follow(FollowSpec),
}

/// Fixed print order between statistic categories.
///
/// Categories print in this forward order, with reverse command-line order
/// inside one category, so every table family has a stable position in the
/// report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Category {
    IoStat = 0,
    IoPhs = 1,
    Endpoints = 2,
    Conversations = 3,
    Trees = 4,
    Expert = 5,
    Follow = 6,
}

impl StatsSpec {
    fn category(&self) -> Category {
        match self {
            Self::IoStat(_) => Category::IoStat,
            Self::IoPhs { .. } => Category::IoPhs,
            Self::Endpoints { .. } => Category::Endpoints,
            Self::Conversations { .. } => Category::Conversations,
            Self::Expert { .. } => Category::Expert,
            Self::DnsTree { .. } | Self::HttpTree { .. } => Category::Trees,
            Self::Follow(_) => Category::Follow,
        }
    }
}

/// Statistics selected for one run.
#[derive(Clone, Debug, PartialEq)]
pub struct StatsOptions {
    /// Specifications in command-line order.
    pub specs: Vec<StatsSpec>,
    /// Byte budget shared by every statistic.
    pub budget: usize,
}

impl Default for StatsOptions {
    fn default() -> Self {
        Self {
            specs: Vec::new(),
            budget: DEFAULT_STATS_BUDGET,
        }
    }
}

/// Parse one `-z` specification.
///
/// Filters compile here, before any capture file is opened, so an invalid
/// filter exits before the read loop starts.
pub fn parse_spec(text: &str) -> Result<StatsSpec, String> {
    if text == "help" {
        return Err(unsupported(text));
    }
    if text == "io,stat" || text.starts_with("io,stat,") {
        return io_stat::parse(text).map(StatsSpec::IoStat);
    }
    if text == "io,phs" || text.starts_with("io,phs,") {
        let filter = match text.strip_prefix("io,phs,") {
            Some(filter) => StatsFilter::compile(filter, "Couldn't register io,phs tap: ", "")?,
            None => StatsFilter::none(),
        };
        return Ok(StatsSpec::IoPhs { filter });
    }
    if let Some(rest) = text.strip_prefix("conv,") {
        let (family, filter) = rest
            .split_once(',')
            .map_or((rest, None), |(family, filter)| (family, Some(filter)));
        let Some(kind) = ConvKind::parse(family) else {
            return Err(unsupported(text));
        };
        let filter = match filter {
            Some(filter) => {
                StatsFilter::compile(filter, "Couldn't register conversations tap: ", "")?
            }
            None => StatsFilter::none(),
        };
        return Ok(StatsSpec::Conversations { kind, filter });
    }
    if let Some(rest) = text.strip_prefix("endpoints,") {
        let (family, filter) = rest
            .split_once(',')
            .map_or((rest, None), |(family, filter)| (family, Some(filter)));
        let Some(kind) = ConvKind::parse(family) else {
            return Err(unsupported(text));
        };
        let filter = match filter {
            Some(filter) => StatsFilter::compile(filter, "Couldn't register endpoint tap: ", "")?,
            None => StatsFilter::none(),
        };
        return Ok(StatsSpec::Endpoints { kind, filter });
    }
    if text == "expert" || text.starts_with("expert,") {
        return expert::parse(text).map(|(min_severity, filter)| StatsSpec::Expert {
            min_severity,
            filter,
        });
    }
    if text == "dns,tree" || text.starts_with("dns,tree,") {
        let filter = match text.strip_prefix("dns,tree,") {
            Some(filter) => StatsFilter::compile(filter, "Couldn't register dns,tree tap: ", "")?,
            None => StatsFilter::none(),
        };
        return Ok(StatsSpec::DnsTree { filter });
    }
    if text == "http,tree" || text.starts_with("http,tree,") {
        let filter = match text.strip_prefix("http,tree,") {
            Some(filter) => StatsFilter::compile(filter, "Couldn't register http,tree tap: ", "")?,
            None => StatsFilter::none(),
        };
        return Ok(StatsSpec::HttpTree { filter });
    }
    if text == "follow" || text.starts_with("follow,") {
        return follow::parse(text).map(StatsSpec::Follow);
    }
    Err(unsupported(text))
}

/// Whether `-z text` names a statistic Packetfin implements.
///
/// Category and family names are validated eagerly so an unknown statistic
/// still wins over an invalid display filter; filter and interval grammar is
/// compiled later, after `-Y`.
pub fn name_supported(text: &str) -> bool {
    if text == "io,stat" || text.starts_with("io,stat,") {
        return true;
    }
    if text == "io,phs" || text.starts_with("io,phs,") {
        return true;
    }
    if let Some(rest) = text.strip_prefix("conv,") {
        let family = rest.split(',').next().unwrap_or_default();
        return ConvKind::parse(family).is_some();
    }
    if let Some(rest) = text.strip_prefix("endpoints,") {
        let family = rest.split(',').next().unwrap_or_default();
        return ConvKind::parse(family).is_some();
    }
    if text == "dns,tree" || text.starts_with("dns,tree,") {
        return true;
    }
    if text == "http,tree" || text.starts_with("http,tree,") {
        return true;
    }
    if text == "follow" || text.starts_with("follow,") {
        return true;
    }
    text == "expert" || text.starts_with("expert,")
}

/// Build the message for a `-z` name Packetfin does not implement, including
/// the list of supported names.
pub fn unsupported(text: &str) -> String {
    let mut message = format!("Invalid -z argument \"{text}\"; it must be one of:");
    for name in SUPPORTED {
        message.push_str("\n     ");
        message.push_str(name);
    }
    message
}

/// The `-z help` body, without the leading diagnostic prefix.
pub fn help_text() -> String {
    let mut text = STATS_HELP_HEADING.to_string();
    for name in SUPPORTED {
        text.push_str("\n     ");
        text.push_str(name);
    }
    text
}

/// One statistics run over a capture.
///
/// The set borrows its specifications so the CLI option value survives
/// untouched, and owns only aggregation state.
pub struct StatsSet<'a> {
    specs: &'a [StatsSpec],
    states: Vec<State>,
    interests: Interests,
    clock: Clock,
    budget: Budget,
    follow_limit: usize,
    /// Bytes of the shared budget currently charged by follow states.
    follow_charged: usize,
    notices: Notices,
}

enum State {
    IoStat(io_stat::State),
    IoPhs(io_phs::State),
    Conversations(conv::State),
    Endpoints(conv::State),
    Expert(expert::State),
    DnsTree(dns_tree::State),
    HttpTree(http_tree::State),
    Follow(follow::State),
}

impl<'a> StatsSet<'a> {
    /// Create aggregation state for the selected specifications.
    pub fn new(options: &'a StatsOptions) -> Self {
        let interests = Interests::for_specs(&options.specs);
        let follow_limit = options.budget.min(follow::TOTAL_LIMIT);
        let follow_specs = options
            .specs
            .iter()
            .filter(|spec| matches!(spec, StatsSpec::Follow(_)))
            .count()
            .max(1);
        let follow_share = follow_limit / follow_specs;
        // Conversation and endpoint tables each get an equal share of the
        // ledger so two tables cannot both grow toward the full budget.
        let conv_tables = options
            .specs
            .iter()
            .filter(|spec| {
                matches!(
                    spec,
                    StatsSpec::Conversations { .. } | StatsSpec::Endpoints { .. }
                )
            })
            .count()
            .max(1);
        let conv_share = options.budget / conv_tables;
        let mut states = Vec::with_capacity(options.specs.len());
        for spec in &options.specs {
            states.push(match spec {
                StatsSpec::IoStat(spec) => State::IoStat(io_stat::State::new(spec)),
                StatsSpec::IoPhs { .. } => State::IoPhs(io_phs::State::default()),
                StatsSpec::Endpoints { kind, .. } => {
                    State::Endpoints(conv::State::new(*kind, true, conv_share))
                }
                StatsSpec::Conversations { kind, .. } => {
                    State::Conversations(conv::State::new(*kind, false, conv_share))
                }
                StatsSpec::Expert { .. } => State::Expert(expert::State::default()),
                StatsSpec::DnsTree { .. } => State::DnsTree(dns_tree::State::default()),
                StatsSpec::HttpTree { .. } => State::HttpTree(http_tree::State::default()),
                StatsSpec::Follow(spec) => {
                    State::Follow(follow::State::with_limit(spec.clone(), follow_share))
                }
            });
        }
        Self {
            specs: &options.specs,
            states,
            interests,
            clock: Clock::default(),
            budget: Budget::new(options.budget),
            follow_limit,
            follow_charged: 0,
            notices: Notices::default(),
        }
    }

    /// Feed one decoded frame to every specification.
    ///
    /// `packet` must still carry the complete tree: callers feed statistics
    /// before an output mode prunes it.
    pub fn observe(&mut self, frame: &Frame, packet: &Packet) {
        if self.specs.is_empty() {
            return;
        }
        self.clock.observe(frame);
        let facts = FrameFacts::build(frame, packet, &self.interests);
        let Self {
            specs,
            states,
            clock,
            budget,
            notices,
            ..
        } = self;
        for (index, spec) in specs.iter().enumerate() {
            let Some(state) = states.get_mut(index) else {
                continue;
            };
            state.observe(spec, &facts, clock, budget, notices);
        }
    }

    /// Render every table in category order.
    pub fn finish(&mut self, output: &mut dyn fmt::Write) -> fmt::Result {
        let duration = self.clock.duration_micros();
        if self.follow_used() >= follow::TOTAL_LIMIT
            || self.states.iter().any(|state| match state {
                State::Follow(state) => state.truncated(),
                _ => false,
            })
        {
            self.notices.once(
                "follow-buffer",
                "follow stream buffer limit reached; stream truncated",
            );
        }
        for spec in self.specs {
            if let StatsSpec::IoStat(spec) = spec
                && spec.interval_micros > 0
                && duration / spec.interval_micros > io_stat::MAX_BUCKETS as u64
            {
                self.notices.once(
                    "io-stat-render-cap",
                    "statistics budget reached; io,stat rows were capped",
                );
            }
        }
        for category in [
            Category::IoStat,
            Category::IoPhs,
            Category::Endpoints,
            Category::Conversations,
            Category::Trees,
            Category::Expert,
            Category::Follow,
        ] {
            for (index, spec) in self.specs.iter().enumerate().rev() {
                if spec.category() != category {
                    continue;
                }
                if let Some(state) = self.states.get_mut(index) {
                    state.finish(spec, duration, output)?;
                }
            }
        }
        Ok(())
    }

    /// Consume the budget and format notices collected during the run.
    pub fn take_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notices.messages)
    }

    /// Bytes currently charged to the statistics budget.
    pub fn budget_used(&self) -> usize {
        self.budget.used
    }
}

impl State {
    fn observe(
        &mut self,
        spec: &StatsSpec,
        facts: &FrameFacts<'_>,
        clock: &Clock,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        match (self, spec) {
            (Self::IoStat(state), StatsSpec::IoStat(spec)) => {
                state.observe(spec, facts, clock, budget, notices);
            }
            (Self::IoPhs(state), StatsSpec::IoPhs { filter }) => {
                state.observe(facts, filter, budget, notices);
            }
            (Self::Conversations(state), StatsSpec::Conversations { filter, .. })
            | (Self::Endpoints(state), StatsSpec::Endpoints { filter, .. }) => {
                state.observe(facts, filter, budget, notices, clock);
            }
            (
                Self::Expert(state),
                StatsSpec::Expert {
                    min_severity,
                    filter,
                },
            ) => {
                state.observe(facts, *min_severity, filter, budget, notices);
            }
            (Self::DnsTree(state), StatsSpec::DnsTree { filter }) => {
                state.observe(facts, filter, clock, budget, notices);
            }
            (Self::HttpTree(state), StatsSpec::HttpTree { filter }) => {
                state.observe(facts, filter, clock, budget, notices);
            }
            (Self::Follow(_), StatsSpec::Follow(_)) => {}
            _ => {}
        }
    }

    fn finish(
        &mut self,
        spec: &StatsSpec,
        duration_micros: u64,
        output: &mut dyn fmt::Write,
    ) -> fmt::Result {
        match (self, spec) {
            (Self::IoStat(state), StatsSpec::IoStat(spec)) => {
                state.finish(spec, duration_micros, output)
            }
            (Self::IoPhs(state), StatsSpec::IoPhs { filter }) => state.finish(filter, output),
            (Self::Conversations(state), StatsSpec::Conversations { filter, .. })
            | (Self::Endpoints(state), StatsSpec::Endpoints { filter, .. }) => {
                state.finish(filter, output)
            }
            (
                Self::Expert(state),
                StatsSpec::Expert {
                    min_severity,
                    filter,
                },
            ) => state.finish(*min_severity, filter, output),
            (Self::DnsTree(state), StatsSpec::DnsTree { .. }) => state.finish(output),
            (Self::HttpTree(state), StatsSpec::HttpTree { .. }) => state.finish(output),
            (Self::Follow(state), StatsSpec::Follow(_)) => state.finish(output),
            _ => Ok(()),
        }
    }
}

impl crate::state::StreamObserver for StatsSet<'_> {
    fn tcp_payload(
        &mut self,
        key: crate::state::StreamKey,
        direction: u8,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) {
        self.forward_follow(|state| {
            state.tcp_event(key, direction, sequence, acknowledgement, payload);
        });
    }

    fn udp_payload(&mut self, key: crate::state::StreamKey, _direction: u8, payload: &[u8]) {
        self.forward_follow(|state| state.udp_event(key, payload));
    }

    fn http_message(&mut self, key: crate::state::StreamKey, _direction: u8, message: &[u8]) {
        self.forward_follow(|state| state.http_event(key, message));
    }
}

impl StatsSet<'_> {
    /// The follow sink the decode session forwards payloads to.
    pub fn stream_observer(&mut self) -> &mut dyn crate::state::StreamObserver {
        self
    }

    /// Tell HTTP follows whether the TCP dissector reassembled messages.
    pub fn set_http_desegment(&mut self, desegment: bool) {
        for state in &mut self.states {
            if let State::Follow(state) = state {
                state.set_http_desegment(desegment);
            }
        }
    }

    fn forward_follow(&mut self, mut observe: impl FnMut(&mut follow::State)) {
        let Self {
            specs,
            states,
            budget,
            follow_limit,
            follow_charged,
            ..
        } = self;
        // Other statistics have already reserved their share; follow may only
        // use what remains of the one shared ledger. `budget.used` includes
        // the amount charged here on the previous event, so subtract it
        // before deciding how much room follow has now.
        let other_used = budget.used.saturating_sub(*follow_charged);
        let used = follow_retained(states);
        let follow_cap = budget.limit.saturating_sub(other_used).min(*follow_limit);
        // When the ledger is already full, still let the states see the
        // event: `allow` gives them no room, so a chunk that would cross the
        // cap is dropped and the state records truncation for the finish
        // notice instead of being discarded silently.
        let mut running = used;
        for (index, spec) in specs.iter().enumerate() {
            if !matches!(spec, StatsSpec::Follow(_)) {
                continue;
            }
            let Some(State::Follow(state)) = states.get_mut(index) else {
                continue;
            };
            let remaining = follow_cap.saturating_sub(running);
            state.allow(remaining);
            let before = state.retained();
            observe(state);
            running = running
                .saturating_sub(before)
                .saturating_add(state.retained());
        }
        let grown = follow_retained(states);
        *follow_charged = grown;
        if grown >= used {
            // The per-spec caps above keep `other_used + grown` within the
            // ledger, so this cannot fail; a checked failure would only mean
            // the caller configured a zero-byte budget.
            let _ = budget.reserve(grown - used);
        } else {
            budget.release(used - grown);
        }
    }

    fn follow_used(&self) -> usize {
        follow_retained(&self.states)
    }
}

fn follow_retained(states: &[State]) -> usize {
    states
        .iter()
        .filter_map(|state| match state {
            State::Follow(state) => Some(state.retained()),
            _ => None,
        })
        .sum()
}

/// Capture clock shared by every statistic.
///
/// `relative_ns` is the current frame's time since the first timestamped
/// frame (negative for out-of-order captures). `duration_micros` spans the
/// first and last frame read, independent of any statistic filter.
#[derive(Default)]
struct Clock {
    first: Option<Timestamp>,
    last: Option<Timestamp>,
    relative_ns: i64,
}

impl Clock {
    fn observe(&mut self, frame: &Frame) {
        let Some(timestamp) = frame.timestamp else {
            self.relative_ns = 0;
            return;
        };
        let first = *self.first.get_or_insert(timestamp);
        self.relative_ns = crate::state::timestamp_delta(first, timestamp);
        self.last = Some(timestamp);
    }

    fn duration_micros(&self) -> u64 {
        match (self.first, self.last) {
            (Some(first), Some(last)) => {
                let delta = crate::state::timestamp_delta(first, last).max(0);
                micros_from_nanos(delta)
            }
            _ => 0,
        }
    }
}

/// Convert nanoseconds to microseconds, rounding half up.
fn micros_from_nanos(nanos: i64) -> u64 {
    let rounded = i128::from(nanos) + 500;
    let micros = rounded.div_euclid(1_000);
    u64::try_from(micros.max(0)).unwrap_or(u64::MAX)
}

/// Shared byte accounting for every statistic.
struct Budget {
    limit: usize,
    used: usize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Charge `bytes`, or report that the budget is full.
    fn reserve(&mut self, bytes: usize) -> bool {
        let Some(total) = self.used.checked_add(bytes) else {
            return false;
        };
        if total > self.limit {
            return false;
        }
        self.used = total;
        true
    }

    fn release(&mut self, bytes: usize) {
        self.used = self.used.saturating_sub(bytes);
    }
}

/// One-shot notices for bounded statistics.
#[derive(Default)]
struct Notices {
    seen: HashSet<&'static str>,
    messages: Vec<String>,
}

impl Notices {
    fn once(&mut self, key: &'static str, message: impl Into<String>) {
        if self.seen.insert(key) {
            self.messages.push(message.into());
        }
    }
}

/// Look up a field or protocol name for an `io,stat` expression.
fn field_or_protocol(name: &str) -> Option<IoArgument> {
    if let Some(field) = field_by_abbrev(name) {
        return Some(IoArgument::Field(field));
    }
    protocols()
        .iter()
        .find(|protocol| protocol.filter_name == name)
        .copied()
        .map(IoArgument::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Frame, Timestamp};
    use crate::decode::decode_frame;

    fn spec(text: &str) -> StatsSpec {
        match parse_spec(text) {
            Ok(spec) => spec,
            Err(error) => {
                eprintln!("invalid statistic {text:?}: {error}");
                std::process::exit(1);
            }
        }
    }

    fn ethernet_udp_frame(number: u64) -> Frame {
        let mut captured = Vec::new();
        captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        captured.extend_from_slice(&0x0800_u16.to_be_bytes());
        captured.extend_from_slice(&[0x45, 0, 0, 36, 0, 1, 0x40, 0, 64, 17, 0, 0]);
        captured.extend_from_slice(&[192, 0, 2, 1]);
        captured.extend_from_slice(&[198, 51, 100, 2]);
        captured.extend_from_slice(&[0x04, 0xd2, 0x08, 0xae]);
        captured.extend_from_slice(&8_u16.to_be_bytes());
        captured.extend_from_slice(&[0, 0]);
        Frame {
            number,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            timestamp_precision: 6,
            captured,
            original_len: 42,
            link_type: 1,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: None,
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: crate::capture::PacketOptions::default(),
        }
    }

    #[test]
    fn a_zero_budget_keeps_tables_bounded_and_notices() {
        let options = StatsOptions {
            specs: vec![
                spec("conv,eth"),
                spec("endpoints,eth"),
                spec("expert"),
                spec("io,phs"),
            ],
            budget: 0,
        };
        let frame = ethernet_udp_frame(1);
        let packet = decode_frame(&frame);
        let mut set = StatsSet::new(&options);
        for _ in 0..8 {
            set.observe(&frame, &packet);
        }
        assert_eq!(set.budget_used(), 0);
        let notices = set.take_notices();
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("conversation rows")),
            "a bounded run announces its loss: {notices:?}"
        );
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("protocol hierarchy")),
            "io,phs is inside the budget: {notices:?}"
        );
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        assert!(output.contains("Ethernet Conversations"));
        assert!(output.contains("Ethernet Endpoints"));
    }

    fn find_node<'a>(
        node: &'a mut crate::tree::Node,
        name: &str,
    ) -> Option<&'a mut crate::tree::Node> {
        if node.protocol.filter_name == name {
            return Some(node);
        }
        node.children
            .iter_mut()
            .find_map(|child| find_node(child, name))
    }

    fn set_field(
        packet: &mut crate::decode::Packet,
        node_name: &str,
        abbrev: &str,
        value: crate::tree::Value,
    ) {
        let Some(node) = find_node(&mut packet.tree.frame, node_name) else {
            return;
        };
        if let Some(field) = node
            .fields
            .iter_mut()
            .find(|field| field.def.abbrev == abbrev)
        {
            field.value = value;
        }
    }

    #[test]
    fn a_million_conversations_stay_inside_the_budget() {
        let options = StatsOptions {
            specs: vec![spec("conv,ip")],
            budget: 64 * 1024,
        };
        let frame = ethernet_udp_frame(1);
        let mut packet = decode_frame(&frame);
        let mut set = StatsSet::new(&options);
        for index in 0..1_000_000_u32 {
            let address = index.to_be_bytes();
            set_field(
                &mut packet,
                "ip",
                "ip.src",
                crate::tree::Value::Ipv4([10, address[1], address[2], address[3]]),
            );
            set.observe(&frame, &packet);
        }
        assert!(set.budget_used() <= 64 * 1024);
        assert!(
            set.take_notices()
                .iter()
                .any(|notice| notice.contains("conversation rows")),
            "row eviction is announced"
        );
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        assert!(output.lines().count() < 5_000, "bounded row output");
    }

    #[test]
    fn two_conversation_tables_share_the_budget() {
        let budget = 64 * 1024;
        let options = StatsOptions {
            specs: vec![spec("conv,ip"), spec("endpoints,ip")],
            budget,
        };
        let frame = ethernet_udp_frame(1);
        let mut packet = decode_frame(&frame);
        let mut set = StatsSet::new(&options);
        for index in 0..200_000_u32 {
            let address = index.to_be_bytes();
            set_field(
                &mut packet,
                "ip",
                "ip.src",
                crate::tree::Value::Ipv4([10, address[1], address[2], address[3]]),
            );
            set.observe(&frame, &packet);
        }
        assert!(
            set.budget_used() <= budget,
            "two tables stay inside one ledger: {} > {budget}",
            set.budget_used()
        );
        assert!(
            set.take_notices()
                .iter()
                .any(|notice| notice.contains("conversation rows")),
            "row eviction is announced"
        );
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        assert!(output.contains("IPv4 Conversations"));
        assert!(output.contains("IPv4 Endpoints"));
        assert!(output.lines().count() < 5_000, "bounded two-table output");
    }

    #[test]
    fn a_table_evicted_before_a_successful_reserve_still_notices() {
        // The shared ledger has room for all rows, but the conv table's own
        // share forces eviction; the later reserve succeeds, so the notice
        // must come from the share eviction rather than from a failed insert.
        let options = StatsOptions {
            specs: vec![spec("conv,ip"), spec("conv,tcp")],
            budget: 256 * 1024,
        };
        let frame = ethernet_udp_frame(1);
        let mut packet = decode_frame(&frame);
        let mut set = StatsSet::new(&options);
        for index in 0..10_000_u32 {
            let address = index.to_be_bytes();
            set_field(
                &mut packet,
                "ip",
                "ip.src",
                crate::tree::Value::Ipv4([10, address[1], address[2], address[3]]),
            );
            set.observe(&frame, &packet);
        }
        assert!(
            set.take_notices()
                .iter()
                .any(|notice| notice.contains("conversation rows")),
            "a share eviction is announced even when the ledger reserve succeeds"
        );
        assert!(set.budget_used() <= 256 * 1024);
    }

    #[test]
    fn a_million_expert_entries_stay_inside_the_key_cap() {
        let options = StatsOptions {
            specs: vec![spec("expert")],
            budget: 16 * 1024 * 1024,
        };
        let frame = ethernet_udp_frame(1);
        let mut packet = decode_frame(&frame);
        let mut set = StatsSet::new(&options);
        for index in 0..1_000_000_u32 {
            let Some(node) = find_node(&mut packet.tree.frame, "udp") else {
                continue;
            };
            node.experts = vec![crate::tree::ExpertInfo {
                severity: Severity::Note,
                group: crate::tree::Group::Sequence,
                message: format!("expert entry {index}"),
            }];
            set.observe(&frame, &packet);
        }
        assert!(set.budget_used() <= 16 * 1024 * 1024);
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        assert!(
            output.lines().count() <= 100_010,
            "expert key cap bounds rows"
        );
    }

    fn short_frame(link_type: u32, captured: Vec<u8>, number: u64) -> Frame {
        Frame {
            number,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: u32::try_from(number).unwrap_or(0),
            }),
            timestamp_precision: 6,
            original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
            captured,
            link_type,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: None,
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: crate::capture::PacketOptions::default(),
        }
    }

    #[test]
    fn short_ethernet_and_sll_headers_do_not_create_conversations() {
        let eth_options = StatsOptions {
            specs: vec![spec("conv,eth")],
            budget: DEFAULT_STATS_BUDGET,
        };
        let mut eth = StatsSet::new(&eth_options);
        let mut full_ethernet = Vec::new();
        full_ethernet.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        full_ethernet.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        full_ethernet.extend_from_slice(&0x0800_u16.to_be_bytes());
        for length in [12_usize, 13, 14] {
            let mut bytes = full_ethernet.clone();
            bytes.truncate(length);
            let frame = short_frame(1, bytes, u64::try_from(length).unwrap_or(0));
            let packet = crate::decode::decode_frame(&frame);
            eth.observe(&frame, &packet);
        }
        let mut output = String::new();
        assert!(eth.finish(&mut output).is_ok());
        assert!(output.contains("1 14 bytes"), "{output}");
        assert!(!output.contains("12 bytes"), "{output}");
        assert!(!output.contains("13 bytes"), "{output}");

        let sll_options = StatsOptions {
            specs: vec![spec("conv,sll")],
            budget: DEFAULT_STATS_BUDGET,
        };
        let mut sll = StatsSet::new(&sll_options);
        let mut full_sll = Vec::new();
        full_sll.extend_from_slice(&1_u16.to_be_bytes());
        full_sll.extend_from_slice(&1_u16.to_be_bytes());
        full_sll.extend_from_slice(&6_u16.to_be_bytes());
        full_sll.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        full_sll.extend_from_slice(&[0, 0]);
        full_sll.extend_from_slice(&0x0800_u16.to_be_bytes());
        for length in [15_usize, 16] {
            let mut bytes = full_sll.clone();
            bytes.truncate(length);
            let frame = short_frame(113, bytes, u64::try_from(length).unwrap_or(0));
            let packet = crate::decode::decode_frame(&frame);
            sll.observe(&frame, &packet);
        }
        let mut output = String::new();
        assert!(sll.finish(&mut output).is_ok());
        assert!(output.contains("1 16 bytes"), "{output}");
        assert!(!output.contains("15 bytes"), "{output}");
    }

    #[test]
    fn a_long_multibyte_column_label_wraps_without_panicking() {
        let label = format!("dns.qry.name==\"a{}\"", "ü".repeat(40));
        let spec = spec(&format!("io,stat,1,{label}"));
        let options = StatsOptions {
            specs: vec![spec],
            budget: DEFAULT_STATS_BUDGET,
        };
        let mut set = StatsSet::new(&options);
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        assert!(output.contains("Col  1:"), "{output}");
    }

    #[test]
    fn specs_parse_filters_before_reading() {
        assert!(parse_spec("io,stat,1us").is_err());
        assert!(parse_spec("io,stat,0,").is_err());
        assert!(parse_spec("io,phs,bogus").is_err());
        assert!(parse_spec("conv,nosuch").is_err());
        assert!(parse_spec("endpoints,ip,bogus").is_err());
        assert!(parse_spec("expert,bogus").is_err());
        assert!(parse_spec("follow,nosuch,ascii,0").is_err());
        assert!(parse_spec("follow,tcp,bogus,0").is_err());
        assert!(parse_spec("dns,tree,bogus").is_err());
        assert!(parse_spec("http,tree,bogus").is_err());
    }

    #[test]
    fn expert_specs_carry_their_threshold_and_filter() {
        match spec("expert,note") {
            StatsSpec::Expert {
                min_severity,
                filter,
            } => {
                assert_eq!(min_severity, Severity::Note);
                assert!(filter.filter.is_none());
            }
            other => {
                eprintln!("unexpected {other:?}");
                std::process::exit(1);
            }
        }
        match spec("expert,tcp") {
            StatsSpec::Expert {
                min_severity,
                filter,
            } => {
                assert_eq!(min_severity, Severity::Comment);
                assert_eq!(filter.text.as_deref(), Some("tcp"));
            }
            other => {
                eprintln!("unexpected {other:?}");
                std::process::exit(1);
            }
        }
    }

    #[test]
    fn invalid_filters_use_fixed_wording() {
        let Err(error) = parse_spec("io,phs,bogus") else {
            eprintln!("invalid filter accepted");
            return;
        };
        assert!(
            error.contains(
                "Filter \"bogus\" is invalid - \"bogus\" is not a valid protocol or protocol field."
            ),
            "{error}"
        );
    }
}

#[cfg(test)]
mod follow_budget_tests {
    use super::*;
    use crate::state::{StreamAddress, StreamKey, StreamObserver};

    #[test]
    fn a_follow_cap_prints_one_notice() {
        let specs = ["follow,tcp,ascii,0", "follow,tcp,ascii,1"]
            .into_iter()
            .filter_map(|spec| parse_spec(spec).ok())
            .collect::<Vec<_>>();
        let options = StatsOptions {
            specs,
            budget: DEFAULT_STATS_BUDGET,
        };
        let mut set = StatsSet::new(&options);
        let key = StreamKey {
            index: 0,
            source: StreamAddress::Ipv4([10, 0, 0, 1]),
            source_port: 1000,
            destination: StreamAddress::Ipv4([10, 0, 0, 2]),
            destination_port: 2000,
        };
        let payload = vec![0x41_u8; follow::SPEC_LIMIT + 1];
        set.tcp_payload(key, 0, 1, 1, &payload);
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        let notices = set.take_notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(
            notices
                .first()
                .is_some_and(|notice| notice.contains("follow stream buffer limit"))
        );
    }

    #[test]
    fn a_full_follow_ledger_still_notices_a_dropped_chunk() {
        let key = StreamKey {
            index: 0,
            source: StreamAddress::Ipv4([10, 0, 0, 1]),
            source_port: 1000,
            destination: StreamAddress::Ipv4([10, 0, 0, 2]),
            destination_port: 2000,
        };
        let specs = ["follow,tcp,ascii,0"]
            .into_iter()
            .filter_map(|spec| parse_spec(spec).ok())
            .collect::<Vec<_>>();
        let probe_options = StatsOptions {
            specs: specs.clone(),
            budget: DEFAULT_STATS_BUDGET,
        };
        let mut probe = StatsSet::new(&probe_options);
        probe.tcp_payload(key, 0, 1, 1, b"0123456789");
        let charge = probe.follow_used();
        assert!(charge > 10, "the record overhead is charged: {charge}");

        let options = StatsOptions {
            specs,
            budget: charge,
        };
        let mut set = StatsSet::new(&options);
        set.tcp_payload(key, 0, 1, 1, b"0123456789");
        assert_eq!(
            set.follow_used(),
            charge,
            "the first chunk fills the ledger"
        );
        set.tcp_payload(key, 0, 11, 1, b"x");
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        let notices = set.take_notices();
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("follow stream buffer limit")),
            "{notices:?}"
        );
    }

    #[test]
    fn a_zero_budget_retains_no_follow_chunks() {
        let specs = ["follow,tcp,ascii,0"]
            .into_iter()
            .filter_map(|spec| parse_spec(spec).ok())
            .collect::<Vec<_>>();
        let options = StatsOptions { specs, budget: 0 };
        let mut set = StatsSet::new(&options);
        let key = StreamKey {
            index: 0,
            source: StreamAddress::Ipv4([10, 0, 0, 1]),
            source_port: 1000,
            destination: StreamAddress::Ipv4([10, 0, 0, 2]),
            destination_port: 2000,
        };
        set.tcp_payload(key, 0, 1, 1, b"payload");
        assert_eq!(set.follow_used(), 0);
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
    }

    #[test]
    fn follow_state_never_exceeds_the_total_budget() {
        let specs = std::iter::repeat_n("follow,tcp,ascii,0", 5)
            .filter_map(|spec| parse_spec(spec).ok())
            .collect::<Vec<_>>();
        let options = StatsOptions {
            specs,
            budget: DEFAULT_STATS_BUDGET,
        };
        let mut set = StatsSet::new(&options);
        let key = StreamKey {
            index: 0,
            source: StreamAddress::Ipv4([10, 0, 0, 1]),
            source_port: 1000,
            destination: StreamAddress::Ipv4([10, 0, 0, 2]),
            destination_port: 2000,
        };
        let payload = vec![0x41_u8; follow::SPEC_LIMIT];
        set.tcp_payload(key, 0, 1, 1, &payload);
        assert!(set.follow_used() <= follow::TOTAL_LIMIT);
        let mut output = String::new();
        assert!(set.finish(&mut output).is_ok());
        assert!(!set.take_notices().is_empty());
    }
}
