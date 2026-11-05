//! `conv,*` and `endpoints,*` tables.
//!
//! Conversations keep the first packet's direction: `tx` counts packets from
//! that first source, `rx` the reverse direction. Endpoints count `tx` when an
//! address is the packet source and `rx` when it is the destination. Rows sort
//! by total packets descending with first-seen order breaking ties, and byte
//! counts are original frame lengths rendered with SI size units.
//!
//! Bounded runs evict the rows with the oldest activity, in batches, so a
//! hostile capture with millions of conversations cannot exhaust the budget.

use std::collections::HashMap;
use std::fmt;

use crate::fields::Display;
use crate::tree::Value;

use super::facts::{ConvKind, FrameFacts, ProtocolFact};
use super::render::format_size;
use super::{Budget, Clock, Notices, StatsFilter};

/// Per-row charge beyond the stored key and value.
///
/// A hash-map entry is not just `size_of::<K>() + size_of::<V>()`: the table
/// keeps a control byte per bucket, grows by allocating a second bucket array
/// before the first is freed, and the eviction pass holds a sort scratch
/// list. The constant is the measured amortised cost of that bookkeeping plus
/// allocator rounding at scale (about 1 KiB per conversation row); without it
/// a nominal 64 MiB budget retained about 330,000 rows and peaked near 430 MB
/// of statistics memory.
const MAP_OVERHEAD: usize = 768;

/// A conversation endpoint address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Address {
    None,
    Ethernet([u8; 6]),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Bytes(Vec<u8>),
}

impl Address {
    fn from_value(value: &Value) -> Option<Self> {
        Some(match value {
            Value::Ethernet(address) => Self::Ethernet(*address),
            Value::Ipv4(address) => Self::Ipv4(*address),
            Value::Ipv6(address) => Self::Ipv6(*address),
            Value::Bytes(bytes) => Self::Bytes(bytes.to_vec()),
            _ => return None,
        })
    }

    fn display(&self) -> String {
        match self {
            Self::None => "NONE".to_string(),
            Self::Ethernet(address) => Value::Ethernet(*address).render(Display::None),
            Self::Ipv4(address) => Value::Ipv4(*address).render(Display::None),
            Self::Ipv6(address) => Value::Ipv6(*address).render(Display::None),
            Self::Bytes(bytes) => {
                let mut text = String::with_capacity(bytes.len() * 3);
                for (index, byte) in bytes.iter().enumerate() {
                    if index > 0 {
                        text.push(':');
                    }
                    text.push_str(&format!("{byte:02x}"));
                }
                text
            }
        }
    }

    fn heap_bytes(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.capacity(),
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Endpoint {
    address: Address,
    port: u16,
}

impl Endpoint {
    fn heap_bytes(&self) -> usize {
        self.address.heap_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ConversationKey {
    first: Endpoint,
    second: Endpoint,
    /// TCP/UDP stream instance; `None` for address-only families.
    id: Option<u32>,
}

impl ConversationKey {
    fn new(source: &Endpoint, destination: &Endpoint, id: Option<u32>) -> Self {
        if source <= destination {
            Self {
                first: source.clone(),
                second: destination.clone(),
                id,
            }
        } else {
            Self {
                first: destination.clone(),
                second: source.clone(),
                id,
            }
        }
    }
}

struct Row {
    seq: u64,
    source: Endpoint,
    destination: Endpoint,
    rx_frames: u64,
    tx_frames: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    start_ns: i64,
    stop_ns: i64,
    last_seen: u64,
    charge: usize,
}

fn endpoint(address: Address, port: u16) -> Endpoint {
    Endpoint { address, port }
}

fn node_address(facts: &FrameFacts<'_>, fact: &ProtocolFact<'_>, abbrev: &str) -> Option<Address> {
    facts
        .fact_first_field(fact, abbrev)
        .and_then(Address::from_value)
}

fn node_port(facts: &FrameFacts<'_>, fact: &ProtocolFact<'_>, abbrev: &str) -> u16 {
    match facts.fact_first_field(fact, abbrev) {
        Some(Value::Uint16(port)) => *port,
        _ => 0,
    }
}

/// Address pair of the nearest enclosing non-quoted IP layer.
fn network_addresses(facts: &FrameFacts<'_>, fact: &ProtocolFact<'_>) -> (Address, Address) {
    let mut parent = fact.parent;
    while let Some(index) = parent {
        let Some(candidate) = facts.protocols.get(index) else {
            break;
        };
        if !candidate.quoted {
            let name = candidate.node.protocol.filter_name;
            let (source, destination) = match name {
                "ip" => ("ip.src", "ip.dst"),
                "ipv6" => ("ipv6.src", "ipv6.dst"),
                _ => {
                    parent = candidate.parent;
                    continue;
                }
            };
            if let (Some(source), Some(destination)) = (
                node_address(facts, candidate, source),
                node_address(facts, candidate, destination),
            ) {
                return (source, destination);
            }
        }
        parent = candidate.parent;
    }
    (Address::None, Address::None)
}

struct Contribution {
    source: Endpoint,
    destination: Endpoint,
    id: Option<u32>,
    bytes: u64,
    timestamp: i64,
}

/// Whether an IPv6 extension-header chain below this occurrence broke before
/// reaching the terminal next header.
///
/// The IPv6 conversation table counts a packet only after its extension chain
/// is walked; a malformed option, routing or fragment header keeps the packet
/// out even though the base addresses are visible.
fn ipv6_chain_broken(facts: &FrameFacts<'_>, index: usize, depth: usize) -> bool {
    for candidate in facts.protocols.iter().skip(index + 1) {
        if candidate.depth <= depth {
            break;
        }
        if candidate.quoted
            || !matches!(
                candidate.node.protocol.filter_name,
                "ipv6.hopopts" | "ipv6.dstopts" | "ipv6.routing" | "ipv6.fraghdr"
            )
        {
            continue;
        }
        if node_has_malformed(candidate.node) {
            return true;
        }
    }
    false
}

fn node_has_malformed(node: &crate::tree::Node) -> bool {
    if node.protocol_exception
        || node
            .experts
            .iter()
            .any(|expert| expert.group == crate::tree::Group::Malformed)
    {
        return true;
    }
    let mut malformed = false;
    let _ = node.try_for_each_field(&mut |field| {
        if field
            .experts
            .iter()
            .any(|expert| expert.group == crate::tree::Group::Malformed)
        {
            malformed = true;
        }
        Ok::<(), ()>(())
    });
    malformed
}

/// Aggregation state for one conversation or endpoint table.
pub(crate) struct State {
    kind: ConvKind,
    endpoints: bool,
    rows: HashMap<ConversationKey, Row>,
    endpoint_rows: HashMap<Endpoint, Row>,
    /// This table's share of the shared statistics budget.
    ///
    /// Conversation and endpoint tables coexist in one ledger; without a
    /// per-table share one table can occupy the whole budget and grow a
    /// bucket array the other table then doubles again during eviction. Each
    /// table is charged against an equal share, while the ledger still caps
    /// their sum.
    limit: usize,
    /// Bytes currently charged by this table's rows.
    used: usize,
    next_seq: u64,
    frame_number: u64,
    dropped: bool,
}

/// The ordering key of the row at the middle of `ages`, which is the first
/// row the next eviction drops.
///
/// `select_nth_unstable` finds that key in linear time and leaves the scratch
/// vector in the same 16-byte-per-row footprint as the input.
fn drop_cutoff(ages: impl Iterator<Item = (u64, u64)>) -> (u64, u64) {
    let mut ages: Vec<(u64, u64)> = ages.collect();
    let middle = ages.len() / 2;
    if middle == 0 {
        return (0, 0);
    }
    let (_, cutoff, _) = ages.select_nth_unstable(middle - 1);
    *cutoff
}

/// Bytes one replacement bucket array allocates for `capacity` retained rows.
///
/// A hash table rounds its usable capacity up to a power-of-two bucket count at
/// a 7/8 load factor and keeps one control byte per bucket. The growth path
/// allocates the replacement array before the old one is freed, so the
/// replacement is the extra working set a rebuild adds.
fn bucket_array_bytes<K, V>(capacity: usize) -> usize {
    let buckets = capacity
        .saturating_mul(8)
        .div_ceil(7)
        .next_power_of_two()
        .max(8);
    buckets.saturating_mul(std::mem::size_of::<K>() + std::mem::size_of::<V>() + 1)
}

/// Rebuild `map` with a bucket array sized to its retained rows.
///
/// The new array is charged to the shared statistics ledger for the duration
/// of the rebuild: the old array is already covered by each row's
/// [`MAP_OVERHEAD`] charge, but the replacement is a second live allocation.
/// If the ledger has no room the rebuild is skipped; the capacity stays at its
/// bounded high-water mark and the next eviction tries again after releasing
/// more rows.
fn rebuild<K, V>(map: &mut HashMap<K, V>, budget: &mut Budget)
where
    K: Eq + std::hash::Hash,
{
    let transient = bucket_array_bytes::<K, V>(map.len());
    if !budget.reserve(transient) {
        return;
    }
    let old = std::mem::take(map);
    let mut fresh = HashMap::with_capacity(old.len());
    fresh.extend(old);
    *map = fresh;
    budget.release(transient);
}

impl State {
    pub(crate) fn new(kind: ConvKind, endpoints: bool, limit: usize) -> Self {
        Self {
            kind,
            endpoints,
            rows: HashMap::new(),
            endpoint_rows: HashMap::new(),
            limit,
            used: 0,
            next_seq: 0,
            frame_number: 0,
            dropped: false,
        }
    }

    pub(crate) fn observe(
        &mut self,
        facts: &FrameFacts<'_>,
        filter: &StatsFilter,
        budget: &mut Budget,
        notices: &mut Notices,
        clock: &Clock,
    ) {
        if !filter.matches(facts.tree) {
            return;
        }
        self.frame_number = self.frame_number.saturating_add(1);
        let bytes = u64::from(facts.frame.original_len);
        let timestamp = clock.relative_ns;
        let family = self.kind.protocol();
        for (fact_index, fact) in facts.protocols.iter().enumerate() {
            // Conversation tables never count a quoted copy.
            if fact.quoted || fact.node.protocol.filter_name != family {
                continue;
            }
            match self.kind {
                ConvKind::Ethernet => {
                    // The Ethernet table skips a short frame that lacks the
                    // full 14-byte header.
                    if fact.node.range.length < 14 {
                        continue;
                    }
                    let (Some(source), Some(destination)) = (
                        node_address(facts, fact, "eth.src"),
                        node_address(facts, fact, "eth.dst"),
                    ) else {
                        continue;
                    };
                    self.contribute(
                        Contribution {
                            source: endpoint(source, 0),
                            destination: endpoint(destination, 0),
                            id: None,
                            bytes,
                            timestamp,
                        },
                        budget,
                        notices,
                    );
                }
                ConvKind::Ipv4 => {
                    // The IPv4 tap runs only when the complete header was
                    // captured; a truncated option area leaves the address
                    // fields visible but the conversation untouched.
                    let header_length = match facts.fact_first_field(fact, "ip.hdr_len") {
                        Some(Value::Uint8(length)) => usize::from(*length),
                        _ => 20,
                    };
                    if fact.node.range.length < header_length {
                        continue;
                    }
                    let (Some(source), Some(destination)) = (
                        node_address(facts, fact, "ip.src"),
                        node_address(facts, fact, "ip.dst"),
                    ) else {
                        continue;
                    };
                    self.contribute(
                        Contribution {
                            source: endpoint(source, 0),
                            destination: endpoint(destination, 0),
                            id: None,
                            bytes,
                            timestamp,
                        },
                        budget,
                        notices,
                    );
                }
                ConvKind::Ipv6 => {
                    if fact.node.range.length < 40
                        || ipv6_chain_broken(facts, fact_index, fact.depth)
                    {
                        continue;
                    }
                    let (Some(source), Some(destination)) = (
                        node_address(facts, fact, "ipv6.src"),
                        node_address(facts, fact, "ipv6.dst"),
                    ) else {
                        continue;
                    };
                    self.contribute(
                        Contribution {
                            source: endpoint(source, 0),
                            destination: endpoint(destination, 0),
                            id: None,
                            bytes,
                            timestamp,
                        },
                        budget,
                        notices,
                    );
                }
                ConvKind::Sll => {
                    // The SLL table requires the full 16-byte cooked header
                    // before it records an endpoint.
                    if fact.node.range.length < 16 {
                        continue;
                    }
                    // It only records Ethernet and IPv4 source addresses; an
                    // "other" address leaves the source at NONE.
                    let source = facts
                        .fact_first_field(fact, "sll.src.eth")
                        .or_else(|| facts.fact_first_field(fact, "sll.src.ipv4"))
                        .and_then(Address::from_value)
                        .unwrap_or(Address::None);
                    self.contribute(
                        Contribution {
                            source: endpoint(source, 0),
                            destination: endpoint(Address::None, 0),
                            id: None,
                            bytes,
                            timestamp,
                        },
                        budget,
                        notices,
                    );
                }
                ConvKind::Tcp | ConvKind::Udp => {
                    let stream_field = if self.kind == ConvKind::Tcp {
                        "tcp.stream"
                    } else {
                        "udp.stream"
                    };
                    // A stream is assigned only to a complete transport
                    // header; incomplete headers have no stream.
                    let Some(Value::Uint32(stream)) = facts.fact_first_field(fact, stream_field)
                    else {
                        continue;
                    };
                    if self.kind == ConvKind::Tcp {
                        // A bogus data offset keeps the segment out of the TCP
                        // conversation table even though the stream is already
                        // assigned.
                        let header_length = match facts.fact_first_field(fact, "tcp.hdr_len") {
                            Some(Value::Uint8(length)) => usize::from(*length),
                            _ => 0,
                        };
                        if header_length < 20 {
                            continue;
                        }
                    }
                    let (source, destination) = network_addresses(facts, fact);
                    let (source_port, destination_port) = if self.kind == ConvKind::Tcp {
                        ("tcp.srcport", "tcp.dstport")
                    } else {
                        ("udp.srcport", "udp.dstport")
                    };
                    self.contribute(
                        Contribution {
                            source: endpoint(source, node_port(facts, fact, source_port)),
                            destination: endpoint(
                                destination,
                                node_port(facts, fact, destination_port),
                            ),
                            id: Some(*stream),
                            bytes,
                            timestamp,
                        },
                        budget,
                        notices,
                    );
                }
            }
        }
    }

    fn contribute(
        &mut self,
        contribution: Contribution,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        let Contribution {
            source,
            destination,
            id,
            bytes,
            timestamp,
        } = contribution;
        if self.endpoints {
            self.observe_endpoint(source, true, bytes, budget, notices);
            // SLL has only a source address; the endpoint table adds just
            // that sender and no destination row.
            if self.kind != ConvKind::Sll {
                self.observe_endpoint(destination, false, bytes, budget, notices);
            }
            return;
        }
        let key = ConversationKey::new(&source, &destination, id);
        if let Some(row) = self.rows.get_mut(&key) {
            row.last_seen = self.frame_number;
            if row.source == source && row.destination == destination {
                row.tx_frames = row.tx_frames.saturating_add(1);
                row.tx_bytes = row.tx_bytes.saturating_add(bytes);
            } else {
                row.rx_frames = row.rx_frames.saturating_add(1);
                row.rx_bytes = row.rx_bytes.saturating_add(bytes);
            }
            row.stop_ns = row.stop_ns.max(timestamp);
            row.start_ns = row.start_ns.min(timestamp);
            return;
        }
        // Both the map key and the row store a copy of the two endpoints, so
        // every heap-backed address is charged twice.
        let charge = std::mem::size_of::<Row>()
            + std::mem::size_of::<ConversationKey>()
            + source.heap_bytes().saturating_mul(2)
            + destination.heap_bytes().saturating_mul(2)
            + MAP_OVERHEAD;
        let share_evicted = self.evict_to_share(budget, charge);
        // A map that is about to grow allocates a second bucket array before
        // freeing the first. Charge that replacement to the ledger for the
        // duration of the insert; when it does not fit, evict first so the
        // insert reuses the retained capacity instead of growing.
        let (growth_charge, growth_evicted) = self.growth_charge::<ConversationKey, Row>(
            budget,
            self.rows.len(),
            self.rows.capacity(),
        );
        let (fits, evicted) = self.reserve(budget, charge);
        if share_evicted || growth_evicted || evicted || !fits {
            self.note_drop(notices);
        }
        if fits {
            self.used = self.used.saturating_add(charge);
            let seq = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            self.rows.insert(
                key,
                Row {
                    seq,
                    source,
                    destination,
                    rx_frames: 0,
                    tx_frames: 1,
                    rx_bytes: 0,
                    tx_bytes: bytes,
                    start_ns: timestamp,
                    stop_ns: timestamp,
                    last_seen: self.frame_number,
                    charge,
                },
            );
        }
        budget.release(growth_charge);
    }

    fn observe_endpoint(
        &mut self,
        endpoint: Endpoint,
        sender: bool,
        bytes: u64,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        if let Some(row) = self.endpoint_rows.get_mut(&endpoint) {
            row.last_seen = self.frame_number;
            if sender {
                row.tx_frames = row.tx_frames.saturating_add(1);
                row.tx_bytes = row.tx_bytes.saturating_add(bytes);
            } else {
                row.rx_frames = row.rx_frames.saturating_add(1);
                row.rx_bytes = row.rx_bytes.saturating_add(bytes);
            }
            return;
        }
        let charge = std::mem::size_of::<Row>()
            + std::mem::size_of::<Endpoint>()
            + endpoint.heap_bytes().saturating_mul(2)
            + MAP_OVERHEAD;
        let share_evicted = self.evict_to_share(budget, charge);
        let (growth_charge, growth_evicted) = self.growth_charge::<Endpoint, Row>(
            budget,
            self.endpoint_rows.len(),
            self.endpoint_rows.capacity(),
        );
        let (fits, evicted) = self.reserve(budget, charge);
        if share_evicted || growth_evicted || evicted || !fits {
            self.note_drop(notices);
        }
        if !fits {
            budget.release(growth_charge);
            return;
        }
        self.used = self.used.saturating_add(charge);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.endpoint_rows.insert(
            endpoint.clone(),
            Row {
                seq,
                source: endpoint,
                destination: Endpoint {
                    address: Address::None,
                    port: 0,
                },
                rx_frames: if sender { 0 } else { 1 },
                tx_frames: if sender { 1 } else { 0 },
                rx_bytes: if sender { 0 } else { bytes },
                tx_bytes: if sender { bytes } else { 0 },
                start_ns: 0,
                stop_ns: 0,
                last_seen: self.frame_number,
                charge,
            },
        );
        budget.release(growth_charge);
    }

    /// Evict this table until `charge` fits its own share.
    ///
    /// The shared ledger bounds every table together; the per-table share
    /// keeps one table from occupying it all and leaving the next table to
    /// grow a second large bucket array beside it.
    fn evict_to_share(&mut self, budget: &mut Budget, charge: usize) -> bool {
        let mut dropped = false;
        while self.used.saturating_add(charge) > self.limit {
            let before = self.used;
            dropped |= self.evict(budget);
            if self.used >= before {
                break;
            }
        }
        dropped
    }

    /// Reserve the replacement bucket array before an insert grows a map.
    ///
    /// Returns the amount charged, or zero after evicting the table so the
    /// insert reuses its retained capacity. The caller releases the charge
    /// once the insert finishes.
    fn growth_charge<K, V>(
        &mut self,
        budget: &mut Budget,
        len: usize,
        capacity: usize,
    ) -> (usize, bool) {
        if len < capacity {
            return (0, false);
        }
        let transient = bucket_array_bytes::<K, V>(capacity.saturating_mul(2).max(8));
        if self.used.saturating_add(transient) > self.limit {
            return (0, self.evict(budget));
        }
        if budget.reserve(transient) {
            return (transient, false);
        }
        (0, self.evict(budget))
    }

    fn reserve(&mut self, budget: &mut Budget, charge: usize) -> (bool, bool) {
        if budget.reserve(charge) {
            return (true, false);
        }
        self.evict(budget);
        (budget.reserve(charge), true)
    }

    /// Drop the half of the rows with the oldest activity.
    ///
    /// The age scratch holds only the two ordering keys, so evicting a large
    /// table does not clone every map key. After the drop the bucket array is
    /// rebuilt when it has drifted well past the retained rows; that rebuild
    /// briefly holds two arrays, so its second allocation is charged to the
    /// shared ledger before it happens (see [`rebuild`]).
    fn evict(&mut self, budget: &mut Budget) -> bool {
        if !self.endpoints {
            if self.rows.len() < 2 {
                return false;
            }
            let drop = drop_cutoff(self.rows.values().map(|row| (row.last_seen, row.seq)));
            let mut released = 0_usize;
            self.rows.retain(|_, row| {
                let keep = (row.last_seen, row.seq) > drop;
                if !keep {
                    released = released.saturating_add(row.charge);
                }
                keep
            });
            budget.release(released);
            self.used = self.used.saturating_sub(released);
            if self.rows.capacity() > self.rows.len().saturating_mul(2) {
                rebuild(&mut self.rows, budget);
            }
            released > 0
        } else {
            if self.endpoint_rows.len() < 2 {
                return false;
            }
            let drop = drop_cutoff(
                self.endpoint_rows
                    .values()
                    .map(|row| (row.last_seen, row.seq)),
            );
            let mut released = 0_usize;
            self.endpoint_rows.retain(|_, row| {
                let keep = (row.last_seen, row.seq) > drop;
                if !keep {
                    released = released.saturating_add(row.charge);
                }
                keep
            });
            budget.release(released);
            self.used = self.used.saturating_sub(released);
            if self.endpoint_rows.capacity() > self.endpoint_rows.len().saturating_mul(2) {
                rebuild(&mut self.endpoint_rows, budget);
            }
            released > 0
        }
    }

    fn note_drop(&mut self, notices: &mut Notices) {
        if self.dropped {
            return;
        }
        self.dropped = true;
        notices.once(
            "conversation-rows",
            "statistics budget reached; the oldest conversation rows were dropped",
        );
    }

    pub(crate) fn finish(
        &mut self,
        filter: &StatsFilter,
        output: &mut dyn fmt::Write,
    ) -> fmt::Result {
        writeln!(
            output,
            "================================================================================"
        )?;
        if self.endpoints {
            writeln!(output, "{} Endpoints", self.kind.title())?;
        } else {
            writeln!(output, "{} Conversations", self.kind.title())?;
        }
        writeln!(
            output,
            "Filter:{}",
            filter.header_text().unwrap_or("<No Filter>")
        )?;
        if self.endpoints {
            self.write_endpoint_header(output)?;
            self.write_endpoints(output)?;
        } else {
            self.write_conversation_header(output)?;
            self.write_conversations(output)?;
        }
        writeln!(
            output,
            "================================================================================"
        )?;
        Ok(())
    }

    fn write_conversation_header(&mut self, output: &mut dyn fmt::Write) -> fmt::Result {
        let prefix = if self.kind.has_ports() {
            "            "
        } else {
            ""
        };
        writeln!(
            output,
            "{prefix}                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |"
        )?;
        writeln!(
            output,
            "{prefix}                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |"
        )?;
        Ok(())
    }

    fn write_endpoint_header(&mut self, output: &mut dyn fmt::Write) -> fmt::Result {
        if self.kind.has_ports() {
            writeln!(
                output,
                "                       |  Port  | | Packets | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |"
            )?;
        } else {
            writeln!(
                output,
                "                       | Packets | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |"
            )?;
        }
        Ok(())
    }

    fn write_conversations(&mut self, output: &mut dyn fmt::Write) -> fmt::Result {
        let mut rows: Vec<&Row> = self.rows.values().collect();
        rows.sort_by(|left, right| {
            let left_total = left.rx_frames + left.tx_frames;
            let right_total = right.rx_frames + right.tx_frames;
            right_total
                .cmp(&left_total)
                .then_with(|| left.seq.cmp(&right.seq))
        });
        for row in rows {
            let source = if self.kind.has_ports() {
                format!("{}:{}", row.source.address.display(), row.source.port)
            } else {
                row.source.address.display()
            };
            let destination = if self.kind.has_ports() {
                format!(
                    "{}:{}",
                    row.destination.address.display(),
                    row.destination.port
                )
            } else {
                row.destination.address.display()
            };
            if self.kind.has_ports() {
                write!(output, "{source:<26} <-> {destination:<26}")?;
            } else {
                write!(output, "{source:<20} <-> {destination:<20}")?;
            }
            let rx_bytes = format_size(row.rx_bytes);
            let tx_bytes = format_size(row.tx_bytes);
            let total_bytes = format_size(row.rx_bytes.saturating_add(row.tx_bytes));
            let total_frames = row.rx_frames.saturating_add(row.tx_frames);
            write!(
                output,
                "  {:>6} {:<9}  {:>6} {:<9}  {:>6} {:<9}  ",
                row.rx_frames, rx_bytes, row.tx_frames, tx_bytes, total_frames, total_bytes
            )?;
            let start = row.start_ns as f64 / 1_000_000_000.0;
            let duration = row.stop_ns.saturating_sub(row.start_ns) as f64 / 1_000_000_000.0;
            writeln!(output, "{start:>14.9}   {duration:>12.4}")?;
        }
        Ok(())
    }

    fn write_endpoints(&mut self, output: &mut dyn fmt::Write) -> fmt::Result {
        let mut rows: Vec<&Row> = self.endpoint_rows.values().collect();
        rows.sort_by(|left, right| {
            let left_total = left.rx_frames + left.tx_frames;
            let right_total = right.rx_frames + right.tx_frames;
            right_total
                .cmp(&left_total)
                .then_with(|| left.seq.cmp(&right.seq))
        });
        for row in rows {
            write!(output, "{:<20}", row.source.address.display())?;
            if self.kind.has_ports() {
                write!(output, "      {:>5}", row.source.port)?;
            }
            let total_frames = row.rx_frames.saturating_add(row.tx_frames);
            let total_bytes = format_size(row.rx_bytes.saturating_add(row.tx_bytes));
            let tx_bytes = format_size(row.tx_bytes);
            let rx_bytes = format_size(row.rx_bytes);
            writeln!(
                output,
                "     {total_frames:>8}   {total_bytes:<11}  {:>8}      {tx_bytes:<11}   {:>8}      {rx_bytes:<11} ",
                row.tx_frames, row.rx_frames
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod charge_tests {
    use super::*;

    #[test]
    fn a_conversation_row_is_charged_for_its_key_and_map() {
        let mut state = State::new(ConvKind::Udp, false, usize::MAX);
        let mut budget = Budget::new(usize::MAX);
        let mut notices = Notices::default();
        state.contribute(
            Contribution {
                source: endpoint(Address::Ipv4([10, 0, 0, 1]), 1000),
                destination: endpoint(Address::Ipv4([10, 0, 0, 2]), 2000),
                id: Some(0),
                bytes: 42,
                timestamp: 0,
            },
            &mut budget,
            &mut notices,
        );
        assert_eq!(state.rows.len(), 1);
        if let Some(row) = state.rows.values().next() {
            assert!(
                row.charge
                    >= std::mem::size_of::<Row>()
                        + std::mem::size_of::<ConversationKey>()
                        + MAP_OVERHEAD
            );
            assert_eq!(budget.used, row.charge);
        }
    }

    #[test]
    fn an_endpoint_row_is_charged_for_its_key_and_map() {
        let mut state = State::new(ConvKind::Udp, true, usize::MAX);
        let mut budget = Budget::new(usize::MAX);
        let mut notices = Notices::default();
        state.observe_endpoint(
            endpoint(Address::Ipv4([10, 0, 0, 1]), 1000),
            true,
            42,
            &mut budget,
            &mut notices,
        );
        assert_eq!(state.endpoint_rows.len(), 1);
        if let Some(row) = state.endpoint_rows.values().next() {
            assert!(
                row.charge
                    >= std::mem::size_of::<Row>() + std::mem::size_of::<Endpoint>() + MAP_OVERHEAD
            );
        }
    }
}
