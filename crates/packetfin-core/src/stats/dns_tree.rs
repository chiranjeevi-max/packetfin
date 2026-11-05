//! `-z dns,tree`: the DNS packet counter tree.
//!
//! The tree's schema, in print order: Total Packets, the
//! Query/Response pivot, Query Type, Answer Type, Query Name, Class, rcode,
//! opcodes and Payload size, then the Query, Response and Service stat
//! groups. Query numbers come from question fields and answer types from
//! answer records. The response counters are added once for an unsolicited
//! response and twice for a matched one. Packetfin derives "unsolicited" and
//! "retransmission" from the same transaction id and endpoint pair the DNS
//! decoder matches, so the tree never needs decoder-private state.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::fmt;

use crate::capture::Timestamp;
use crate::decode;
use crate::tree::Value;

use super::facts::{FrameFacts, ProtocolFact};
use super::stat_tree::Tree;
use super::{Budget, Clock, Notices, StatsFilter};

/// Fields the DNS tree reads from the decoded frame.
pub(crate) const FIELDS: &[&str] = &[
    "dns.id",
    "dns.flags.response",
    "dns.qry.type",
    "dns.resp.type",
    "dns.qry.name.len",
    "dns.count.labels",
    "dns.qry.class",
    "dns.flags.rcode",
    "dns.flags.opcode",
    "dns.count.queries",
    "dns.count.answers",
    "dns.count.auth_rr",
    "dns.count.add_rr",
    "dns.count.zones",
    "dns.count.prerequisites",
    "dns.count.updates",
];

/// DNS transactions retained for service statistics.
const MAX_PENDING: usize = 100_000;
/// DNS's `dns.retransmission_timer` default in nanoseconds.
const RETRANSMISSION_WINDOW_NS: i128 = 5_000_000_000;

/// Aggregation state for one `dns,tree` specification.
pub(crate) struct State {
    tree: Tree,
    total: usize,
    responses: usize,
    query_types: usize,
    answer_types: usize,
    classes: usize,
    rcodes: usize,
    opcodes: usize,
    payload: usize,
    qname_len: usize,
    levels: [usize; 4],
    nquestions: usize,
    nanswers: usize,
    nauthorities: usize,
    nadditionals: usize,
    unsolicited: usize,
    retransmissions: usize,
    rrt: usize,
    pending: HashMap<PairKey, Pending>,
    order: VecDeque<PairKey>,
}

struct Pending {
    time: Option<Timestamp>,
    answered: bool,
}

impl Default for State {
    fn default() -> Self {
        let mut tree = Tree::new("DNS", false);
        let total = tree.root_child("Total Packets");
        let responses = tree.root_child("Response");
        let query_types = tree.root_child("Query Type");
        let answer_types = tree.root_child("Answer Type");
        tree.root_child("Query Name");
        let classes = tree.root_child("Class");
        let rcodes = tree.root_child("rcode");
        let opcodes = tree.root_child("opcodes");
        let payload = tree.root_child("Payload size");
        let query_stats = tree.root_child("Query Stats");
        let qname_len = tree.child(query_stats, "Qname Len");
        let label_stats = tree.child(query_stats, "Label Stats");
        let levels = [
            tree.child(label_stats, "1st Level"),
            tree.child(label_stats, "2nd Level"),
            tree.child(label_stats, "3rd Level"),
            tree.child(label_stats, "4th Level or more"),
        ];
        let response_stats = tree.root_child("Response Stats");
        let nquestions = tree.child(response_stats, "no. of questions");
        let nauthorities = tree.child(response_stats, "no. of authorities");
        let nanswers = tree.child(response_stats, "no. of answers");
        let nadditionals = tree.child(response_stats, "no. of additionals");
        let service_stats = tree.root_child("Service Stats");
        let rrt = tree.child(service_stats, "request-response time (msec)");
        let unsolicited = tree.child(service_stats, "no. of unsolicited responses");
        let retransmissions = tree.child(service_stats, "no. of retransmissions");
        Self {
            tree,
            total,
            responses,
            query_types,
            answer_types,
            classes,
            rcodes,
            opcodes,
            payload,
            qname_len,
            levels,
            nquestions,
            nanswers,
            nauthorities,
            nadditionals,
            unsolicited,
            retransmissions,
            rrt,
            pending: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl State {
    /// Observe one frame.
    pub(crate) fn observe(
        &mut self,
        facts: &FrameFacts<'_>,
        filter: &StatsFilter,
        clock: &Clock,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        if !filter.matches(facts.tree) {
            return;
        }
        let time = clock.relative_ns;
        for fact in facts
            .protocols
            .iter()
            .filter(|fact| fact.node.protocol.filter_name == "dns" && !fact.quoted)
        {
            self.observe_message(fact, facts, time, budget, notices);
        }
    }

    fn observe_message(
        &mut self,
        fact: &ProtocolFact<'_>,
        facts: &FrameFacts<'_>,
        time: i64,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        // The tree counts a message only after its twelve-octet fixed
        // header parses, whatever its opcode: UPDATE uses the zone,
        // prerequisite and update counts instead of the question counts.
        const HEADER_COUNTS: [&str; 7] = [
            "dns.count.queries",
            "dns.count.answers",
            "dns.count.auth_rr",
            "dns.count.add_rr",
            "dns.count.zones",
            "dns.count.prerequisites",
            "dns.count.updates",
        ];
        // Qname Len is a field tap independent of the message tree: it
        // still counts a request's name lengths when the message itself is
        // marked malformed, but never counts a response's echoed question.
        let response = matches!(
            facts.fact_first_field(fact, "dns.flags.response"),
            Some(Value::Boolean(true))
        );
        if !response && let Some(value) = facts.fact_fields(fact, "dns.qry.name.len").next() {
            // Qname Len counts the first question only: a message with
            // two questions contributes one value, not two. A root-only name
            // has a zero field and is stored as one, which keeps the malformed
            // fixture's minimum at 1.
            let length = value_u16(value).unwrap_or(0).max(1);
            self.tree.add_int(self.qname_len, i64::from(length), time);
        }
        if fact.node.protocol_exception
            || !HEADER_COUNTS
                .iter()
                .any(|field| facts.fact_first_field(fact, field).is_some())
        {
            return;
        }
        let response = matches!(
            facts.fact_first_field(fact, "dns.flags.response"),
            Some(Value::Boolean(true))
        );
        self.tree.tick(self.total, time);
        let pivot = if response { "Response" } else { "Query" };
        self.tree
            .tick_pivot(self.responses, pivot, time, budget, notices);

        let qtype = field_u16(facts, fact, "dns.qry.type").unwrap_or(0);
        self.tree
            .tick_pivot(self.query_types, &type_name(qtype), time, budget, notices);

        let class = field_u16(facts, fact, "dns.qry.class").unwrap_or(0);
        self.tree
            .tick_pivot(self.classes, &class_name(class), time, budget, notices);

        let rcode = field_u16(facts, fact, "dns.flags.rcode").unwrap_or(0);
        self.tree
            .tick_pivot(self.rcodes, &rcode_name(rcode), time, budget, notices);

        let opcode = field_u16(facts, fact, "dns.flags.opcode").unwrap_or(0);
        self.tree.tick_pivot(
            self.opcodes,
            opcode_name(opcode).as_ref(),
            time,
            budget,
            notices,
        );

        let payload = i64::try_from(fact.node.range.length).unwrap_or(i64::MAX);
        self.tree.add_int(self.payload, payload, time);

        if response {
            let nquestions = i64::from(field_u16(facts, fact, "dns.count.queries").unwrap_or(0));
            let nanswers = i64::from(field_u16(facts, fact, "dns.count.answers").unwrap_or(0));
            let nauthorities = i64::from(field_u16(facts, fact, "dns.count.auth_rr").unwrap_or(0));
            let nadditionals = i64::from(field_u16(facts, fact, "dns.count.add_rr").unwrap_or(0));
            let outcome = self.response_outcome(fact, facts);
            self.tree.add_int(self.nquestions, nquestions, time);
            self.tree.add_int(self.nanswers, nanswers, time);
            self.tree.add_int(self.nauthorities, nauthorities, time);
            self.tree.add_int(self.nadditionals, nadditionals, time);
            if !outcome.unsolicited {
                // A response with a matching request adds the same values a
                // second time.
                self.tree.add_int(self.nquestions, nquestions, time);
                self.tree.add_int(self.nanswers, nanswers, time);
                self.tree.add_int(self.nauthorities, nauthorities, time);
                self.tree.add_int(self.nadditionals, nadditionals, time);
            }
            for value in facts.fact_fields(fact, "dns.resp.type") {
                if let Some(rtype) = value_u16(value) {
                    self.tree.tick_pivot(
                        self.answer_types,
                        type_name(rtype).as_ref(),
                        time,
                        budget,
                        notices,
                    );
                }
            }
            if outcome.unsolicited {
                self.tree.tick(self.unsolicited, time);
            } else if outcome.retransmission {
                self.tree.tick(self.retransmissions, time);
            } else if let Some(elapsed) = outcome.elapsed_ms {
                self.tree.add_float(self.rrt, elapsed, time);
            }
        } else {
            self.note_request(fact, facts);
            let labels = field_u16(facts, fact, "dns.count.labels").unwrap_or(0);
            let index = match labels {
                1 => 0,
                2 => 1,
                3 => 2,
                _ => 3,
            };
            if let Some(node) = self.levels.get(index).copied() {
                self.tree.tick(node, time);
            }
        }
    }

    fn response_outcome(&mut self, fact: &ProtocolFact<'_>, facts: &FrameFacts<'_>) -> Outcome {
        let Some(key) = pair_key(facts, fact) else {
            return Outcome {
                unsolicited: true,
                retransmission: false,
                elapsed_ms: None,
            };
        };
        let now = facts.frame.timestamp;
        if let Some(pending) = self.pending.get_mut(&key) {
            if pending.answered {
                return Outcome {
                    unsolicited: false,
                    retransmission: true,
                    elapsed_ms: None,
                };
            }
            let elapsed = match (pending.time, now) {
                (Some(request), Some(response)) => Some(
                    (i128::from(response.seconds) * 1_000_000_000 + i128::from(response.nanos)
                        - i128::from(request.seconds) * 1_000_000_000
                        - i128::from(request.nanos)) as f64
                        / 1_000_000.0,
                ),
                _ => None,
            };
            pending.answered = true;
            return Outcome {
                unsolicited: false,
                retransmission: false,
                elapsed_ms: elapsed,
            };
        }
        Outcome {
            unsolicited: true,
            retransmission: false,
            elapsed_ms: None,
        }
    }

    /// Render the tree.
    pub(crate) fn finish(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        self.tree.finish(output)
    }
}

impl State {
    /// Record a query so a later response can be matched to it.
    pub(crate) fn note_request(&mut self, fact: &ProtocolFact<'_>, facts: &FrameFacts<'_>) {
        let Some(key) = pair_key(facts, fact) else {
            return;
        };
        let now = facts.frame.timestamp;
        if let Some(pending) = self.pending.get_mut(&key) {
            let recent = match (pending.time, now) {
                (Some(request), Some(current)) => {
                    i128::from(current.seconds - request.seconds) * 1_000_000_000
                        + i128::from(current.nanos)
                        - i128::from(request.nanos)
                        < RETRANSMISSION_WINDOW_NS
                }
                _ => true,
            };
            if !pending.answered && recent {
                return;
            }
            pending.time = now;
            pending.answered = false;
            return;
        }
        if self.pending.len() >= MAX_PENDING
            && let Some(oldest) = self.order.pop_front()
        {
            self.pending.remove(&oldest);
        }
        self.pending.insert(
            key,
            Pending {
                time: now,
                answered: false,
            },
        );
        self.order.push_back(key);
    }
}

struct Outcome {
    unsolicited: bool,
    retransmission: bool,
    elapsed_ms: Option<f64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    version: u8,
    bytes: [u8; 16],
    port: u16,
}

impl PartialOrd for EndpointKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EndpointKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.version, self.bytes, self.port).cmp(&(other.version, other.bytes, other.port))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PairKey {
    first: EndpointKey,
    second: EndpointKey,
    id: u16,
}

fn pair_key(facts: &FrameFacts<'_>, fact: &ProtocolFact<'_>) -> Option<PairKey> {
    let source = endpoint(
        facts,
        fact,
        "ip.src",
        "ipv6.src",
        "udp.srcport",
        "tcp.srcport",
    )?;
    let destination = endpoint(
        facts,
        fact,
        "ip.dst",
        "ipv6.dst",
        "udp.dstport",
        "tcp.dstport",
    )?;
    let (first, second) = if source <= destination {
        (source, destination)
    } else {
        (destination, source)
    };
    Some(PairKey {
        first,
        second,
        id: field_u16(facts, fact, "dns.id").unwrap_or(0),
    })
}

fn endpoint(
    facts: &FrameFacts<'_>,
    fact: &ProtocolFact<'_>,
    v4: &str,
    v6: &str,
    udp_port: &str,
    tcp_port: &str,
) -> Option<EndpointKey> {
    let address = facts
        .fact_first_field(fact, v4)
        .or_else(|| first_anywhere(facts, v4))
        .or_else(|| facts.fact_first_field(fact, v6))
        .or_else(|| first_anywhere(facts, v6))?;
    let (version, bytes) = match address {
        Value::Ipv4(address) => {
            let mut bytes = [0_u8; 16];
            bytes[..4].copy_from_slice(address);
            (4, bytes)
        }
        Value::Ipv6(address) => (6, *address),
        _ => return None,
    };
    let port = facts
        .fact_first_field(fact, udp_port)
        .or_else(|| first_anywhere(facts, udp_port))
        .or_else(|| facts.fact_first_field(fact, tcp_port))
        .or_else(|| first_anywhere(facts, tcp_port))?;
    Some(EndpointKey {
        version,
        bytes,
        port: value_u16(port)?,
    })
}

fn first_anywhere<'a>(facts: &'a FrameFacts<'_>, abbrev: &str) -> Option<&'a Value> {
    facts.field_values(abbrev).next().map(|(_, value)| value)
}

fn field_u16(facts: &FrameFacts<'_>, fact: &ProtocolFact<'_>, abbrev: &str) -> Option<u16> {
    facts.fact_first_field(fact, abbrev).and_then(value_u16)
}

fn value_u16(value: &Value) -> Option<u16> {
    match value {
        Value::Uint8(value) => Some(u16::from(*value)),
        Value::Uint16(value) => Some(*value),
        Value::Uint24(value) | Value::Uint32(value) => u16::try_from(*value).ok(),
        Value::Uint64(value) => u16::try_from(*value).ok(),
        Value::Int8(value) => u16::try_from(*value).ok(),
        Value::Int16(value) => u16::try_from(*value).ok(),
        Value::Int32(value) => u16::try_from(*value).ok(),
        Value::Int64(value) => u16::try_from(*value).ok(),
        _ => None,
    }
}

fn type_name(rtype: u16) -> Cow<'static, str> {
    // IANA DNS Parameters registry names, as the tree prints them; the
    // summary line's short table stays in decode::dns.
    let name = match rtype {
        0 => "Unused",
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        19 => "X25",
        20 => "ISDN",
        21 => "RT",
        22 => "NSAP",
        23 => "NSAP-PTR",
        24 => "SIG",
        25 => "KEY",
        26 => "PX",
        27 => "GPOS",
        28 => "AAAA",
        29 => "LOC",
        30 => "NXT",
        31 => "EID",
        32 => "NIMLOC",
        33 => "SRV",
        34 => "ATMA",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        38 => "A6",
        39 => "DNAME",
        40 => "SINK",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        56 => "NINFO",
        57 => "RKEY",
        58 => "TALINK",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        100 => "UINFO",
        101 => "UID",
        102 => "GID",
        103 => "UNSPEC",
        104 => "NID",
        105 => "L32",
        106 => "L64",
        107 => "LP",
        108 => "EUI48",
        109 => "EUI64",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        258 => "AVC",
        259 => "DOA",
        260 => "AMTRELAY",
        261 => "RESINFO",
        262 => "WALLET",
        263 => "CLA",
        264 => "IPN",
        32768 => "TA",
        32769 => "DLV",
        _ => return Cow::Owned(format!("Unknown packet type ({rtype})")),
    };
    Cow::Borrowed(name)
}

fn class_name(class: u16) -> Cow<'static, str> {
    match class {
        1 => Cow::Borrowed("IN"),
        2 => Cow::Borrowed("CS"),
        3 => Cow::Borrowed("CH"),
        4 => Cow::Borrowed("HS"),
        254 => Cow::Borrowed("NONE"),
        255 => Cow::Borrowed("ANY"),
        other => Cow::Owned(format!("Unknown class ({other})")),
    }
}

fn rcode_name(rcode: u16) -> Cow<'static, str> {
    match rcode {
        0 => Cow::Borrowed("No error"),
        other => match decode::rcode_text(other) {
            Some(name) => Cow::Borrowed(name),
            None => Cow::Owned(format!("Unknown rcode ({other})")),
        },
    }
}

fn opcode_name(opcode: u16) -> Cow<'static, str> {
    match opcode {
        0 => Cow::Borrowed("Standard query"),
        1 => Cow::Borrowed("Inverse query"),
        2 => Cow::Borrowed("Server status request"),
        4 => Cow::Borrowed("Zone change notification"),
        5 => Cow::Borrowed("Dynamic update"),
        6 => Cow::Borrowed("DNS Stateful operations (DSO)"),
        other => Cow::Owned(format!("Unknown operation ({other})")),
    }
}
