//! The once-per-frame view statistics read.
//!
//! A [`FrameFacts`] snapshot is built from the complete decoded tree before
//! any output filter prunes it. It carries the protocol nodes in preorder
//! (with depths), the expert entries in decode order, and the typed values of
//! only the fields the selected statistics ask for. Building it once keeps a
//! run with several `-z` families from walking the tree repeatedly.

use crate::capture::Frame;
use crate::decode::Packet;
use crate::fields::FieldDef;
use crate::tree::{ExpertInfo, Group, Node, Severity, Value};

use super::StatsSpec;

/// Which parts of the tree the selected statistics need.
#[derive(Default)]
pub(crate) struct Interests {
    /// Expert entries are needed for `-z expert`.
    experts: bool,
    /// Field abbreviations to collect, sorted for binary search.
    fields: Vec<&'static str>,
}

impl Interests {
    pub(crate) fn for_specs(specs: &[StatsSpec]) -> Self {
        let mut interests = Self::default();
        for spec in specs {
            match spec {
                StatsSpec::IoStat(spec) => {
                    for column in &spec.columns {
                        if let Some(crate::stats::IoArgument::Field(field)) = &column.argument {
                            interests.add_field(field.abbrev);
                        }
                    }
                }
                StatsSpec::Conversations { kind, .. } | StatsSpec::Endpoints { kind, .. } => {
                    for field in kind.fields() {
                        interests.add_field(field);
                    }
                }
                StatsSpec::Expert { .. } => interests.experts = true,
                StatsSpec::DnsTree { .. } => {
                    for field in super::dns_tree::FIELDS {
                        interests.add_field(field);
                    }
                    for field in [
                        "ip.src",
                        "ip.dst",
                        "ipv6.src",
                        "ipv6.dst",
                        "udp.srcport",
                        "udp.dstport",
                        "tcp.srcport",
                        "tcp.dstport",
                    ] {
                        interests.add_field(field);
                    }
                }
                StatsSpec::HttpTree { .. } => {
                    for field in super::http_tree::FIELDS {
                        interests.add_field(field);
                    }
                }
                StatsSpec::Follow(_) | StatsSpec::IoPhs { .. } => {}
            }
        }
        interests.fields.sort_unstable();
        interests.fields.dedup();
        interests
    }

    fn add_field(&mut self, abbrev: &'static str) {
        self.fields.push(abbrev);
    }

    fn wants_field(&self, abbrev: &str) -> bool {
        self.fields.binary_search(&abbrev).is_ok()
    }
}

/// One protocol node occurrence in the frame.
pub struct ProtocolFact<'a> {
    /// The protocol node.
    pub node: &'a Node,
    /// Nesting depth: the frame node is zero.
    pub depth: usize,
    /// Index of the enclosing protocol fact, if any.
    pub parent: Option<usize>,
    /// Whether this node belongs to a quoted datagram.
    pub quoted: bool,
    /// First interested field index belonging to this protocol node.
    pub(crate) field_start: usize,
    /// One past the last interested field index belonging to this node.
    pub(crate) field_end: usize,
}

/// One expert entry together with the protocol that raised it.
pub struct ExpertFact<'a> {
    /// Severity from the decoder.
    pub severity: Severity,
    /// Group from the decoder.
    pub group: Group,
    /// Short protocol name, printed in the Protocol column.
    pub protocol: &'static str,
    /// Summary text.
    pub summary: &'a str,
}

/// Snapshot of one frame for the statistic implementations.
pub struct FrameFacts<'a> {
    /// The original frame, for lengths and capture comments.
    pub frame: &'a Frame,
    /// The complete decoded tree, for statistic filters.
    pub tree: &'a crate::tree::Tree,
    /// Protocol nodes in preorder.
    pub protocols: Vec<ProtocolFact<'a>>,
    /// Expert entries in decode order; empty unless `-z expert` is selected.
    pub experts: Vec<ExpertFact<'a>>,
    /// Interested field occurrences in tree order.
    fields: Vec<(&'static FieldDef, &'a Value)>,
}

impl<'a> FrameFacts<'a> {
    pub(crate) fn build(frame: &'a Frame, packet: &'a Packet, interests: &Interests) -> Self {
        let mut facts = Self {
            frame,
            tree: &packet.tree,
            protocols: Vec::with_capacity(8),
            experts: Vec::new(),
            fields: Vec::with_capacity(16),
        };
        facts.walk(&packet.tree.frame, 0, None, interests);
        facts
    }

    fn walk(&mut self, node: &'a Node, depth: usize, parent: Option<usize>, interests: &Interests) {
        let protocol = node.protocol.short_name;
        let quoted = node.quoted;
        if interests.experts && !quoted {
            for expert in &node.experts {
                if node.protocol_exception && expert.group == Group::Malformed {
                    // A protocol exception reaches the expert tap with a
                    // generic summary; field-level malformed experts keep
                    // their specific text.
                    self.experts.push(ExpertFact {
                        severity: expert.severity,
                        group: expert.group,
                        protocol,
                        summary: "Malformed Packet (Exception occurred)",
                    });
                } else {
                    self.push_expert(expert, protocol);
                }
            }
        }
        let field_start = self.fields.len();
        for field in &node.fields {
            self.collect_field(field, protocol, interests, quoted);
        }
        let field_end = self.fields.len();
        let index = self.protocols.len();
        self.protocols.push(ProtocolFact {
            node,
            depth,
            parent,
            quoted,
            field_start,
            field_end,
        });
        for child in &node.children {
            self.walk(child, depth + 1, Some(index), interests);
        }
    }

    fn collect_field(
        &mut self,
        field: &'a crate::tree::Field,
        protocol: &'static str,
        interests: &Interests,
        quoted: bool,
    ) {
        if interests.experts && !quoted {
            for expert in &field.experts {
                self.push_expert(expert, protocol);
            }
        }
        if interests.wants_field(field.def.abbrev) {
            self.fields.push((field.def, &field.value));
        }
        for child in &field.children {
            self.collect_field(child, protocol, interests, quoted);
        }
    }

    fn push_expert(&mut self, expert: &'a ExpertInfo, protocol: &'static str) {
        self.experts.push(ExpertFact {
            severity: expert.severity,
            group: expert.group,
            protocol,
            summary: &expert.message,
        });
    }

    /// Number of occurrences of a protocol name.
    pub(crate) fn protocol_count(&self, filter_name: &str) -> usize {
        self.protocols
            .iter()
            .filter(|fact| fact.node.protocol.filter_name == filter_name)
            .count()
    }

    /// The first value of an interested field inside one protocol node.
    pub(crate) fn fact_first_field<'b>(
        &'b self,
        fact: &ProtocolFact<'a>,
        abbrev: &str,
    ) -> Option<&'a Value> {
        self.fields
            .get(fact.field_start..fact.field_end)?
            .iter()
            .find(|(field, _)| field.abbrev == abbrev)
            .map(|(_, value)| *value)
    }

    /// Every occurrence of an interested field inside one protocol node.
    pub(crate) fn fact_fields<'b>(
        &'b self,
        fact: &'b ProtocolFact<'a>,
        abbrev: &'b str,
    ) -> impl Iterator<Item = &'a Value> + 'b {
        self.fields
            .get(fact.field_start..fact.field_end)
            .unwrap_or_default()
            .iter()
            .filter(move |(field, _)| field.abbrev == abbrev)
            .map(|(_, value)| *value)
    }

    /// Every occurrence of a field, with its definition.
    pub(crate) fn field_values<'b>(
        &'b self,
        abbrev: &'b str,
    ) -> impl Iterator<Item = (&'static FieldDef, &'a Value)> + 'b {
        self.fields
            .iter()
            .filter(move |(field, _)| field.abbrev == abbrev)
            .map(|(field, value)| (*field, *value))
    }
}

/// Address families `conv,*` and `endpoints,*` accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConvKind {
    /// Ethernet MAC addresses.
    Ethernet,
    /// Linux cooked capture source addresses.
    Sll,
    /// IPv4 addresses.
    Ipv4,
    /// IPv6 addresses.
    Ipv6,
    /// TCP addresses and ports.
    Tcp,
    /// UDP addresses and ports.
    Udp,
}

impl ConvKind {
    /// Parse one `conv,`/`endpoints,` family name.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "eth" => Self::Ethernet,
            "sll" => Self::Sll,
            "ip" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            _ => return None,
        })
    }

    /// Conversation-table title.
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Ethernet => "Ethernet",
            Self::Sll => "SLL",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }

    /// Whether the table has port columns.
    pub(crate) fn has_ports(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }

    /// Protocol node that must be present in the frame.
    pub(crate) fn protocol(self) -> &'static str {
        match self {
            Self::Ethernet => "eth",
            Self::Sll => "sll",
            Self::Ipv4 => "ip",
            Self::Ipv6 => "ipv6",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Fields the conversation aggregator reads.
    pub(crate) fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Ethernet => &["eth.src", "eth.dst"],
            Self::Sll => &["sll.src.eth", "sll.src.ipv4"],
            Self::Ipv4 => &["ip.src", "ip.dst", "ip.hdr_len"],
            Self::Ipv6 => &["ipv6.src", "ipv6.dst"],
            Self::Tcp => &[
                "ip.src",
                "ip.dst",
                "ipv6.src",
                "ipv6.dst",
                "tcp.srcport",
                "tcp.dstport",
                "tcp.stream",
                "tcp.hdr_len",
            ],
            Self::Udp => &[
                "ip.src",
                "ip.dst",
                "ipv6.src",
                "ipv6.dst",
                "udp.srcport",
                "udp.dstport",
                "udp.stream",
            ],
        }
    }
}
