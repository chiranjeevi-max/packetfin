//! Protocol policy, decode-as entries and decoder preferences.
//!
//! The command line feeds three independent controls into the decoder:
//! per-protocol enablement (including the heuristic step), `-d` decode-as
//! entries, and `-o` preferences. Dispatch consults all three at every
//! registry table; keeping the state here means decoders never parse options.

use std::net::IpAddr;

use crate::fields::{self, Protocol};
use crate::names::NameResPrefs;

/// A layer type that `-d` can force.
///
/// `-d` accepts exactly these four names. VLAN and SLL inner types use
/// the `ethertype` table and IPv6 next headers use `ip.proto`, so no separate
/// layer types are needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LayerType {
    /// TCP port.
    TcpPort,
    /// UDP port.
    UdpPort,
    /// IPv4 protocol or IPv6 next header.
    IpProto,
    /// Ethernet, VLAN, SLL or SNAP EtherType.
    Ethertype,
}

impl LayerType {
    /// Every layer type `-d` accepts, in report order.
    pub const ALL: &'static [LayerType] =
        &[Self::TcpPort, Self::UdpPort, Self::IpProto, Self::Ethertype];

    /// The command-line name.
    pub fn name(self) -> &'static str {
        match self {
            Self::TcpPort => "tcp.port",
            Self::UdpPort => "udp.port",
            Self::IpProto => "ip.proto",
            Self::Ethertype => "ethertype",
        }
    }

    /// The parent protocol name used by `-G heuristic-decodes`.
    pub fn table_name(self) -> &'static str {
        match self {
            Self::TcpPort => "tcp",
            Self::UdpPort => "udp",
            Self::IpProto => "ip",
            Self::Ethertype => "ethertype",
        }
    }

    /// Resolve a command-line layer type name.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|layer| layer.name() == name)
    }

    /// Whether this layer can force `protocol`.
    pub fn accepts(self, protocol: Protocol) -> bool {
        if protocol == Protocol::Data {
            return true;
        }
        match self {
            Self::TcpPort => matches!(protocol, Protocol::Dns | Protocol::Http2),
            Self::UdpPort => fields::udp_port_protocols().any(|candidate| candidate == protocol),
            Self::IpProto => fields::ip_protocol_protocols().any(|candidate| candidate == protocol),
            Self::Ethertype => fields::ethertype_protocols().any(|candidate| candidate == protocol),
        }
    }

    /// The protocols this layer accepts, sorted by display name.
    pub fn valid_protocols(self) -> Vec<Protocol> {
        let mut protocols: Vec<Protocol> = Protocol::ALL
            .iter()
            .copied()
            .filter(|protocol| self.accepts(*protocol))
            .collect();
        protocols.sort_by_key(|protocol| protocol.filter_name());
        protocols.dedup();
        protocols
    }
}

/// A `-d` selector: exact value, inclusive range or a range of port numbers
/// with a given length (`8888:3` means 8888 through 8890).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selector {
    /// One value.
    Exact(u32),
    /// Inclusive first and last value.
    Range(u32, u32),
    /// First value and the number of consecutive values.
    Length(u32, u32),
}

impl Selector {
    /// Whether `value` is selected.
    pub fn matches(self, value: u32) -> bool {
        match self {
            Self::Exact(exact) => value == exact,
            Self::Range(first, last) => value >= first && value <= last,
            Self::Length(first, count) => {
                count != 0 && value >= first && value.saturating_sub(first) < count
            }
        }
    }
}

/// Parse a `-d` selector.
///
/// The number parser accepts leading whitespace and a leading `+` but no
/// trailing whitespace; the whole selector is therefore not trimmed.
pub fn parse_selector(text: &str) -> Result<Selector, String> {
    if let Some((first, last)) = text.split_once('-') {
        let first = parse_selector_number(first)?;
        let last = parse_selector_number(last)?;
        if first > last {
            return Err(format!("invalid selector range {text:?}"));
        }
        return Ok(Selector::Range(first, last));
    }
    if let Some((first, count)) = text.split_once(':') {
        let first = parse_selector_number(first)?;
        let count = parse_selector_number(count)?;
        if count == 0 {
            return Err(format!("invalid selector range {text:?}"));
        }
        return Ok(Selector::Length(first, count));
    }
    Ok(Selector::Exact(parse_selector_number(text)?))
}

fn parse_selector_number(text: &str) -> Result<u32, String> {
    let text = text.trim_start_matches(|character: char| character.is_ascii_whitespace());
    if text.is_empty() {
        return Err("invalid selector number".to_string());
    }
    let value = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid selector number {text:?}"));
        }
        u32::from_str_radix(hex, 16)
    } else {
        text.parse::<u32>()
    };
    value.map_err(|_| format!("invalid selector number {text:?}"))
}

/// One force entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeAsEntry {
    /// Layer the selector belongs to.
    pub layer: LayerType,
    /// Value selector.
    pub selector: Selector,
    /// Forced protocol.
    pub protocol: Protocol,
}

/// The `-d` table. Entries are consulted last-first, so a later entry that
/// overlaps an earlier one wins.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecodeAsTable {
    entries: Vec<DecodeAsEntry>,
}

impl DecodeAsTable {
    /// Add an entry. A later entry with the same layer and selector replaces
    /// the earlier one.
    pub fn insert(&mut self, entry: DecodeAsEntry) {
        self.entries.retain(|existing| {
            existing.layer != entry.layer || existing.selector != entry.selector
        });
        self.entries.push(entry);
    }

    /// The entry selected by `values`.
    ///
    /// Non-exact selectors (ranges and length lists) take priority over
    /// exact values. Among non-exact entries the smallest start wins; an equal
    /// start is resolved by the later registration, and identical selectors
    /// have already replaced each other in `insert`.
    pub fn lookup(&self, layer: LayerType, values: &[u32]) -> Option<Protocol> {
        let mut non_exact: Option<(usize, u32, &DecodeAsEntry)> = None;
        let mut exact: Option<(usize, &DecodeAsEntry)> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.layer != layer || !values.iter().any(|value| entry.selector.matches(*value)) {
                continue;
            }
            match entry.selector {
                Selector::Exact(_) => exact = Some((index, entry)),
                Selector::Range(start, _) | Selector::Length(start, _) => {
                    let better = match non_exact {
                        None => true,
                        Some((best_index, best_start, _)) => {
                            start < best_start || (start == best_start && index > best_index)
                        }
                    };
                    if better {
                        non_exact = Some((index, start, entry));
                    }
                }
            }
        }
        non_exact
            .map(|(_, _, entry)| entry.protocol)
            .or_else(|| exact.map(|(_, entry)| entry.protocol))
    }

    /// Whether the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The decode-as entry selected by forced packet data, including the
/// TCP-aware DNS wrapper.
pub fn forced_decoder(
    protocol: Protocol,
    layer: LayerType,
    data: &[u8],
) -> Option<crate::fields::Decoder> {
    if !forced_accepts(protocol, layer, data) {
        return None;
    }
    Some(decoder_for(protocol, layer))
}

/// The decoder a heuristic may apply, with the heuristic's stricter payload
/// check. Forced UDP DNS accepts any payload (and marks it malformed); the
/// `dns_udp` heuristic only claims DNS-shaped datagrams.
pub fn heuristic_decoder(
    protocol: Protocol,
    layer: LayerType,
    data: &[u8],
) -> Option<crate::fields::Decoder> {
    if !heuristic_accepts(protocol, layer, data) {
        return None;
    }
    Some(decoder_for(protocol, layer))
}

fn decoder_for(protocol: Protocol, layer: LayerType) -> crate::fields::Decoder {
    if protocol == Protocol::Dns && layer == LayerType::TcpPort {
        return crate::decode::dns_tcp;
    }
    protocol.decoder()
}

/// Whether a forced dissector accepts this payload.
///
/// A payload the forced dissector rejects falls back to the normal table.
/// Packetfin checks DNS framing over TCP and SNMP's BER header; other forced
/// dissectors accept and may mark the payload malformed. A forced UDP DNS
/// entry accepts arbitrary payloads so the decoder can add its malformed node.
fn forced_accepts(protocol: Protocol, layer: LayerType, data: &[u8]) -> bool {
    match protocol {
        Protocol::Data => true,
        Protocol::Dns | Protocol::Mdns | Protocol::Llmnr => {
            layer != LayerType::TcpPort || dns_tcp_payload(data).is_some()
        }
        Protocol::Snmp => looks_like_snmp(data),
        _ => true,
    }
}

fn heuristic_accepts(protocol: Protocol, layer: LayerType, data: &[u8]) -> bool {
    match protocol {
        Protocol::Dns | Protocol::Mdns | Protocol::Llmnr => crate::decode::looks_like_dns(data),
        _ => forced_accepts(protocol, layer, data),
    }
}

/// The DNS message inside a TCP payload: RFC 1035 section 4.2.2 requires a
/// two-byte length prefix that exactly frames the message.
pub(crate) fn dns_tcp_payload(data: &[u8]) -> Option<&[u8]> {
    if let Some(first) = data.first().copied()
        && let Some(second) = data.get(1).copied()
    {
        let length = usize::from(u16::from_be_bytes([first, second]));
        if length >= 12
            && length.saturating_add(2) == data.len()
            && let Some(payload) = data.get(2..)
            && crate::decode::looks_like_dns(payload)
        {
            return Some(payload);
        }
    }
    None
}

fn looks_like_snmp(data: &[u8]) -> bool {
    let Some(&tag) = data.first() else {
        return false;
    };
    if tag != 0x30 {
        return false;
    }
    let Some(&length_byte) = data.get(1) else {
        return false;
    };
    if length_byte & 0x80 == 0 {
        return usize::from(length_byte).saturating_add(2) <= data.len();
    }
    let octets = usize::from(length_byte & 0x7f);
    if octets == 0 || octets > 4 {
        return false;
    }
    let Some(length_bytes) = data.get(2..2 + octets) else {
        return false;
    };
    let mut length = 0_usize;
    for byte in length_bytes {
        length = length
            .saturating_mul(256)
            .saturating_add(usize::from(*byte));
    }
    length.saturating_add(2 + octets) <= data.len()
}

/// A heuristic dissector Packetfin can enable or disable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeuristicDef {
    /// Parent dispatch layer.
    pub layer: LayerType,
    /// Protocol the heuristic selects.
    pub protocol: Protocol,
    /// Short name used by `--enable-heuristic` and `-G heuristic-decodes`.
    pub short_name: &'static str,
    /// Long name for the report.
    pub long_name: &'static str,
    /// Whether the heuristic runs by default.
    pub enabled_by_default: bool,
}

/// Every implemented heuristic.
pub static HEURISTICS: &[HeuristicDef] = &[HeuristicDef {
    layer: LayerType::UdpPort,
    protocol: Protocol::Dns,
    short_name: "dns_udp",
    long_name: "DNS over UDP",
    enabled_by_default: true,
}];

/// Find a heuristic by its short name.
pub fn heuristic(name: &str) -> Option<&'static HeuristicDef> {
    HEURISTICS
        .iter()
        .find(|heuristic| heuristic.short_name == name)
}

/// Protocol enablement and heuristic switches for one run.
///
/// `--enable-protocol` wins over `--disable-protocol` regardless of order;
/// `--only-protocols` is "disable all, then enable the list". Heuristic
/// disabling wins over enabling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolPolicy {
    explicitly_enabled: u64,
    explicitly_disabled: u64,
    heuristics_enabled: u64,
    heuristics_disabled: u64,
    enabled: u64,
}

impl ProtocolPolicy {
    /// Every protocol and heuristic enabled.
    pub fn new() -> Self {
        Self {
            explicitly_enabled: 0,
            explicitly_disabled: 0,
            heuristics_enabled: 0,
            heuristics_disabled: 0,
            enabled: Self::all_protocols(),
        }
    }

    fn protocol_mask(protocol: Protocol) -> u64 {
        1_u64 << protocol.index()
    }

    fn all_protocols() -> u64 {
        Protocol::ALL.iter().fold(0_u64, |mask, protocol| {
            mask | Self::protocol_mask(*protocol)
        })
    }

    /// Enable one protocol.
    pub fn enable(&mut self, protocol: Protocol) {
        self.explicitly_enabled |= Self::protocol_mask(protocol);
    }

    /// Disable one protocol.
    pub fn disable(&mut self, protocol: Protocol) {
        self.explicitly_disabled |= Self::protocol_mask(protocol);
    }

    /// Enable every protocol.
    pub fn enable_all(&mut self) {
        self.explicitly_enabled |= Self::all_protocols();
    }

    /// Disable every protocol.
    pub fn disable_all(&mut self) {
        self.explicitly_disabled |= Self::all_protocols();
    }

    /// Resolve the accumulated flags.
    pub fn finalize(&mut self) {
        self.enabled =
            self.explicitly_enabled | (Self::all_protocols() & !self.explicitly_disabled);
    }

    /// Whether a protocol may decode.
    pub fn enabled(&self, protocol: Protocol) -> bool {
        if matches!(protocol, Protocol::Frame | Protocol::Data) {
            return true;
        }
        self.enabled & Self::protocol_mask(protocol) != 0
    }

    /// Enable one heuristic. A matching disable still wins.
    pub fn enable_heuristic(&mut self, heuristic: &'static HeuristicDef) {
        let index = heuristic_index(heuristic);
        self.heuristics_enabled |= 1_u64 << index;
    }

    /// Disable one heuristic.
    pub fn disable_heuristic(&mut self, heuristic: &'static HeuristicDef) {
        let index = heuristic_index(heuristic);
        self.heuristics_disabled |= 1_u64 << index;
    }

    /// Whether a heuristic may run.
    pub fn heuristic_enabled(&self, heuristic: &'static HeuristicDef) -> bool {
        let index = heuristic_index(heuristic);
        (heuristic.enabled_by_default || self.heuristics_enabled & (1_u64 << index) != 0)
            && self.heuristics_disabled & (1_u64 << index) == 0
    }
}

impl Default for ProtocolPolicy {
    fn default() -> Self {
        let mut policy = Self::new();
        policy.finalize();
        policy
    }
}

fn heuristic_index(heuristic: &'static HeuristicDef) -> u32 {
    HEURISTICS
        .iter()
        .position(|candidate| std::ptr::eq(candidate, heuristic))
        .and_then(|index| u32::try_from(index).ok())
        .unwrap_or(0)
}

/// The typed preference set read by implemented decoders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preferences {
    /// `ip.check_checksum`.
    pub ip_check_checksum: bool,
    /// `udp.check_checksum`.
    pub udp_check_checksum: bool,
    /// `tcp.check_checksum`.
    pub tcp_check_checksum: bool,
    /// `tcp.relative_sequence_numbers`.
    pub tcp_relative_sequence_numbers: bool,
    /// `nameres.*`.
    pub nameres: NameResPrefs,
    /// `cflow.netflow.ports`.
    pub cflow_netflow_ports: Vec<u16>,
    /// `cflow.ipfix.ports`.
    pub cflow_ipfix_ports: Vec<u16>,
    /// `ip.defragment`.
    pub ip_defragment: bool,
    /// `ipv6.defragment`.
    pub ipv6_defragment: bool,
    /// `tcp.analyze_sequence_numbers`.
    pub tcp_analyze_sequence_numbers: bool,
    /// `tcp.desegment_tcp_streams`.
    pub tcp_desegment_tcp_streams: bool,
    /// `tcp.reassemble_out_of_order`.
    pub tcp_reassemble_out_of_order: bool,
    /// `tcp.track_bytes_in_flight`.
    pub tcp_track_bytes_in_flight: bool,
    /// `tcp.calculate_timestamps`.
    pub tcp_calculate_timestamps: bool,
    /// `tcp.fastrt_supersedes_ooo`.
    pub tcp_fastrt_supersedes_ooo: bool,
    /// `tcp.default_window_scaling`; `-1` means "Not known".
    pub tcp_default_window_scaling: i8,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            ip_check_checksum: false,
            udp_check_checksum: false,
            tcp_check_checksum: false,
            tcp_relative_sequence_numbers: true,
            nameres: NameResPrefs::default(),
            cflow_netflow_ports: vec![2055, 9996],
            cflow_ipfix_ports: vec![4739],
            ip_defragment: true,
            ipv6_defragment: true,
            tcp_analyze_sequence_numbers: true,
            tcp_desegment_tcp_streams: true,
            tcp_reassemble_out_of_order: false,
            tcp_track_bytes_in_flight: true,
            tcp_calculate_timestamps: true,
            tcp_fastrt_supersedes_ooo: true,
            tcp_default_window_scaling: -1,
        }
    }
}

impl Preferences {
    /// Whether the external resolver was requested and network resolution is
    /// on, the only state in which a lookup would happen.
    pub fn external_resolver_active(&self) -> bool {
        self.nameres.use_external_name_resolver && self.nameres.network_name
    }
}

/// The kind and validation rule of one preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefKind {
    /// Boolean; only case-insensitive `TRUE` is true.
    Bool,
    /// Decimal integer in an inclusive range.
    Uint {
        /// Smallest accepted value.
        min: u64,
        /// Largest accepted value.
        max: u64,
    },
    /// Enumerated string; invalid values are accepted leniently and ignored.
    Enum {
        /// Accepted spellings.
        values: &'static [&'static str],
    },
    /// Free-form string.
    String,
    /// Comma-separated ports and inclusive ranges.
    PortList,
}

/// One registered preference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefDef {
    /// Canonical `protocol.preference` name.
    pub name: &'static str,
    /// Value syntax.
    pub kind: PrefKind,
}

/// The preferences Packetfin actually reads.
pub static PREF_DEFS: &[PrefDef] = &[
    PrefDef {
        name: "ip.check_checksum",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "udp.check_checksum",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.check_checksum",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.relative_sequence_numbers",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.mac_name",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.transport_name",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.network_name",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.dns_pkt_addr_resolution",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.handshake_sni_addr_resolution",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.use_external_name_resolver",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.vlan_name",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "nameres.maxmind_geoip",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "ip.defragment",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "ipv6.defragment",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.analyze_sequence_numbers",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.desegment_tcp_streams",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.reassemble_out_of_order",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.track_bytes_in_flight",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.calculate_timestamps",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.fastrt_supersedes_ooo",
        kind: PrefKind::Bool,
    },
    PrefDef {
        name: "tcp.default_window_scaling",
        kind: PrefKind::Enum {
            values: &[
                "Not known",
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "10",
                "11",
                "12",
                "13",
                "14",
            ],
        },
    },
    PrefDef {
        name: "cflow.netflow.ports",
        kind: PrefKind::PortList,
    },
    PrefDef {
        name: "cflow.ipfix.ports",
        kind: PrefKind::PortList,
    },
];

/// Why a `-o` value was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefError {
    /// The value has no colon separator.
    MissingColon,
    /// The preference name is not registered.
    UnknownName,
    /// The value does not satisfy the preference's kind.
    InvalidValue,
}

/// Apply one `-o NAME:VALUE` setting.
pub fn apply_preference(value: &str, preferences: &mut Preferences) -> Result<(), PrefError> {
    let (name, setting) = value.split_once(':').ok_or(PrefError::MissingColon)?;
    if name.is_empty() {
        return Err(PrefError::UnknownName);
    }
    let canonical = canonical_name(name).ok_or(PrefError::UnknownName)?;
    let definition = PREF_DEFS
        .iter()
        .find(|definition| definition.name == canonical)
        .ok_or(PrefError::UnknownName)?;
    let setting = setting.trim_start_matches(' ');
    if definition.name == "tcp.default_window_scaling" {
        preferences.tcp_default_window_scaling = if setting.eq_ignore_ascii_case("not known") {
            -1
        } else {
            setting
                .parse::<i8>()
                .ok()
                .filter(|value| (0..=14).contains(value))
                .ok_or(PrefError::InvalidValue)?
        };
        return Ok(());
    }
    match definition.kind {
        PrefKind::Bool => {
            let enabled = setting.eq_ignore_ascii_case("TRUE");
            set_bool(definition.name, enabled, preferences);
        }
        PrefKind::Uint { min, max } => {
            let value = parse_uint(setting).ok_or(PrefError::InvalidValue)?;
            if value < min || value > max {
                return Err(PrefError::InvalidValue);
            }
        }
        PrefKind::Enum { values } => {
            // Accept an unknown spelling and keep the default.
            let _ = values.contains(&setting);
        }
        PrefKind::String => {}
        PrefKind::PortList => {
            let ports = parse_port_list(setting).ok_or(PrefError::InvalidValue)?;
            if definition.name == "cflow.netflow.ports" {
                preferences.cflow_netflow_ports = ports;
            } else {
                preferences.cflow_ipfix_ports = ports;
            }
        }
    }
    Ok(())
}

fn canonical_name(name: &str) -> Option<String> {
    let (protocol, preference) = name.split_once('.')?;
    Some(format!("{}.{preference}", protocol.to_ascii_lowercase()))
}

fn set_bool(name: &str, value: bool, preferences: &mut Preferences) {
    match name {
        "ip.check_checksum" => preferences.ip_check_checksum = value,
        "udp.check_checksum" => preferences.udp_check_checksum = value,
        "tcp.check_checksum" => preferences.tcp_check_checksum = value,
        "tcp.relative_sequence_numbers" => preferences.tcp_relative_sequence_numbers = value,
        "ip.defragment" => preferences.ip_defragment = value,
        "ipv6.defragment" => preferences.ipv6_defragment = value,
        "tcp.analyze_sequence_numbers" => preferences.tcp_analyze_sequence_numbers = value,
        "tcp.desegment_tcp_streams" => preferences.tcp_desegment_tcp_streams = value,
        "tcp.reassemble_out_of_order" => preferences.tcp_reassemble_out_of_order = value,
        "tcp.track_bytes_in_flight" => preferences.tcp_track_bytes_in_flight = value,
        "tcp.calculate_timestamps" => preferences.tcp_calculate_timestamps = value,
        "tcp.fastrt_supersedes_ooo" => preferences.tcp_fastrt_supersedes_ooo = value,
        "nameres.mac_name" => preferences.nameres.mac_name = value,
        "nameres.transport_name" => preferences.nameres.transport_name = value,
        "nameres.network_name" => preferences.nameres.network_name = value,
        "nameres.dns_pkt_addr_resolution" => {
            preferences.nameres.dns_pkt_addr_resolution = value;
        }
        "nameres.handshake_sni_addr_resolution" => {
            preferences.nameres.handshake_sni_addr_resolution = value;
        }
        "nameres.use_external_name_resolver" => {
            preferences.nameres.use_external_name_resolver = value;
        }
        "nameres.vlan_name" => preferences.nameres.vlan_name = value,
        "nameres.maxmind_geoip" => preferences.nameres.maxmind_geoip = value,
        _ => {}
    }
}

fn parse_uint(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Parse a port list: comma-separated values and inclusive `first-last`
/// ranges. An empty value means no ports.
fn parse_port_list(text: &str) -> Option<Vec<u16>> {
    const MAX_PORTS: usize = 65_536;
    if text.is_empty() {
        return Some(Vec::new());
    }
    let items: Vec<&str> = text.split(',').collect();
    let mut ports = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let item = item.trim();
        if item.is_empty() {
            // Accept one trailing empty item but reject a leading or interior
            // empty one.
            if index + 1 == items.len() {
                continue;
            }
            return None;
        }
        if let Some((first, last)) = item.split_once('-') {
            let first = parse_port(first.trim())?;
            let last = parse_port(last.trim())?;
            if first > last {
                return None;
            }
            for port in first..=last {
                ports.push(port);
                if ports.len() > MAX_PORTS {
                    return None;
                }
            }
        } else {
            ports.push(parse_port(item)?);
            if ports.len() > MAX_PORTS {
                return None;
            }
        }
    }
    Some(ports)
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Everything the command line can change about decoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecodeOptions {
    /// `-o` preferences.
    pub preferences: Preferences,
    /// Protocol and heuristic enablement.
    pub policy: ProtocolPolicy,
    /// `-d` decode-as entries.
    pub decode_as: DecodeAsTable,
    /// `-H` hosts-file entries, in file order.
    pub hosts: Vec<(IpAddr, String)>,
    /// One-shot diagnostics for the session driver.
    pub notices: Vec<String>,
    /// Whether UDP's per-stream timestamp fields are built.
    ///
    /// Every datagram carries them, but they are only observable in the full
    /// tree, a selected field or a filter. Skipping them on plain summaries
    /// keeps the one-field path within its performance guard.
    pub udp_timestamps: bool,
}

/// Name-resolution preferences for a command-line `-N` flag string.
///
/// Every `-N` replaces the whole set. An unknown flag is reported by the
/// caller.
pub fn nameres_from_flags(flags: &str) -> Option<NameResPrefs> {
    let mut prefs = NameResPrefs {
        mac_name: false,
        transport_name: false,
        network_name: false,
        dns_pkt_addr_resolution: false,
        handshake_sni_addr_resolution: false,
        use_external_name_resolver: false,
        vlan_name: false,
        maxmind_geoip: false,
    };
    for flag in flags.chars() {
        match flag {
            'm' => prefs.mac_name = true,
            'n' => prefs.network_name = true,
            't' => prefs.transport_name = true,
            'd' => prefs.dns_pkt_addr_resolution = true,
            's' => prefs.handshake_sni_addr_resolution = true,
            'v' => prefs.vlan_name = true,
            'N' => prefs.use_external_name_resolver = true,
            'g' => prefs.maxmind_geoip = true,
            _ => return None,
        }
    }
    Some(prefs)
}

/// Why one `-d` value was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeAsError {
    /// The value lacks `==` or a comma.
    Template,
    /// The layer type is not one of [`LayerType::ALL`].
    UnknownLayer(String),
    /// The selector is not a number, range or length.
    InvalidSelector(String),
    /// The protocol name is not registered.
    UnknownProtocol {
        /// Layer type named on the command line.
        layer: LayerType,
        /// Protocol name named on the command line.
        protocol: String,
    },
    /// The protocol cannot be forced for this layer.
    InvalidForLayer {
        /// Layer type named on the command line.
        layer: LayerType,
        /// Protocol name named on the command line.
        protocol: String,
    },
}

/// Parse one `<layer_type>==<selector>,<protocol>` value into `table`.
pub fn parse_decode_as(value: &str, table: &mut DecodeAsTable) -> Result<(), DecodeAsError> {
    let (left, protocol_name) = value.split_once(',').ok_or(DecodeAsError::Template)?;
    let (layer_name, selector) = left.split_once("==").ok_or(DecodeAsError::Template)?;
    let layer = LayerType::parse(layer_name)
        .ok_or_else(|| DecodeAsError::UnknownLayer(layer_name.to_string()))?;
    let selector = parse_selector(selector).map_err(DecodeAsError::InvalidSelector)?;
    let protocol =
        fields::protocol_by_name(protocol_name).ok_or_else(|| DecodeAsError::UnknownProtocol {
            layer,
            protocol: protocol_name.to_string(),
        })?;
    if !layer.accepts(protocol) {
        return Err(DecodeAsError::InvalidForLayer {
            layer,
            protocol: protocol_name.to_string(),
        });
    }
    table.insert(DecodeAsEntry {
        layer,
        selector,
        protocol,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_exact_range_and_length() {
        assert!(Selector::Exact(53).matches(53));
        assert!(!Selector::Exact(53).matches(54));
        assert!(Selector::Range(10, 12).matches(12));
        assert!(!Selector::Range(10, 12).matches(13));
        assert!(Selector::Length(8888, 3).matches(8890));
        assert!(!Selector::Length(8888, 3).matches(8891));
        assert!(!Selector::Length(8888, 0).matches(8888));
    }

    #[test]
    fn selector_grammar_accepts_hex_ranges_and_lengths() {
        assert_eq!(parse_selector("0x0800"), Ok(Selector::Exact(2048)));
        assert_eq!(parse_selector("8888-8890"), Ok(Selector::Range(8888, 8890)));
        assert_eq!(parse_selector("8888:3"), Ok(Selector::Length(8888, 3)));
        assert_eq!(parse_selector(" +20006"), Ok(Selector::Exact(20006)));
        assert_eq!(
            parse_selector("20005- 20010"),
            Ok(Selector::Range(20005, 20010))
        );
        assert_eq!(parse_selector("20005: 3"), Ok(Selector::Length(20005, 3)));
        assert!(parse_selector("20006 ").is_err());
        assert!(parse_selector("20005 - 20010").is_err());
        assert!(parse_selector("20005 :3").is_err());
        assert!(parse_selector("53:0").is_err());
        assert!(parse_selector("abc").is_err());
        assert!(parse_selector("-1").is_err());
        assert!(parse_selector("9-1").is_err());
        assert!(parse_selector("").is_err());
    }

    #[test]
    fn a_later_decode_as_entry_replaces_the_same_selector() {
        let mut table = DecodeAsTable::default();
        table.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Exact(53),
            protocol: Protocol::Dns,
        });
        table.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Exact(53),
            protocol: Protocol::Data,
        });
        assert_eq!(
            table.lookup(LayerType::UdpPort, &[53]),
            Some(Protocol::Data)
        );
    }

    #[test]
    fn non_exact_selectors_outrank_exact_and_smallest_start_wins() {
        let mut table = DecodeAsTable::default();
        table.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Range(20_005, 20_010),
            protocol: Protocol::Dns,
        });
        table.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Exact(20_006),
            protocol: Protocol::Data,
        });
        assert_eq!(
            table.lookup(LayerType::UdpPort, &[20_006]),
            Some(Protocol::Dns)
        );

        let mut reversed = DecodeAsTable::default();
        reversed.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Exact(20_006),
            protocol: Protocol::Data,
        });
        reversed.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Length(20_005, 5),
            protocol: Protocol::Dns,
        });
        assert_eq!(
            reversed.lookup(LayerType::UdpPort, &[20_006]),
            Some(Protocol::Dns)
        );

        let mut starts = DecodeAsTable::default();
        starts.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Range(20_006, 20_010),
            protocol: Protocol::Data,
        });
        starts.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Range(20_005, 20_010),
            protocol: Protocol::Dns,
        });
        assert_eq!(
            starts.lookup(LayerType::UdpPort, &[20_006]),
            Some(Protocol::Dns)
        );

        let mut same_start = DecodeAsTable::default();
        same_start.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Range(20_005, 20_010),
            protocol: Protocol::Dns,
        });
        same_start.insert(DecodeAsEntry {
            layer: LayerType::UdpPort,
            selector: Selector::Range(20_005, 20_008),
            protocol: Protocol::Data,
        });
        assert_eq!(
            same_start.lookup(LayerType::UdpPort, &[20_006]),
            Some(Protocol::Data)
        );
    }

    #[test]
    fn forced_udp_dns_accepts_arbitrary_payloads_but_the_heuristic_does_not() {
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        assert!(forced_decoder(Protocol::Dns, LayerType::UdpPort, b"\0").is_some());
        assert!(heuristic_decoder(Protocol::Dns, LayerType::UdpPort, b"\0").is_none());
        assert!(forced_decoder(Protocol::Dns, LayerType::UdpPort, query).is_some());
        assert!(heuristic_decoder(Protocol::Dns, LayerType::UdpPort, query).is_some());
        assert!(forced_decoder(Protocol::Dns, LayerType::TcpPort, query).is_none());
    }

    #[test]
    fn implemented_decoders_are_valid_forced_protocols() {
        for protocol in [Protocol::Llc, Protocol::Stp, Protocol::Lacp] {
            assert!(LayerType::Ethertype.accepts(protocol), "{protocol:?}");
        }
        for protocol in [
            Protocol::Ipv6Hopopts,
            Protocol::Ipv6Dstopts,
            Protocol::Ipv6Routing,
            Protocol::Ipv6Fraghdr,
        ] {
            assert!(LayerType::IpProto.accepts(protocol), "{protocol:?}");
        }
        let mut table = DecodeAsTable::default();
        assert_eq!(parse_decode_as("ethertype==0x1234,llc", &mut table), Ok(()));
        assert_eq!(
            parse_decode_as("ip.proto==0,ipv6.hopopts", &mut table),
            Ok(())
        );
    }

    #[test]
    fn decode_as_grammar_reports_error_classes() {
        let mut table = DecodeAsTable::default();
        assert_eq!(parse_decode_as("udp.port==53,dns", &mut table), Ok(()));
        assert_eq!(parse_decode_as("tcp.port==40000:3,dns", &mut table), Ok(()));
        assert_eq!(
            parse_decode_as("bogus==1,dns", &mut table),
            Err(DecodeAsError::UnknownLayer("bogus".to_string()))
        );
        assert!(matches!(
            parse_decode_as("tcp.port==abc,dns", &mut table),
            Err(DecodeAsError::InvalidSelector(_))
        ));
        assert!(matches!(
            parse_decode_as("tcp.port==53,nosuch", &mut table),
            Err(DecodeAsError::UnknownProtocol { .. })
        ));
        assert_eq!(
            parse_decode_as("tcp.port==53,udp", &mut table),
            Err(DecodeAsError::InvalidForLayer {
                layer: LayerType::TcpPort,
                protocol: "udp".to_string(),
            })
        );
        assert_eq!(
            parse_decode_as("tcp.port==53", &mut table),
            Err(DecodeAsError::Template)
        );
    }

    #[test]
    fn enable_wins_over_disable_and_only_disables_the_rest() {
        let mut policy = ProtocolPolicy::new();
        policy.disable(Protocol::Dns);
        policy.enable(Protocol::Dns);
        policy.finalize();
        assert!(policy.enabled(Protocol::Dns));

        let mut only = ProtocolPolicy::new();
        only.disable_all();
        only.enable(Protocol::Dns);
        only.enable(Protocol::Ipv4);
        only.finalize();
        assert!(only.enabled(Protocol::Dns));
        assert!(only.enabled(Protocol::Ipv4));
        assert!(!only.enabled(Protocol::Udp));
    }

    #[test]
    fn heuristic_disable_wins_over_enable() {
        let Some(dns) = heuristic("dns_udp") else {
            return;
        };
        let mut policy = ProtocolPolicy::new();
        policy.disable_heuristic(dns);
        policy.enable_heuristic(dns);
        assert!(!policy.heuristic_enabled(dns));
    }

    #[test]
    fn preferences_use_bool_and_port_list_rules() {
        let mut prefs = Preferences::default();
        assert_eq!(
            apply_preference("ip.check_checksum: TRUE", &mut prefs),
            Ok(())
        );
        assert!(prefs.ip_check_checksum);
        assert_eq!(
            apply_preference("ip.check_checksum:maybe", &mut prefs),
            Ok(())
        );
        assert!(!prefs.ip_check_checksum);
        assert_eq!(
            apply_preference("IP.check_checksum:tRuE", &mut prefs),
            Ok(())
        );
        assert!(prefs.ip_check_checksum);
        assert_eq!(
            apply_preference("cflow.netflow.ports:2055,2056", &mut prefs),
            Ok(())
        );
        assert_eq!(prefs.cflow_netflow_ports, vec![2055, 2056]);
        assert_eq!(
            apply_preference("cflow.netflow.ports:9999, 9998", &mut prefs),
            Ok(())
        );
        assert_eq!(prefs.cflow_netflow_ports, vec![9999, 9998]);
        assert_eq!(
            apply_preference("cflow.netflow.ports:2055,", &mut prefs),
            Ok(())
        );
        assert_eq!(prefs.cflow_netflow_ports, vec![2055]);
        assert_eq!(
            apply_preference("cflow.netflow.ports:2055-2057", &mut prefs),
            Ok(())
        );
        assert_eq!(prefs.cflow_netflow_ports, vec![2055, 2056, 2057]);
        assert_eq!(
            apply_preference("cflow.netflow.ports:70000", &mut prefs),
            Err(PrefError::InvalidValue)
        );
        assert_eq!(apply_preference("cflow.netflow.ports:", &mut prefs), Ok(()));
        assert!(prefs.cflow_netflow_ports.is_empty());
    }

    #[test]
    fn nameres_flags_replace_the_whole_set() {
        let enabled = nameres_from_flags("nt").unwrap_or_default();
        assert!(enabled.network_name);
        assert!(enabled.transport_name);
        assert!(!enabled.mac_name);
        assert!(!enabled.use_external_name_resolver);
        let cleared = nameres_from_flags("").unwrap_or_default();
        assert!(!cleared.mac_name);
        assert!(!cleared.dns_pkt_addr_resolution);
        assert!(nameres_from_flags("x").is_none());
    }
}
