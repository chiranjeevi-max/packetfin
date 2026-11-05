//! Name resolution for MAC, network and transport addresses.
//!
//! Static OUI and service-name tables come from authoritative registries
//! (`tools/gen-names`). Address-to-name mappings are learned from three
//! bounded sources: the `-H` hosts file, pcapng name-resolution blocks and,
//! when the corresponding `-N` flags are set, DNS answers and TLS SNI.
//! Lookup precedence is hosts file, capture block, then learned names.
//!
//! No network lookups happen here. `-N N` is accepted for compatibility but
//! Packetfin never sends a resolver query: the external resolver flag is
//! recorded and the session prints one notice.

mod oui;
mod services;
mod sni;

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Read};
use std::net::IpAddr;

pub use oui::{mac_organization, short_label as mac_short_label};
pub use services::service_name;
pub use sni::client_hello_sni;

/// Largest hosts file Packetfin reads, in bytes.
pub const HOSTS_MAX_BYTES: usize = 1024 * 1024;
/// Largest single hosts-file line Packetfin parses, in bytes.
pub const HOSTS_MAX_LINE: usize = 8192;
/// Largest number of hosts-file entries Packetfin retains.
pub const HOSTS_MAX_ENTRIES: usize = 65_536;

/// The entries a hosts file contributed and whether a cap stopped the read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedHosts {
    /// Address and first name pairs, in file order.
    pub entries: Vec<(IpAddr, String)>,
    /// Whether the byte, line or entry cap ended the read early.
    pub truncated: bool,
}

/// Parse `/etc/hosts` syntax from `reader`.
///
/// Full-line and trailing `#` comments are ignored, the first name after the
/// address is kept, aliases are dropped and malformed lines (including MAC
/// addresses) are skipped. Reads stop at the documented caps so a hostile
/// file cannot grow memory without bound.
pub fn parse_hosts(mut reader: impl BufRead) -> std::io::Result<ParsedHosts> {
    let mut parsed = ParsedHosts::default();
    let mut line = Vec::new();
    let mut bytes = 0_usize;
    loop {
        line.clear();
        let read = {
            let mut limited = (&mut reader).take((HOSTS_MAX_LINE + 1) as u64);
            limited.read_until(b'\n', &mut line)?
        };
        if read == 0 {
            break;
        }
        let mut consumed = read;
        let overlong = read > HOSTS_MAX_LINE && !line.ends_with(b"\n");
        let mut truncated = false;
        if overlong {
            // Discard the rest of this line through the buffered reader so a
            // multi-gigabyte line cannot be assembled in memory. The byte
            // budget is enforced inside the discard loop: a newline-free
            // stream such as /dev/zero must not spin forever.
            loop {
                let buffer = reader.fill_buf()?;
                if buffer.is_empty() {
                    break;
                }
                let (length, found_newline) = match buffer.iter().position(|byte| *byte == b'\n') {
                    Some(position) => (position.saturating_add(1), true),
                    None => (buffer.len(), false),
                };
                if bytes.saturating_add(consumed).saturating_add(length) > HOSTS_MAX_BYTES {
                    truncated = true;
                    break;
                }
                reader.consume(length);
                consumed = consumed.saturating_add(length);
                if found_newline {
                    break;
                }
            }
        }
        bytes = bytes.saturating_add(consumed);
        if truncated || bytes > HOSTS_MAX_BYTES || parsed.entries.len() >= HOSTS_MAX_ENTRIES {
            parsed.truncated = true;
            break;
        }
        if overlong {
            continue;
        }
        let comment = line
            .iter()
            .position(|byte| *byte == b'#')
            .unwrap_or(line.len());
        let content = line.get(..comment).unwrap_or(&[]);
        let mut tokens = content
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|token| !token.is_empty());
        let (Some(address), Some(name)) = (tokens.next(), tokens.next()) else {
            continue;
        };
        let (Ok(address), Ok(name)) = (std::str::from_utf8(address), std::str::from_utf8(name))
        else {
            continue;
        };
        let Ok(address) = address.parse::<IpAddr>() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        parsed.entries.push((address, name.to_string()));
    }
    Ok(parsed)
}

/// Bytes a name resolver may retain for hosts, capture and learned names.
pub const DEFAULT_NAME_BUDGET: usize = 4 * 1024 * 1024;

/// Largest number of learned entries, independent of the byte budget.
const MAX_LEARNED: usize = 65_536;
/// Largest number of capture or hosts entries, independent of the byte budget.
const MAX_ENTRIES: usize = 65_536;

/// Name-resolution preferences, set through `nameres.*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameResPrefs {
    /// Resolve Ethernet MAC addresses through the OUI table.
    pub mac_name: bool,
    /// Resolve transport port numbers through the IANA registry.
    pub transport_name: bool,
    /// Resolve IPv4 and IPv6 addresses.
    pub network_name: bool,
    /// Learn addresses from DNS answers; requires `network_name`.
    pub dns_pkt_addr_resolution: bool,
    /// Learn the server address from TLS ClientHello SNI; requires `network_name`.
    pub handshake_sni_addr_resolution: bool,
    /// Remember the requested external resolver behaviour.
    pub use_external_name_resolver: bool,
    /// Remember the requested VLAN-name behaviour; no table is installed.
    pub vlan_name: bool,
    /// Remember the requested MaxMind behaviour; no database is installed.
    pub maxmind_geoip: bool,
}

impl Default for NameResPrefs {
    fn default() -> Self {
        Self {
            mac_name: true,
            transport_name: false,
            network_name: false,
            dns_pkt_addr_resolution: true,
            handshake_sni_addr_resolution: false,
            use_external_name_resolver: true,
            vlan_name: false,
            maxmind_geoip: true,
        }
    }
}

impl NameResPrefs {
    /// The rendering switches these preferences select.
    pub fn resolution(self) -> Resolution {
        Resolution {
            mac: self.mac_name,
            network: self.network_name,
            transport: self.transport_name,
        }
    }
}

/// The resolution switches that affect how this packet's values are rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    /// Short OUI labels replace raw MAC addresses.
    pub mac: bool,
    /// Host names replace raw IP addresses.
    pub network: bool,
    /// Service names replace bare port numbers.
    pub transport: bool,
}

/// Bounded address-to-name tables shared by one decode session.
#[derive(Debug)]
pub struct NameResolver {
    prefs: NameResPrefs,
    hosts: HashMap<IpAddr, String>,
    capture: HashMap<IpAddr, String>,
    learned: HashMap<IpAddr, LearnedName>,
    order: VecDeque<(IpAddr, u64)>,
    next_order: u64,
    bytes: usize,
    limit: usize,
    dropped: bool,
    mac_labels: Vec<Option<MacLabel>>,
}

/// One cached pair of resolved MAC renderings.
///
/// The label is a pure function of the address and the resolution
/// preferences, which do not change during a run, so a cache hit returns
/// exactly what a fresh lookup would.
#[derive(Clone, Debug)]
struct MacLabel {
    address: [u8; 6],
    label: String,
    organization: Option<&'static str>,
}

/// Entries in the direct-mapped MAC label cache. A capture with more unique
/// addresses than this pays a miss per frame but never grows the cache.
const MAC_LABEL_CACHE: usize = 1024;

/// The cache slot for a MAC address.
fn mac_label_slot(address: [u8; 6]) -> usize {
    let mut hash = u64::from_le_bytes([
        address[0], address[1], address[2], address[3], address[4], address[5], 0, 0,
    ]);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    (hash as usize) & (MAC_LABEL_CACHE - 1)
}

#[derive(Clone, Debug)]
struct LearnedName {
    name: String,
    order: u64,
}

impl NameResolver {
    /// Build a resolver with the default name budget.
    pub fn new(prefs: NameResPrefs, hosts: Vec<(IpAddr, String)>) -> Self {
        Self::with_budget(prefs, hosts, DEFAULT_NAME_BUDGET)
    }

    /// Build a resolver with an explicit byte budget.
    ///
    /// Zero disables retention of hosts, capture and learned names.
    pub fn with_budget(prefs: NameResPrefs, hosts: Vec<(IpAddr, String)>, limit: usize) -> Self {
        let mut resolver = Self {
            prefs,
            hosts: HashMap::new(),
            capture: HashMap::new(),
            learned: HashMap::new(),
            order: VecDeque::new(),
            next_order: 0,
            bytes: 0,
            limit,
            dropped: false,
            mac_labels: vec![None; MAC_LABEL_CACHE],
        };
        for (address, name) in hosts {
            if resolver.hosts.contains_key(&address) {
                continue;
            }
            if resolver.hosts.len() >= MAX_ENTRIES || !resolver.charge(&name) {
                resolver.dropped = true;
                break;
            }
            resolver.hosts.insert(address, name);
        }
        resolver
    }

    /// The preferences that drive this resolver.
    pub fn prefs(&self) -> NameResPrefs {
        self.prefs
    }

    /// The rendering switches for one decoded packet.
    pub fn resolution(&self) -> Resolution {
        Resolution {
            mac: self.prefs.mac_name,
            network: self.prefs.network_name,
            transport: self.prefs.transport_name,
        }
    }

    /// Whether DNS answers should be collected during decoding.
    pub fn dns_learning_enabled(&self) -> bool {
        self.prefs.network_name && self.prefs.dns_pkt_addr_resolution
    }

    /// Whether a TLS ClientHello should be inspected for a server name.
    pub fn sni_learning_enabled(&self) -> bool {
        self.prefs.network_name && self.prefs.handshake_sni_addr_resolution
    }

    /// Add names learned from a pcapng name-resolution block.
    pub fn add_capture_names(&mut self, names: impl IntoIterator<Item = (IpAddr, String)>) {
        for (address, name) in names {
            if let Some(previous) = self.capture.get(&address) {
                let previous_cost = entry_bytes(&address, previous);
                if previous_cost >= entry_bytes(&address, &name) {
                    self.bytes = self.bytes.saturating_sub(previous_cost);
                    self.bytes = self.bytes.saturating_add(entry_bytes(&address, &name));
                    self.capture.insert(address, name);
                    continue;
                }
                if !self.make_room(entry_bytes(&address, &name).saturating_sub(previous_cost)) {
                    self.dropped = true;
                    return;
                }
                self.bytes = self.bytes.saturating_sub(previous_cost);
                self.bytes = self.bytes.saturating_add(entry_bytes(&address, &name));
                self.capture.insert(address, name);
                continue;
            }
            if self.capture.len() >= MAX_ENTRIES || !self.charge(&name) {
                self.dropped = true;
                return;
            }
            self.capture.insert(address, name);
        }
    }

    /// Learn the address a DNS answer maps to.
    pub fn learn_dns(&mut self, address: IpAddr, name: &str) {
        if self.dns_learning_enabled() {
            self.learn(address, name);
        }
    }

    /// Learn the server address named by a TLS ClientHello.
    pub fn learn_sni(&mut self, address: IpAddr, name: &str) {
        if self.sni_learning_enabled() {
            self.learn(address, name);
        }
    }

    /// The best name for an address, if any source knows one.
    ///
    /// Network resolution must be enabled; the tables are still populated so
    /// turning it on later in the same run keeps the learned names.
    pub fn host(&self, address: &IpAddr) -> Option<&str> {
        if !self.prefs.network_name {
            return None;
        }
        self.lookup_host(address)
    }

    /// The best name for an address, refreshing a learned entry's LRU order.
    pub fn host_mut(&mut self, address: &IpAddr) -> Option<&str> {
        if !self.prefs.network_name {
            return None;
        }
        self.touch(address);
        self.lookup_host(address)
    }

    fn lookup_host(&self, address: &IpAddr) -> Option<&str> {
        self.hosts
            .get(address)
            .or_else(|| self.capture.get(address))
            .or_else(|| self.learned.get(address).map(|learned| &learned.name))
            .map(String::as_str)
    }

    fn touch(&mut self, address: &IpAddr) {
        if !self.learned.contains_key(address) {
            return;
        }
        self.next_order = self.next_order.wrapping_add(1);
        let order = self.next_order;
        if let Some(entry) = self.learned.get_mut(address) {
            entry.order = order;
        }
        self.order.push_back((*address, order));
        let threshold = self.learned.len().saturating_mul(2).saturating_add(1024);
        if self.order.len() > threshold {
            self.compact_order();
        }
    }

    /// The short MAC label for `address`, or the raw address when the OUI is
    /// unknown or MAC resolution is off.
    pub fn resolved_mac(&self, address: [u8; 6]) -> String {
        if self.prefs.mac_name
            && let Some(label) = mac_short_label(address)
        {
            return label;
        }
        crate::tree::Value::Ethernet(address).render(crate::fields::Display::None)
    }

    /// The long registry name for a MAC address's OUI, independent of `-n`.
    pub fn mac_organization(&self, address: [u8; 6]) -> Option<&'static str> {
        if address == [0xff; 6] {
            return None;
        }
        oui::mac_organization(address)
    }

    /// The resolved short label and long OUI name for `address`.
    ///
    /// Both renderings are pure functions of the address and the resolution
    /// preferences, so they are cached per address in a fixed-size table.
    /// Frames repeat addresses far more often than they change them, and the
    /// cached value is identical to a fresh [`Self::resolved_mac`] and
    /// [`Self::mac_organization`] pair. The label is returned owned because
    /// the decoder stores it in the packet tree.
    pub fn mac_labels(&mut self, address: [u8; 6]) -> (String, Option<&'static str>) {
        let slot = mac_label_slot(address);
        if let Some(entry) = self.mac_labels.get(slot).and_then(Option::as_ref)
            && entry.address == address
        {
            return (entry.label.clone(), entry.organization);
        }
        let entry = MacLabel {
            address,
            label: self.resolved_mac(address),
            organization: self.mac_organization(address),
        };
        let labels = (entry.label.clone(), entry.organization);
        if let Some(cached) = self.mac_labels.get_mut(slot) {
            *cached = Some(entry);
        }
        labels
    }

    /// Whether a name was dropped because a table was full.
    pub fn take_dropped(&mut self) -> bool {
        std::mem::take(&mut self.dropped)
    }

    fn learn(&mut self, address: IpAddr, name: &str) {
        let cost = entry_bytes(&address, name);
        if cost > self.limit {
            self.dropped = true;
            return;
        }
        let previous_cost = self
            .learned
            .get(&address)
            .map(|previous| entry_bytes(&address, &previous.name));
        if previous_cost.is_none() && self.learned.len() >= MAX_LEARNED {
            self.dropped = true;
            return;
        }
        let extra = cost.saturating_sub(previous_cost.unwrap_or(0));
        if !self.make_room(extra) {
            self.dropped = true;
            return;
        }
        self.next_order = self.next_order.wrapping_add(1);
        if let Some(previous) = self.learned.insert(
            address,
            LearnedName {
                name: name.to_string(),
                order: self.next_order,
            },
        ) {
            self.bytes = self
                .bytes
                .saturating_sub(entry_bytes(&address, &previous.name));
        }
        self.bytes = self.bytes.saturating_add(cost);
        self.order.push_back((address, self.next_order));
        let threshold = self.learned.len().saturating_mul(2).saturating_add(1024);
        if self.order.len() > threshold {
            self.compact_order();
        }
    }

    fn compact_order(&mut self) {
        let learned = &self.learned;
        self.order.retain(|(address, order)| {
            learned
                .get(address)
                .is_some_and(|current| current.order == *order)
        });
    }

    fn make_room(&mut self, cost: usize) -> bool {
        if cost > self.limit {
            return false;
        }
        while self.bytes.saturating_add(cost) > self.limit {
            let Some((address, order)) = self.order.pop_front() else {
                return false;
            };
            if self
                .learned
                .get(&address)
                .is_some_and(|current| current.order == order)
                && let Some(removed) = self.learned.remove(&address)
            {
                self.bytes = self
                    .bytes
                    .saturating_sub(entry_bytes(&address, &removed.name));
            }
        }
        true
    }

    fn charge(&mut self, name: &str) -> bool {
        let cost = name.len().saturating_add(24);
        if (cost > self.limit || self.bytes.saturating_add(cost) > self.limit)
            && !self.make_room(cost)
        {
            return false;
        }
        self.bytes = self.bytes.saturating_add(cost);
        true
    }
}

fn entry_bytes(_address: &IpAddr, name: &str) -> usize {
    name.len()
        .saturating_add(std::mem::size_of::<IpAddr>())
        .saturating_add(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> IpAddr {
        text.parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }

    #[test]
    fn default_preferences_are_as_documented() {
        let prefs = NameResPrefs::default();
        assert!(prefs.mac_name);
        assert!(!prefs.transport_name);
        assert!(!prefs.network_name);
        assert!(prefs.dns_pkt_addr_resolution);
        assert!(!prefs.handshake_sni_addr_resolution);
        assert!(!prefs.vlan_name);
    }

    #[test]
    fn lookup_precedence_is_hosts_then_capture_then_learned() {
        let mut resolver = NameResolver::new(
            NameResPrefs {
                network_name: true,
                ..NameResPrefs::default()
            },
            vec![(address("192.0.2.1"), "hosts.example".to_string())],
        );
        resolver.add_capture_names(vec![
            (address("192.0.2.1"), "capture.example".to_string()),
            (address("192.0.2.2"), "capture.example".to_string()),
        ]);
        resolver.learn_dns(address("192.0.2.2"), "dns.example");
        assert_eq!(resolver.host(&address("192.0.2.1")), Some("hosts.example"));
        assert_eq!(
            resolver.host(&address("192.0.2.2")),
            Some("capture.example")
        );
    }

    #[test]
    fn hosts_syntax_keeps_first_names_and_ignores_bad_lines() {
        let input = b"# comment\n192.0.2.1 host.example alias.example\n\
                      00:11:22:33:44:55 mac.example\n\
                      8.8.8.8 dns.google # trailing\n\
                      malformed line\n\xff\xfe bad-utf8\n";
        let parsed = parse_hosts(std::io::Cursor::new(input)).unwrap_or_default();
        assert_eq!(
            parsed.entries,
            vec![
                (address("192.0.2.1"), "host.example".to_string()),
                (address("8.8.8.8"), "dns.google".to_string()),
            ]
        );
        assert!(!parsed.truncated);
    }

    #[test]
    fn a_hosts_file_past_the_byte_cap_is_truncated() {
        let input = vec![b'\n'; HOSTS_MAX_BYTES + 1];
        let parsed = parse_hosts(std::io::Cursor::new(input)).unwrap_or_default();
        assert!(parsed.truncated);
        assert!(parsed.entries.len() <= HOSTS_MAX_ENTRIES);
    }

    #[test]
    fn a_newline_free_stream_stops_at_the_byte_cap() {
        let reader = std::io::BufReader::new(std::io::repeat(0));
        let parsed = parse_hosts(reader).unwrap_or_default();
        assert!(parsed.truncated);
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn a_single_overlong_hosts_line_is_discarded() {
        let mut input = vec![b'x'; HOSTS_MAX_LINE.saturating_mul(8)];
        input.push(b'\n');
        input.extend_from_slice(b"192.0.2.1 host.example\n");
        let parsed = parse_hosts(std::io::Cursor::new(input)).unwrap_or_default();
        assert_eq!(
            parsed.entries,
            vec![(address("192.0.2.1"), "host.example".to_string())]
        );
    }

    #[test]
    fn learning_requires_network_resolution() {
        let mut resolver = NameResolver::new(NameResPrefs::default(), Vec::new());
        resolver.learn_dns(address("203.0.113.9"), "foo.test");
        resolver.learn_sni(address("203.0.113.9"), "sni.example");
        assert_eq!(resolver.host(&address("203.0.113.9")), None);
    }

    #[test]
    fn a_host_lookup_refreshes_the_learned_lru_order() {
        let prefs = NameResPrefs {
            network_name: true,
            ..NameResPrefs::default()
        };
        let mut resolver = NameResolver::new(prefs, Vec::new());
        let first = address("203.0.113.1");
        let second = address("203.0.113.2");
        resolver.learn_dns(first, "first.test");
        resolver.learn_dns(second, "second.test");
        let before_first = resolver
            .learned
            .get(&first)
            .map(|entry| entry.order)
            .unwrap_or(0);
        let before_second = resolver
            .learned
            .get(&second)
            .map(|entry| entry.order)
            .unwrap_or(0);
        assert!(before_second > before_first);
        assert_eq!(resolver.host_mut(&first), Some("first.test"));
        assert!(
            resolver.learned.get(&first).map(|entry| entry.order) > Some(before_second),
            "the looked-up entry must become most recent"
        );
    }

    #[test]
    fn repeated_learning_does_not_grow_the_order_queue() {
        let prefs = NameResPrefs {
            network_name: true,
            ..NameResPrefs::default()
        };
        let mut resolver = NameResolver::new(prefs, Vec::new());
        let address = address("203.0.113.9");
        for _ in 0..20_000 {
            resolver.learn_dns(address, "foo.test");
        }
        assert_eq!(resolver.learned.len(), 1);
        assert!(resolver.order.len() <= 1026);
        assert_eq!(resolver.host(&address), Some("foo.test"));
    }

    #[test]
    fn a_small_budget_evicts_without_growing() {
        let prefs = NameResPrefs {
            network_name: true,
            ..NameResPrefs::default()
        };
        let mut resolver = NameResolver::with_budget(prefs, Vec::new(), 256);
        for index in 0..100 {
            resolver.learn_dns(
                IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, index)),
                "example.test",
            );
        }
        assert!(resolver.bytes <= 256);
        assert!(resolver.learned.len() < 100);
    }

    #[test]
    fn mac_labels_cache_matches_uncached_lookups_across_evictions() {
        let mut resolver = NameResolver::new(NameResPrefs::default(), Vec::new());
        for index in 0..(MAC_LABEL_CACHE + 8) {
            let mac = [
                0x02,
                (index >> 8) as u8,
                index as u8,
                0x11,
                0x22,
                index as u8,
            ];
            let expected = (resolver.resolved_mac(mac), resolver.mac_organization(mac));
            assert_eq!(resolver.mac_labels(mac), expected);
            assert_eq!(resolver.mac_labels(mac), expected);
        }
        for mac in [
            [0xff; 6],
            [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb],
            [0x33, 0x33, 0, 0, 0, 1],
        ] {
            let expected = (resolver.resolved_mac(mac), resolver.mac_organization(mac));
            assert_eq!(resolver.mac_labels(mac), expected);
        }
    }

    #[test]
    fn mac_labels_with_resolution_off_keep_the_raw_address() {
        let prefs = NameResPrefs {
            mac_name: false,
            ..NameResPrefs::default()
        };
        let mut resolver = NameResolver::new(prefs, Vec::new());
        let mac = [0x00, 0x00, 0x0c, 0x11, 0x22, 0x33];
        assert_eq!(resolver.mac_labels(mac).0, "00:00:0c:11:22:33");
        assert_eq!(resolver.mac_labels(mac).1, Some("Cisco Systems, Inc"));
    }
}
