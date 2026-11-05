//! Bounded cache of NetFlow v9 and IPFIX templates.
//!
//! A template applies to one exporter stream: the exporter's address, source
//! port, transport protocol, observation domain (source ID for v9) and
//! template ID. A template defined by another address, port or domain never
//! applies. See RFC 3954 section 5.1 and RFC 7011 section 8.1.
//!
//! The cache keeps at most 4096 templates and 8 MiB of metadata. Both limits
//! are independent of the session budget: the session ledger still accounts
//! every byte, while this table evicts its own least-recently-used entries
//! when either limit would be exceeded.

use std::mem::size_of;

use super::budget::{Budget, PutOutcome, StateStore, StateValue};

/// Most templates the cache retains.
pub(crate) const MAX_TEMPLATES: usize = 4096;

/// Most metadata bytes the cache retains.
pub(crate) const MAX_TEMPLATE_BYTES: usize = 8 * 1024 * 1024;

/// Most fields a single template may declare.
///
/// RFC 3954 and RFC 7011 put no small bound on the field count. Packetfin
/// refuses a template with more fields, which keeps a hostile field count
/// from multiplying the per-record decoding work.
pub(crate) const MAX_TEMPLATE_FIELDS: usize = 60;

/// One exporter's network address.
///
/// v9 and IPFIX run over IPv4 or IPv6; a datagram without a decoded network
/// layer still gets a stream key so its templates work within the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ExporterAddress {
    /// IPv4 exporter address.
    V4([u8; 4]),
    /// IPv6 exporter address.
    V6([u8; 16]),
    /// No network layer supplied an address.
    Unknown,
}

/// Cache key for one template definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TemplateKey {
    /// Exporter address.
    pub exporter: ExporterAddress,
    /// Exporter source port.
    pub port: u16,
    /// Transport protocol number (17 for UDP).
    pub transport: u8,
    /// Observation domain ID, or the v9 source ID.
    pub domain: u32,
    /// Template ID.
    pub template_id: u16,
}

/// Whether a template describes data records or option records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TemplateKind {
    /// Data template; every field is a flow field.
    Data,
    /// v9 options template; the first `scope_count` fields use the v9 scope
    /// field types of RFC 3954 section 6.1.
    OptionsV9,
    /// IPFIX options template; scope fields are ordinary information
    /// elements (RFC 7011 section 3.4.2).
    OptionsIpfix,
}

/// One template field: information element, encoded width and optional
/// private enterprise number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TemplateField {
    /// Information element ID, with the enterprise bit removed.
    pub element: u16,
    /// Encoded width in octets.
    pub length: u16,
    /// Private enterprise number for an enterprise-specific element.
    pub enterprise: Option<u32>,
}

/// A cached template definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TemplateEntry {
    /// Data or options template.
    pub kind: TemplateKind,
    /// Number of leading scope fields for an options template.
    pub scope_count: u16,
    /// Frame number that defined this version of the template.
    pub frame: u64,
    /// Fields in wire order.
    pub fields: Vec<TemplateField>,
}

impl TemplateEntry {
    /// Total encoded width of one data record, or `None` when it is empty or
    /// would overflow `usize`.
    pub fn record_length(&self) -> Option<usize> {
        let mut length = 0_usize;
        for field in &self.fields {
            length = length.checked_add(usize::from(field.length))?;
        }
        (length > 0).then_some(length)
    }
}

impl StateValue for TemplateEntry {
    fn state_bytes(&self) -> usize {
        self.fields
            .capacity()
            .saturating_mul(size_of::<TemplateField>())
    }
}

/// The session's template table.
#[derive(Debug)]
pub(crate) struct TemplateCache {
    store: StateStore<TemplateKey, TemplateEntry>,
}

impl TemplateCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            store: StateStore::new(),
        }
    }

    /// Look up a template and mark it most recently used.
    pub fn lookup(&mut self, budget: &mut Budget, key: &TemplateKey) -> Option<TemplateEntry> {
        self.store.get_with(budget, key).cloned()
    }

    /// Number of retained templates.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Insert or replace a template, evicting least-recently-used entries
    /// until both the entry count and metadata limits fit.
    pub fn insert(
        &mut self,
        budget: &mut Budget,
        key: TemplateKey,
        entry: TemplateEntry,
    ) -> PutOutcome {
        if budget.limit() == 0 {
            // Zero disables retention; a template in the same datagram is
            // decoded from the per-message map instead.
            return PutOutcome {
                evicted: 0,
                dropped: true,
                charged: 0,
            };
        }
        let charge = StateStore::<TemplateKey, TemplateEntry>::charge_for(&entry);
        if charge > MAX_TEMPLATE_BYTES {
            // Unreachable while MAX_TEMPLATE_FIELDS bounds the vector, but
            // keep the hard limit independent of that constant.
            return PutOutcome {
                evicted: 0,
                dropped: true,
                charged: 0,
            };
        }
        if !self.store.contains_key(&key) {
            while self.store.len() >= MAX_TEMPLATES {
                if !self.store.evict_oldest_with(budget) {
                    break;
                }
            }
        }
        while self.store.used().saturating_add(charge) > MAX_TEMPLATE_BYTES {
            if !self.store.evict_oldest_with(budget) {
                break;
            }
        }
        self.store.put_with(budget, key, entry)
    }

    /// Remove a withdrawn template.
    pub fn remove(&mut self, budget: &mut Budget, key: &TemplateKey) -> bool {
        self.store.take_with(budget, key).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u16) -> TemplateKey {
        TemplateKey {
            exporter: ExporterAddress::V4([192, 0, 2, 1]),
            port: 2055,
            transport: 17,
            domain: 7,
            template_id: id,
        }
    }

    fn entry(id: u64, fields: usize) -> TemplateEntry {
        TemplateEntry {
            kind: TemplateKind::Data,
            scope_count: 0,
            frame: id,
            fields: vec![
                TemplateField {
                    element: 8,
                    length: 4,
                    enterprise: None,
                };
                fields
            ],
        }
    }

    #[test]
    fn a_template_is_visible_only_under_its_full_key() {
        let mut budget = Budget::new(1 << 20);
        let mut cache = TemplateCache::new();
        cache.insert(&mut budget, key(256), entry(1, 2));

        assert_eq!(cache.lookup(&mut budget, &key(256)), Some(entry(1, 2)));
        assert_eq!(cache.lookup(&mut budget, &key(257)), None);
        let mut other = key(256);
        other.port = 40001;
        assert_eq!(cache.lookup(&mut budget, &other), None);
        other = key(256);
        other.domain = 8;
        assert_eq!(cache.lookup(&mut budget, &other), None);
        other = key(256);
        other.exporter = ExporterAddress::V4([192, 0, 2, 9]);
        assert_eq!(cache.lookup(&mut budget, &other), None);
    }

    #[test]
    fn refresh_replaces_the_previous_definition() {
        let mut budget = Budget::new(1 << 20);
        let mut cache = TemplateCache::new();
        cache.insert(&mut budget, key(256), entry(1, 2));
        cache.insert(&mut budget, key(256), entry(2, 3));
        assert_eq!(cache.lookup(&mut budget, &key(256)), Some(entry(2, 3)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn eviction_removes_templates_before_the_entry_cap() {
        let mut budget = Budget::new(1 << 24);
        let mut cache = TemplateCache::new();
        for id in 0..MAX_TEMPLATES {
            let id = u16::try_from(id).unwrap_or(u16::MAX);
            cache.insert(&mut budget, key(id), entry(u64::from(id), 1));
        }
        assert_eq!(cache.len(), MAX_TEMPLATES);
        cache.insert(&mut budget, key(MAX_TEMPLATES as u16), entry(9_999, 1));
        assert_eq!(cache.len(), MAX_TEMPLATES);
        assert_eq!(cache.lookup(&mut budget, &key(0)), None);
        assert!(
            cache
                .lookup(&mut budget, &key(MAX_TEMPLATES as u16))
                .is_some()
        );
    }

    #[test]
    fn the_metadata_guard_holds_for_a_full_cache() {
        let mut budget = Budget::new(1 << 30);
        let mut cache = TemplateCache::new();
        for id in 0..MAX_TEMPLATES {
            let id = u16::try_from(id).unwrap_or(u16::MAX);
            cache.insert(&mut budget, key(id), entry(u64::from(id), 64));
        }
        assert_eq!(cache.len(), MAX_TEMPLATES);
        assert!(cache.store.used() <= MAX_TEMPLATE_BYTES);
        // The 4096-entry cap binds first for 64-field templates; the 8 MiB
        // guard is a hard upper bound for a future larger field bound.
        cache.insert(&mut budget, key(MAX_TEMPLATES as u16), entry(1, 64));
        assert_eq!(cache.len(), MAX_TEMPLATES);
        assert!(cache.store.used() <= MAX_TEMPLATE_BYTES);
        assert_eq!(cache.lookup(&mut budget, &key(0)), None);
    }

    #[test]
    fn removal_makes_a_later_lookup_miss() {
        let mut budget = Budget::new(1 << 20);
        let mut cache = TemplateCache::new();
        cache.insert(&mut budget, key(256), entry(1, 2));
        assert!(cache.remove(&mut budget, &key(256)));
        assert!(!cache.remove(&mut budget, &key(256)));
        assert_eq!(cache.lookup(&mut budget, &key(256)), None);
    }

    #[test]
    fn zero_budget_retains_no_templates() {
        let mut budget = Budget::new(0);
        let mut cache = TemplateCache::new();
        let outcome = cache.insert(&mut budget, key(256), entry(1, 2));
        assert!(outcome.dropped);
        assert_eq!(cache.lookup(&mut budget, &key(256)), None);
        assert_eq!(budget.used(), 0);
    }
}
