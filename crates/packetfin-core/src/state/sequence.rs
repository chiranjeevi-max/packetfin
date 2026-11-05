//! NetFlow v9 and IPFIX flow-sequence expectations.
//!
//! One expectation is kept per exporter stream. The stored value is the
//! previous datagram's sequence number (not its successor), the frame number
//! records where that value was established, and only a datagram that carried
//! a decoded data set is checked. Template sets update the expectation without
//! reporting a mismatch. See RFC 3954 section 5.1 and RFC 7011 section 3.1
//! for the header sequence field.

use super::budget::{Budget, PutOutcome, StateStore, StateValue};
use super::template::ExporterAddress;

/// Key for one exporter's sequence stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SequenceKey {
    /// Exporter address.
    pub exporter: ExporterAddress,
    /// Exporter source port.
    pub port: u16,
    /// Transport protocol number (17 for UDP).
    pub transport: u8,
    /// Observation domain ID, or the v9 source ID.
    pub domain: u32,
}

/// Last sequence number and frame retained for an exporter stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SequenceState {
    /// Sequence number of the previous datagram for this stream.
    pub expected: u32,
    /// Frame that established `expected`.
    pub previous_frame: u64,
}

impl StateValue for SequenceState {
    fn state_bytes(&self) -> usize {
        0
    }
}

/// The session's sequence-expectation table.
#[derive(Debug)]
pub(crate) struct SequenceCache {
    store: StateStore<SequenceKey, SequenceState>,
}

impl SequenceCache {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            store: StateStore::new(),
        }
    }

    /// Return the stored expectation and mark it most recently used.
    pub fn lookup(&mut self, budget: &mut Budget, key: &SequenceKey) -> Option<SequenceState> {
        self.store.get_with(budget, key).copied()
    }

    /// Record the latest sequence number for a stream.
    pub fn insert(
        &mut self,
        budget: &mut Budget,
        key: SequenceKey,
        state: SequenceState,
    ) -> PutOutcome {
        self.store.put_with(budget, key, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(domain: u32) -> SequenceKey {
        SequenceKey {
            exporter: ExporterAddress::V4([192, 0, 2, 1]),
            port: 2055,
            transport: 17,
            domain,
        }
    }

    #[test]
    fn expectations_are_per_domain_and_stream() {
        let mut budget = Budget::new(1 << 20);
        let mut cache = SequenceCache::new();
        cache.insert(
            &mut budget,
            key(7),
            SequenceState {
                expected: 1,
                previous_frame: 1,
            },
        );
        assert_eq!(
            cache.lookup(&mut budget, &key(7)),
            Some(SequenceState {
                expected: 1,
                previous_frame: 1
            })
        );
        assert_eq!(cache.lookup(&mut budget, &key(8)), None);
        let mut other = key(7);
        other.port = 40001;
        assert_eq!(cache.lookup(&mut budget, &other), None);
    }

    #[test]
    fn an_update_replaces_the_expectation() {
        let mut budget = Budget::new(1 << 20);
        let mut cache = SequenceCache::new();
        cache.insert(
            &mut budget,
            key(7),
            SequenceState {
                expected: 1,
                previous_frame: 1,
            },
        );
        cache.insert(
            &mut budget,
            key(7),
            SequenceState {
                expected: 2,
                previous_frame: 2,
            },
        );
        assert_eq!(
            cache.lookup(&mut budget, &key(7)),
            Some(SequenceState {
                expected: 2,
                previous_frame: 2
            })
        );
    }
}
