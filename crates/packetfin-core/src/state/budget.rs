//! Bounded least-recently-used storage for cross-packet state.
//!
//! Every table a decoder keeps between frames is meant to live in one
//! [`StateStore`] keyed by a state-kind enum, so the global limit and the
//! least-recently-used order are shared across conversation, fragment,
//! reassembly and template state. [`SessionState`] owns the budget ledger and
//! a store borrows it for each operation; keeping the ledger on the session
//! lets the session own the store without a second copy of the budget.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::mem::size_of;

use super::SessionState;
use crate::tree::{ExpertInfo, Group, Severity};

/// A value retained between frames.
///
/// The store accounts `size_of::<Self>()` plus whatever heap buffers the
/// value reports here, so [`state_bytes`](Self::state_bytes) must cover every
/// allocation the value owns and nothing it borrows.
pub trait StateValue {
    /// Bytes allocated outside the value's inline representation.
    fn state_bytes(&self) -> usize;
}

/// What one insertion did to the store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PutOutcome {
    /// Entries evicted to make room for the inserted value.
    pub evicted: usize,
    /// Whether the inserted value itself could not be retained.
    pub dropped: bool,
    /// Bytes the inserted value was charged, including bookkeeping overhead.
    ///
    /// Zero when the value was dropped or state is suspended.
    pub charged: usize,
}

/// Session-wide retention limit and least-recently-used clock.
///
/// One ledger belongs to each [`SessionState`] and every state table borrows
/// it for each operation, so no table can exceed the budget configured for
/// the invocation.
#[derive(Debug)]
pub(super) struct Budget {
    limit: usize,
    used: usize,
    clock: u64,
    suspended: bool,
    dropped: bool,
}

impl Budget {
    /// Create a budget with `limit` bytes of retained-state allowance.
    ///
    /// Zero disables retention: every insertion is dropped without an
    /// eviction or a loss expert, because dropping is the requested
    /// behaviour.
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            clock: 0,
            suspended: false,
            dropped: false,
        }
    }

    /// Whether analysis state is suspended while a quoted header decodes.
    pub(super) fn suspended(&self) -> bool {
        self.suspended
    }

    /// The configured retention limit in bytes.
    pub(super) fn limit(&self) -> usize {
        self.limit
    }

    /// Bytes currently retained by all state tables.
    pub(super) fn used(&self) -> usize {
        self.used
    }

    /// Whether a state value has been dropped since the last check.
    ///
    /// The decoder that completes a frame consumes this once and reports the
    /// loss as an expert item on that frame.
    pub(super) fn take_dropped(&mut self) -> bool {
        std::mem::take(&mut self.dropped)
    }

    /// Suspend or resume state retention, returning the previous setting.
    ///
    /// Quoted ICMP headers decode through the ordinary dispatch tables but
    /// suspend analysis and reassembly state: while suspended, a general
    /// state store neither returns nor retains entries. Conversation tables
    /// use their own accessors because quoted headers still consume stream
    /// numbers.
    pub(super) fn set_suspended(&mut self, suspended: bool) -> bool {
        std::mem::replace(&mut self.suspended, suspended)
    }

    fn next_stamp(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }
}

/// Bytes charged per entry beyond its inline value and keys.
///
/// The ledger must bound resident memory, not just inline values. Floods of
/// short conversations and of fragment buffers showed the raw `Entry` charge
/// under-counting RSS several-fold: the hash-map bucket array, tombstones
/// from insert/evict churn, the least-recently-used tree node and allocator
/// slack were free. The constant is the measured amortised cost of that
/// bookkeeping. At 640 bytes a UDP conversation is charged 768 bytes, a
/// 1,000,000-flow conversation flood stays below 300 MiB, and a 1,000,000-
/// datagram IPv4 fragment flood peaks at about 205 MiB.
const MAP_ENTRY_OVERHEAD: usize = 640;

/// The expert item reported when a state value cannot be retained.
pub(crate) fn state_dropped_expert() -> ExpertInfo {
    ExpertInfo {
        severity: Severity::Warning,
        group: Group::Sequence,
        message: "state budget exhausted; state dropped".to_string(),
    }
}

#[derive(Debug)]
struct Entry<V> {
    value: V,
    bytes: usize,
    /// Stamp in the session's least-recently-used index.
    stamp: u64,
}

/// A typed table of values retained under one session budget.
///
/// The key must be inline data (a copied address/port tuple, identifier or
/// address); heap buffers belong in the value and are reported by
/// [`StateValue`].
#[derive(Debug)]
pub struct StateStore<K, V> {
    entries: HashMap<K, Entry<V>>,
    /// Insertion or last-touch stamp to key. Stamps come from the session
    /// clock and are unique, so the first entry is always the least recently
    /// used one.
    lru: BTreeMap<u64, K>,
}

impl<K, V> Default for StateStore<K, V>
where
    K: Copy + Eq + Hash,
    V: StateValue,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> StateStore<K, V>
where
    K: Copy + Eq + Hash,
    V: StateValue,
{
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
        }
    }

    /// Read a retained value without touching its recency.
    #[cfg(test)]
    pub(super) fn peek(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    /// Number of retained entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Bytes this table retains, including the session's entry accounting.
    ///
    /// [`SessionState::used`] is the global total when the store holds every
    /// table.
    pub fn used(&self) -> usize {
        self.entries.values().map(|entry| entry.bytes).sum()
    }

    /// Whether no entry is retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes one entry with this key and value is charged.
    ///
    /// The inline footprint covers both the stored entry and the key copy in
    /// the least-recently-used index; variable-length key parts are not
    /// supported, so they do not need to be counted here.
    pub fn charge_for(value: &V) -> usize {
        size_of::<Entry<V>>()
            .saturating_add(value.state_bytes())
            .saturating_add(size_of::<K>().saturating_mul(2))
            .saturating_add(MAP_ENTRY_OVERHEAD)
    }

    /// Whether a value is retained for `key`.
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Read a retained value and mark it most recently used.
    ///
    /// Returns `None` while state is suspended, leaving the recency order
    /// untouched.
    pub(super) fn get_with(&mut self, budget: &mut Budget, key: &K) -> Option<&V> {
        if budget.suspended {
            return None;
        }
        let old_stamp = self.entries.get(key)?.stamp;
        self.lru.remove(&old_stamp);
        let stamp = self.next_stamp(budget);
        if let Some(entry) = self.entries.get_mut(key) {
            entry.stamp = stamp;
        }
        self.lru.insert(stamp, *key);
        self.entries.get(key).map(|entry| &entry.value)
    }

    /// Evict the least recently used entry, returning whether one was
    /// removed.
    pub(super) fn evict_oldest_with(&mut self, budget: &mut Budget) -> bool {
        if budget.suspended {
            return false;
        }
        let Some((&stamp, &key)) = self.lru.first_key_value() else {
            return false;
        };
        self.lru.remove(&stamp);
        let Some(entry) = self.entries.remove(&key) else {
            return false;
        };
        budget.used = budget.used.saturating_sub(entry.bytes);
        true
    }

    /// Remove and return the value for `key`.
    ///
    /// Returns `None` while state is suspended, leaving the table untouched.
    pub fn take(&mut self, state: &mut SessionState, key: &K) -> Option<V> {
        self.take_with(&mut state.budget, key)
    }

    /// Remove and return the value for `key` against a split-out ledger.
    ///
    /// The session's own tables use this form so the table and the ledger can
    /// be borrowed at the same time.
    pub(super) fn take_with(&mut self, budget: &mut Budget, key: &K) -> Option<V> {
        if budget.suspended {
            return None;
        }
        self.take_value(budget, key)
    }

    /// Remove a value even while quoted-header state is suspended.
    ///
    /// Conversation stream numbers classify traffic and are assigned inside
    /// quoted ICMP headers too, so only analysis and reassembly state is
    /// suspended for those copies.
    pub(super) fn take_for_conversation(&mut self, budget: &mut Budget, key: &K) -> Option<V> {
        self.take_value(budget, key)
    }

    fn take_value(&mut self, budget: &mut Budget, key: &K) -> Option<V> {
        let entry = self.entries.remove(key)?;
        self.lru.remove(&entry.stamp);
        budget.used = budget.used.saturating_sub(entry.bytes);
        Some(entry.value)
    }

    /// Visit every retained value and release the table.
    ///
    /// The end-of-pass bookkeeping needs to see each remaining value (for
    /// example to mark unanswered DNS queries) without paying for a second
    /// collection.
    pub(super) fn drain_with(&mut self, budget: &mut Budget, mut visit: impl FnMut(&K, &V)) {
        for (key, entry) in self.entries.drain() {
            budget.used = budget.used.saturating_sub(entry.bytes);
            visit(&key, &entry.value);
        }
        self.lru.clear();
    }

    /// Borrow a retained conversation and mark it most recently used.
    ///
    /// This is the common per-packet path: no value is inserted, so no
    /// eviction can happen and the value's charge is unchanged. Returning a
    /// borrow here avoids the remove-and-reinsert round trip that the
    /// general [`StateStore::put`] path needs for arbitrary values.
    pub(super) fn get_mut_for_conversation(
        &mut self,
        budget: &mut Budget,
        key: &K,
    ) -> Option<&mut V> {
        let entry = self.entries.get_mut(key)?;
        let old_stamp = entry.stamp;
        self.lru.remove(&old_stamp);
        let stamp = budget.next_stamp();
        entry.stamp = stamp;
        self.lru.insert(stamp, *key);
        Some(&mut entry.value)
    }

    /// Recompute an entry's charge after mutating its value in place.
    ///
    /// The conversation accessor borrows a value so the caller can update it
    /// without a remove/insert round trip; when the value's heap buffers can
    /// grow, this method brings the ledger back in line. A missing key is a
    /// no-op.
    pub(super) fn recharge_for_conversation(&mut self, budget: &mut Budget, key: &K) {
        let Some(entry) = self.entries.get_mut(key) else {
            return;
        };
        let old = entry.bytes;
        let new = Self::charge_for(&entry.value);
        entry.bytes = new;
        if new >= old {
            budget.used = budget.used.saturating_add(new - old);
        } else {
            budget.used = budget.used.saturating_sub(old - new);
        }
    }

    /// Evict least-recently-used entries until the ledger fits again.
    ///
    /// The entry just updated is protected only in the sense that it is now
    /// the most recently used one: if it alone exceeds the limit it is still
    /// removed and the loss flag is set, matching [`StateStore::put`].
    pub(super) fn shrink_to_fit(&mut self, budget: &mut Budget, key: &K) {
        while budget.used > budget.limit {
            let Some((&oldest_stamp, &oldest_key)) = self.lru.first_key_value() else {
                break;
            };
            let Some(removed) = self.entries.remove(&oldest_key) else {
                self.lru.remove(&oldest_stamp);
                continue;
            };
            self.lru.remove(&oldest_stamp);
            budget.used = budget.used.saturating_sub(removed.bytes);
            if oldest_key == *key {
                budget.dropped = true;
            }
        }
    }

    /// Mark an existing entry as the most recently used one.
    ///
    /// A missing key and a suspended session are both no-ops.
    pub fn touch(&mut self, state: &mut SessionState, key: &K) {
        self.touch_with(&mut state.budget, key);
    }

    pub(super) fn touch_with(&mut self, budget: &mut Budget, key: &K) {
        if budget.suspended {
            return;
        }
        let Some(old_stamp) = self.entries.get(key).map(|entry| entry.stamp) else {
            return;
        };
        self.lru.remove(&old_stamp);
        let stamp = self.next_stamp(budget);
        if let Some(entry) = self.entries.get_mut(key) {
            entry.stamp = stamp;
        }
        self.lru.insert(stamp, *key);
    }

    /// Insert or replace the value for `key`, evicting least-recently-used
    /// entries until it fits.
    ///
    /// The inserted entry is never chosen for eviction while another entry
    /// exists: only when it alone exceeds the budget is it dropped and
    /// [`SessionState::take_dropped`] becomes true.
    pub fn put(&mut self, state: &mut SessionState, key: K, value: V) -> PutOutcome {
        self.put_with(&mut state.budget, key, value)
    }

    pub(super) fn put_with(&mut self, budget: &mut Budget, key: K, value: V) -> PutOutcome {
        if budget.suspended {
            return PutOutcome::default();
        }
        self.put_value(budget, key, value)
    }

    /// Insert or replace a conversation even while quoted-header state is
    /// suspended; see [`StateStore::take_for_conversation`].
    pub(super) fn put_for_conversation(
        &mut self,
        budget: &mut Budget,
        key: K,
        value: V,
    ) -> PutOutcome {
        self.put_value(budget, key, value)
    }

    fn put_value(&mut self, budget: &mut Budget, key: K, value: V) -> PutOutcome {
        if let Some(old) = self.entries.remove(&key) {
            self.lru.remove(&old.stamp);
            budget.used = budget.used.saturating_sub(old.bytes);
        }
        let charged = Self::charge_for(&value);
        if budget.limit == 0 {
            // Retention was disabled by the operator, so dropping is the
            // configured behaviour rather than a loss worth reporting.
            return PutOutcome {
                evicted: 0,
                dropped: true,
                charged: 0,
            };
        }
        if charged > budget.limit {
            budget.dropped = true;
            return PutOutcome {
                evicted: 0,
                dropped: true,
                charged: 0,
            };
        }

        let stamp = self.next_stamp(budget);
        self.entries.insert(
            key,
            Entry {
                value,
                bytes: charged,
                stamp,
            },
        );
        self.lru.insert(stamp, key);
        budget.used = budget.used.saturating_add(charged);

        let mut evicted = 0;
        while budget.used > budget.limit {
            let Some((&oldest_stamp, &oldest_key)) = self.lru.first_key_value() else {
                break;
            };
            let Some(removed) = self.entries.remove(&oldest_key) else {
                self.lru.remove(&oldest_stamp);
                continue;
            };
            self.lru.remove(&oldest_stamp);
            budget.used = budget.used.saturating_sub(removed.bytes);
            if oldest_key == key {
                budget.dropped = true;
                return PutOutcome {
                    evicted,
                    dropped: true,
                    charged: 0,
                };
            }
            evicted += 1;
        }

        PutOutcome {
            evicted,
            dropped: false,
            charged,
        }
    }

    fn next_stamp(&mut self, budget: &mut Budget) -> u64 {
        if budget.clock == u64::MAX {
            // Rebuild this table's order from scratch rather than let two
            // entries share a stamp. A session decodes fewer frames than this
            // in practice, so the path exists only to keep the invariant
            // total.
            let ordered: Vec<K> = std::mem::take(&mut self.lru).into_values().collect();
            for (index, key) in ordered.into_iter().enumerate() {
                let stamp = u64::try_from(index).unwrap_or(u64::MAX) + 1;
                self.lru.insert(stamp, key);
                if let Some(entry) = self.entries.get_mut(&key) {
                    entry.stamp = stamp;
                }
            }
            budget.clock = self.lru.len() as u64;
        }
        budget.next_stamp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct TestKey(u8);

    struct TestValue(usize);

    impl StateValue for TestValue {
        fn state_bytes(&self) -> usize {
            self.0
        }
    }

    fn budget(limit: usize) -> SessionState {
        SessionState::new(limit)
    }

    fn one_entry() -> usize {
        StateStore::<TestKey, TestValue>::charge_for(&TestValue(0))
    }

    #[test]
    fn used_tracks_exact_charges_and_take_releases_them() {
        let mut state = budget(10_000);
        let mut store = StateStore::new();
        let first = store.put(&mut state, TestKey(1), TestValue(100));
        assert_eq!(first.charged, one_entry() + 100);
        assert_eq!(state.used(), first.charged);
        assert_eq!(store.used(), first.charged);
        let second = store.put(&mut state, TestKey(2), TestValue(200));
        assert_eq!(state.used(), first.charged + second.charged);
        assert_eq!(store.used(), state.used());
        assert_eq!(store.len(), 2);

        assert_eq!(
            store.take(&mut state, &TestKey(1)).map(|value| value.0),
            Some(100)
        );
        assert_eq!(state.used(), second.charged);
        assert_eq!(
            store.take(&mut state, &TestKey(2)).map(|value| value.0),
            Some(200)
        );
        assert_eq!(state.used(), 0);
    }

    #[test]
    fn replacing_a_key_releases_the_old_charge_and_stamp() {
        let mut state = budget(one_entry().saturating_mul(2).saturating_add(20));
        let mut store = StateStore::new();
        store.put(&mut state, TestKey(1), TestValue(10));
        let replacement = store.put(&mut state, TestKey(1), TestValue(20));
        assert_eq!(replacement.charged, one_entry() + 20);
        assert_eq!(state.used(), replacement.charged);
        assert_eq!(store.used(), replacement.charged);
        assert_eq!(store.len(), 1);

        let other = store.put(&mut state, TestKey(2), TestValue(0));
        assert_eq!(other.evicted, 0, "the replacement must leave one slot free");
        assert_eq!(state.used(), replacement.charged + other.charged);
    }

    #[test]
    fn touch_changes_eviction_order() {
        let charge = one_entry();
        let mut state = budget(charge * 2);
        let mut store = StateStore::new();
        store.put(&mut state, TestKey(1), TestValue(0));
        store.put(&mut state, TestKey(2), TestValue(0));
        store.touch(&mut state, &TestKey(1));

        let outcome = store.put(&mut state, TestKey(3), TestValue(0));
        assert_eq!(outcome.evicted, 1);
        assert!(!outcome.dropped);
        assert_eq!(state.used(), charge * 2);
        assert!(store.take(&mut state, &TestKey(1)).is_some());
        assert!(store.take(&mut state, &TestKey(2)).is_none());
        assert!(store.take(&mut state, &TestKey(3)).is_some());
    }

    #[test]
    fn eviction_keeps_the_inserted_entry() {
        let charge = one_entry();
        let mut state = budget(charge);
        let mut store = StateStore::new();
        store.put(&mut state, TestKey(1), TestValue(0));
        let outcome = store.put(&mut state, TestKey(2), TestValue(0));
        assert_eq!(outcome.evicted, 1);
        assert!(!outcome.dropped);
        assert_eq!(outcome.charged, charge);
        assert_eq!(state.used(), charge);
        assert!(store.take(&mut state, &TestKey(1)).is_none());
        assert!(store.take(&mut state, &TestKey(2)).is_some());
    }

    #[test]
    fn a_value_larger_than_the_budget_is_dropped() {
        let mut state = budget(one_entry() + 50);
        let mut store = StateStore::new();
        let outcome = store.put(&mut state, TestKey(1), TestValue(51));
        assert!(outcome.dropped);
        assert_eq!(outcome.evicted, 0);
        assert_eq!(outcome.charged, 0);
        assert_eq!(state.used(), 0);
        assert!(store.is_empty());
        assert!(state.take_dropped());
        let expert = state_dropped_expert();
        assert_eq!(expert.severity, Severity::Warning);
        assert_eq!(expert.group, Group::Sequence);
        assert!(!expert.message.is_empty());
    }

    #[test]
    fn zero_budget_retains_nothing() {
        let mut state = budget(0);
        let mut store = StateStore::new();
        let outcome = store.put(&mut state, TestKey(1), TestValue(0));
        assert!(outcome.dropped);
        assert_eq!(state.used(), 0);
        assert!(store.is_empty());
        assert!(
            !state.take_dropped(),
            "disabled retention is not a state loss"
        );
    }

    #[test]
    fn suspended_state_neither_reads_nor_writes() {
        let mut state = budget(10_000);
        let mut store = StateStore::new();
        store.put(&mut state, TestKey(1), TestValue(10));

        assert!(!state.set_suspended(true));
        assert!(store.take(&mut state, &TestKey(1)).is_none());
        let outcome = store.put(&mut state, TestKey(2), TestValue(10));
        assert_eq!(outcome, PutOutcome::default());
        store.touch(&mut state, &TestKey(1));
        assert_eq!(store.len(), 1);
        assert_eq!(state.used(), one_entry() + 10);

        assert!(state.set_suspended(false));
        assert!(store.take(&mut state, &TestKey(1)).is_some());
        assert_eq!(state.used(), 0);
    }
}
