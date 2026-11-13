//! IPv4 and IPv6 fragment reassembly.
//!
//! A datagram's fragments are buffered per key until the datagram is
//! complete. IPv4 keys on the source, destination, protocol and
//! identification (RFC 791 section 3.2); IPv6 keys on the source, destination
//! and identification (RFC 8200 section 4.5). Fragments arrive in any order:
//! each part keeps the captured bytes, its offset and the frame it came from,
//! and the first-arrived bytes win where parts overlap.
//!
//! The buffer completes only when a part at offset zero and a last fragment
//! are present and the captured bytes cover every byte of `[0, total_len)`.
//! A gap keeps the datagram buffered and decodes nothing. A fragment whose
//! declared end passes the total is flagged too long; a second last fragment
//! sets the multiple-tails flag. Overlap with different bytes and either of
//! those illegal conditions make the part a defragmentation error.
//!
//! Every retained byte is charged to the session store. A datagram stops at
//! [`MAX_FRAGMENTS`] parts or the family's maximum assembled size, and a
//! fragment that declares more than the maximum is discarded.

use std::mem::size_of;

use super::StateValue;
use crate::capture::Timestamp;
use crate::tree::{ExpertInfo, Group, Severity};

/// How long an incomplete datagram waits for its remaining fragments.
///
/// RFC 1122 section 3.3.2 requires a reassembly timeout and recommends a
/// fixed value between 60 and 120 seconds; this implementation uses the
/// recommended lower bound.  A capture can hold two datagrams that reuse a
/// 16-bit identification minutes apart, so a buffer must not outlive the
/// timeout and merge the later datagram into the stale one.
const REASSEMBLY_TIMEOUT_SECONDS: i64 = 60;

/// Most fragments retained for one datagram.
pub(crate) const MAX_FRAGMENTS: usize = 128;

/// Largest IPv4 datagram, from the 16-bit Total Length field (RFC 791).
pub(crate) const MAX_IPV4_DATAGRAM: usize = 65_535;

/// Largest IPv6 payload Packetfin assembles.
///
/// RFC 8200 jumbograms can declare more; the cap keeps reassembly state
/// bounded.
pub(crate) const MAX_ASSEMBLED: usize = 1024 * 1024;

/// One shared fragment-table key covering both address families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FragmentKey {
    /// An IPv4 datagram.
    Ipv4(Frag4Key),
    /// An IPv6 datagram.
    Ipv6(Frag6Key),
}

/// IPv4 reassembly key (RFC 791 section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Frag4Key {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub protocol: u8,
    pub identification: u16,
}

/// IPv6 reassembly key (RFC 8200 section 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Frag6Key {
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub identification: u32,
}

/// One fragment offered to a datagram buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FragmentPart<'a> {
    /// Byte offset from the first byte of the fragmentable payload.
    pub offset: usize,
    /// Captured bytes of this fragment.
    pub data: &'a [u8],
    /// Payload bytes the IP header declares for this fragment.
    ///
    /// A capture cut inside the fragment leaves this larger than `data`.
    pub declared_len: usize,
    /// One-based display frame number the fragment came from.
    pub frame: u64,
    /// One-based capture frame number the fragment came from.
    pub file: u64,
    /// Whether the More Fragments flag is set.
    pub more: bool,
    /// Capture time of the frame that carried this fragment.
    ///
    /// The first stored fragment's time starts the reassembly timeout; a
    /// fragment without a timestamp cannot be timed.
    pub timestamp: Option<Timestamp>,
}

/// Illegal conditions measured on one fragment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FragmentFlags {
    /// The fragment intersects bytes another fragment already supplied.
    pub overlap: bool,
    /// The intersecting bytes differ from the first-arrived bytes.
    pub conflict: bool,
    /// A last fragment arrived before this one.
    pub multipletails: bool,
    /// The declared end passes the datagram's total length.
    pub toolongfragment: bool,
}

impl FragmentFlags {
    /// Whether the fragment counts as a defragmentation error.
    ///
    /// A plain overlap with identical bytes is legal; conflicting bytes,
    /// several tails and data past the datagram end are not.
    fn is_error(self) -> bool {
        self.conflict || self.multipletails || self.toolongfragment
    }
}

/// One buffered fragment, kept for the reassembled field tree.
#[derive(Clone, Debug)]
pub(crate) struct FragmentRecord {
    /// Byte offset in the reassembled payload.
    pub offset: usize,
    /// Captured bytes, in the same order as the frame.
    pub data: Vec<u8>,
    /// Declared end offset, possibly past the eventual datagram total.
    pub declared_end: usize,
    /// One-based display frame number.
    pub frame: u64,
    /// One-based capture frame number.
    pub file: u64,
    /// Illegal conditions measured when the fragment arrived.
    pub flags: FragmentFlags,
}

impl FragmentRecord {
    /// Whether this fragment is reported as `*.fragment.error`.
    pub fn is_error(&self) -> bool {
        self.flags.is_error()
    }
}

/// A datagram whose bytes cover the whole reassembled payload.
#[derive(Clone, Debug)]
pub(crate) struct Reassembly {
    /// Contiguous reassembled payload; first-arrived bytes win.
    pub data: Vec<u8>,
    /// Declared payload length of the datagram.
    pub total_len: usize,
    /// Every accepted fragment, ordered by offset.
    pub parts: Vec<FragmentRecord>,
}

/// Result of offering one fragment to a datagram buffer.
#[derive(Debug)]
pub(crate) enum FragmentOutcome {
    /// The fragment was stored and the datagram is still incomplete.
    Buffered,
    /// The fragment is illegal on its own and was not stored.
    Malformed,
    /// The capture is shorter than the declared fragment payload, so the
    /// fragment cannot supply the bytes its header promises.
    Truncated,
    /// The fragment declares bytes past the family's maximum and was not
    /// stored.
    TooLong,
    /// The datagram reached [`MAX_FRAGMENTS`]; the buffer was released.
    LimitExceeded,
    /// The store could not retain the buffer under the session budget.
    NotRetained,
    /// The fragment completed the datagram.
    Complete(Reassembly),
}

impl FragmentOutcome {
    /// Whether the caller must put the buffer back into the store.
    pub fn keep_buffer(&self) -> bool {
        matches!(
            self,
            Self::Buffered | Self::Malformed | Self::Truncated | Self::TooLong
        )
    }

    /// The warning Packetfin reports when its own fragment bound is hit.
    pub fn own_limit_expert(&self) -> Option<ExpertInfo> {
        matches!(self, Self::LimitExceeded).then(|| ExpertInfo {
            severity: Severity::Warning,
            group: Group::Sequence,
            message: "fragment reassembly limit reached; fragments dropped".to_string(),
        })
    }
}

/// Buffered parts of one incomplete datagram.
#[derive(Debug, Default)]
pub(crate) struct FragmentBuffer {
    parts: Vec<FragmentRecord>,
    total_len: Option<usize>,
    /// Capture time of the first stored fragment, in whole seconds.
    ///
    /// The timeout has minute resolution, so storing the seconds keeps the
    /// per-buffer cost at one machine word while still measuring it.
    first_seen: Option<i64>,
}

impl FragmentBuffer {
    /// Add one fragment, reassembling when it completes the datagram.
    ///
    /// A fragment that is illegal by itself is rejected without changing the
    /// buffer. `max_len` is the family's maximum assembled size; a fragment
    /// whose declared end passes it is discarded.
    pub fn insert(&mut self, part: FragmentPart<'_>, max_len: usize) -> FragmentOutcome {
        self.expire(part.timestamp);
        let declared_len = part.declared_len.max(part.data.len());
        // RFC 791 section 3.1 and RFC 8200 section 4.5 constrain the declared
        // fragment payload, not the captured prefix.
        if part.more && !declared_len.is_multiple_of(8) {
            return FragmentOutcome::Malformed;
        }
        if declared_len > part.data.len() {
            // A datagram whose fragment promises more bytes than the capture
            // holds cannot complete; never fill the gap with zeros.
            return FragmentOutcome::Truncated;
        }
        if self.parts.len() >= MAX_FRAGMENTS {
            return FragmentOutcome::LimitExceeded;
        }

        let Some(end) = part.offset.checked_add(declared_len) else {
            return FragmentOutcome::TooLong;
        };
        if end > max_len || part.offset > max_len {
            return FragmentOutcome::TooLong;
        }

        let mut flags = FragmentFlags::default();
        for existing in &self.parts {
            let start = part.offset.max(existing.offset);
            let overlap_end =
                (part.offset + part.data.len()).min(existing.offset + existing.data.len());
            if start >= overlap_end {
                continue;
            }
            flags.overlap = true;
            let captured = part
                .data
                .get(start - part.offset..overlap_end - part.offset);
            let known = existing
                .data
                .get(start - existing.offset..overlap_end - existing.offset);
            if let (Some(captured), Some(known)) = (captured, known)
                && captured != known
            {
                flags.conflict = true;
            }
        }

        let total = self.total_len;
        let duplicate_tail = !part.more
            && total
                .is_some_and(|total| self.fully_covered_identical(part.offset, part.data, total));
        let record_len = if duplicate_tail {
            total
                .map(|total| {
                    (part.offset.saturating_add(part.data.len()))
                        .min(total)
                        .saturating_sub(part.offset)
                })
                .unwrap_or(part.data.len())
        } else {
            if !part.more && total.is_some() {
                flags.multipletails = true;
            }
            if total.is_some_and(|total| end > total) {
                flags.toolongfragment = true;
            }
            part.data.len()
        };

        if self.first_seen.is_none() {
            self.first_seen = part.timestamp.map(|timestamp| timestamp.seconds);
        }
        self.parts.push(FragmentRecord {
            offset: part.offset,
            data: part.data.get(..record_len).unwrap_or(part.data).to_vec(),
            declared_end: if duplicate_tail {
                total.map_or(end, |total| end.min(total))
            } else {
                end
            },
            frame: part.frame,
            file: part.file,
            flags,
        });
        if !part.more && total.is_none() {
            self.total_len = Some(end);
            // Fragments stored before the first tail can reach past the
            // datagram end; mark them now that the total is known.
            for record in &mut self.parts {
                if record.declared_end > end {
                    record.flags.toolongfragment = true;
                }
            }
        }

        let Some(total) = self.total_len else {
            return FragmentOutcome::Buffered;
        };
        if !self.covers(total) {
            return FragmentOutcome::Buffered;
        }
        FragmentOutcome::Complete(self.assemble(total))
    }

    /// Whether a last fragment's range clipped to the datagram total is
    /// already present with identical bytes.
    fn fully_covered_identical(&self, offset: usize, data: &[u8], total: usize) -> bool {
        let start = offset.min(total);
        let end = offset.saturating_add(data.len()).min(total);
        if start >= end {
            return false;
        }
        (start..end).all(|index| {
            let byte = data.get(index - offset);
            byte.is_some_and(|byte| {
                self.parts.iter().any(|part| {
                    if index < part.offset {
                        return false;
                    }
                    part.data
                        .get(index - part.offset)
                        .is_some_and(|known| known == byte)
                })
            })
        })
    }

    /// Drop the buffer when the arriving fragment outlives the timeout.
    ///
    /// RFC 1122 section 3.3.2: a partially reassembled datagram is discarded
    /// when its reassembly timeout expires.  Clearing the parts and the
    /// baseline makes the arriving fragment start a new datagram, so a reused
    /// identification cannot complete with the stale datagram's bytes.
    fn expire(&mut self, now: Option<Timestamp>) {
        let (Some(first), Some(now)) = (self.first_seen, now) else {
            return;
        };
        if now.seconds.saturating_sub(first) > REASSEMBLY_TIMEOUT_SECONDS {
            self.parts.clear();
            self.total_len = None;
            self.first_seen = None;
        }
    }

    /// Whether no fragment is retained.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Whether captured bytes cover every offset in `[0, total)`.
    ///
    /// Declared lengths larger than the captured bytes leave a gap: bytes are
    /// never invented for a capture cut inside a fragment.
    fn covers(&self, total: usize) -> bool {
        let mut intervals: Vec<(usize, usize)> = self
            .parts
            .iter()
            .filter_map(|part| {
                let start = part.offset.min(total);
                let end = (part.offset + part.data.len()).min(total);
                (start < end).then_some((start, end))
            })
            .collect();
        intervals.sort_unstable();
        let mut covered = 0_usize;
        for (start, end) in intervals {
            if start > covered {
                return false;
            }
            covered = covered.max(end);
            if covered == total {
                return true;
            }
        }
        covered == total
    }

    /// Build the contiguous payload in arrival order, first-arrived bytes
    /// winning where fragments overlap.
    fn assemble(&mut self, total: usize) -> Reassembly {
        let mut data = vec![0_u8; total];
        let mut written = vec![0_u64; total.div_ceil(64)];
        for part in &self.parts {
            let start = part.offset.min(total);
            let end = (part.offset + part.data.len()).min(total);
            for index in start..end {
                let word = index / 64;
                let bit = 1_u64 << (index % 64);
                if written.get(word).is_some_and(|value| value & bit != 0) {
                    continue;
                }
                if let (Some(slot), Some(byte)) =
                    (data.get_mut(index), part.data.get(index - part.offset))
                {
                    *slot = *byte;
                    if let Some(word) = written.get_mut(word) {
                        *word |= bit;
                    }
                }
            }
        }
        let mut parts = std::mem::take(&mut self.parts);
        parts.sort_by_key(|part| part.offset);
        self.total_len = None;
        self.first_seen = None;
        Reassembly {
            data,
            total_len: total,
            parts,
        }
    }
}

impl StateValue for FragmentBuffer {
    fn state_bytes(&self) -> usize {
        // Only out-of-line bytes: the parts vector and the fragment data.
        // The first-seen timestamp is an inline field of the buffer, so
        // `StateStore::charge_for`'s `size_of::<Entry<FragmentBuffer>>()`
        // already charges it.
        self.parts
            .capacity()
            .saturating_mul(size_of::<FragmentRecord>())
            .saturating_add(
                self.parts
                    .iter()
                    .map(|part| part.data.capacity())
                    .sum::<usize>(),
            )
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "the tests index fixed fragment offsets they just decoded"
)]
mod tests {
    use super::*;

    fn part<'a>(
        offset: usize,
        data: &'a [u8],
        declared_len: usize,
        frame: u64,
        more: bool,
    ) -> FragmentPart<'a> {
        FragmentPart {
            offset,
            data,
            declared_len,
            frame,
            file: frame,
            more,
            timestamp: None,
        }
    }

    fn timed<'a>(
        offset: usize,
        data: &'a [u8],
        declared_len: usize,
        frame: u64,
        more: bool,
        seconds: i64,
    ) -> FragmentPart<'a> {
        FragmentPart {
            timestamp: Some(Timestamp { seconds, nanos: 0 }),
            ..part(offset, data, declared_len, frame, more)
        }
    }

    #[expect(
        clippy::panic,
        reason = "a different outcome means the reassembly test failed"
    )]
    fn complete(outcome: FragmentOutcome) -> Reassembly {
        match outcome {
            FragmentOutcome::Complete(reassembly) => reassembly,
            other => panic!("expected completion, got {other:?}"),
        }
    }

    #[test]
    fn ordered_fragments_reassemble_on_the_last_one() {
        let first = [1_u8; 80];
        let last = [2_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(!buffer.is_empty());
        let reassembled = complete(buffer.insert(part(80, &last, 20, 2, false), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.total_len, 100);
        assert_eq!(reassembled.data.len(), 100);
        assert_eq!(&reassembled.data[..80], &first);
        assert_eq!(&reassembled.data[80..], &last);
        assert_eq!(reassembled.parts.len(), 2);
        assert_eq!(reassembled.parts[0].frame, 1);
        assert_eq!(reassembled.parts[1].frame, 2);
    }

    #[test]
    fn fragments_inside_the_reassembly_timeout_reassemble() {
        let first = [5_u8; 80];
        let last = [6_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(timed(0, &first, 80, 1, true, 1_000), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        // Exactly the timeout still reassembles; only a later fragment is
        // stale.
        let reassembled =
            complete(buffer.insert(timed(80, &last, 20, 2, false, 1_060), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.total_len, 100);
        assert_eq!(&reassembled.data[80..], &last);
    }

    #[test]
    fn fragments_past_the_reassembly_timeout_do_not_reassemble() {
        let first = [7_u8; 80];
        let last = [8_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(timed(0, &first, 80, 1, true, 1_000), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(timed(80, &last, 20, 2, false, 1_061), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert_eq!(buffer.parts.len(), 1);
        assert_eq!(buffer.parts[0].offset, 80);
    }

    #[test]
    fn a_reused_identification_after_the_timeout_starts_a_new_datagram() {
        let stale = [9_u8; 80];
        let fresh = [10_u8; 80];
        let fresh_tail = [11_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(timed(0, &stale, 80, 1, true, 1_000), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        // The second datagram reuses the identification; the stale first
        // fragment must not supply the leading bytes.
        assert!(matches!(
            buffer.insert(timed(0, &fresh, 80, 2, true, 1_061), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(
            timed(80, &fresh_tail, 20, 3, false, 1_062),
            MAX_IPV4_DATAGRAM,
        ));
        assert_eq!(&reassembled.data[..80], &fresh);
        assert_eq!(&reassembled.data[80..], &fresh_tail);
        assert_eq!(reassembled.parts[0].frame, 2);
        assert_eq!(reassembled.parts.len(), 2);
    }

    #[test]
    fn out_of_order_fragments_complete_and_sort_by_offset() {
        let first = [3_u8; 80];
        let last = [4_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(80, &last, 20, 1, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(part(0, &first, 80, 2, true), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.parts[0].frame, 2);
        assert_eq!(reassembled.parts[1].frame, 1);
        assert_eq!(&reassembled.data[..80], &first);
        assert_eq!(&reassembled.data[80..], &last);
    }

    #[test]
    fn a_gap_keeps_buffering_and_a_fill_completes() {
        let first = [5_u8; 80];
        let fill = [6_u8; 16];
        let last = [7_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(96, &last, 20, 2, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(part(80, &fill, 16, 3, true), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.total_len, 116);
        assert_eq!(&reassembled.data[80..96], &fill);
        assert_eq!(&reassembled.data[96..], &last);
        assert_eq!(
            reassembled
                .parts
                .iter()
                .map(|part| part.frame)
                .collect::<Vec<_>>(),
            vec![1, 3, 2]
        );
    }

    #[test]
    fn first_arrived_bytes_win_and_conflicts_are_flagged() {
        let first = [0x11_u8; 80];
        let second = [0x22_u8; 92];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled =
            complete(buffer.insert(part(72, &second, 92, 2, false), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.total_len, 164);
        assert_eq!(&reassembled.data[..80], &first);
        assert_eq!(&reassembled.data[80..], &second[8..]);
        assert!(reassembled.parts[1].flags.overlap);
        assert!(reassembled.parts[1].flags.conflict);
        assert!(reassembled.parts[1].is_error());
    }

    #[test]
    fn identical_overlap_is_not_a_defragmentation_error() {
        let first = [0x33_u8; 80];
        let second = [0x33_u8; 92];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled =
            complete(buffer.insert(part(72, &second, 92, 2, false), MAX_IPV4_DATAGRAM));
        assert!(reassembled.parts[1].flags.overlap);
        assert!(!reassembled.parts[1].flags.conflict);
        assert!(!reassembled.parts[1].is_error());
    }

    #[test]
    fn a_duplicate_first_fragment_is_an_error_but_keeps_the_original_bytes() {
        let first = [0x41_u8; 80];
        let duplicate = [0x42_u8; 40];
        let last = [0x43_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(0, &duplicate, 40, 2, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(part(80, &last, 20, 3, false), MAX_IPV4_DATAGRAM));
        assert_eq!(&reassembled.data[..80], &first);
        assert!(reassembled.parts[1].is_error());
        assert_eq!(
            reassembled
                .parts
                .iter()
                .filter(|part| !part.is_error())
                .map(|part| part.frame)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
    }

    #[test]
    fn a_second_tail_sets_multiple_tails_and_too_long() {
        let first = [0x51_u8; 80];
        let tail = [0x52_u8; 20];
        let second_tail = [0x53_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(80, &tail, 20, 1, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(96, &second_tail, 20, 2, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(part(0, &first, 80, 3, true), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.total_len, 100);
        assert!(reassembled.parts[2].flags.multipletails);
        assert!(reassembled.parts[2].flags.toolongfragment);
        assert!(reassembled.parts[2].is_error());
    }

    #[test]
    fn a_capture_cut_inside_a_fragment_is_not_buffered() {
        let first = [0x61_u8; 80];
        let tail = [0x62_u8; 10];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(80, &tail, 20, 2, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Truncated
        ));
    }

    #[test]
    fn a_capture_cut_with_a_captured_multiple_of_eight_is_still_truncated() {
        let first = [0x63_u8; 72];
        let tail = [0x64_u8; 28];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Truncated
        ));
        assert!(matches!(
            buffer.insert(part(72, &tail, 28, 2, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        // The rejected first fragment cannot complete the datagram.
        assert!(!buffer.is_empty());
    }

    #[test]
    fn a_declared_non_multiple_of_eight_is_rejected() {
        let short = [0x65_u8; 72];
        let full = [0x66_u8; 79];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &short, 79, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Malformed
        ));
        assert!(matches!(
            buffer.insert(part(0, &full, 79, 2, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Malformed
        ));
    }

    #[test]
    fn a_fragment_stored_before_the_tail_is_marked_too_long() {
        let early = [0x67_u8; 56];
        let first = [0x68_u8; 80];
        let tail = [0x67_u8; 20];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(80, &early, 56, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(0, &first, 80, 2, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(part(96, &tail, 20, 3, false), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.total_len, 116);
        assert!(reassembled.parts[1].flags.toolongfragment);
        assert!(reassembled.parts[1].is_error());
        assert_eq!(
            reassembled
                .parts
                .iter()
                .filter(|part| !part.is_error())
                .map(|part| part.frame)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn an_identical_duplicate_tail_is_not_multiple_tails() {
        let tail = [0x6a_u8; 20];
        let first = [0x6b_u8; 80];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(80, &tail, 20, 1, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(80, &tail, 20, 2, false), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        let reassembled = complete(buffer.insert(part(0, &first, 80, 3, true), MAX_IPV4_DATAGRAM));
        assert_eq!(reassembled.parts.len(), 3);
        assert!(reassembled.parts[2].flags.overlap);
        assert!(!reassembled.parts[2].flags.multipletails);
        assert!(!reassembled.parts[2].is_error());
        assert_eq!(
            reassembled
                .parts
                .iter()
                .map(|part| part.frame)
                .collect::<Vec<_>>(),
            vec![3, 1, 2]
        );
    }

    #[test]
    fn a_non_final_fragment_must_carry_a_multiple_of_eight_octets() {
        let data = [0x71_u8; 79];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(part(0, &data, 79, 1, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Malformed
        ));
        assert!(buffer.is_empty());
    }

    #[test]
    fn fragments_past_the_family_maximum_are_discarded() {
        let data = [0x81_u8; 16];
        let mut buffer = FragmentBuffer::default();
        assert!(matches!(
            buffer.insert(
                part(MAX_IPV4_DATAGRAM - 8, &data, 16, 1, false),
                MAX_IPV4_DATAGRAM
            ),
            FragmentOutcome::TooLong
        ));
        assert!(buffer.is_empty());
        assert!(matches!(
            buffer.insert(part(0, &data, 16, 2, true), MAX_IPV4_DATAGRAM),
            FragmentOutcome::Buffered
        ));
        assert!(matches!(
            buffer.insert(part(MAX_ASSEMBLED - 8, &data, 16, 3, false), MAX_ASSEMBLED),
            FragmentOutcome::TooLong
        ));
    }

    #[test]
    fn the_fragment_count_is_bounded() {
        let data = [0x91_u8; 8];
        let mut buffer = FragmentBuffer::default();
        for index in 0..MAX_FRAGMENTS {
            let offset = index * 8;
            assert!(matches!(
                buffer.insert(
                    part(offset, &data, 8, index as u64 + 1, true),
                    MAX_ASSEMBLED
                ),
                FragmentOutcome::Buffered
            ));
        }
        assert!(matches!(
            buffer.insert(part(MAX_FRAGMENTS * 8, &data, 8, 129, true), MAX_ASSEMBLED),
            FragmentOutcome::LimitExceeded
        ));
    }

    #[test]
    fn a_million_datagrams_never_exceed_the_budget() {
        use crate::state::SessionState;

        let mut state = SessionState::new(64 * 1024);
        let data = [0x5a_u8; 8];
        for identifier in 0..1_000_000_u32 {
            let key = Frag4Key {
                source: [10, 0, 0, 1],
                destination: [10, 0, 0, 2],
                protocol: 17,
                identification: u16::try_from(identifier & 0xffff).unwrap_or(0),
            };
            let _ = state.insert_fragment4(
                key,
                FragmentPart {
                    offset: 0,
                    data: &data,
                    declared_len: data.len(),
                    frame: u64::from(identifier) + 1,
                    file: u64::from(identifier) + 1,
                    more: true,
                    timestamp: None,
                },
            );
            assert!(state.used() <= 64 * 1024);
        }
    }

    #[test]
    fn the_ipv6_assembled_size_is_bounded() {
        let mut buffer = FragmentBuffer::default();
        let tail = [0_u8; 8];
        assert!(matches!(
            buffer.insert(part(MAX_ASSEMBLED - 8, &tail, 8, 1, false), MAX_ASSEMBLED),
            FragmentOutcome::Buffered
        ));
        let first = vec![0x77_u8; MAX_ASSEMBLED - 8];
        let reassembled =
            complete(buffer.insert(part(0, &first, MAX_ASSEMBLED - 8, 2, true), MAX_ASSEMBLED));
        assert_eq!(reassembled.total_len, MAX_ASSEMBLED);
        assert_eq!(reassembled.data.len(), MAX_ASSEMBLED);
        assert_eq!(&reassembled.data[..MAX_ASSEMBLED - 8], &first);
    }

    #[test]
    fn retained_bytes_cover_the_part_data() {
        let data = [0xa1_u8; 8];
        let mut buffer = FragmentBuffer::default();
        assert_eq!(buffer.state_bytes(), 0);
        let _ = buffer.insert(part(0, &data, 8, 1, true), MAX_ASSEMBLED);
        assert!(buffer.state_bytes() >= 8);
    }
}
