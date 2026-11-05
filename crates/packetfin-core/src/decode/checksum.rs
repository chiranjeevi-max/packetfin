//! RFC 1071 Internet checksums for the transport pseudo-headers.
//!
//! UDP and TCP checksums cover a pseudo-header made of the network-layer
//! addresses, the protocol number and the transport length, followed by the
//! transport segment. The accumulator adds byte slices in order, so a
//! pseudo-header and a header with the checksum field zeroed can be summed
//! without building a contiguous copy.

use crate::fields::FieldDef;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

/// The fields that carry one checksum's status and calculated value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChecksumFields {
    /// The field that carries the stored checksum's status.
    pub status: &'static FieldDef,
    /// The field that carries the checksum the message should have, when the
    /// protocol reports one.
    pub calculated: Option<&'static FieldDef>,
}

/// How a checksum value of zero is reported.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ZeroChecksum {
    /// Zero is validated like any other value.
    Validate,
    /// Zero means the sender did not compute a checksum (IPv4 UDP).
    NotPresent,
    /// Zero is illegal (IPv6 UDP).
    Illegal,
}

/// Add a checksum's status and calculated fields and a bad-checksum expert.
///
/// `calculated` is `None` when validation is disabled or the message is not
/// fully captured; the status is then unverified. `accept_zero_ffff` covers
/// the rule that a computed `0x0000` matches a stored `0xffff`.
#[expect(
    clippy::too_many_arguments,
    reason = "the checksum fields, verdict and reporting policy are one call"
)]
pub(crate) fn report(
    node: &mut Node,
    fields: ChecksumFields,
    status_range: Range,
    stored: u16,
    calculated: Option<u16>,
    zero: ZeroChecksum,
    severity: Severity,
    accept_zero_ffff: bool,
) {
    if stored == 0 {
        let status = match zero {
            ZeroChecksum::Validate => None,
            ZeroChecksum::NotPresent => Some(STATUS_NOT_PRESENT),
            ZeroChecksum::Illegal => {
                node.add_expert(ExpertInfo {
                    severity: Severity::Error,
                    group: Group::Checksum,
                    message: "Illegal checksum value (0)".to_string(),
                });
                Some(STATUS_ILLEGAL)
            }
        };
        if let Some(status) = status {
            node.add_field(fields.status, status_range, Value::Uint8(status));
            return;
        }
    }
    let Some(calculated) = calculated else {
        node.add_field(fields.status, status_range, Value::Uint8(STATUS_UNVERIFIED));
        return;
    };
    let good = calculated == stored || (accept_zero_ffff && calculated == 0 && stored == 0xffff);
    node.add_field(
        fields.status,
        status_range,
        Value::Uint8(if good { STATUS_GOOD } else { STATUS_BAD }),
    );
    if let Some(calculated_field) = fields.calculated {
        node.add_field(calculated_field, status_range, Value::Uint16(calculated));
    }
    if !good {
        node.add_expert(ExpertInfo {
            severity,
            group: Group::Checksum,
            message: format!("Bad checksum [should be 0x{calculated:04x}]"),
        });
    }
}

/// Checksum status value: the checksum is wrong.
pub(crate) const STATUS_BAD: u8 = 0;
/// Checksum status value: the checksum is correct.
pub(crate) const STATUS_GOOD: u8 = 1;
/// Checksum status value: validation is disabled.
pub(crate) const STATUS_UNVERIFIED: u8 = 2;
/// Checksum status value: the field is zero and ignored.
pub(crate) const STATUS_NOT_PRESENT: u8 = 3;
/// Checksum status value: the field is zero where that is illegal.
pub(crate) const STATUS_ILLEGAL: u8 = 4;

/// A running one's-complement sum over big-endian 16-bit words.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InternetChecksum {
    sum: u32,
    pending: Option<u8>,
}

impl InternetChecksum {
    /// Start an empty sum.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add one 16-bit word.
    fn add_word(&mut self, word: u16) {
        self.sum += u32::from(word);
        if self.sum > 0xffff {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
    }

    /// Add the bytes of one part, carrying an odd byte into the next part.
    pub(crate) fn add(&mut self, data: &[u8]) {
        let mut remaining = data;
        if let Some(high) = self.pending.take() {
            let Some((&low, rest)) = remaining.split_first() else {
                self.pending = Some(high);
                return;
            };
            self.add_word(u16::from_be_bytes([high, low]));
            remaining = rest;
        }
        let (words, rest) = remaining.as_chunks::<2>();
        for word in words {
            self.add_word(u16::from_be_bytes(*word));
        }
        if let [last] = rest {
            self.pending = Some(*last);
        }
    }

    /// Add a 16-bit value in network byte order.
    pub(crate) fn add_u16(&mut self, value: u16) {
        self.add(&value.to_be_bytes());
    }

    /// Add a 32-bit value in network byte order.
    pub(crate) fn add_u32(&mut self, value: u32) {
        self.add(&value.to_be_bytes());
    }

    /// Fold the carries and return the one's complement.
    pub(crate) fn finish(mut self) -> u16 {
        if let Some(high) = self.pending.take() {
            self.add_word(u16::from_be_bytes([high, 0]));
        }
        while self.sum > 0xffff {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        let [_, _, high, low] = self.sum.to_be_bytes();
        !u16::from_be_bytes([high, low])
    }
}

/// Checksum a message that has no pseudo-header, with its checksum field
/// treated as zero. ICMPv4 uses this layout.
pub(crate) fn without_pseudo_header(data: &[u8], checksum_offset: usize) -> u16 {
    let mut sum = InternetChecksum::new();
    add_without_checksum(&mut sum, data, checksum_offset);
    sum.finish()
}

/// Checksum an IPv4 transport segment with its checksum field treated as zero.
///
/// `data` holds the transport bytes the checksum covers; `checksum_offset` is
/// the offset of the two checksum bytes within it. The pseudo-header length is
/// a 32-bit field: RFC 793 specifies 16 bits, but every legal IPv4 total
/// length fits there (the high word is zero, so the sum is unchanged), while
/// a TCP segmentation offload frame larger than 64 KiB needs the wider value.
pub(crate) fn ipv4_transport(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    length: u32,
    data: &[u8],
    checksum_offset: usize,
) -> u16 {
    let mut sum = InternetChecksum::new();
    sum.add(&source);
    sum.add(&destination);
    sum.add(&[0, protocol]);
    sum.add_u32(length);
    add_without_checksum(&mut sum, data, checksum_offset);
    sum.finish()
}

/// Checksum an IPv6 transport segment with its checksum field treated as zero.
pub(crate) fn ipv6_transport(
    source: [u8; 16],
    destination: [u8; 16],
    protocol: u8,
    length: u32,
    data: &[u8],
    checksum_offset: usize,
) -> u16 {
    let mut sum = InternetChecksum::new();
    sum.add(&source);
    sum.add(&destination);
    sum.add_u32(length);
    sum.add(&[0, 0, 0, protocol]);
    add_without_checksum(&mut sum, data, checksum_offset);
    sum.finish()
}

fn add_without_checksum(sum: &mut InternetChecksum, data: &[u8], checksum_offset: usize) {
    if let Some(before) = data.get(..checksum_offset) {
        sum.add(before);
    }
    let after_offset = checksum_offset.saturating_add(2);
    if let Some(after) = data.get(after_offset..) {
        sum.add(after);
    }
}
