//! HPACK header compression (RFC 7541).
//!
//! The decoder implements the integer and string primitives of section 5, the
//! static table of Appendix A, the dynamic table of sections 2.3 and 4, and
//! the Huffman code of Appendix B. A header block is decoded as one ordered
//! unit: every representation is read in sequence, incremental-indexing
//! entries enter the dynamic table in the order they complete, and a
//! representation that cannot be decoded stops the block.
//!
//! Every output is bounded. A string decodes to at most
//! [`MAX_STRING_BYTES`], a header block produces at most [`MAX_HEADER_LINES`]
//! items and [`MAX_HEADER_BYTES`] octets of header list (the RFC 7541 section
//! 4.1 entry size), and the dynamic table never exceeds [`MAX_TABLE_SIZE`].
//! Reaching a bound stops decompression and reports it to the caller instead
//! of aborting the packet.

use std::collections::VecDeque;
use std::mem::size_of;
use std::sync::LazyLock;

use super::hpack_tables::{HUFFMAN_CODES, STATIC_TABLE};

/// The octets an entry adds beyond its name and value (RFC 7541 section 4.1).
pub(crate) const ENTRY_OVERHEAD: usize = 32;

/// The dynamic table capacity before any SETTINGS or size update.
pub(crate) const DEFAULT_TABLE_SIZE: usize = 4096;

/// The largest dynamic table this decoder retains.
///
/// RFC 7541 section 6.3 lets the protocol set the limit; HTTP/2 defaults to
/// 4096 octets (RFC 9113 section 6.5.2). The cap keeps a hostile size update
/// from reserving memory beyond the state budget, and a value above it is a
/// decoding error.
pub(crate) const MAX_TABLE_SIZE: usize = 64 * 1024;

/// The longest string one representation may decode to.
pub(crate) const MAX_STRING_BYTES: usize = 16 * 1024;

/// The most header-list octets one block may decode (RFC 7541 section 4.1).
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// The most items one header block may decode.
///
/// The bound covers table size updates as well as header fields, because both
/// produce a tree item and the reference stops after 200 lines.
pub(crate) const MAX_HEADER_LINES: usize = 200;

/// One dynamic-table entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    value: String,
}

impl Entry {
    fn size(&self) -> usize {
        self.name
            .len()
            .saturating_add(self.value.len())
            .saturating_add(ENTRY_OVERHEAD)
    }
}

/// The connection's dynamic table, newest entry first.
///
/// RFC 7541 section 2.3 numbers dynamic entries from 62 upward and inserts
/// new entries at the front, so the newest entry is index 62.
#[derive(Debug)]
pub(crate) struct DynamicTable {
    entries: VecDeque<Entry>,
    size: usize,
    capacity: usize,
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicTable {
    /// An empty table at the default capacity.
    pub(crate) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            capacity: DEFAULT_TABLE_SIZE,
        }
    }

    /// Set the maximum size and evict entries that no longer fit.
    ///
    /// The caller has already checked the value against the protocol limit
    /// (RFC 7541 section 6.3).
    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.min(MAX_TABLE_SIZE);
        self.evict();
    }

    /// Insert one entry, evicting from the oldest end until it fits.
    ///
    /// RFC 7541 section 4.4: an entry larger than the whole table empties the
    /// table and is not inserted.
    pub(crate) fn insert(&mut self, name: String, value: String) {
        let entry = Entry { name, value };
        let size = entry.size();
        self.entries.push_front(entry);
        self.size = self.size.saturating_add(size);
        self.evict();
    }

    /// Look up one 1-based HPACK index across the static and dynamic tables.
    pub(crate) fn get(&self, index: usize) -> Option<(&str, &str)> {
        if index == 0 {
            return None;
        }
        if let Some((name, value)) = STATIC_TABLE.get(index.saturating_sub(1)) {
            return Some((name, value));
        }
        let dynamic = index.saturating_sub(STATIC_TABLE.len().saturating_add(1));
        let entry = self.entries.get(dynamic)?;
        Some((&entry.name, &entry.value))
    }

    /// Number of retained dynamic entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// The current maximum size in octets.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Heap bytes this table retains, for the state ledger.
    pub(crate) fn state_bytes(&self) -> usize {
        let mut bytes = self.entries.capacity().saturating_mul(size_of::<Entry>());
        for entry in &self.entries {
            bytes = bytes
                .saturating_add(entry.name.capacity())
                .saturating_add(entry.value.capacity());
        }
        bytes
    }

    fn evict(&mut self) {
        while self.size > self.capacity {
            let Some(entry) = self.entries.pop_back() else {
                self.size = 0;
                return;
            };
            self.size = self.size.saturating_sub(entry.size());
        }
    }
}

/// How one header field was encoded (RFC 7541 section 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Representation {
    /// Indexed header field (section 6.1).
    Indexed,
    /// Literal without indexing, indexed name (section 6.2.2).
    WithoutIndexingIndexedName,
    /// Literal without indexing, new name (section 6.2.2).
    WithoutIndexingNewName,
    /// Literal never indexed, indexed name (section 6.2.3).
    NeverIndexedIndexedName,
    /// Literal never indexed, new name (section 6.2.3).
    NeverIndexedNewName,
    /// Literal with incremental indexing, indexed name (section 6.2.1).
    IncrementalIndexedName,
    /// Literal with incremental indexing, new name (section 6.2.1).
    IncrementalNewName,
}

impl Representation {
    /// The label the reference registry's `http2.header.repr` field prints.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Indexed => "Indexed Header Field",
            Self::WithoutIndexingIndexedName => {
                "Literal Header Field without Indexing - Indexed Name"
            }
            Self::WithoutIndexingNewName => "Literal Header Field without Indexing - New Name",
            Self::NeverIndexedIndexedName => "Literal Header Field never Indexed - Indexed Name",
            Self::NeverIndexedNewName => "Literal Header Field never Indexed - New Name",
            Self::IncrementalIndexedName => {
                "Literal Header Field with Incremental Indexing - Indexed Name"
            }
            Self::IncrementalNewName => "Literal Header Field with Incremental Indexing - New Name",
        }
    }
}

/// One decoded header field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    /// Field name, lower-case as HPACK transmits it.
    pub(crate) name: String,
    /// Field value.
    pub(crate) value: String,
    /// The representation that produced it.
    pub(crate) representation: Representation,
    /// The static or dynamic index used, when the representation names one.
    pub(crate) index: Option<u32>,
}

/// One decoded header-block item, in wire order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    /// A dynamic table size update (RFC 7541 section 6.3).
    TableSizeUpdate(u32),
    /// A header field.
    Header(Header),
}

/// Why a block stopped before its last byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The block decoded completely.
    Complete,
    /// The header-list octet bound stopped decompression.
    SizeExceeded,
    /// The item-count bound stopped decompression.
    LinesExceeded,
    /// A representation was invalid: an index, integer or Huffman code.
    Invalid,
}

/// A decoded header block.
#[derive(Debug)]
pub(crate) struct Block {
    /// Decoded items in wire order.
    pub(crate) items: Vec<Item>,
    /// Header-list octets, the RFC 7541 section 4.1 entry size.
    pub(crate) header_bytes: u32,
    /// Header fields plus table size updates, the reference's header count.
    pub(crate) header_count: u32,
    /// How decoding ended.
    pub(crate) stop: Stop,
}

impl Block {
    /// Iterate the header fields, skipping size updates.
    pub(crate) fn headers(&self) -> impl Iterator<Item = &Header> {
        self.items.iter().filter_map(|item| match item {
            Item::Header(header) => Some(header),
            Item::TableSizeUpdate(_) => None,
        })
    }
}

/// Decode one complete header block.
///
/// `table_limit` is the largest dynamic table size the peer's SETTINGS allows
/// (RFC 7541 section 6.3); a size update above it is invalid. The dynamic
/// table is updated as representations complete, so a later block that
/// references an entry inserted here decodes correctly.
pub(crate) fn decode_block(data: &[u8], table: &mut DynamicTable, table_limit: usize) -> Block {
    let mut block = Block {
        items: Vec::new(),
        header_bytes: 0,
        header_count: 0,
        stop: Stop::Complete,
    };
    let mut position = 0_usize;
    while position < data.len() {
        let Some(&first) = data.get(position) else {
            break;
        };
        if first & 0x80 != 0 {
            let Some((index, next)) = decode_integer(data, position, 7) else {
                block.stop = Stop::Invalid;
                return block;
            };
            position = next;
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            let Some((name, value)) = table.get(index as usize) else {
                block.stop = Stop::Invalid;
                return block;
            };
            let header = Header {
                name: name.to_string(),
                value: value.to_string(),
                representation: Representation::Indexed,
                index: Some(index),
            };
            if !push_header(&mut block, header) {
                return block;
            }
            continue;
        }
        let (representation, prefix_bits) = if first & 0x40 != 0 {
            (Representation::IncrementalNewName, 6)
        } else if first & 0x20 != 0 {
            // A table size update is not a header field and does not count
            // toward the header-list octets.
            let Some((size, next)) = decode_integer(data, position, 5) else {
                block.stop = Stop::Invalid;
                return block;
            };
            position = next;
            if size > u64::try_from(table_limit).unwrap_or(u64::MAX) {
                block.stop = Stop::Invalid;
                return block;
            }
            table.set_capacity(usize::try_from(size).unwrap_or(MAX_TABLE_SIZE));
            block.items.push(Item::TableSizeUpdate(
                u32::try_from(size).unwrap_or(u32::MAX),
            ));
            block.header_count = block.header_count.saturating_add(1);
            if usize::try_from(block.header_count).unwrap_or(usize::MAX) > MAX_HEADER_LINES {
                block.stop = Stop::LinesExceeded;
                return block;
            }
            continue;
        } else if first & 0x10 != 0 {
            (Representation::NeverIndexedNewName, 4)
        } else {
            (Representation::WithoutIndexingNewName, 4)
        };
        let Some((name_index, next)) = decode_integer(data, position, prefix_bits) else {
            block.stop = Stop::Invalid;
            return block;
        };
        position = next;
        let (name, index) = if name_index == 0 {
            let Some((name, next)) = decode_string(data, position) else {
                block.stop = Stop::Invalid;
                return block;
            };
            position = next;
            (name, None)
        } else {
            let index = u32::try_from(name_index).unwrap_or(u32::MAX);
            let Some((name, _)) = table.get(name_index as usize) else {
                block.stop = Stop::Invalid;
                return block;
            };
            (name.to_string(), Some(index))
        };
        let Some((value, next)) = decode_string(data, position) else {
            block.stop = Stop::Invalid;
            return block;
        };
        position = next;
        let representation = match (representation, index.is_some()) {
            (Representation::IncrementalNewName, true) => Representation::IncrementalIndexedName,
            (Representation::NeverIndexedNewName, true) => Representation::NeverIndexedIndexedName,
            (Representation::WithoutIndexingNewName, true) => {
                Representation::WithoutIndexingIndexedName
            }
            (other, _) => other,
        };
        if representation == Representation::IncrementalIndexedName
            || representation == Representation::IncrementalNewName
        {
            table.insert(name.clone(), value.clone());
        }
        let header = Header {
            name,
            value,
            representation,
            index,
        };
        if !push_header(&mut block, header) {
            return block;
        }
    }
    block
}

/// Add one header, applying the list bounds.
///
/// Returns whether decoding may continue. The offending header is not
/// emitted, so the tree keeps only what fit the bound.
fn push_header(block: &mut Block, header: Header) -> bool {
    let bytes = header
        .name
        .len()
        .saturating_add(header.value.len())
        .saturating_add(8);
    let next_bytes = usize::try_from(block.header_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(bytes);
    if next_bytes > MAX_HEADER_BYTES {
        block.stop = Stop::SizeExceeded;
        return false;
    }
    let next_count = usize::try_from(block.header_count)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    if next_count > MAX_HEADER_LINES {
        block.stop = Stop::LinesExceeded;
        return false;
    }
    block.header_bytes = u32::try_from(next_bytes).unwrap_or(u32::MAX);
    block.header_count = u32::try_from(next_count).unwrap_or(u32::MAX);
    block.items.push(Item::Header(header));
    true
}

/// Decode one HPACK integer with an N-bit prefix (RFC 7541 section 5.1).
///
/// Returns the value and the position after it. A value that does not fit in
/// 32 bits, or a continuation longer than five octets, is rejected: HPACK
/// values this decoder uses never exceed that, and the bound keeps a hostile
/// block from shifting without limit.
fn decode_integer(data: &[u8], start: usize, prefix_bits: u8) -> Option<(u64, usize)> {
    let first = u64::from(*data.get(start)?);
    let mask = (1_u64 << prefix_bits).wrapping_sub(1);
    let mut value = first & mask;
    let mut position = start.checked_add(1)?;
    if value < mask {
        return Some((value, position));
    }
    let mut shift = 0_u32;
    loop {
        let byte = *data.get(position)?;
        position = position.checked_add(1)?;
        let chunk = u64::from(byte & 0x7f);
        value = value.checked_add(chunk.checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some((value, position));
        }
        shift = shift.checked_add(7)?;
        if shift > 28 {
            return None;
        }
    }
}

/// Decode one HPACK string literal (RFC 7541 section 5.2).
///
/// Returns the decoded string and the position after it.
fn decode_string(data: &[u8], start: usize) -> Option<(String, usize)> {
    let first = *data.get(start)?;
    let huffman = first & 0x80 != 0;
    let (length, position) = decode_integer(data, start, 7)?;
    let length = usize::try_from(length).ok()?;
    if length > MAX_STRING_BYTES {
        return None;
    }
    let end = position.checked_add(length)?;
    let bytes = data.get(position..end)?;
    let text = if huffman {
        huffman_decode(bytes)?
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    Some((text, end))
}

/// The canonical Huffman decoding tables of RFC 7541 Appendix B.
struct HuffmanTable {
    /// Symbols ordered by code length, then code value.
    symbols: Vec<u16>,
    /// First code of each length, indexed by length.
    first_code: [u32; 31],
    /// Number of codes of each length.
    count: [u32; 31],
    /// Index of the first symbol of each length in `symbols`.
    first_index: [u32; 31],
}

impl HuffmanTable {
    fn build() -> Self {
        let mut entries: Vec<(u8, u32, u16)> = HUFFMAN_CODES
            .iter()
            .enumerate()
            .map(|(symbol, (code, length))| (*length, *code, u16::try_from(symbol).unwrap_or(0)))
            .collect();
        entries.sort_unstable();
        let mut symbols = Vec::with_capacity(entries.len());
        let mut first_code = [0_u32; 31];
        let mut count = [0_u32; 31];
        let mut first_index = [0_u32; 31];
        let mut previous_length = 0_u8;
        for (length, code, symbol) in entries {
            let slot = usize::from(length).min(30);
            if length != previous_length {
                if let Some(entry) = first_code.get_mut(slot) {
                    *entry = code;
                }
                if let Some(entry) = first_index.get_mut(slot) {
                    *entry = u32::try_from(symbols.len()).unwrap_or(u32::MAX);
                }
                previous_length = length;
            }
            if let Some(entry) = count.get_mut(slot) {
                *entry = entry.saturating_add(1);
            }
            symbols.push(symbol);
        }
        Self {
            symbols,
            first_code,
            count,
            first_index,
        }
    }

    fn lookup(&self, code: u32, length: u8) -> Option<u16> {
        let slot = usize::from(length);
        let first_code = self.first_code.get(slot)?;
        let count = self.count.get(slot)?;
        let offset = code.checked_sub(*first_code)?;
        if offset >= *count {
            return None;
        }
        let index = usize::try_from(self.first_index.get(slot)?.checked_add(offset)?).ok()?;
        self.symbols.get(index).copied()
    }
}

static HUFFMAN: LazyLock<HuffmanTable> = LazyLock::new(HuffmanTable::build);

/// Decode one Huffman-coded string (RFC 7541 Appendix B).
///
/// The final byte may carry up to seven padding bits, all ones, which must be
/// a prefix of the EOS code (section 5.2). Any other leftover bits, an EOS in
/// the middle, or output beyond the string bound is invalid.
fn huffman_decode(bytes: &[u8]) -> Option<String> {
    let table = &*HUFFMAN;
    let mut output = Vec::with_capacity(bytes.len());
    let mut code = 0_u32;
    let mut length = 0_u8;
    for byte in bytes {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            length = length.checked_add(1)?;
            let Some(symbol) = table.lookup(code, length) else {
                continue;
            };
            if symbol == 256 {
                // EOS is not a valid string symbol (RFC 7541 section 5.2).
                return None;
            }
            output.push(u8::try_from(symbol).ok()?);
            if output.len() > MAX_STRING_BYTES {
                return None;
            }
            code = 0;
            length = 0;
        }
    }
    if length > 7 {
        return None;
    }
    if length > 0 && code != (1_u32 << length).wrapping_sub(1) {
        return None;
    }
    Some(String::from_utf8_lossy(&output).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_entries_match_appendix_a() {
        assert_eq!(STATIC_TABLE.len(), 61);
        assert_eq!(STATIC_TABLE.first(), Some(&(":authority", "")));
        assert_eq!(STATIC_TABLE.get(1), Some(&(":method", "GET")));
        assert_eq!(STATIC_TABLE.get(60), Some(&("www-authenticate", "")));
    }

    #[test]
    fn huffman_table_is_canonical_and_complete() {
        let table = &*HUFFMAN;
        assert_eq!(table.symbols.len(), 257);
        let mut covered = 0_u64;
        for length in 1..=30 {
            let count = table.count.get(length).copied().unwrap_or(0);
            if count == 0 {
                continue;
            }
            let shift = 30_u32.saturating_sub(u32::try_from(length).unwrap_or(30));
            covered = covered.saturating_add(u64::from(count) << shift);
            let first = table.first_code.get(length).copied().unwrap_or(0);
            let last = first.saturating_add(count.saturating_sub(1));
            assert!(last < (1_u32 << length));
        }
        assert_eq!(covered, 1_u64 << 30);
    }

    #[test]
    fn rfc_example_c3_request_decodes() {
        // RFC 7541 Appendix C.3.1: first request with an empty table.
        let mut table = DynamicTable::new();
        let block = decode_block(
            &[
                0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                0x90, 0xf4, 0xff,
            ],
            &mut table,
            DEFAULT_TABLE_SIZE,
        );
        assert_eq!(block.stop, Stop::Complete);
        let headers: Vec<(&str, &str)> = block
            .headers()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect();
        assert_eq!(
            headers,
            vec![
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ]
        );
        assert_eq!(block.header_bytes, 84);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn rfc_example_c4_second_request_uses_the_dynamic_table() {
        let mut table = DynamicTable::new();
        let first = decode_block(
            &[
                0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                0x90, 0xf4, 0xff,
            ],
            &mut table,
            DEFAULT_TABLE_SIZE,
        );
        assert_eq!(first.stop, Stop::Complete);
        let second = decode_block(
            &[
                0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
            ],
            &mut table,
            DEFAULT_TABLE_SIZE,
        );
        assert_eq!(second.stop, Stop::Complete);
        let headers: Vec<(&str, &str)> = second
            .headers()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect();
        assert_eq!(
            headers,
            vec![
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ]
        );
    }

    #[test]
    fn an_index_beyond_the_tables_stops_the_block() {
        let mut table = DynamicTable::new();
        let block = decode_block(&[0x82, 0xbe], &mut table, DEFAULT_TABLE_SIZE);
        assert_eq!(block.stop, Stop::Invalid);
        assert_eq!(block.headers().count(), 1);
    }

    #[test]
    fn a_size_update_above_the_limit_is_invalid() {
        let mut table = DynamicTable::new();
        // 0x3f 0xe1 0x3f encodes 31 + 97 + 63 * 128 = 8192.
        let block = decode_block(&[0x3f, 0xe1, 0x3f, 0x82], &mut table, DEFAULT_TABLE_SIZE);
        assert_eq!(block.stop, Stop::Invalid);
        assert_eq!(table.capacity(), DEFAULT_TABLE_SIZE);
        assert!(block.items.is_empty());
    }

    #[test]
    fn eviction_follows_the_entry_size_rule() {
        let mut table = DynamicTable::new();
        table.set_capacity(64);
        table.insert("a".to_string(), "b".to_string());
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(62), Some(("a", "b")));
        // Two 33-octet entries do not fit in 64 octets.
        table.insert("c".to_string(), "d".to_string());
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(62), Some(("c", "d")));
        assert_eq!(table.get(63), None);
    }

    #[test]
    fn an_oversized_entry_empties_the_table() {
        let mut table = DynamicTable::new();
        table.set_capacity(40);
        table.insert("x".to_string(), "y".to_string());
        assert_eq!(table.len(), 1);
        table.insert("n".repeat(32), String::new());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn huffman_padding_must_be_eos_bits() {
        // RFC 7541 Appendix C.4.1: "www.example.com" with a valid final pad.
        let decoded = huffman_decode(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        assert_eq!(decoded.as_deref(), Some("www.example.com"));
        // A final byte with a zero pad bit is invalid.
        assert!(huffman_decode(&[0x00]).is_none());
        // EOS in the middle of the string is invalid.
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn a_string_longer_than_the_bound_is_rejected() {
        let mut data = vec![0x7f];
        let mut length = MAX_STRING_BYTES + 1 - 0x7f;
        loop {
            let byte = u8::try_from(length & 0x7f).unwrap_or(0);
            length >>= 7;
            if length == 0 {
                data.push(byte);
                break;
            }
            data.push(byte | 0x80);
        }
        assert!(decode_string(&data, 0).is_none());
    }
}
