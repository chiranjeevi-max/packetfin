//! Bounds-checked big-endian reads shared by the decoders.
//!
//! Each read validates its offset and length with checked arithmetic before
//! slicing, so a truncated frame yields `None` instead of panicking.

/// Read `N` bytes at `offset`, or `None` when the slice is too short.
pub(crate) fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let bytes = data.get(offset..end)?;
    <[u8; N]>::try_from(bytes).ok()
}

/// Read a big-endian 16-bit integer at `offset`.
pub(crate) fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_be_bytes)
}

/// Read a big-endian 32-bit integer at `offset`.
pub(crate) fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_be_bytes)
}

/// Read a big-endian 24-bit integer at `offset`.
pub(crate) fn read_u24_be(data: &[u8], offset: usize) -> Option<u32> {
    let [high, middle, low] = array::<3>(data, offset)?;
    Some(u32::from_be_bytes([0, high, middle, low]))
}

/// Read a 4-byte IPv4 address at `offset`.
pub(crate) fn read_ipv4(data: &[u8], offset: usize) -> Option<[u8; 4]> {
    array(data, offset)
}

/// Read a 16-byte IPv6 address at `offset`.
pub(crate) fn read_ipv6(data: &[u8], offset: usize) -> Option<[u8; 16]> {
    array(data, offset)
}

/// A byte-count phrase, with the singular for one byte.
pub(crate) fn byte_count_text(length: usize) -> String {
    format!("{length} byte{}", if length == 1 { "" } else { "s" })
}

/// Lowercase hexadecimal text for bytes, without separators.
pub fn hex_lower(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Decode the bytes of a string field into display text.
///
/// ASCII bytes map to their characters; every byte at or above 0x80 becomes
/// one U+FFFD, including bytes that would form valid UTF-8.
pub(crate) fn ascii_lossy(data: &[u8]) -> String {
    data.iter()
        .map(|byte| {
            if *byte < 0x80 {
                char::from(*byte)
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// Whether a link-layer type is Ethernet-like for display purposes.
pub(crate) fn is_ethernet_link_layer(hardware_type: u16) -> bool {
    matches!(hardware_type, 1 | 6)
}

/// Render a link-layer address string: colon hex for a 6-byte Ethernet-like
/// address, contiguous lowercase hex otherwise.
pub(crate) fn link_layer_text(hardware_type: u16, address: &[u8]) -> String {
    if is_ethernet_link_layer(hardware_type) && address.len() == 6 {
        let mut text = String::with_capacity(17);
        for (index, byte) in address.iter().enumerate() {
            if index > 0 {
                text.push(':');
            }
            text.push_str(&format!("{byte:02x}"));
        }
        text
    } else {
        hex_lower(address)
    }
}

/// The Ethernet address for a 6-byte Ethernet link-layer value.
pub(crate) fn link_layer_mac(hardware_type: u16, address: &[u8]) -> Option<[u8; 6]> {
    if is_ethernet_link_layer(hardware_type) && address.len() == 6 {
        <[u8; 6]>::try_from(address).ok()
    } else {
        None
    }
}
