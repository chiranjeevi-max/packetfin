//! Raw-IP link type.
//!
//! Link type 101 has no link-layer header; the first nibble selects the IP
//! version. The decoder adds no protocol node and hands the whole frame to the
//! IP-version dispatch table.

use crate::decode::{self, DecodeContext};
use crate::tree::Node;

const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;

/// Decode one raw-IP frame.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    let Some(first) = data.first().copied() else {
        context.mark_malformed(parent, "Raw IP packet is empty");
        return;
    };
    let version = first >> 4;
    if version == IPV4_VERSION || version == IPV6_VERSION {
        decode::dispatch_ip_version(context, parent, version, data, base);
    }
}

/// Decode a raw link type whose payload is always IPv4.
pub(crate) fn decode_ipv4(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    crate::decode::ipv4(context, parent, data, base);
}

/// Decode a raw link type whose payload is always IPv6.
pub(crate) fn decode_ipv6(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    crate::decode::ipv6(context, parent, data, base);
}
