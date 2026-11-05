//! Null/loopback link layers.
//!
//! Link type 0 (`DLT_NULL`) stores a four-byte address family in the capturing
//! host's byte order, so the decoder accepts either byte order; link type 108
//! (`DLT_LOOP`) always stores it in network byte order. The family selects the
//! IP version: 2 is IPv4, and 24, 28 and 30 are the IPv6 family values used by
//! OpenBSD, FreeBSD and macOS.

use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const FAMILY_LENGTH: usize = 4;
const AF_INET: u32 = 2;
const AF_INET6_FREEBSD: u32 = 28;
const AF_INET6_OPENBSD: u32 = 24;
const AF_INET6_MACOS: u32 = 30;

/// One family's byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FamilyOrder {
    /// Try both byte orders and prefer one that names an IP family.
    Detect,
    /// Network byte order, as used by `DLT_LOOP`.
    Big,
}

/// Decode a `DLT_NULL` frame.
pub(crate) fn decode_null(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    decode_family(context, parent, data, base, FamilyOrder::Detect);
}

/// Decode a `DLT_LOOP` frame.
pub(crate) fn decode_loopback(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    decode_family(context, parent, data, base, FamilyOrder::Big);
}

fn decode_family(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
    order: FamilyOrder,
) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::NULL_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::NULL_PROTOCOL, Range::new(base, data.len()));

    let Some(bytes) = data.get(..FAMILY_LENGTH) else {
        context.mark_malformed(&mut node, "Null/loopback header shorter than four bytes");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let Ok(family_bytes) = <[u8; FAMILY_LENGTH]>::try_from(bytes) else {
        context.mark_malformed(&mut node, "Null/loopback header shorter than four bytes");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let family = match order {
        FamilyOrder::Big => u32::from_be_bytes(family_bytes),
        FamilyOrder::Detect => detect_family(family_bytes),
    };
    node.add_field(
        &fields::NULL_FAMILY,
        Range::new(base, FAMILY_LENGTH),
        Value::Uint32(family),
    );

    let payload = data.get(FAMILY_LENGTH..).unwrap_or(&[]);
    match family {
        AF_INET => {
            decode::dispatch_ip_version(context, &mut node, 4, payload, base + FAMILY_LENGTH)
        }
        AF_INET6_OPENBSD | AF_INET6_FREEBSD | AF_INET6_MACOS => {
            decode::dispatch_ip_version(context, &mut node, 6, payload, base + FAMILY_LENGTH);
        }
        _ => {}
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Choose the byte order that names a known address family.
fn detect_family(bytes: [u8; FAMILY_LENGTH]) -> u32 {
    let big = u32::from_be_bytes(bytes);
    let little = u32::from_le_bytes(bytes);
    if is_ip_family(big) { big } else { little }
}

const fn is_ip_family(family: u32) -> bool {
    matches!(
        family,
        AF_INET | AF_INET6_OPENBSD | AF_INET6_FREEBSD | AF_INET6_MACOS
    )
}
