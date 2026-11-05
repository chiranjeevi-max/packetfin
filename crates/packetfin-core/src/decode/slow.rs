//! IEEE 802.3 slow protocols.
//!
//! Slow-protocol frames carry a one-byte subtype and a one-byte version
//! shared by every protocol defined in IEEE 802.3 clause 43 and annex 57.
//! Link Aggregation Control Protocol (subtype 1) and the Link Aggregation
//! Marker Protocol (subtype 2) are handed to their own decoders; other
//! subtypes keep only the shared header.

use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const SUBTYPE_OFFSET: usize = 0;
const PAYLOAD_OFFSET: usize = 1;

/// Decode one slow-protocol frame into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::SLOW_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::SLOW_PROTOCOL, Range::new(base, data.len()));
    let subtype = data.first().copied();
    if let Some(subtype) = subtype {
        node.add_field(
            &fields::SLOW_SUBTYPE,
            Range::new(base.saturating_add(SUBTYPE_OFFSET), 1),
            Value::Uint8(subtype),
        );
    }
    let protocol: Option<fields::Protocol> = match subtype {
        Some(1) => Some(fields::Protocol::Lacp),
        Some(2) => Some(fields::Protocol::Marker),
        _ => None,
    };
    if subtype.is_some() {
        let payload = data.get(PAYLOAD_OFFSET..).unwrap_or(&[]);
        decode::dispatch(
            context,
            &mut node,
            protocol,
            payload,
            base.saturating_add(PAYLOAD_OFFSET),
        );
    }
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
