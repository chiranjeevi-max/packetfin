//! MultiProtocol Label Switching.
//!
//! RFC 3032 section 2 defines the four-octet label stack entry: a 20-bit
//! label, three experimental bits, the bottom-of-stack bit and a TTL. The
//! stack is read until the bottom bit is set; the payload protocol is then
//! selected by the first nibble of the payload, as RFC 4385 and RFC 4928
//! describe (4 is IPv4, 6 is IPv6). A stack without a bottom bit that runs
//! out of captured bytes is malformed, and the entry count is capped so a
//! hostile frame cannot grow the tree without bound.

use crate::decode::bytes::read_u32_be;
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const LABEL_LENGTH: usize = 4;

/// Deepest label stack Packetfin follows.
///
/// RFC 3032 has no bound; real stacks are a handful of entries.
const MAX_LABELS: usize = 64;

/// Decode an MPLS label stack and dispatch its payload by version nibble.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::MPLS_PROTOCOL.filter_name);

    if data.len() < LABEL_LENGTH {
        let mut node = Node::new(&fields::MPLS_PROTOCOL, Range::new(base, data.len()));
        context.mark_malformed(&mut node, "MPLS label stack is truncated");
        finish(context, parent, node);
        return;
    }

    let mut labels = Vec::new();
    let mut offset = 0_usize;
    let mut bottom = false;
    while labels.len() < MAX_LABELS {
        let Some(word) = read_u32_be(data, offset) else {
            break;
        };
        labels.push((offset, word));
        offset = offset.saturating_add(LABEL_LENGTH);
        if word & 0x0000_0100 != 0 {
            bottom = true;
            break;
        }
    }

    let payload = data.get(offset..).unwrap_or(&[]);
    let version = payload.first().copied().unwrap_or(0) >> 4;
    let mut inner: Option<Node> = None;
    for (index, (label_offset, word)) in labels.iter().enumerate().rev() {
        let mut node = Node::new(
            &fields::MPLS_PROTOCOL,
            Range::new(base + label_offset, LABEL_LENGTH),
        );
        node.add_field(
            &fields::MPLS_LABEL,
            Range::new(base + label_offset, LABEL_LENGTH),
            Value::Uint32((word >> 12) & 0x000f_ffff),
        );
        node.add_field(
            &fields::MPLS_EXP,
            Range::new(base + label_offset, LABEL_LENGTH),
            Value::Uint32((word >> 9) & 0x7),
        );
        node.add_field(
            &fields::MPLS_BOTTOM,
            Range::new(base + label_offset, LABEL_LENGTH),
            Value::Uint32((word >> 8) & 0x1),
        );
        node.add_field(
            &fields::MPLS_TTL,
            Range::new(base + label_offset, LABEL_LENGTH),
            Value::Uint32(word & 0xff),
        );
        if index + 1 == labels.len() {
            if !bottom {
                context.mark_malformed(
                    &mut node,
                    if labels.len() == MAX_LABELS {
                        "MPLS label stack exceeds its label limit"
                    } else {
                        "MPLS label stack has no bottom of stack"
                    },
                );
            } else if payload.is_empty() {
                context.mark_malformed(&mut node, "MPLS payload is missing");
            } else {
                decode::dispatch_ip_version(context, &mut node, version, payload, base + offset);
            }
        }
        if let Some(child) = inner.take() {
            node.add_child(child);
        }
        inner = Some(node);
    }

    match inner {
        Some(node) => finish(context, parent, node),
        None => {
            let mut node = Node::new(&fields::MPLS_PROTOCOL, Range::new(base, 0));
            context.mark_malformed(&mut node, "MPLS label stack is truncated");
            finish(context, parent, node);
        }
    }
}

fn finish(context: &mut DecodeContext<'_>, parent: &mut Node, node: Node) {
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
