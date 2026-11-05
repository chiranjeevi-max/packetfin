//! IEEE 802.1Q VLAN, QinQ and IEEE 802.1ad provider-bridge decoding.
//!
//! A VLAN tag is a two-byte tag control identifier followed by the inner
//! value. The 0x8100 and the old non-standard 0x9100 TPIDs decode as
//! `vlan`; 0x88a8 is the separate `ieee8021ad` protocol. A `vlan` inner value
//! of 0 through 1500 is an IEEE 802.3 length and carries LLC bounded by that
//! length; a larger value is the inner EtherType. The 802.1ad inner value is
//! always treated as an EtherType. Stacked tags recurse through the
//! EtherType table.

use crate::decode::bytes::read_u16_be;
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const TAG_LENGTH: usize = 4;
const INNER_TYPE_OFFSET: usize = 2;
const SECOND_TAG_OFFSET: usize = 4;
const SECOND_TYPE_OFFSET: usize = 6;
const MAX_8023_LENGTH: u16 = 1_500;
const PROVIDER_TPID: u16 = 0x88a8;

/// Decode one 802.1Q or 0x9100 VLAN tag into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::VLAN_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::VLAN_PROTOCOL, Range::new(base, data.len()));

    if let Some(tci) = read_u16_be(data, 0) {
        add_tag_fields(&mut node, base, tci);
    }

    let Some(inner) = read_u16_be(data, INNER_TYPE_OFFSET) else {
        context.mark_malformed(&mut node, "VLAN tag shorter than its inner type");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };

    let payload = data.get(TAG_LENGTH..).unwrap_or(&[]);
    let payload_start = base + TAG_LENGTH;
    if inner <= MAX_8023_LENGTH {
        node.add_field(
            &fields::VLAN_LEN,
            Range::new(base + INNER_TYPE_OFFSET, 2),
            Value::Uint16(inner),
        );
        let declared = usize::from(inner);
        if declared > payload.len() {
            context.mark_malformed(
                &mut node,
                "Length field value goes past the end of the payload",
            );
        }
        let bounded_length = declared.min(payload.len());
        let bounded = payload.get(..bounded_length).unwrap_or(&[]);
        decode::dispatch(
            context,
            &mut node,
            Some(fields::Protocol::Llc),
            bounded,
            payload_start,
        );
    } else {
        node.add_field(
            &fields::VLAN_ETYPE,
            Range::new(base + INNER_TYPE_OFFSET, 2),
            Value::Uint16(inner),
        );
        decode::dispatch_ethertype(context, &mut node, inner, payload, payload_start);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Decode one IEEE 802.1ad provider tag into the parent node.
///
/// The first `0x88a8` tag followed by another `0x88a8` tag carries an S-VID
/// and a C-VID in one protocol node; only `ieee8021ad.id` is exposed when a
/// single provider tag is followed by a different inner type.
pub(crate) fn decode_8021ad(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::IEEE8021AD_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::IEEE8021AD_PROTOCOL, Range::new(base, data.len()));

    let tag = read_u16_be(data, 0);
    let inner = read_u16_be(data, INNER_TYPE_OFFSET);
    let (Some(tag), Some(inner)) = (tag, inner) else {
        context.mark_malformed(&mut node, "802.1ad tag shorter than four bytes");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };

    if inner == PROVIDER_TPID {
        // Add no 802.1ad fields until the second tag control identifier is
        // present; with only four or five bytes, report malformed instead.
        let Some(second) = read_u16_be(data, SECOND_TAG_OFFSET) else {
            context.mark_malformed(&mut node, "802.1ad second tag is truncated");
            parent.add_child(node);
            context.depth = context.depth.saturating_sub(1);
            return;
        };
        node.add_field(
            &fields::IEEE8021AD_SVID,
            Range::new(base, 2),
            Value::Uint16(tag & 0x0fff),
        );
        node.add_field(
            &fields::IEEE8021AD_CVID,
            Range::new(base + SECOND_TAG_OFFSET, 2),
            Value::Uint16(second & 0x0fff),
        );
        add_provider_fields(&mut node, base, tag);
        add_provider_fields(&mut node, base + SECOND_TAG_OFFSET, second);

        match read_u16_be(data, SECOND_TYPE_OFFSET) {
            Some(second_inner) => {
                let payload = data.get(TAG_LENGTH * 2..).unwrap_or(&[]);
                decode::dispatch_ethertype(
                    context,
                    &mut node,
                    second_inner,
                    payload,
                    base + TAG_LENGTH * 2,
                );
            }
            None => {
                context.mark_malformed(&mut node, "802.1ad tag shorter than its inner type");
            }
        }
    } else {
        node.add_field(
            &fields::IEEE8021AD_ID,
            Range::new(base, 2),
            Value::Uint16(tag & 0x0fff),
        );
        add_provider_fields(&mut node, base, tag);
        let payload = data.get(TAG_LENGTH..).unwrap_or(&[]);
        decode::dispatch_ethertype(context, &mut node, inner, payload, base + TAG_LENGTH);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Add the priority and drop-eligibility fields shared between the VLAN and
/// 802.1ad tags.
fn add_provider_fields(node: &mut Node, base: usize, tci: u16) {
    let range = Range::new(base, 2);
    node.add_field(
        &fields::IEEE8021AD_PRIORITY,
        range,
        Value::Uint16(tci >> 13),
    );
    node.add_field(
        &fields::IEEE8021AD_DEI,
        range,
        Value::Uint16((tci >> 12) & 1),
    );
}

/// Add the three 802.1Q tag fields.
fn add_tag_fields(node: &mut Node, base: usize, tci: u16) {
    let range = Range::new(base, 2);
    node.add_field(&fields::VLAN_PRIORITY, range, Value::Uint16(tci >> 13));
    node.add_field(&fields::VLAN_DEI, range, Value::Boolean(tci & 0x1000 != 0));
    node.add_field(&fields::VLAN_ID, range, Value::Uint16(tci & 0x0fff));
}
