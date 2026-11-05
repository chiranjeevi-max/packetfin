//! Logical Link Control and SNAP decoding.
//!
//! IEEE 802.3 replaces the Ethernet type with a length, and the payload is an
//! LLC frame. The first two bytes are the destination and source service
//! access points; the control field is one byte for unnumbered frames and two
//! bytes for information and supervisory frames. SNAP is the `AA AA 03`
//! header: a three-byte organization code followed by a protocol identifier.
//! When the organization code is zero, the protocol identifier is exposed as
//! `llc.type` and dispatched as an EtherType.

use crate::decode::bytes::read_u16_be;
use crate::decode::{self, DecodeContext};
use crate::fields;
use crate::tree::{Node, Range, Value};

const SNAP_DSAP: u8 = 0xaa;
const SNAP_SSAP: u8 = 0xaa;
const SNAP_CONTROL: u16 = 0x0003;
const CONTROL_OFFSET: usize = 2;
const OUI_OFFSET: usize = 3;
const OUI_LENGTH: usize = 3;
const PID_OFFSET: usize = 6;
const SNAP_HEADER_LENGTH: usize = 8;
const UNNUMBERED_MASK: u8 = 0x03;
/// DSAP of the Spanning Tree BPDU service access point.
const STP_DSAP: u8 = 0x42;
/// Cisco PVST+ SNAP organization code and protocol identifier.
const PVST_OUI: u32 = 0x00_00_0c;
const PVST_PID: u16 = 0x010b;

/// Decode one LLC frame into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::LLC_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::LLC_PROTOCOL, Range::new(base, data.len()));

    let dsap = data.first().copied();
    let ssap = data.get(1).copied();
    if let Some(dsap) = dsap {
        node.add_field(&fields::LLC_DSAP, Range::new(base, 1), Value::Uint8(dsap));
    }
    if let Some(ssap) = ssap {
        node.add_field(
            &fields::LLC_SSAP,
            Range::new(base + 1, 1),
            Value::Uint8(ssap),
        );
    }

    let control = read_control(data);
    let Some((control_value, control_length)) = control else {
        context.mark_malformed(&mut node, "LLC frame shorter than its control field");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    node.add_field(
        &fields::LLC_CONTROL,
        Range::new(base + CONTROL_OFFSET, control_length),
        Value::Uint16(control_value),
    );

    let is_snap =
        dsap == Some(SNAP_DSAP) && ssap == Some(SNAP_SSAP) && control_value == SNAP_CONTROL;
    if is_snap {
        decode_snap(context, &mut node, data, base);
    } else if dsap == Some(STP_DSAP)
        && ssap == Some(STP_DSAP)
        && (control_value == SNAP_CONTROL || control_value & 0x0003 == 0)
    {
        let payload_start = CONTROL_OFFSET.saturating_add(control_length);
        let payload = data.get(payload_start..).unwrap_or(&[]);
        if !payload.is_empty() {
            decode::dispatch(
                context,
                &mut node,
                Some(fields::Protocol::Stp),
                payload,
                base.saturating_add(payload_start),
            );
        }
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Decode the SNAP header that follows an `AA AA 03` LLC header.
fn decode_snap(context: &mut DecodeContext<'_>, node: &mut Node, data: &[u8], base: usize) {
    let Some(oui) = read_oui(data) else {
        context.mark_malformed(node, "SNAP header shorter than its organization code");
        return;
    };
    node.add_field(
        &fields::LLC_OUI,
        Range::new(base + OUI_OFFSET, OUI_LENGTH),
        Value::Uint32(oui),
    );

    let Some(pid) = read_u16_be(data, PID_OFFSET) else {
        context.mark_malformed(node, "SNAP header shorter than its protocol identifier");
        return;
    };
    if oui == 0 {
        node.add_field(
            &fields::LLC_TYPE,
            Range::new(base + PID_OFFSET, 2),
            Value::Uint16(pid),
        );
        let payload = data.get(SNAP_HEADER_LENGTH..).unwrap_or(&[]);
        decode::dispatch_ethertype(context, node, pid, payload, base + SNAP_HEADER_LENGTH);
    } else {
        let pid_field = if oui == PVST_OUI {
            &fields::LLC_CISCO_PID
        } else {
            &fields::LLC_PID
        };
        node.add_field(
            pid_field,
            Range::new(base + PID_OFFSET, 2),
            Value::Uint16(pid),
        );
        if oui == PVST_OUI && pid == PVST_PID {
            let payload = data.get(SNAP_HEADER_LENGTH..).unwrap_or(&[]);
            if !payload.is_empty() {
                decode::dispatch(
                    context,
                    node,
                    Some(fields::Protocol::Stp),
                    payload,
                    base.saturating_add(SNAP_HEADER_LENGTH),
                );
            }
        }
    }
}

/// Read the LLC control field and its encoded length.
///
/// The low two bits of the first byte select the format: `11` is an
/// unnumbered frame with a one-byte control field, and the other values use
/// two bytes. The two-byte form is read little-endian.
fn read_control(data: &[u8]) -> Option<(u16, usize)> {
    let first = data.get(CONTROL_OFFSET).copied()?;
    if first & UNNUMBERED_MASK == UNNUMBERED_MASK {
        return Some((u16::from(first), 1));
    }
    let second = data.get(CONTROL_OFFSET.checked_add(1)?).copied()?;
    Some((u16::from_le_bytes([first, second]), 2))
}

/// Read the three-byte organization code at the SNAP offset.
fn read_oui(data: &[u8]) -> Option<u32> {
    let end = OUI_OFFSET.checked_add(OUI_LENGTH)?;
    let bytes = data.get(OUI_OFFSET..end)?;
    Some(
        (u32::from(*bytes.first()?) << 16)
            | (u32::from(*bytes.get(1)?) << 8)
            | u32::from(*bytes.get(2)?),
    )
}
