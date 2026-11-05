//! Ethernet II and IEEE 802.3 decoding.
//!
//! The decoder reads the two 48-bit MAC addresses and the 16-bit type/length
//! field from the first 14 bytes, and classifies that field as follows:
//! zero is EtherType 0, 1 through 1500 is an 802.3 length, 1501 through 1535
//! is invalid, and 1536 and above is an EtherType. An 802.3 length bounds the
//! LLC frame, so Ethernet padding is never decoded as part of the LLC header.
//! Payload dispatch by EtherType goes through the registry table.

use crate::decode::bytes::read_u16_be;
use crate::decode::{self, DecodeContext, LayerType};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const MAC_LENGTH: usize = 6;
const BOTH_MACS_LENGTH: usize = 12;
const TYPE_OFFSET: usize = 12;
const ETHERNET_HEADER_LENGTH: usize = 14;
/// Largest value the type field carries when it is an IEEE 802.3 length.
const MAX_8023_LENGTH: u16 = 1_500;
/// Smallest invalid length/type value (`0x05dd`).
const MIN_INVALID_LENGTH_TYPE: u16 = 1_501;
/// Largest invalid length/type value (`0x05ff`).
const MAX_INVALID_LENGTH_TYPE: u16 = 1_535;

/// Decode one Ethernet frame into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::ETH_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::ETH_PROTOCOL, Range::new(base, data.len()));

    // The summary columns use whatever address bytes are present, even when
    // the frame is too short for complete fields. A partially captured source
    // address fills only the destination.
    if let Some(address) = read_mac(data, 0) {
        context.columns.destination = Some(render_ethernet(address));
    }
    if let Some(address) = read_mac(data, MAC_LENGTH) {
        context.columns.source = Some(render_ethernet(address));
    }

    if data.len() >= BOTH_MACS_LENGTH {
        if let Some(address) = read_mac(data, 0) {
            let range = Range::new(base, MAC_LENGTH);
            node.add_field(&fields::ETH_DST, range, Value::Ethernet(address));
            let (label, organization) = context.names.mac_labels(address);
            node.add_field(&fields::ETH_DST_RESOLVED, range, Value::String(label));
            if let Some(organization) = organization {
                node.add_field(
                    &fields::ETH_DST_OUI_RESOLVED,
                    range,
                    Value::String(organization.to_string()),
                );
            }
            node.add_field(&fields::ETH_ADDR, range, Value::Ethernet(address));
        }
        if let Some(address) = read_mac(data, MAC_LENGTH) {
            let range = Range::new(base + MAC_LENGTH, MAC_LENGTH);
            node.add_field(&fields::ETH_SRC, range, Value::Ethernet(address));
            let (label, organization) = context.names.mac_labels(address);
            node.add_field(&fields::ETH_SRC_RESOLVED, range, Value::String(label));
            if let Some(organization) = organization {
                node.add_field(
                    &fields::ETH_SRC_OUI_RESOLVED,
                    range,
                    Value::String(organization.to_string()),
                );
            }
            node.add_field(&fields::ETH_ADDR, range, Value::Ethernet(address));
        }
    }

    if let Some(value) = read_u16_be(data, TYPE_OFFSET) {
        let payload = data.get(ETHERNET_HEADER_LENGTH..).unwrap_or(&[]);
        let payload_start = base + ETHERNET_HEADER_LENGTH;
        match value {
            0 => decode_ethertype(context, &mut node, value, payload, payload_start),
            1..=MAX_8023_LENGTH => decode_8023(context, &mut node, value, payload, payload_start),
            MIN_INVALID_LENGTH_TYPE..=MAX_INVALID_LENGTH_TYPE => {
                invalid_length_type(context, &mut node, value);
            }
            _ => decode_ethertype(context, &mut node, value, payload, payload_start),
        }
    } else {
        context.columns.protocol = Some("Ethernet".to_string());
        context.columns.info = Some("[Malformed Packet]".to_string());
        let message = if data.len() < BOTH_MACS_LENGTH {
            "Ethernet frame shorter than 12 bytes"
        } else {
            "Ethernet frame shorter than 14 bytes"
        };
        context.mark_malformed(&mut node, message);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Add an EtherType and hand the payload to its registered decoder.
fn decode_ethertype(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    value: u16,
    payload: &[u8],
    payload_start: usize,
) {
    node.add_field(
        &fields::ETH_TYPE,
        Range::new(node.range.offset + TYPE_OFFSET, 2),
        Value::Uint16(value),
    );
    if let Some(protocol) = fields::registry().protocol_for_ethertype(value) {
        let forced = context
            .options
            .decode_as
            .lookup(LayerType::Ethertype, &[u32::from(value)])
            .is_some();
        if forced || context.options.policy.enabled(protocol) {
            decode::dispatch_ethertype(context, node, value, payload, payload_start);
        } else {
            context.columns.protocol = Some(format!("0x{value:04x}"));
            context.columns.info = Some(ethertype_name(protocol).to_string());
        }
    } else {
        context.columns.protocol = Some(format!("0x{value:04x}"));
        context.columns.info = Some("Ethernet II".to_string());
    }
}

/// The one-line name shown when an EtherType's decoder is disabled.
fn ethertype_name(protocol: fields::Protocol) -> &'static str {
    match protocol {
        fields::Protocol::Ipv4 => "IPv4",
        fields::Protocol::Ipv6 => "IPv6",
        fields::Protocol::Arp => "ARP",
        fields::Protocol::Vlan | fields::Protocol::Ieee8021ad => "802.1Q",
        _ => protocol.def().short_name,
    }
}

/// Add an 802.3 length and decode the bounded LLC frame.
fn decode_8023(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    value: u16,
    payload: &[u8],
    payload_start: usize,
) {
    node.add_field(
        &fields::ETH_LEN,
        Range::new(node.range.offset + TYPE_OFFSET, 2),
        Value::Uint16(value),
    );
    let declared = usize::from(value);
    if declared > payload.len() {
        context.mark_field_malformed(node, "Length field value goes past the end of the payload");
    }
    let bounded_length = declared.min(payload.len());
    let bounded = payload.get(..bounded_length).unwrap_or(&[]);
    decode::dispatch(
        context,
        node,
        Some(fields::Protocol::Llc),
        bounded,
        payload_start,
    );
}

/// Report a value in the invalid length/type range as a protocol warning.
fn invalid_length_type(context: &mut DecodeContext<'_>, node: &mut Node, value: u16) {
    let message = format!("Invalid length/type: 0x{value:04x} ({value})");
    node.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Protocol,
        message: message.clone(),
    });
    context.columns.protocol = Some("Ethernet".to_string());
    context.columns.info = Some(format!("Ethernet Unknown: {message}"));
}

/// Read a 48-bit MAC address at `offset`, or `None` when fewer than six
/// bytes are available.
fn read_mac(data: &[u8], offset: usize) -> Option<[u8; MAC_LENGTH]> {
    let end = offset.checked_add(MAC_LENGTH)?;
    let bytes = data.get(offset..end)?;
    <[u8; MAC_LENGTH]>::try_from(bytes).ok()
}

fn render_ethernet(address: [u8; MAC_LENGTH]) -> String {
    Value::Ethernet(address).render(fields::Display::None)
}
