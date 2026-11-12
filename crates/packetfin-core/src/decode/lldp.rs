//! IEEE 802.1AB Link Layer Discovery Protocol.
//!
//! An LLDPDU is a sequence of type-length-value records. Each record starts
//! with a 16-bit header: nine bits of type, nine bits of length and one
//! reserved bit. The first three records are the mandatory chassis ID, port
//! ID and time-to-live (IEEE 802.1AB-2016 clause 8); the End TLV (type zero)
//! terminates the sequence. Every record is bounded by its declared length,
//! and an unrecognized record is skipped without consuming its content.
//!
//! Organizationally specific records carry a three-byte OUI and a one-byte
//! subtype. The IEEE 802.1 and IEEE 802.3 subtypes decoded here are the port
//! VLAN, VLAN name, protocol identity and link aggregation records from
//! IEEE 802.1AB-2016 annex F, and the MAC/PHY, link aggregation and maximum
//! frame size records from IEEE 802.3-2018 clause 79.

use crate::decode::DecodeContext;
use crate::decode::bytes::{array, read_u16_be, read_u32_be};
use crate::fields;
use crate::tree::{
    Bytes, ExpertInfo, Field, FieldParent, Group, Node, Range, RawField, RawSource, Severity, Value,
};

const HEADER_LENGTH: usize = 2;
const TYPE_SHIFT: u32 = 9;
const LENGTH_MASK: u16 = 0x01ff;

const TLV_END: u16 = 0;
const TLV_CHASSIS: u16 = 1;
const TLV_PORT: u16 = 2;
const TLV_TTL: u16 = 3;
const TLV_PORT_DESC: u16 = 4;
const TLV_SYSTEM_NAME: u16 = 5;
const TLV_SYSTEM_DESC: u16 = 6;
const TLV_SYSTEM_CAP: u16 = 7;
const TLV_MANAGEMENT: u16 = 8;
const TLV_ORGANIZATION: u16 = 127;

const CHASSIS_MAC: u8 = 4;
const CHASSIS_NETWORK: u8 = 5;
const PORT_MAC: u8 = 3;
const PORT_NETWORK: u8 = 4;

const OUI_IEEE_802_1: u32 = 0x00_80_c2;
const OUI_IEEE_802_3: u32 = 0x00_12_0f;

const ADDRESS_IPV4: u8 = 1;
const ADDRESS_IPV6: u8 = 2;

const CAPABILITY_BITS: [(&fields::FieldDef, u16); 11] = [
    (&fields::LLDP_TLV_SYSTEM_CAP_OTHER, 0x0001),
    (&fields::LLDP_TLV_SYSTEM_CAP_REPEATER, 0x0002),
    (&fields::LLDP_TLV_SYSTEM_CAP_BRIDGE, 0x0004),
    (&fields::LLDP_TLV_SYSTEM_CAP_WLAN_ACCESS_PT, 0x0008),
    (&fields::LLDP_TLV_SYSTEM_CAP_ROUTER, 0x0010),
    (&fields::LLDP_TLV_SYSTEM_CAP_TELEPHONE, 0x0020),
    (&fields::LLDP_TLV_SYSTEM_CAP_DOCSIS_CABLE_DEVICE, 0x0040),
    (&fields::LLDP_TLV_SYSTEM_CAP_STATION_ONLY, 0x0080),
    (&fields::LLDP_TLV_SYSTEM_CAP_CVLAN, 0x0100),
    (&fields::LLDP_TLV_SYSTEM_CAP_SVLAN, 0x0200),
    (&fields::LLDP_TLV_SYSTEM_CAP_TPMR, 0x0400),
];

const ENABLED_CAPABILITY_BITS: [(&fields::FieldDef, u16); 11] = [
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_OTHER, 0x0001),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_REPEATER, 0x0002),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_BRIDGE, 0x0004),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_WLAN_ACCESS_PT, 0x0008),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_ROUTER, 0x0010),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_TELEPHONE, 0x0020),
    (
        &fields::LLDP_TLV_ENABLE_SYSTEM_CAP_DOCSIS_CABLE_DEVICE,
        0x0040,
    ),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_STATION_ONLY, 0x0080),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_CVLAN, 0x0100),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_SVLAN, 0x0200),
    (&fields::LLDP_TLV_ENABLE_SYSTEM_CAP_TPMR, 0x0400),
];

/// One IEEE 802.3 clause 30 PMD auto-negotiation capability bit, in the bit
/// order a 16-bit network-order word exposes.
const PMD_CAPABILITY_BITS: [(&fields::FieldDef, u16); 16] = [
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_TFD,
        0x0001,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_T,
        0x0002,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_XFD,
        0x0004,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_X,
        0x0008,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_BPAUSE,
        0x0010,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_SPAUSE,
        0x0020,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_APAUSE,
        0x0040,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_PAUSE,
        0x0080,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T2FD,
        0x0100,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T2,
        0x0200,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_TXFD,
        0x0400,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_TX,
        0x0800,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T4,
        0x1000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_10BASE_TFD,
        0x2000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_10BASE_T,
        0x4000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_OTHER,
        0x8000,
    ),
];

/// The same sixteen capabilities read with the octet pair swapped, which is
/// what a receiver that treats the field as little-endian reports.
const PMD_CAPABILITY_BITS_INVERSE: [(&fields::FieldDef, u16); 16] = [
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_TFD,
        0x8000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_T,
        0x4000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_XFD,
        0x2000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_X,
        0x1000,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_BPAUSE,
        0x0800,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_SPAUSE,
        0x0400,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_APAUSE,
        0x0200,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_PAUSE,
        0x0100,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T2FD,
        0x0080,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T2,
        0x0040,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_TXFD,
        0x0020,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_TX,
        0x0010,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T4,
        0x0008,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_10BASE_TFD,
        0x0004,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_10BASE_T,
        0x0002,
    ),
    (
        &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_OTHER,
        0x0001,
    ),
];

#[derive(Clone, Copy, Default)]
struct Mandatory {
    chassis: bool,
    port: bool,
    ttl: bool,
}

/// Decode one LLDPDU into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::LLDP_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::LLDP_PROTOCOL, Range::new(base, data.len()));
    let mut mandatory = Mandatory::default();
    let mut offset = 0_usize;
    let mut consumed = 0_usize;
    if data.is_empty() {
        context.mark_malformed(&mut node, "LLDPDU is empty");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    while offset < data.len() {
        if data.len().saturating_sub(offset) < HEADER_LENGTH {
            context.mark_malformed(&mut node, "LLDP TLV header is truncated");
            break;
        }
        let Some(word) = read_u16_be(data, offset) else {
            break;
        };
        let tlv_type = (word >> TYPE_SHIFT) & LENGTH_MASK;
        let length = usize::from(word & LENGTH_MASK);
        let content_start = offset.saturating_add(HEADER_LENGTH);
        let Some(content_end) = content_start.checked_add(length) else {
            break;
        };
        if content_end > data.len() {
            context.mark_field_malformed(
                &mut node,
                "length of contained item exceeds length of containing item",
            );
            break;
        }
        let content = data.get(content_start..content_end).unwrap_or(&[]);
        let header = Range::new(base.saturating_add(offset), HEADER_LENGTH);
        let content_base = base.saturating_add(content_start);
        let mut tlv = Field::container(
            &fields::UNNAMED_CONTAINER,
            Range::new(
                base.saturating_add(offset),
                HEADER_LENGTH.saturating_add(length),
            ),
            Some(String::new()),
        );
        let mut stop = false;
        let mut discard = false;
        if tlv_type == TLV_TTL
            && let Some(ttl) = read_u16_be(content, 0)
        {
            let field = tlv.add_field(
                &fields::LLDP_PDU_TYPE,
                Range::new(base.saturating_add(offset), HEADER_LENGTH.saturating_add(2)),
                Value::None,
            );
            field.showname = Some(if ttl == 0 {
                "Shutdown LLDPDU".to_string()
            } else {
                "Normal LLDPDU".to_string()
            });
            field.generated = true;
            field.raw = Some(RawField {
                bytes: Bytes::from(
                    data.get(offset..offset.saturating_add(4))
                        .unwrap_or_default()
                        .to_vec(),
                ),
                start: base.saturating_add(offset),
                length: 4,
                bitmask: 0,
                field_type: 0,
                source: RawSource::Field,
            });
        }
        add_tlv_header(&mut tlv, header, word, tlv_type);
        tlv.showname = Some(default_tlv_label(tlv_type));

        'tlv: {
            match tlv_type {
                TLV_END => {
                    if !mandatory.ttl {
                        let message = if !mandatory.chassis {
                            "Invalid TLV type (0x00), expected ChassisID type (0x01)"
                        } else if !mandatory.port {
                            "Invalid Port ID (0x00), expected (0x02)"
                        } else {
                            "Invalid Time-to-Live (0x00), expected (0x03)"
                        };
                        reject_tlv(&mut tlv, &fields::LLDP_BAD_TYPE, message);
                        stop = true;
                        break 'tlv;
                    }
                    if length != 0 {
                        let message = format!(
                            "Invalid Length ({length}) for Type (End of LLDPDU), expected (0)"
                        );
                        add_tlv_expert(
                            &mut tlv,
                            "lldp.tlv.len",
                            &fields::LLDP_EXCESS_LENGTH,
                            "LLDP excess TLV length",
                            &message,
                            Group::Malformed,
                        );
                    }
                    consumed = content_end;
                    stop = true;
                    break 'tlv;
                }
                TLV_CHASSIS => {
                    if !mandatory.chassis && offset == 0 {
                        if !decode_chassis(context, &mut node, &mut tlv, content, content_base) {
                            stop = true;
                            break 'tlv;
                        }
                        mandatory.chassis = true;
                    } else if !mandatory.port && !mandatory.ttl {
                        reject_tlv(
                            &mut tlv,
                            &fields::LLDP_BAD_TYPE,
                            "Invalid Port ID (0x01), expected (0x02)",
                        );
                        stop = true;
                        break 'tlv;
                    } else if !decode_chassis(context, &mut node, &mut tlv, content, content_base) {
                        stop = true;
                        break 'tlv;
                    }
                }
                TLV_PORT => {
                    if mandatory.port && !mandatory.ttl {
                        stop = true;
                        break 'tlv;
                    }
                    if !mandatory.chassis {
                        reject_tlv(
                            &mut tlv,
                            &fields::LLDP_BAD_TYPE,
                            "Invalid TLV type (0x02), expected ChassisID type (0x01)",
                        );
                        stop = true;
                        break 'tlv;
                    }
                    if !decode_port(context, &mut node, &mut tlv, content, content_base) {
                        stop = true;
                        break 'tlv;
                    }
                    mandatory.port = true;
                }
                TLV_TTL => {
                    if !mandatory.port {
                        reject_tlv(
                            &mut tlv,
                            &fields::LLDP_BAD_TYPE,
                            "Invalid Port ID (0x03), expected (0x02)",
                        );
                        stop = true;
                        break 'tlv;
                    }
                    if !decode_ttl(context, &mut node, &mut tlv, content, content_base, length) {
                        stop = true;
                        break 'tlv;
                    }
                    mandatory.ttl = true;
                }
                TLV_PORT_DESC | TLV_SYSTEM_NAME | TLV_SYSTEM_DESC => {
                    if !decode_optional_string(&mut tlv, tlv_type, content, content_base) {
                        stop = true;
                        break 'tlv;
                    }
                    if is_shutdown(&node) {
                        add_shutdown_excess(&mut tlv, tlv_type);
                    }
                }
                TLV_SYSTEM_CAP => {
                    if !decode_capabilities(context, &mut node, &mut tlv, content, content_base) {
                        stop = true;
                        break 'tlv;
                    }
                    if is_shutdown(&node) {
                        add_shutdown_excess(&mut tlv, tlv_type);
                    }
                }
                TLV_MANAGEMENT => {
                    if !decode_management(context, &mut node, &mut tlv, content, content_base) {
                        stop = true;
                        break 'tlv;
                    }
                    if is_shutdown(&node) {
                        add_shutdown_excess(&mut tlv, tlv_type);
                    }
                }
                TLV_ORGANIZATION => {
                    if content.len() < 4 {
                        // The OUI and subtype cannot be read, so the TLV is
                        // not reported at all; only the protocol-level
                        // malformed marker remains.
                        context.mark_malformed(&mut node, "LLDP organization TLV is too short");
                        discard = true;
                        stop = true;
                        break 'tlv;
                    }
                    if !decode_organization(context, &mut node, &mut tlv, content, content_base) {
                        stop = true;
                        break 'tlv;
                    }
                    if is_shutdown(&node) {
                        add_shutdown_excess(&mut tlv, tlv_type);
                    }
                }
                // IEEE 802.1AB-2016 clause 8: unrecognized TLV types are ignored,
                // and the following record starts after the declared length.
                _ => {
                    tlv.showname = Some(format!("Unknown TLV ({tlv_type})"));
                }
            }
        }
        if !discard {
            node.fields.push(tlv);
        }
        if stop {
            break;
        }
        offset = content_end;
        consumed = offset;
        if offset >= data.len() {
            break;
        }
    }
    if node.protocol_exception {
        // A malformed TLV ends the decode, but the protocol still spans every
        // captured byte of the PDU; the reference reports the full extent
        // rather than the bytes decoded before the failure.
        node.range = Range::new(base, data.len());
    } else if consumed != 0 {
        node.range = Range::new(base, consumed);
    }
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn default_tlv_label(tlv_type: u16) -> String {
    match tlv_type {
        TLV_END => "End of LLDPDU".to_string(),
        TLV_CHASSIS => "Chassis Id".to_string(),
        TLV_PORT => "Port Id".to_string(),
        TLV_TTL => "Time To Live".to_string(),
        TLV_PORT_DESC => "Port Description".to_string(),
        TLV_SYSTEM_NAME => "System Name".to_string(),
        TLV_SYSTEM_DESC => "System Description".to_string(),
        TLV_SYSTEM_CAP => "Capabilities".to_string(),
        TLV_MANAGEMENT => "Management Address".to_string(),
        TLV_ORGANIZATION => "Organization Specific".to_string(),
        _ => format!("Unknown TLV ({tlv_type})"),
    }
}

/// Mark a TLV that broke the mandatory chassis/port/TTL order.
///
/// The order check runs before the type and length fields are added, so the
/// group carries only the message label and its expert block.
fn reject_tlv(tlv: &mut Field, marker: &'static fields::FieldDef, message: &str) {
    tlv.children.clear();
    tlv.showname = Some(message.to_string());
    tlv.add_expert_for(
        ExpertInfo {
            severity: Severity::Warning,
            group: Group::Malformed,
            message: message.to_string(),
        },
        marker,
    );
}

fn add_tlv_header(tlv: &mut Field, header: Range, word: u16, tlv_type: u16) {
    let field = tlv.add_field(&fields::LLDP_TLV_TYPE, header, Value::Uint16(tlv_type));
    field.showname = Some(format!(
        "{} = TLV Type: {} ({tlv_type})",
        tlv_bit_pattern(16, 0xfe00, u64::from(word)),
        fields::value_name("lldp.tlv.type", u64::from(tlv_type)).unwrap_or("Unknown")
    ));
    let field = tlv.add_field(
        &fields::LLDP_TLV_LEN,
        header,
        Value::Uint16(word & LENGTH_MASK),
    );
    field.showname = Some(format!(
        "{} = TLV Length: {}",
        tlv_bit_pattern(16, 0x01ff, u64::from(word)),
        word & LENGTH_MASK
    ));
}

fn tlv_bit_pattern(width: usize, mask: u64, raw: u64) -> String {
    let mut pattern = String::with_capacity(width + width / 4 + 2);
    for bit in (0..width).rev() {
        let bit_mask = 1_u64 << bit;
        if mask & bit_mask == 0 {
            pattern.push('.');
        } else {
            pattern.push(if raw & bit_mask != 0 { '1' } else { '0' });
        }
        if bit % 4 == 0 && bit != 0 {
            pattern.push(' ');
        }
    }
    pattern
}

/// Add one boolean child of a wider field.
///
/// The showname carries the bit diagram for `width` bits and the field's own
/// true/false words (for example `Capable`/`Not capable`), which is the form
/// the detail view prints for capability bits.
fn add_bit_child(
    parent: &mut Field,
    definition: &'static fields::FieldDef,
    range: Range,
    mask: u16,
    raw: u16,
    width: usize,
) {
    let set = raw & mask != 0;
    let child = parent.add_field(definition, range, Value::Boolean(set));
    let (yes, no) = fields::true_false_name(definition.abbrev).unwrap_or(("True", "False"));
    child.showname = Some(format!(
        "{} = {}: {}",
        tlv_bit_pattern(width, u64::from(mask), u64::from(raw)),
        definition.name,
        if set { yes } else { no }
    ));
}

fn decode_chassis(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    content: &[u8],
    base: usize,
) -> bool {
    if content.is_empty() {
        context.mark_malformed(node, "LLDP chassis ID TLV is empty");
        return false;
    }
    let Some(subtype) = content.first().copied() else {
        return false;
    };
    let subtype_name = value_name_or("lldp.chassis.subtype", u64::from(subtype), "Unknown");
    let subtype_range = Range::new(base, 1);
    tlv.add_field(
        &fields::LLDP_CHASSIS_SUBTYPE,
        subtype_range,
        Value::Uint8(subtype),
    );
    let id = content.get(1..).unwrap_or(&[]);
    let id_start = base.saturating_add(1);
    let mut label = format!("Chassis Subtype = {subtype_name}");

    match subtype {
        CHASSIS_MAC => {
            let Some(address) = array::<6>(content, 1).filter(|_| id.len() == 6) else {
                tlv.showname = Some(label);
                return invalid_fixed_length(
                    context,
                    node,
                    tlv,
                    &format!(
                        "Invalid Chassis ID Length ({}) for Type (MAC address), expected (7)",
                        content.len()
                    ),
                );
            };
            tlv.add_field(
                &fields::LLDP_CHASSIS_ID_MAC,
                Range::new(id_start, 6),
                Value::Ethernet(address),
            );
            label.push_str(&format!(
                ", Id: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                address[0], address[1], address[2], address[3], address[4], address[5]
            ));
        }
        CHASSIS_NETWORK => {
            if !decode_network_address(tlv, id, id_start, true) {
                tlv.showname = Some(label);
                return invalid_fixed_length(
                    context,
                    node,
                    tlv,
                    &format!(
                        "Invalid Chassis ID Length ({}) for a network address",
                        content.len()
                    ),
                );
            }
            label.push_str(&format!(", Id: {}", network_address_text(id)));
        }
        _ => {
            tlv.add_field(
                &fields::LLDP_CHASSIS_ID,
                Range::new(id_start, id.len()),
                Value::bytes(id.to_vec()),
            );
            if !id.is_empty() {
                let text = if subtype == 3 {
                    id.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                } else {
                    string_value(id)
                };
                label.push_str(&format!(", Id: {text}"));
            }
        }
    }
    tlv.showname = Some(label);
    true
}

fn decode_port(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    content: &[u8],
    base: usize,
) -> bool {
    if content.is_empty() {
        context.mark_malformed(node, "LLDP port ID TLV is empty");
        return false;
    }
    let Some(subtype) = content.first().copied() else {
        return false;
    };
    let subtype_name = value_name_or("lldp.port.subtype", u64::from(subtype), "Unknown");
    tlv.add_field(
        &fields::LLDP_PORT_SUBTYPE,
        Range::new(base, 1),
        Value::Uint8(subtype),
    );
    let id = content.get(1..).unwrap_or(&[]);
    let id_start = base.saturating_add(1);
    let mut label = format!("Port Subtype = {subtype_name}");
    match subtype {
        PORT_MAC => {
            let Some(address) = array::<6>(content, 1).filter(|_| id.len() == 6) else {
                tlv.showname = Some(label);
                return invalid_fixed_length(
                    context,
                    node,
                    tlv,
                    &format!("Invalid Port ID Length ({}) for MAC address", content.len()),
                );
            };
            tlv.add_field(
                &fields::LLDP_PORT_ID_MAC,
                Range::new(id_start, 6),
                Value::Ethernet(address),
            );
            label.push_str(&format!(
                ", Id: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                address[0], address[1], address[2], address[3], address[4], address[5]
            ));
        }
        PORT_NETWORK => {
            if !decode_network_address(tlv, id, id_start, false) {
                tlv.showname = Some(label);
                return invalid_fixed_length(
                    context,
                    node,
                    tlv,
                    &format!(
                        "Invalid Port ID Length ({}) for a network address",
                        content.len()
                    ),
                );
            }
            label.push_str(&format!(", Id: {}", network_address_text(id)));
        }
        _ => {
            tlv.add_field(
                &fields::LLDP_PORT_ID,
                Range::new(id_start, id.len()),
                Value::String(string_value(id)),
            );
            if !id.is_empty() {
                let text = if subtype == 2 {
                    id.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                } else {
                    string_value(id)
                };
                label.push_str(&format!(", Id: {text}"));
            }
        }
    }
    tlv.showname = Some(label);
    true
}

fn decode_ttl(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    content: &[u8],
    base: usize,
    length: usize,
) -> bool {
    if content.len() < 2 {
        context.mark_malformed(node, "LLDP time-to-live TLV is too short");
        return false;
    }
    if let Some(ttl) = read_u16_be(content, 0) {
        tlv.add_field(
            &fields::LLDP_TIME_TO_LIVE,
            Range::new(base, 2),
            Value::Uint16(ttl),
        );
        tlv.showname = Some(format!("Time To Live = {ttl} sec"));
    }
    if content.len() != 2 || length != 2 {
        context.mark_malformed(node, "LLDP time-to-live TLV has an invalid length");
        return false;
    }
    true
}

fn decode_capabilities(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    content: &[u8],
    base: usize,
) -> bool {
    if content.len() < 2 {
        context.mark_malformed(node, "LLDP system capabilities TLV is too short");
        return false;
    }
    let Some(capabilities) = read_u16_be(content, 0) else {
        return false;
    };
    let range = Range::new(base, 2);
    let system_cap = tlv.add_container(&fields::LLDP_TLV_SYSTEM_CAP, range, None);
    system_cap.value = Value::Uint16(capabilities);
    for (field, mask) in CAPABILITY_BITS {
        add_bit_child(system_cap, field, range, mask, capabilities, 16);
    }
    if content.len() < 4 {
        context.mark_malformed(node, "LLDP enabled capabilities TLV is too short");
        return false;
    }
    let Some(enabled) = read_u16_be(content, 2) else {
        return false;
    };
    let enabled_range = Range::new(base.saturating_add(2), 2);
    let enabled_cap = tlv.add_container(&fields::LLDP_TLV_ENABLE_SYSTEM_CAP, enabled_range, None);
    enabled_cap.value = Value::Uint16(enabled);
    for (field, mask) in ENABLED_CAPABILITY_BITS {
        add_bit_child(enabled_cap, field, enabled_range, mask, enabled, 16);
    }
    tlv.showname = Some("Capabilities".to_string());
    true
}

fn decode_management(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    content: &[u8],
    base: usize,
) -> bool {
    let mut offset = 0_usize;
    let Some(address_length) = content.first().copied() else {
        context.mark_malformed(node, "LLDP management address TLV is empty");
        return false;
    };
    tlv.add_field(
        &fields::LLDP_MGN_ADDRESS_LEN,
        Range::new(base, 1),
        Value::Uint8(address_length),
    );
    offset = offset.saturating_add(1);
    if address_length == 0 {
        context.mark_malformed(node, "LLDP management address length is zero");
        return false;
    }

    let Some(subtype) = content.get(offset).copied() else {
        context.mark_malformed(node, "LLDP management address subtype is truncated");
        return false;
    };
    tlv.add_field(
        &fields::LLDP_MGN_ADDRESS_SUBTYPE,
        Range::new(base.saturating_add(offset), 1),
        Value::Uint8(subtype),
    );
    offset = offset.saturating_add(1);

    let address_bytes = usize::from(address_length).saturating_sub(1);
    let Some(address_end) = offset.checked_add(address_bytes) else {
        return false;
    };
    let Some(address) = content.get(offset..address_end) else {
        context.mark_malformed(node, "LLDP management address is truncated");
        return false;
    };
    let address_start = base.saturating_add(offset);
    match subtype {
        ADDRESS_IPV4 if address.len() == 4 => {
            if let Some(value) = array::<4>(address, 0) {
                tlv.add_field(
                    &fields::LLDP_MGN_ADDR_IP4,
                    Range::new(address_start, 4),
                    Value::Ipv4(value),
                );
            }
        }
        ADDRESS_IPV6 if address.len() == 16 => {
            if let Some(value) = array::<16>(address, 0) {
                tlv.add_field(
                    &fields::LLDP_MGN_ADDR_IP6,
                    Range::new(address_start, 16),
                    Value::Ipv6(value),
                );
            }
        }
        _ => {
            tlv.add_field(
                &fields::LLDP_MGN_ADDR_HEX,
                Range::new(address_start, address.len()),
                Value::bytes(address.to_vec()),
            );
        }
    }
    offset = address_end;

    let Some(interface_subtype) = content.get(offset).copied() else {
        context.mark_malformed(node, "LLDP management interface subtype is truncated");
        return false;
    };
    tlv.add_field(
        &fields::LLDP_MGN_INTERFACE_SUBTYPE,
        Range::new(base.saturating_add(offset), 1),
        Value::Uint8(interface_subtype),
    );
    offset = offset.saturating_add(1);
    let Some(interface_number) = read_u32_be(content, offset) else {
        context.mark_malformed(node, "LLDP management interface number is truncated");
        return false;
    };
    tlv.add_field(
        &fields::LLDP_MGN_INTERFACE_NUMBER,
        Range::new(base.saturating_add(offset), 4),
        Value::Uint32(interface_number),
    );
    offset = offset.saturating_add(4);

    let Some(oid_length) = content.get(offset).copied() else {
        context.mark_malformed(node, "LLDP management OID length is truncated");
        return false;
    };
    tlv.add_field(
        &fields::LLDP_MGN_OBJ_LEN,
        Range::new(base.saturating_add(offset), 1),
        Value::Uint8(oid_length),
    );
    offset = offset.saturating_add(1);
    let oid_bytes = usize::from(oid_length);
    let Some(oid_end) = offset.checked_add(oid_bytes) else {
        return false;
    };
    let Some(oid) = content.get(offset..oid_end) else {
        context.mark_malformed(node, "LLDP management OID is truncated");
        return false;
    };
    if !oid.is_empty() {
        let text = oid_text(oid);
        let field = tlv.add_field(
            &fields::LLDP_MGN_OBJ_ID,
            Range::new(base.saturating_add(offset), oid.len()),
            Value::String(text.clone()),
        );
        let resolved = oid_resolved_text(&text);
        field.showname = Some(format!("Object Identifier: {text} ({resolved})"));
    }
    if oid_end != content.len() {
        context.mark_malformed(node, "LLDP management OID length does not match the TLV");
        return false;
    }
    tlv.showname = Some("Management Address".to_string());
    true
}

fn decode_organization(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    content: &[u8],
    base: usize,
) -> bool {
    if content.len() < 4 {
        context.mark_malformed(node, "LLDP organization TLV is too short");
        return false;
    }
    let Some(oui) = read_oui(content) else {
        return false;
    };
    let oui_range = Range::new(base, 3);
    let oui_name = lldp_oui_name(oui);
    tlv.add_field(&fields::LLDP_ORGTLV_OUI, oui_range, Value::Uint32(oui));
    let Some(subtype) = content.get(3).copied() else {
        return false;
    };
    let body = content.get(4..).unwrap_or(&[]);
    let body_start = base.saturating_add(4);
    let subtype_name = match oui {
        OUI_IEEE_802_1 => value_name_or("lldp.ieee.802_1.subtype", u64::from(subtype), "Unknown"),
        OUI_IEEE_802_3 => value_name_or("lldp.ieee.802_3.subtype", u64::from(subtype), "Unknown"),
        _ => "Unknown",
    };
    let label = match oui {
        OUI_IEEE_802_1 | OUI_IEEE_802_3 => format!("{oui_name} - {subtype_name}"),
        _ => format!("{oui_name} - {subtype_name} ({subtype})"),
    };
    match oui {
        OUI_IEEE_802_1 => {
            let subtype_field = tlv.add_field(
                &fields::LLDP_IEEE_802_1_SUBTYPE,
                Range::new(base.saturating_add(3), 1),
                Value::Uint8(subtype),
            );
            let _ = subtype_field;
            let decoded = decode_ieee_802_1(context, node, tlv, subtype, body, body_start);
            tlv.showname = Some(label);
            decoded
        }
        OUI_IEEE_802_3 => {
            let subtype_field = tlv.add_field(
                &fields::LLDP_IEEE_802_3_SUBTYPE,
                Range::new(base.saturating_add(3), 1),
                Value::Uint8(subtype),
            );
            if subtype == 3 {
                subtype_field.add_expert_for(
                    ExpertInfo {
                        severity: Severity::Warning,
                        group: Group::Protocol,
                        message: "TLV has been deprecated".to_string(),
                    },
                    &fields::LLDP_TLV_DEPRECATED,
                );
                tlv.add_field(&fields::LLDP_TLV_DEPRECATED, Range::new(0, 0), Value::None)
                    .hide();
            }
            let decoded = decode_ieee_802_3(context, node, tlv, subtype, body, body_start);
            tlv.showname = Some(label);
            decoded
        }
        _ => {
            tlv.add_field(
                &fields::LLDP_UNKNOWN_SUBTYPE,
                Range::new(base.saturating_add(3), 1),
                Value::Uint8(subtype),
            );
            if !body.is_empty() {
                tlv.add_field(
                    &fields::LLDP_UNKNOWN_SUBTYPE_CONTENT,
                    Range::new(body_start, body.len()),
                    Value::bytes(body.to_vec()),
                );
            }
            tlv.showname = Some(label);
            true
        }
    }
}

fn value_name_or(abbrev: &str, value: u64, fallback: &'static str) -> &'static str {
    fields::value_name(abbrev, value).unwrap_or(fallback)
}

fn lldp_oui_name(oui: u32) -> &'static str {
    match oui {
        OUI_IEEE_802_1 => "IEEE 802.1 Chair",
        OUI_IEEE_802_3 => "IEEE 802.3 Working Group",
        _ => "Unknown",
    }
}

fn decode_ieee_802_1(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    subtype: u8,
    body: &[u8],
    body_start: usize,
) -> bool {
    match subtype {
        1 => {
            let Some(port_vlan) = read_u16_be(body, 0).filter(|_| body.len() >= 2) else {
                context.mark_malformed(node, "IEEE 802.1 port VLAN TLV is too short");
                return false;
            };
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_PORT_VLAN_ID,
                Range::new(body_start, 2),
                Value::Uint16(port_vlan),
            );
            true
        }
        2 => {
            let Some(flags) = body.first().copied().filter(|_| body.len() >= 3) else {
                context.mark_malformed(node, "IEEE 802.1 port and protocol VLAN TLV is too short");
                return false;
            };
            let range = Range::new(body_start, 1);
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG,
                range,
                Value::Uint8(flags),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG_SUPPORTED,
                range,
                Value::Boolean(flags & 0x02 != 0),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG_ENABLED,
                range,
                Value::Boolean(flags & 0x04 != 0),
            );
            if let Some(port_proto_vlan) = read_u16_be(body, 1) {
                tlv.add_field(
                    &fields::LLDP_IEEE_802_1_PORT_PROTO_VLAN_ID,
                    Range::new(body_start.saturating_add(1), 2),
                    Value::Uint16(port_proto_vlan),
                );
            }
            true
        }
        3 => {
            let (Some(vlan), Some(name_length)) = (read_u16_be(body, 0), body.get(2).copied())
            else {
                context.mark_malformed(node, "IEEE 802.1 VLAN name TLV is too short");
                return false;
            };
            let Some(name) = body.get(3..3_usize.saturating_add(usize::from(name_length))) else {
                context.mark_malformed(node, "IEEE 802.1 VLAN name is truncated");
                return false;
            };
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_VLAN_ID,
                Range::new(body_start, 2),
                Value::Uint16(vlan),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_VLAN_NAME_LEN,
                Range::new(body_start.saturating_add(2), 1),
                Value::Uint8(name_length),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_VLAN_NAME,
                Range::new(body_start.saturating_add(3), name.len()),
                Value::String(string_value(name)),
            );
            true
        }
        4 => {
            let Some(id_length) = body.first().copied() else {
                context.mark_malformed(node, "IEEE 802.1 protocol identity TLV is too short");
                return false;
            };
            let Some(id) = body.get(1..1_usize.saturating_add(usize::from(id_length))) else {
                context.mark_malformed(node, "IEEE 802.1 protocol identity is truncated");
                return false;
            };
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_PROTO_ID_LENGTH,
                Range::new(body_start, 1),
                Value::Uint8(id_length),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_PROTO_ID,
                Range::new(body_start.saturating_add(1), id.len()),
                Value::bytes(id.to_vec()),
            );
            true
        }
        7 => {
            let (Some(status), Some(port)) = (body.first().copied(), read_u32_be(body, 1)) else {
                context.mark_malformed(node, "IEEE 802.1 link aggregation TLV is too short");
                return false;
            };
            let range = Range::new(body_start, 1);
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_AGGREGATION_STATUS,
                range,
                Value::Uint8(status),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_AGGREGATION_STATUS_CAP,
                range,
                Value::Boolean(status & 0x01 != 0),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_AGGREGATION_STATUS_ENABLED,
                range,
                Value::Boolean(status & 0x02 != 0),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_AGGREGATION_STATUS_PORTTYPE,
                range,
                Value::Uint8((status & 0x0c) >> 2),
            );
            tlv.add_field(
                &fields::LLDP_IEEE_802_1_AGGREGATED_PORT_ID,
                Range::new(body_start.saturating_add(1), 4),
                Value::Uint32(port),
            );
            true
        }
        _ => true,
    }
}

fn decode_ieee_802_3(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    subtype: u8,
    body: &[u8],
    body_start: usize,
) -> bool {
    match subtype {
        1 => {
            // IEEE 802.1AB-2016 clause 8.5.5: one octet of auto-negotiation
            // support/status, a two-octet capability word and a two-octet
            // operational MAU type. Fields present before a short body are
            // kept; the decoder still reports that the TLV stopped early.
            if let Some(autonegotiation) = body.first().copied() {
                let range = Range::new(body_start, 1);
                let status = tlv.add_container(
                    &fields::LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS,
                    range,
                    None,
                );
                status.value = Value::Uint8(autonegotiation);
                add_bit_child(
                    status,
                    &fields::LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS_SUPPORTED,
                    range,
                    0x01,
                    u16::from(autonegotiation),
                    8,
                );
                add_bit_child(
                    status,
                    &fields::LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS_ENABLED,
                    range,
                    0x02,
                    u16::from(autonegotiation),
                    8,
                );
            }
            if let Some(capabilities) = read_u16_be(body, 1) {
                let range = Range::new(body_start.saturating_add(1), 2);
                let caps = tlv.add_container(
                    &fields::LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS,
                    range,
                    None,
                );
                caps.value = Value::Uint16(capabilities);
                for (field, mask) in PMD_CAPABILITY_BITS {
                    add_bit_child(caps, field, range, mask, capabilities, 16);
                }
                let inverse =
                    tlv.add_unnamed(range, "Same in inverse (wrong) bitorder".to_string());
                for (field, mask) in PMD_CAPABILITY_BITS_INVERSE {
                    add_bit_child(inverse, field, range, mask, capabilities, 16);
                }
            }
            if let Some(mau) = read_u16_be(body, 3) {
                tlv.add_field(
                    &fields::LLDP_IEEE_802_3_PMD_MAU_TYPE,
                    Range::new(body_start.saturating_add(3), 2),
                    Value::Uint16(mau),
                );
            }
            if body.len() < 5 {
                context.mark_malformed(node, "IEEE 802.3 MAC/PHY TLV is too short");
                return false;
            }
            if body.len() > 5 {
                mark_excess_length(tlv, body_start.saturating_add(5), body.len() - 5);
            }
            true
        }
        3 => {
            // IEEE 802.1AB-2016 clause 8.5.6: one status octet and a
            // four-octet aggregated port identifier.
            if let Some(status) = body.first().copied() {
                let range = Range::new(body_start, 1);
                let aggregation =
                    tlv.add_container(&fields::LLDP_IEEE_802_3_AGGREGATION_STATUS, range, None);
                aggregation.value = Value::Uint8(status);
                add_bit_child(
                    aggregation,
                    &fields::LLDP_IEEE_802_3_AGGREGATION_STATUS_CAP,
                    range,
                    0x01,
                    u16::from(status),
                    8,
                );
                add_bit_child(
                    aggregation,
                    &fields::LLDP_IEEE_802_3_AGGREGATION_STATUS_ENABLED,
                    range,
                    0x02,
                    u16::from(status),
                    8,
                );
            }
            if let Some(port) = read_u32_be(body, 1) {
                tlv.add_field(
                    &fields::LLDP_IEEE_802_3_AGGREGATED_PORT_ID,
                    Range::new(body_start.saturating_add(1), 4),
                    Value::Uint32(port),
                );
            }
            if body.len() < 5 {
                context.mark_malformed(node, "IEEE 802.3 link aggregation TLV is too short");
                return false;
            }
            if body.len() > 5 {
                mark_excess_length(tlv, body_start.saturating_add(5), body.len() - 5);
            }
            true
        }
        4 => {
            // IEEE 802.1AB-2016 clause 8.5.7: a two-octet maximum frame size.
            if let Some(maximum) = read_u16_be(body, 0) {
                tlv.add_field(
                    &fields::LLDP_IEEE_802_3_MAX_FRAME_SIZE,
                    Range::new(body_start, 2),
                    Value::Uint16(maximum),
                );
            }
            if body.len() < 2 {
                context.mark_malformed(node, "IEEE 802.3 maximum frame size TLV is too short");
                return false;
            }
            if body.len() > 2 {
                mark_excess_length(tlv, body_start.saturating_add(2), body.len() - 2);
            }
            true
        }
        _ => true,
    }
}

fn decode_network_address(tlv: &mut Field, body: &[u8], start: usize, chassis: bool) -> bool {
    let Some(family) = body.first().copied() else {
        return false;
    };
    let address = body.get(1..).unwrap_or(&[]);
    let address_start = start.saturating_add(1);
    tlv.add_field(
        &fields::LLDP_NETWORK_ADDRESS_SUBTYPE,
        Range::new(start, 1),
        Value::Uint8(family),
    );
    match family {
        ADDRESS_IPV4 if address.len() == 4 => {
            let Some(value) = array::<4>(address, 0) else {
                return false;
            };
            let field = if chassis {
                &fields::LLDP_CHASSIS_ID_IP4
            } else {
                &fields::LLDP_PORT_ID_IP4
            };
            tlv.add_field(field, Range::new(address_start, 4), Value::Ipv4(value));
        }
        ADDRESS_IPV6 if address.len() == 16 => {
            let Some(value) = array::<16>(address, 0) else {
                return false;
            };
            let field = if chassis {
                &fields::LLDP_CHASSIS_ID_IP6
            } else {
                &fields::LLDP_PORT_ID_IP6
            };
            tlv.add_field(field, Range::new(address_start, 16), Value::Ipv6(value));
        }
        _ => return false,
    }
    true
}

fn invalid_fixed_length(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    tlv: &mut Field,
    message: &str,
) -> bool {
    add_tlv_expert(
        tlv,
        "lldp.tlv.len",
        &fields::LLDP_INCORRECT_LENGTH,
        "LLDP incorrect TLV length",
        message,
        Group::Malformed,
    );
    let _ = (context, node);
    false
}

/// Report bytes beyond the fixed length of an organizationally specific TLV.
///
/// The expert belongs to an unnamed group spanning the extra bytes, not to
/// the TLV length field, so the detail view prints it after the decoded
/// sub-fields; `lldp.excess_length` is its zero-length marker.
fn mark_excess_length(tlv: &mut Field, start: usize, length: usize) {
    let group = tlv.add_unnamed(
        Range::new(start, length),
        "Invalid length, greater than expected".to_string(),
    );
    group.add_expert_for(
        ExpertInfo {
            severity: Severity::Warning,
            group: Group::Malformed,
            message: "Invalid length, greater than expected".to_string(),
        },
        &fields::LLDP_EXCESS_LENGTH,
    );
}

fn add_tlv_expert(
    tlv: &mut Field,
    offending: &str,
    marker: &'static fields::FieldDef,
    marker_showname: &str,
    message: &str,
    group: Group,
) {
    if let Some(field) = tlv
        .children
        .iter_mut()
        .rev()
        .find(|field| field.def.abbrev == offending)
    {
        field.add_expert_for(
            ExpertInfo {
                severity: Severity::Warning,
                group,
                message: message.to_string(),
            },
            marker,
        );
    }
    let occurrence = tlv.add_field(marker, Range::new(0, 0), Value::None);
    occurrence.hide();
    occurrence.showname = Some(marker_showname.to_string());
}

fn add_shutdown_excess(tlv: &mut Field, tlv_type: u16) {
    add_tlv_expert(
        tlv,
        "lldp.time_to_live",
        &fields::LLDP_EXCESS_TLV,
        "LLDP TLV not allowed in Shutdown PDU",
        &format!("TLV type 0x{tlv_type:02x} not allowed in Shutdown PDU"),
        Group::Malformed,
    );
}

fn is_shutdown(node: &Node) -> bool {
    node.fields.iter().any(field_tree_has_ttl_zero)
}

fn field_tree_has_ttl_zero(field: &Field) -> bool {
    field_contains_u64(field, "lldp.time_to_live", 0)
        || field.children.iter().any(field_tree_has_ttl_zero)
}

fn field_contains_u64(field: &Field, abbrev: &str, expected: u64) -> bool {
    if field.def.abbrev != abbrev {
        return false;
    }
    match field.value {
        Value::Uint8(value) => u64::from(value) == expected,
        Value::Uint16(value) => u64::from(value) == expected,
        _ => false,
    }
}

fn decode_optional_string(tlv: &mut Field, tlv_type: u16, content: &[u8], base: usize) -> bool {
    let (field, label) = match tlv_type {
        TLV_PORT_DESC => (&fields::LLDP_PORT_DESC, "Port Description"),
        TLV_SYSTEM_NAME => (&fields::LLDP_TLV_SYSTEM_NAME, "System Name"),
        _ => (&fields::LLDP_TLV_SYSTEM_DESC, "System Description"),
    };
    let text = string_value(content);
    tlv.add_field(
        field,
        Range::new(base, content.len()),
        Value::String(text.clone()),
    );
    tlv.showname = Some(format!("{label} = {text}"));
    true
}

fn string_value(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or(&[])).into_owned()
}

/// Render a BER OID with its root arc resolved to a name.
fn oid_resolved_text(text: &str) -> String {
    if let Some(rest) = text.strip_prefix("2.") {
        format!("joint-iso-itu-t.{rest}")
    } else if let Some(rest) = text.strip_prefix("1.") {
        format!("iso.{rest}")
    } else {
        text.to_string()
    }
}

/// Render a BER object identifier as dotted decimal.
///
/// The first octet encodes the first two arcs as `40 * first + second`;
/// later arcs use a continuation bit. The walk is bounded by the field's
/// declared length.
fn oid_text(bytes: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value = 0_u64;
    for byte in bytes {
        value = value
            .saturating_mul(128)
            .saturating_add(u64::from(byte & 0x7f));
        if byte & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    if value != 0 {
        arcs.push(value);
    }
    let Some(first) = arcs.first().copied() else {
        return String::new();
    };
    let mut parts: Vec<u64> = Vec::with_capacity(arcs.len().saturating_add(1));
    if first < 40 {
        parts.push(0);
        parts.push(first);
    } else if first < 80 {
        parts.push(1);
        parts.push(first.saturating_sub(40));
    } else {
        parts.push(2);
        parts.push(first.saturating_sub(80));
    }
    parts.extend(arcs.iter().skip(1).copied());
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn network_address_text(id: &[u8]) -> String {
    let Some((family, address)) = id.split_first() else {
        return String::new();
    };
    match (family, address.len()) {
        (1, 4) => {
            let bytes: [u8; 4] = address.try_into().unwrap_or([0; 4]);
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        (2, 16) => {
            let bytes: [u8; 16] = address.try_into().unwrap_or([0; 16]);
            ipv6_text(&bytes)
        }
        _ => address
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    }
}

fn ipv6_text(address: &[u8; 16]) -> String {
    std::net::Ipv6Addr::from(*address).to_string()
}

fn read_oui(data: &[u8]) -> Option<u32> {
    let bytes = data.get(..3)?;
    Some(
        (u32::from(*bytes.first()?) << 16)
            | (u32::from(*bytes.get(1)?) << 8)
            | u32::from(*bytes.get(2)?),
    )
}
