//! IEEE 802.1D, 802.1w and 802.1s Spanning Tree Protocol.
//!
//! STP BPDUs travel over LLC with DSAP and SSAP 0x42, or inside a SNAP
//! frame with Cisco's PVST+ protocol identifier. The common header is the
//! 802.1D configuration BPDU (clause 9): protocol identifier, version, BPDU
//! type, flags, root and bridge identifiers, port identifier and four
//! 1/256-second timers. RSTP adds a version-1 length octet (802.1w clause
//! 9.3); MSTP appends the version-3 length and the MST configuration
//! (802.1s clause 13.8). Every step is bounded by the captured BPDU.

use crate::decode::DecodeContext;
use crate::decode::bytes::{array, read_u16_be, read_u32_be};
use crate::fields;
use crate::tree::{ExpertInfo, Group, Node, Range, Severity, Value};

const PROTOCOL_LENGTH: usize = 4;
const FLAGS_OFFSET: usize = 4;
const ROOT_OFFSET: usize = 5;
const ROOT_COST_OFFSET: usize = 13;
const BRIDGE_OFFSET: usize = 17;
const PORT_OFFSET: usize = 25;
const TIMER_OFFSET: usize = 27;
const VERSION_1_LENGTH_OFFSET: usize = 35;
const VERSION_3_LENGTH_OFFSET: usize = 36;
const MST_EXTENSION_OFFSET: usize = 38;
const MST_FIXED_LENGTH: usize = 64;
const MSTI_LENGTH: usize = 16;

const BPDU_CONFIGURATION: u8 = 0x00;
const BPDU_RAPID: u8 = 0x02;
const BPDU_TOPOLOGY_CHANGE: u8 = 0x80;

const FLAG_TCACK: u8 = 0x80;
const FLAG_AGREEMENT: u8 = 0x40;
const FLAG_FORWARDING: u8 = 0x20;
const FLAG_LEARNING: u8 = 0x10;
const FLAG_PORT_ROLE: u8 = 0x0c;
const FLAG_PROPOSAL: u8 = 0x02;
const FLAG_TC: u8 = 0x01;

const FLAG_BITS: [(&fields::FieldDef, u8); 7] = [
    (&fields::STP_FLAGS_TCACK, FLAG_TCACK),
    (&fields::STP_FLAGS_AGREEMENT, FLAG_AGREEMENT),
    (&fields::STP_FLAGS_FORWARDING, FLAG_FORWARDING),
    (&fields::STP_FLAGS_LEARNING, FLAG_LEARNING),
    (&fields::STP_FLAGS_PORT_ROLE, FLAG_PORT_ROLE),
    (&fields::STP_FLAGS_PROPOSAL, FLAG_PROPOSAL),
    (&fields::STP_FLAGS_TC, FLAG_TC),
];

/// Decode one spanning-tree BPDU into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::STP_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::STP_PROTOCOL, Range::new(base, data.len()));
    if data.len() < PROTOCOL_LENGTH {
        context.mark_malformed(&mut node, "Spanning Tree BPDU is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }
    let Some(protocol) = read_u16_be(data, 0) else {
        return;
    };
    let Some(version) = data.get(2).copied() else {
        return;
    };
    let Some(bpdu_type) = data.get(3).copied() else {
        return;
    };
    node.add_field(
        &fields::STP_PROTOCOL_ID,
        Range::new(base, 2),
        Value::Uint16(protocol),
    );
    node.add_field(
        &fields::STP_VERSION,
        Range::new(base.saturating_add(2), 1),
        Value::Uint8(version),
    );
    if !matches!(version, 0 | 2 | 3 | 4) {
        node.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Protocol,
            message: "Unknown protocol version; versions 0, 2, 3 and 4 are decoded".to_string(),
        });
    }
    node.add_field(
        &fields::STP_TYPE,
        Range::new(base.saturating_add(3), 1),
        Value::Uint8(bpdu_type),
    );

    match bpdu_type {
        BPDU_TOPOLOGY_CHANGE => {}
        BPDU_CONFIGURATION | BPDU_RAPID => {
            decode_configuration(context, &mut node, data, base, version);
        }
        _ => {
            node.add_field(
                &fields::STP_TYPE_UNKNOWN,
                Range::new(0, 0),
                Value::String(String::new()),
            );
            node.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: "Unknown BPDU type data".to_string(),
            });
        }
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn decode_configuration(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    version: u8,
) {
    let Some(flags) = data.get(FLAGS_OFFSET).copied() else {
        context.mark_malformed(node, "Spanning Tree BPDU is truncated");
        return;
    };
    let flags_range = Range::new(base.saturating_add(FLAGS_OFFSET), 1);
    node.add_field(&fields::STP_FLAGS, flags_range, Value::Uint8(flags));
    decode_flags(node, flags, flags_range, version != 0);

    if !decode_identifier(
        node,
        data,
        base,
        ROOT_OFFSET,
        &fields::STP_ROOT_PRIO,
        &fields::STP_ROOT_EXT,
        &fields::STP_ROOT_HW,
    ) {
        context.mark_malformed(node, "Spanning Tree root identifier is truncated");
        return;
    }
    let Some(root_cost) = read_u32_be(data, ROOT_COST_OFFSET) else {
        context.mark_malformed(node, "Spanning Tree root path cost is truncated");
        return;
    };
    node.add_field(
        &fields::STP_ROOT_COST,
        Range::new(base.saturating_add(ROOT_COST_OFFSET), 4),
        Value::Uint32(root_cost),
    );
    if !decode_identifier(
        node,
        data,
        base,
        BRIDGE_OFFSET,
        &fields::STP_BRIDGE_PRIO,
        &fields::STP_BRIDGE_EXT,
        &fields::STP_BRIDGE_HW,
    ) {
        context.mark_malformed(node, "Spanning Tree bridge identifier is truncated");
        return;
    }
    let Some(port) = read_u16_be(data, PORT_OFFSET) else {
        context.mark_malformed(node, "Spanning Tree port identifier is truncated");
        return;
    };
    node.add_field(
        &fields::STP_PORT,
        Range::new(base.saturating_add(PORT_OFFSET), 2),
        Value::Uint16(port),
    );
    if !decode_timers(context, node, data, base) {
        return;
    }
    if version < 1 {
        return;
    }
    let Some(version_1_length) = data.get(VERSION_1_LENGTH_OFFSET).copied() else {
        context.mark_malformed(node, "Spanning Tree version 1 length is truncated");
        return;
    };
    if version >= 2 {
        node.add_field(
            &fields::STP_VERSION_1_LENGTH,
            Range::new(base.saturating_add(VERSION_1_LENGTH_OFFSET), 1),
            Value::Uint8(version_1_length),
        );
    }
    if version != 3 || version_1_length != 0 {
        return;
    }
    decode_mst_extension(context, node, data, base);
}

/// Add the flag subfields exposed for this BPDU version.
///
/// An 802.1D configuration BPDU carries only the topology-change and
/// topology-change-acknowledgement bits (clause 9.3.1); RSTP and MSTP add the
/// role, proposal, agreement, learning and forwarding bits.
fn decode_flags(node: &mut Node, flags: u8, range: Range, full: bool) {
    for (field, mask) in FLAG_BITS {
        if !full && mask != FLAG_TCACK && mask != FLAG_TC {
            continue;
        }
        if mask == FLAG_PORT_ROLE {
            node.add_field(field, range, Value::Uint8((flags & FLAG_PORT_ROLE) >> 2));
        } else {
            node.add_field(field, range, Value::Boolean(flags & mask != 0));
        }
    }
}

fn decode_identifier(
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    priority: &'static fields::FieldDef,
    extension: &'static fields::FieldDef,
    hardware: &'static fields::FieldDef,
) -> bool {
    let Some(priority_value) = read_u16_be(data, offset) else {
        return false;
    };
    let Some(address) = array::<6>(data, offset.saturating_add(2)) else {
        return false;
    };
    node.add_field(
        priority,
        Range::new(base.saturating_add(offset), 1),
        Value::Uint16(priority_value),
    );
    node.add_field(
        extension,
        Range::new(base.saturating_add(offset), 2),
        Value::Uint16(priority_value & 0x0fff),
    );
    node.add_field(
        hardware,
        Range::new(base.saturating_add(offset).saturating_add(2), 6),
        Value::Ethernet(address),
    );
    true
}

fn decode_timers(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
) -> bool {
    let fields = [
        (&fields::STP_MSG_AGE, TIMER_OFFSET),
        (&fields::STP_MAX_AGE, TIMER_OFFSET.saturating_add(2)),
        (&fields::STP_HELLO, TIMER_OFFSET.saturating_add(4)),
        (&fields::STP_FORWARD, TIMER_OFFSET.saturating_add(6)),
    ];
    for (field, offset) in fields {
        let Some(value) = read_u16_be(data, offset) else {
            context.mark_malformed(node, "Spanning Tree timer is truncated");
            return false;
        };
        node.add_field(
            field,
            Range::new(base.saturating_add(offset), 2),
            Value::Uint16(value),
        );
    }
    true
}

fn decode_mst_extension(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
) {
    let Some(version_3_length) = read_u16_be(data, VERSION_3_LENGTH_OFFSET) else {
        context.mark_malformed(node, "Spanning Tree version 3 length is truncated");
        return;
    };
    if usize::from(version_3_length) < MST_FIXED_LENGTH {
        return;
    }
    node.add_field(
        &fields::MSTP_VERSION_3_LENGTH,
        Range::new(base.saturating_add(VERSION_3_LENGTH_OFFSET), 2),
        Value::Uint16(version_3_length),
    );
    let remainder = usize::from(version_3_length).saturating_sub(MST_FIXED_LENGTH) % MSTI_LENGTH;
    if remainder != 0 {
        context.mark_malformed(node, "Spanning Tree MST extension has a partial record");
    }
    let declared_end = MST_EXTENSION_OFFSET.saturating_add(usize::from(version_3_length));
    let extension_end = declared_end.min(data.len());
    if declared_end > data.len() {
        context.mark_malformed(node, "Spanning Tree MST extension is truncated");
    }
    let extension = data.get(MST_EXTENSION_OFFSET..extension_end).unwrap_or(&[]);
    let extension_base = base.saturating_add(MST_EXTENSION_OFFSET);
    if extension.len() < MST_FIXED_LENGTH {
        context.mark_malformed(node, "Spanning Tree MST configuration is truncated");
        return;
    }
    let Some(selector) = extension.first().copied() else {
        return;
    };
    let Some(name) = extension.get(1..33) else {
        return;
    };
    let Some(revision) = read_u16_be(extension, 33) else {
        return;
    };
    let Some(digest) = extension.get(35..51) else {
        return;
    };
    let Some(cist_cost) = read_u32_be(extension, 51) else {
        return;
    };
    let Some(cist_priority) = extension.get(55).copied() else {
        return;
    };
    let Some(cist_extension) = read_u16_be(extension, 55) else {
        return;
    };
    let Some(cist_address) = array::<6>(extension, 57) else {
        return;
    };
    let Some(cist_hops) = extension.get(63).copied() else {
        return;
    };
    node.add_field(
        &fields::MSTP_CONFIG_FORMAT_SELECTOR,
        Range::new(extension_base, 1),
        Value::Uint8(selector),
    );
    node.add_field(
        &fields::MSTP_CONFIG_NAME,
        Range::new(extension_base.saturating_add(1), 32),
        Value::String(padded_string(name)),
    );
    node.add_field(
        &fields::MSTP_CONFIG_REVISION_LEVEL,
        Range::new(extension_base.saturating_add(33), 2),
        Value::Uint16(revision),
    );
    node.add_field(
        &fields::MSTP_CONFIG_DIGEST,
        Range::new(extension_base.saturating_add(35), 16),
        Value::bytes(digest.to_vec()),
    );
    node.add_field(
        &fields::MSTP_CIST_INTERNAL_ROOT_PATH_COST,
        Range::new(extension_base.saturating_add(51), 4),
        Value::Uint32(cist_cost),
    );
    node.add_field(
        &fields::MSTP_CIST_BRIDGE_PRIO,
        Range::new(extension_base.saturating_add(55), 1),
        Value::Uint16(u16::from(cist_priority) << 8),
    );
    node.add_field(
        &fields::MSTP_CIST_BRIDGE_EXT,
        Range::new(extension_base.saturating_add(55), 2),
        Value::Uint16(cist_extension & 0x0fff),
    );
    node.add_field(
        &fields::MSTP_CIST_BRIDGE_HW,
        Range::new(extension_base.saturating_add(57), 6),
        Value::Ethernet(cist_address),
    );
    node.add_field(
        &fields::MSTP_CIST_REMAINING_HOPS,
        Range::new(extension_base.saturating_add(63), 1),
        Value::Uint8(cist_hops),
    );

    let record_count = usize::from(version_3_length)
        .saturating_sub(MST_FIXED_LENGTH)
        .div_euclid(MSTI_LENGTH);
    for index in 0..record_count {
        let offset = MST_FIXED_LENGTH.saturating_add(index.saturating_mul(MSTI_LENGTH));
        let Some(record) = extension.get(offset..offset.saturating_add(MSTI_LENGTH)) else {
            context.mark_malformed(node, "Spanning Tree MSTI record is truncated");
            return;
        };
        let record_base = extension_base.saturating_add(offset);
        decode_msti(node, record, record_base);
    }
}

fn decode_msti(node: &mut Node, record: &[u8], base: usize) {
    let Some(flags) = record.first().copied() else {
        return;
    };
    let flags_range = Range::new(base, 1);
    node.add_field(&fields::MSTP_MSTI_FLAGS, flags_range, Value::Uint8(flags));
    decode_flags(node, flags, flags_range, true);
    let Some(priority) = record.get(1).copied() else {
        return;
    };
    let Some(identifier) = read_u16_be(record, 1) else {
        return;
    };
    let Some(root_address) = array::<6>(record, 3) else {
        return;
    };
    let Some(root_cost) = read_u32_be(record, 9) else {
        return;
    };
    let Some(bridge_priority) = record.get(13).copied() else {
        return;
    };
    let Some(port_priority) = record.get(14).copied() else {
        return;
    };
    let Some(remaining_hops) = record.get(15).copied() else {
        return;
    };
    node.add_field(
        &fields::MSTP_MSTI_PRIORITY,
        Range::new(base.saturating_add(1), 1),
        Value::Uint8((priority & 0xf0) >> 4),
    );
    node.add_field(
        &fields::MSTP_MSTI_MSTI_ID,
        Range::new(base.saturating_add(1), 2),
        Value::Uint16(identifier & 0x0fff),
    );
    node.add_field(
        &fields::MSTP_MSTI_ROOT_HW,
        Range::new(base.saturating_add(3), 6),
        Value::Ethernet(root_address),
    );
    node.add_field(
        &fields::MSTP_MSTI_ROOT_COST,
        Range::new(base.saturating_add(9), 4),
        Value::Uint32(root_cost),
    );
    node.add_field(
        &fields::MSTP_MSTI_BRIDGE_PRIORITY,
        Range::new(base.saturating_add(13), 1),
        Value::Uint8((bridge_priority & 0xf0) >> 4),
    );
    node.add_field(
        &fields::MSTP_MSTI_PORT_PRIORITY,
        Range::new(base.saturating_add(14), 1),
        Value::Uint8((port_priority & 0xf0) >> 4),
    );
    node.add_field(
        &fields::MSTP_MSTI_REMAINING_HOPS,
        Range::new(base.saturating_add(15), 1),
        Value::Uint8(remaining_hops),
    );
}

fn padded_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or(&[])).into_owned()
}
