//! Bidirectional Forwarding Detection control and echo packets.
//!
//! A control packet starts with a required 24-byte section: version and
//! diagnostic code, session state and flags, detect multiplier, message
//! length, discriminators and the three interval fields (RFC 5880 section
//! 4.1). An optional authentication section follows when the Authentication
//! Present flag is set; its declared length covers the whole section and
//! bounds every field after it (RFC 5880 sections 4.2 to 4.5).
//!
//! The echo packet carries only originator-specific bytes (RFC 5880 section
//! 4.6). The port registry assigns BFD control to UDP ports 3784, 4784, 6784
//! and 7784, and echo to 3785.

use crate::decode::DecodeContext;
use crate::decode::bytes::read_u32_be;
use crate::fields;
use crate::tree::{ExpertInfo, FieldParent, Group, Node, Range, Severity, Value};

const CONTROL_HEADER_LENGTH: usize = 24;
const AUTH_FLAG: u8 = 0x04;

/// Decode one BFD control message.
pub(crate) fn decode_control(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::BFD_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::BFD_PROTOCOL, Range::new(base, data.len()));
    if data.len() < CONTROL_HEADER_LENGTH {
        context.mark_malformed(&mut node, "BFD control header is shorter than 24 bytes");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }
    let first = data.first().copied().unwrap_or(0);
    let second = data.get(1).copied().unwrap_or(0);
    let version = (first >> 5) & 0x07;
    let diagnostic = first & 0x1f;
    let state = (second >> 6) & 0x03;
    let field = node.add_field(
        &fields::BFD_VERSION,
        Range::new(base, 1),
        Value::Uint8(version),
    );
    field.showname = Some(format!(
        "{} = Protocol Version: {version}",
        bfd_bit_pattern(8, 0xe0, u64::from(first))
    ));
    let field = node.add_field(
        &fields::BFD_DIAG,
        Range::new(base, 1),
        Value::Uint8(diagnostic),
    );
    field.showname = Some(format!(
        "{} = Diagnostic Code: {} (0x{diagnostic:02x})",
        bfd_bit_pattern(8, 0x1f, u64::from(first)),
        fields::value_name("bfd.diag", u64::from(diagnostic)).unwrap_or("Unknown")
    ));
    let flags_range = Range::new(base + 1, 1);
    if version == 0 {
        let mut flags = node.add_container(&fields::BFD_FLAGS, flags_range, None);
        flags.value = Value::Uint8(second);
        flags.showname = Some(bfd_flags_showname(
            second,
            &[
                (0x80, "I hear you"),
                (0x40, "Demand"),
                (0x20, "Poll"),
                (0x10, "Final"),
            ],
        ));
        for (definition, bit, pattern) in [
            (&fields::BFD_FLAGS_H, 0x80, "0... ...."),
            (&fields::BFD_FLAGS_D, 0x40, ".0.. ...."),
            (&fields::BFD_FLAGS_P, 0x20, "..0. ...."),
            (&fields::BFD_FLAGS_F, 0x10, "...0 ...."),
        ] {
            let set = second & bit != 0;
            add_bfd_flag(&mut flags, definition, flags_range, set, pattern);
        }
    } else {
        add_field_with_showname(
            &mut node,
            &fields::BFD_STA,
            Range::new(base + 1, 1),
            Value::Uint8(state),
            &format!(
                "{} = Session State: {} (0x{:x})",
                bfd_bit_pattern(8, 0xc0, u64::from(second)),
                fields::value_name("bfd.sta", u64::from(state)).unwrap_or("Unknown"),
                state
            ),
        );
        let mut flags = node.add_container(&fields::BFD_FLAGS, flags_range, None);
        flags.value = Value::Uint8(second);
        flags.showname = Some(bfd_flags_showname(
            second,
            &[
                (0x20, "Poll"),
                (0x10, "Final"),
                (0x08, "Control Plane Independent"),
                (0x04, "Authentication Present"),
                (0x02, "Demand"),
                (0x01, "Multipoint"),
            ],
        ));
        for (definition, bit, pattern) in [
            (&fields::BFD_FLAGS_P, 0x20, "0... .."),
            (&fields::BFD_FLAGS_F, 0x10, ".0.. .."),
            (&fields::BFD_FLAGS_C, 0x08, "..0. .."),
            (&fields::BFD_FLAGS_A, 0x04, "...0 .."),
            (&fields::BFD_FLAGS_D, 0x02, ".... 0."),
            (&fields::BFD_FLAGS_M, 0x01, ".... .0"),
        ] {
            let set = second & bit != 0;
            add_bfd_flag(&mut flags, definition, flags_range, set, pattern);
        }
    }
    let detect_multiplier = data.get(2).copied().unwrap_or(0);
    let message_length = data.get(3).copied().unwrap_or(0);
    add_field_with_showname(
        &mut node,
        &fields::BFD_DETECT_TIME_MULTIPLIER,
        Range::new(base + 2, 1),
        Value::Uint8(detect_multiplier),
        &format!(
            "Detect Time Multiplier: {detect_multiplier} (= {} ms Detection time)",
            u64::from(detect_multiplier) * 1000
        ),
    );
    add_field_with_showname(
        &mut node,
        &fields::BFD_MESSAGE_LENGTH,
        Range::new(base + 3, 1),
        Value::Uint8(message_length),
        &format!("Message Length: {message_length} bytes"),
    );
    for (offset, definition, label) in [
        (4, &fields::BFD_MY_DISCRIMINATOR, "My Discriminator"),
        (8, &fields::BFD_YOUR_DISCRIMINATOR, "Your Discriminator"),
        (
            12,
            &fields::BFD_DESIRED_MIN_TX_INTERVAL,
            "Desired Min TX Interval",
        ),
        (
            16,
            &fields::BFD_REQUIRED_MIN_RX_INTERVAL,
            "Required Min RX Interval",
        ),
        (
            20,
            &fields::BFD_REQUIRED_MIN_ECHO_INTERVAL,
            "Required Min Echo Interval",
        ),
    ] {
        if let Some(value) = read_u32_be(data, offset) {
            let showname = if offset < 12 {
                None
            } else {
                Some(format!(
                    "{label}: {:4} ms ({value} us)",
                    u64::from(value) / 1000
                ))
            };
            let field = node.add_field(
                definition,
                Range::new(base + offset, 4),
                Value::Uint32(value),
            );
            field.showname = showname;
        }
    }

    if second & AUTH_FLAG != 0 {
        decode_authentication(context, &mut node, data, base, message_length);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn bfd_bit_pattern(width: usize, mask: u64, raw: u64) -> String {
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

fn bfd_flags_showname(flags: u8, names: &[(u8, &str)]) -> String {
    let mut text = format!("Message Flags: 0x{flags:02x}");
    for (bit, name) in names {
        if flags & bit != 0 {
            text.push_str(", ");
            text.push_str(name);
            text.push_str(": Set");
        }
    }
    text
}

fn add_field_with_showname(
    parent: &mut impl FieldParent,
    definition: &'static fields::FieldDef,
    range: Range,
    value: Value,
    showname: &str,
) {
    let field = parent.add_field(definition, range, value);
    field.showname = Some(showname.to_string());
}

fn add_bfd_flag(
    parent: &mut impl FieldParent,
    definition: &'static fields::FieldDef,
    range: Range,
    set: bool,
    pattern: &str,
) {
    let pattern = if set {
        pattern.replace('0', "1")
    } else {
        pattern.to_string()
    };
    add_field_with_showname(
        parent,
        definition,
        range,
        Value::Boolean(set),
        &format!(
            "{pattern} = {}: {}",
            definition.name,
            if set { "Set" } else { "Not set" }
        ),
    );
}
/// Decode the optional authentication section.
///
/// `message_length` is the whole control packet length; the section itself
/// starts after the required 24 bytes (RFC 5880 section 4.1).
fn decode_authentication(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    data: &[u8],
    base: usize,
    message_length: u8,
) {
    let declared_length = usize::from(message_length);
    let available = data.len().saturating_sub(CONTROL_HEADER_LENGTH);
    if declared_length <= CONTROL_HEADER_LENGTH || available == 0 {
        add_authentication_warning(
            node,
            &fields::BFD_AUTH_NO_DATA,
            &format!("Authentication: Length of the BFD frame is invalid ({declared_length})"),
            Range::new(base + CONTROL_HEADER_LENGTH, 0),
        );
        return;
    }
    let Some(auth_type) = data.get(CONTROL_HEADER_LENGTH).copied() else {
        add_authentication_warning(
            node,
            &fields::BFD_AUTH_NO_DATA,
            &format!("Authentication: Length of the BFD frame is invalid ({declared_length})"),
            Range::new(base + CONTROL_HEADER_LENGTH, 0),
        );
        return;
    };
    let Some(auth_length) = data.get(CONTROL_HEADER_LENGTH + 1).copied() else {
        add_authentication_warning(
            node,
            &fields::BFD_AUTH_NO_DATA,
            &format!("Authentication: Length of the BFD frame is invalid ({declared_length})"),
            Range::new(base + CONTROL_HEADER_LENGTH, 0),
        );
        return;
    };
    let section_length = usize::from(auth_length);
    let type_name = fields::value_name("bfd.auth.type", u64::from(auth_type)).unwrap_or("Unknown");
    if section_length < 3 {
        add_authentication_warning(
            node,
            &fields::BFD_AUTH_NO_DATA,
            &format!("Authentication: Length of the BFD frame is invalid ({declared_length})"),
            Range::new(base + CONTROL_HEADER_LENGTH, 0),
        );
        return;
    }
    let section_start = base + CONTROL_HEADER_LENGTH;
    let stored_length = section_length.min(available);
    let section = data
        .get(CONTROL_HEADER_LENGTH..CONTROL_HEADER_LENGTH + stored_length)
        .unwrap_or_default();
    let mut group = node.add_unnamed(
        Range::new(section_start, section.len()),
        format!("Authentication: {type_name}"),
    );
    add_field_with_showname(
        &mut group,
        &fields::BFD_AUTH_TYPE,
        Range::new(section_start, 1),
        Value::Uint8(auth_type),
        &format!("Authentication Type: {type_name} ({auth_type})"),
    );
    add_field_with_showname(
        &mut group,
        &fields::BFD_AUTH_LEN,
        Range::new(section_start + 1, 1),
        Value::Uint8(auth_length),
        &format!("Authentication Length: {auth_length} bytes"),
    );
    if let Some(key) = data.get(CONTROL_HEADER_LENGTH + 2).copied() {
        add_field_with_showname(
            &mut group,
            &fields::BFD_AUTH_KEY,
            Range::new(section_start + 2, 1),
            Value::Uint8(key),
            &format!("Authentication Key ID: {key}"),
        );
    }
    let expected = match auth_type {
        1 => None,
        2 | 3 => Some(24),
        4 | 5 => Some(28),
        _ => None,
    };
    if let Some(expected) = expected
        && section_length != expected
    {
        let message = format!(
            "Length of authentication section ({section_length}) is invalid for Authentication Type: {type_name}"
        );
        let nested = group.add_unnamed(Range::new(section_start, section.len()), message.clone());
        nested.add_expert_for(
            ExpertInfo {
                severity: Severity::Warning,
                group: Group::Malformed,
                message: message.clone(),
            },
            &fields::BFD_AUTH_LEN_INVALID,
        );
        nested
            .add_field(&fields::BFD_AUTH_LEN_INVALID, Range::new(0, 0), Value::None)
            .hide();
        context.mark_malformed(node, "BFD authentication section is truncated");
        return;
    }
    if CONTROL_HEADER_LENGTH.saturating_add(section_length) > data.len() {
        context.mark_malformed(node, "BFD authentication section is truncated");
        return;
    }
    if auth_type == 1 {
        let password = data.get(CONTROL_HEADER_LENGTH + 3..CONTROL_HEADER_LENGTH + section_length);
        if let Some(password) = password {
            let field = group.add_field(
                &fields::BFD_AUTH_PASSWORD,
                Range::new(base + CONTROL_HEADER_LENGTH + 3, password.len()),
                Value::String(String::from_utf8_lossy(password).into_owned()),
            );
            field.showname = Some(format!("Password: {}", String::from_utf8_lossy(password)));
        }
    } else if matches!(auth_type, 2..=5)
        && let Some(sequence) = read_u32_be(data, CONTROL_HEADER_LENGTH + 4)
    {
        group.add_field(
            &fields::BFD_AUTH_SEQ_NUM,
            Range::new(base + CONTROL_HEADER_LENGTH + 4, 4),
            Value::Uint32(sequence),
        );
        if let Some(checksum) =
            data.get(CONTROL_HEADER_LENGTH + 8..CONTROL_HEADER_LENGTH + section_length)
        {
            group.add_field(
                &fields::BFD_CHECKSUM,
                Range::new(base + CONTROL_HEADER_LENGTH + 8, checksum.len()),
                Value::bytes(checksum.to_vec()),
            );
        }
    }
    if declared_length > data.len() {
        context.mark_malformed(node, "BFD message length exceeds the captured packet");
    }
}

/// Attach a warning/malformed expert and its marker field.
fn add_authentication_warning(
    node: &mut Node,
    definition: &'static fields::FieldDef,
    message: &str,
    range: Range,
) {
    let group = node.add_unnamed(range, message.to_string());
    group.add_expert_for(
        ExpertInfo {
            severity: Severity::Warning,
            group: Group::Malformed,
            message: message.to_string(),
        },
        definition,
    );
    group
        .add_field(definition, Range::new(0, 0), Value::None)
        .hide();
}

/// Decode one BFD echo packet.
pub(crate) fn decode_echo(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::BFD_ECHO_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::BFD_ECHO_PROTOCOL, Range::new(base, data.len()));
    node.add_field(
        &fields::BFD_ECHO_PACKET,
        Range::new(base, data.len()),
        Value::bytes(data.to_vec()),
    );
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}
