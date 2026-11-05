//! Network Time Protocol version 3/4.
//!
//! Layout follows RFC 5905 section 7.3: a 48-octet header with the leap,
//! version and mode flags, stratum, poll exponent, precision, the two 16.16
//! fixed-point root values, the reference identifier and four 64-bit
//! timestamps. Timestamp conversion follows RFC 5905 appendix A: the 32-bit
//! seconds field is unfolded into the era starting in 1968 and the fraction is
//! scaled to nanoseconds. Bytes after the header are the legacy MAC area: a
//! four-octet key identifier followed by the message digest.
//!
//! A payload shorter than the header keeps the fields whose bytes are all
//! captured, then stops with a malformed expert. Modes 6 (control) and 7
//! (private) only decode the common flags octet here.

use crate::decode::DecodeContext;
use crate::fields;
use crate::tree::{Node, Range, Value};

const FLAGS: usize = 0;
const STRATUM: usize = 1;
const POLL: usize = 2;
const PRECISION: usize = 3;
const ROOT_DELAY: usize = 4;
const ROOT_DISPERSION: usize = 8;
const REFERENCE_ID: usize = 12;
const REFERENCE_TIME: usize = 16;
const ORIGIN_TIME: usize = 24;
const RECEIVE_TIME: usize = 32;
const TRANSMIT_TIME: usize = 40;
const KEY_ID: usize = 48;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch.
const NTP_EPOCH_OFFSET: i64 = 2_208_988_800;

/// Decode one NTP message into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::NTP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::NTP_PROTOCOL, Range::new(base, data.len()));
    parse(&mut node, context, data, base);

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

fn parse(node: &mut Node, context: &mut DecodeContext<'_>, data: &[u8], base: usize) {
    let Some(flags) = data.first().copied() else {
        context.mark_malformed(node, "NTP header is empty");
        return;
    };
    let flags_range = Range::new(base + FLAGS, 1);
    node.add_field(&fields::NTP_FLAGS, flags_range, Value::Uint8(flags));
    node.add_field(&fields::NTP_FLAGS_LI, flags_range, Value::Uint8(flags >> 6));
    node.add_field(
        &fields::NTP_FLAGS_VN,
        flags_range,
        Value::Uint8((flags >> 3) & 0x7),
    );
    node.add_field(
        &fields::NTP_FLAGS_MODE,
        flags_range,
        Value::Uint8(flags & 0x7),
    );

    if data.len() < STRATUM + 1 {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    }
    let Some(stratum) = data.get(STRATUM).copied() else {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    };
    node.add_field(
        &fields::NTP_STRATUM,
        Range::new(base + STRATUM, 1),
        Value::Uint8(stratum),
    );
    if data.len() < POLL + 1 {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    }
    let Some(poll) = data.get(POLL).copied() else {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    };
    node.add_field(
        &fields::NTP_PPOLL,
        Range::new(base + POLL, 1),
        Value::Int8(poll as i8),
    );
    if data.len() < PRECISION + 1 {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    }
    let Some(precision) = data.get(PRECISION).copied() else {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    };
    node.add_field(
        &fields::NTP_PRECISION,
        Range::new(base + PRECISION, 1),
        Value::Int8(precision as i8),
    );

    if data.len() < ROOT_DELAY + 4 {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    }
    node.add_field(
        &fields::NTP_ROOTDELAY,
        Range::new(base + ROOT_DELAY, 4),
        Value::Uint32(read_u32(data, ROOT_DELAY)),
    );
    if data.len() < ROOT_DISPERSION + 4 {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    }
    node.add_field(
        &fields::NTP_ROOTDISPERSION,
        Range::new(base + ROOT_DISPERSION, 4),
        Value::Uint32(read_u32(data, ROOT_DISPERSION)),
    );
    if data.len() < REFERENCE_ID + 4 {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    }
    let Some(reference_id) = data.get(REFERENCE_ID..REFERENCE_ID + 4) else {
        context.mark_malformed(node, "NTP header is truncated");
        return;
    };
    node.add_field(
        &fields::NTP_REFID,
        Range::new(base + REFERENCE_ID, 4),
        Value::bytes(reference_id.to_vec()),
    );

    for (offset, definition) in [
        (REFERENCE_TIME, &fields::NTP_REFTIME),
        (ORIGIN_TIME, &fields::NTP_ORG),
        (RECEIVE_TIME, &fields::NTP_REC),
        (TRANSMIT_TIME, &fields::NTP_XMT),
    ] {
        let Some(raw) = data.get(offset..offset + 8) else {
            context.mark_malformed(node, "NTP header is truncated");
            return;
        };
        node.add_field(
            definition,
            Range::new(base + offset, 8),
            timestamp_value(raw),
        );
    }

    if data.len() <= KEY_ID {
        return;
    }
    let Some(trailer) = data.get(KEY_ID..) else {
        return;
    };
    let Some(key_id) = trailer.get(..4) else {
        return;
    };
    node.add_field(
        &fields::NTP_KEYID,
        Range::new(base + KEY_ID, 4),
        Value::bytes(key_id.to_vec()),
    );
    if let Some(mac) = trailer.get(4..).filter(|mac| !mac.is_empty()) {
        node.add_field(
            &fields::NTP_MAC,
            Range::new(base + KEY_ID + 4, mac.len()),
            Value::bytes(mac.to_vec()),
        );
    }
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map_or(0, u32::from_be_bytes)
}

/// Convert one 64-bit NTP timestamp to the tree's time value.
fn timestamp_value(raw: &[u8]) -> Value {
    let Some(bytes) = raw
        .get(..8)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
    else {
        return Value::String("NULL".to_string());
    };
    let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let fraction = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if seconds == 0 && fraction == 0 {
        return Value::String("NULL".to_string());
    }
    let unfolded = if seconds & 0x8000_0000 == 0 {
        u64::from(seconds) + (1_u64 << 32)
    } else {
        u64::from(seconds)
    };
    let unix = unfolded as i64 - NTP_EPOCH_OFFSET;
    let nanos = (u64::from(fraction) * 1_000_000_000) >> 32;
    Value::AbsoluteTime(crate::Timestamp {
        seconds: unix,
        nanos: u32::try_from(nanos).unwrap_or(0),
    })
}
