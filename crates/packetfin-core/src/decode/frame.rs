//! Frame pseudo-protocol fields and summary columns.

use crate::capture::Frame;
use crate::decode::Columns;
use crate::fields;
use crate::state::FrameInfo;
use crate::tree::{Node, Range, Value};

/// The offset and length of a generated frame field. Frame fields take no
/// bytes from the capture, so their range is empty.
const GENERATED_RANGE: Range = Range::new(0, 0);

/// Add the `frame.*` fields and fill the frame-owned summary columns.
pub(crate) fn decode(node: &mut Node, frame: &Frame, info: FrameInfo, columns: &mut Columns) {
    columns.number = Some(frame.number);
    columns.time = frame.timestamp;
    columns.length = Some(frame.original_len);

    if let Some(timestamp) = frame.timestamp {
        node.add_field(
            &fields::FRAME_TIME_EPOCH,
            GENERATED_RANGE,
            Value::AbsoluteTime(timestamp),
        );
    }
    if let Some(delta) = info.time_delta {
        node.add_field(
            &fields::FRAME_TIME_DELTA,
            GENERATED_RANGE,
            Value::RelativeTime(delta),
        );
    }
    if let Some(relative) = info.time_relative {
        node.add_field(
            &fields::FRAME_TIME_RELATIVE,
            GENERATED_RANGE,
            Value::RelativeTime(relative),
        );
    }
    node.add_field(
        &fields::FRAME_NUMBER,
        GENERATED_RANGE,
        Value::Uint32(u32::try_from(frame.number).unwrap_or(u32::MAX)),
    );
    node.add_field(
        &fields::FRAME_LEN,
        GENERATED_RANGE,
        Value::Uint32(frame.original_len),
    );
    node.add_field(
        &fields::FRAME_CAP_LEN,
        GENERATED_RANGE,
        Value::Uint32(u32::try_from(frame.captured.len()).unwrap_or(u32::MAX)),
    );
    node.add_field(
        &fields::FRAME_INTERFACE_ID,
        GENERATED_RANGE,
        Value::Uint32(frame.interface_id),
    );
    if let Some(name) = &frame.interface_name {
        node.add_field(
            &fields::FRAME_INTERFACE_NAME,
            GENERATED_RANGE,
            Value::String(name.clone()),
        );
    }
}
