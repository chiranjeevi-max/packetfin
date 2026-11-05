//! Classic pcap reader: both byte orders and both timestamp resolutions.

use std::io::Read;

use super::bytes::{self, Cursor, Endian};
use super::{
    CaptureError, CountingReader, FrameData, MAX_FRAME_SIZE, PacketOptions, Resolution, Timestamp,
};

pub(crate) struct State {
    endian: Endian,
    pub(crate) resolution: Resolution,
    pub(crate) link_type: u32,
    pub(crate) snap_len: u32,
}

/// Read the 24-byte pcap global header after its four magic bytes.
pub(crate) fn read_header<R: Read>(
    reader: &mut R,
    endian: Endian,
    resolution: Resolution,
) -> Result<State, CaptureError> {
    let mut header = [0_u8; 20];
    bytes::read_exact_initial(reader, &mut header, "pcap global header")?;

    let mut cursor = Cursor::new(&header);
    let major = cursor.u16(endian)?;
    let minor = cursor.u16(endian)?;
    if major != 2 {
        return Err(CaptureError::Malformed(format!(
            "unsupported pcap version {major}.{minor}"
        )));
    }
    cursor.skip(4)?; // thiszone
    cursor.skip(4)?; // sigfigs
    let snap_len = cursor.u32(endian)?;
    let link_type = cursor.u32(endian)?;

    Ok(State {
        endian,
        resolution,
        link_type,
        snap_len,
    })
}

pub(crate) fn next<R: Read>(
    reader: &mut CountingReader<R>,
    state: &State,
) -> Result<Option<FrameData>, CaptureError> {
    let source_offset = reader.position();
    let mut header = [0_u8; 16];
    if !bytes::read_full_or_eof(reader, &mut header)? {
        return Ok(None);
    }

    let mut cursor = Cursor::new(&header);
    let seconds = cursor.u32(state.endian)?;
    let fraction = cursor.u32(state.endian)?;
    let captured_length = cursor.u32(state.endian)?;
    let original_length = cursor.u32(state.endian)?;

    if u64::from(captured_length) > MAX_FRAME_SIZE as u64 {
        return Err(CaptureError::FrameTooLarge);
    }
    let captured_len = usize::try_from(captured_length).map_err(|_| CaptureError::FrameTooLarge)?;
    let captured = bytes::read_bounded(reader, captured_len)?;
    let timestamp = timestamp(seconds, fraction, state.resolution)?;
    let units_per_second = match state.resolution {
        Resolution::Microsecond => 1_000_000,
        Resolution::Nanosecond => 1_000_000_000,
    };
    let timestamp_units = u64::from(seconds)
        .checked_mul(units_per_second)
        .and_then(|ticks| ticks.checked_add(u64::from(fraction)))
        .ok_or_else(|| CaptureError::Malformed("pcap timestamp overflow".to_string()))?;

    Ok(Some(FrameData {
        timestamp: Some(timestamp),
        timestamp_precision: match state.resolution {
            Resolution::Microsecond => 6,
            Resolution::Nanosecond => 9,
        },
        captured,
        original_len: original_length,
        link_type: state.link_type,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: Some(timestamp_units),
        source_offset,
        interface_name: None,
        section_number: None,
        options: PacketOptions::default(),
    }))
}

/// Convert pcap's seconds and fraction into a nanosecond timestamp.
///
/// A fraction larger than the resolution allows is carried into the seconds
/// field instead of rejecting the capture.
fn timestamp(
    seconds: u32,
    fraction: u32,
    resolution: Resolution,
) -> Result<Timestamp, CaptureError> {
    let multiplier: u128 = match resolution {
        Resolution::Microsecond => 1_000,
        Resolution::Nanosecond => 1,
    };
    let total_nanos = u128::from(fraction)
        .checked_mul(multiplier)
        .ok_or_else(|| CaptureError::Malformed("pcap timestamp overflow".to_string()))?;
    let extra_seconds = i64::try_from(total_nanos / 1_000_000_000)
        .map_err(|_| CaptureError::Malformed("pcap timestamp seconds out of range".to_string()))?;
    let nanos = u32::try_from(total_nanos % 1_000_000_000)
        .map_err(|_| CaptureError::Malformed("pcap timestamp nanos out of range".to_string()))?;
    let seconds = i64::from(seconds)
        .checked_add(extra_seconds)
        .ok_or_else(|| {
            CaptureError::Malformed("pcap timestamp seconds out of range".to_string())
        })?;
    Ok(Timestamp { seconds, nanos })
}

#[cfg(test)]
mod tests {
    use super::timestamp;
    use crate::capture::{Resolution, Timestamp};

    #[test]
    fn microseconds_scale_to_nanoseconds() -> Result<(), String> {
        let value = timestamp(1_700_000_000, 123_456, Resolution::Microsecond)
            .map_err(|error| error.to_string())?;
        assert_eq!(
            value,
            Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_000,
            }
        );
        Ok(())
    }

    #[test]
    fn nanoseconds_are_kept_exactly() -> Result<(), String> {
        let value = timestamp(1_700_000_000, 123_456_789, Resolution::Nanosecond)
            .map_err(|error| error.to_string())?;
        assert_eq!(
            value,
            Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_789,
            }
        );
        Ok(())
    }

    #[test]
    fn an_oversized_fraction_carries_into_seconds() -> Result<(), String> {
        let value = timestamp(1_700_000_000, 2_000_000, Resolution::Microsecond)
            .map_err(|error| error.to_string())?;
        assert_eq!(
            value,
            Timestamp {
                seconds: 1_700_000_002,
                nanos: 0,
            }
        );
        Ok(())
    }
}
