//! Low-level primitives shared by the capture-file builders.

/// Byte order of the numeric fields in a capture file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl ByteOrder {
    pub(crate) fn put_u16(self, out: &mut Vec<u8>, value: u16) {
        let bytes = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
    }

    pub(crate) fn put_u32(self, out: &mut Vec<u8>, value: u32) {
        let bytes = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
    }

    pub(crate) fn put_u64(self, out: &mut Vec<u8>, value: u64) {
        let bytes = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
    }

    pub(crate) fn put_i64(self, out: &mut Vec<u8>, value: i64) {
        let bytes = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        out.extend_from_slice(&bytes);
    }
}

/// A timestamp split into whole seconds and a fraction of a second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch.
    pub seconds: u64,
    /// Fraction of a second in the resolution of the containing capture.
    pub fraction: u32,
}

impl Timestamp {
    /// Create a timestamp from whole seconds and a fraction of a second.
    pub const fn new(seconds: u64, fraction: u32) -> Self {
        Self { seconds, fraction }
    }

    /// Convert to a count of `resolution` units since the Unix epoch.
    pub(crate) fn in_units(self, resolution: TimestampResolution) -> Result<u64, String> {
        if u64::from(self.fraction) >= resolution.units_per_second() {
            return Err(format!(
                "timestamp fraction {} does not fit a {} timestamp",
                self.fraction,
                resolution.name()
            ));
        }
        self.seconds
            .checked_mul(resolution.units_per_second())
            .and_then(|seconds| seconds.checked_add(u64::from(self.fraction)))
            .ok_or_else(|| {
                format!(
                    "timestamp {}.{:09} is out of range",
                    self.seconds, self.fraction
                )
            })
    }
}

/// Timestamp resolution of a capture file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampResolution {
    /// Fractions of a second have six decimal digits.
    Microsecond,
    /// Fractions of a second have nine decimal digits.
    Nanosecond,
    /// Fractions of a second are binary, `2^-exponent` seconds.
    PowerOfTwo(u8),
}

impl TimestampResolution {
    /// Units in one second at this resolution.
    pub fn units_per_second(self) -> u64 {
        match self {
            Self::Microsecond => 1_000_000,
            Self::Nanosecond => 1_000_000_000,
            Self::PowerOfTwo(exponent) => 1_u64.checked_shl(u32::from(exponent)).unwrap_or(0),
        }
    }

    /// The pcapng `if_tsresol` value for a power-of-ten resolution.
    pub(crate) const fn pcapng_code(self) -> u8 {
        match self {
            Self::Microsecond => 6,
            Self::Nanosecond => 9,
            Self::PowerOfTwo(exponent) => 0x80 | exponent,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Microsecond => "microsecond",
            Self::Nanosecond => "nanosecond",
            Self::PowerOfTwo(_) => "binary",
        }
    }
}

/// Ethernet link type, as used by both pcap and pcapng.
pub(crate) const LINKTYPE_ETHERNET: u16 = 1;

/// Pad `out` with zero bytes up to the next 32-bit boundary.
pub(crate) fn pad_to_4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Append a pcapng option item, padding its value to a 32-bit boundary.
pub(crate) fn put_option(
    out: &mut Vec<u8>,
    order: ByteOrder,
    code: u16,
    value: &[u8],
) -> Result<(), String> {
    let length = u16::try_from(value.len()).map_err(|_| {
        format!(
            "pcapng option {code} value is {} bytes; the maximum is 65535",
            value.len()
        )
    })?;
    order.put_u16(out, code);
    order.put_u16(out, length);
    out.extend_from_slice(value);
    pad_to_4(out);
    Ok(())
}

/// Append the `opt_endofopt` item that terminates a pcapng option list.
pub(crate) fn put_end_of_options(out: &mut Vec<u8>, order: ByteOrder) {
    order.put_u16(out, 0);
    order.put_u16(out, 0);
}
