//! Capture-open options, link types and timestamp conversion.

use packetfin_core::Timestamp;

use crate::error::OpenError;

/// Snapshot length Packetfin asks for when `-s` is absent.
///
/// libpcap may lower it during activation, which
/// [`crate::LiveCapture::snaplen`] reports.
pub const DEFAULT_SNAPLEN: u32 = 524_288;

/// Read timeout used when the caller does not choose one.
pub const DEFAULT_TIMEOUT_MS: i32 = 100;

/// Largest blocking read timeout.
///
/// libpcap's read timeout is the only wake-up point for a blocking handle on
/// macOS, and a zero timeout means "block indefinitely", which would make
/// SIGINT/SIGTERM unobservable. Packetfin caps the effective timeout so a
/// stop is observed within this many milliseconds.
pub const MAX_BLOCKING_TIMEOUT_MS: i32 = 100;

/// Bytes in one mebibyte, the unit `-B` uses.
pub const MIB: u64 = 1_048_576;

/// A libpcap link type (data link type).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Linktype(pub u32);

impl Linktype {
    /// Resolve a link-type name such as `NULL` or `EN10MB`.
    pub fn from_name(name: &str) -> Result<Self, OpenError> {
        let value = pcap::Linktype::from_name(name).map_err(|error| OpenError::LinkType {
            message: format!("unknown name '{name}': {error}"),
        })?;
        Ok(Self(u32::try_from(value.0).unwrap_or(0)))
    }

    /// The libpcap name for this link type.
    pub fn name(self) -> Result<String, OpenError> {
        let value = i32::try_from(self.0).map_err(|_| OpenError::LinkType {
            message: format!("link type {} is outside libpcap's range", self.0),
        })?;
        pcap::Linktype(value)
            .get_name()
            .map_err(|error| OpenError::LinkType {
                message: error.to_string(),
            })
    }

    /// The libpcap description for this link type.
    pub fn description(self) -> Result<String, OpenError> {
        let value = i32::try_from(self.0).map_err(|_| OpenError::LinkType {
            message: format!("link type {} is outside libpcap's range", self.0),
        })?;
        pcap::Linktype(value)
            .get_description()
            .map_err(|error| OpenError::LinkType {
                message: error.to_string(),
            })
    }

    /// A display record, falling back to `DLT <value> (not supported)` when
    /// libpcap has no name for the value.
    #[must_use]
    pub fn info(self) -> LinktypeInfo {
        match self.name() {
            Ok(name) => LinktypeInfo {
                value: self.0,
                description: self.description().unwrap_or_default(),
                name,
            },
            Err(_) => LinktypeInfo {
                value: self.0,
                name: format!("DLT {}", self.0),
                description: "not supported".to_owned(),
            },
        }
    }

    /// The numeric link type.
    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
}

/// A link type as shown by `-L`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinktypeInfo {
    /// Numeric data link type.
    pub value: u32,
    /// libpcap's short name, such as `NULL`.
    pub name: String,
    /// libpcap's description, such as `BSD loopback`.
    pub description: String,
}

impl LinktypeInfo {
    /// `name (description)`, or `name` when the description is empty.
    #[must_use]
    pub fn label(&self) -> String {
        if self.description.is_empty() {
            self.name.clone()
        } else {
            format!("{} ({})", self.name, self.description)
        }
    }
}

/// Fractional-second precision libpcap reports for a live handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampPrecision {
    /// Timestamps carry six fractional digits.
    Microsecond,
    /// Timestamps carry nine fractional digits.
    Nanosecond,
}

impl TimestampPrecision {
    /// Fractional digits this precision represents.
    #[must_use]
    pub fn digits(self) -> u8 {
        match self {
            Self::Microsecond => 6,
            Self::Nanosecond => 9,
        }
    }

    pub(crate) fn from_raw(raw: i32) -> Self {
        if raw == 1 {
            Self::Nanosecond
        } else {
            Self::Microsecond
        }
    }
}

/// How to open one live interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenOptions {
    /// Snapshot length; `Some(0)` asks libpcap for its default.
    pub snaplen: Option<u32>,
    /// Whether to put the interface in promiscuous mode. `-p` clears this.
    pub promisc: bool,
    /// Whether to request monitor (rfmon) mode. `-I` sets this.
    pub monitor: bool,
    /// Kernel capture buffer size in bytes. `-B` converts MiB to this.
    pub buffer_bytes: Option<u32>,
    /// Link type to select after activation. `-y` sets this.
    pub link_type: Option<Linktype>,
    /// libpcap timestamp type value. `--time-stamp-type` sets this.
    pub tstamp_type: Option<u32>,
    /// Read timeout in milliseconds.
    ///
    /// Zero means "wait for a packet"; it is capped together with larger
    /// values by [`Self::effective_timeout_ms`] so a stop is observed.
    pub timeout_ms: i32,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            snaplen: Some(DEFAULT_SNAPLEN),
            promisc: true,
            monitor: false,
            buffer_bytes: None,
            link_type: None,
            tstamp_type: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

impl OpenOptions {
    /// Reject values libpcap cannot represent before a handle is created.
    pub fn validate(&self) -> Result<(), OpenError> {
        if let Some(snaplen) = self.snaplen
            && snaplen > u32::try_from(i32::MAX).unwrap_or(u32::MAX)
        {
            return Err(OpenError::Snaplen {
                message: format!("{snaplen} exceeds libpcap's 32-bit signed limit"),
            });
        }
        if let Some(buffer) = self.buffer_bytes
            && buffer > u32::try_from(i32::MAX).unwrap_or(u32::MAX)
        {
            return Err(OpenError::Buffer {
                message: format!("{buffer} bytes exceed libpcap's 32-bit signed limit"),
            });
        }
        if self.timeout_ms < 0 {
            return Err(OpenError::Timeout {
                message: format!("{} is negative", self.timeout_ms),
            });
        }
        Ok(())
    }

    /// Timeout actually applied to libpcap.
    ///
    /// Zero and values above [`MAX_BLOCKING_TIMEOUT_MS`] are capped so a
    /// blocking `next` returns often enough to observe a stop.
    #[must_use]
    pub fn effective_timeout_ms(&self) -> i32 {
        if self.timeout_ms <= 0 {
            MAX_BLOCKING_TIMEOUT_MS
        } else {
            self.timeout_ms.min(MAX_BLOCKING_TIMEOUT_MS)
        }
    }

    pub(crate) fn snaplen_i32(&self) -> Result<Option<i32>, OpenError> {
        self.snaplen
            .map(|value| {
                i32::try_from(value).map_err(|_| OpenError::Snaplen {
                    message: format!("{value} does not fit in a signed 32-bit integer"),
                })
            })
            .transpose()
    }

    pub(crate) fn buffer_i32(&self) -> Result<Option<i32>, OpenError> {
        self.buffer_bytes
            .map(|value| {
                i32::try_from(value).map_err(|_| OpenError::Buffer {
                    message: format!("{value} does not fit in a signed 32-bit integer"),
                })
            })
            .transpose()
    }
}

/// Convert `-B`'s mebibytes into a byte count with overflow checks.
pub fn buffer_bytes_from_mib(mib: u64) -> Result<u32, OpenError> {
    let bytes = mib.checked_mul(MIB).ok_or_else(|| OpenError::Buffer {
        message: format!("{mib} MiB overflows a 64-bit byte count"),
    })?;
    u32::try_from(bytes).map_err(|_| OpenError::Buffer {
        message: format!("{mib} MiB exceeds the maximum capture buffer"),
    })
}

/// Convert libpcap's timeval into a nanosecond [`Timestamp`].
///
/// libpcap stores nanoseconds in `tv_usec` when the handle uses nanosecond
/// precision, so the precision decides the scale.
#[expect(
    clippy::unnecessary_cast,
    reason = "time_t and suseconds_t differ between Unix and Windows; the explicit casts keep one expression portable"
)]
pub(crate) fn timestamp_from_timeval(
    time: libc::timeval,
    precision: TimestampPrecision,
) -> Result<Timestamp, String> {
    let seconds = time.tv_sec as i64;
    let fraction = time.tv_usec as i64;
    if fraction < 0 {
        return Err(format!("negative fractional second {fraction}"));
    }
    let nanos = match precision {
        TimestampPrecision::Microsecond => fraction.checked_mul(1_000),
        TimestampPrecision::Nanosecond => Some(fraction),
    }
    .ok_or_else(|| format!("fractional second {fraction} overflows"))?;
    if nanos >= 1_000_000_000 {
        return Err(format!("fractional second {nanos} is not below one second"));
    }
    let nanos = u32::try_from(nanos)
        .map_err(|_| format!("fractional second {nanos} does not fit in 32 bits"))?;
    Ok(Timestamp { seconds, nanos })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn timeval(seconds: i64, fraction: i64) -> libc::timeval {
        libc::timeval {
            tv_sec: seconds as libc::time_t,
            tv_usec: fraction as libc::suseconds_t,
        }
    }

    #[cfg(windows)]
    fn timeval(seconds: i64, fraction: i64) -> libc::timeval {
        libc::timeval {
            tv_sec: seconds as libc::c_long,
            tv_usec: fraction as libc::c_long,
        }
    }

    #[test]
    fn default_options_match_live_defaults() {
        let options = OpenOptions::default();
        assert_eq!(options.snaplen, Some(DEFAULT_SNAPLEN));
        assert!(options.promisc);
        assert!(!options.monitor);
        assert_eq!(options.buffer_bytes, None);
        assert_eq!(options.link_type, None);
        assert_eq!(options.tstamp_type, None);
        assert_eq!(options.timeout_ms, DEFAULT_TIMEOUT_MS);
    }

    #[test]
    fn explicit_zero_snaplen_is_preserved() {
        let options = OpenOptions {
            snaplen: Some(0),
            ..OpenOptions::default()
        };
        assert_eq!(options.snaplen_i32(), Ok(Some(0)));
    }

    #[test]
    fn oversized_snaplen_is_rejected() {
        let options = OpenOptions {
            snaplen: Some(u32::MAX),
            ..OpenOptions::default()
        };
        assert!(matches!(options.validate(), Err(OpenError::Snaplen { .. })));
    }

    #[test]
    fn oversized_buffer_is_rejected() {
        let options = OpenOptions {
            buffer_bytes: Some(u32::MAX),
            ..OpenOptions::default()
        };
        assert!(matches!(options.validate(), Err(OpenError::Buffer { .. })));
    }

    #[test]
    fn negative_timeout_is_rejected() {
        let options = OpenOptions {
            timeout_ms: -1,
            ..OpenOptions::default()
        };
        assert!(matches!(options.validate(), Err(OpenError::Timeout { .. })));
    }

    #[test]
    fn zero_timeout_is_allowed() {
        let options = OpenOptions {
            timeout_ms: 0,
            ..OpenOptions::default()
        };
        assert!(options.validate().is_ok());
    }

    #[test]
    fn effective_timeout_is_bounded() {
        let zero = OpenOptions {
            timeout_ms: 0,
            ..OpenOptions::default()
        };
        assert_eq!(zero.effective_timeout_ms(), MAX_BLOCKING_TIMEOUT_MS);
        let large = OpenOptions {
            timeout_ms: 5_000,
            ..OpenOptions::default()
        };
        assert_eq!(large.effective_timeout_ms(), MAX_BLOCKING_TIMEOUT_MS);
        let small = OpenOptions {
            timeout_ms: 25,
            ..OpenOptions::default()
        };
        assert_eq!(small.effective_timeout_ms(), 25);
    }

    #[test]
    fn mib_conversion_uses_1048576_bytes() {
        assert_eq!(buffer_bytes_from_mib(0), Ok(0));
        assert_eq!(buffer_bytes_from_mib(1), Ok(1_048_576));
        assert_eq!(buffer_bytes_from_mib(4), Ok(4_194_304));
    }

    #[test]
    fn mib_conversion_rejects_overflow() {
        assert!(matches!(
            buffer_bytes_from_mib(u64::MAX),
            Err(OpenError::Buffer { .. })
        ));
        assert!(matches!(
            buffer_bytes_from_mib(u64::from(u32::MAX)),
            Err(OpenError::Buffer { .. })
        ));
    }

    #[test]
    fn microsecond_timestamps_scale_to_nanoseconds() {
        let timestamp = timestamp_from_timeval(
            timeval(1_700_000_000, 123_456),
            TimestampPrecision::Microsecond,
        );
        assert_eq!(
            timestamp,
            Ok(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_000
            })
        );
    }

    #[test]
    fn nanosecond_timestamps_keep_their_fraction() {
        let timestamp = timestamp_from_timeval(
            timeval(1_700_000_000, 123_456_789),
            TimestampPrecision::Nanosecond,
        );
        assert_eq!(
            timestamp,
            Ok(Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_789
            })
        );
    }

    #[test]
    fn out_of_range_fraction_is_rejected() {
        let micro = timestamp_from_timeval(timeval(1, 1_000_000), TimestampPrecision::Microsecond);
        assert!(micro.is_err());
        let nano =
            timestamp_from_timeval(timeval(1, 1_000_000_000), TimestampPrecision::Nanosecond);
        assert!(nano.is_err());
    }

    #[test]
    fn negative_fraction_is_rejected() {
        let timestamp = timestamp_from_timeval(timeval(1, -1), TimestampPrecision::Microsecond);
        assert!(timestamp.is_err());
    }

    #[test]
    fn linktype_round_trips_a_known_name() {
        let linktype = Linktype::from_name("NULL").unwrap_or(Linktype(0));
        assert_eq!(linktype.name().as_deref(), Ok("NULL"));
        let info = linktype.info();
        assert_eq!(info.name, "NULL");
        assert!(info.label().starts_with("NULL"));
    }

    #[test]
    fn unknown_linktype_name_is_typed() {
        assert!(matches!(
            Linktype::from_name("NOT_A_LINKTYPE"),
            Err(OpenError::LinkType { .. })
        ));
    }

    #[test]
    fn unknown_linktype_info_uses_fallback() {
        let info = Linktype(9_999).info();
        assert_eq!(info.value, 9_999);
        assert_eq!(info.name, "DLT 9999");
        assert_eq!(info.description, "not supported");
        assert_eq!(info.label(), "DLT 9999 (not supported)");
    }

    #[test]
    fn linktype_info_label_handles_empty_description() {
        let info = LinktypeInfo {
            value: 1,
            name: "EN10MB".to_owned(),
            description: String::new(),
        };
        assert_eq!(info.label(), "EN10MB");
    }

    #[test]
    fn precision_reports_its_digits() {
        assert_eq!(TimestampPrecision::Microsecond.digits(), 6);
        assert_eq!(TimestampPrecision::Nanosecond.digits(), 9);
        assert_eq!(
            TimestampPrecision::from_raw(0),
            TimestampPrecision::Microsecond
        );
        assert_eq!(
            TimestampPrecision::from_raw(1),
            TimestampPrecision::Nanosecond
        );
        assert_eq!(
            TimestampPrecision::from_raw(-3),
            TimestampPrecision::Microsecond
        );
    }
}
