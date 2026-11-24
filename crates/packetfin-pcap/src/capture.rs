//! One live capture handle.

use packetfin_core::Timestamp;

use crate::device::DeviceInfo;
use crate::error::{CaptureError, OpenError, OpenWarning, classify_activation};
use crate::ffi;
use crate::handle::{Activation, Handle};
use crate::options::{
    DEFAULT_SNAPLEN, Linktype, LinktypeInfo, OpenOptions, TimestampPrecision,
    timestamp_from_timeval,
};
use crate::tstamp::{TimestampTypeInfo, timestamp_type_info};

/// Largest number of timestamp types accepted from libpcap.
const MAX_TIMESTAMP_TYPES: usize = 64;

/// Counters libpcap reports for one interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureStats {
    /// Packets received by the capture mechanism.
    pub received: u64,
    /// Packets dropped because the capture buffer was full.
    pub dropped: u64,
    /// Packets dropped by the interface or its driver.
    pub interface_dropped: u64,
}

/// One packet borrowed from a live handle.
#[derive(Debug)]
pub struct CapturedPacket<'a> {
    /// Capture timestamp at nanosecond precision.
    pub timestamp: Timestamp,
    /// Captured bytes, at most the interface snapshot length.
    pub data: &'a [u8],
    /// Original packet length on the wire.
    pub original_len: u32,
    /// Link type of the interface.
    pub link_type: u32,
    /// Interface metadata for this packet.
    pub device: &'a DeviceInfo,
}

impl CapturedPacket<'_> {
    /// Number of captured bytes.
    #[must_use]
    pub fn captured_len(&self) -> usize {
        self.data.len()
    }
}

/// A configured, activated libpcap handle for one interface.
pub struct LiveCapture {
    capture: Handle,
    device: DeviceInfo,
    link_type: u32,
    snaplen: u32,
    precision: TimestampPrecision,
    timeout_ms: i32,
    nonblocking: bool,
    warnings: Vec<OpenWarning>,
}

impl std::fmt::Debug for LiveCapture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveCapture")
            .field("device", &self.device)
            .field("link_type", &self.link_type)
            .field("snaplen", &self.snaplen)
            .field("precision", &self.precision)
            .field("timeout_ms", &self.timeout_ms)
            .field("nonblocking", &self.nonblocking)
            .field("warnings", &self.warnings)
            .finish()
    }
}

impl LiveCapture {
    /// Open an interface with a bounded blocking read timeout.
    ///
    /// The effective libpcap timeout is capped at
    /// [`crate::MAX_BLOCKING_TIMEOUT_MS`], so `next` returns at least every
    /// 100 ms and a SIGINT/SIGTERM stop is observed even when the caller asks
    /// for zero (libpcap's "block forever") or a large timeout.
    pub fn open(device: &DeviceInfo, options: &OpenOptions) -> Result<Self, OpenError> {
        Self::open_with(device, options, false)
    }

    /// Open an interface for polling, where `next` returns immediately.
    ///
    /// [`crate::CaptureSet`] uses this mode; a lone `next` on a non-blocking
    /// handle returns `Ok(None)` when no packet is buffered.
    pub fn open_nonblocking(device: &DeviceInfo, options: &OpenOptions) -> Result<Self, OpenError> {
        Self::open_with(device, options, true)
    }

    fn open_with(
        device: &DeviceInfo,
        options: &OpenOptions,
        nonblocking: bool,
    ) -> Result<Self, OpenError> {
        options.validate()?;
        let (mut capture, warning) = Self::activate(device, options)?;
        if nonblocking {
            capture
                .set_nonblocking()
                .map_err(|message| OpenError::Open {
                    device: device.name.clone(),
                    message,
                })?;
        }
        let warnings = warning
            .map(|message| OpenWarning::PromiscuousNotSupported {
                device: device.name.clone(),
                message,
            })
            .into_iter()
            .collect();
        let link_type = u32::try_from(capture.datalink()).unwrap_or(0);
        // SAFETY: the handle is active and alive; pcap_snapshot has no
        // pointer arguments beyond the handle.
        let snapshot = unsafe { ffi::pcap_snapshot(capture.as_ptr()) };
        let snaplen = u32::try_from(snapshot)
            .ok()
            .filter(|value| *value > 0)
            .or(options.snaplen)
            .unwrap_or(DEFAULT_SNAPLEN);
        // SAFETY: same handle-lifetime argument as pcap_snapshot.
        let precision_raw = unsafe { ffi::pcap_get_tstamp_precision(capture.as_ptr()) };
        let precision = TimestampPrecision::from_raw(precision_raw);
        Ok(Self {
            capture,
            device: device.clone(),
            link_type,
            snaplen,
            precision,
            timeout_ms: options.effective_timeout_ms(),
            nonblocking,
            warnings,
        })
    }

    /// Create, configure and activate a libpcap handle.
    ///
    /// Returns the active handle and libpcap's promiscuous-mode warning, if
    /// the interface could not enter promiscuous mode.
    fn activate(
        device: &DeviceInfo,
        options: &OpenOptions,
    ) -> Result<(Handle, Option<String>), OpenError> {
        let open_error = |message: String| OpenError::Open {
            device: device.name.clone(),
            message,
        };
        let mut capture = Handle::create(device.name.as_str()).map_err(open_error)?;
        capture
            .set_snaplen(options.snaplen_i32()?.unwrap_or(0))
            .map_err(open_error)?;
        capture.set_promisc(options.promisc).map_err(open_error)?;
        capture
            .set_timeout(options.effective_timeout_ms())
            .map_err(open_error)?;
        #[cfg(not(windows))]
        capture
            .set_rfmon(options.monitor)
            .map_err(|message| OpenError::Monitor { message })?;
        #[cfg(windows)]
        if options.monitor {
            return Err(OpenError::Monitor {
                message: "monitor mode is not available through Npcap".to_owned(),
            });
        }
        if let Some(buffer) = options.buffer_i32()? {
            capture
                .set_buffer_size(buffer)
                .map_err(|message| OpenError::Buffer { message })?;
        }
        if let Some(tstamp_type) = options.tstamp_type {
            let raw = i32::try_from(tstamp_type).map_err(|_| OpenError::TimestampType {
                message: format!("value {tstamp_type} does not fit in a signed 32-bit integer"),
            })?;
            // SAFETY: the handle is inactive and alive; libpcap copies the
            // value and does not retain the pointer.
            let result = unsafe { ffi::pcap_set_tstamp_type(capture.as_ptr(), raw) };
            if result != 0 {
                return Err(OpenError::TimestampType {
                    message: format!(
                        "libpcap rejected timestamp type {} (code {result})",
                        timestamp_type_info(tstamp_type).label()
                    ),
                });
            }
        }
        let warning = match capture.activate() {
            Activation::Ready => None,
            Activation::PromiscuousNotSupported(message) => Some(message),
            Activation::Failed { status, message } => {
                return Err(classify_activation(
                    &device.name,
                    options.monitor,
                    status,
                    message,
                ));
            }
        };
        if let Some(link_type) = options.link_type {
            let raw = i32::try_from(link_type.value()).map_err(|_| OpenError::LinkType {
                message: format!(
                    "link type {} does not fit in a signed 32-bit integer",
                    link_type.0
                ),
            })?;
            capture
                .set_datalink(raw)
                .map_err(|error| OpenError::LinkType {
                    message: format!("'{}': {error}", device.name),
                })?;
        }
        Ok((capture, warning))
    }

    /// The interface this handle captures from.
    #[must_use]
    pub fn device(&self) -> &DeviceInfo {
        &self.device
    }

    /// The link type selected after activation.
    #[must_use]
    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    /// The link type as a display record.
    #[must_use]
    pub fn link_type_info(&self) -> LinktypeInfo {
        Linktype(self.link_type).info()
    }

    /// Snapshot length libpcap reports for this handle.
    #[must_use]
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Timestamp precision libpcap reports for this handle.
    #[must_use]
    pub fn precision(&self) -> TimestampPrecision {
        self.precision
    }

    /// Effective read timeout in milliseconds, capped at
    /// [`crate::MAX_BLOCKING_TIMEOUT_MS`].
    #[must_use]
    pub fn timeout_ms(&self) -> i32 {
        self.timeout_ms
    }

    /// Whether `next` returns immediately when no packet is buffered.
    #[must_use]
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking
    }

    /// Non-fatal conditions recorded while opening this handle.
    #[must_use]
    pub fn warnings(&self) -> &[OpenWarning] {
        &self.warnings
    }

    /// Convert this handle to non-blocking mode.
    pub fn into_nonblocking(self) -> Result<Self, OpenError> {
        if self.nonblocking {
            return Ok(self);
        }
        let Self {
            mut capture,
            device,
            link_type,
            snaplen,
            precision,
            timeout_ms,
            warnings,
            ..
        } = self;
        capture
            .set_nonblocking()
            .map_err(|message| OpenError::Open {
                device: device.name.clone(),
                message,
            })?;
        Ok(Self {
            capture,
            device,
            link_type,
            snaplen,
            precision,
            timeout_ms,
            nonblocking: true,
            warnings,
        })
    }

    /// Compile and install a BPF capture filter.
    ///
    /// Call this after [`Self::open`] and before creating an output file so a
    /// bad expression leaves no empty file behind.
    pub fn set_filter(&mut self, expression: &str) -> Result<(), OpenError> {
        self.capture
            .set_filter(expression)
            .map_err(|message| OpenError::Filter {
                expression: expression.to_owned(),
                message,
            })
    }

    /// Read the next packet, or `None` on a read timeout.
    ///
    /// A blocking handle wakes at least every
    /// [`crate::MAX_BLOCKING_TIMEOUT_MS`] so a caller can observe a stop.
    #[expect(
        clippy::should_implement_trait,
        reason = "a live capture is polled and can fail, so it returns Result instead of implementing Iterator"
    )]
    pub fn next(&mut self) -> Result<Option<CapturedPacket<'_>>, CaptureError> {
        read_packet(
            &mut self.capture,
            &self.device,
            self.link_type,
            self.precision,
        )
    }

    /// Counters since the handle was opened.
    pub fn stats(&mut self) -> Result<CaptureStats, CaptureError> {
        self.capture
            .stats()
            .map(|stats| CaptureStats {
                received: u64::from(stats.received),
                dropped: u64::from(stats.dropped),
                interface_dropped: u64::from(stats.interface_dropped),
            })
            .map_err(|message| CaptureError::Stats {
                device: self.device.name.clone(),
                message,
            })
    }

    /// Link types the active handle supports, for `-L`.
    pub fn link_types(&self) -> Result<Vec<LinktypeInfo>, OpenError> {
        let links = self
            .capture
            .datalinks()
            .map_err(|error| OpenError::LinkType {
                message: format!("'{}': {error}", self.device.name),
            })?;
        Ok(links
            .into_iter()
            .map(|link| Linktype(u32::try_from(link).unwrap_or(0)).info())
            .collect())
    }

    /// Timestamp types the active handle supports.
    pub fn timestamp_types(&self) -> Result<Vec<TimestampTypeInfo>, OpenError> {
        let mut pointer: *mut std::ffi::c_int = std::ptr::null_mut();
        // SAFETY: the handle is active and alive; on success libpcap allocates
        // an array of `count` integers that we copy and then free.
        let count = unsafe { ffi::pcap_list_tstamp_types(self.capture.as_ptr(), &mut pointer) };
        if count < 0 {
            return Err(OpenError::TimestampType {
                message: format!(
                    "libpcap could not list timestamp types for '{}'",
                    self.device.name
                ),
            });
        }
        let count = usize::try_from(count).map_err(|_| OpenError::TimestampType {
            message: "libpcap returned an unrepresentable timestamp type count".to_owned(),
        })?;
        if count > MAX_TIMESTAMP_TYPES {
            // SAFETY: the pointer was allocated by libpcap on a nonnegative
            // count and is freed exactly once here.
            unsafe { ffi::pcap_free_tstamp_types(pointer) };
            return Err(OpenError::TimestampType {
                message: format!(
                    "libpcap returned {count} timestamp types, above the supported limit"
                ),
            });
        }
        let mut types = Vec::with_capacity(count.max(1));
        if count > 0 && !pointer.is_null() {
            for index in 0..count {
                // SAFETY: libpcap returned `count` entries at `pointer`.
                let value = unsafe { *pointer.add(index) };
                types.push(timestamp_type_info(u32::try_from(value).unwrap_or(0)));
            }
        }
        if !pointer.is_null() {
            // SAFETY: allocated by pcap_list_tstamp_types and not used again.
            unsafe { ffi::pcap_free_tstamp_types(pointer) };
        }
        Ok(types)
    }

    /// File descriptor that becomes readable when packets are available.
    #[cfg(unix)]
    pub(crate) fn selectable_fd(&self) -> i32 {
        // SAFETY: the handle is active and alive; libpcap returns a borrowed
        // descriptor owned by the handle.
        unsafe { ffi::pcap_get_selectable_fd(self.capture.as_ptr()) }
    }
}

fn read_packet<'a>(
    capture: &'a mut Handle,
    device: &'a DeviceInfo,
    link_type: u32,
    precision: TimestampPrecision,
) -> Result<Option<CapturedPacket<'a>>, CaptureError> {
    let Some(packet) = capture
        .next_packet()
        .map_err(|message| CaptureError::Read {
            device: device.name.clone(),
            message,
        })?
    else {
        return Ok(None);
    };
    let timestamp = timestamp_from_timeval(packet.timestamp, precision).map_err(|message| {
        CaptureError::Timestamp {
            device: device.name.clone(),
            message,
        }
    })?;
    Ok(Some(CapturedPacket {
        timestamp,
        data: packet.data,
        original_len: packet.original_len,
        link_type,
        device,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_packet_reports_its_length() {
        let device = DeviceInfo::new("lo0", None);
        let packet = CapturedPacket {
            timestamp: Timestamp {
                seconds: 1,
                nanos: 2,
            },
            data: &[1, 2, 3],
            original_len: 9,
            link_type: 0,
            device: &device,
        };
        assert_eq!(packet.captured_len(), 3);
        assert_eq!(packet.original_len, 9);
    }

    #[test]
    fn stats_default_to_zero() {
        assert_eq!(
            CaptureStats::default(),
            CaptureStats {
                received: 0,
                dropped: 0,
                interface_dropped: 0
            }
        );
    }
}
