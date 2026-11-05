//! Live capture session: interfaces, messages and frame production.
//!
//! One [`LiveSession`] owns every libpcap handle, the shared stop handle and
//! the pcapng interface descriptions. The capture loop in `main.rs` polls it
//! between sink work, so `-a duration` and `-b duration` regain control while
//! an interface is idle without a second thread.
//!
//! Interface selectors are resolved here, after the command line has been
//! validated, so `-D`/`-L` keep separate exit statuses: an unknown
//! name exits 5 and a bad index exits 1.

use std::fmt;
use std::time::Instant;

use packetfin_core::Frame;
use packetfin_core::Timestamp;
use packetfin_core::capture::{InterfaceInfo, InterfaceOption, TimestampResolution};
use packetfin_pcap::{
    CaptureError, CaptureSet, CaptureStats, DEFAULT_SNAPLEN, DeviceError, DeviceInfo, LiveCapture,
    OpenError, OpenOptions, OpenWarning, StopHandle, default_device_in, devices,
    format_device_list, resolve_device_in, timestamp_type_from_name,
};

use crate::cli::{ListModes, LiveOptions};

/// A live setup or listing failure with its process exit status.
#[derive(Debug)]
pub struct LiveFailure {
    /// Process exit status.
    pub status: i32,
    /// Packetfin's own wording, printed to standard error by the caller.
    pub message: String,
}

impl LiveFailure {
    fn new(status: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl fmt::Display for LiveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// A packet capture flag for the `if_tsresol` written for every live file.
const LIVE_TSRESOL: TimestampResolution = TimestampResolution::PowerOfTen(6);

/// One open live capture plus the metadata its writer needs.
pub struct LiveSession {
    set: CaptureSet,
    devices: Vec<DeviceInfo>,
    interfaces: Vec<InterfaceInfo>,
    warnings: Vec<OpenWarning>,
    number: u64,
    started: Instant,
}

impl LiveSession {
    /// Resolve the interfaces, open them, and compile the capture filter.
    ///
    /// The filter is installed before the caller creates any output file, so
    /// an invalid expression leaves no empty file behind.
    pub fn open(options: &LiveOptions) -> Result<Self, LiveFailure> {
        let available = devices().map_err(|error| LiveFailure::new(1, error.to_string()))?;
        let selected = selected_devices(&available, options, 1)?;
        let open_options = capture_open_options(options)?;
        let stop = stop_handle()?;
        let mut set = CaptureSet::open(&selected, &open_options, stop)
            .map_err(|error| LiveFailure::new(1, error.to_string()))?;
        if let Some(filter) = &options.capture_filter {
            set.set_filter(filter)
                .map_err(|error| LiveFailure::new(1, error.to_string()))?;
        }
        let interfaces = set
            .captures()
            .iter()
            .enumerate()
            .map(|(index, capture)| interface_info(index, capture))
            .collect();
        let warnings = set
            .captures()
            .iter()
            .flat_map(|capture| capture.warnings().iter().cloned())
            .collect();
        Ok(Self {
            set,
            devices: selected,
            interfaces,
            warnings,
            number: 0,
            started: Instant::now(),
        })
    }

    /// The pcapng interface descriptions, in `-i` order.
    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceInfo] {
        &self.interfaces
    }

    /// The opened devices, in `-i` order.
    #[must_use]
    pub fn devices(&self) -> &[DeviceInfo] {
        &self.devices
    }

    /// Non-fatal conditions reported while opening the interfaces.
    #[must_use]
    pub fn warnings(&self) -> &[OpenWarning] {
        &self.warnings
    }

    /// Time since the handles were opened, for `-a duration`.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.started.elapsed()
    }

    /// Whether SIGINT/SIGTERM (or a caller stop) asked the capture to end.
    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.set.stop_handle().is_stopped()
    }

    /// One poll round: a captured frame, or `None` for an idle interval, a
    /// stop request or an empty set.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        let (index, timestamp, original_len, link_type, captured) = {
            let Some((index, packet)) = self.set.next()? else {
                return Ok(None);
            };
            (
                index,
                packet.timestamp,
                packet.original_len,
                packet.link_type,
                packet.data.to_vec(),
            )
        };
        self.number = self.number.saturating_add(1);
        let device = self.devices.get(index).map(|device| device.name.clone());
        Ok(Some(Frame {
            number: self.number,
            timestamp: Some(timestamp),
            // A live pcapng interface declares 10^-6 seconds; the display
            // precision follows the file, not libpcap's handle precision.
            timestamp_precision: 6,
            captured,
            original_len,
            link_type,
            interface_id: u32::try_from(index).unwrap_or(0),
            global_interface: u32::try_from(index).unwrap_or(0),
            timestamp_units: Some(timestamp_units(timestamp)),
            // Live capture has no file offset; `-a filesize` uses the
            // writer's logical byte count instead.
            source_offset: 0,
            interface_name: device,
            // A live capture is one implicit pcapng section.
            section_number: Some(1),
            comments: Vec::new(),
            options: Default::default(),
        }))
    }

    /// libpcap counters for every interface, in `-i` order.
    pub fn stats(&mut self) -> Result<Vec<CaptureStats>, CaptureError> {
        self.set.stats()
    }
}

/// Render the numbered `-D` list.
pub fn list_devices() -> Result<String, LiveFailure> {
    let available = devices().map_err(|error| LiveFailure::new(1, error.to_string()))?;
    let mut text = format_device_list(&available);
    text.push('\n');
    Ok(text)
}

/// Render the requested `-L` and `--list-time-stamp-types` reports.
pub fn list_capabilities(options: &LiveOptions, modes: ListModes) -> Result<String, LiveFailure> {
    let available = devices().map_err(|error| LiveFailure::new(1, error.to_string()))?;
    let selected = selected_devices(&available, options, 5)?;
    // A capability listing ignores `-y`, `-s`, `-B` and
    // `--time-stamp-type`: only monitor mode selects a different link-type
    // list, and the listing still prints when those other options are
    // unsupported.
    let open_options = OpenOptions {
        monitor: options.monitor,
        ..OpenOptions::default()
    };
    let mut text = String::new();
    for device in &selected {
        let capture = LiveCapture::open(device, &open_options)
            .map_err(|error| LiveFailure::new(list_status(&error), error.to_string()))?;
        if modes.link_types {
            let monitor = if options.monitor {
                " when in monitor mode"
            } else {
                ""
            };
            text.push_str(&format!(
                "Data link types of interface {}{monitor} (use option -y to set):\n",
                device.name
            ));
            let links = capture
                .link_types()
                .map_err(|error| LiveFailure::new(list_status(&error), error.to_string()))?;
            for link in links {
                text.push_str("  ");
                text.push_str(&link.label());
                text.push('\n');
            }
        }
        if modes.timestamp_types {
            text.push_str(
                "Timestamp types of the interface (use option --time-stamp-type to set):\n",
            );
            let types = capture
                .timestamp_types()
                .map_err(|error| LiveFailure::new(list_status(&error), error.to_string()))?;
            for timestamp_type in types {
                text.push_str("  ");
                text.push_str(&timestamp_type.label());
                text.push('\n');
            }
        }
    }
    Ok(text)
}

/// `Capturing on 'A'` with comma-separated labels in `-i` order.
#[must_use]
pub fn capturing_message(devices: &[DeviceInfo]) -> String {
    let labels: Vec<String> = devices.iter().map(device_label).collect();
    format!("Capturing on {}", join_labels(&labels))
}

/// Drop and packet-count lines: per-interface drops when non-zero, then the
/// captured total.
#[must_use]
pub fn stats_message(devices: &[DeviceInfo], stats: &[CaptureStats], captured: u64) -> String {
    let mut text = String::new();
    for (index, counters) in stats.iter().enumerate() {
        let Some(device) = devices.get(index) else {
            continue;
        };
        let label = device_label(device);
        if counters.dropped > 0 {
            text.push_str(&format!(
                "{} dropped from {label}\n",
                packets(counters.dropped)
            ));
        }
        if counters.interface_dropped > 0 {
            text.push_str(&format!(
                "{} dropped by the interface {label}\n",
                packets(counters.interface_dropped)
            ));
        }
    }
    text.push_str(&format!("{} captured\n", packets(captured)));
    text
}

fn interface_info(index: usize, capture: &LiveCapture) -> InterfaceInfo {
    let device = capture.device();
    let mut options = vec![InterfaceOption::Name(device.name.clone())];
    if let Some(description) = &device.description {
        options.push(InterfaceOption::Description(description.clone()));
    }
    options.push(InterfaceOption::Os(std::env::consts::OS.to_owned()));
    options.push(InterfaceOption::TimestampResolution(LIVE_TSRESOL));
    InterfaceInfo {
        global_index: u32::try_from(index).unwrap_or(0),
        link_type: capture.link_type(),
        snap_len: capture.snaplen(),
        options,
    }
}

fn selected_devices(
    available: &[DeviceInfo],
    options: &LiveOptions,
    not_found_status: i32,
) -> Result<Vec<DeviceInfo>, LiveFailure> {
    if options.interfaces.is_empty() {
        return default_device_in(available)
            .map(|device| vec![device])
            .ok_or_else(|| {
                LiveFailure::new(not_found_status, "no capture interfaces are available")
            });
    }
    options
        .interfaces
        .iter()
        .map(|spec| {
            resolve_device_in(available, spec).map_err(|error| {
                let status = match &error {
                    OpenError::Device(DeviceError::NotFound { .. }) => not_found_status,
                    _ => 1,
                };
                LiveFailure::new(status, error.to_string())
            })
        })
        .collect()
}

fn capture_open_options(options: &LiveOptions) -> Result<OpenOptions, LiveFailure> {
    let tstamp_type = match &options.tstamp_type {
        Some(name) => Some(
            timestamp_type_from_name(name)
                .map_err(|error| LiveFailure::new(1, error.to_string()))?,
        ),
        None => None,
    };
    Ok(OpenOptions {
        // Without `-s`, the snapshot length defaults to 524288 bytes;
        // `-s 0` passes zero through for libpcap to clamp.
        snaplen: options.snaplen.or(Some(DEFAULT_SNAPLEN)),
        promisc: options.promisc,
        monitor: options.monitor,
        buffer_bytes: options.buffer_bytes,
        link_type: options.link_type,
        tstamp_type,
        ..OpenOptions::default()
    })
}

fn stop_handle() -> Result<StopHandle, LiveFailure> {
    #[cfg(unix)]
    let result = StopHandle::install_signal_handlers();
    #[cfg(not(unix))]
    let result = StopHandle::new();
    result.map_err(|error| LiveFailure::new(1, error.to_string()))
}

/// An unknown interface name exits 5 for capability lists; every other open
/// failure exits 1.
fn list_status(error: &OpenError) -> i32 {
    match error {
        OpenError::Device(DeviceError::NotFound { .. }) => 5,
        _ => 1,
    }
}

fn device_label(device: &DeviceInfo) -> String {
    match &device.description {
        Some(description) => format!("{description}: {}", device.name),
        None => device.name.clone(),
    }
}

fn join_labels(labels: &[String]) -> String {
    let quoted: Vec<String> = labels.iter().map(|label| format!("'{label}'")).collect();
    match quoted.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [first, second] => format!("{first} and {second}"),
        _ => {
            let Some((last, rest)) = quoted.split_last() else {
                return String::new();
            };
            format!("{}, and {last}", rest.join(", "))
        }
    }
}

fn packets(count: u64) -> String {
    if count == 1 {
        "1 packet".to_string()
    } else {
        format!("{count} packets")
    }
}

/// Raw pcapng timestamp units for a live frame at the declared microsecond
/// resolution.
fn timestamp_units(timestamp: Timestamp) -> u64 {
    let seconds = u64::try_from(timestamp.seconds).unwrap_or(0);
    seconds
        .saturating_mul(1_000_000)
        .saturating_add(u64::from(timestamp.nanos / 1_000))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, description: Option<&str>) -> DeviceInfo {
        DeviceInfo::new(name, description.map(str::to_owned))
    }

    #[test]
    fn one_interface_message_names_the_friendly_label() {
        let listed = vec![device("lo0", Some("Loopback"))];
        assert_eq!(capturing_message(&listed), "Capturing on 'Loopback: lo0'");
    }

    #[test]
    fn multiple_interfaces_keep_order_and_punctuation() {
        let listed = vec![
            device("lo0", Some("Loopback")),
            device("en0", Some("Wi-Fi")),
            device("awdl0", None),
        ];
        assert_eq!(
            capturing_message(&listed),
            "Capturing on 'Loopback: lo0', 'Wi-Fi: en0', and 'awdl0'"
        );
        let two = vec![device("lo0", Some("Loopback")), device("en0", None)];
        assert_eq!(
            capturing_message(&two),
            "Capturing on 'Loopback: lo0' and 'en0'"
        );
    }

    #[test]
    fn stats_report_drops_per_interface_and_a_total() {
        let listed = vec![device("lo0", Some("Loopback")), device("en0", None)];
        let stats = [
            CaptureStats {
                received: 12,
                dropped: 1,
                interface_dropped: 0,
            },
            CaptureStats {
                received: 30,
                dropped: 0,
                interface_dropped: 2,
            },
        ];
        assert_eq!(
            stats_message(&listed, &stats, 42),
            "1 packet dropped from Loopback: lo0\n2 packets dropped by the interface en0\n42 packets captured\n"
        );
    }

    #[test]
    fn timestamp_units_use_microseconds() {
        let timestamp = Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_789,
        };
        assert_eq!(timestamp_units(timestamp), 1_700_000_000_123_456);
    }

    #[test]
    fn negative_timestamps_saturate_to_epoch() {
        let timestamp = Timestamp {
            seconds: -1,
            nanos: 0,
        };
        assert_eq!(timestamp_units(timestamp), 0);
    }
}
