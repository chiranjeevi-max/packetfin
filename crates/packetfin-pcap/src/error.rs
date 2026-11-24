//! Typed errors for device lookup, capture opening and packet reads.
//!
//! The variants exist so the command-line layer can map failures onto
//! its exit codes and wording without parsing libpcap strings a second
//! time. Activation failures are classified by libpcap's status code first,
//! and by its message when the code does not settle the variant.

use std::ffi::c_int;
use std::fmt;

use crate::ffi;

/// Why an interface selector or the device list failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// No interface has the requested name.
    NotFound { spec: String },
    /// A one-based numeric selector is zero or beyond the list.
    IndexOutOfRange { index: u64, count: usize },
    /// libpcap could not enumerate interfaces.
    List { message: String },
}

impl fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { spec } => {
                write!(formatter, "no capture interface named '{spec}'")
            }
            Self::IndexOutOfRange { index, count } => {
                if *count == 0 {
                    write!(
                        formatter,
                        "interface index {index} is out of range: no interfaces are available"
                    )
                } else {
                    write!(
                        formatter,
                        "interface index {index} is out of range: choose 1 through {count}"
                    )
                }
            }
            Self::List { message } => {
                write!(formatter, "could not list capture interfaces: {message}")
            }
        }
    }
}

impl std::error::Error for DeviceError {}

/// A non-fatal condition reported while opening a capture.
///
/// libpcap can activate a handle and still return a warning, for example when
/// an interface cannot enter promiscuous mode. The capture keeps running, and
/// [`crate::LiveCapture::warnings`] exposes the warning for the caller to print.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenWarning {
    /// Promiscuous mode was requested but the interface rejected it.
    PromiscuousNotSupported { device: String, message: String },
    /// libpcap activated the capture with another warning.
    Activation { device: String, message: String },
}

impl fmt::Display for OpenWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PromiscuousNotSupported { device, message } => {
                write!(
                    formatter,
                    "promiscuous mode is not supported on '{device}': {message}"
                )
            }
            Self::Activation { device, message } => {
                write!(
                    formatter,
                    "capture on '{device}' opened with a warning: {message}"
                )
            }
        }
    }
}

impl std::error::Error for OpenWarning {}

/// Why a live capture could not be opened or configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Interface enumeration or selector resolution failed.
    Device(DeviceError),
    /// The capture handle could not be created or activated.
    Open { device: String, message: String },
    /// The operating system refused access to the capture device.
    Permission { device: String, message: String },
    /// The capture filter did not compile.
    Filter { expression: String, message: String },
    /// The requested link type is unknown or unsupported by the interface.
    LinkType { message: String },
    /// The requested timestamp type is unknown or unsupported.
    TimestampType { message: String },
    /// Monitor (rfmon) mode was requested but the interface cannot provide it.
    Monitor { message: String },
    /// The requested kernel capture buffer size is invalid.
    Buffer { message: String },
    /// The requested snapshot length is invalid.
    Snaplen { message: String },
    /// The read timeout is negative.
    Timeout { message: String },
}

impl fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => error.fmt(formatter),
            Self::Open { device, message } => {
                write!(formatter, "could not open capture on '{device}': {message}")
            }
            Self::Permission { device, message } => {
                write!(
                    formatter,
                    "no permission to capture on '{device}': {message}"
                )
            }
            Self::Filter {
                expression,
                message,
            } => {
                write!(
                    formatter,
                    "invalid capture filter '{expression}': {message}"
                )
            }
            Self::LinkType { message } => {
                write!(formatter, "unsupported link type: {message}")
            }
            Self::TimestampType { message } => {
                write!(formatter, "unsupported timestamp type: {message}")
            }
            Self::Monitor { message } => {
                write!(formatter, "monitor mode is not available: {message}")
            }
            Self::Buffer { message } => {
                write!(formatter, "invalid capture buffer size: {message}")
            }
            Self::Snaplen { message } => {
                write!(formatter, "invalid snapshot length: {message}")
            }
            Self::Timeout { message } => {
                write!(formatter, "invalid capture timeout: {message}")
            }
        }
    }
}

impl std::error::Error for OpenError {}

impl From<DeviceError> for OpenError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

/// Why a packet could not be read or statistics could not be fetched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureError {
    /// libpcap reported an error while reading from a live handle.
    Read { device: String, message: String },
    /// libpcap reported an error while fetching counters.
    Stats { device: String, message: String },
    /// A timestamp carried an out-of-range fractional second.
    Timestamp { device: String, message: String },
    /// Waiting for packet readiness failed.
    Poll { message: String },
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { device, message } => {
                write!(formatter, "capture read failed on '{device}': {message}")
            }
            Self::Stats { device, message } => {
                write!(
                    formatter,
                    "capture statistics failed on '{device}': {message}"
                )
            }
            Self::Timestamp { device, message } => {
                write!(formatter, "invalid timestamp from '{device}': {message}")
            }
            Self::Poll { message } => {
                write!(formatter, "waiting for captured packets failed: {message}")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

/// Decide which typed error a failed activation represents.
///
/// libpcap's specific status codes decide first. Any other code carries the
/// detail only in its message, so the message is matched as a fallback, in
/// one place instead of through the open path.
pub(crate) fn classify_activation(
    device: &str,
    monitor_requested: bool,
    status: c_int,
    message: String,
) -> OpenError {
    match status {
        ffi::PCAP_ERROR_PERM_DENIED | ffi::PCAP_ERROR_PROMISC_PERM_DENIED => {
            return OpenError::Permission {
                device: device.to_owned(),
                message,
            };
        }
        ffi::PCAP_ERROR_RFMON_NOTSUP if monitor_requested => {
            return OpenError::Monitor { message };
        }
        _ => {}
    }
    let lower = message.to_ascii_lowercase();
    let permission = lower.contains("permission")
        || lower.contains("not permitted")
        || lower.contains("access denied")
        || lower.contains("operation not permitted");
    if permission {
        return OpenError::Permission {
            device: device.to_owned(),
            message,
        };
    }
    let monitor =
        lower.contains("monitor") || lower.contains("rfmon") || lower.contains("radiotap");
    if monitor_requested && monitor {
        return OpenError::Monitor { message };
    }
    if lower.contains("buffer") {
        return OpenError::Buffer { message };
    }
    OpenError::Open {
        device: device.to_owned(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// libpcap's generic `PCAP_ERROR`, which carries detail only in text.
    const GENERIC: c_int = -1;

    #[test]
    fn device_errors_display() {
        let not_found = DeviceError::NotFound {
            spec: "bogus".to_owned(),
        };
        assert_eq!(not_found.to_string(), "no capture interface named 'bogus'");
        let index = DeviceError::IndexOutOfRange { index: 9, count: 5 };
        assert_eq!(
            index.to_string(),
            "interface index 9 is out of range: choose 1 through 5"
        );
        let empty = DeviceError::IndexOutOfRange { index: 1, count: 0 };
        assert!(empty.to_string().contains("no interfaces"));
    }

    #[test]
    fn open_errors_display_the_device_and_detail() {
        let error = OpenError::Permission {
            device: "en0".to_owned(),
            message: "Operation not permitted".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "no permission to capture on 'en0': Operation not permitted"
        );
        let filter = OpenError::Filter {
            expression: "not a filter".to_owned(),
            message: "syntax error".to_owned(),
        };
        assert_eq!(
            filter.to_string(),
            "invalid capture filter 'not a filter': syntax error"
        );
    }

    #[test]
    fn activation_messages_classify_permission() {
        let error = classify_activation(
            "en0",
            false,
            GENERIC,
            "You don't have permission to capture on that device (socket: Operation not permitted)"
                .to_owned(),
        );
        assert!(matches!(error, OpenError::Permission { .. }));
    }

    #[test]
    fn activation_messages_classify_monitor_only_when_requested() {
        let message = "monitor mode not supported on that device".to_owned();
        let requested = classify_activation("lo0", true, GENERIC, message.clone());
        assert!(matches!(requested, OpenError::Monitor { .. }));
        let not_requested = classify_activation("lo0", false, GENERIC, message);
        assert!(matches!(not_requested, OpenError::Open { .. }));
    }

    #[test]
    fn activation_messages_classify_buffer() {
        let error = classify_activation(
            "en0",
            false,
            GENERIC,
            "could not set buffer size".to_owned(),
        );
        assert!(matches!(error, OpenError::Buffer { .. }));
    }

    #[test]
    fn activation_messages_fall_back_to_open() {
        let error = classify_activation("en0", false, GENERIC, "BIOCSETIF failed".to_owned());
        match error {
            OpenError::Open { device, message } => {
                assert_eq!(device, "en0");
                assert_eq!(message, "BIOCSETIF failed");
            }
            other => unreachable!("unexpected {other:?}"),
        }
    }

    #[test]
    fn activation_status_codes_classify_before_messages() {
        let denied = classify_activation("en0", false, ffi::PCAP_ERROR_PERM_DENIED, String::new());
        assert!(matches!(denied, OpenError::Permission { .. }));
        let promisc = classify_activation(
            "en0",
            false,
            ffi::PCAP_ERROR_PROMISC_PERM_DENIED,
            "no detail".to_owned(),
        );
        assert!(matches!(promisc, OpenError::Permission { .. }));
        let rfmon = classify_activation("en0", true, ffi::PCAP_ERROR_RFMON_NOTSUP, String::new());
        assert!(matches!(rfmon, OpenError::Monitor { .. }));
        let rfmon_unrequested =
            classify_activation("en0", false, ffi::PCAP_ERROR_RFMON_NOTSUP, String::new());
        assert!(matches!(rfmon_unrequested, OpenError::Open { .. }));
    }

    #[test]
    fn open_warning_displays_the_device() {
        let warning = OpenWarning::PromiscuousNotSupported {
            device: "awdl0".to_owned(),
            message: "BIOCPROMISC: Operation not supported on socket".to_owned(),
        };
        assert_eq!(
            warning.to_string(),
            "promiscuous mode is not supported on 'awdl0': BIOCPROMISC: Operation not supported on socket"
        );
        let other = OpenWarning::Activation {
            device: "en0".to_owned(),
            message: "Warning".to_owned(),
        };
        assert_eq!(
            other.to_string(),
            "capture on 'en0' opened with a warning: Warning"
        );
    }
}
