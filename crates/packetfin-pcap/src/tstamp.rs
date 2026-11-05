//! Timestamp-type discovery and name lookup.

use std::ffi::{CStr, CString, c_char};

use crate::error::OpenError;
use crate::ffi;

/// One libpcap timestamp type, as shown by `--list-time-stamp-types`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampTypeInfo {
    /// Numeric value used by `pcap_set_tstamp_type`.
    pub value: u32,
    /// Short name such as `host`.
    pub name: String,
    /// Human-readable description such as `Host`.
    pub description: String,
}

impl TimestampTypeInfo {
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

/// Resolve a timestamp type name such as `host` or `adapter`.
pub fn timestamp_type_from_name(name: &str) -> Result<u32, OpenError> {
    let name = CString::new(name).map_err(|_| OpenError::TimestampType {
        message: format!("'{name}' contains a NUL byte"),
    })?;
    // SAFETY: `name` is a valid NUL-terminated string for the call.
    let value = unsafe { ffi::pcap_tstamp_type_name_to_val(name.as_ptr()) };
    if value < 0 {
        return Err(OpenError::TimestampType {
            message: format!("unknown name '{}'", name.to_string_lossy()),
        });
    }
    Ok(u32::try_from(value).unwrap_or(0))
}

/// Describe one numeric timestamp type, falling back to `type_<value>`.
#[must_use]
pub fn timestamp_type_info(value: u32) -> TimestampTypeInfo {
    let raw = i32::try_from(value).unwrap_or(-1);
    // SAFETY: both calls return borrowed static strings or null; they are
    // copied before the next libpcap call.
    let name = unsafe { string_from_pointer(ffi::pcap_tstamp_type_val_to_name(raw)) }
        .unwrap_or_else(|| format!("type_{value}"));
    let description = unsafe { string_from_pointer(ffi::pcap_tstamp_type_val_to_description(raw)) }
        .unwrap_or_default();
    TimestampTypeInfo {
        value,
        name,
        description,
    }
}

/// Copy a borrowed C string, returning `None` for null or non-UTF-8 text.
///
/// # Safety
///
/// `pointer` must be null or point to a NUL-terminated string that remains
/// valid for the duration of the call.
pub(crate) unsafe fn string_from_pointer(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: guaranteed by the caller.
    let text = unsafe { CStr::from_ptr(pointer) };
    text.to_str().ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_resolves_on_every_supported_libpcap() {
        let value = timestamp_type_from_name("host");
        assert!(matches!(value, Ok(0)));
    }

    #[test]
    fn unknown_name_is_typed() {
        assert!(matches!(
            timestamp_type_from_name("not-a-timestamp-type"),
            Err(OpenError::TimestampType { .. })
        ));
    }

    #[test]
    fn name_with_nul_is_typed() {
        assert!(matches!(
            timestamp_type_from_name("host\0trailing"),
            Err(OpenError::TimestampType { .. })
        ));
    }

    #[test]
    fn host_description_is_present() {
        let info = timestamp_type_info(0);
        assert_eq!(info.value, 0);
        assert_eq!(info.name, "host");
        assert_eq!(info.description, "Host");
        assert_eq!(info.label(), "host (Host)");
    }

    #[test]
    fn unknown_value_falls_back_to_a_stable_name() {
        let info = timestamp_type_info(9_999);
        assert_eq!(info.value, 9_999);
        assert_eq!(info.name, "type_9999");
        assert_eq!(info.description, "");
        assert_eq!(info.label(), "type_9999");
    }

    #[test]
    fn null_pointer_has_no_string() {
        // SAFETY: the helper explicitly accepts null.
        assert_eq!(unsafe { string_from_pointer(std::ptr::null()) }, None);
    }
}
