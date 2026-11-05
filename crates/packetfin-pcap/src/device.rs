//! Interface enumeration, friendly names and selector resolution.
//!
//! libpcap lists interfaces in its own order; the command line uses that order
//! for `-D` and for one-based `-i` indexes. macOS libpcap leaves descriptions
//! empty, so friendly names come from SystemConfiguration there.

use crate::error::{DeviceError, OpenError};

/// One capture interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The name libpcap accepts, such as `lo0` or `eth0`.
    pub name: String,
    /// A human-readable name, when the platform supplies one.
    pub description: Option<String>,
    /// Whether this is a loopback interface.
    pub loopback: bool,
}

impl DeviceInfo {
    /// Build a device record, normalizing an empty description to `None`.
    pub fn new(name: impl Into<String>, description: Option<String>) -> Self {
        let name = name.into();
        let loopback = is_loopback_name(&name);
        Self {
            name,
            description: description.filter(|value| !value.is_empty()),
            loopback,
        }
    }

    /// Build a device record from libpcap's loopback flag.
    pub(crate) fn with_flags(
        name: impl Into<String>,
        description: Option<String>,
        loopback: bool,
    ) -> Self {
        let name = name.into();
        let loopback = loopback || is_loopback_name(&name);
        Self {
            name,
            description: description.filter(|value| !value.is_empty()),
            loopback,
        }
    }

    /// The description when present, otherwise the interface name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.description.as_deref().unwrap_or(&self.name)
    }

    /// `name (description)`, or just `name` when no description is known.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.description {
            Some(description) => format!("{} ({description})", self.name),
            None => self.name.clone(),
        }
    }
}

/// Whether an interface name denotes loopback on any supported platform.
#[must_use]
pub fn is_loopback_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "lo" || lower.starts_with("lo0") || lower.contains("loopback")
}

/// Enumerate capture interfaces in libpcap order.
pub fn devices() -> Result<Vec<DeviceInfo>, OpenError> {
    let listed = pcap::Device::list().map_err(|error| DeviceError::List {
        message: error.to_string(),
    })?;
    let friendly = crate::macos::friendly_names();
    let mut devices = Vec::with_capacity(listed.len());
    for device in listed {
        #[cfg(target_os = "macos")]
        let description = friendly.get(&device.name).cloned().or(device.desc);
        #[cfg(not(target_os = "macos"))]
        let description = {
            let _ = &friendly;
            device.desc
        };
        let loopback = device.flags.is_loopback();
        let mut info = DeviceInfo::with_flags(device.name, description, loopback);
        if info.description.is_none() && info.loopback {
            // Name a loopback interface "Loopback" when libpcap and
            // SystemConfiguration both leave the description empty.
            info.description = Some("Loopback".to_owned());
        }
        devices.push(info);
    }
    Ok(devices)
}

/// The default interface: the first non-loopback entry, else the first entry.
pub fn default_device() -> Result<DeviceInfo, OpenError> {
    let listed = devices()?;
    default_device_in(&listed).ok_or_else(|| {
        DeviceError::NotFound {
            spec: "default".to_owned(),
        }
        .into()
    })
}

/// Pick the default interface from an already enumerated list.
#[must_use]
pub fn default_device_in(devices: &[DeviceInfo]) -> Option<DeviceInfo> {
    devices
        .iter()
        .find(|device| !device.loopback)
        .or_else(|| devices.first())
        .cloned()
}

/// Resolve an exact interface name or a one-based decimal index.
pub fn resolve_device(spec: &str) -> Result<DeviceInfo, OpenError> {
    let listed = devices()?;
    resolve_device_in(&listed, spec)
}

/// Resolve a selector against an already enumerated list.
///
/// An exact name always wins, so an interface literally named `2` remains
/// reachable. A decimal selector that is not a name is treated as a one-based
/// index, matching `-i`'s observed behavior.
pub fn resolve_device_in(devices: &[DeviceInfo], spec: &str) -> Result<DeviceInfo, OpenError> {
    if let Some(exact) = devices.iter().find(|device| device.name == spec) {
        return Ok(exact.clone());
    }
    if let Some(index) = parse_index(spec) {
        return resolve_index_in(devices, index);
    }
    Err(DeviceError::NotFound {
        spec: spec.to_owned(),
    }
    .into())
}

/// Resolve a one-based index against an already enumerated list.
pub fn resolve_index_in(devices: &[DeviceInfo], index: u64) -> Result<DeviceInfo, OpenError> {
    let position = usize::try_from(index)
        .ok()
        .and_then(|value| value.checked_sub(1))
        .filter(|value| *value < devices.len());
    match position.and_then(|value| devices.get(value)) {
        Some(device) => Ok(device.clone()),
        None => Err(DeviceError::IndexOutOfRange {
            index,
            count: devices.len(),
        }
        .into()),
    }
}

fn parse_index(spec: &str) -> Option<u64> {
    if spec.is_empty() || !spec.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    spec.parse::<u64>().ok()
}

/// Render `-D`-style numbered lines, one per interface.
#[must_use]
pub fn format_device_list(devices: &[DeviceInfo]) -> String {
    let mut output = String::new();
    for (position, device) in devices.iter().enumerate() {
        let number = position.saturating_add(1);
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&format!("{number}. {}", device.label()));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn sample() -> Vec<DeviceInfo> {
        vec![
            DeviceInfo::new("lo0", Some("Loopback".to_owned())),
            DeviceInfo::new("en0", Some("Wi-Fi".to_owned())),
            DeviceInfo::new("utun0", None),
        ]
    }

    #[test]
    fn empty_description_becomes_none() {
        let device = DeviceInfo::new("en0", Some(String::new()));
        assert_eq!(device.description, None);
        assert_eq!(device.display_name(), "en0");
        assert_eq!(device.label(), "en0");
    }

    #[test]
    fn label_uses_the_description() {
        let device = DeviceInfo::new("lo0", Some("Loopback".to_owned()));
        assert_eq!(device.label(), "lo0 (Loopback)");
    }

    #[test]
    fn loopback_names_cover_all_platforms() {
        assert!(is_loopback_name("lo"));
        assert!(is_loopback_name("lo0"));
        assert!(is_loopback_name("\\Device\\NPF_Loopback"));
        assert!(!is_loopback_name("en0"));
        assert!(!is_loopback_name("utun0"));
    }

    #[test]
    fn exact_name_wins_over_a_numeric_index() {
        let devices = vec![DeviceInfo::new("2", None), DeviceInfo::new("en0", None)];
        let resolved = resolve_device_in(&devices, "2");
        assert!(matches!(resolved, Ok(device) if device.name == "2"));
    }

    #[test]
    fn one_based_index_resolves() {
        let devices = sample();
        let first = resolve_device_in(&devices, "1");
        assert!(matches!(first, Ok(device) if device.name == "lo0"));
        let third = resolve_device_in(&devices, "3");
        assert!(matches!(third, Ok(device) if device.name == "utun0"));
    }

    #[test]
    fn index_zero_is_out_of_range() {
        let devices = sample();
        match resolve_device_in(&devices, "0") {
            Err(OpenError::Device(DeviceError::IndexOutOfRange { index, count })) => {
                assert_eq!(index, 0);
                assert_eq!(count, 3);
            }
            other => unreachable!("unexpected {other:?}"),
        }
    }

    #[test]
    fn index_past_the_end_is_out_of_range() {
        let devices = sample();
        match resolve_device_in(&devices, "99") {
            Err(OpenError::Device(DeviceError::IndexOutOfRange { index, count })) => {
                assert_eq!(index, 99);
                assert_eq!(count, 3);
            }
            other => unreachable!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unknown_name_is_not_found() {
        let devices = sample();
        match resolve_device_in(&devices, "bogus") {
            Err(OpenError::Device(DeviceError::NotFound { spec })) => assert_eq!(spec, "bogus"),
            other => unreachable!("unexpected {other:?}"),
        }
    }

    #[test]
    fn empty_selector_is_not_found() {
        let devices = sample();
        assert!(matches!(
            resolve_device_in(&devices, ""),
            Err(OpenError::Device(DeviceError::NotFound { .. }))
        ));
    }

    #[test]
    fn default_prefers_the_first_non_loopback() {
        let devices = sample();
        let default = default_device_in(&devices);
        assert!(matches!(default, Some(device) if device.name == "en0"));
    }

    #[test]
    fn default_falls_back_to_the_first_interface() {
        let devices = vec![DeviceInfo::new("lo0", None)];
        let default = default_device_in(&devices);
        assert!(matches!(default, Some(device) if device.name == "lo0"));
    }

    #[test]
    fn default_of_an_empty_list_is_none() {
        assert!(default_device_in(&[]).is_none());
    }

    #[test]
    fn device_list_is_numbered_from_one() {
        let devices = sample();
        assert_eq!(
            format_device_list(&devices),
            "1. lo0 (Loopback)\n2. en0 (Wi-Fi)\n3. utun0"
        );
    }

    #[test]
    fn friendly_names_are_optional() {
        // The platform lookup may return nothing in a sandbox; the map must
        // still be usable and never panic.
        let names: HashMap<String, String> = crate::macos::friendly_names();
        for (name, friendly) in names {
            assert!(!name.is_empty());
            assert!(!friendly.is_empty());
        }
    }
}
