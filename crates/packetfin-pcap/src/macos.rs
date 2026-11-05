//! Friendly interface names.
//!
//! macOS libpcap reports no interface descriptions, while Packetfin shows names
//! such as `Wi-Fi`. SystemConfiguration is the system source for those names;
//! the query maps an interface's BSD name to its localized display name.
//! Linux and Windows already get descriptions from libpcap/Npcap.

#[cfg(not(target_os = "macos"))]
use std::collections::HashMap;

#[cfg(target_os = "macos")]
mod platform {
    use std::collections::HashMap;
    use std::ffi::{c_char, c_void};

    type CfIndex = isize;
    type CfStringEncoding = u32;
    type Boolean = u8;

    const CF_STRING_ENCODING_UTF8: CfStringEncoding = 0x0800_0100;
    const MAX_NAME_BYTES: usize = 4_096;

    #[repr(C)]
    struct __ScNetworkInterface {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct __CfArray {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct __CfString {
        _private: [u8; 0],
    }

    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCNetworkInterfaceCopyAll() -> *const __CfArray;
        fn SCNetworkInterfaceGetBSDName(
            interface: *const __ScNetworkInterface,
        ) -> *const __CfString;
        fn SCNetworkInterfaceGetLocalizedDisplayName(
            interface: *const __ScNetworkInterface,
        ) -> *const __CfString;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFArrayGetCount(array: *const __CfArray) -> CfIndex;
        fn CFArrayGetValueAtIndex(array: *const __CfArray, index: CfIndex) -> *const c_void;
        fn CFStringGetLength(string: *const __CfString) -> CfIndex;
        fn CFStringGetMaximumSizeForEncoding(
            length: CfIndex,
            encoding: CfStringEncoding,
        ) -> CfIndex;
        fn CFStringGetCString(
            string: *const __CfString,
            buffer: *mut c_char,
            buffer_size: CfIndex,
            encoding: CfStringEncoding,
        ) -> Boolean;
        fn CFRelease(value: *const c_void);
    }

    /// Convert a borrowed CFString into an owned Rust string.
    fn string_from_cf(value: *const __CfString) -> Option<String> {
        if value.is_null() {
            return None;
        }
        // SAFETY: `value` is a non-null CFString owned by the caller for the
        // duration of this call.
        unsafe {
            let length = CFStringGetLength(value);
            if length < 0 {
                return None;
            }
            let maximum = CFStringGetMaximumSizeForEncoding(length, CF_STRING_ENCODING_UTF8);
            if maximum < 0 {
                return None;
            }
            let size = usize::try_from(maximum).ok()?.checked_add(1)?;
            if size > MAX_NAME_BYTES {
                return None;
            }
            let mut buffer = vec![0_u8; size];
            let buffer_size = CfIndex::try_from(size).ok()?;
            let converted = CFStringGetCString(
                value,
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer_size,
                CF_STRING_ENCODING_UTF8,
            );
            if converted == 0 {
                return None;
            }
            let end = buffer
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(buffer.len());
            String::from_utf8(buffer.get(..end)?.to_vec()).ok()
        }
    }

    pub(crate) fn friendly_names() -> HashMap<String, String> {
        let mut names = HashMap::new();
        // SAFETY: SCNetworkInterfaceCopyAll returns an owned CFArray or null;
        // every borrowed value stays valid until the array is released.
        unsafe {
            let array = SCNetworkInterfaceCopyAll();
            if array.is_null() {
                return names;
            }
            let count = CFArrayGetCount(array);
            let mut index = 0;
            while index < count {
                let interface = CFArrayGetValueAtIndex(array, index).cast::<__ScNetworkInterface>();
                if !interface.is_null() {
                    let bsd = string_from_cf(SCNetworkInterfaceGetBSDName(interface));
                    let display =
                        string_from_cf(SCNetworkInterfaceGetLocalizedDisplayName(interface));
                    if let (Some(bsd), Some(display)) = (bsd, display)
                        && !bsd.is_empty()
                        && !display.is_empty()
                    {
                        names.entry(bsd).or_insert(display);
                    }
                }
                index = index.saturating_add(1);
            }
            CFRelease(array.cast::<c_void>());
        }
        names
    }
}

#[cfg(target_os = "macos")]
pub(crate) use platform::friendly_names;

/// Other platforms take descriptions from libpcap/Npcap directly.
#[cfg(not(target_os = "macos"))]
pub(crate) fn friendly_names() -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    #[test]
    fn friendly_names_never_panic() {
        let names = super::friendly_names();
        assert!(names.len() < 1_000);
    }
}
