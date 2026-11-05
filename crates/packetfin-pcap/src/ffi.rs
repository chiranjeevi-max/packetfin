//! Raw libpcap entry points that the `pcap` crate does not expose.
//!
//! Everything here is an opaque pointer plus a C ABI call. The safe wrappers
//! in [`crate::capture`], [`crate::tstamp`] and [`crate::set`] own the
//! lifetime rules: the handle must stay alive for the duration of a call, and
//! pointers returned by libpcap are either copied immediately or freed with
//! the matching libpcap free function.

use std::ffi::c_int;

/// Opaque `pcap_t`. The `pcap` crate owns the real object; this type only
/// gives the raw calls a pointer type to accept.
#[repr(C)]
pub struct PcapHandle {
    _private: [u8; 0],
}

unsafe extern "C" {
    /// Active snapshot length; `PCAP_ERROR_NOT_ACTIVATED` when inactive.
    pub fn pcap_snapshot(handle: *mut PcapHandle) -> c_int;
    /// 0 for microsecond, 1 for nanosecond precision.
    pub fn pcap_get_tstamp_precision(handle: *mut PcapHandle) -> c_int;
    /// Numeric timestamp type for a name, or -1 when unknown.
    pub fn pcap_tstamp_type_name_to_val(name: *const std::ffi::c_char) -> c_int;
    /// Name for a numeric timestamp type, or null when unknown.
    pub fn pcap_tstamp_type_val_to_name(value: c_int) -> *const std::ffi::c_char;
    /// Description for a numeric timestamp type, or null when unknown.
    pub fn pcap_tstamp_type_val_to_description(value: c_int) -> *const std::ffi::c_char;
    /// Supported timestamp types; caller frees with `pcap_free_tstamp_types`.
    pub fn pcap_list_tstamp_types(handle: *mut PcapHandle, types: *mut *mut c_int) -> c_int;
    /// Free an array returned by `pcap_list_tstamp_types`.
    pub fn pcap_free_tstamp_types(types: *mut c_int);
    /// Select a timestamp type before activation.
    pub fn pcap_set_tstamp_type(handle: *mut PcapHandle, value: c_int) -> c_int;
    /// File descriptor that becomes readable when packets are available.
    #[cfg(unix)]
    pub fn pcap_get_selectable_fd(handle: *mut PcapHandle) -> c_int;
}
