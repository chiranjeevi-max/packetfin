//! Safe ownership of libpcap handles, interface lists and lookup tables.
//!
//! [`Handle`] owns one `pcap_t` from `pcap_create` and closes it on drop.
//! Each method is one libpcap call with its pointer contract checked here,
//! so the rest of the crate never touches a raw handle except through
//! [`Handle::as_ptr`] for the timestamp-type calls in [`crate::capture`].

use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::{self, NonNull};

use crate::ffi;

/// Largest number of interfaces or link types accepted from libpcap.
///
/// A real host has far fewer; the bound stops a corrupt list from looping
/// or allocating without limit.
const MAX_LIST_ENTRIES: usize = 4096;

/// Text for an unknown link-type name or value.
pub(crate) const UNKNOWN_LINK_TYPE: &str = "invalid or unknown linktype";

/// Result of `pcap_activate`.
#[derive(Debug)]
pub(crate) enum Activation {
    /// Activated with no warning.
    Ready,
    /// Activated, but promiscuous mode is not supported.
    PromiscuousNotSupported(String),
    /// Not activated: a negative error or any other warning.
    Failed { status: c_int, message: String },
}

/// One packet borrowed from a handle until the next read.
pub(crate) struct RawPacket<'a> {
    pub(crate) timestamp: libc::timeval,
    pub(crate) original_len: u32,
    pub(crate) data: &'a [u8],
}

/// Capture counters from `pcap_stats`.
pub(crate) struct RawStats {
    pub(crate) received: u32,
    pub(crate) dropped: u32,
    pub(crate) interface_dropped: u32,
}

/// One interface from `pcap_findalldevs`.
pub(crate) struct RawDevice {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) loopback: bool,
}

/// An owned libpcap handle.
pub(crate) struct Handle {
    raw: NonNull<ffi::PcapHandle>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `raw` came from pcap_create, is closed exactly once here,
        // and no borrowed packet outlives `self`.
        unsafe { ffi::pcap_close(self.raw.as_ptr()) };
    }
}

impl Handle {
    /// Create an inactive handle for an interface name.
    pub(crate) fn create(source: &str) -> Result<Self, String> {
        let source = CString::new(source).map_err(|_| nul_error("interface name"))?;
        let mut errbuf = ErrorBuffer::new();
        // SAFETY: both pointers are valid for the call; libpcap copies the
        // name and writes at most PCAP_ERRBUF_SIZE bytes to the buffer.
        let raw = unsafe { ffi::pcap_create(source.as_ptr(), errbuf.as_mut_ptr()) };
        NonNull::new(raw)
            .map(|raw| Self { raw })
            .ok_or_else(|| errbuf.text())
    }

    /// The raw handle, for calls this module does not wrap.
    pub(crate) fn as_ptr(&self) -> *mut ffi::PcapHandle {
        self.raw.as_ptr()
    }

    /// Request a snapshot length before activation.
    pub(crate) fn set_snaplen(&mut self, snaplen: c_int) -> Result<(), String> {
        // SAFETY: the handle is alive; the call takes no other pointer.
        let status = unsafe { ffi::pcap_set_snaplen(self.as_ptr(), snaplen) };
        self.check(status)
    }

    /// Request promiscuous mode before activation.
    pub(crate) fn set_promisc(&mut self, promisc: bool) -> Result<(), String> {
        // SAFETY: the handle is alive; the call takes no other pointer.
        let status = unsafe { ffi::pcap_set_promisc(self.as_ptr(), c_int::from(promisc)) };
        self.check(status)
    }

    /// Request a read timeout before activation.
    pub(crate) fn set_timeout(&mut self, milliseconds: c_int) -> Result<(), String> {
        // SAFETY: the handle is alive; the call takes no other pointer.
        let status = unsafe { ffi::pcap_set_timeout(self.as_ptr(), milliseconds) };
        self.check(status)
    }

    /// Request a kernel buffer size before activation.
    pub(crate) fn set_buffer_size(&mut self, bytes: c_int) -> Result<(), String> {
        // SAFETY: the handle is alive; the call takes no other pointer.
        let status = unsafe { ffi::pcap_set_buffer_size(self.as_ptr(), bytes) };
        self.check(status)
    }

    /// Request monitor mode before activation.
    #[cfg(not(windows))]
    pub(crate) fn set_rfmon(&mut self, rfmon: bool) -> Result<(), String> {
        // SAFETY: the handle is alive; the call takes no other pointer.
        let status = unsafe { ffi::pcap_set_rfmon(self.as_ptr(), c_int::from(rfmon)) };
        self.check(status)
    }

    /// Activate the handle.
    ///
    /// A promiscuous-mode warning leaves the handle active and is reported
    /// as such. Any other warning fails the open, as a negative status does.
    pub(crate) fn activate(&mut self) -> Activation {
        // SAFETY: the handle is alive and not yet active.
        let status = unsafe { ffi::pcap_activate(self.as_ptr()) };
        match status {
            0 => Activation::Ready,
            ffi::PCAP_WARNING_PROMISC_NOTSUP => {
                Activation::PromiscuousNotSupported(self.status_message(status))
            }
            _ => Activation::Failed {
                status,
                message: self.status_message(status),
            },
        }
    }

    /// Switch an active handle to non-blocking reads.
    pub(crate) fn set_nonblocking(&mut self) -> Result<(), String> {
        let mut errbuf = ErrorBuffer::new();
        // SAFETY: the handle is alive; libpcap writes at most
        // PCAP_ERRBUF_SIZE bytes to the buffer.
        let status = unsafe { ffi::pcap_setnonblock(self.as_ptr(), 1, errbuf.as_mut_ptr()) };
        if status < 0 {
            Err(errbuf.text())
        } else {
            Ok(())
        }
    }

    /// Link type of the active handle.
    pub(crate) fn datalink(&self) -> c_int {
        // SAFETY: the handle is alive; the call takes no other pointer.
        unsafe { ffi::pcap_datalink(self.as_ptr()) }
    }

    /// Select a link type on the active handle.
    pub(crate) fn set_datalink(&mut self, link_type: c_int) -> Result<(), String> {
        // SAFETY: the handle is alive; the call takes no other pointer.
        let status = unsafe { ffi::pcap_set_datalink(self.as_ptr(), link_type) };
        if status < 0 {
            Err(self.last_error())
        } else {
            Ok(())
        }
    }

    /// Link types the active handle supports.
    pub(crate) fn datalinks(&self) -> Result<Vec<c_int>, String> {
        let mut list: *mut c_int = ptr::null_mut();
        // SAFETY: the handle is alive; on success libpcap stores an array of
        // `count` values in `list`, copied and freed below.
        let count = unsafe { ffi::pcap_list_datalinks(self.as_ptr(), &mut list) };
        if count < 0 {
            return Err(self.last_error());
        }
        let values = copy_ints(list, count);
        if !list.is_null() {
            // SAFETY: allocated by pcap_list_datalinks and not used again.
            unsafe { ffi::pcap_free_datalinks(list) };
        }
        values
    }

    /// Compile a filter expression and install it.
    pub(crate) fn set_filter(&mut self, expression: &str) -> Result<(), String> {
        let expression = CString::new(expression).map_err(|_| nul_error("filter"))?;
        let mut program = ffi::BpfProgram {
            bf_len: 0,
            bf_insns: ptr::null_mut(),
        };
        // SAFETY: the handle, program and expression are valid for the call;
        // libpcap fills `program` only on success.
        let compiled = unsafe {
            ffi::pcap_compile(
                self.as_ptr(),
                &mut program,
                expression.as_ptr(),
                1,
                ffi::COMPILE_NETMASK,
            )
        };
        if compiled < 0 {
            return Err(self.last_error());
        }
        // SAFETY: `program` was filled by pcap_compile; libpcap copies it.
        let installed = unsafe { ffi::pcap_setfilter(self.as_ptr(), &mut program) };
        let result = if installed < 0 {
            Err(self.last_error())
        } else {
            Ok(())
        };
        // SAFETY: `program` came from a successful pcap_compile and is freed
        // exactly once.
        unsafe { ffi::pcap_freecode(&mut program) };
        result
    }

    /// Read the next packet, or `None` when the read timed out.
    pub(crate) fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, String> {
        let mut header: *mut ffi::PcapPkthdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: the handle is alive; libpcap stores pointers to buffers it
        // owns until the next read on this handle, which `&mut self`
        // prevents while the packet is borrowed.
        let status = unsafe { ffi::pcap_next_ex(self.as_ptr(), &mut header, &mut data) };
        match status {
            1 => {
                // SAFETY: on status 1 libpcap stores a valid header pointer.
                let Some(header) = (unsafe { header.as_ref() }) else {
                    return Err("libpcap returned a packet without a header".to_owned());
                };
                let captured = usize::try_from(header.caplen)
                    .map_err(|_| "captured length does not fit in memory".to_owned())?;
                let data = if captured == 0 {
                    &[][..]
                } else if data.is_null() {
                    return Err("libpcap returned a packet without data".to_owned());
                } else {
                    // SAFETY: libpcap guarantees `caplen` readable bytes at
                    // `data` until the next read on this handle.
                    unsafe { std::slice::from_raw_parts(data, captured) }
                };
                Ok(Some(RawPacket {
                    timestamp: header.ts,
                    original_len: header.len,
                    data,
                }))
            }
            // A live read timed out (0) or a source ran out of packets (-2).
            0 | -2 => Ok(None),
            _ => Err(self.last_error()),
        }
    }

    /// Counters since activation.
    pub(crate) fn stats(&mut self) -> Result<RawStats, String> {
        let mut stats = ffi::PcapStat::default();
        // SAFETY: the handle is alive and `stats` is a full-size pcap_stat
        // for this platform.
        let status = unsafe { ffi::pcap_stats(self.as_ptr(), &mut stats) };
        if status < 0 {
            return Err(self.last_error());
        }
        Ok(RawStats {
            received: stats.ps_recv,
            dropped: stats.ps_drop,
            interface_dropped: stats.ps_ifdrop,
        })
    }

    /// Fail with the status text when a setter returns nonzero.
    fn check(&self, status: c_int) -> Result<(), String> {
        if status == 0 {
            Ok(())
        } else {
            Err(self.status_message(status))
        }
    }

    /// The handle's error text, or the generic text for `status` when
    /// libpcap left the error buffer empty.
    fn status_message(&self, status: c_int) -> String {
        let message = self.last_error();
        if message.is_empty() {
            // SAFETY: pcap_statustostr returns static storage or a buffer
            // valid until the next call; it is copied at once.
            unsafe { string_from_pointer(ffi::pcap_statustostr(status)) }.unwrap_or_default()
        } else {
            message
        }
    }

    /// The handle's last error text.
    fn last_error(&self) -> String {
        // SAFETY: the handle is alive; pcap_geterr returns a buffer the
        // handle owns, copied at once.
        unsafe { string_from_pointer(ffi::pcap_geterr(self.as_ptr())) }.unwrap_or_default()
    }
}

/// Interfaces in libpcap order.
pub(crate) fn find_all_devices() -> Result<Vec<RawDevice>, String> {
    let mut list: *mut ffi::PcapIf = ptr::null_mut();
    let mut errbuf = ErrorBuffer::new();
    // SAFETY: both pointers are valid for the call; on success libpcap
    // stores a list freed below.
    let status = unsafe { ffi::pcap_findalldevs(&mut list, errbuf.as_mut_ptr()) };
    if status < 0 {
        return Err(errbuf.text());
    }
    let mut devices = Vec::new();
    let mut entry = list;
    while !entry.is_null() && devices.len() < MAX_LIST_ENTRIES {
        // SAFETY: `entry` is a node of the list libpcap returned, alive until
        // pcap_freealldevs below.
        let node = unsafe { &*entry };
        // SAFETY: name and description are null or NUL-terminated strings
        // owned by the node; both are copied at once.
        let name = unsafe { string_from_pointer(node.name) };
        let description = unsafe { string_from_pointer(node.description) };
        if let Some(name) = name {
            devices.push(RawDevice {
                name,
                description,
                loopback: node.flags & ffi::PCAP_IF_LOOPBACK != 0,
            });
        }
        entry = node.next;
    }
    if !list.is_null() {
        // SAFETY: allocated by pcap_findalldevs and not used again.
        unsafe { ffi::pcap_freealldevs(list) };
    }
    Ok(devices)
}

/// Link type for a libpcap name such as `EN10MB`.
pub(crate) fn link_type_from_name(name: &str) -> Result<c_int, String> {
    let name = CString::new(name).map_err(|_| nul_error("link-type name"))?;
    // SAFETY: the name is a valid C string for the call.
    let value = unsafe { ffi::pcap_datalink_name_to_val(name.as_ptr()) };
    if value < 0 {
        Err(UNKNOWN_LINK_TYPE.to_owned())
    } else {
        Ok(value)
    }
}

/// libpcap's name for a link type.
pub(crate) fn link_type_name(value: c_int) -> Option<String> {
    // SAFETY: libpcap returns null or a static string, copied at once.
    unsafe { string_from_pointer(ffi::pcap_datalink_val_to_name(value)) }
}

/// libpcap's description of a link type.
pub(crate) fn link_type_description(value: c_int) -> Option<String> {
    // SAFETY: libpcap returns null or a static string, copied at once.
    unsafe { string_from_pointer(ffi::pcap_datalink_val_to_description(value)) }
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

/// Copy `count` integers from a libpcap-owned array.
fn copy_ints(list: *const c_int, count: c_int) -> Result<Vec<c_int>, String> {
    let count = usize::try_from(count).map_err(|_| "libpcap returned a negative count")?;
    if count > MAX_LIST_ENTRIES {
        return Err(format!(
            "libpcap returned {count} entries, above the limit of {MAX_LIST_ENTRIES}"
        ));
    }
    if count == 0 || list.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: libpcap returned `count` readable integers at `list`.
    Ok(unsafe { std::slice::from_raw_parts(list, count) }.to_vec())
}

fn nul_error(what: &str) -> String {
    format!("the {what} contains a NUL character")
}

/// A zeroed `PCAP_ERRBUF_SIZE` buffer for calls that report errors in place.
struct ErrorBuffer([c_char; ffi::PCAP_ERRBUF_SIZE]);

impl ErrorBuffer {
    fn new() -> Self {
        Self([0; ffi::PCAP_ERRBUF_SIZE])
    }

    fn as_mut_ptr(&mut self) -> *mut c_char {
        self.0.as_mut_ptr()
    }

    /// The text libpcap wrote, stopping at the first NUL or the buffer end.
    fn text(&self) -> String {
        let bytes: Vec<u8> = self
            .0
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| byte.to_ne_bytes()[0])
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_buffer_stops_at_nul_and_at_the_end() {
        let mut buffer = ErrorBuffer::new();
        for (slot, byte) in buffer.0.iter_mut().zip(b"no such device\0junk") {
            *slot = c_char::from_ne_bytes([*byte]);
        }
        assert_eq!(buffer.text(), "no such device");
        let mut full = ErrorBuffer::new();
        full.0.fill(c_char::from_ne_bytes(*b"x"));
        assert_eq!(full.text().len(), ffi::PCAP_ERRBUF_SIZE);
    }

    #[test]
    fn link_type_names_round_trip() {
        assert_eq!(link_type_from_name("EN10MB"), Ok(1));
        assert_eq!(link_type_name(1).as_deref(), Some("EN10MB"));
        assert!(link_type_description(1).is_some());
        assert_eq!(
            link_type_from_name("NOT_A_LINK_TYPE"),
            Err(UNKNOWN_LINK_TYPE.to_owned())
        );
        assert!(link_type_from_name("EN10\0MB").is_err());
    }

    #[test]
    fn copy_ints_bounds_the_count() {
        let values = [1, 2, 3];
        assert_eq!(copy_ints(values.as_ptr(), 3), Ok(vec![1, 2, 3]));
        assert_eq!(copy_ints(ptr::null(), 0), Ok(Vec::new()));
        assert!(copy_ints(values.as_ptr(), -1).is_err());
        let over = c_int::try_from(MAX_LIST_ENTRIES + 1).unwrap_or(c_int::MAX);
        assert!(copy_ints(values.as_ptr(), over).is_err());
    }

    #[test]
    fn unknown_device_fails_to_activate() {
        let Ok(mut handle) = Handle::create("packetfin-no-such-interface") else {
            return;
        };
        assert!(matches!(handle.activate(), Activation::Failed { .. }));
    }

    #[test]
    fn null_pointer_has_no_string() {
        // SAFETY: the helper explicitly accepts null.
        assert_eq!(unsafe { string_from_pointer(ptr::null()) }, None);
    }

    #[test]
    fn interface_name_with_nul_is_rejected() {
        assert!(Handle::create("en\0x").is_err());
    }
}
