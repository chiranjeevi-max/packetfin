//! Raw libpcap and Npcap entry points.
//!
//! Everything here is a C type or a C ABI declaration from libpcap's public
//! `pcap/pcap.h`. The safe wrappers in [`crate::handle`] and
//! [`crate::tstamp`] own the lifetime rules: a handle stays alive for the
//! duration of each call, and every pointer libpcap returns is copied at once
//! or freed with the matching libpcap free function.
//!
//! The library is `libpcap` on Unix and Npcap's `wpcap` on Windows. Linking
//! it directly, instead of through a binding crate, keeps old `windows-sys`
//! import libraries out of the Windows link line; see `build.rs`.

use std::ffi::{c_char, c_int, c_uchar, c_uint};

/// Size of the error buffer libpcap fills (`PCAP_ERRBUF_SIZE`).
pub const PCAP_ERRBUF_SIZE: usize = 256;

/// Interface flag: the interface is a loopback interface.
pub const PCAP_IF_LOOPBACK: c_uint = 0x0000_0001;

/// Activation warning: promiscuous mode is not supported.
pub const PCAP_WARNING_PROMISC_NOTSUP: c_int = 2;
/// Activation error: monitor mode is not supported.
pub const PCAP_ERROR_RFMON_NOTSUP: c_int = -6;
/// Activation error: no permission to open the capture source.
pub const PCAP_ERROR_PERM_DENIED: c_int = -8;
/// Activation error: no permission to enter promiscuous mode.
pub const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;

/// Netmask passed to `pcap_compile`. Zero, as before, so `ip broadcast`
/// filters behave as they always have.
pub const COMPILE_NETMASK: c_uint = 0;

/// Opaque `pcap_t`.
#[repr(C)]
pub struct PcapHandle {
    _private: [u8; 0],
}

/// Opaque `struct pcap_addr`; Packetfin does not read interface addresses.
#[repr(C)]
pub struct PcapAddr {
    _private: [u8; 0],
}

/// `pcap_if_t`, one entry of the list `pcap_findalldevs` returns.
#[repr(C)]
pub struct PcapIf {
    pub next: *mut PcapIf,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut PcapAddr,
    pub flags: c_uint,
}

/// `struct pcap_pkthdr`. Packetfin only reads headers libpcap allocates, so
/// a platform's trailing private fields need no space here.
#[repr(C)]
pub struct PcapPkthdr {
    pub ts: libc::timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

/// `struct pcap_stat`. Windows adds three counters after the common ones,
/// and the library may write them, so the structure is declared at full
/// size.
#[repr(C)]
#[derive(Default)]
pub struct PcapStat {
    pub ps_recv: c_uint,
    pub ps_drop: c_uint,
    pub ps_ifdrop: c_uint,
    #[cfg(windows)]
    pub ps_capt: c_uint,
    #[cfg(windows)]
    pub ps_sent: c_uint,
    #[cfg(windows)]
    pub ps_netdrop: c_uint,
}

// Three counters everywhere, six on Windows.
const _: () =
    assert!(size_of::<PcapStat>() == size_of::<c_uint>() * if cfg!(windows) { 6 } else { 3 });

/// Opaque `struct bpf_insn`.
#[repr(C)]
pub struct BpfInsn {
    _private: [u8; 0],
}

/// `struct bpf_program`, filled by `pcap_compile` and freed by
/// `pcap_freecode`.
#[repr(C)]
pub struct BpfProgram {
    pub bf_len: c_uint,
    pub bf_insns: *mut BpfInsn,
}

#[cfg_attr(not(windows), link(name = "pcap"))]
#[cfg_attr(windows, link(name = "wpcap"))]
unsafe extern "C" {
    /// List capture interfaces; free with `pcap_freealldevs`.
    pub fn pcap_findalldevs(devices: *mut *mut PcapIf, errbuf: *mut c_char) -> c_int;
    /// Free a list returned by `pcap_findalldevs`.
    pub fn pcap_freealldevs(devices: *mut PcapIf);

    /// Create an inactive handle for a capture source.
    pub fn pcap_create(source: *const c_char, errbuf: *mut c_char) -> *mut PcapHandle;
    /// Activate a handle: 0 on success, a positive warning or a negative error.
    pub fn pcap_activate(handle: *mut PcapHandle) -> c_int;
    /// Close a handle created by `pcap_create`.
    pub fn pcap_close(handle: *mut PcapHandle);
    /// Error text for the last failed call on a handle; owned by the handle.
    pub fn pcap_geterr(handle: *mut PcapHandle) -> *mut c_char;
    /// Generic text for a status code; static storage.
    pub fn pcap_statustostr(status: c_int) -> *const c_char;

    /// Snapshot length to request before activation.
    pub fn pcap_set_snaplen(handle: *mut PcapHandle, snaplen: c_int) -> c_int;
    /// Promiscuous mode to request before activation.
    pub fn pcap_set_promisc(handle: *mut PcapHandle, promisc: c_int) -> c_int;
    /// Read timeout in milliseconds to request before activation.
    pub fn pcap_set_timeout(handle: *mut PcapHandle, milliseconds: c_int) -> c_int;
    /// Kernel buffer size in bytes to request before activation.
    pub fn pcap_set_buffer_size(handle: *mut PcapHandle, bytes: c_int) -> c_int;
    /// Monitor mode to request before activation.
    #[cfg(not(windows))]
    pub fn pcap_set_rfmon(handle: *mut PcapHandle, rfmon: c_int) -> c_int;
    /// Select a timestamp type before activation.
    pub fn pcap_set_tstamp_type(handle: *mut PcapHandle, value: c_int) -> c_int;

    /// Active snapshot length; `PCAP_ERROR_NOT_ACTIVATED` when inactive.
    pub fn pcap_snapshot(handle: *mut PcapHandle) -> c_int;
    /// 0 for microsecond, 1 for nanosecond precision.
    pub fn pcap_get_tstamp_precision(handle: *mut PcapHandle) -> c_int;
    /// Put an active handle in non-blocking mode.
    pub fn pcap_setnonblock(handle: *mut PcapHandle, nonblock: c_int, errbuf: *mut c_char)
    -> c_int;
    /// Link type of an active handle.
    pub fn pcap_datalink(handle: *mut PcapHandle) -> c_int;
    /// Select a link type on an active handle.
    pub fn pcap_set_datalink(handle: *mut PcapHandle, link_type: c_int) -> c_int;
    /// Supported link types; free with `pcap_free_datalinks`.
    pub fn pcap_list_datalinks(handle: *mut PcapHandle, link_types: *mut *mut c_int) -> c_int;
    /// Free an array returned by `pcap_list_datalinks`.
    pub fn pcap_free_datalinks(link_types: *mut c_int);
    /// Compile a filter expression into `program`.
    pub fn pcap_compile(
        handle: *mut PcapHandle,
        program: *mut BpfProgram,
        expression: *const c_char,
        optimize: c_int,
        netmask: c_uint,
    ) -> c_int;
    /// Install a compiled filter; libpcap keeps its own copy.
    pub fn pcap_setfilter(handle: *mut PcapHandle, program: *mut BpfProgram) -> c_int;
    /// Free the instructions `pcap_compile` allocated.
    pub fn pcap_freecode(program: *mut BpfProgram);
    /// Read one packet: 1 read, 0 timeout, -1 error, -2 no more packets.
    pub fn pcap_next_ex(
        handle: *mut PcapHandle,
        header: *mut *mut PcapPkthdr,
        data: *mut *const c_uchar,
    ) -> c_int;
    /// Capture counters since activation.
    pub fn pcap_stats(handle: *mut PcapHandle, stats: *mut PcapStat) -> c_int;

    /// Link type for a name such as `EN10MB`, or -1 when unknown.
    pub fn pcap_datalink_name_to_val(name: *const c_char) -> c_int;
    /// Name for a link type, or null when unknown; static storage.
    pub fn pcap_datalink_val_to_name(link_type: c_int) -> *const c_char;
    /// Description for a link type, or null when unknown; static storage.
    pub fn pcap_datalink_val_to_description(link_type: c_int) -> *const c_char;

    /// Numeric timestamp type for a name, or -1 when unknown.
    pub fn pcap_tstamp_type_name_to_val(name: *const c_char) -> c_int;
    /// Name for a numeric timestamp type, or null when unknown.
    pub fn pcap_tstamp_type_val_to_name(value: c_int) -> *const c_char;
    /// Description for a numeric timestamp type, or null when unknown.
    pub fn pcap_tstamp_type_val_to_description(value: c_int) -> *const c_char;
    /// Supported timestamp types; caller frees with `pcap_free_tstamp_types`.
    pub fn pcap_list_tstamp_types(handle: *mut PcapHandle, types: *mut *mut c_int) -> c_int;
    /// Free an array returned by `pcap_list_tstamp_types`.
    pub fn pcap_free_tstamp_types(types: *mut c_int);

    /// File descriptor that becomes readable when packets are available.
    #[cfg(unix)]
    pub fn pcap_get_selectable_fd(handle: *mut PcapHandle) -> c_int;
}
