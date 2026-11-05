//! Live packet capture over libpcap (macOS, Linux) and Npcap (Windows).
//!
//! This is the only Packetfin crate allowed to contain `unsafe` code. It
//! isolates three boundaries:
//!
//! * libpcap/Npcap through the safe `pcap` crate, plus raw calls for the
//!   snapshot length, timestamp precision and timestamp-type listing that the
//!   crate does not expose;
//! * macOS SystemConfiguration, which supplies the friendly interface names
//!   libpcap omits there;
//! * the Unix SIGINT/SIGTERM self-pipe used to interrupt an idle poll.
//!
//! Capture is single-threaded: a [`CaptureSet`] polls non-blocking
//! handles on Unix, and a blocking [`LiveCapture`] caps libpcap's read
//! timeout at [`MAX_BLOCKING_TIMEOUT_MS`] so a signal is observed within that
//! bound even when the requested timeout is zero or large. Windows falls back
//! to the same bounded timeout plus an atomic stop flag. Windows
//! console-handler integration and Npcap runtime testing are deferred; the
//! crate still compiles for `x86_64-pc-windows-msvc`.
//!
//! ```no_run
//! use packetfin_pcap::{DeviceInfo, LiveCapture, OpenOptions};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let device = DeviceInfo::new("lo0", None);
//! let mut capture = LiveCapture::open(&device, &OpenOptions::default())?;
//! capture.set_filter("udp port 45999")?;
//! while let Some(packet) = capture.next()? {
//!     println!("{} bytes", packet.captured_len());
//! }
//! # Ok(())
//! # }
//! ```

mod capture;
mod device;
mod error;
mod ffi;
mod macos;
mod options;
mod set;
mod stop;
mod tstamp;

pub use capture::{CaptureStats, CapturedPacket, LiveCapture};
pub use device::{
    DeviceInfo, default_device, default_device_in, devices, format_device_list, is_loopback_name,
    resolve_device, resolve_device_in, resolve_index_in,
};
pub use error::{CaptureError, DeviceError, OpenError, OpenWarning};
pub use options::{
    DEFAULT_SNAPLEN, DEFAULT_TIMEOUT_MS, Linktype, LinktypeInfo, MAX_BLOCKING_TIMEOUT_MS, MIB,
    OpenOptions, TimestampPrecision, buffer_bytes_from_mib,
};
pub use set::CaptureSet;
pub use stop::StopHandle;
pub use tstamp::{TimestampTypeInfo, timestamp_type_from_name, timestamp_type_info};

pub use packetfin_core::Timestamp;
