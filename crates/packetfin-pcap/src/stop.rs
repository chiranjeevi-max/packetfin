//! Cooperative stop signalling.
//!
//! Unix installs SIGINT/SIGTERM handlers that set an atomic flag and write one
//! byte to a non-blocking self-pipe; a polling capture set waits on that pipe,
//! so a signal interrupts an otherwise idle poll immediately. Windows builds
//! use the same atomic flag with non-blocking handles and a short sleep; the
//! console-handler half of that path belongs to the deferred Windows runtime
//! work.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::OpenError;

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(unix)]
use std::sync::LazyLock;
#[cfg(unix)]
use std::sync::atomic::AtomicI32;

/// Set by the Unix signal handler; every handle observes it.
#[cfg(unix)]
static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

/// Write end used by the signal handler, or -1 before the pipe exists.
#[cfg(unix)]
static SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

#[cfg(unix)]
struct SignalPipe {
    read_fd: RawFd,
    write_fd: RawFd,
}

#[cfg(unix)]
static SIGNAL_PIPE: LazyLock<Result<SignalPipe, String>> =
    LazyLock::new(|| create_pipe().map_err(|error| error.to_string()));

#[cfg(unix)]
static HANDLERS: LazyLock<Result<(), String>> = LazyLock::new(install_handlers);

/// A clonable stop request shared by a capture set and its caller.
#[derive(Clone, Debug)]
pub struct StopHandle {
    inner: Arc<StopInner>,
}

#[derive(Debug)]
struct StopInner {
    requested: AtomicBool,
    #[cfg(unix)]
    read_fd: RawFd,
    #[cfg(unix)]
    write_fd: RawFd,
}

impl StopHandle {
    /// Create a stop handle without installing signal handlers.
    pub fn new() -> Result<Self, OpenError> {
        #[cfg(unix)]
        {
            let pipe = signal_pipe()?;
            Ok(Self {
                inner: Arc::new(StopInner {
                    requested: AtomicBool::new(false),
                    read_fd: pipe.read_fd,
                    write_fd: pipe.write_fd,
                }),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                inner: Arc::new(StopInner {
                    requested: AtomicBool::new(false),
                }),
            })
        }
    }

    /// Create a stop handle and install SIGINT/SIGTERM handlers.
    ///
    /// Installation is idempotent and process-wide. The handlers stay
    /// installed for the process lifetime, which is what a command-line tool
    /// wants: after the first capture there is no mode that should ignore
    /// Ctrl-C.
    #[cfg(unix)]
    pub fn install_signal_handlers() -> Result<Self, OpenError> {
        let pipe = signal_pipe()?;
        match &*HANDLERS {
            Ok(()) => Ok(Self {
                inner: Arc::new(StopInner {
                    requested: AtomicBool::new(false),
                    read_fd: pipe.read_fd,
                    write_fd: pipe.write_fd,
                }),
            }),
            Err(message) => Err(OpenError::Open {
                device: "signal".to_owned(),
                message: message.clone(),
            }),
        }
    }

    /// Ask every capture set sharing this handle to stop.
    pub fn request_stop(&self) {
        self.inner.requested.store(true, Ordering::SeqCst);
        self.wake();
    }

    /// Whether a stop was requested directly or by a signal.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.inner.requested.load(Ordering::SeqCst) || signal_stopped()
    }

    fn wake(&self) {
        #[cfg(unix)]
        {
            write_byte(self.inner.write_fd);
        }
    }

    /// Drain the self-pipe after a poll reports it readable.
    #[cfg(unix)]
    pub(crate) fn drain(&self) {
        let mut buffer = [0_u8; 64];
        loop {
            // SAFETY: `read_fd` is a live non-blocking pipe read end.
            let count = unsafe {
                libc::read(
                    self.inner.read_fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count <= 0 {
                break;
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn read_fd(&self) -> RawFd {
        self.inner.read_fd
    }
}

#[cfg(unix)]
fn signal_stopped() -> bool {
    SIGNAL_STOP.load(Ordering::SeqCst)
}

#[cfg(not(unix))]
fn signal_stopped() -> bool {
    false
}

#[cfg(unix)]
fn write_byte(fd: RawFd) {
    if fd < 0 {
        return;
    }
    let byte = 1_u8;
    // SAFETY: `fd` is a non-blocking pipe write end; a failed write means the
    // pipe is already readable or closed, both harmless.
    unsafe {
        libc::write(fd, (&byte as *const u8).cast::<libc::c_void>(), 1);
    }
}

#[cfg(unix)]
extern "C" fn handle_signal(_signal: libc::c_int) {
    // POSIX requires a handler to leave errno as it found it. `write` can set
    // EAGAIN on a full pipe or EBADF on a closed one.
    // SAFETY: the errno location is thread-local and valid for this thread.
    let errno = unsafe { errno_pointer() };
    let saved = if errno.is_null() {
        0
    } else {
        // SAFETY: non-null errno location from the C library.
        unsafe { *errno }
    };
    SIGNAL_STOP.store(true, Ordering::SeqCst);
    write_byte(SIGNAL_WRITE_FD.load(Ordering::Relaxed));
    if !errno.is_null() {
        // SAFETY: same non-null thread-local location.
        unsafe { *errno = saved };
    }
}

/// Thread-local errno location for the signal handler.
///
/// # Safety
///
/// The returned pointer, when non-null, is valid for the calling thread.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errno_pointer() -> *mut libc::c_int {
    // SAFETY: libc's thread-local errno accessor.
    unsafe { libc::__errno_location() }
}

/// Thread-local errno location for BSD-derived systems.
///
/// # Safety
///
/// The returned pointer, when non-null, is valid for the calling thread.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
unsafe fn errno_pointer() -> *mut libc::c_int {
    // SAFETY: libc's thread-local errno accessor.
    unsafe { libc::__error() }
}

/// Other Unix targets do not expose an errno accessor through this crate's
/// supported platforms; the handler then skips the save/restore.
///
/// # Safety
///
/// Always returns null.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
unsafe fn errno_pointer() -> *mut libc::c_int {
    std::ptr::null_mut()
}

#[cfg(unix)]
fn signal_pipe() -> Result<&'static SignalPipe, OpenError> {
    match &*SIGNAL_PIPE {
        Ok(pipe) => {
            let _ = SIGNAL_WRITE_FD.compare_exchange(
                -1,
                pipe.write_fd,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            Ok(pipe)
        }
        Err(message) => Err(OpenError::Open {
            device: "signal".to_owned(),
            message: message.clone(),
        }),
    }
}

#[cfg(unix)]
fn create_pipe() -> Result<SignalPipe, std::io::Error> {
    let mut descriptors = [0_i32; 2];
    // SAFETY: `descriptors` has room for the two descriptors pipe writes.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let [read_fd, write_fd] = descriptors;
    for descriptor in [read_fd, write_fd] {
        if let Err(error) = configure_pipe_end(descriptor) {
            // SAFETY: both descriptors were just created and are owned here.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(error);
        }
    }
    Ok(SignalPipe { read_fd, write_fd })
}

#[cfg(unix)]
fn configure_pipe_end(descriptor: RawFd) -> Result<(), std::io::Error> {
    // SAFETY: `descriptor` is a live pipe end.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same descriptor; F_SETFL only changes status flags.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same descriptor; F_SETFD only changes descriptor flags.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn install_handlers() -> Result<(), String> {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: the handler is async-signal-safe: it stores an atomic and
        // writes one byte to a non-blocking pipe. The sigaction struct is
        // fully initialized before use.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handle_signal as *const () as usize;
            if libc::sigemptyset(&mut action.sa_mask) != 0 {
                return Err(format!(
                    "sigemptyset for signal {signal}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            action.sa_flags = 0;
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction for signal {signal}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_handle_is_not_stopped() {
        let handle = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
        assert!(!handle.is_stopped());
    }

    #[test]
    fn request_stop_is_visible_through_clones() {
        let handle = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
        let clone = handle.clone();
        assert!(!clone.is_stopped());
        handle.request_stop();
        assert!(clone.is_stopped());
    }

    #[cfg(unix)]
    #[test]
    fn installing_signal_handlers_succeeds() {
        let handle =
            StopHandle::install_signal_handlers().unwrap_or_else(|error| unreachable!("{error}"));
        assert!(!handle.is_stopped());
    }

    #[cfg(unix)]
    #[test]
    fn the_pipe_is_non_blocking() {
        let handle = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
        handle.request_stop();
        handle.drain();
        // Draining twice must not block or fail.
        handle.drain();
    }
}
