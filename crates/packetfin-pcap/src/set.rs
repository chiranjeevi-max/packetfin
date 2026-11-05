//! Capture over one or more interfaces.

use crate::capture::{CaptureStats, CapturedPacket, LiveCapture};
use crate::device::DeviceInfo;
use crate::error::{CaptureError, OpenError};
use crate::options::OpenOptions;
use crate::stop::StopHandle;

/// How long one idle poll waits before the caller gets a chance to check its
/// own autostop policy.
const MAX_POLL_MS: i32 = 100;

/// A set of live interfaces read without threads.
///
/// Handles are non-blocking. Each [`Self::next`] drains every handle in
/// round-robin order and then polls the selectable descriptors plus the stop
/// pipe, so an idle set wakes on a packet, on [`StopHandle::request_stop`] or
/// on SIGINT/SIGTERM.
pub struct CaptureSet {
    captures: Vec<LiveCapture>,
    stop: StopHandle,
    poll_ms: i32,
    next_start: usize,
    #[cfg(unix)]
    poll_fds: Vec<libc::pollfd>,
}

impl CaptureSet {
    /// Open every device in order, non-blocking, sharing one stop handle.
    pub fn open(
        devices: &[DeviceInfo],
        options: &OpenOptions,
        stop: StopHandle,
    ) -> Result<Self, OpenError> {
        let mut captures = Vec::with_capacity(devices.len());
        for device in devices {
            captures.push(LiveCapture::open_nonblocking(device, options)?);
        }
        Self::new(captures, stop)
    }

    /// Build a set from already opened handles, converting blocking ones.
    pub fn new(captures: Vec<LiveCapture>, stop: StopHandle) -> Result<Self, OpenError> {
        let mut converted: Vec<LiveCapture> = Vec::with_capacity(captures.len());
        for capture in captures {
            converted.push(capture.into_nonblocking()?);
        }
        let poll_ms = converted
            .iter()
            .map(|capture| capture.timeout_ms().clamp(1, MAX_POLL_MS))
            .min()
            .unwrap_or(MAX_POLL_MS);
        #[cfg(unix)]
        let poll_fds = poll_descriptors(&converted, &stop);
        Ok(Self {
            captures: converted,
            stop,
            poll_ms,
            next_start: 0,
            #[cfg(unix)]
            poll_fds,
        })
    }

    /// The interfaces in the order they were opened.
    #[must_use]
    pub fn captures(&self) -> &[LiveCapture] {
        &self.captures
    }

    /// Number of interfaces in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.captures.len()
    }

    /// Whether the set has no interfaces.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.captures.is_empty()
    }

    /// The shared stop handle.
    #[must_use]
    pub fn stop_handle(&self) -> &StopHandle {
        &self.stop
    }

    /// Compile and install the same BPF filter on every interface.
    ///
    /// The first failure is returned; handles already filtered keep their
    /// program, which is harmless because the caller aborts before creating
    /// output.
    pub fn set_filter(&mut self, expression: &str) -> Result<(), OpenError> {
        for capture in &mut self.captures {
            capture.set_filter(expression)?;
        }
        Ok(())
    }

    /// One drain-and-poll round.
    ///
    /// Returns a packet when one is already buffered or arrives within the
    /// poll interval. `None` means the interval elapsed, the set is empty or a
    /// stop was requested; callers check [`Self::stop_handle`] and loop. This
    /// shape lets an autostop timer (`-a duration`) regain control while the
    /// interface is idle without a second thread.
    #[expect(
        clippy::should_implement_trait,
        reason = "a capture set is polled with errors and a stop handle, not iterated; the name follows the capture API"
    )]
    pub fn next(&mut self) -> Result<Option<(usize, CapturedPacket<'_>)>, CaptureError> {
        if self.captures.is_empty() || self.stop.is_stopped() {
            return Ok(None);
        }
        if let Some(packet) = drain(&mut self.captures, &mut self.next_start)? {
            return Ok(Some(packet));
        }
        if self.stop.is_stopped() {
            return Ok(None);
        }
        #[cfg(unix)]
        wait(&mut self.poll_fds, self.poll_ms, &self.stop)?;
        #[cfg(not(unix))]
        wait(self.poll_ms)?;
        Ok(None)
    }

    /// Counters for every interface, in set order.
    pub fn stats(&mut self) -> Result<Vec<CaptureStats>, CaptureError> {
        let mut stats = Vec::with_capacity(self.captures.len());
        for capture in &mut self.captures {
            stats.push(capture.stats()?);
        }
        Ok(stats)
    }
}

/// Drain one already-buffered packet, scanning round-robin from `start`.
///
/// The cursor advances past the handle that produced the packet, so a busy
/// earlier interface cannot starve later ones.
fn drain<'a>(
    captures: &'a mut [LiveCapture],
    start: &mut usize,
) -> Result<Option<(usize, CapturedPacket<'a>)>, CaptureError> {
    let len = captures.len();
    if len == 0 {
        return Ok(None);
    }
    let first = (*start) % len;
    let (head, tail) = captures.split_at_mut(first);
    for (offset, capture) in tail.iter_mut().enumerate() {
        let index = first + offset;
        if let Some(packet) = capture.next()? {
            *start = (index + 1) % len;
            return Ok(Some((index, packet)));
        }
    }
    for (index, capture) in head.iter_mut().enumerate() {
        if let Some(packet) = capture.next()? {
            *start = (index + 1) % len;
            return Ok(Some((index, packet)));
        }
    }
    Ok(None)
}

#[cfg(unix)]
fn wait(
    poll_fds: &mut [libc::pollfd],
    poll_ms: i32,
    stop: &StopHandle,
) -> Result<(), CaptureError> {
    let count = libc::nfds_t::try_from(poll_fds.len()).map_err(|_| CaptureError::Poll {
        message: "too many poll descriptors".to_owned(),
    })?;
    // SAFETY: `poll_fds` is a live vector of descriptors for the duration of
    // the call; poll only reads and writes its `revents` fields.
    let result = unsafe { libc::poll(poll_fds.as_mut_ptr(), count, poll_ms) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(CaptureError::Poll {
            message: error.to_string(),
        });
    }
    stop.drain();
    Ok(())
}

#[cfg(not(unix))]
fn wait(poll_ms: i32) -> Result<(), CaptureError> {
    let millis = u64::try_from(poll_ms).unwrap_or(1).max(1);
    std::thread::sleep(std::time::Duration::from_millis(millis));
    Ok(())
}

#[cfg(unix)]
fn poll_descriptors(captures: &[LiveCapture], stop: &StopHandle) -> Vec<libc::pollfd> {
    let mut descriptors = Vec::with_capacity(captures.len().saturating_add(1));
    for capture in captures {
        descriptors.push(libc::pollfd {
            fd: capture.selectable_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
    }
    descriptors.push(libc::pollfd {
        fd: stop.read_fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    descriptors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_set_finishes_immediately() {
        let stop = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
        let mut set =
            CaptureSet::new(Vec::new(), stop).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.next().is_ok_and(|packet| packet.is_none()));
    }

    #[test]
    fn a_requested_stop_ends_the_set() {
        let stop = StopHandle::new().unwrap_or_else(|error| unreachable!("{error}"));
        let mut set = CaptureSet::new(Vec::new(), stop.clone())
            .unwrap_or_else(|error| unreachable!("{error}"));
        stop.request_stop();
        assert!(set.stop_handle().is_stopped());
        assert!(set.next().is_ok_and(|packet| packet.is_none()));
    }
}
