//! Capture-writing session: one owner for the current writer, ring rotation
//! and the file-name log.
//!
//! The read loop forwards metadata events and selected frames here. All
//! format and sink choices were resolved by the command-line parser; this
//! module creates files, names ring members, enforces the files limit and
//! maps writer failures to read-mode exit statuses
//! (9 before any output byte, 15 afterwards).
//!
//! Autostop conditions that depend on the read stream (`-a packets`,
//! read-mode `-a filesize`) stay in the driver, which sees frame offsets and
//! the display-filter result. Wall-clock and output-size conditions live here
//! because only this module knows when a file was opened and how many
//! uncompressed bytes it holds.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions as FsOpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use packetfin_core::capture::InterfaceInfo;
use packetfin_core::{
    CaptureEvent, CaptureWriter, Frame, OutputFormat, PacketRecord, Resolution, WriteError,
    WriterOptions,
};

use crate::cli::{CREATOR, WriteOptions};

/// A writer failure with the exit status the read path must return.
#[derive(Debug)]
pub struct WriteFailure {
    /// Process exit status.
    pub status: i32,
    /// Packetfin's own wording, printed to standard error by the caller.
    pub message: String,
}

impl WriteFailure {
    fn new(status: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// The output side of one capture-writing run.
pub struct WriterSession {
    file: PathBuf,
    format: OutputFormat,
    compression: packetfin_core::Compression,
    comments: Vec<String>,
    ring_packets: Option<u64>,
    ring_filesize: Option<u64>,
    ring_duration: Option<std::time::Duration>,
    ring_files: Option<u64>,
    stop_after_files: Option<u64>,
    writer: Option<CaptureWriter<Destination>>,
    current: Option<PathBuf>,
    sequence: u64,
    packets_in_file: u64,
    files_finished: u64,
    opened_at: Instant,
    ring_paths: VecDeque<PathBuf>,
    printname: Option<File>,
    metadata: Vec<CaptureEvent>,
    replay_metadata: bool,
    rotate_before_next: bool,
    stop: bool,
    live: bool,
    interfaces: Vec<InterfaceInfo>,
}

impl WriterSession {
    /// Create the session, opening the first output file eagerly.
    ///
    /// `None` means the command line did not request capture output. An open
    /// failure is exit 9: the output is created before the first record is
    /// read, and a path error wins over a later capture read error.
    pub fn new(write: &WriteOptions) -> Result<Option<Self>, WriteFailure> {
        Self::create(write, false, &[])
    }

    /// Create the session for a live capture, opening the output eagerly.
    ///
    /// The output switches to pcapng when more than one interface feeds
    /// one output, even when `-F pcap` was requested, because classic pcap
    /// cannot describe two interfaces. Live files are created mode 0600.
    pub fn new_live(
        write: &WriteOptions,
        interfaces: &[InterfaceInfo],
    ) -> Result<Option<Self>, WriteFailure> {
        if interfaces.is_empty() {
            return Err(WriteFailure::new(1, "no capture interfaces were opened"));
        }
        Self::create(write, true, interfaces)
    }

    fn create(
        write: &WriteOptions,
        live: bool,
        interfaces: &[InterfaceInfo],
    ) -> Result<Option<Self>, WriteFailure> {
        let Some(file) = write.file.clone() else {
            return Ok(None);
        };
        let ring = &write.ring;
        let mut session = Self {
            file: file.clone(),
            format: if live && interfaces.len() > 1 {
                // Classic pcap cannot describe two interfaces.
                OutputFormat::PcapNg
            } else if live && write.format == OutputFormat::NsecPcap {
                // A live nanosecond request writes microsecond pcap
                // rather than a nanosecond header.
                OutputFormat::Pcap(Resolution::Microsecond)
            } else {
                write.format
            },
            compression: write.compression,
            comments: write.comments.clone(),
            ring_packets: ring.packets,
            ring_filesize: ring.filesize,
            // `-b duration:0` is accepted but never rotates, so a zero
            // duration is inert rather than immediate.
            ring_duration: ring.duration.filter(|duration| !duration.is_zero()),
            ring_files: ring.files,
            stop_after_files: write.autostop.files,
            writer: None,
            current: None,
            sequence: 0,
            packets_in_file: 0,
            files_finished: 0,
            opened_at: Instant::now(),
            ring_paths: VecDeque::new(),
            printname: None,
            metadata: Vec::new(),
            replay_metadata: !live && ring.rotates(),
            rotate_before_next: false,
            stop: false,
            live,
            interfaces: interfaces.to_vec(),
        };
        if file == Path::new("-") {
            session.writer = Some(session.make_writer(Destination::Stdout(io::stdout())));
            session.open_live_writer()?;
        } else {
            let first = if ring.rotates() {
                let name = ring_path(&file, 1, &local_timestamp());
                session.sequence = 1;
                name
            } else {
                file.clone()
            };
            session.open(&first)?;
        }
        if let Some(path) = &ring.printname {
            let status = if session.live { 1 } else { 9 };
            let file = File::create(path).map_err(|error| {
                WriteFailure::new(status, format!("cannot create {}: {error}", path.display()))
            })?;
            session.printname = Some(file);
            if let Some(current) = session.current.clone() {
                session.record_printname(&current)?;
            }
        }
        Ok(Some(session))
    }

    /// Forward one metadata event to the current writer.
    ///
    /// The events are retained so a ring rotation can reproduce the section
    /// and interface descriptions in every file it opens.
    pub fn observe(&mut self, event: &CaptureEvent) -> Result<(), WriteFailure> {
        if self.replay_metadata && !matches!(event, CaptureEvent::Frame(_)) {
            self.metadata.push(event.clone());
        }
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };
        writer.observe(event).map_err(|error| self.failure(error))
    }

    /// Write one selected frame and apply ring rotation.
    pub fn write_frame(&mut self, frame: &Frame) -> Result<(), WriteFailure> {
        if self.rotate_before_next {
            self.sequence = self.sequence.saturating_add(1);
            let path = ring_path(&self.file, self.sequence, &local_timestamp());
            self.rotate_before_next = false;
            self.open(&path)?;
        }
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };
        writer
            .write_packet(PacketRecord {
                timestamp: frame.timestamp,
                timestamp_units: frame.timestamp_units,
                interface: frame.global_interface,
                captured: &frame.captured,
                original_len: frame.original_len,
                options: &frame.options,
            })
            .map_err(|error| self.failure(error))?;
        self.packets_in_file = self.packets_in_file.saturating_add(1);
        if self.rotation_due() {
            self.rotate(false)?;
        }
        Ok(())
    }

    /// Apply a live ring-buffer timer between packets.
    ///
    /// Packet-driven rotations stay lazy (the next member is created when
    /// another packet arrives), but a duration condition wakes on an idle
    /// poll and opens the next member immediately. Read-mode sessions never
    /// call this.
    pub fn tick(&mut self) -> Result<(), WriteFailure> {
        if self.live && self.writer.is_some() && self.rotation_due() {
            self.rotate(true)?;
        }
        Ok(())
    }

    /// Uncompressed bytes written to the current file.
    pub fn logical_bytes(&self) -> u64 {
        self.writer.as_ref().map_or(0, CaptureWriter::logical_bytes)
    }

    /// Flush the current capture output without finishing it.
    pub fn flush(&mut self) -> Result<(), WriteFailure> {
        let Some(writer) = &mut self.writer else {
            return Ok(());
        };
        writer.flush().map_err(|error| self.failure(error))
    }

    /// Whether `-a files` ended the run after a finished ring file.
    pub fn should_stop(&self) -> bool {
        self.stop
    }

    /// Finish the current file and the file-name log.
    ///
    /// Safe to call twice; a finished session has no writer and only flushes
    /// the log once.
    pub fn finish(&mut self) -> Result<(), WriteFailure> {
        if let Some(mut writer) = self.writer.take() {
            writer.finish().map_err(|error| self.failure(error))?;
        }
        if let Some(log) = &mut self.printname {
            log.flush().map_err(|error| {
                self.output_failure(format!("cannot write file names: {error}"))
            })?;
        }
        Ok(())
    }

    fn make_writer(&self, destination: Destination) -> CaptureWriter<Destination> {
        CaptureWriter::new(
            destination,
            WriterOptions {
                format: self.format,
                compression: self.compression,
                application: CREATOR,
                capture_comments: &self.comments,
            },
        )
    }

    /// Open `path` as the current output file.
    fn open(&mut self, path: &Path) -> Result<(), WriteFailure> {
        let file = create_output(path, self.live).map_err(|error| {
            // A path failure before capture is read-mode 9 and live 1; the
            // later writer-failure mapping does not apply to creation.
            let status = if self.live { 1 } else { 9 };
            WriteFailure::new(status, format!("cannot create {}: {error}", path.display()))
        })?;
        self.writer = Some(self.make_writer(Destination::File(file)));
        self.current = Some(path.to_path_buf());
        self.packets_in_file = 0;
        self.opened_at = Instant::now();
        if let Some(limit) = self.ring_files {
            self.ring_paths.push_back(path.to_path_buf());
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            while self.ring_paths.len() > limit {
                if let Some(oldest) = self.ring_paths.pop_front() {
                    let _ = std::fs::remove_file(oldest);
                }
            }
        }
        if self.printname.is_some() {
            self.record_printname(path)?;
        }
        self.open_live_writer()?;
        self.replay_metadata()
    }

    /// Write the live interface descriptions into the current writer.
    fn open_live_writer(&mut self) -> Result<(), WriteFailure> {
        if !self.live {
            return Ok(());
        }
        let interfaces = self.interfaces.clone();
        let result = {
            let Some(writer) = &mut self.writer else {
                return Ok(());
            };
            writer.open_live(&interfaces)
        };
        result.map_err(|error| self.failure(error))
    }

    /// Re-emit the source metadata a fresh ring file needs.
    fn replay_metadata(&mut self) -> Result<(), WriteFailure> {
        let metadata = self.metadata.clone();
        let result = {
            let Some(writer) = &mut self.writer else {
                return Ok(());
            };
            metadata.iter().try_for_each(|event| writer.observe(event))
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.failure(error)),
        }
    }

    fn record_printname(&mut self, path: &Path) -> Result<(), WriteFailure> {
        let Some(log) = &mut self.printname else {
            return Ok(());
        };
        let bytes = print_name_bytes(path);
        log.write_all(&bytes)
            .map_err(|error| self.output_failure(format!("cannot write file names: {error}")))
    }

    fn rotation_due(&self) -> bool {
        if self.current.is_none() {
            return false;
        }
        if let Some(limit) = self.ring_packets
            && self.packets_in_file >= limit
        {
            return true;
        }
        if let Some(kib) = self.ring_filesize
            && self
                .writer
                .as_ref()
                .is_some_and(|writer| writer.logical_bytes() >= kib.saturating_mul(1024))
        {
            return true;
        }
        if let Some(duration) = self.ring_duration
            && self.opened_at.elapsed() >= duration
        {
            return true;
        }
        false
    }

    fn rotate(&mut self, eager: bool) -> Result<(), WriteFailure> {
        if let Some(mut writer) = self.writer.take() {
            writer.finish().map_err(|error| self.failure(error))?;
        }
        self.current = None;
        self.files_finished = self.files_finished.saturating_add(1);
        if self
            .stop_after_files
            .is_some_and(|limit| self.files_finished >= limit)
        {
            self.stop = true;
            return Ok(());
        }
        if eager {
            self.sequence = self.sequence.saturating_add(1);
            let path = ring_path(&self.file, self.sequence, &local_timestamp());
            self.open(&path)?;
        } else {
            // A packet-driven rotation creates the next member only when
            // another packet arrives, so a run that ends exactly on the
            // boundary leaves no empty file.
            self.rotate_before_next = true;
        }
        Ok(())
    }

    /// One writer or file-log failure with the status for this run mode.
    fn output_failure(&self, message: impl Into<String>) -> WriteFailure {
        WriteFailure::new(if self.live { 1 } else { 15 }, message)
    }

    /// Map a writer error to its exit status.
    ///
    /// Read mode: `Incompatible` is discovered before the writer emits any
    /// byte and exits 9; any later failure exits 15. Live mode maps every
    /// writer failure to 1. An output that has not emitted a byte is removed
    /// in both modes, so a failed start leaves no empty file.
    fn failure(&self, error: WriteError) -> WriteFailure {
        let before_output = matches!(error, WriteError::Incompatible(_));
        let empty = self
            .writer
            .as_ref()
            .is_none_or(|writer| writer.logical_bytes() == 0);
        if (before_output || self.live) && empty {
            // The current path is retained while the writer is open; a
            // rotation clears it after finishing the previous file.
            if let Some(path) = &self.current {
                let _ = std::fs::remove_file(path);
            }
        }
        let status = if self.live {
            1
        } else if before_output {
            9
        } else {
            15
        };
        WriteFailure::new(status, error.to_string())
    }
}

/// Create an output file, with live captures restricted to their owner.
///
/// The mode is requested at creation so no window exposes a new live capture
/// at the umask default. A later chmod is limited to regular files: devices
/// such as `/dev/null` and FIFOs must keep their own permissions.
fn create_output(path: &Path, live: bool) -> io::Result<File> {
    let mut options = FsOpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if live {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    if live && file.metadata()?.is_file() {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = live;
    Ok(file)
}

/// One output destination: a file or standard output.
enum Destination {
    File(File),
    Stdout(io::Stdout),
}

impl Write for Destination {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.write(buffer),
            Self::Stdout(stdout) => stdout.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.flush(),
            Self::Stdout(stdout) => stdout.flush(),
        }
    }
}

/// Build a ring member name: `stem_00001_YYYYmmddHHMMSS.ext`.
///
/// The suffix is inserted before the first dot in the base name, so
/// `capture.pcap.gz` becomes `capture_00001_....pcap.gz`; the name
/// keeps every extension there. A name without a dot keeps none. On Unix the
/// original bytes are preserved, so a non-UTF-8 live name still rotates
/// instead of overwriting the same path.
#[cfg(unix)]
fn ring_path(path: &Path, sequence: u64, timestamp: &str) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let Some(name) = path.file_name() else {
        return path.to_path_buf();
    };
    let bytes = name.as_bytes();
    let split = bytes
        .iter()
        .position(|byte| *byte == b'.')
        .filter(|index| *index > 0)
        .unwrap_or(bytes.len());
    let Some(stem) = bytes.get(..split) else {
        return path.to_path_buf();
    };
    let extension = bytes.get(split..).unwrap_or_default();
    let mut member = Vec::with_capacity(bytes.len() + 24);
    member.extend_from_slice(stem);
    member.extend_from_slice(format!("_{sequence:05}_{timestamp}").as_bytes());
    member.extend_from_slice(extension);
    let member = OsString::from_vec(member);
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(member),
        _ => PathBuf::from(member),
    }
}

#[cfg(not(unix))]
fn ring_path(path: &Path, sequence: u64, timestamp: &str) -> PathBuf {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path.to_path_buf();
    };
    let split = name.find('.').filter(|index| *index > 0);
    let (stem, extension) = match split {
        Some(index) => (&name[..index], &name[index..]),
        None => (name, ""),
    };
    let member = format!("{stem}_{sequence:05}_{timestamp}{extension}");
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(member),
        _ => PathBuf::from(member),
    }
}

/// Render one printname line, prefixing a bare name with `./`.
#[cfg(unix)]
fn print_name_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    let bare = path
        .parent()
        .is_some_and(|parent| parent.as_os_str().is_empty());
    let mut bytes = Vec::with_capacity(path.as_os_str().as_bytes().len() + 3);
    if bare {
        bytes.extend_from_slice(b"./");
    }
    bytes.extend_from_slice(path.as_os_str().as_bytes());
    bytes.push(b'\n');
    bytes
}

#[cfg(not(unix))]
fn print_name_bytes(path: &Path) -> Vec<u8> {
    let text = path.to_string_lossy();
    if path
        .parent()
        .is_some_and(|parent| parent.as_os_str().is_empty())
    {
        format!("./{text}\n").into_bytes()
    } else {
        format!("{text}\n").into_bytes()
    }
}

/// Current wall-clock time in the local zone, used in ring member names.
fn local_timestamp() -> String {
    chrono::Local::now().format("%Y%m%d%H%M%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::{WriterSession, ring_path};
    use crate::cli::{AutostopOptions, RingOptions, WriteOptions};
    use packetfin_core::capture::{CaptureEvent, CaptureReader, InterfaceInfo};
    use packetfin_core::{Frame, OutputFormat, Resolution};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "packetfin-session-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        path
    }

    fn frame(number: u64) -> Frame {
        Frame {
            number,
            timestamp: Some(packetfin_core::Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            timestamp_precision: 6,
            captured: vec![0; 60],
            original_len: 60,
            link_type: 1,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: Some(0),
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: Default::default(),
        }
    }

    fn options(file: &Path) -> WriteOptions {
        WriteOptions {
            file: Some(file.to_path_buf()),
            format: OutputFormat::Pcap(Resolution::Microsecond),
            ..WriteOptions::default()
        }
    }

    #[test]
    fn ring_names_insert_before_the_first_dot() {
        let cases = [
            ("r.pcapng", "r_00001_20261103224943.pcapng"),
            ("r.pcap.gz", "r_00001_20261103224943.pcap.gz"),
            ("r.tar.gz", "r_00001_20261103224943.tar.gz"),
            ("r", "r_00001_20261103224943"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                ring_path(Path::new(input), 1, "20261103224943"),
                PathBuf::from(expected)
            );
        }
        assert_eq!(
            ring_path(Path::new("/tmp/out/r.pcapng"), 42, "20261103224943"),
            PathBuf::from("/tmp/out/r_00042_20261103224943.pcapng")
        );
    }

    #[test]
    fn a_missing_pcapng_timestamp_units_maps_to_fifteen() -> Result<(), String> {
        let directory = scratch("missing-units");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("r.pcapng");
        let mut write = options(&file);
        write.format = OutputFormat::PcapNg;
        let mut session = WriterSession::new(&write)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        session
            .observe(&CaptureEvent::Interface(InterfaceInfo {
                global_index: 0,
                link_type: 1,
                snap_len: 262_144,
                options: Vec::new(),
            }))
            .map_err(|failure| failure.message)?;
        let mut frame = frame(1);
        frame.timestamp_units = None;
        let failure = match session.write_frame(&frame) {
            Ok(()) => return Err("a timestamp without raw units did not fail".to_string()),
            Err(failure) => failure,
        };
        assert_eq!(failure.status, 15, "{}", failure.message);
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ring_names_preserve_non_utf8_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let path = PathBuf::from(OsString::from_vec(b"r\xff.pcap.gz".to_vec()));
        let member = ring_path(&path, 7, "20261103224943");
        assert_eq!(
            member.file_name().map(|name| name.as_bytes()),
            Some(b"r\xff_00007_20261103224943.pcap.gz".as_slice())
        );
        assert_eq!(
            super::print_name_bytes(&member),
            b"./r\xff_00007_20261103224943.pcap.gz\n"
        );
    }

    #[test]
    fn local_timestamp_has_fourteen_digits() {
        let timestamp = super::local_timestamp();
        assert_eq!(timestamp.len(), 14);
        assert!(timestamp.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn ring_rotation_names_and_stops_after_the_files_limit() -> Result<(), String> {
        let directory = scratch("rotate");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("r.pcap");
        let mut write = options(&file);
        write.ring = RingOptions {
            packets: Some(1),
            files: Some(2),
            ..RingOptions::default()
        };
        write.autostop = AutostopOptions {
            files: Some(2),
            ..AutostopOptions::default()
        };
        let mut session = WriterSession::new(&write)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        session
            .observe(&CaptureEvent::Interface(InterfaceInfo {
                global_index: 0,
                link_type: 1,
                snap_len: 262_144,
                options: Vec::new(),
            }))
            .map_err(|failure| failure.message)?;
        session
            .write_frame(&frame(1))
            .map_err(|failure| failure.message)?;
        session
            .write_frame(&frame(2))
            .map_err(|failure| failure.message)?;
        assert!(session.should_stop());
        session.finish().map_err(|failure| failure.message)?;

        let mut names: Vec<String> = fs::read_dir(&directory)
            .map_err(|error| error.to_string())?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(
            names
                .first()
                .is_some_and(|name| name.starts_with("r_00001_")),
            "{names:?}"
        );
        assert!(
            names
                .get(1)
                .is_some_and(|name| name.starts_with("r_00002_")),
            "{names:?}"
        );
        assert!(
            names.first().is_some_and(|name| name.ends_with(".pcap")),
            "{names:?}"
        );

        let second = names.get(1).ok_or("second ring file missing")?;
        let bytes = fs::read(directory.join(second)).map_err(|error| error.to_string())?;
        let mut reader = CaptureReader::new(bytes.as_slice()).map_err(|error| error.to_string())?;
        let frame = reader
            .next_frame()
            .map_err(|error| error.to_string())?
            .ok_or("missing frame")?;
        assert_eq!(frame.number, 1);
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn files_limit_unlinks_the_oldest_member() -> Result<(), String> {
        let directory = scratch("retain");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("r.pcap");
        let mut write = options(&file);
        write.ring = RingOptions {
            packets: Some(1),
            files: Some(1),
            ..RingOptions::default()
        };
        let mut session = WriterSession::new(&write)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        session
            .observe(&CaptureEvent::Interface(InterfaceInfo {
                global_index: 0,
                link_type: 1,
                snap_len: 262_144,
                options: Vec::new(),
            }))
            .map_err(|failure| failure.message)?;
        for number in 1..=3 {
            session
                .write_frame(&frame(number))
                .map_err(|failure| failure.message)?;
        }
        session.finish().map_err(|failure| failure.message)?;
        let names: Vec<String> = fs::read_dir(&directory)
            .map_err(|error| error.to_string())?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(
            names
                .first()
                .is_some_and(|name| name.starts_with("r_00003_")),
            "{names:?}"
        );
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }

    fn live_interfaces() -> Vec<InterfaceInfo> {
        vec![
            InterfaceInfo {
                global_index: 0,
                link_type: 0,
                snap_len: 524_288,
                options: vec![
                    packetfin_core::capture::InterfaceOption::Name("lo0".to_owned()),
                    packetfin_core::capture::InterfaceOption::Description("Loopback".to_owned()),
                    packetfin_core::capture::InterfaceOption::TimestampResolution(
                        packetfin_core::capture::TimestampResolution::PowerOfTen(6),
                    ),
                ],
            },
            InterfaceInfo {
                global_index: 1,
                link_type: 1,
                snap_len: 524_288,
                options: vec![packetfin_core::capture::InterfaceOption::Name(
                    "en0".to_owned(),
                )],
            },
        ]
    }

    #[test]
    fn live_writer_forces_pcapng_and_private_files() -> Result<(), String> {
        let directory = scratch("live-multi");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("live.pcap");
        let interfaces = live_interfaces();
        let write = options(&file);
        let mut session = WriterSession::new_live(&write, &interfaces)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        session
            .write_frame(&frame(1))
            .map_err(|failure| failure.message)?;
        session.finish().map_err(|failure| failure.message)?;
        let bytes = fs::read(&file).map_err(|error| error.to_string())?;
        assert_eq!(
            bytes.get(..4),
            Some(0x0a0d_0d0a_u32.to_le_bytes().as_slice())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&file)
                .map_err(|error| error.to_string())?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let mut reader = CaptureReader::new(bytes.as_slice()).map_err(|error| error.to_string())?;
        let mut names = Vec::new();
        let mut frames = 0;
        while let Some(event) = reader.next_event().map_err(|error| error.to_string())? {
            match event {
                CaptureEvent::Section(_) => {}
                CaptureEvent::Interface(interface) => {
                    names.push(interface.name().unwrap_or_default().to_owned());
                }
                CaptureEvent::Frame(_) => frames += 1,
                CaptureEvent::NameResolution(_) => {}
            }
        }
        assert_eq!(names, ["lo0", "en0"]);
        assert_eq!(frames, 1);
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn live_nsecpcap_writes_microsecond_pcap_like_the_reference() -> Result<(), String> {
        let directory = scratch("live-nsec");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("live.pcap");
        let mut write = options(&file);
        write.format = OutputFormat::NsecPcap;
        let interfaces = vec![live_interfaces().remove(0)];
        let mut session = WriterSession::new_live(&write, &interfaces)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        session
            .write_frame(&frame(1))
            .map_err(|failure| failure.message)?;
        session.finish().map_err(|failure| failure.message)?;
        let bytes = fs::read(&file).map_err(|error| error.to_string())?;
        assert_eq!(bytes.get(..4), Some(&[0xd4, 0xc3, 0xb2, 0xa1][..]));
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn live_duration_rotation_opens_the_next_file_while_idle() -> Result<(), String> {
        let directory = scratch("live-duration");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let file = directory.join("r.pcapng");
        let mut write = options(&file);
        write.ring = RingOptions {
            duration: Some(std::time::Duration::from_millis(20)),
            ..RingOptions::default()
        };
        let interfaces = live_interfaces();
        let mut session = WriterSession::new_live(&write, &interfaces)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        std::thread::sleep(std::time::Duration::from_millis(30));
        session.tick().map_err(|failure| failure.message)?;
        session.finish().map_err(|failure| failure.message)?;
        let names: Vec<String> = fs::read_dir(&directory)
            .map_err(|error| error.to_string())?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn live_output_to_a_device_keeps_its_permissions() -> Result<(), String> {
        use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
        let path = Path::new("/dev/null");
        let before = fs::metadata(path)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode();
        let interfaces = live_interfaces();
        let write = options(path);
        let mut session = WriterSession::new_live(&write, &interfaces)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        session
            .write_frame(&frame(1))
            .map_err(|failure| failure.message)?;
        session.finish().map_err(|failure| failure.message)?;
        let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
        assert!(metadata.file_type().is_char_device(), "expected a device");
        assert_eq!(metadata.permissions().mode(), before);
        Ok(())
    }

    #[test]
    fn live_output_failures_use_exit_one() -> Result<(), String> {
        let interfaces = live_interfaces();
        let write = options(Path::new("/nonexistent/packetfin-live.pcapng"));
        match WriterSession::new_live(&write, &interfaces) {
            Ok(_) => Err("live writer unexpectedly opened".to_string()),
            Err(failure) => {
                assert_eq!(failure.status, 1);
                Ok(())
            }
        }
    }

    #[test]
    fn printname_prefixes_bare_names_with_a_dot_slash() -> Result<(), String> {
        let directory = scratch("printname");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let previous = std::env::current_dir().map_err(|error| error.to_string())?;
        std::env::set_current_dir(&directory).map_err(|error| error.to_string())?;
        let mut write = options(Path::new("r.pcap"));
        write.ring = RingOptions {
            packets: Some(1),
            printname: Some(PathBuf::from("names.txt")),
            ..RingOptions::default()
        };
        let session = WriterSession::new(&write)
            .map_err(|failure| failure.message)?
            .ok_or("session missing")?;
        drop(session);
        let names = fs::read_to_string("names.txt").map_err(|error| error.to_string())?;
        assert!(names.starts_with("./r_00001_"), "{names}");
        std::env::set_current_dir(previous).map_err(|error| error.to_string())?;
        fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }
}
