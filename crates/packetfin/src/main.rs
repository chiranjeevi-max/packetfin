mod cli;
mod color;
mod detail;
mod ek;
mod export;
mod fields;
mod hexdump;
mod json;
mod live;
mod mask;
mod pdml;
mod ps;
mod psml;
mod raw;
mod record_buffer;
mod render_context;
mod reports;
mod session;
mod summary;
#[cfg(test)]
mod test_support;
mod xml;

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::exit;

use zeroize::Zeroize;

use packetfin_core::decode::DecodeOptions;
use packetfin_core::stats::{StatsOptions, StatsSet};
use packetfin_core::{
    AnnotationStore, CaptureError, CaptureEvent, CaptureReader, DecodeSession, ExportedKey,
    FieldDef, FieldSelection, Filter, FilterError, Frame, FrameAnnotation, KeyLog, Packet,
    PassMode, ProtocolSelection, RenumberMap, apply_annotations,
};

use cli::{
    Action, EkOptions, ExportObjects, ExportProtocol, FieldsOptions, Input, JsonOptions, ListModes,
    LiveOptions, PdmlOptions, PsOptions, PsmlOptions, Report, SummaryOptions, TlsOptions,
    WriteOptions,
};
use detail::DetailWriter;
use ek::EkWriter;
use hexdump::HexdumpWriter;
use json::JsonWriter;
use live::LiveSession;
use pdml::PdmlWriter;
use ps::PsWriter;
use psml::PsmlWriter;
use session::WriterSession;

/// Sized so a short capture read is served from the buffer without growing
/// the per-process footprint beyond a few hundred kilobytes.
const READ_BUFFER_SIZE: usize = 256 * 1024;
/// Batches packet lines before each standard-output write.
const WRITE_BUFFER_SIZE: usize = 64 * 1024;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    match cli::parse(&args) {
        Action::Help => {
            cli::print_help();
            exit(0);
        }
        Action::Version => {
            cli::print_version();
            exit(0);
        }
        Action::ListDevices => exit(run_list_devices()),
        Action::ListCaptureModes { options, modes } => {
            exit(run_list_capture_modes(&options, modes))
        }
        Action::Unknown(option) => {
            diagnostic(&format!("unrecognized option: {option}"));
            cli::print_usage(&mut io::stderr());
            exit(1);
        }
        Action::Argument(argument) => {
            diagnostic(&format!("unexpected argument: {argument}"));
            cli::print_usage(&mut io::stderr());
            exit(1);
        }
        Action::Usage(message) => {
            diagnostic(&message);
            cli::print_usage(&mut io::stderr());
            exit(1);
        }
        Action::Error(message) => {
            diagnostic(&message);
            exit(1);
        }
        Action::StatsHelp => {
            write_stats_message(&packetfin_core::stats::help_text());
            exit(0);
        }
        Action::StatsError(message) => {
            for (index, line) in message.lines().enumerate() {
                // Prefix the diagnostic lines but leave the indented
                // supported-name list unprefixed.
                if index == 0 || !line.starts_with(' ') {
                    diagnostic(line);
                } else {
                    raw_stderr_line(line);
                }
            }
            exit(1);
        }
        Action::ExitZero(message) => {
            diagnostic(&message);
            exit(0);
        }
        Action::Fields(options) => exit(run_fields(&options)),
        Action::Json(options) => exit(run_json(&options)),
        Action::Pdml(options) => exit(run_pdml(&options)),
        Action::Psml(options) => exit(run_psml(&options)),
        Action::Ek(options) => exit(run_ek(&options)),
        Action::Ps(options) => exit(run_ps(&options)),
        Action::Summary(options) => exit(run_summary(&options)),
        Action::Report(report) => exit(run_report(report)),
        Action::HexdumpHelp => {
            cli::print_hexdump_help();
            exit(0);
        }
        Action::DisplayFilter { filter, error } => {
            report_filter_error(&filter, &error);
            exit(4)
        }
    }
}

/// Write one statistics list line without the diagnostic prefix.
fn raw_stderr_line(line: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{}", escape_controls(line));
}

/// Print a multi-line statistics message without escaping its line breaks.
fn write_stats_message(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "packetfin: {message}");
}

/// Open a capture path or standard input, reporting an unreadable input.
fn open_input(read_file: &std::path::Path) -> Result<Box<dyn Read>, i32> {
    if read_file.as_os_str() == OsStr::new("-") {
        if stdin_is_special() {
            diagnostic("standard input is a special file; use a pipe or a regular file");
            return Err(3);
        }
        return Ok(Box::new(BufReader::with_capacity(
            READ_BUFFER_SIZE,
            io::stdin().lock(),
        )));
    }
    match File::open(read_file) {
        Ok(file) => Ok(Box::new(BufReader::with_capacity(READ_BUFFER_SIZE, file))),
        Err(error) => {
            diagnostic(&format!("cannot open {}: {error}", read_file.display()));
            Err(3)
        }
    }
}

/// One output mode's part of the read loop.
///
/// The driver owns the capture reader, the decode session and standard
/// output; a sink only turns decoded packets into its format's bytes and
/// reports whether a packet reached stdout.
trait PacketSink {
    /// Write the format's leading bytes before the first packet.
    fn start(&mut self, _writer: &mut impl Write) -> io::Result<()> {
        Ok(())
    }

    /// Restart presentation state that `-M` resets with the session.
    fn reset(&mut self) {}

    /// Observe a read-filter-rejected frame for time baselines and state.
    fn observe_skipped(&mut self, _frame: &Frame) {}

    /// Write or hide one decoded packet.
    ///
    /// `matched` is the display-filter result the driver computed once; the
    /// sink must not evaluate the filter again. Returns whether the packet
    /// was displayed; a hidden packet advances the format's frame state but
    /// never triggers a line flush.
    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool>;

    /// Write the format's trailing bytes after the last packet.
    fn finish(&mut self, _writer: &mut impl Write) -> io::Result<()> {
        Ok(())
    }

    /// Close a partial document after a capture read error.
    ///
    /// The capture's exit status wins over a write failure here.
    fn abort(&mut self, writer: &mut impl Write) {
        let _ = self.finish(writer);
    }
}

/// Read-path settings shared by every output mode.
struct CaptureOptions<'a> {
    input: &'a Input,
    packet_count: Option<u64>,
    flush: bool,
    decode_options: DecodeOptions,
    state_budget: usize,
    write: &'a WriteOptions,
    display_filter: Option<&'a Filter>,
    exports: &'a [ExportObjects],
    tls: &'a TlsOptions,
    stats: &'a StatsOptions,
}

/// Capture once, feed every frame through one decode session and hand it to
/// `sink`.
///
/// A file or a live capture differs only in where frames come from: decoding,
/// display filtering, writing, flushing and error mapping use the same
/// [`output_frame`] path.
fn drive<S: PacketSink>(options: &CaptureOptions<'_>, sink: S) -> i32 {
    for notice in &options.decode_options.notices {
        diagnostic(notice);
    }
    match options.input {
        Input::Read(read_file) => drive_read(options, read_file, sink),
        Input::Live(live) => drive_live(options, live, sink),
    }
}

/// Read a capture file once and hand every frame to `sink`.
///
/// This is the only read/decode loop: output formats differ in their sink,
/// not in how frames are counted, filtered, flushed or reported on error.
/// A two-pass run reuses the same loop for its second pass after recording
/// the read-filter matches.
fn drive_read<S: PacketSink>(options: &CaptureOptions<'_>, read_file: &Path, sink: S) -> i32 {
    if options.write.two_pass {
        if let Err(status) = two_pass_input_status(read_file) {
            return status;
        }
        if let Err(status) = reject_same_input_output(options, read_file) {
            return status;
        }
        return drive_two_pass(options, read_file, sink);
    }

    let input = match open_input(read_file) {
        Ok(input) => input,
        Err(status) => return status,
    };
    let reader = match CaptureReader::new(input) {
        Ok(reader) => reader,
        Err(error) => {
            diagnostic(&error.to_string());
            return capture_exit_code(&error);
        }
    };
    let writer_session = match WriterSession::new(options.write) {
        Ok(session) => session,
        Err(failure) => {
            diagnostic(&failure.message);
            return failure.status;
        }
    };
    drive_frames(options, reader, writer_session, sink)
}

/// Two-pass reading keeps one open file and rewinds it instead of reopening
/// the path, so `/dev/stdin` and `/dev/fd/N` do not share a consumed offset
/// and a rename between passes cannot change the source.
fn drive_two_pass<S: PacketSink>(options: &CaptureOptions<'_>, read_file: &Path, sink: S) -> i32 {
    let file = match File::open(read_file) {
        Ok(file) => file,
        Err(error) => {
            diagnostic(&format!("cannot open {}: {error}", read_file.display()));
            return 3;
        }
    };
    let pass_one = match file.try_clone() {
        Ok(file) => file,
        Err(error) => {
            diagnostic(&format!("cannot open the input twice: {error}"));
            return 3;
        }
    };
    let input: Box<dyn Read> = Box::new(BufReader::with_capacity(READ_BUFFER_SIZE, pass_one));
    let reader = match CaptureReader::new(input) {
        Ok(reader) => reader,
        Err(error) => {
            diagnostic(&error.to_string());
            return capture_exit_code(&error);
        }
    };
    let mut writer_session = match WriterSession::new(options.write) {
        Ok(session) => session,
        Err(failure) => {
            diagnostic(&failure.message);
            return failure.status;
        }
    };

    let (accepted, metadata, annotations) =
        match first_pass(options, reader, options.write.file.is_some()) {
            Ok(result) => result,
            Err((status, metadata)) => {
                replay_metadata(&mut writer_session, &metadata);
                let _ = finish_writer(&mut writer_session);
                return status;
            }
        };
    let mut file = file;
    if let Err(error) = file.seek(SeekFrom::Start(0)) {
        diagnostic(&format!(
            "cannot rewind {} for the second pass: {error}",
            read_file.display()
        ));
        replay_metadata(&mut writer_session, &metadata);
        let _ = finish_writer(&mut writer_session);
        return 3;
    }
    let input: Box<dyn Read> = Box::new(BufReader::with_capacity(READ_BUFFER_SIZE, file));
    let reader = match CaptureReader::new(input) {
        Ok(reader) => reader,
        Err(error) => {
            diagnostic(&error.to_string());
            replay_metadata(&mut writer_session, &metadata);
            let _ = finish_writer(&mut writer_session);
            return capture_exit_code(&error);
        }
    };
    // Pass two re-reads the metadata; the pass-one copy is only needed to
    // repair an output after an error.
    drop(metadata);
    second_pass(
        options,
        reader,
        &accepted,
        annotations,
        writer_session,
        sink,
    )
}

/// Replay metadata into a writer without turning a capture-read failure into
/// a writer failure.
fn replay_metadata(session: &mut Option<WriterSession>, metadata: &[CaptureEvent]) {
    let Some(session) = session else {
        return;
    };
    for event in metadata {
        if session.observe(event).is_err() {
            break;
        }
    }
}

/// The two-pass first pass: decode every frame, keep the file frame numbers
/// the read filter accepts and record no output.
///
/// The decode session runs with [`PassMode::First`] so the annotation task
/// can attach cross-frame state to this pass without changing the driver.
type FirstPassResult =
    Result<(Vec<u64>, Vec<CaptureEvent>, AnnotationStore), (i32, Vec<CaptureEvent>)>;

fn first_pass(
    options: &CaptureOptions<'_>,
    mut reader: CaptureReader<Box<dyn Read>>,
    buffer_metadata: bool,
) -> FirstPassResult {
    let mut session = DecodeSession::with_budgets(
        options.decode_options.clone(),
        options.state_budget,
        options.write.annotation_budget,
        PassMode::First,
    );
    let mut accepted = Vec::new();
    let mut metadata = Vec::new();
    let mut noticed_truncation = false;
    loop {
        match reader.next_event() {
            Ok(Some(CaptureEvent::Frame(mut frame))) => {
                let file_number = frame.number;
                // The read filter sees the prospective output position
                // in the recording pass: the count of accepted frames plus
                // one, whether or not this frame is accepted.
                frame.number = u64::try_from(accepted.len()).unwrap_or(u64::MAX) + 1;
                let packet = session.decode_at(&frame, file_number);
                if session.take_annotation_truncated() && !noticed_truncation {
                    noticed_truncation = true;
                    diagnostic("annotation budget exhausted; later link fields are omitted");
                }
                if options
                    .write
                    .read_filter
                    .as_ref()
                    .is_none_or(|filter| filter.matches(&packet.tree))
                {
                    accepted.push(file_number);
                    // The recording pass stops after the accepted frame at
                    // or past the -c limit; rejected frames never stop it,
                    // so links are still recorded for a frame that will not
                    // be displayed.
                    if options
                        .packet_count
                        .is_some_and(|limit| file_number >= limit)
                    {
                        break;
                    }
                }
            }
            Ok(Some(event)) => {
                // Metadata is replayed only to repair a capture output; a run
                // without `-w` must not retain 16 MB name-resolution blocks.
                if buffer_metadata {
                    metadata.push(event);
                }
            }
            Ok(None) => break,
            Err(error) => {
                diagnostic(&error.to_string());
                return Err((capture_exit_code(&error), metadata));
            }
        }
    }
    session.finish_pass();
    if session.take_annotation_truncated() && !noticed_truncation {
        diagnostic("annotation budget exhausted; later link fields are omitted");
    }
    let annotations = session.into_annotations();
    Ok((accepted, metadata, annotations))
}

/// Report why a two-pass run cannot read its input.
///
/// Both passes need random access. A pipe/FIFO, a character or block device,
/// a socket and a directory are rejected with status 3; a regular file
/// redirected into standard input still works through the single-handle
/// rewind in [`drive_two_pass`].
fn two_pass_input_status(read_file: &Path) -> Result<(), i32> {
    if read_file == Path::new("-") {
        let message = if stdin_is_fifo() {
            "the standard input is a pipe or FIFO; two-pass mode cannot read it"
        } else {
            "the standard input cannot be opened for random access"
        };
        diagnostic(message);
        return Err(3);
    }
    let metadata = match std::fs::metadata(read_file) {
        Ok(metadata) => metadata,
        Err(error) => {
            diagnostic(&format!("cannot open {}: {error}", read_file.display()));
            return Err(3);
        }
    };
    if metadata.is_file() {
        return Ok(());
    }
    let message = if metadata_is_fifo(&metadata) {
        format!(
            "the file \"{}\" is a pipe or FIFO; two-pass mode cannot read it",
            read_file.display()
        )
    } else {
        format!(
            "the file \"{}\" is a special file, socket or other non-regular file; two-pass mode cannot read it",
            read_file.display()
        )
    };
    diagnostic(&message);
    Err(3)
}

/// Refuse a two-pass run whose output names the input file.
///
/// The writer truncates its path before the first pass, so the only safe
/// option is to stop before opening it. A single-pass run still exits 14 after
/// the damaged read.
fn reject_same_input_output(options: &CaptureOptions<'_>, read_file: &Path) -> Result<(), i32> {
    let Some(output) = options.write.file.as_deref() else {
        return Ok(());
    };
    if output == Path::new("-") || !same_file(read_file, output) {
        return Ok(());
    }
    diagnostic(
        "the input and output name the same file; two-pass mode refuses to overwrite the capture it is reading",
    );
    Err(1)
}

#[cfg(unix)]
fn same_file(input: &Path, output: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    match (std::fs::metadata(input), std::fs::metadata(output)) {
        (Ok(input), Ok(output)) => input.dev() == output.dev() && input.ino() == output.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(input: &Path, output: &Path) -> bool {
    match (std::fs::canonicalize(input), std::fs::canonicalize(output)) {
        (Ok(input), Ok(output)) => input == output,
        _ => false,
    }
}

#[cfg(unix)]
fn metadata_is_fifo(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;

    metadata.file_type().is_fifo()
}

#[cfg(not(unix))]
fn metadata_is_fifo(_: &std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn stdin_is_fifo() -> bool {
    std::fs::metadata("/dev/stdin").is_ok_and(|metadata| metadata_is_fifo(&metadata))
}

#[cfg(not(unix))]
fn stdin_is_fifo() -> bool {
    false
}

/// Run one pass over the frames, writing selected packets through `sink`.
fn drive_frames<S: PacketSink>(
    options: &CaptureOptions<'_>,
    mut reader: CaptureReader<Box<dyn Read>>,
    mut writer_session: Option<WriterSession>,
    mut sink: S,
) -> i32 {
    let mut keylog = KeyLog::new();
    if let Some(path) = options.tls.keylog_file.as_ref()
        && let Ok(file) = File::open(path)
    {
        keylog = KeyLog::read(BufReader::new(file));
        if keylog.truncated() {
            diagnostic("TLS key log reached its size or entry limit; remaining lines ignored");
        }
    }
    let mut session = DecodeSession::with_pass(
        options.decode_options.clone(),
        options.state_budget,
        PassMode::One,
    );
    attach_object_export(&mut session, options.exports);
    session.set_keylog(keylog);
    session.set_tls_key_export(options.tls.export_session_keys.is_some());
    let mut tls_keys = options
        .tls
        .export_session_keys
        .as_deref()
        .and_then(open_tls_key_file);
    let mut statistics = StatsSet::new(options.stats);
    statistics.set_http_desegment(options.decode_options.preferences.tcp_desegment_tcp_streams);
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, io::stdout().lock());
    if let Err(error) = sink.start(&mut writer) {
        if let Err(write_status) = finish_writer(&mut writer_session) {
            return write_status;
        }
        return output_failure(&error);
    }

    // `-c` counts packets read, not packets that pass a display
    // filter; `-a packets` counts the packets that are selected instead.
    let mut read_packets = 0_u64;
    let mut selected_packets = 0_u64;
    let reset_interval = options.write.reset_interval;
    let mut displayed_number = 0_u64;
    loop {
        if options
            .packet_count
            .is_some_and(|limit| read_packets >= limit)
        {
            break;
        }
        let event = match reader.next_event() {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(error) => {
                // Frames read before the error are already buffered; emit what
                // can be written before reporting why the capture stopped.
                sink.abort(&mut writer);
                let _ = writer.flush();
                if let Some(status) = render_statistics(&mut statistics, options.stats, &mut writer)
                {
                    return status;
                }
                let _ = finish_writer(&mut writer_session);
                diagnostic(&error.to_string());
                return capture_exit_code(&error);
            }
        };
        let names = reader.take_name_records();
        if !names.is_empty() {
            session.add_capture_names(names);
        }
        let mut frame = match event {
            CaptureEvent::Frame(frame) => frame,
            metadata => {
                if let Some(session) = &mut writer_session
                    && let Err(failure) = session.observe(&metadata)
                {
                    diagnostic(&failure.message);
                    return failure.status;
                }
                continue;
            }
        };

        read_packets = read_packets.saturating_add(1);
        let file_number = frame.number;
        if let Some(interval) = reset_interval
            && read_packets > 1
            && (read_packets - 1).is_multiple_of(u64::from(interval))
        {
            // The notice goes to stderr, and neither -q nor -Q suppresses
            // it, unlike the summary line.
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "resetting session.");
            session.reset_session();
            sink.reset();
            displayed_number = 0;
        }
        if reset_interval.is_some() {
            displayed_number = displayed_number.saturating_add(1);
            frame.number = displayed_number;
        }
        let outcome = match output_frame(
            &frame,
            &mut session,
            &mut statistics,
            options,
            &mut writer_session,
            &mut sink,
            &mut writer,
            file_number,
            None,
        ) {
            Ok(outcome) => outcome,
            Err(FrameError::Writer(status)) => {
                drop(writer_session.take());
                return status;
            }
            Err(FrameError::Output(status)) => {
                if let Err(write_status) = finish_writer(&mut writer_session) {
                    return write_status;
                }
                return status;
            }
        };
        let keys = session.take_export_keys();
        if let Some(file) = tls_keys.as_mut() {
            write_exported_keys(file, keys);
        }
        if session.take_name_drop() {
            diagnostic("the name tables are full; some learned names were not retained");
        }
        if outcome.matched {
            selected_packets = selected_packets.saturating_add(1);
        }

        if options
            .write
            .autostop
            .packets
            .is_some_and(|limit| selected_packets >= limit)
        {
            break;
        }
        // Read-mode `-a filesize` compares the decompressed source offset of
        // the frame that was just processed, even when `-Y` hid it.
        if options
            .write
            .autostop
            .filesize
            .is_some_and(|limit| frame.source_offset >= limit)
        {
            break;
        }
        if writer_session
            .as_ref()
            .is_some_and(WriterSession::should_stop)
        {
            break;
        }
    }

    if let Err(failure) = finish_writer(&mut writer_session) {
        return failure;
    }
    if let Err(error) = sink.finish(&mut writer) {
        return output_failure(&error);
    }
    if let Some(status) = render_statistics(&mut statistics, options.stats, &mut writer) {
        return status;
    }
    // A write failure from the final buffered flush is ignored when
    // no packet flush exposed it earlier; `-l` makes each packet flush
    // observable and still exits 16 through `output_failure`.
    let _ = writer.flush();
    0
}

/// Second pass of a two-pass run: re-read the file, renumber selected frames
/// from one and pass them to the same sink as a normal run.
fn second_pass<S: PacketSink>(
    options: &CaptureOptions<'_>,
    mut reader: CaptureReader<Box<dyn Read>>,
    accepted: &[u64],
    annotations: AnnotationStore,
    mut writer_session: Option<WriterSession>,
    mut sink: S,
) -> i32 {
    // With no read-filter match the output capture still holds the source
    // metadata but no packet blocks. Passing the metadata events through
    // keeps the pcap link type and the pcapng section and interface
    // description.
    if accepted.is_empty() {
        let mut statistics = StatsSet::new(options.stats);
        statistics.set_http_desegment(options.decode_options.preferences.tcp_desegment_tcp_streams);
        let mut writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, io::stdout().lock());
        if let Err(error) = sink.start(&mut writer) {
            if let Err(write_status) = finish_writer(&mut writer_session) {
                return write_status;
            }
            return output_failure(&error);
        }
        loop {
            match reader.next_event() {
                Ok(Some(CaptureEvent::Frame(_))) => {}
                Ok(Some(metadata)) => {
                    if let Some(session) = &mut writer_session
                        && let Err(failure) = session.observe(&metadata)
                    {
                        diagnostic(&failure.message);
                        return failure.status;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    sink.abort(&mut writer);
                    let _ = writer.flush();
                    let _ = finish_writer(&mut writer_session);
                    diagnostic(&error.to_string());
                    return capture_exit_code(&error);
                }
            }
        }
        if let Err(failure) = finish_writer(&mut writer_session) {
            return failure;
        }
        if let Err(error) = sink.finish(&mut writer) {
            return output_failure(&error);
        }
        if let Some(status) = render_statistics(&mut statistics, options.stats, &mut writer) {
            return status;
        }
        let _ = writer.flush();
        return 0;
    }

    let mut session = DecodeSession::with_annotations(
        options.decode_options.clone(),
        options.state_budget,
        annotations,
        PassMode::Second,
    );
    attach_object_export(&mut session, options.exports);
    let mut tls_keys = attach_tls_session(&mut session, options.tls);
    let mut statistics = StatsSet::new(options.stats);
    statistics.set_http_desegment(options.decode_options.preferences.tcp_desegment_tcp_streams);
    let renumber = RenumberMap::new(accepted.iter().copied());
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, io::stdout().lock());
    if let Err(error) = sink.start(&mut writer) {
        if let Err(write_status) = finish_writer(&mut writer_session) {
            return write_status;
        }
        return output_failure(&error);
    }

    let mut next = 0_usize;
    let mut output_number = 0_u64;
    let mut accepted_count = 0_u64;
    loop {
        if next >= accepted.len() {
            break;
        }
        let event = match reader.next_event() {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(error) => {
                sink.abort(&mut writer);
                let _ = writer.flush();
                if let Some(status) = render_statistics(&mut statistics, options.stats, &mut writer)
                {
                    return status;
                }
                let _ = finish_writer(&mut writer_session);
                diagnostic(&error.to_string());
                return capture_exit_code(&error);
            }
        };
        let names = reader.take_name_records();
        if !names.is_empty() {
            session.add_capture_names(names);
        }
        let original = match event {
            CaptureEvent::Frame(frame) => frame,
            metadata => {
                if let Some(session) = &mut writer_session
                    && let Err(failure) = session.observe(&metadata)
                {
                    diagnostic(&failure.message);
                    return failure.status;
                }
                continue;
            }
        };

        let Some(expected) = accepted.get(next).copied() else {
            break;
        };
        if original.number != expected {
            // Keep decoding frames the read filter did not select:
            // stream reassembly and request/response state must see them so
            // an accepted frame split across skipped segments still decodes.
            let file_number = original.number;
            let mut skipped = original;
            // The read filter sees the prospective output position; skipped
            // frames keep that number for state but are never displayed.
            skipped.number = accepted_count.saturating_add(1);
            let _ = session.decode_observation(&skipped, file_number);
            sink.observe_skipped(&skipped);
            // Always emit the first read-filter match, even when the
            // size limit was crossed by an earlier skipped frame. Once one
            // frame has been emitted, a skipped oversized frame stops the
            // pass as usual.
            if accepted_count > 0
                && options
                    .write
                    .autostop
                    .filesize
                    .is_some_and(|limit| skipped.source_offset >= limit)
            {
                break;
            }
            continue;
        }
        next += 1;
        accepted_count = accepted_count.saturating_add(1);
        output_number = output_number.saturating_add(1);
        let mut frame = original;
        let file_number = frame.number;
        // A read-filter match is renumbered from one in pass two, so
        // `frame.number` and a `-Y frame.number==N` expression both see the
        // output position. First-pass annotations use the same map.
        frame.number = output_number;
        let annotation = session.annotation(file_number).copied();
        if let Err(error) = output_frame(
            &frame,
            &mut session,
            &mut statistics,
            options,
            &mut writer_session,
            &mut sink,
            &mut writer,
            file_number,
            annotation
                .as_ref()
                .map(|annotation| (annotation, &renumber)),
        ) {
            return match error {
                FrameError::Writer(status) => {
                    drop(writer_session.take());
                    status
                }
                FrameError::Output(status) => {
                    if let Err(write_status) = finish_writer(&mut writer_session) {
                        write_status
                    } else {
                        status
                    }
                }
            };
        }
        let keys = session.take_export_keys();
        if let Some(file) = tls_keys.as_mut() {
            write_exported_keys(file, keys);
        }
        if session.take_name_drop() {
            diagnostic("the name tables are full; some learned names were not retained");
        }
        if options
            .packet_count
            .is_some_and(|limit| accepted_count >= limit)
        {
            break;
        }
        if options
            .write
            .autostop
            .filesize
            .is_some_and(|limit| frame.source_offset >= limit)
        {
            break;
        }
        if writer_session
            .as_ref()
            .is_some_and(WriterSession::should_stop)
        {
            break;
        }
    }

    if let Err(failure) = finish_writer(&mut writer_session) {
        return failure;
    }
    if let Err(error) = sink.finish(&mut writer) {
        return output_failure(&error);
    }
    if let Some(status) = render_statistics(&mut statistics, options.stats, &mut writer) {
        return status;
    }
    let _ = writer.flush();
    0
}

/// Decode one frame, apply the display filter, write and display it.
///
/// Every capture source uses this function, so `-w`, `-Y`, `-l` and sink
/// failures behave identically for a file and a live interface.
#[expect(
    clippy::too_many_arguments,
    reason = "the driver passes its independent session, writer and sink state"
)]
fn output_frame<S: PacketSink>(
    frame: &Frame,
    session: &mut DecodeSession,
    statistics: &mut StatsSet<'_>,
    options: &CaptureOptions<'_>,
    writer_session: &mut Option<WriterSession>,
    sink: &mut S,
    writer: &mut impl Write,
    file_number: u64,
    annotation: Option<(&FrameAnnotation, &RenumberMap)>,
) -> Result<FrameOutcome, FrameError> {
    let mut packet = session.decode_observed_at(frame, file_number, statistics.stream_observer());
    if let Some((annotation, renumber)) = annotation {
        apply_annotations(&mut packet, annotation, renumber);
    }
    statistics.observe(frame, &packet);
    let matched = options
        .display_filter
        .is_none_or(|filter| filter.matches(&packet.tree));
    if matched && let Some(writer_session) = writer_session {
        if let Err(failure) = writer_session.write_frame(frame) {
            diagnostic(&failure.message);
            return Err(FrameError::Writer(failure.status));
        }
        if options.flush
            && write_targets_stdout(options.write)
            && let Err(failure) = writer_session.flush()
        {
            diagnostic(&failure.message);
            return Err(FrameError::Writer(failure.status));
        }
    }
    match sink.packet(writer, frame, &mut packet, matched) {
        Ok(displayed) => {
            if displayed
                && options.flush
                && let Err(error) = writer.flush()
            {
                return Err(FrameError::Output(output_failure(&error)));
            }
        }
        Err(error) => return Err(FrameError::Output(output_failure(&error))),
    }
    Ok(FrameOutcome { matched })
}

/// Render accumulated statistics and notices, returning a write-failure exit
/// status when the table output could not reach standard output.
fn render_statistics(
    statistics: &mut StatsSet<'_>,
    options: &StatsOptions,
    writer: &mut impl Write,
) -> Option<i32> {
    if options.specs.is_empty() {
        return None;
    }
    let mut adapter = FmtWriter {
        writer,
        error: None,
    };
    if statistics.finish(&mut adapter).is_err() {
        return Some(adapter.error.as_ref().map_or(16, output_failure));
    }
    if let Some(error) = adapter.error {
        return Some(output_failure(&error));
    }
    for notice in statistics.take_notices() {
        diagnostic(&notice);
    }
    None
}

/// Bridge a statistics renderer that writes `fmt::Write` to a byte sink.
struct FmtWriter<'a, W: io::Write> {
    writer: &'a mut W,
    error: Option<io::Error>,
}

impl<W: io::Write> std::fmt::Write for FmtWriter<'_, W> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        if self.error.is_some() {
            return Err(std::fmt::Error);
        }
        self.writer.write_all(text.as_bytes()).map_err(|error| {
            self.error = Some(error);
            std::fmt::Error
        })
    }
}

/// Why `output_frame` stopped: a capture writer failure or a dissected-output
/// failure. The first must drop the writer (finishing would repeat the error),
/// while the second still finalizes a valid capture file.
enum FrameError {
    Writer(i32),
    Output(i32),
}

/// Whether a frame matched the display filter.
struct FrameOutcome {
    matched: bool,
}

/// Poll a live capture until a limit or signal stops it, writing and
/// displaying each frame through the shared [`output_frame`] path.
fn drive_live<S: PacketSink>(
    options: &CaptureOptions<'_>,
    live_options: &LiveOptions,
    mut sink: S,
) -> i32 {
    let mut live = match LiveSession::open(live_options) {
        Ok(live) => live,
        Err(failure) => {
            diagnostic(&failure.message);
            return failure.status;
        }
    };
    if !live_options.suppress_messages {
        notice(&live::capturing_message(live.devices()));
        for warning in live.warnings() {
            diagnostic(&warning.to_string());
        }
    }
    let mut writer_session = match WriterSession::new_live(options.write, live.interfaces()) {
        Ok(session) => session,
        Err(failure) => {
            diagnostic(&failure.message);
            if !live_options.suppress_messages {
                notice(&live::stats_message(live.devices(), &[], 0));
            }
            return failure.status;
        }
    };
    let mut session = DecodeSession::with_pass(
        options.decode_options.clone(),
        options.state_budget,
        PassMode::One,
    );
    attach_object_export(&mut session, options.exports);
    let mut tls_keys = attach_tls_session(&mut session, options.tls);
    let mut statistics = StatsSet::new(options.stats);
    statistics.set_http_desegment(options.decode_options.preferences.tcp_desegment_tcp_streams);
    let mut writer = BufWriter::with_capacity(WRITE_BUFFER_SIZE, io::stdout().lock());
    if let Err(error) = sink.start(&mut writer) {
        let _ = finish_writer(&mut writer_session);
        return output_failure(&error);
    }

    let mut captured = 0_u64;
    let mut selected = 0_u64;
    loop {
        if live.stop_requested()
            || options
                .write
                .autostop
                .duration
                .is_some_and(|limit| live.elapsed() >= limit)
            || options.packet_count.is_some_and(|limit| captured >= limit)
            || options
                .write
                .autostop
                .packets
                .is_some_and(|limit| selected >= limit)
            || writer_session
                .as_ref()
                .is_some_and(WriterSession::should_stop)
            || writer_session.as_ref().is_some_and(|session| {
                options
                    .write
                    .autostop
                    .filesize
                    .is_some_and(|kib| session.logical_bytes() >= kib.saturating_mul(1024))
            })
        {
            break;
        }
        let frame = match live.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                if let Some(session) = &mut writer_session
                    && let Err(failure) = session.tick()
                {
                    diagnostic(&failure.message);
                    // The writer already reported its error; finishing it
                    // would only repeat the same diagnostic.
                    drop(writer_session.take());
                    return failure.status;
                }
                continue;
            }
            Err(error) => {
                diagnostic(&error.to_string());
                let _ = finish_writer(&mut writer_session);
                return 1;
            }
        };
        captured = captured.saturating_add(1);
        match output_frame(
            &frame,
            &mut session,
            &mut statistics,
            options,
            &mut writer_session,
            &mut sink,
            &mut writer,
            frame.number,
            None,
        ) {
            Ok(outcome) => {
                if outcome.matched {
                    selected = selected.saturating_add(1);
                }
            }
            Err(FrameError::Writer(status)) => {
                drop(writer_session.take());
                return status;
            }
            Err(FrameError::Output(status)) => {
                if let Err(write_status) = finish_writer(&mut writer_session) {
                    return write_status;
                }
                return status;
            }
        }
        let keys = session.take_export_keys();
        if let Some(file) = tls_keys.as_mut() {
            write_exported_keys(file, keys);
        }
        if let Some(session) = &mut writer_session
            && let Err(failure) = session.tick()
        {
            diagnostic(&failure.message);
            drop(writer_session.take());
            return failure.status;
        }
    }

    if let Err(status) = finish_writer(&mut writer_session) {
        return status;
    }
    if let Err(error) = sink.finish(&mut writer) {
        return output_failure(&error);
    }
    if let Some(status) = render_statistics(&mut statistics, options.stats, &mut writer) {
        return status;
    }
    let _ = writer.flush();

    if !live_options.suppress_messages {
        let stats = match live.stats() {
            Ok(stats) => stats,
            Err(error) => {
                diagnostic(&error.to_string());
                Vec::new()
            }
        };
        notice(&live::stats_message(live.devices(), &stats, captured));
    }
    0
}

/// Print the numbered interface list for `-D`.
fn run_list_devices() -> i32 {
    match live::list_devices() {
        Ok(text) => {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
            0
        }
        Err(failure) => {
            diagnostic(&failure.message);
            failure.status
        }
    }
}

/// Print the requested interface capability reports for `-L` and
/// `--list-time-stamp-types`.
fn run_list_capture_modes(options: &LiveOptions, modes: ListModes) -> i32 {
    match live::list_capabilities(options, modes) {
        Ok(text) => {
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
            0
        }
        Err(failure) => {
            diagnostic(&failure.message);
            failure.status
        }
    }
}

/// Whether `-w` targets standard output.
fn write_targets_stdout(write: &WriteOptions) -> bool {
    write.file.as_deref() == Some(Path::new("-"))
}

/// Finish the writer and return its failure status, if any.
fn finish_writer(writer_session: &mut Option<WriterSession>) -> Result<(), i32> {
    let Some(session) = writer_session else {
        return Ok(());
    };
    match session.finish() {
        Ok(()) => Ok(()),
        Err(failure) => {
            diagnostic(&failure.message);
            Err(failure.status)
        }
    }
}

/// Load the TLS key log and open the session-key export file.
fn attach_tls_session(session: &mut DecodeSession, tls: &TlsOptions) -> Option<File> {
    let mut keylog = KeyLog::new();
    if let Some(path) = tls.keylog_file.as_ref()
        && let Ok(file) = File::open(path)
    {
        keylog = KeyLog::read(BufReader::new(file));
        if keylog.truncated() {
            diagnostic("TLS key log reached its size or entry limit; remaining lines ignored");
        }
    }
    session.set_keylog(keylog);
    session.set_tls_key_export(tls.export_session_keys.is_some());
    tls.export_session_keys
        .as_deref()
        .and_then(open_tls_key_file)
}

/// Create every export destination and attach the HTTP object sink.
///
/// The destination is created after the capture opens and before the
/// first frame, and a directory failure does not change the exit status.
fn attach_object_export(session: &mut DecodeSession, exports: &[ExportObjects]) {
    for export in exports {
        let writer = export::ObjectWriter::setup(&export.directory);
        if export.protocol == ExportProtocol::Http {
            session.set_object_sink(Box::new(writer));
        }
    }
}

/// `-T fields` output.
struct FieldsSink {
    selection: FieldSelection,
    protocols: ProtocolSelection,
    formatter: fields::Formatter,
}

impl PacketSink for FieldsSink {
    fn start(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.write_prefix(writer)
    }

    fn packet(
        &mut self,
        writer: &mut impl Write,
        _frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        if !matched {
            return Ok(false);
        }
        packet.tree.prune_keeping(&self.selection, &self.protocols);
        self.formatter.write_packet(writer, &packet.tree)?;
        Ok(true)
    }
}

/// Read the capture, decode each frame, print the requested fields and return
/// the exit status.
fn run_fields(options: &FieldsOptions) -> i32 {
    let filter = options.display_filter.as_ref();
    let (filter_fields, filter_protocols) =
        filter.map(|filter| filter.references()).unwrap_or_default();
    let mut selected_fields: Vec<&'static FieldDef> = options.fields.clone();
    selected_fields.extend(filter_fields);
    let sink = FieldsSink {
        selection: FieldSelection::new(&selected_fields),
        protocols: ProtocolSelection::new(&filter_protocols),
        formatter: fields::Formatter::new(&options.fields, options.output),
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// `-T json` and `-T jsonraw` output.
struct JsonSink<'a> {
    selection: Option<(FieldSelection, ProtocolSelection)>,
    formatter: JsonWriter<'a>,
}

impl PacketSink for JsonSink<'_> {
    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        if !matched {
            self.formatter.observe_hidden(frame);
            return Ok(false);
        }
        if let Some((selection, protocols)) = &self.selection {
            packet.tree.prune_keeping(selection, protocols);
        }
        self.formatter.write_packet(writer, frame, packet)?;
        Ok(true)
    }

    fn finish(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.finish(writer)
    }
}

/// Read the capture, decode each frame and print JSON packets.
fn run_json(options: &JsonOptions) -> i32 {
    let filter = options.display_filter.as_ref();
    let selection = if options.fields.is_empty() {
        None
    } else {
        let (filter_fields, filter_protocols) =
            filter.map(|filter| filter.references()).unwrap_or_default();
        let mut selected_fields: Vec<&'static FieldDef> = options.fields.clone();
        selected_fields.extend(filter_fields);
        Some((
            FieldSelection::new(&selected_fields),
            ProtocolSelection::new(&filter_protocols),
        ))
    };
    let sink = JsonSink {
        selection,
        formatter: JsonWriter::new(
            options.mode,
            options.protocol_filter.as_ref(),
            options.merge_keys,
            &options.fields,
            options.print_hex,
        ),
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// `-T pdml` output.
struct PdmlSink<'a> {
    capture_file: &'a Path,
    formatter: PdmlWriter<'a>,
}

impl PacketSink for PdmlSink<'_> {
    fn start(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.write_header(writer, self.capture_file)
    }

    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        if !matched {
            self.formatter.observe_hidden(frame);
            return Ok(false);
        }
        self.formatter.write_packet(writer, frame, packet)?;
        Ok(true)
    }

    fn finish(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.finish(writer)
    }
}

/// Read the capture, decode each frame and print PDML packets.
fn run_pdml(options: &PdmlOptions) -> i32 {
    let sink = PdmlSink {
        capture_file: options.input.capture_path(),
        formatter: PdmlWriter::new(options.protocol_filter.as_ref(), &options.fields)
            .with_color(options.color),
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// `-T psml` output.
struct PsmlSink {
    formatter: PsmlWriter,
}

impl PacketSink for PsmlSink {
    fn start(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.write_header(writer)
    }

    fn reset(&mut self) {
        self.formatter.reset_session();
    }

    fn observe_skipped(&mut self, frame: &Frame) {
        self.formatter.observe_capture_time(frame);
    }

    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        if !matched {
            self.formatter.observe_hidden(frame, packet);
            return Ok(false);
        }
        self.formatter.write_packet(writer, frame, packet)?;
        Ok(true)
    }

    fn finish(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.finish(writer)
    }
}

/// Read the capture, decode each frame and print PSML packets.
fn run_psml(options: &PsmlOptions) -> i32 {
    let sink = PsmlSink {
        formatter: PsmlWriter::new(options.time).with_color(options.color),
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// `-T ek` output.
struct EkSink<'a> {
    formatter: EkWriter<'a>,
}

impl PacketSink for EkSink<'_> {
    fn reset(&mut self) {
        self.formatter.reset_session();
    }

    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        if !matched {
            self.formatter.observe_hidden(frame, packet);
            return Ok(false);
        }
        self.formatter.write_packet(writer, frame, packet)?;
        Ok(true)
    }
}

/// Read the capture, decode each frame and print EK bulk documents.
fn run_ek(options: &EkOptions) -> i32 {
    let sink = EkSink {
        formatter: EkWriter::new(
            options.protocol_filter.as_ref(),
            &options.fields,
            options.print_hex,
            options.print_summary,
            options.time,
        ),
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// `-T ps` output.
struct PsSink<'a> {
    capture_file: &'a Path,
    formatter: PsWriter,
}

impl PacketSink for PsSink<'_> {
    fn start(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.write_header(writer, self.capture_file)
    }

    fn reset(&mut self) {
        self.formatter.reset_session();
    }

    fn observe_skipped(&mut self, frame: &Frame) {
        self.formatter.observe_capture_time(frame);
    }

    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        if !matched {
            self.formatter.observe_hidden(frame, packet);
            return Ok(false);
        }
        self.formatter.write_packet(writer, frame, packet)?;
        Ok(true)
    }

    fn finish(&mut self, writer: &mut impl Write) -> io::Result<()> {
        self.formatter.finish(writer)
    }
}

/// Read the capture, decode each frame and print PostScript pages.
fn run_ps(options: &PsOptions) -> i32 {
    let sink = PsSink {
        capture_file: options.input.capture_path(),
        formatter: PsWriter::new(options.time, options.detail.clone(), options.hexdump),
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// Summary-line, detail and hexdump output.
struct SummarySink {
    has_filter: bool,
    summary: Option<summary::SummaryWriter>,
    detail: Option<DetailWriter>,
    hexdump: Option<HexdumpWriter>,
    blocks: bool,
    print: bool,
    print_summary: bool,
}

impl PacketSink for SummarySink {
    fn reset(&mut self) {
        if let Some(summary) = &mut self.summary {
            summary.reset_session();
        }
    }

    fn observe_skipped(&mut self, frame: &Frame) {
        if let Some(summary) = &mut self.summary {
            summary.observe_capture_time(frame);
        }
    }

    fn packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &mut Packet,
        matched: bool,
    ) -> io::Result<bool> {
        let displayed = matched && (self.blocks || self.print || self.print_summary);
        if self.blocks {
            if matched {
                if let Some(summary) = &mut self.summary {
                    summary.write_packet(writer, frame, packet, true, false)?;
                }
                if self.summary.is_some() && self.hexdump.is_some() && self.detail.is_none() {
                    writer.write_all(b"\n")?;
                }
                if let Some(detail) = &mut self.detail {
                    detail.write_packet(writer, frame, packet)?;
                }
                if let Some(hexdump) = &mut self.hexdump {
                    hexdump.write_packet(writer, frame, packet)?;
                }
            } else {
                if let Some(detail) = &mut self.detail {
                    detail.observe_hidden(frame);
                }
                if let Some(hexdump) = &mut self.hexdump {
                    hexdump.observe_hidden(frame);
                }
                if let Some(summary) = &mut self.summary {
                    summary.write_packet(writer, frame, packet, false, true)?;
                }
            }
        } else if let Some(summary) = &mut self.summary {
            let summary_displayed = matched && (self.print || self.print_summary);
            let observe_hidden = self.has_filter && !summary_displayed;
            summary.write_packet(writer, frame, packet, summary_displayed, observe_hidden)?;
        }
        Ok(displayed)
    }
}

/// Read the capture, decode each frame and print the default summary.
fn run_summary(options: &SummaryOptions) -> i32 {
    let filter = options.display_filter.as_ref();
    let blocks = options.detail.is_some() || options.hexdump.is_some();
    let use_color =
        options.color && (options.force_terminal_color || std::io::stdout().is_terminal());
    let summary = if blocks {
        options.print_summary.then(|| {
            summary::SummaryWriter::new(options.time)
                .with_style(options.style)
                .with_color(use_color)
        })
    } else {
        Some(
            summary::SummaryWriter::new(options.time)
                .with_style(options.style)
                .with_color(use_color),
        )
    };
    let hexdump_active = options.hexdump.is_some();
    let detail_separator: &[u8] = if hexdump_active {
        &[]
    } else {
        &options.separator
    };
    let sink = SummarySink {
        has_filter: filter.is_some(),
        summary,
        detail: options
            .detail
            .as_ref()
            .map(|detail| DetailWriter::new(detail, detail_separator, hexdump_active)),
        hexdump: options
            .hexdump
            .map(|hexdump| HexdumpWriter::new(hexdump, options.time, &options.separator)),
        blocks,
        print: options.print,
        print_summary: options.print_summary,
    };
    drive(
        &CaptureOptions {
            input: &options.input,
            packet_count: options.packet_count,
            flush: options.flush,
            decode_options: options.decode_options.clone(),
            state_budget: options.state_budget,
            write: &options.write,
            stats: &options.stats,
            display_filter: options.display_filter.as_ref(),
            exports: &options.exports,
            tls: &options.tls,
        },
        sink,
    )
}

/// Print a `-G` glossary report and return the exit status.
fn run_report(report: Report) -> i32 {
    let mut writer = BufWriter::new(io::stdout().lock());
    let result = match report {
        Report::Fields => reports::write_fields(&mut writer),
        Report::Protocols => reports::write_protocols(&mut writer),
        Report::HeuristicDecodes => reports::write_heuristic_decodes(&mut writer),
        Report::Help => reports::write_help(&mut writer),
    };
    // Write errors from glossary reports are ignored: a broken pipe and
    // EFBIG both exit 0.
    let _ = result.and_then(|()| writer.flush());
    0
}

/// Map a capture-reader error to its exit status.
fn capture_exit_code(error: &CaptureError) -> i32 {
    match error {
        CaptureError::Truncated | CaptureError::FrameTooLarge => 14,
        CaptureError::Io(_)
        | CaptureError::Unrecognized
        | CaptureError::Malformed(_)
        | CaptureError::LimitExceeded(_)
        | CaptureError::Compressed(_) => 3,
    }
}

/// Open `--export-tls-session-keys` output, truncating an existing file.
fn open_tls_key_file(path: &Path) -> Option<File> {
    #[cfg(unix)]
    let symlink =
        std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink());
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            #[cfg(unix)]
            if !symlink {
                use std::os::unix::fs::PermissionsExt as _;
                // Tighten a pre-existing regular file through its descriptor;
                // never chmod a symlink target by path.
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            Some(file)
        }
        Err(error) => {
            diagnostic(&format!(
                "cannot open TLS session key file \"{}\": {error}",
                path.display()
            ));
            None
        }
    }
}

/// Write key-log lines (`LABEL client_random secret`) without keeping a
/// secret copy.
fn write_exported_keys(file: &mut File, keys: Vec<ExportedKey>) {
    let mut buffer = [0_u8; 256];
    for key in keys {
        let length = export_line(&key, &mut buffer);
        if length == 0 {
            continue;
        }
        if let Err(error) = file.write_all(buffer.get(..length).unwrap_or(&[])) {
            diagnostic(&format!("cannot write TLS session keys: {error}"));
            buffer.zeroize();
            return;
        }
        buffer.zeroize();
    }
}

fn export_line(key: &ExportedKey, buffer: &mut [u8; 256]) -> usize {
    let mut length = 0_usize;
    let label = key.label.as_bytes();
    let Some(label_end) = length.checked_add(label.len()) else {
        return 0;
    };
    if label_end.saturating_add(1) > buffer.len() {
        return 0;
    }
    let Some(slot) = buffer.get_mut(length..label_end) else {
        return 0;
    };
    slot.copy_from_slice(label);
    length = label_end;
    let Some(slot) = buffer.get_mut(length) else {
        return 0;
    };
    *slot = b' ';
    length = length.saturating_add(1);
    for byte in key.client_random {
        let Some(pair) = hex_pair(byte) else {
            return 0;
        };
        let Some(end) = length.checked_add(2) else {
            return 0;
        };
        let Some(slot) = buffer.get_mut(length..end) else {
            return 0;
        };
        slot.copy_from_slice(&pair);
        length = end;
    }
    let Some(slot) = buffer.get_mut(length) else {
        return 0;
    };
    *slot = b' ';
    length = length.saturating_add(1);
    for byte in key.secret_bytes() {
        let Some(pair) = hex_pair(*byte) else {
            return 0;
        };
        let Some(end) = length.checked_add(2) else {
            return 0;
        };
        let Some(slot) = buffer.get_mut(length..end) else {
            return 0;
        };
        slot.copy_from_slice(&pair);
        length = end;
    }
    if length >= buffer.len() {
        return 0;
    }
    let Some(slot) = buffer.get_mut(length) else {
        return 0;
    };
    *slot = b'\n';
    length.saturating_add(1)
}

fn hex_pair(byte: u8) -> Option<[u8; 2]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let high = HEX.get(usize::from(byte >> 4)).copied()?;
    let low = HEX.get(usize::from(byte & 0x0f)).copied()?;
    Some([high, low])
}

/// Report a stdout failure and return its exit status.
///
/// Every packet-output write error exits 16; a broken pipe is silent.
fn output_failure(error: &io::Error) -> i32 {
    if error.kind() != ErrorKind::BrokenPipe {
        diagnostic(&format!("cannot write output: {error}"));
    }
    16
}

/// Write capture notices (start, drops, counts) without Packetfin's error
/// prefix, escaping control characters from device-supplied text.
fn notice(text: &str) {
    let mut stderr = io::stderr().lock();
    for line in text.lines() {
        let _ = writeln!(stderr, "{}", escape_controls(line));
    }
}

/// Write one diagnostic line to standard error.
///
/// A closed or full standard error must not become a panic: the process still
/// exits with the code for the condition.
fn diagnostic(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "packetfin: {}", escape_controls(message));
}

/// Render control characters as escapes so an untrusted path or option value
/// cannot drive the terminal or forge lines in a log.
fn escape_controls(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control.is_control() => {
                escaped.push_str(&format!("\\u{{{:x}}}", u32::from(control)));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Report an unparsable `-Y` expression with a caret underline.
///
/// The byte position and underline mark the failing part of the filter. A
/// filter containing control characters is not echoed, so an untrusted
/// argument cannot drive the terminal.
fn report_filter_error(filter: &str, error: &FilterError) {
    if filter.chars().any(char::is_control) {
        diagnostic(&format!("{} (at byte {})", error.message(), error.offset()));
        return;
    }
    diagnostic(error.message());
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "    {filter}");
    if let Some(length) = error.length() {
        let _ = writeln!(
            stderr,
            "    {}{}",
            " ".repeat(error.offset()),
            "^".repeat(length)
        );
    }
}

/// Whether standard input is a character device, block device or socket.
///
/// Packetfin refuses `-r -` for those; Rust's standard library has no safe
/// `fstat`, so the platform's standard-input link is inspected instead. If
/// that link is unavailable the read proceeds as before.
#[cfg(unix)]
fn stdin_is_special() -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata("/dev/stdin").is_ok_and(|metadata| {
        let kind = metadata.file_type();
        kind.is_char_device() || kind.is_block_device() || kind.is_socket()
    })
}

#[cfg(not(unix))]
fn stdin_is_special() -> bool {
    false
}
