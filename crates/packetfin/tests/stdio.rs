//! End-to-end tests for standard-stream failures and capture-size limits.
//!
//! The child's standard streams are injected with a pipe whose read end is
//! already closed (EPIPE) and, on Unix, with a file-size limit that fails
//! regular-file writes with EFBIG. Packetfin keeps its documented exit status
//! when a diagnostic cannot be written, exits 16 for packet-output write
//! failures and ignores glossary-report write failures.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

use packetfin_testkit::pcap;
use packetfin_testkit::{ByteOrder, Timestamp, TimestampResolution};

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

/// Serializes tests that spawn children. A child forked while another test
/// holds a broken-pipe descriptor inherits the read end, which keeps the
/// writer alive past the point where the test expects EPIPE.
static PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn process_guard() -> MutexGuard<'static, ()> {
    PROCESS_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// libpcap's maximum snapshot length. Packetfin reads frames at and above
/// it, up to its own larger frame limit.
const PCAP_SNAPLEN_LIMIT: usize = 262_144;

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn finish(command: &mut Command, stdin: Stdio, stdout: Stdio, stderr: Stdio) -> Run {
    let output = match command.stdin(stdin).stdout(stdout).stderr(stderr).output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        }
    };
    Run {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn run(args: &[&str], stdin: Stdio, stdout: Stdio, stderr: Stdio) -> Run {
    let mut command = Command::new(BIN);
    command.args(args);
    finish(&mut command, stdin, stdout, stderr)
}

/// A pipe whose read end is gone: the next write fails with EPIPE.
fn broken_pipe() -> Stdio {
    match std::io::pipe() {
        Ok((reader, writer)) => {
            drop(reader);
            Stdio::from(writer)
        }
        Err(error) => {
            eprintln!("failed to create a pipe: {error}");
            std::process::exit(1);
        }
    }
}

fn scratch(label: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "packetfin-stdio-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    path
}

fn fixture(name: &str) -> PathBuf {
    packetfin_testkit::golden::fixtures_dir().join(name)
}

fn fixture_text(name: &str) -> String {
    fixture(name).to_string_lossy().into_owned()
}

/// Run under `RLIMIT_FSIZE=0` with `SIGXFSZ` ignored so a write to a regular
/// file returns EFBIG instead of killing the process.
#[cfg(unix)]
fn run_with_file_size_limit(args: &[&str], stdout: Stdio, stderr: Stdio) -> Run {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("trap '' XFSZ; ulimit -f 0; exec \"$0\" \"$@\"")
        .arg(BIN)
        .args(args);
    finish(&mut command, Stdio::null(), stdout, stderr)
}

fn status_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

#[test]
fn broken_stderr_keeps_usage_exit_status() {
    let _guard = process_guard();
    let run = run(
        &["--nonsense"],
        Stdio::null(),
        Stdio::piped(),
        broken_pipe(),
    );
    assert_eq!(
        status_code(run.status),
        Some(1),
        "exit status: {}",
        run.status
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
}

#[test]
fn broken_stderr_keeps_missing_capture_exit_status() {
    let _guard = process_guard();
    let missing = scratch("missing.pcap");
    let run = run(
        &[
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-r",
            &missing.to_string_lossy(),
        ],
        Stdio::null(),
        Stdio::piped(),
        broken_pipe(),
    );
    assert_eq!(
        status_code(run.status),
        Some(3),
        "exit status: {}",
        run.status
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
}

#[test]
fn broken_stderr_keeps_truncated_capture_exit_status() {
    let _guard = process_guard();
    let path = fixture_text("truncated.pcap");
    let run = run(
        &["-T", "fields", "-e", "frame.number", "-r", &path],
        Stdio::null(),
        Stdio::piped(),
        broken_pipe(),
    );
    assert_eq!(
        status_code(run.status),
        Some(14),
        "exit status: {}",
        run.status
    );
}

#[cfg(unix)]
#[test]
fn full_stderr_keeps_usage_exit_status() {
    let _guard = process_guard();
    let path = scratch("stderr-efbig.log");
    let sink = match File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to create {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    let run = run_with_file_size_limit(&["--nonsense"], Stdio::piped(), Stdio::from(sink));
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status_code(run.status),
        Some(1),
        "exit status: {}",
        run.status
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
}

#[cfg(unix)]
#[test]
fn full_stdout_ignores_the_final_buffered_flush() {
    let _guard = process_guard();
    let path = scratch("stdout-efbig-fields");
    let sink = match File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to create {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    let capture = fixture_text("ethernet-udp-le-us.pcap");
    let run = run_with_file_size_limit(
        &["-T", "fields", "-e", "frame.number", "-r", &capture],
        Stdio::from(sink),
        Stdio::piped(),
    );
    let size = std::fs::metadata(&path).map_or(0, |metadata| metadata.len());
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(size, 0, "the limited output file stays empty");
}

#[cfg(unix)]
#[test]
fn full_stdout_with_packet_flush_exits_sixteen() {
    let _guard = process_guard();
    let path = scratch("stdout-efbig-flush");
    let sink = match File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to create {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    let capture = fixture_text("field-output.pcapng");
    let run = run_with_file_size_limit(
        &["-T", "fields", "-l", "-e", "frame.number", "-r", &capture],
        Stdio::from(sink),
        Stdio::piped(),
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status_code(run.status),
        Some(16),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn broken_stdout_ignores_the_final_buffered_flush() {
    let _guard = process_guard();
    let capture = fixture_text("ethernet-udp-le-us.pcap");
    let run = run(
        &["-T", "fields", "-e", "frame.number", "-r", &capture],
        Stdio::null(),
        broken_pipe(),
        Stdio::piped(),
    );
    assert_eq!(
        status_code(run.status),
        Some(0),
        "exit status: {}",
        run.status
    );
    assert!(run.stderr.is_empty(), "stderr: {:?}", run.stderr);
}

#[test]
fn broken_stdout_with_packet_flush_exits_sixteen() {
    let _guard = process_guard();
    let capture = fixture_text("field-output.pcapng");
    let run = run(
        &["-T", "fields", "-l", "-e", "frame.number", "-r", &capture],
        Stdio::null(),
        broken_pipe(),
        Stdio::piped(),
    );
    assert_eq!(
        status_code(run.status),
        Some(16),
        "exit status: {}",
        run.status
    );
    assert!(run.stderr.is_empty(), "stderr: {:?}", run.stderr);
}

#[test]
fn zero_packet_prefix_failure_keeps_the_capture_status() {
    let _guard = process_guard();
    let empty = fixture_text("empty.bin");
    for option in ["header=y", "bom=y"] {
        let run = run(
            &[
                "-T",
                "fields",
                "-E",
                option,
                "-e",
                "frame.number",
                "-r",
                &empty,
            ],
            Stdio::null(),
            broken_pipe(),
            Stdio::piped(),
        );
        assert_eq!(
            status_code(run.status),
            Some(0),
            "{option} exit status: {}",
            run.status
        );
        assert!(run.stderr.is_empty(), "stderr: {:?}", run.stderr);
    }

    let truncated = fixture_text("truncated.pcap");
    let run = run(
        &[
            "-T",
            "fields",
            "-E",
            "header=y",
            "-e",
            "frame.number",
            "-r",
            &truncated,
        ],
        Stdio::null(),
        broken_pipe(),
        Stdio::piped(),
    );
    assert_eq!(
        status_code(run.status),
        Some(14),
        "exit status: {}",
        run.status
    );
}

#[test]
fn broken_stdout_is_ignored_for_glossary_reports() {
    let _guard = process_guard();
    let run = run(
        &["-G", "fields"],
        Stdio::null(),
        broken_pipe(),
        Stdio::piped(),
    );
    assert_eq!(
        status_code(run.status),
        Some(0),
        "exit status: {}",
        run.status
    );
    assert!(run.stderr.is_empty(), "stderr: {:?}", run.stderr);
}

#[cfg(unix)]
#[test]
fn full_stdout_is_ignored_for_glossary_reports() {
    let _guard = process_guard();
    let path = scratch("stdout-efbig-report");
    let sink = match File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to create {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    let run = run_with_file_size_limit(&["-G", "fields"], Stdio::from(sink), Stdio::piped());
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stderr.is_empty(), "stderr: {:?}", run.stderr);
}

fn write_capture(label: &str, declared_length: usize, data_length: usize) -> PathBuf {
    let Ok(captured_len) = u32::try_from(declared_length) else {
        eprintln!("test capture declares {declared_length} bytes beyond the pcap field");
        std::process::exit(1);
    };
    let mut file = pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond);
    if let Err(error) = file.push_packet(pcap::Packet {
        timestamp: Timestamp::new(1_700_000_000, 0),
        captured_len,
        original_len: captured_len,
        data: vec![0; data_length],
    }) {
        eprintln!("failed to add the test packet: {error}");
        std::process::exit(1);
    }
    let bytes = match file.to_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to serialize the test capture: {error}");
            std::process::exit(1);
        }
    };
    let path = scratch(label);
    if let Err(error) = std::fs::write(&path, bytes) {
        eprintln!("failed to write {}: {error}", path.display());
        std::process::exit(1);
    }
    path
}

fn frame_number_output(path: &Path, label: &str) -> Run {
    let path_text = path.to_string_lossy();
    let run = run(
        &["-T", "fields", "-e", "frame.number", "-r", &path_text],
        Stdio::null(),
        Stdio::piped(),
        Stdio::piped(),
    );
    let _ = std::fs::remove_file(path);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "{label} stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    run
}

#[test]
fn frame_at_snaplen_limit_is_accepted() {
    let _guard = process_guard();
    let path = write_capture(
        "frame-at-snaplen-limit.pcap",
        PCAP_SNAPLEN_LIMIT,
        PCAP_SNAPLEN_LIMIT,
    );
    let run = frame_number_output(&path, "frame at the snaplen limit");
    assert_eq!(run.stdout, b"1\n".to_vec());
}

#[test]
fn frame_above_snaplen_limit_is_accepted() {
    let _guard = process_guard();
    // Packetfin keeps its larger bounded frame ceiling.
    let path = write_capture(
        "frame-above-snaplen-limit.pcap",
        PCAP_SNAPLEN_LIMIT + 1,
        PCAP_SNAPLEN_LIMIT + 1,
    );
    let run = frame_number_output(&path, "frame above the snaplen limit");
    assert_eq!(run.stdout, b"1\n".to_vec());
}

#[test]
fn frame_at_reader_limit_is_accepted() {
    let _guard = process_guard();
    let limit = packetfin_core::MAX_FRAME_SIZE;
    let path = write_capture("frame-at-reader-limit.pcap", limit, limit);
    let run = frame_number_output(&path, "frame at the Packetfin limit");
    assert_eq!(run.stdout, b"1\n".to_vec());
}

#[test]
fn frame_above_reader_limit_exits_fourteen() {
    let _guard = process_guard();
    let path = write_capture(
        "frame-above-reader-limit.pcap",
        packetfin_core::MAX_FRAME_SIZE + 1,
        0,
    );
    let path_text = path.to_string_lossy();
    let run = run(
        &["-T", "fields", "-e", "frame.number", "-r", &path_text],
        Stdio::null(),
        Stdio::piped(),
        Stdio::piped(),
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status_code(run.status),
        Some(14),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("exceeds the supported limit"),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[cfg(unix)]
#[test]
fn special_standard_input_exits_three() {
    let _guard = process_guard();
    let run = run(
        &["-T", "fields", "-e", "frame.number", "-r", "-"],
        Stdio::null(),
        Stdio::piped(),
        Stdio::piped(),
    );
    assert_eq!(
        status_code(run.status),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        !run.stderr.is_empty(),
        "stderr must explain the rejected standard input"
    );
}

#[test]
fn empty_pipe_standard_input_exits_zero() {
    let _guard = process_guard();
    let mut child = match Command::new(BIN)
        .args(["-T", "fields", "-e", "frame.number", "-r", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        }
    };
    drop(child.stdin.take());
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to wait for packetfin: {error}");
            std::process::exit(1);
        }
    };
    assert_eq!(
        status_code(output.status),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "stdout: {:?}", output.stdout);
}

#[test]
fn empty_regular_standard_input_exits_zero() {
    let _guard = process_guard();
    let path = scratch("empty-stdin.pcap");
    let mut file = match File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to create {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    if let Err(error) = file.flush() {
        eprintln!("failed to flush {}: {error}", path.display());
        std::process::exit(1);
    }
    let input = match File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to open {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    let run = run(
        &["-T", "fields", "-e", "frame.number", "-r", "-"],
        Stdio::from(input),
        Stdio::piped(),
        Stdio::piped(),
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
}
