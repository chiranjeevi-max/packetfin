//! Capture-writing goldens and command-line validation.
//!
//! Every `rewrite-*` fixture case runs the built binary from the repository
//! root, compares standard output and the exit status with the golden output,
//! and compares the produced capture after decompression and the
//! documented normalisation of the SHB identity and name-resolution bodies.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::fixtures::{self, GoldenCase};
use packetfin_testkit::golden;
use packetfin_testkit::{ByteOrder, Timestamp, TimestampResolution, pcap, pcapng};

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn invoke(args: &[&str]) -> Run {
    let output = match Command::new(BIN)
        .args(args)
        .current_dir(golden::repo_root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
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

/// Extract a value or stop the test with its diagnostic.
fn must<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{what}: {error}");
            std::process::exit(1);
        }
    }
}

/// Extract an optional value or stop the test with its diagnostic.
fn must_some<T>(value: Option<T>, what: &str) -> T {
    match value {
        Some(value) => value,
        None => {
            eprintln!("{what}: value is absent");
            std::process::exit(1);
        }
    }
}

fn scratch(label: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "packetfin-write-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    path
}

fn run_case(case: &GoldenCase) -> Run {
    let arguments: Vec<&str> = case.args.iter().map(String::as_str).collect();
    invoke(&arguments)
}

fn write_fixtures() -> Vec<&'static fixtures::Fixture> {
    fixtures::all()
        .iter()
        .filter(|fixture| fixture.name.starts_with("rewrite-"))
        .collect()
}

#[test]
fn write_goldens_match_stored_runs() -> Result<(), String> {
    let mut failures = Vec::new();
    let mut cases = 0;
    for fixture in write_fixtures() {
        for case in fixture.cases() {
            let directory = scratch(&format!("{}-{}", fixture.name, case.id));
            let output = directory.join("output.capture");
            let scratch_output = directory.join("scratch.capture");
            let resolved = fixture
                .cases_with_paths(&output, &scratch_output)
                .into_iter()
                .find(|resolved| resolved.id == case.id)
                .ok_or_else(|| format!("{}: lost case {}", fixture.name, case.id))?;
            fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
            let run = run_case(&resolved);
            cases += 1;
            let status = run.status.code().unwrap_or(-1);
            let normalized = golden::normalize_volatile(case.id, &run.stdout);
            if let Err(error) =
                golden::compare_golden_stdout_status(fixture.name, case.id, &normalized, status)
            {
                failures.push(format!(
                    "{error}; stderr: {}",
                    String::from_utf8_lossy(&run.stderr)
                ));
            }
            if let Some(expected) = &case.capture {
                let produced = directory.join(
                    expected
                        .file_name()
                        .ok_or_else(|| "capture path has no file name".to_string())?,
                );
                let expected_bytes = match fs::read(
                    golden::golden_dir()
                        .join(fixture.name)
                        .join(format!("{}.file", case.id)),
                ) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        failures.push(format!(
                            "golden {}/{}: cannot read capture golden: {error}",
                            fixture.name, case.id
                        ));
                        let _ = fs::remove_dir_all(&directory);
                        continue;
                    }
                };
                match fs::read(&produced) {
                    Ok(bytes) => {
                        let normalized = golden::normalize_capture(&bytes);
                        if normalized != expected_bytes {
                            failures.push(format!(
                                "golden {}/{}: capture differs (stored {} bytes, observed {} bytes)",
                                fixture.name,
                                case.id,
                                expected_bytes.len(),
                                normalized.len()
                            ));
                        }
                    }
                    Err(error) => failures.push(format!(
                        "golden {}/{}: cannot read produced capture {}: {error}",
                        fixture.name,
                        case.id,
                        produced.display()
                    )),
                }
            }
            let _ = fs::remove_dir_all(&directory);
        }
    }
    assert!(cases > 40, "only {cases} write cases ran");
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn fixture(name: &str) -> String {
    golden::fixtures_dir()
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn writer_path_failures_exit_nine_without_a_file() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&["-n", "-r", &capture, "-w", "/nonexistent/packetfin-write"]);
    assert_eq!(
        run.status.code(),
        Some(9),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let run = invoke(&["-n", "-r", &capture, "-w", "/tmp"]);
    assert_eq!(run.status.code(), Some(9));
}

#[test]
fn unknown_compression_mode_exits_zero_without_a_file() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("compress-unknown");
    must(fs::create_dir_all(&directory), "scratch directory");
    let output = directory.join("out.pcapng");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "--compress",
        "nope",
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert!(
        !output.exists(),
        "unknown compression must not create a file"
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn zstd_compression_and_extension_exit_one() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&["-n", "-r", &capture, "--compress", "zstd", "-w", "/tmp/x"]);
    assert_eq!(run.status.code(), Some(1));
    let run = invoke(&["-n", "-r", &capture, "-w", "/tmp/x.zst"]);
    assert_eq!(run.status.code(), Some(1));
}

#[test]
fn directories_are_not_capture_paths() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&["-n", "-r", &capture, "-w", "/tmp"]);
    assert_eq!(run.status.code(), Some(9));
    assert!(String::from_utf8_lossy(&run.stderr).contains("directory"));
}

#[test]
fn broken_stdout_capture_pipe_exits_fifteen() {
    let capture = fixture("rewrite-basic.pcap");
    let (reader, writer) = must(std::io::pipe(), "pipe");
    drop(reader);
    let mut command = Command::new(BIN);
    command
        .args(["-n", "-r", &capture, "-q", "-w", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped());
    let output = must(command.output(), "run packetfin");
    assert_eq!(output.status.code(), Some(15));
}

#[test]
fn two_pass_stdin_is_rejected_with_status_three() {
    let capture_bytes = must(
        fs::read(golden::fixtures_dir().join("rewrite-basic.pcap")),
        "read fixture",
    );
    // A pipe/FIFO.
    let child = Command::new(BIN)
        .args(["-n", "-2", "-r", "-", "-T", "fields", "-e", "frame.number"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = must(child, "spawn");
    let mut stdin = must_some(child.stdin.take(), "stdin");
    must(stdin.write_all(&capture_bytes), "write stdin");
    let output = must(child.wait_with_output(), "wait");
    assert_eq!(output.status.code(), Some(3));

    // A regular file redirected to standard input.
    let file = must(
        fs::File::open(golden::fixtures_dir().join("rewrite-basic.pcap")),
        "open fixture",
    );
    let output = Command::new(BIN)
        .args(["-n", "-2", "-r", "-", "-T", "fields", "-e", "frame.number"])
        .stdin(Stdio::from(file))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    let output = must(output, "run");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn two_pass_without_a_read_file_is_a_live_error() {
    let run = invoke(&["-n", "-2", "-T", "fields", "-e", "frame.number"]);
    assert_eq!(run.status.code(), Some(1));
}

#[test]
fn read_filter_requires_two_pass() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&["-n", "-r", &capture, "-R", "tcp.flags.syn==1"]);
    assert_eq!(run.status.code(), Some(1));
}

#[test]
fn read_filter_field_error_exits_four() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-2",
        "-R",
        "bogus.field==1",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.status.code(), Some(4));
}

#[test]
fn two_pass_renumbers_and_accepts_the_read_filter() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-2",
        "-R",
        "tcp.flags.syn==0",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(run.stdout, b"1\n2\n3\n4\n");
}

#[test]
fn read_filter_frame_number_uses_the_renumbered_position() {
    let capture = fixture("rewrite-basic.pcap");
    // The recording pass numbers accepted frames prospectively, so file
    // frame 2 is the first accepted frame and is numbered 1; with no later
    // frame reaching 2, `frame.number==2` selects nothing. The output pass
    // uses that selection unchanged.
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-2",
        "-R",
        "frame.number==2",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
}

#[test]
fn two_pass_packet_limit_counts_accepted_frames() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-2",
        "-R",
        "tcp.flags.syn==0",
        "-c",
        "2",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.status.code(), Some(0));
    // The recording pass stops after the accepted
    // frame reaches the -c limit, which here is file frame 2; only that
    // frame is left in the selection.
    assert_eq!(run.stdout, b"1\n");
}

#[test]
fn read_mode_autostop_counts_selected_frames_and_source_bytes() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-a",
        "packets:2",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.stdout, b"1\n2\n");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-a",
        "filesize:100",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.stdout, b"1\n2\n");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-Y",
        "frame.number==3",
        "-a",
        "packets:2",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.stdout, b"3\n");
}

#[test]
fn read_mode_rejects_wall_clock_and_ring_conditions() {
    let capture = fixture("rewrite-basic.pcap");
    for arguments in [
        vec!["-n", "-r", &capture, "-a", "duration:1"],
        vec!["-n", "-r", &capture, "-a", "files:1"],
        vec!["-n", "-r", &capture, "-b", "packets:1"],
        vec!["-n", "-r", &capture, "-b", "printname:/tmp/names"],
    ] {
        let run = invoke(&arguments);
        assert_eq!(run.status.code(), Some(1), "{arguments:?}");
    }
}

#[test]
fn write_stdout_conflicts_with_dissected_output() {
    let capture = fixture("rewrite-basic.pcap");
    for arguments in [
        vec![
            "-n",
            "-r",
            &capture,
            "-w",
            "-",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        vec!["-n", "-r", &capture, "-w", "-", "-V"],
        vec!["-n", "-r", &capture, "-w", "-", "-x"],
        vec!["-n", "-r", &capture, "-w", "-", "-P"],
        vec!["-n", "-r", &capture, "-w", "-", "-O", "tcp"],
    ] {
        let run = invoke(&arguments);
        assert_eq!(run.status.code(), Some(1), "{arguments:?}");
        assert!(run.stdout.is_empty(), "{arguments:?}");
    }
}

#[test]
fn capture_comments_require_pcapng_and_an_output_file() {
    let capture = fixture("rewrite-basic.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-F",
        "pcap",
        "--capture-comment",
        "x",
        "-w",
        "/tmp/x",
    ]);
    assert_eq!(run.status.code(), Some(1));
    let run = invoke(&["-n", "-r", &capture, "--capture-comment", "x"]);
    assert_eq!(run.status.code(), Some(1));
}

#[test]
fn autostop_and_ring_values_are_validated() {
    let capture = fixture("rewrite-basic.pcap");
    for value in ["packets:0", "packets:-1", "packets:abc", "bogus:1"] {
        let run = invoke(&["-n", "-r", &capture, "-a", value]);
        assert_eq!(run.status.code(), Some(1), "-a {value}");
    }
    for value in ["packets:0", "files:0", "filesize:0", "bogus:1"] {
        let run = invoke(&["-n", "-r", &capture, "-b", value]);
        assert_eq!(run.status.code(), Some(1), "-b {value}");
    }
}

fn write_capture(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    must(fs::write(&path, bytes), "write input capture");
    path
}

#[test]
fn output_extension_does_not_select_the_format() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("format-extension");
    must(fs::create_dir_all(&directory), "scratch directory");
    let output = directory.join("out.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    let bytes = must(fs::read(&output), "read output");
    assert_eq!(bytes.get(0..4), Some([0x0a, 0x0d, 0x0d, 0x0a].as_slice()));
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn pcap_header_uses_the_expected_snaplen_and_link_type() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("pcap-header");
    must(fs::create_dir_all(&directory), "scratch directory");
    let output = directory.join("out.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-F",
        "pcap",
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    let bytes = must(fs::read(&output), "read output");
    assert_eq!(bytes.get(0..4), Some([0xd4, 0xc3, 0xb2, 0xa1].as_slice()));
    assert_eq!(bytes.get(16..20), Some([0x00, 0x00, 0x04, 0x00].as_slice()));
    assert_eq!(bytes.get(20..24), Some([0x01, 0x00, 0x00, 0x00].as_slice()));
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn upper_case_extension_is_not_compressed() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("upper-extension");
    must(fs::create_dir_all(&directory), "scratch directory");
    let output = directory.join("out.GZ");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    let bytes = must(fs::read(&output), "read output");
    assert_eq!(bytes.get(0..4), Some([0x0a, 0x0d, 0x0d, 0x0a].as_slice()));
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn gzip_output_is_deterministic() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("gzip-deterministic");
    must(fs::create_dir_all(&directory), "scratch directory");
    let first = directory.join("first.gz");
    let second = directory.join("second.gz");
    for path in [&first, &second] {
        let run = invoke(&[
            "-n",
            "-r",
            &capture,
            "-w",
            must_some(path.to_str(), "utf-8 path"),
        ]);
        assert_eq!(run.status.code(), Some(0));
    }
    assert_eq!(
        must(fs::read(&first), "read first"),
        must(fs::read(&second), "read second")
    );
    let _ = fs::remove_dir_all(&directory);
}

#[cfg(unix)]
#[test]
fn read_mode_output_is_world_readable() {
    use std::os::unix::fs::PermissionsExt;

    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("mode");
    must(fs::create_dir_all(&directory), "scratch directory");
    let output = directory.join("out.pcapng");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    let mode = must(fs::metadata(&output), "stat output")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn timestamp_beyond_pcap_seconds_exits_fifteen_with_a_header_only_file() {
    let directory = scratch("timestamp");
    must(fs::create_dir_all(&directory), "scratch directory");
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = must(
        file.add_interface(pcapng::Interface::ethernet()),
        "add interface",
    );
    must(
        file.add_enhanced_packet(pcapng::EnhancedPacket::new(
            interface,
            Timestamp::new(1 << 33, 0),
            vec![0_u8; 60],
        )),
        "add packet",
    );
    let input = write_capture(
        &directory,
        "year2200.pcapng",
        &must(file.to_bytes(), "build pcapng"),
    );
    let output = directory.join("out.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        must_some(input.to_str(), "utf-8 path"),
        "-F",
        "pcap",
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(15));
    assert_eq!(must(fs::metadata(&output), "stat output").len(), 24);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn oversized_frame_exits_fifteen() {
    let directory = scratch("oversize");
    must(fs::create_dir_all(&directory), "scratch directory");
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = must(
        file.add_interface(pcapng::Interface::ethernet()),
        "add interface",
    );
    must(
        file.add_enhanced_packet(pcapng::EnhancedPacket::new(
            interface,
            Timestamp::new(1_700_000_000, 0),
            vec![0_u8; 262_145],
        )),
        "add packet",
    );
    let input = write_capture(
        &directory,
        "oversize.pcapng",
        &must(file.to_bytes(), "build pcapng"),
    );
    let output = directory.join("out.pcapng");
    let run = invoke(&[
        "-n",
        "-r",
        must_some(input.to_str(), "utf-8 path"),
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(15));
    let _ = fs::remove_dir_all(&directory);
}

fn pcapng_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = u32::try_from(body.len() + 12).unwrap_or(u32::MAX);
    let mut block = Vec::with_capacity(body.len() + 12);
    block.extend_from_slice(&block_type.to_le_bytes());
    block.extend_from_slice(&total.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total.to_le_bytes());
    block
}

fn pcapng_shb() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1a2b_3c4d_u32.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&(-1_i64).to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    pcapng_block(0x0a0d_0d0a, &body)
}

fn pcapng_idb(link_type: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&link_type.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&262_144_u32.to_le_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    pcapng_block(1, &body)
}

fn pcapng_epb(interface: u32, timestamp: u64, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&interface.to_le_bytes());
    body.extend_from_slice(
        &u32::try_from(timestamp >> 32)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    body.extend_from_slice(
        &u32::try_from(timestamp & 0xffff_ffff)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    body.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
    body.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
    body.extend_from_slice(data);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    body.extend_from_slice(&[0, 0, 0, 0]);
    pcapng_block(6, &body)
}

fn pcapng_option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut option = Vec::new();
    option.extend_from_slice(&code.to_le_bytes());
    option.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_le_bytes());
    option.extend_from_slice(value);
    while !option.len().is_multiple_of(4) {
        option.push(0);
    }
    option
}

fn pcapng_shb_commented(comment: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x1a2b_3c4d_u32.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&(-1_i64).to_le_bytes());
    body.extend_from_slice(&pcapng_option(1, comment.as_bytes()));
    body.extend_from_slice(&[0, 0, 0, 0]);
    pcapng_block(0x0a0d_0d0a, &body)
}

fn pcapng_idb_named(link_type: u16, name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&link_type.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&262_144_u32.to_le_bytes());
    body.extend_from_slice(&pcapng_option(2, name.as_bytes()));
    body.extend_from_slice(&[0, 0, 0, 0]);
    pcapng_block(1, &body)
}

/// A block header that promises 100 bytes but ends immediately.
fn pcapng_partial_epb() -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&6_u32.to_le_bytes());
    block.extend_from_slice(&100_u32.to_le_bytes());
    block
}

#[cfg(unix)]
fn run_with_timeout(args: &[&str], timeout: std::time::Duration) -> Run {
    let mut child = match Command::new(BIN)
        .args(args)
        .current_dir(golden::repo_root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            eprintln!("failed to spawn packetfin: {error}");
            std::process::exit(1);
        }
    };
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                eprintln!("packetfin did not exit within {timeout:?}: {args:?}");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("failed to wait for packetfin: {error}");
                std::process::exit(1);
            }
        }
    }
    match child.wait_with_output() {
        Ok(output) => Run {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        },
        Err(error) => {
            eprintln!("failed to collect packetfin output: {error}");
            std::process::exit(1);
        }
    }
}

#[test]
fn a_late_link_type_conflict_exits_fifteen_with_a_partial_file() {
    let directory = scratch("late-conflict");
    must(fs::create_dir_all(&directory), "scratch directory");
    // The second interface description appears after the first packet, which
    // is the only way a streaming writer can discover the conflict after it
    // has opened the pcap output.
    let mut bytes = pcapng_shb();
    bytes.extend_from_slice(&pcapng_idb(1));
    bytes.extend_from_slice(&pcapng_epb(0, 1_700_000_000_000_000, &[0_u8; 60]));
    bytes.extend_from_slice(&pcapng_idb(101));
    bytes.extend_from_slice(&pcapng_epb(1, 1_700_000_001_000_000, &[0_u8; 40]));
    let input = write_capture(&directory, "late.pcapng", &bytes);
    let output = directory.join("out.pcap");
    let run = invoke(&[
        "-n",
        "-r",
        must_some(input.to_str(), "utf-8 path"),
        "-F",
        "pcap",
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    // Packetfin's streaming writer opens pcap when the first interface is
    // described and notices the second link type after writing frame one,
    // so the run exits 15 with a partial file.
    assert_eq!(run.status.code(), Some(15));
    assert!(must(fs::metadata(&output), "stat output").len() > 24);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn pcapng_source_autostop_uses_block_offsets() {
    let capture = fixture("rewrite-sections.pcapng");
    let directory = scratch("filesize-pcapng");
    must(fs::create_dir_all(&directory), "scratch directory");
    let output = directory.join("out.pcapng");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-a",
        "filesize:200",
        "-w",
        must_some(output.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    let read = invoke(&[
        "-n",
        "-r",
        must_some(output.to_str(), "utf-8 path"),
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(read.status.code(), Some(0));
    assert_eq!(read.stdout, b"1\n");
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn oversized_capture_comment_is_dropped_like_the_reference() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("huge-comment");
    must(fs::create_dir_all(&directory), "scratch directory");
    let plain = directory.join("plain.pcapng");
    let dropped = directory.join("dropped.pcapng");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-w",
        must_some(plain.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    let huge = "x".repeat(65_536);
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "--capture-comment",
        &huge,
        "-w",
        must_some(dropped.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(
        must(fs::read(&plain), "read plain"),
        must(fs::read(&dropped), "read dropped")
    );
    let empty = directory.join("empty-comment.pcapng");
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "--capture-comment",
        "",
        "-w",
        must_some(empty.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(
        must(fs::read(&plain), "read plain"),
        must(fs::read(&empty), "read empty comment")
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn display_options_and_quiet_flags_do_not_change_written_bytes() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("write-modes");
    must(fs::create_dir_all(&directory), "scratch directory");
    let modes: &[&[&str]] = &[
        &[],
        &["-q"],
        &["-Q"],
        &["-P"],
        &["-T", "fields", "-e", "frame.number"],
        &["-V"],
        &["-x"],
        &["-l"],
    ];
    let mut reference: Option<Vec<u8>> = None;
    for (index, extra) in modes.iter().enumerate() {
        let output = directory.join(format!("out-{index}.pcapng"));
        let mut arguments = vec!["-n", "-r", &capture, "-w"];
        let path = must_some(output.to_str(), "utf-8 path");
        arguments.push(path);
        arguments.extend_from_slice(extra);
        let run = invoke(&arguments);
        assert_eq!(
            run.status.code(),
            Some(0),
            "{extra:?}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let bytes = must(fs::read(&output), "read output");
        match &reference {
            None => reference = Some(bytes),
            Some(expected) => assert_eq!(&bytes, expected, "{extra:?} changed written bytes"),
        }
    }
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn compressed_sources_use_decompressed_source_offsets() {
    let compressed = fixture("compressed-gzip.gz");
    let run = invoke(&[
        "-n",
        "-r",
        &compressed,
        "-a",
        "filesize:50",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(run.stdout, b"1\n2\n");

    let run = invoke(&[
        "-n",
        "-r",
        &compressed,
        "-2",
        "-R",
        "udp",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(run.stdout, b"1\n2\n3\n");

    let directory = scratch("compressed-write");
    must(fs::create_dir_all(&directory), "scratch directory");
    let mut written: Option<Vec<u8>> = None;
    for (name, compressed_fixture) in [
        ("gzip", "compressed-gzip.gz"),
        ("zstd", "compressed-zstd.zst"),
        ("lz4", "compressed-lz4.lz4"),
    ] {
        let input = fixture(compressed_fixture);
        let output = directory.join(format!("out-{name}.pcapng"));
        let run = invoke(&[
            "-n",
            "-r",
            &input,
            "-w",
            must_some(output.to_str(), "utf-8 path"),
        ]);
        assert_eq!(
            run.status.code(),
            Some(0),
            "{name}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let read = invoke(&[
            "-n",
            "-r",
            must_some(output.to_str(), "utf-8 path"),
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]);
        assert_eq!(read.stdout, b"1\n2\n3\n", "{name}");
        let bytes = must(fs::read(&output), "read output");
        match &written {
            None => written = Some(bytes),
            Some(expected) => assert_eq!(&bytes, expected, "{name} rewrite differs"),
        }
    }
    let _ = fs::remove_dir_all(&directory);
}

#[cfg(unix)]
#[test]
fn two_pass_rejects_non_regular_and_fifo_inputs() {
    let directory = scratch("two-pass-special");
    must(fs::create_dir_all(&directory), "scratch directory");
    let fifo = directory.join("capture.fifo");
    let status = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map_err(|error| error.to_string());
    let status = must(status, "mkfifo");
    assert!(status.success(), "mkfifo failed");

    let output = directory.join("should-not-exist.pcapng");
    let fifo_text = must_some(fifo.to_str(), "utf-8 fifo path");
    let output_text = must_some(output.to_str(), "utf-8 output path");
    let run = run_with_timeout(
        &[
            "-n",
            "-2",
            "-r",
            fifo_text,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-w",
            output_text,
        ],
        std::time::Duration::from_secs(5),
    );
    assert_eq!(
        run.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(!output.exists(), "a rejected FIFO must not create output");

    let run = run_with_timeout(
        &[
            "-n",
            "-2",
            "-r",
            "/dev/null",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        std::time::Duration::from_secs(5),
    );
    assert_eq!(run.status.code(), Some(3));
    let _ = fs::remove_dir_all(&directory);
}

#[cfg(unix)]
#[test]
fn two_pass_reads_a_regular_file_through_dev_stdin() {
    let capture = golden::fixtures_dir().join("rewrite-basic.pcap");
    for path in ["/dev/stdin", "/dev/fd/0"] {
        let file = must(fs::File::open(&capture), "open capture");
        let output = must(
            Command::new(BIN)
                .args(["-n", "-2", "-r", path, "-T", "fields", "-e", "frame.number"])
                .current_dir(golden::repo_root())
                .stdin(Stdio::from(file))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
            "run packetfin",
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{path}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"1\n2\n3\n4\n5\n6\n", "{path}");
    }
}

#[test]
fn two_pass_preserves_metadata_seen_before_a_pass_one_error() {
    let directory = scratch("metadata-error");
    must(fs::create_dir_all(&directory), "scratch directory");
    let mut bytes = pcapng_shb_commented("hello");
    bytes.extend_from_slice(&pcapng_idb_named(1, "ethX"));
    bytes.extend_from_slice(&pcapng_partial_epb());
    let input = write_capture(&directory, "trunc.pcapng", &bytes);
    let pcapng = directory.join("out.pcapng");
    let run = invoke(&[
        "-n",
        "-2",
        "-r",
        must_some(input.to_str(), "utf-8 path"),
        "-w",
        must_some(pcapng.to_str(), "utf-8 path"),
    ]);
    assert_eq!(
        run.status.code(),
        Some(14),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let written = must(fs::read(&pcapng), "read pcapng");
    assert!(
        written.windows(5).any(|window| window == b"hello"),
        "SHB comment was dropped"
    );
    assert!(
        written.windows(4).any(|window| window == b"ethX"),
        "IDB name was dropped"
    );

    let pcap = directory.join("out.pcap");
    let run = invoke(&[
        "-n",
        "-2",
        "-r",
        must_some(input.to_str(), "utf-8 path"),
        "-F",
        "pcap",
        "-w",
        must_some(pcap.to_str(), "utf-8 path"),
    ]);
    assert_eq!(run.status.code(), Some(14));
    let written = must(fs::read(&pcap), "read pcap");
    assert_eq!(
        written.get(20..24),
        Some([1_u8, 0, 0, 0].as_slice()),
        "pcap link type was not copied"
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn two_pass_refuses_to_overwrite_its_input() {
    let directory = scratch("same-path");
    must(fs::create_dir_all(&directory), "scratch directory");
    let path = directory.join("same.pcap");
    let original = must(
        fs::read(golden::fixtures_dir().join("rewrite-basic.pcap")),
        "read fixture",
    );
    must(fs::write(&path, &original), "write input");
    let path_text = must_some(path.to_str(), "utf-8 path");
    let run = invoke(&["-n", "-2", "-r", path_text, "-w", path_text]);
    assert_eq!(
        run.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(must(fs::read(&path), "read input"), original);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn two_pass_filesize_keeps_the_first_read_filter_match() {
    let capture = fixture("rewrite-basic.pcap");
    for limit in ["25", "100", "200"] {
        let run = invoke(&[
            "-n",
            "-r",
            &capture,
            "-2",
            "-R",
            "tcp.flags.syn==0",
            "-a",
            &format!("filesize:{limit}"),
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]);
        assert_eq!(run.status.code(), Some(0));
        assert_eq!(run.stdout, b"1\n", "filesize:{limit}");
    }
    let run = invoke(&[
        "-n",
        "-r",
        &capture,
        "-2",
        "-R",
        "tcp.flags.syn==0",
        "-a",
        "filesize:250",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    assert_eq!(run.stdout, b"1\n2\n");
}

#[test]
fn compression_options_produce_the_expected_sink_magic() {
    let capture = fixture("rewrite-basic.pcap");
    let directory = scratch("compression-magic");
    must(fs::create_dir_all(&directory), "scratch directory");
    let gzip = directory.join("out.gz");
    let gzip_text = must_some(gzip.to_str(), "utf-8 path");
    assert_eq!(
        invoke(&["-n", "-r", &capture, "-w", gzip_text])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        must(fs::read(&gzip), "read gzip").get(0..2),
        Some([0x1f, 0x8b].as_slice())
    );

    let lz4 = directory.join("out.lz4");
    let lz4_text = must_some(lz4.to_str(), "utf-8 path");
    assert_eq!(
        invoke(&["-n", "-r", &capture, "-w", lz4_text])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        must(fs::read(&lz4), "read lz4").get(0..4),
        Some([0x04, 0x22, 0x4d, 0x18].as_slice())
    );

    let explicit = directory.join("out");
    let explicit_text = must_some(explicit.to_str(), "utf-8 path");
    assert_eq!(
        invoke(&[
            "-n",
            "-r",
            &capture,
            "--compress",
            "gzip",
            "-w",
            explicit_text,
        ])
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        must(fs::read(&explicit), "read explicit gzip").get(0..2),
        Some([0x1f, 0x8b].as_slice())
    );

    let stdout = invoke(&["-n", "-r", &capture, "-q", "--compress", "gzip", "-w", "-"]);
    assert_eq!(stdout.stdout.get(0..2), Some([0x1f, 0x8b].as_slice()));
    let stdout = invoke(&["-n", "-r", &capture, "-q", "--compress", "lz4", "-w", "-"]);
    assert_eq!(
        stdout.stdout.get(0..4),
        Some([0x04, 0x22, 0x4d, 0x18].as_slice())
    );

    let upper = directory.join("out.GZ");
    let upper_text = must_some(upper.to_str(), "utf-8 path");
    assert_eq!(
        invoke(&["-n", "-r", &capture, "-w", upper_text])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        must(fs::read(&upper), "read upper").get(0..4),
        Some([0x0a, 0x0d, 0x0d, 0x0a].as_slice())
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn line_flush_streams_written_stdout_capture() {
    let mut input = pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond);
    must(
        input.push(Timestamp::new(1_700_000_000, 0), vec![0_u8; 60]),
        "pcap frame",
    );
    let bytes = must(input.to_bytes(), "pcap bytes");
    let mut child = must(
        Command::new(BIN)
            .args(["-n", "-r", "-", "-q", "-l", "-F", "pcap", "-w", "-"])
            .current_dir(golden::repo_root())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn(),
        "spawn packetfin",
    );
    let mut stdin = must_some(child.stdin.take(), "stdin");
    must(stdin.write_all(&bytes), "write stdin");
    must(stdin.flush(), "flush stdin");
    let mut stdout = must_some(child.stdout.take(), "stdout");
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut magic = [0_u8; 4];
        let result = stdout.read_exact(&mut magic);
        let _ = sender.send((result, magic));
    });
    let received = match receiver.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(received) => received,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("-l did not flush the capture header while the input stayed open");
            std::process::exit(1);
        }
    };
    let (result, magic) = received;
    assert!(result.is_ok(), "-l stdout read failed");
    assert_eq!(magic, [0xd4, 0xc3, 0xb2, 0xa1]);
    drop(stdin);
    must(child.wait(), "wait packetfin");
    let _ = reader.join();
}

#[cfg(target_os = "macos")]
#[test]
fn two_pass_without_a_writer_does_not_retain_large_metadata() {
    let directory = scratch("metadata-rss");
    must(fs::create_dir_all(&directory), "scratch directory");
    let mut file = pcapng::PcapNg::new(ByteOrder::Little);
    let interface = must(
        file.add_interface(pcapng::Interface::ethernet()),
        "add interface",
    );
    let mut resolution = pcapng::NameResolution::new();
    for _ in 0..256 {
        resolution = resolution.add_other(4, vec![b'A'; 65_000]);
    }
    must(file.add_name_resolution(resolution), "add NRB");
    must(
        file.add_enhanced_packet(pcapng::EnhancedPacket::new(
            interface,
            Timestamp::new(1_700_000_000, 0),
            vec![0_u8; 60],
        )),
        "add packet",
    );
    let input = write_capture(
        &directory,
        "large-nrb.pcapng",
        &must(file.to_bytes(), "build pcapng"),
    );
    let output = must(
        Command::new("/usr/bin/time")
            .arg("-l")
            .arg(BIN)
            .args([
                "-n",
                "-2",
                "-r",
                must_some(input.to_str(), "utf-8 path"),
                "-T",
                "fields",
                "-e",
                "frame.number",
            ])
            .current_dir(golden::repo_root())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
        "run under time",
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"1\n");
    let statistics = String::from_utf8_lossy(&output.stderr);
    let rss = statistics
        .lines()
        .find(|line| line.contains("maximum resident set size"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok());
    let rss = must_some(rss, "maximum resident set size");
    assert!(
        rss < 64 * 1024 * 1024,
        "no-writer two-pass retained too much metadata: {rss} bytes"
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn unsupported_file_types_are_rejected_before_output() {
    let capture = fixture("rewrite-basic.pcap");
    for value in ["erf", "PCAP", ""] {
        let run = invoke(&["-n", "-r", &capture, "-F", value, "-w", "/tmp/x"]);
        assert_eq!(run.status.code(), Some(1), "-F {value}");
    }
}

#[test]
fn broken_dissected_stdout_still_finalizes_the_writer() -> Result<(), String> {
    let directory = scratch("broken-stdout");
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let output = directory.join("output.lz4");
    let fixture = golden::fixtures_dir()
        .join("ipv6-truncated-prefixes.pcap")
        .to_string_lossy()
        .into_owned();
    let output_arg = output.to_string_lossy().into_owned();
    let mut child = Command::new(BIN)
        .args(["-r", &fixture, "-T", "pdml", "-l", "-w", &output_arg])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdout = child.stdout.take().ok_or("child stdout missing")?;
    let mut first = [0_u8; 1];
    stdout
        .read_exact(&mut first)
        .map_err(|error| error.to_string())?;
    drop(stdout);
    let status = child.wait().map_err(|error| error.to_string())?;
    assert_eq!(status.code(), Some(16), "broken stdout must exit 16");

    let read = invoke(&["-r", &output_arg, "-T", "fields", "-e", "frame.number"]);
    let stderr = String::from_utf8_lossy(&read.stderr);
    assert!(
        read.status.success(),
        "finalized lz4 capture is unreadable: {stderr}"
    );
    let frames = String::from_utf8_lossy(&read.stdout).lines().count();
    assert!(frames > 0, "writer left no readable frames");
    fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(())
}
