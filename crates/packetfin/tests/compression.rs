//! End-to-end tests for compressed capture input.
//!
//! Every gzip, zstd and lz4 fixture is opened by magic from a regular file and
//! from standard input. Failure cases assert Packetfin's exit taxonomy:
//! truncation before a capture header is exit 3, truncation or trailing data
//! after one is exit 14, gzip/lz4 payload corruption after a frame is exit 14
//! and a header-only stream stays exit 3, zstd payload corruption is exit 3,
//! and frames decoded before any failure are still printed. Skippable zstd/lz4
//! frames are consumed wherever they occur.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::fixtures::{self, Fixture};
use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

const FRAME_FIELDS: &[&str] = &[
    "-n",
    "-T",
    "fields",
    "-e",
    "frame.number",
    "-e",
    "frame.len",
    "-e",
    "frame.cap_len",
    "-e",
    "frame.time_epoch",
];

/// Fixtures whose compressed input behaves exactly like their plain capture,
/// so their stored `frame-fields` golden applies unchanged.
const GOLDEN_COMPRESSED: &[&str] = &[
    "compressed-gzip",
    "compressed-zstd",
    "compressed-lz4",
    "compressed-gzip-concat",
    "compressed-gzip-mid-deflate",
    "compressed-gzip-multimember-truncated",
    "compressed-zstd-content-size",
    "compressed-zstd-reserved",
    "compressed-lz4-bad-checksum",
    "compressed-lz4-bad-header",
    "compressed-zstd-split",
    "compressed-lz4-split",
    "compressed-pcapng-gzip",
    "compressed-lz4-truncated",
    "compressed-zstd-concat",
    "compressed-lz4-concat",
    "compressed-gzip-bad-crc-frames",
    "compressed-gzip-bad-size-frames",
];

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[OsString], input: Option<&[u8]>) -> Run {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        }
    };
    if let Some(bytes) = input {
        match child.stdin.take() {
            Some(mut stdin) => {
                if let Err(error) = stdin.write_all(bytes) {
                    eprintln!("failed to write standard input: {error}");
                    std::process::exit(1);
                }
            }
            None => {
                eprintln!("packetfin's standard input was not piped");
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
            eprintln!("failed to wait for packetfin: {error}");
            std::process::exit(1);
        }
    }
}

fn status_code(run: &Run) -> i32 {
    run.status.code().unwrap_or(-1)
}

fn line_count(run: &Run) -> usize {
    run.stdout.iter().filter(|byte| **byte == b'\n').count()
}

fn stderr_text(run: &Run) -> String {
    String::from_utf8_lossy(&run.stderr).into_owned()
}

fn fixture(name: &str) -> &'static Fixture {
    match fixtures::all().iter().find(|fixture| fixture.name == name) {
        Some(fixture) => fixture,
        None => {
            eprintln!("no fixture named {name}");
            std::process::exit(1);
        }
    }
}

fn fixture_path(fixture: &Fixture) -> PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

fn fixture_bytes(fixture: &Fixture) -> Vec<u8> {
    match fixture.build() {
        Ok(bytes) => bytes,
        Err(message) => {
            eprintln!("failed to build {}: {message}", fixture.name);
            std::process::exit(1);
        }
    }
}

fn file_args(path: &Path) -> Vec<OsString> {
    field_args(Some(path))
}

fn stdin_args() -> Vec<OsString> {
    field_args(None)
}

fn field_args(path: Option<&Path>) -> Vec<OsString> {
    let mut args: Vec<OsString> = FRAME_FIELDS.iter().map(OsString::from).collect();
    args.push(OsString::from("-r"));
    match path {
        Some(path) => args.push(path.as_os_str().to_owned()),
        None => args.push(OsString::from("-")),
    }
    args
}

fn stored_frame_fields(name: &str) -> golden::Golden {
    match golden::load(name, "frame-fields") {
        Ok(golden) => golden,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

fn assert_golden(name: &str, run: &Run) {
    if let Err(message) =
        golden::compare_golden_stdout_status(name, "frame-fields", &run.stdout, status_code(run))
    {
        eprintln!("{message}");
        eprintln!("observed stderr: {}", stderr_text(run));
        eprintln!(
            "observed stdout: {:?}",
            String::from_utf8_lossy(&run.stdout)
        );
        std::process::exit(1);
    }
}

#[test]
fn standard_input_matches_the_stored_golden_for_every_format() {
    for name in GOLDEN_COMPRESSED {
        let fixture = fixture(name);
        let run = run(&stdin_args(), Some(&fixture_bytes(fixture)));
        assert_golden(name, &run);
    }
}

#[test]
fn truncation_before_a_header_exits_three() {
    for name in ["compressed-gzip-truncated", "compressed-zstd-truncated"] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 3, "{name}: {}", stderr_text(&run));
        assert!(run.stdout.is_empty(), "{name} printed frames");
        assert!(
            stderr_text(&run).starts_with("packetfin:"),
            "{name} used foreign diagnostic text: {}",
            stderr_text(&run)
        );
    }
}

#[test]
fn truncation_after_a_header_exits_fourteen_and_keeps_frames() {
    let header_only = run(
        &file_args(&fixture_path(fixture(
            "compressed-gzip-truncated-after-header",
        ))),
        None,
    );
    assert_eq!(
        status_code(&header_only),
        14,
        "{}",
        stderr_text(&header_only)
    );
    assert!(
        header_only.stdout.is_empty(),
        "header-only truncation printed frames"
    );

    let zstd = run(
        &file_args(&fixture_path(fixture(
            "compressed-zstd-truncated-after-header",
        ))),
        None,
    );
    assert_eq!(status_code(&zstd), 14, "{}", stderr_text(&zstd));
    assert_eq!(line_count(&zstd), 1, "zstd truncation lost decoded frames");

    let lz4 = run(
        &file_args(&fixture_path(fixture("compressed-lz4-truncated"))),
        None,
    );
    assert_eq!(status_code(&lz4), 14, "{}", stderr_text(&lz4));
    assert_eq!(line_count(&lz4), 3, "lz4 truncation lost decoded frames");
}

#[test]
fn standard_input_truncation_after_frames_exits_fourteen() {
    let fixture = fixture("compressed-lz4-truncated");
    let run = run(&stdin_args(), Some(&fixture_bytes(fixture)));
    assert_eq!(status_code(&run), 14, "{}", stderr_text(&run));
    assert_eq!(line_count(&run), 3, "{}", stderr_text(&run));
}

#[test]
fn gzip_trailer_corruption_after_frames_exits_fourteen() {
    // A header-only stream never emitted a frame, so it is reported as
    // "cannot be decompressed" (exit 3); both fixtures contain only the pcap
    // global header.
    for name in ["compressed-gzip-bad-crc", "compressed-gzip-bad-size"] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 3, "{name}: {}", stderr_text(&run));
        assert!(run.stdout.is_empty(), "{name} printed frames");
    }

    // Once frames were decoded, CRC or ISIZE corruption is a damaged capture
    // (exit 14) and the frames decoded before the failure are kept.
    let expected = stored_frame_fields("compressed-gzip");
    for name in [
        "compressed-gzip-bad-crc-frames",
        "compressed-gzip-bad-size-frames",
    ] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 14, "{name}: {}", stderr_text(&run));
        assert_eq!(
            run.stdout, expected.stdout,
            "{name}: frames decoded before the trailer failure were not printed"
        );
    }
}

#[test]
fn gzip_deflate_corruption_after_frames_exits_fourteen() {
    let run = run(
        &file_args(&fixture_path(fixture("compressed-gzip-bad-deflate-frames"))),
        None,
    );
    assert_eq!(status_code(&run), 14, "{}", stderr_text(&run));
    assert_eq!(
        line_count(&run),
        1,
        "frames decoded before the deflate failure were dropped"
    );
}

#[test]
fn trailing_data_exits_fourteen_after_frames() {
    let run = run(
        &file_args(&fixture_path(fixture("compressed-gzip-trailing"))),
        None,
    );
    assert_eq!(status_code(&run), 14, "{}", stderr_text(&run));
    let expected = stored_frame_fields("compressed-gzip");
    assert_eq!(
        run.stdout, expected.stdout,
        "frames decoded before the trailing data were not printed"
    );
}

#[test]
fn oversized_zstd_window_and_legacy_lz4_exit_three() {
    for name in ["compressed-zstd-window", "compressed-lz4-legacy"] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 3, "{name}: {}", stderr_text(&run));
        assert!(run.stdout.is_empty(), "{name} printed frames");
        assert!(
            stderr_text(&run).starts_with("packetfin:"),
            "{name} used foreign diagnostic text: {}",
            stderr_text(&run)
        );
    }
}

#[test]
fn detection_uses_the_magic_not_the_file_name() {
    let fixture = fixture("compressed-gzip");
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("compressed-input.dat");
    if let Err(error) = std::fs::write(&path, fixture_bytes(fixture)) {
        eprintln!("cannot write {}: {error}", path.display());
        std::process::exit(1);
    }
    let run = run(&file_args(&path), None);
    assert_golden("compressed-gzip", &run);
}

#[test]
fn unsupported_compression_magics_exit_three() {
    let bzip2 = b"BZh9\x31\x41\x59\x26\x53\x59\x00\x00\x00\x00";
    let xz = b"\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F";
    for (name, bytes) in [("bzip2", bzip2.as_slice()), ("xz", xz.as_slice())] {
        let run = run(&stdin_args(), Some(bytes));
        assert_eq!(status_code(&run), 3, "{name}: {}", stderr_text(&run));
        assert!(run.stdout.is_empty(), "{name} printed frames");
    }
}

#[test]
fn two_byte_gzip_magic_is_recognized_as_truncated() {
    let run = run(&stdin_args(), Some(&[0x1f, 0x8b]));
    assert_eq!(status_code(&run), 3, "{}", stderr_text(&run));
    assert!(run.stdout.is_empty());
    assert!(stderr_text(&run).starts_with("packetfin:"));
}

#[test]
fn bomb_streams_stop_after_the_requested_count() {
    for name in [
        "compressed-gzip-bomb",
        "compressed-zstd-bomb",
        "compressed-lz4-bomb",
    ] {
        let mut args = file_args(&fixture_path(fixture(name)));
        args.push(OsString::from("-c"));
        args.push(OsString::from("2"));
        let run = run(&args, None);
        assert_eq!(status_code(&run), 0, "{name}: {}", stderr_text(&run));
        assert_eq!(line_count(&run), 2, "{name} did not stop at -c 2");
    }
}

#[test]
fn unnamed_container_failures_follow_the_taxonomy() {
    let gzip = fixture_bytes(fixture("compressed-gzip"));
    let zstd = fixture_bytes(fixture("compressed-zstd"));
    let lz4 = fixture_bytes(fixture("compressed-lz4"));

    // lz4 cut inside its frame header: no capture header was decoded.
    let cut = lz4.get(..10).unwrap_or_default();
    let observed = run(&stdin_args(), Some(cut));
    assert_eq!(status_code(&observed), 3, "{}", stderr_text(&observed));
    assert!(observed.stdout.is_empty());

    // zstd is complete, then trailing garbage.
    let mut trailing = zstd.clone();
    trailing.extend_from_slice(b"junk");
    let observed = run(&stdin_args(), Some(&trailing));
    assert_eq!(status_code(&observed), 14, "{}", stderr_text(&observed));
    assert_eq!(line_count(&observed), 3);

    // gzip loses the last three trailer bytes after the third frame.
    let cut = gzip.len().saturating_sub(3);
    let observed = run(&stdin_args(), gzip.get(..cut));
    assert_eq!(status_code(&observed), 14, "{}", stderr_text(&observed));
    assert_eq!(line_count(&observed), 3);

    // A corrupt deflate body is decoder corruption, not a cut-short capture.
    let mut broken = gzip;
    if let Some(byte) = broken.get_mut(40) {
        *byte ^= 0xff;
    }
    let observed = run(&stdin_args(), Some(&broken));
    assert_eq!(status_code(&observed), 3, "{}", stderr_text(&observed));
}

#[test]
fn gzip_mid_deflate_truncation_keeps_decoded_frames() {
    for name in [
        "compressed-gzip-mid-deflate",
        "compressed-gzip-multimember-truncated",
    ] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 14, "{name}: {}", stderr_text(&run));
        assert_eq!(
            line_count(&run),
            2,
            "{name} dropped frames decoded before the cut"
        );
    }
}

#[test]
fn corruption_mapping_is_per_container() {
    // gzip CRC corruption after frames: exit 14.
    let gzip = run(
        &file_args(&fixture_path(fixture("compressed-gzip-bad-crc-frames"))),
        None,
    );
    assert_eq!(status_code(&gzip), 14, "{}", stderr_text(&gzip));
    assert_eq!(line_count(&gzip), 3);

    // zstd content-size and checksum corruption stays exit 3, while the
    // frames decoded before the mismatch are kept.
    for name in [
        "compressed-zstd-content-size-bad",
        "compressed-zstd-bad-checksum",
    ] {
        let zstd = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&zstd), 3, "{name}: {}", stderr_text(&zstd));
        assert_eq!(line_count(&zstd), 3, "{name} dropped decoded frames");
    }

    // lz4 corruption after the capture header: exit 14.
    let lz4 = run(
        &file_args(&fixture_path(fixture("compressed-lz4-bad-checksum"))),
        None,
    );
    assert_eq!(status_code(&lz4), 14, "{}", stderr_text(&lz4));
    assert_eq!(line_count(&lz4), 3);

    // lz4 corruption in the frame header, before any capture data: exit 3.
    let lz4_header = run(
        &file_args(&fixture_path(fixture("compressed-lz4-bad-header"))),
        None,
    );
    assert_eq!(status_code(&lz4_header), 3, "{}", stderr_text(&lz4_header));
    assert!(lz4_header.stdout.is_empty());
}

#[test]
fn zstd_declared_zero_content_size_with_data_exits_three() {
    let observed = run(
        &file_args(&fixture_path(fixture("compressed-zstd-content-size-zero"))),
        None,
    );
    assert_eq!(status_code(&observed), 3, "{}", stderr_text(&observed));
    assert_eq!(line_count(&observed), 3, "decoded frames were dropped");

    // An empty frame with the same declaration is valid and produces no
    // capture data (exit 0), distinguishing absent from declared-zero.
    let empty = packetfin_testkit::compress::zstd_frame_with_content_size(&[], 0);
    let observed = run(&stdin_args(), Some(&empty));
    assert_eq!(status_code(&observed), 0, "{}", stderr_text(&observed));
    assert!(observed.stdout.is_empty());
}

#[test]
fn skippable_frames_decode_like_the_plain_stream() {
    let expected = stored_frame_fields("compressed-gzip");
    for name in [
        "compressed-zstd-skippable-first",
        "compressed-zstd-skippable-middle",
        "compressed-zstd-skippable-trailing",
        "compressed-zstd-seekable",
        "compressed-lz4-skippable-first",
        "compressed-lz4-skippable-middle",
        "compressed-lz4-skippable-trailing",
    ] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 0, "{name}: {}", stderr_text(&run));
        assert_eq!(
            run.stdout, expected.stdout,
            "{name}: skippable metadata changed the decoded frames"
        );
    }
}

#[test]
fn skippable_frames_decode_from_standard_input() {
    let expected = stored_frame_fields("compressed-gzip");
    for name in [
        "compressed-zstd-skippable-middle",
        "compressed-lz4-skippable-middle",
    ] {
        let run = run(&stdin_args(), Some(&fixture_bytes(fixture(name))));
        assert_eq!(status_code(&run), 0, "{name}: {}", stderr_text(&run));
        assert_eq!(run.stdout, expected.stdout, "{name}: stdin differs");
    }
}

#[test]
fn malformed_skippable_frames_are_bounded() {
    for name in [
        "compressed-skippable-truncated-header",
        "compressed-skippable-truncated-payload",
        "compressed-skippable-huge",
    ] {
        let run = run(&file_args(&fixture_path(fixture(name))), None);
        assert_eq!(status_code(&run), 3, "{name}: {}", stderr_text(&run));
        assert!(run.stdout.is_empty(), "{name} printed frames");
        assert!(
            stderr_text(&run).starts_with("packetfin:"),
            "{name} used foreign diagnostic text"
        );
    }
}

#[test]
fn skippable_only_input_is_an_empty_capture() {
    let data = packetfin_testkit::compress::skippable_frame(14, b"seek table");
    let run = run(&stdin_args(), Some(&data));
    assert_eq!(status_code(&run), 0, "{}", stderr_text(&run));
    assert!(run.stdout.is_empty());
}

#[test]
fn lone_trailing_gzip_magic_byte_is_exit_fourteen() {
    // All frames still print, but the trailing byte is reported as a damaged
    // stream instead of being ignored.
    let observed = run(
        &file_args(&fixture_path(fixture(
            "compressed-gzip-trailing-magic-byte",
        ))),
        None,
    );
    assert_eq!(status_code(&observed), 14, "{}", stderr_text(&observed));
    assert_eq!(line_count(&observed), 3);
}
