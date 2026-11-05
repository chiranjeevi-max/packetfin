//! End-to-end `--export-objects http` tests through the real binary.
//!
//! The expected names and bodies come from the golden output in
//! `tests/golden/<fixture>/export-http.manifest`. The remaining cases cover
//! the filesystem rules: never overwrite, never follow a symlink, never escape
//! the destination, and keep the exit status at zero for per-object failures.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use packetfin_testkit::export;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");
static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[&str]) -> Run {
    run_os(&args.iter().map(OsString::from).collect::<Vec<_>>())
}

fn run_os(args: &[OsString]) -> Run {
    let output = match Command::new(BIN)
        .args(args)
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

fn fixture_path(name: &str) -> String {
    packetfin_testkit::golden::fixtures_dir()
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn scratch(label: &str) -> PathBuf {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "packetfin-export-{}-{counter}-{label}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    match fs::create_dir_all(&directory) {
        Ok(()) => directory,
        Err(error) => {
            eprintln!("cannot create {}: {error}", directory.display());
            std::process::exit(1);
        }
    }
}

fn cleanup(directory: &Path) {
    let _ = fs::remove_dir_all(directory);
}

fn export_args<'a>(capture: &'a str, directory: &'a str) -> Vec<String> {
    vec![
        "-r".to_string(),
        capture.to_string(),
        "--export-objects".to_string(),
        format!("http,{directory}"),
        "-q".to_string(),
    ]
}

/// Run the base export command plus `extra` options.
fn run_export(capture: &str, directory: &str, extra: &[&str]) -> Run {
    let mut arguments = export_args(capture, directory);
    arguments.extend(extra.iter().map(|item| item.to_string()));
    let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
    run(&refs)
}

fn exported_names(directory: &Path) -> Vec<String> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("cannot read {}: {error}", directory.display());
            std::process::exit(1);
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("cannot read an entry: {error}");
                std::process::exit(1);
            }
        };
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names
}

fn read(path: &Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}

#[test]
fn exported_names_and_bodies_match_golden_output() {
    for case in export::CASES {
        let directory = scratch(case.fixture);
        let directory_text = directory.to_string_lossy().into_owned();
        let capture = fixture_path(&format!("{}.pcap", case.fixture));
        let resolved: Vec<String> = case
            .prefs
            .iter()
            .map(|pref| match pref.split_once("tests/fixtures/") {
                Some((prefix, rest)) => {
                    format!(
                        "{prefix}{}",
                        packetfin_testkit::golden::fixtures_dir()
                            .join(rest)
                            .display()
                    )
                }
                None => (*pref).to_string(),
            })
            .collect();
        let pref_refs: Vec<&str> = resolved.iter().map(String::as_str).collect();
        let run = run_export(&capture, &directory_text, &pref_refs);
        assert_eq!(
            run.status.code(),
            Some(0),
            "{}: stderr: {}",
            case.fixture,
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(
            run.stdout.is_empty(),
            "{}: stdout: {:?}",
            case.fixture,
            run.stdout
        );
        assert!(
            run.stderr.is_empty(),
            "{}: stderr: {}",
            case.fixture,
            String::from_utf8_lossy(&run.stderr)
        );
        assert_eq!(
            export::compare_manifest(&directory, case),
            Ok(()),
            "{}: manifest comparison failed",
            case.fixture
        );
        cleanup(&directory);
    }
}

#[test]
fn hostile_names_stay_one_component_and_are_percent_escaped() {
    let directory = scratch("names");
    let directory_text = directory.to_string_lossy().into_owned();
    let capture = fixture_path("http-object-names.pcap");
    let run = run_export(&capture, &directory_text, &[]);
    assert_eq!(run.status.code(), Some(0));
    let expected = [
        "%00",
        "%2e",
        "%2e%2e",
        "%2e%2e(1)",
        "..%2f.(1).%2fetc",
        "..%2f..%2fetc",
        "caf%c3%a9.txt",
        "chunk-partial",
        "object17.a%7fb%2fc",
        "object18.caf%c3%a9.txt",
        "passwd",
    ];
    assert_eq!(exported_names(&directory), expected);
    for name in expected {
        if name == "chunk-partial" {
            // Reassembly joins the truncated response body with the frames
            // that follow it.
            assert_eq!(
                read(&directory.join(name)),
                b"0123456789HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
                "body of {name}"
            );
        } else {
            assert_eq!(read(&directory.join(name)), b"x", "body of {name}");
        }
    }
    cleanup(&directory);
}

#[test]
fn a_display_filter_does_not_restrict_export() {
    let plain = scratch("filter-plain");
    let filtered = scratch("filter-active");
    let capture = fixture_path("http-objects.pcap");
    for (directory, extra) in [(&plain, None), (&filtered, Some("frame.number==1"))] {
        let directory_text = directory.to_string_lossy().into_owned();
        let mut arguments = export_args(&capture, &directory_text);
        if let Some(filter) = extra {
            arguments.insert(0, "-Y".to_string());
            arguments.insert(1, filter.to_string());
        }
        let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let run = run(&refs);
        assert_eq!(run.status.code(), Some(0));
    }
    let case = export::CASES
        .iter()
        .find(|case| case.fixture == "http-objects" && case.id == "http");
    if let Some(case) = case {
        assert_eq!(export::compare_manifest(&plain, case), Ok(()));
        assert_eq!(export::compare_manifest(&filtered, case), Ok(()));
    }
    cleanup(&plain);
    cleanup(&filtered);
}

#[test]
fn every_output_mode_exports_the_same_objects() {
    let capture = fixture_path("http-objects.pcap");
    let modes: [&[&str]; 4] = [
        &["-q"],
        &["-T", "fields", "-e", "frame.number", "-q"],
        &["-T", "json", "-q"],
        &["-V", "-q"],
    ];
    for (index, mode) in modes.iter().enumerate() {
        let directory = scratch(&format!("mode-{index}"));
        let directory_text = directory.to_string_lossy().into_owned();
        let mut arguments = vec![
            "-r".to_string(),
            capture.clone(),
            "--export-objects".to_string(),
            format!("http,{directory_text}"),
        ];
        arguments.extend(mode.iter().map(|item| item.to_string()));
        let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let run = run(&refs);
        assert_eq!(
            run.status.code(),
            Some(0),
            "mode {index}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        if let Some(case) = export::CASES
            .iter()
            .find(|case| case.fixture == "http-objects" && case.id == "http")
        {
            assert_eq!(
                export::compare_manifest(&directory, case),
                Ok(()),
                "mode {index}"
            );
        }
        cleanup(&directory);
    }
}

#[cfg(unix)]
#[test]
fn existing_files_symlinks_and_directories_are_never_overwritten() {
    let directory = scratch("collisions");
    let target_directory = scratch("symlink-target");
    let target = target_directory.join("outside.txt");
    if let Err(error) = fs::write(&target, b"outside") {
        eprintln!("cannot seed symlink target: {error}");
        std::process::exit(1);
    }
    if let Err(error) = fs::write(directory.join("normal.txt"), b"keep") {
        eprintln!("cannot seed normal.txt: {error}");
        std::process::exit(1);
    }
    if let Err(error) = fs::create_dir(directory.join("chunked.txt")) {
        eprintln!("cannot seed chunked.txt directory: {error}");
        std::process::exit(1);
    }
    if let Err(error) = std::os::unix::fs::symlink(&target, directory.join("dup.txt")) {
        eprintln!("cannot seed dup.txt symlink: {error}");
        std::process::exit(1);
    }

    let directory_text = directory.to_string_lossy().into_owned();
    let capture = fixture_path("http-objects.pcap");
    let run = run_export(&capture, &directory_text, &[]);
    assert_eq!(run.status.code(), Some(0));

    assert_eq!(read(&directory.join("normal.txt")), b"keep");
    assert_eq!(read(&directory.join("normal(1).txt")), b"Hello, world!");
    assert_eq!(read(&target), b"outside");
    let symlink_metadata = fs::symlink_metadata(directory.join("dup.txt"));
    assert!(
        symlink_metadata.is_ok_and(|metadata| metadata.file_type().is_symlink()),
        "dup.txt must stay a symlink"
    );
    assert_eq!(read(&directory.join("dup(1).txt")), b"one");
    assert_eq!(read(&directory.join("dup(2).txt")), b"two");
    assert_eq!(read(&directory.join("dup(3).txt")), b"three");
    assert!(
        fs::metadata(directory.join("chunked.txt")).is_ok_and(|metadata| metadata.is_dir()),
        "chunked.txt must stay a directory"
    );
    assert_eq!(read(&directory.join("chunked(1).txt")), b"abcdefghijk");
    let entries = fs::read_dir(&directory);
    assert!(entries.is_ok());
    if let Ok(entries) = entries {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".part"), "temporary file leaked: {name}");
        }
    }
    cleanup(&directory);
    cleanup(&target_directory);
}

#[cfg(unix)]
#[test]
fn exported_files_use_0644_and_the_directory_0755() {
    let parent = scratch("modes");
    let directory = parent.join("nested").join("objects");
    let directory_text = directory.to_string_lossy().into_owned();
    let capture = fixture_path("http-objects.pcap");
    let run = run_export(&capture, &directory_text, &[]);
    assert_eq!(run.status.code(), Some(0));
    let directory_mode = mode_bits(&directory);
    assert_eq!(directory_mode & 0o777, 0o755, "object directory mode");
    let file_mode = mode_bits(&directory.join("normal.txt"));
    assert_eq!(file_mode & 0o777, 0o644, "object file mode");
    cleanup(&parent);
}

#[cfg(unix)]
fn mode_bits(path: &Path) -> u32 {
    match fs::metadata(path) {
        Ok(metadata) => metadata.permissions().mode(),
        Err(error) => {
            eprintln!("cannot stat {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}

#[test]
fn a_destination_that_is_a_file_prints_one_diagnostic_and_exits_zero() {
    let directory = scratch("file-destination");
    let destination = directory.join("plain.txt");
    if let Err(error) = fs::write(&destination, b"not a directory") {
        eprintln!("cannot create the destination file: {error}");
        std::process::exit(1);
    }
    let destination_text = destination.to_string_lossy().into_owned();
    let capture = fixture_path("http-objects.pcap");
    let run = run_export(&capture, &destination_text, &[]);
    assert_eq!(run.status.code(), Some(0));
    assert!(!run.stderr.is_empty(), "a diagnostic is expected");
    assert_eq!(read(&destination), b"not a directory");
    cleanup(&directory);
}

#[test]
fn an_empty_destination_prints_one_diagnostic_and_exits_zero() {
    let capture = fixture_path("http-objects.pcap");
    let arguments = [
        "-r".to_string(),
        capture,
        "--export-objects".to_string(),
        "http,".to_string(),
        "-q".to_string(),
    ];
    let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let run = run(&refs);
    assert_eq!(run.status.code(), Some(0));
    assert!(!run.stderr.is_empty(), "a diagnostic is expected");
    assert!(run.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn an_unwritable_destination_reports_each_object_and_exits_zero() {
    let directory = scratch("readonly");
    let mode = fs::Permissions::from_mode(0o500);
    if fs::set_permissions(&directory, mode).is_err() {
        cleanup(&directory);
        return;
    }
    let probe = directory.join("probe");
    if fs::write(&probe, b"x").is_ok() {
        // Running with privileges that ignore the mode bits.
        let _ = fs::remove_file(&probe);
        let _ = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700));
        cleanup(&directory);
        return;
    }
    let directory_text = directory.to_string_lossy().into_owned();
    let capture = fixture_path("http-objects.pcap");
    let run = run_export(&capture, &directory_text, &[]);
    assert_eq!(run.status.code(), Some(0));
    assert!(
        !run.stderr.is_empty(),
        "one diagnostic per object is expected"
    );
    assert_eq!(exported_names(&directory), Vec::<String>::new());
    let _ = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700));
    cleanup(&directory);
}

#[test]
fn malformed_and_repeated_export_options_exit_one() {
    let capture = fixture_path("http-objects.pcap");
    for value in ["http", ",objects", "bogus,objects", "HTTP,objects"] {
        let run = run(&["-r", &capture, "--export-objects", value, "-q"]);
        assert_eq!(
            run.status.code(),
            Some(1),
            "value {value:?}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(run.stdout.is_empty());
    }
    let directory = scratch("duplicate");
    let directory_text = directory.to_string_lossy().into_owned();
    let run = run(&[
        "-r",
        &capture,
        "--export-objects",
        &format!("http,{directory_text}"),
        "--export-objects",
        &format!("http,{directory_text}"),
        "-q",
    ]);
    assert_eq!(run.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("already specified"),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    cleanup(&directory);
}

#[test]
fn attached_values_extra_commas_and_unimplemented_protocols_are_accepted() {
    let directory = scratch("attached");
    let directory_text = directory.to_string_lossy().into_owned();
    let capture = fixture_path("http-objects.pcap");
    let attached = format!("--export-objects=http,{directory_text}");
    let attached_run = run(&["-r", &capture, &attached, "-q"]);
    assert_eq!(attached_run.status.code(), Some(0));
    let count = exported_names(&directory).len();
    assert_eq!(count, 26, "attached form exports every object");
    cleanup(&directory);

    let comma_directory = scratch("comma");
    let comma_destination = comma_directory.join("out,extra");
    let comma_text = comma_destination.to_string_lossy().into_owned();
    let comma_run = run(&[
        "-r",
        &capture,
        "--export-objects",
        &format!("http,{comma_text}"),
        "-q",
    ]);
    assert_eq!(comma_run.status.code(), Some(0));
    assert_eq!(exported_names(&comma_destination).len(), 26);
    cleanup(&comma_directory);

    let noop_directory = scratch("protocols");
    let http_directory = noop_directory.join("http");
    let imf_directory = noop_directory.join("imf");
    let protocols_run = run(&[
        "-r",
        &capture,
        "--export-objects",
        &format!("http,{}", http_directory.display()),
        "--export-objects",
        &format!("imf,{}", imf_directory.display()),
        "--export-objects",
        &format!("x509af,{}", noop_directory.join("x509af").display()),
        "-q",
    ]);
    assert_eq!(protocols_run.status.code(), Some(0));
    assert!(imf_directory.is_dir(), "the imf directory is created");
    assert!(noop_directory.join("x509af").is_dir());
    assert_eq!(exported_names(&http_directory).len(), 26);
    assert_eq!(exported_names(&imf_directory).len(), 0);
    cleanup(&noop_directory);
}

#[test]
fn a_missing_capture_does_not_create_the_destination() {
    let directory = scratch("missing-capture");
    let destination = directory.join("objects");
    let destination_text = destination.to_string_lossy().into_owned();
    let missing = directory.join("does-not-exist.pcap");
    let missing_text = missing.to_string_lossy().into_owned();
    let run = run(&[
        "-r",
        &missing_text,
        "--export-objects",
        &format!("http,{destination_text}"),
        "-q",
    ]);
    assert_eq!(run.status.code(), Some(3));
    assert!(!destination.exists(), "the destination must not be created");
    cleanup(&directory);
}

#[test]
fn the_packet_limit_stops_export_at_the_same_frame() {
    let directory = scratch("packet-limit");
    let directory_text = directory.to_string_lossy().into_owned();
    let capture = fixture_path("http-objects.pcap");
    let run = run(&[
        "-r",
        &capture,
        "--export-objects",
        &format!("http,{directory_text}"),
        "-c",
        "1",
        "-q",
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(
        exported_names(&directory),
        Vec::<String>::new(),
        "one request frame carries no object"
    );
    cleanup(&directory);
}

#[cfg(unix)]
#[test]
fn a_non_utf8_destination_is_used_verbatim() {
    let parent = scratch("non-utf8");
    let mut bytes = parent.as_os_str().as_bytes().to_vec();
    bytes.push(b'/');
    bytes.extend_from_slice(b"objects\xff");
    let destination = PathBuf::from(OsString::from_vec(bytes));
    let mut value = b"http,".to_vec();
    value.extend_from_slice(destination.as_os_str().as_bytes());
    let capture = fixture_path("http-objects.pcap");
    let arguments = vec![
        OsString::from("-r"),
        OsString::from(capture),
        OsString::from("--export-objects"),
        OsString::from_vec(value),
        OsString::from("-q"),
    ];
    let run = run_os(&arguments);
    assert_eq!(run.status.code(), Some(0));
    if destination.exists() {
        assert_eq!(exported_names(&destination).len(), 26);
    } else {
        // macOS refuses a non-UTF-8 path in the standard library; the run
        // must still exit 0 with one diagnostic.
        assert!(!run.stderr.is_empty());
    }
    cleanup(&parent);
}

/// Build a two-frame pcap with a request and one gzip response body.
fn write_gzip_capture(path: &Path, body: &[u8]) {
    let request = b"GET /bomb.bin HTTP/1.1\r\nHost: h\r\n\r\n";
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);

    let frames = [
        tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 80, 1_000, request),
        tcp_frame([10, 0, 0, 2], [10, 0, 0, 1], 80, 40_000, 5_000, &response),
    ];
    let mut capture = Vec::new();
    capture.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
    capture.extend_from_slice(&2_u16.to_le_bytes());
    capture.extend_from_slice(&4_u16.to_le_bytes());
    capture.extend_from_slice(&0_i32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        capture.extend_from_slice(&(1_000_u32 + index as u32).to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        let length = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(frame);
    }
    if let Err(error) = fs::write(path, capture) {
        eprintln!("cannot write {}: {error}", path.display());
        std::process::exit(1);
    }
}

/// Ethernet II + IPv4 + TCP frame with zero checksums.
fn tcp_frame(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_length = u16::try_from(20_usize.saturating_add(payload.len())).unwrap_or(u16::MAX);
    let total = u16::try_from(20_usize.saturating_add(usize::from(tcp_length))).unwrap_or(u16::MAX);
    let mut datagram = vec![0x45, 0];
    datagram.extend_from_slice(&total.to_be_bytes());
    datagram.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
    datagram.extend_from_slice(&source);
    datagram.extend_from_slice(&destination);
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&sequence.to_be_bytes());
    datagram.extend_from_slice(&1_u32.to_be_bytes());
    datagram.extend_from_slice(&[0x50, 0x18]);
    datagram.extend_from_slice(&65_535_u16.to_be_bytes());
    datagram.extend_from_slice(&[0, 0, 0, 0]);
    datagram.extend_from_slice(payload);

    let mut frame = Vec::with_capacity(14 + datagram.len());
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&datagram);
    frame
}

/// Gzip data that expands to one byte over the export cap.
fn gzip_over_cap() -> Vec<u8> {
    use std::io::{self, Read as _};

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let limit = packetfin_core::export::MAX_EXPORT_OBJECT_BYTES;
    let mut zeros = io::repeat(0).take(limit.saturating_add(1));
    if io::copy(&mut zeros, &mut encoder).is_err() {
        eprintln!("cannot compress the over-cap body");
        std::process::exit(1);
    }
    match encoder.finish() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot finish the gzip stream: {error}");
            std::process::exit(1);
        }
    }
}

#[test]
fn an_over_limit_decompressed_object_is_refused_with_a_diagnostic() {
    let directory = scratch("over-cap");
    let capture = directory.join("over-cap.pcap");
    let body = gzip_over_cap();
    write_gzip_capture(&capture, &body);
    let destination = directory.join("objects");
    let destination_text = destination.to_string_lossy().into_owned();
    let capture_text = capture.to_string_lossy().into_owned();
    let run = run_export(&capture_text, &destination_text, &[]);
    assert_eq!(
        run.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(exported_names(&destination), Vec::<String>::new());
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("export limit"),
        "a refusal diagnostic is expected: {stderr}"
    );
    cleanup(&directory);
}
