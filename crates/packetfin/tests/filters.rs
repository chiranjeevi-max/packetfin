//! End-to-end tests for `-Y` display filters.
//!
//! Every golden case whose id starts with `filter` runs the built binary and
//! compares stdout and the exit status with the golden output.
//! The remaining tests pin the error position, the `-c` read-before-filter
//! semantics and the option forms.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::fixtures;
use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[OsString]) -> Run {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("failed to spawn packetfin: {error}");
            std::process::exit(1);
        }
    };
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to wait for packetfin: {error}");
            std::process::exit(1);
        }
    };
    Run {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn fixture_path(fixture: &fixtures::Fixture) -> PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

fn tcp_handshake() -> Option<PathBuf> {
    fixtures::all()
        .iter()
        .find(|fixture| fixture.name == "tcp-handshake")
        .map(fixture_path)
}

fn ethernet_udp() -> Option<PathBuf> {
    fixtures::all()
        .iter()
        .find(|fixture| fixture.name == "ethernet-udp-le-us")
        .map(fixture_path)
}

fn error_line(stderr: &str) -> Option<(&str, &str)> {
    let mut lines = stderr.lines();
    let mut previous = lines.next()?;
    for line in lines {
        if line.trim_start().starts_with('^') {
            return Some((previous, line));
        }
        previous = line;
    }
    None
}

#[test]
fn filter_cases_match_stored_goldens() -> Result<(), String> {
    let mut failures = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("filter") {
                continue;
            }
            let relative = fixture.relative_path();
            let absolute = fixture_path(fixture);
            let args: Vec<OsString> = case
                .args
                .iter()
                .map(|argument| {
                    if argument == &relative {
                        absolute.as_os_str().to_owned()
                    } else if !std::path::Path::new(argument).is_absolute()
                        && let Some(rest) = argument.strip_prefix("tests/fixtures/")
                    {
                        packetfin_testkit::golden::fixtures_dir()
                            .join(rest)
                            .into_os_string()
                    } else if !std::path::Path::new(argument).is_absolute()
                        && let Some((prefix, rest)) = argument.split_once("tests/fixtures/")
                    {
                        let mut resolved = OsString::from(prefix);
                        resolved.push(packetfin_testkit::golden::fixtures_dir().join(rest));
                        resolved
                    } else {
                        OsString::from(argument.clone())
                    }
                })
                .collect();
            let run = run(&args);
            let status = run.status.code().unwrap_or(-1);
            if let Err(message) =
                golden::compare_golden_stdout_status(fixture.name, case.id, &run.stdout, status)
            {
                failures.push(message);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        let mut writer = std::io::stdout();
        for failure in &failures {
            let _ = writeln!(writer, "{failure}");
        }
        Err(format!("{} filter golden case(s) differ", failures.len()))
    }
}

#[test]
fn unknown_field_exits_four_and_underlines_its_token() {
    let Some(path) = ethernet_udp() else {
        eprintln!("no ethernet-udp-le-us fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-Y"),
        OsString::from("ip.nope == 1"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
    ]);
    assert_eq!(run.status.code(), Some(4));
    assert!(run.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&run.stderr);
    let Some((filter_line, caret_line)) = error_line(&stderr) else {
        eprintln!("no caret line in: {stderr}");
        std::process::exit(1);
    };
    assert_eq!(filter_line.trim_end(), "    ip.nope == 1");
    let carets = caret_line.trim_start_matches(' ');
    assert_eq!(carets, "^^^^^^^");
    assert_eq!(caret_line.find('^'), Some(4));
}

#[test]
fn unknown_field_after_a_prefix_keeps_its_column() {
    let Some(path) = tcp_handshake() else {
        eprintln!("no tcp-handshake fixture");
        std::process::exit(1);
    };
    let filter = "frame.number == 1 and nope";
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-Y"),
        OsString::from(filter),
    ]);
    assert_eq!(run.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&run.stderr);
    let Some((filter_line, caret_line)) = error_line(&stderr) else {
        eprintln!("no caret line in: {stderr}");
        std::process::exit(1);
    };
    assert_eq!(filter_line.trim_end(), format!("    {filter}"));
    assert_eq!(
        caret_line.find('^'),
        Some(4 + filter.find("nope").unwrap_or(0))
    );
    let carets = caret_line.trim_start_matches(' ');
    assert_eq!(carets, "^^^^");
}

#[test]
fn count_limits_read_packets_before_the_filter() {
    let Some(path) = tcp_handshake() else {
        eprintln!("no tcp-handshake fixture");
        std::process::exit(1);
    };
    let with_count = |count: &str| {
        run(&[
            OsString::from("-n"),
            OsString::from("-c"),
            OsString::from(count),
            OsString::from("-Y"),
            OsString::from("frame.number == 2"),
            OsString::from("-T"),
            OsString::from("fields"),
            OsString::from("-e"),
            OsString::from("frame.number"),
            OsString::from("-r"),
            path.as_os_str().to_owned(),
        ])
    };
    let one = with_count("1");
    assert_eq!(one.status.code(), Some(0));
    assert!(one.stdout.is_empty(), "-c 1 read frame 2 before filtering");

    let two = with_count("2");
    assert_eq!(two.status.code(), Some(0));
    assert_eq!(two.stdout, b"2\n");
}

#[test]
fn invalid_filters_are_checked_before_the_capture_is_opened() {
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        OsString::from("/definitely/not/a/capture.pcap"),
        OsString::from("-Y"),
        OsString::from("ip.nope"),
    ]);
    assert_eq!(run.status.code(), Some(4));
}

#[test]
fn unknown_output_fields_keep_their_exit_code() {
    let Some(path) = ethernet_udp() else {
        eprintln!("no ethernet-udp-le-us fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("not.a.field"),
        OsString::from("-Y"),
        OsString::from("ip.nope"),
    ]);
    assert_eq!(run.status.code(), Some(1));
}

#[test]
fn attached_and_detached_display_filters_select_the_same_frames() {
    let Some(path) = ethernet_udp() else {
        eprintln!("no ethernet-udp-le-us fixture");
        std::process::exit(1);
    };
    let detached = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
        OsString::from("-Y"),
        OsString::from("ip.src == 192.0.2.1"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
    ]);
    let attached = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-Yip.src == 192.0.2.1"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
    ]);
    assert_eq!(detached.status.code(), Some(0));
    assert_eq!(attached.status.code(), Some(0));
    assert_eq!(detached.stdout, attached.stdout);
    assert_eq!(detached.stdout, b"1\n");
}
#[test]
fn invalid_literal_classification_exits_four_before_opening() {
    for filter in [
        "eth.dst contains 0",
        "eth.dst contains 00",
        "eth.dst contains 0x00",
        "frame.interface_name == 123",
        "frame.interface_name == and",
        "frame.interface_name in {0}",
        "ip.src in {192.0.2.0/+24}",
        "eth.dst contains \"\"",
        "eth.dst contains \"\\x02\"",
        "eth.dst contains 02:00:00:00:00:02:03",
        "frame.interface_name == -08",
        "frame.interface_name contains -abc",
        "frame.interface_name in {-08}",
        "sll.unused contains +0",
        "frame.interface_name contains +eth0",
        "frame.interface_name contains +0o10",
        "frame.interface_name == +",
        "frame.interface_name in {+}",
    ] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-r"),
            OsString::from("/definitely/not/a/capture.pcap"),
            OsString::from("-Y"),
            OsString::from(filter),
        ]);
        assert_eq!(run.status.code(), Some(4), "{filter}");
    }
}

#[test]
fn protocol_slices_exit_four_with_their_position() {
    let Some(path) = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == "ntp-client-server")
        .map(fixture_path)
    else {
        eprintln!("no ntp-client-server fixture");
        std::process::exit(1);
    };
    for filter in ["frame[0:1] == 02", "eth[0:1] == 02"] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-Y"),
            OsString::from(filter),
        ]);
        assert_eq!(run.status.code(), Some(4), "{filter}");
        assert!(run.stdout.is_empty(), "{filter}");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            stderr.contains("protocol cannot be sliced into a sequence of bytes"),
            "{filter}: {stderr}"
        );
        let Some((filter_line, caret_line)) = error_line(&stderr) else {
            eprintln!("no caret line for {filter}: {stderr}");
            std::process::exit(1);
        };
        let name = filter.split('[').next().unwrap_or_default();
        assert_eq!(filter_line.trim_end(), format!("    {filter}"));
        let column = 4 + filter.find(name).unwrap_or(0);
        assert_eq!(caret_line.find('^'), Some(column), "{filter}");
        assert_eq!(
            caret_line.trim_start_matches(' ').trim_end(),
            "^".repeat(name.len()),
            "{filter}"
        );
    }
}

#[test]
fn relative_time_arithmetic_scales_a_scalar_operand_in_seconds() {
    let Some(path) = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == "tcp-analysis")
        .map(fixture_path)
    else {
        eprintln!("no tcp-analysis fixture");
        std::process::exit(1);
    };
    let matches = |filter: &str| -> String {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-Y"),
            OsString::from(filter),
            OsString::from("-T"),
            OsString::from("fields"),
            OsString::from("-e"),
            OsString::from("frame.number"),
        ]);
        assert_eq!(run.status.code(), Some(0), "{filter}");
        String::from_utf8_lossy(&run.stdout).into_owned()
    };
    // Every frame after the first has a 0.0005 s delta, so a scalar is a
    // count of seconds: dividing by two yields a non-zero offset.
    assert_eq!(matches("frame.time_delta / 2 == 0"), "", "division by two");
    assert_eq!(
        matches("frame.time_delta / 2 == 0.00025").lines().count(),
        61,
        "division by two in seconds"
    );
    let doubled = matches("frame.time_delta * 2 == 0.001");
    assert_eq!(doubled.lines().next(), Some("2"), "doubled delta");
    assert_eq!(doubled.lines().last(), Some("62"), "doubled delta");
    assert_eq!(doubled.lines().count(), 61, "doubled delta");
}
