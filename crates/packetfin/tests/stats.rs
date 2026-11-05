//! End-to-end tests for `-z` statistics.
//!
//! Golden cases whose id starts with `stats` run the built binary and compare
//! stdout and the exit status against the golden output. Packetfin's own
//! statistics validation, name list and table order are checked with direct
//! assertions instead.

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

fn stats_fixture(name: &str) -> &'static fixtures::Fixture {
    let Some(fixture) = fixtures::all().iter().find(|fixture| fixture.name == name) else {
        eprintln!("no {name} fixture");
        std::process::exit(1);
    };
    fixture
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn stats_cases_match_stored_goldens() -> Result<(), String> {
    let mut failures = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !(case.id.starts_with("stats")
                || case.id.starts_with("follow")
                || case.id.starts_with("dns-tree")
                || case.id.starts_with("http-tree")
                || case.id == "tls-streams")
            {
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
        Err(format!("{} stats golden case(s) differ", failures.len()))
    }
}

#[test]
fn help_lists_the_supported_statistics() {
    let run = run(&[OsString::from("-z"), OsString::from("help")]);
    assert_eq!(run.status.code(), Some(0));
    let stderr = text(&run.stderr);
    assert!(
        stderr.contains("The available statistics for the \"-z\" option are:"),
        "{stderr}"
    );
    for name in [
        "conv,eth",
        "conv,ip",
        "conv,ipv6",
        "conv,sll",
        "conv,tcp",
        "conv,udp",
        "endpoints,eth",
        "endpoints,ip",
        "endpoints,ipv6",
        "endpoints,sll",
        "endpoints,tcp",
        "endpoints,udp",
        "dns,tree",
        "expert",
        "follow,http",
        "follow,tcp",
        "follow,tls",
        "follow,udp",
        "http,tree",
        "io,phs",
        "io,stat",
    ] {
        assert!(stderr.lines().any(|line| line.trim() == name), "{name}");
    }
    assert!(!stderr.contains("follow,dccp"), "{stderr}");
}

#[test]
fn unknown_statistics_list_the_supported_names() {
    let fixture = stats_fixture("stats-one");
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        fixture_path(fixture).into_os_string(),
        OsString::from("-z"),
        OsString::from("io,bogus"),
    ]);
    assert_eq!(run.status.code(), Some(1));
    assert!(run.stdout.is_empty());
    let stderr = text(&run.stderr);
    assert!(
        stderr.contains("Invalid -z argument \"io,bogus\"; it must be one of:"),
        "{stderr}"
    );
    assert!(
        stderr.lines().any(|line| line.trim() == "io,phs"),
        "{stderr}"
    );
    assert!(
        stderr.lines().any(|line| line.trim() == "io,stat"),
        "{stderr}"
    );
}

#[test]
fn invalid_filters_and_intervals_fail_before_reading() {
    let fixture = stats_fixture("stats-one");
    let path = fixture_path(fixture);
    for (spec, message) in [
        (
            "io,phs,bogus",
            "Filter \"bogus\" is invalid - \"bogus\" is not a valid protocol or protocol field.",
        ),
        (
            "conv,tcp,bogus",
            "Filter \"bogus\" is invalid - \"bogus\" is not a valid protocol or protocol field.",
        ),
        (
            "endpoints,ip,bogus",
            "Filter \"bogus\" is invalid - \"bogus\" is not a valid protocol or protocol field.",
        ),
        ("io,stat,1us", "invalid \"-z io,stat"),
        ("io,stat,0,", "invalid \"-z io,stat"),
        (
            "io,stat,0.0000001",
            "\"-z\" interval must be >=0.000001 seconds or \"0\" for the entire capture duration.",
        ),
    ] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-q"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-z"),
            OsString::from(spec),
        ]);
        assert_eq!(run.status.code(), Some(1), "{spec}");
        assert!(run.stdout.is_empty(), "{spec}");
        assert!(
            text(&run.stderr).contains(message),
            "{spec}: {}",
            text(&run.stderr)
        );
    }
}

#[test]
fn tables_print_in_category_order_and_reverse_command_line_order() {
    let fixture = stats_fixture("stats-conv");
    let path = fixture_path(fixture);
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-z"),
        OsString::from("conv,tcp"),
        OsString::from("-z"),
        OsString::from("io,phs"),
        OsString::from("-z"),
        OsString::from("endpoints,ip"),
        OsString::from("-z"),
        OsString::from("io,stat,0"),
        OsString::from("-z"),
        OsString::from("conv,udp"),
        OsString::from("-z"),
        OsString::from("endpoints,tcp"),
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    let find = |needle: &str| match stdout.find(needle) {
        Some(index) => index,
        None => {
            eprintln!("missing {needle:?} in {stdout}");
            std::process::exit(1);
        }
    };
    let io_stat = find("| IO Statistics");
    let io_phs = find("Protocol Hierarchy Statistics");
    let endpoints_tcp = find("TCP Endpoints");
    let endpoints_ip = find("IPv4 Endpoints");
    let conv_udp = find("UDP Conversations");
    let conv_tcp = find("TCP Conversations");
    assert!(io_stat < io_phs, "io,stat before io,phs");
    assert!(io_phs < endpoints_tcp, "io,phs before endpoints");
    assert!(endpoints_tcp < endpoints_ip, "endpoints reverse CLI order");
    assert!(endpoints_ip < conv_udp, "endpoints before conversations");
    assert!(conv_udp < conv_tcp, "conversations reverse CLI order");
}

#[test]
fn quiet_suppresses_packets_but_keeps_statistics() {
    let fixture = stats_fixture("stats-one");
    let path = fixture_path(fixture);
    let quiet = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.clone().into_os_string(),
        OsString::from("-z"),
        OsString::from("io,phs"),
    ]);
    let stdout = text(&quiet.stdout);
    assert!(!stdout.contains("Who has"), "{stdout}");
    assert!(stdout.contains("Protocol Hierarchy Statistics"), "{stdout}");

    let loud = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-z"),
        OsString::from("io,phs"),
    ]);
    let stdout = text(&loud.stdout);
    assert!(stdout.contains("Who has"), "{stdout}");
    assert!(stdout.contains("Protocol Hierarchy Statistics"), "{stdout}");
    assert!(
        stdout.find("Who has").unwrap_or(usize::MAX)
            < stdout.find("Protocol Hierarchy Statistics").unwrap_or(0),
        "packets print first"
    );
}

#[test]
fn display_filter_errors_win_over_stats_errors() {
    let fixture = stats_fixture("stats-one");
    let path = fixture_path(fixture);
    let display_error = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.clone().into_os_string(),
        OsString::from("-Y"),
        OsString::from("bogus"),
        OsString::from("-z"),
        OsString::from("io,phs,bogus"),
    ]);
    assert_eq!(
        display_error.status.code(),
        Some(4),
        "{}",
        text(&display_error.stderr)
    );
    assert!(
        text(&display_error.stderr).contains("bogus"),
        "{}",
        text(&display_error.stderr)
    );

    let unknown = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-Y"),
        OsString::from("bogus"),
        OsString::from("-z"),
        OsString::from("io,bogus"),
    ]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(
        text(&unknown.stderr).contains("Invalid -z argument \"io,bogus\""),
        "{}",
        text(&unknown.stderr)
    );
}

#[test]
fn a_long_multibyte_column_label_does_not_panic() {
    let fixture = stats_fixture("stats-one");
    let label = format!("dns.qry.name==\"a{}\"", "ü".repeat(40));
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        fixture_path(fixture).into_os_string(),
        OsString::from("-z"),
        OsString::from(format!("io,stat,1,{label}")),
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert!(
        text(&run.stdout).contains("Col  1:"),
        "{}",
        text(&run.stdout)
    );
}

#[test]
fn statistics_print_before_a_capture_read_error() {
    let fixture = stats_fixture("stats-truncated-read");
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        fixture_path(fixture).into_os_string(),
        OsString::from("-z"),
        OsString::from("io,phs"),
    ]);
    assert_eq!(run.status.code(), Some(14), "{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    assert!(stdout.contains("Protocol Hierarchy Statistics"), "{stdout}");
    assert!(stdout.contains("frames:1 bytes:42"), "{stdout}");
    assert!(!run.stderr.is_empty(), "the read error is still reported");
}

#[test]
fn empty_capture_prints_headers_and_exits_zero() {
    let fixture = stats_fixture("stats-empty");
    let path = fixture_path(fixture);
    for spec in [
        "io,phs",
        "io,stat,0",
        "conv,tcp",
        "endpoints,ip",
        "dns,tree",
        "http,tree",
    ] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-q"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-z"),
            OsString::from(spec),
        ]);
        assert_eq!(run.status.code(), Some(0), "{spec}");
        assert!(!run.stdout.is_empty(), "{spec}");
    }
    let expert = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-z"),
        OsString::from("expert"),
    ]);
    assert_eq!(expert.status.code(), Some(0));
    assert!(expert.stdout.is_empty());
}

fn fixture_path_named(name: &str) -> PathBuf {
    let fixture = stats_fixture(name);
    fixture_path(fixture)
}

#[test]
fn write_mode_still_prints_statistics() {
    let path = fixture_path_named("dns-tree");
    let written =
        std::env::temp_dir().join(format!("packetfin-stats-write-{}.pcap", std::process::id()));
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-w"),
        written.clone().into_os_string(),
        OsString::from("-z"),
        OsString::from("dns,tree"),
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    assert!(stdout.contains("DNS:"), "{stdout}");
    assert!(
        std::fs::metadata(&written).is_ok_and(|meta| meta.len() > 0),
        "the capture file is written"
    );
    let _ = std::fs::remove_file(written);
}

#[test]
fn invalid_follow_specifications_exit_one() {
    let path = fixture_path_named("follow-tcp");
    for (spec, message) in [
        ("follow,tcp,bogus,0", "Invalid display mode."),
        ("follow,tcp,ascii", "Invalid address."),
        ("follow,tcp,,0", "Invalid display mode."),
        ("follow,tcp", "Invalid display mode."),
        ("follow,tcp,ascii,0,0-1", "Invalid range value."),
        ("follow,tcp,ascii,0,abc", "Invalid range."),
        ("follow,tcp,ascii,0,", "Invalid range."),
        (
            "follow,tcp,ascii,10.0.0.1:1,[::1]:2",
            "Mismatched IP address types.",
        ),
        ("follow,tcp,ascii,0,1,2", "Invalid parameter."),
        ("follow,tcp,ascii,0,1-", "Invalid parameter."),
        ("follow,tcp,ascii,0,1-2-3", "Invalid parameter."),
        ("follow,nosuch,ascii,0", "Invalid -z argument"),
    ] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-q"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-z"),
            OsString::from(spec),
        ]);
        assert_eq!(run.status.code(), Some(1), "{spec}");
        assert!(run.stdout.is_empty(), "{spec}");
        assert!(
            text(&run.stderr).contains(message),
            "{spec}: {}",
            text(&run.stderr)
        );
    }
}

#[test]
fn invalid_tree_filters_exit_one() {
    let path = fixture_path_named("dns-tree");
    for spec in ["dns,tree,bogus", "http,tree,bogus"] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-q"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-z"),
            OsString::from(spec),
        ]);
        assert_eq!(run.status.code(), Some(1), "{spec}");
        assert!(run.stdout.is_empty(), "{spec}");
        assert!(text(&run.stderr).contains("is not a valid protocol or protocol field"));
    }
}

#[test]
fn follow_diagnostics_keep_the_reference_secondary_lines() {
    let path = fixture_path_named("follow-tcp");
    for (spec, expected) in [
        (
            "follow,tcp,ascii,0,",
            "packetfin: Invalid range.\npacketfin: Invalid parameter.\n",
        ),
        (
            "follow,tcp,,0",
            "packetfin: Invalid display mode.\npacketfin: Invalid address.\npacketfin: Invalid range.\npacketfin: Invalid parameter.\n",
        ),
    ] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-q"),
            OsString::from("-r"),
            path.clone().into_os_string(),
            OsString::from("-z"),
            OsString::from(spec),
        ]);
        assert_eq!(run.status.code(), Some(1), "{spec}");
        assert_eq!(text(&run.stderr), expected, "{spec}");
    }
    let accepted = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-z"),
        OsString::from("follow,tcp,ascii,0,-2"),
    ]);
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "{}",
        text(&accepted.stderr)
    );
    assert!(
        !text(&accepted.stdout).contains("one"),
        "{}",
        text(&accepted.stdout)
    );
}

#[test]
fn follow_tables_print_in_reverse_command_line_order() {
    let path = fixture_path_named("follow-tcp");
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-z"),
        OsString::from("follow,tcp,ascii,0"),
        OsString::from("-z"),
        OsString::from("follow,tcp,ascii,1"),
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    let stream0 = stdout.find("Filter: tcp.stream eq 0").unwrap_or(usize::MAX);
    let stream1 = stdout.find("Filter: tcp.stream eq 1").unwrap_or(usize::MAX);
    assert!(stream1 < stream0, "{stdout}");
}

#[test]
fn follow_ignores_the_display_filter() {
    let path = fixture_path_named("follow-tcp");
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-q"),
        OsString::from("-Y"),
        OsString::from("frame.number == 1"),
        OsString::from("-r"),
        path.into_os_string(),
        OsString::from("-z"),
        OsString::from("follow,tcp,ascii,0"),
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    assert!(stdout.contains("one\ntwo\n"), "{stdout}");
    assert!(stdout.contains("four\n"), "{stdout}");
}

/// One Ethernet/IPv4/UDP frame whose source address identifies the flow.
fn flow_frame(index: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&36_u16.to_be_bytes());
    frame.extend_from_slice(&[0, 1]);
    frame.extend_from_slice(&[0x40, 0]);
    frame.extend_from_slice(&[64, 17]);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[10, (index >> 16) as u8, (index >> 8) as u8, index as u8]);
    frame.extend_from_slice(&[203, 0, 113, 1]);
    frame.extend_from_slice(&5000_u16.to_be_bytes());
    frame.extend_from_slice(&6000_u16.to_be_bytes());
    frame.extend_from_slice(&8_u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&[0; 8]);
    frame
}

fn flow_capture(count: u32) -> Result<Vec<u8>, String> {
    use packetfin_testkit::pcap::Pcap;
    use packetfin_testkit::{ByteOrder, Timestamp, TimestampResolution};
    let mut capture = Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond);
    for index in 0..count {
        capture.push(
            Timestamp::new(
                1_700_000_000 + u64::from(index / 1_000_000),
                index % 1_000_000,
            ),
            flow_frame(index),
        )?;
    }
    capture.to_bytes()
}

fn conversation_rows(stdout: &[u8]) -> usize {
    text(stdout)
        .lines()
        .filter(|line| line.contains(" <-> "))
        .count()
}

#[test]
fn stats_budget_caps_a_flow_flood() -> Result<(), String> {
    let count = 20_000_u32;
    let directory =
        std::env::temp_dir().join(format!("packetfin-stats-budget-{}", std::process::id()));
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let capture = directory.join("flows.pcap");
    std::fs::write(&capture, flow_capture(count)?).map_err(|error| error.to_string())?;

    let base = [
        OsString::from("-q"),
        OsString::from("-z"),
        OsString::from("conv,udp"),
        OsString::from("-r"),
        capture.as_os_str().to_owned(),
    ];
    let mut capped_args = base.to_vec();
    capped_args.extend([OsString::from("--pf-stats-budget"), OsString::from("65536")]);
    let capped = run(&capped_args);
    assert_eq!(capped.status.code(), Some(0), "{}", text(&capped.stderr));
    assert!(
        text(&capped.stderr)
            .contains("statistics budget reached; the oldest conversation rows were dropped"),
        "stderr: {}",
        text(&capped.stderr)
    );
    let kept = conversation_rows(&capped.stdout);
    assert!(kept > 0, "a 64 KiB budget should still print rows");
    assert!(
        kept < usize::try_from(count).unwrap_or(usize::MAX),
        "the budget must drop rows: {kept} rows"
    );
    assert!(
        kept <= 128,
        "a 64 KiB budget retained {kept} rows; the charge is too small"
    );

    let full = run(&base);
    assert_eq!(full.status.code(), Some(0), "{}", text(&full.stderr));
    assert_eq!(
        conversation_rows(&full.stdout),
        usize::try_from(count).unwrap_or(usize::MAX)
    );

    std::fs::remove_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(())
}
