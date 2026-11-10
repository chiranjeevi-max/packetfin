//! End-to-end tests for `-T fields` frame and link-layer output.
//!
//! Every `frame-fields`, `interface-fields`, `eth-fields` and `link-fields`
//! golden case runs the built binary and compares stdout and the exit status.
//! Summary cases are skipped until protocol summaries exist.

use std::ffi::OsString;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::fixtures::{self, Fixture};
use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

/// Golden case ids that this test runs. Summary cases are skipped until
/// protocol summaries exist.
const FIELD_CASE_IDS: &[&str] = &[
    "frame-fields",
    "lldp-8023-fields",
    "interface-fields",
    "eth-fields",
    "link-fields",
    "arp-fields",
    "ip-fields",
    "ip-option-fields",
    "ip-checksum-fields",
    "tso-fields",
    "tso-checksum",
    "tso-truncated-fields",
    "tso-truncated-checksum",
    "ipv6-fields",
    "fragment-fields",
    "ipv6-fragment-fields",
    "fragment-fields-defragment-off",
    "ipv6-fragment-fields-defragment-off",
    "udp-fields",
    "udp-time-fields",
    "udp-checksum-fields",
    "dns-fields",
    "dns-link-fields",
    "dns-link-fields-two-pass",
    "dns-link-fields-r-queries",
    "dns-link-fields-r-responses",
    "dns-link-fields-r-c2",
    "dns-link-fields-c1",
    "dns-link-fields-c2",
    "dns-link-fields-c3",
    "dns-link-fields-m1",
    "dns-link-fields-m2",
    "dns-link-fields-m3",
    "dns-link-r-literal",
    "dns-link-r-literal-rejected",
    "dns-link-r-retrans-literal",
    "dns-link-missing-two-pass",
    "dns-link-truncated-one-pass",
    "dns-link-truncated-two-pass",
    "dns-tcp-fields",
    "http-fields",
    "tls-fields",
    "bgp-fields",
    "tls-edge-fields",
    "http-edge-fields",
    "bgp-overlong-fields",
    "http2-fields",
    "http2-links",
    "filter-http2",
    "filter-method",
    "decode-as",
    "decode-as-summary",
    "syslog-fields",
    "sflow-fields",
    "cflow-fields",
    "cflow-fields-before-refresh",
    "cflow-fields-before-withdrawal-data",
    "snmp-fields",
    "dhcp-fields",
    "dhcpv6-fields",
    "ntp-fields",
    "tcp-fields",
    "tcp-option-fields",
    "tcp-checksum-fields",
    "sack-relative",
    "stream-fields",
    "analysis-fields",
    "analysis-absolute",
    "analysis-disabled",
    "analysis-no-tracking",
    "analysis-no-timestamps",
    "desegment-disabled",
    "window-fields",
    "window-default-scaling",
    "syn-option-absent",
    "relative-false",
    "reassembly-fields",
    "split-fields",
    "fin-fields",
    "dns-split-fields",
    "http-split-fields",
    "tls-split-fields",
    "bgp-split-fields",
    "link-fields",
    "link-fields-two-pass",
    "link-fields-two-pass-r",
    "link-fields-r",
    "link-fields-r-responses",
    "link-fields-r-requests",
    "link-fields-two-pass-json",
    "pdml-link-fields-two-pass",
    "link-fields-two-pass-r-requests",
    "link-fields-two-pass-c2",
    "json-link-fields-two-pass",
    "icmp-fields",
    "icmp-quoted-fields",
    "icmpv6-fields",
    "icmpv6-nd-fields",
    "icmpv6-quoted-fields",
    "icmpv6-options-fields",
    "lldp-fields",
    "stp-fields",
    "lacp-fields",
    "marker-fields",
    "slow-fields",
    "llc-fields",
    "gre-fields",
    "erspan-fields",
    "vxlan-fields",
    "geneve-fields",
    "mpls-fields",
    "ip-tunnel-fields",
    "ospf-fields",
    "ospf3-fields",
    "vrrp-fields",
    "bfd-fields",
    "header-bom",
    "field-defaults",
    "field-escape-off",
    "field-quote-double",
    "field-quote-single",
    "field-separator-comma",
    "field-separator-space",
    "field-aggregator-space",
    "field-occurrence-first",
    "field-occurrence-last",
    "field-header",
    "field-bom",
    "field-header-bom",
    "field-escape-off-quote-double",
    "field-escape-off-quote-single",
    "field-aggregator-tab",
    "field-backslash-aggregator",
    "field-backslash-separator",
    "field-duplicates",
    "field-count-one",
    "field-count-two",
    "field-count-over",
    "field-flush",
    "field-quiet",
    "field-only-errors",
    "field-quiet-flush",
    "field-invalid-option",
    "field-invalid-value",
    "field-invalid-separator",
    "field-count-zero",
    "field-count-negative",
    "field-count-text",
    "eth-names-fields",
    "eth-names-fields-n",
    "udp-names-ports-fields",
    "ip-names-nrb-fields",
    "ip-names-hosts-fields",
    "ip-names-dns-fields",
    "ip-names-sni-fields",
    "decode-as-tcp-dns-fields",
    "decode-as-range-fields",
    "decode-as-length-fields",
    "decode-as-data-fields",
    "decode-as-last-wins-fields",
    "decode-as-reject-fields",
    "decode-as-heuristic-off-fields",
    "decode-as-heuristic-on-fields",
    "cflow-prefs-fields",
    "cflow-default-fields",
    "ipv6-ext-forced-data-fields",
    "ipv6-ext-forced-hopopts-fields",
    "decode-as-overlap-fields",
    "http-body",
];

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[OsString]) -> Run {
    run_with_input(args, None)
}

fn run_with_input(args: &[OsString], input: Option<&[u8]>) -> Run {
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

fn status_code(status: ExitStatus) -> Option<i32> {
    status.code()
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

fn fixture_path(fixture: &Fixture) -> std::path::PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

/// Build `-n -T fields -e FIELD... -r PATH`.
fn field_args(path: &Path, fields: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("fields"),
    ];
    for field in fields {
        args.push(OsString::from("-e"));
        args.push(OsString::from(field));
    }
    args.push(OsString::from("-r"));
    args.push(path.as_os_str().to_owned());
    args
}

fn fixture_field_args(fixture: &Fixture, fields: &[&str]) -> Vec<OsString> {
    field_args(&fixture_path(fixture), fields)
}

fn assert_exit_one(args: &[OsString]) {
    let run = run(args);
    assert_eq!(
        status_code(run.status),
        Some(1),
        "expected status 1; stderr: {}",
        stderr_text(&run)
    );
    assert!(
        run.stdout.is_empty(),
        "stdout must be empty: {:?}",
        String::from_utf8_lossy(&run.stdout)
    );
    assert!(
        !run.stderr.is_empty(),
        "stderr must explain the command-line error"
    );
}

#[test]
fn golden_frame_field_cases_match() {
    let mut compared = 0_usize;
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if case.id.starts_with("summary")
                || case.id.starts_with("filter")
                || case.id.starts_with("detail")
                || case.id.starts_with("hexdump")
                || case.id.starts_with("print-")
                || case.id.starts_with("sep-")
                || case.id.starts_with("json")
                || case.id.starts_with("pdml")
                || case.id.starts_with("psml")
                || case.id.starts_with("ek")
                || case.id == "ps"
                || case.id.starts_with("ps-")
                || case.id.starts_with("tabs")
                || case.id.starts_with("stats")
                || case.id.starts_with("follow")
                || case.id.starts_with("dns-tree")
                || case.id.starts_with("http-tree")
                || case.id == "tls-streams"
                || case.id.starts_with("write")
            {
                continue;
            }
            assert!(
                FIELD_CASE_IDS.contains(&case.id),
                "unexpected golden case {} for {}",
                case.id,
                fixture.name
            );

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
                        OsString::from(argument)
                    }
                })
                .collect();

            let run = run(&args);
            let comparison = golden::compare_golden_stdout_status(
                fixture.name,
                case.id,
                &run.stdout,
                status_code(run.status).unwrap_or(-1),
            );
            if let Err(message) = &comparison {
                eprintln!("{message}");
                eprintln!(
                    "observed stdout: {:?}",
                    String::from_utf8_lossy(&run.stdout)
                );
                eprintln!("observed stderr: {}", stderr_text(&run));
            }
            assert!(
                comparison.is_ok(),
                "golden comparison failed for {}/{}",
                fixture.name,
                case.id
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no frame-field golden cases were compared");
}

#[test]
fn truncated_fixture_exits_fourteen_with_empty_stdout() {
    let run = run(&fixture_field_args(fixture("truncated"), &["frame.number"]));
    assert_eq!(
        status_code(run.status),
        Some(14),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(!run.stderr.is_empty(), "stderr must explain the truncation");
}

#[test]
fn garbage_fixture_exits_three_with_empty_stdout() {
    let run = run(&fixture_field_args(fixture("garbage"), &["frame.number"]));
    assert_eq!(
        status_code(run.status),
        Some(3),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(!run.stderr.is_empty(), "stderr must explain the input");
}

#[test]
fn empty_fixture_exits_zero_with_no_frames() {
    let run = run(&fixture_field_args(fixture("empty"), &["frame.number"]));
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(run.stderr.is_empty(), "stderr: {}", stderr_text(&run));
}

#[test]
fn snaplen_fixture_prints_original_and_captured_lengths() {
    let run = run(&fixture_field_args(
        fixture("snaplen-truncated"),
        &[
            "frame.number",
            "frame.len",
            "frame.cap_len",
            "frame.time_epoch",
        ],
    ));
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, b"1\t1500\t60\t1700000000.123456000\n".to_vec());
}

#[test]
fn standard_input_matches_golden() {
    let fixture = fixture("ethernet-udp-le-us");
    let bytes = match fixture.build() {
        Ok(bytes) => bytes,
        Err(message) => {
            eprintln!("failed to build {}: {message}", fixture.name);
            std::process::exit(1);
        }
    };
    let expected = match golden::load(fixture.name, "frame-fields") {
        Ok(golden) => golden,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    };
    let args: Vec<OsString> = [
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
        "-r",
        "-",
    ]
    .iter()
    .map(|argument| OsString::from(*argument))
    .collect();

    let run = run_with_input(&args, Some(&bytes));
    assert_eq!(
        status_code(run.status),
        Some(expected.status),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, expected.stdout);
    assert!(run.stderr.is_empty(), "stderr: {}", stderr_text(&run));
}

#[test]
fn unknown_field_exits_one_and_names_the_field() {
    let run = run(&fixture_field_args(
        fixture("ethernet-udp-le-us"),
        &["frame.bogus"],
    ));
    assert_eq!(
        status_code(run.status),
        Some(1),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        stderr_text(&run).contains("frame.bogus"),
        "stderr must name the field: {}",
        stderr_text(&run)
    );
}

#[test]
fn missing_file_exits_three() {
    let path = golden::fixtures_dir().join("does-not-exist.pcap");
    let run = run(&field_args(&path, &["frame.number"]));
    assert_eq!(
        status_code(run.status),
        Some(3),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        !run.stderr.is_empty(),
        "stderr must explain the open failure"
    );
}

#[test]
fn missing_or_invalid_option_combinations_exit_one() {
    let path = fixture_path(fixture("ethernet-udp-le-us"))
        .as_os_str()
        .to_owned();

    let cases: Vec<Vec<OsString>> = vec![
        // -T fields without -e.
        vec![
            OsString::from("-T"),
            OsString::from("fields"),
            OsString::from("-r"),
            path.clone(),
        ],
        // -e without -T.
        vec![
            OsString::from("-e"),
            OsString::from("frame.number"),
            OsString::from("-r"),
            path.clone(),
        ],
        // Missing values.
        vec![OsString::from("-T")],
        vec![OsString::from("-r")],
        vec![
            OsString::from("-T"),
            OsString::from("fields"),
            OsString::from("-r"),
            path.clone(),
            OsString::from("-e"),
        ],
        // Unsupported -T value.
        vec![
            OsString::from("-T"),
            OsString::from("text"),
            OsString::from("-e"),
            OsString::from("frame.number"),
            OsString::from("-r"),
            path,
        ],
    ];

    for args in &cases {
        assert_exit_one(args);
    }
}

#[test]
fn attached_option_forms_work() {
    let path = fixture_path(fixture("ethernet-udp-le-us"));
    let mut read_file = OsString::from("--read-file=");
    read_file.push(path.as_os_str());
    let args = vec![
        OsString::from("-n"),
        OsString::from("-Tfields"),
        OsString::from("-eframe.number"),
        OsString::from("-eframe.cap_len"),
        read_file,
    ];

    let run = run(&args);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, b"1\t51\n".to_vec());
    assert!(run.stderr.is_empty(), "stderr: {}", stderr_text(&run));
}

#[test]
fn fields_keep_command_line_order() {
    let run = run(&fixture_field_args(
        fixture("ethernet-udp-le-us"),
        &["frame.cap_len", "frame.number"],
    ));
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, b"51\t1\n".to_vec());
}

#[test]
fn last_read_file_wins() {
    let missing = golden::fixtures_dir().join("does-not-exist.pcap");
    let mut args = field_args(&missing, &["frame.number"]);
    args.push(OsString::from("-r"));
    args.push(fixture_path(fixture("ethernet-udp-le-us")).into_os_string());

    let run = run(&args);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, b"1\n".to_vec());
}

#[test]
fn pcap_interface_id_is_zero() {
    let run = run(&fixture_field_args(
        fixture("ethernet-udp-le-us"),
        &["frame.interface_id"],
    ));
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, b"0\n".to_vec());
}

#[cfg(unix)]
#[test]
fn non_utf8_read_path_to_missing_file_exits_three() {
    let mut path = std::env::temp_dir().into_os_string();
    path.push(format!("packetfin-missing-{}-", std::process::id()));
    path.push(OsString::from_vec(b"\xff".to_vec()));
    path.push(".pcap");

    let args = vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        OsString::from("-r"),
        path,
    ];

    let run = run(&args);
    let code = status_code(run.status);
    assert_eq!(code, Some(3), "stderr: {}", stderr_text(&run));
    assert_ne!(code, Some(101), "the process must not panic");
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        !run.stderr.is_empty(),
        "stderr must explain the open failure"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_field_name_exits_one() {
    let args = vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from_vec(b"frame.\xff".to_vec()),
        OsString::from("-r"),
        fixture_path(fixture("ethernet-udp-le-us")).into_os_string(),
    ];

    let run = run(&args);
    let code = status_code(run.status);
    assert_eq!(code, Some(1), "stderr: {}", stderr_text(&run));
    assert_ne!(code, Some(101), "the process must not panic");
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(!run.stderr.is_empty(), "stderr must reject the field value");
}

#[test]
fn attached_read_file_matches_separate_form() {
    let fixture = fixture("ethernet-udp-le-us");
    let path = fixture_path(fixture);
    let mut attached = OsString::from("-r");
    attached.push(path.as_os_str());

    let attached_run = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        attached,
    ]);
    let separate_run = run(&fixture_field_args(fixture, &["frame.number"]));

    assert_eq!(
        status_code(attached_run.status),
        Some(0),
        "attached stderr: {}",
        stderr_text(&attached_run)
    );
    assert_eq!(
        status_code(separate_run.status),
        Some(0),
        "separate stderr: {}",
        stderr_text(&separate_run)
    );
    assert_eq!(attached_run.stdout, separate_run.stdout);
    assert_eq!(attached_run.stdout, b"1\n".to_vec());
}

#[test]
fn ethernet_fields_include_both_addresses_and_occurrences() {
    let run = run(&fixture_field_args(
        fixture("ethernet-unknown"),
        &["eth.dst", "eth.src", "eth.type", "eth.addr"],
    ));
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(
        run.stdout,
        b"02:00:00:00:00:02\t02:00:00:00:00:01\t0x1234\t02:00:00:00:00:02,02:00:00:00:00:01\n"
            .to_vec()
    );
    assert!(run.stderr.is_empty(), "stderr: {}", stderr_text(&run));
}

#[test]
fn malformed_ethernet_frame_prints_empty_ethernet_fields() {
    let run = run(&fixture_field_args(
        fixture("ethernet-malformed"),
        &["frame.number", "eth.dst", "eth.src", "eth.type", "eth.addr"],
    ));
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(run.stdout, b"1\t\t\t\t\n".to_vec());
}

#[test]
fn checksum_preference_accepts_any_value_and_only_true_enables_validation() {
    let path = fixture_path(fixture("ipv4-bad-checksum"));
    let run_with = |value: &str| {
        let args = vec![
            OsString::from("-n"),
            OsString::from("-o"),
            OsString::from(format!("ip.check_checksum:{value}")),
            OsString::from("-T"),
            OsString::from("fields"),
            OsString::from("-e"),
            OsString::from("ip.checksum.status"),
            OsString::from("-r"),
            path.as_os_str().to_owned(),
        ];
        run(&args)
    };

    let on = run_with("TrUe");
    assert_eq!(status_code(on.status), Some(0));
    assert_eq!(on.stdout, b"1\n0\n".to_vec());

    let ignored = run_with("yes");
    assert_eq!(status_code(ignored.status), Some(0));
    assert_eq!(ignored.stdout, b"2\n2\n".to_vec());
}

fn require<T>(value: Option<T>, what: &str) -> T {
    match value {
        Some(value) => value,
        None => {
            eprintln!("{what}");
            std::process::exit(1);
        }
    }
}

fn require_ok<T, E: std::fmt::Display>(value: Result<T, E>, what: &str) -> T {
    match value {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{what}: {error}");
            std::process::exit(1);
        }
    }
}

/// Build a one-frame pcap whose frame is `length` zero bytes.
fn pcap_frame(seconds: u64, length: usize) -> Vec<u8> {
    let mut file = packetfin_testkit::pcap::Pcap::new(
        packetfin_testkit::ByteOrder::Little,
        packetfin_testkit::TimestampResolution::Microsecond,
    );
    require_ok(
        file.push(
            packetfin_testkit::Timestamp::new(seconds, 0),
            vec![0_u8; length],
        ),
        "a zero-filled packet fits the builder",
    );
    require_ok(file.to_bytes(), "the pcap header is writable")
}

fn stdin_field_args(count: Option<&str>) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("fields"),
    ];
    if let Some(count) = count {
        args.push(OsString::from("-c"));
        args.push(OsString::from(count));
    }
    args.push(OsString::from("-e"));
    args.push(OsString::from("frame.number"));
    args.push(OsString::from("-r"));
    args.push(OsString::from("-"));
    args
}

#[test]
fn packet_count_stops_before_malformed_trailing_data() {
    let mut capture = pcap_frame(1, 60);
    capture.extend_from_slice(&[0_u8; 10]);

    let limited = run_with_input(&stdin_field_args(Some("1")), Some(&capture));
    assert_eq!(
        status_code(limited.status),
        Some(0),
        "stderr: {}",
        stderr_text(&limited)
    );
    assert_eq!(limited.stdout, b"1\n".to_vec());
    assert!(
        limited.stderr.is_empty(),
        "the unread trailing record must not be reported: {}",
        stderr_text(&limited)
    );

    let over = run_with_input(&stdin_field_args(Some("2")), Some(&capture));
    assert_eq!(
        status_code(over.status),
        Some(14),
        "stderr: {}",
        stderr_text(&over)
    );
    assert_eq!(over.stdout, b"1\n".to_vec());
    assert!(!over.stderr.is_empty());
}

#[test]
fn flush_option_emits_each_packet_before_input_ends() {
    use std::io::Read as _;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let first = pcap_frame(1, 60);
    let second = pcap_frame(2, 60);
    let second_record = require(second.get(24..), "pcap record follows its header");

    let mut child = require_ok(
        Command::new(BIN)
            .args(stdin_field_args(None))
            .arg("-l")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn(),
        "packetfin starts",
    );
    let mut stdin = require(child.stdin.take(), "stdin was piped");
    let mut stdout = require(child.stdout.take(), "stdout was piped");
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut chunk = [0_u8; 32];
        let count = require_ok(stdout.read(&mut chunk), "stdout is readable");
        require_ok(
            sender.send(require(chunk.get(..count), "read count fits the buffer").to_vec()),
            "the test still listens",
        );
        let mut rest = Vec::new();
        require_ok(stdout.read_to_end(&mut rest), "stdout ends");
        rest
    });

    require_ok(stdin.write_all(&first), "write first packet");
    require_ok(stdin.flush(), "flush first packet");
    assert_eq!(
        require_ok(
            receiver.recv_timeout(Duration::from_secs(2)),
            "the first line arrives"
        ),
        b"1\n".to_vec(),
        "-l must flush the first packet while the capture is still open"
    );

    require_ok(stdin.write_all(second_record), "write second record");
    drop(stdin);
    let output = require_ok(child.wait_with_output(), "packetfin exits");
    let rest = match reader.join() {
        Ok(rest) => rest,
        Err(_) => {
            eprintln!("the reader thread panicked");
            std::process::exit(1);
        }
    };
    assert_eq!(status_code(output.status), Some(0));
    assert_eq!(rest, b"2\n".to_vec());
}

#[test]
fn invalid_field_output_option_exits_one_before_reading() {
    let path = fixture_path(fixture("field-output"));
    let mut args = field_args(&path, &["frame.number"]);
    args.insert(3, OsString::from("-E"));
    args.insert(4, OsString::from("bogus=y"));
    let run = run(&args);
    assert_eq!(
        status_code(run.status),
        Some(1),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        stderr_text(&run).contains("bogus"),
        "stderr must name the option: {}",
        stderr_text(&run)
    );
}
