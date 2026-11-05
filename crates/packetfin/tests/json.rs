//! End-to-end tests for `-T json` and `-T jsonraw`.
//!
//! Every golden case whose id starts with `json` runs the built binary and
//! compares stdout and the exit status. The remaining tests cover command-line
//! validation and structural guarantees for the generated fields that the
//! byte-identical golden cases leave out.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::fixtures::{self, Fixture};
use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

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

fn fixture_path(fixture: &Fixture) -> PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

fn json_args(path: &Path, extra: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("json"),
    ];
    args.extend(extra.iter().map(OsString::from));
    args.push(OsString::from("-r"));
    args.push(path.as_os_str().to_owned());
    args
}

fn fixture_json_args(fixture: &Fixture, extra: &[&str]) -> Vec<OsString> {
    json_args(&fixture_path(fixture), extra)
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
fn golden_json_cases_match() {
    let mut compared = 0_usize;
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("json") {
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
    assert!(compared > 0, "no JSON golden cases were compared");
}

#[test]
fn duplicate_keys_merge_into_arrays() {
    let path = fixture_path(fixture("dns-query-response"));
    let plain = run(&json_args(
        &path,
        &["-j", "dns", "-c", "2", "-Y", "frame.number == 2"],
    ));
    let merged = run(&json_args(
        &path,
        &[
            "-j",
            "dns",
            "-c",
            "2",
            "-Y",
            "frame.number == 2",
            "--no-duplicate-keys",
        ],
    ));
    assert_eq!(status_code(plain.status), Some(0));
    assert_eq!(status_code(merged.status), Some(0));
    let plain = String::from_utf8_lossy(&plain.stdout);
    let merged = String::from_utf8_lossy(&merged.stdout);
    assert!(
        plain.matches("\"dns.resp.name\":").count() > 1,
        "the response must repeat dns.resp.name without merging"
    );
    assert!(
        merged.contains("\"dns.resp.name\": [\n"),
        "duplicate dns.resp.name keys must become one array"
    );
    assert_eq!(merged.matches("\"dns.resp.name\":").count(), 1);
}

#[test]
fn generated_fields_are_tracked_or_hidden() {
    let icmp = run(&fixture_json_args(
        fixture("icmp-echo"),
        &["-j", "icmp", "-c", "1"],
    ));
    let text = String::from_utf8_lossy(&icmp.stdout);
    assert!(!text.contains("\"icmp.checksum_calculated\""));
    let raw = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("icmp"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("icmp-echo")).as_os_str().to_owned(),
    ]);
    let raw_text = String::from_utf8_lossy(&raw.stdout);
    assert!(!raw_text.contains("checksum_calculated"));

    let advanced = run(&fixture_json_args(fixture("advanced"), &["-c", "4"]));
    let advanced = String::from_utf8_lossy(&advanced.stdout);
    assert!(!advanced.contains("\"_ws.malformed\""));

    let short = run(&fixture_json_args(
        fixture("snaplen-truncated"),
        &["-c", "1"],
    ));
    assert!(String::from_utf8_lossy(&short.stdout).contains("\"_ws.short\""));
}

#[test]
fn capture_limit_pseudo_layer_uses_the_summary_model() {
    let snaplen = fixture("snaplen-truncated");
    let text = run(&fixture_json_args(snaplen, &["-c", "1"]));
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("\"_ws.short\""));
    let raw = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(snaplen).as_os_str().to_owned(),
    ]);
    let raw = String::from_utf8_lossy(&raw.stdout);
    assert!(raw.contains("\"_ws.short_raw\": ["));
    assert!(raw.contains("\"\",\n          0,\n          0,\n          0,\n          1,"));

    for name in ["icmp-capture-truncated", "advanced"] {
        let run = run(&fixture_json_args(fixture(name), &["-c", "4"]));
        assert!(
            !String::from_utf8_lossy(&run.stdout).contains("\"_ws.short\""),
            "{name} must not report a capture limit"
        );
    }
}

#[test]
fn extension_and_quote_raw_extents_exclude_transport() {
    let truncated = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("ipv6"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("ipv6-ext-truncation"))
            .as_os_str()
            .to_owned(),
    ]);
    let truncated = String::from_utf8_lossy(&truncated.stdout);
    assert!(truncated.contains("          14,\n          40,\n          0,\n          1,"));

    let zero = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("ipv6"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("ipv6-truncated-prefixes"))
            .as_os_str()
            .to_owned(),
    ]);
    let zero = String::from_utf8_lossy(&zero.stdout);
    assert!(zero.contains("\"ipv6_raw\": [\n          \"\",\n          14,\n          0,"));

    let extended = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("ipv6"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("ipv6-ext-udp")).as_os_str().to_owned(),
    ]);
    let extended = String::from_utf8_lossy(&extended.stdout);
    assert!(extended.contains("          14,\n          48,\n          0,\n          1,"));

    let quote = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("icmp"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("icmp-quote-ipv6-ext"))
            .as_os_str()
            .to_owned(),
    ]);
    let quote = String::from_utf8_lossy(&quote.stdout);
    assert!(quote.contains("          34,\n          64,\n          0,\n          1,"));
    assert!(quote.contains("            42,\n            48,\n            0,\n            1,"));
}

#[test]
fn masked_raw_spans_use_storage_windows() {
    let ip = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("ip ip.flags"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("ipv4-basic")).as_os_str().to_owned(),
    ]);
    let ip = String::from_utf8_lossy(&ip.stdout);
    assert!(
        ip.contains("\"ip.flags_raw\": [\n            \"2\",\n            20,\n            1,")
    );

    let ipv6 = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("ipv6"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("ipv6-basic")).as_os_str().to_owned(),
    ]);
    let ipv6 = String::from_utf8_lossy(&ipv6.stdout);
    assert!(
        ipv6.contains(
            "\"ipv6.tclass_raw\": [\n            \"0\",\n            14,\n            4,"
        )
    );
    assert!(
        ipv6.contains("\"ipv6.flow_raw\": [\n            \"0\",\n            15,\n            3,")
    );

    let flags = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("json"),
        OsString::from("-x"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("tcp-options")).as_os_str().to_owned(),
    ]);
    let flags = String::from_utf8_lossy(&flags.stdout);
    assert!(flags.contains(
        "\"tcp.flags.str_raw\": [\n            \"6002\",\n            46,\n            2,"
    ));
}

#[test]
fn zero_length_protocol_raw_is_limited_to_ipv6_and_llc() {
    for (name, frame, protocol) in [
        ("ethernet-malformed", "1", "eth"),
        ("dns-malformed", "2", "dns"),
        ("icmp-truncated", "1", "icmp"),
        ("link-boundary", "5", "ip"),
        ("udp-prefixes", "2", "udp"),
    ] {
        let run = run(&[
            OsString::from("-n"),
            OsString::from("-T"),
            OsString::from("jsonraw"),
            OsString::from("-Y"),
            OsString::from(format!("frame.number=={frame}")),
            OsString::from("-r"),
            fixture_path(fixture(name)).as_os_str().to_owned(),
        ]);
        let text = String::from_utf8_lossy(&run.stdout);
        let key = format!("\"{protocol}_raw\"");
        assert!(!text.contains(&key), "{name} f{frame} must omit {key}");
    }

    let ipv6 = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-c"),
        OsString::from("1"),
        OsString::from("-r"),
        fixture_path(fixture("ipv6-truncated-prefixes"))
            .as_os_str()
            .to_owned(),
    ]);
    assert!(
        String::from_utf8_lossy(&ipv6.stdout)
            .contains("\"ipv6_raw\": [\n          \"\",\n          14,\n          0,")
    );

    let llc = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("llc"),
        OsString::from("-Y"),
        OsString::from("frame.number==3"),
        OsString::from("-r"),
        fixture_path(fixture("link-vlan")).as_os_str().to_owned(),
    ]);
    assert!(
        String::from_utf8_lossy(&llc.stdout)
            .contains("\"llc_raw\": [\n          \"\",\n          18,\n          0,")
    );
}

#[test]
fn untimestamped_frames_break_delta_chains() {
    let run = run(&fixture_json_args(
        fixture("advanced"),
        &["-j", "frame", "-Y", "frame.number==5"],
    ));
    let text = String::from_utf8_lossy(&run.stdout);
    assert!(!text.contains("frame.time_delta\""));
    assert!(!text.contains("frame.time_delta_displayed\""));
    assert!(text.contains("frame.time_relative\""));
}

#[test]
fn extension_and_quote_siblings_keep_their_keys() {
    let ext = run(&fixture_json_args(
        fixture("ipv6-ext-headers"),
        &["-j", "ipv6", "-c", "1"],
    ));
    let ext = String::from_utf8_lossy(&ext.stdout);
    assert!(ext.contains("\"ipv6.hopopts\""));
    assert!(ext.contains("\"ipv6.dstopts\""));

    let quote = run(&fixture_json_args(
        fixture("icmp-quote-ipv6-ext"),
        &["-j", "icmp", "-c", "1"],
    ));
    let quote = String::from_utf8_lossy(&quote.stdout);
    assert!(quote.contains("\"ipv6\": {"));
    assert!(quote.contains("\"udp\": {"));
}

#[test]
fn ordinary_experts_and_data_layers_are_serialised() {
    let expert = run(&fixture_json_args(
        fixture("icmp-bad-checksum"),
        &["-c", "1"],
    ));
    let expert = String::from_utf8_lossy(&expert.stdout);
    assert!(expert.contains("\"_ws.expert\""));
    assert!(expert.contains("Bad checksum"));

    let data = run(&fixture_json_args(
        fixture("ethernet-udp-le-us"),
        &["-j", "data", "-c", "1"],
    ));
    let data = String::from_utf8_lossy(&data.stdout);
    assert!(data.contains("\"data.data\""));
}

#[test]
fn repeated_specified_fields_are_deduplicated() {
    let path = fixture_path(fixture("arp-request"));
    let run = run(&json_args(&path, &["-e", "arp.opcode", "-e", "arp.opcode"]));
    let text = String::from_utf8_lossy(&run.stdout);
    assert_eq!(text.matches("\"arp.opcode\": [").count(), 1);
}

#[test]
fn no_orphan_json_golden_files() {
    for fixture in fixtures::all() {
        let expected: Vec<&str> = fixture
            .cases()
            .iter()
            .filter(|case| case.id.starts_with("json"))
            .map(|case| case.id)
            .collect();
        let directory = golden::golden_dir().join(fixture.name);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            // A fixture exercised only by Rust tests has no golden case.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                eprintln!("cannot list {}: {error}", directory.display());
                std::process::exit(1);
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("json") {
                continue;
            }
            let stem = name.split('.').next().unwrap_or(name);
            assert!(
                expected.contains(&stem),
                "golden {}/{} has no registry case",
                fixture.name,
                name
            );
        }
    }
}

#[test]
fn representative_protocols_have_json_layers() {
    for (name, extra, protocol, field) in [
        (
            "ipv4-basic",
            Vec::new(),
            "\"ip\": {",
            "\"ip.src\": \"192.0.2.1\"",
        ),
        (
            "ipv6-basic",
            Vec::new(),
            "\"ipv6\": {",
            "\"ipv6.src\": \"2001:db8::1\"",
        ),
        (
            "ethernet-udp-le-us",
            Vec::new(),
            "\"udp\": {",
            "\"udp.srcport\": \"12345\"",
        ),
        (
            "tcp-handshake",
            vec!["-o", "tcp.relative_sequence_numbers:FALSE"],
            "\"tcp\": {",
            "\"tcp.flags\"",
        ),
        (
            "icmp-echo",
            Vec::new(),
            "\"icmp\": {",
            "\"icmp.type\": \"8\"",
        ),
        (
            "dns-query-response",
            Vec::new(),
            "\"dns\": {",
            "\"dns.qry.name\"",
        ),
    ] {
        let run = run(&fixture_json_args(fixture(name), &extra));
        assert_eq!(
            status_code(run.status),
            Some(0),
            "{name}: {}",
            stderr_text(&run)
        );
        let text = String::from_utf8_lossy(&run.stdout);
        assert!(text.starts_with("[\n"), "{name}: no top-level array");
        assert!(text.ends_with("]\n"), "{name}: no final newline");
        assert!(text.contains("\"_source\""), "{name}: no envelope");
        assert!(text.contains("\"layers\""), "{name}: no layers object");
        assert!(text.contains(protocol), "{name}: no {protocol} layer");
        assert!(text.contains(field), "{name}: no {field} field");
    }
}

#[test]
fn empty_capture_is_an_empty_array() {
    let run = run(&fixture_json_args(fixture("empty"), &[]));
    assert_eq!(status_code(run.status), Some(0));
    assert_eq!(run.stdout, b"[]\n");
}

#[test]
fn invalid_protocol_filters_exit_one() {
    let path = fixture_path(fixture("arp-request"));
    for value in ["bogus", "arp,eth", "arp bogus arp.x"] {
        let args = json_args(&path, &["-j", value]);
        assert_exit_one(&args);
    }
    let args = json_args(&path, &["-J", "ip.src =="]);
    assert_exit_one(&args);
    assert_exit_one(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("text"),
        OsString::from("-j"),
        OsString::from("bogus"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
}

#[test]
fn protocol_filters_are_ignored_outside_json() {
    let path = fixture_path(fixture("arp-request"));
    let plain = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
    let filtered = run(&[
        OsString::from("-n"),
        OsString::from("-j"),
        OsString::from("arp frame"),
        OsString::from("-J"),
        OsString::from("eth"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
    assert_eq!(filtered.stdout, plain.stdout);
    assert_eq!(status_code(filtered.status), Some(0));
}

#[test]
fn no_duplicate_keys_requires_json() {
    let path = fixture_path(fixture("arp-request"));
    assert_exit_one(&[
        OsString::from("-n"),
        OsString::from("--no-duplicate-keys"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
    assert_exit_one(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        OsString::from("--no-duplicate-keys"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
}

#[test]
fn jsonraw_rejects_e_fields() {
    let path = fixture_path(fixture("arp-request"));
    assert_exit_one(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-e"),
        OsString::from("arp.opcode"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
}

#[test]
fn multiple_output_formats_exit_one() {
    let path = fixture_path(fixture("arp-request"));
    assert_exit_one(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("json"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
}

#[test]
fn empty_protocol_filter_is_not_a_filter() {
    let path = fixture_path(fixture("arp-request"));
    let filtered = run(&json_args(&path, &["-j", "", "-c", "1"]));
    let plain = run(&json_args(&path, &["-c", "1"]));
    assert_eq!(filtered.stdout, plain.stdout);
    assert_eq!(status_code(filtered.status), Some(0));
}

#[test]
fn json_ignores_quiet_verbose_and_print_flags() {
    let path = fixture_path(fixture("arp-request"));
    let plain = run(&json_args(&path, &["-j", "arp"]));
    for extra in [vec!["-q"], vec!["-Q"], vec!["-V"], vec!["-P"], vec!["-l"]] {
        let mut args = vec![
            OsString::from("-n"),
            OsString::from("-T"),
            OsString::from("json"),
        ];
        args.extend(extra.iter().map(OsString::from));
        args.extend([
            OsString::from("-j"),
            OsString::from("arp"),
            OsString::from("-r"),
            path.as_os_str().to_owned(),
        ]);
        let run = run(&args);
        assert_eq!(run.stdout, plain.stdout, "flags {extra:?} changed JSON");
        assert_eq!(status_code(run.status), Some(0));
    }
}

#[test]
fn hexdump_adds_raw_keys_to_plain_json() {
    let path = fixture_path(fixture("arp-request"));
    let plain = run(&json_args(&path, &["-j", "arp"]));
    let mixed = run(&json_args(&path, &["-j", "arp", "-x"]));
    assert_eq!(status_code(mixed.status), Some(0));
    let plain = String::from_utf8_lossy(&plain.stdout);
    let mixed = String::from_utf8_lossy(&mixed.stdout);
    assert!(!plain.contains("\"_raw\""));
    assert!(mixed.contains("\"arp_raw\": ["));
    assert!(mixed.contains("\"arp.hw.type_raw\": ["));
    assert!(mixed.contains("\"arp.hw.type\": \"1\""));

    let raw = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("arp"),
        OsString::from("-x"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
    let raw_without = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("arp"),
        OsString::from("-r"),
        path.as_os_str().to_owned(),
    ]);
    assert_eq!(raw.stdout, raw_without.stdout, "-x must not change jsonraw");

    let fields = run(&json_args(&path, &["-e", "arp.opcode", "-x"]));
    let fields_without = run(&json_args(&path, &["-e", "arp.opcode"]));
    assert_eq!(
        fields.stdout, fields_without.stdout,
        "-x must not change -e"
    );
}

#[test]
fn count_and_filter_select_packets() {
    let path = fixture_path(fixture("arp-opcodes"));
    let counted = run(&json_args(&path, &["-c", "1"]));
    assert_eq!(status_code(counted.status), Some(0));
    let packets = String::from_utf8_lossy(&counted.stdout)
        .matches("\"_index\"")
        .count();
    assert_eq!(packets, 1, "-c 1 must print one packet");

    let filtered = run(&json_args(&path, &["-Y", "arp.opcode == 8"]));
    let text = String::from_utf8_lossy(&filtered.stdout);
    assert!(text.contains("\"arp.opcode\": \"8\""));
    assert_eq!(
        text.matches("\"arp.opcode\": \"8\"").count(),
        text.matches("\"arp.opcode\"").count(),
        "the display filter must drop every other opcode"
    );
}

#[test]
fn tso_ip_len_raw_keeps_the_uint16_field_type() {
    let path = fixture_path(fixture("ipv4-tso-large"));
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from("jsonraw"),
        OsString::from("-j"),
        OsString::from("ip"),
        OsString::from("-r"),
        path.into_os_string(),
    ]);
    assert_eq!(status_code(run.status), Some(0), "{}", stderr_text(&run));
    let text = String::from_utf8_lossy(&run.stdout);
    let compact: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        compact.contains("\"ip.len_raw\": [ \"0000\", 16, 2, 0, 5, 0 ]"),
        "ip.len must stay FT_UINT16 with the on-wire zero: {compact}"
    );
}

#[test]
fn stdin_matches_a_file_run() {
    let fixture = fixture("arp-request");
    let path = fixture_path(fixture);
    let file_run = run(&json_args(&path, &["-j", "arp"]));
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read fixture: {error}");
            std::process::exit(1);
        }
    };
    let stdin_run = run_with_input(
        &[
            OsString::from("-n"),
            OsString::from("-T"),
            OsString::from("json"),
            OsString::from("-j"),
            OsString::from("arp"),
            OsString::from("-r"),
            OsString::from("-"),
        ],
        Some(&bytes),
    );
    assert_eq!(stdin_run.stdout, file_run.stdout);
    assert_eq!(status_code(stdin_run.status), Some(0));
}

#[test]
fn truncated_capture_exits_fourteen_with_empty_array() {
    let run = run(&fixture_json_args(fixture("truncated"), &[]));
    assert_eq!(status_code(run.status), Some(14));
    assert_eq!(run.stdout, b"[]\n");
}

#[test]
fn specified_fields_use_arrays_and_skip_absent_fields() {
    let path = fixture_path(fixture("arp-request"));
    let run = run(&json_args(
        &path,
        &["-e", "arp.opcode", "-e", "ip.src", "-e", "arp.src.hw_mac"],
    ));
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    assert!(text.contains("\"layers\": {"), "no layers object: {text}");
    assert!(text.contains("\"arp.opcode\": [\n          \"1\"\n        ]"));
    assert!(text.contains("\"arp.src.hw_mac\": ["));
    assert!(
        !text.contains("\"ip.src\""),
        "absent fields must be omitted"
    );
}
