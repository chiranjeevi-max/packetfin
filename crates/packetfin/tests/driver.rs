//! The single read/decode driver serves every output mode.
//!
//! Line flushing must not change the bytes a mode writes, and `-c` must stop
//! on exactly the same packet. Both checks run through the real binary so a
//! sink that buffers differently from the others is caught.

use std::process::{Command, ExitStatus, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[&str]) -> Run {
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

/// Every output mode `drive` serves, with a case that exercises its writer.
fn modes() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("fields", vec!["-T", "fields", "-e", "frame.number"]),
        ("json", vec!["-T", "json", "-e", "frame.number"]),
        ("jsonraw", vec!["-T", "jsonraw"]),
        ("pdml", vec!["-T", "pdml", "-e", "frame.number"]),
        ("psml", vec!["-T", "psml"]),
        ("ek", vec!["-T", "ek"]),
        ("ps", vec!["-T", "ps"]),
        ("summary", vec![]),
        ("text", vec!["-T", "text"]),
        ("tabs", vec!["-T", "tabs"]),
    ]
}

/// PDML records the wall-clock start time to the second, so two runs that
/// straddle a second boundary differ by exactly that attribute. Every other
/// mode is compared verbatim.
fn comparable_stdout(name: &str, stdout: &[u8]) -> Vec<u8> {
    if name != "pdml" {
        return stdout.to_vec();
    }
    let mut output = stdout.to_vec();
    let Some(start) = output.windows(6).position(|window| window == b"time=\"") else {
        return output;
    };
    let value_start = start + 6;
    let Some(length) = output
        .get(value_start..)
        .and_then(|rest| rest.iter().position(|byte| *byte == b'"'))
    else {
        return output;
    };
    output.drain(value_start..value_start + length);
    output
}

#[test]
fn flush_does_not_change_any_output_mode() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for (name, mut arguments) in modes() {
        arguments.extend(["-r", &capture]);
        let plain = run(&arguments);
        arguments.push("-l");
        let flushed = run(&arguments);
        assert_eq!(plain.status.code(), Some(0), "{name}: {:?}", plain.stderr);
        assert_eq!(
            plain.status.code(),
            flushed.status.code(),
            "{name}: status differs with -l"
        );
        let expected = comparable_stdout(name, &plain.stdout);
        let actual = comparable_stdout(name, &flushed.stdout);
        assert_eq!(expected, actual, "{name}: stdout differs with -l");
        assert_eq!(
            plain.stderr, flushed.stderr,
            "{name}: stderr differs with -l"
        );
    }
}

#[test]
fn packet_limit_stops_every_output_mode_after_the_same_frame() {
    // Both fixtures hold more than two frames, so a missing or off-by-one
    // limit must show up as a byte difference rather than pass a one-frame
    // capture unchanged.
    for fixture in ["advanced.pcapng", "field-output.pcapng"] {
        let capture = fixture_path(fixture);
        for (name, arguments) in modes() {
            let mut base = arguments.clone();
            base.extend(["-r", &capture]);
            let full = run(&base);
            assert_eq!(full.status.code(), Some(0), "{name}: {:?}", full.stderr);

            let one = run_with(&base, &["-c", "1"]);
            let two = run_with(&base, &["-c", "2"]);
            let filtered_one = run_with(&base, &["-Y", "frame.number <= 1"]);
            let filtered_two = run_with(&base, &["-Y", "frame.number <= 2"]);

            for (limit, limited, filtered) in
                [("1", &one, &filtered_one), ("2", &two, &filtered_two)]
            {
                assert_eq!(
                    limited.status.code(),
                    Some(0),
                    "{fixture}/{name}: -c {limit}: {:?}",
                    limited.stderr
                );
                let limited_stdout = without_pdml_wall_clock(&limited.stdout);
                let filtered_stdout = without_pdml_wall_clock(&filtered.stdout);
                assert_eq!(
                    limited_stdout, filtered_stdout,
                    "{fixture}/{name}: -c {limit} did not stop exactly after frame {limit}"
                );
            }
            assert_ne!(
                one.stdout, two.stdout,
                "{fixture}/{name}: -c 1 and -c 2 printed the same bytes, so the fixture cannot detect a limit regression"
            );
            assert_ne!(
                full.stdout, two.stdout,
                "{fixture}/{name}: -c 2 printed the whole capture, so the limit was ignored"
            );
        }
    }
}

/// Stream numbers survive a budget that fits the fixture's conversations,
/// and a zero budget starts a stream for every packet.
///
/// Per-conversation analysis and reassembly state make the retained
/// conversation charge larger than a 4096-byte budget.
#[test]
fn state_budget_changes_stream_retention() {
    let capture = fixture_path("tcp-streams.pcap");
    let retained = run(&[
        "-n",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "tcp.stream",
        "-e",
        "tcp.stream.pnum",
        "-e",
        "udp.stream",
        "-e",
        "udp.stream.pnum",
        "--pf-state-budget",
        "8192",
        "-r",
        &capture,
    ]);
    assert_eq!(retained.status.code(), Some(0));
    assert!(retained.stderr.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&retained.stdout),
        concat!(
            "1\t0\t1\t\t\n",
            "2\t0\t2\t\t\n",
            "3\t0\t3\t\t\n",
            "4\t0\t4\t\t\n",
            "5\t0\t5\t\t\n",
            "6\t1\t1\t\t\n",
            "7\t0\t6\t\t\n",
            "8\t2\t1\t\t\n",
            "9\t1\t2\t\t\n",
            "10\t2\t2\t\t\n",
            "11\t2\t3\t\t\n",
            "12\t3\t1\t\t\n",
            "13\t3\t2\t\t\n",
            "14\t4\t1\t\t\n",
            "15\t4\t2\t\t\n",
            "16\t2\t4\t\t\n",
            "17\t\t\t0\t1\n",
        )
    );

    let disabled = run(&[
        "-n",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "tcp.stream",
        "-e",
        "tcp.stream.pnum",
        "-e",
        "udp.stream",
        "-e",
        "udp.stream.pnum",
        "--pf-state-budget",
        "0",
        "-r",
        &capture,
    ]);
    assert_eq!(disabled.status.code(), Some(0));
    assert!(disabled.stderr.is_empty());
    let mut expected = String::new();
    for frame in 1_u32..=16 {
        let stream = frame - 1;
        expected.push_str(&format!("{frame}\t{stream}\t1\t\t\n"));
    }
    expected.push_str("17\t\t\t0\t1\n");
    assert_eq!(String::from_utf8_lossy(&disabled.stdout), expected);
}

/// Replace the PDML `<pdml ... time="...">` wall-clock attribute with a
/// fixed placeholder. Two invocations can straddle a second boundary even
/// when their packet output is identical; this test compares packet limits,
/// not the process start time.
fn without_pdml_wall_clock(stdout: &[u8]) -> Vec<u8> {
    let Some(start) = stdout.windows(6).position(|window| window == b"<pdml ") else {
        return stdout.to_vec();
    };
    let Some(tag_end) = stdout
        .get(start..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'>'))
        .and_then(|offset| start.checked_add(offset))
    else {
        return stdout.to_vec();
    };
    let Some(attribute) = stdout
        .get(start..tag_end)
        .and_then(|tag| tag.windows(7).position(|window| window == b" time=\""))
        .and_then(|offset| start.checked_add(offset))
    else {
        return stdout.to_vec();
    };
    let value_start = attribute.saturating_add(7);
    let Some(value_end) = stdout
        .get(value_start..tag_end)
        .and_then(|rest| rest.iter().position(|byte| *byte == b'"'))
        .and_then(|offset| value_start.checked_add(offset))
    else {
        return stdout.to_vec();
    };
    let mut normalized = Vec::with_capacity(stdout.len());
    if let Some(prefix) = stdout.get(..value_start) {
        normalized.extend_from_slice(prefix);
    }
    normalized.extend_from_slice(b"<time>");
    if let Some(suffix) = stdout.get(value_end..) {
        normalized.extend_from_slice(suffix);
    }
    normalized
}

fn run_with(base: &[&str], extra: &[&str]) -> Run {
    let mut arguments = base.to_vec();
    arguments.extend_from_slice(extra);
    run(&arguments)
}

fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{context}: {error}");
            std::process::exit(1);
        }
    }
}

fn must_some<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => {
            eprintln!("{context}");
            std::process::exit(1);
        }
    }
}

fn run_with_stdin(args: &[&str], stdin: Stdio) -> Run {
    let output = Command::new(BIN)
        .args(args)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error| {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        });
    Run {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

#[test]
fn two_pass_rejects_pipe_and_redirected_standard_input() {
    let capture = fixture_path("dns-pairs.pcap");
    let bytes = must(std::fs::read(&capture), "read fixture");

    let mut piped = must(
        Command::new(BIN)
            .args(["-n", "-2", "-r", "-", "-T", "fields", "-e", "frame.number"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn(),
        "spawn packetfin",
    );
    {
        use std::io::Write as _;
        let stdin = must_some(piped.stdin.as_mut(), "stdin pipe");
        must(stdin.write_all(&bytes), "write capture to pipe");
    }
    let output = must(piped.wait_with_output(), "wait for packetfin");
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("pipe or FIFO"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let file = must(std::fs::File::open(&capture), "open fixture");
    let redirected = run_with_stdin(
        &["-n", "-2", "-r", "-", "-T", "fields", "-e", "frame.number"],
        Stdio::from(file),
    );
    assert_eq!(redirected.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&redirected.stderr).contains("random access"),
        "stderr: {}",
        String::from_utf8_lossy(&redirected.stderr)
    );
}

#[test]
fn session_reset_reports_and_restarts_analysis_state() {
    let capture = fixture_path("dns-pairs.pcap");
    let quiet = run(&[
        "-n",
        "-M",
        "2",
        "-q",
        "-Q",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "dns.response_to",
        "-e",
        "dns.response_in",
        "-r",
        &capture,
    ]);
    assert_eq!(quiet.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&quiet.stdout),
        concat!(
            "1\t\t\n", "2\t1\t\n", "1\t\t\n", "2\t1\t\n", "1\t\t\n", "2\t1\t\n",
        )
    );
    // Each reset prints one line, even with -q or -Q.
    assert_eq!(
        String::from_utf8_lossy(&quiet.stderr),
        "resetting session.\nresetting session.\n"
    );
}

#[test]
fn annotation_budget_zero_omits_links_and_notices_once() {
    let capture = fixture_path("dns-pairs.pcap");
    let run = run(&[
        "-n",
        "-2",
        "--pf-annotation-budget",
        "0",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "dns.response_in",
        "-e",
        "dns.response_to",
        "-r",
        &capture,
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run.stdout),
        "1\t\t\n2\t\t\n3\t\t\n4\t\t\n5\t\t\n6\t\t\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&run.stderr),
        "packetfin: annotation budget exhausted; later link fields are omitted\n"
    );
}

#[test]
fn annotation_budget_zero_omits_reassembly_links() {
    let capture = fixture_path("http-links.pcap");
    let run = run(&[
        "-n",
        "-2",
        "--pf-annotation-budget",
        "0",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "tcp.reassembled_in",
        "-e",
        "http.request_in",
        "-e",
        "http.response_in",
        "-r",
        &capture,
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run.stdout),
        "1\t\t\t\n2\t\t\t\n3\t\t\t\n4\t\t\t\n5\t\t\t\n6\t\t\t\n7\t\t\t\n8\t\t\t\n9\t\t\t\n10\t\t\t\n11\t\t\t\n12\t\t\t\n13\t\t\t\n14\t\t\t\n15\t\t\t\n16\t\t\t\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&run.stderr),
        "packetfin: annotation budget exhausted; later link fields are omitted\n"
    );
}

#[test]
fn small_state_budget_loses_dns_links_without_failing() {
    let capture = fixture_path("dns-pairs.pcap");
    let run = run(&[
        "-n",
        "-2",
        "--pf-state-budget",
        "1",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "dns.response_in",
        "-e",
        "dns.response_to",
        "-r",
        &capture,
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&run.stdout),
        "1\t\t\n2\t\t\n3\t\t\n4\t\t\n5\t\t\n6\t\t\n"
    );
    assert!(run.stderr.is_empty(), "stderr: {:?}", run.stderr);
}

#[test]
fn truncated_input_in_two_pass_mode_uses_the_truncation_status() {
    let capture = fixture_path("dns-pairs.pcap");
    let bytes = must(std::fs::read(&capture), "read fixture");
    let directory = std::env::temp_dir().join(format!("packetfin-t25-{}", std::process::id()));
    must(std::fs::create_dir_all(&directory), "create temp dir");
    let path = directory.join("truncated.pcap");
    let Some(truncated) = bytes.get(..30) else {
        eprintln!("fixture is shorter than the truncation point");
        std::process::exit(1);
    };
    must(std::fs::write(&path, truncated), "write truncated capture");
    let run = run(&[
        "-n",
        "-2",
        "-r",
        must_some(path.to_str(), "input path"),
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]);
    let _ = std::fs::remove_dir_all(&directory);
    // A capture cut short mid-record exits 14 in both passes; the second
    // pass must not retry or panic.
    assert_eq!(run.status.code(), Some(14));
    assert!(!run.stderr.is_empty());
}

#[test]
fn two_pass_writer_renumbers_the_selection() {
    let capture = fixture_path("dns-pairs.pcap");
    let directory = std::env::temp_dir().join(format!("packetfin-t25w-{}", std::process::id()));
    must(std::fs::create_dir_all(&directory), "create temp dir");
    let output = directory.join("selected.pcapng");
    let write = run(&[
        "-n",
        "-2",
        "-R",
        "dns.flags.response==1",
        "-w",
        must_some(output.to_str(), "output path"),
        "-r",
        &capture,
    ]);
    assert_eq!(write.status.code(), Some(0), "{:?}", write.stderr);
    let read_back = run(&[
        "-n",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-r",
        must_some(output.to_str(), "output path"),
    ]);
    let _ = std::fs::remove_dir_all(&directory);
    assert_eq!(read_back.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&read_back.stdout), "1\n2\n3\n");
}

#[test]
fn session_reset_blank_delta_and_rebases_on_the_first_file_frame() {
    let capture = fixture_path("dns-pairs.pcap");
    let two = run(&["-n", "-M", "2", "-t", "d", "-r", &capture]);
    assert_eq!(two.status.code(), Some(0), "{:?}", two.stderr);
    assert_eq!(
        String::from_utf8_lossy(&two.stdout),
        concat!(
            "    1               192.0.2.1 \u{2192} 198.51.100.2 DNS 70 Standard query 0x1001 A pairs.test\n",
            "    2   0.000000 198.51.100.2 \u{2192} 192.0.2.1    DNS 86 Standard query response 0x1001 A pairs.test A 203.0.113.10\n",
            "    1               192.0.2.1 \u{2192} 198.51.100.2 DNS 71 Standard query 0x1002 A second.test\n",
            "    2   1.010000 198.51.100.2 \u{2192} 192.0.2.1    DNS 87 Standard query response 0x1002 A second.test A 203.0.113.11\n",
            "    1               192.0.2.1 \u{2192} 198.51.100.2 DNS 70 Standard query 0x1003 A third.test\n",
            "    2   2.010000 198.51.100.2 \u{2192} 192.0.2.1    DNS 86 Standard query response 0x1003 A third.test A 203.0.113.12\n",
        )
    );
    let one = run(&["-n", "-M", "1", "-t", "d", "-r", &capture]);
    assert_eq!(one.status.code(), Some(0), "{:?}", one.stderr);
    for line in String::from_utf8_lossy(&one.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.first(), Some(&"1"), "frame number: {line}");
    }
}

#[test]
fn snmp_pair_links_are_positive() {
    let capture = fixture_path("snmp-pairs.pcap");
    let args = [
        "-n",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "snmp.response_in",
        "-e",
        "snmp.response_to",
        "-e",
        "snmp.time",
        "-r",
        &capture,
    ];
    let one = run(&args);
    assert_eq!(one.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&one.stdout),
        "1\t\t\t\n2\t\t1\t0.000001000\n3\t\t\t\n4\t\t\t\n5\t\t\t\n6\t\t4\t0.000002000\n"
    );
    let mut two_args = args.to_vec();
    two_args.insert(1, "-2");
    let two = run(&two_args);
    assert_eq!(two.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&two.stdout),
        "1\t2\t\t\n2\t\t1\t0.000001000\n3\t\t\t\n4\t6\t\t\n5\t\t\t\n6\t\t4\t0.000002000\n"
    );
}
