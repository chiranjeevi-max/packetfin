//! End-to-end tests for `-V` packet detail and `-O` protocol selection.
//!
//! Every golden case whose id starts with `detail` runs the built binary and
//! compares stdout and the exit status with the golden output.

use std::ffi::OsString;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
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
    let output = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error| {
            eprintln!("failed to run packetfin: {error}");
            std::process::exit(1);
        });
    Run {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn fixture_path(fixture: &fixtures::Fixture) -> PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

#[test]
fn detail_cases_match_stored_goldens() -> Result<(), String> {
    let mut failures = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("detail") {
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
        Err(format!("{} detail golden case(s) differ", failures.len()))
    }
}

#[test]
fn o_requires_a_value() {
    let run = run(&[OsString::from("-n"), OsString::from("-O")]);
    assert_eq!(run.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("option -O requires a value"),
        "missing -O value must report usage: {stderr}"
    );
}

#[test]
fn v_without_a_read_file_attempts_live_capture() {
    let run = run(&[
        OsString::from("-V"),
        OsString::from("-i"),
        OsString::from("bogus"),
    ]);
    assert_eq!(run.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("no capture interface named 'bogus'"),
        "detail output should resolve live interfaces without -r: {stderr}"
    );
}

fn fixture(name: &str) -> Option<PathBuf> {
    fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .map(fixture_path)
}

#[test]
fn selected_transport_after_extension_header_is_not_dropped() {
    let Some(path) = fixture("ipv6-ext-udp") else {
        eprintln!("no ipv6-ext-udp fixture");
        std::process::exit(1);
    };
    let udp_run = run(&[
        OsString::from("-n"),
        OsString::from("-O"),
        OsString::from("udp"),
        OsString::from("-r"),
        path.clone().into_os_string(),
    ]);
    let stdout = String::from_utf8_lossy(&udp_run.stdout);
    assert!(
        stdout.contains("User Datagram Protocol, Src Port: 12345, Dst Port: 9999"),
        "UDP header must print after an IPv6 extension header: {stdout}"
    );
    assert!(
        stdout.contains("    Source Port: 12345"),
        "-O udp must expand UDP after an IPv6 extension header: {stdout}"
    );
    let frame = run(&[
        OsString::from("-n"),
        OsString::from("-O"),
        OsString::from("frame"),
        OsString::from("-r"),
        path.into_os_string(),
    ]);
    let stdout = String::from_utf8_lossy(&frame.stdout);
    assert!(
        stdout.contains("User Datagram Protocol, Src Port: 12345, Dst Port: 9999"),
        "a collapsed transport after an extension header keeps its header line: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_protocol_lists_are_unknown() {
    let Some(path) = fixture("arp-request") else {
        eprintln!("no arp-request fixture");
        std::process::exit(1);
    };
    for args in [
        vec![
            OsString::from("-n"),
            OsString::from("-O"),
            OsString::from_vec(vec![0xff]),
            OsString::from("-r"),
            path.clone().into_os_string(),
        ],
        vec![
            OsString::from("-n"),
            OsString::from_vec(b"-O\xff".to_vec()),
            OsString::from("-r"),
            path.clone().into_os_string(),
        ],
    ] {
        let case = run(&args);
        assert_eq!(case.status.code(), Some(0), "unknown protocol list exits 0");
        let stdout = String::from_utf8_lossy(&case.stdout);
        assert!(
            stdout.contains("Frame 1: Packet"),
            "detail output still prints with an unknown list: {stdout}"
        );
        assert!(
            !stdout.contains("    Hardware type:"),
            "an unknown list must not expand ARP: {stdout}"
        );
    }
}

fn detail_stdout(name: &str, args: &[&str]) -> String {
    let Some(path) = fixture(name) else {
        eprintln!("no {name} fixture");
        std::process::exit(1);
    };
    let mut full: Vec<OsString> = args.iter().map(OsString::from).collect();
    full.push(OsString::from("-r"));
    full.push(path.into_os_string());
    String::from_utf8_lossy(&run(&full).stdout).into_owned()
}

#[test]
fn quoted_transport_keeps_the_quote_level() {
    let stdout = detail_stdout("icmp-error-tcp", &["-n", "-O", "icmp", "-V"]);
    assert!(
        stdout.contains("    Transmission Control Protocol, Src Port: 40000, Dst Port: 4444"),
        "quoted TCP sits at the quote level: {stdout}"
    );
    assert!(
        !stdout.contains("        Transmission Control Protocol"),
        "quoted TCP must not be indented two levels: {stdout}"
    );
    assert!(
        stdout.contains("        Source Port: 40000"),
        "quoted TCP fields indent one level below it: {stdout}"
    );
}

#[test]
fn truncated_headers_omit_absent_address_clauses() {
    let ipv4 = detail_stdout("ipv4-truncated", &["-n", "-O", "frame", "-V"]);
    assert!(
        ipv4.contains("Internet Protocol Version 4, Src: 192.0.2.1\n"),
        "an IPv4 header without a destination prints only the source: {ipv4}"
    );
    let ipv6 = detail_stdout("ipv6-truncated", &["-n", "-O", "frame", "-V"]);
    assert!(
        ipv6.contains("Internet Protocol Version 6\n"),
        "an empty IPv6 header prints no address clause: {ipv6}"
    );
}

#[test]
fn truncated_tcp_omits_absent_clauses() {
    let stdout = detail_stdout("tcp-option-lone", &["-n", "-O", "frame", "-V"]);
    assert!(
        stdout.contains("Transmission Control Protocol, Src Port: 40000, Dst Port: 443, Seq: 0\n"),
        "a truncated TCP header keeps Seq but omits Len: {stdout}"
    );
}

#[test]
fn protocols_in_frame_lists_raw_and_data_layers() {
    let raw = detail_stdout("link-rawip", &["-n", "-O", "frame", "-V"]);
    assert!(
        raw.contains("[Protocols in frame: raw:ip:udp:data]"),
        "raw-IP captures list the raw protocol: {raw}"
    );
    assert!(
        raw.contains("\nRaw packet data\n"),
        "raw-IP captures print the raw header line: {raw}"
    );
    let tcp = detail_stdout("tcp-boundary", &["-n", "-O", "frame", "-V"]);
    assert!(
        !tcp.contains("tcp:data"),
        "a TCP payload not handed to the data decoder must not claim data: {tcp}"
    );
    let qinq = detail_stdout("link-qinq", &["-n", "-O", "frame", "-V"]);
    assert!(
        qinq.contains("ieee8021ad:ethertype:vlan"),
        "QinQ lists the provider-bridge ethertype marker: {qinq}"
    );
}

#[test]
fn quoted_ipv6_extension_keeps_the_quote_level() {
    let stdout = detail_stdout("icmp-quote-ipv6-ext", &["-n", "-O", "icmp", "-V"]);
    assert!(
        stdout.contains("    Internet Protocol Version 6, Src: 2001:db8::1, Dst: 2001:db8::2"),
        "quoted IPv6 sits at the quote level: {stdout}"
    );
    assert!(
        stdout.contains("        IPv6 Hop-by-Hop Option"),
        "quoted IPv6 extension headers indent below the quote: {stdout}"
    );
    assert!(
        stdout.contains("    User Datagram Protocol, Src Port: 12345, Dst Port: 9999"),
        "the successor after a quoted extension returns to the quote level: {stdout}"
    );
    assert!(
        !stdout
            .lines()
            .any(|line| line.starts_with("User Datagram Protocol")),
        "a quoted transport is never packet scope: {stdout}"
    );
    let selected = detail_stdout("icmp-quote-ipv6-ext", &["-n", "-O", "udp", "-V"]);
    assert!(
        !selected.contains("User Datagram Protocol"),
        "a quoted transport is not selectable by -O: {selected}"
    );
}

#[test]
fn ipv4_payload_data_uses_the_reported_header_length() {
    let stdout = detail_stdout("ipv4-basic", &["-n", "-O", "frame", "-V"]);
    assert!(
        stdout.contains("[Protocols in frame: eth:ethertype:ip:data]"),
        "a small unclaimed IPv4 payload is listed as data: {stdout}"
    );
}

#[test]
fn sll2_header_uses_the_link_type() {
    let stdout = detail_stdout("link-sll2", &["-n", "-O", "frame", "-V"]);
    assert!(
        stdout.contains("Linux cooked capture v2"),
        "SLL2 is selected from the link type, not its fields: {stdout}"
    );
}

#[test]
fn root_data_is_bounded_by_reported_payload() {
    let ipv4 = detail_stdout(
        "ipv4-truncated",
        &["-n", "-O", "frame", "-V", "-Y", "frame.number == 4"],
    );
    assert!(
        !ipv4.contains("Data ("),
        "a truncated IPv4 header has no root Data line: {ipv4}"
    );
    let payload = detail_stdout(
        "ipv4-truncated",
        &["-n", "-O", "frame", "-V", "-Y", "frame.number == 5"],
    );
    assert!(
        payload.contains("Data (8 bytes)"),
        "the root Data length is bounded by the reported payload, padding excluded: {payload}"
    );
    let ipv6 = detail_stdout("ipv6-truncated", &["-n", "-O", "frame", "-V"]);
    let lines: Vec<&str> = ipv6
        .lines()
        .filter(|line| line.starts_with("Data ("))
        .collect();
    assert_eq!(
        lines,
        vec!["Data (4 bytes)"],
        "the root Data length is bounded by the reported payload, padding excluded: {ipv6}"
    );
}

#[test]
fn dns_link_detail_lines_have_exact_placement_and_shownames() {
    let Some(path) = fixture("dns-retrans") else {
        eprintln!("no dns-retrans fixture");
        std::process::exit(1);
    };

    let frame = |number: &str, extra: &[&str]| {
        let mut args = vec![
            OsString::from("-n"),
            OsString::from("-2"),
            OsString::from("-V"),
            OsString::from("-Y"),
            OsString::from(format!("frame.number=={number}")),
            OsString::from("-r"),
            path.as_os_str().to_owned(),
        ];
        args.extend(extra.iter().map(OsString::from));
        String::from_utf8_lossy(&run(&args).stdout).into_owned()
    };

    let request = frame("1", &[]);
    assert!(
        request.contains("    [Response In: 3]\n"),
        "query link missing: {request}"
    );

    let retransmission = frame("2", &[]);
    assert!(
        retransmission.contains(
            "        [Expert Info (Warning/Protocol): DNS query retransmission. Original request in frame 1]\n\
             \x20           [DNS query retransmission. Original request in frame 1]\n\
             \x20           [Severity level: Warning]\n\
             \x20           [Group: Protocol]\n"
        ),
        "query retransmission expert missing: {retransmission}"
    );
    assert!(
        retransmission.contains(
            "    [Retransmitted request. Original request in: 1]\n    [Retransmission: True]\n"
        ),
        "query retransmission fields missing: {retransmission}"
    );

    let response = frame("3", &[]);
    assert!(
        response.contains("    [Request In: 1]\n    [Time: 1 second]\n"),
        "response links missing: {response}"
    );

    let response_retransmission = frame("4", &[]);
    assert!(
        response_retransmission.contains(
            "    [Retransmitted response. Original response in: 3]\n    [Retransmission: True]\n"
        ),
        "response retransmission fields missing: {response_retransmission}"
    );

    let missing = frame("5", &[]);
    assert!(
        missing.contains("        [Expert Info (Warning/Protocol): DNS response missing]\n"),
        "missing-response expert absent: {missing}"
    );
    assert!(
        !missing.contains("DNS response missing: 1"),
        "the expert label must not render as a normal field: {missing}"
    );
}

fn tls_frame_protocols(fixture: &str, frame_number: usize) -> String {
    let path = golden::fixtures_dir().join(fixture);
    let output = Command::new(BIN)
        .args(["-n", "-2", "-V", "-r"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error| {
            eprintln!("failed to run packetfin: {error}");
            std::process::exit(1);
        });
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let marker = format!("Frame {frame_number}:");
    let after = text.split(&marker).nth(1).unwrap_or_default();
    let frame = after.split("\nFrame ").next().unwrap_or_default();
    frame
        .lines()
        .find(|line| line.contains("[Protocols in frame:"))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn two_pass_tls_partial_segments_are_plain_tcp() {
    assert!(
        tls_frame_protocols("tls-handshake.pcap", 7).ends_with("ip:tcp]"),
        "frame 7 must not claim TLS in two-pass"
    );
    assert!(
        tls_frame_protocols("tls-handshake-split.pcap", 1).ends_with("ip:tcp]"),
        "split TLS frame 1 must not claim TLS in two-pass"
    );
}
