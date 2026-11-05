//! End-to-end behaviour for name resolution, decode-as, protocol control,
//! preferences and colour that is not covered by a byte-exact golden.
//!
//! The committed goldens exercise fields, summaries, JSON, PDML and PSML; this
//! file pins the terminal-only colour path, detail rendering, notices, bounds
//! and command-line validation.

use std::fs;
use std::io::Write as _;
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
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

fn fixture(name: &str) -> String {
    golden::fixtures_dir()
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn hosts_fixture() -> String {
    golden::fixtures_dir()
        .join("names-hosts.txt")
        .to_string_lossy()
        .into_owned()
}

fn text(run: &Run) -> String {
    String::from_utf8_lossy(&run.stdout).into_owned()
}

fn stderr(run: &Run) -> String {
    String::from_utf8_lossy(&run.stderr).into_owned()
}

fn status(run: &Run) -> i32 {
    run.status.code().unwrap_or(-1)
}

#[test]
fn detail_shows_resolved_mac_labels_and_raw_addresses() {
    let capture = fixture("names-mac.pcap");
    let resolved = run(&["-V", "-c", "1", "-r", &capture]);
    assert_eq!(status(&resolved), 0, "{}", stderr(&resolved));
    let resolved = text(&resolved);
    assert!(
        resolved.contains("Source: Cisco_11:22:33 (00:00:0c:11:22:33)"),
        "{resolved}"
    );
    assert!(
        resolved.contains("Destination: Broadcast (ff:ff:ff:ff:ff:ff)"),
        "{resolved}"
    );

    let raw = run(&["-n", "-V", "-c", "1", "-r", &capture]);
    let raw = text(&raw);
    assert!(raw.contains("Source: 00:00:0c:11:22:33"), "{raw}");
    assert!(!raw.contains("Cisco_"), "{raw}");
}

#[test]
fn detail_shows_service_names_only_with_transport_resolution() {
    let capture = fixture("names-services.pcap");
    let resolved = run(&["-N", "t", "-V", "-c", "1", "-r", &capture]);
    let resolved = text(&resolved);
    assert!(
        resolved
            .contains("User Datagram Protocol, Src Port: search-agent (1234), Dst Port: http (80)"),
        "{resolved}"
    );
    assert!(
        resolved.contains("Source Port: search-agent (1234)"),
        "{resolved}"
    );

    let numeric = run(&["-V", "-c", "1", "-r", &capture]);
    let numeric = text(&numeric);
    assert!(
        numeric.contains("Src Port: 1234, Dst Port: 80"),
        "{numeric}"
    );
}

#[test]
fn detail_shows_hosts_file_names_and_double_parentheses_when_unresolved() {
    let capture = fixture("names-hosts.pcap");
    let hosts = hosts_fixture();
    let resolved = run(&["-H", &hosts, "-N", "n", "-V", "-c", "1", "-r", &capture]);
    let resolved = text(&resolved);
    assert!(
        resolved.contains("Source Address: gateway.local (192.168.1.1)"),
        "{resolved}"
    );
    assert!(
        resolved.contains("Destination Address: dns.google (8.8.8.8)"),
        "{resolved}"
    );

    let unresolved = run(&["-N", "n", "-V", "-c", "1", "-r", &capture]);
    let unresolved = text(&unresolved);
    assert!(
        unresolved.contains("Source Address: 192.168.1.1 (192.168.1.1)"),
        "{unresolved}"
    );
}

#[test]
fn pdml_default_output_contains_hidden_resolved_children() {
    let capture = fixture("names-mac.pcap");
    let run = run(&["-T", "pdml", "-c", "1", "-r", &capture]);
    let pdml = text(&run);
    assert!(
        pdml.contains(
            "name=\"eth.src_resolved\" showname=\"Source (resolved): Cisco_11:22:33\" hide=\"yes\""
        ),
        "{pdml}"
    );
    assert!(
        pdml.contains(
            "name=\"eth.src.oui_resolved\" showname=\"Source OUI (resolved): Cisco Systems, Inc\""
        ),
        "{pdml}"
    );
}

#[test]
fn resolved_fields_are_available_to_display_filters() {
    let capture = fixture("names-mac.pcap");
    let run = run(&[
        "-Y",
        "eth.src_resolved == \"Cisco_11:22:33\" or eth.src.oui_resolved == \"Apple, Inc.\"",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-r",
        &capture,
    ]);
    assert_eq!(text(&run), "1\n3\n", "stderr: {}", stderr(&run));
}

#[test]
fn forced_terminal_colour_writes_the_escape_sequence() {
    let capture = fixture("color.pcap");
    let colored = run(&["--color", "--pf-terminal-color", "-r", &capture]);
    let stdout = text(&colored);
    let mut lines = stdout.lines();
    let first = lines.next().unwrap_or_default();
    assert!(
        first.starts_with("\u{1b}[38;2;18;39;46m\u{1b}[48;2;250;240;215m"),
        "first coloured line: {first:?}"
    );
    assert!(
        stdout.contains("\u{1b}[K\r\n"),
        "colour terminator missing: {stdout:?}"
    );
    assert!(
        stdout.contains("\u{1b}[38;2;183;247;116m\u{1b}[48;2;18;39;46m"),
        "ICMP-error rule missing: {stdout:?}"
    );

    let piped = run(&["--color", "-r", &capture]);
    assert!(
        !text(&piped).contains('\u{1b}'),
        "piped output must stay uncoloured"
    );
}

#[test]
fn colour_without_the_flag_stays_uncoloured_on_a_forced_terminal() {
    let capture = fixture("color.pcap");
    let run = run(&["--pf-terminal-color", "-r", &capture]);
    assert!(!text(&run).contains('\u{1b}'));
}

#[test]
fn heuristic_report_lists_the_dns_udp_decoder() {
    let run = run(&["-G", "heuristic-decodes"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
    assert_eq!(text(&run), "udp\tdns\tT\tT\tdns_udp\tDNS over UDP\n");
}

#[test]
fn external_resolver_is_never_invoked_and_warns_once() {
    let capture = fixture("names-nrb.pcapng");
    for flags in ["nN", "N"] {
        let run = run(&["-N", flags, "-r", &capture]);
        assert_eq!(status(&run), 0, "{}", stderr(&run));
        let stderr = stderr(&run);
        assert_eq!(
            stderr.matches("external name resolution").count(),
            1,
            "{flags}: {stderr}"
        );
    }

    let cleared = run(&["-N", "nN", "-N", "n", "-r", &capture]);
    assert!(!stderr(&cleared).contains("external name resolution"));
}

#[test]
fn empty_nameres_value_clears_every_flag() {
    let capture = fixture("names-nrb.pcapng");
    let run = run(&[
        "-N",
        "",
        "-T",
        "fields",
        "-e",
        "ip.src_host",
        "-r",
        &capture,
    ]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
    assert_eq!(text(&run), "192.0.2.55\n\n");
}

#[test]
fn invalid_name_and_policy_options_exit_one() {
    let capture = fixture("names-dns.pcap");
    for arguments in [
        vec!["-N", "x", "-r", &capture],
        vec!["-H", "/nonexistent/packetfin-hosts", "-r", &capture],
        vec!["-d", "bogus==1,http", "-r", &capture],
        vec!["-d", "tcp.port==abc,udp", "-r", &capture],
        vec!["-d", "tcp.port==53,udp", "-r", &capture],
        vec!["-d", "tcp.port==53", "-r", &capture],
        vec!["-o", "bogus:x", "-r", &capture],
        vec!["-o", "IP.CHECK_CHECKSUM:TRUE", "-r", &capture],
        vec!["-o", "cflow.netflow.ports:70000", "-r", &capture],
        vec!["-d", "udp.port==20006 ,dns", "-r", &capture],
        vec!["-o", "cflow.netflow.ports:,9999", "-r", &capture],
        vec!["--disable-protocol", "DNS", "-r", &capture],
        vec!["--enable-protocol", "nosuch", "-r", &capture],
        vec!["--disable-heuristic", "ALL", "-r", &capture],
    ] {
        let run = run(&arguments);
        assert_eq!(status(&run), 1, "arguments: {arguments:?}");
        assert!(!run.stderr.is_empty(), "arguments: {arguments:?}");
    }
}

#[test]
fn preference_and_decode_as_validation_follow_the_rules() {
    let capture = fixture("names-dns.pcap");
    for arguments in [
        vec!["-o", "IP.check_checksum:TRUE"],
        vec!["-o", "ip.check_checksum: TRUE"],
        vec!["-o", "ip.check_checksum:maybe"],
        vec!["-o", "cflow.netflow.ports:2055,2056"],
        vec!["-o", "cflow.netflow.ports:"],
    ] {
        let mut arguments = arguments;
        arguments.extend(["-r", &capture]);
        let run = run(&arguments);
        assert_eq!(
            status(&run),
            0,
            "arguments: {arguments:?}: {}",
            stderr(&run)
        );
    }
}

#[test]
fn huge_and_invalid_utf8_hosts_files_stay_bounded() {
    let capture = fixture("names-hosts.pcap");
    let path = std::env::temp_dir().join(format!("packetfin-names-hosts-{}", std::process::id()));
    let mut file = fs::File::create(&path).unwrap_or_else(|error| {
        eprintln!("cannot create {}: {error}", path.display());
        std::process::exit(1);
    });
    for index in 0..200_000_u32 {
        let _ = writeln!(file, "10.0.0.{} host{index}.example", index % 250);
    }
    let _ = file.write_all(&[0xff, 0xfe, b' ', b'h', b'o', b's', b't', b'\n']);
    drop(file);

    let path_text = path.to_string_lossy().into_owned();
    let run = run(&["-H", &path_text, "-N", "n", "-r", &capture]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
    let stderr = stderr(&run);
    assert!(stderr.contains("truncated"), "{stderr}");
    let _ = fs::remove_file(&path);
}

fn control_nrb_capture() -> Vec<u8> {
    use packetfin_testkit::pcapng::{EnhancedPacket, Interface, NameResolution, PcapNg};
    use packetfin_testkit::{ByteOrder, Timestamp};

    let mut capture = PcapNg::new(ByteOrder::Little);
    let interface = capture
        .add_interface(Interface::ethernet())
        .unwrap_or_else(|error| {
            eprintln!("cannot add interface: {error}");
            std::process::exit(1);
        });
    capture
        .add_name_resolution(NameResolution::new().add_ipv4([192, 0, 2, 9], &["nrb.\u{1b}example"]))
        .unwrap_or_else(|error| {
            eprintln!("cannot add names: {error}");
            std::process::exit(1);
        });

    let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
    frame.extend_from_slice(&[
        0x45, 0, 0, 29, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 9, 192, 0, 2, 1,
    ]);
    frame.extend_from_slice(&[0x04, 0xd2, 0x22, 0x3d, 0, 9, 0, 0, b'x']);
    capture
        .add_enhanced_packet(EnhancedPacket::new(
            interface,
            Timestamp::new(1_700_000_000, 0),
            frame,
        ))
        .unwrap_or_else(|error| {
            eprintln!("cannot add packet: {error}");
            std::process::exit(1);
        });
    capture.to_bytes().unwrap_or_else(|error| {
        eprintln!("cannot build capture: {error}");
        std::process::exit(1);
    })
}

#[test]
fn control_characters_in_hosts_and_nrb_names_are_escaped() {
    let hosts_capture = fixture("names-hosts.pcap");
    let hosts_path = std::env::temp_dir().join(format!(
        "packetfin-names-control-hosts-{}",
        std::process::id()
    ));
    fs::write(&hosts_path, b"192.168.1.1 host.\x1b[31mexample\n").unwrap_or_else(|error| {
        eprintln!("cannot write {}: {error}", hosts_path.display());
        std::process::exit(1);
    });
    let hosts_text = hosts_path.to_string_lossy().into_owned();
    let detail = run(&[
        "-H",
        &hosts_text,
        "-N",
        "n",
        "-V",
        "-c",
        "1",
        "-r",
        &hosts_capture,
    ]);
    let detail = text(&detail);
    assert!(
        detail.contains("Source Address: host.\\x1B[31mexample (192.168.1.1)"),
        "{detail}"
    );
    assert!(
        !detail.contains(['\u{1b}']),
        "raw escape in detail: {detail:?}"
    );

    let psml = run(&[
        "-H",
        &hosts_text,
        "-N",
        "n",
        "-T",
        "psml",
        "-c",
        "1",
        "-r",
        &hosts_capture,
    ]);
    let psml = text(&psml);
    assert!(
        psml.contains("<section>host.\\x1b[31mexample</section>"),
        "{psml}"
    );
    assert!(!psml.contains(['\u{1b}']), "raw escape in PSML: {psml:?}");
    let _ = fs::remove_file(&hosts_path);

    let nrb_path = std::env::temp_dir().join(format!(
        "packetfin-names-control-nrb-{}",
        std::process::id()
    ));
    fs::write(&nrb_path, control_nrb_capture()).unwrap_or_else(|error| {
        eprintln!("cannot write {}: {error}", nrb_path.display());
        std::process::exit(1);
    });
    let nrb_text = nrb_path.to_string_lossy().into_owned();
    let detail = run(&["-N", "n", "-V", "-c", "1", "-r", &nrb_text]);
    let detail = text(&detail);
    assert!(
        detail.contains("Source Address: nrb.\\x1Bexample (192.0.2.9)"),
        "{detail}"
    );
    let psml = run(&["-N", "n", "-T", "psml", "-c", "1", "-r", &nrb_text]);
    let psml = text(&psml);
    assert!(
        psml.contains("<section>nrb.\\x1bexample</section>"),
        "{psml}"
    );
    let _ = fs::remove_file(&nrb_path);
}

#[test]
fn forced_tcp_decode_as_stops_sni_learning() {
    let capture = fixture("names-sni.pcap");

    let learned = run(&[
        "-N",
        "ns",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "ip.src_host",
        "-e",
        "ip.dst_host",
        "-r",
        &capture,
    ]);
    assert!(
        text(&learned).ends_with("2\t198.51.100.40\tsni.example\n"),
        "{}",
        text(&learned)
    );

    let forced = run(&[
        "-N",
        "ns",
        "-d",
        "tcp.port==443,data",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "ip.src_host",
        "-e",
        "ip.dst_host",
        "-r",
        &capture,
    ]);
    assert_eq!(
        text(&forced),
        "1\t198.51.100.40\t192.0.2.1\n2\t198.51.100.40\t192.0.2.1\n",
        "{}",
        stderr(&forced)
    );
}

#[test]
fn pdml_ipv6_host_fields_carry_the_address_bytes() {
    let capture = fixture("names-nrb.pcapng");
    let run = run(&["-N", "n", "-T", "pdml", "-c", "2", "-r", &capture]);
    let pdml = text(&run);
    assert!(
        pdml.contains(
            "name=\"ipv6.src_host\" showname=\"Source Host: host6.example\" hide=\"yes\" size=\"16\""
        ),
        "{pdml}"
    );
    assert!(
        pdml.contains("value=\"20010db8000000000000000000000037\""),
        "{pdml}"
    );
}
