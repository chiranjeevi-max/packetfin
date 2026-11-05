//! End-to-end tests for `-G` glossary reports.

use std::process::{Command, ExitStatus, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(args: &[&str]) -> Run {
    match Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => Run {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        },
        Err(error) => {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        }
    }
}

fn status_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

fn stdout_text(run: &Run) -> String {
    String::from_utf8_lossy(&run.stdout).into_owned()
}

fn stderr_text(run: &Run) -> String {
    String::from_utf8_lossy(&run.stderr).into_owned()
}

#[test]
fn fields_report_lists_the_registry_without_a_capture() {
    let run = run(&["-G", "fields"]);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stderr.is_empty(), "stderr: {}", stderr_text(&run));

    let stdout = stdout_text(&run);
    assert_eq!(stdout, include_str!("reference/fields.tsv"));
}

#[test]
fn protocols_report_lists_the_registry() {
    let run = run(&["-G", "protocols"]);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(run.stderr.is_empty(), "stderr: {}", stderr_text(&run));
    assert_eq!(
        stdout_text(&run),
        "Frame\tFrame\tframe\tT\tT\tF\n\
         Ethernet\tEthernet\teth\tT\tT\tT\n\
         Logical-Link Control\tLLC\tllc\tT\tT\tT\n\
         802.1Q Virtual LAN\tVLAN\tvlan\tT\tT\tT\n\
         IEEE 802.1ad\tIEEE 802.1AD\tieee8021ad\tT\tT\tT\n\
         Linux cooked-mode capture\tSLL\tsll\tT\tT\tT\n\
         Null/Loopback\tNull\tnull\tT\tT\tT\n\
         Address Resolution Protocol\tARP/RARP\tarp\tT\tT\tT\n\
         Internet Protocol Version 4\tIPv4\tip\tT\tT\tT\n\
         Internet Protocol Version 6\tIPv6\tipv6\tT\tT\tT\n\
         IPv6 Hop-by-Hop Option\tIPv6 Hop-by-Hop\tipv6.hopopts\tT\tT\tT\n\
         Destination Options for IPv6\tIPv6 Destination\tipv6.dstopts\tT\tT\tT\n\
         Routing Header for IPv6\tIPv6 Routing\tipv6.routing\tT\tT\tT\n\
         Fragment Header for IPv6\tIPv6 Fragment\tipv6.fraghdr\tT\tT\tT\n\
         Transmission Control Protocol\tTCP\ttcp\tT\tT\tT\n\
         User Datagram Protocol\tUDP\tudp\tT\tT\tT\n\
         Domain Name System\tDNS\tdns\tT\tT\tT\n\
         Multicast Domain Name System\tmDNS\tmdns\tT\tT\tT\n\
         Link-local Multicast Name Resolution\tLLMNR\tllmnr\tT\tT\tT\n\
         Dynamic Host Configuration Protocol\tDHCP/BOOTP\tdhcp\tT\tT\tT\n\
         DHCPv6\tDHCPv6\tdhcpv6\tT\tT\tT\n\
         Network Time Protocol\tNTP\tntp\tT\tT\tT\n\
         Internet Control Message Protocol\tICMP\ticmp\tT\tT\tT\n\
         Internet Control Message Protocol v6\tICMPv6\ticmpv6\tT\tT\tT\n\
         Encapsulated Remote Switch Packet ANalysis\tERSPAN\terspan\tT\tT\tT\n\
         Generic Network Virtualization Encapsulation\tGeneve\tgeneve\tT\tT\tT\n\
         Generic Routing Encapsulation\tGRE\tgre\tT\tT\tT\n\
         MultiProtocol Label Switching Header\tMPLS\tmpls\tT\tT\tT\n\
         Virtual eXtensible Local Area Network\tVXLAN\tvxlan\tT\tT\tT\n\
         Bidirectional Forwarding Detection Control Message\tBFD Control\tbfd\tT\tT\tT\n\
         Bidirectional Forwarding Detection Echo Packet\tBFD Echo\tbfd_echo\tT\tT\tT\n\
         Open Shortest Path First\tOSPF\tospf\tT\tT\tT\n\
         Virtual Router Redundancy Protocol\tVRRP\tvrrp\tT\tT\tT\n\
         Link Aggregation Control Protocol\tLACP\tlacp\tT\tT\tT\n\
         Link Layer Discovery Protocol\tLLDP\tlldp\tT\tT\tT\n\
         Link Aggregation Marker Protocol\tMarker\tmarker\tT\tT\tT\n\
         802.3 Slow protocols\tSlow Protocols\tslow\tT\tT\tT\n\
         Spanning Tree Protocol\tSTP\tstp\tT\tT\tT\n\
         Cisco NetFlow/IPFIX\tCFLOW\tcflow\tT\tT\tT\n\
         InMon sFlow\tsFlow\tsflow\tT\tT\tT\n\
         Simple Network Management Protocol\tSNMP\tsnmp\tT\tT\tT\n\
         Syslog Message\tSyslog\tsyslog\tT\tT\tT\n\
         Border Gateway Protocol\tBGP\tbgp\tT\tT\tT\n\
         Hypertext Transfer Protocol\tHTTP\thttp\tT\tT\tT\n\
         Transport Layer Security\tTLS\ttls\tT\tT\tT\n"
    );
}

#[test]
fn bare_g_requires_a_report() {
    let bare = run(&["-G"]);
    assert_eq!(
        status_code(bare.status),
        Some(1),
        "stderr: {}",
        stderr_text(&bare)
    );
    assert!(bare.stdout.is_empty(), "stdout: {:?}", bare.stdout);
    let stderr = stderr_text(&bare);
    assert!(!stderr.is_empty(), "stderr must explain the missing report");
    assert!(
        stderr.contains("option -G requires an argument"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("Usage:"), "stderr: {stderr}");

    let attached = run(&["-Gfields"]);
    assert_eq!(
        status_code(attached.status),
        Some(0),
        "stderr: {}",
        stderr_text(&attached)
    );
    assert!(
        stdout_text(&attached).starts_with("F\t"),
        "attached -G fields must still print the report"
    );
}

#[test]
fn g_help_exits_zero_and_documents_reports() {
    let run = run(&["-G", "help"]);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    let stdout = stdout_text(&run);
    assert!(stdout.contains("-G fields"), "stdout: {stdout}");
    assert!(stdout.contains("-G protocols"), "stdout: {stdout}");
    assert!(!stdout.contains("With no report"), "stdout: {stdout}");
}

#[test]
fn unknown_report_exits_one_without_output() {
    let run = run(&["-G", "bogus"]);
    assert_eq!(status_code(run.status), Some(1));
    assert!(run.stdout.is_empty(), "stdout: {:?}", run.stdout);
    assert!(
        stderr_text(&run).contains("bogus"),
        "stderr: {}",
        stderr_text(&run)
    );
}

#[test]
fn report_ignores_a_later_capture_argument() {
    let run = run(&["-G", "protocols", "-r", "does-not-exist.pcap"]);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert!(stdout_text(&run).contains("Frame\tFrame\tframe"));
}

#[test]
fn broken_stdout_pipe_is_ignored_for_reports() {
    let (reader, writer) = match std::io::pipe() {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("failed to create a pipe: {error}");
            std::process::exit(1);
        }
    };
    drop(reader);

    let output = match Command::new(BIN)
        .args(["-G", "fields"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        }
    };
    assert_eq!(status_code(output.status), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn report_ignores_words_after_double_dash() {
    let run = run(&["-G", "fields", "--", "udp.port==53"]);
    assert_eq!(
        status_code(run.status),
        Some(0),
        "stderr: {}",
        stderr_text(&run)
    );
    assert_eq!(stdout_text(&run), include_str!("reference/fields.tsv"));
}

#[test]
fn trailing_unknown_option_after_report_exits_one() {
    let run = run(&["-G", "fields", "--bogus"]);
    assert_eq!(status_code(run.status), Some(1));
    assert!(run.stdout.is_empty(), "stdout must not hold a report");
    assert!(
        stderr_text(&run).starts_with("packetfin: unrecognized option: --bogus"),
        "stderr: {}",
        stderr_text(&run)
    );
}

#[test]
fn second_glossary_report_exits_one() {
    for args in [
        ["-G", "fields", "-G", "bogus"].as_slice(),
        ["-G", "fields", "-G", "fields"].as_slice(),
    ] {
        let run = run(args);
        assert_eq!(status_code(run.status), Some(1), "args: {args:?}");
        assert!(run.stdout.is_empty(), "stdout must not hold a report");
        assert!(
            stderr_text(&run).contains("multiple glossary reports"),
            "stderr: {}",
            stderr_text(&run)
        );
    }
}

#[test]
fn help_after_invalid_report_value_exits_zero() {
    let run = run(&["-G", "bogus", "-h"]);
    assert_eq!(status_code(run.status), Some(0));
    assert!(
        stdout_text(&run).contains("Usage: packetfin [options]"),
        "stdout: {}",
        stdout_text(&run)
    );
}

#[test]
fn report_still_validates_field_arguments() {
    let unknown_field = run(&["-G", "fields", "-T", "fields", "-e", "bogus"]);
    assert_eq!(status_code(unknown_field.status), Some(1));
    assert!(
        unknown_field.stdout.is_empty(),
        "stdout must not hold a report"
    );

    let missing_format = run(&["-G", "fields", "-e", "frame.number"]);
    assert_eq!(status_code(missing_format.status), Some(1));
    assert!(
        missing_format.stdout.is_empty(),
        "stdout must not hold a report"
    );

    let missing_fields = run(&["-G", "fields", "-T", "fields"]);
    assert_eq!(status_code(missing_fields.status), Some(1));
    assert!(
        missing_fields.stdout.is_empty(),
        "stdout must not hold a report"
    );
}
