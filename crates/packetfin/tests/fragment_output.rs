//! Raw byte sources for transports decoded from a reassembled fragment
//! datagram, and the fragment-specific output contracts.

use std::path::PathBuf;
use std::process::Command;

use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

fn fixture(name: &str) -> PathBuf {
    golden::fixtures_dir().join(name)
}

fn run(arguments: &[&str], fixture_name: &str) -> String {
    let path = fixture(fixture_name);
    let output = Command::new(BIN)
        .args(arguments)
        .arg("-r")
        .arg(path)
        .output()
        .unwrap_or_else(|error| {
            eprintln!("failed to run packetfin: {error}");
            std::process::exit(1);
        });
    assert!(
        output.status.success(),
        "packetfin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn field_line<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find(|line| line.contains(name))
}

fn raw_array<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let start = text.find(key)?;
    let rest = text.get(start..)?;
    let end = rest.find(']')?;
    rest.get(..=end)
}

fn raw_array_last<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let start = text.rfind(key)?;
    let rest = text.get(start..)?;
    let end = rest.find(']')?;
    rest.get(..=end)
}

fn source_is_one(array: &str) -> bool {
    array.trim_end_matches([' ', '\n', ']']).ends_with('1')
}

#[test]
fn reassembled_transport_pdml_uses_the_reassembled_bytes() {
    for (fixture_name, checksum) in [
        ("ipv4-fragments.pcap", "933f"),
        ("ipv6-fragments.pcap", "9876"),
    ] {
        let text = run(
            &["-n", "-Y", "frame.number == 2", "-T", "pdml"],
            fixture_name,
        );
        let srcport = field_line(&text, "<field name=\"udp.srcport\"");
        assert!(srcport.is_some(), "udp.srcport missing: {fixture_name}");
        assert!(
            srcport
                .is_some_and(|line| line.contains("size=\"2\"") && line.contains("value=\"0001\"")),
            "udp.srcport must carry the reassembled source bytes: {srcport:?}"
        );
        let payload = field_line(&text, "<field name=\"udp.payload\"");
        assert!(
            payload.is_some_and(|line| line.contains("size=\"92\"")
                && line.contains("pos=\"8\"")
                && !line.contains("field length invalid!")),
            "udp.payload must cover the reassembled payload: {payload:?}"
        );
        assert!(
            text.contains(checksum),
            "the reassembled checksum is missing for {fixture_name}"
        );
        assert!(
            !text.contains("value=\"0200\""),
            "frame bytes leaked into the transport: {fixture_name}"
        );
    }
}

#[test]
fn reassembled_transport_jsonraw_and_ek_use_the_reassembled_bytes() {
    for (fixture_name, udp_raw, payload_prefix) in [
        ("ipv4-fragments.pcap", "000102030064933f", "1011121314"),
        ("ipv6-fragments.pcap", "0001020300649876", "5051525354"),
    ] {
        let jsonraw = run(
            &["-n", "-Y", "frame.number == 2", "-T", "jsonraw"],
            fixture_name,
        );
        let srcport = raw_array(&jsonraw, "\"udp.srcport_raw\"");
        assert!(
            srcport.is_some_and(|array| array.contains("0001")),
            "udp.srcport_raw is not the reassembled source: {srcport:?}"
        );
        let payload = raw_array(&jsonraw, "\"udp.payload_raw\"");
        assert!(
            payload.is_some_and(|array| array.contains(payload_prefix)),
            "udp.payload_raw is not the reassembled payload: {payload:?}"
        );
        let port = raw_array_last(&jsonraw, "\"udp.port_raw\"");
        assert!(
            port.is_some_and(|array| array.contains("0203") && source_is_one(array)),
            "udp.port_raw is not the reassembled port: {port:?}"
        );
        let stream = raw_array(&jsonraw, "\"udp.stream_raw\"");
        assert!(
            stream.is_some_and(|array| array.contains("8,") && source_is_one(array)),
            "udp.stream_raw is not the generated stream index: {stream:?}"
        );

        let ek = run(
            &["-n", "-Y", "frame.number == 2", "-T", "ek", "-x"],
            fixture_name,
        );
        let line = ek
            .lines()
            .find(|line| line.contains("\"udp_raw\""))
            .unwrap_or_default();
        let value = line
            .split("\"udp_raw\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        assert_eq!(
            value, udp_raw,
            "EK udp_raw must be the reassembled header: {line}"
        );
        assert!(
            line.contains("\"udp_udp_port_raw\":[\"0001\",\"0203\"]"),
            "EK udp.port raws are missing or frame-derived: {line}"
        );
    }
}

#[test]
fn conflicting_overlap_records_use_the_merged_reassembly() {
    for (fixture_name, expected) in [
        ("ipv4-fragments.pcap", "202122232425"),
        ("ipv6-fragments.pcap", "606162636465"),
    ] {
        let jsonraw = run(
            &["-n", "-Y", "frame.number == 6", "-T", "jsonraw"],
            fixture_name,
        );
        let key = if fixture_name.starts_with("ipv4") {
            "\"ip.fragment.error_raw\""
        } else {
            "\"ipv6.fragment.error_raw\""
        };
        let raw = raw_array(&jsonraw, key);
        assert!(
            raw.is_some_and(|array| array.contains(expected)),
            "the record raw must use the merged bytes: {raw:?}"
        );
        assert!(
            raw.is_some_and(|array| !array.contains("eeeeeeeeeeeeeeee")),
            "the record raw kept the fragment's own conflicting bytes: {raw:?}"
        );
    }
}

#[test]
fn defragment_preferences_disable_reassembly() {
    let ipv4 = run(
        &[
            "-n",
            "-o",
            "ip.defragment:FALSE",
            "-T",
            "fields",
            "-e",
            "ip.fragment",
            "-e",
            "ip.reassembled.length",
        ],
        "ipv4-fragments.pcap",
    );
    assert!(
        ipv4.lines().all(|line| line.trim().is_empty()),
        "ip.defragment:FALSE retained fragment state: {ipv4}"
    );
    let ipv6 = run(
        &[
            "-n",
            "-o",
            "ipv6.defragment:FALSE",
            "-T",
            "fields",
            "-e",
            "ipv6.fragment",
            "-e",
            "ipv6.reassembled.length",
        ],
        "ipv6-fragments.pcap",
    );
    assert!(
        ipv6.lines().all(|line| line.trim().is_empty()),
        "ipv6.defragment:FALSE retained fragment state: {ipv6}"
    );
}

#[test]
fn completed_unknown_protocols_do_not_keep_a_fragment_summary() {
    let summary = run(&["-n"], "fragment-unknown.pcap");
    assert!(
        summary.contains("IPv4 54 Unknown (250)"),
        "IPv4 unknown completion kept the fragment label: {summary}"
    );
    assert!(
        summary.contains("Unknown IP Protocol: Unknown (250)"),
        "IPv6 unknown completion kept the fragment label: {summary}"
    );
    let completions: Vec<&str> = summary
        .lines()
        .filter(|line| {
            line.contains(" 2 ")
                || line.contains(" 4 ")
                || line.contains(" 6 ")
                || line.contains(" 8 ")
        })
        .collect();
    for line in completions {
        assert!(
            !line.contains("Fragmented IP protocol") && !line.contains("IPv6 fragment"),
            "a completed datagram kept a fragment summary: {line}"
        );
    }
}

#[test]
fn tunneled_reassembled_udp_has_no_false_bad_length() {
    let summary = run(&["-n"], "fragment-tunnel.pcap");
    assert!(
        summary.contains("UDP 74 1 → 515 Len=92"),
        "the tunneled reassembled UDP summary is wrong: {summary}"
    );
    assert!(
        !summary.contains("BAD UDP LENGTH"),
        "the outer IP payload was used for the inner datagram: {summary}"
    );
}

#[test]
fn fragmented_transport_masks_keep_their_masked_values() {
    let tcp_pdml = run(
        &["-n", "-Y", "frame.number == 2", "-T", "pdml"],
        "fragment-transports.pcap",
    );
    let flags = field_line(&tcp_pdml, "<field name=\"tcp.flags\"");
    assert!(
        flags.is_some_and(
            |line| line.contains("value=\"18\"") && line.contains("unmaskedvalue=\"5018\"")
        ),
        "tcp.flags mask is lost: {flags:?}"
    );
    let ack = field_line(&tcp_pdml, "<field name=\"tcp.flags.ack\"");
    assert!(
        ack.is_some_and(|line| line.contains("size=\"1\"")
            && line.contains("pos=\"13\"")
            && line.contains("value=\"1\"")
            && line.contains("unmaskedvalue=\"18\"")),
        "tcp.flags.ack mask is lost: {ack:?}"
    );
    let tcp_json = run(
        &["-n", "-Y", "frame.number == 2", "-T", "jsonraw"],
        "fragment-transports.pcap",
    );
    let raw = raw_array(&tcp_json, "\"tcp.flags_raw\"");
    assert!(
        raw.is_some_and(|array| array.contains("\"18\"") && array.contains("4095")),
        "tcp.flags_raw is not masked: {raw:?}"
    );
    let str_raw = raw_array(&tcp_json, "\"tcp.flags.str_raw\"");
    assert!(
        str_raw.is_some_and(|array| array.contains("5018")),
        "tcp.flags.str_raw is not the reassembled flags: {str_raw:?}"
    );
    let tcp_ek = run(
        &["-n", "-Y", "frame.number == 2", "-T", "ek", "-x"],
        "fragment-transports.pcap",
    );
    let line = tcp_ek
        .lines()
        .find(|line| line.contains("\"tcp\""))
        .unwrap_or_default();
    assert!(
        line.contains("\"tcp_tcp_flags_raw\":\"18\"")
            && line.contains("\"tcp_tcp_flags_str_raw\":\"5018\"")
            && line.contains("\"tcp_tcp_flags_ack_raw\":\"1\""),
        "EK TCP flag raws are not masked: {line}"
    );

    let dns_pdml = run(
        &["-n", "-Y", "frame.number == 4", "-T", "pdml"],
        "fragment-transports.pcap",
    );
    let response = field_line(&dns_pdml, "<field name=\"dns.flags.response\"");
    assert!(
        response.is_some_and(
            |line| line.contains("value=\"1\"") && line.contains("unmaskedvalue=\"8180\"")
        ),
        "dns.flags.response mask is lost: {response:?}"
    );
    let dns_json = run(
        &["-n", "-Y", "frame.number == 4", "-T", "jsonraw"],
        "fragment-transports.pcap",
    );
    let flags_raw = raw_array(&dns_json, "\"dns.flags_raw\"");
    assert!(
        flags_raw.is_some_and(|array| array.contains("8180")),
        "dns.flags_raw is not the reassembled flags: {flags_raw:?}"
    );
    let response_raw = raw_array(&dns_json, "\"dns.flags.response_raw\"");
    assert!(
        response_raw.is_some_and(|array| array.contains("\"1\"") && array.contains("32768")),
        "dns.flags.response_raw is not masked: {response_raw:?}"
    );
}

#[test]
fn tunnel_reassembly_link_is_placed_on_the_inner_ip_header() {
    let text = run(&["-n", "-2", "-V"], "fragment-tunnel.pcap");
    let frame = text.split("Frame 2:").next().unwrap_or_default();
    let first = frame.find("Internet Protocol Version 4,").unwrap_or(0);
    let second = frame
        .get(first.saturating_add(1)..)
        .and_then(|rest| rest.find("Internet Protocol Version 4,"))
        .map_or(first, |offset| {
            first.saturating_add(1).saturating_add(offset)
        });
    let link = frame
        .find("[Reassembled IPv4 in frame: 2]")
        .unwrap_or(usize::MAX);
    assert!(
        second > first && link > second,
        "link must follow the inner IPv4 header: {frame:?}"
    );
}
