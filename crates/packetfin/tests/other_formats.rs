//! End-to-end tests for `-T ek`, `-T tabs` and `-T ps`.
//!
//! Tabs and EK golden output is compared byte for byte. PostScript tests
//! compare only the logical `putline` records with the golden output; the
//! prolog itself is checked structurally.

use std::ffi::OsString;
use std::path::PathBuf;
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
    let output = Command::new(BIN)
        .args(args)
        .current_dir(golden::repo_root())
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

fn status_code(status: ExitStatus) -> Option<i32> {
    status.code()
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

fn format_args(path: &std::path::Path, format: &str, extra: &[&str]) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from(format),
    ];
    args.extend(extra.iter().map(OsString::from));
    args.push(OsString::from("-r"));
    args.push(path.as_os_str().to_owned());
    args
}

fn stderr_text(run: &Run) -> String {
    String::from_utf8_lossy(&run.stderr).into_owned()
}

fn is_ps(case: &str) -> bool {
    case == "ps" || case.starts_with("ps-")
}

#[test]
fn golden_tabs_and_ek_cases_match() {
    let mut compared = 0_usize;
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("tabs")
                && !case.id.starts_with("ek-e-")
                && case.id != "ek-p"
                && case.id != "ek-empty"
            {
                continue;
            }
            let args: Vec<OsString> = case.args.iter().map(OsString::from).collect();
            let run = run(&args);
            let expected = match golden::load(fixture.name, case.id) {
                Ok(expected) => expected,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(1);
                }
            };
            assert_eq!(
                status_code(run.status),
                Some(expected.status),
                "{}/{}: status; stderr: {}",
                fixture.name,
                case.id,
                stderr_text(&run)
            );
            assert_eq!(
                run.stdout,
                expected.stdout,
                "{}/{}: stdout differs; stderr: {}",
                fixture.name,
                case.id,
                stderr_text(&run)
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no tabs/EK golden cases were compared");
}

#[test]
fn golden_postscript_text_records_match() {
    let mut compared = 0_usize;
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !is_ps(case.id) {
                continue;
            }
            let args: Vec<OsString> = case.args.iter().map(OsString::from).collect();
            let run = run(&args);
            let expected = match golden::load(fixture.name, case.id) {
                Ok(expected) => expected,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(1);
                }
            };
            assert_eq!(
                status_code(run.status),
                Some(expected.status),
                "{}/{}: status; stderr: {}",
                fixture.name,
                case.id,
                stderr_text(&run)
            );
            let observed = String::from_utf8_lossy(&run.stdout);
            let stored = String::from_utf8_lossy(&expected.stdout);
            assert_eq!(
                putline_records(&observed),
                putline_records(&stored),
                "{}/{}: PostScript text records differ",
                fixture.name,
                case.id
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no PostScript golden cases were compared");
}

fn golden_args(fixture: &Fixture, case_id: &str) -> Vec<OsString> {
    fixture
        .cases()
        .iter()
        .find(|case| case.id == case_id)
        .map(|case| case.args.iter().map(OsString::from).collect())
        .unwrap_or_default()
}

fn extract_object(text: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":{{");
    let start = text.find(&marker)? + marker.len() - 1;
    let bytes = text.as_bytes();
    let mut depth = 0_i32;
    let mut index = start;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(byte) = bytes.get(index) {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
        } else if *byte == b'"' {
            in_string = true;
        } else if *byte == b'{' {
            depth += 1;
        } else if *byte == b'}' {
            depth -= 1;
            if depth == 0 {
                return text.get(start..=index).map(str::to_string);
            }
        }
        index += 1;
    }
    None
}

#[test]
fn ek_tree_cases_match_parsed_and_layer_order() {
    let expected_layers = |fixture_name: &str, case_id: &str| -> &'static [&'static str] {
        match (fixture_name, case_id) {
            ("routing-ospf-v2", _) => &["frame", "eth", "ip", "ospf"],
            ("routing-ospf-v3", "ek-tree-expert" | "ek-tree-malformed") => {
                &["frame", "eth", "ipv6", "ospf", "_ws_malformed"]
            }
            ("routing-ospf-v3", _) => &["frame", "eth", "ipv6", "ospf"],
            ("routing-bfd", _) => &["frame", "eth", "ip", "udp", "bfd"],
            ("routing-vrrp", _) => &["frame", "eth", "ip", "vrrp"],
            ("lldp" | "lldp-malformed", _) => &["frame", "eth", "lldp"],
            ("udp-edge", _) => &["frame", "eth", "ip", "udp", "data"],
            (
                "dhcp-discover-offer"
                | "dhcp-overload"
                | "dhcp-malformed"
                | "dhcp-client-id"
                | "dhcp-hardware"
                | "dhcp-long-option",
                _,
            ) => &["frame", "eth", "ip", "udp", "dhcp"],
            ("dhcpv6-solicit-advertise" | "dhcpv6-relay" | "dhcpv6-malformed", _) => {
                &["frame", "eth", "ip", "udp", "dhcpv6"]
            }
            _ => &[],
        }
    };
    let mut compared = 0_usize;
    let mut executed: Vec<(&str, &str)> = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("ek-tree") {
                continue;
            }
            let args = golden_args(fixture, case.id);
            assert!(!args.is_empty(), "missing {}", case.id);
            let run = run(&args);
            let expected = match golden::load(fixture.name, case.id) {
                Ok(expected) => expected,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::exit(1);
                }
            };
            assert_eq!(
                status_code(run.status),
                Some(expected.status),
                "{}/{}: status; stderr: {}",
                fixture.name,
                case.id,
                String::from_utf8_lossy(&run.stderr)
            );
            let observed = String::from_utf8_lossy(&run.stdout);
            let stored = String::from_utf8_lossy(&expected.stdout);
            let observed_lines: Vec<&str> = observed.lines().collect();
            let stored_lines: Vec<&str> = stored.lines().collect();
            assert_eq!(
                observed_lines.len(),
                stored_lines.len(),
                "{}/{}: document count",
                fixture.name,
                case.id
            );
            for (index, (observed_line, stored_line)) in
                observed_lines.iter().zip(&stored_lines).enumerate()
            {
                let observed = Json::parse(observed_line);
                let stored = Json::parse(stored_line);
                assert_eq!(
                    observed, stored,
                    "{}/{}: document {index} differs",
                    fixture.name, case.id
                );
                if let Some(body) = observed.as_object()
                    && let Some((_, layers)) = body.iter().find(|(key, _)| key == "layers")
                {
                    let keys: Vec<&str> = layers
                        .as_object()
                        .unwrap_or_default()
                        .iter()
                        .map(|(key, _)| key.as_str())
                        .collect();
                    let mut expected = expected_layers(fixture.name, case.id).to_vec();
                    // A protocol exception adds the generated malformed
                    // layer after the decoded protocols.
                    if keys.last() == Some(&"_ws_malformed") && !expected.contains(&"_ws_malformed")
                    {
                        expected.push("_ws_malformed");
                    }
                    assert_eq!(
                        keys, expected,
                        "{}/{}: EK layer order",
                        fixture.name, case.id
                    );
                }
            }
            executed.push((fixture.name, case.id));
            compared += 1;
        }
    }
    for expected in [
        ("routing-ospf-v2", "ek-tree"),
        ("routing-ospf-v2", "ek-tree-expert"),
        ("routing-ospf-v3", "ek-tree"),
        ("routing-bfd", "ek-tree"),
        ("routing-bfd", "ek-tree-expert"),
        ("routing-vrrp", "ek-tree"),
        ("routing-vrrp", "ek-tree-expert"),
        ("lldp", "ek-tree"),
        ("lldp-malformed", "ek-tree-expert"),
    ] {
        assert!(
            executed.contains(&expected),
            "EK full-tree case {}/{} did not run",
            expected.0,
            expected.1
        );
    }
    assert!(compared >= 9, "only {compared} EK full-tree cases ran");
}

#[test]
fn ek_quoted_layers_are_nested_without_duplicate_keys() {
    let fixture = fixture("icmp-error-tcp");
    let args = golden_args(fixture, "ek-quoted");
    assert!(!args.is_empty(), "missing ek-quoted case");
    let run = run(&args);
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    let document = match text.lines().nth(1) {
        Some(line) => line,
        None => {
            eprintln!("missing EK document");
            std::process::exit(1);
        }
    };
    let icmp = extract_object(document, "icmp").unwrap_or_default();
    assert!(icmp.contains("\"ip\":{"), "quoted ip not nested under icmp");
    assert!(
        icmp.contains("\"tcp\":{"),
        "quoted tcp not nested under icmp"
    );
    assert!(icmp.contains("\"ip_ip_src\":\"10.0.0.1\""));
    let outer = extract_object(document, "ip").unwrap_or_default();
    assert!(outer.contains("\"ip_ip_src\":\"192.0.2.1\""));
    assert_eq!(
        document.matches("\"ip_ip_src\":\"192.0.2.1\"").count(),
        1,
        "outer IP header duplicated"
    );
    assert_eq!(
        document.matches("\"ip_ip_src\":\"10.0.0.1\"").count(),
        1,
        "quoted IP header duplicated"
    );
}

#[test]
fn ek_comment_and_data_layers_match_golden_output() {
    for (fixture_name, case_id, layer) in [
        ("detail-hostile", "ek-comments-mask", "pkt_comment"),
        ("detail-hostile", "ek-comments-expand", "pkt_comment"),
        ("ipv4-basic", "ek-x-data", "data"),
    ] {
        let fixture = fixture(fixture_name);
        let args = golden_args(fixture, case_id);
        assert!(!args.is_empty(), "missing {case_id}");
        let run = run(&args);
        let expected = match golden::load(fixture_name, case_id) {
            Ok(expected) => expected,
            Err(message) => {
                eprintln!("{message}");
                std::process::exit(1);
            }
        };
        assert_eq!(status_code(run.status), Some(0));
        let observed = String::from_utf8_lossy(&run.stdout);
        let stored = String::from_utf8_lossy(&expected.stdout);
        let observed_document = observed.lines().nth(1).unwrap_or_default();
        let stored_document = stored.lines().nth(1).unwrap_or_default();
        assert_eq!(
            extract_object(observed_document, layer),
            extract_object(stored_document, layer),
            "{case_id}: {layer} differs"
        );
    }
}

#[test]
fn ek_extension_transport_is_a_top_level_layer() {
    for (case_id, expected_udp) in [
        ("ek-placement", "\"udp_udp_srcport\":\"12345\""),
        (
            "ek-j-udp",
            "\"udp_udp_srcport\":{\"filtered\":\"udp.srcport\"}",
        ),
        ("ek-expand-udp", "\"udp_udp_srcport\":\"12345\""),
    ] {
        let fixture = fixture("ipv6-ext-udp");
        let args = golden_args(fixture, case_id);
        assert!(!args.is_empty(), "missing {case_id}");
        let run = run(&args);
        assert_eq!(status_code(run.status), Some(0));
        let observed = String::from_utf8_lossy(&run.stdout);
        let document = observed.lines().nth(1).unwrap_or_default();
        assert!(
            document.contains("\"udp\":{"),
            "{case_id}: no top-level udp"
        );
        let ipv6 = extract_object(document, "ipv6").unwrap_or_default();
        if case_id == "ek-placement" {
            assert!(
                ipv6.contains("\"ipv6_hopopts\":{"),
                "{case_id}: hopopts not nested"
            );
        } else {
            assert!(
                ipv6.contains("\"filtered\":\"ipv6\""),
                "{case_id}: ipv6 not filtered"
            );
        }
        assert!(
            !ipv6.contains("\"udp\":{"),
            "{case_id}: udp nested inside ipv6"
        );
        let udp = extract_object(document, "udp").unwrap_or_default();
        assert!(
            udp.contains(expected_udp),
            "{case_id}: udp body differs: {udp}"
        );
        if case_id == "ek-placement" {
            assert!(
                document.contains("\"ipv6_ipv6_opt_type\":"),
                "{case_id}: option key prefix is not the field parent"
            );
            assert!(
                !document.contains("\"ipv6_hopopts_ipv6_opt_type\":"),
                "{case_id}: option key still uses the enclosing layer"
            );
        }
    }
}

#[test]
fn ek_raw_protocol_extents_match_golden_output() {
    for (fixture_name, case_id, keys) in [
        (
            "arp-request",
            "ek-x-extents",
            vec![("eth_raw", 14_usize), ("arp_raw", 28)],
        ),
        (
            "ethernet-udp-le-us",
            "ek-x-extents",
            vec![("eth_raw", 14), ("ip_raw", 20), ("udp_raw", 8)],
        ),
        (
            "ipv6-ext-udp",
            "ek-x-extents",
            vec![
                ("eth_raw", 14),
                ("ipv6_raw", 48),
                ("ipv6_hopopts_raw", 8),
                ("udp_raw", 8),
            ],
        ),
    ] {
        let fixture = fixture(fixture_name);
        let args = golden_args(fixture, case_id);
        assert!(!args.is_empty(), "missing {case_id}");
        let run = run(&args);
        let expected = match golden::load(fixture_name, case_id) {
            Ok(expected) => expected,
            Err(message) => {
                eprintln!("{message}");
                std::process::exit(1);
            }
        };
        assert_eq!(status_code(run.status), Some(0));
        let observed = String::from_utf8_lossy(&run.stdout);
        let stored = String::from_utf8_lossy(&expected.stdout);
        let observed_document = observed.lines().nth(1).unwrap_or_default();
        let stored_document = stored.lines().nth(1).unwrap_or_default();
        for (key, length) in keys {
            let observed_raw = key_value(observed_document, key).unwrap_or_default();
            let stored_raw = key_value(stored_document, key).unwrap_or_default();
            assert_eq!(
                observed_raw.len(),
                length * 2,
                "{case_id}: {key} extent differs"
            );
            assert_eq!(observed_raw, stored_raw, "{case_id}: {key} bytes differ");
        }
    }
}

fn key_value(document: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let start = document.find(&marker)? + marker.len();
    let rest = document.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(str::to_string)
}

#[test]
fn no_orphan_other_golden_files() {
    for fixture in fixtures::all() {
        let expected: Vec<&str> = fixture
            .cases()
            .iter()
            .filter(|case| {
                case.id.starts_with("tabs") || case.id.starts_with("ek") || is_ps(case.id)
            })
            .map(|case| case.id)
            .collect();
        let directory = golden::golden_dir().join(fixture.name);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let stem = name.split('.').next().unwrap_or(name);
            if stem.starts_with("tabs") || stem.starts_with("ek") || is_ps(stem) {
                assert!(
                    expected.contains(&stem),
                    "golden {}/{} has no registry case",
                    fixture.name,
                    name
                );
            }
        }
    }
}

/// Extract `indent (text) putline` records, unescaping PostScript strings.
fn putline_records(text: &str) -> Vec<(usize, String)> {
    let mut records = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_suffix(" putline") else {
            continue;
        };
        let digits_end = rest.find(' ').unwrap_or(rest.len());
        let Ok(indent) = rest.get(..digits_end).unwrap_or_default().parse() else {
            continue;
        };
        let Some(body) = rest
            .get(digits_end..)
            .and_then(|tail| tail.strip_prefix(" ("))
        else {
            continue;
        };
        let Some(body) = body.strip_suffix(')') else {
            continue;
        };
        records.push((indent, unescape_ps(body)));
    }
    records
}

fn unescape_ps(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(character);
        }
    }
    out
}

#[test]
fn ek_default_is_bulk_json_with_layers() {
    let run = run(&format_args(
        &fixture_path(fixture("ipv4-basic")),
        "ek",
        &["-c", "2"],
    ));
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "two bulk documents");
    for pair in lines.chunks(2) {
        let Some(action) = pair.first() else {
            continue;
        };
        let Some(document) = pair.get(1) else {
            continue;
        };
        assert!(action.starts_with("{\"index\":{\"_index\":\"packets-"));
        assert!(document.starts_with("{\"timestamp\":\""));
        assert!(document.contains("\"layers\":{"));
        assert!(document.contains("\"ip\":{"));
        assert!(document.contains("\"frame\":{"));
        assert!(document.contains("\"frame_frame_time\":\"2023-11-14T"));
        assert!(document.contains("\"frame_frame_encap_type\":\"1\""));
        assert!(document.contains("\"frame_frame_protocols\":\"eth:ethertype:ip:data\""));
        assert!(document.contains("\"frame_frame_encoding\":\"0\""));
        assert!(document.contains("\"frame_frame_marked\":false"));
        assert!(document.contains("\"frame_frame_ignored\":false"));
        assert!(document.contains("\"ip_ip_id\":\""));
        assert!(document.contains("\"ip_ip_checksum\":\""));
        assert!(document.contains("\"ip_ip_flags\":\""));
        assert!(document.contains("\"eth_eth_type\":\""));
    }
}

#[test]
fn ek_filter_and_raw_modes_change_layer_values() {
    let path = fixture_path(fixture("arp-request"));
    let filtered = run(&format_args(&path, "ek", &["-j", "arp"]));
    assert_eq!(status_code(filtered.status), Some(0));
    let text = String::from_utf8_lossy(&filtered.stdout);
    assert!(text.contains("\"frame\":{\"filtered\":\"frame\"}"));
    assert!(text.contains("\"arp_arp_opcode\":{\"filtered\":\"arp.opcode\"}"));

    let raw = run(&format_args(&path, "ek", &["-x"]));
    assert_eq!(status_code(raw.status), Some(0));
    let text = String::from_utf8_lossy(&raw.stdout);
    assert!(text.contains("\"arp_raw\":\""));
    assert!(text.contains("\"arp_arp_opcode_raw\":\"0001\""));
    let ipv4 = run(&format_args(
        &fixture_path(fixture("ipv4-basic")),
        "ek",
        &["-x", "-c", "1"],
    ));
    assert_eq!(status_code(ipv4.status), Some(0));
    let ipv4 = String::from_utf8_lossy(&ipv4.stdout);
    assert!(ipv4.contains("\"ip_ip_flags_raw\":\"2\""));
    assert!(ipv4.contains("\"ip_ip_id_raw\":\"1c46\""));
    assert!(ipv4.contains("\"ip_ip_version_raw\":\"45\""));
}

#[test]
fn ek_empty_capture_writes_nothing() {
    let run = run(&format_args(&fixture_path(fixture("empty")), "ek", &[]));
    assert_eq!(status_code(run.status), Some(0));
    assert!(run.stdout.is_empty());
}

#[test]
fn tabs_use_the_summary_columns_and_respect_blocks() {
    let path = fixture_path(fixture("arp-request"));
    let tabs = run(&format_args(&path, "tabs", &[]));
    assert_eq!(status_code(tabs.status), Some(0));
    let text = String::from_utf8_lossy(&tabs.stdout);
    assert!(text.contains('\t'));
    assert!(text.contains("\t\u{2192}\t"));
    assert!(text.ends_with('\n'));

    let detail = run(&format_args(&path, "tabs", &["-V"]));
    assert_eq!(status_code(detail.status), Some(0));
    assert!(
        !String::from_utf8_lossy(&detail.stdout).contains('\t'),
        "-V suppresses the tabs line"
    );
    assert!(String::from_utf8_lossy(&detail.stdout).contains("Frame 1:"));

    let forced = run(&format_args(&path, "tabs", &["-V", "-P"]));
    assert_eq!(status_code(forced.status), Some(0));
    assert!(String::from_utf8_lossy(&forced.stdout).contains('\t'));
}

#[test]
fn tabs_and_ps_reject_output_fields() {
    for format in ["tabs", "ps"] {
        let run = run(&format_args(
            &fixture_path(fixture("arp-request")),
            format,
            &["-e", "arp.opcode"],
        ));
        assert_eq!(status_code(run.status), Some(1), "{format}");
        assert!(run.stdout.is_empty(), "{format}: wrote stdout");
        assert!(!run.stderr.is_empty(), "{format}: no diagnostic");
    }
}

#[test]
fn postscript_has_an_original_prolog_and_page_markers() {
    let run = run(&format_args(
        &fixture_path(fixture("arp-request")),
        "ps",
        &[],
    ));
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    assert!(text.starts_with("%!PS-Adobe-3.0\n"));
    assert!(text.contains("%%Creator: packetfin/"));
    assert!(text.contains("/ws_title ("));
    assert!(text.contains("showpage"));
    assert!(text.ends_with("%%EOF\n"));
    let records = putline_records(&text);
    assert_eq!(records.len(), 1);
    let Some((indent, line)) = records.first() else {
        return;
    };
    assert_eq!(*indent, 0);
    assert!(line.contains("ARP"));
}

#[test]
fn postscript_detail_and_hexdump_use_indented_records() {
    let path = fixture_path(fixture("arp-request"));
    let detail = run(&format_args(&path, "ps", &["-V"]));
    assert_eq!(status_code(detail.status), Some(0));
    let records = putline_records(&String::from_utf8_lossy(&detail.stdout));
    assert!(
        records
            .iter()
            .any(|(indent, text)| *indent == 1 && text.starts_with("Encapsulation type:"))
    );
    let hexdump = run(&format_args(&path, "ps", &["-x"]));
    assert_eq!(status_code(hexdump.status), Some(0));
    let records = putline_records(&String::from_utf8_lossy(&hexdump.stdout));
    assert!(
        records
            .iter()
            .any(|(indent, text)| *indent == 0 && text.starts_with("0000  "))
    );
}

#[test]
fn postscript_escapes_parentheses_and_backslashes() {
    let run = run(&format_args(
        &fixture_path(fixture("detail-hostile")),
        "ps",
        &["-V", "-c", "1"],
    ));
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    assert!(text.contains("\\("));
    assert!(text.contains("\\)"));
    let records = putline_records(&text);
    assert!(records.iter().any(|(_, line)| line.contains("(336 bits)")));
}

#[derive(Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl PartialEq for Json {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Number(left), Self::Number(right)) => left == right,
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => left == right,
            (Self::Object(left), Self::Object(right)) => {
                left.len() == right.len()
                    && left.iter().all(|(key, value)| {
                        right.iter().any(|(other_key, other_value)| {
                            key == other_key && value == other_value
                        })
                    })
            }
            _ => false,
        }
    }
}

impl Eq for Json {}

impl Json {
    fn parse(text: &str) -> Self {
        let mut parser = JsonParser {
            bytes: text.as_bytes(),
            index: 0,
        };
        let value = parser.value();
        parser.skip_whitespace();
        assert_eq!(parser.index, parser.bytes.len(), "trailing JSON data");
        value
    }

    fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Object(entries) => Some(entries),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

#[expect(
    clippy::panic,
    clippy::indexing_slicing,
    reason = "the minimal test parser validates generated JSON"
)]
impl JsonParser<'_> {
    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.index += 1;
        }
    }

    fn value(&mut self) -> Json {
        self.skip_whitespace();
        match self.bytes.get(self.index).copied() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Json::String(self.string()),
            Some(b't') => {
                self.literal(b"true");
                Json::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false");
                Json::Bool(false)
            }
            Some(b'n') => {
                self.literal(b"null");
                Json::Null
            }
            Some(_) => self.number(),
            None => panic!("unexpected end of JSON"),
        }
    }

    fn literal(&mut self, text: &[u8]) {
        assert_eq!(
            self.bytes.get(self.index..self.index + text.len()),
            Some(text)
        );
        self.index += text.len();
    }

    fn number(&mut self) -> Json {
        let start = self.index;
        while self.bytes.get(self.index).is_some_and(|byte| {
            byte.is_ascii_digit() || matches!(*byte, b'-' | b'+' | b'.' | b'e' | b'E')
        }) {
            self.index += 1;
        }
        Json::Number(String::from_utf8_lossy(&self.bytes[start..self.index]).into_owned())
    }

    fn string(&mut self) -> String {
        assert_eq!(self.bytes.get(self.index), Some(&b'"'));
        self.index += 1;
        let mut text = String::new();
        while let Some(byte) = self.bytes.get(self.index).copied() {
            self.index += 1;
            match byte {
                b'"' => return text,
                b'\\' => {
                    let escaped = self.bytes.get(self.index).copied().unwrap_or_default();
                    self.index += 1;
                    match escaped {
                        b'"' => text.push('"'),
                        b'\\' => text.push('\\'),
                        b'/' => text.push('/'),
                        b'b' => text.push('\u{8}'),
                        b'f' => text.push('\u{c}'),
                        b'n' => text.push('\n'),
                        b'r' => text.push('\r'),
                        b't' => text.push('\t'),
                        b'u' => {
                            let end = self.index + 4;
                            let digits = std::str::from_utf8(&self.bytes[self.index..end])
                                .unwrap_or_default();
                            let value = u32::from_str_radix(digits, 16).unwrap_or_default();
                            if let Some(character) = char::from_u32(value) {
                                text.push(character);
                            }
                            self.index = end;
                        }
                        _ => panic!("invalid JSON escape"),
                    }
                }
                _ => text.push(char::from(byte)),
            }
        }
        panic!("unterminated JSON string")
    }

    fn array(&mut self) -> Json {
        assert_eq!(self.bytes.get(self.index), Some(&b'['));
        self.index += 1;
        let mut values = Vec::new();
        loop {
            self.skip_whitespace();
            if self.bytes.get(self.index) == Some(&b']') {
                self.index += 1;
                return Json::Array(values);
            }
            values.push(self.value());
            self.skip_whitespace();
            match self.bytes.get(self.index) {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    return Json::Array(values);
                }
                _ => panic!("invalid JSON array"),
            }
        }
    }

    fn object(&mut self) -> Json {
        assert_eq!(self.bytes.get(self.index), Some(&b'{'));
        self.index += 1;
        let mut entries: Vec<(String, Json)> = Vec::new();
        loop {
            self.skip_whitespace();
            if self.bytes.get(self.index) == Some(&b'}') {
                self.index += 1;
                return Json::Object(entries);
            }
            let key = self.string();
            self.skip_whitespace();
            assert_eq!(self.bytes.get(self.index), Some(&b':'));
            self.index += 1;
            let value = self.value();
            entries.push((key, value));
            self.skip_whitespace();
            match self.bytes.get(self.index) {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    return Json::Object(entries);
                }
                _ => panic!("invalid JSON object"),
            }
        }
    }
}
