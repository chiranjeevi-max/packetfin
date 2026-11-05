//! End-to-end tests for `-T pdml` and `-T psml`.
//!
//! Golden cases run the built binary from the repository root with the same
//! relative fixture path the golden output records, so PDML's `capture_file`
//! attribute is exact. Identity and generation-time attributes are
//! normalized on both sides; every other byte must match the golden output.
//! Structural tests cover default output, hostile data, truncation and the
//! generated fields that keep those cases out of the byte-identical set.

use std::ffi::OsString;
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

fn xml_args(path: &Path, format: &str, extra: &[&str]) -> Vec<OsString> {
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

fn relative_args(fixture: &Fixture, format: &str) -> Vec<OsString> {
    vec![
        OsString::from("-n"),
        OsString::from("-T"),
        OsString::from(format),
        OsString::from("-r"),
        OsString::from(fixture.relative_path()),
    ]
}

fn stderr_text(run: &Run) -> String {
    String::from_utf8_lossy(&run.stderr).into_owned()
}

#[test]
fn golden_xml_cases_match() {
    let mut compared = 0_usize;
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if (!case.id.starts_with("pdml") && !case.id.starts_with("psml"))
                || case.id.starts_with("pdml-mask-")
                || case.id == "pdml-escape"
                || case.id == "pdml-placement"
                || case.id == "pdml-j-udp"
                || case.id == "pdml-expand-udp"
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
            let observed = golden::normalize_volatile(case.id, &run.stdout);
            let stored = golden::normalize_volatile(case.id, &expected.stdout);
            assert_eq!(
                status_code(run.status),
                Some(expected.status),
                "{}/{}: status; stderr: {}",
                fixture.name,
                case.id,
                stderr_text(&run)
            );
            assert_eq!(
                observed,
                stored,
                "{}/{}: stdout differs; stderr: {}",
                fixture.name,
                case.id,
                stderr_text(&run)
            );
            compared += 1;
        }
    }
    assert!(compared > 0, "no PDML/PSML golden cases were compared");
}

#[test]
fn pdml_mask_families_match_golden_lines() {
    for (fixture_name, case_id, names) in [
        (
            "ipv6-basic",
            "pdml-mask-ipv6",
            vec![
                "ipv6.version",
                "ipv6.tclass",
                "ipv6.tclass.dscp",
                "ipv6.tclass.ecn",
                "ipv6.flow",
                "ip.hdr_len",
                "ip.flags",
                "ip.flags.rb",
                "ip.flags.df",
                "ip.flags.mf",
                "ip.frag_offset",
            ],
        ),
        (
            "ipv4-basic",
            "pdml-mask-ipv4",
            vec![
                "ip.version",
                "ip.hdr_len",
                "ip.dsfield",
                "ip.dsfield.dscp",
                "ip.dsfield.ecn",
                "ip.flags",
                "ip.flags.rb",
                "ip.flags.df",
                "ip.flags.mf",
                "ip.frag_offset",
            ],
        ),
        (
            "dns-compression",
            "pdml-mask-flags",
            vec![
                "dns.flags",
                "dns.flags.recavail",
                "dns.flags.z",
                "dns.flags.authenticated",
                "dns.flags.checkdisable",
                "dns.flags.rcode",
            ],
        ),
        (
            "dns-query-response",
            "pdml-mask-flags",
            vec![
                "dns.flags",
                "dns.flags.response",
                "dns.flags.opcode",
                "dns.flags.truncated",
                "dns.flags.recdesired",
                "dns.flags.recavail",
                "dns.flags.z",
                "dns.flags.checkdisable",
                "dns.flags.rcode",
            ],
        ),
        (
            "dns-update",
            "pdml-mask-flags",
            vec!["dns.flags", "dns.flags.opcode", "dns.flags.recdesired"],
        ),
        (
            "dns-mdns-llmnr",
            "pdml-mask-flags",
            vec!["dns.flags", "dns.flags.conflict", "dns.flags.recdesired"],
        ),
        ("tcp-handshake", "pdml-mask-tcpflags", vec!["tcp.flags"]),
    ] {
        let (observed, stored) = golden_case(fixture_name, case_id);
        assert_eq!(
            named_lines(&observed, &names),
            named_lines(&stored, &names),
            "{case_id}: named lines differ"
        );
    }
}

fn golden_case(fixture_name: &str, case_id: &str) -> (String, String) {
    let fixture = fixture(fixture_name);
    let args: Vec<OsString> = fixture
        .cases()
        .iter()
        .find(|case| case.id == case_id)
        .map(|case| case.args.iter().map(OsString::from).collect())
        .unwrap_or_default();
    assert!(!args.is_empty(), "missing {case_id} case");
    let run = run(&args);
    let expected = match golden::load(fixture_name, case_id) {
        Ok(expected) => expected,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    };
    assert_eq!(status_code(run.status), Some(0), "{case_id}");
    (
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&expected.stdout).into_owned(),
    )
}

fn attribute(line: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let start = line.find(&marker)? + marker.len();
    let rest = line.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(str::to_string)
}

fn named_lines(text: &str, names: &[&str]) -> Vec<String> {
    text.lines()
        .filter(|line| attribute(line, "name").is_some_and(|name| names.contains(&name.as_str())))
        .map(|line| line.trim_start().to_string())
        .collect()
}

#[test]
fn pdml_escape_golden_matches_full_string_lines() {
    let (observed, stored) = golden_case("xml-escape", "pdml-escape");
    let names = ["dns.qry.name", "dns.txt"];
    assert_eq!(
        named_lines(&observed, &names),
        named_lines(&stored, &names),
        "PDML string lines differ"
    );
}

#[test]
fn pdml_extension_transport_is_a_top_level_sibling() {
    for case_id in ["pdml-placement", "pdml-j-udp", "pdml-expand-udp"] {
        let (observed, stored) = golden_case("ipv6-ext-udp", case_id);
        assert_eq!(
            protocol_structure(&observed),
            protocol_structure(&stored),
            "{case_id}: protocol nesting differs"
        );
        assert!(
            observed.contains("  </proto>\n  <proto name=\"udp\""),
            "{case_id}: udp is not a top-level sibling"
        );
    }
}

fn protocol_structure(text: &str) -> Vec<String> {
    let mut records = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if let Some(rest) = trimmed.strip_prefix("<proto name=\"") {
            let name = rest.split('"').next().unwrap_or_default();
            records.push(format!("{indent}:open:{name}"));
        } else if trimmed == "</proto>" {
            records.push(format!("{indent}:close"));
        }
    }
    records
}

#[test]
fn no_orphan_xml_golden_files() {
    for fixture in fixtures::all() {
        let expected: Vec<&str> = fixture
            .cases()
            .iter()
            .filter(|case| case.id.starts_with("pdml") || case.id.starts_with("psml"))
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
            if !name.starts_with("pdml") && !name.starts_with("psml") {
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

/// A small tag-stack checker for the XML subset both formats use.
///
/// It accepts declarations, processing instructions and comments, and checks
/// that every element closes in order. It deliberately does not validate
/// character data or entities; the hostile-data tests assert those.
fn assert_well_formed(text: &str) {
    let bytes = text.as_bytes();
    let mut stack: Vec<String> = Vec::new();
    let mut index = 0;
    while let Some(byte) = bytes.get(index) {
        if *byte != b'<' {
            index += 1;
            continue;
        }
        let relative_end = text.get(index..).and_then(|rest| rest.find('>'));
        assert!(relative_end.is_some(), "unterminated tag at byte {index}");
        let Some(relative_end) = relative_end else {
            return;
        };
        let end = index + relative_end;
        let body = text.get(index + 1..end).unwrap_or_default();
        if body.starts_with('?') || body.starts_with('!') {
            index = end + 1;
            continue;
        }
        let closing = body.starts_with('/');
        let body = body.trim_start_matches('/');
        let self_closing = body.ends_with('/');
        let body = body.trim_end_matches('/');
        let name = body
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        if closing {
            let open = stack.pop().unwrap_or_default();
            assert_eq!(open, name, "mismatched closing tag at byte {index}");
        } else if !self_closing {
            stack.push(name);
        }
        index = end + 1;
    }
    assert!(stack.is_empty(), "unclosed tags: {stack:?}");
}

#[test]
fn default_pdml_is_well_formed_for_representative_protocols() {
    for (name, field) in [
        ("arp-request", "arp.opcode"),
        ("ipv4-basic", "ip.src"),
        ("ipv6-basic", "ipv6.src"),
        ("ethernet-udp-le-us", "udp.srcport"),
        ("tcp-handshake", "tcp.flags"),
        ("icmp-echo", "icmp.type"),
        ("dns-query-response", "dns.qry.name"),
        ("link-vlan", "vlan.id"),
    ] {
        let run = run(&xml_args(
            &fixture_path(fixture(name)),
            "pdml",
            &["-c", "1"],
        ));
        assert_eq!(
            status_code(run.status),
            Some(0),
            "{name}: {}",
            stderr_text(&run)
        );
        let text = String::from_utf8_lossy(&run.stdout);
        assert_well_formed(&text);
        assert!(
            text.contains(&format!("name=\"{field}\"")),
            "{name}: no {field}"
        );
        assert!(
            text.contains("<proto name=\"geninfo\""),
            "{name}: no geninfo"
        );
        assert!(text.contains("<proto name=\"frame\""), "{name}: no frame");
    }
}

#[test]
fn hostile_values_and_comments_are_escaped() {
    let result = run(&xml_args(
        &fixture_path(fixture("detail-hostile")),
        "pdml",
        &["-J", "pkt_comment", "-c", "3"],
    ));
    assert_eq!(status_code(result.status), Some(0));
    let text = String::from_utf8_lossy(&result.stdout);
    assert_well_formed(&text);
    assert!(text.contains("&quot;"), "quote not escaped");
    assert!(text.contains("\\x1B"), "control escape missing");
    assert!(!text.contains("\u{1b}"), "raw escape byte in output");

    let psml = run(&xml_args(
        &fixture_path(fixture("detail-hostile")),
        "psml",
        &[],
    ));
    assert_eq!(status_code(psml.status), Some(0));
    let psml = String::from_utf8_lossy(&psml.stdout);
    assert_well_formed(&psml);
    assert!(psml.contains("<psml version=\"0\" creator=\""));
}

#[test]
fn truncated_capture_closes_the_document_and_exits_14() {
    for format in ["pdml", "psml"] {
        let result = run(&xml_args(&fixture_path(fixture("truncated")), format, &[]));
        assert_eq!(
            status_code(result.status),
            Some(14),
            "{format}: {}",
            stderr_text(&result)
        );
        assert!(!result.stderr.is_empty(), "{format}: no diagnostic");
        let text = String::from_utf8_lossy(&result.stdout);
        assert_well_formed(&text);
        assert!(
            text.ends_with(if format == "pdml" {
                "</pdml>\n"
            } else {
                "</psml>\n"
            }),
            "{format}: document not closed"
        );
    }
}

#[test]
fn snaplen_truncation_marks_the_short_frame() {
    let run = run(&xml_args(
        &fixture_path(fixture("snaplen-truncated")),
        "pdml",
        &["-c", "1"],
    ));
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    assert_well_formed(&text);
    assert!(text.contains("name=\"_ws.short\""));
}

#[test]
fn malformed_packets_have_a_malformed_protocol() {
    let run = run(&xml_args(
        &fixture_path(fixture("ipv4-truncated")),
        "pdml",
        &["-c", "1"],
    ));
    assert_eq!(status_code(run.status), Some(0));
    let text = String::from_utf8_lossy(&run.stdout);
    assert_well_formed(&text);
    assert!(text.contains("<proto name=\"_ws.malformed\""));
    assert!(text.contains("Expert Info (Error/Malformed)"));
}

#[test]
fn specified_fields_ignore_the_protocol_filter() {
    let path = fixture_path(fixture("arp-request"));
    let plain = run(&xml_args(&path, "pdml", &["-e", "arp.opcode"]));
    let filtered = run(&xml_args(&path, "pdml", &["-j", "arp", "-e", "arp.opcode"]));
    assert_eq!(status_code(plain.status), Some(0));
    assert_eq!(status_code(filtered.status), Some(0));
    // The PDML root carries a wall-clock generation time; compare after
    // normalizing it so two runs in different seconds still agree.
    assert_eq!(
        golden::normalize_volatile("pdml", &plain.stdout),
        golden::normalize_volatile("pdml", &filtered.stdout)
    );
    let text = String::from_utf8_lossy(&plain.stdout);
    assert!(text.contains("<field name=\"arp.opcode\" value=\"1\"/>"));
    assert!(!text.contains("<proto name=\"arp\""));
}

#[test]
fn empty_capture_prints_the_envelope() {
    let pdml = run(&xml_args(&fixture_path(fixture("empty")), "pdml", &[]));
    assert_eq!(status_code(pdml.status), Some(0));
    let text = String::from_utf8_lossy(&pdml.stdout);
    assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
    assert!(text.contains("<pdml version=\"0\" creator=\""));
    assert!(text.ends_with("</pdml>\n"));
    assert!(!text.contains("<packet>"));

    let psml = run(&xml_args(&fixture_path(fixture("empty")), "psml", &[]));
    assert_eq!(status_code(psml.status), Some(0));
    let text = String::from_utf8_lossy(&psml.stdout);
    assert!(text.contains("<structure>"));
    assert!(text.ends_with("</psml>\n"));
    assert!(!text.contains("<packet>"));
}

#[test]
fn multiple_packets_are_separated_by_two_blank_lines() {
    let result = run(&xml_args(
        &fixture_path(fixture("ipv4-basic")),
        "pdml",
        &["-j", "frame", "-c", "2"],
    ));
    assert_eq!(status_code(result.status), Some(0));
    let text = String::from_utf8_lossy(&result.stdout);
    assert_eq!(text.matches("<packet>").count(), 2);
    assert!(text.contains("</packet>\n\n\n<packet>"));
    assert!(text.ends_with("</packet>\n\n\n</pdml>\n"));
}

#[test]
fn psml_time_formats_follow_t_and_u() {
    let path = fixture_path(fixture("arp-request"));
    let absolute = run(&xml_args(&path, "psml", &["-t", "a"]));
    assert_eq!(status_code(absolute.status), Some(0));
    let text = String::from_utf8_lossy(&absolute.stdout);
    assert!(text.contains("<section>22:13:20.123456</section>"));

    let hms = run(&xml_args(&path, "psml", &["-u", "hms"]));
    assert_eq!(status_code(hms.status), Some(0));
    let text = String::from_utf8_lossy(&hms.stdout);
    assert!(text.contains("<section>0.000000s</section>"));
}

#[test]
fn command_line_errors_exit_one_without_output() {
    let path = fixture_path(fixture("arp-request"));
    for args in [
        xml_args(&path, "pdml", &["-e", "arp.nope"]),
        xml_args(&path, "psml", &["-e", "arp.nope"]),
        xml_args(&path, "pdml", &["-j", "nope"]),
        xml_args(&path, "pdml", &["-x"]),
        xml_args(&path, "psml", &["-x"]),
        xml_args(&path, "psml", &["-O", "arp"]),
    ] {
        let run = run(&args);
        assert_eq!(
            status_code(run.status),
            Some(1),
            "args {args:?}: {}",
            stderr_text(&run)
        );
        assert!(run.stdout.is_empty(), "args {args:?}: wrote stdout");
        assert!(!run.stderr.is_empty(), "args {args:?}: no diagnostic");
    }
}

#[test]
fn relative_and_absolute_capture_paths_are_reported_verbatim() {
    let fixture = fixture("arp-request");
    let relative = run(&relative_args(fixture, "pdml"));
    assert_eq!(status_code(relative.status), Some(0));
    let text = String::from_utf8_lossy(&relative.stdout);
    assert!(text.contains(&format!("capture_file=\"{}\"", fixture.relative_path())));

    let absolute = run(&xml_args(&fixture_path(fixture), "pdml", &["-c", "1"]));
    let text = String::from_utf8_lossy(&absolute.stdout);
    assert!(text.contains("capture_file=\"/"));
}
