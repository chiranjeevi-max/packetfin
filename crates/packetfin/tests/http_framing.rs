//! End-to-end checks for the HTTP/1.x framing rules of RFC 9112 where the
//! expected output disagrees with them.
//!
//! The `http-framing-rfc` fixture has no golden case: its messages are exactly
//! the shapes whose expected output disagrees with the standard, so the
//! assertions below state the RFC rules (sections 6.1, 6.3, 7.1 and 9.3.6)
//! instead of storing expected output.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

fn fixture() -> PathBuf {
    golden::fixtures_dir().join("http-framing-rfc.pcap")
}

/// Run the binary on the fixture and return stdout.
fn run(args: &[&str]) -> Result<String, String> {
    let output = Command::new(BIN)
        .args(args)
        .arg("-r")
        .arg(fixture())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("cannot run packetfin: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "packetfin {args:?} exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run `-T fields` with the given columns and split the output into rows.
fn field_rows(columns: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let mut args = vec!["-n", "-T", "fields"];
    for column in columns {
        args.push("-e");
        args.push(column);
    }
    let output = run(&args)?;
    Ok(output
        .lines()
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect())
}

fn row<'a>(rows: &'a [Vec<String>], frame: &str) -> Result<&'a [String], String> {
    rows.iter()
        .find(|row| row.first().is_some_and(|value| value == frame))
        .map(Vec::as_slice)
        .ok_or_else(|| format!("no field row for frame {frame}"))
}

fn column(row: &[String], index: usize) -> Result<&str, String> {
    row.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("column {index} missing from row {row:?}"))
}

/// The single detail view of one frame.
fn detail(frame: &str) -> Result<String, String> {
    run(&["-n", "-Y", &format!("frame.number == {frame}"), "-V"])
}

#[test]
fn repeated_content_length_fields_follow_rfc_9112() -> Result<(), String> {
    let rows = field_rows(&[
        "frame.number",
        "http.response.code",
        "http.content_length",
        "http.file_data",
    ])?;
    // RFC 9112 section 6.3: equal decimal values are collapsed into one
    // length, so the declared body frames the message once.
    let agree = row(&rows, "5")?;
    assert_eq!(column(agree, 1)?, "200");
    assert_eq!(column(agree, 2)?, "5,5");
    assert_eq!(column(agree, 3)?, "68656c6c6f");
    // Disagreeing values make the length unusable; the captured remainder is
    // the message body rather than the last readable length.
    let disagree = row(&rows, "8")?;
    assert_eq!(column(disagree, 2)?, "3,5");
    assert_eq!(column(disagree, 3)?, "68656c6c6f21");
    // A later usable field does not recover an unreadable one.
    let unreadable = row(&rows, "11")?;
    assert_eq!(column(unreadable, 2)?, "5");
    assert_eq!(column(unreadable, 3)?, "68656c6c6f21");
    Ok(())
}

#[test]
fn an_unusable_content_length_raises_one_malformed_expert() -> Result<(), String> {
    let unusable = detail("8")?;
    let expert = "[Expert Info (Error/Malformed): Content-Length does not declare one body length]";
    assert_eq!(
        unusable.matches(expert).count(),
        1,
        "expected one expert: {unusable}"
    );
    // An agreeing duplicate keeps the declared body and needs no expert.
    let agree = detail("5")?;
    assert!(
        !agree.contains("Expert Info"),
        "an agreeing duplicate must not raise an expert: {agree}"
    );
    Ok(())
}

#[test]
fn only_a_final_chunked_coding_selects_chunk_framing() -> Result<(), String> {
    let rows = field_rows(&[
        "frame.number",
        "http.request.method",
        "http.request.full_uri",
        "http.response.code",
        "http.file_data",
    ])?;
    // RFC 9112 section 6.3 case 4: a response whose final coding is not
    // chunked is delimited by the connection close, so the captured bytes are
    // its body.
    let response = rows
        .iter()
        .find(|row| {
            row.get(2).is_some_and(|uri| uri == "http://h/coding")
                && row.get(3).is_some_and(|code| code == "200")
        })
        .ok_or_else(|| "no /coding response row".to_string())?;
    assert_eq!(column(response, 4)?, "626f6479");
    // RFC 9112 section 6.1: a request whose final coding is not chunked cannot
    // be framed, and its captured remainder stays with the message.
    let request = rows
        .iter()
        .find(|row| {
            row.get(1).is_some_and(|method| method == "POST")
                && row.get(2).is_some_and(|uri| uri == "http://h/coding")
        })
        .ok_or_else(|| "no POST /coding row".to_string())?;
    assert_eq!(column(request, 4)?, "626f6479");
    let expert = detail("16")?;
    assert!(
        expert.contains("[Expert Info (Error/Malformed): Final transfer coding is not chunked]"),
        "the request must explain its unusable framing: {expert}"
    );
    Ok(())
}

#[test]
fn bodyless_responses_end_at_the_header_section() -> Result<(), String> {
    let rows = field_rows(&[
        "frame.number",
        "http.response.code",
        "http.file_data",
        "http.excess_data",
    ])?;
    // RFC 9112 section 6.3 case 1: a 304 response and the response to HEAD end
    // at the header section. The bytes after it cannot start a message, so
    // they become a continuation record instead of the declared body.
    for (frame, code) in [("19", "304"), ("22", "200")] {
        let row = row(&rows, frame)?;
        assert_eq!(column(row, 1)?, code, "frame {frame}");
        assert_eq!(column(row, 2)?, "6a756e6b0d0a", "frame {frame}");
        assert_eq!(column(row, 3)?, "1", "frame {frame}");
    }
    Ok(())
}

#[test]
fn a_malformed_chunk_boundary_shows_the_captured_bytes() -> Result<(), String> {
    let output = detail("25")?;
    assert!(
        output.contains("Chunk size: 1 octets") && output.contains("Chunk data: 61"),
        "the decoded chunk fields must stay: {output}"
    );
    assert!(
        output.contains("Chunk boundary: 5858"),
        "the boundary must show the captured bytes: {output}"
    );
    let expert = "[Expert Info (Error/Malformed): Chunk data is not followed by CRLF]";
    assert_eq!(
        output.matches(expert).count(),
        1,
        "expected one boundary expert: {output}"
    );
    Ok(())
}

#[test]
fn a_propfind_request_reaches_the_follow_output() -> Result<(), String> {
    // Without reassembly the tap decides from one segment whether a message
    // starts here; the method set must not be a fixed list.
    let output = run(&[
        "-n",
        "-q",
        "-o",
        "tcp.desegment_tcp_streams:FALSE",
        "-z",
        "follow,http,ascii,0",
    ])?;
    assert!(
        output.contains("PROPFIND /dav HTTP/1.1"),
        "a method outside the common set must start a follow record: {output}"
    );
    assert!(
        output.contains("HTTP/1.1 207 Multi-Status"),
        "the response must follow the request: {output}"
    );
    Ok(())
}
