//! End-to-end checks for the HTTP/1.x framing rules of RFC 9112 where the
//! expected output disagrees with them.
//!
//! The `http-framing-rfc` fixture has no golden case: its messages are exactly
//! the shapes whose expected output disagrees with the standard, so the
//! assertions below state the RFC rules (sections 6.1, 6.3, 7.1 and 9.3.6)
//! instead of storing expected output.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");
static COUNTER: AtomicU64 = AtomicU64::new(0);

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
    field_rows_where(&[], columns)
}

/// Run `-T fields` with extra decode options before the column list.
fn field_rows_where(options: &[&str], columns: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let mut args = vec!["-n"];
    args.extend_from_slice(options);
    args.push("-T");
    args.push("fields");
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

/// Export the fixture's HTTP objects into a fresh directory.
fn exported_objects(options: &[&str]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "packetfin-framing-{}-{counter}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
    let objects = format!("http,{}", directory.display());
    let mut args = vec!["-n"];
    args.extend_from_slice(options);
    args.push("--export-objects");
    args.push(&objects);
    args.push("-q");
    let result = run(&args);
    let exported = collect_objects(&directory);
    let _ = fs::remove_dir_all(&directory);
    result?;
    exported
}

/// Read every exported object as a name and its bytes, sorted by name.
fn collect_objects(directory: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    let mut objects = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read an entry: {error}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("cannot read {}: {error}", entry.path().display()))?;
        objects.push((name, bytes));
    }
    objects.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(objects)
}

/// The field row of the response to `uri`.
fn response_row<'a>(rows: &'a [Vec<String>], uri: &str) -> Result<&'a [String], String> {
    rows.iter()
        .find(|row| {
            row.get(1).is_some_and(|code| code.starts_with("200"))
                && row.get(2).is_some_and(|value| value == uri)
        })
        .map(Vec::as_slice)
        .ok_or_else(|| format!("no 200 response row for {uri}"))
}

#[test]
fn repeated_content_length_fields_follow_rfc_9112() -> Result<(), String> {
    let rows = field_rows(&[
        "frame.number",
        "http.response.code",
        "http.request.full_uri",
        "http.content_length",
        "http.file_data",
    ])?;
    // RFC 9112 section 6.3: equal decimal values are collapsed into one
    // length, so the declared body frames the message once.
    let agree = response_row(&rows, "http://h/agree")?;
    assert_eq!(column(agree, 3)?, "5,5");
    assert_eq!(column(agree, 4)?, "68656c6c6f");
    // Disagreeing values make the length unusable; the captured remainder is
    // the message body rather than the last readable length. The body arrives
    // in the header's segment for `/disagree` and in a later segment for
    // `/disagree-split`; the connection close bounds both, so both frame the
    // same six bytes.
    for uri in ["http://h/disagree", "http://h/disagree-split"] {
        let disagree = response_row(&rows, uri)?;
        assert_eq!(column(disagree, 3)?, "3,5", "{uri}");
        assert_eq!(column(disagree, 4)?, "68656c6c6f21", "{uri}");
    }
    // A later usable field does not recover an unreadable one.
    let unreadable = response_row(&rows, "http://h/unreadable")?;
    assert_eq!(column(unreadable, 3)?, "5");
    assert_eq!(column(unreadable, 4)?, "68656c6c6f21");
    // Without a connection close there is no boundary at all, so the response
    // stays a TCP row: the reference frames it at the segment end instead.
    let no_fin = row(&rows, "31")?;
    assert_eq!(column(no_fin, 1)?, "");
    assert_eq!(column(no_fin, 4)?, "");
    Ok(())
}

#[test]
fn an_unusable_content_length_raises_one_malformed_expert() -> Result<(), String> {
    let unusable = detail("9")?;
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
    // RFC 9112 section 6.3 case 4: a request whose final coding is not chunked
    // cannot be framed, and its captured remainder stays with the message.
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
fn bodyless_responses_keep_trailing_bytes_without_reassembly() -> Result<(), String> {
    // Without desegmentation the decoder receives the header section and the
    // trailing bytes in one segment, so it must present the remainder through
    // the continuation path instead of dropping it (RFC 9112 section 6.3
    // case 1: the message ends at the empty line, and the bytes after it are
    // not a body).
    let rows = field_rows_where(
        &["-o", "tcp.desegment_tcp_streams:FALSE"],
        &[
            "frame.number",
            "http.response.code",
            "http.file_data",
            "http.excess_data",
        ],
    )?;
    for (frame, code) in [("19", "304"), ("22", "200")] {
        let row = row(&rows, frame)?;
        assert_eq!(column(row, 1)?, code, "frame {frame}");
        assert_eq!(column(row, 2)?, "6a756e6b0d0a", "frame {frame}");
        assert_eq!(column(row, 3)?, "1", "frame {frame}");
    }
    let output = run(&[
        "-n",
        "-o",
        "tcp.desegment_tcp_streams:FALSE",
        "-Y",
        "frame.number == 19",
        "-V",
    ])?;
    assert!(
        output.contains("Excess data after a body"),
        "the continuation must explain the trailing bytes: {output}"
    );
    assert!(
        output.contains("File Data: 6 bytes"),
        "the continuation must present the trailing bytes: {output}"
    );
    let summary = run(&[
        "-n",
        "-o",
        "tcp.desegment_tcp_streams:FALSE",
        "-Y",
        "frame.number == 19",
    ])?;
    assert!(
        summary.contains("HTTP/1.1 304 Not Modified Continuation"),
        "the frame summary must match the reassembled path: {summary}"
    );
    // The continuation is file data, so the object export must keep the
    // trailing bytes the reassembled path exports for the same responses.
    let direct = exported_objects(&["-o", "tcp.desegment_tcp_streams:FALSE"])?;
    for name in ["304", "head"] {
        let body = direct
            .iter()
            .find(|(object, _)| object == name)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or_else(|| format!("no {name} object in {direct:?}"))?;
        assert_eq!(body, b"junk\r\n", "{name}");
    }
    Ok(())
}

#[test]
fn a_quoted_comma_does_not_split_the_transfer_coding() -> Result<(), String> {
    let rows = field_rows(&[
        "frame.number",
        "http.response.code",
        "http.request.full_uri",
        "http.file_data",
        "http.excess_data",
    ])?;
    // RFC 9110 section 5.6.1 splits the coding list at commas outside quoted
    // strings, and section 5.6.6 allows a transfer parameter's value to be a
    // quoted string. The final coding is `chunked`, so the body is de-chunked
    // and the pipelined 204 in the same segment still decodes.
    let response = response_row(&rows, "http://h/quoted")?;
    assert_eq!(column(response, 1)?, "200,204");
    assert_eq!(column(response, 3)?, "61");
    assert_eq!(column(response, 4)?, "");
    Ok(())
}

#[test]
fn the_rendered_length_agrees_with_the_framing() -> Result<(), String> {
    let rows = field_rows(&[
        "frame.number",
        "http.response.code",
        "http.request.full_uri",
        "http.content_length",
        "http.file_data",
    ])?;
    // RFC 9110 section 8.6 allows a Content-Length value of one or more
    // digits. `+5` is not a length, so the field must not render one even
    // though the captured remainder still stays with the message.
    let plus = response_row(&rows, "http://h/plus")?;
    assert_eq!(column(plus, 3)?, "");
    assert_eq!(column(plus, 4)?, "68656c6c6f");
    let plus_detail = detail("37")?;
    assert!(
        !plus_detail.contains("[Content length:"),
        "a rejected length must not render: {plus_detail}"
    );
    assert!(
        plus_detail.contains("Content-Length does not declare one body length"),
        "the rejected value must be explained: {plus_detail}"
    );
    // RFC 9112 section 6.3 lets a list of identical decimal values collapse to
    // one usable length, and the rendered value is that length.
    let listed = response_row(&rows, "http://h/list")?;
    assert_eq!(column(listed, 3)?, "5");
    assert_eq!(column(listed, 4)?, "68656c6c6f");
    let list_detail = detail("39")?;
    assert!(
        list_detail.contains("[Content length: 5]"),
        "the collapsed length must render once: {list_detail}"
    );
    assert!(
        !list_detail.contains("Expert Info"),
        "a collapsible list needs no expert: {list_detail}"
    );
    Ok(())
}

#[test]
fn both_framing_fields_raise_one_warning_expert() -> Result<(), String> {
    // RFC 9112 section 6.3 case 3: Transfer-Encoding overrides
    // Content-Length, and a message with both "ought to be handled as an
    // error". The chunked coding still frames the body, and one warning
    // explains the combination on the Content-Length field.
    let field = detail("41")?;
    let warning = "[Expert Info (Warning/Malformed): The Content-Length and \
                   Transfer-Encoding header must not be set together]";
    assert_eq!(
        field.matches(warning).count(),
        1,
        "expected one warning: {field}"
    );
    assert!(
        field.contains("Chunk size: 5 octets") && field.contains("Chunk data: 68656c6c6f"),
        "chunked must still frame the body: {field}"
    );
    assert!(
        field.contains("[Content length: 5]"),
        "the declared length is still readable: {field}"
    );
    let rows = field_rows(&["frame.number", "http.request.method", "http.file_data"])?;
    let request = row(&rows, "41")?;
    assert_eq!(column(request, 1)?, "POST");
    assert_eq!(column(request, 2)?, "68656c6c6f");
    Ok(())
}

#[test]
fn a_head_follow_keeps_the_trailing_bytes_in_one_record() -> Result<(), String> {
    // The tap knows the request method of the direction it follows, so a
    // response to HEAD ends at its header section there too (RFC 9112
    // section 6.3 case 1) and the trailing bytes are one record.
    let output = run(&[
        "-n",
        "-q",
        "-o",
        "tcp.desegment_tcp_streams:FALSE",
        "-z",
        "follow,http,ascii,7",
    ])?;
    assert!(
        output.contains("6\njunk\r"),
        "the trailing bytes must be one record: {output}"
    );
    assert!(
        !output.contains("4\njunk"),
        "the declared length must not split a HEAD answer: {output}"
    );
    Ok(())
}

#[test]
fn a_split_request_with_an_unusable_length_ends_at_the_header_segment() -> Result<(), String> {
    // RFC 9112 section 6.3's note says request messages are never
    // close-delimited, so an unframeable request cannot wait for a client
    // close the way a response does; waiting would lose every such request in
    // a capture that never sees the client FIN. The message keeps the bytes
    // its header segment carries, and a later body segment is not attached.
    // Pin the shape so the limitation stays measured instead of silent.
    let rows = field_rows(&[
        "frame.number",
        "http.request.method",
        "http.response.code",
        "http.file_data",
    ])?;
    let header = row(&rows, "44")?;
    assert_eq!(column(header, 1)?, "POST");
    assert_eq!(column(header, 3)?, "");
    let body = row(&rows, "45")?;
    assert_eq!(column(body, 1)?, "");
    assert_eq!(column(body, 2)?, "");
    assert_eq!(column(body, 3)?, "");
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
