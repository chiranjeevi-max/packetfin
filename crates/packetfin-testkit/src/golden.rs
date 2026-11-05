//! Stored golden output: loading it and comparing a run against it.

use std::env;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

/// The stored expected output of one golden case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Golden {
    /// Expected stdout bytes.
    pub stdout: Vec<u8>,
    /// Expected stderr bytes.
    pub stderr: Vec<u8>,
    /// Expected exit status.
    pub status: i32,
}

/// Locate the repository root from this crate's manifest directory.
pub fn repo_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

/// Directory holding the generated capture fixtures.
pub fn fixtures_dir() -> PathBuf {
    repo_root().join("tests/fixtures")
}

/// Directory holding the stored golden output.
pub fn golden_dir() -> PathBuf {
    repo_root().join("tests/golden")
}

/// Load the stored stdout, stderr and exit status for one fixture case.
pub fn load(fixture: &str, case: &str) -> Result<Golden, String> {
    let directory = golden_dir().join(fixture);
    let stdout = read(&directory.join(format!("{case}.stdout")), fixture, case)?;
    let stderr = read(&directory.join(format!("{case}.stderr")), fixture, case)?;
    let status_path = directory.join(format!("{case}.status"));
    let status_text = fs::read_to_string(&status_path).map_err(|error| {
        format!(
            "golden {fixture}/{case}: cannot read {}: {error}",
            status_path.display()
        )
    })?;
    let status_line = status_text.lines().next().ok_or_else(|| {
        format!(
            "golden {fixture}/{case}: {} is empty",
            status_path.display()
        )
    })?;
    let status = status_line.trim().parse::<i32>().map_err(|error| {
        format!(
            "golden {fixture}/{case}: {} does not contain an exit status: {error}",
            status_path.display()
        )
    })?;
    Ok(Golden {
        stdout,
        stderr,
        status,
    })
}

/// Compare a run against the stored golden output for one fixture case.
///
/// The returned error names the fixture, the case and the first byte offset
/// that differs.
pub fn compare_golden(
    fixture: &str,
    case: &str,
    stdout: &[u8],
    stderr: &[u8],
    status: i32,
) -> Result<(), String> {
    let expected = load(fixture, case)?;
    compare_stream(fixture, case, "stdout", &expected.stdout, stdout)?;
    compare_stream(fixture, case, "stderr", &expected.stderr, stderr)?;
    compare_status(fixture, case, expected.status, status)
}

/// Compare a run against the stored stdout and exit status, ignoring stderr.
///
/// Error messages use Packetfin's own wording, so a case whose expected
/// stderr has different text uses this policy while its stdout and exit
/// status still have to match exactly.
pub fn compare_golden_stdout_status(
    fixture: &str,
    case: &str,
    stdout: &[u8],
    status: i32,
) -> Result<(), String> {
    let expected = load(fixture, case)?;
    compare_stream(fixture, case, "stdout", &expected.stdout, stdout)?;
    compare_status(fixture, case, expected.status, status)
}

fn compare_status(fixture: &str, case: &str, expected: i32, status: i32) -> Result<(), String> {
    if expected != status {
        return Err(format!(
            "golden {fixture}/{case}: status differs: stored {expected}, observed {status}"
        ));
    }
    Ok(())
}

fn read(path: &std::path::Path, fixture: &str, case: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| {
        format!(
            "golden {fixture}/{case}: cannot read {}: {error}",
            path.display()
        )
    })
}

fn compare_stream(
    fixture: &str,
    case: &str,
    stream: &str,
    expected: &[u8],
    observed: &[u8],
) -> Result<(), String> {
    if expected == observed {
        return Ok(());
    }
    let first = expected
        .iter()
        .zip(observed)
        .take_while(|(expected_byte, observed_byte)| expected_byte == observed_byte)
        .count();
    let line = expected
        .iter()
        .take(first)
        .filter(|byte| **byte == b'\n')
        .count()
        + 1;
    let stored_byte = expected
        .get(first)
        .map_or_else(|| "<end>".to_string(), |byte| format!("0x{byte:02x}"));
    let observed_byte = observed
        .get(first)
        .map_or_else(|| "<end>".to_string(), |byte| format!("0x{byte:02x}"));
    Err(format!(
        "golden {fixture}/{case}: {stream} differs at byte {first} (line {line}): \
         stored {stored_byte}, observed {observed_byte}; \
         stored {} bytes, observed {} bytes",
        expected.len(),
        observed.len()
    ))
}

/// Normalize the parts of XML output that are identity or wall-clock state.
///
/// PDML's root `creator` and `time` attributes and its stylesheet comment
/// carry the producing program's identity and generation time; PSML's root
/// carries only `creator`. Packetfin writes its own identity and cannot
/// reproduce the stored generation time, so both the stored golden and the
/// observed output pass through this function. Every other byte stays exact.
pub fn normalize_volatile(case: &str, stdout: &[u8]) -> Vec<u8> {
    if case.starts_with("write-") {
        return normalize_capture(stdout);
    }
    let pdml = case.starts_with("pdml");
    let psml = case.starts_with("psml");
    let ps = case == "ps" || case.starts_with("ps-");
    if ps {
        let text = String::from_utf8_lossy(stdout);
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            if is_putline_record(line) {
                out.push_str(line);
                out.push('\n');
            }
        }
        return out.into_bytes();
    }
    if !pdml && !psml {
        return stdout.to_vec();
    }
    let text = String::from_utf8_lossy(stdout);
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if pdml && line.starts_with("<!--") {
            out.push_str("<!-- normalized -->\n");
        } else if line.starts_with("<pdml ") || line.starts_with("<psml ") {
            let mut normalized = replace_attribute(line, "creator", "creator");
            if pdml {
                normalized = replace_attribute(&normalized, "time", "time");
            }
            out.push_str(&normalized);
        } else {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

/// Decompress a capture stream and normalise implementation-specific bytes.
///
/// gzip and lz4 output is stored decompressed because the compressed frame
/// bytes are encoder-specific. A pcapng stream then gets its `shb_userappl`
/// values replaced and its name-resolution block bodies canonicalised; pcap
/// bytes are returned unchanged.
pub fn normalize_capture(bytes: &[u8]) -> Vec<u8> {
    let decompressed = decompress_capture(bytes);
    normalize_pcapng(&decompressed).unwrap_or(decompressed)
}

/// Decode gzip or lz4 framing, leaving every other byte stream unchanged.
fn decompress_capture(bytes: &[u8]) -> Vec<u8> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        if flate2::read::MultiGzDecoder::new(bytes)
            .read_to_end(&mut out)
            .is_ok()
        {
            return out;
        }
    } else if bytes.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        let mut out = Vec::new();
        if lz4_flex::frame::FrameDecoder::new(bytes)
            .read_to_end(&mut out)
            .is_ok()
        {
            return out;
        }
    }
    bytes.to_vec()
}

/// Replace the implementation-specific pcapng bytes both writers may choose.
///
/// Only little-endian pcapng is handled, which both writers produce. An
/// unparsable stream is returned untouched so a malformed output still fails
/// the byte comparison.
fn normalize_pcapng(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) || bytes.len() < 12 {
        return None;
    }
    if u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?) != 0x1a2b_3c4d {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let header = bytes.get(offset..offset.checked_add(8)?)?;
        let block_type = u32::from_le_bytes(header.get(0..4)?.try_into().ok()?);
        let length =
            usize::try_from(u32::from_le_bytes(header.get(4..8)?.try_into().ok()?)).ok()?;
        if length < 12 || !length.is_multiple_of(4) || offset.checked_add(length)? > bytes.len() {
            return None;
        }
        let block = bytes.get(offset..offset + length)?;
        match block_type {
            0x0a0d_0d0a => out.extend_from_slice(&normalize_section(block)?),
            4 => out.extend_from_slice(&normalize_name_resolution()?),
            _ => out.extend_from_slice(block),
        }
        offset += length;
    }
    Some(out)
}

/// Rewrite one section header block with a fixed application identity.
fn normalize_section(block: &[u8]) -> Option<Vec<u8>> {
    let body = block.get(8..block.len().checked_sub(4)?)?;
    let fixed = body.get(0..16)?;
    let mut rewritten = Vec::with_capacity(body.len());
    rewritten.extend_from_slice(fixed);
    let mut cursor = 16_usize;
    loop {
        let header = body.get(cursor..cursor.checked_add(4)?)?;
        let code = u16::from_le_bytes(header.get(0..2)?.try_into().ok()?);
        let length = usize::from(u16::from_le_bytes(header.get(2..4)?.try_into().ok()?));
        cursor += 4;
        if code == 0 {
            break;
        }
        let padded = length.checked_add(3)? & !3;
        let value = body.get(cursor..cursor.checked_add(length)?)?;
        let value = if code == 4 { b"packetfin-test" } else { value };
        rewritten.extend_from_slice(&code.to_le_bytes());
        rewritten.extend_from_slice(&u16::try_from(value.len()).ok()?.to_le_bytes());
        rewritten.extend_from_slice(value);
        while !rewritten.len().is_multiple_of(4) {
            rewritten.push(0);
        }
        cursor = cursor.checked_add(padded)?;
    }
    rewritten.extend_from_slice(&[0, 0, 0, 0]);
    Some(encode_block(0x0a0d_0d0a, &rewritten))
}

/// Give every name-resolution block the same empty body.
///
/// Packetfin forwards the source body verbatim, while the stored golden has
/// rebuilt records. Replacing the body still checks block position and count.
fn normalize_name_resolution() -> Option<Vec<u8>> {
    Some(encode_block(4, &[0, 0, 0, 0, 0, 0, 0, 0]))
}

fn encode_block(block_type: u32, body: &[u8]) -> Vec<u8> {
    let total = u32::try_from(body.len() + 12).unwrap_or(u32::MAX);
    let mut block = Vec::with_capacity(body.len() + 12);
    block.extend_from_slice(&block_type.to_le_bytes());
    block.extend_from_slice(&total.to_le_bytes());
    block.extend_from_slice(body);
    block.extend_from_slice(&total.to_le_bytes());
    block
}

fn is_putline_record(line: &str) -> bool {
    let Some(rest) = line.strip_suffix(" putline") else {
        return false;
    };
    let Some(space) = rest.find(' ') else {
        return false;
    };
    rest.get(..space)
        .is_some_and(|digits| digits.chars().all(|character| character.is_ascii_digit()))
        && rest.get(space..).is_some_and(|tail| tail.starts_with(" ("))
        && rest.ends_with(')')
}

fn replace_attribute(line: &str, name: &str, value: &str) -> String {
    let marker = format!("{name}=\"");
    let Some(start) = line.find(&marker) else {
        return line.to_string();
    };
    let value_start = start + marker.len();
    let Some(end_offset) = line[value_start..].find('"') else {
        return line.to_string();
    };
    let value_end = value_start + end_offset;
    let mut replaced = String::with_capacity(line.len());
    replaced.push_str(&line[..value_start]);
    replaced.push_str(value);
    replaced.push_str(&line[value_end..]);
    replaced
}
