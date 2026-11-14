#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests use fixed fixtures and a private temporary directory"
)]

//! TLS key-log decryption, detail offsets and `--export-tls-session-keys`.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

fn fixture(name: &str) -> PathBuf {
    packetfin_testkit::golden::fixtures_dir().join(name)
}

fn run(args: &[OsString], environment: &[(String, String)], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.output().expect("run packetfin")
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn temp_path(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("packetfin-tls-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("temp dir");
    path
}

#[test]
fn keylog_decrypts_a_tls13_connection() {
    let capture = fixture("tls13-aes256.pcap");
    let keylog = fixture("tls13-aes256-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-Y",
        "http",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "http.request.uri",
        "-e",
        "http.response.code",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(stdout.contains("/hello"), "stdout: {stdout}");
    assert!(stdout.contains("200"), "stdout: {stdout}");
}

#[test]
fn missing_keylog_is_silent_and_keeps_records_opaque() {
    let capture = fixture("tls12-gcm.pcap");
    let args: Vec<OsString> = ["-n", "-r", capture.to_string_lossy().as_ref()]
        .into_iter()
        .map(OsString::from)
        .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "status: {:?}", output.status);
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(
        stdout.contains("Encrypted Handshake Message"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("HTTP"), "stdout: {stdout}");
}

#[test]
fn an_unopenable_keylog_is_reported_once() {
    let capture = fixture("tls12-gcm.pcap");
    let keylog = temp_path("missing-keylog").join("absent.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "status: {:?}", output.status);
    assert!(!stdout.trim().is_empty(), "stdout: {stdout}");
    assert_eq!(
        stderr.matches("cannot open TLS key log").count(),
        1,
        "stderr: {stderr}"
    );
}

#[test]
fn sslkeylogfile_environment_is_ignored() {
    let capture = fixture("tls13-aes256.pcap");
    let keylog = fixture("tls13-aes256-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-Y",
        "http",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let environment = [("SSLKEYLOGFILE".to_string(), keylog.display().to_string())];
    let output = run(&args, &environment, None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "status: {:?}", output.status);
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(stdout.trim().is_empty(), "stdout: {stdout}");
}

#[test]
fn malformed_keylog_lines_are_ignored() {
    let directory = temp_path("malformed");
    let keylog = directory.join("bad.log");
    fs::write(
        &keylog,
        b"# comment\n\nNOT_A_LABEL 00 11\nCLIENT_HANDSHAKE_TRAFFIC_SECRET zz 00\n",
    )
    .expect("write keylog");
    let capture = fixture("tls13-aes256.pcap");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    assert!(output.status.success(), "status: {:?}", output.status);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn a_wrong_secret_keeps_records_opaque() {
    let directory = temp_path("wrong-secret");
    let source = fs::read_to_string(fixture("tls13-aes256-keys.log")).expect("keylog");
    let lines: Vec<String> = source
        .lines()
        .map(|line| {
            let mut fields: Vec<String> = line.split(' ').map(str::to_string).collect();
            if let Some(secret) = fields.get_mut(2) {
                *secret = format!("0{}", secret.chars().skip(1).collect::<String>());
            }
            fields.join(" ")
        })
        .collect();
    let keylog = directory.join("wrong.log");
    fs::write(&keylog, lines.join("\n")).expect("write keylog");
    let capture = fixture("tls13-aes256.pcap");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-Y",
        "http",
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "status: {:?}", output.status);
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(stdout.trim().is_empty(), "stdout: {stdout}");
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn export_dash_is_a_literal_file_name() {
    let directory = temp_path("export-dash");
    let capture = fixture("tls12-gcm.pcap");
    let keylog = fixture("tls12-gcm-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        "-",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], Some(&directory));
    assert!(output.status.success(), "status: {:?}", output.status);
    let file = directory.join("-");
    let text = fs::read_to_string(file).expect("dash file");
    assert!(text.starts_with("CLIENT_RANDOM "), "file: {text}");
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn app_data_is_bounded_to_its_record_and_absent_after_decryption() {
    let capture = fixture("tls13-two-records.pcap");
    let keylog = fixture("tls13-two-records-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-T",
        "pdml",
        "-Y",
        "frame.number==9",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("name=\"tls.record.length\" showname=\"Length: 60\""),
        "record length: {stdout}"
    );
    let app = stdout
        .split("name=\"tls.app_data\"")
        .nth(1)
        .unwrap_or_default();
    assert!(app.contains("size=\"60\""), "app_data size: {app}");
    assert!(
        app.contains("value=\"0f3f39c7"),
        "app_data value starts at its record: {app}"
    );
    assert_eq!(
        stdout.matches("name=\"tls.app_data\"").count(),
        1,
        "one application-data record: {stdout}"
    );

    // Decrypted handshake records keep only the inner handshake fields.
    let fields: Vec<OsString> = [
        "-n",
        "-r",
        fixture("tls13-aes128.pcap").to_string_lossy().as_ref(),
        "-o",
        &format!(
            "tls.keylog_file:{}",
            fixture("tls13-aes128-keys.log").display()
        ),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "tls.record.content_type",
        "-e",
        "tls.app_data",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&fields, &[], None);
    let (stdout, _) = text(&output);
    for line in stdout.lines() {
        let mut columns = line.split('\t');
        let _number = columns.next();
        let content_type = columns.next().unwrap_or("");
        let app = columns.next().unwrap_or("");
        if content_type == "22" {
            assert!(app.is_empty(), "handshake record keeps app_data: {line}");
        }
    }
}

#[test]
fn finished_verify_data_uses_the_hash_length() {
    let tls12 = fixture("tls12-gcm.pcap");
    let tls12_keys = fixture("tls12-gcm-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        tls12.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", tls12_keys.display()),
        "-T",
        "fields",
        "-e",
        "tls.handshake.type",
        "-e",
        "tls.handshake.verify_data",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, _) = text(&output);
    let verify: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|value| !value.is_empty())
        .collect();
    assert_eq!(verify.len(), 2, "stdout: {stdout}");
    assert!(
        verify.iter().all(|value| value.len() == 24),
        "stdout: {stdout}"
    );

    let tls13 = fixture("tls13-aes256.pcap");
    let tls13_keys = fixture("tls13-aes256-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        tls13.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", tls13_keys.display()),
        "-T",
        "fields",
        "-e",
        "tls.handshake.type",
        "-e",
        "tls.handshake.verify_data",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, _) = text(&output);
    let verify: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|value| !value.is_empty())
        .collect();
    assert_eq!(verify.len(), 2, "stdout: {stdout}");
    assert!(
        verify.iter().all(|value| value.len() == 96),
        "stdout: {stdout}"
    );
}

#[test]
fn json_and_ek_raw_use_the_plaintext_source() {
    let args = |mode: &str| -> Vec<OsString> {
        [
            "-n",
            "-r",
            fixture("tls13-aes128.pcap").to_string_lossy().as_ref(),
            "-o",
            &format!(
                "tls.keylog_file:{}",
                fixture("tls13-aes128-keys.log").display()
            ),
            "-T",
            mode,
            "-x",
            "-Y",
            "frame.number==4",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    };
    let output = run(&args("json"), &[], None);
    let (json, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        json.contains("\"08000000\""),
        "tls.handshake_raw must be plaintext: {json}"
    );
    assert!(
        json.contains("\"08\""),
        "tls.handshake.type_raw must be plaintext: {json}"
    );
    let output = run(&args("ek"), &[], None);
    let (ek, _) = text(&output);
    assert!(
        ek.contains("tls_tls_handshake_raw\":\"08000000\""),
        "EK handshake raw: {ek}"
    );

    let args: Vec<OsString> = [
        "-n",
        "-r",
        fixture("tls13-aes128.pcap").to_string_lossy().as_ref(),
        "-o",
        &format!(
            "tls.keylog_file:{}",
            fixture("tls13-aes128-keys.log").display()
        ),
        "-T",
        "json",
        "-x",
        "-Y",
        "frame.number==8",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (json, _) = text(&output);
    assert!(
        json.contains("474554202f68656c6c6f"),
        "http_raw must be plaintext: {json}"
    );
}

#[test]
fn export_matches_the_keylog_for_tls13() {
    let directory = temp_path("export13");
    let capture = fixture("tls13-chacha.pcap");
    let keylog = fixture("tls13-chacha-keys.log");
    let exported = directory.join("exported.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        exported.to_string_lossy().as_ref(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    assert!(output.status.success(), "status: {:?}", output.status);
    let expected = fs::read_to_string(&keylog).expect("keylog");
    let observed = fs::read_to_string(&exported).expect("exported keys");
    assert_eq!(observed, expected);
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn export_marks_resumed_tls12_sessions_with_the_shared_master() {
    let directory = temp_path("export12-resume");
    let capture = fixture("tls12-resume.pcap");
    let keylog = fixture("tls12-resume-keys.log");
    let exported = directory.join("exported.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        exported.to_string_lossy().as_ref(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    assert!(output.status.success(), "status: {:?}", output.status);
    let observed = fs::read_to_string(&exported).expect("exported keys");
    let lines: Vec<&str> = observed.lines().collect();
    assert_eq!(lines.len(), 2, "exported: {observed}");
    let secret = |line: &str| line.split(' ').nth(2).unwrap_or("").to_string();
    assert_eq!(secret(lines[0]), secret(lines[1]));
    assert_ne!(
        lines[0].split(' ').nth(1),
        lines[1].split(' ').nth(1),
        "resumed session has a new client random"
    );
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn export_truncates_an_existing_file() {
    let directory = temp_path("export-truncate");
    let capture = fixture("tls12-gcm.pcap");
    let keylog = fixture("tls12-gcm-keys.log");
    let exported = directory.join("keys.log");
    fs::write(&exported, b"PRESET\n").expect("preseed");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        exported.to_string_lossy().as_ref(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    assert!(output.status.success(), "status: {:?}", output.status);
    let observed = fs::read_to_string(&exported).expect("exported");
    assert!(!observed.contains("PRESET"), "exported: {observed}");
    assert!(
        observed.starts_with("CLIENT_RANDOM "),
        "exported: {observed}"
    );
    let _ = fs::remove_dir_all(&directory);
}

#[cfg(unix)]
#[test]
fn export_file_is_private_and_does_not_chmod_a_symlink_target() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = temp_path("export-mode");
    let capture = fixture("tls12-gcm.pcap");
    let keylog = fixture("tls12-gcm-keys.log");
    let regular = directory.join("regular.log");
    fs::write(&regular, b"PRESET\n").expect("preseed");
    fs::set_permissions(&regular, fs::Permissions::from_mode(0o644)).expect("mode");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        regular.to_string_lossy().as_ref(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    assert!(output.status.success(), "status: {:?}", output.status);
    let mode = fs::metadata(&regular)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "regular export mode");

    let victim = directory.join("victim.txt");
    fs::write(&victim, b"ORIGINAL\n").expect("victim");
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).expect("victim mode");
    let link = directory.join("keys.log");
    symlink(&victim, &link).expect("symlink");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        link.to_string_lossy().as_ref(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    assert!(output.status.success(), "status: {:?}", output.status);
    let mode = fs::metadata(&victim)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644, "symlink target mode stays untouched");
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn export_reports_a_missing_parent_and_exits_zero() {
    let directory = temp_path("export-missing");
    let capture = fixture("tls12-gcm.pcap");
    let keylog = fixture("tls12-gcm-keys.log");
    let exported = directory.join("absent").join("keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "--export-tls-session-keys",
        exported.to_string_lossy().as_ref(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (_, stderr) = text(&output);
    assert!(output.status.success(), "status: {:?}", output.status);
    assert!(
        stderr.contains("cannot open TLS session key file"),
        "stderr: {stderr}"
    );
    assert!(!exported.exists());
    let _ = fs::remove_dir_all(&directory);
}

#[test]
fn decrypted_pdml_uses_the_plaintext_data_source() {
    let capture = fixture("tls13-aes256.pcap");
    let keylog = fixture("tls13-aes256-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-T",
        "pdml",
        "-Y",
        "frame.number==8",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    let http = stdout
        .split("<proto name=\"http\"")
        .nth(1)
        .unwrap_or_default();
    assert!(
        http.contains("size=\"39\" pos=\"0\""),
        "HTTP protocol range: {http}"
    );
    assert!(
        http.contains(
            "name=\"http.request.uri\" showname=\"Request URI: /hello\" size=\"6\" pos=\"4\""
        ),
        "request URI range: {http}"
    );
    assert!(http.contains("https://tls.test/hello"), "full URI: {http}");
    assert!(
        stdout.contains("name=\"tls.record.sequence_number\" showname=\"Sequence Number: 0\""),
        "sequence field: {stdout}"
    );
}

fn decrypted_fields(capture: &str, keylog: &str, fields: &[&str]) -> String {
    let mut args: Vec<OsString> = vec![
        "-n".into(),
        "-r".into(),
        fixture(capture).to_string_lossy().into_owned().into(),
        "-o".into(),
        format!("tls.keylog_file:{}", fixture(keylog).display()).into(),
        "-T".into(),
        "fields".into(),
    ];
    for field in fields {
        args.push("-e".into());
        args.push((*field).into());
    }
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    stdout
}

#[test]
fn split_records_and_handshakes_decrypt_across_segments() {
    let tls13 = decrypted_fields(
        "tls13-split.pcap",
        "tls13-aes128-keys.log",
        &[
            "frame.number",
            "tls.handshake.verify_data",
            "tls.app_data_proto",
            "http.request.uri",
            "http.response.code",
        ],
    );
    assert_eq!(
        tls13.matches("/split").count(),
        2,
        "one request and its response: {tls13}"
    );
    assert!(
        tls13.lines().any(|line| line.ends_with("\t/split\t200")),
        "response on the completion frame: {tls13}"
    );
    assert_eq!(
        tls13
            .lines()
            .filter(|line| line.contains("\tHypertext Transfer Protocol\t"))
            .count(),
        5,
        "each decrypted record is labelled: {tls13}"
    );

    let tls12 = decrypted_fields(
        "tls12-split.pcap",
        "tls12-gcm-keys.log",
        &[
            "frame.number",
            "tls.handshake.verify_data",
            "http.request.uri",
            "http.response.code",
        ],
    );
    let verify: Vec<&str> = tls12
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|value| !value.is_empty())
        .collect();
    assert_eq!(verify.len(), 2, "two Finished messages: {tls12}");
    assert!(
        verify.iter().all(|value| value.len() == 24),
        "TLS 1.2 verify_data is 12 bytes: {tls12}"
    );
    assert!(tls12.contains("/split"), "TLS 1.2 request: {tls12}");
}

#[test]
fn keyupdate_split_across_frames_advances_the_epoch() {
    let stdout = decrypted_fields(
        "tls13-keyupdate-split.pcap",
        "tls13-keyupdate-keys.log",
        &[
            "frame.number",
            "tls.handshake.type",
            "http.request.uri",
            "http.response.code",
        ],
    );
    assert!(stdout.contains("/before"), "pre-rekey request: {stdout}");
    assert!(stdout.contains("/after"), "post-rekey request: {stdout}");
    assert_eq!(
        stdout.matches("200").count(),
        2,
        "both responses decrypt: {stdout}"
    );
}

#[test]
fn unauthenticated_plaintext_records_do_not_advance_tls13_state() {
    for capture in [
        "tls13-plaintext-keyupdate.pcap",
        "tls13-plaintext-alert.pcap",
    ] {
        let stdout = decrypted_fields(
            capture,
            "tls13-aes128-keys.log",
            &[
                "frame.number",
                "tls.handshake.type",
                "http.request.uri",
                "http.response.code",
                "http.file_data",
            ],
        );
        assert!(stdout.contains("/spoof"), "request after spoof: {stdout}");
        assert!(
            stdout.contains("200") && stdout.contains("68656c6c6f"),
            "later records still decrypt: {stdout}"
        );
    }
    let keyupdate = decrypted_fields(
        "tls13-plaintext-keyupdate.pcap",
        "tls13-aes128-keys.log",
        &["frame.number", "tls.handshake.type"],
    );
    assert!(
        keyupdate.contains("\t24"),
        "spoofed KeyUpdate is shown: {keyupdate}"
    );
}

#[test]
fn a_hello_retry_request_only_accepts_its_matching_client_hello() {
    let stdout = decrypted_fields(
        "tls13-hrr-spoof.pcap",
        "tls13-aes128-keys.log",
        &[
            "frame.number",
            "tls.handshake.type",
            "tls.handshake.verify_data",
        ],
    );
    for (frame, handshake) in [(5, "8"), (6, "20"), (7, "20")] {
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with(&format!("{frame}\t{handshake}\t"))),
            "frame {frame} handshake {handshake} survives the HRR spoof: {stdout}"
        );
    }
    let finished = stdout
        .lines()
        .find(|line| line.starts_with("6\t20\t"))
        .unwrap_or_default();
    assert!(
        finished
            .split('\t')
            .nth(2)
            .is_some_and(|value| value.len() == 64),
        "the genuine Finished verify_data is present: {stdout}"
    );
}

#[test]
fn an_unauthenticated_close_notify_does_not_flush_pending_http() {
    let stdout = decrypted_fields(
        "tls13-close-notify-spoof.pcap",
        "tls13-aes128-keys.log",
        &[
            "frame.number",
            "http.request.uri",
            "http.response.code",
            "http.file_data",
        ],
    );
    assert!(
        stdout.contains("/notify"),
        "genuine request decodes: {stdout}"
    );
    assert!(
        !stdout.contains("200") && !stdout.contains("68656c6c6f"),
        "spoofed close_notify must not complete the response: {stdout}"
    );
}

#[test]
fn a_close_delimited_tls_response_decodes_at_fin() {
    let stdout = decrypted_fields(
        "tls13-close-delimited.pcap",
        "tls13-aes128-keys.log",
        &[
            "frame.number",
            "http.request.uri",
            "http.response.code",
            "http.file_data",
        ],
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.ends_with("\t/close\t200\t68656c6c6f207468657265")),
        "close-delimited response and body at FIN: {stdout}"
    );
}

#[test]
fn json_raw_arrays_report_data_source_ids() {
    let args: Vec<OsString> = [
        "-n",
        "-r",
        fixture("tls13-split.pcap").to_string_lossy().as_ref(),
        "-o",
        &format!(
            "tls.keylog_file:{}",
            fixture("tls13-aes128-keys.log").display()
        ),
        "-T",
        "json",
        "-x",
        "-Y",
        "frame.number==7",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert_eq!(
        raw_source(&stdout, "tls.handshake_raw"),
        Some(2),
        "decrypted handshake raw source: {stdout}"
    );
    assert_eq!(
        raw_source(&stdout, "tls.record_raw"),
        Some(1),
        "reassembled record raw source: {stdout}"
    );
}

/// Sixth element of one JSON raw array.
fn raw_source(json: &str, key: &str) -> Option<u32> {
    let start = json.find(&format!("\"{key}\": ["))?;
    let rest = json.get(start..)?;
    let end = rest.find(']')?;
    rest.get(..end)?.lines().rev().find_map(|line| {
        let value = line.trim().trim_end_matches(',');
        value.parse().ok()
    })
}

#[test]
fn retransmission_and_gap_never_decrypt_a_record_twice() {
    let retransmit = decrypted_fields(
        "tls13-retransmit.pcap",
        "tls13-aes128-keys.log",
        &["frame.number", "http.request.uri", "http.response.code"],
    );
    assert_eq!(retransmit.matches("/one").count(), 2, "{retransmit}");
    assert_eq!(retransmit.matches("/after").count(), 2, "{retransmit}");
    assert_eq!(retransmit.matches("200").count(), 2, "{retransmit}");

    let gap = decrypted_fields(
        "tls13-gap.pcap",
        "tls13-aes128-keys.log",
        &["frame.number", "http.request.uri", "http.response.code"],
    );
    assert!(gap.contains("/gap"), "request before the gap: {gap}");
    assert!(
        !gap.contains("200"),
        "the incomplete response stays opaque: {gap}"
    );
}

#[test]
fn a_bad_tag_stops_the_direction_without_leaking_plaintext() {
    let stdout = decrypted_fields(
        "tls13-bad-tag.pcap",
        "tls13-aes128-keys.log",
        &["frame.number", "http.request.uri", "http.response.code"],
    );
    assert!(
        stdout.contains("/bad"),
        "request before the bad tag: {stdout}"
    );
    assert!(
        !stdout.contains("200"),
        "corrupted and following records stay opaque: {stdout}"
    );
}

#[test]
fn reassembled_record_fields_read_the_reassembly_buffer() {
    let capture = fixture("tls13-split.pcap");
    let keylog = fixture("tls13-aes128-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-T",
        "pdml",
        "-Y",
        "frame.number==2",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    let content_type = stdout
        .lines()
        .find(|line| line.contains("name=\"tls.record.content_type\""))
        .unwrap_or_default();
    assert!(
        content_type.contains("value=\"16\""),
        "record header comes from the reassembled record: {content_type}"
    );
    let handshake_type = stdout
        .lines()
        .find(|line| line.contains("name=\"tls.handshake.type\""))
        .unwrap_or_default();
    assert!(
        handshake_type.contains("value=\"01\""),
        "handshake bytes come from the reassembled record: {handshake_type}"
    );
}

#[test]
fn tls10_and_tls11_cbc_records_decrypt_from_a_client_random() {
    let tls10 = decrypted_fields(
        "tls10-cbc.pcap",
        "tls10-cbc-keys.log",
        &[
            "frame.number",
            "tls.record.sequence_number",
            "tls.record.version",
            "http.request.uri",
            "http.response.code",
        ],
    );
    // Both directions number their protected records from zero and count
    // their own records only (RFC 2246 section 6.2.3.1).
    let sequences: Vec<&str> = tls10
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|value| !value.is_empty())
        .collect();
    assert_eq!(sequences, ["0", "0", "1", "1", "2", "2"], "{tls10}");
    assert_eq!(tls10.matches("/one").count(), 2, "{tls10}");
    assert_eq!(tls10.matches("/two").count(), 2, "{tls10}");
    assert_eq!(tls10.matches("\t200").count(), 2, "{tls10}");
    // The record version field carries the negotiated version.
    let versions: Vec<&str> = tls10
        .lines()
        .filter_map(|line| line.split('\t').nth(2))
        .filter(|value| !value.is_empty())
        .collect();
    assert!(!versions.is_empty(), "{tls10}");
    assert!(
        versions.iter().all(|version| *version == "0x0301"),
        "{tls10}"
    );

    let tls11 = decrypted_fields(
        "tls11-cbc.pcap",
        "tls11-cbc-keys.log",
        &[
            "frame.number",
            "tls.record.version",
            "http.request.uri",
            "http.response.code",
        ],
    );
    assert!(tls11.contains("/one-one"), "{tls11}");
    assert_eq!(tls11.matches("\t200").count(), 1, "{tls11}");
    let versions: Vec<&str> = tls11
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|value| !value.is_empty())
        .collect();
    assert!(!versions.is_empty(), "{tls11}");
    assert!(
        versions.iter().all(|version| *version == "0x0302"),
        "every record carries 0x0302: {tls11}"
    );
}

#[test]
fn tls10_record_split_across_segments_decrypts_once() {
    let stdout = decrypted_fields(
        "tls10-split.pcap",
        "tls10-split-keys.log",
        &["frame.number", "http.request.uri", "http.response.code"],
    );
    assert_eq!(stdout.matches("/split").count(), 2, "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("10\t") && line.ends_with("\t200")),
        "the response completes on the second segment: {stdout}"
    );
}

#[test]
fn tls10_truncated_record_stays_opaque() {
    let stdout = decrypted_fields(
        "tls10-truncated.pcap",
        "tls10-truncated-keys.log",
        &["frame.number", "http.request.uri", "http.response.code"],
    );
    assert!(
        stdout.contains("/truncated"),
        "request before the gap: {stdout}"
    );
    assert!(
        !stdout.contains("200"),
        "the incomplete response stays opaque: {stdout}"
    );
}

#[test]
fn tls10_encrypt_then_mac_decrypts_with_an_iv_less_mac() {
    let stdout = decrypted_fields(
        "tls10-cbc-etm.pcap",
        "tls10-cbc-etm-keys.log",
        &[
            "frame.number",
            "tls.record.sequence_number",
            "http.request.uri",
            "http.response.code",
        ],
    );
    assert_eq!(stdout.matches("/etm").count(), 2, "{stdout}");
    assert_eq!(stdout.matches("\t200").count(), 1, "{stdout}");
    let sequences: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|value| !value.is_empty())
        .collect();
    assert_eq!(sequences, ["0", "0", "1", "1"], "{stdout}");

    let capture = fixture("tls10-cbc-etm.pcap");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-Y",
        "frame.number==2",
        "-V",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (verbose, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        verbose.contains("Extension: encrypt_then_mac (len=0)"),
        "{verbose}"
    );
}

#[test]
fn tls10_bad_mac_and_wrong_sequence_stop_the_direction() {
    let stdout = decrypted_fields(
        "tls10-malformed.pcap",
        "tls10-malformed-keys.log",
        &[
            "frame.number",
            "tls.record.content_type",
            "http.request.uri",
            "http.response.code",
        ],
    );
    assert!(stdout.contains("/bad-mac"), "{stdout}");
    assert!(stdout.contains("/sequence"), "{stdout}");
    // Each conversation keeps its protected application record: the
    // bad-MAC response, and the second response, which was protected with
    // the next server sequence number after the first response was dropped
    // from the capture, so it arrives where the first one is expected.
    assert!(
        stdout.lines().any(|line| line == "8\t23\t\t"),
        "the bad-MAC response record stays opaque: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| line == "16\t23\t\t"),
        "the sequence-skipping response record stays in the capture and opaque: {stdout}"
    );
    assert!(
        !stdout.contains("200"),
        "records with a bad MAC or a skipped sequence number stay opaque: {stdout}"
    );
}

#[test]
fn tls10_bad_padding_and_version_mismatch_stay_opaque() {
    // The expected output decrypts every response; RFC 2246 sections 6.2.1
    // and 6.2.3.2 reject them, so this capture has no stored expected output.
    // `/version-only` is answered by a record that authenticates under its
    // TLS 1.2 header, so only the version check keeps it opaque.
    let stdout = decrypted_fields(
        "tls10-strict.pcap",
        "tls10-strict-keys.log",
        &["frame.number", "http.request.uri", "http.response.code"],
    );
    assert!(stdout.contains("/bad-padding"), "{stdout}");
    assert!(stdout.contains("/version\t"), "{stdout}");
    assert!(stdout.contains("/version-only"), "{stdout}");
    assert!(
        !stdout.contains("200"),
        "invalid padding and a mismatched record version stay opaque: {stdout}"
    );
}

#[test]
fn tls10_padding_run_is_stripped_completely() {
    let stdout = decrypted_fields(
        "tls10-padded.pcap",
        "tls10-padded-keys.log",
        &["frame.number", "http.response.code", "http.file_data"],
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.ends_with("\t200\t68656c6c6f21")),
        "a full block of padding leaves only the body: {stdout}"
    );
}

#[test]
fn tls10_and_tls11_version_labels_match_the_reference() {
    let capture = fixture("tls10-cbc.pcap");
    let keylog = fixture("tls10-cbc-keys.log");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-Y",
        "frame.number==1",
        "-V",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("TLSv1 Record Layer: Handshake Protocol: Client Hello"),
        "{stdout}"
    );
    assert!(stdout.contains("Version: TLS 1.0 (0x0301)"), "{stdout}");

    let capture = fixture("tls11-cbc.pcap");
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-Y",
        "frame.number==2",
        "-V",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("TLSv1.1 Record Layer: Handshake Protocol: Server Hello"),
        "{stdout}"
    );
    assert!(stdout.contains("Version: TLS 1.1 (0x0302)"), "{stdout}");
}

#[test]
fn keylog_option_requires_a_value() {
    let args: Vec<OsString> = ["-o", "tls.keylog_file"]
        .into_iter()
        .map(OsString::from)
        .collect();
    let output = run(&args, &[], None);
    let (_, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("needs NAME:VALUE"), "stderr: {stderr}");
}

#[test]
fn export_option_requires_a_value() {
    let args: Vec<OsString> = [OsStr::new("--export-tls-session-keys")]
        .into_iter()
        .map(OsString::from)
        .collect();
    let output = run(&args, &[], None);
    let (_, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("requires a value"), "stderr: {stderr}");
}

#[test]
fn a_session_reset_keeps_the_key_log_and_key_export() {
    let directory = temp_path("reset-tls");
    let capture = fixture("tls10-strict.pcap");
    let keylog = fixture("tls10-strict-keys.log");
    let exported = directory.join("exported.log");
    // The capture holds three handshakes; the later two start after the
    // reset, so they can only be decrypted and exported if the key log and
    // the export flag survive the reset.
    let args: Vec<OsString> = [
        "-n",
        "-r",
        capture.to_string_lossy().as_ref(),
        "-o",
        &format!("tls.keylog_file:{}", keylog.display()),
        "-M",
        "8",
        "--export-tls-session-keys",
        exported.to_string_lossy().as_ref(),
        "-T",
        "fields",
        "-e",
        "http.request.uri",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let output = run(&args, &[], None);
    let (stdout, stderr) = text(&output);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stdout.contains("/bad-padding"), "stdout: {stdout}");
    assert!(stdout.contains("/version"), "stdout: {stdout}");
    let keys = fs::read_to_string(&exported).expect("exported keys");
    assert_eq!(
        keys.lines()
            .filter(|line| line.starts_with("CLIENT_RANDOM "))
            .count(),
        3,
        "exported keys: {keys}"
    );
    let _ = fs::remove_dir_all(&directory);
}
