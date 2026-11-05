//! End-to-end tests for the default summary output and its time controls.
//!
//! Every golden case whose id starts with `summary` runs the built binary and
//! compares stdout, stderr and the exit status.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

use packetfin_testkit::fixtures;
use packetfin_testkit::golden;

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

struct Run {
    status: ExitStatus,
    stdout: Vec<u8>,
}

fn run(args: &[OsString]) -> Run {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("failed to spawn packetfin: {error}");
            std::process::exit(1);
        }
    };
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to wait for packetfin: {error}");
            std::process::exit(1);
        }
    };
    Run {
        status: output.status,
        stdout: output.stdout,
    }
}

fn fixture_path(fixture: &fixtures::Fixture) -> PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

#[test]
fn tcp_truncated_options_do_not_invent_tsecr() {
    let Some(fixture) = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == "tcp-truncated-options")
    else {
        eprintln!("no tcp-truncated-options fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        fixture_path(fixture).into_os_string(),
    ]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        !stdout.contains("TSecr=0"),
        "a timestamp option without TSecr must not print one: {stdout}"
    );
    assert!(
        stdout.contains("TSval=287454020 TSecr=1432778632"),
        "the complete timestamp option must still print: {stdout}"
    );
    assert!(
        stdout.contains(
            "[Malformed Packet: length of contained item exceeds length of containing item]"
        ),
        "a truncated TCP option keeps the malformed detail: {stdout}"
    );
}

#[test]
fn tcp_bogus_header_length_omits_len() {
    let Some(fixture) = fixtures::all()
        .iter()
        .find(|fixture| fixture.name == "tcp-boundary")
    else {
        eprintln!("no tcp-boundary fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-r"),
        fixture_path(fixture).into_os_string(),
    ]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let line = stdout
        .lines()
        .find(|line| line.contains("bogus TCP header length (16, must be at least 20)"));
    let Some(line) = line else {
        eprintln!("bogus header line missing: {stdout}");
        std::process::exit(1);
    };
    assert!(
        !line.contains("Len="),
        "bogus header frame must omit Len: {line}"
    );
    assert!(
        stdout.contains(
            "[Malformed Packet: length of contained item exceeds length of containing item]"
        ),
        "contained-item detail missing: {stdout}"
    );
}

#[test]
fn summary_cases_match_stored_goldens() -> Result<(), String> {
    let mut failures = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("summary") {
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
        Err(format!("{} summary golden case(s) differ", failures.len()))
    }
}
