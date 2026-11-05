//! End-to-end tests for `-x` and `--hexdump`.
//!
//! Every golden case whose id starts with `hexdump` compares stdout and the
//! exit status with the golden output. The remaining tests pin the
//! option parser, the `-T fields` conflict and the help exit.

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
    stderr: Vec<u8>,
}

fn run(args: &[OsString]) -> Run {
    let output = Command::new(BIN)
        .args(args)
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

fn fixture_path(fixture: &fixtures::Fixture) -> PathBuf {
    golden::fixtures_dir().join(fixture.file_name())
}

fn fixture(name: &str) -> Option<PathBuf> {
    fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .map(fixture_path)
}

#[test]
fn hexdump_cases_match_stored_goldens() -> Result<(), String> {
    let mut failures = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !case.id.starts_with("hexdump") {
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
        Err(format!("{} hexdump golden case(s) differ", failures.len()))
    }
}

#[test]
fn fields_output_rejects_raw_hex() {
    let Some(path) = fixture("arp-request") else {
        eprintln!("no arp-request fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-x"),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        OsString::from("-r"),
        path.into_os_string(),
    ]);
    assert_eq!(run.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("cannot be printed with -T fields"),
        "the field-output conflict is reported"
    );
}

#[test]
fn hexdump_help_exits_zero() {
    let run = run(&[OsString::from("--hexdump"), OsString::from("help")]);
    assert_eq!(run.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("Data source options:"));
    assert!(stdout.contains("frames"));
    assert!(stdout.contains("notime"));
}

#[test]
fn invalid_hexdump_option_exits_one() {
    let Some(path) = fixture("arp-request") else {
        eprintln!("no arp-request fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("--hexdump"),
        OsString::from("bogus"),
        OsString::from("-r"),
        path.into_os_string(),
    ]);
    assert_eq!(run.status.code(), Some(1));
    assert!(run.stdout.is_empty());
    assert!(String::from_utf8_lossy(&run.stderr).contains("bogus"));
}

#[test]
fn missing_hexdump_value_exits_one() {
    let run = run(&[OsString::from("-n"), OsString::from("--hexdump")]);
    assert_eq!(run.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&run.stderr).contains("requires a value"));
}
