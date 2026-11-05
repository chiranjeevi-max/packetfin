//! End-to-end tests for `-P` and `-S`.
//!
//! Every golden case whose id starts with `print-` or `sep-` compares stdout
//! and the exit status with the golden output. The remaining tests pin the
//! missing `-S` argument and the long `--print` form.

use std::ffi::OsString;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
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
fn print_and_separator_cases_match_stored_goldens() -> Result<(), String> {
    let mut failures = Vec::new();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            if !(case.id.starts_with("print-") || case.id.starts_with("sep-")) {
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
        Err(format!("{} -P/-S golden case(s) differ", failures.len()))
    }
}

#[test]
fn separator_requires_a_value() {
    let run = run(&[OsString::from("-n"), OsString::from("-S")]);
    assert_eq!(run.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&run.stderr).contains("option -S requires a value"));
}

#[test]
fn long_print_matches_short_print() {
    let Some(path) = fixture("arp-hardware-types") else {
        eprintln!("no arp-hardware-types fixture");
        std::process::exit(1);
    };
    let short = run(&[
        OsString::from("-n"),
        OsString::from("-P"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.clone().into_os_string(),
    ]);
    let long = run(&[
        OsString::from("-n"),
        OsString::from("--print"),
        OsString::from("-q"),
        OsString::from("-r"),
        path.into_os_string(),
    ]);
    assert_eq!(short.stdout, long.stdout);
}

#[cfg(unix)]
#[test]
fn attached_non_utf8_separator_is_raw() {
    let Some(path) = fixture("arp-hardware-types") else {
        eprintln!("no arp-hardware-types fixture");
        std::process::exit(1);
    };
    let run = run(&[
        OsString::from("-n"),
        OsString::from("-O"),
        OsString::from("frame"),
        OsString::from_vec(b"-S\xff".to_vec()),
        OsString::from("-r"),
        path.into_os_string(),
    ]);
    assert_eq!(run.status.code(), Some(0));
    assert!(
        run.stdout.contains(&0xff),
        "the separator byte is written unchanged"
    );
}
