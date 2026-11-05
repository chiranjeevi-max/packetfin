use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::process::{Command, ExitStatus, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_packetfin");

fn run(args: &[&str]) -> (ExitStatus, String, String) {
    let arguments: Vec<OsString> = args.iter().map(OsString::from).collect();
    run_os(&arguments)
}

fn run_os(args: &[OsString]) -> (ExitStatus, String, String) {
    let output = match Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("failed to execute packetfin: {error}");
            std::process::exit(1);
        }
    };
    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn fixture_path(name: &str) -> String {
    packetfin_testkit::golden::fixtures_dir()
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn help_exits_zero_and_prints_usage() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert!(status.success(), "exit status: {status}");
    assert!(
        stdout.contains("Usage: packetfin [options]"),
        "stdout: {stdout}"
    );
    assert!(stderr.is_empty(), "stderr must be empty: {stderr}");
}

#[test]
fn short_help_exits_zero() {
    let (status, stdout, _) = run(&["-h"]);
    assert!(status.success());
    assert!(stdout.contains("Usage: packetfin [options]"));
}

#[test]
fn version_exits_zero_and_prints_banner() {
    let (status, stdout, stderr) = run(&["--version"]);
    assert!(status.success(), "exit status: {status}");
    assert!(stdout.contains("packetfin 0.1.0"), "stdout: {stdout}");
    assert!(
        stdout.contains("command-line packet analyzer"),
        "stdout: {stdout}"
    );
    assert!(stderr.is_empty(), "stderr must be empty: {stderr}");
}

#[test]
fn short_version_exits_zero() {
    let (status, stdout, _) = run(&["-v"]);
    assert!(status.success());
    assert!(stdout.contains("packetfin 0.1.0"));
}

#[test]
fn unknown_option_exits_one_with_stderr_prefix() {
    let (status, stdout, stderr) = run(&["--nonsense"]);
    assert!(!status.success(), "exit status: {status}");
    assert!(
        stderr.starts_with("packetfin: unrecognized option: --nonsense"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("Usage: packetfin [options]"),
        "stderr must include usage: {stderr}"
    );
    assert!(stdout.is_empty(), "stdout must be empty: {stdout}");
}

#[test]
fn short_unknown_option_exits_one() {
    let (status, _, stderr) = run(&["-Z"]);
    assert!(!status.success());
    assert!(
        stderr.starts_with("packetfin: unrecognized option: -Z"),
        "stderr: {stderr}"
    );
}

// No-argument invocation is a live capture on the default interface, which
// cannot run in the test harness. The parser-level test in `cli.rs` pins that
// the default input is live instead of the old usage error.

#[test]
fn first_help_flag_wins_over_unknown_option() {
    let (status, stdout, stderr) = run(&["-h", "--nonsense"]);
    assert!(status.success(), "exit status: {status}");
    assert!(
        stdout.contains("Usage: packetfin [options]"),
        "stdout: {stdout}"
    );
    assert!(stderr.is_empty(), "stderr must be empty: {stderr}");
}

#[test]
fn combined_short_flags_are_one_unknown_option() {
    // `-hv` is not a recognised combined flag; it is one unknown option.
    let (status, _, stderr) = run(&["-hv"]);
    assert!(!status.success());
    assert!(
        stderr.starts_with("packetfin: unrecognized option: -hv"),
        "stderr: {stderr}"
    );
}

#[test]
fn double_dash_ends_options() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    let (status, stdout, stderr) =
        run(&["-T", "fields", "-e", "frame.number", "-r", &capture, "--"]);
    assert!(status.success(), "stderr: {stderr}");
    assert_eq!(stdout, "1\n");
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn argument_after_double_dash_exits_one() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    let (status, stdout, stderr) = run(&[
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-r",
        &capture,
        "--",
        "udp.port==53",
    ]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.starts_with("packetfin: unexpected argument: udp.port==53"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_attached_read_file_exits_three() {
    let mut argument = b"--read-file=".to_vec();
    argument.extend_from_slice(b"/tmp/packetfin-missing-\xff.pcap");
    let args = vec![
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        OsString::from_vec(argument),
    ];
    let (status, stdout, stderr) = run_os(&args);
    assert_eq!(status.code(), Some(3), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(!stderr.is_empty(), "stderr must explain the open failure");
}

#[cfg(unix)]
#[test]
fn non_utf8_attached_short_read_file_exits_three() {
    let mut argument = b"-r".to_vec();
    argument.extend_from_slice(b"/tmp/packetfin-missing-\xff.pcap");
    let args = vec![
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-e"),
        OsString::from("frame.number"),
        OsString::from_vec(argument),
    ];
    let (status, stdout, stderr) = run_os(&args);
    assert_eq!(status.code(), Some(3), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(!stderr.is_empty(), "stderr must explain the open failure");
}

#[test]
fn control_characters_in_field_diagnostic_are_escaped() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    let (status, _, stderr) = run(&[
        "-T",
        "fields",
        "-e",
        "\u{1b}[31mred\nsecond",
        "-r",
        &capture,
    ]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(!stderr.contains('\u{1b}'), "raw ESC in stderr: {stderr:?}");
    assert!(
        !stderr.contains("\nsecond"),
        "raw newline in stderr: {stderr:?}"
    );
    assert!(stderr.contains("\\u{1b}[31mred"), "stderr: {stderr:?}");
    assert!(stderr.contains("\\nsecond"), "stderr: {stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "stderr: {stderr:?}");
}

#[test]
fn control_characters_in_path_diagnostic_are_escaped() {
    let mut path = std::env::temp_dir().into_os_string();
    path.push("packetfin-missing-\u{1b}[31m");
    path.push("\nname.pcap");
    let path = path.to_string_lossy();
    let (status, _, stderr) = run(&["-T", "fields", "-e", "frame.number", "-r", &path]);
    assert_eq!(status.code(), Some(3), "stderr: {stderr}");
    assert!(!stderr.contains('\u{1b}'), "raw ESC in stderr: {stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "stderr: {stderr:?}");
    assert!(stderr.contains("\\u{1b}[31m"), "stderr: {stderr:?}");
    assert!(stderr.contains("\\nname.pcap"), "stderr: {stderr:?}");
}

#[test]
fn control_characters_in_unknown_option_are_escaped() {
    let (status, _, stderr) = run(&["--\u{1b}[31mred"]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(!stderr.contains('\u{1b}'), "raw ESC in stderr: {stderr:?}");
    assert!(stderr.contains("\\u{1b}[31mred"), "stderr: {stderr:?}");
}

#[test]
fn help_documents_the_state_budget_option() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert!(status.success(), "exit status: {status}");
    assert!(
        stdout.contains("--pf-state-budget BYTES"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(&packetfin_core::DEFAULT_STATE_BUDGET.to_string()),
        "help must derive the default from DEFAULT_STATE_BUDGET: {stdout}"
    );
    assert!(stderr.is_empty(), "stderr: {stderr}");
}

#[test]
fn state_budget_accepts_zero_and_attached_values() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for argument in ["--pf-state-budget", "--pf-state-budget="] {
        let value = if argument.ends_with('=') {
            format!("{argument}0")
        } else {
            argument.to_string()
        };
        let mut args = vec!["-T", "fields", "-e", "frame.number"];
        if argument.ends_with('=') {
            args.push(&value);
        } else {
            args.push(&value);
            args.push("0");
        }
        args.extend(["-r", &capture]);
        let (status, stdout, stderr) = run(&args);
        assert!(status.success(), "stderr: {stderr}");
        assert_eq!(stdout, "1\n", "stderr: {stderr}");
        assert!(stderr.is_empty(), "stderr: {stderr}");
    }
}

#[test]
fn stats_budget_accepts_zero_and_attached_values() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for argument in ["--pf-stats-budget", "--pf-stats-budget="] {
        let value = if argument.ends_with('=') {
            format!("{argument}0")
        } else {
            argument.to_string()
        };
        let mut args = vec!["-T", "fields", "-e", "frame.number", "-z", "io,phs"];
        if argument.ends_with('=') {
            args.push(&value);
        } else {
            args.push(&value);
            args.push("0");
        }
        args.extend(["-r", &capture]);
        let (status, stdout, stderr) = run(&args);
        assert!(status.success(), "stderr: {stderr}");
        assert!(stdout.starts_with("1\n"), "stdout: {stdout}");
        assert!(stdout.contains("Protocol Hierarchy Statistics"), "{stdout}");
    }
}

#[test]
fn invalid_stats_budgets_exit_one_with_own_wording() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for value in ["", "-1", "+1", "1.5", "abc", "18446744073709551616"] {
        let (status, stdout, stderr) = run(&[
            "-T",
            "fields",
            "-e",
            "frame.number",
            "--pf-stats-budget",
            value,
            "-r",
            &capture,
        ]);
        assert_eq!(status.code(), Some(1), "value {value:?}: {stderr}");
        assert!(stdout.is_empty(), "value {value:?}: {stdout}");
        assert!(
            stderr.starts_with("packetfin: invalid --pf-stats-budget value")
                || stderr.starts_with("packetfin: --pf-stats-budget value"),
            "value {value:?}: {stderr}"
        );
    }
}

#[test]
fn the_stats_option_requires_a_value() {
    let (status, stdout, stderr) = run(&["-z"]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("option -z requires a value"),
        "stderr: {stderr}"
    );
}

#[test]
fn invalid_state_budgets_exit_one_with_own_wording() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for value in ["", "-1", "+1", "1.5", "abc", "18446744073709551616"] {
        let (status, stdout, stderr) = run(&[
            "-T",
            "fields",
            "-e",
            "frame.number",
            "--pf-state-budget",
            value,
            "-r",
            &capture,
        ]);
        assert_eq!(status.code(), Some(1), "value {value:?}: {stderr}");
        assert!(stdout.is_empty(), "value {value:?}: {stdout}");
        assert!(
            stderr.starts_with("packetfin: invalid --pf-state-budget value")
                || stderr.starts_with("packetfin: --pf-state-budget value"),
            "value {value:?}: {stderr}"
        );
        assert!(
            stderr.contains("--pf-state-budget"),
            "value {value:?}: {stderr}"
        );
    }
}

#[test]
fn state_budget_requires_a_value() {
    let (status, stdout, stderr) = run(&["--pf-state-budget"]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("option --pf-state-budget requires a value"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_attached_state_budget_exits_one() {
    let mut argument = b"--pf-state-budget=".to_vec();
    argument.push(0xff);
    let (status, stdout, stderr) = run_os(&[OsString::from_vec(argument)]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("--pf-state-budget value is not valid UTF-8"),
        "stderr: {stderr}"
    );
}

#[test]
fn reset_count_validation_uses_fixed_messages() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for (value, fragment) in [
        ("abc", "isn't a decimal number"),
        ("1x", "isn't a decimal number"),
        ("2 ", "isn't a decimal number"),
        ("", "isn't a decimal number"),
        ("-1", "is a negative number"),
        ("-0", "is zero"),
        ("0", "is zero"),
        ("2147483648", "too large (greater than 2147483647)"),
        (
            "99999999999999999999",
            "too large (greater than 2147483647)",
        ),
    ] {
        let (status, stdout, stderr) = run(&["-M", value, "-c", "1", "-r", &capture]);
        assert_eq!(status.code(), Some(1), "value {value:?}: {stderr}");
        assert!(stdout.is_empty(), "value {value:?}: {stdout}");
        assert!(
            stderr.starts_with("packetfin: The specified session reset count"),
            "value {value:?}: {stderr}"
        );
        assert!(
            stderr.contains(fragment),
            "value {value:?}: expected {fragment:?} in {stderr}"
        );
    }
    for value in ["2", "+2", "007", " 2", "2147483647"] {
        let (status, stdout, stderr) = run(&[
            "-M",
            value,
            "-c",
            "1",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-r",
            &capture,
        ]);
        assert_eq!(status.code(), Some(0), "value {value:?}: {stderr}");
        assert_eq!(stdout, "1\n", "value {value:?}: {stderr}");
    }
}

#[test]
fn two_pass_rejects_a_reset_count() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    let (status, stdout, stderr) = run(&["-2", "-M", "2", "-r", &capture]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("-M does not support two-pass analysis."),
        "stderr: {stderr}"
    );
}

#[test]
fn annotation_budget_requires_a_value_and_validates() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    let (status, stdout, stderr) = run(&["--pf-annotation-budget"]);
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
    assert!(stdout.is_empty(), "stdout: {stdout}");
    assert!(
        stderr.contains("option --pf-annotation-budget requires a value"),
        "stderr: {stderr}"
    );
    for value in ["", "-1", "abc", "1.5"] {
        let (status, stdout, stderr) =
            run(&["-2", "--pf-annotation-budget", value, "-r", &capture]);
        assert_eq!(status.code(), Some(1), "value {value:?}: {stderr}");
        assert!(stdout.is_empty(), "value {value:?}: {stdout}");
        assert!(
            stderr.contains("--pf-annotation-budget"),
            "value {value:?}: {stderr}"
        );
    }
}

#[test]
fn reset_and_two_pass_conflicts_report_at_the_second_option() {
    let capture = fixture_path("ethernet-udp-le-us.pcap");
    for (arguments, fragment) in [
        (
            vec!["-2", "-M", "0"],
            "-M does not support two-pass analysis.",
        ),
        (
            vec!["-2", "-M", "abc"],
            "-M does not support two-pass analysis.",
        ),
        (vec!["-2", "-M=2"], "-M does not support two-pass analysis."),
        (vec!["-M2", "-2"], "-2 does not support auto session reset."),
        (
            vec!["-M", "0", "-2"],
            "The specified session reset count is zero",
        ),
    ] {
        let mut full = arguments.clone();
        full.extend(["-r", &capture]);
        let (status, stdout, stderr) = run(&full);
        assert_eq!(status.code(), Some(1), "{arguments:?}: {stderr}");
        assert!(stdout.is_empty(), "{arguments:?}: {stdout}");
        assert!(
            stderr.contains(fragment),
            "{arguments:?}: expected {fragment:?} in {stderr}"
        );
    }
}
