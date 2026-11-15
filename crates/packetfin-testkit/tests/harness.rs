//! Harness tests: committed fixtures and goldens must match the registry, and
//! golden comparison must report differences clearly.

use std::collections::HashSet;
use std::fs;

use packetfin_testkit::fixtures::{self, Fixture, GoldenCase};
use packetfin_testkit::golden;

#[test]
fn fixture_registry_has_unique_names() {
    let fixtures = fixtures::all();
    assert_eq!(fixtures.len(), 306);
    let mut names = HashSet::new();
    for fixture in fixtures {
        assert!(
            names.insert(fixture.name),
            "duplicate fixture name: {}",
            fixture.name
        );
    }
}

#[test]
fn committed_fixtures_match_generated_bytes() -> Result<(), String> {
    for fixture in fixtures::all() {
        let path = golden::fixtures_dir().join(fixture.file_name());
        let committed =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let generated = fixture.build()?;
        if committed != generated {
            return Err(format!(
                "fixture {} ({}) differs: committed {} bytes, generated {} bytes; run `cargo run -p packetfin-testkit --bin gen-fixtures`",
                fixture.name,
                path.display(),
                committed.len(),
                generated.len()
            ));
        }
    }
    Ok(())
}

#[test]
fn every_case_has_stored_golden_files() -> Result<(), String> {
    let directory = golden::golden_dir();
    for fixture in fixtures::all() {
        for case in fixture.cases() {
            for extension in ["stdout", "stderr", "status"] {
                let path = directory
                    .join(fixture.name)
                    .join(format!("{}.{extension}", case.id));
                if !path.is_file() {
                    return Err(format!(
                        "missing golden file {}; maintainers regenerate expected output",
                        path.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn compare_golden_accepts_matching_output() -> Result<(), String> {
    let (fixture, case, stored) = sample()?;
    golden::compare_golden(
        fixture.name,
        case.id,
        &stored.stdout,
        &stored.stderr,
        stored.status,
    )
}

#[test]
fn compare_golden_rejects_changed_stdout() -> Result<(), String> {
    let (fixture, case, stored) = sample()?;
    let mut stdout = stored.stdout.clone();
    stdout.push(b'!');
    let message = expect_mismatch(fixture, &case, &stdout, &stored.stderr, stored.status)?;
    if !message.contains("stdout") {
        return Err(format!("message does not name stdout: {message}"));
    }
    Ok(())
}

#[test]
fn compare_golden_rejects_changed_stderr() -> Result<(), String> {
    let (fixture, case, stored) = sample()?;
    let mut stderr = stored.stderr.clone();
    stderr.push(b'!');
    let message = expect_mismatch(fixture, &case, &stored.stdout, &stderr, stored.status)?;
    if !message.contains("stderr") {
        return Err(format!("message does not name stderr: {message}"));
    }
    Ok(())
}

#[test]
fn compare_golden_rejects_changed_status() -> Result<(), String> {
    let (fixture, case, stored) = sample()?;
    let message = expect_mismatch(
        fixture,
        &case,
        &stored.stdout,
        &stored.stderr,
        stored.status.wrapping_add(1),
    )?;
    if !message.contains("status") {
        return Err(format!("message does not name status: {message}"));
    }
    Ok(())
}

#[test]
fn fixture_building_is_deterministic() -> Result<(), String> {
    for fixture in fixtures::all() {
        let first = fixture.build()?;
        let second = fixture.build()?;
        if first != second {
            return Err(format!(
                "fixture {} built different bytes on two runs",
                fixture.name
            ));
        }
    }
    Ok(())
}

#[test]
fn pcap_rejects_fraction_beyond_resolution() -> Result<(), String> {
    use packetfin_testkit::{ByteOrder, Timestamp, TimestampResolution};

    let mut file =
        packetfin_testkit::pcap::Pcap::new(ByteOrder::Little, TimestampResolution::Microsecond);
    let result = file.push(Timestamp::new(0, 1_000_000), Vec::new());
    if result.is_ok() {
        return Err("a microsecond pcap accepted a fraction of one second".to_string());
    }
    Ok(())
}

#[test]
fn compare_golden_stdout_status_accepts_matching_output_and_ignores_stderr() -> Result<(), String> {
    let fixture = fixture_named("garbage")?;
    let case = fixture
        .cases()
        .into_iter()
        .find(|case| case.id == "frame-fields")
        .ok_or_else(|| "garbage fixture has no frame-fields case".to_string())?;
    let stored = golden::load(fixture.name, case.id)?;
    if stored.stderr.is_empty() {
        return Err("garbage golden should carry the expected stderr".to_string());
    }
    golden::compare_golden_stdout_status(fixture.name, case.id, &stored.stdout, stored.status)
}

#[test]
fn compare_golden_stdout_status_rejects_changed_stdout() -> Result<(), String> {
    let (fixture, case, stored) = sample()?;
    let mut stdout = stored.stdout.clone();
    stdout.push(b'!');
    let message = expect_stdout_status_mismatch(fixture, &case, &stdout, stored.status)?;
    if !message.contains("stdout") {
        return Err(format!("message does not name stdout: {message}"));
    }
    Ok(())
}

#[test]
fn compare_golden_stdout_status_rejects_changed_status() -> Result<(), String> {
    let (fixture, case, stored) = sample()?;
    let message = expect_stdout_status_mismatch(
        fixture,
        &case,
        &stored.stdout,
        stored.status.wrapping_add(1),
    )?;
    if !message.contains("status") {
        return Err(format!("message does not name status: {message}"));
    }
    Ok(())
}

fn fixture_named(name: &str) -> Result<&'static Fixture, String> {
    fixtures::all()
        .iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| format!("fixture {name} is not registered"))
}

fn sample() -> Result<(&'static Fixture, GoldenCase, golden::Golden), String> {
    let fixture = fixtures::all().first().ok_or("fixture registry is empty")?;
    let case = fixture
        .cases()
        .into_iter()
        .next()
        .ok_or("golden case registry is empty")?;
    let stored = golden::load(fixture.name, case.id)?;
    Ok((fixture, case, stored))
}

fn expect_stdout_status_mismatch(
    fixture: &Fixture,
    case: &GoldenCase,
    stdout: &[u8],
    status: i32,
) -> Result<String, String> {
    match golden::compare_golden_stdout_status(fixture.name, case.id, stdout, status) {
        Ok(()) => Err(format!(
            "changed stdout or status for {}/{} was accepted",
            fixture.name, case.id
        )),
        Err(message) => {
            if !message.contains(fixture.name) {
                return Err(format!("message does not name the fixture: {message}"));
            }
            if !message.contains(case.id) {
                return Err(format!("message does not name the case: {message}"));
            }
            Ok(message)
        }
    }
}

fn expect_mismatch(
    fixture: &Fixture,
    case: &GoldenCase,
    stdout: &[u8],
    stderr: &[u8],
    status: i32,
) -> Result<String, String> {
    match golden::compare_golden(fixture.name, case.id, stdout, stderr, status) {
        Ok(()) => Err(format!(
            "changed output for {}/{} was accepted",
            fixture.name, case.id
        )),
        Err(message) => {
            if !message.contains(fixture.name) {
                return Err(format!("message does not name the fixture: {message}"));
            }
            if !message.contains(case.id) {
                return Err(format!("message does not name the case: {message}"));
            }
            Ok(message)
        }
    }
}
