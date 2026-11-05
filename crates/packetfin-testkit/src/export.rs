//! Golden manifests for `--export-objects` output.
//!
//! `--export-objects` writes objects into a directory rather than to stdout,
//! so the golden record is a sorted manifest of `sha256`, byte count and file
//! name. The integration tests run Packetfin into a fresh directory and
//! compare its manifest with the stored one.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::golden;

/// One fixture whose exported directory has a stored golden manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportCase {
    /// Fixture name, also the golden directory name.
    pub fixture: &'static str,
    /// Case id, the `export-<id>` manifest stem.
    pub id: &'static str,
    /// `--export-objects` protocol name.
    pub protocol: &'static str,
    /// Extra options the export run needs.
    ///
    /// A decrypted-TLS fixture needs its key log; plain captures pass an
    /// empty slice.
    pub prefs: &'static [&'static str],
}

/// Key log for the TLS export case.
const TLS12_GCM_LARGE_KEYLOG: &[&str] = &[
    "-o",
    "tls.keylog_file:tests/fixtures/tls12-gcm-large-keys.log",
];

/// Export cases whose expected manifests are stored under `tests/golden/`.
pub const CASES: &[ExportCase] = &[
    ExportCase {
        fixture: "http-objects",
        id: "http",
        protocol: "http",
        prefs: &[],
    },
    ExportCase {
        fixture: "http-objects-split",
        id: "http",
        protocol: "http",
        prefs: &[],
    },
    ExportCase {
        fixture: "http-objects-fin-edge",
        id: "http",
        protocol: "http",
        prefs: &[],
    },
    ExportCase {
        fixture: "http-objects-large",
        id: "http",
        protocol: "http",
        prefs: &[],
    },
    ExportCase {
        fixture: "tls12-gcm-large",
        id: "http",
        protocol: "http",
        prefs: TLS12_GCM_LARGE_KEYLOG,
    },
];

/// Path of the stored manifest for one case.
pub fn manifest_path(fixture: &str, id: &str) -> PathBuf {
    golden::golden_dir()
        .join(fixture)
        .join(format!("export-{id}.manifest"))
}

/// Path of the stored manifest for one registered case.
pub fn case_manifest_path(case: &ExportCase) -> PathBuf {
    manifest_path(case.fixture, case.id)
}

/// Build the canonical manifest text for a directory.
///
/// Every entry must be a regular file; a symlink, directory or unreadable
/// name is an error rather than silently omitted. Lines are sorted by name.
pub fn directory_manifest(directory: &Path) -> Result<String, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    let mut lines = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read an entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "unexpected non-file export entry {}",
                path.display()
            ));
        }
        let name = entry
            .file_name()
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| format!("export name is not UTF-8: {}", path.display()))?;
        if name.contains('\t') || name.contains('\n') {
            return Err(format!("export name contains a separator: {name:?}"));
        }
        let bytes =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let digest = Sha256::digest(&bytes);
        let mut sha256 = String::with_capacity(64);
        for byte in digest {
            sha256.push(hex_digit(byte >> 4));
            sha256.push(hex_digit(byte & 0x0f));
        }
        lines.push(format!("{sha256}\t{}\t{name}", bytes.len()));
    }
    lines.sort();
    let mut manifest = lines.join("\n");
    if !manifest.is_empty() {
        manifest.push('\n');
    }
    Ok(manifest)
}

/// Store a manifest for `directory`, reporting whether it changed.
pub fn store_manifest(directory: &Path, case: &ExportCase) -> Result<bool, String> {
    let manifest = directory_manifest(directory)?;
    let path = case_manifest_path(case);
    if fs::read(&path).is_ok_and(|stored| stored == manifest.as_bytes()) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::write(&path, manifest)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(true)
}

fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0'.saturating_add(nibble)
    } else {
        b'a'.saturating_add(nibble.saturating_sub(10))
    })
}

/// Compare a directory with the stored manifest for one case.
pub fn compare_manifest(directory: &Path, case: &ExportCase) -> Result<(), String> {
    let actual = directory_manifest(directory)?;
    let path = case_manifest_path(case);
    let expected = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if actual == expected {
        return Ok(());
    }
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    for (index, (expected, actual)) in expected_lines.iter().zip(&actual_lines).enumerate() {
        if expected != actual {
            return Err(format!(
                "{}/{}: line {} differs\nexpected: {expected}\nobserved: {actual}",
                case.fixture,
                case.id,
                index.saturating_add(1)
            ));
        }
    }
    if expected_lines.len() != actual_lines.len() {
        return Err(format!(
            "{}/{}: {} entries expected, {} observed",
            case.fixture,
            case.id,
            expected_lines.len(),
            actual_lines.len()
        ));
    }
    Err(format!("{}/{}: manifest differs", case.fixture, case.id))
}
