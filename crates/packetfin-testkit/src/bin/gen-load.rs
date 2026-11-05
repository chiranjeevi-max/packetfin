//! Write the large captures used by the memory regression tool.
//!
//! These captures are generated on demand rather than committed: one is
//! 64 MiB of TCP payload and the TLS one is larger still. `tools/memory`
//! invokes this binary when its cache is missing.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use packetfin_testkit::fixtures;

/// Payload bytes in each generated object: the 64 MiB export cap.
const BODY_BYTES: usize = 64 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("gen-load: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let directory = match args.next() {
        Some(path) => PathBuf::from(path),
        None => return Err("usage: gen-load <output-directory>".to_string()),
    };
    if args.next().is_some() {
        return Err("usage: gen-load <output-directory>".to_string());
    }
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;

    let plain = fixtures::build_http_load_capture(BODY_BYTES, false)?;
    write(&directory.join("plain64.pcap"), &plain)?;

    let chunked = fixtures::build_http_load_capture(BODY_BYTES, true)?;
    write(&directory.join("chunked64.pcap"), &chunked)?;

    let (tls, keylog) = fixtures::build_tls_load_capture(BODY_BYTES)?;
    write(&directory.join("tls64.pcap"), &tls)?;
    write(&directory.join("tls64-keys.log"), &keylog)?;
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}
