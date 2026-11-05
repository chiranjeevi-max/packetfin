//! Write every registered fixture to a directory.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use packetfin_testkit::fixtures;
use packetfin_testkit::golden;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("gen-fixtures: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let directory = match args.next() {
        Some(path) => PathBuf::from(path),
        None => golden::fixtures_dir(),
    };
    if args.next().is_some() {
        return Err("usage: gen-fixtures [output-directory]".to_string());
    }

    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
    for fixture in fixtures::all() {
        let bytes = fixture.build()?;
        let path = directory.join(fixture.file_name());
        fs::write(&path, &bytes)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        println!("wrote {} ({} bytes)", path.display(), bytes.len());
    }
    Ok(())
}
