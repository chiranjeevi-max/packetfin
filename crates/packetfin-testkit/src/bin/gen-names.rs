//! Generate the committed OUI and service-name tables from the IEEE and IANA
//! registries.
//!
//! The generator reads the registries as CSV, keeps only the facts Packetfin
//! needs (24-bit assignments and port/transport/service triples), sorts them
//! and writes Rust source files under `crates/packetfin-core/src/names/`.
//! Every generated file records the source URL, retrieval date, source
//! SHA-256 and license in its header; `data/registry/PROVENANCE.md` carries
//! the same facts for the committed snapshot.
//!
//! Run through `tools/gen-names`, which downloads the registries with `curl`
//! and passes the paths here.

use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";
const SERVICES_URL: &str =
    "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv";

struct Options {
    oui: PathBuf,
    services: PathBuf,
    oui_url: String,
    services_url: String,
    date: String,
    out: PathBuf,
    provenance: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("gen-names: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let Some(options) = parse_args()? else {
        return Ok(());
    };
    let oui = read_oui(&options.oui)?;
    let (tcp, udp) = read_services(&options.services)?;
    let oui_sha = sha256(&options.oui)?;
    let services_sha = sha256(&options.services)?;

    write_oui(
        &options.out.join("oui_data.rs"),
        &oui,
        &options.oui_url,
        &options.date,
        &oui_sha,
    )?;
    write_services(
        &options.out.join("services_data.rs"),
        &tcp,
        &udp,
        &options.services_url,
        &options.date,
        &services_sha,
    )?;
    write_provenance(
        &options,
        oui.len(),
        tcp.len(),
        udp.len(),
        &oui_sha,
        &services_sha,
    )?;
    Ok(())
}

fn parse_args() -> Result<Option<Options>, String> {
    let mut oui = None;
    let mut services = None;
    let mut oui_url = OUI_URL.to_string();
    let mut services_url = SERVICES_URL.to_string();
    let mut date = None;
    let mut out = None;
    let mut provenance = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--oui" => oui = Some(PathBuf::from(next_value(&mut args, "--oui")?)),
            "--services" => {
                services = Some(PathBuf::from(next_value(&mut args, "--services")?));
            }
            "--oui-url" => oui_url = next_value(&mut args, "--oui-url")?,
            "--services-url" => services_url = next_value(&mut args, "--services-url")?,
            "--date" => date = Some(next_value(&mut args, "--date")?),
            "--out" => out = Some(PathBuf::from(next_value(&mut args, "--out")?)),
            "--provenance" => {
                provenance = Some(PathBuf::from(next_value(&mut args, "--provenance")?));
            }
            "-h" | "--help" => {
                println!(
                    "Usage: gen-names --oui FILE --services FILE [--oui-url URL] \
                     [--services-url URL] --date YYYY-MM-DD --out DIR --provenance FILE"
                );
                return Ok(None);
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Some(Options {
        oui: oui.ok_or("--oui is required")?,
        services: services.ok_or("--services is required")?,
        oui_url,
        services_url,
        date: date.ok_or("--date is required")?,
        out: out.ok_or("--out is required")?,
        provenance: provenance.ok_or("--provenance is required")?,
    }))
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{option} needs a value"))
}

/// One MA-L assignment. The table key is the 24-bit prefix.
fn read_oui(path: &Path) -> Result<Vec<(u32, String)>, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut assignments: BTreeMap<u32, String> = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = parse_csv_line(line);
        let Some(assignment) = fields.get(1) else {
            continue;
        };
        let Some(organization) = fields.get(2) else {
            continue;
        };
        if assignment.len() != 6 || !assignment.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(key) = u32::from_str_radix(assignment, 16) else {
            continue;
        };
        let organization = normalize(organization);
        if organization.is_empty() {
            continue;
        }
        assignments.entry(key).or_insert(organization);
    }
    Ok(assignments.into_iter().collect())
}

/// TCP and UDP services, first registry entry per port. IANA lists aliases as
/// separate rows; the first one is the name Packetfin shows.
type PortTable = Vec<(u16, String)>;

fn read_services(path: &Path) -> Result<(PortTable, PortTable), String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut tcp: BTreeMap<u16, String> = BTreeMap::new();
    let mut udp: BTreeMap<u16, String> = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line_number == 0 {
            continue;
        }
        let fields = parse_csv_line(line);
        let (Some(name), Some(port), Some(transport)) =
            (fields.first(), fields.get(1), fields.get(2))
        else {
            continue;
        };
        let name = normalize(name);
        if name.is_empty() {
            continue;
        }
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        match transport.as_str() {
            "tcp" => {
                tcp.entry(port).or_insert(name);
            }
            "udp" => {
                udp.entry(port).or_insert(name);
            }
            _ => {}
        }
    }
    Ok((tcp.into_iter().collect(), udp.into_iter().collect()))
}

/// Parse one CSV record, handling quoted fields and doubled quotes.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted => {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            }
            '"' if field.is_empty() && !quoted => quoted = true,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

/// Registry text is UTF-8 but can carry stray control characters and padding.
fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .collect::<String>()
        .trim()
        .to_string()
}

fn write_oui(
    path: &Path,
    entries: &[(u32, String)],
    url: &str,
    date: &str,
    sha: &str,
) -> Result<(), String> {
    let mut text = String::with_capacity(entries.len().saturating_mul(48));
    text.push_str("// Generated by tools/gen-names; do not edit.\n");
    let _ = writeln!(text, "// Source: {url}");
    let _ = writeln!(text, "// Retrieved: {date}");
    let _ = writeln!(text, "// Source SHA-256: {sha}");
    text.push_str(
        "// License: IEEE OUI public MA-L listing; factual assignment data. See the source URL for IEEE terms.\n",
    );
    let _ = writeln!(text, "// Entries: {}", entries.len());
    text.push_str("static OUI_NAMES: &[(u32, &str)] = &[\n");
    for (key, organization) in entries {
        let _ = writeln!(text, "    (0x{key:06x}, {organization:?}),");
    }
    text.push_str("];\n");
    fs::write(path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn write_services(
    path: &Path,
    tcp: &[(u16, String)],
    udp: &[(u16, String)],
    url: &str,
    date: &str,
    sha: &str,
) -> Result<(), String> {
    let mut text = String::with_capacity((tcp.len() + udp.len()).saturating_mul(48));
    text.push_str("// Generated by tools/gen-names; do not edit.\n");
    let _ = writeln!(text, "// Source: {url}");
    let _ = writeln!(text, "// Retrieved: {date}");
    let _ = writeln!(text, "// Source SHA-256: {sha}");
    text.push_str(
        "// License: CC0 1.0 public-domain dedication (IANA/IETF protocol registries, 2021-11-10).\n",
    );
    let _ = writeln!(
        text,
        "// TCP entries: {}; UDP entries: {}",
        tcp.len(),
        udp.len()
    );
    for (name, entries) in [("TCP_SERVICES", tcp), ("UDP_SERVICES", udp)] {
        let _ = writeln!(text, "static {name}: &[(u16, &str)] = &[");
        for (port, service) in entries {
            let _ = writeln!(text, "    ({port}, {service:?}),");
        }
        text.push_str("];\n");
    }
    fs::write(path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn write_provenance(
    options: &Options,
    oui_entries: usize,
    tcp_entries: usize,
    udp_entries: usize,
    oui_sha: &str,
    services_sha: &str,
) -> Result<(), String> {
    let mut text = String::new();
    text.push_str("# Registry provenance\n\n");
    text.push_str(
        "Packetfin's MAC and service-name tables are generated from the authoritative\n\
         registries below by `tools/gen-names`. The generated Rust files record the same\n\
         facts in their headers. Do not hand-edit them.\n\n",
    );
    text.push_str("## IEEE MA-L (OUI)\n\n");
    let _ = writeln!(text, "- Source: {}", options.oui_url);
    let _ = writeln!(text, "- Retrieved: {}", options.date);
    let _ = writeln!(text, "- Source SHA-256: `{oui_sha}`");
    let _ = writeln!(text, "- Entries used: {oui_entries}");
    text.push_str(
        "- License: IEEE's public MA-L listing. Only the factual 24-bit\n\
         assignment and organization-name mapping is retained; the source CSV is\n\
         not committed. See the source URL for IEEE's terms; this project does not\n\
         reproduce a separate IEEE copyright notice.\n\n",
    );
    text.push_str("## IANA Service Name and Transport Protocol Port Number Registry\n\n");
    let _ = writeln!(text, "- Source: {}", options.services_url);
    let _ = writeln!(text, "- Retrieved: {}", options.date);
    let _ = writeln!(text, "- Source SHA-256: `{services_sha}`");
    let _ = writeln!(text, "- Entries used: {tcp_entries} TCP, {udp_entries} UDP");
    text.push_str(
        "- License: IANA and IETF dedicate the protocol registries to the public\n\
         domain under CC0 1.0 (Joint Statement, 2021-11-10).\n\n",
    );
    text.push_str("## Short MAC labels\n\n");
    text.push_str(
        "Wire registries carry organization names only. Packetfin derives the short\n\
         label shown in `Source (resolved)` by taking the first whitespace-delimited\n\
         token of the organization name before the first comma. This is Packetfin's\n\
         derivation, not a registry value.\n",
    );
    fs::write(&options.provenance, text)
        .map_err(|error| format!("cannot write {}: {error}", options.provenance.display()))
}

/// SHA-256 of a file, using the platform's `sha256sum` or `shasum`.
fn sha256(path: &Path) -> Result<String, String> {
    for (program, arguments) in [
        ("sha256sum", vec!["--"]),
        ("shasum", vec!["-a", "256", "--"]),
    ] {
        let mut command = Command::new(program);
        command.args(arguments).arg(path);
        if let Ok(output) = command.output()
            && output.status.success()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(first) = text.split_whitespace().next() {
                return Ok(first.to_ascii_lowercase());
            }
        }
    }
    Err("no sha256sum or shasum found; cannot record source hashes".to_string())
}
