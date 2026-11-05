# Packetfin

[![CI](https://github.com/chiranjeevi-max/packetfin/actions/workflows/ci.yml/badge.svg)](https://github.com/chiranjeevi-max/packetfin/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.99](https://img.shields.io/badge/rust-1.99-orange.svg)](rust-toolchain.toml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Packetfin is a command-line packet analyzer written in Rust. It reads capture files or live traffic, decodes 45 protocols, filters packets, and prints summaries, full packet details or structured output such as JSON, CSV and XML.

It is built for captures you don't trust. A malformed or hostile capture should not crash Packetfin, hang it, or make its memory grow without limit.

> **Status:** early development (version 0.1.0). Options and output formats may still change.

## What Packetfin focuses on

- **Standards first.** Decoders follow the published RFCs and IEEE specifications.
- **Safety on untrusted input.** Memory stays within fixed budgets, every parser is fuzzed, and only the live-capture crate uses `unsafe` code.
- **Scripting.** Field extraction, JSON, CSV and XML output fit into scripts and pipelines.
- **Privacy.** No telemetry, no update checks and no network connections of its own. Names come from built-in tables, your hosts files and the capture itself.

## Features

**Input and capture**

- Read pcap and pcapng files, or standard input with `-r -`.
- Read gzip, zstd and lz4 compressed captures. Packetfin detects compression from the file contents, so pipes work too.
- Capture live traffic on macOS and Linux through libpcap. Windows builds use Npcap but haven't been tested on Windows yet.
- Write pcap, pcapng or nanosecond pcap files, optionally compressed with gzip or lz4, with ring buffers (`-b`), autostop conditions (`-a`) and capture comments.

**Protocols**

| Area | Protocols |
| --- | --- |
| Link layer | Ethernet II, 802.3 LLC/SNAP, VLAN (802.1Q), QinQ (802.1ad), Linux cooked capture (SLL, SLL2), BSD loopback, raw IP |
| Network | ARP, IPv4 with options, IPv6 with extension headers, ICMP, ICMPv6 with neighbor discovery |
| Transport | TCP, UDP |
| Tunnels | GRE, ERSPAN types I–III, VXLAN, Geneve, MPLS, IP-in-IP, 6in4 |
| Layer 2 control | LLDP, LACP, Marker, STP, RSTP, MSTP |
| Routing | OSPFv2, OSPFv3, BGP, VRRP, BFD |
| Services | DNS over UDP and TCP, mDNS, LLMNR, DHCP, DHCPv6, NTP, HTTP/1.x, TLS |
| Monitoring | Syslog, SNMP v1 and v2c, NetFlow v5 and v9, IPFIX, sFlow v5 |

Run `packetfin -G protocols` for the full list and `packetfin -G fields` for all 1,493 field names.

**Analysis**

- Reassemble IPv4 and IPv6 fragments, TCP streams, and DNS, HTTP, TLS and BGP messages that span several segments.
- TCP analysis: retransmissions, duplicate ACKs, out-of-order and lost segments, zero windows, keep-alives and round-trip times.
- Expert notes flag malformed packets, protocol errors and unusual behavior.
- Two-pass mode (`-2`) links requests to responses and lets the read filter (`-R`) see the whole capture.
- Decrypt TLS 1.2 and 1.3 with a key log file (the `SSLKEYLOGFILE` format), and compute JA3, JA3S and JA4 fingerprints.
- Export HTTP objects to a folder with `--export-objects http,DIR`.

**Filters**

- Display filters (`-Y`) support comparisons, `and`/`or`/`not`, `contains`, `matches` (regular expressions), sets and ranges with `in`, CIDR blocks, byte slices, arithmetic, field references and functions such as `len()`, `count()` and `lower()`.
- Capture filters (`-f`) use BPF syntax.

**Output**

- One-line summaries, full packet details (`-V`) and hex dumps (`-x`).
- Selected fields (`-T fields -e FIELD`) with your choice of separator, quoting and header row.
- JSON, Elasticsearch bulk format, PDML and PSML XML, PostScript and tab-separated summaries (`-T`).
- Statistics (`-z`): traffic over time (`io,stat`), protocol hierarchy (`io,phs`), conversations and endpoints, expert notes, DNS and HTTP trees, and stream follow for TCP, UDP, TLS and HTTP.

**Memory limits**

Cross-packet state, statistics and two-pass annotations each have a byte budget: 256 MiB, 64 MiB and 64 MiB by default. Change them with `--pf-state-budget`, `--pf-stats-budget` and `--pf-annotation-budget`. When the state budget is full, Packetfin drops the least recently used state and adds an expert note to the packet that needed it.

## Tech stack

- **Language:** Rust, 2024 edition. The toolchain is pinned to 1.99.0 in [`rust-toolchain.toml`](rust-toolchain.toml).
- **Live capture:** libpcap on macOS and Linux and Npcap on Windows, through the [`pcap`](https://crates.io/crates/pcap) crate.
- **TLS:** [RustCrypto](https://github.com/RustCrypto) crates for AES-GCM, AES-CBC, ChaCha20-Poly1305, HKDF, HMAC, SHA-1, SHA-2 and MD5.
- **Compression:** [`flate2`](https://crates.io/crates/flate2) with its pure-Rust backend, [`ruzstd`](https://crates.io/crates/ruzstd) and [`lz4_flex`](https://crates.io/crates/lz4_flex).
- **Filters:** [`regex`](https://crates.io/crates/regex) for the `matches` operator.
- **Testing:** cargo-fuzz with libFuzzer, cargo-deny, Clippy, and Docker for the Linux test run.

Decoding is pure Rust. Only live capture links to a C library.

## Getting started

### Prerequisites

- [Rust](https://rustup.rs), installed through rustup. The first build installs the pinned toolchain.
- A C linker: Xcode Command Line Tools on macOS, `build-essential` on Debian and Ubuntu, or Visual Studio Build Tools on Windows.
- libpcap development files:
  - macOS: included with the system.
  - Debian and Ubuntu: `sudo apt install libpcap-dev`
  - Fedora: `sudo dnf install libpcap-devel`
  - Windows: install [Npcap](https://npcap.com), download the Npcap SDK, and add its `Lib\x64` folder to the `LIB` environment variable.

Reading files needs no special permissions. Live capture does: run Packetfin with `sudo`, or on Linux give the binary the capture capabilities once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/packetfin
```

### Installation

```bash
git clone https://github.com/chiranjeevi-max/packetfin.git
cd packetfin
cargo build --release
```

The binary is `target/release/packetfin`. To install it into `~/.cargo/bin` instead:

```bash
cargo install --path crates/packetfin
```

## Usage

```bash
# One summary line per packet
packetfin -r capture.pcapng

# DNS packets only, with full details
packetfin -r capture.pcapng -Y dns -V

# Selected fields as CSV
packetfin -r capture.pcapng -T fields -E header=y -E separator=, \
  -e frame.number -e ip.src -e ip.dst -e tcp.dstport

# All packets as JSON
packetfin -r capture.pcapng -T json > packets.json

# Capture 100 HTTPS packets on en0 and save them
sudo packetfin -i en0 -f "tcp port 443" -c 100 -w https.pcapng

# Decrypt TLS with a key log file and show the HTTP requests
packetfin -r tls.pcapng -o tls.keylog_file:keys.log -Y http.request

# Conversations and protocol hierarchy
packetfin -r capture.pcapng -q -z conv,tcp -z io,phs

# Follow the first TCP stream as text
packetfin -r capture.pcapng -q -z follow,tcp,ascii,0

# Save HTTP bodies to a folder
packetfin -r capture.pcapng -q --export-objects http,objects/
```

Run `packetfin --help` to see every option.

## Notable techniques

- **One memory budget for all cross-packet state.** Conversations, IP fragments, TCP reassembly buffers and NetFlow/IPFIX templates share one store with a byte limit and a single least-recently-used clock ([`budget.rs`](crates/packetfin-core/src/state/budget.rs)). Each stored value reports the heap memory it owns, so the limit counts real bytes. When the store is full, Packetfin evicts the oldest entries and records an expert note instead of failing.
- **Lints that rule out panics.** Outside the live-capture crate, `unsafe` code is forbidden, and every crate denies slice indexing, `unwrap`, `expect` and `panic!` ([`Cargo.toml`](Cargo.toml)). Each exception must state its reason. Integer overflow checks stay on in release builds. Parsers read bytes through checked accessors, so a short packet becomes a decode error rather than a crash, and 24 fuzz targets in [`fuzz/fuzz_targets`](fuzz/fuzz_targets) exercise them.
- **Test captures generated from code.** No recorded traffic is checked in. Every test capture is built by a function in [`fixtures.rs`](crates/packetfin-testkit/src/fixtures.rs), and each protocol family comes with normal, truncated, malformed and padded variants. The TLS captures are encrypted with real cipher suites and generated keys, and ship with their key log files.

## Project structure

```text
packetfin/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   └── workflows/
├── crates/
│   ├── packetfin/
│   │   ├── src/
│   │   └── tests/
│   │       └── reference/
│   ├── packetfin-core/
│   │   ├── src/
│   │   │   ├── capture/
│   │   │   │   └── write/
│   │   │   ├── decode/
│   │   │   │   ├── cflow/
│   │   │   │   └── tls/
│   │   │   ├── names/
│   │   │   ├── state/
│   │   │   └── stats/
│   │   └── tests/
│   ├── packetfin-pcap/
│   │   ├── examples/
│   │   ├── src/
│   │   └── tests/
│   └── packetfin-testkit/
│       ├── src/
│       │   └── bin/
│       └── tests/
├── data/
│   └── registry/
├── fuzz/
│   ├── corpus/
│   └── fuzz_targets/
├── tests/
│   ├── fixtures/
│   └── golden/
├── tools/
├── AGENTS.md
├── CONTRIBUTING.md
├── Cargo.lock
├── Cargo.toml
├── LICENSE
├── README.md
├── SECURITY.md
├── deny.toml
└── rust-toolchain.toml
```

- [`crates/packetfin`](crates/packetfin): the command-line tool, with option parsing and every output format. [`tests/reference`](crates/packetfin/tests/reference) holds the expected field list.
- [`crates/packetfin-core`](crates/packetfin-core): the decoding library. It does no I/O of its own. [`decode`](crates/packetfin-core/src/decode) has one module per protocol, [`state`](crates/packetfin-core/src/state) keeps cross-packet state under the memory budget, [`stats`](crates/packetfin-core/src/stats) implements `-z`, and [`capture`](crates/packetfin-core/src/capture) reads and writes capture files.
- [`crates/packetfin-pcap`](crates/packetfin-pcap): live capture through libpcap or Npcap, and the only crate that uses `unsafe`.
- [`crates/packetfin-testkit`](crates/packetfin-testkit): builds the test captures and compares Packetfin's output with the expected results.
- [`tests/fixtures`](tests/fixtures) and [`tests/golden`](tests/golden): the generated captures and, for each test case, the expected standard output, standard error and exit status.
- [`fuzz`](fuzz): fuzz targets and their seed inputs.
- [`data/registry`](data/registry): the sources, dates and checksums of the IEEE and IANA data behind the vendor and service-name tables.
- [`tools`](tools): scripts for the full check, the Linux container run, fuzzing, benchmarks, memory limits and stress tests.

## Roadmap

**Next**

- HTTP/2, including HPACK header compression.
- TLS 1.0 and 1.1 decryption.
- Windows: test live capture with Npcap and run the test suite on Windows in CI.
- Prebuilt binaries for macOS, Linux and Windows.
- `packetfin-core` on crates.io, so other Rust programs can decode packets with it.
- More protocols, chosen by how often they show up in real traffic.

**Known gaps**

- Live capture on Windows is untested.
- Detail output for some DHCP, LLDP and OSPF edge cases is incomplete.
- The `matches` operator uses Rust's `regex` crate, so lookaround and backreferences aren't supported.

**Ideas**

- **Terminal UI:** browse the packet list, details and bytes in a terminal, including over SSH.
- **Desktop app:** a graphical interface built on `packetfin-core`.
- **Browser version:** compile the decoder to WebAssembly and open captures in a web page without uploading them.
- **Capture redaction:** replace addresses consistently and strip payloads and secrets, so you can share a capture safely.
- **Columnar export:** write fields to Parquet or Arrow and query captures with DuckDB, Polars or pandas.
- **Capture checks in CI:** fail a pipeline when a filter matches, for example on any TCP retransmission or TLS 1.0 handshake.
- **Plugin decoders:** add decoders for your own protocols as sandboxed WebAssembly modules.
- **Capture diff:** compare two captures field by field.

Ideas aren't commitments. If one would help you, open an issue.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request. In short:

- Sign off each commit with `git commit -s` to agree to the [Developer Certificate of Origin](https://developercertificate.org). A check runs on every pull request.
- Write commit messages as [Conventional Commits](https://www.conventionalcommits.org), for example `fix(dns): reject compression loops`.
- Run `tools/check` before you push. It runs formatting, Clippy, tests, dependency checks and cross-platform builds.
- Add generated test captures and a fuzz target with every new decoder.
- Write decoders from the published specifications. Don't copy code from other packet analyzers.

To report a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

Packetfin is licensed under the [MIT License](LICENSE).

The MAC vendor table comes from the IEEE Registration Authority's public listing, and the service-name table from the IANA registry. [`data/registry/PROVENANCE.md`](data/registry/PROVENANCE.md) records both sources.
