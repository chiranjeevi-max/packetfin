# AGENTS.md

Packetfin is a command-line packet analyzer written in Rust. [README.md](README.md) covers the features and layout; [CONTRIBUTING.md](CONTRIBUTING.md) holds the full rules. This file is the short version for coding agents.

## Finish line

Run `tools/check` and get it passing. Report the commands you ran and what they printed.

## Rules

- **Specifications first.** Decode from RFCs, IEEE standards and IANA registries, and cite the section where a comment explains a decision. Write the code, comments and tables yourself; other analyzers' source stays out of this repository.
- **Checked access.** Read bytes with `get()` and checked arithmetic. `unsafe` lives only in `crates/packetfin-pcap`. Clippy denies `unwrap`, `expect`, `panic!` and slice indexing everywhere else; an exception needs `#[expect(lint, reason = "...")]` and maintainer approval.
- **Bounded state.** Keep cross-packet state in the state store under `crates/packetfin-core/src/state`, so the memory budget covers it.
- **Generated fixtures.** Test captures are builders in `crates/packetfin-testkit/src/fixtures.rs`, with normal, truncated, malformed and padded variants. After changing one, run `cargo run -p packetfin-testkit --bin gen-fixtures`.
- **Maintainer-owned expected output.** `tests/golden/` changes only through the maintainers' generator; when a change needs new expected output, say so in the pull request. A new field gets a row in `crates/packetfin/tests/reference/fields.tsv` at its registry position.
- **Fuzzed parsers.** A new parser gets a fuzz target in `fuzz/fuzz_targets/` with seeds in the target's input format, and runs clean for five minutes (`tools/fuzz 5`).
- **Commits.** Follow the commit rules in CONTRIBUTING.md, sign off with `git commit -s`, and check the message with `tools/lint-commit`. Messages describe the change only, with no tool-attribution trailers.
