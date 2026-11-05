# Contributing to Packetfin

Thanks for helping. This guide covers setup, the checks a change must pass, and the rules for commits and pull requests. For anything bigger than a small fix, open an issue first so we can agree on the approach.

## Setup

Install the prerequisites listed in the [README](README.md#prerequisites), then:

```bash
git clone https://github.com/chiranjeevi-max/packetfin.git
cd packetfin
cargo test --workspace
```

## Checks

Run the full check before you open a pull request:

```bash
tools/check
```

It runs `cargo fmt`, Clippy with warnings denied, the workspace tests, `cargo deny`, and build checks for the Linux and Windows targets. CI runs the same steps.

Two more scripts help when you change parsers or memory handling:

- `tools/fuzz [minutes]` runs every fuzz target for the given number of minutes. It needs a nightly toolchain and cargo-fuzz, and prints the install commands if they're missing.
- `tools/checklinux` runs the tests in a Linux container. It needs Docker.

## Code rules

- Write decoders from the published specifications (RFCs, IEEE standards and IANA registries). Where a comment explains a decision, cite the section. Write your own code, comments and tables; don't copy them from other packet analyzers.
- Only `crates/packetfin-pcap` may use `unsafe`. Everywhere else, Clippy denies `unwrap`, `expect`, `panic!` and slice indexing, so read bytes with checked accessors. An exception needs `#[expect(lint, reason = "...")]` and a maintainer's agreement in review.
- Keep state that lives across packets in the state store in `crates/packetfin-core/src/state`, so the memory budget covers it.
- Keep comments short, and use them to explain why the code does something.

## Tests

- Test captures are built by functions in [`fixtures.rs`](crates/packetfin-testkit/src/fixtures.rs); recorded traffic is never committed. Each protocol family needs normal, truncated, malformed and padded frames. After you add or change a builder, write the capture files with:

  ```bash
  cargo run -p packetfin-testkit --bin gen-fixtures
  ```

- The files in `tests/golden/` hold the expected output of each test case and are never edited by hand. If your change needs new or updated expected output, say so in the pull request and a maintainer will regenerate it.
- `crates/packetfin/tests/reference/fields.tsv` is the expected `packetfin -G fields` output. When you add a field, add its row at the same position as in the field registry.
- A new parser needs a fuzz target in `fuzz/fuzz_targets/`, with seed inputs in the target's own input format, and must run for at least five minutes without findings. Every crash becomes a regression test.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org):

```text
<type>(<scope>): <short description>
```

- **Type:** one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci` or `chore`.
- **Scope:** the area you changed, such as `dns`, `tls`, `cli` or `filter`. Leave it out for changes that span the project.
- **Subject:** at most 50 characters, in the imperative mood ("add", not "added" or "adds"), all lowercase, with no period at the end.
- **Body:** only for significant changes. Leave a blank line after the subject, wrap lines at 72 characters, explain why rather than what, and use bullet points for several changes.

For example:

```text
fix(dns): reject compression loops

- a name whose pointer leads back to itself made the decoder walk
  the same labels until it reached the length limit

Signed-off-by: Jane Doe <jane@example.com>
```

`tools/lint-commit FILE` checks a message against these rules, and CI runs it on every pull request. To check each commit as you make it, use it as your `commit-msg` hook:

```bash
ln -s ../../tools/lint-commit .git/hooks/commit-msg
```

## Sign-off

Packetfin uses the [Developer Certificate of Origin](https://developercertificate.org) (DCO). By signing off, you certify that you wrote the change or have the right to submit it under the project's license. Sign off each commit with:

```bash
git commit -s
```

A DCO check runs on every pull request. To sign off commits you already made, run `git rebase --signoff main` and force-push your branch.

## Pull requests

- Keep each pull request to one change, and each commit to one logical step.
- Describe what the change does and why, and link the issue it addresses.
- Make sure CI passes.

## Bug reports

Use the bug report form on the issue tracker. Include the version (`packetfin -v`), your operating system, the exact command and its output. Attach a capture only if it contains nothing private.

For a security issue, follow [SECURITY.md](SECURITY.md) instead.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
