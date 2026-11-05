# Security policy

Packetfin reads untrusted input, so a crash, a hang or runaway memory use on a crafted capture counts as a security bug.

## Report a vulnerability

Report it privately through GitHub: open the [new advisory form](https://github.com/chiranjeevi-max/packetfin/security/advisories/new), or go to the repository's **Security** tab and choose **Report a vulnerability**. Please don't open a public issue.

Include:

- the version (`packetfin -v`) or the commit you built
- your operating system
- the exact command you ran
- an input that reproduces the problem, with anything private removed
- what you expected and what happened

## What to expect

Packetfin has one maintainer, so responses are best effort. You should hear back within seven days. When a fix is ready, a security advisory is published with credit to you, unless you'd rather stay anonymous.

## Supported versions

Packetfin is in early development. Fixes land on the `main` branch; there are no maintained release branches yet.

## Scope

In scope, for example:

- a crash, panic or hang while reading a capture or live traffic
- memory use beyond the configured budgets
- reading or writing files outside the intended paths, such as during `--export-objects`
- mishandled TLS key material

Out of scope: problems that need an attacker who can already change Packetfin's command line or local files.
