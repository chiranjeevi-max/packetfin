# Registry provenance

Packetfin's MAC and service-name tables are generated from the authoritative
registries below by `tools/gen-names`. The generated Rust files record the same
facts in their headers. Do not hand-edit them.

## IEEE MA-L (OUI)

- Source: https://standards-oui.ieee.org/oui/oui.csv
- Retrieved: 2026-11-04
- Source SHA-256: `e8b6a42ff78ce6d28173513dbefb2620c50ff73780ae74b25472f89e6ec66b7a`
- Entries used: 40439
- License: IEEE's public MA-L listing. Only the factual 24-bit
assignment and organization-name mapping is retained; the source CSV is
not committed. See the source URL for IEEE's terms; this project does not
reproduce a separate IEEE copyright notice.

## IANA Service Name and Transport Protocol Port Number Registry

- Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
- Retrieved: 2026-11-04
- Source SHA-256: `8e21243f3c2b45039e7bcd97b16e7564d96a7330da64432f5f62f622a91ef95c`
- Entries used: 5890 TCP, 5503 UDP
- License: IANA and IETF dedicate the protocol registries to the public
domain under CC0 1.0 (Joint Statement, 2021-11-10).

## Short MAC labels

Wire registries carry organization names only. Packetfin derives the short
label shown in `Source (resolved)` by taking the first whitespace-delimited
token of the organization name before the first comma. This is Packetfin's
derivation, not a registry value.
