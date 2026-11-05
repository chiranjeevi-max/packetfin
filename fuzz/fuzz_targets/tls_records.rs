#![no_main]

//! Fuzz TLS 1.2/1.3 record protection with arbitrary secrets and records.
//!
//! One selector byte chooses a suite; the next bytes split into key material,
//! a five-byte header and the record fragment. Both the TLS 1.3 AEAD path and
//! the TLS 1.2 AEAD/CBC paths run, including Encrypt-then-MAC and arbitrary
//! sequence numbers.

use libfuzzer_sys::fuzz_target;
use packetfin_core::fuzz_support::{decrypt_tls12, decrypt_tls13};

const SUITES: [u16; 10] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030, 0xcca8, 0xc009, 0xc014, 0xc027,
];

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let suite = SUITES[usize::from(*selector) % SUITES.len()];
    let split = rest.len().min(64);
    let (secret, rest) = rest.split_at(split);
    let header_split = rest.len().min(5);
    let (header_bytes, fragment) = rest.split_at(header_split);
    let mut header = [0_u8; 5];
    header[..header_bytes.len()].copy_from_slice(header_bytes);

    let _ = decrypt_tls13(suite, secret, u64::from(*selector), header, fragment);

    let mut client_random = [0_u8; 32];
    client_random[0] = *selector;
    let mut server_random = [0_u8; 32];
    server_random[0] = selector.wrapping_add(1);
    let content_type = header[0];
    let sequence = u64::from(*selector) << 8;
    let _ = decrypt_tls12(
        suite,
        secret,
        client_random,
        server_random,
        *selector & 1 == 1,
        *selector & 2 == 0,
        content_type,
        0x0303,
        sequence,
        fragment,
    );
});
