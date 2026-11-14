#![no_main]

//! Fuzz TLS 1.0/1.1/1.2/1.3 record protection with arbitrary secrets.
//!
//! Input layout: a suite selector, a protocol selector, a secret length, the
//! secret, the client and server randoms, a five-octet record header and the
//! record fragment. In the protocol selector the low two bits pick the
//! version the pre-TLS 1.3 path negotiates, bit 2 selects Encrypt-then-MAC
//! (RFC 7366, whose TLS 1.0 MAC input carries no IV) and the high nibble is
//! the record's sequence number. Both directions and both record openers run
//! for every input; each opener rejects a suite or protocol it cannot
//! protect.

use libfuzzer_sys::fuzz_target;
use packetfin_core::fuzz_support::{decrypt_tls12, decrypt_tls13};

const SUITES: [u16; 11] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030, 0xcca8, 0xc009, 0xc013, 0xc014, 0xc027,
];

const VERSIONS: [u16; 4] = [0x0301, 0x0302, 0x0303, 0x0304];

fuzz_target!(|data: &[u8]| {
    let Some((suite_selector, rest)) = data.split_first() else {
        return;
    };
    let Some((protocol_selector, rest)) = rest.split_first() else {
        return;
    };
    let Some((secret_length, rest)) = rest.split_first() else {
        return;
    };
    let Some(suite) = SUITES
        .get(usize::from(*suite_selector) % SUITES.len())
        .copied()
    else {
        return;
    };
    let Some(version) = VERSIONS
        .get(usize::from(*protocol_selector & 0x03))
        .copied()
    else {
        return;
    };
    let encrypt_then_mac = *protocol_selector & 0x04 != 0;
    let sequence = u64::from(*protocol_selector >> 4);

    let (secret, rest) = take(rest, usize::from(*secret_length).min(64));
    let (client_random, rest) = take(rest, 32);
    let (server_random, rest) = take(rest, 32);
    let (header_bytes, fragment) = take(rest, 5);
    let client_random = fixed::<32>(client_random);
    let server_random = fixed::<32>(server_random);
    let header = fixed::<5>(header_bytes);

    let _ = decrypt_tls13(
        suite,
        secret,
        u64::from(*suite_selector),
        header,
        fragment,
    );

    for from_client in [true, false] {
        let _ = decrypt_tls12(
            suite,
            secret,
            client_random,
            server_random,
            encrypt_then_mac,
            from_client,
            header.first().copied().unwrap_or(0),
            version,
            sequence,
            fragment,
        );
    }
});

/// Split off at most `length` bytes.
fn take(data: &[u8], length: usize) -> (&[u8], &[u8]) {
    data.split_at(data.len().min(length))
}

/// Copy at most `N` bytes into a zero-filled array.
fn fixed<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut out = [0_u8; N];
    let length = data.len().min(N);
    if let Some(prefix) = out.get_mut(..length)
        && let Some(source) = data.get(..length)
    {
        prefix.copy_from_slice(source);
    }
    out
}
