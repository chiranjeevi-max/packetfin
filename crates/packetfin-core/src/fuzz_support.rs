//! Low-level decryption entry points used by `cargo fuzz` targets.
//!
//! These functions are compiled only with the `fuzzing` feature. They expose
//! the same record protection path the dissector uses, with caller-supplied
//! secrets and arbitrary record bytes, so a fuzzer can reach authenticated
//! decryption without first constructing a handshake.

use crate::decode::tls::cipher::{self, RecordKeys};
use crate::decode::tls::keylog::Secret;

/// Decrypt a TLS 1.3 record with arbitrary key material.
pub fn decrypt_tls13(
    suite_id: u16,
    secret: &[u8],
    sequence: u64,
    header: [u8; 5],
    fragment: &[u8],
) -> Option<Vec<u8>> {
    let suite = cipher::suite(suite_id)?;
    if !suite.is_tls13() {
        return None;
    }
    let secret = Secret::new(secret)?;
    let mut keys = RecordKeys::tls13(secret, suite)?;
    keys.set_sequence(sequence);
    keys.open_tls13(&header, fragment)
        .map(|record| record.content)
}

/// Decrypt a TLS 1.2 record with arbitrary master secret and record bytes.
pub fn decrypt_tls12(
    suite_id: u16,
    master: &[u8],
    client_random: [u8; 32],
    server_random: [u8; 32],
    encrypt_then_mac: bool,
    from_client: bool,
    content_type: u8,
    version: u16,
    sequence: u64,
    fragment: &[u8],
) -> Option<Vec<u8>> {
    let suite = cipher::suite(suite_id)?;
    if suite.is_tls13() {
        return None;
    }
    let block = cipher::derive_tls12_key_block(master, &client_random, &server_random, suite)?;
    let (key, iv, mac) = if from_client {
        (block.client_key, block.client_iv, block.client_mac)
    } else {
        (block.server_key, block.server_iv, block.server_mac)
    };
    let mut keys = RecordKeys::tls12(key, iv, mac, suite, encrypt_then_mac);
    keys.set_sequence(sequence);
    keys.open_tls12(content_type, version, fragment)
        .map(|record| record.content)
}
