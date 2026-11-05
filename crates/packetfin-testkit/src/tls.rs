#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "deterministic fixture writer: sizes are fixed constants and a failure is a programming error in test tooling"
)]

//! Deterministic TLS handshake and record writer for fixtures.
//!
//! The fixtures need standard records that Packetfin can decrypt from a
//! key-log file. The writer therefore follows RFC 5246/8446 record
//! protection literally: fixed client/server randoms and secrets, a selected
//! cipher suite, and one sequence counter per direction and epoch. It is a
//! test-vector generator, not a TLS implementation: there is no key exchange,
//! certificate or Finished verification.
//!
//! Aes-gcm, ChaCha20-Poly1305, AES-CBC and HMAC come from RustCrypto. The
//! published RFC/NIST vectors that pin those primitives live in
//! `packetfin-core`'s cipher tests; the expected output stored for these
//! fixtures is the independent protocol check.

use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};

/// TLS 1.2 record header version.
pub const TLS12_VERSION: u16 = 0x0303;

/// TLS 1.3 record header version (the legacy version field).
pub const TLS13_VERSION: u16 = 0x0303;

/// SHA-256("HelloRetryRequest") magic that an HRR uses as its random.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Content types.
pub const HANDSHAKE: u8 = 22;
/// Alert record.
pub const ALERT: u8 = 21;
/// Change Cipher Spec.
pub const CHANGE_CIPHER_SPEC: u8 = 20;
/// Application data.
pub const APPLICATION_DATA: u8 = 23;

/// Hash used by a fixture suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
}

impl Hash {
    fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bulk {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20,
    Aes128Cbc,
    Aes256Cbc,
}

#[derive(Clone, Copy, Debug)]
struct Suite {
    bulk: Bulk,
    prf: Hash,
    mac: Hash,
}

fn suite(id: u16) -> Option<Suite> {
    let (bulk, prf, mac) = match id {
        0x1301 => (Bulk::Aes128Gcm, Hash::Sha256, Hash::Sha256),
        0x1302 => (Bulk::Aes256Gcm, Hash::Sha384, Hash::Sha384),
        0x1303 => (Bulk::ChaCha20, Hash::Sha256, Hash::Sha256),
        0xc02b | 0xc02f => (Bulk::Aes128Gcm, Hash::Sha256, Hash::Sha256),
        0xc02c | 0xc030 => (Bulk::Aes256Gcm, Hash::Sha384, Hash::Sha384),
        0xcca8 => (Bulk::ChaCha20, Hash::Sha256, Hash::Sha256),
        0x009c | 0x009e => (Bulk::Aes128Gcm, Hash::Sha256, Hash::Sha256),
        0x009d | 0x009f => (Bulk::Aes256Gcm, Hash::Sha384, Hash::Sha384),
        0xc013 | 0x002f => (Bulk::Aes128Cbc, Hash::Sha256, Hash::Sha1),
        0xc014 | 0x0035 => (Bulk::Aes256Cbc, Hash::Sha256, Hash::Sha1),
        0xc027 | 0x003c => (Bulk::Aes128Cbc, Hash::Sha256, Hash::Sha256),
        0xc028 | 0x003d => (Bulk::Aes256Cbc, Hash::Sha384, Hash::Sha384),
        _ => return None,
    };
    Some(Suite { bulk, prf, mac })
}

impl Suite {
    fn key_len(self) -> usize {
        match self.bulk {
            Bulk::Aes128Gcm | Bulk::Aes128Cbc => 16,
            Bulk::Aes256Gcm | Bulk::Aes256Cbc | Bulk::ChaCha20 => 32,
        }
    }

    fn fixed_iv_len(self) -> usize {
        match self.bulk {
            Bulk::Aes128Gcm | Bulk::Aes256Gcm => 4,
            Bulk::ChaCha20 => 12,
            Bulk::Aes128Cbc | Bulk::Aes256Cbc => 0,
        }
    }

    fn is_cbc(self) -> bool {
        matches!(self.bulk, Bulk::Aes128Cbc | Bulk::Aes256Cbc)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    text
}

fn hmac(hash: Hash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    match hash {
        Hash::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        }
        Hash::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        }
        Hash::Sha384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn prf(hash: Hash, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);
    let mut a = hmac(hash, secret, &[&label_seed]);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let block = hmac(hash, secret, &[&a, &label_seed]);
        out.extend_from_slice(&block);
        a = hmac(hash, secret, &[&a]);
    }
    out.truncate(len);
    out
}

fn hkdf_expand_label(
    hash: Hash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full_label = format!("tls13 {}", String::from_utf8_lossy(label));
    let mut info = Vec::new();
    info.extend_from_slice(&u16::try_from(len).expect("length").to_be_bytes());
    info.push(u8::try_from(full_label.len()).expect("label"));
    info.extend_from_slice(full_label.as_bytes());
    info.push(u8::try_from(context.len()).expect("context"));
    info.extend_from_slice(context);
    let mut out = vec![0_u8; len];
    match hash {
        Hash::Sha1 => panic!("TLS 1.3 has no SHA-1 suite"),
        Hash::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .expect("prk")
            .expand(&info, &mut out)
            .expect("expand"),
        Hash::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .expect("prk")
            .expand(&info, &mut out)
            .expect("expand"),
    }
    out
}

fn xor_sequence(iv: &[u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (slot, byte) in nonce.iter_mut().skip(4).zip(sequence.to_be_bytes()) {
        *slot ^= byte;
    }
    nonce
}

/// A plaintext TLS record.
pub fn plain_record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(body.len())
            .expect("record length")
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

/// A handshake message.
pub fn handshake(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![message_type];
    out.extend_from_slice(&[0, 0, 0]);
    out[1..4].copy_from_slice(
        &u32::try_from(body.len())
            .expect("handshake length")
            .to_be_bytes()[1..],
    );
    out.extend_from_slice(body);
    out
}

/// One hello extension.
pub fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(
        &u16::try_from(body.len())
            .expect("extension length")
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

fn extensions(list: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (kind, value) in list {
        body.extend_from_slice(&extension(*kind, value));
    }
    let mut out = u16::try_from(body.len())
        .expect("extension vector")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&body);
    out
}

/// A ClientHello handshake message.
pub fn client_hello(
    random: [u8; 32],
    session_id: &[u8],
    ciphers: &[u16],
    list: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut body = TLS12_VERSION.to_be_bytes().to_vec();
    body.extend_from_slice(&random);
    body.push(u8::try_from(session_id.len()).expect("session id"));
    body.extend_from_slice(session_id);
    body.extend_from_slice(
        &u16::try_from(ciphers.len().saturating_mul(2))
            .expect("cipher vector")
            .to_be_bytes(),
    );
    for cipher in ciphers {
        body.extend_from_slice(&cipher.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&extensions(list));
    handshake(1, &body)
}

/// A ServerHello handshake message.
pub fn server_hello(
    random: [u8; 32],
    session_id: &[u8],
    cipher: u16,
    list: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut body = TLS12_VERSION.to_be_bytes().to_vec();
    body.extend_from_slice(&random);
    body.push(u8::try_from(session_id.len()).expect("session id"));
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&extensions(list));
    handshake(2, &body)
}

/// A TLS 1.2 record protector.
pub struct Tls12Writer {
    suite: Suite,
    suite_id: u16,
    encrypt_then_mac: bool,
    client_random: [u8; 32],
    server_random: [u8; 32],
    master: [u8; 48],
    client_key: Vec<u8>,
    client_mac: Vec<u8>,
    client_iv: [u8; 12],
    server_key: Vec<u8>,
    server_mac: Vec<u8>,
    server_iv: [u8; 12],
    client_sequence: u64,
    server_sequence: u64,
}

impl Tls12Writer {
    /// Create a writer with deterministic randoms and master secret.
    pub fn new(suite_id: u16, encrypt_then_mac: bool) -> Self {
        Self::with_material(
            suite_id,
            encrypt_then_mac,
            [0x11_u8; 32],
            [0x22_u8; 32],
            [0x33_u8; 48],
        )
    }

    /// Create a writer for a resumed session using an existing master secret.
    pub fn resumed(
        suite_id: u16,
        encrypt_then_mac: bool,
        client_random: [u8; 32],
        server_random: [u8; 32],
        master: [u8; 48],
    ) -> Self {
        Self::with_material(
            suite_id,
            encrypt_then_mac,
            client_random,
            server_random,
            master,
        )
    }

    fn with_material(
        suite_id: u16,
        encrypt_then_mac: bool,
        client_random: [u8; 32],
        server_random: [u8; 32],
        master: [u8; 48],
    ) -> Self {
        let suite = suite(suite_id).expect("supported TLS 1.2 suite");
        assert!(!matches!(suite_id, 0x1301..=0x1303));
        let mac_len = if suite.is_cbc() { suite.mac.len() } else { 0 };
        let total = mac_len
            .saturating_mul(2)
            .saturating_add(suite.key_len().saturating_mul(2))
            .saturating_add(suite.fixed_iv_len().saturating_mul(2));
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&server_random);
        seed.extend_from_slice(&client_random);
        let block = prf(suite.prf, &master, b"key expansion", &seed, total);
        let mut offset = 0_usize;
        let mut take = |length: usize| {
            let slice = block[offset..offset + length].to_vec();
            offset += length;
            slice
        };
        let client_mac = if mac_len > 0 {
            take(mac_len)
        } else {
            Vec::new()
        };
        let server_mac = if mac_len > 0 {
            take(mac_len)
        } else {
            Vec::new()
        };
        let client_key = take(suite.key_len());
        let server_key = take(suite.key_len());
        let mut client_iv = [0_u8; 12];
        let mut server_iv = [0_u8; 12];
        if suite.fixed_iv_len() > 0 {
            client_iv[..suite.fixed_iv_len()].copy_from_slice(&take(suite.fixed_iv_len()));
            server_iv[..suite.fixed_iv_len()].copy_from_slice(&take(suite.fixed_iv_len()));
        }
        Self {
            suite,
            suite_id,
            encrypt_then_mac,
            client_random,
            server_random,
            master,
            client_key,
            client_mac,
            client_iv,
            server_key,
            server_mac,
            server_iv,
            client_sequence: 0,
            server_sequence: 0,
        }
    }

    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    pub fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    pub fn server_random(&self) -> [u8; 32] {
        self.server_random
    }

    /// The `CLIENT_RANDOM` key-log line for this session.
    pub fn keylog(&self) -> String {
        format!(
            "CLIENT_RANDOM {} {}\n",
            hex(&self.client_random),
            hex(&self.master)
        )
    }

    /// Protect one record.
    pub fn record(&mut self, from_client: bool, content_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let sequence = if from_client {
            self.client_sequence
        } else {
            self.server_sequence
        };
        let mut header = vec![content_type];
        header.extend_from_slice(&TLS12_VERSION.to_be_bytes());
        let fragment = if self.suite.is_cbc() {
            self.cbc_record(from_client, sequence, content_type, plaintext)
        } else {
            self.aead_record(from_client, sequence, content_type, plaintext)
        };
        header.extend_from_slice(&u16::try_from(fragment.len()).expect("record").to_be_bytes());
        header.extend_from_slice(&fragment);
        if from_client {
            self.client_sequence = self.client_sequence.saturating_add(1);
        } else {
            self.server_sequence = self.server_sequence.saturating_add(1);
        }
        header
    }

    fn aead_record(
        &self,
        from_client: bool,
        sequence: u64,
        content_type: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let (key, iv) = if from_client {
            (self.client_key.as_slice(), self.client_iv)
        } else {
            (self.server_key.as_slice(), self.server_iv)
        };
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad.push(content_type);
        aad.extend_from_slice(&TLS12_VERSION.to_be_bytes());
        aad.extend_from_slice(
            &u16::try_from(plaintext.len())
                .expect("plaintext")
                .to_be_bytes(),
        );
        match self.suite.bulk {
            Bulk::Aes128Gcm | Bulk::Aes256Gcm => {
                let mut nonce = iv;
                let explicit = sequence.to_be_bytes();
                nonce[4..].copy_from_slice(&explicit);
                let mut fragment = explicit.to_vec();
                let start = fragment.len();
                fragment.extend_from_slice(plaintext);
                let tag = if self.suite.bulk == Bulk::Aes128Gcm {
                    let cipher = Aes128Gcm::new_from_slice(key).expect("key");
                    cipher
                        .encrypt_in_place_detached(
                            nonce.as_ref().into(),
                            &aad,
                            &mut fragment[start..],
                        )
                        .expect("encrypt")
                } else {
                    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
                    cipher
                        .encrypt_in_place_detached(
                            nonce.as_ref().into(),
                            &aad,
                            &mut fragment[start..],
                        )
                        .expect("encrypt")
                };
                fragment.extend_from_slice(&tag);
                fragment
            }
            Bulk::ChaCha20 => {
                let nonce = xor_sequence(&iv, sequence);
                let mut fragment = plaintext.to_vec();
                let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key");
                let tag = cipher
                    .encrypt_in_place_detached(nonce.as_ref().into(), &aad, &mut fragment)
                    .expect("encrypt");
                fragment.extend_from_slice(&tag);
                fragment
            }
            _ => unreachable!("AEAD only"),
        }
    }

    fn cbc_record(
        &self,
        from_client: bool,
        sequence: u64,
        content_type: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let (key, mac) = if from_client {
            (self.client_key.as_slice(), self.client_mac.as_slice())
        } else {
            (self.server_key.as_slice(), self.server_mac.as_slice())
        };
        let mut iv = [0_u8; 16];
        for (index, byte) in iv.iter_mut().enumerate() {
            *byte = u8::try_from((sequence as usize).wrapping_add(index)).expect("iv");
        }
        let mut content = plaintext.to_vec();
        if !self.encrypt_then_mac {
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&sequence.to_be_bytes());
            aad.push(content_type);
            aad.extend_from_slice(&TLS12_VERSION.to_be_bytes());
            aad.extend_from_slice(
                &u16::try_from(plaintext.len())
                    .expect("plaintext")
                    .to_be_bytes(),
            );
            let tag = hmac(self.suite.mac, mac, &[&aad, plaintext]);
            content.extend_from_slice(&tag);
        }
        let padding_length = 15 - (content.len() % 16);
        content.extend(std::iter::repeat_n(
            u8::try_from(padding_length).expect("padding"),
            padding_length + 1,
        ));
        let mut buffer = content;
        let length = buffer.len();
        let ciphertext = if self.suite.bulk == Bulk::Aes128Cbc {
            let cipher = cbc::Encryptor::<Aes128>::new_from_slices(key, &iv).expect("cipher");
            cipher
                .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer, length)
                .expect("encrypt")
                .to_vec()
        } else {
            let cipher = cbc::Encryptor::<Aes256>::new_from_slices(key, &iv).expect("cipher");
            cipher
                .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer, length)
                .expect("encrypt")
                .to_vec()
        };
        let mut fragment = iv.to_vec();
        fragment.extend_from_slice(&ciphertext);
        if self.encrypt_then_mac {
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&sequence.to_be_bytes());
            aad.push(content_type);
            aad.extend_from_slice(&TLS12_VERSION.to_be_bytes());
            aad.extend_from_slice(
                &u16::try_from(fragment.len())
                    .expect("fragment")
                    .to_be_bytes(),
            );
            let tag = hmac(self.suite.mac, mac, &[&aad, &fragment]);
            fragment.extend_from_slice(&tag);
        }
        fragment
    }
}

/// TLS 1.3 record epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Epoch {
    /// 0-RTT client data.
    Early,
    /// Encrypted handshake.
    Handshake,
    /// Application data.
    Application,
}

struct DirectionKeys {
    secret: Vec<u8>,
    key: Vec<u8>,
    iv: [u8; 12],
    sequence: u64,
}

/// A TLS 1.3 record protector with deterministic secrets.
pub struct Tls13Writer {
    suite: Suite,
    suite_id: u16,
    client_random: [u8; 32],
    server_random: [u8; 32],
    early_secret: Option<Vec<u8>>,
    early_exporter: Option<Vec<u8>>,
    early_sequence: u64,
    exporter: Vec<u8>,
    client_hs: DirectionKeys,
    server_hs: DirectionKeys,
    client_app: DirectionKeys,
    server_app: DirectionKeys,
}

impl Tls13Writer {
    pub fn new(suite_id: u16) -> Self {
        let suite = suite(suite_id).expect("TLS 1.3 suite");
        assert!(matches!(suite_id, 0x1301..=0x1303));
        let client_random = [0x44_u8; 32];
        let server_random = [0x55_u8; 32];
        let hash_len = suite.prf.len();
        let make = |seed: u8, seq: u64| DirectionKeys {
            secret: vec![seed; hash_len],
            key: Vec::new(),
            iv: [0_u8; 12],
            sequence: seq,
        };
        let mut client_hs = make(0x61, 0);
        let mut server_hs = make(0x62, 0);
        let mut client_app = make(0x63, 0);
        let mut server_app = make(0x64, 0);
        for keys in [
            &mut client_hs,
            &mut server_hs,
            &mut client_app,
            &mut server_app,
        ] {
            keys.key = hkdf_expand_label(suite.prf, &keys.secret, b"key", &[], suite.key_len());
            keys.iv = hkdf_expand_label(suite.prf, &keys.secret, b"iv", &[], 12)
                .try_into()
                .expect("iv");
        }
        Self {
            suite,
            suite_id,
            client_random,
            server_random,
            early_secret: None,
            early_exporter: None,
            early_sequence: 0,
            exporter: vec![0x65; hash_len],
            client_hs,
            server_hs,
            client_app,
            server_app,
        }
    }

    pub fn suite_id(&self) -> u16 {
        self.suite_id
    }

    pub fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    pub fn server_random(&self) -> [u8; 32] {
        self.server_random
    }

    /// Add 0-RTT secrets; the early record epoch becomes available.
    pub fn with_early(&mut self) {
        let hash_len = self.suite.prf.len();
        self.early_secret = Some(vec![0x60; hash_len]);
        self.early_exporter = Some(vec![0x66; hash_len]);
    }

    /// Whether 0-RTT secrets were configured.
    pub fn has_early(&self) -> bool {
        self.early_secret.is_some()
    }

    /// The key-log text for this session, one line per secret in a fixed order.
    pub fn keylog(&self) -> String {
        let mut text = String::new();
        let mut line = |label: &str, secret: &[u8]| {
            text.push_str(label);
            text.push(' ');
            text.push_str(&hex(&self.client_random));
            text.push(' ');
            text.push_str(&hex(secret));
            text.push('\n');
        };
        if let Some(secret) = &self.early_secret {
            line("CLIENT_EARLY_TRAFFIC_SECRET", secret);
        }
        line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &self.client_hs.secret);
        line("SERVER_HANDSHAKE_TRAFFIC_SECRET", &self.server_hs.secret);
        line("SERVER_TRAFFIC_SECRET_0", &self.server_app.secret);
        line("CLIENT_TRAFFIC_SECRET_0", &self.client_app.secret);
        if let Some(secret) = &self.early_exporter {
            line("EARLY_EXPORTER_SECRET", secret);
        }
        line("EXPORTER_SECRET", &self.exporter);
        text
    }

    /// Protect one record in one epoch.
    pub fn record(
        &mut self,
        from_client: bool,
        epoch: Epoch,
        content_type: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let keys = match (from_client, epoch) {
            (true, Epoch::Early) => {
                // Derive a temporary early key from the early secret. Early
                // records share one sequence counter until EndOfEarlyData.
                let secret = self.early_secret.as_ref().expect("early secret");
                let mut keys = DirectionKeys {
                    secret: secret.clone(),
                    key: hkdf_expand_label(
                        self.suite.prf,
                        secret,
                        b"key",
                        &[],
                        self.suite.key_len(),
                    ),
                    iv: hkdf_expand_label(self.suite.prf, secret, b"iv", &[], 12)
                        .try_into()
                        .expect("iv"),
                    sequence: self.early_sequence,
                };
                let record = Self::protected_record(self.suite, &mut keys, content_type, plaintext);
                self.early_sequence = self.early_sequence.saturating_add(1);
                return record;
            }
            (true, Epoch::Handshake) => &mut self.client_hs,
            (false, Epoch::Handshake) => &mut self.server_hs,
            (true, Epoch::Application) => &mut self.client_app,
            (false, Epoch::Application) => &mut self.server_app,
            (false, Epoch::Early) => panic!("no server early keys"),
        };
        Self::protected_record(self.suite, keys, content_type, plaintext)
    }

    fn protected_record(
        suite: Suite,
        keys: &mut DirectionKeys,
        content_type: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut content = plaintext.to_vec();
        content.push(content_type);
        let ciphertext_len = content.len().saturating_add(16);
        let mut header = vec![APPLICATION_DATA];
        header.extend_from_slice(&TLS13_VERSION.to_be_bytes());
        header.extend_from_slice(&u16::try_from(ciphertext_len).expect("record").to_be_bytes());
        let nonce = xor_sequence(&keys.iv, keys.sequence);
        let mut fragment = content;
        let tag = match suite.bulk {
            Bulk::Aes128Gcm => Aes128Gcm::new_from_slice(&keys.key)
                .expect("key")
                .encrypt_in_place_detached(nonce.as_ref().into(), &header, &mut fragment)
                .expect("encrypt"),
            Bulk::Aes256Gcm => Aes256Gcm::new_from_slice(&keys.key)
                .expect("key")
                .encrypt_in_place_detached(nonce.as_ref().into(), &header, &mut fragment)
                .expect("encrypt"),
            Bulk::ChaCha20 => ChaCha20Poly1305::new_from_slice(&keys.key)
                .expect("key")
                .encrypt_in_place_detached(nonce.as_ref().into(), &header, &mut fragment)
                .expect("encrypt"),
            _ => unreachable!("TLS 1.3 AEAD"),
        };
        fragment.extend_from_slice(&tag);
        header.extend_from_slice(&fragment);
        keys.sequence = keys.sequence.saturating_add(1);
        header
    }

    /// Advance one application direction after a KeyUpdate handshake.
    pub fn key_update(&mut self, from_client: bool) {
        let keys = if from_client {
            &mut self.client_app
        } else {
            &mut self.server_app
        };
        let hash_len = self.suite.prf.len();
        let next = hkdf_expand_label(self.suite.prf, &keys.secret, b"traffic upd", &[], hash_len);
        keys.secret = next;
        keys.key = hkdf_expand_label(
            self.suite.prf,
            &keys.secret,
            b"key",
            &[],
            self.suite.key_len(),
        );
        keys.iv = hkdf_expand_label(self.suite.prf, &keys.secret, b"iv", &[], 12)
            .try_into()
            .expect("iv");
        keys.sequence = 0;
    }
}
