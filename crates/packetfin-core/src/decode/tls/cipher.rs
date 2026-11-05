//! TLS record protection primitives.
//!
//! The module holds the cipher-suite table, the TLS 1.2 PRF (RFC 5246
//! section 5) and key block, the TLS 1.3 HKDF-Expand-Label/key schedule
//! (RFC 8446 section 7.1), and the two record-protection profiles:
//!
//! * TLS 1.2 AEAD (RFC 5288 AES-GCM, RFC 7905 ChaCha20-Poly1305) with the
//!   sequence-number nonce and the `seq || type || version || length` AAD.
//! * TLS 1.2 CBC with HMAC-then-encrypt (RFC 5246 section 6.2.3.2), an
//!   explicit per-record IV and constant-time tag verification.
//! * TLS 1.3 AEAD (RFC 8446 section 5.2) with the 12-byte IV XOR sequence
//!   nonce, the five-byte record header as AAD, and the inner content type
//!   followed by zero padding.
//!
//! Only the bulk-protection layer is here: key exchange is out of scope
//! because every secret comes from the key log. AES and ChaCha20 primitives,
//! HMAC and HKDF come from RustCrypto crates; the constructions, table and
//! nonce/AAD rules are original and cite the RFCs.
//!
//! Key material is held in [`Secret`], which zeroizes on drop and never
//! implements `Debug` or `Display`. Decryption is authenticated: a failed tag,
//! MAC or padding check returns `None` and the caller keeps the record
//! opaque, so no partial plaintext can escape.

use aes::Aes128;
use aes::Aes256;
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq as _;

use super::keylog::Secret;

/// Longest AES-CBC record fragment plus TLS 1.2 overhead.
const MAX_CBC_FRAGMENT: usize = 18_432;

/// Hash algorithms used by the supported TLS 1.2/1.3 suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HashAlgorithm {
    /// HMAC-SHA-1, used by the older CBC suites.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-384.
    Sha384,
}

impl HashAlgorithm {
    /// Digest output length in bytes.
    pub(crate) const fn len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// The bulk cipher of a TLS 1.2 or 1.3 suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BulkCipher {
    /// AES-128 in GCM mode.
    Aes128Gcm,
    /// AES-256 in GCM mode.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    Chacha20Poly1305,
    /// AES-128 in CBC mode with a separate HMAC.
    Aes128Cbc,
    /// AES-256 in CBC mode with a separate HMAC.
    Aes256Cbc,
}

impl BulkCipher {
    /// Encryption key length.
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes128Cbc => 16,
            Self::Aes256Gcm | Self::Aes256Cbc | Self::Chacha20Poly1305 => 32,
        }
    }

    /// AEAD tag or CBC MAC length.
    const fn tag_len(self, hash: HashAlgorithm) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::Chacha20Poly1305 => 16,
            Self::Aes128Cbc | Self::Aes256Cbc => hash.len(),
        }
    }

    /// Fixed IV bytes carried in the TLS 1.2 key block.
    ///
    /// GCM uses four fixed bytes plus the eight-byte explicit nonce;
    /// ChaCha20-Poly1305 uses a full 12-byte IV; CBC carries none because the
    /// explicit per-record IV replaced it in TLS 1.2.
    const fn fixed_iv_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 4,
            Self::Chacha20Poly1305 => 12,
            Self::Aes128Cbc | Self::Aes256Cbc => 0,
        }
    }

    const fn is_aead(self) -> bool {
        !matches!(self, Self::Aes128Cbc | Self::Aes256Cbc)
    }
}

/// One cipher suite Packetfin can decrypt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Suite {
    /// IANA cipher-suite value.
    pub(crate) id: u16,
    /// Bulk cipher.
    pub(crate) bulk: BulkCipher,
    /// PRF hash (TLS 1.2) or key-schedule hash (TLS 1.3).
    pub(crate) hash: HashAlgorithm,
    /// CBC record MAC hash. AEAD suites ignore it.
    pub(crate) mac_hash: HashAlgorithm,
    /// TLS version the suite belongs to (`0x0303` or `0x0304`).
    pub(crate) version: u16,
}

impl Suite {
    /// Whether the suite is a TLS 1.3 suite.
    pub(crate) const fn is_tls13(self) -> bool {
        self.version == 0x0304
    }
}

/// Look up a cipher suite by its IANA value.
///
/// TLS 1.3 suites are 0x1301-0x1303 (RFC 8446 section 9.1). TLS 1.2 entries
/// cover the AES-GCM suites from RFC 5288, the ChaCha20-Poly1305 suites from
/// RFC 7905, and a set of AES-CBC suites that a key log can decrypt.
pub(crate) fn suite(id: u16) -> Option<Suite> {
    // TLS 1.2 uses SHA-256 for the PRF for every suite except the SHA-384
    // CBC suites (RFC 5246 section 5); the CBC MAC hash is independent and
    // comes from the suite name.
    let (bulk, hash, mac_hash, version) = match id {
        0x1301 => (
            BulkCipher::Aes128Gcm,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha256,
            0x0304,
        ),
        0x1302 => (
            BulkCipher::Aes256Gcm,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha384,
            0x0304,
        ),
        0x1303 => (
            BulkCipher::Chacha20Poly1305,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha256,
            0x0304,
        ),
        0xc02b | 0xc02f | 0x009c | 0x009e => (
            BulkCipher::Aes128Gcm,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha256,
            0x0303,
        ),
        0xc02c | 0xc030 | 0x009d | 0x009f => (
            BulkCipher::Aes256Gcm,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha384,
            0x0303,
        ),
        0xcca8..=0xccaa => (
            BulkCipher::Chacha20Poly1305,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha256,
            0x0303,
        ),
        0xc009 | 0xc013 | 0x002f | 0x0033 => (
            BulkCipher::Aes128Cbc,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha1,
            0x0303,
        ),
        0xc00a | 0xc014 | 0x0035 | 0x0039 => (
            BulkCipher::Aes256Cbc,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha1,
            0x0303,
        ),
        0xc023 | 0xc027 | 0x003c | 0x0067 => (
            BulkCipher::Aes128Cbc,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha256,
            0x0303,
        ),
        0x003d | 0x006b => (
            BulkCipher::Aes256Cbc,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha256,
            0x0303,
        ),
        0xc024 | 0xc028 => (
            BulkCipher::Aes256Cbc,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha384,
            0x0303,
        ),
        _ => return None,
    };
    Some(Suite {
        id,
        bulk,
        hash,
        mac_hash,
        version,
    })
}

/// A TLS 1.2 key block, split by direction.
pub(crate) struct Tls12KeyBlock {
    /// Client write key.
    pub(crate) client_key: Secret,
    /// Server write key.
    pub(crate) server_key: Secret,
    /// Client fixed IV (GCM/ChaCha20); zero for CBC.
    pub(crate) client_iv: [u8; 12],
    /// Server fixed IV (GCM/ChaCha20); zero for CBC.
    pub(crate) server_iv: [u8; 12],
    /// Client write MAC key (CBC only).
    pub(crate) client_mac: Option<Secret>,
    /// Server write MAC key (CBC only).
    pub(crate) server_mac: Option<Secret>,
}

/// Record keys for one direction of one epoch.
pub(crate) struct RecordKeys {
    suite: Suite,
    /// AEAD key or CBC encryption key.
    key: Secret,
    /// Fixed IV (GCM/ChaCha20) or the TLS 1.3 12-byte IV.
    iv: [u8; 12],
    /// TLS 1.2 CBC write MAC key.
    mac_key: Option<Secret>,
    /// Whether the TLS 1.2 CBC suite uses Encrypt-then-MAC (RFC 7366).
    encrypt_then_mac: bool,
    /// TLS 1.3 traffic secret, retained so KeyUpdate can advance it.
    traffic_secret: Option<Secret>,
    /// Next record sequence number.
    sequence: u64,
    /// Set once the 64-bit sequence number is exhausted.
    exhausted: bool,
}

impl RecordKeys {
    /// Build keys for a TLS 1.2 direction.
    pub(crate) fn tls12(
        key: Secret,
        iv: [u8; 12],
        mac_key: Option<Secret>,
        suite: Suite,
        encrypt_then_mac: bool,
    ) -> Self {
        Self {
            suite,
            key,
            iv,
            mac_key,
            encrypt_then_mac,
            traffic_secret: None,
            sequence: 0,
            exhausted: false,
        }
    }

    /// Build keys for a TLS 1.3 direction from a traffic secret.
    pub(crate) fn tls13(secret: Secret, suite: Suite) -> Option<Self> {
        let (key, iv) = derive_tls13_key_iv(secret.as_bytes(), suite)?;
        Some(Self {
            suite,
            key,
            iv,
            mac_key: None,
            encrypt_then_mac: false,
            traffic_secret: Some(secret),
            sequence: 0,
            exhausted: false,
        })
    }

    /// The next sequence number (tests).
    #[cfg(test)]
    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Set the next sequence number (fuzz and test harnesses).
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn set_sequence(&mut self, sequence: u64) {
        self.sequence = sequence;
        self.exhausted = false;
    }

    /// Advance the sequence number after an attempted record.
    fn advance(&mut self) {
        match self.sequence.checked_add(1) {
            Some(next) => self.sequence = next,
            None => self.exhausted = true,
        }
    }

    /// Decrypt one TLS 1.3 record.
    ///
    /// `header` is the five-byte record header and `fragment` the ciphertext
    /// including the tag. Returns the inner content type and content, with
    /// the zero padding before the type removed.
    pub(crate) fn open_tls13(&mut self, header: &[u8; 5], fragment: &[u8]) -> Option<Decrypted> {
        if self.exhausted || self.suite.version != 0x0304 {
            return None;
        }
        let sequence = self.sequence;
        let mut nonce = self.iv;
        xor_sequence(&mut nonce, sequence);
        let mut buffer = zeroize::Zeroizing::new(fragment.to_vec());
        if !self.open_in_place_aad(&nonce, header, &mut buffer) {
            return None;
        }
        self.advance();
        let plaintext_len = buffer.len().checked_sub(16)?;
        buffer.truncate(plaintext_len);
        let plaintext = std::mem::take(&mut *buffer);
        let mut decrypted = strip_tls13_padding(plaintext)?;
        decrypted.sequence = sequence;
        Some(decrypted)
    }

    /// Decrypt one TLS 1.2 record.
    ///
    /// `content_type`, `version` and `fragment` are the wire fields. Returns
    /// the record's content bytes on success.
    pub(crate) fn open_tls12(
        &mut self,
        content_type: u8,
        version: u16,
        fragment: &[u8],
    ) -> Option<Decrypted> {
        if self.exhausted || self.suite.version != 0x0303 {
            return None;
        }
        let sequence = self.sequence;
        let content = if self.suite.bulk.is_aead() {
            self.open_tls12_aead(sequence, content_type, version, fragment)?
        } else {
            self.open_tls12_cbc(sequence, content_type, version, fragment)?
        };
        self.advance();
        Some(Decrypted {
            content,
            content_type,
            padding: 0,
            sequence,
            tls13: false,
        })
    }

    fn open_tls12_aead(
        &self,
        sequence: u64,
        content_type: u8,
        version: u16,
        fragment: &[u8],
    ) -> Option<Vec<u8>> {
        let (explicit_len, tag_len) = match self.suite.bulk {
            BulkCipher::Aes128Gcm | BulkCipher::Aes256Gcm => (8_usize, 16_usize),
            BulkCipher::Chacha20Poly1305 => (0_usize, 16_usize),
            BulkCipher::Aes128Cbc | BulkCipher::Aes256Cbc => return None,
        };
        let plaintext_len = fragment
            .len()
            .checked_sub(explicit_len)?
            .checked_sub(tag_len)?;
        if plaintext_len > usize::from(u16::MAX) {
            return None;
        }
        let mut nonce = self.iv;
        if explicit_len > 0 {
            // RFC 5288 section 3: nonce = fixed_iv || explicit_nonce, where
            // the explicit nonce is the first eight fragment octets.
            nonce
                .get_mut(4..12)?
                .copy_from_slice(fragment.get(..explicit_len)?);
        } else {
            // RFC 7905 section 2: nonce = IV XOR padded sequence number.
            xor_sequence(&mut nonce, sequence);
        }
        let mut aad = [0_u8; 13];
        aad.get_mut(..8)?.copy_from_slice(&sequence.to_be_bytes());
        *aad.get_mut(8)? = content_type;
        aad.get_mut(9..11)?.copy_from_slice(&version.to_be_bytes());
        aad.get_mut(11..13)?
            .copy_from_slice(&u16::try_from(plaintext_len).ok()?.to_be_bytes());
        let mut buffer = zeroize::Zeroizing::new(fragment.get(explicit_len..)?.to_vec());
        if !self.open_in_place_aad(&nonce, &aad, &mut buffer) {
            return None;
        }
        let plaintext_len = buffer.len().checked_sub(16)?;
        buffer.truncate(plaintext_len);
        Some(std::mem::take(&mut *buffer))
    }

    fn open_in_place_aad(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> bool {
        let Some((ciphertext, tag)) = buffer.split_last_chunk_mut::<16>() else {
            return false;
        };
        let tag: &[u8; 16] = tag;
        match self.suite.bulk {
            BulkCipher::Aes128Gcm => {
                let Ok(cipher) = Aes128Gcm::new_from_slice(self.key.as_bytes()) else {
                    return false;
                };
                cipher
                    .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), tag.into())
                    .is_ok()
            }
            BulkCipher::Aes256Gcm => {
                let Ok(cipher) = Aes256Gcm::new_from_slice(self.key.as_bytes()) else {
                    return false;
                };
                cipher
                    .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), tag.into())
                    .is_ok()
            }
            BulkCipher::Chacha20Poly1305 => {
                let Ok(cipher) = ChaCha20Poly1305::new_from_slice(self.key.as_bytes()) else {
                    return false;
                };
                cipher
                    .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), tag.into())
                    .is_ok()
            }
            BulkCipher::Aes128Cbc | BulkCipher::Aes256Cbc => false,
        }
    }

    fn open_tls12_cbc(
        &mut self,
        sequence: u64,
        content_type: u8,
        version: u16,
        fragment: &[u8],
    ) -> Option<Vec<u8>> {
        let mac_key = self.mac_key.as_ref()?;
        let mac_len = self.suite.bulk.tag_len(self.suite.mac_hash);
        // RFC 7366 Encrypt-then-MAC keeps the tag outside the ciphertext:
        // fragment = IV || ENC(content || padding) || MAC(header || IV ||
        // ciphertext). Classic TLS 1.2 CBC (RFC 5246) keeps it inside.
        let (record, outer_tag) = if self.encrypt_then_mac {
            let split = fragment.len().checked_sub(mac_len)?;
            (fragment.get(..split)?, Some(fragment.get(split..)?))
        } else {
            (fragment, None)
        };
        if record.len() < 16 || record.len() > MAX_CBC_FRAGMENT {
            return None;
        }
        let (iv, ciphertext) = record.split_at_checked(16)?;
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return None;
        }
        if !self.encrypt_then_mac && ciphertext.len() < mac_len.saturating_add(1) {
            return None;
        }
        let mut buffer = zeroize::Zeroizing::new(ciphertext.to_vec());
        if !match self.suite.bulk {
            BulkCipher::Aes128Cbc => {
                let cipher = Decryptor::<Aes128>::new_from_slices(self.key.as_bytes(), iv).ok()?;
                cipher
                    .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
                    .is_ok()
            }
            BulkCipher::Aes256Cbc => {
                let cipher = Decryptor::<Aes256>::new_from_slices(self.key.as_bytes(), iv).ok()?;
                cipher
                    .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
                    .is_ok()
            }
            _ => false,
        } {
            return None;
        }
        // RFC 5246 section 6.2.3.2: padding_length is the last octet; the
        // padding is padding_length+1 octets, each equal to padding_length.
        let padding_length = usize::from(*buffer.last()?);
        let padding = padding_length.checked_add(1)?;
        if padding > buffer.len() {
            return None;
        }
        let split = buffer.len().checked_sub(padding)?;
        let padding_bytes = buffer.get(split..)?;
        // Check every padding octet; `acc` keeps the loop uniform.
        let mut accumulator = 0_u8;
        for byte in padding_bytes {
            accumulator |= *byte ^ u8::try_from(padding_length).ok()?;
        }
        if accumulator != 0 {
            return None;
        }
        let content_length = if self.encrypt_then_mac {
            split
        } else {
            split.checked_sub(mac_len)?
        };
        let content = buffer.get(..content_length)?;
        if content.len() > usize::from(u16::MAX) {
            return None;
        }
        let mut mac_input = [0_u8; 13];
        mac_input
            .get_mut(..8)?
            .copy_from_slice(&sequence.to_be_bytes());
        *mac_input.get_mut(8)? = content_type;
        mac_input
            .get_mut(9..11)?
            .copy_from_slice(&version.to_be_bytes());
        // RFC 7366 MACs the whole fragment (IV + ciphertext); classic CBC
        // MACs the content length only.
        let mac_length = if self.encrypt_then_mac {
            record.len()
        } else {
            content_length
        };
        mac_input
            .get_mut(11..13)?
            .copy_from_slice(&u16::try_from(mac_length).ok()?.to_be_bytes());
        let verified = if let Some(tag) = outer_tag {
            verify_hmac_parts(
                self.suite.mac_hash,
                mac_key.as_bytes(),
                &[&mac_input, iv, ciphertext],
                tag,
            )
        } else {
            let tag_start = content_length;
            let tag = buffer.get(tag_start..tag_start.checked_add(mac_len)?)?;
            verify_hmac(
                self.suite.mac_hash,
                mac_key.as_bytes(),
                &mac_input,
                content,
                tag,
            )
        };
        if !verified {
            return None;
        }
        Some(content.to_vec())
    }

    /// Advance a TLS 1.3 application traffic secret after a KeyUpdate.
    ///
    /// RFC 8446 section 7.2: `secret = HKDF-Expand-Label(secret,
    /// "traffic upd", "", Hash.length)`; the next record uses sequence 0.
    pub(crate) fn key_update(&mut self) -> Option<()> {
        if !self.suite.is_tls13() {
            return None;
        }
        let secret = self.traffic_secret.as_ref()?;
        let hash_len = self.suite.hash.len();
        let mut next = [0_u8; 48];
        hkdf_expand_label(
            self.suite.hash,
            secret.as_bytes(),
            b"traffic upd",
            &[],
            next.get_mut(..hash_len)?,
        )?;
        let next_secret = Secret::new(next.get(..hash_len)?)?;
        let (key, iv) = derive_tls13_key_iv(next_secret.as_bytes(), self.suite)?;
        self.key = key;
        self.iv = iv;
        self.traffic_secret = Some(next_secret);
        self.sequence = 0;
        self.exhausted = false;
        next.zeroize();
        Some(())
    }
}

impl std::fmt::Debug for RecordKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecordKeys")
            .field("suite", &self.suite)
            .field("sequence", &self.sequence)
            .field("exhausted", &self.exhausted)
            .field("iv", &"[redacted]")
            .field("mac_key", &self.mac_key.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

/// A decrypted TLS 1.3 record.
pub(crate) struct Decrypted {
    /// Content bytes with the inner type and padding removed.
    pub(crate) content: Vec<u8>,
    /// Inner content type.
    pub(crate) content_type: u8,
    /// Number of zero padding octets between content and type.
    pub(crate) padding: usize,
    /// Sequence number that protected this record.
    pub(crate) sequence: u64,
    /// Whether this record was protected by a TLS 1.3 key.
    pub(crate) tls13: bool,
}

/// Split a TLS 1.3 plaintext into content, inner type and padding.
fn strip_tls13_padding(mut plaintext: Vec<u8>) -> Option<Decrypted> {
    let end = plaintext.iter().rposition(|byte| *byte != 0)?;
    let content_type = *plaintext.get(end)?;
    let padding = plaintext.len().checked_sub(end)?.checked_sub(1)?;
    plaintext.truncate(end);
    Some(Decrypted {
        content: plaintext,
        content_type,
        padding,
        sequence: 0,
        tls13: true,
    })
}

/// Apply the TLS 1.3 padded-sequence XOR to a 12-byte nonce.
fn xor_sequence(nonce: &mut [u8; 12], sequence: u64) {
    let sequence_bytes = sequence.to_be_bytes();
    for (slot, byte) in nonce.iter_mut().skip(4).zip(sequence_bytes) {
        *slot ^= byte;
    }
}

/// Expand a TLS 1.3 traffic secret into its write key and IV.
fn derive_tls13_key_iv(secret: &[u8], suite: Suite) -> Option<(Secret, [u8; 12])> {
    let key_len = suite.bulk.key_len();
    let mut key_bytes = [0_u8; 32];
    hkdf_expand_label(
        suite.hash,
        secret,
        b"key",
        &[],
        key_bytes.get_mut(..key_len)?,
    )?;
    let key = Secret::new(key_bytes.get(..key_len)?)?;
    key_bytes.zeroize();
    let mut iv = [0_u8; 12];
    hkdf_expand_label(suite.hash, secret, b"iv", &[], &mut iv)?;
    Some((key, iv))
}

/// Derive the TLS 1.2 key block (RFC 5246 section 6.3).
pub(crate) fn derive_tls12_key_block(
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    suite: Suite,
) -> Option<Tls12KeyBlock> {
    if suite.is_tls13() {
        return None;
    }
    let mac_len = match suite.bulk {
        BulkCipher::Aes128Cbc | BulkCipher::Aes256Cbc => suite.mac_hash.len(),
        _ => 0,
    };
    let key_len = suite.bulk.key_len();
    let iv_len = suite.bulk.fixed_iv_len();
    let total = mac_len
        .checked_mul(2)?
        .checked_add(key_len.checked_mul(2)?)?
        .checked_add(iv_len.checked_mul(2)?)?;
    if total > 256 {
        return None;
    }
    let mut seed = [0_u8; 64];
    seed.get_mut(..32)?.copy_from_slice(server_random);
    seed.get_mut(32..64)?.copy_from_slice(client_random);
    let mut block = [0_u8; 256];
    let output = block.get_mut(..total)?;
    prf(suite.hash, master, b"key expansion", &seed, output)?;

    let mut offset = 0_usize;
    let mut next = |length: usize| -> Option<&[u8]> {
        let start = offset;
        let end = start.checked_add(length)?;
        let slice = output.get(start..end)?;
        offset = end;
        Some(slice)
    };
    let client_mac = if mac_len > 0 {
        Some(Secret::new(next(mac_len)?)?)
    } else {
        None
    };
    let server_mac = if mac_len > 0 {
        Some(Secret::new(next(mac_len)?)?)
    } else {
        None
    };
    let client_key = Secret::new(next(key_len)?)?;
    let server_key = Secret::new(next(key_len)?)?;
    let mut client_iv = [0_u8; 12];
    if iv_len > 0 {
        let source = next(iv_len)?;
        client_iv.get_mut(..iv_len)?.copy_from_slice(source);
    }
    let mut server_iv = [0_u8; 12];
    if iv_len > 0 {
        let source = next(iv_len)?;
        server_iv.get_mut(..iv_len)?.copy_from_slice(source);
    }
    drop(next);
    block.zeroize();
    Some(Tls12KeyBlock {
        client_key,
        server_key,
        client_iv,
        server_iv,
        client_mac,
        server_mac,
    })
}

/// Compute the TLS 1.2 PRF (RFC 5246 section 5) with the suite's hash.
fn prf(
    hash: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> Option<()> {
    let mut label_seed = [0_u8; 128];
    let label_len = label.len().checked_add(seed.len())?;
    if label_len > label_seed.len() {
        return None;
    }
    label_seed.get_mut(..label.len())?.copy_from_slice(label);
    label_seed
        .get_mut(label.len()..label_len)?
        .copy_from_slice(seed);
    let seed_slice = label_seed.get(..label_len)?;

    let mut a = [0_u8; 48];
    let mut a_len = hmac_parts(hash, secret, &[seed_slice], &mut a)?;
    let mut written = 0_usize;
    while written < out.len() {
        let mut block = [0_u8; 48];
        let block_len = hmac_parts(hash, secret, &[a.get(..a_len)?, seed_slice], &mut block)?;
        let remaining = out.len().saturating_sub(written);
        let take = block_len.min(remaining);
        out.get_mut(written..written.checked_add(take)?)?
            .copy_from_slice(block.get(..take)?);
        block.zeroize();
        written = written.checked_add(take)?;
        // A(i+1) = HMAC(secret, A(i))
        let mut next_a = [0_u8; 48];
        a_len = hmac_parts(hash, secret, &[a.get(..a_len)?], &mut next_a)?;
        a.zeroize();
        a = next_a;
        next_a.zeroize();
    }
    a.zeroize();
    label_seed.zeroize();
    Some(())
}

/// HMAC over the concatenation of `parts`, writing into `out`.
fn hmac_parts(
    hash: HashAlgorithm,
    key: &[u8],
    parts: &[&[u8]],
    out: &mut [u8; 48],
) -> Option<usize> {
    match hash {
        HashAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
            for part in parts {
                mac.update(part);
            }
            let mut tag = mac.finalize().into_bytes();
            out.get_mut(..tag.len())?.copy_from_slice(&tag);
            tag.as_mut_slice().zeroize();
            Some(tag.len())
        }
        HashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
            for part in parts {
                mac.update(part);
            }
            let mut tag = mac.finalize().into_bytes();
            out.get_mut(..tag.len())?.copy_from_slice(&tag);
            tag.as_mut_slice().zeroize();
            Some(tag.len())
        }
        HashAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key).ok()?;
            for part in parts {
                mac.update(part);
            }
            let mut tag = mac.finalize().into_bytes();
            out.get_mut(..tag.len())?.copy_from_slice(&tag);
            tag.as_mut_slice().zeroize();
            Some(tag.len())
        }
    }
}

/// Verify a CBC record's HMAC in constant time.
fn verify_hmac(hash: HashAlgorithm, key: &[u8], aad: &[u8], content: &[u8], tag: &[u8]) -> bool {
    if tag.len() != hash.len() {
        return false;
    }
    match hash {
        HashAlgorithm::Sha1 => verify_mac::<Hmac<Sha1>>(key, aad, content, tag),
        HashAlgorithm::Sha256 => verify_mac::<Hmac<Sha256>>(key, aad, content, tag),
        HashAlgorithm::Sha384 => verify_mac::<Hmac<Sha384>>(key, aad, content, tag),
    }
}

fn verify_mac<M: Mac + KeyInit>(key: &[u8], aad: &[u8], content: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = M::new_from_slice(key) else {
        return false;
    };
    mac.update(aad);
    mac.update(content);
    mac.verify_slice(tag).is_ok()
}

/// Verify a MAC over several non-contiguous parts in constant time.
fn verify_hmac_parts(hash: HashAlgorithm, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut computed = [0_u8; 48];
    let Some(length) = hmac_parts(hash, key, parts, &mut computed) else {
        return false;
    };
    if tag.len() != length {
        computed.zeroize();
        return false;
    }
    let equal = computed
        .get(..length)
        .is_some_and(|bytes| bytes.ct_eq(tag).into());
    computed.zeroize();
    equal
}

/// HKDF-Expand-Label (RFC 8446 section 7.1).
fn hkdf_expand_label(
    hash: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Option<()> {
    let mut info = [0_u8; 128];
    let label_len = label.len().checked_add(6)?; // "tls13 " + label
    let length = out.len();
    let info_len = 2_usize
        .checked_add(1)?
        .checked_add(label_len)?
        .checked_add(1)?
        .checked_add(context.len())?;
    if info_len > info.len() {
        return None;
    }
    info.get_mut(..2)?
        .copy_from_slice(&u16::try_from(length).ok()?.to_be_bytes());
    *info.get_mut(2)? = u8::try_from(label_len).ok()?;
    info.get_mut(3..9)?.copy_from_slice(b"tls13 ");
    info.get_mut(9..9 + label.len())?.copy_from_slice(label);
    *info.get_mut(9 + label.len())? = u8::try_from(context.len()).ok()?;
    info.get_mut(10 + label.len()..info_len)?
        .copy_from_slice(context);
    let expanded = info.get(..info_len)?;
    match hash {
        HashAlgorithm::Sha1 => return None, // TLS 1.3 has no SHA-1 suite.
        HashAlgorithm::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .ok()?
            .expand(expanded, out)
            .ok()?,
        HashAlgorithm::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .ok()?
            .expand(expanded, out)
            .ok()?,
    }
    info.zeroize();
    Some(())
}

// `zeroize` for the stack IV helpers.
use zeroize::Zeroize;

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "known-answer tests use fixed vectors with infallible sizes"
)]
mod tests {
    use super::*;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

    fn hex(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut high = None;
        for byte in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("not hex"),
            };
            match high.take() {
                None => high = Some(digit),
                Some(high) => out.push((high << 4) | digit),
            }
        }
        out
    }

    fn secret(bytes: &[u8]) -> Secret {
        Secret::new(bytes).expect("secret")
    }

    #[test]
    fn nist_aes_gcm_vectors() {
        // NIST SP 800-38D, GCM test case 2.
        let key = [0_u8; 16];
        let nonce = [0_u8; 12];
        let expected_ciphertext = hex("0388dace60b6a392f328c2b971b2fe78");
        let expected_tag = hex("ab6e47d42cec13bdf53a67b21257bddf");
        let plaintext = [0_u8; 16];
        let cipher = Aes128Gcm::new_from_slice(&key).expect("key");
        let mut buffer = plaintext;
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), &[], buffer.as_mut_slice().into())
            .expect("encrypt");
        assert_eq!(buffer, expected_ciphertext.as_slice());
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
        let mut opened = expected_ciphertext;
        cipher
            .decrypt_inout_detached(
                (&nonce).into(),
                &[],
                opened.as_mut_slice().into(),
                expected_tag.as_slice().try_into().expect("tag"),
            )
            .expect("decrypt");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn tls13_record_round_trip() {
        let suite = suite(0x1301).expect("suite");
        let traffic_secret = [0x5a_u8; 32];
        let mut keys = RecordKeys::tls13(secret(&traffic_secret), suite).expect("keys");
        let plaintext = [b'h', b'e', b'l', b'l', b'o', 23];
        let cipher = Aes128Gcm::new_from_slice(keys.key.as_bytes()).expect("key");
        let mut nonce = keys.iv;
        xor_sequence(&mut nonce, keys.sequence());
        let mut fragment = plaintext.to_vec();
        let tag = cipher
            .encrypt_inout_detached(
                (&nonce).into(),
                &[23, 3, 3, 0, 22],
                fragment.as_mut_slice().into(),
            )
            .expect("encrypt");
        fragment.extend_from_slice(&tag);
        let header = [23, 3, 3, 0, u8::try_from(fragment.len()).unwrap()];
        let decrypted = keys.open_tls13(&header, &fragment).expect("open");
        assert_eq!(decrypted.content, b"hello");
        assert_eq!(decrypted.content_type, 23);
        assert_eq!(decrypted.padding, 0);
    }

    #[test]
    fn rfc8439_chacha20_poly1305_vector() {
        // RFC 8439 section 2.8.2.
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex("070000004041424344454647");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116\
             1ae10b594f09e26a7e902ecbd0600691",
        );
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("key");
        let (ciphertext, tag) = expected.split_at(expected.len() - 16);
        let mut buffer = ciphertext.to_vec();
        cipher
            .decrypt_inout_detached(
                nonce.as_slice().try_into().expect("nonce"),
                &aad,
                buffer.as_mut_slice().into(),
                tag.try_into().expect("tag"),
            )
            .expect("decrypt");
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn nist_aes_cbc_vector() {
        // NIST SP 800-38A, F.2.1 CBC-AES128.
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let ciphertext = hex("7649abac8119b246cee98e9b12e9197d");
        let expected = hex("6bc1bee22e409f96e93d7e117393172a");
        let mut buffer = ciphertext;
        let cipher = Decryptor::<Aes128>::new_from_slices(&key, &iv).expect("cipher");
        let plaintext = cipher
            .decrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
            .expect("decrypt");
        assert_eq!(plaintext, expected.as_slice());
    }

    #[test]
    fn rfc5869_hkdf_sha256_vector() {
        // RFC 5869 test case 1.
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0_u8; 42];
        hk.expand(&info, &mut okm).expect("expand");
        assert_eq!(
            okm.as_slice(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn rfc8448_tls13_key_schedule_and_record() {
        // RFC 8448 section 3: server handshake traffic secret, key and IV.
        let traffic_secret =
            hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        let suite = suite(0x1301).expect("suite");
        let keys = RecordKeys::tls13(secret(&traffic_secret), suite).expect("keys");
        assert_eq!(keys.key.as_bytes(), hex("3fce516009c21727d0f2e4e86ee403bc"));
        assert_eq!(keys.iv, hex("5d313eb2671276ee13000b30").as_slice());

        // The complete protected record from the RFC decrypts to the payload
        // of EncryptedExtensions, Certificate, CertificateVerify and Finished
        // with inner content type 22.
        let record = hex(
            "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf\
             7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b1\
             11b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9\
             aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7\
             477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed6\
             5b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d\
             809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945b\
             a246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b36845\
             96c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f44\
             15cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f5\
             9ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b\
             49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b\
             7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c\
             87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461\
             e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a\
             37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb99\
             2f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977\
             b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038eb\
             ba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e\
             275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2\
             af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e75\
             0edc53370d2b",
        );
        let mut header = [0_u8; 5];
        header.copy_from_slice(&record[..5]);
        let mut keys = RecordKeys::tls13(secret(&traffic_secret), suite).expect("keys");
        let decrypted = keys
            .open_tls13(&header, &record[5..])
            .expect("record opens");
        assert_eq!(decrypted.content_type, 22);
        assert_eq!(decrypted.padding, 0);
        assert_eq!(decrypted.content.len(), 657);
        assert_eq!(decrypted.content.first(), Some(&8));
        assert_eq!(keys.sequence(), 1);
    }

    #[test]
    fn bad_tag_returns_none_without_consuming_the_sequence() {
        let suite = suite(0x1301).expect("suite");
        let mut keys = RecordKeys::tls13(secret(&[7_u8; 32]), suite).expect("keys");
        let header = [23, 3, 3, 0, 17];
        assert!(keys.open_tls13(&header, &[0_u8; 17]).is_none());
        assert_eq!(keys.sequence(), 0);
    }

    #[test]
    fn tls12_gcm_round_trip() {
        let suite = suite(0xc030).expect("suite");
        let master = [0x11_u8; 48];
        let client_random = [0x22_u8; 32];
        let server_random = [0x33_u8; 32];
        let block =
            derive_tls12_key_block(&master, &client_random, &server_random, suite).expect("block");
        assert_eq!(block.client_key.len(), 32);
        assert_eq!(block.client_iv.len(), 12);
        assert!(block.client_mac.is_none());
        // Encrypt a record with the same block, then open it through the
        // public TLS 1.2 path.
        let mut keys = RecordKeys::tls12(block.client_key, block.client_iv, None, suite, false);
        let plaintext = b"hello";
        let content_type = 23_u8;
        let version = 0x0303_u16;
        let explicit = [0x01_u8, 2, 3, 4, 5, 6, 7, 8];
        let mut nonce = block.client_iv;
        nonce[4..].copy_from_slice(&explicit);
        let mut aad = [0_u8; 13];
        aad[..8].copy_from_slice(&keys.sequence().to_be_bytes());
        aad[8] = content_type;
        aad[9..11].copy_from_slice(&version.to_be_bytes());
        aad[11..].copy_from_slice(&u16::try_from(plaintext.len()).unwrap().to_be_bytes());
        let cipher = Aes256Gcm::new_from_slice(keys.key.as_bytes()).expect("key");
        let mut fragment = explicit.to_vec();
        fragment.extend_from_slice(plaintext);
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), &aad, (&mut fragment[8..]).into())
            .expect("encrypt");
        fragment.extend_from_slice(&tag);
        let opened = keys
            .open_tls12(content_type, version, &fragment)
            .expect("open");
        assert_eq!(opened.content, plaintext);
    }

    #[test]
    fn tls12_prf_matches_openssl() {
        // OpenSSL 4.1.0:
        // openssl kdf -keylen 104 -kdfopt digest:SHA256         //   -kdfopt hexsecret:<0b * 48>         //   -kdfopt hexseed:<"key expansion" || 00..3f> TLS1-PRF
        let master = [0x0b_u8; 48];
        let mut seed = b"key expansion".to_vec();
        seed.extend(0_u8..64);
        let mut out = [0_u8; 104];
        prf(
            HashAlgorithm::Sha256,
            &master,
            b"key expansion",
            &seed[13..],
            &mut out,
        )
        .expect("prf");
        assert_eq!(
            out.as_slice(),
            hex(
                "b93b89a13f094cc4ae7fd935a6b58a8b0c50fa58cddeed38b34378fb8919d856\
                 63e5f6817728ae563dfccf0bafe821bd62d0bf115dd0f324a68d379a7b4125d3\
                 bf77cc7d844a82f32544b1197e1f1dcdcc04beae5d215c8c59d728511c0a82fe\
                 005ba169ca580e66"
            )
            .as_slice()
        );
    }

    #[test]
    fn tls12_cbc_round_trip_and_bad_mac() {
        let suite = suite(0xc014).expect("suite");
        let master = [0x44_u8; 48];
        let block =
            derive_tls12_key_block(&master, &[1_u8; 32], &[2_u8; 32], suite).expect("block");
        let mac_key = block.client_mac.expect("mac");
        let key = block.client_key;
        let seq = 0_u64;
        let content_type = 22_u8;
        let version = 0x0303_u16;
        let content = b"cbc content";
        let mut mac_input = [0_u8; 13];
        mac_input[..8].copy_from_slice(&seq.to_be_bytes());
        mac_input[8] = content_type;
        mac_input[9..11].copy_from_slice(&version.to_be_bytes());
        mac_input[11..].copy_from_slice(&u16::try_from(content.len()).unwrap().to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(mac_key.as_bytes()).expect("hmac");
        mac.update(&mac_input);
        mac.update(content);
        let tag = mac.finalize().into_bytes();
        let base = content.len() + tag.len();
        let padding_length = u8::try_from(15 - (base % 16)).expect("padding");
        let mut plaintext = content.to_vec();
        plaintext.extend_from_slice(&tag);
        plaintext.extend(std::iter::repeat_n(
            padding_length,
            usize::from(padding_length) + 1,
        ));
        assert_eq!(plaintext.len() % 16, 0);
        let iv = [9_u8; 16];
        let cipher =
            cbc::Encryptor::<Aes256>::new_from_slices(key.as_bytes(), &iv).expect("cipher");
        let mut buffer = plaintext;
        let length = buffer.len();
        let ciphertext = cipher
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buffer, length)
            .expect("encrypt")
            .to_vec();
        let mut fragment = iv.to_vec();
        fragment.extend_from_slice(&ciphertext);
        let mut keys = RecordKeys::tls12(key, [0_u8; 12], Some(mac_key), suite, false);
        let opened = keys
            .open_tls12(content_type, version, &fragment)
            .expect("open");
        assert_eq!(opened.content, content);
        let mut bad = fragment.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut keys = RecordKeys::tls12(
            Secret::new(&[0_u8; 32]).expect("key"),
            [0_u8; 12],
            Some(Secret::new(&[0_u8; 20]).expect("mac")),
            suite,
            false,
        );
        assert!(keys.open_tls12(content_type, version, &bad).is_none());
    }

    #[test]
    fn tls12_cbc_encrypt_then_mac_round_trip() {
        // RFC 7366: fragment = IV || ENC(content || padding) || MAC(header ||
        // IV || ciphertext).
        let suite = suite(0xc014).expect("suite");
        let master = [0x44_u8; 48];
        let block =
            derive_tls12_key_block(&master, &[1_u8; 32], &[2_u8; 32], suite).expect("block");
        let mac_key = block.client_mac.expect("mac");
        let key = block.client_key;
        let sequence = 3_u64;
        let content_type = 23_u8;
        let version = 0x0303_u16;
        let content = b"etm content";
        let padding_length = 15 - (content.len() % 16);
        let mut plaintext = content.to_vec();
        plaintext.extend(std::iter::repeat_n(
            u8::try_from(padding_length).expect("padding"),
            padding_length + 1,
        ));
        let iv = [0x5a_u8; 16];
        let cipher =
            cbc::Encryptor::<Aes256>::new_from_slices(key.as_bytes(), &iv).expect("cipher");
        let mut buffer = plaintext;
        let length = buffer.len();
        let ciphertext = cipher
            .encrypt_padded::<cbc::cipher::block_padding::NoPadding>(&mut buffer, length)
            .expect("encrypt")
            .to_vec();
        let mut fragment = iv.to_vec();
        fragment.extend_from_slice(&ciphertext);
        let mut mac_input = [0_u8; 13];
        mac_input[..8].copy_from_slice(&sequence.to_be_bytes());
        mac_input[8] = content_type;
        mac_input[9..11].copy_from_slice(&version.to_be_bytes());
        mac_input[11..]
            .copy_from_slice(&u16::try_from(fragment.len()).expect("length").to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(mac_key.as_bytes()).expect("hmac");
        mac.update(&mac_input);
        mac.update(&fragment);
        fragment.extend_from_slice(&mac.finalize().into_bytes());
        let mut keys = RecordKeys::tls12(key, [0_u8; 12], Some(mac_key), suite, true);
        keys.set_sequence(sequence);
        let opened = keys
            .open_tls12(content_type, version, &fragment)
            .expect("open");
        assert_eq!(opened.content, content);
        // A flipped tag is rejected.
        let mut keys = RecordKeys::tls12(
            Secret::new(&[0_u8; 32]).expect("key"),
            [0_u8; 12],
            Some(Secret::new(&[0_u8; 20]).expect("mac")),
            suite,
            true,
        );
        let mut bad = fragment;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(keys.open_tls12(content_type, version, &bad).is_none());
    }

    #[test]
    fn key_update_matches_the_rfc_8446_derivation() {
        let traffic_secret =
            hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
        let suite = suite(0x1301).expect("suite");
        let mut keys = RecordKeys::tls13(secret(&traffic_secret), suite).expect("keys");
        let mut expected = [0_u8; 32];
        hkdf_expand_label(
            HashAlgorithm::Sha256,
            &traffic_secret,
            b"traffic upd",
            &[],
            &mut expected,
        )
        .expect("expand");
        keys.key_update().expect("update");
        assert_eq!(keys.sequence(), 0);
        assert_eq!(
            keys.traffic_secret.as_ref().map(Secret::as_bytes),
            Some(expected.as_slice())
        );
    }

    #[test]
    fn tls13_padding_is_stripped() {
        let decrypted = strip_tls13_padding(vec![b'a', b'b', 23, 0, 0]).expect("strip");
        assert_eq!(decrypted.content, b"ab");
        assert_eq!(decrypted.content_type, 23);
        assert_eq!(decrypted.padding, 2);
        assert!(strip_tls13_padding(vec![0, 0, 0]).is_none());
        let empty = strip_tls13_padding(vec![23]).expect("type-only record");
        assert!(empty.content.is_empty());
        assert_eq!(empty.content_type, 23);
    }
}
