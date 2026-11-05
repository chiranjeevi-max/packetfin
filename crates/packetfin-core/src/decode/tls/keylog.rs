//! TLS key-log files (NSS Key Log Format).
//!
//! The format is one record per line: a label, the client random in lowercase
//! or uppercase hex, and a secret. Packetfin reads it through
//! `-o tls.keylog_file:PATH`; the environment variable is not consulted.
//! Comments and blank lines are skipped, a label must start in column zero,
//! fields are split on ASCII whitespace, anything after the secret is ignored,
//! unknown labels are ignored, and a later valid line replaces an earlier
//! value for the same client random. Malformed lines never abort the load.
//!
//! The loader is bounded. A line longer than [`MAX_KEYLOG_LINE`] is discarded
//! whole, reading stops at [`MAX_KEYLOG_BYTES`] and [`MAX_KEYLOG_ENTRIES`],
//! and [`KeyLog::truncated`] reports that the file was not read to its end.
//! Secrets are kept in [`Secret`], which zeroizes on drop and has no
//! `Debug`/`Display`; no secret can reach an output stream through a log line.

use std::collections::HashMap;
use std::fmt;
use std::io::BufRead;

use zeroize::Zeroize;

/// Largest key-log file prefix read from disk.
pub const MAX_KEYLOG_BYTES: usize = 64 * 1024 * 1024;

/// Longest line accepted; a longer line is skipped.
pub const MAX_KEYLOG_LINE: usize = 8 * 1024;

/// Most client random entries retained.
pub const MAX_KEYLOG_ENTRIES: usize = 65_536;

/// Longest secret any recognised label carries.
const MAX_SECRET_LEN: usize = 64;

/// Secret length for SHA-256 TLS traffic and exporter secrets.
const TRAFFIC_SECRET_LEN: usize = 32;

/// Secret length for SHA-384 TLS traffic and exporter secrets.
const TRAFFIC_SECRET_LEN_SHA384: usize = 48;

/// Secret length for a TLS 1.2 `CLIENT_RANDOM` master secret.
const MASTER_SECRET_LEN: usize = 48;

/// One key-log label Packetfin recognises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLabel {
    /// TLS 1.2 master secret.
    ClientRandom,
    /// TLS 1.3 0-RTT client secret.
    ClientEarlyTraffic,
    /// TLS 1.3 client handshake traffic secret.
    ClientHandshakeTraffic,
    /// TLS 1.3 server handshake traffic secret.
    ServerHandshakeTraffic,
    /// TLS 1.3 client application traffic secret.
    ClientTraffic,
    /// TLS 1.3 server application traffic secret.
    ServerTraffic,
    /// TLS 1.3 early exporter secret.
    EarlyExporter,
    /// TLS 1.3 exporter secret.
    Exporter,
    /// TLS 1.2 pre-master secret (`PMS_CLIENT_RANDOM`).
    PmsClientRandom,
}

impl KeyLabel {
    /// The exact label written to and read from key-log files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientRandom => "CLIENT_RANDOM",
            Self::ClientEarlyTraffic => "CLIENT_EARLY_TRAFFIC_SECRET",
            Self::ClientHandshakeTraffic => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            Self::ServerHandshakeTraffic => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            Self::ClientTraffic => "CLIENT_TRAFFIC_SECRET_0",
            Self::ServerTraffic => "SERVER_TRAFFIC_SECRET_0",
            Self::EarlyExporter => "EARLY_EXPORTER_SECRET",
            Self::Exporter => "EXPORTER_SECRET",
            Self::PmsClientRandom => "PMS_CLIENT_RANDOM",
        }
    }

    /// The label for a key-log token, matched without ASCII case.
    fn from_token(token: &[u8]) -> Option<Self> {
        const LABELS: [KeyLabel; 9] = [
            KeyLabel::ClientRandom,
            KeyLabel::ClientEarlyTraffic,
            KeyLabel::ClientHandshakeTraffic,
            KeyLabel::ServerHandshakeTraffic,
            KeyLabel::ClientTraffic,
            KeyLabel::ServerTraffic,
            KeyLabel::EarlyExporter,
            KeyLabel::Exporter,
            KeyLabel::PmsClientRandom,
        ];
        LABELS
            .iter()
            .copied()
            .find(|label| token.eq_ignore_ascii_case(label.as_str().as_bytes()))
    }

    /// The secret lengths this label accepts.
    fn accepts(self, length: usize) -> bool {
        match self {
            Self::ClientRandom => length == MASTER_SECRET_LEN,
            Self::PmsClientRandom => (1..=MAX_SECRET_LEN).contains(&length),
            _ => length == TRAFFIC_SECRET_LEN || length == TRAFFIC_SECRET_LEN_SHA384,
        }
    }
}

/// A key-log secret that zeroizes when it is dropped.
///
/// The type deliberately implements neither `Clone` nor `Debug`/`Display`:
/// secrets are moved, never copied or formatted.
pub struct Secret {
    bytes: [u8; MAX_SECRET_LEN],
    len: u8,
}

impl Secret {
    /// Copy at most [`MAX_SECRET_LEN`] bytes into a zeroizing buffer.
    pub(crate) fn new(bytes: &[u8]) -> Option<Self> {
        let len = u8::try_from(bytes.len()).ok()?;
        if bytes.is_empty() || bytes.len() > MAX_SECRET_LEN {
            return None;
        }
        let mut storage = [0_u8; MAX_SECRET_LEN];
        storage.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            bytes: storage,
            len,
        })
    }

    /// The secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Copy the secret into a second zeroizing buffer.
    ///
    /// Used when one secret must live in both a session and the bounded
    /// resumption cache; both copies are zeroized independently.
    pub(crate) fn duplicate(&self) -> Option<Self> {
        Self::new(self.as_bytes())
    }

    /// The secret length.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether the secret carries no bytes. Construction rejects empty
    /// secrets, so this is always false; it accompanies [`len`](Self::len).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the bytes, not even truncated.
        formatter
            .debug_struct("Secret")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// The secrets known for one client random.
#[derive(Debug, Default)]
pub struct KeyEntry {
    /// TLS 1.2 master secret (`CLIENT_RANDOM`).
    pub master: Option<Secret>,
    /// TLS 1.3 0-RTT traffic secret.
    pub early: Option<Secret>,
    /// TLS 1.3 client handshake traffic secret.
    pub client_handshake: Option<Secret>,
    /// TLS 1.3 server handshake traffic secret.
    pub server_handshake: Option<Secret>,
    /// TLS 1.3 client application traffic secret.
    pub client_traffic: Option<Secret>,
    /// TLS 1.3 server application traffic secret.
    pub server_traffic: Option<Secret>,
    /// TLS 1.3 early exporter secret.
    pub early_exporter: Option<Secret>,
    /// TLS 1.3 exporter secret.
    pub exporter: Option<Secret>,
    /// TLS 1.2 pre-master secret (`PMS_CLIENT_RANDOM`).
    pub pms: Option<Secret>,
}

impl KeyEntry {
    fn slot(&mut self, label: KeyLabel) -> &mut Option<Secret> {
        match label {
            KeyLabel::ClientRandom => &mut self.master,
            KeyLabel::ClientEarlyTraffic => &mut self.early,
            KeyLabel::ClientHandshakeTraffic => &mut self.client_handshake,
            KeyLabel::ServerHandshakeTraffic => &mut self.server_handshake,
            KeyLabel::ClientTraffic => &mut self.client_traffic,
            KeyLabel::ServerTraffic => &mut self.server_traffic,
            KeyLabel::EarlyExporter => &mut self.early_exporter,
            KeyLabel::Exporter => &mut self.exporter,
            KeyLabel::PmsClientRandom => &mut self.pms,
        }
    }
}

/// A loaded key-log file.
pub struct KeyLog {
    entries: HashMap<[u8; 32], KeyEntry>,
    /// Bytes consumed from the reader, including discarded lines.
    bytes: usize,
    /// Whether loading stopped before the reader's end.
    truncated: bool,
    /// Lines ignored because they were malformed or unrecognised.
    skipped: u32,
}

impl KeyLog {
    /// An empty key log.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            truncated: false,
            skipped: 0,
        }
    }

    /// Read a key-log from a buffered reader.
    ///
    /// A read error ends the load quietly: a missing or unreadable key-log
    /// file disables decryption without failing the run.
    pub fn read<R: BufRead>(mut reader: R) -> Self {
        let mut log = Self::new();
        let limits = Limits::default();
        while log.bytes < limits.bytes {
            let Some(mut line) = read_line(&mut reader, &mut log.bytes, limits.line, limits.bytes)
            else {
                break;
            };
            if line.overlong {
                log.skipped = log.skipped.saturating_add(1);
                continue;
            }
            if !log.add_line(&line.bytes, limits.entries) {
                log.skipped = log.skipped.saturating_add(1);
            }
            line.bytes.zeroize();
            // The entry cap makes the rest of the file irrelevant; stop
            // consuming input instead of streaming an unbounded file.
            if log.truncated {
                break;
            }
        }
        if log.bytes >= limits.bytes && matches!(reader.fill_buf(), Ok(chunk) if !chunk.is_empty())
        {
            // The cap stopped the load before the reader's end.
            log.truncated = true;
        }
        log
    }

    /// Read a key-log from a byte slice. Test and fixture convenience.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::read(bytes)
    }

    /// Add one line, returning whether it was recognised and well formed.
    fn add_line(&mut self, line: &[u8], max_entries: usize) -> bool {
        if line.is_empty() || line.first() == Some(&b'#') {
            return true;
        }
        // The label must start in column zero: a leading blank makes the line
        // useless.
        if line.first().is_some_and(u8::is_ascii_whitespace) {
            return false;
        }
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let Some(label_token) = fields.next() else {
            return false;
        };
        let Some(random_token) = fields.next() else {
            return false;
        };
        let Some(secret_token) = fields.next() else {
            return false;
        };
        let Some(label) = KeyLabel::from_token(label_token) else {
            return false;
        };
        let mut random = [0_u8; 32];
        if !decode_hex(random_token, &mut random) {
            return false;
        }
        if secret_token.len() % 2 != 0 || !label.accepts(secret_token.len() / 2) {
            return false;
        }
        let Some(secret) = decode_secret(secret_token) else {
            return false;
        };
        let entry = match self.entries.get_mut(&random) {
            Some(entry) => entry,
            None => {
                if self.entries.len() >= max_entries {
                    self.truncated = true;
                    return false;
                }
                self.entries.entry(random).or_default()
            }
        };
        *entry.slot(label) = Some(secret);
        true
    }

    /// The entry for a client random.
    pub fn get(&self, client_random: &[u8; 32]) -> Option<&KeyEntry> {
        self.entries.get(client_random)
    }

    /// Number of client-random entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entry is loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether loading stopped at a cap instead of the end of input.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Lines skipped as malformed or unknown.
    pub fn skipped(&self) -> u32 {
        self.skipped
    }

    /// Bytes consumed from the reader.
    pub fn bytes_read(&self) -> usize {
        self.bytes
    }
}

impl Default for KeyLog {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyLog")
            .field("entries", &self.entries.len())
            .field("bytes", &self.bytes)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

struct Limits {
    bytes: usize,
    line: usize,
    entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_KEYLOG_BYTES,
            line: MAX_KEYLOG_LINE,
            entries: MAX_KEYLOG_ENTRIES,
        }
    }
}

struct Line {
    bytes: Vec<u8>,
    /// The line exceeded the line cap and was discarded.
    overlong: bool,
}

/// Read one line, consuming at most `line_limit` bytes into memory.
///
/// The byte counter includes bytes discarded because the line was too long.
fn read_line<R: BufRead>(
    reader: &mut R,
    consumed: &mut usize,
    line_limit: usize,
    byte_limit: usize,
) -> Option<Line> {
    let mut bytes = Vec::new();
    let mut overlong = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(chunk) => chunk,
            Err(_) => return None,
        };
        if chunk.is_empty() {
            if bytes.is_empty() && !overlong {
                return None;
            }
            return Some(Line { bytes, overlong });
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(chunk.len(), |position| position.saturating_add(1));
        let slice = chunk.get(..take).unwrap_or(chunk);
        if slice.len() > byte_limit.saturating_sub(*consumed) {
            // The file cap is reached inside a line: stop without consuming
            // the rest, so an endless stream cannot hang the loader.
            *consumed = byte_limit;
            return Some(Line {
                bytes: Vec::new(),
                overlong: true,
            });
        }
        *consumed = consumed.saturating_add(slice.len());
        if !overlong {
            let room = line_limit.saturating_sub(bytes.len());
            if slice.len() > room {
                overlong = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(slice);
            }
        }
        reader.consume(take);
        if newline.is_some() {
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return Some(Line { bytes, overlong });
        }
    }
}

/// Decode exactly 32 hex bytes, accepting either letter case.
fn decode_hex(text: &[u8], out: &mut [u8; 32]) -> bool {
    if text.len() != 64 {
        return false;
    }
    for (index, &[high_byte, low_byte]) in text.as_chunks::<2>().0.iter().enumerate() {
        let (Some(high), Some(low)) = (hex_digit(high_byte), hex_digit(low_byte)) else {
            return false;
        };
        let Some(slot) = out.get_mut(index) else {
            return false;
        };
        *slot = (high << 4) | low;
    }
    true
}

fn decode_secret(text: &[u8]) -> Option<Secret> {
    // Reject odd lengths before allocating; hex pairs only.
    if !text.len().is_multiple_of(2) || text.is_empty() || text.len() > MAX_SECRET_LEN * 2 {
        return None;
    }
    let mut bytes = [0_u8; MAX_SECRET_LEN];
    for (index, &[high_byte, low_byte]) in text.as_chunks::<2>().0.iter().enumerate() {
        let (Some(high), Some(low)) = (hex_digit(high_byte), hex_digit(low_byte)) else {
            bytes.zeroize();
            return None;
        };
        let slot = bytes.get_mut(index)?;
        *slot = (high << 4) | low;
    }
    let secret = Secret::new(bytes.get(..text.len() / 2)?);
    bytes.zeroize();
    secret
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The export order for a TLS 1.3 session.
pub const EXPORT_LABEL_ORDER: [KeyLabel; 7] = [
    KeyLabel::ClientEarlyTraffic,
    KeyLabel::ClientHandshakeTraffic,
    KeyLabel::ServerHandshakeTraffic,
    KeyLabel::ServerTraffic,
    KeyLabel::ClientTraffic,
    KeyLabel::EarlyExporter,
    KeyLabel::Exporter,
];

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "parser tests use fixed vectors with infallible sizes"
)]
mod tests {
    use super::*;
    use std::io::{BufReader, Read};

    fn random(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn line(label: &str, random_byte: u8, secret: &[u8]) -> String {
        format!(
            "{label} {} {}\n",
            random(random_byte),
            crate::decode::bytes::hex_lower(secret)
        )
    }

    fn secret(n: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index).unwrap_or(0).wrapping_add(n))
            .collect()
    }

    fn entry(log: &KeyLog, byte: u8) -> Option<&KeyEntry> {
        let mut random_bytes = [0_u8; 32];
        decode_hex(random(byte).as_bytes(), &mut random_bytes).then_some(())?;
        log.get(&random_bytes)
    }

    #[test]
    fn parses_every_recognised_label() {
        let mut text = String::new();
        text.push_str(&line("CLIENT_RANDOM", 1, &secret(0, 48)));
        text.push_str(&line("CLIENT_EARLY_TRAFFIC_SECRET", 1, &secret(1, 32)));
        text.push_str(&line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", 1, &secret(2, 32)));
        text.push_str(&line("SERVER_HANDSHAKE_TRAFFIC_SECRET", 1, &secret(3, 32)));
        text.push_str(&line("CLIENT_TRAFFIC_SECRET_0", 1, &secret(4, 32)));
        text.push_str(&line("SERVER_TRAFFIC_SECRET_0", 1, &secret(5, 32)));
        text.push_str(&line("EARLY_EXPORTER_SECRET", 1, &secret(6, 32)));
        text.push_str(&line("EXPORTER_SECRET", 1, &secret(7, 32)));
        text.push_str(&line("PMS_CLIENT_RANDOM", 1, &secret(8, 48)));
        let log = KeyLog::from_bytes(text.as_bytes());
        let entry = entry(&log, 1).expect("entry");
        assert_eq!(
            entry.master.as_ref().map(Secret::as_bytes),
            Some(secret(0, 48).as_slice())
        );
        assert_eq!(
            entry.early.as_ref().map(Secret::as_bytes),
            Some(secret(1, 32).as_slice())
        );
        assert_eq!(
            entry.client_handshake.as_ref().map(Secret::as_bytes),
            Some(secret(2, 32).as_slice())
        );
        assert_eq!(
            entry.server_handshake.as_ref().map(Secret::as_bytes),
            Some(secret(3, 32).as_slice())
        );
        assert_eq!(
            entry.client_traffic.as_ref().map(Secret::as_bytes),
            Some(secret(4, 32).as_slice())
        );
        assert_eq!(
            entry.server_traffic.as_ref().map(Secret::as_bytes),
            Some(secret(5, 32).as_slice())
        );
        assert_eq!(
            entry.early_exporter.as_ref().map(Secret::as_bytes),
            Some(secret(6, 32).as_slice())
        );
        assert_eq!(
            entry.exporter.as_ref().map(Secret::as_bytes),
            Some(secret(7, 32).as_slice())
        );
        assert_eq!(
            entry.pms.as_ref().map(Secret::as_bytes),
            Some(secret(8, 48).as_slice())
        );
    }

    #[test]
    fn comments_blanks_crlf_and_case_are_accepted() {
        let text = format!(
            "# comment\r\n\r\n{} \r\n",
            line("client_handshake_traffic_secret", 2, &secret(9, 32))
                .trim_end()
                .replace(&random(2), &random(2).to_uppercase())
        );
        // Uppercase hex and lowercase label.
        let log = KeyLog::from_bytes(text.as_bytes());
        let entry = entry(&log, 2).expect("entry");
        assert!(entry.client_handshake.is_some());
        assert_eq!(log.skipped(), 0);
    }

    #[test]
    fn leading_blank_rejects_the_line() {
        let text = format!(
            " {}",
            line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", 3, &secret(1, 32))
        );
        let log = KeyLog::from_bytes(text.as_bytes());
        assert!(log.is_empty());
        assert_eq!(log.skipped(), 1);
    }

    #[test]
    fn trailing_whitespace_and_extra_tokens_are_ignored() {
        let text = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}   extra\n",
            random(4),
            crate::decode::bytes::hex_lower(&secret(1, 32))
        );
        let log = KeyLog::from_bytes(text.as_bytes());
        assert!(entry(&log, 4).is_some_and(|entry| entry.client_handshake.is_some()));
    }

    #[test]
    fn no_final_newline_is_accepted() {
        let text = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}",
            random(5),
            crate::decode::bytes::hex_lower(&secret(1, 32))
        );
        let log = KeyLog::from_bytes(text.as_bytes());
        assert!(entry(&log, 5).is_some_and(|entry| entry.client_handshake.is_some()));
    }

    #[test]
    fn sha384_traffic_secret_length_is_accepted() {
        let text = format!(
            "SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            random(14),
            crate::decode::bytes::hex_lower(&secret(1, 48))
        );
        let log = KeyLog::from_bytes(text.as_bytes());
        assert!(entry(&log, 14).is_some_and(|entry| entry.server_handshake.is_some()));
    }

    #[test]
    fn unknown_labels_and_bad_hex_are_skipped() {
        let text = format!(
            "FOO_SECRET {} {}\nCLIENT_HANDSHAKE_TRAFFIC_SECRET {} zz{}\n",
            random(6),
            crate::decode::bytes::hex_lower(&secret(1, 32)),
            random(7),
            "00".repeat(31)
        );
        let log = KeyLog::from_bytes(text.as_bytes());
        assert!(log.is_empty());
        assert_eq!(log.skipped(), 2);
    }

    #[test]
    fn invalid_lengths_are_ignored_and_keep_the_previous_value() {
        let good = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            random(8),
            crate::decode::bytes::hex_lower(&secret(1, 32))
        );
        let short = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            random(8),
            crate::decode::bytes::hex_lower(&secret(2, 31))
        );
        let long = format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            random(8),
            crate::decode::bytes::hex_lower(&secret(3, 33))
        );
        let log = KeyLog::from_bytes(format!("{good}{short}{long}").as_bytes());
        let entry = entry(&log, 8).expect("entry");
        assert_eq!(
            entry.client_handshake.as_ref().map(Secret::as_bytes),
            Some(secret(1, 32).as_slice())
        );
        assert_eq!(log.skipped(), 2);
    }

    #[test]
    fn the_last_valid_value_wins() {
        let first = format!(
            "SERVER_TRAFFIC_SECRET_0 {} {}\n",
            random(9),
            crate::decode::bytes::hex_lower(&secret(1, 32))
        );
        let second = format!(
            "SERVER_TRAFFIC_SECRET_0 {} {}\n",
            random(9),
            crate::decode::bytes::hex_lower(&secret(2, 32))
        );
        let log = KeyLog::from_bytes(format!("{first}{second}").as_bytes());
        let entry = entry(&log, 9).expect("entry");
        assert_eq!(
            entry.server_traffic.as_ref().map(Secret::as_bytes),
            Some(secret(2, 32).as_slice())
        );
    }

    #[test]
    fn a_bad_secret_after_a_good_one_does_not_clear_it() {
        let good = format!(
            "SERVER_TRAFFIC_SECRET_0 {} {}\n",
            random(10),
            crate::decode::bytes::hex_lower(&secret(1, 32))
        );
        let bad = format!("SERVER_TRAFFIC_SECRET_0 {} zz\n", random(10));
        let log = KeyLog::from_bytes(format!("{good}{bad}").as_bytes());
        assert!(entry(&log, 10).is_some_and(|entry| entry.server_traffic.is_some()));
    }

    #[test]
    fn a_line_cannot_read_past_the_byte_cap() {
        let mut cursor = std::io::Cursor::new(b"aaaaaaaaaaaaaaaaaaaa\nCLIENT_RANDOM x\n");
        let mut consumed = 0_usize;
        let line = read_line(&mut cursor, &mut consumed, MAX_KEYLOG_LINE, 10).expect("line result");
        assert!(line.overlong);
        assert_eq!(consumed, 10);
    }

    #[test]
    fn endless_lines_stop_at_the_byte_cap() {
        let endless = BufReader::new(
            std::io::repeat(b'A').take(u64::try_from(MAX_KEYLOG_BYTES + 1).unwrap_or(u64::MAX)),
        );
        let log = KeyLog::read(endless);
        assert!(log.truncated());
        assert!(log.bytes_read() <= MAX_KEYLOG_BYTES);
    }

    #[test]
    fn a_file_ending_at_the_cap_is_not_reported_truncated() {
        let exact = BufReader::new(
            std::io::repeat(b'#').take(u64::try_from(MAX_KEYLOG_BYTES).unwrap_or(u64::MAX)),
        );
        let log = KeyLog::read(exact);
        assert!(!log.truncated());
        assert_eq!(log.bytes_read(), MAX_KEYLOG_BYTES);
    }

    #[test]
    fn overlong_lines_are_discarded_without_losing_later_lines() {
        let mut text = vec![b'C'; MAX_KEYLOG_LINE + 10];
        text.push(b'\n');
        text.extend_from_slice(
            format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
                random(11),
                crate::decode::bytes::hex_lower(&secret(1, 32))
            )
            .as_bytes(),
        );
        let log = KeyLog::from_bytes(&text);
        assert!(entry(&log, 11).is_some_and(|entry| entry.client_handshake.is_some()));
    }

    #[test]
    fn binary_garbage_is_tolerated() {
        let mut text = vec![0_u8, 1, 2, 0xff, b'\n'];
        text.extend_from_slice(
            format!(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
                random(12),
                crate::decode::bytes::hex_lower(&secret(1, 32))
            )
            .as_bytes(),
        );
        let log = KeyLog::from_bytes(&text);
        assert!(entry(&log, 12).is_some());
    }

    #[test]
    fn a_master_only_entry_is_retained() {
        let master = format!(
            "CLIENT_RANDOM {} {}\n",
            random(13),
            crate::decode::bytes::hex_lower(&secret(1, 48))
        );
        let log = KeyLog::from_bytes(master.as_bytes());
        let entry = entry(&log, 13);
        assert!(entry.is_some_and(|entry| entry.master.is_some()));
        assert!(entry.is_some_and(|entry| entry.client_traffic.is_none()));
    }
}
