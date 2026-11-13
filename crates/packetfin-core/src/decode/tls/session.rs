//! TLS session, epoch and resumption state.
//!
//! One [`TlsFlow`] belongs to a TCP conversation. It keeps the bounded
//! history of handshakes seen on that conversation (a renegotiation starts a
//! new one) and the record keys of each epoch. Keys activate only at the
//! protocol's own transitions: Change Cipher Spec for TLS 1.0-1.2, and the
//! decrypted Finished messages for TLS 1.3 (RFC 5246 section 6.1, RFC 8446
//! section 4.4). No trial decryption picks a key.
//!
//! TLS 1.0, 1.1 and 1.2 master secrets may come from `CLIENT_RANDOM` or from
//! the bounded session-id/ticket cache ([`TlsSecretCache`]); TLS 1.3 traffic
//! secrets come from the key log labels. There is no key exchange here: the
//! key log is the only source.
//!
//! Key material never leaves this module except through [`ExportedKey`],
//! which is written by the binary only when `--export-tls-session-keys` is
//! enabled. Every secret is zeroized on drop; debug output redacts it.

use std::collections::VecDeque;
use std::fmt;
use std::mem::size_of;

use super::cipher::{Decrypted, KeyBlock, Protocol, RecordKeys, Suite, derive_key_block};
use super::keylog::{EXPORT_LABEL_ORDER, KeyEntry, KeyLabel, Secret};

/// Oldest handshake history kept per conversation.
pub(crate) const MAX_TLS_SESSIONS: usize = 4;

/// Most session-id or ticket secrets retained across the capture.
pub(crate) const MAX_CACHED_SECRETS: usize = 8192;

/// Largest key or ticket accepted by the cache.
const MAX_CACHE_KEY: usize = 8192;

/// Total bytes the session cache may retain.
const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;

/// Record direction within a TLS flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Client to server.
    Client,
    /// Server to client.
    Server,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }
}

/// Which epoch's keys protect a TLS 1.3 direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No encryption yet (plaintext handshake records).
    Plaintext,
    /// 0-RTT early data, client to server only.
    Early,
    /// Encrypted handshake messages.
    Handshake,
    /// Application data after Finished.
    Application,
}

/// Keys for both directions of one TLS 1.3 epoch.
#[derive(Default)]
struct Epoch {
    client: Option<RecordKeys>,
    server: Option<RecordKeys>,
}

impl Epoch {
    fn keys(&mut self, direction: Direction) -> Option<&mut RecordKeys> {
        match direction {
            Direction::Client => self.client.as_mut(),
            Direction::Server => self.server.as_mut(),
        }
    }

    fn is_empty(&self) -> bool {
        self.client.is_none() && self.server.is_none()
    }
}

/// One key-export line produced by a session.
///
/// The secret itself stays private; [`secret_bytes`](Self::secret_bytes)
/// borrows it for the single write that the binary performs.
pub struct ExportedKey {
    /// Key-log label, such as `CLIENT_HANDSHAKE_TRAFFIC_SECRET`.
    pub label: &'static str,
    /// Client random that identifies the session.
    pub client_random: [u8; 32],
    secret: Secret,
}

impl ExportedKey {
    /// The secret bytes to hex-encode.
    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }
}

impl fmt::Debug for ExportedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportedKey")
            .field("label", &self.label)
            .field("client_random", &self.client_random)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// One TLS handshake and its record-protection state.
pub(crate) struct TlsSession {
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    version: Option<u16>,
    suite: Option<Suite>,
    /// Session id from the ClientHello.
    client_session_id: Vec<u8>,
    /// Session id chosen or echoed by the ServerHello.
    server_session_id: Vec<u8>,
    /// Session ticket offered in the ClientHello.
    client_ticket: Option<Vec<u8>>,
    /// Pre-TLS 1.3 master secret.
    master: Option<Secret>,
    /// Whether the server chose Encrypt-then-MAC for a CBC suite.
    encrypt_then_mac: bool,
    /// Whether each direction has sent Change Cipher Spec.
    ccs_seen: [bool; 2],
    /// Pre-TLS 1.3 keys waiting for the direction's Change Cipher Spec.
    pending_client: Option<RecordKeys>,
    pending_server: Option<RecordKeys>,
    /// Pre-TLS 1.3 keys after Change Cipher Spec.
    client_keys: Option<RecordKeys>,
    server_keys: Option<RecordKeys>,
    early: Epoch,
    handshake: Epoch,
    application: Epoch,
    client_phase: Phase,
    server_phase: Phase,
    /// Whether 0-RTT keys were installed for this session.
    early_installed: bool,
    /// Whether the TLS 1.3 handshake/application keys were installed.
    tls13_installed: bool,
    /// Whether a ServerHello has established the session version.
    server_hello_seen: bool,
    /// Whether the last ServerHello was a HelloRetryRequest.
    hrr_pending: bool,
    /// Whether the matching second ClientHello after that HRR was accepted.
    hrr_client_hello_seen: bool,
}

impl TlsSession {
    fn new(client_random: [u8; 32], session_id: Vec<u8>, ticket: Option<Vec<u8>>) -> Self {
        Self {
            client_random,
            server_random: None,
            version: None,
            suite: None,
            client_session_id: session_id,
            server_session_id: Vec::new(),
            client_ticket: ticket,
            master: None,
            encrypt_then_mac: false,
            ccs_seen: [false; 2],
            pending_client: None,
            pending_server: None,
            client_keys: None,
            server_keys: None,
            early: Epoch::default(),
            handshake: Epoch::default(),
            application: Epoch::default(),
            client_phase: Phase::Plaintext,
            server_phase: Phase::Plaintext,
            early_installed: false,
            tls13_installed: false,
            server_hello_seen: false,
            hrr_pending: false,
            hrr_client_hello_seen: false,
        }
    }

    fn state_bytes(&self) -> usize {
        self.client_session_id.capacity()
            + self.server_session_id.capacity()
            + self.client_ticket.as_ref().map_or(0, Vec::capacity)
    }

    /// Install a TLS 1.3 traffic secret for one direction of an epoch.
    fn install_epoch(
        epoch: &mut Epoch,
        direction: Direction,
        secret: Option<&Secret>,
        suite: Suite,
    ) -> bool {
        let Some(secret) = secret else {
            return false;
        };
        let Some(copy) = secret.duplicate() else {
            return false;
        };
        let Some(keys) = RecordKeys::tls13(copy, suite) else {
            return false;
        };
        match direction {
            Direction::Client => epoch.client = Some(keys),
            Direction::Server => epoch.server = Some(keys),
        }
        true
    }

    /// Install the client's 0-RTT keys from the ClientHello.
    fn install_early(&mut self, entry: &KeyEntry, suite: Suite) -> bool {
        if self.early_installed || !suite.is_tls13() {
            return false;
        }
        if !Self::install_epoch(
            &mut self.early,
            Direction::Client,
            entry.early.as_ref(),
            suite,
        ) {
            return false;
        }
        self.early_installed = true;
        self.client_phase = Phase::Early;
        true
    }

    /// Install TLS 1.3 handshake and application keys from the key log.
    fn install_tls13(&mut self, entry: &KeyEntry, suite: Suite) -> bool {
        if self.tls13_installed || !suite.is_tls13() {
            return false;
        }
        let client_hs = Self::install_epoch(
            &mut self.handshake,
            Direction::Client,
            entry.client_handshake.as_ref(),
            suite,
        );
        let server_hs = Self::install_epoch(
            &mut self.handshake,
            Direction::Server,
            entry.server_handshake.as_ref(),
            suite,
        );
        let client_app = Self::install_epoch(
            &mut self.application,
            Direction::Client,
            entry.client_traffic.as_ref(),
            suite,
        );
        let server_app = Self::install_epoch(
            &mut self.application,
            Direction::Server,
            entry.server_traffic.as_ref(),
            suite,
        );
        if !client_hs && !server_hs && !client_app && !server_app {
            return false;
        }
        // A traffic secret without the matching handshake secret is enough to
        // decode application data; it cannot decrypt the encrypted
        // handshake flight, so that direction starts directly at the
        // application epoch.
        if client_hs {
            self.client_phase = if self.client_phase == Phase::Early {
                Phase::Early
            } else {
                Phase::Handshake
            };
        } else if client_app {
            self.client_phase = Phase::Application;
        }
        if server_hs {
            self.server_phase = Phase::Handshake;
        } else if server_app {
            self.server_phase = Phase::Application;
        }
        self.tls13_installed = true;
        true
    }

    /// Apply a decrypted handshake message to the epoch state.
    fn on_handshake(&mut self, direction: Direction, message_type: u8) {
        if self.version != Some(0x0304) && !self.tls13_installed {
            return;
        }
        match message_type {
            5 => {
                // EndOfEarlyData: encrypted with handshake keys; client early
                // data is over.
                if direction == Direction::Client && self.client_phase == Phase::Early {
                    self.client_phase = Phase::Handshake;
                }
            }
            20 => {
                // Finished: the sender's application keys take over.
                match direction {
                    Direction::Client => self.client_phase = Phase::Application,
                    Direction::Server => {
                        self.server_phase = Phase::Application;
                        if self.client_phase == Phase::Early {
                            self.client_phase = Phase::Handshake;
                        }
                    }
                }
            }
            24 => {
                // KeyUpdate advances this direction's application secret. The
                // message itself was protected with the previous key, so it
                // is only valid in the application epoch.
                let phase = match direction {
                    Direction::Client => self.client_phase,
                    Direction::Server => self.server_phase,
                };
                if phase == Phase::Application
                    && let Some(keys) = self.application.keys(direction)
                {
                    let _ = keys.key_update();
                }
            }
            _ => {}
        }
    }

    /// Decrypt one protected record; `None` keeps it opaque.
    fn open_record(
        &mut self,
        direction: Direction,
        outer_type: u8,
        record_version: u16,
        header: &[u8; 5],
        fragment: &[u8],
    ) -> Option<Decrypted> {
        // TLS 1.0-1.2: after this direction's CCS every record is protected,
        // whatever its outer content type.
        let pre13 = match direction {
            Direction::Client => self.client_keys.as_mut(),
            Direction::Server => self.server_keys.as_mut(),
        };
        if let Some(keys) = pre13 {
            return keys.open_pre13(outer_type, record_version, fragment);
        }
        // TLS 1.3: only application-data records carry protected content, and
        // only once an epoch is active.
        if outer_type != 23 {
            return None;
        }
        let epoch = match direction {
            Direction::Client => match self.client_phase {
                Phase::Plaintext => return None,
                Phase::Early => &mut self.early,
                Phase::Handshake => &mut self.handshake,
                Phase::Application => &mut self.application,
            },
            Direction::Server => match self.server_phase {
                Phase::Plaintext | Phase::Early => return None,
                Phase::Handshake => &mut self.handshake,
                Phase::Application => &mut self.application,
            },
        };
        let keys = epoch.keys(direction)?;
        keys.open_tls13(header, fragment)
    }

    fn ccs(&mut self, direction: Direction) {
        if let Some(slot) = self.ccs_seen.get_mut(direction.index()) {
            *slot = true;
        }
        match direction {
            Direction::Client => {
                if let Some(keys) = self.pending_client.take() {
                    self.client_keys = Some(keys);
                }
            }
            Direction::Server => {
                if let Some(keys) = self.pending_server.take() {
                    self.server_keys = Some(keys);
                }
            }
        }
    }

    fn encrypted(&self, direction: Direction) -> bool {
        self.ccs_seen
            .get(direction.index())
            .copied()
            .unwrap_or(false)
    }

    /// Export lines installed by the ClientHello (0-RTT only).
    fn early_exports(&self, entry: &KeyEntry) -> Vec<ExportedKey> {
        entry
            .early
            .as_ref()
            .and_then(|secret| exported(KeyLabel::ClientEarlyTraffic, self.client_random, secret))
            .into_iter()
            .collect()
    }

    /// Create export lines for this session in the fixed export order.
    fn exports(
        &self,
        entry: Option<&KeyEntry>,
        include_tls13: bool,
        include_master: bool,
    ) -> Vec<ExportedKey> {
        let mut exports = Vec::new();
        if include_master
            && let Some(master) = self.master.as_ref()
            && let Some(key) = exported(KeyLabel::ClientRandom, self.client_random, master)
        {
            exports.push(key);
        }
        if include_tls13 && let Some(entry) = entry {
            for label in EXPORT_LABEL_ORDER {
                // The early traffic secret is exported when the ClientHello
                // installs 0-RTT keys, before the rest of the session's
                // labels, so it is not repeated here.
                if label == KeyLabel::ClientEarlyTraffic {
                    continue;
                }
                let secret = match label {
                    KeyLabel::ClientEarlyTraffic => None,
                    KeyLabel::ClientHandshakeTraffic => entry.client_handshake.as_ref(),
                    KeyLabel::ServerHandshakeTraffic => entry.server_handshake.as_ref(),
                    KeyLabel::ServerTraffic => entry.server_traffic.as_ref(),
                    KeyLabel::ClientTraffic => entry.client_traffic.as_ref(),
                    KeyLabel::EarlyExporter => entry.early_exporter.as_ref(),
                    KeyLabel::Exporter => entry.exporter.as_ref(),
                    KeyLabel::ClientRandom | KeyLabel::PmsClientRandom => None,
                };
                if let Some(secret) = secret
                    && let Some(key) = exported(label, self.client_random, secret)
                {
                    exports.push(key);
                }
            }
        }
        exports
    }
}

fn exported(label: KeyLabel, client_random: [u8; 32], secret: &Secret) -> Option<ExportedKey> {
    Some(ExportedKey {
        label: label.as_str(),
        client_random,
        secret: secret.duplicate()?,
    })
}

impl fmt::Debug for TlsSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsSession")
            .field("client_random", &self.client_random)
            .field("version", &self.version)
            .field("suite", &self.suite)
            .field("master", &self.master.as_ref().map(|_| "[redacted]"))
            .field("client_phase", &self.client_phase)
            .field("server_phase", &self.server_phase)
            .finish_non_exhaustive()
    }
}

/// The handshake history of one TCP conversation.
pub(crate) struct TlsFlow {
    /// Client source port; the server direction is everything else.
    pub(crate) client_port: u16,
    sessions: Vec<TlsSession>,
    /// The client offered HTTP/1.x in ALPN; application data takes that
    /// protocol label even when the record cannot be decrypted.
    http: bool,
    /// The client offered HTTP/2 in ALPN; both application directions use
    /// the HTTP/2 framing and label.
    http2: bool,
}

impl TlsFlow {
    /// Create an empty flow whose client uses `client_port`.
    pub(crate) fn new(client_port: u16) -> Self {
        Self {
            client_port,
            sessions: Vec::new(),
            http: false,
            http2: false,
        }
    }

    /// Remember the application protocol offered in the ClientHello.
    pub(crate) fn set_http_alpn(&mut self, alpn: Option<&str>) {
        self.http = alpn.is_some_and(|protocol| {
            protocol.eq_ignore_ascii_case("h1") || protocol.eq_ignore_ascii_case("http/1.1")
        });
        self.http2 = alpn.is_some_and(|protocol| protocol.eq_ignore_ascii_case("h2"));
    }

    /// Whether the session negotiated HTTP/1.x in ALPN.
    pub(crate) fn http_alpn(&self) -> bool {
        self.http
    }

    /// Whether the session negotiated HTTP/2 in ALPN.
    ///
    /// RFC 9113 section 3.3: `h2` identifies HTTP/2 over TLS, and the
    /// negotiation fixes the framing for both directions. The server opens
    /// with SETTINGS rather than the client preface, so its first plaintext
    /// record has no marker of its own.
    pub(crate) fn http2_alpn(&self) -> bool {
        self.http2
    }

    /// Whether a TLS 1.3 ServerHello makes plaintext records state-opaque.
    pub(crate) fn plaintext_locked(&self) -> bool {
        self.sessions
            .last()
            .is_some_and(TlsSession::plaintext_locked)
    }

    /// Whether a plaintext ClientHello is the HRR continuation for this
    /// session: same client random, client direction, before the second
    /// ServerHello.
    pub(crate) fn hrr_accepts_client_hello(
        &self,
        client_random: [u8; 32],
        direction: Option<Direction>,
    ) -> bool {
        let Some(session) = self.sessions.last() else {
            return false;
        };
        direction == Some(Direction::Client)
            && session.hrr_pending()
            && !session.hrr_client_hello_seen()
            && session.client_random() == client_random
    }

    /// Whether a plaintext ServerHello may complete the HRR exchange.
    pub(crate) fn hrr_accepts_server_hello(&self, direction: Option<Direction>) -> bool {
        let Some(session) = self.sessions.last() else {
            return false;
        };
        direction == Some(Direction::Server)
            && session.hrr_pending()
            && session.hrr_client_hello_seen()
    }

    /// Record the accepted HRR continuation ClientHello.
    pub(crate) fn mark_hrr_client_hello(&mut self) {
        if let Some(session) = self.sessions.last_mut() {
            session.hrr_client_hello_seen = true;
        }
    }

    /// The direction of a segment by its source port.
    pub(crate) fn direction(&self, source_port: u16) -> Direction {
        if source_port == self.client_port {
            Direction::Client
        } else {
            Direction::Server
        }
    }

    /// Start a handshake for a ClientHello, or return the existing session
    /// when the same ClientHello was retransmitted.
    pub(crate) fn begin_session(
        &mut self,
        client_random: [u8; 32],
        session_id: Vec<u8>,
        ticket: Option<Vec<u8>>,
    ) -> Option<&mut TlsSession> {
        if self
            .sessions
            .last()
            .is_some_and(|last| last.client_random == client_random)
        {
            return self.sessions.last_mut();
        }
        if self.sessions.len() >= MAX_TLS_SESSIONS {
            self.sessions.remove(0);
        }
        self.sessions
            .push(TlsSession::new(client_random, session_id, ticket));
        self.sessions.last_mut()
    }

    fn session(&self) -> Option<&TlsSession> {
        self.sessions.last()
    }

    fn session_mut(&mut self) -> Option<&mut TlsSession> {
        self.sessions.last_mut()
    }

    /// Decrypt one record against the newest session that has keys for its
    /// direction and epoch.
    pub(crate) fn open_record(
        &mut self,
        direction: Direction,
        outer_type: u8,
        record_version: u16,
        header: &[u8; 5],
        fragment: &[u8],
    ) -> Option<Decrypted> {
        for session in self.sessions.iter_mut().rev() {
            if let Some(decrypted) =
                session.open_record(direction, outer_type, record_version, header, fragment)
            {
                return Some(decrypted);
            }
        }
        None
    }

    /// Activate the pending pre-TLS 1.3 keys for one direction at CCS.
    pub(crate) fn ccs(&mut self, direction: Direction) {
        if let Some(session) = self.session_mut() {
            session.ccs(direction);
        }
    }

    /// Whether a record in this direction is protected by CCS without keys.
    pub(crate) fn encrypted(&self, direction: Direction) -> bool {
        self.session()
            .is_some_and(|session| session.encrypted(direction))
    }

    /// Apply a decrypted handshake message to the session state.
    pub(crate) fn on_handshake(&mut self, direction: Direction, message_type: u8) {
        if let Some(session) = self.session_mut() {
            session.on_handshake(direction, message_type);
        }
    }

    /// Install 0-RTT keys and return export lines when the log carries them.
    pub(crate) fn install_early(
        &mut self,
        entry: &KeyEntry,
        suite: Suite,
        export: bool,
    ) -> Vec<ExportedKey> {
        let Some(session) = self.session_mut() else {
            return Vec::new();
        };
        if !session.install_early(entry, suite) || !export {
            return Vec::new();
        }
        session.early_exports(entry)
    }

    /// Install TLS 1.3 handshake/application keys and return export lines.
    pub(crate) fn install_tls13(
        &mut self,
        entry: &KeyEntry,
        suite: Suite,
        export: bool,
    ) -> Vec<ExportedKey> {
        let Some(session) = self.session_mut() else {
            return Vec::new();
        };
        if !session.install_tls13(entry, suite) || !export {
            return Vec::new();
        }
        session.exports(Some(entry), true, false)
    }

    /// Install a pre-TLS 1.3 master secret and derive the pending key block.
    ///
    /// The negotiated version set by the ServerHello selects the PRF and the
    /// key-block layout (RFC 2246 section 6.3, RFC 5246 section 6.3). A suite
    /// that the version cannot protect, or the absence of a ServerHello,
    /// installs nothing: the records stay opaque.
    pub(crate) fn install_master_secret(
        &mut self,
        master: Secret,
        suite: Suite,
        server_random: &[u8; 32],
        export: bool,
    ) -> Vec<ExportedKey> {
        let Some(session) = self.session_mut() else {
            return Vec::new();
        };
        if session.master.is_some() {
            return Vec::new();
        }
        let Some(protocol) = session.version.and_then(Protocol::from_version) else {
            return Vec::new();
        };
        let Some(block) = derive_key_block(
            master.as_bytes(),
            &session.client_random,
            server_random,
            suite,
            protocol,
        ) else {
            return Vec::new();
        };
        let KeyBlock {
            client_key,
            server_key,
            client_iv,
            server_iv,
            client_mac,
            server_mac,
        } = block;
        let Some(client_pending) = RecordKeys::tls(
            protocol,
            client_key,
            client_iv,
            client_mac,
            suite,
            session.encrypt_then_mac,
        ) else {
            return Vec::new();
        };
        let Some(server_pending) = RecordKeys::tls(
            protocol,
            server_key,
            server_iv,
            server_mac,
            suite,
            session.encrypt_then_mac,
        ) else {
            return Vec::new();
        };
        session.pending_client = Some(client_pending);
        session.pending_server = Some(server_pending);
        session.master = Some(master);
        if !export {
            return Vec::new();
        }
        session.exports(None, false, true)
    }

    /// Forget every record key after a fatal alert.
    pub(crate) fn fatal_alert(&mut self) {
        for session in &mut self.sessions {
            session.pending_client = None;
            session.pending_server = None;
            session.client_keys = None;
            session.server_keys = None;
            session.early = Epoch::default();
            session.handshake = Epoch::default();
            session.application = Epoch::default();
            session.ccs_seen = [false; 2];
            session.client_phase = Phase::Plaintext;
            session.server_phase = Phase::Plaintext;
        }
    }

    /// Whether any session has decryption keys.
    pub(crate) fn has_keys(&self) -> bool {
        self.sessions.iter().any(|session| {
            session.master.is_some()
                || !session.early.is_empty()
                || !session.handshake.is_empty()
                || !session.application.is_empty()
        })
    }
}

impl crate::state::StateValue for TlsFlow {
    fn state_bytes(&self) -> usize {
        self.sessions
            .capacity()
            .saturating_mul(size_of::<TlsSession>())
            + self
                .sessions
                .iter()
                .map(TlsSession::state_bytes)
                .sum::<usize>()
    }
}

impl fmt::Debug for TlsFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsFlow")
            .field("client_port", &self.client_port)
            .field("sessions", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

/// Bounded session-id and ticket to master-secret cache.
///
/// TLS 1.2 resumption uses the first connection's master secret with a new
/// client random; the key log only carries the old `CLIENT_RANDOM` line.
/// Master secrets are therefore cached by session id and by ticket. Entries
/// are evicted oldest first, with an 8 MiB byte ceiling so a hostile ticket
/// cannot exhaust the state budget.
pub(crate) struct TlsSecretCache {
    entries: VecDeque<(Vec<u8>, Secret)>,
    bytes: usize,
}

impl TlsSecretCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
        }
    }

    fn entry_bytes(key: &[u8]) -> usize {
        key.len().saturating_add(size_of::<(Vec<u8>, Secret)>())
    }

    /// Cache a secret under an exact session id or ticket.
    pub(crate) fn insert(&mut self, key: &[u8], secret: &Secret) {
        if key.is_empty() || key.len() > MAX_CACHE_KEY {
            return;
        }
        if let Some(position) = self.entries.iter().position(|(stored, _)| stored == key)
            && let Some((_, old)) = self.entries.remove(position)
        {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(key));
            drop(old);
        }
        let Some(copy) = secret.duplicate() else {
            return;
        };
        let size = Self::entry_bytes(key);
        while (self.entries.len() >= MAX_CACHED_SECRETS
            || self.bytes.saturating_add(size) > MAX_CACHE_BYTES)
            && let Some((old_key, old_secret)) = self.entries.pop_front()
        {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&old_key));
            drop(old_secret);
        }
        self.bytes = self.bytes.saturating_add(size);
        self.entries.push_back((key.to_vec(), copy));
    }

    /// Look up a session id or ticket.
    pub(crate) fn get(&self, key: &[u8]) -> Option<&Secret> {
        if key.is_empty() {
            return None;
        }
        self.entries
            .iter()
            .find(|(stored, _)| stored == key)
            .map(|(_, secret)| secret)
    }
}

impl fmt::Debug for TlsSecretCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsSecretCache")
            .field("entries", &self.entries.len())
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// Accessors used by the TLS record decoder.
impl TlsFlow {
    /// The last session, for ServerHello processing.
    pub(crate) fn last_session_mut(&mut self) -> Option<&mut TlsSession> {
        self.sessions.last_mut()
    }

    /// Immutable last session.
    pub(crate) fn last_session(&self) -> Option<&TlsSession> {
        self.sessions.last()
    }
}

/// Small accessors used by the ServerHello and record paths.
impl TlsSession {
    pub(crate) fn set_server_hello(
        &mut self,
        server_random: [u8; 32],
        suite: Suite,
        version: u16,
        session_id: Vec<u8>,
        encrypt_then_mac: bool,
        hello_retry_request: bool,
    ) {
        self.server_random = Some(server_random);
        self.encrypt_then_mac = encrypt_then_mac;
        self.suite = Some(suite);
        self.version = Some(version);
        self.server_session_id = session_id;
        self.server_hello_seen = true;
        self.hrr_pending = hello_retry_request;
        self.hrr_client_hello_seen = false;
    }

    /// Whether a TLS 1.3 session must reject plaintext state changes.
    fn plaintext_locked(&self) -> bool {
        self.server_hello_seen && self.version == Some(0x0304)
    }

    fn hrr_pending(&self) -> bool {
        self.hrr_pending
    }

    fn hrr_client_hello_seen(&self) -> bool {
        self.hrr_client_hello_seen
    }

    pub(crate) fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    pub(crate) fn session_id_for_cache(&self) -> &[u8] {
        if self.server_session_id.is_empty() {
            &self.client_session_id
        } else {
            &self.server_session_id
        }
    }

    pub(crate) fn ticket(&self) -> Option<&[u8]> {
        self.client_ticket.as_deref()
    }

    pub(crate) fn master_secret(&self) -> Option<&Secret> {
        self.master.as_ref()
    }
}
