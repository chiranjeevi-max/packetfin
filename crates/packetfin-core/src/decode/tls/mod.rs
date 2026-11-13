//! Transport Layer Security records and handshake messages.
//!
//! The record layer is five octets: content type, protocol version and
//! fragment length (RFC 8446 section 5.1). A record is decoded only when the
//! whole fragment is in the segment; otherwise TCP reassembly collects the
//! rest. A payload whose first four octets are printable text is rejected so
//! the HTTP heuristic can claim it, which is how plain HTTP on 443 decodes.
//!
//! ClientHello and ServerHello follow RFC 8446 sections 4.1.2 and 4.1.3.
//! JA3 and JA4 are computed from those fields: GREASE values are excluded,
//! JA4 sorts its cipher and extension lists, and JA4's signature list keeps
//! wire order.

pub(crate) mod cipher;
pub(crate) mod keylog;
pub(crate) mod session;

pub use keylog::KeyLog;
pub(crate) use keylog::Secret;
pub use session::ExportedKey;
pub(crate) use session::{Direction, TlsFlow, TlsSecretCache};

use std::fmt::Write as _;

use md5::{Digest as _, Md5};
use sha2::Sha256;

use crate::capture::Timestamp;
use crate::decode::DecodeContext;
use crate::decode::bytes::{hex_lower, read_u16_be, read_u24_be, read_u32_be};
use crate::decode::http;
use crate::fields;
use crate::state::{ConversationKey, PduAction};
use crate::tree::{Field, Node, Range, RawField, RawSource, Value};

use self::cipher::{Suite, suite};

const RECORD_HEADER_LENGTH: usize = 5;

/// Largest TLS 1.2 record fragment (RFC 5246 section 6.2.3).
const MAX_TLS12_FRAGMENT: usize = 16_384 + 2_048;

/// Largest TLS 1.3 record fragment (RFC 8446 section 5.1).
const MAX_TLS13_FRAGMENT: usize = 16_384 + 256;

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;
const CONTENT_HEARTBEAT: u8 = 24;

const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_FINISHED: u8 = 20;
const HANDSHAKE_KEY_UPDATE: u8 = 24;

const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_SUPPORTED_GROUPS: u16 = 10;
const EXTENSION_EC_POINT_FORMATS: u16 = 11;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;
const EXTENSION_ALPN: u16 = 16;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 43;
const EXTENSION_KEY_SHARE: u16 = 51;
const EXTENSION_SESSION_TICKET: u16 = 35;
const EXTENSION_ENCRYPT_THEN_MAC: u16 = 22;

const VERSION_TLS_1_2: u16 = 0x0303;
const VERSION_TLS_1_3: u16 = 0x0304;

/// Largest handshake message the cross-record buffer retains.
const MAX_HANDSHAKE_BYTES: usize = 1024 * 1024;

/// A handshake message whose parsed data changes session state.
enum HandshakeEvent {
    ClientHello {
        client_random: [u8; 32],
        session_id: Vec<u8>,
        ticket: Option<Vec<u8>>,
        alpn: Option<String>,
        first_tls13_suite: Option<Suite>,
    },
    ServerHello {
        server_random: [u8; 32],
        suite: Option<Suite>,
        version: u16,
        session_id: Vec<u8>,
        encrypt_then_mac: bool,
        hello_retry_request: bool,
        alpn: Option<String>,
    },
    EncryptedExtensions {
        alpn: Option<String>,
    },
    NewSessionTicket {
        ticket: Vec<u8>,
    },
    Message(u8),
}

/// Whether the first TLS record's declared body is fully present.
fn first_record_fits(data: &[u8]) -> bool {
    let Some(record_version) = read_u16_be(data, 1) else {
        return false;
    };
    let Some(record_length) = read_u16_be(data, 3) else {
        return false;
    };
    let end = 5_usize.saturating_add(usize::from(record_length));
    end <= data.len() && record_version != 0
}

/// Whether a TCP payload begins with a plausible TLS record header.
///
/// TLS is also recognised on non-standard ports; this is the conservative
/// check used after the registered port decoders decline. A record's content
/// type, protocol version and fragment bound must all be valid, so arbitrary
/// payloads are not claimed.
pub(crate) fn looks_like_tls(data: &[u8]) -> bool {
    let Some(content_type) = data.first().copied() else {
        return false;
    };
    if !valid_content_type(content_type) {
        return false;
    }
    let Some(version) = read_u16_be(data, 1) else {
        return false;
    };
    if !(0x0300..=VERSION_TLS_1_3).contains(&version) {
        return false;
    }
    let Some(length) = read_u16_be(data, 3) else {
        return false;
    };
    let limit = if version == VERSION_TLS_1_3 {
        16_384_usize + 256
    } else {
        16_384_usize + 2_048
    };
    usize::from(length) <= limit
}

/// Decode the TLS records carried by one TCP segment.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    // Reject a payload that begins with four printable ASCII octets:
    // that is almost certainly cleartext for another dissector.
    if data.len() > 4
        && data
            .get(..4)
            .is_some_and(|first| first.iter().all(|byte| (0x20..=0x7e).contains(byte)))
    {
        return;
    }

    // The two-pass output keeps a segment that cannot hold a complete first
    // record as plain TCP; the one-pass tree still shows the TLS segment node.
    if context.pass == crate::state::PassMode::Second && !first_record_fits(data) {
        return;
    }

    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::TLS_PROTOCOL.filter_name);
    let mut node = Node::new(&fields::TLS_PROTOCOL, Range::new(base, data.len()));
    let record_source = context.tls_record_source;
    let conversation_and_direction = context
        .transport_ports
        .and_then(|(source, destination)| context.conversation_key(source, destination));
    if let Some(conversation) = conversation_and_direction.map(|(key, _)| key)
        && let Some(stream) = context.state.tls_stream(conversation, context.quoted)
    {
        node.add_field(
            &fields::TLS_STREAM,
            Range::new(base, 0),
            Value::Uint32(stream),
        );
    }

    let mut offset = 0_usize;
    let conversation = conversation_and_direction.map(|(key, _)| key);
    if !context.quoted
        && let Some(key) = conversation
    {
        context.state.note_tls_frame(key, context.frame.file_number);
    }
    let annotated_version = (!context.quoted)
        .then(|| {
            context
                .state
                .annotation(context.frame.file_number)
                .map(|annotation| annotation.tls_version)
        })
        .flatten()
        .filter(|version| *version != 0);
    let initial_version = annotated_version.or_else(|| {
        conversation
            .filter(|_| !context.quoted)
            .and_then(|key| context.state.tls_version(key))
    });
    let mut session_version: Option<u16> = initial_version;
    let mut column: Option<u16> = None;
    let mut infos: Vec<String> = Vec::new();
    let source_port = context.transport_ports.map(|(source, _)| source);
    let mut flow = conversation
        .filter(|_| !context.quoted)
        .and_then(|key| context.state.take_tls_flow(key));
    let keylog = if context.quoted {
        None
    } else {
        context.state.keylog()
    };
    let export = !context.quoted && context.state.tls_key_export();
    let mut events: Vec<HandshakeEvent> = Vec::new();
    let mut client_plaintext: Vec<u8> = Vec::new();
    let mut server_plaintext: Vec<u8> = Vec::new();
    let mut saw_client_plaintext = false;
    let mut saw_server_plaintext = false;
    let mut handshake_pending: Option<HandshakeBuffer> = conversation_and_direction
        .filter(|_| !context.quoted)
        .and_then(|(key, direction)| {
            context
                .state
                .take_tls_handshake(key, direction, context.tcp_sequence)
        })
        .map(|(bytes, name, first_file)| HandshakeBuffer {
            bytes,
            name,
            first_file,
        });
    let mut client_app_records: Vec<(usize, usize)> = Vec::new();
    let mut server_app_records: Vec<(usize, usize)> = Vec::new();
    while offset.saturating_add(RECORD_HEADER_LENGTH) <= data.len() {
        let Some(record) = data.get(offset..) else {
            break;
        };
        let Some(content_type) = record.first().copied() else {
            break;
        };
        let Some(record_version) = read_u16_be(record, 1) else {
            break;
        };
        let Some(record_length) = read_u16_be(record, 3) else {
            break;
        };
        let record_length = usize::from(record_length);
        if !valid_content_type(content_type) {
            infos.push("Continuation Data".to_string());
            break;
        }
        let Some(record_end) = offset
            .checked_add(RECORD_HEADER_LENGTH)
            .and_then(|start| start.checked_add(record_length))
        else {
            break;
        };
        let limit = if session_version == Some(VERSION_TLS_1_3) {
            MAX_TLS13_FRAGMENT
        } else {
            MAX_TLS12_FRAGMENT
        };
        if record_length > limit {
            let record_base = base.saturating_add(offset);
            let record_field = add_record(
                &mut node,
                record,
                record_base,
                record_length.min(limit),
                "Record Layer",
                session_version,
                None,
                false,
                0,
                0,
            );
            if let Some(source) = record_source {
                record_field.set_range_source(source);
            }
            record_field.add_field(
                &fields::TLS_RECORD_LENGTH_INVALID,
                Range::new(record_base.saturating_add(3), 0),
                Value::None,
            );
            context.mark_malformed(&mut node, "Record fragment length is too large");
            if record_end > data.len() {
                break;
            }
            offset = record_end;
            continue;
        }
        if record_end > data.len() {
            // The fragment continues in a later segment; TCP reassembly joins it.
            break;
        }
        let body = data
            .get(offset.saturating_add(RECORD_HEADER_LENGTH)..record_end)
            .unwrap_or(&[]);
        let record_base = base.saturating_add(offset);
        if content_type == CONTENT_HANDSHAKE && body.is_empty() {
            // The first body octet is read before fields are added, so an
            // empty handshake record is malformed and keeps the record fields.
            let empty = add_record(
                &mut node,
                record,
                record_base,
                record_length,
                "Record Layer",
                session_version,
                None,
                false,
                0,
                0,
            );
            if let Some(source) = record_source {
                empty.set_range_source(source);
            }
            context.mark_malformed(&mut node, "Handshake record is empty");
            offset = record_end;
            continue;
        }
        if body.is_empty() {
            // An empty alert, change-cipher-spec or application-data record
            // is malformed and keeps the record header but no body fields.
            let showname = format!(
                "{} Record Layer",
                version_name(session_version.unwrap_or(record_version))
            );
            let empty = add_record(
                &mut node,
                record,
                record_base,
                record_length,
                &showname,
                session_version,
                None,
                false,
                0,
                0,
            );
            if let Some(source) = record_source {
                empty.set_range_source(source);
            }
            context.mark_malformed(&mut node, "Record body is empty");
            column = session_version;
            offset = record_end;
            continue;
        }

        let direction = source_port.and_then(|port| flow.as_ref().map(|flow| flow.direction(port)));
        let mut decrypted = None;
        if content_type != CONTENT_CHANGE_CIPHER_SPEC
            && let (Some(flow), Some(direction)) = (flow.as_mut(), direction)
        {
            let mut header = [0_u8; RECORD_HEADER_LENGTH];
            if let Some(prefix) = record.get(..RECORD_HEADER_LENGTH) {
                header.copy_from_slice(prefix);
            }
            decrypted = flow.open_record(direction, content_type, record_version, &header, body);
        }
        let inner_type = decrypted
            .as_ref()
            .map_or(content_type, |record| record.content_type);
        let padding = decrypted.as_ref().map_or(0, |record| record.padding);
        let protected = decrypted.is_some();
        if decrypted.as_ref().is_some_and(|record| record.tls13) {
            // A protected TLS 1.3 record resolves the version even when the
            // ServerHello was in an earlier segment.
            session_version = Some(VERSION_TLS_1_3);
        }
        let encrypted_without_keys = !protected
            && matches!(content_type, CONTENT_HANDSHAKE | CONTENT_ALERT)
            && direction.is_some_and(|direction| {
                flow.as_ref().is_some_and(|flow| flow.encrypted(direction))
            });
        let sequence = decrypted.as_ref().map_or(0, |record| record.sequence);
        let display_version = session_version.unwrap_or(record_version);
        let http_alpn = flow.as_ref().is_some_and(TlsFlow::http_alpn);
        let record_label = if encrypted_without_keys {
            if inner_type == CONTENT_ALERT {
                "Encrypted Alert".to_string()
            } else {
                "Encrypted Handshake Message".to_string()
            }
        } else if inner_type == CONTENT_APPLICATION_DATA && http_alpn {
            "Application Data Protocol: Hypertext Transfer Protocol".to_string()
        } else if protected && inner_type == CONTENT_APPLICATION_DATA {
            "Application Data Protocol: Application Data".to_string()
        } else {
            let continuation = inner_type == CONTENT_HANDSHAKE && handshake_pending.is_some();
            record_text(
                inner_type,
                decrypted
                    .as_ref()
                    .map_or(body, |record| record.content.as_slice()),
                continuation,
                handshake_pending.as_ref().map(|pending| pending.name),
            )
        };
        let showname = format!(
            "{} Record Layer: {record_label}",
            version_name(display_version)
        );
        let record_field = add_record(
            &mut node,
            record,
            record_base,
            record_length,
            &showname,
            session_version,
            protected.then_some(inner_type),
            protected,
            sequence,
            u8::try_from(padding).unwrap_or(u8::MAX),
        );
        if let Some(source) = record_source {
            record_field.set_range_source(source);
        }
        column = Some(session_version.unwrap_or(record_version));
        match inner_type {
            CONTENT_ALERT => {
                if encrypted_without_keys {
                    infos.push("Encrypted Alert".to_string());
                    if session_version.is_none() {
                        session_version = Some(record_version);
                    }
                    column = Some(session_version.unwrap_or(record_version));
                    offset = record_end;
                    continue;
                }
                let source = decrypted
                    .as_ref()
                    .map(|_| context.reserve_plaintext_source());
                let body_base = if source.is_some() {
                    0
                } else {
                    record_base.saturating_add(RECORD_HEADER_LENGTH)
                };
                let alert_body = decrypted
                    .as_ref()
                    .map_or(body, |record| record.content.as_slice());
                let authenticated_alert = decrypted.is_some();
                if alert_body.len() < 2 {
                    let alert = record_field.add_container(
                        &fields::TLS_ALERT_MESSAGE,
                        Range::new(body_base, alert_body.len()),
                        Some("Alert Message: Encrypted Alert".to_string()),
                    );
                    if let Some(source) = source {
                        alert.set_range_source(source);
                    }
                    infos.push("Encrypted Alert".to_string());
                } else {
                    parse_alert(record_field, alert_body, body_base, source);
                    infos.push(alert_text(alert_body));
                }
                if alert_body.first() == Some(&2)
                    && let Some(flow) = flow.as_mut()
                    && (authenticated_alert || !flow.plaintext_locked())
                {
                    flow.fatal_alert();
                }
                let close_notify = alert_body == [1, 0];
                let close_authenticated = authenticated_alert
                    || flow.as_ref().is_none_or(|flow| !flow.plaintext_locked());
                if let Some(source) = source
                    && let Some(record) = decrypted.take()
                {
                    context.set_data_source(source, record.content.into());
                }
                if close_notify
                    && close_authenticated
                    && let (Some(key), Some((_, direction))) =
                        (conversation, conversation_and_direction)
                    && let Some(info) = finish_plaintext(context, &mut node, key, direction)
                {
                    context.columns.info = Some(info);
                }
                if session_version.is_none() {
                    session_version = Some(record_version);
                }
                column = Some(session_version.unwrap_or(record_version));
            }
            CONTENT_CHANGE_CIPHER_SPEC => {
                infos.push("Change Cipher Spec".to_string());
                if let (Some(flow), Some(direction)) = (flow.as_mut(), direction) {
                    flow.ccs(direction);
                }
                if session_version.is_none() {
                    session_version = Some(record_version);
                }
                column = Some(session_version.unwrap_or(record_version));
            }
            CONTENT_APPLICATION_DATA => {
                infos.push("Application Data".to_string());
                if inner_type == CONTENT_APPLICATION_DATA
                    && let Some(direction) = direction
                {
                    let record_index = node.fields.len().saturating_sub(1);
                    match direction {
                        Direction::Client => {
                            client_app_records.push((record_index, record_base));
                        }
                        Direction::Server => {
                            server_app_records.push((record_index, record_base));
                        }
                    }
                }
                if let (Some(record), Some(direction)) = (decrypted, direction) {
                    match direction {
                        Direction::Client => {
                            saw_client_plaintext = true;
                            client_plaintext.extend_from_slice(&record.content);
                        }
                        Direction::Server => {
                            saw_server_plaintext = true;
                            server_plaintext.extend_from_slice(&record.content);
                        }
                    }
                }
                if session_version.is_none() {
                    session_version = Some(record_version);
                }
                column = Some(session_version.unwrap_or(record_version));
            }
            CONTENT_HANDSHAKE => {
                if encrypted_without_keys {
                    infos.push("Encrypted Handshake Message".to_string());
                    if session_version.is_none() {
                        session_version = Some(record_version);
                    }
                    column = Some(session_version.unwrap_or(record_version));
                    offset = record_end;
                    continue;
                }
                let source = decrypted
                    .as_ref()
                    .map(|_| context.reserve_plaintext_source());
                let body_base = if source.is_some() {
                    0
                } else {
                    record_base.saturating_add(RECORD_HEADER_LENGTH)
                };
                let decrypted_handshake = decrypted.is_some();
                let handshake_body = decrypted
                    .as_ref()
                    .map_or(body, |record| record.content.as_slice());
                decode_handshake(
                    context,
                    record_field,
                    handshake_body,
                    body_base,
                    record_base,
                    source,
                    decrypted_handshake,
                    &mut infos,
                    &mut session_version,
                    &mut column,
                    record_version,
                    &mut events,
                    &mut handshake_pending,
                );
                if let Some(source) = source
                    && let Some(record) = decrypted.take()
                {
                    context.set_data_source(source, record.content.into());
                }
                let authenticated = decrypted_handshake;
                for event in events.drain(..) {
                    process_event(
                        context,
                        &mut flow,
                        keylog.as_deref(),
                        export,
                        source_port,
                        direction,
                        &mut session_version,
                        &mut column,
                        authenticated,
                        event,
                    );
                }
            }
            CONTENT_HEARTBEAT => {
                let heartbeat_body = decrypted
                    .as_ref()
                    .map_or(body, |record| record.content.as_slice());
                let kind = heartbeat_body.first().copied().unwrap_or(0);
                let payload_length = read_u16_be(heartbeat_body, 1);
                let valid = matches!(kind, 1 | 2)
                    && payload_length.is_some_and(|length| {
                        usize::from(length).saturating_add(3) == heartbeat_body.len()
                    });
                if valid {
                    infos.push(if kind == 1 {
                        "Heartbeat Request".to_string()
                    } else {
                        "Heartbeat Response".to_string()
                    });
                } else {
                    context.mark_malformed(&mut node, "Heartbeat message is malformed");
                }
                let source = decrypted
                    .as_ref()
                    .map(|_| context.reserve_plaintext_source());
                if let Some(source) = source
                    && let Some(record) = decrypted.take()
                {
                    context.set_data_source(source, record.content.into());
                }
                if session_version.is_none() {
                    session_version = Some(record_version);
                }
                column = Some(session_version.unwrap_or(record_version));
            }
            _ => {}
        }
        offset = record_end;
    }
    // A record header with no complete fragment is reported as TLS segment
    // data (a shorter tail keeps only the protocol node).
    if data.len().saturating_sub(offset) >= RECORD_HEADER_LENGTH {
        add_partial_segment_data(
            &mut node,
            data.get(offset..).unwrap_or_default(),
            base.saturating_add(offset),
        );
    }

    let alpn_http2 = flow.as_ref().is_some_and(TlsFlow::http2_alpn);
    let alpn_http = flow
        .as_ref()
        .is_some_and(|flow| flow.http_alpn() || flow.http2_alpn());
    if !context.quoted
        && let Some(key) = conversation
    {
        if let Some(flow) = flow.take() {
            context.state.put_tls_flow(key, flow);
        }
        if session_version != initial_version
            && let Some(version) = session_version
        {
            context.state.set_tls_version(key, version);
        }
    }
    if !context.quoted
        && let Some((key, direction)) = conversation_and_direction
        && let Some(pending) = handshake_pending
    {
        context.state.put_tls_handshake(
            key,
            direction,
            context.tcp_sequence,
            pending.bytes,
            pending.name,
            pending.first_file,
        );
    }
    let protocol = column
        .or(session_version)
        .map(version_name)
        .unwrap_or("SSL");
    context.columns.protocol = Some(protocol.to_string());
    if !infos.is_empty() {
        context.columns.info = Some(infos.join(", "));
    }

    // Decrypted application data is a byte stream: record boundaries are
    // invisible to HTTP/1.x (RFC 9112 section 3). The session frames the
    // plaintext exactly like cleartext TCP, so a message split across records,
    // segments or frames completes once and decodes at its completion frame.
    let mut plaintext_info: Option<String> = None;
    let plaintext_direction = conversation_and_direction.map_or(0, |(_, direction)| direction);
    let mut client_http = alpn_http;
    if saw_client_plaintext {
        let (http, info) = decode_plaintext(
            context,
            &mut node,
            conversation,
            plaintext_direction,
            &mut client_plaintext,
            plaintext_info,
            alpn_http2,
        );
        plaintext_info = info;
        client_http |= http;
    }
    let mut server_http = alpn_http;
    if saw_server_plaintext {
        let (http, info) = decode_plaintext(
            context,
            &mut node,
            conversation,
            plaintext_direction,
            &mut server_plaintext,
            plaintext_info,
            alpn_http2,
        );
        plaintext_info = info;
        server_http |= http;
    }
    if client_http {
        annotate_app_records(
            &mut node,
            &client_app_records,
            "Hypertext Transfer Protocol",
        );
    }
    if server_http {
        annotate_app_records(
            &mut node,
            &server_app_records,
            "Hypertext Transfer Protocol",
        );
    }
    if let Some(info) = plaintext_info {
        context.columns.info = Some(info);
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Feed decrypted application bytes to the conversation's plaintext stream.
///
/// Returns whether the direction is HTTP and the Info text of every HTTP
/// message that completed in this frame.
fn decode_plaintext(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    conversation: Option<ConversationKey>,
    direction: usize,
    plaintext: &mut Vec<u8>,
    info: Option<String>,
    http2: bool,
) -> (bool, Option<String>) {
    if plaintext.is_empty() {
        return (false, info);
    }
    let Some(conversation) = conversation else {
        plaintext.clear();
        return (false, info);
    };
    let (report, http) = context.state.insert_tls_plaintext(
        conversation,
        direction,
        context.frame.number,
        plaintext,
        false,
        http2,
    );
    plaintext.clear();
    (
        http,
        decode_plaintext_actions(context, parent, report.actions, info),
    )
}

/// Finish a pending plaintext PDU at FIN or close_notify.
pub(crate) fn finish_plaintext(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    conversation: ConversationKey,
    direction: usize,
) -> Option<String> {
    let report = context
        .state
        .finish_tls_plaintext(conversation, direction, context.frame.number);
    decode_plaintext_actions(context, parent, report.actions, None)
}

/// Decode every complete HTTP PDU the plaintext framer produced.
fn decode_plaintext_actions(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    actions: Vec<PduAction>,
    mut info: Option<String>,
) -> Option<String> {
    for action in actions {
        let (ulp, data) = match action {
            PduAction::Standalone { ulp, data, .. } => (ulp, data),
            PduAction::Reassembled { pdu, .. } => (pdu.ulp, pdu.data),
            _ => continue,
        };
        if !matches!(ulp, crate::state::Ulp::Http | crate::state::Ulp::Http2) {
            continue;
        }
        let before = parent.children.len();
        let source = context.reserve_plaintext_source();
        let previous = std::mem::replace(&mut context.tls_plaintext, true);
        let previous_info = context.columns.info.take();
        if ulp == crate::state::Ulp::Http2 {
            crate::decode::http2::decode(context, parent, &data, 0);
        } else {
            http::decode(context, parent, &data, 0);
        }
        context.tls_plaintext = previous;
        let current = context.columns.info.take();
        context.columns.info = previous_info;
        if parent.children.len() > before
            && let Some(children) = parent.children.get_mut(before..)
        {
            for child in children {
                child.set_range_source(source);
            }
        }
        // Keep the decoded PDU in the data source. It shares the reassembly
        // allocation with the fields already added, so no body copy is made.
        context.set_data_source(source, data);
        if let Some(current) = current {
            info = Some(join_plaintext_info(
                info,
                current,
                ulp == crate::state::Ulp::Http2,
            ));
        }
    }
    info
}

/// Append one PDU's summary to the plaintext column.
///
/// HTTP/2 summaries carry no separators of their own, so a preface PDU and a
/// following frame PDU would otherwise read `MagicSETTINGS[0]`. HTTP/1.x
/// messages keep their existing spacing.
fn join_plaintext_info(info: Option<String>, current: String, http2: bool) -> String {
    match info {
        Some(previous) if http2 => format!("{previous}, {current}"),
        Some(previous) => format!("{previous}{current}"),
        None => current,
    }
}

/// Name the inner protocol on the records whose plaintext the HTTP decoder
/// consumed, through the generated `tls.app_data_proto` field.
fn annotate_app_records(node: &mut Node, records: &[(usize, usize)], name: &str) {
    for (index, base) in records {
        let Some(field) = node.fields.get_mut(*index) else {
            continue;
        };
        if let Some(showname) = field.showname.as_mut()
            && !showname.ends_with(name)
            && let Some(position) = showname.rfind("Application Data")
        {
            showname.truncate(position);
            showname.push_str(name);
        }
        let proto = field.add_field(
            &fields::TLS_APP_DATA_PROTO,
            Range::new(*base, 0),
            Value::String(name.to_string()),
        );
        proto.showname = Some(format!("Application Data Protocol: {name}"));
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "event handling carries the decoder context and session state it mutates"
)]
fn process_event(
    context: &mut DecodeContext<'_>,
    flow: &mut Option<TlsFlow>,
    keylog: Option<&KeyLog>,
    export: bool,
    source_port: Option<u16>,
    direction: Option<Direction>,
    session_version: &mut Option<u16>,
    column: &mut Option<u16>,
    authenticated: bool,
    event: HandshakeEvent,
) {
    let mut accepted_hrr_client_hello = false;
    if !authenticated && flow.as_ref().is_some_and(TlsFlow::plaintext_locked) {
        let allowed = match (&event, direction) {
            (HandshakeEvent::ClientHello { client_random, .. }, direction) => flow
                .as_ref()
                .is_some_and(|flow| flow.hrr_accepts_client_hello(*client_random, direction)),
            (HandshakeEvent::ServerHello { .. }, direction) => flow
                .as_ref()
                .is_some_and(|flow| flow.hrr_accepts_server_hello(direction)),
            _ => false,
        };
        if !allowed {
            // TLS 1.3 requires every post-ServerHello handshake and alert to
            // be protected. A plaintext one is spoofed or out of spec: keep
            // the decoded fields for display, but never let it change state.
            return;
        }
        accepted_hrr_client_hello = matches!(&event, HandshakeEvent::ClientHello { .. });
    }
    if accepted_hrr_client_hello && let Some(flow) = flow.as_mut() {
        flow.mark_hrr_client_hello();
    }
    match event {
        HandshakeEvent::ClientHello {
            client_random,
            session_id,
            ticket,
            alpn,
            first_tls13_suite,
        } => {
            if flow.is_none() {
                *flow = Some(TlsFlow::new(source_port.unwrap_or(0)));
            }
            let Some(flow) = flow.as_mut() else {
                return;
            };
            flow.begin_session(client_random, session_id, ticket);
            flow.set_http_alpn(alpn.as_deref());
            if let Some(suite) = first_tls13_suite
                && let Some(entry) = keylog.and_then(|log| log.get(&client_random))
            {
                let exports = flow.install_early(entry, suite, export);
                context.state.push_exported_keys(exports);
                // A 0-RTT client has negotiated TLS 1.3 for the records that
                // follow in this frame; label the CCS and early data with the
                // supported version from the ClientHello.
                if flow.has_keys() {
                    *session_version = Some(VERSION_TLS_1_3);
                    *column = Some(VERSION_TLS_1_3);
                }
            }
        }
        HandshakeEvent::ServerHello {
            server_random,
            suite,
            version,
            session_id,
            encrypt_then_mac,
            hello_retry_request,
            alpn,
        } => {
            let Some(flow) = flow.as_mut() else {
                return;
            };
            // RFC 7301 section 3.2: only the server's selection fixes the
            // application protocol; the client's offer order proves nothing.
            flow.set_selected_alpn(alpn.as_deref());
            let Some(session) = flow.last_session_mut() else {
                return;
            };
            if let Some(suite) = suite {
                session.set_server_hello(
                    server_random,
                    suite,
                    version,
                    session_id,
                    encrypt_then_mac,
                    hello_retry_request,
                );
            }
            *session_version = Some(version);
            *column = Some(version);
            let Some(suite) = suite else {
                return;
            };
            let client_random = flow
                .last_session()
                .map(|session| session.client_random())
                .unwrap_or([0_u8; 32]);
            let entry = keylog.and_then(|log| log.get(&client_random));
            if suite.is_tls13() {
                if let Some(entry) = entry {
                    // A key log may carry the 0-RTT secret without a suite
                    // from the ClientHello; install it now that the actual
                    // suite is known.
                    let early = flow.install_early(entry, suite, export);
                    context.state.push_exported_keys(early);
                    let exports = flow.install_tls13(entry, suite, export);
                    context.state.push_exported_keys(exports);
                }
                return;
            }
            let master = entry
                .and_then(|entry| entry.master.as_ref())
                .and_then(Secret::duplicate)
                .or_else(|| {
                    flow.last_session().and_then(|session| {
                        context
                            .state
                            .cached_tls_secret(session.session_id_for_cache())
                    })
                })
                .or_else(|| {
                    flow.last_session().and_then(|session| {
                        session
                            .ticket()
                            .and_then(|ticket| context.state.cached_tls_secret(ticket))
                    })
                });
            let Some(master) = master else {
                return;
            };
            let exports = flow.install_master_secret(master, suite, &server_random, export);
            context.state.push_exported_keys(exports);
            let Some(session) = flow.last_session() else {
                return;
            };
            if let Some(master) = session.master_secret().and_then(Secret::duplicate) {
                let id = session.session_id_for_cache().to_vec();
                context.state.cache_tls_secret(&id, &master);
            }
        }
        HandshakeEvent::EncryptedExtensions { alpn } => {
            if let Some(flow) = flow.as_mut() {
                flow.set_selected_alpn(alpn.as_deref());
            }
        }
        HandshakeEvent::NewSessionTicket { ticket } => {
            let Some(flow) = flow.as_ref() else {
                return;
            };
            let Some(session) = flow.last_session() else {
                return;
            };
            // RFC 5077 applies to TLS 1.0 and later; a session has a master
            // secret only when a pre-TLS 1.3 key block was installed, so the
            // version needs no separate test.
            if let Some(master) = session.master_secret().and_then(Secret::duplicate) {
                context.state.cache_tls_secret(&ticket, &master);
            }
        }
        HandshakeEvent::Message(message_type) => {
            if let (Some(flow), Some(direction)) = (flow.as_mut(), direction) {
                flow.on_handshake(direction, message_type);
            }
        }
    }
}

/// `tls.segment_data`, the generated field for a partial record.
///
/// The field is not filterable, so it is declared outside the registry and
/// only the detail and PDML renderers see it.
pub(crate) static TLS_SEGMENT_DATA: fields::FieldDef = fields::FieldDef {
    abbrev: "tls.segment_data",
    name: "TLS segment data",
    field_type: fields::FieldType::Bytes,
    parent: "tls",
    display: fields::Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tls.handshake.fragments`, the generated reassembled-handshake field.
///
/// The field is not filterable, so it is declared outside the registry; the
/// hexdump renderer reads its bytes.
pub(crate) static TLS_HANDSHAKE_FRAGMENTS: fields::FieldDef = fields::FieldDef {
    abbrev: "tls.handshake.fragments",
    name: "Reassembled Handshake Fragments",
    field_type: fields::FieldType::Bytes,
    parent: "tls",
    display: fields::Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// Add `tls.segment_data` for a partial record's captured bytes.
pub(crate) fn add_partial_segment_data(node: &mut Node, data: &[u8], base: usize) {
    if data.len() < RECORD_HEADER_LENGTH {
        return;
    }
    let field = node.add_field(
        &TLS_SEGMENT_DATA,
        Range::new(base, data.len()),
        Value::bytes(data.to_vec()),
    );
    field.showname = Some(format!("TLS segment data ({} bytes)", data.len()));
}

/// Add a record container and its fixed fields, returning the container.
#[expect(
    clippy::too_many_arguments,
    reason = "record fields carry wire type, inner type, protection and sequence state"
)]
fn add_record<'a>(
    node: &'a mut Node,
    record: &[u8],
    base: usize,
    record_length: usize,
    showname: &str,
    session_version: Option<u16>,
    inner_type: Option<u8>,
    protected: bool,
    sequence: u64,
    padding: u8,
) -> &'a mut Field {
    let record_field = node.add_container(
        &fields::TLS_RECORD,
        Range::new(base, RECORD_HEADER_LENGTH.saturating_add(record_length)),
        Some(showname.to_string()),
    );
    let wire_type = record.first().copied();
    if let Some(content_type) = wire_type {
        // TLS 1.3 hides the real content type behind application data, so
        // the octet is labelled as the opaque type for those records.
        let opaque =
            session_version == Some(VERSION_TLS_1_3) && content_type == CONTENT_APPLICATION_DATA;
        let def = if opaque {
            &fields::TLS_RECORD_OPAQUE_TYPE
        } else {
            &fields::TLS_RECORD_CONTENT_TYPE
        };
        let field = record_field.add_field(def, Range::new(base, 1), Value::Uint8(content_type));
        field.showname = Some(if opaque {
            format!(
                "Opaque Type: {} ({content_type})",
                content_type_name(content_type)
            )
        } else {
            format!(
                "Content Type: {} ({content_type})",
                content_type_name(content_type)
            )
        });
    }
    if let Some(version) = read_u16_be(record, 1) {
        let field = record_field.add_field(
            &fields::TLS_RECORD_VERSION,
            Range::new(base.saturating_add(1), 2),
            Value::Uint16(version),
        );
        field.showname = Some(format!(
            "Version: {} (0x{version:04x})",
            version_label(version)
        ));
    }
    if let Some(length) = read_u16_be(record, 3) {
        record_field.add_field(
            &fields::TLS_RECORD_LENGTH,
            Range::new(base.saturating_add(3), 2),
            Value::Uint16(length),
        );
    }
    if session_version == Some(VERSION_TLS_1_3)
        && wire_type == Some(CONTENT_APPLICATION_DATA)
        && let Some(inner) = inner_type
    {
        // The decrypted inner type sits at the record header position
        // (pos=base).
        let inner_field = record_field.add_field(
            &fields::TLS_RECORD_CONTENT_TYPE,
            Range::new(base, 1),
            Value::Uint8(inner),
        );
        inner_field.showname = Some(format!(
            "Content Type: {} ({inner})",
            content_type_name(inner)
        ));
    }
    if protected {
        record_field.add_field(
            &fields::TLS_RECORD_SEQUENCE_NUMBER,
            Range::new(base, 0),
            Value::Uint64(sequence),
        );
    }
    if padding > 0 {
        record_field.add_field(
            &fields::TLS_RECORD_PADDING_LENGTH,
            Range::new(base, 0),
            Value::Uint8(padding),
        );
    }
    if wire_type == Some(CONTENT_APPLICATION_DATA)
        && inner_type.is_none_or(|inner| inner == CONTENT_APPLICATION_DATA)
        && let Some(body) = record
            .get(RECORD_HEADER_LENGTH..)
            .and_then(|rest| rest.get(..record_length))
    {
        let field = record_field.add_field(
            &fields::TLS_APP_DATA,
            Range::new(base.saturating_add(RECORD_HEADER_LENGTH), body.len()),
            Value::bytes(body.to_vec()),
        );
        field.showname = Some(format!("Encrypted Application Data: {}", hex_lower(body)));
    }
    record_field
}

/// The record label that follows `... Record Layer:`.
fn record_text(
    content_type: u8,
    body: &[u8],
    continuation: bool,
    pending_name: Option<&'static str>,
) -> String {
    match content_type {
        CONTENT_HANDSHAKE => {
            if continuation {
                return format!(
                    "Handshake Protocol: {}",
                    pending_name.unwrap_or("Handshake")
                );
            }
            let message_type = body.first().copied().unwrap_or(0);
            let name = handshake_name(message_type);
            if handshake_fragment(body) {
                format!("Handshake Protocol: {name} (fragment)")
            } else {
                format!("Handshake Protocol: {name}")
            }
        }
        CONTENT_ALERT => {
            if body.len() < 2 {
                "Encrypted Alert".to_string()
            } else {
                alert_text(body)
            }
        }
        CONTENT_CHANGE_CIPHER_SPEC => "Change Cipher Spec".to_string(),
        CONTENT_APPLICATION_DATA => "Application Data".to_string(),
        CONTENT_HEARTBEAT => "Heartbeat".to_string(),
        _ => "Continuation Data".to_string(),
    }
}

/// Whether the first handshake message declares more bytes than the record.
fn handshake_fragment(body: &[u8]) -> bool {
    let Some(length) = read_u24_be(body, 1) else {
        return false;
    };
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    body.len() < 4_usize.saturating_add(length)
}

fn parse_alert(record_field: &mut Field, body: &[u8], base: usize, source: Option<u32>) {
    if body.len() < 2 {
        return;
    }
    let level = body.first().copied().unwrap_or(0);
    let description = body.get(1).copied().unwrap_or(0);
    let alert = record_field.add_container(
        &fields::TLS_ALERT_MESSAGE,
        Range::new(base, body.len()),
        Some("Alert Message".to_string()),
    );
    let level_field = alert.add_field(
        &fields::TLS_ALERT_MESSAGE_LEVEL,
        Range::new(base, 1),
        Value::Uint8(level),
    );
    level_field.showname = Some(format!("Level: {} ({level})", alert_level_name(level)));
    let desc_field = alert.add_field(
        &fields::TLS_ALERT_MESSAGE_DESC,
        Range::new(base.saturating_add(1), 1),
        Value::Uint8(description),
    );
    desc_field.showname = Some(format!(
        "Description: {} ({description})",
        alert_description(description)
    ));
    if let Some(source) = source {
        alert.set_range_source(source);
    }
}

/// An incomplete handshake message carried to the next TLS record.
struct HandshakeBuffer {
    bytes: Vec<u8>,
    name: &'static str,
    first_file: u64,
}

/// Parse the handshake messages inside one record.
///
/// Handshake messages that span records and TCP segments are reassembled
/// before parsing. The buffer is bounded by [`MAX_HANDSHAKE_BYTES`].
#[expect(
    clippy::too_many_arguments,
    reason = "handshake decoding carries record, plaintext and session-event state"
)]
fn decode_handshake(
    context: &mut DecodeContext<'_>,
    record_field: &mut Field,
    body: &[u8],
    body_base: usize,
    frame_base: usize,
    source: Option<u32>,
    plaintext: bool,
    infos: &mut Vec<String>,
    session_version: &mut Option<u16>,
    column: &mut Option<u16>,
    record_version: u16,
    events: &mut Vec<HandshakeEvent>,
    pending: &mut Option<HandshakeBuffer>,
) {
    let continuation = pending.is_some();
    let first_file = pending
        .as_ref()
        .map_or(context.frame.file_number, |buffer| buffer.first_file);
    let current_file = context.frame.file_number;
    let mut data = pending
        .take()
        .map(|buffer| buffer.bytes)
        .unwrap_or_default();
    data.extend_from_slice(body);
    if data.len() > MAX_HANDSHAKE_BYTES {
        return;
    }
    let mut offset = 0_usize;
    loop {
        if offset >= data.len() {
            return;
        }
        if data.len().saturating_sub(offset) < 4 {
            if !continuation && offset == 0 {
                infos.push("[Handshake Fragment]".to_string());
            }
            *pending = Some(HandshakeBuffer {
                bytes: data.get(offset..).unwrap_or(&[]).to_vec(),
                name: "Handshake",
                first_file: if continuation {
                    first_file
                } else {
                    current_file
                },
            });
            return;
        }
        let Some(message_type) = data.get(offset).copied() else {
            return;
        };
        let Some(length) = read_u24_be(&data, offset.saturating_add(1)) else {
            return;
        };
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        let message_start = offset.saturating_add(4);
        let Some(message_end) = message_start.checked_add(length) else {
            return;
        };
        if message_end > data.len() {
            let name = handshake_name(message_type);
            if !continuation || offset > 0 {
                let message_base = body_base.saturating_add(offset);
                let fragment = record_field.add_container(
                    &fields::TLS_HANDSHAKE,
                    Range::new(message_base, data.len().saturating_sub(offset)),
                    Some(format!("Handshake Protocol: {name} (fragment)")),
                );
                if let Some(source) = source {
                    fragment.set_range_source(source);
                }
                infos.push(format!("[{name} Fragment]"));
            }
            *pending = Some(HandshakeBuffer {
                bytes: data.get(offset..).unwrap_or(&[]).to_vec(),
                name,
                first_file: if continuation {
                    first_file
                } else {
                    current_file
                },
            });
            return;
        }
        let message = data.get(offset..message_end).unwrap_or(&[]);
        if continuation && offset == 0 {
            if context.pass == crate::state::PassMode::First {
                context
                    .state
                    .annotations_mut()
                    .link_tls_handshake_reassembled(first_file, current_file);
            }
            let field = record_field.add_field(
                &TLS_HANDSHAKE_FRAGMENTS,
                Range::new(body_base, message.len()),
                Value::bytes(message.to_vec()),
            );
            field.showname = Some(format!("Reassembled Handshake ({} bytes)", message.len()));
            if let Some(source) = source {
                field.set_range_source(source);
            }
        }
        let message_body = message.get(4..).unwrap_or(&[]);
        let hrr = message_type == HANDSHAKE_SERVER_HELLO && server_hello_is_hrr(message_body);
        let message_name = if hrr {
            "Hello Retry Request"
        } else {
            handshake_name(message_type)
        };
        let message_base = body_base.saturating_add(offset);
        let message_length = length.saturating_add(4);
        let handshake = record_field.add_container(
            &fields::TLS_HANDSHAKE,
            Range::new(
                if source.is_some() {
                    frame_base
                } else {
                    message_base
                },
                message_length,
            ),
            Some(format!("Handshake Protocol: {message_name}")),
        );
        handshake.add_field(
            &fields::TLS_HANDSHAKE_TYPE,
            Range::new(message_base, 1),
            Value::Uint8(message_type),
        );
        handshake.add_field(
            &fields::TLS_HANDSHAKE_LENGTH,
            Range::new(message_base.saturating_add(1), 3),
            Value::Uint24(u32::try_from(length).unwrap_or(u32::MAX)),
        );
        let message_body_base = message_base.saturating_add(4);
        let mut key_update_request = None;
        match message_type {
            HANDSHAKE_CLIENT_HELLO => {
                let info = parse_client_hello(handshake, message_body, message_body_base);
                let mut text = String::from("Client Hello");
                if let Some(sni) = &info.sni {
                    let _ = write!(text, " (SNI={sni})");
                }
                infos.push(text);
                if session_version.is_none()
                    && let Some(supported) = info.last_supported_version
                {
                    *column = Some(supported);
                }
                if let Some(client_random) = info.client_random {
                    events.push(HandshakeEvent::ClientHello {
                        client_random,
                        session_id: info.session_id,
                        ticket: info.ticket,
                        alpn: info.alpn,
                        first_tls13_suite: info.first_tls13_suite,
                    });
                } else {
                    events.push(HandshakeEvent::Message(message_type));
                }
            }
            HANDSHAKE_SERVER_HELLO => {
                let info = parse_server_hello(handshake, message_body, message_body_base);
                infos.push(message_name.to_string());
                if session_version.is_none() {
                    *session_version = Some(info.negotiated_version);
                    *column = Some(info.negotiated_version);
                }
                if let Some(server_random) = info.server_random {
                    events.push(HandshakeEvent::ServerHello {
                        server_random,
                        suite: info.cipher_suite.and_then(suite),
                        version: info.negotiated_version,
                        session_id: info.session_id,
                        encrypt_then_mac: info.encrypt_then_mac,
                        hello_retry_request: hrr,
                        alpn: info.alpn,
                    });
                } else {
                    events.push(HandshakeEvent::Message(message_type));
                }
            }
            HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                let alpn = parse_encrypted_extensions(handshake, message_body, message_body_base);
                infos.push(message_name.to_string());
                events.push(HandshakeEvent::EncryptedExtensions { alpn });
            }
            HANDSHAKE_NEW_SESSION_TICKET => {
                if let Some(ticket) = parse_new_session_ticket(
                    handshake,
                    message_body,
                    message_body_base,
                    *session_version,
                ) {
                    events.push(HandshakeEvent::NewSessionTicket { ticket });
                } else {
                    events.push(HandshakeEvent::Message(message_type));
                }
                infos.push(message_name.to_string());
            }
            HANDSHAKE_FINISHED => {
                if let Some(verify_data) = message_body.get(..message_body.len().min(48))
                    && !verify_data.is_empty()
                {
                    handshake.add_field(
                        &fields::TLS_HANDSHAKE_VERIFY_DATA,
                        Range::new(message_body_base, verify_data.len()),
                        Value::bytes(verify_data.to_vec()),
                    );
                }
                events.push(HandshakeEvent::Message(message_type));
                infos.push(message_name.to_string());
            }
            HANDSHAKE_KEY_UPDATE => {
                key_update_request = message_body.first().copied();
                events.push(HandshakeEvent::Message(message_type));
                infos.push(message_name.to_string());
            }
            _ => {
                events.push(HandshakeEvent::Message(message_type));
                infos.push(message_name.to_string());
                if session_version.is_none() {
                    *session_version = Some(record_version);
                    *column = Some(record_version);
                }
            }
        }
        if let Some(source) = source {
            // Fields are plaintext-relative; the container keeps the frame
            // position and carries its plaintext bytes in `Node::raw`.
            handshake.set_range_source(source);
            handshake.range = Range::new(frame_base, message_length);
            handshake.raw = Some(RawField {
                bytes: (if continuation {
                    message.to_vec()
                } else {
                    body.get(offset..message_end).unwrap_or(&[]).to_vec()
                })
                .into(),
                start: if continuation { 0 } else { offset },
                length: message_length,
                bitmask: 0,
                field_type: 1,
                source: if plaintext {
                    RawSource::Plaintext
                } else {
                    RawSource::Field
                },
            });
        }
        if let Some(request) = key_update_request {
            // Attach this generated field to the record container, beside
            // the handshake message rather than inside it. Its PDML
            // position is frame-relative while its raw array starts at the
            // plaintext body offset, so keep both in `RawField`.
            let range = if source.is_some() {
                Range::new(frame_base.saturating_add(message_start), 1)
            } else {
                Range::new(message_body_base, 1)
            };
            let field = record_field.add_field(
                &fields::TLS_HANDSHAKE_KEY_UPDATE_REQUEST,
                range,
                Value::Uint8(request),
            );
            field.raw = Some(RawField {
                bytes: vec![request].into(),
                start: message_start,
                length: 1,
                bitmask: 0,
                field_type: 4,
                source: if plaintext {
                    RawSource::Plaintext
                } else {
                    RawSource::Field
                },
            });
            field.showname = Some(if request == 0 {
                "Key Update Request: update_not_requested (0)".to_string()
            } else {
                "Key Update Request: update_requested (1)".to_string()
            });
        }
        offset = message_end;
    }
}

/// Parse a New Session Ticket body and return its ticket bytes.
fn parse_new_session_ticket(
    field: &mut Field,
    body: &[u8],
    base: usize,
    version: Option<u16>,
) -> Option<Vec<u8>> {
    let tls13 = version == Some(VERSION_TLS_1_3);
    let mut offset = 0_usize;
    if let Some(lifetime) = read_u32_be(body, 0) {
        field.add_field(
            &fields::TLS_HANDSHAKE_SESSION_TICKET_LIFETIME_HINT,
            Range::new(base, 4),
            Value::Uint32(lifetime),
        );
        offset = 4;
    }
    if tls13 {
        if let Some(age_add) = read_u32_be(body, offset) {
            field.add_field(
                &fields::TLS_HANDSHAKE_SESSION_TICKET_AGE_ADD,
                Range::new(base.saturating_add(offset), 4),
                Value::Uint32(age_add),
            );
            offset = offset.saturating_add(4);
        }
        if let Some(nonce_length) = body.get(offset).copied() {
            field.add_field(
                &fields::TLS_HANDSHAKE_SESSION_TICKET_NONCE_LENGTH,
                Range::new(base.saturating_add(offset), 1),
                Value::Uint8(nonce_length),
            );
            let nonce_start = offset.saturating_add(1);
            let nonce_end = nonce_start.saturating_add(usize::from(nonce_length));
            if let Some(nonce) = body.get(nonce_start..nonce_end) {
                field.add_field(
                    &fields::TLS_HANDSHAKE_SESSION_TICKET_NONCE,
                    Range::new(base.saturating_add(nonce_start), nonce.len()),
                    Value::bytes(nonce.to_vec()),
                );
            }
            offset = nonce_end;
        }
    }
    let length = read_u16_be(body, offset)?;
    field.add_field(
        &fields::TLS_HANDSHAKE_SESSION_TICKET_LENGTH,
        Range::new(base.saturating_add(offset), 2),
        Value::Uint16(length),
    );
    let start = offset.saturating_add(2);
    let end = start.saturating_add(usize::from(length));
    let ticket = body.get(start..end)?;
    let ticket_field = field.add_field(
        &fields::TLS_HANDSHAKE_SESSION_TICKET,
        Range::new(base.saturating_add(start), ticket.len()),
        Value::bytes(ticket.to_vec()),
    );
    ticket_field.showname = Some(format!("Session Ticket […]: {}", hex_lower(ticket)));
    Some(ticket.to_vec())
}

struct ClientHelloInfo {
    version: u16,
    last_supported_version: Option<u16>,
    max_supported_version: Option<u16>,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    sni: Option<String>,
    has_sni: bool,
    alpn: Option<String>,
    client_random: Option<[u8; 32]>,
    session_id: Vec<u8>,
    ticket: Option<Vec<u8>>,
    first_tls13_suite: Option<Suite>,
    encrypt_then_mac: bool,
}

struct ServerHelloInfo {
    negotiated_version: u16,
    server_random: Option<[u8; 32]>,
    cipher_suite: Option<u16>,
    session_id: Vec<u8>,
    encrypt_then_mac: bool,
    alpn: Option<String>,
}

/// Parse a ClientHello and add `tls.handshake.*` fields.
fn parse_client_hello(field: &mut Field, body: &[u8], base: usize) -> ClientHelloInfo {
    let mut info = ClientHelloInfo {
        version: read_u16_be(body, 0).unwrap_or(0),
        last_supported_version: None,
        max_supported_version: None,
        cipher_suites: Vec::new(),
        extensions: Vec::new(),
        groups: Vec::new(),
        formats: Vec::new(),
        signature_algorithms: Vec::new(),
        sni: None,
        has_sni: false,
        alpn: None,
        client_random: None,
        session_id: Vec::new(),
        ticket: None,
        first_tls13_suite: None,
        encrypt_then_mac: false,
    };
    if let Some(random) = body.get(2..34) {
        let mut client_random = [0_u8; 32];
        client_random.copy_from_slice(random);
        info.client_random = Some(client_random);
    }
    if let Some(version) = read_u16_be(body, 0) {
        let version_field = field.add_field(
            &fields::TLS_HANDSHAKE_VERSION,
            Range::new(base, 2),
            Value::Uint16(version),
        );
        version_field.showname = Some(format!(
            "Version: {} (0x{version:04x})",
            version_label(version)
        ));
    }
    add_random(field, body, base, false);
    let Some(session_length) = body.get(34).copied() else {
        return info;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_SESSION_ID_LENGTH,
        Range::new(base.saturating_add(34), 1),
        Value::Uint16(u16::from(session_length)),
    );
    let session_end = 35_usize.saturating_add(usize::from(session_length));
    if let Some(session) = body.get(35..session_end) {
        info.session_id = session.to_vec();
        let session_field = field.add_field(
            &fields::TLS_HANDSHAKE_SESSION_ID,
            Range::new(base.saturating_add(35), session.len()),
            Value::bytes(session.to_vec()),
        );
        session_field.showname = Some(format!("Session ID: {}", hex_lower(session)));
    }
    let Some(cipher_length) = read_u16_be(body, session_end) else {
        return info;
    };
    let cipher_length = usize::from(cipher_length);
    let cipher_start = session_end.saturating_add(2);
    field.add_field(
        &fields::TLS_HANDSHAKE_CIPHER_SUITES_LENGTH,
        Range::new(base.saturating_add(session_end), 2),
        Value::Uint16(u16::try_from(cipher_length).unwrap_or(u16::MAX)),
    );
    let cipher_end = cipher_start.saturating_add(cipher_length);
    let ciphers = body.get(cipher_start..cipher_end).unwrap_or(&[]);
    let count = ciphers.len() / 2;
    let suites = field.add_container(
        &fields::TLS_HANDSHAKE_CIPHERSUITES,
        Range::new(base.saturating_add(cipher_start), ciphers.len()),
        Some(format!(
            "Cipher Suites ({count} suite{})",
            if count == 1 { "" } else { "s" }
        )),
    );
    let mut cipher_offset = 0_usize;
    while cipher_offset.saturating_add(2) <= ciphers.len() {
        let Some(suite) = read_u16_be(ciphers, cipher_offset) else {
            break;
        };
        info.cipher_suites.push(suite);
        let suite_field = suites.add_field(
            &fields::TLS_HANDSHAKE_CIPHERSUITE,
            Range::new(
                base.saturating_add(cipher_start)
                    .saturating_add(cipher_offset),
                2,
            ),
            Value::Uint16(suite),
        );
        suite_field.showname = Some(format!(
            "Cipher Suite: {} (0x{suite:04x})",
            cipher_suite_name(suite)
        ));
        cipher_offset = cipher_offset.saturating_add(2);
    }
    info.first_tls13_suite = info
        .cipher_suites
        .iter()
        .find_map(|id| suite(*id).filter(|candidate| candidate.is_tls13()));
    let Some(compression_length) = body.get(cipher_end).copied() else {
        return info;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_COMP_METHODS_LENGTH,
        Range::new(base.saturating_add(cipher_end), 1),
        Value::Uint8(compression_length),
    );
    let compression_start = cipher_end.saturating_add(1);
    let compression_end = compression_start.saturating_add(usize::from(compression_length));
    let methods = body.get(compression_start..compression_end).unwrap_or(&[]);
    let compression = field.add_container(
        &fields::TLS_HANDSHAKE_COMP_METHODS,
        Range::new(base.saturating_add(compression_start), methods.len()),
        Some(format!(
            "Compression Methods ({} method{})",
            methods.len(),
            if methods.len() == 1 { "" } else { "s" }
        )),
    );
    let mut method_offset = 0_usize;
    while method_offset < methods.len() {
        let Some(method) = methods.get(method_offset).copied() else {
            break;
        };
        let method_field = compression.add_field(
            &fields::TLS_HANDSHAKE_COMP_METHOD,
            Range::new(
                base.saturating_add(compression_start)
                    .saturating_add(method_offset),
                1,
            ),
            Value::Uint8(method),
        );
        method_field.showname = Some(format!(
            "Compression Method: {} ({method})",
            compression_method_name(method)
        ));
        method_offset = method_offset.saturating_add(1);
    }
    let Some(extensions_length) = read_u16_be(body, compression_end) else {
        return info;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_LENGTH,
        Range::new(base.saturating_add(compression_end), 2),
        Value::Uint16(extensions_length),
    );
    let extensions_start = compression_end.saturating_add(2);
    let extensions_end = extensions_start.saturating_add(usize::from(extensions_length));
    let extension_data = body.get(extensions_start..extensions_end).unwrap_or(&[]);
    parse_extensions(
        field,
        extension_data,
        base.saturating_add(extensions_start),
        true,
        &mut info,
    );
    let ja4 = ja4_strings(&info);
    let ja4_field = field.add_field(
        &fields::TLS_HANDSHAKE_JA4,
        Range::new(base, 0),
        Value::String(ja4.0.clone()),
    );
    ja4_field.generated = true;
    ja4_field.showname = Some(format!("JA4: {}", ja4.0));
    let ja4_r_field = field.add_field(
        &fields::TLS_HANDSHAKE_JA4_R,
        Range::new(base, 0),
        Value::String(ja4.1.clone()),
    );
    ja4_r_field.generated = true;
    ja4_r_field.showname = Some(format!("JA4_r: {}", ja4.1));
    let ja3 = ja3_string(&info);
    let ja3_field = field.add_field(
        &fields::TLS_HANDSHAKE_JA3_FULL,
        Range::new(base, 0),
        Value::String(ja3.clone()),
    );
    ja3_field.generated = true;
    ja3_field.showname = Some(format!("JA3 Fullstring: {ja3}"));
    let hash = md5_hex(&ja3);
    let ja3_hash = field.add_field(
        &fields::TLS_HANDSHAKE_JA3,
        Range::new(base, 0),
        Value::String(hash.clone()),
    );
    ja3_hash.generated = true;
    ja3_hash.showname = Some(format!("JA3: {hash}"));
    info
}

/// The SHA-256("HelloRetryRequest") magic that a HelloRetryRequest uses as
/// its random value (RFC 8446 section 4.1.3).
const HELLO_RETRY_REQUEST_MAGIC: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn server_hello_is_hrr(body: &[u8]) -> bool {
    body.get(2..34)
        .is_some_and(|random| random == HELLO_RETRY_REQUEST_MAGIC)
}

/// The supported_versions extension value of a ServerHello, when present.
fn server_hello_supported_version(body: &[u8]) -> Option<u16> {
    let legacy = read_u16_be(body, 0)?;
    if legacy != VERSION_TLS_1_2 {
        return None;
    }
    let session_length = usize::from(*body.get(34)?);
    let mut offset = 35_usize.saturating_add(session_length);
    offset = offset.checked_add(2)?.checked_add(1)?;
    let extensions_length = read_u16_be(body, offset)?;
    offset = offset.checked_add(2)?;
    let end = offset.checked_add(usize::from(extensions_length))?;
    let data = body.get(offset..end)?;
    let mut position = 0_usize;
    while position.saturating_add(4) <= data.len() {
        let kind = read_u16_be(data, position)?;
        let length = usize::from(read_u16_be(data, position.checked_add(2)?)?);
        let value_start = position.checked_add(4)?;
        let value_end = value_start.checked_add(length)?;
        if value_end > data.len() {
            break;
        }
        if kind == EXTENSION_SUPPORTED_VERSIONS && length == 2 {
            return read_u16_be(data, value_start);
        }
        position = value_end;
    }
    None
}

/// Parse a TLS 1.3 EncryptedExtensions and return its ALPN selection.
///
/// The body is a two-octet extension-vector length followed by the same
/// extension encoding a hello carries (RFC 8446 section 4.3.1).
fn parse_encrypted_extensions(field: &mut Field, body: &[u8], base: usize) -> Option<String> {
    let length = read_u16_be(body, 0)?;
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_LENGTH,
        Range::new(base, 2),
        Value::Uint16(length),
    );
    let start = 2_usize;
    let end = start.checked_add(usize::from(length))?;
    let data = body.get(start..end)?;
    let mut info = ClientHelloInfo {
        version: 0,
        last_supported_version: None,
        max_supported_version: None,
        cipher_suites: Vec::new(),
        extensions: Vec::new(),
        groups: Vec::new(),
        formats: Vec::new(),
        signature_algorithms: Vec::new(),
        sni: None,
        has_sni: false,
        alpn: None,
        client_random: None,
        session_id: Vec::new(),
        ticket: None,
        first_tls13_suite: None,
        encrypt_then_mac: false,
    };
    parse_extensions(field, data, base.saturating_add(start), false, &mut info);
    info.alpn
}

/// Parse a ServerHello and add `tls.handshake.*` fields.
fn parse_server_hello(field: &mut Field, body: &[u8], base: usize) -> ServerHelloInfo {
    let mut negotiated = read_u16_be(body, 0).unwrap_or(0);
    let legacy = negotiated;
    let hrr = server_hello_is_hrr(body);
    if legacy == VERSION_TLS_1_2
        && let Some(supported) = server_hello_supported_version(body)
    {
        negotiated = supported;
    }
    let mut cipher_suite = 0_u16;
    let mut extensions = Vec::new();
    let mut server_random = None;
    let mut session_id = Vec::new();
    let mut encrypt_then_mac = false;
    let mut alpn = None;
    if let Some(random) = body.get(2..34) {
        let mut parsed = [0_u8; 32];
        parsed.copy_from_slice(random);
        server_random = Some(parsed);
    }
    if let Some(version) = read_u16_be(body, 0) {
        let version_field = field.add_field(
            &fields::TLS_HANDSHAKE_VERSION,
            Range::new(base, 2),
            Value::Uint16(version),
        );
        version_field.showname = Some(format!(
            "Version: {} (0x{version:04x})",
            version_label(version)
        ));
    }
    // A TLS 1.3 ServerHello and a HelloRetryRequest omit the random time and
    // trailing random bytes; only the 32-octet random field remains.
    add_random(field, body, base, hrr || negotiated == VERSION_TLS_1_3);
    let Some(session_length) = body.get(34).copied() else {
        return ServerHelloInfo {
            negotiated_version: negotiated,
            server_random,
            cipher_suite: Some(cipher_suite),
            session_id,
            encrypt_then_mac,
            alpn: None,
        };
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_SESSION_ID_LENGTH,
        Range::new(base.saturating_add(34), 1),
        Value::Uint16(u16::from(session_length)),
    );
    let session_end = 35_usize.saturating_add(usize::from(session_length));
    if let Some(session) = body.get(35..session_end) {
        session_id = session.to_vec();
        let session_field = field.add_field(
            &fields::TLS_HANDSHAKE_SESSION_ID,
            Range::new(base.saturating_add(35), session.len()),
            Value::bytes(session.to_vec()),
        );
        session_field.showname = Some(format!("Session ID: {}", hex_lower(session)));
    }
    if let Some(suite) = read_u16_be(body, session_end) {
        cipher_suite = suite;
        let suite_field = field.add_field(
            &fields::TLS_HANDSHAKE_CIPHERSUITE,
            Range::new(base.saturating_add(session_end), 2),
            Value::Uint16(suite),
        );
        suite_field.showname = Some(format!(
            "Cipher Suite: {} (0x{suite:04x})",
            cipher_suite_name(suite)
        ));
    }
    let compression_offset = session_end.saturating_add(2);
    if let Some(compression) = body.get(compression_offset).copied() {
        let method = field.add_field(
            &fields::TLS_HANDSHAKE_COMP_METHOD,
            Range::new(base.saturating_add(compression_offset), 1),
            Value::Uint8(compression),
        );
        method.showname = Some(format!(
            "Compression Method: {} ({compression})",
            compression_method_name(compression)
        ));
    }
    let extensions_offset = compression_offset.saturating_add(1);
    if let Some(extensions_length) = read_u16_be(body, extensions_offset) {
        field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_LENGTH,
            Range::new(base.saturating_add(extensions_offset), 2),
            Value::Uint16(extensions_length),
        );
        let start = extensions_offset.saturating_add(2);
        let end = start.saturating_add(usize::from(extensions_length));
        let extension_data = body.get(start..end).unwrap_or(&[]);
        let mut hello = ClientHelloInfo {
            version: negotiated,
            last_supported_version: None,
            max_supported_version: None,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            groups: Vec::new(),
            formats: Vec::new(),
            signature_algorithms: Vec::new(),
            sni: None,
            has_sni: false,
            alpn: None,
            client_random: None,
            session_id: Vec::new(),
            ticket: None,
            first_tls13_suite: None,
            encrypt_then_mac: false,
        };
        parse_extensions(
            field,
            extension_data,
            base.saturating_add(start),
            false,
            &mut hello,
        );
        extensions = hello.extensions;
        encrypt_then_mac = hello.encrypt_then_mac;
        alpn = hello.alpn;
        if legacy == VERSION_TLS_1_2
            && let Some(supported) = hello.last_supported_version
        {
            negotiated = supported;
        }
    }
    let ja3s = ja3s_string(legacy, cipher_suite, &extensions);
    let full = field.add_field(
        &fields::TLS_HANDSHAKE_JA3S_FULL,
        Range::new(base, 0),
        Value::String(ja3s.clone()),
    );
    full.generated = true;
    full.showname = Some(format!("JA3S Fullstring: {ja3s}"));
    let hash = md5_hex(&ja3s);
    let hash_field = field.add_field(
        &fields::TLS_HANDSHAKE_JA3S,
        Range::new(base, 0),
        Value::String(hash.clone()),
    );
    hash_field.generated = true;
    hash_field.showname = Some(format!("JA3S: {hash}"));
    ServerHelloInfo {
        negotiated_version: negotiated,
        server_random,
        cipher_suite: Some(cipher_suite),
        session_id,
        encrypt_then_mac,
        alpn,
    }
}

/// Add the random value and, unless TLS 1.3 hides it, its time and tail.
fn add_random(field: &mut Field, body: &[u8], base: usize, skip_time: bool) {
    let Some(random) = body.get(2..34) else {
        return;
    };
    let random_field = field.add_field(
        &fields::TLS_HANDSHAKE_RANDOM,
        Range::new(base.saturating_add(2), 32),
        Value::bytes(random.to_vec()),
    );
    random_field.showname = Some(format!("Random: {}", hex_lower(random)));
    if skip_time {
        return;
    }
    if let Some(seconds) = read_u32_be(random, 0) {
        let time_field = random_field.add_field(
            &fields::TLS_HANDSHAKE_RANDOM_TIME,
            Range::new(base.saturating_add(2), 4),
            Value::AbsoluteTime(Timestamp {
                seconds: i64::from(seconds),
                nanos: 0,
            }),
        );
        time_field.showname = Some(format!(
            "GMT Unix Time: {}",
            crate::time::iso_time(i64::from(seconds), 0, "+0000")
        ));
    }
    if let Some(bytes) = random.get(4..) {
        let child = random_field.add_field(
            &fields::TLS_HANDSHAKE_RANDOM_BYTES,
            Range::new(base.saturating_add(6), bytes.len()),
            Value::bytes(bytes.to_vec()),
        );
        child.showname = Some(format!("Random Bytes: {}", hex_lower(bytes)));
    }
}

/// Parse the extension vector of a hello message.
fn parse_extensions(
    field: &mut Field,
    data: &[u8],
    base: usize,
    client: bool,
    info: &mut ClientHelloInfo,
) {
    let mut offset = 0_usize;
    while offset.saturating_add(4) <= data.len() {
        let Some(kind) = read_u16_be(data, offset) else {
            break;
        };
        let Some(length) = read_u16_be(data, offset.saturating_add(2)) else {
            break;
        };
        let length = usize::from(length);
        let extension_start = offset.saturating_add(4);
        let Some(extension_end) = extension_start.checked_add(length) else {
            break;
        };
        if extension_end > data.len() {
            break;
        }
        let extension = data.get(extension_start..extension_end).unwrap_or(&[]);
        let extension_base = base.saturating_add(extension_start);
        if !is_grease(kind) {
            info.extensions.push(kind);
        }
        let name = extension_name(kind);
        let extension_field = field.add_container(
            &fields::TLS_HANDSHAKE_EXTENSION,
            Range::new(base.saturating_add(offset), length.saturating_add(4)),
            Some(format!("Extension: {name} (len={length})")),
        );
        let type_field = extension_field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSION_TYPE,
            Range::new(base.saturating_add(offset), 2),
            Value::Uint16(kind),
        );
        type_field.showname = Some(format!("Type: {name} ({kind})"));
        extension_field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSION_LEN,
            Range::new(base.saturating_add(offset).saturating_add(2), 2),
            Value::Uint16(u16::try_from(length).unwrap_or(u16::MAX)),
        );
        if kind == EXTENSION_SESSION_TICKET && client {
            info.ticket = (!extension.is_empty()).then(|| extension.to_vec());
        }
        if kind == EXTENSION_ENCRYPT_THEN_MAC {
            info.encrypt_then_mac = true;
        }
        match kind {
            EXTENSION_SERVER_NAME if client => {
                info.has_sni = true;
                info.sni = parse_server_name(extension_field, extension, extension_base);
            }
            EXTENSION_ALPN => {
                info.alpn = parse_alpn(extension_field, extension, extension_base);
            }
            EXTENSION_SUPPORTED_VERSIONS => {
                parse_supported_versions(extension_field, extension, extension_base, client, info)
            }
            EXTENSION_SIGNATURE_ALGORITHMS => {
                parse_signature_algorithms(extension_field, extension, extension_base, info);
            }
            EXTENSION_SUPPORTED_GROUPS => {
                parse_supported_groups(extension_field, extension, extension_base, info);
            }
            EXTENSION_EC_POINT_FORMATS => {
                parse_ec_point_formats(extension_field, extension, extension_base, info);
            }
            EXTENSION_KEY_SHARE => {
                parse_key_share(extension_field, extension, extension_base, client);
            }
            _ => {
                if !extension.is_empty() {
                    let data_field = extension_field.add_field(
                        &fields::TLS_HANDSHAKE_EXTENSION_DATA,
                        Range::new(extension_base, extension.len()),
                        Value::bytes(extension.to_vec()),
                    );
                    data_field.showname = Some(format!("Data: {}", hex_lower(extension)));
                }
            }
        }
        offset = extension_end;
    }
}

fn parse_server_name(field: &mut Field, data: &[u8], base: usize) -> Option<String> {
    let list_length = read_u16_be(data, 0)?;
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_LIST_LEN,
        Range::new(base, 2),
        Value::Uint16(list_length),
    );
    let mut offset = 2_usize;
    let mut name = None;
    while offset < data.len() {
        let Some(kind) = data.get(offset).copied() else {
            break;
        };
        let Some(name_length) = read_u16_be(data, offset.saturating_add(1)) else {
            break;
        };
        let name_length = usize::from(name_length);
        let start = offset.saturating_add(3);
        let Some(end) = start.checked_add(name_length) else {
            break;
        };
        if end > data.len() {
            break;
        }
        field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_TYPE,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(kind),
        );
        field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_LEN,
            Range::new(base.saturating_add(offset).saturating_add(1), 2),
            Value::Uint16(u16::try_from(name_length).unwrap_or(u16::MAX)),
        );
        let value = data.get(start..end).unwrap_or(&[]);
        let text = String::from_utf8_lossy(value).into_owned();
        field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME,
            Range::new(base.saturating_add(start), value.len()),
            Value::String(text.clone()),
        );
        if name.is_none() {
            name = Some(text);
        }
        offset = end;
    }
    name
}

fn parse_alpn(field: &mut Field, data: &[u8], base: usize) -> Option<String> {
    let length = read_u16_be(data, 0)?;
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_ALPN_LEN,
        Range::new(base, 2),
        Value::Uint16(length),
    );
    let list = field.add_container(
        &fields::TLS_HANDSHAKE_EXTENSIONS_ALPN_LIST,
        Range::new(base.saturating_add(2), usize::from(length)),
        Some("ALPN Protocol".to_string()),
    );
    // RFC 7301 section 3.1: the ProtocolNameList length bounds the names;
    // bytes after it belong to no protocol and are not read.
    let list_end = 2_usize.saturating_add(usize::from(length));
    let mut offset = 2_usize;
    let mut first = None;
    while offset < list_end {
        let Some(protocol_length) = data.get(offset).copied() else {
            break;
        };
        let protocol_length = usize::from(protocol_length);
        let start = offset.saturating_add(1);
        let Some(end) = start.checked_add(protocol_length) else {
            break;
        };
        if end > list_end || end > data.len() {
            break;
        }
        list.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_ALPN_STR_LEN,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(u8::try_from(protocol_length).unwrap_or(u8::MAX)),
        );
        let value = data.get(start..end).unwrap_or(&[]);
        let text = String::from_utf8_lossy(value).into_owned();
        list.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_ALPN_STR,
            Range::new(base.saturating_add(start), value.len()),
            Value::String(text.clone()),
        );
        if first.is_none() {
            first = Some(text);
        }
        offset = end;
    }
    first
}

fn parse_supported_versions(
    field: &mut Field,
    data: &[u8],
    base: usize,
    client: bool,
    info: &mut ClientHelloInfo,
) {
    if !client {
        if let Some(version) = read_u16_be(data, 0) {
            let version_field = field.add_field(
                &fields::TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSION,
                Range::new(base, 2),
                Value::Uint16(version),
            );
            version_field.showname = Some(format!(
                "Supported Version: {} (0x{version:04x})",
                version_label(version)
            ));
            // The negotiated-version scan only reads a two-octet
            // supported_versions extension.
            if data.len() == 2 {
                info.last_supported_version = Some(version);
            }
        }
        return;
    }
    let Some(length) = data.first().copied() else {
        return;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSIONS_LEN,
        Range::new(base, 1),
        Value::Uint8(length),
    );
    let mut offset = 1_usize;
    let mut last = None;
    let mut max = None;
    while offset.saturating_add(2) <= data.len() {
        let Some(version) = read_u16_be(data, offset) else {
            break;
        };
        if !is_grease(version) {
            max = Some(max.map_or(version, |current: u16| current.max(version)));
        }
        let version_field = field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSION,
            Range::new(base.saturating_add(offset), 2),
            Value::Uint16(version),
        );
        version_field.showname = Some(format!(
            "Supported Version: {} (0x{version:04x})",
            version_label(version)
        ));
        last = Some(version);
        offset = offset.saturating_add(2);
    }
    info.last_supported_version = last;
    info.max_supported_version = max;
}

fn parse_signature_algorithms(
    field: &mut Field,
    data: &[u8],
    base: usize,
    info: &mut ClientHelloInfo,
) {
    let Some(length) = read_u16_be(data, 0) else {
        return;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_SIG_HASH_ALG_LEN,
        Range::new(base, 2),
        Value::Uint16(length),
    );
    let list = field.add_container(
        &fields::TLS_HANDSHAKE_SIG_HASH_ALGS,
        Range::new(base.saturating_add(2), usize::from(length)),
        Some("Signature Algorithms".to_string()),
    );
    let mut offset = 2_usize;
    while offset.saturating_add(2) <= data.len() {
        let Some(algorithm) = read_u16_be(data, offset) else {
            break;
        };
        if !is_grease(algorithm) {
            info.signature_algorithms.push(algorithm);
        }
        let algorithm_field = list.add_field(
            &fields::TLS_HANDSHAKE_SIG_HASH_ALG,
            Range::new(base.saturating_add(offset), 2),
            Value::Uint16(algorithm),
        );
        algorithm_field.showname = Some(format!(
            "Signature Algorithm: {} (0x{algorithm:04x})",
            signature_algorithm_name(algorithm)
        ));
        let hash = u8::try_from(algorithm >> 8).unwrap_or(0);
        let signature = u8::try_from(algorithm & 0xff).unwrap_or(0);
        let hash_field = algorithm_field.add_field(
            &fields::TLS_HANDSHAKE_SIG_HASH_HASH,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(hash),
        );
        hash_field.showname = Some(format!(
            "Signature Hash Algorithm Hash: {} ({hash})",
            signature_hash_name(hash)
        ));
        let signature_field = algorithm_field.add_field(
            &fields::TLS_HANDSHAKE_SIG_HASH_SIG,
            Range::new(base.saturating_add(offset).saturating_add(1), 1),
            Value::Uint8(signature),
        );
        signature_field.showname = Some(format!(
            "Signature Hash Algorithm Signature: {} ({signature})",
            signature_name(signature)
        ));
        offset = offset.saturating_add(2);
    }
}

fn parse_supported_groups(field: &mut Field, data: &[u8], base: usize, info: &mut ClientHelloInfo) {
    let Some(length) = read_u16_be(data, 0) else {
        return;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUPS_LENGTH,
        Range::new(base, 2),
        Value::Uint16(length),
    );
    let count = usize::from(length) / 2;
    let list = field.add_container(
        &fields::TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUPS,
        Range::new(base.saturating_add(2), usize::from(length)),
        Some(format!(
            "Supported Groups ({count} group{})",
            if count == 1 { "" } else { "s" }
        )),
    );
    let mut offset = 2_usize;
    while offset.saturating_add(2) <= data.len() {
        let Some(group) = read_u16_be(data, offset) else {
            break;
        };
        if !is_grease(group) {
            info.groups.push(group);
        }
        let group_field = list.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUP,
            Range::new(base.saturating_add(offset), 2),
            Value::Uint16(group),
        );
        group_field.showname = Some(format!(
            "Supported Group: {} ({group})",
            supported_group_name(group)
        ));
        offset = offset.saturating_add(2);
    }
}

fn parse_ec_point_formats(field: &mut Field, data: &[u8], base: usize, info: &mut ClientHelloInfo) {
    let Some(length) = data.first().copied() else {
        return;
    };
    field.add_field(
        &fields::TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMATS_LENGTH,
        Range::new(base, 1),
        Value::Uint8(length),
    );
    let list = field.add_container(
        &fields::TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMATS,
        Range::new(base.saturating_add(1), usize::from(length)),
        Some(format!("Elliptic curves point formats ({length})")),
    );
    let mut offset = 1_usize;
    while offset < data.len() && offset < 1_usize.saturating_add(usize::from(length)) {
        let Some(format) = data.get(offset).copied() else {
            break;
        };
        info.formats.push(format);
        let format_field = list.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMAT,
            Range::new(base.saturating_add(offset), 1),
            Value::Uint8(format),
        );
        format_field.showname = Some(format!(
            "EC point format: {} ({format})",
            ec_point_format_name(format)
        ));
        offset = offset.saturating_add(1);
    }
}

fn parse_key_share(field: &mut Field, data: &[u8], base: usize, client: bool) {
    if client {
        let Some(length) = read_u16_be(data, 0) else {
            return;
        };
        field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_CLIENT_LENGTH,
            Range::new(base, 2),
            Value::Uint16(length),
        );
        let mut offset = 2_usize;
        while offset.saturating_add(4) <= data.len() {
            let Some(group) = read_u16_be(data, offset) else {
                break;
            };
            let Some(exchange_length) = read_u16_be(data, offset.saturating_add(2)) else {
                break;
            };
            let exchange_length = usize::from(exchange_length);
            let start = offset.saturating_add(4);
            let Some(end) = start.checked_add(exchange_length) else {
                break;
            };
            if end > data.len() {
                break;
            }
            field.add_field(
                &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_GROUP,
                Range::new(base.saturating_add(offset), 2),
                Value::Uint16(group),
            );
            field.add_field(
                &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE_LENGTH,
                Range::new(base.saturating_add(offset).saturating_add(2), 2),
                Value::Uint16(u16::try_from(exchange_length).unwrap_or(u16::MAX)),
            );
            field.add_field(
                &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE,
                Range::new(base.saturating_add(start), exchange_length),
                Value::bytes(data.get(start..end).unwrap_or(&[]).to_vec()),
            );
            offset = end;
        }
    } else if data.len() >= 4 {
        // A normal ServerHello key_share is group + key exchange; the
        // two-octet HelloRetryRequest form selects a group instead.
        if let Some(group) = read_u16_be(data, 0) {
            field.add_field(
                &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_GROUP,
                Range::new(base, 2),
                Value::Uint16(group),
            );
        }
        if let Some(length) = read_u16_be(data, 2) {
            let start = 4_usize;
            let end = start.saturating_add(usize::from(length));
            field.add_field(
                &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE_LENGTH,
                Range::new(base.saturating_add(2), 2),
                Value::Uint16(length),
            );
            if let Some(exchange) = data.get(start..end) {
                field.add_field(
                    &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE,
                    Range::new(base.saturating_add(start), exchange.len()),
                    Value::bytes(exchange.to_vec()),
                );
            }
        }
    } else if let Some(group) = read_u16_be(data, 0) {
        field.add_field(
            &fields::TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_SELECTED_GROUP,
            Range::new(base, 2),
            Value::Uint16(group),
        );
    }
}

/// Build the JA3 full string.
fn ja3_string(info: &ClientHelloInfo) -> String {
    let ciphers: Vec<String> = info
        .cipher_suites
        .iter()
        .filter(|suite| !is_grease(**suite))
        .map(u16::to_string)
        .collect();
    let extensions: Vec<String> = info
        .extensions
        .iter()
        .filter(|kind| !is_grease(**kind))
        .map(u16::to_string)
        .collect();
    let groups: Vec<String> = info.groups.iter().map(u16::to_string).collect();
    let formats: Vec<String> = info.formats.iter().map(u8::to_string).collect();
    let mut text = format!(
        "{},{},{}",
        info.version,
        ciphers.join("-"),
        extensions.join("-")
    );
    if groups.is_empty() {
        text.push(',');
    } else {
        let _ = write!(text, ",{}", groups.join("-"));
    }
    if formats.is_empty() {
        text.push(',');
    } else {
        let _ = write!(text, ",{}", formats.join("-"));
    }
    text
}

fn ja3s_string(version: u16, cipher: u16, extensions: &[u16]) -> String {
    let extensions: Vec<String> = extensions
        .iter()
        .filter(|kind| !is_grease(**kind))
        .map(u16::to_string)
        .collect();
    format!("{version},{cipher},{}", extensions.join("-"))
}

/// Build the JA4 and JA4_r strings for a ClientHello.
fn ja4_strings(info: &ClientHelloInfo) -> (String, String) {
    let version = info.max_supported_version.unwrap_or(info.version);
    let ciphers: Vec<u16> = info
        .cipher_suites
        .iter()
        .copied()
        .filter(|suite| !is_grease(*suite))
        .collect();
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_text = sorted_ciphers
        .iter()
        .map(|suite| format!("{suite:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let cipher_hash = if cipher_text.is_empty() {
        "000000000000".to_string()
    } else {
        truncate_sha256(&cipher_text)
    };
    let extension_types: Vec<u16> = info
        .extensions
        .iter()
        .copied()
        .filter(|kind| {
            !is_grease(*kind) && *kind != EXTENSION_SERVER_NAME && *kind != EXTENSION_ALPN
        })
        .collect();
    let mut sorted_extensions = extension_types;
    sorted_extensions.sort_unstable();
    let mut extension_text = sorted_extensions
        .iter()
        .map(|kind| format!("{kind:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    if !info.signature_algorithms.is_empty() {
        let signatures = info
            .signature_algorithms
            .iter()
            .map(|algorithm| format!("{algorithm:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        if !extension_text.is_empty() {
            extension_text.push('_');
        }
        extension_text.push_str(&signatures);
    }
    let extension_hash = if extension_text.is_empty() {
        "000000000000".to_string()
    } else {
        truncate_sha256(&extension_text)
    };
    let alpn = info
        .alpn
        .as_deref()
        .map(alpn_code)
        .unwrap_or_else(|| "00".to_string());
    let mut a = String::new();
    a.push('t');
    a.push_str(ja4_version(version));
    a.push(if info.has_sni { 'd' } else { 'i' });
    let cipher_count = ciphers.len();
    let extension_count = info
        .extensions
        .iter()
        .filter(|kind| !is_grease(**kind))
        .count();
    let _ = write!(
        a,
        "{:02}{:02}{alpn}",
        cipher_count.min(99),
        extension_count.min(99)
    );
    let ja4 = format!("{a}_{cipher_hash}_{extension_hash}");
    let ja4_r = format!("{a}_{cipher_text}_{extension_text}");
    (ja4, ja4_r)
}

fn alpn_code(protocol: &str) -> String {
    let bytes = protocol.as_bytes();
    let first = bytes.first().copied().unwrap_or(0);
    let last = bytes.last().copied().unwrap_or(0);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", char::from(first), char::from(last))
    } else {
        format!("{:x}{:x}", first >> 4 & 0x0f, last & 0x0f)
    }
}

fn ja4_version(version: u16) -> &'static str {
    match version {
        0x0100 => "s1",
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    }
}

fn truncate_sha256(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let hex = hex_lower(digest.as_slice());
    hex.get(..12).unwrap_or(&hex).to_string()
}

fn md5_hex(text: &str) -> String {
    hex_lower(Md5::digest(text.as_bytes()).as_slice())
}

/// TLS GREASE values are reserved and excluded from JA3 and JA4.
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

fn valid_content_type(content_type: u8) -> bool {
    matches!(
        content_type,
        CONTENT_CHANGE_CIPHER_SPEC
            | CONTENT_ALERT
            | CONTENT_HANDSHAKE
            | CONTENT_APPLICATION_DATA
            | CONTENT_HEARTBEAT
    )
}

fn content_type_name(content_type: u8) -> &'static str {
    match content_type {
        CONTENT_CHANGE_CIPHER_SPEC => "Change Cipher Spec",
        CONTENT_ALERT => "Alert",
        CONTENT_HANDSHAKE => "Handshake",
        CONTENT_APPLICATION_DATA => "Application Data",
        CONTENT_HEARTBEAT => "Heartbeat",
        _ => "Unknown",
    }
}

/// The two spellings of a TLS version.
///
/// The short form names the protocol column and the record-layer prefix
/// (`TLSv1.2 Record Layer`); the long form follows `Version: ` and
/// `Supported Version: `, matching the version labels the expected output
/// prints (`TLS 1.2`, `SSL 3.0`).
const fn version_names(version: u16) -> (&'static str, &'static str) {
    match version {
        0x0300 => ("SSLv3", "SSL 3.0"),
        0x0301 => ("TLSv1", "TLS 1.0"),
        0x0302 => ("TLSv1.1", "TLS 1.1"),
        0x0303 => ("TLSv1.2", "TLS 1.2"),
        0x0304 => ("TLSv1.3", "TLS 1.3"),
        _ => ("TLS", "TLS"),
    }
}

/// The protocol-column and record-layer name of a version.
fn version_name(version: u16) -> &'static str {
    version_names(version).0
}

/// The field showname of a version, without its hex value.
fn version_label(version: u16) -> &'static str {
    version_names(version).1
}

fn handshake_name(message_type: u8) -> &'static str {
    match message_type {
        0 => "Hello Request",
        1 => "Client Hello",
        2 => "Server Hello",
        3 => "Hello Verify Request",
        4 => "New Session Ticket",
        5 => "End of Early Data",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        24 => "Key Update",
        _ => "Unknown",
    }
}

fn alert_text(body: &[u8]) -> String {
    let level = body.first().copied().unwrap_or(0);
    let description = body.get(1).copied().unwrap_or(0);
    format!(
        "Alert (Level: {}, Description: {})",
        alert_level_name(level),
        alert_description(description)
    )
}

fn alert_level_name(level: u8) -> &'static str {
    match level {
        1 => "Warning",
        2 => "Fatal",
        _ => "Unknown",
    }
}

fn alert_description(description: u8) -> &'static str {
    match description {
        0 => "Close Notify",
        10 => "Unexpected Message",
        20 => "Bad Record MAC",
        21 => "Decryption Failed",
        22 => "Record Overflow",
        30 => "Decompression Failure",
        40 => "Handshake Failure",
        41 => "No Certificate",
        42 => "Bad Certificate",
        43 => "Unsupported Certificate",
        44 => "Certificate Revoked",
        45 => "Certificate Expired",
        46 => "Certificate Unknown",
        47 => "Illegal Parameter",
        48 => "Unknown CA",
        49 => "Access Denied",
        50 => "Decode Error",
        51 => "Decrypt Error",
        60 => "Export Restriction",
        70 => "Protocol Version",
        71 => "Insufficient Security",
        80 => "User Canceled",
        90 => "Internal Error",
        100 => "No Renegotiation",
        109 => "Missing Extension",
        110 => "Unsupported Extension",
        111 => "Certificate Unobtainable",
        112 => "Unrecognized Name",
        113 => "Bad Certificate Status Response",
        114 => "Bad Certificate Hash Value",
        115 => "Unknown PSK Identity",
        116 => "Certificate Required",
        120 => "No Application Protocol",
        _ => "Unknown",
    }
}

fn cipher_suite_name(suite: u16) -> &'static str {
    match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        _ => "Unknown",
    }
}

fn compression_method_name(method: u8) -> &'static str {
    match method {
        0 => "null",
        1 => "deflate",
        _ => "Unknown",
    }
}

fn extension_name(kind: u16) -> &'static str {
    match kind {
        0 => "server_name",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        21 => "padding",
        22 => "encrypt_then_mac",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        49 => "post_handshake_auth",
        51 => "key_share",
        65281 => "renegotiation_info",
        _ => "Unknown",
    }
}

fn signature_hash_name(hash: u8) -> &'static str {
    match hash {
        1 => "MD5",
        2 => "SHA1",
        3 => "SHA224",
        4 => "SHA256",
        5 => "SHA384",
        6 => "SHA512",
        8 => "Intrinsic",
        _ => "Unknown",
    }
}

fn signature_name(signature: u8) -> &'static str {
    match signature {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        7 => "RSA-PSS",
        8 => "Ed448",
        _ => "Unknown",
    }
}

fn signature_algorithm_name(algorithm: u16) -> &'static str {
    match algorithm {
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        _ => "Unknown",
    }
}

fn supported_group_name(group: u16) -> &'static str {
    match group {
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x001d => "x25519",
        0x001e => "x448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        _ => "Unknown",
    }
}

fn ec_point_format_name(format: u8) -> &'static str {
    match format {
        0 => "uncompressed",
        1 => "ansiX962_compressed_prime",
        2 => "ansiX962_compressed_char2",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names_use_the_short_and_long_spellings() {
        for (version, short, long) in [
            (0x0300_u16, "SSLv3", "SSL 3.0"),
            (0x0301, "TLSv1", "TLS 1.0"),
            (0x0302, "TLSv1.1", "TLS 1.1"),
            (0x0303, "TLSv1.2", "TLS 1.2"),
            (0x0304, "TLSv1.3", "TLS 1.3"),
            (0x1234, "TLS", "TLS"),
        ] {
            assert_eq!(version_names(version), (short, long), "{version:#06x}");
        }
    }

    fn example_client_hello() -> ClientHelloInfo {
        ClientHelloInfo {
            version: 0x0303,
            last_supported_version: Some(0x0303),
            max_supported_version: Some(0x0303),
            cipher_suites: vec![0x1301, 0x1302],
            extensions: vec![0, 16, 43],
            groups: Vec::new(),
            formats: Vec::new(),
            signature_algorithms: Vec::new(),
            sni: Some("example.com".to_string()),
            has_sni: true,
            alpn: Some("h2".to_string()),
            client_random: None,
            session_id: Vec::new(),
            ticket: None,
            first_tls13_suite: None,
            encrypt_then_mac: false,
        }
    }

    #[test]
    fn encrypted_extensions_select_their_alpn_protocol() {
        let mut node = Node::new(&fields::TLS_PROTOCOL, Range::default());
        let field = node.add_field(
            &fields::TLS_HANDSHAKE_LENGTH,
            Range::default(),
            Value::Uint32(0),
        );
        // EncryptedExtensions: a 9-octet extension vector holding one ALPN
        // extension whose list names h2 (RFC 8446 section 4.3.1).
        let body = [
            0x00, 0x09, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2',
        ];
        assert_eq!(
            parse_encrypted_extensions(field, &body, 0).as_deref(),
            Some("h2")
        );
    }

    #[test]
    fn an_alpn_list_stops_at_its_declared_length() {
        let mut node = Node::new(&fields::TLS_PROTOCOL, Range::default());
        let field = node.add_field(
            &fields::TLS_HANDSHAKE_LENGTH,
            Range::default(),
            Value::Uint32(0),
        );
        // A three-octet list names h2; the trailing octets are not a second
        // protocol.
        let data = [0x00, 0x03, 0x02, b'h', b'2', 0x02, b'h', b'3'];
        assert_eq!(parse_alpn(field, &data, 0).as_deref(), Some("h2"));
        let list = field
            .children
            .get(1)
            .unwrap_or_else(|| unreachable!("the ALPN list container"));
        // Only h2's length and value sit inside the declared list.
        assert_eq!(list.children.len(), 2);

        let mut node = Node::new(&fields::TLS_PROTOCOL, Range::default());
        let field = node.add_field(
            &fields::TLS_HANDSHAKE_LENGTH,
            Range::default(),
            Value::Uint32(0),
        );
        // A two-octet list cannot hold the two-octet name that starts at its
        // last octet, so the crossing name is not a protocol at all.
        let data = [0x00, 0x02, 0x02, b'h', b'2'];
        assert_eq!(parse_alpn(field, &data, 0), None);
    }

    #[test]
    fn http2_plaintext_summaries_keep_their_separator() {
        assert_eq!(
            join_plaintext_info(Some("Magic".to_string()), "SETTINGS[0]".to_string(), true),
            "Magic, SETTINGS[0]"
        );
        assert_eq!(
            join_plaintext_info(Some("GET / ".to_string()), "HTTP/1.1".to_string(), false),
            "GET / HTTP/1.1"
        );
    }

    #[test]
    fn ja3_and_ja4_match_the_published_vectors() {
        let info = example_client_hello();
        let ja3 = ja3_string(&info);
        assert_eq!(ja3, "771,4865-4866,0-16-43,,");
        assert_eq!(md5_hex(&ja3), "1dae9c1bb9ff5e63c969a12a81eed58d");
        let (ja4, ja4_r) = ja4_strings(&info);
        assert_eq!(ja4, "t12d0203h2_62ed6f6ca7ad_b9a491fefe05");
        assert_eq!(ja4_r, "t12d0203h2_1301,1302_002b");
    }

    #[test]
    fn ja4_matches_the_tls13_capture_vector() {
        let mut info = example_client_hello();
        info.max_supported_version = Some(0x0304);
        info.last_supported_version = Some(0x0303);
        info.cipher_suites = vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f];
        info.extensions = vec![0, 16, 13, 10, 11, 43, 51];
        info.groups = vec![0x001d, 0x0017, 0x0018];
        info.formats = vec![0, 1, 2];
        info.signature_algorithms = vec![0x0403, 0x0804, 0x0401];
        let (ja4, ja4_r) = ja4_strings(&info);
        assert_eq!(ja4, "t13d0507h2_e133e205ac38_5e6a61e7dae5");
        assert_eq!(
            ja4_r,
            "t13d0507h2_1301,1302,1303,c02b,c02f_000a,000b,000d,002b,0033_0403,0804,0401"
        );
    }

    #[test]
    fn grease_values_are_excluded_from_ja3_and_ja4() {
        let mut info = example_client_hello();
        info.cipher_suites.push(0x0a0a);
        info.extensions.push(0x1a1a);
        assert_eq!(ja3_string(&info), "771,4865-4866,0-16-43,,");
        let (ja4, _) = ja4_strings(&info);
        assert_eq!(ja4, "t12d0203h2_62ed6f6ca7ad_b9a491fefe05");
    }
}
