//! Hypertext Transfer Protocol version 1.
//!
//! The parser reads a request or status line, a bounded header block and a
//! message body (RFC 7230 sections 3, 3.3.2 and 4.1).
//!
//! A response matches the conversation's most recent request, even when that
//! request already carries a final response, so a pipelined capture
//! attributes the second response to the wrong request. That association
//! drives `http.request_in` and `http.time` and does not follow RFC 7230
//! response ordering. `http.response_in` points forward, so the recording
//! pass stores it as an annotation for the output pass.
//!
//! TCP reassembly hands over complete messages, so bodies may span segments.
//! A response without a length delimiter arrives only when the direction's
//! FIN ends it. Printable trailing bytes that cannot begin a message become
//! `Continuation` file data, which `--export-objects` may export as a
//! continuation object named from the preceding request.

use crate::decode::DecodeContext;
use crate::export::ObjectName;
use crate::fields;
use crate::http_syntax::{
    Answer, BodyPlan, ChunkScanner, ChunkStep, Framing, HeaderBudget, HeaderLine, StartLine,
    continuation_at, next_line, parse_header_line, parse_start_line,
};
use crate::tree::{Bytes, ExpertInfo, Group, HexShowname, Node, Range, Severity, Value};

/// Unnamed start-line or chunk field, which PDML prints with `name=""`.
static UNNAMED_FIELD: fields::FieldDef = fields::FieldDef {
    abbrev: "",
    name: "",
    field_type: fields::FieldType::String,
    parent: "http",
    display: fields::Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// Unnamed chunked-body container.
static CHUNKED_BODY: fields::FieldDef = fields::FieldDef {
    abbrev: "",
    name: "",
    field_type: fields::FieldType::None,
    parent: "http",
    display: fields::Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// Whether a payload begins with a complete HTTP/1.x start line.
///
/// The check accepts the RFC 7230 token grammar and requires the URI and
/// version instead of matching a fixed method list; a rejected payload keeps
/// its existing output.
pub(crate) fn looks_like_http(data: &[u8]) -> bool {
    let Some((line, _)) = next_line(data, 0) else {
        return false;
    };
    parse_start_line(line).is_some()
}

/// Whether the payload starts with a complete HTTP/1.x start line, even when
/// the line's terminating LF has not arrived yet.
///
/// The heuristic recognises the version token in the first segment and then
/// asks TCP for the rest; a segment that stops before the version (or in
/// the middle of it) is left to the port dissector.
pub(crate) fn looks_like_http_prefix(data: &[u8]) -> bool {
    let line_end = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let mut line = data.get(..line_end).unwrap_or_default();
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped;
    }
    parse_start_line(line).is_some()
}

/// Whether a decrypted stream starts with an HTTP/1.x request or response.
///
/// TLS application data can be recognised before the whole start line
/// arrives: the first record of a split request carries the method and a
/// space, and a response carries the version. The record gets its
/// application protocol label at that point, so this check accepts that
/// permissive prefix.
pub(crate) fn looks_like_http_stream_prefix(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP/1.") {
        return true;
    }
    const METHODS: [&[u8]; 9] = [
        b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE",
    ];
    let Some(space) = data.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let method = data.get(..space).unwrap_or_default();
    space > 0 && METHODS.contains(&method)
}

/// The start line of an incomplete HTTP message, which sets the Info column
/// before the whole header block arrives.
pub(crate) fn partial_info(data: &[u8]) -> Option<String> {
    let (line, _) = next_line(data, 0)?;
    match parse_start_line(line)? {
        StartLine::Request {
            method,
            uri,
            version,
        } => Some(format!("{method} {uri} {version} ")),
        StartLine::Response {
            version,
            code,
            phrase,
        } => {
            if phrase.is_empty() {
                Some(format!("{version} {code} "))
            } else {
                Some(format!("{version} {code} {phrase} "))
            }
        }
    }
}

/// Decode every complete HTTP message in the data handed over by TCP.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    let conversation = context
        .transport_ports
        .and_then(|(source, destination)| context.conversation_key(source, destination))
        .map(|(key, _)| key);
    let mut offset = 0_usize;
    let mut info = String::new();
    let mut decoded = false;
    let export = context.objects.is_some();
    if context.http_continuation {
        // The stream classified this PDU, so the decoder must not try the
        // message grammar and then reclassify it.
        if !context.quoted {
            context.depth = context.depth.saturating_add(1);
            context
                .protocol_stack
                .push(fields::HTTP_PROTOCOL.filter_name);
            if let Some(continuation) = continuation_at(data) {
                let excess = context.http_pdu_offset > 0;
                add_continuation(
                    context,
                    parent,
                    continuation.body,
                    base.saturating_add(continuation.skip),
                    excess,
                );
                context.columns.info = Some("Continuation".to_string());
            }
            context.depth = context.depth.saturating_sub(1);
        }
        return;
    }
    while offset < data.len() {
        let message_base = base.saturating_add(offset);
        let pending_method = conversation
            .filter(|_| !context.quoted)
            .and_then(|key| context.state.http_pending_method(key));
        let response_to_head = pending_method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));
        let response_to_connect = pending_method
            .as_deref()
            .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"));
        let Some(mut message) = parse_message(
            data.get(offset..).unwrap_or(&[]),
            message_base,
            &MessageOptions {
                tls_plaintext: context.tls_plaintext,
                response_to_head,
                response_to_connect,
                export,
                fin: context.http_fin,
                source: context.pdu_bytes.as_ref().map(|bytes| (bytes, offset)),
            },
        ) else {
            break;
        };
        if !decoded {
            context.depth = context.depth.saturating_add(1);
            context
                .protocol_stack
                .push(fields::HTTP_PROTOCOL.filter_name);
        }
        decoded = true;
        let mut matched = None;
        if let Some(key) = conversation
            && !context.quoted
        {
            matched = record_state(context, key, &mut message);
        }
        if context.objects.is_some() {
            context.http_last_uri = match (&message.request, matched.as_ref()) {
                (Some(request), _) => Some(request.uri.clone()),
                (None, Some(matched)) => matched.uri.clone(),
                (None, None) => None,
            };
        }
        // Export from the shared body before the field tree references it;
        // both the export and the field value share the reassembly buffer.
        export_object(context, &message, matched.as_ref());
        add_body_fields(&mut message);
        let consumed = message.consumed;
        info.push_str(&message.info);
        parent.add_child(message.node);
        if consumed == 0 {
            break;
        }
        offset = offset.saturating_add(consumed);
    }
    if decoded {
        context.columns.info = Some(info);
        context.depth = context.depth.saturating_sub(1);
    }
}

/// A reassembly buffer and the message offset within it.
type PduSource<'a> = (&'a Bytes, usize);

/// The bytes of a body or chunk, sharing a reassembly buffer when possible.
fn shared_bytes(source: Option<PduSource<'_>>, offset: usize, data: &[u8]) -> Bytes {
    match source {
        Some((source, base)) => source.subslice(base.saturating_add(offset), data.len()),
        None => Bytes::from(data.to_vec()),
    }
}

/// The body of one message, already delimited inside the segment.
///
/// A body backed by the reassembly buffer shares that allocation: exporting
/// and the field tree both hold references to the same bytes instead of
/// copies. A body parsed from a standalone frame copies only when no shared
/// source exists.
struct Body {
    offset: usize,
    end: usize,
    bytes: Bytes,
    chunked: bool,
    /// Whether this message body is exported (not a HEAD/1xx/204/304 body or
    /// a quoted header).
    exportable: bool,
    /// Chunk records for the chunked-body container.
    chunks: Vec<Chunk>,
    /// Trailer terminator range, when the chunked body carried one.
    trailer_end: Option<usize>,
    /// Trailer lines: offset, length and text within the message data.
    trailers: Vec<(usize, usize, String)>,
}

struct Chunk {
    size: u32,
    offset: usize,
    data: Bytes,
    data_offset: usize,
    boundary_offset: usize,
    final_chunk: bool,
}

/// One decoded message before its state and body fields are added.
struct HttpMessage {
    node: Node,
    info: String,
    consumed: usize,
    request: Option<RequestMeta>,
    response_code: Option<u32>,
    /// Present when a Content-Type header was decoded, even if it is empty.
    content_type: Option<String>,
    /// Present when a Content-Encoding header was decoded, even if empty.
    content_encoding: Option<String>,
    body: Option<Body>,
}

struct RequestMeta {
    uri: String,
    full_uri: Option<String>,
    method: String,
}

/// Options controlling one message parse.
struct MessageOptions<'a> {
    tls_plaintext: bool,
    response_to_head: bool,
    response_to_connect: bool,
    export: bool,
    fin: bool,
    source: Option<PduSource<'a>>,
}

/// Parse one message, or return `None` when it does not fit the segment.
fn parse_message(data: &[u8], base: usize, options: &MessageOptions<'_>) -> Option<HttpMessage> {
    let tls_plaintext = options.tls_plaintext;
    let response_to_head = options.response_to_head;
    let response_to_connect = options.response_to_connect;
    let export = options.export;
    let fin = options.fin;
    let source = options.source;
    let (start, start_end) = next_line(data, 0)?;
    let start_line = parse_start_line(start)?;
    let start_text = std::str::from_utf8(start).ok()?;

    let mut headers: Vec<HeaderLine<'_>> = Vec::new();
    let mut budget = HeaderBudget::default();
    let mut offset = start_end;
    loop {
        let (line, consumed) = next_line(data, offset)?;
        let line_offset = offset;
        let field = !line.is_empty();
        if !budget.take(consumed, field) {
            return None;
        }
        offset = offset.saturating_add(consumed);
        if !field {
            break;
        }
        headers.push(parse_header_line(line, line_offset));
    }

    let method = match &start_line {
        StartLine::Request { method, .. } => Some(*method),
        StartLine::Response { .. } => None,
    };
    let framing = Framing::of(start, headers.iter().copied());
    let answer = Answer {
        head: response_to_head,
        connect: response_to_connect,
    };
    let plan = framing.body_plan(answer);
    let bodyless = framing.status_bodyless()
        || framing.answers_head(answer)
        || framing.answers_connect(answer)
        || method.is_some_and(|method| method.eq_ignore_ascii_case("HEAD"));

    let mut body = None;
    let consumed;
    match plan {
        BodyPlan::Empty => {
            // A request without framing fields has no body, and a bodyless
            // status owns nothing after its header section (RFC 9112
            // section 6.3 cases 1 and 6).
            consumed = offset;
        }
        BodyPlan::Answer(declared) => {
            // The message has no body, but the bytes the segment carried
            // still belong to it: the declared length caps them when present,
            // and a HEAD/CONNECT answer owns everything captured.
            let end = declared.map_or(data.len(), |length| {
                offset.saturating_add(length).min(data.len())
            });
            let bytes = data.get(offset..end).unwrap_or(&[]);
            body = Some(Body {
                offset,
                end,
                bytes: shared_bytes(source, offset, bytes),
                chunked: false,
                exportable: end > offset,
                chunks: Vec::new(),
                trailer_end: None,
                trailers: Vec::new(),
            });
            consumed = end;
        }
        BodyPlan::Fixed(length) => {
            let end = offset.checked_add(length)?;
            let bytes = data.get(offset..end)?;
            body = Some(Body {
                offset,
                end,
                bytes: shared_bytes(source, offset, bytes),
                chunked: false,
                exportable: true,
                chunks: Vec::new(),
                trailer_end: None,
                trailers: Vec::new(),
            });
            consumed = end;
        }
        BodyPlan::Chunked => {
            let chunked_body = parse_chunked(
                data.get(offset..)?,
                fin,
                source.map(|(bytes, base)| (bytes, base.saturating_add(offset))),
            )?;
            let end = if chunked_body.truncated {
                data.len()
            } else {
                offset.saturating_add(chunked_body.end)
            };
            body = Some(Body {
                offset,
                end,
                bytes: Bytes::from(chunked_body.bytes),
                chunked: true,
                exportable: !chunked_body.chunks.is_empty() || !chunked_body.truncated,
                chunks: chunked_body.chunks,
                trailer_end: chunked_body.trailer_end,
                trailers: chunked_body.trailers,
            });
            consumed = end;
        }
        BodyPlan::InvalidLength => {
            // The declared length is unusable, so the captured remainder stays
            // with the message rather than being guessed at.
            let bytes = data.get(offset..)?;
            body = Some(Body {
                offset,
                end: data.len(),
                bytes: shared_bytes(source, offset, bytes),
                chunked: false,
                exportable: true,
                chunks: Vec::new(),
                trailer_end: None,
                trailers: Vec::new(),
            });
            consumed = data.len();
        }
        BodyPlan::CloseDelimited => {
            // A close-delimited response keeps the bytes available here as its
            // body; the stream layer completes it at FIN, and a direct decode
            // (for example with desegmentation disabled) takes the remainder.
            let bytes = data.get(offset..).unwrap_or_default();
            body = Some(Body {
                offset,
                end: data.len(),
                bytes: shared_bytes(source, offset, bytes),
                chunked: false,
                exportable: true,
                chunks: Vec::new(),
                trailer_end: None,
                trailers: Vec::new(),
            });
            consumed = data.len();
        }
    }

    let mut node = Node::new(&fields::HTTP_PROTOCOL, Range::new(base, consumed));
    let mut info = String::new();
    let mut request = None;
    let mut response_code = None;
    match start_line {
        StartLine::Request {
            method,
            uri,
            version,
        } => {
            let line_field = node.add_field(
                &UNNAMED_FIELD,
                Range::new(base, start_end),
                Value::String(format!("{start_text}\\r\\n")),
            );
            line_field.showname = Some(format!("{start_text}\\r\\n"));
            let child = node.fields.last_mut();
            if let Some(child) = child {
                child.add_field(
                    &fields::HTTP_REQUEST_METHOD,
                    Range::new(base, method.len()),
                    Value::String(method.to_string()),
                );
                child.add_field(
                    &fields::HTTP_REQUEST_URI,
                    Range::new(
                        base.saturating_add(method.len()).saturating_add(1),
                        uri.len(),
                    ),
                    Value::String(uri.to_string()),
                );
                child.add_field(
                    &fields::HTTP_REQUEST_VERSION,
                    Range::new(
                        base.saturating_add(method.len())
                            .saturating_add(uri.len())
                            .saturating_add(2),
                        version.len(),
                    ),
                    Value::String(version.to_string()),
                );
            }
            let host = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("Host"))
                .map(|header| header.value.trim());
            let full_uri = if method.eq_ignore_ascii_case("CONNECT") {
                Some(uri.to_string())
            } else {
                full_uri(uri, host, tls_plaintext.then_some("https://"))
            };
            request = Some(RequestMeta {
                uri: uri.to_string(),
                full_uri: full_uri.clone(),
                method: method.to_string(),
            });
            info.push_str(start_text);
            info.push(' ');
        }
        StartLine::Response {
            version,
            code,
            phrase,
        } => {
            response_code = Some(code);
            let line_field = node.add_field(
                &UNNAMED_FIELD,
                Range::new(base, start_end),
                Value::String(format!("{start_text}\\r\\n")),
            );
            line_field.showname = Some(format!("{start_text}\\r\\n"));
            let code_offset = version.len().saturating_add(1);
            if let Some(child) = node.fields.last_mut() {
                child.add_field(
                    &fields::HTTP_RESPONSE_VERSION,
                    Range::new(base, version.len()),
                    Value::String(version.to_string()),
                );
                child.add_field(
                    &fields::HTTP_RESPONSE_CODE,
                    Range::new(base.saturating_add(code_offset), 3),
                    Value::Uint24(code),
                );
                let description = status_description(code);
                let desc = child.add_field(
                    &fields::HTTP_RESPONSE_CODE_DESC,
                    Range::new(base.saturating_add(code_offset), 3),
                    Value::String(description.to_string()),
                );
                desc.generated = true;
                if !phrase.is_empty() {
                    child.add_field(
                        &fields::HTTP_RESPONSE_PHRASE,
                        Range::new(
                            base.saturating_add(code_offset).saturating_add(4),
                            phrase.len(),
                        ),
                        Value::String(phrase.to_string()),
                    );
                }
            }
            info.push_str(start_text);
            info.push(' ');
        }
    }

    let is_request = matches!(start_line, StartLine::Request { .. });
    let mut media_suffix = None;
    let mut content_type = None;
    let mut content_encoding = None;
    let mut malformed_header = None;
    for header in &headers {
        let header_base = base.saturating_add(header.offset);
        if !header.colon {
            malformed_header = Some(header);
            break;
        }
        if !header.valid {
            let line_showname = format!("{}\r\n", String::from_utf8_lossy(header.raw));
            let field = node.add_field(
                &UNNAMED_FIELD,
                Range::new(header_base, header.raw.len().saturating_add(2)),
                Value::String(line_showname.clone()),
            );
            field.showname = Some(line_showname);
            field.add_expert(ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: "Illegal characters found in header name".to_string(),
            });
            let mut line = String::from_utf8_lossy(header.raw).into_owned();
            line.push_str("\r\n");
            node.add_field(
                if is_request {
                    &fields::HTTP_REQUEST_LINE
                } else {
                    &fields::HTTP_RESPONSE_LINE
                },
                Range::new(header_base, header.raw.len().saturating_add(2)),
                Value::String(line),
            );
            continue;
        }
        add_header_fields(&mut node, header, header_base, is_request);
        if header.name.eq_ignore_ascii_case("Content-Type") {
            media_suffix = media_suffix_for(header.value);
            if export {
                content_type = Some(header.value.to_string());
            }
        }
        if export && header.name.eq_ignore_ascii_case("Content-Encoding") {
            content_encoding = Some(header.value.to_string());
        }
    }

    if let Some(header) = malformed_header {
        // Stop at the first unusable header line and present the rest of the
        // segment as file data with a `Continuation` summary.
        let line_showname = format!("{}\\r\\n", String::from_utf8_lossy(header.raw));
        let field = node.add_field(
            &UNNAMED_FIELD,
            Range::new(
                base.saturating_add(header.offset),
                header.raw.len().saturating_add(2),
            ),
            Value::String(line_showname.clone()),
        );
        field.showname = Some(line_showname);
        field.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Protocol,
            message: "Illegal characters found in header name".to_string(),
        });
        info.push_str("Continuation");
        node.add_field(
            &fields::HTTP_EXCESS_DATA,
            Range::new(base.saturating_add(header.offset), 0),
            Value::None,
        );
        let body_bytes = data.get(header.offset..).unwrap_or(&[]);
        let mut message = HttpMessage {
            node,
            info,
            consumed: data.len(),
            request,
            response_code,
            content_type,
            content_encoding,
            body: Some(Body {
                offset: header.offset,
                end: data.len(),
                bytes: shared_bytes(source, header.offset, body_bytes),
                chunked: false,
                // Export the malformed-header continuation as file data,
                // named from the request URI.
                exportable: !bodyless,
                chunks: Vec::new(),
                trailer_end: None,
                trailers: Vec::new(),
            }),
        };
        if let Some(request) = &message.request {
            message.node.add_field(
                &fields::HTTP_REQUEST,
                Range::new(base, 0),
                Value::Boolean(true),
            );
            if let Some(full_uri) = &request.full_uri {
                let field = message.node.add_field(
                    &fields::HTTP_REQUEST_FULL_URI,
                    Range::new(base, 0),
                    Value::String(full_uri.clone()),
                );
                field.generated = true;
            }
        }
        if message.response_code.is_some() {
            message.node.add_field(
                &fields::HTTP_RESPONSE,
                Range::new(base, 0),
                Value::Boolean(true),
            );
        }
        return Some(message);
    }

    let terminator = node.add_field(
        &UNNAMED_FIELD,
        Range::new(base.saturating_add(offset).saturating_sub(2), 2),
        Value::String("\\r\\n".to_string()),
    );
    terminator.showname = Some("\\r\\n".to_string());

    if let Some(request) = &request {
        node.add_field(
            &fields::HTTP_REQUEST,
            Range::new(base, 0),
            Value::Boolean(true),
        );
        if let Some(full_uri) = &request.full_uri {
            let field = node.add_field(
                &fields::HTTP_REQUEST_FULL_URI,
                Range::new(base, 0),
                Value::String(full_uri.clone()),
            );
            field.generated = true;
        }
    }
    if response_code.is_some() {
        node.add_field(
            &fields::HTTP_RESPONSE,
            Range::new(base, 0),
            Value::Boolean(true),
        );
    }
    if let Some(chunked) = body.as_ref().filter(|body| body.chunked) {
        add_chunk_fields(&mut node, chunked, base);
    }
    if let Some(suffix) = media_suffix {
        info.push_str(&suffix);
    }
    Some(HttpMessage {
        node,
        info,
        consumed,
        request,
        response_code,
        content_type,
        content_encoding,
        body,
    })
}

/// Add the named header field and the hidden raw-line field.
fn add_header_fields(node: &mut Node, header: &HeaderLine<'_>, base: usize, is_request: bool) {
    let showname = format!("{}\\r\\n", String::from_utf8_lossy(header.raw));
    let full_range = Range::new(base, header.raw.len().saturating_add(2));
    let def = curated_header(header.name);
    if let Some(def) = def {
        let field = node.add_field(def, full_range, Value::String(header.value.to_string()));
        field.showname = Some(showname.clone());
        if header.name.eq_ignore_ascii_case("Content-Length")
            && let Ok(length) = header.value.parse::<u64>()
        {
            let child = field.add_field(
                &fields::HTTP_CONTENT_LENGTH,
                full_range,
                Value::Uint64(length),
            );
            child.generated = true;
            child.showname = Some(format!("Content length: {length}"));
        }
    }
    let mut line = String::from_utf8_lossy(header.raw).into_owned();
    line.push_str("\r\n");
    node.add_field(
        if is_request {
            &fields::HTTP_REQUEST_LINE
        } else {
            &fields::HTTP_RESPONSE_LINE
        },
        full_range,
        Value::String(line),
    );
}

/// Map a header name to its curated field definition.
fn curated_header(name: &str) -> Option<&'static fields::FieldDef> {
    Some(match name.to_ascii_lowercase().as_str() {
        "host" => &fields::HTTP_HOST,
        "user-agent" => &fields::HTTP_USER_AGENT,
        "accept" => &fields::HTTP_ACCEPT,
        "accept-encoding" => &fields::HTTP_ACCEPT_ENCODING,
        "accept-language" => &fields::HTTP_ACCEPT_LANGUAGE,
        "connection" => &fields::HTTP_CONNECTION,
        "server" => &fields::HTTP_SERVER,
        "content-type" => &fields::HTTP_CONTENT_TYPE,
        "content-length" => &fields::HTTP_CONTENT_LENGTH_HEADER,
        "content-encoding" => &fields::HTTP_CONTENT_ENCODING,
        "transfer-encoding" => &fields::HTTP_TRANSFER_ENCODING,
        _ => return None,
    })
}

/// One chunked body's de-chunked bytes and the records the field tree shows.
struct ChunkedBody {
    /// De-chunked body bytes, in wire order.
    bytes: Vec<u8>,
    /// Offset just past the trailer section's empty line.
    end: usize,
    /// Chunk records, including the final zero-size chunk.
    chunks: Vec<Chunk>,
    /// Offset just past the trailer terminator, when the body completed.
    trailer_end: Option<usize>,
    /// Trailer field lines: offset, length and text within the body.
    trailers: Vec<(usize, usize, String)>,
    /// The body stopped at the end of the stream before its last chunk.
    truncated: bool,
}

/// Parse a chunked body, or `None` when it does not fit the segment.
///
/// At end of stream (`tolerate_truncated`) the complete chunk prefix is
/// returned with the truncated flag set, so those bytes are exported even when
/// the terminating zero chunk never arrived. An unusable size line ends the
/// entity at the bytes already read, the way a peer that stops sending
/// mid-body ends it.
fn parse_chunked(
    data: &[u8],
    tolerate_truncated: bool,
    source: Option<PduSource<'_>>,
) -> Option<ChunkedBody> {
    let mut scanner = ChunkScanner::new(0);
    let mut chunks = Vec::new();
    let mut bytes = Vec::with_capacity(data.len());
    let mut trailers = Vec::new();
    loop {
        match scanner.step(data, data.len()) {
            ChunkStep::Data {
                line,
                size,
                data: data_offset,
                bytes: chunk_data,
                boundary,
                ..
            } => {
                // A declared chunk that fits the segment always fits the field
                // type; the conversion only rejects an impossible size.
                let size = u32::try_from(size).ok()?;
                bytes.extend_from_slice(chunk_data);
                chunks.push(Chunk {
                    size,
                    offset: line,
                    data: shared_bytes(source, data_offset, chunk_data),
                    data_offset,
                    boundary_offset: boundary,
                    final_chunk: false,
                });
            }
            ChunkStep::Last { .. } => {}
            ChunkStep::Trailer { line, consumed } => {
                let text = data
                    .get(line..line.saturating_add(consumed))
                    .unwrap_or_default();
                let text = text.strip_suffix(b"\r\n").unwrap_or(text);
                trailers.push((
                    line,
                    consumed,
                    format!("{}\r\n", String::from_utf8_lossy(text)),
                ));
            }
            ChunkStep::TrailerEnd { end, last } => {
                chunks.push(Chunk {
                    size: 0,
                    offset: last,
                    data: Bytes::default(),
                    data_offset: end,
                    boundary_offset: end.saturating_sub(2),
                    final_chunk: true,
                });
                return Some(ChunkedBody {
                    bytes,
                    end,
                    chunks,
                    trailer_end: Some(end),
                    trailers,
                    truncated: false,
                });
            }
            ChunkStep::Incomplete { restart, .. } => {
                return tolerate_truncated.then_some(ChunkedBody {
                    bytes,
                    end: restart,
                    chunks,
                    trailer_end: None,
                    trailers: Vec::new(),
                    truncated: true,
                });
            }
            ChunkStep::Invalid { .. } => {
                // An unusable chunk size terminates the chunked entity: the
                // records read so far stay, and the rest of the segment is
                // consumed so it cannot reopen as another message.
                return Some(ChunkedBody {
                    bytes,
                    end: data.len(),
                    chunks,
                    trailer_end: None,
                    trailers: Vec::new(),
                    truncated: false,
                });
            }
        }
    }
}

/// Add the chunked-body container and its records.
fn add_chunk_fields(node: &mut Node, body: &Body, base: usize) {
    let container = node.add_container(
        &CHUNKED_BODY,
        Range::new(
            base.saturating_add(body.offset),
            body.end.saturating_sub(body.offset),
        ),
        Some("HTTP chunked response".to_string()),
    );
    for chunk in &body.chunks {
        let chunk_base = base
            .saturating_add(body.offset)
            .saturating_add(chunk.offset);
        if chunk.final_chunk {
            let final_field = container.add_container(
                &CHUNKED_BODY,
                Range::new(chunk_base, 0),
                Some("End of chunked encoding".to_string()),
            );
            let size_field = final_field.add_field(
                &fields::HTTP_CHUNK_SIZE,
                Range::new(chunk_base, 0),
                Value::Uint32(0),
            );
            size_field.showname = Some("Chunk size: 0 octets".to_string());
        } else {
            let child = container.add_container(
                &CHUNKED_BODY,
                Range::new(chunk_base, chunk.data.len().saturating_add(4)),
                Some(format!("Data chunk ({} octets)", chunk.size)),
            );
            let size_field = child.add_field(
                &fields::HTTP_CHUNK_SIZE,
                Range::new(chunk_base, 0),
                Value::Uint32(chunk.size),
            );
            size_field.showname = Some(format!("Chunk size: {} octets", chunk.size));
            let data_field = child.add_field(
                &fields::HTTP_CHUNK_DATA,
                Range::new(
                    base.saturating_add(body.offset)
                        .saturating_add(chunk.data_offset),
                    chunk.data.len(),
                ),
                Value::bytes(chunk.data.clone()),
            );
            data_field.showname_hex = Some(HexShowname {
                prefix: "Chunk data: ",
                bytes: chunk.data.clone(),
            });
            let boundary = child.add_field(
                &fields::HTTP_CHUNK_BOUNDARY,
                Range::new(
                    base.saturating_add(body.offset)
                        .saturating_add(chunk.boundary_offset),
                    2,
                ),
                Value::bytes(b"\r\n".to_vec()),
            );
            boundary.showname = Some("Chunk boundary: 0d0a".to_string());
        }
    }
    for (line_start, line_length, text) in &body.trailers {
        container.add_field(
            &fields::HTTP_CHUNKED_TRAILER_PART,
            Range::new(
                base.saturating_add(body.offset).saturating_add(*line_start),
                *line_length,
            ),
            Value::String(text.clone()),
        );
    }
    if let Some(end) = body.trailer_end {
        let field = container.add_field(
            &UNNAMED_FIELD,
            Range::new(
                base.saturating_add(body.offset)
                    .saturating_add(end)
                    .saturating_sub(2),
                2,
            ),
            Value::String("\\r\\n".to_string()),
        );
        field.showname = Some("\\r\\n".to_string());
    }
}

/// Add the message body's file data after the state fields.
///
/// The body is moved out of the message: a de-chunked body already owns its
/// bytes, and a borrowed Content-Length body copies exactly once into the
/// field value.
fn add_body_fields(message: &mut HttpMessage) {
    let Some(body) = message.body.take() else {
        return;
    };
    if body.bytes.is_empty() {
        if body.chunked {
            message.node.add_field(
                &fields::HTTP_FILE_DATA,
                Range::new(message.node.range.offset, 0),
                Value::Missing,
            );
        }
        return;
    }
    let length = body.bytes.len();
    let file_data = message.node.add_field(
        &fields::HTTP_FILE_DATA,
        Range::new(
            message.node.range.offset.saturating_add(body.offset),
            length,
        ),
        Value::bytes(body.bytes),
    );
    file_data.showname = Some(format!("File Data: {length} bytes"));
}

/// Record the message in the conversation state and add the link fields.
///
/// Returns the request a response matched so object export can name the body
/// from its URI.
fn record_state(
    context: &mut DecodeContext<'_>,
    key: crate::state::ConversationKey,
    message: &mut HttpMessage,
) -> Option<crate::state::HttpRequestInfo> {
    let frame = context.frame.number;
    let file = context.frame.file_number;
    let time = context.frame.timestamp;
    if let Some(request) = &message.request {
        context.state.http_request(
            key,
            crate::state::HttpFrame {
                display: frame,
                file,
            },
            time,
            Some(&request.method),
            Some(&request.uri),
            request.full_uri.as_deref(),
        );
    }
    if let Some(code) = message.response_code {
        let matched =
            context
                .state
                .http_response(key, frame, u16::try_from(code).unwrap_or(u16::MAX));
        let matched = matched?;
        let delay = match (matched.time, time) {
            (Some(request), Some(response)) => Some(crate::state::elapsed_nanos(request, response)),
            _ => None,
        };
        if context.pass == crate::state::PassMode::First {
            let annotations = context.state.annotations_mut();
            if let Some(delay) = delay {
                annotations.link_response(file, matched.file, delay);
            }
            annotations.link_response_in(matched.file, file);
        }
        let base = message.node.range.offset;
        // The output pass reads these links from the recording pass, so it
        // must not add a second occurrence the annotations will duplicate.
        if context.pass != crate::state::PassMode::Second {
            message.node.add_field(
                &fields::HTTP_REQUEST_IN,
                Range::new(base, 0),
                Value::Uint32(u32::try_from(matched.frame).unwrap_or(u32::MAX)),
            );
            if let Some(delay) = delay {
                message.node.add_field(
                    &fields::HTTP_TIME,
                    Range::new(base, 0),
                    Value::RelativeTime(delay),
                );
            }
        }
        if let Some(uri) = &matched.uri {
            let field = message.node.add_field(
                &fields::HTTP_REQUEST_URI,
                Range::new(base, 0),
                Value::String(uri.clone()),
            );
            field.generated = true;
            field.showname = Some(format!("Request URI: {uri}"));
        }
        if let Some(full_uri) = &matched.full_uri {
            let field = message.node.add_field(
                &fields::HTTP_REQUEST_FULL_URI,
                Range::new(base, 0),
                Value::String(full_uri.clone()),
            );
            field.generated = true;
            field.showname = Some(format!("Full request URI: {full_uri}"));
        }
        return Some(matched);
    }
    None
}

/// Content coding decoded before exporting a body.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContentCoding {
    /// No Content-Encoding, or `identity`.
    Identity,
    /// `gzip` or `x-gzip`, decoded with the gzip container.
    Gzip,
    /// `deflate`: a zlib wrapper or raw DEFLATE stream.
    Deflate,
}

/// Resolve the Content-Encoding header to a coding the exporter decodes.
///
/// The gzip, x-gzip, deflate and identity codings are decoded; an empty
/// header, an unsupported coding such as `br` or a list of two codings produce
/// no object at all. Only the first gzip member is decoded and trailing bytes
/// or members are ignored, as `flate2`'s single-member decoder does.
fn content_coding(value: Option<&str>) -> Option<ContentCoding> {
    let Some(value) = value else {
        return Some(ContentCoding::Identity);
    };
    let mut tokens = value.split(',').map(str::trim);
    let token = tokens.next().unwrap_or("");
    if tokens.next().is_some() {
        return None;
    }
    if token.eq_ignore_ascii_case("identity") {
        Some(ContentCoding::Identity)
    } else if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
        Some(ContentCoding::Gzip)
    } else if token.eq_ignore_ascii_case("deflate") {
        Some(ContentCoding::Deflate)
    } else {
        None
    }
}

/// Whether a DEFLATE body starts with a valid zlib wrapper.
fn has_zlib_wrapper(bytes: &[u8]) -> bool {
    let (Some(cmf), Some(flg)) = (bytes.first(), bytes.get(1)) else {
        return false;
    };
    (cmf & 0x0f) == 8
        && (cmf >> 4) <= 7
        && (u16::from(*cmf)
            .saturating_mul(256)
            .saturating_add(u16::from(*flg)))
            % 31
            == 0
}

/// Stream a decompressed body to the sink, bounded by the object cap.
///
/// Returns false on a decoding error; the caller then aborts silently and
/// drops the body. When the body exceeds the cap the sink's `refuse` hook
/// reports why and discards it; the later abort is a no-op.
fn stream_decompressed<R: std::io::Read>(
    mut reader: R,
    sink: &mut (dyn crate::export::ObjectSink + 'static),
) -> bool {
    let mut buffer = [0_u8; 16 * 1024];
    let mut written = 0_u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return true,
            Ok(read) => read,
            Err(_) => return false,
        };
        let Some(length) = u64::try_from(read).ok() else {
            return false;
        };
        let Some(total) = written.checked_add(length) else {
            return false;
        };
        if total > crate::export::MAX_EXPORT_OBJECT_BYTES {
            sink.refuse();
            return false;
        }
        sink.write(buffer.get(..read).unwrap_or(&[]));
        written = total;
    }
}

/// Add the `Continuation` node and export its file data.
fn add_continuation(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    body: &[u8],
    offset: usize,
    excess: bool,
) {
    let mut node = Node::new(&fields::HTTP_PROTOCOL, Range::new(offset, body.len()));
    let field = node.add_field(
        &fields::HTTP_FILE_DATA,
        Range::new(offset, body.len()),
        Value::bytes(body.to_vec()),
    );
    field.showname = Some(format!("File Data: {} bytes", body.len()));
    if excess {
        let excess_field = node.add_field(
            &fields::HTTP_EXCESS_DATA,
            Range::new(offset, 0),
            Value::None,
        );
        excess_field.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Protocol,
            message: "Excess data after a body (not a new request/response), previous Content-Length bogus?".to_string(),
        });
    }
    if !context.quoted
        && let Some(sink) = context.objects.as_deref_mut()
    {
        let name = match context.http_last_uri.as_deref() {
            Some(uri) => ObjectName::from_request_uri(uri),
            None => ObjectName::fallback(context.frame.number, None),
        };
        let expected = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if sink.begin(&name, Some(expected)) {
            sink.write(body);
            sink.commit();
        }
    }
    parent.add_child(node);
}

/// Name one message body and hand it to the object sink.
///
/// Requests use their own URI; a response uses the request it matched, and
/// falls back to `object<frame>.<media type>` when no request is known.
/// Content-Length zero is not an object, while a completed chunked body is
/// exported even when its dechunked length is zero. A malformed-header
/// continuation exports as file data, and quoted headers never export.
fn export_object(
    context: &mut DecodeContext<'_>,
    message: &HttpMessage,
    matched: Option<&crate::state::HttpRequestInfo>,
) {
    if context.quoted {
        return;
    }
    let Some(body) = message.body.as_ref().filter(|body| body.exportable) else {
        return;
    };
    if body.bytes.is_empty() && !body.chunked {
        return;
    }
    let Some(coding) = content_coding(message.content_encoding.as_deref()) else {
        return;
    };
    let frame = context.frame.number;
    let Some(sink) = context.objects.as_deref_mut() else {
        return;
    };
    let name = match (&message.request, matched) {
        (Some(request), _) => ObjectName::from_request_uri(&request.uri),
        (None, Some(matched)) => match matched.uri.as_deref() {
            Some(uri) => ObjectName::from_request_uri(uri),
            None => ObjectName::fallback(frame, message.content_type.as_deref()),
        },
        (None, None) => ObjectName::fallback(frame, message.content_type.as_deref()),
    };
    let expected = if coding == ContentCoding::Identity {
        Some(u64::try_from(body.bytes.len()).unwrap_or(u64::MAX))
    } else {
        None
    };
    if !sink.begin(&name, expected) {
        return;
    }
    let decoded = match coding {
        ContentCoding::Identity => {
            sink.write(&body.bytes);
            true
        }
        ContentCoding::Gzip => {
            stream_decompressed(flate2::read::GzDecoder::new(body.bytes.as_ref()), sink)
        }
        ContentCoding::Deflate => {
            if has_zlib_wrapper(&body.bytes) {
                stream_decompressed(flate2::read::ZlibDecoder::new(body.bytes.as_ref()), sink)
            } else {
                stream_decompressed(flate2::read::DeflateDecoder::new(body.bytes.as_ref()), sink)
            }
        }
    };
    if decoded {
        sink.commit();
    } else {
        sink.abort();
    }
}

/// Compose the absolute request URI.
fn full_uri(uri: &str, host: Option<&str>, scheme: Option<&str>) -> Option<String> {
    if uri.starts_with("http://") || uri.starts_with("https://") || uri.starts_with("CONNECT ") {
        return Some(uri.to_string());
    }
    let host = host?.trim();
    if host.is_empty() {
        return None;
    }
    Some(format!("{}{host}{uri}", scheme.unwrap_or("http://")))
}

/// The status-code description, separate from the server's phrase.
fn status_description(code: u32) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// The media-type suffix appended to the summary.
fn media_suffix_for(content_type: &str) -> Option<String> {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media.is_empty() {
        // A present but empty Content-Type header renders an empty
        // parenthesised media type.
        return Some(" ()".to_string());
    }
    if media == "application/json" {
        return Some(", JSON (application/json)".to_string());
    }
    let dissected = media.starts_with("text/")
        || media.starts_with("image/")
        || media.starts_with("audio/")
        || media.starts_with("video/")
        || media.starts_with("font/")
        || matches!(
            media.as_str(),
            "application/x-www-form-urlencoded"
                | "application/xml"
                | "application/javascript"
                | "application/x-javascript"
        );
    dissected.then(|| format!(" ({media})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_syntax::MAX_HEADER_LINES;

    #[test]
    fn published_start_line_forms_are_recognized() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(looks_like_http(b"HTTP/1.1 204 No Content\r\n\r\n"));
        assert!(!looks_like_http(b"HTTP/1.2 200 OK\r\n\r\n"));
        assert!(!looks_like_http(b"GET / HTTP/2.0\r\n\r\n"));
        assert!(!looks_like_http(b"NOT A REQUEST\r\n\r\n"));
    }

    #[test]
    fn a_chunk_size_beyond_the_segment_is_rejected_without_allocating() {
        let message = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\nx";
        assert!(
            parse_message(
                message,
                0,
                &MessageOptions {
                    tls_plaintext: false,
                    response_to_head: false,
                    response_to_connect: false,
                    export: false,
                    fin: false,
                    source: None,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn the_header_count_is_bounded() {
        let mut message = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..(MAX_HEADER_LINES + 1) {
            message.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        message.extend_from_slice(b"\r\n");
        assert!(
            parse_message(
                &message,
                0,
                &MessageOptions {
                    tls_plaintext: false,
                    response_to_head: false,
                    response_to_connect: false,
                    export: false,
                    fin: false,
                    source: None,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn a_long_header_line_is_decoded() {
        let mut message = b"GET / HTTP/1.1\r\nX-Big: ".to_vec();
        message.extend(std::iter::repeat_n(b'a', 9000));
        message.extend_from_slice(b"\r\n\r\n");
        let parsed = parse_message(
            &message,
            0,
            &MessageOptions {
                tls_plaintext: false,
                response_to_head: false,
                response_to_connect: false,
                export: false,
                fin: false,
                source: None,
            },
        );
        assert!(parsed.is_some());
    }

    #[test]
    fn content_codings_are_recognized() {
        assert!(matches!(
            content_coding(None),
            Some(ContentCoding::Identity)
        ));
        for value in [
            "identity",
            "IDENTITY",
            "gzip",
            "GZIP",
            "x-gzip",
            "deflate",
            " deflate ",
        ] {
            assert!(content_coding(Some(value)).is_some(), "value {value:?}");
        }
        for value in ["", "br", "gzip, br", "gzip,deflate", "zstd"] {
            assert!(content_coding(Some(value)).is_none(), "value {value:?}");
        }
    }

    #[test]
    fn zlib_wrappers_are_distinguished_from_raw_deflate() {
        assert!(has_zlib_wrapper(&[0x78, 0x9c, 0x03, 0x00]));
        assert!(has_zlib_wrapper(&[0x78, 0x01, 0x00, 0x00]));
        assert!(!has_zlib_wrapper(&[0x4b, 0x4c, 0x4a, 0x06]));
        assert!(!has_zlib_wrapper(&[]));
        assert!(!has_zlib_wrapper(&[0x78]));
    }
}
