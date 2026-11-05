//! HTTP/1.x start-line grammar shared by the reassembler and decoder.
//!
//! The stream layer uses this predicate to decide whether a PDU starts an
//! HTTP message or is continuation data. Keeping one parser here prevents the
//! two layers from disagreeing about the same bytes.

/// Longest HTTP header block the decoder and reassembler accept.
///
/// This bounds the start line plus all header lines and their terminator. A
/// message whose header block exceeds it is reported as an oversized PDU by
/// the stream layer and left undecoded by the decoder, so the two layers
/// cannot disagree about a huge header.
pub(crate) const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// A parsed HTTP/1.x start line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartLine<'a> {
    /// A request line.
    Request {
        /// Method token.
        method: &'a str,
        /// Request target.
        uri: &'a str,
        /// HTTP version.
        version: &'a str,
    },
    /// A status line.
    Response {
        /// HTTP version.
        version: &'a str,
        /// Status code.
        code: u32,
        /// Reason phrase, empty when absent.
        phrase: &'a str,
    },
}

impl StartLine<'_> {
    /// Whether this is a response status line.
    pub(crate) fn is_response(&self) -> bool {
        matches!(self, Self::Response { .. })
    }

    /// The response status code, when this is a status line.
    pub(crate) fn response_code(&self) -> Option<u32> {
        match self {
            Self::Response { code, .. } => Some(*code),
            Self::Request { .. } => None,
        }
    }
}

/// Parse and validate a request or status line.
///
/// A request line with extra tokens after the version and a status code
/// shorter than three digits are accepted, although the RFC 7230 grammar
/// (sections 3.1.1 and 3.1.2) allows neither.
pub(crate) fn parse_start_line(line: &[u8]) -> Option<StartLine<'_>> {
    if line.starts_with(b"HTTP/1.") {
        let text = std::str::from_utf8(line).ok()?;
        let mut parts = text.splitn(3, ' ');
        let version = parts.next()?;
        if version != "HTTP/1.0" && version != "HTTP/1.1" {
            return None;
        }
        let code_text = parts.next()?;
        if code_text.is_empty()
            || code_text.len() > 3
            || !code_text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let code = code_text.parse().ok()?;
        let phrase = parts.next().unwrap_or("");
        return Some(StartLine::Response {
            version,
            code,
            phrase,
        });
    }
    // The fourth field (if any) is ignored: only the request line's first
    // three tokens are parsed, and the request stays usable.
    let mut parts = line.splitn(4, |byte| *byte == b' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    let _extra = parts.next();
    if method.len() > 16
        || !method
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
    {
        return None;
    }
    if uri.is_empty() || uri.iter().any(u8::is_ascii_control) {
        return None;
    }
    if version != b"HTTP/1.0" && version != b"HTTP/1.1" {
        return None;
    }
    Some(StartLine::Request {
        method: std::str::from_utf8(method).ok()?,
        uri: std::str::from_utf8(uri).ok()?,
        version: std::str::from_utf8(version).ok()?,
    })
}
