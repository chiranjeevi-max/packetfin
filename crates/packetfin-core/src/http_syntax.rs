//! HTTP/1.x message framing shared by the reassembler, the decoder and the
//! follow tap.
//!
//! Three consumers need the same answer to "where does this message end": the
//! reassembler (`state/stream.rs`) picks the PDU boundary, the decoder
//! (`decode/http.rs`) builds the body and chunk fields, and the follow tap
//! (`stats/follow.rs`) splits records. This module owns the rules once, so a
//! message cannot be delimited one way to decide its boundary and shown
//! another way in the field tree.
//!
//! The rules are RFC 9112 section 6.3 for the message body length, evaluated in
//! the order its cases are written, and section 7.1 for the chunked transfer
//! coding: size line with optional extensions, chunk data followed by CRLF,
//! last-chunk and trailer section. The start-line grammar lives here as well
//! because the reassembler must recognise a message before the decoder has
//! validated it.
//!
//! Repeated Content-Length fields must agree (RFC 9112 section 6.3), only a
//! final `chunked` transfer coding selects chunk framing (sections 6.1 and
//! 6.3), and 1xx, 204 and 304 responses and every response to HEAD end at the
//! header section. Where the expected output framed these message shapes
//! differently, the difference is recorded as a deviation row.

/// Header bytes both consumers accept for one message.
///
/// [`HeaderBudget`] charges the start line, every field line and the empty line
/// that ends the section against this single cap. The reassembler stops waiting
/// when the field lines alone pass it, and a block over the cap still consumes
/// its framed length, so the bytes after an oversized header stay aligned with
/// the wire instead of reopening as a message.
pub(crate) const MAX_HEADER_BYTES: usize = 1024 * 1024;

/// Header lines the decoder retains for one message.
///
/// The cap keeps a hostile message from producing unbounded string fields; a
/// block with more lines is left undecoded. The reassembler has no line bound
/// because it only needs the framing facts of a block it has already
/// delimited, and a port-registered message may carry more fields than this
/// decoder displays.
pub(crate) const MAX_HEADER_LINES: usize = 256;

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
/// shorter than three digits are accepted, although the RFC 9112 grammar
/// (sections 3.1 and 3.2) allows neither.
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

/// Split one LF-terminated line from `data` at `offset`.
///
/// A line ends at LF and a CR immediately before that LF belongs to the
/// terminator. A bare LF is accepted because the direct decode path sees
/// un-reassembled payloads, where the expected output reads lines that way.
/// Returns the line without its terminator and the bytes consumed, terminator
/// included.
pub(crate) fn next_line(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let rest = data.get(offset..)?;
    let index = rest.iter().position(|byte| *byte == b'\n')?;
    let mut line = rest.get(..index)?;
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped;
    }
    Some((line, index.saturating_add(1)))
}

/// The offset just past the empty line that ends a header section.
///
/// The reassembler and the follow tap look for the RFC 9112 section 2.1 field
/// terminator (CRLF CRLF) before they hand bytes to the framer.
pub(crate) fn header_section_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index.saturating_add(4))
}

/// One header field line and the parts the field tree needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HeaderLine<'a> {
    /// Field name, still in wire case.
    pub(crate) name: &'a str,
    /// Field value with optional whitespace removed.
    pub(crate) value: &'a str,
    /// The line without its terminator.
    pub(crate) raw: &'a [u8],
    /// Offset of the line within the message, after the start line.
    pub(crate) offset: usize,
    /// Whether a colon separates a name from a value.
    pub(crate) colon: bool,
    /// Whether the part before the colon is an RFC 9110 section 5.6.2 token.
    pub(crate) valid: bool,
}

/// Split one header line at its colon and validate the field name.
pub(crate) fn parse_header_line(line: &[u8], offset: usize) -> HeaderLine<'_> {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return HeaderLine {
            name: "",
            value: "",
            raw: line,
            offset,
            colon: false,
            valid: false,
        };
    };
    let name = line.get(..colon).unwrap_or(&[]);
    let value = line.get(colon.saturating_add(1)..).unwrap_or(&[]);
    let valid = !name.is_empty()
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte));
    HeaderLine {
        name: std::str::from_utf8(name).unwrap_or(""),
        value: std::str::from_utf8(value).map(str::trim).unwrap_or(""),
        raw: line,
        offset,
        colon: true,
        valid,
    }
}

/// The decoder's header retention budget.
///
/// These are display bounds, not framing bounds: a block beyond either cap is
/// left undissected but still consumes its framed length, so the bytes after
/// it stay aligned with the wire. Counting them in one place keeps the caps
/// and the framing facts from drifting apart.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HeaderBudget {
    bytes: usize,
    lines: usize,
}

impl HeaderBudget {
    /// Account for one line, its terminator included.
    ///
    /// `field` marks a header field line; the empty line that ends the section
    /// and the start line only consume bytes. Returns false when the block
    /// exceeds either cap, after which the decoder refuses the message.
    pub(crate) fn take(&mut self, consumed: usize, field: bool) -> bool {
        self.bytes = self.bytes.saturating_add(consumed);
        if self.bytes > MAX_HEADER_BYTES {
            return false;
        }
        if field {
            if self.lines >= MAX_HEADER_LINES {
                return false;
            }
            self.lines = self.lines.saturating_add(1);
        }
        true
    }
}

/// The peer request that a response answers, as both directions share it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Answer {
    /// The request method was HEAD.
    pub(crate) head: bool,
    /// The request method was CONNECT.
    pub(crate) connect: bool,
}

/// The body-length facts of one HTTP/1.x header block (RFC 9112 section 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Framing {
    /// The start line is a response status line.
    pub(crate) response: bool,
    /// The status code the start line carries, when it carries one.
    pub(crate) code: Option<u16>,
    /// The Content-Length value the message declares, when it is usable.
    pub(crate) content_length: Option<usize>,
    /// A Content-Length field was unusable: a value was not a decimal length,
    /// or repeated values disagreed (RFC 9112 section 6.3).
    pub(crate) invalid_length: bool,
    /// A Transfer-Encoding field carried at least one coding.
    pub(crate) transfer_coding: bool,
    /// The final transfer coding is `chunked`, so the body is delimited by its
    /// chunk framing (RFC 9112 sections 6.1 and 7.1).
    pub(crate) chunked: bool,
}

impl Framing {
    /// Read the framing facts from a complete header block.
    ///
    /// `block` starts at the start line and ends after the empty line that
    /// closes the header section. A block without a complete start line
    /// contributes the facts of an empty one, which is what a caller that has
    /// already delimited CRLF CRLF can only reach for a block of two CRLFs.
    pub(crate) fn of_block(block: &[u8]) -> Self {
        let (start, consumed) = next_line(block, 0).unwrap_or((&[], 0));
        Self::of(start, HeaderLines::new(block, consumed))
    }

    /// Read the framing facts from a start line and the header lines after it.
    pub(crate) fn of<'a>(start: &[u8], headers: impl Iterator<Item = HeaderLine<'a>>) -> Self {
        let (response, code) = framing_start(start);
        let mut declared = None;
        let mut invalid_length = false;
        let mut transfer_coding = false;
        let mut final_coding: Option<&str> = None;
        for header in headers {
            if !header.valid {
                continue;
            }
            if header.name.eq_ignore_ascii_case("Content-Length") {
                // RFC 9112 section 6.3: repeated fields may be collapsed only
                // when they carry the same decimal value; a disagreement or
                // an unreadable value makes the declared length unusable and
                // no later field recovers it.
                match content_length_value(header.value) {
                    Some(value) => match declared {
                        Some(previous) if previous != value => invalid_length = true,
                        Some(_) => {}
                        None => declared = Some(value),
                    },
                    None => invalid_length = true,
                }
            } else if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
                // RFC 9110 section 5.2 combines repeated fields into one list,
                // so the last coding across every field is the final coding,
                // and RFC 9112 section 6.1 accepts chunked only in that
                // position.
                for coding in header.value.split(',') {
                    let name = coding.split(';').next().unwrap_or(coding).trim();
                    if !name.is_empty() {
                        transfer_coding = true;
                        final_coding = Some(name);
                    }
                }
            }
        }
        Self {
            response,
            code,
            content_length: if invalid_length { None } else { declared },
            invalid_length,
            transfer_coding,
            chunked: final_coding.is_some_and(|coding| coding.eq_ignore_ascii_case("chunked")),
        }
    }

    /// A status that never carries a body: 1xx, 204 and 304 (RFC 9112
    /// section 6.3, case 1).
    pub(crate) fn status_bodyless(&self) -> bool {
        self.response
            && self
                .code
                .is_some_and(|code| (100..200).contains(&code) || code == 204 || code == 304)
    }

    /// Whether this is the response to a HEAD request (RFC 9112 section 6.3,
    /// case 1): the response never carries the body its headers describe.
    pub(crate) fn answers_head(&self, answer: Answer) -> bool {
        self.response && answer.head
    }

    /// Whether this is a 2xx response to CONNECT (RFC 9112 section 9.3.6):
    /// after the header section the connection carries the tunnel.
    pub(crate) fn answers_connect(&self, answer: Answer) -> bool {
        self.response && answer.connect && self.code.is_some_and(|code| (200..300).contains(&code))
    }

    /// The body-length rule of RFC 9112 section 6.3 in its precedence order.
    pub(crate) fn body_plan(&self, answer: Answer) -> BodyPlan {
        if self.status_bodyless() || self.answers_head(answer) {
            // Case 1: 1xx, 204, 304 and every response to HEAD end at the
            // first empty line after the header fields, whatever the fields
            // say about a body.
            return BodyPlan::Empty;
        }
        if self.answers_connect(answer) {
            // Section 9.3.6: a 2xx answer to CONNECT turns the connection into
            // a tunnel, so every captured trailing byte belongs to the answer.
            return BodyPlan::Answer;
        }
        if self.chunked {
            // Case 3: a final chunked coding delimits the body itself and
            // takes precedence over any declared length.
            return BodyPlan::Chunked;
        }
        if self.transfer_coding {
            // Case 4: a final transfer coding that is not chunked leaves a
            // response delimited by the connection close, while a request that
            // carries one cannot be framed at all (section 6.1). The captured
            // remainder stays with the request so it cannot reopen as another
            // message.
            return if self.response {
                BodyPlan::CloseDelimited
            } else {
                BodyPlan::InvalidLength
            };
        }
        if let Some(length) = self.content_length {
            // Case 5.
            return BodyPlan::Fixed(length);
        }
        if self.invalid_length {
            // Case 5 with no usable value: nothing declares a boundary, so the
            // captured remainder is the message.
            return BodyPlan::InvalidLength;
        }
        if !self.response {
            // Case 7: a request without framing fields has no body.
            return BodyPlan::Empty;
        }
        // Case 8: a response is delimited by the connection close.
        BodyPlan::CloseDelimited
    }
}

/// How the bytes after the header section are delimited (RFC 9112 section
/// 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyPlan {
    /// No body follows the header section.
    Empty,
    /// Exactly this many bytes follow it.
    Fixed(usize),
    /// A 2xx answer to CONNECT: the connection becomes a tunnel, so every
    /// captured trailing byte belongs to the answer (RFC 9112 section 9.3.6).
    Answer,
    /// The framing fields are unusable; the captured remainder is body.
    InvalidLength,
    /// The chunked transfer coding delimits the body (RFC 9112 section 7.1).
    Chunked,
    /// The body ends when the connection closes.
    CloseDelimited,
}

/// One Content-Length field value as a decimal body length.
///
/// RFC 9112 section 6.3 lets a recipient collapse a field value that lists
/// identical decimal values, so `5, 5` is as usable as `5`; every other shape
/// is unusable. RFC 9110 section 5.6.1 makes an empty list element
/// insignificant, and the value itself is one or more digits.
fn content_length_value(value: &str) -> Option<usize> {
    let mut length = None;
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if !item.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let parsed = item.parse::<usize>().ok()?;
        match length {
            Some(previous) if previous != parsed => return None,
            Some(_) => {}
            None => length = Some(parsed),
        }
    }
    length
}

/// The response status a framing decision needs.
///
/// The decoder validates the whole start line with [`parse_start_line`] before
/// it dissects a message, but the reassembler must delimit a message whose
/// start line the port table already claimed, so this reads only the version
/// prefix and the status token. Those are the facts RFC 9112 section 4 makes
/// decide whether a response can carry a body.
fn framing_start(line: &[u8]) -> (bool, Option<u16>) {
    if !line.starts_with(b"HTTP/1.") {
        return (false, None);
    }
    let code = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
        .nth(1)
        .and_then(|token| std::str::from_utf8(token).ok())
        .and_then(|token| token.parse::<u16>().ok());
    (true, code)
}

/// Iterate the header lines of one block after its start line.
struct HeaderLines<'a> {
    data: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> HeaderLines<'a> {
    fn new(data: &'a [u8], offset: usize) -> Self {
        Self {
            data,
            offset,
            done: false,
        }
    }
}

impl<'a> Iterator for HeaderLines<'a> {
    type Item = HeaderLine<'a>;

    fn next(&mut self) -> Option<HeaderLine<'a>> {
        if self.done {
            return None;
        }
        let (line, consumed) = next_line(self.data, self.offset)?;
        let offset = self.offset;
        self.offset = self.offset.saturating_add(consumed);
        if line.is_empty() {
            self.done = true;
            return None;
        }
        Some(parse_header_line(line, offset))
    }
}

/// A message continuation: bytes after a completed message that cannot begin
/// a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Continuation<'a> {
    /// Bytes to skip before the file data (one leading CRLF).
    pub(crate) skip: usize,
    /// The file data, starting at `skip`.
    pub(crate) body: &'a [u8],
}

/// The continuation that follows a completed message.
///
/// Printable bytes after a completed message are file data once a complete
/// first line is available; one leading CRLF is ignored, and a first line that
/// parses as a start line starts a message instead.
///
/// `newline` is the first LF at or after the continuation probe. The
/// reassembler scans incrementally and caches it, so a hostile long first line
/// is examined once per pending message rather than once per segment.
pub(crate) fn continuation<'a>(data: &'a [u8], newline: Option<usize>) -> Option<Continuation<'a>> {
    let skip = probe_start(data);
    let probe = data.get(skip..)?;
    let first = *probe.first()?;
    if !(0x20..=0x7e).contains(&first) {
        return None;
    }
    let mut line = data.get(skip..newline?)?;
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped;
    }
    if parse_start_line(line).is_some() {
        return None;
    }
    Some(Continuation { skip, body: probe })
}

/// The continuation in `data`, scanning for its first line.
///
/// The decoder owns only the presented segment, so it has no cached scan.
pub(crate) fn continuation_at(data: &[u8]) -> Option<Continuation<'_>> {
    let skip = probe_start(data);
    let newline = data
        .get(skip..)?
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|index| index.saturating_add(skip))?;
    continuation(data, Some(newline))
}

/// The offset of the continuation probe, past one leading CRLF.
fn probe_start(data: &[u8]) -> usize {
    if data.starts_with(b"\r\n") { 2 } else { 0 }
}

/// One chunk whose data is still arriving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingChunk {
    /// Offset of the chunk's size line.
    pub(crate) line: usize,
    /// Offset of the chunk data, just past the size line.
    pub(crate) data: usize,
    /// Declared size.
    pub(crate) size: usize,
}

/// One structural element of a chunked body (RFC 9112 section 7.1).
#[derive(Clone, Copy, Debug)]
pub(crate) enum ChunkStep<'a> {
    /// A complete data chunk.
    Data {
        /// Offset of the chunk's size line.
        line: usize,
        /// Declared size.
        size: usize,
        /// Offset of the chunk data.
        data: usize,
        /// The chunk data.
        bytes: &'a [u8],
        /// Offset of the two bytes between the data and the next size line.
        boundary: usize,
        /// Whether those two bytes were the CRLF the section requires. A
        /// malformed boundary is reported, not resynchronised.
        boundary_ok: bool,
    },
    /// The zero-size last chunk's size line; the trailer section follows.
    Last,
    /// One trailer field line.
    Trailer {
        /// Offset of the line.
        line: usize,
        /// Bytes consumed, terminator included.
        consumed: usize,
    },
    /// The empty line that ends the trailer section, which also ends the body.
    TrailerEnd {
        /// Offset just past the empty line.
        end: usize,
        /// Offset of the last-chunk size line.
        last: usize,
    },
    /// The grammar cannot continue without more bytes.
    Incomplete {
        /// Offset of the incomplete size or trailer line, or of the pending
        /// chunk's data.
        restart: usize,
        /// The chunk whose data is still arriving.
        pending: Option<PendingChunk>,
        /// The stop is inside the trailer section.
        trailers: bool,
    },
    /// A size line is not a hexadecimal length.
    Invalid {
        /// Offset of the unusable size line.
        at: usize,
    },
}

/// Scan position within one chunked message body (RFC 9112 section 7.1).
///
/// Positions are relative to the slice passed to [`Self::step`]. The scan
/// position survives across calls, so a body split across segments is scanned
/// once and [`Self::step`] is linear in the bytes it is shown; an incomplete
/// size or trailer line is not rescanned from its start on every call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChunkScanner {
    /// Offset of the next structure.
    position: usize,
    /// The chunk whose data is still arriving.
    pending: Option<PendingChunk>,
    /// The last-chunk line arrived; trailer lines are being read.
    trailers: bool,
    /// Offset of the last-chunk size line.
    last: usize,
    /// End already searched for the current line's CRLF.
    line_scan: usize,
}

impl ChunkScanner {
    /// Start a scan at `position`, the first byte after the header section.
    pub(crate) fn new(position: usize) -> Self {
        Self {
            position,
            pending: None,
            trailers: false,
            last: 0,
            line_scan: 0,
        }
    }

    /// Advance to the next structural element within `data[..end]`.
    pub(crate) fn step<'a>(&mut self, data: &'a [u8], end: usize) -> ChunkStep<'a> {
        loop {
            if self.trailers {
                let start = self.position.max(self.line_scan.saturating_sub(1));
                let Some(line_end) = find_crlf(data, start, end) else {
                    self.line_scan = end;
                    return ChunkStep::Incomplete {
                        restart: self.position,
                        pending: None,
                        trailers: true,
                    };
                };
                self.line_scan = 0;
                if line_end == self.position {
                    let end = self.position.saturating_add(2);
                    self.position = end;
                    return ChunkStep::TrailerEnd {
                        end,
                        last: self.last,
                    };
                }
                let line = self.position;
                self.position = line_end.saturating_add(2);
                return ChunkStep::Trailer {
                    line,
                    consumed: self.position.saturating_sub(line),
                };
            }
            if let Some(pending) = self.pending {
                let data_end = pending.data.saturating_add(pending.size);
                let boundary_end = data_end.saturating_add(2);
                if end < boundary_end {
                    return ChunkStep::Incomplete {
                        restart: pending.data,
                        pending: Some(pending),
                        trailers: false,
                    };
                }
                let bytes = data.get(pending.data..data_end).unwrap_or_default();
                let boundary_ok = data.get(data_end..boundary_end) == Some(b"\r\n");
                self.position = boundary_end;
                self.pending = None;
                self.line_scan = 0;
                return ChunkStep::Data {
                    line: pending.line,
                    size: pending.size,
                    data: pending.data,
                    bytes,
                    boundary: data_end,
                    boundary_ok,
                };
            }
            let start = self.position.max(self.line_scan.saturating_sub(1));
            let Some(line_end) = find_crlf(data, start, end) else {
                self.line_scan = end;
                return ChunkStep::Incomplete {
                    restart: self.position,
                    pending: None,
                    trailers: false,
                };
            };
            self.line_scan = 0;
            let size_text = data
                .get(self.position..line_end)
                .unwrap_or_default()
                .split(|byte| *byte == b';')
                .next()
                .unwrap_or_default();
            let Ok(size_text) = std::str::from_utf8(size_text) else {
                return ChunkStep::Invalid { at: self.position };
            };
            let Ok(size) = usize::from_str_radix(size_text.trim(), 16) else {
                return ChunkStep::Invalid { at: self.position };
            };
            let line = self.position;
            self.position = line_end.saturating_add(2);
            if size == 0 {
                self.trailers = true;
                self.last = line;
                return ChunkStep::Last;
            }
            self.pending = Some(PendingChunk {
                line,
                data: self.position,
                size,
            });
        }
    }
}

/// Find the next CRLF at or after `start`, bounded by `end`.
fn find_crlf(data: &[u8], start: usize, end: usize) -> Option<usize> {
    let window = data.get(start..end)?;
    window
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| start.saturating_add(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framing(block: &[u8]) -> Framing {
        Framing::of_block(block)
    }

    fn plan(block: &[u8], answer: Answer) -> BodyPlan {
        framing(block).body_plan(answer)
    }

    #[test]
    fn published_start_line_forms_are_recognized() {
        assert!(parse_start_line(b"GET / HTTP/1.1").is_some());
        assert!(parse_start_line(b"HTTP/1.1 204 No Content").is_some());
        assert!(parse_start_line(b"HTTP/1.2 200 OK").is_none());
        assert!(parse_start_line(b"GET / HTTP/2.0").is_none());
        assert!(parse_start_line(b"NOT A REQUEST").is_none());
    }

    #[test]
    fn a_chunked_coding_overrides_content_length() {
        // RFC 9112 section 6.3 case 3 and section 6.1: both fields must not
        // be present, and the chunked coding decides the framing.
        let block = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let facts = framing(block);
        assert!(facts.chunked);
        assert_eq!(facts.content_length, Some(5));
        assert_eq!(facts.body_plan(Answer::default()), BodyPlan::Chunked);
    }

    #[test]
    fn a_transfer_coding_that_is_not_chunked_overrides_content_length() {
        // RFC 9112 section 6.1: a message with both fields is framed by its
        // Transfer-Encoding, never by the declared length. RFC 9112 section
        // 6.3 case 4 then leaves a response to the connection close; a request
        // that carries such a coding cannot be framed at all.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(plan(response, Answer::default()), BodyPlan::CloseDelimited);
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(plan(response, Answer::default()), BodyPlan::CloseDelimited);
        let request = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(plan(request, Answer::default()), BodyPlan::InvalidLength);
        let request = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(plan(request, Answer::default()), BodyPlan::InvalidLength);
    }

    #[test]
    fn an_empty_transfer_coding_carries_no_framing() {
        // RFC 9112 section 6.1 requires at least one coding; an empty field is
        // malformed, so it neither selects chunked nor hides Content-Length.
        let block = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\nContent-Length: 4\r\n\r\n";
        let facts = framing(block);
        assert!(!facts.chunked);
        assert!(!facts.transfer_coding);
        assert_eq!(facts.body_plan(Answer::default()), BodyPlan::Fixed(4));
    }

    #[test]
    fn only_a_final_chunked_coding_selects_chunk_framing() {
        // RFC 9112 sections 6.1 and 7.1: chunked is usable only as the final
        // transfer coding.
        for value in ["chunked", "gzip, chunked", "CHUNKED", "gzip , chunked"] {
            let block = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {value}\r\n\r\n");
            let facts = framing(block.as_bytes());
            assert!(facts.transfer_coding, "value {value:?}");
            assert!(facts.chunked, "value {value:?}");
            assert_eq!(facts.body_plan(Answer::default()), BodyPlan::Chunked);
        }
        for value in ["chunked, gzip", "chunked,chunked, gzip", "xchunked", "gzip"] {
            let block = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {value}\r\n\r\n");
            let facts = framing(block.as_bytes());
            assert!(facts.transfer_coding, "value {value:?}");
            assert!(!facts.chunked, "value {value:?}");
            assert_eq!(
                facts.body_plan(Answer::default()),
                BodyPlan::CloseDelimited,
                "value {value:?}"
            );
        }
        // A coding parameter belongs to the coding, not to its name.
        let parameter = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked; q=1\r\n\r\n";
        assert!(framing(parameter).chunked);
        // Repeated fields combine into one list (RFC 9110 section 5.2), so the
        // last coding of the last field decides.
        let block =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(framing(block).chunked);
        let block =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(!framing(block).chunked);
    }

    #[test]
    fn content_length_is_the_body_length_when_nothing_overrides_it() {
        let block = b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n";
        assert_eq!(plan(block, Answer::default()), BodyPlan::Fixed(17));
        let block = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\n";
        assert_eq!(plan(block, Answer::default()), BodyPlan::Fixed(3));
    }

    #[test]
    fn repeated_content_length_values_must_agree() {
        // RFC 9112 section 6.3: repeated fields with the same decimal value
        // may be collapsed into one; any disagreement or unreadable value
        // makes the length unusable, and no later field recovers it.
        let same = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let facts = framing(same);
        assert!(!facts.invalid_length);
        assert_eq!(facts.content_length, Some(5));
        assert_eq!(facts.body_plan(Answer::default()), BodyPlan::Fixed(5));

        // "05" and "5" carry the same decimal value.
        let padded = b"HTTP/1.1 200 OK\r\nContent-Length: 05\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(plan(padded, Answer::default()), BodyPlan::Fixed(5));

        // A single field may list identical decimal values.
        let listed = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n";
        assert_eq!(plan(listed, Answer::default()), BodyPlan::Fixed(5));

        for block in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\nContent-Length: 5\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: abc\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ] {
            let facts = framing(block);
            assert!(facts.invalid_length, "{block:?}");
            assert_eq!(facts.content_length, None, "{block:?}");
            assert_eq!(
                facts.body_plan(Answer::default()),
                BodyPlan::InvalidLength,
                "{block:?}"
            );
        }
    }

    #[test]
    fn bodyless_responses_end_at_the_header_section() {
        // RFC 9112 section 6.3 case 1: 1xx, 204 and 304 responses are
        // terminated by the empty line whatever their fields declare.
        for line in [
            b"HTTP/1.1 100 Continue\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\n\r\n",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n",
            b"HTTP/1.1 304 Not Modified\r\n\r\n",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
        ] {
            assert_eq!(plan(line, Answer::default()), BodyPlan::Empty, "{line:?}");
        }
        // A response to HEAD describes the body a GET answer would carry and
        // carries none of it.
        let head = Answer {
            head: true,
            connect: false,
        };
        let block = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        assert_eq!(plan(block, head), BodyPlan::Empty);
        assert_eq!(plan(b"HTTP/1.1 200 OK\r\n\r\n", head), BodyPlan::Empty);
    }

    #[test]
    fn only_a_connect_tunnel_owns_its_captured_bytes() {
        // RFC 9112 section 9.3.6: a 2xx answer to CONNECT turns the connection
        // into a tunnel, and every captured trailing byte belongs to it.
        let connect = Answer {
            head: false,
            connect: true,
        };
        let block = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        assert_eq!(plan(block, connect), BodyPlan::Answer);
        assert_eq!(plan(b"HTTP/1.1 200 OK\r\n\r\n", connect), BodyPlan::Answer);
        // A failed CONNECT keeps the response rules.
        let failed = b"HTTP/1.1 403 Forbidden\r\n\r\n";
        assert_eq!(plan(failed, connect), BodyPlan::CloseDelimited);
    }

    #[test]
    fn a_close_delimited_response_and_a_bodyless_request() {
        let response = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(plan(response, Answer::default()), BodyPlan::CloseDelimited);
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(plan(request, Answer::default()), BodyPlan::Empty);
    }

    #[test]
    fn a_header_line_without_a_colon_is_invalid() {
        let line = parse_header_line(b"Host x", 0);
        assert!(!line.colon);
        assert!(!line.valid);
        assert_eq!(line.offset, 0);
        let line = parse_header_line(b"Content-Length: 5 ", 7);
        assert!(line.valid);
        assert_eq!(line.value, "5");
        assert_eq!(line.offset, 7);
        assert_eq!(line.raw, b"Content-Length: 5 ");
    }

    #[test]
    fn the_decoder_budget_counts_bytes_and_field_lines() {
        let mut budget = HeaderBudget::default();
        assert!(budget.take(MAX_HEADER_BYTES, false));
        assert!(!budget.take(1, false));
        let mut budget = HeaderBudget::default();
        for _ in 0..MAX_HEADER_LINES {
            assert!(budget.take(4, true));
        }
        assert!(!budget.take(4, true));
        // The terminator line is not a field and stays inside the line cap.
        assert!(budget.take(2, false));
    }

    #[test]
    fn framing_facts_survive_blocks_at_both_decoder_caps() {
        // The reassembler frames a message the decoder will not dissect, so
        // the framer must derive its facts without the display caps.
        let mut block = b"HTTP/1.1 200 OK\r\n".to_vec();
        for index in 0..MAX_HEADER_LINES {
            block.extend_from_slice(format!("X-{index}: v\r\n").as_bytes());
        }
        block.extend_from_slice(b"Content-Length: 7\r\n\r\n");
        assert_eq!(
            framing(&block).body_plan(Answer::default()),
            BodyPlan::Fixed(7)
        );
        let mut block = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        block.resize(MAX_HEADER_BYTES, b'a');
        block.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            framing(&block).body_plan(Answer::default()),
            BodyPlan::CloseDelimited
        );
    }

    #[test]
    fn a_continuation_skips_one_crlf_and_rejects_a_start_line() {
        let data = b"\r\ngarbage\n";
        let step = continuation_at(data);
        assert!(
            matches!(step, Some(Continuation { .. })),
            "a printable non-start line must be a continuation: {step:?}"
        );
        let Some(continuation) = step else {
            unreachable!("the continuation was asserted to be present");
        };
        assert_eq!(continuation.skip, 2);
        assert_eq!(continuation.body, b"garbage\n");
        assert!(continuation_at(b"GET / HTTP/1.1\r\n").is_none());
        assert!(continuation_at(b"\x00binary\n").is_none());
        assert!(continuation_at(b"no newline").is_none());
    }

    #[test]
    fn the_header_terminator_is_the_first_empty_line() {
        let data = b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody";
        assert_eq!(header_section_end(data), Some(25));
        assert_eq!(
            next_line(data, 0),
            Some((b"HTTP/1.1 200 OK".as_slice(), 17))
        );
        assert_eq!(header_section_end(b"no terminator"), None);
    }

    #[test]
    fn chunk_grammar_accepts_the_rfc_9112_form() {
        let body = b"5;ext=1\r\nHello\r\n6\r\n world\r\n0\r\nX-Trailer: v\r\n\r\n";
        let mut scanner = ChunkScanner::new(0);
        let mut pieces: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut trailer: Option<(usize, usize)> = None;
        let mut end = None;
        while end.is_none() {
            match scanner.step(body, body.len()) {
                ChunkStep::Data {
                    line,
                    size,
                    bytes,
                    boundary_ok,
                    ..
                } => {
                    assert!(boundary_ok);
                    assert_eq!(bytes.len(), size);
                    pieces.push((line, bytes.to_vec()));
                }
                ChunkStep::Last => {}
                ChunkStep::Trailer { line, consumed } => trailer = Some((line, consumed)),
                ChunkStep::TrailerEnd { end: offset, last } => {
                    assert_eq!(last, 27);
                    end = Some(offset);
                }
                ChunkStep::Incomplete { .. } | ChunkStep::Invalid { .. } => break,
            }
        }
        assert_eq!(end, Some(body.len()));
        assert_eq!(
            pieces,
            vec![(0, b"Hello".to_vec()), (16, b" world".to_vec())]
        );
        assert_eq!(trailer, Some((30, 14)));
    }

    #[test]
    fn a_chunk_size_split_across_calls_is_scanned_once() {
        let body = b"5\r\nHello\r\n0\r\n\r\n";
        let mut scanner = ChunkScanner::new(0);
        // Only the first byte of the size line has arrived.
        assert!(matches!(
            scanner.step(body, 1),
            ChunkStep::Incomplete {
                restart: 0,
                pending: None,
                trailers: false
            }
        ));
        let step = scanner.step(body, body.len());
        assert!(
            matches!(step, ChunkStep::Data { .. }),
            "a complete chunk must be reported as data: {step:?}"
        );
        let ChunkStep::Data { size, bytes, .. } = step else {
            unreachable!("the step was asserted to be a data chunk");
        };
        assert_eq!(size, 5);
        assert_eq!(bytes, b"Hello");
        assert!(matches!(scanner.step(body, body.len()), ChunkStep::Last));
        assert!(matches!(
            scanner.step(body, body.len()),
            ChunkStep::TrailerEnd { end: 15, last: 10 }
        ));
    }

    #[test]
    fn chunk_data_split_across_calls_reports_the_pending_chunk() {
        let body = b"5\r\nHel";
        let mut scanner = ChunkScanner::new(0);
        let step = scanner.step(body, body.len());
        assert!(
            matches!(
                step,
                ChunkStep::Incomplete {
                    pending: Some(_),
                    ..
                }
            ),
            "a partially delivered chunk must report its pending size: {step:?}"
        );
        let ChunkStep::Incomplete {
            restart,
            pending: Some(pending),
            trailers,
        } = step
        else {
            unreachable!("the step was asserted to carry a pending chunk");
        };
        assert_eq!(restart, 3);
        assert!(!trailers);
        assert_eq!(pending.data, 3);
        assert_eq!(pending.size, 5);
        // The reassembler uses the pending size to refuse a chunk longer than
        // its reassembly limit before the bytes arrive.
        assert!(pending.data.saturating_add(pending.size) > body.len());
    }

    #[test]
    fn an_unusable_chunk_size_ends_the_entity() {
        for body in [
            b"zz\r\n".as_slice(),
            // A size that does not fit in usize is unusable, not a huge chunk.
            b"fffffffffffffffff\r\n",
            // So is a size line that is not text at all.
            b"\xff\r\n",
        ] {
            let mut scanner = ChunkScanner::new(0);
            assert!(matches!(
                scanner.step(body, body.len()),
                ChunkStep::Invalid { at: 0 }
            ));
        }
    }

    #[test]
    fn a_malformed_chunk_boundary_is_reported_not_resynchronised() {
        let body = b"1\r\naXX1\r\nb\r\n0\r\n\r\n";
        let mut scanner = ChunkScanner::new(0);
        let step = scanner.step(body, body.len());
        assert!(
            matches!(
                step,
                ChunkStep::Data {
                    boundary_ok: false,
                    ..
                }
            ),
            "the non-CRLF boundary must be reported: {step:?}"
        );
        let ChunkStep::Data {
            line, boundary_ok, ..
        } = step
        else {
            unreachable!("the step was asserted to be a data chunk");
        };
        assert_eq!(line, 0);
        assert!(!boundary_ok);
        // The two bytes are consumed, so the next size line is read from the
        // position the wire declares.
        let step = scanner.step(body, body.len());
        assert!(
            matches!(step, ChunkStep::Data { .. }),
            "the next chunk must still decode: {step:?}"
        );
        let ChunkStep::Data { line, .. } = step else {
            unreachable!("the step was asserted to be a data chunk");
        };
        assert_eq!(line, 6);
    }

    #[test]
    fn a_trailer_section_that_never_ends_needs_more_bytes() {
        let body = b"0\r\nX-Trailer: v\r\n";
        let mut scanner = ChunkScanner::new(0);
        assert!(matches!(scanner.step(body, body.len()), ChunkStep::Last));
        assert!(matches!(
            scanner.step(body, body.len()),
            ChunkStep::Trailer { line: 3, .. }
        ));
        let step = scanner.step(body, body.len());
        assert!(
            matches!(step, ChunkStep::Incomplete { trailers: true, .. }),
            "an unterminated trailer section must wait for bytes: {step:?}"
        );
        let ChunkStep::Incomplete {
            restart,
            pending: None,
            trailers: true,
        } = step
        else {
            unreachable!("the step was asserted to be an incomplete trailer section");
        };
        assert_eq!(restart, body.len());
    }
}
