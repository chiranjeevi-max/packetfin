//! Packet-bytes output for `-x` and `--hexdump`.
//!
//! The captured frame bytes print as 16-byte rows: a lowercase offset
//! (four digits, widened once per frame when the last offset needs more),
//! two spaces, `xx ` per byte, two spaces before the ASCII column, then ASCII
//! for `0x20..=0x7e` and `.` otherwise. ASCII text is only present when
//! selected; without it the padding spaces remain. A separator line follows
//! every frame, including a frame with no captured bytes. The `--hexdump
//! time` preamble uses the `-t` format with the capture's precision by
//! default.

use std::fmt::Write as _;
use std::io::{self, Write};

use packetfin_core::Packet;
use packetfin_core::capture::{Frame, Timestamp};

use packetfin_core::tree::{Bytes, Value};

use crate::record_buffer::RecordBuffer;
use crate::summary::{TimeOptions, hexdump_time_text};

/// Parsed `-x` and `--hexdump` options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HexdumpOptions {
    /// Whether the ASCII column is printed.
    pub ascii: bool,
    /// Whether ASCII text is wrapped in `|` characters.
    pub delimit: bool,
    /// Whether the `-t` timestamp preamble is printed.
    pub time: bool,
}

impl Default for HexdumpOptions {
    fn default() -> Self {
        Self {
            ascii: true,
            delimit: false,
            time: false,
        }
    }
}

impl HexdumpOptions {
    /// Apply one `--hexdump` option, returning `false` for an unknown value.
    ///
    /// `all` and `frames` are accepted for compatibility; the frame source is
    /// the only one this slice has, so they select the same bytes.
    pub fn apply(&mut self, option: &str) -> bool {
        match option {
            "all" | "frames" => {}
            "ascii" => {
                self.ascii = true;
                self.delimit = false;
            }
            "delimit" => {
                self.ascii = true;
                self.delimit = true;
            }
            "noascii" => {
                self.ascii = false;
                self.delimit = false;
            }
            "time" => self.time = true,
            "notime" => self.time = false,
            _ => return false,
        }
        true
    }
}

/// Renders one packet's hex dump.
pub struct HexdumpWriter {
    options: HexdumpOptions,
    time: TimeOptions,
    separator: Vec<u8>,
    first_timestamp: Option<Timestamp>,
    previous_captured: Option<Timestamp>,
    previous_displayed: Option<Timestamp>,
    text: RecordBuffer,
}

impl HexdumpWriter {
    /// Create a writer for the selected options and `-t` format.
    pub fn new(options: HexdumpOptions, time: TimeOptions, separator: &[u8]) -> Self {
        Self {
            options,
            time,
            separator: separator.to_vec(),
            first_timestamp: None,
            previous_captured: None,
            previous_displayed: None,
            text: RecordBuffer::new(),
        }
    }

    /// Record a frame that a display filter hides.
    pub fn observe_hidden(&mut self, frame: &Frame) {
        if let Some(timestamp) = frame.timestamp {
            self.first_timestamp.get_or_insert(timestamp);
            self.previous_captured = Some(timestamp);
        }
    }

    /// Write one displayed frame's preamble, dump and separator line.
    ///
    /// A frame that completed a reassembly has more than one byte source: it
    /// prints the frame bytes under a `Packet` label and each reassembled
    /// payload after it.
    pub fn write_packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
    ) -> io::Result<()> {
        self.text.clear();
        if self.options.time {
            match frame.timestamp {
                Some(timestamp) => {
                    let first = *self.first_timestamp.get_or_insert(timestamp);
                    let preamble = hexdump_time_text(
                        self.time,
                        timestamp,
                        first,
                        self.previous_captured,
                        self.previous_displayed,
                        frame.timestamp_precision,
                    );
                    self.text.push_str(&preamble);
                    self.text.push('\n');
                    self.previous_captured = Some(timestamp);
                    self.previous_displayed = Some(timestamp);
                }
                None => self.text.push('\n'),
            }
        }
        let fragments = reassembled_dumps(packet);
        let pdus = reassembled_pdus(packet);
        let handshakes = reassembled_handshakes(packet);
        let dechunked = dechunked_bodies(packet);
        if !fragments.is_empty()
            || !pdus.is_empty()
            || !handshakes.is_empty()
            || !dechunked.is_empty()
        {
            let _ = writeln!(self.text, "Packet ({} bytes):", frame.captured.len());
        }
        let width = offset_width(frame.captured.len());
        write_rows(
            &mut self.text,
            &frame.captured,
            width,
            self.options.ascii,
            self.options.delimit,
        );
        for (family, bytes) in &fragments {
            let _ = writeln!(self.text, "Reassembled {family} ({} bytes):", bytes.len());
            write_rows(
                &mut self.text,
                bytes,
                offset_width(bytes.len()),
                self.options.ascii,
                self.options.delimit,
            );
        }
        for pdu in &pdus {
            let _ = writeln!(self.text, "Reassembled TCP ({} bytes):", pdu.len());
            write_rows(
                &mut self.text,
                pdu,
                width,
                self.options.ascii,
                self.options.delimit,
            );
        }
        for handshake in &handshakes {
            let _ = writeln!(
                self.text,
                "Reassembled TLS Handshake ({} bytes):",
                handshake.len()
            );
            write_rows(
                &mut self.text,
                handshake,
                width,
                self.options.ascii,
                self.options.delimit,
            );
        }
        for body in &dechunked {
            let _ = writeln!(self.text, "De-chunked entity body ({} bytes):", body.len());
            write_rows(
                &mut self.text,
                body,
                width,
                self.options.ascii,
                self.options.delimit,
            );
        }
        self.text.emit(writer)?;
        writer.write_all(&self.separator)?;
        writer.write_all(b"\n")
    }
}

/// Every `tcp.reassembled.data` value in the packet tree, in field order.
fn reassembled_pdus(packet: &Packet) -> Vec<Bytes> {
    let mut pdus = Vec::new();
    let _ = packet.tree.frame.try_for_each_field::<()>(&mut |field| {
        if field.def.abbrev == "tcp.reassembled.data"
            && let Value::Bytes(bytes) = &field.value
        {
            pdus.push(bytes.clone());
        }
        Ok(())
    });
    pdus
}

/// Every reassembled TLS handshake message in the packet tree.
fn reassembled_handshakes(packet: &Packet) -> Vec<Bytes> {
    let mut handshakes = Vec::new();
    let _ = packet.tree.frame.try_for_each_field::<()>(&mut |field| {
        if field.def.abbrev == "tls.handshake.fragments"
            && let Value::Bytes(bytes) = &field.value
        {
            handshakes.push(bytes.clone());
        }
        Ok(())
    });
    handshakes
}

/// Every de-chunked HTTP entity body, one per chunked message.
///
/// The `-x` output adds a pseudo-section for a chunked message's decoded
/// body, whether or not the message was reassembled. A message without
/// `http.chunk_size` keeps its `http.file_data` in the packet dump only.
fn dechunked_bodies(packet: &Packet) -> Vec<Bytes> {
    let mut bodies = Vec::new();
    collect_chunked_bodies(&packet.tree.frame, &mut bodies);
    bodies
}

fn collect_chunked_bodies(node: &packetfin_core::tree::Node, bodies: &mut Vec<Bytes>) {
    if node.protocol.filter_name == "http" {
        let mut chunked = false;
        let mut body = None;
        let _ = node.try_for_each_field::<()>(&mut |field| {
            match field.def.abbrev {
                "http.chunk_size" => chunked = true,
                "http.file_data" => {
                    if let Value::Bytes(bytes) = &field.value {
                        body = Some(bytes.clone());
                    }
                }
                _ => {}
            }
            Ok(())
        });
        if chunked && let Some(body) = body {
            bodies.push(body);
        }
    }
    for child in &node.children {
        collect_chunked_bodies(child, bodies);
    }
}

/// Reassembled fragment payloads in tree order, with their IP family.
fn reassembled_dumps(packet: &Packet) -> Vec<(&'static str, Bytes)> {
    packet
        .tree
        .fields()
        .filter_map(|field| match field.def.abbrev {
            "ip.fragments" => match &field.value {
                Value::Bytes(bytes) => Some(("IPv4", bytes.clone())),
                _ => None,
            },
            "ipv6.reassembled.data" => match &field.value {
                Value::Bytes(bytes) => Some(("IPv6", bytes.clone())),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The offset width for one frame.
///
/// Four digits until the last offset exceeds `0xffff`, then the digits that
/// offset needs; every row in the frame uses the same width.
pub(crate) fn offset_width(length: usize) -> usize {
    let last = length.saturating_sub(1);
    let digits = if last == 0 {
        1
    } else {
        (usize::BITS - last.leading_zeros()) as usize
    };
    digits.div_ceil(4).max(1).max(4)
}

/// Write one frame's or nested data item's hex and optional ASCII rows.
///
/// `width` is the offset column width selected by [`offset_width`]; callers
/// pass the enclosing frame's width so nested dumps align with it.
pub(crate) fn write_rows(
    text: &mut dyn std::fmt::Write,
    bytes: &[u8],
    width: usize,
    ascii: bool,
    delimit: bool,
) {
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(text, "{:0width$x}  ", row * 16);
        for index in 0..16 {
            match chunk.get(index) {
                Some(byte) => {
                    let _ = write!(text, "{byte:02x} ");
                }
                None => {
                    let _ = text.write_str("   ");
                }
            }
        }
        let _ = text.write_str("  ");
        if ascii {
            if delimit {
                let _ = text.write_char('|');
            }
            for byte in chunk {
                let _ = text.write_char(if (0x20..=0x7e).contains(byte) {
                    char::from(*byte)
                } else {
                    '.'
                });
            }
            if delimit {
                let _ = text.write_char('|');
            }
        }
        let _ = text.write_char('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(bytes: &[u8], options: HexdumpOptions) -> String {
        let mut text = String::new();
        write_rows(
            &mut text,
            bytes,
            offset_width(bytes.len()),
            options.ascii,
            options.delimit,
        );
        text
    }

    #[test]
    fn rows_use_fixed_layout() {
        let bytes: Vec<u8> = (0..18).collect();
        let text = dump(&bytes, HexdumpOptions::default());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines.first().map(|line| line.len()), Some(72));
        assert_eq!(
            lines.first().copied(),
            Some("0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   ................")
        );
        assert_eq!(
            lines.get(1).copied(),
            Some("0010  10 11                                             ..")
        );
    }

    #[test]
    fn noascii_keeps_padding() {
        let lines: Vec<String> = dump(
            &[0xde, 0xad],
            HexdumpOptions {
                ascii: false,
                ..HexdumpOptions::default()
            },
        )
        .lines()
        .map(str::to_string)
        .collect();
        assert_eq!(lines.first().map(|line| line.len()), Some(56));
        assert!(lines.first().is_some_and(|line| line.ends_with("   ")));
    }

    #[test]
    fn delimit_wraps_ascii() {
        let lines: Vec<String> = dump(
            &[0x41, 0x42],
            HexdumpOptions {
                delimit: true,
                ..HexdumpOptions::default()
            },
        )
        .lines()
        .map(str::to_string)
        .collect();
        assert!(lines.first().is_some_and(|line| line.ends_with("|AB|")));
    }

    #[test]
    fn empty_input_writes_no_rows() {
        assert!(dump(&[], HexdumpOptions::default()).is_empty());
    }

    #[test]
    fn offset_width_widens_once_per_frame() {
        assert_eq!(offset_width(0), 4);
        assert_eq!(offset_width(1), 4);
        assert_eq!(offset_width(65_536), 4);
        assert_eq!(offset_width(65_537), 5);
        assert_eq!(offset_width(70_000), 5);
    }
}
