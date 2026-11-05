//! `-T ps` output: PostScript pages of summary, detail or hexdump text.
//!
//! The page prolog is Packetfin's own. The printable lines use the same text
//! as the corresponding text modes: one summary line per displayed packet, or
//! the `-V`/`-x` blocks, with detail indentation converted to a PostScript
//! indent count. Tests compare only the `putline` records with the golden
//! output.

use std::io::{self, Write};

use packetfin_core::Frame;
use packetfin_core::decode::Packet;

use crate::cli::CREATOR;
use crate::detail::{DetailOptions, DetailWriter};
use crate::hexdump::{HexdumpOptions, HexdumpWriter};
use crate::summary::{SummaryWriter, TimeOptions};

/// Streaming `-T ps` writer for one invocation.
pub struct PsWriter {
    summary: SummaryWriter,
    detail: Option<DetailWriter>,
    hexdump: Option<HexdumpWriter>,
    scratch: Vec<u8>,
    line: String,
}

impl PsWriter {
    /// Restart the summary state `-M` resets.
    pub fn reset_session(&mut self) {
        self.summary.reset_session();
    }

    /// Seed the summary time baseline from a skipped frame.
    pub fn observe_capture_time(&mut self, frame: &Frame) {
        self.summary.observe_capture_time(frame);
    }

    /// Prepare a writer for the selected detail, hexdump and time options.
    pub fn new(
        time: TimeOptions,
        detail: Option<DetailOptions>,
        hexdump: Option<HexdumpOptions>,
    ) -> Self {
        let hexdump_active = hexdump.is_some();
        Self {
            summary: SummaryWriter::new(time),
            detail: detail
                .as_ref()
                .map(|options| DetailWriter::new(options, &[], hexdump_active)),
            hexdump: hexdump.map(|options| HexdumpWriter::new(options, time, &[])),
            scratch: Vec::with_capacity(16 * 1024),
            line: String::with_capacity(16 * 1024),
        }
    }

    /// Write the PostScript header and page prolog.
    pub fn write_header(
        &self,
        writer: &mut impl Write,
        capture_file: &std::path::Path,
    ) -> io::Result<()> {
        let mut title = String::new();
        title.push_str(&capture_file.to_string_lossy());
        title.push_str(" - packetfin ");
        title.push_str(env!("CARGO_PKG_VERSION"));
        let mut escaped_title = String::new();
        escape_ps(&mut escaped_title, &title);
        let mut header = String::with_capacity(2048);
        header.push_str("%!PS-Adobe-3.0\n");
        header.push_str("%%Creator: ");
        header.push_str(CREATOR);
        header.push_str("\n%%Title: ");
        header.push_str(&escaped_title);
        header.push_str("\n%%DocumentFonts: Helvetica Monaco\n%%Pages: (atend)\n%%EndComments\n\n");
        header.push_str(PROLOG);
        header.push_str("\n/ws_title (");
        header.push_str(&escaped_title);
        header.push_str(") def\n\n");
        writer.write_all(header.as_bytes())
    }

    /// Record a frame that the display filter hides.
    pub fn observe_hidden(&mut self, frame: &Frame, packet: &Packet) {
        self.summary.observe_hidden(frame, packet, true);
        if let Some(detail) = &mut self.detail {
            detail.observe_hidden(frame);
        }
        if let Some(hexdump) = &mut self.hexdump {
            hexdump.observe_hidden(frame);
        }
    }

    /// Write one displayed packet's text records.
    pub fn write_packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
    ) -> io::Result<()> {
        self.line.clear();
        if self.detail.is_some() || self.hexdump.is_some() {
            if let Some(detail) = &mut self.detail {
                self.scratch.clear();
                detail.write_packet(&mut self.scratch, frame, packet)?;
                self.push_block(false);
            }
            if let Some(hexdump) = &mut self.hexdump {
                self.scratch.clear();
                hexdump.write_packet(&mut self.scratch, frame, packet)?;
                self.push_block(false);
            }
        } else {
            self.scratch.clear();
            self.summary
                .write_packet(&mut self.scratch, frame, packet, true, false)?;
            self.push_block(true);
        }
        writer.write_all(self.line.as_bytes())
    }

    /// Write the closing page decorations and end marker.
    pub fn finish(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(b"pf_decorate\nshowpage\n\n%%EOF\n")
    }

    fn push_block(&mut self, summary: bool) {
        let text = String::from_utf8_lossy(&self.scratch);
        for raw in text.split_inclusive('\n') {
            let line = raw.strip_suffix('\n').unwrap_or(raw);
            let (indent, body) = if summary {
                (0, line)
            } else {
                let spaces = line.len() - line.trim_start_matches(' ').len();
                (spaces / 4, &line[spaces..])
            };
            let mut escaped = String::new();
            let truncated: String = body.chars().take(255).collect();
            escape_ps(&mut escaped, &truncated);
            self.line.push_str(&indent.to_string());
            self.line.push_str(" (");
            self.line.push_str(&escaped);
            self.line.push_str(") putline\n");
        }
    }
}

/// Escape the three characters PostScript strings treat specially.
fn escape_ps(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
}

/// Packetfin's page prolog. It lays out 8-point Monaco text at ten-point
/// leading inside half-inch margins and decorates each rendered page.
const PROLOG: &str = r#"clippath pathbbox
/pf_ury exch def
/pf_urx exch def
pop pop

/pf_left 36 def
/pf_bottom 36 def
/pf_top pf_ury def
/pf_right pf_urx def
/pf_y pf_top 20 sub def
/pf_page 1 def
/pf_pageno 8 string def

/pf_break {
  pf_decorate
  showpage
  /pf_y pf_top 20 sub def
} def

/pf_decorate {
  gsave
  /Helvetica findfont 8 scalefont setfont
  pf_left pf_top 8 sub moveto ws_title show
  pf_right (Page ) stringwidth pop sub
  pf_page pf_pageno cvs stringwidth pop sub
  pf_top 8 sub moveto
  (Page ) show pf_page pf_pageno cvs show
  newpath pf_left pf_top 10 sub moveto pf_right pf_top 10 sub lineto stroke
  newpath pf_left pf_bottom moveto pf_right pf_bottom lineto stroke
  grestore
} def

/pf_line {
  exch 10 mul pf_left add pf_y moveto show
  /pf_y pf_y 10 sub def
  pf_y pf_bottom le { pf_break } if
} def

/pf_wrap {
  /pf_text exch def
  /pf_indent exch def
  /pf_width pf_right pf_left sub (M) stringwidth pop div cvi def
  pf_text length pf_width le
  { pf_indent pf_text pf_line }
  { pf_indent pf_text 0 pf_width getinterval pf_line
    pf_indent pf_text pf_width pf_text length pf_width sub getinterval pf_wrap }
  ifelse
} def

/Monaco findfont 8 scalefont setfont"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use std::path::Path;

    #[test]
    fn ps_summary_does_not_gain_container_output() {
        let frame = test_support::frame();
        let packet = test_support::packet(test_support::analysis_tree());
        let mut writer = PsWriter::new(TimeOptions::default(), None, None);
        let mut output = Vec::new();
        assert!(
            writer
                .write_header(&mut output, Path::new("test.pcap"))
                .is_ok()
        );
        assert!(writer.write_packet(&mut output, &frame, &packet).is_ok());
        assert!(writer.finish(&mut output).is_ok());
        let text = String::from_utf8(output).unwrap_or_default();
        assert!(!text.contains("SEQ/ACK"), "{text}");
        assert!(!text.contains("TCP Analysis Flags"), "{text}");
    }
}
