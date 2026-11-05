//! `-T psml` output: one XML element per summary column.
//!
//! The seven default summary columns are written as `<section>` elements:
//! a fixed `<structure>` block names them, then each displayed packet is a
//! `<packet>` with one section per column. The time column follows `-t` and
//! `-u`, and a display filter or `-c` selects packets exactly as the text
//! summary does. Packetfin reuses [`SummaryWriter`] so both outputs agree.

use std::io::{self, Write};

use packetfin_core::Frame;
use packetfin_core::decode::Packet;

use std::fmt::Write as _;

use crate::cli::CREATOR;
use crate::summary::{Columns, SummaryWriter, TimeOptions};
use crate::xml;

/// Streaming `-T psml` writer for one invocation.
pub struct PsmlWriter {
    summary: SummaryWriter,
    line: String,
    color: bool,
}

impl PsmlWriter {
    /// Restart the summary state `-M` resets.
    pub fn reset_session(&mut self) {
        self.summary.reset_session();
    }

    /// Seed the summary time baseline from a skipped frame.
    pub fn observe_capture_time(&mut self, frame: &Frame) {
        self.summary.observe_capture_time(frame);
    }

    /// Prepare a writer for the selected `-t`/`-u` options.
    pub fn new(time: TimeOptions) -> Self {
        Self {
            summary: SummaryWriter::new(time),
            line: String::with_capacity(256),
            color: false,
        }
    }

    /// Add packet foreground/background attributes when colour is enabled.
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// Write the XML declaration, root element and column structure.
    pub fn write_header(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")?;
        let mut line = String::with_capacity(128);
        line.push_str("<psml version=\"0\" creator=\"");
        xml::escape(&mut line, CREATOR);
        line.push_str("\">\n<structure>\n");
        for name in [
            "No.",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length",
            "Info",
        ] {
            line.push_str("<section>");
            xml::escape(&mut line, name);
            line.push_str("</section>\n");
        }
        line.push_str("</structure>\n\n");
        writer.write_all(line.as_bytes())
    }

    /// Record a frame that the display filter hides.
    pub fn observe_hidden(&mut self, frame: &Frame, packet: &Packet) {
        self.summary.observe_hidden(frame, packet, true);
    }

    /// Write one displayed packet block.
    pub fn write_packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
    ) -> io::Result<()> {
        let columns = self.summary.columns(frame, packet);
        self.line.clear();
        if self.color
            && let Some(rule) = crate::color::rule_for(&packet.tree)
        {
            let _ = writeln!(
                self.line,
                "<packet foreground='{}' background='{}'>",
                crate::color::hex(rule.foreground),
                crate::color::hex(rule.background)
            );
        } else {
            self.line.push_str("<packet>\n");
        }
        for section in columns_sections(&columns) {
            self.line.push_str("<section>");
            xml::escape_show(&mut self.line, &section);
            self.line.push_str("</section>\n");
        }
        self.line.push_str("</packet>\n\n");
        writer.write_all(self.line.as_bytes())
    }

    /// Close the root element.
    pub fn finish(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(b"</psml>\n")
    }
}

fn columns_sections(columns: &Columns) -> [String; 7] {
    [
        columns.number.to_string(),
        columns.time.clone(),
        columns.source.clone(),
        columns.destination.clone(),
        columns.protocol.clone(),
        columns.length.to_string(),
        columns.info.clone(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn psml_does_not_gain_container_output() {
        let frame = test_support::frame();
        let packet = test_support::packet(test_support::analysis_tree());
        let mut writer = PsmlWriter::new(TimeOptions::default());
        let mut output = Vec::new();
        assert!(writer.write_header(&mut output).is_ok());
        assert!(writer.write_packet(&mut output, &frame, &packet).is_ok());
        assert!(writer.finish(&mut output).is_ok());
        let text = String::from_utf8(output).unwrap_or_default();
        assert!(!text.contains("SEQ/ACK"), "{text}");
        assert!(!text.contains("TCP Analysis Flags"), "{text}");
    }
}
