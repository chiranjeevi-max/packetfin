//! pcapng option encoding shared by section, interface and packet blocks.
//!
//! Options are emitted in source order. Values shorter than four bytes are
//! padded with zeroes, and a list ends with the `opt_endofopt` marker when it
//! contains at least one option; option-free interface and packet blocks
//! carry no marker.

use crate::capture::{InterfaceOption, PacketOption, SectionOption, TimestampResolution};

use super::WriteError;

const OPT_END: u16 = 0;
const OPT_COMMENT: u16 = 1;
const OPT_SHB_HARDWARE: u16 = 2;
const OPT_SHB_OS: u16 = 3;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_DESCRIPTION: u16 = 3;
const OPT_IF_SPEED: u16 = 8;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_IF_FILTER: u16 = 11;
const OPT_IF_OS: u16 = 12;
const OPT_IF_FCSLEN: u16 = 13;
const OPT_IF_TSOFFSET: u16 = 14;
const OPT_IF_HARDWARE: u16 = 15;
const OPT_EPB_FLAGS: u16 = 2;
const OPT_EPB_HASH: u16 = 3;
const OPT_EPB_DROPCOUNT: u16 = 4;
const OPT_EPB_PACKETID: u16 = 5;
const OPT_EPB_QUEUE: u16 = 6;
const OPT_EPB_VERDICT: u16 = 7;

fn push_option(out: &mut Vec<u8>, code: u16, value: &[u8]) -> Result<(), WriteError> {
    let length = u16::try_from(value.len()).map_err(|_| WriteError::OptionTooLong {
        code,
        length: value.len(),
    })?;
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    Ok(())
}

fn push_end(out: &mut Vec<u8>) {
    out.extend_from_slice(&OPT_END.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
}

/// Append a text option unless it is empty or cannot fit the length field.
///
/// Empty string options and options longer than 65535 bytes after decoding
/// are dropped, including values whose lossy UTF-8 expansion grew past the
/// limit. Binary option values keep the strict error so a caller bug is still
/// reported.
fn push_text(out: &mut Vec<u8>, code: u16, text: &str) -> Result<bool, WriteError> {
    if text.is_empty() || text.len() > usize::from(u16::MAX) {
        return Ok(false);
    }
    push_option(out, code, text.as_bytes())?;
    Ok(true)
}

fn push_tsresol(out: &mut Vec<u8>, resolution: TimestampResolution) -> Result<(), WriteError> {
    let code = match resolution {
        TimestampResolution::PowerOfTen(exponent) => exponent,
        TimestampResolution::PowerOfTwo(exponent) => 0x80 | (exponent & 0x7f),
    };
    push_option(out, OPT_IF_TSRESOL, &[code])
}

/// Append section header options in source order.
///
/// The application identity is appended when the source had no
/// `shb_userappl`. An empty source value still counts as present: the empty
/// option is dropped and nothing replaces it. Capture comments are appended
/// after every source option; empty comments and comments longer than 65535
/// bytes are dropped. The end-of-options marker is written only when at
/// least one option was emitted.
pub(crate) fn push_section(
    out: &mut Vec<u8>,
    options: &[SectionOption],
    application: &str,
    capture_comments: &[String],
) -> Result<(), WriteError> {
    let mut has_application = false;
    let mut emitted = false;
    for option in options {
        match option {
            SectionOption::Hardware(text) => {
                emitted |= push_text(out, OPT_SHB_HARDWARE, text)?;
            }
            SectionOption::Os(text) => {
                emitted |= push_text(out, OPT_SHB_OS, text)?;
            }
            SectionOption::UserApplication(text) => {
                has_application = true;
                emitted |= push_text(out, OPT_SHB_USERAPPL, text)?;
            }
            SectionOption::Comment(text) => {
                emitted |= push_text(out, OPT_COMMENT, text)?;
            }
        }
    }
    if !has_application {
        emitted |= push_text(out, OPT_SHB_USERAPPL, application)?;
    }
    for comment in capture_comments {
        emitted |= push_text(out, OPT_COMMENT, comment)?;
    }
    if emitted {
        push_end(out);
    }
    Ok(())
}

/// Append interface description options in source order.
pub(crate) fn push_interface(
    out: &mut Vec<u8>,
    options: &[InterfaceOption],
) -> Result<(), WriteError> {
    let mut emitted = false;
    for option in options {
        match option {
            InterfaceOption::Comment(text) => emitted |= push_text(out, OPT_COMMENT, text)?,
            InterfaceOption::Name(text) => emitted |= push_text(out, OPT_IF_NAME, text)?,
            InterfaceOption::Description(text) => {
                emitted |= push_text(out, OPT_IF_DESCRIPTION, text)?;
            }
            InterfaceOption::Speed(speed) => {
                push_option(out, OPT_IF_SPEED, &speed.to_le_bytes())?;
                emitted = true;
            }
            InterfaceOption::TimestampResolution(resolution) => {
                push_tsresol(out, *resolution)?;
                emitted = true;
            }
            InterfaceOption::Os(text) => emitted |= push_text(out, OPT_IF_OS, text)?,
            InterfaceOption::Filter(filter) => {
                if filter.is_empty() {
                    continue;
                }
                push_option(out, OPT_IF_FILTER, filter)?;
                emitted = true;
            }
            InterfaceOption::FcsLength(length) => {
                push_option(out, OPT_IF_FCSLEN, &[*length])?;
                emitted = true;
            }
            InterfaceOption::TimestampOffset(offset) => {
                push_option(out, OPT_IF_TSOFFSET, &offset.to_le_bytes())?;
                emitted = true;
            }
            InterfaceOption::Hardware(text) => emitted |= push_text(out, OPT_IF_HARDWARE, text)?,
        }
    }
    if emitted {
        push_end(out);
    }
    Ok(())
}

/// Append enhanced packet options in source order.
pub(crate) fn push_packet(out: &mut Vec<u8>, options: &[PacketOption]) -> Result<(), WriteError> {
    let mut emitted = false;
    for option in options {
        match option {
            PacketOption::Comment(text) => emitted |= push_text(out, OPT_COMMENT, text)?,
            PacketOption::Flags(flags) => {
                push_option(out, OPT_EPB_FLAGS, &flags.to_le_bytes())?;
                emitted = true;
            }
            PacketOption::Hash(hash) => {
                push_option(out, OPT_EPB_HASH, hash)?;
                emitted = true;
            }
            PacketOption::DropCount(count) => {
                push_option(out, OPT_EPB_DROPCOUNT, &count.to_le_bytes())?;
                emitted = true;
            }
            PacketOption::PacketId(id) => {
                push_option(out, OPT_EPB_PACKETID, &id.to_le_bytes())?;
                emitted = true;
            }
            PacketOption::Queue(queue) => {
                push_option(out, OPT_EPB_QUEUE, &queue.to_le_bytes())?;
                emitted = true;
            }
            PacketOption::Verdict(verdict) => {
                push_option(out, OPT_EPB_VERDICT, verdict)?;
                emitted = true;
            }
        }
    }
    if emitted {
        push_end(out);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{push_interface, push_option, push_packet, push_section};
    use crate::capture::{InterfaceOption, PacketOption, SectionOption, TimestampResolution};

    fn expected(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn an_option_pads_its_value_to_four_bytes() -> Result<(), String> {
        let mut out = Vec::new();
        push_option(&mut out, 2, b"abc").map_err(|error| error.to_string())?;
        assert_eq!(out, expected(&[&[2, 0, 3, 0], b"abc", &[0]]));
        Ok(())
    }

    #[test]
    fn an_oversized_option_is_rejected_before_writing() {
        let value = vec![0_u8; usize::from(u16::MAX) + 1];
        let mut out = Vec::new();
        assert!(push_option(&mut out, 2, &value).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn section_options_keep_order_and_add_the_application_last() -> Result<(), String> {
        let mut out = Vec::new();
        let options = vec![
            SectionOption::Hardware("hw".to_string()),
            SectionOption::Comment("one".to_string()),
            SectionOption::Os("os".to_string()),
        ];
        let comments = vec!["two".to_string(), String::new(), "x".repeat(65_536)];
        push_section(&mut out, &options, "app", &comments).map_err(|error| error.to_string())?;
        let expected = expected(&[
            &[2, 0, 2, 0],
            b"hw",
            &[0, 0],
            &[1, 0, 3, 0],
            b"one",
            &[0],
            &[3, 0, 2, 0],
            b"os",
            &[0, 0],
            &[4, 0, 3, 0],
            b"app",
            &[0],
            &[1, 0, 3, 0],
            b"two",
            &[0],
            &[0, 0, 0, 0],
        ]);
        assert_eq!(out, expected);
        Ok(())
    }

    #[test]
    fn a_source_application_suppresses_the_default_one() -> Result<(), String> {
        let mut out = Vec::new();
        let options = vec![SectionOption::UserApplication("source".to_string())];
        push_section(&mut out, &options, "packetfin", &[]).map_err(|error| error.to_string())?;
        let expected = expected(&[&[4, 0, 6, 0], b"source", &[0, 0], &[0, 0, 0, 0]]);
        assert_eq!(out, expected);
        Ok(())
    }

    #[test]
    fn interface_and_packet_lists_end_only_when_they_have_options() -> Result<(), String> {
        let mut interface = Vec::new();
        push_interface(&mut interface, &[]).map_err(|error| error.to_string())?;
        assert!(interface.is_empty());

        let mut packet = Vec::new();
        push_packet(&mut packet, &[]).map_err(|error| error.to_string())?;
        assert!(packet.is_empty());

        let mut packet = Vec::new();
        push_packet(
            &mut packet,
            &[
                PacketOption::Flags(1),
                PacketOption::Comment("pkt".to_string()),
                PacketOption::Hash(vec![2, 0, 1, 0]),
            ],
        )
        .map_err(|error| error.to_string())?;
        let expected = expected(&[
            &[2, 0, 4, 0],
            &[1, 0, 0, 0],
            &[1, 0, 3, 0],
            b"pkt",
            &[0],
            &[3, 0, 4, 0],
            &[2, 0, 1, 0],
            &[0, 0, 0, 0],
        ]);
        assert_eq!(packet, expected);
        Ok(())
    }

    #[test]
    fn binary_and_signed_interface_values_are_little_endian() -> Result<(), String> {
        let mut out = Vec::new();
        let options = vec![
            InterfaceOption::TimestampResolution(TimestampResolution::PowerOfTwo(10)),
            InterfaceOption::TimestampOffset(-2),
            InterfaceOption::Speed(1_000_000),
        ];
        push_interface(&mut out, &options).map_err(|error| error.to_string())?;
        let expected = expected(&[
            &[9, 0, 1, 0],
            &[0x8a, 0, 0, 0],
            &[14, 0, 8, 0],
            &(-2_i64).to_le_bytes(),
            &[8, 0, 8, 0],
            &1_000_000_u64.to_le_bytes(),
            &[0, 0, 0, 0],
        ]);
        assert_eq!(out, expected);
        Ok(())
    }

    #[test]
    fn empty_text_options_are_dropped_and_suppress_the_end_marker() -> Result<(), String> {
        let mut interface = Vec::new();
        push_interface(
            &mut interface,
            &[
                InterfaceOption::Name(String::new()),
                InterfaceOption::Description(String::new()),
                InterfaceOption::Os(String::new()),
                InterfaceOption::Hardware(String::new()),
                InterfaceOption::Comment(String::new()),
                InterfaceOption::Filter(Vec::new()),
            ],
        )
        .map_err(|error| error.to_string())?;
        assert!(interface.is_empty());

        let mut packet = Vec::new();
        push_packet(&mut packet, &[PacketOption::Comment(String::new())])
            .map_err(|error| error.to_string())?;
        assert!(packet.is_empty());

        // An empty source userappl counts as present, so the writer does not
        // substitute its own identity and emits no options at all.
        let mut section = Vec::new();
        push_section(
            &mut section,
            &[SectionOption::UserApplication(String::new())],
            "app",
            &[String::new()],
        )
        .map_err(|error| error.to_string())?;
        assert!(section.is_empty());
        Ok(())
    }

    #[test]
    fn text_options_at_the_65535_byte_boundary() -> Result<(), String> {
        let mut accepted = Vec::new();
        push_interface(&mut accepted, &[InterfaceOption::Name("x".repeat(65_535))])
            .map_err(|error| error.to_string())?;
        let (header, body) = accepted.split_at(4);
        assert_eq!(header, [2, 0, 0xff, 0xff]);
        assert_eq!(body.len(), 65_536 + 4);

        // A 65535-byte invalid UTF-8 value expands to 196605 bytes when the
        // reader decodes it lossily; the writer drops the expanded value
        // instead of failing the rewrite.
        let mut dropped = Vec::new();
        push_interface(&mut dropped, &[InterfaceOption::Name("x".repeat(196_605))])
            .map_err(|error| error.to_string())?;
        assert!(dropped.is_empty());

        let mut boundary = Vec::new();
        push_packet(&mut boundary, &[PacketOption::Comment("x".repeat(65_536))])
            .map_err(|error| error.to_string())?;
        assert!(boundary.is_empty());
        Ok(())
    }
}
