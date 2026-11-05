//! `-G` glossary reports.

use std::io::{self, Write};

use packetfin_core::fields;

/// Write the field glossary: one `F` row per registered field.
///
/// The columns are record type, name, abbreviation, field type,
/// parent protocol, display base, bitmask and description.
pub fn write_fields(writer: &mut impl Write) -> io::Result<()> {
    for protocol in fields::protocols() {
        for field in protocol.fields.iter().copied() {
            writeln!(
                writer,
                "F\t{}\t{}\t{}\t{}\t{}\t0x{:x}\t{}",
                field.name,
                field.abbrev,
                field.field_type.abbreviation(),
                field.parent,
                field.display.report_name(),
                field.bitmask.unwrap_or(0),
                field.blurb
            )?;
        }
    }
    Ok(())
}

/// Write the protocol glossary: long name, short name, filter name and the
/// three availability flags.
pub fn write_protocols(writer: &mut impl Write) -> io::Result<()> {
    for protocol in fields::protocols() {
        // The third protocol flag is `F` for the frame pseudo-protocol and
        // `T` for every other protocol. Keep that mapping until the registry
        // has a reason to carry the flag itself.
        let last_flag = if protocol.filter_name == "frame" {
            "F"
        } else {
            "T"
        };
        writeln!(
            writer,
            "{}\t{}\t{}\tT\tT\t{}",
            protocol.long_name, protocol.short_name, protocol.filter_name, last_flag
        )?;
    }
    Ok(())
}

/// Write the heuristic-decoder glossary.
///
/// Columns: parent table, protocol filter
/// name, enabled by default, can be disabled, short name and long name.
pub fn write_heuristic_decodes(writer: &mut impl Write) -> io::Result<()> {
    for heuristic in packetfin_core::decode::HEURISTICS {
        writeln!(
            writer,
            "{}\t{}\t{}\tT\t{}\t{}",
            heuristic.layer.table_name(),
            heuristic.protocol.filter_name(),
            if heuristic.enabled_by_default {
                "T"
            } else {
                "F"
            },
            heuristic.short_name,
            heuristic.long_name
        )?;
    }
    Ok(())
}

/// Write the `-G` help text.
pub fn write_help(writer: &mut impl Write) -> io::Result<()> {
    writeln!(writer, "Usage: packetfin -G <report>")?;
    writeln!(writer)?;
    writeln!(writer, "Glossary table reports:")?;
    writeln!(writer, "  -G fields      Dump the field registry and exit.")?;
    writeln!(
        writer,
        "  -G protocols   Dump the protocol registry and exit."
    )?;
    writeln!(
        writer,
        "  -G heuristic-decodes  Dump the heuristic-decoder registry and exit."
    )?;
    writeln!(writer, "  -G help        Print this help text and exit.")?;
    Ok(())
}
