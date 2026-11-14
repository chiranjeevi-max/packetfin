//! pcapng writer.
//!
//! One little-endian section is emitted. Section, interface and packet
//! options keep their source order; unknown options never reach this writer.
//! Later source sections are merged: their options are dropped and their
//! interfaces are appended with global ids.

use std::io::Write;

use super::options;
use super::sink::Output;
use super::{MAX_PACKET_SIZE, PacketRecord, WriteError};
use crate::capture::{InterfaceInfo, InterfaceOption, SectionInfo, TimestampResolution};

const SHB_TYPE: u32 = 0x0a0d_0d0a;
const IDB_TYPE: u32 = 0x0000_0001;
const SPB_TYPE: u32 = 0x0000_0003;
const NRB_TYPE: u32 = 0x0000_0004;
const EPB_TYPE: u32 = 0x0000_0006;

const LINKTYPE_ERF: u32 = 197;
const SNAP_LEN: u32 = 262_144;

pub(crate) struct Writer<W: Write> {
    out: Output<W>,
    application: String,
    capture_comments: Vec<String>,
    section: Option<SectionInfo>,
    interfaces: usize,
    opened: bool,
}

impl<W: Write> Writer<W> {
    pub(crate) fn new(out: Output<W>, application: &str, capture_comments: &[String]) -> Self {
        Self {
            out,
            application: application.to_string(),
            capture_comments: capture_comments.to_vec(),
            section: None,
            interfaces: 0,
            opened: false,
        }
    }

    pub(crate) fn observe_section(&mut self, section: &SectionInfo) -> Result<(), WriteError> {
        if self.opened {
            // Only the first section header survives a merge, so only its
            // options are kept.
            return Ok(());
        }
        self.section = Some(section.clone());
        self.open()
    }

    pub(crate) fn observe_interface(
        &mut self,
        interface: &InterfaceInfo,
    ) -> Result<(), WriteError> {
        self.open()?;
        self.write_interface(interface)?;
        self.interfaces = self.interfaces.saturating_add(1);
        Ok(())
    }

    pub(crate) fn observe_name_resolution(&mut self, body: &[u8]) -> Result<(), WriteError> {
        self.open()?;
        write_block(&mut self.out, NRB_TYPE, body)
    }

    /// Open the output eagerly, as a live capture does after its devices and
    /// filters are ready.
    pub(crate) fn open_live(&mut self, interfaces: &[InterfaceInfo]) -> Result<(), WriteError> {
        self.open()?;
        for interface in interfaces {
            self.write_interface(interface)?;
            self.interfaces = self.interfaces.saturating_add(1);
        }
        Ok(())
    }

    pub(crate) fn write_packet(&mut self, record: &PacketRecord<'_>) -> Result<(), WriteError> {
        if record.timestamp.is_some() && record.timestamp_units.is_none() {
            return Err(WriteError::MissingTimestampUnits);
        }
        if record.captured.len() > MAX_PACKET_SIZE {
            return Err(WriteError::PacketTooLarge {
                length: record.captured.len(),
            });
        }
        self.open()?;
        let known = usize::try_from(record.interface).is_ok_and(|index| index < self.interfaces);
        if !known {
            return Err(WriteError::InvalidInterface(record.interface));
        }

        match record.timestamp_units {
            Some(units) => write_enhanced(&mut self.out, record, units),
            // A simple packet block cannot record a captured length smaller
            // than the original packet, so a truncated packet becomes an
            // enhanced block with timestamp zero.
            None if record.captured.len()
                < usize::try_from(record.original_len).unwrap_or(usize::MAX) =>
            {
                write_enhanced(&mut self.out, record, 0)
            }
            // A simple packet block also has no interface field: it always
            // belongs to the first interface of its section
            // (draft-ietf-opsawg-pcapng section 4.4). Another interface, such
            // as one appended by a section merge, needs an enhanced block,
            // whose Interface ID names it (section 4.3), with no timestamp so
            // its own link type stays attached.
            None if record.interface != 0 => write_enhanced(&mut self.out, record, 0),
            None => write_simple(&mut self.out, record),
        }
    }

    pub(crate) fn finish(&mut self) -> Result<(), WriteError> {
        if !self.opened {
            self.open()?;
            if self.interfaces == 0 {
                // An empty source has no section and no interface, but the
                // output still gets one ERF interface with a nanosecond
                // resolution before finishing.
                self.write_interface(&InterfaceInfo {
                    global_index: 0,
                    link_type: LINKTYPE_ERF,
                    snap_len: SNAP_LEN,
                    options: vec![InterfaceOption::TimestampResolution(
                        TimestampResolution::PowerOfTen(9),
                    )],
                })?;
                self.interfaces = 1;
            }
        }
        self.out.finish()
    }

    pub(crate) fn logical_bytes(&self) -> u64 {
        self.out.logical_bytes()
    }

    pub(crate) fn flush(&mut self) -> Result<(), WriteError> {
        self.out.flush()
    }

    pub(crate) fn into_output(self) -> Output<W> {
        self.out
    }

    fn open(&mut self) -> Result<(), WriteError> {
        if self.opened {
            return Ok(());
        }
        let mut body = Vec::with_capacity(32);
        body.extend_from_slice(&0x1a2b_3c4d_u32.to_le_bytes());
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&(-1_i64).to_le_bytes());
        let empty = SectionInfo {
            number: 0,
            options: Vec::new(),
        };
        let section = self.section.as_ref().unwrap_or(&empty);
        options::push_section(
            &mut body,
            &section.options,
            &self.application,
            &self.capture_comments,
        )?;
        write_block(&mut self.out, SHB_TYPE, &body)?;
        self.opened = true;
        self.section = None;
        Ok(())
    }

    fn write_interface(&mut self, interface: &InterfaceInfo) -> Result<(), WriteError> {
        let link_type =
            u16::try_from(interface.link_type).map_err(|_| WriteError::LinkTypeTooLarge {
                link_type: interface.link_type,
            })?;
        let mut body = Vec::with_capacity(32);
        body.extend_from_slice(&link_type.to_le_bytes());
        body.extend_from_slice(&0_u16.to_le_bytes());
        body.extend_from_slice(&interface.snap_len.to_le_bytes());
        options::push_interface(&mut body, &interface.options)?;
        write_block(&mut self.out, IDB_TYPE, &body)
    }
}

fn write_enhanced<W: Write>(
    out: &mut Output<W>,
    record: &PacketRecord<'_>,
    timestamp_units: u64,
) -> Result<(), WriteError> {
    let captured_len =
        u32::try_from(record.captured.len()).map_err(|_| WriteError::PacketTooLarge {
            length: record.captured.len(),
        })?;
    let mut body = Vec::with_capacity(32 + record.captured.len());
    body.extend_from_slice(&record.interface.to_le_bytes());
    body.extend_from_slice(&((timestamp_units >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(timestamp_units as u32).to_le_bytes());
    body.extend_from_slice(&captured_len.to_le_bytes());
    body.extend_from_slice(&record.original_len.to_le_bytes());
    body.extend_from_slice(record.captured);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    options::push_packet(&mut body, &record.options.options)?;
    write_block(out, EPB_TYPE, &body)
}

fn write_simple<W: Write>(
    out: &mut Output<W>,
    record: &PacketRecord<'_>,
) -> Result<(), WriteError> {
    // A simple packet block has no captured-length field: the body length
    // carries it. The reader supplies exactly min(original length, snap
    // length), so forward those bytes and reject data that claims to be
    // longer than the original packet.
    if record.captured.len() > usize::try_from(record.original_len).unwrap_or(usize::MAX) {
        return Err(WriteError::InvalidBlock(
            "simple packet data is longer than the original packet",
        ));
    }
    let mut body = Vec::with_capacity(4 + record.captured.len());
    body.extend_from_slice(&record.original_len.to_le_bytes());
    body.extend_from_slice(record.captured);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    write_block(out, SPB_TYPE, &body)
}

fn write_block<W: Write>(
    out: &mut Output<W>,
    block_type: u32,
    body: &[u8],
) -> Result<(), WriteError> {
    if !body.len().is_multiple_of(4) {
        return Err(WriteError::InvalidBlock(
            "a pcapng block body is not 4-byte aligned",
        ));
    }
    let total = body
        .len()
        .checked_add(12)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(WriteError::InvalidBlock("a pcapng block is too large"))?;
    let mut header = [0_u8; 8];
    for (slot, value) in header
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip([block_type, total])
    {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    out.write_all(&header)?;
    out.write_all(body)?;
    out.write_all(&total.to_le_bytes())
}
