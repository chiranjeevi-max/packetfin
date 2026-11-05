//! Classic pcap writer.
//!
//! The global header is little-endian, version 2.4, and uses the first
//! interface's link type. A classic pcap source keeps its own snapshot length
//! (zero maps to 262144); a live source keeps the snapshot libpcap activated,
//! so `-s` is represented in the header. A pcapng source, whose sections are
//! merged, uses 262144. A source without a link type uses ERF (197), matching
//! the empty-capture output.

use std::io::Write;

use super::sink::Output;
use super::{MAX_PACKET_SIZE, PacketRecord, Resolution, WriteError};
use crate::capture::InterfaceInfo;

const DEFAULT_SNAP_LEN: u32 = 262_144;
const LINKTYPE_ERF: u32 = 197;

pub(crate) struct Writer<W: Write> {
    out: Output<W>,
    resolution: Resolution,
    opened: bool,
    link_type: Option<u32>,
    interfaces: usize,
    source_snap_len: Option<u32>,
    saw_section: bool,
    saw_event: bool,
}

impl<W: Write> Writer<W> {
    pub(crate) fn new(out: Output<W>, resolution: Resolution) -> Self {
        Self {
            out,
            resolution,
            opened: false,
            link_type: None,
            interfaces: 0,
            source_snap_len: None,
            saw_section: false,
            saw_event: false,
        }
    }

    pub(crate) fn observe_section(&mut self) {
        self.saw_event = true;
        self.saw_section = true;
    }

    pub(crate) fn observe_interface(
        &mut self,
        interface: &InterfaceInfo,
    ) -> Result<(), WriteError> {
        self.saw_event = true;
        if self.interfaces == 0 {
            self.source_snap_len = Some(interface.snap_len);
        }
        self.interfaces = self.interfaces.saturating_add(1);
        self.accept_link_type(interface.link_type)
    }

    pub(crate) fn observe_name_resolution(&mut self) {
        self.saw_event = true;
    }

    /// Open the output eagerly, as a live capture does after its devices and
    /// filters are ready.
    pub(crate) fn open_live(&mut self, interfaces: &[InterfaceInfo]) -> Result<(), WriteError> {
        self.saw_event = true;
        // The activated snapshot is the one the live output describes; a
        // zero is libpcap's "unlimited" request and maps to 262144 below.
        self.source_snap_len = interfaces.first().map(|interface| interface.snap_len);
        self.interfaces = interfaces.len();
        for interface in interfaces {
            self.accept_link_type(interface.link_type)?;
        }
        self.open()
    }

    pub(crate) fn write_packet(&mut self, record: &PacketRecord<'_>) -> Result<(), WriteError> {
        if record.captured.len() > MAX_PACKET_SIZE {
            return Err(WriteError::PacketTooLarge {
                length: record.captured.len(),
            });
        }
        let known = usize::try_from(record.interface).is_ok_and(|index| index < self.interfaces);
        if !known {
            return Err(WriteError::InvalidInterface(record.interface));
        }

        self.open()?;
        let (seconds, fraction) = timestamp_fields(record, self.resolution)?;
        let mut header = [0_u8; 16];
        header
            .get_mut(0..4)
            .ok_or(WriteError::InvalidBlock("pcap record header"))?
            .copy_from_slice(&seconds.to_le_bytes());
        header
            .get_mut(4..8)
            .ok_or(WriteError::InvalidBlock("pcap record header"))?
            .copy_from_slice(&fraction.to_le_bytes());
        let captured_len =
            u32::try_from(record.captured.len()).map_err(|_| WriteError::PacketTooLarge {
                length: record.captured.len(),
            })?;
        header
            .get_mut(8..12)
            .ok_or(WriteError::InvalidBlock("pcap record header"))?
            .copy_from_slice(&captured_len.to_le_bytes());
        header
            .get_mut(12..16)
            .ok_or(WriteError::InvalidBlock("pcap record header"))?
            .copy_from_slice(&record.original_len.to_le_bytes());
        self.out.write_all(&header)?;
        self.out.write_all(record.captured)
    }

    pub(crate) fn finish(&mut self) -> Result<(), WriteError> {
        if !self.opened {
            if self.interfaces == 0 && self.saw_event {
                // A pcapng source with no interface cannot be represented in
                // pcap, so the writer refuses before creating a file.
                return Err(WriteError::Incompatible(
                    "the capture has no interface to describe",
                ));
            }
            self.open()?;
        }
        self.out.finish()
    }

    pub(crate) fn flush(&mut self) -> Result<(), WriteError> {
        self.out.flush()
    }

    pub(crate) fn logical_bytes(&self) -> u64 {
        self.out.logical_bytes()
    }

    pub(crate) fn into_output(self) -> Output<W> {
        self.out
    }

    fn accept_link_type(&mut self, link_type: u32) -> Result<(), WriteError> {
        match self.link_type {
            Some(current) if current != link_type => {
                if self.opened {
                    Err(WriteError::IncompatibleLater(
                        "a later interface uses a different link type",
                    ))
                } else {
                    Err(WriteError::Incompatible(
                        "interfaces use different link types",
                    ))
                }
            }
            Some(_) => Ok(()),
            None => {
                self.link_type = Some(link_type);
                Ok(())
            }
        }
    }

    fn open(&mut self) -> Result<(), WriteError> {
        if self.opened {
            return Ok(());
        }
        let magic: u32 = match self.resolution {
            Resolution::Microsecond => 0xa1b2_c3d4,
            Resolution::Nanosecond => 0xa1b2_3c4d,
        };
        let mut header = Vec::with_capacity(24);
        header.extend_from_slice(&magic.to_le_bytes());
        header.extend_from_slice(&2_u16.to_le_bytes());
        header.extend_from_slice(&4_u16.to_le_bytes());
        header.extend_from_slice(&0_u32.to_le_bytes()); // thiszone
        header.extend_from_slice(&0_u32.to_le_bytes()); // sigfigs
        let snap_len = if self.saw_section {
            DEFAULT_SNAP_LEN
        } else {
            match self.source_snap_len {
                Some(0) | None => DEFAULT_SNAP_LEN,
                Some(snap_len) => snap_len,
            }
        };
        header.extend_from_slice(&snap_len.to_le_bytes());
        header.extend_from_slice(&self.link_type.unwrap_or(LINKTYPE_ERF).to_le_bytes());
        self.out.write_all(&header)?;
        self.opened = true;
        Ok(())
    }
}

fn timestamp_fields(
    record: &PacketRecord<'_>,
    resolution: Resolution,
) -> Result<(u32, u32), WriteError> {
    let Some(timestamp) = record.timestamp else {
        // A pcapng simple packet has no timestamp, so the record stores zero.
        return Ok((0, 0));
    };
    let carry = i64::from(timestamp.nanos / 1_000_000_000);
    let nanos = timestamp.nanos % 1_000_000_000;
    let seconds = timestamp
        .seconds
        .checked_add(carry)
        .and_then(|seconds| u32::try_from(seconds).ok())
        .ok_or(WriteError::TimestampOutOfRange)?;
    let fraction = match resolution {
        Resolution::Microsecond => nanos / 1_000,
        Resolution::Nanosecond => nanos,
    };
    Ok((seconds, fraction))
}
