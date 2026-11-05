//! Builder for classic pcap capture files.
//!
//! The builder writes the 24-byte global header followed by packet records.
//! Both byte orders and both the microsecond and nanosecond timestamp
//! resolutions are supported.

use crate::wire::{ByteOrder, LINKTYPE_ETHERNET, Timestamp, TimestampResolution};

/// A packet record, including the lengths written to its record header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Timestamp in the file's resolution.
    pub timestamp: Timestamp,
    /// Number of bytes captured, as claimed by the record header.
    pub captured_len: u32,
    /// Original length of the packet on the wire.
    pub original_len: u32,
    /// Captured bytes. May be shorter than `captured_len` for a deliberately
    /// truncated file; never longer.
    pub data: Vec<u8>,
}

impl Packet {
    /// Build a fully captured packet whose lengths come from `data`.
    pub fn new(timestamp: Timestamp, data: impl Into<Vec<u8>>) -> Result<Self, String> {
        let data = data.into();
        let length = u32::try_from(data.len()).map_err(|_| {
            format!(
                "packet is {} bytes; pcap records are limited to 4 GiB",
                data.len()
            )
        })?;
        Ok(Self {
            timestamp,
            captured_len: length,
            original_len: length,
            data,
        })
    }
}

/// A pcap file under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcap {
    byte_order: ByteOrder,
    resolution: TimestampResolution,
    snap_len: u32,
    link_type: u32,
    packets: Vec<Packet>,
}

impl Pcap {
    /// Start an empty Ethernet capture with a 262144-byte snapshot length.
    pub fn new(byte_order: ByteOrder, resolution: TimestampResolution) -> Self {
        Self {
            byte_order,
            resolution,
            snap_len: 262_144,
            link_type: u32::from(LINKTYPE_ETHERNET),
            packets: Vec::new(),
        }
    }

    /// Append a fully captured packet.
    pub fn push(&mut self, timestamp: Timestamp, data: impl Into<Vec<u8>>) -> Result<(), String> {
        self.push_packet(Packet::new(timestamp, data)?)
    }

    /// Override the snapshot length written to the global header.
    pub fn with_snap_len(mut self, snap_len: u32) -> Self {
        self.snap_len = snap_len;
        self
    }

    /// Override the link type written to the global header.
    pub fn with_link_type(mut self, link_type: u32) -> Self {
        self.link_type = link_type;
        self
    }

    /// Append a packet with explicit record-header lengths.
    ///
    /// This is how a deliberately truncated file is built: `data` may be
    /// shorter than `captured_len`, but never longer.
    pub fn push_packet(&mut self, packet: Packet) -> Result<(), String> {
        self.validate_timestamp(packet.timestamp)?;
        let captured_len = usize::try_from(packet.captured_len).map_err(|_| {
            format!(
                "captured length {} does not fit this platform",
                packet.captured_len
            )
        })?;
        if packet.data.len() > captured_len {
            return Err(format!(
                "packet carries {} bytes but its record claims only {} captured bytes",
                packet.data.len(),
                packet.captured_len
            ));
        }
        self.packets.push(packet);
        Ok(())
    }

    /// Serialize the global header and every packet record.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        self.byte_order.put_u32(&mut out, self.resolution.magic());
        self.byte_order.put_u16(&mut out, 2);
        self.byte_order.put_u16(&mut out, 4);
        self.byte_order.put_u32(&mut out, 0); // thiszone
        self.byte_order.put_u32(&mut out, 0); // sigfigs
        self.byte_order.put_u32(&mut out, self.snap_len);
        self.byte_order.put_u32(&mut out, self.link_type);

        for packet in &self.packets {
            let seconds = u32::try_from(packet.timestamp.seconds).map_err(|_| {
                format!(
                    "timestamp seconds {} do not fit a 32-bit pcap field",
                    packet.timestamp.seconds
                )
            })?;
            self.byte_order.put_u32(&mut out, seconds);
            self.byte_order.put_u32(&mut out, packet.timestamp.fraction);
            self.byte_order.put_u32(&mut out, packet.captured_len);
            self.byte_order.put_u32(&mut out, packet.original_len);
            out.extend_from_slice(&packet.data);
        }

        Ok(out)
    }

    fn validate_timestamp(&self, timestamp: Timestamp) -> Result<(), String> {
        timestamp.in_units(self.resolution)?;
        if u32::try_from(timestamp.seconds).is_err() {
            return Err(format!(
                "timestamp seconds {} do not fit a 32-bit pcap field",
                timestamp.seconds
            ));
        }
        Ok(())
    }
}

impl TimestampResolution {
    /// Magic number that selects the byte order and timestamp resolution.
    const fn magic(self) -> u32 {
        match self {
            Self::Microsecond => 0xa1b2_c3d4,
            Self::Nanosecond => 0xa1b2_3c4d,
            // pcap has no binary timestamp resolution; only pcapng uses this.
            Self::PowerOfTwo(_) => 0xa1b2_c3d4,
        }
    }
}
