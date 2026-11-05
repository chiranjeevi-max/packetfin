//! Builder for pcapng capture files.
//!
//! A file contains one or more sections. Each section has its own byte order,
//! interface table and blocks. The builder writes section header blocks,
//! interface description blocks, enhanced, simple and obsolete packet blocks,
//! name resolution blocks, interface statistics blocks and unknown blocks,
//! with every option and record padded to a 32-bit boundary.

use crate::wire::{
    ByteOrder, LINKTYPE_ETHERNET, Timestamp, TimestampResolution, pad_to_4, put_end_of_options,
    put_option,
};

const BLOCK_TYPE_SHB: u32 = 0x0a0d_0d0a;
const BLOCK_TYPE_IDB: u32 = 0x0000_0001;
const BLOCK_TYPE_OPB: u32 = 0x0000_0002;
const BLOCK_TYPE_SPB: u32 = 0x0000_0003;
const BLOCK_TYPE_NRB: u32 = 0x0000_0004;
const BLOCK_TYPE_ISB: u32 = 0x0000_0005;
const BLOCK_TYPE_EPB: u32 = 0x0000_0006;

const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;

const OPT_COMMENT: u16 = 1;
const OPT_SHB_HARDWARE: u16 = 2;
const OPT_SHB_OS: u16 = 3;
const OPT_SHB_USERAPPL: u16 = 4;
const OPT_IF_NAME: u16 = 2;
const OPT_IF_DESCRIPTION: u16 = 3;
const OPT_ISB_IFRECV: u16 = 4;
const OPT_ISB_IFDROP: u16 = 5;
const OPT_IF_TSRESOL: u16 = 9;
const OPT_IF_TSOFFSET: u16 = 14;

/// Section-header options written in the order the fields are listed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SectionOptions {
    /// `shb_hardware`.
    pub hardware: Option<String>,
    /// `shb_os`.
    pub os: Option<String>,
    /// `shb_userappl`.
    pub userappl: Option<String>,
    /// `shb_comment` values.
    pub comments: Vec<String>,
}

impl SectionOptions {
    /// Whether no option would be written.
    pub fn is_empty(&self) -> bool {
        self.hardware.is_none()
            && self.os.is_none()
            && self.userappl.is_none()
            && self.comments.is_empty()
    }
}

/// Description of an interface in a section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// Link type of packets on this interface.
    pub link_type: u16,
    /// Maximum number of bytes captured per packet.
    pub snap_len: u32,
    /// `if_name` option.
    pub name: Option<String>,
    /// `if_description` option.
    pub description: Option<String>,
    /// `opt_comment` option.
    pub comment: Option<String>,
    /// Timestamp resolution; `None` leaves `if_tsresol` absent (microseconds
    /// by the pcapng default).
    pub timestamp_resolution: Option<TimestampResolution>,
    /// `if_tsoffset` option, in seconds.
    pub timestamp_offset: Option<i64>,
    /// Additional raw options, written after the structured options.
    pub raw_options: Vec<(u16, Vec<u8>)>,
}

impl Interface {
    /// An Ethernet interface with a 262144-byte snapshot length.
    pub fn ethernet() -> Self {
        Self {
            link_type: LINKTYPE_ETHERNET,
            snap_len: 262_144,
            name: None,
            description: None,
            comment: None,
            timestamp_resolution: None,
            timestamp_offset: None,
            raw_options: Vec::new(),
        }
    }

    /// Set the `if_name` option.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the `if_description` option.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the interface comment option.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the `if_tsresol` option.
    pub fn with_timestamp_resolution(mut self, resolution: TimestampResolution) -> Self {
        self.timestamp_resolution = Some(resolution);
        self
    }

    /// Set the `if_tsoffset` option, in seconds.
    pub fn with_timestamp_offset(mut self, offset: i64) -> Self {
        self.timestamp_offset = Some(offset);
        self
    }

    /// Append an option with raw bytes, for options the builder does not
    /// model (for example `if_filter`).
    pub fn with_raw_option(mut self, code: u16, value: impl Into<Vec<u8>>) -> Self {
        self.raw_options.push((code, value.into()));
        self
    }
}

/// An enhanced packet block under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnhancedPacket {
    interface_id: u32,
    timestamp: Timestamp,
    data: Vec<u8>,
    original_len: Option<u32>,
    comment: Option<String>,
}

impl EnhancedPacket {
    /// Create a packet for `interface_id` at the given timestamp.
    pub fn new(interface_id: u32, timestamp: Timestamp, data: impl Into<Vec<u8>>) -> Self {
        Self {
            interface_id,
            timestamp,
            data: data.into(),
            original_len: None,
            comment: None,
        }
    }

    /// Override the original packet length; defaults to the captured length.
    pub fn original_len(mut self, original_len: u32) -> Self {
        self.original_len = Some(original_len);
        self
    }

    /// Attach an `epb_comment` option.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// A simple packet block under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimplePacket {
    data: Vec<u8>,
    original_len: Option<u32>,
}

impl SimplePacket {
    /// Create a simple packet; simple packets are captured on interface 0 and
    /// carry no timestamp.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            original_len: None,
        }
    }

    /// Override the original packet length; defaults to the captured length.
    pub fn original_len(mut self, original_len: u32) -> Self {
        self.original_len = Some(original_len);
        self
    }
}

/// An obsolete packet block (block type 2) under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObsoletePacket {
    interface_id: u32,
    drop_count: u16,
    timestamp: Timestamp,
    data: Vec<u8>,
    original_len: Option<u32>,
    comment: Option<String>,
    raw_options: Vec<(u16, Vec<u8>)>,
}

impl ObsoletePacket {
    /// Create a packet for `interface_id` at the given timestamp.
    pub fn new(interface_id: u32, timestamp: Timestamp, data: impl Into<Vec<u8>>) -> Self {
        Self {
            interface_id,
            drop_count: 0,
            timestamp,
            data: data.into(),
            original_len: None,
            comment: None,
            raw_options: Vec::new(),
        }
    }

    /// Set the block's 16-bit drop-count field.
    pub fn with_drop_count(mut self, drop_count: u16) -> Self {
        self.drop_count = drop_count;
        self
    }

    /// Override the original packet length; defaults to the captured length.
    pub fn original_len(mut self, original_len: u32) -> Self {
        self.original_len = Some(original_len);
        self
    }

    /// Attach an `opt_comment` option.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Append an option with raw bytes.
    pub fn with_raw_option(mut self, code: u16, value: impl Into<Vec<u8>>) -> Self {
        self.raw_options.push((code, value.into()));
        self
    }
}

/// One name resolution record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameRecord {
    /// An IPv4 address and its names.
    Ipv4 {
        /// Address the names belong to.
        address: [u8; 4],
        /// Null-separated names.
        names: Vec<String>,
    },
    /// An IPv6 address and its names.
    Ipv6 {
        /// Address the names belong to.
        address: [u8; 16],
        /// Null-separated names.
        names: Vec<String>,
    },
    /// A record this builder does not interpret.
    Other {
        /// Record type from the name resolution block.
        record_type: u16,
        /// Raw record value.
        value: Vec<u8>,
    },
}

/// A name resolution block under construction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameResolution {
    records: Vec<NameRecord>,
    comment: Option<String>,
}

impl NameResolution {
    /// Create an empty name resolution block.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an IPv4 address with null-separated names.
    pub fn add_ipv4(mut self, address: [u8; 4], names: &[&str]) -> Self {
        self.records.push(NameRecord::Ipv4 {
            address,
            names: names.iter().map(|name| (*name).to_string()).collect(),
        });
        self
    }

    /// Add an IPv6 address with null-separated names.
    pub fn add_ipv6(mut self, address: [u8; 16], names: &[&str]) -> Self {
        self.records.push(NameRecord::Ipv6 {
            address,
            names: names.iter().map(|name| (*name).to_string()).collect(),
        });
        self
    }

    /// Add an uninterpreted record.
    pub fn add_other(mut self, record_type: u16, value: impl Into<Vec<u8>>) -> Self {
        self.records.push(NameRecord::Other {
            record_type,
            value: value.into(),
        });
        self
    }

    /// Attach an `opt_comment` option.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// An interface statistics block under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceStatistics {
    interface_id: u32,
    timestamp: Timestamp,
    comment: Option<String>,
    received: Option<u64>,
    dropped: Option<u64>,
}

impl InterfaceStatistics {
    /// Create statistics for `interface_id` at the given timestamp.
    pub fn new(interface_id: u32, timestamp: Timestamp) -> Self {
        Self {
            interface_id,
            timestamp,
            comment: None,
            received: None,
            dropped: None,
        }
    }

    /// Attach an `opt_comment` option.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the `isb_ifrecv` counter.
    pub fn with_received(mut self, received: u64) -> Self {
        self.received = Some(received);
        self
    }

    /// Set the `isb_ifdrop` counter.
    pub fn with_dropped(mut self, dropped: u64) -> Self {
        self.dropped = Some(dropped);
        self
    }
}

/// An unknown block, to prove that readers skip block types they do not know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownBlock {
    block_type: u32,
    body: Vec<u8>,
}

impl UnknownBlock {
    /// Create an unknown block with a caller-chosen type and body.
    pub fn new(block_type: u32, body: impl Into<Vec<u8>>) -> Self {
        Self {
            block_type,
            body: body.into(),
        }
    }
}

/// A pcapng file under construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcapNg {
    sections: Vec<Section>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Section {
    byte_order: ByteOrder,
    options: SectionOptions,
    interfaces: Vec<Interface>,
    blocks: Vec<Block>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Block {
    Enhanced(EnhancedBlock),
    Simple(SimpleBlock),
    Obsolete(ObsoleteBlock),
    NameResolution(NameResolution),
    InterfaceStatistics(StatisticsBlock),
    Unknown(UnknownBlock),
}

/// An enhanced packet with its timestamp already converted to interface units.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EnhancedBlock {
    interface_id: u32,
    timestamp_units: u64,
    captured_len: u32,
    original_len: u32,
    data: Vec<u8>,
    comment: Option<String>,
}

/// A simple packet with validated lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SimpleBlock {
    original_len: u32,
    data: Vec<u8>,
}

/// An obsolete packet with its timestamp already converted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObsoleteBlock {
    interface_id: u32,
    drop_count: u16,
    timestamp_units: u64,
    captured_len: u32,
    original_len: u32,
    data: Vec<u8>,
    comment: Option<String>,
    raw_options: Vec<(u16, Vec<u8>)>,
}

/// Statistics with the timestamp already converted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StatisticsBlock {
    interface_id: u32,
    timestamp_units: u64,
    received: Option<u64>,
    dropped: Option<u64>,
    comment: Option<String>,
}

impl PcapNg {
    /// Start an empty file with one section in the given byte order.
    pub fn new(byte_order: ByteOrder) -> Self {
        Self {
            sections: vec![Section {
                byte_order,
                options: SectionOptions::default(),
                interfaces: Vec::new(),
                blocks: Vec::new(),
            }],
        }
    }

    /// Start a new section and return its index.
    pub fn add_section(&mut self, byte_order: ByteOrder) -> Result<u32, String> {
        let index = u32::try_from(self.sections.len())
            .map_err(|_| "pcapng file has too many sections".to_string())?;
        self.sections.push(Section {
            byte_order,
            options: SectionOptions::default(),
            interfaces: Vec::new(),
            blocks: Vec::new(),
        });
        Ok(index)
    }

    /// Set the current section's header options.
    pub fn set_section_options(&mut self, options: SectionOptions) -> Result<(), String> {
        let section = self.current_section_mut()?;
        section.options = options;
        Ok(())
    }

    /// Add an interface to the current section and return its zero-based id.
    pub fn add_interface(&mut self, interface: Interface) -> Result<u32, String> {
        let section = self.current_section_mut()?;
        let id = u32::try_from(section.interfaces.len())
            .map_err(|_| "pcapng section has too many interfaces".to_string())?;
        section.interfaces.push(interface);
        Ok(id)
    }

    /// Add an enhanced packet block.
    pub fn add_enhanced_packet(&mut self, packet: EnhancedPacket) -> Result<(), String> {
        let section = self.current_section_mut()?;
        let interface = interface_for(section, packet.interface_id)?;
        let resolution = interface
            .timestamp_resolution
            .unwrap_or(TimestampResolution::Microsecond);
        let timestamp_units = packet.timestamp.in_units(resolution)?;
        let captured_len = captured_length(&packet.data)?;
        let original_len = original_length(packet.original_len, captured_len)?;
        section.blocks.push(Block::Enhanced(EnhancedBlock {
            interface_id: packet.interface_id,
            timestamp_units,
            captured_len,
            original_len,
            data: packet.data,
            comment: packet.comment,
        }));
        Ok(())
    }

    /// Add a simple packet block.
    pub fn add_simple_packet(&mut self, packet: SimplePacket) -> Result<(), String> {
        let section = self.current_section_mut()?;
        if section.interfaces.is_empty() {
            return Err("a simple packet block requires interface 0".to_string());
        }
        let captured_len = captured_length(&packet.data)?;
        let original_len = original_length(packet.original_len, captured_len)?;
        section.blocks.push(Block::Simple(SimpleBlock {
            original_len,
            data: packet.data,
        }));
        Ok(())
    }

    /// Add an obsolete packet block.
    pub fn add_obsolete_packet(&mut self, packet: ObsoletePacket) -> Result<(), String> {
        let section = self.current_section_mut()?;
        if packet.interface_id > u32::from(u16::MAX) {
            return Err(format!(
                "obsolete packet block interface {} does not fit 16 bits",
                packet.interface_id
            ));
        }
        let interface = interface_for(section, packet.interface_id)?;
        let resolution = interface
            .timestamp_resolution
            .unwrap_or(TimestampResolution::Microsecond);
        let timestamp_units = packet.timestamp.in_units(resolution)?;
        let captured_len = captured_length(&packet.data)?;
        let original_len = original_length(packet.original_len, captured_len)?;
        section.blocks.push(Block::Obsolete(ObsoleteBlock {
            interface_id: packet.interface_id,
            drop_count: packet.drop_count,
            timestamp_units,
            captured_len,
            original_len,
            data: packet.data,
            comment: packet.comment,
            raw_options: packet.raw_options,
        }));
        Ok(())
    }

    /// Add a name resolution block.
    pub fn add_name_resolution(&mut self, block: NameResolution) -> Result<(), String> {
        self.current_section_mut()?
            .blocks
            .push(Block::NameResolution(block));
        Ok(())
    }

    /// Add an interface statistics block.
    pub fn add_interface_statistics(&mut self, block: InterfaceStatistics) -> Result<(), String> {
        let section = self.current_section_mut()?;
        let interface = interface_for(section, block.interface_id)?;
        let resolution = interface
            .timestamp_resolution
            .unwrap_or(TimestampResolution::Microsecond);
        let timestamp_units = block.timestamp.in_units(resolution)?;
        section
            .blocks
            .push(Block::InterfaceStatistics(StatisticsBlock {
                interface_id: block.interface_id,
                timestamp_units,
                received: block.received,
                dropped: block.dropped,
                comment: block.comment,
            }));
        Ok(())
    }

    /// Add an unknown block that readers must skip.
    pub fn add_unknown_block(&mut self, block: UnknownBlock) -> Result<(), String> {
        if matches!(
            block.block_type,
            BLOCK_TYPE_SHB
                | BLOCK_TYPE_IDB
                | BLOCK_TYPE_OPB
                | BLOCK_TYPE_SPB
                | BLOCK_TYPE_NRB
                | BLOCK_TYPE_ISB
                | BLOCK_TYPE_EPB
        ) {
            return Err(format!(
                "block type {:#x} is a known pcapng block",
                block.block_type
            ));
        }
        self.current_section_mut()?
            .blocks
            .push(Block::Unknown(block));
        Ok(())
    }

    /// Serialize every section, interface and block.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for section in &self.sections {
            write_section(&mut out, section)?;
        }
        Ok(out)
    }

    fn current_section_mut(&mut self) -> Result<&mut Section, String> {
        self.sections
            .last_mut()
            .ok_or_else(|| "pcapng file has no section".to_string())
    }
}

fn interface_for(section: &Section, interface_id: u32) -> Result<&Interface, String> {
    let index = usize::try_from(interface_id)
        .map_err(|_| format!("interface {interface_id} does not fit this platform"))?;
    section
        .interfaces
        .get(index)
        .ok_or_else(|| format!("interface {interface_id} has not been added"))
}

fn captured_length(data: &[u8]) -> Result<u32, String> {
    u32::try_from(data.len()).map_err(|_| {
        format!(
            "packet is {} bytes; pcapng records are limited to 4 GiB",
            data.len()
        )
    })
}

fn original_length(requested: Option<u32>, captured_len: u32) -> Result<u32, String> {
    let original_len = requested.unwrap_or(captured_len);
    if original_len < captured_len {
        return Err(format!(
            "original length {original_len} is smaller than captured length {captured_len}"
        ));
    }
    Ok(original_len)
}

fn write_section(out: &mut Vec<u8>, section: &Section) -> Result<(), String> {
    let order = section.byte_order;

    let mut shb = Vec::new();
    order.put_u32(&mut shb, BYTE_ORDER_MAGIC);
    order.put_u16(&mut shb, 1);
    order.put_u16(&mut shb, 0);
    order.put_i64(&mut shb, -1);
    if let Some(hardware) = &section.options.hardware {
        put_option(&mut shb, order, OPT_SHB_HARDWARE, hardware.as_bytes())?;
    }
    if let Some(os) = &section.options.os {
        put_option(&mut shb, order, OPT_SHB_OS, os.as_bytes())?;
    }
    if let Some(userappl) = &section.options.userappl {
        put_option(&mut shb, order, OPT_SHB_USERAPPL, userappl.as_bytes())?;
    }
    for comment in &section.options.comments {
        put_option(&mut shb, order, OPT_COMMENT, comment.as_bytes())?;
    }
    put_end_of_options(&mut shb, order);
    write_block(out, order, BLOCK_TYPE_SHB, &shb)?;

    for interface in &section.interfaces {
        write_interface(out, order, interface)?;
    }

    for block in &section.blocks {
        match block {
            Block::Enhanced(packet) => write_enhanced_packet(out, order, packet)?,
            Block::Simple(packet) => write_simple_packet(out, order, packet)?,
            Block::Obsolete(packet) => write_obsolete_packet(out, order, packet)?,
            Block::NameResolution(block) => write_name_resolution(out, order, block)?,
            Block::InterfaceStatistics(block) => write_interface_statistics(out, order, block)?,
            Block::Unknown(block) => write_unknown_block(out, order, block)?,
        }
    }
    Ok(())
}

fn write_interface(
    out: &mut Vec<u8>,
    order: ByteOrder,
    interface: &Interface,
) -> Result<(), String> {
    let mut body = Vec::new();
    order.put_u16(&mut body, interface.link_type);
    order.put_u16(&mut body, 0);
    order.put_u32(&mut body, interface.snap_len);
    if let Some(name) = &interface.name {
        put_option(&mut body, order, OPT_IF_NAME, name.as_bytes())?;
    }
    if let Some(description) = &interface.description {
        put_option(&mut body, order, OPT_IF_DESCRIPTION, description.as_bytes())?;
    }
    if let Some(comment) = &interface.comment {
        put_option(&mut body, order, OPT_COMMENT, comment.as_bytes())?;
    }
    if let Some(resolution) = interface.timestamp_resolution {
        put_option(
            &mut body,
            order,
            OPT_IF_TSRESOL,
            &[resolution.pcapng_code()],
        )?;
    }
    if let Some(offset) = interface.timestamp_offset {
        let mut value = Vec::new();
        order.put_i64(&mut value, offset);
        put_option(&mut body, order, OPT_IF_TSOFFSET, &value)?;
    }
    for (code, value) in &interface.raw_options {
        put_option(&mut body, order, *code, value)?;
    }
    put_end_of_options(&mut body, order);
    write_block(out, order, BLOCK_TYPE_IDB, &body)
}

fn write_enhanced_packet(
    out: &mut Vec<u8>,
    order: ByteOrder,
    packet: &EnhancedBlock,
) -> Result<(), String> {
    let mut body = Vec::new();
    order.put_u32(&mut body, packet.interface_id);
    put_timestamp(&mut body, order, packet.timestamp_units)?;
    order.put_u32(&mut body, packet.captured_len);
    order.put_u32(&mut body, packet.original_len);
    body.extend_from_slice(&packet.data);
    pad_to_4(&mut body);
    if let Some(comment) = &packet.comment {
        put_option(&mut body, order, OPT_COMMENT, comment.as_bytes())?;
    }
    put_end_of_options(&mut body, order);
    write_block(out, order, BLOCK_TYPE_EPB, &body)
}

fn write_simple_packet(
    out: &mut Vec<u8>,
    order: ByteOrder,
    packet: &SimpleBlock,
) -> Result<(), String> {
    let mut body = Vec::new();
    order.put_u32(&mut body, packet.original_len);
    body.extend_from_slice(&packet.data);
    pad_to_4(&mut body);
    write_block(out, order, BLOCK_TYPE_SPB, &body)
}

fn write_obsolete_packet(
    out: &mut Vec<u8>,
    order: ByteOrder,
    packet: &ObsoleteBlock,
) -> Result<(), String> {
    let mut body = Vec::new();
    let interface_id = u16::try_from(packet.interface_id)
        .map_err(|_| "obsolete packet block interface does not fit 16 bits".to_string())?;
    order.put_u16(&mut body, interface_id);
    order.put_u16(&mut body, packet.drop_count);
    put_timestamp(&mut body, order, packet.timestamp_units)?;
    order.put_u32(&mut body, packet.captured_len);
    order.put_u32(&mut body, packet.original_len);
    body.extend_from_slice(&packet.data);
    pad_to_4(&mut body);
    if let Some(comment) = &packet.comment {
        put_option(&mut body, order, OPT_COMMENT, comment.as_bytes())?;
    }
    for (code, value) in &packet.raw_options {
        put_option(&mut body, order, *code, value)?;
    }
    put_end_of_options(&mut body, order);
    write_block(out, order, BLOCK_TYPE_OPB, &body)
}

fn write_name_resolution(
    out: &mut Vec<u8>,
    order: ByteOrder,
    block: &NameResolution,
) -> Result<(), String> {
    let mut body = Vec::new();
    for record in &block.records {
        let (record_type, value) = match record {
            NameRecord::Ipv4 { address, names } => {
                let mut value = address.to_vec();
                encode_names(&mut value, names);
                (1, value)
            }
            NameRecord::Ipv6 { address, names } => {
                let mut value = address.to_vec();
                encode_names(&mut value, names);
                (2, value)
            }
            NameRecord::Other { record_type, value } => (*record_type, value.clone()),
        };
        let length = u16::try_from(value.len()).map_err(|_| {
            format!(
                "name resolution record is {} bytes; the maximum is 65535",
                value.len()
            )
        })?;
        order.put_u16(&mut body, record_type);
        order.put_u16(&mut body, length);
        body.extend_from_slice(&value);
        pad_to_4(&mut body);
    }
    order.put_u32(&mut body, 0);
    if let Some(comment) = &block.comment {
        put_option(&mut body, order, OPT_COMMENT, comment.as_bytes())?;
    }
    put_end_of_options(&mut body, order);
    write_block(out, order, BLOCK_TYPE_NRB, &body)
}

fn write_interface_statistics(
    out: &mut Vec<u8>,
    order: ByteOrder,
    block: &StatisticsBlock,
) -> Result<(), String> {
    let mut body = Vec::new();
    order.put_u32(&mut body, block.interface_id);
    put_timestamp(&mut body, order, block.timestamp_units)?;
    if let Some(comment) = &block.comment {
        put_option(&mut body, order, OPT_COMMENT, comment.as_bytes())?;
    }
    if let Some(received) = block.received {
        let mut value = Vec::new();
        order.put_u64(&mut value, received);
        put_option(&mut body, order, OPT_ISB_IFRECV, &value)?;
    }
    if let Some(dropped) = block.dropped {
        let mut value = Vec::new();
        order.put_u64(&mut value, dropped);
        put_option(&mut body, order, OPT_ISB_IFDROP, &value)?;
    }
    put_end_of_options(&mut body, order);
    write_block(out, order, BLOCK_TYPE_ISB, &body)
}

fn write_unknown_block(
    out: &mut Vec<u8>,
    order: ByteOrder,
    block: &UnknownBlock,
) -> Result<(), String> {
    let mut body = block.body.clone();
    pad_to_4(&mut body);
    write_block(out, order, block.block_type, &body)
}

fn encode_names(value: &mut Vec<u8>, names: &[String]) {
    for name in names {
        value.extend_from_slice(name.as_bytes());
        value.push(0);
    }
}

fn put_timestamp(out: &mut Vec<u8>, order: ByteOrder, timestamp_units: u64) -> Result<(), String> {
    let high = u32::try_from(timestamp_units >> 32)
        .map_err(|_| "pcapng timestamp exceeds 64 bits".to_string())?;
    let low = u32::try_from(timestamp_units & 0xffff_ffff)
        .map_err(|_| "pcapng timestamp exceeds 64 bits".to_string())?;
    order.put_u32(out, high);
    order.put_u32(out, low);
    Ok(())
}

/// Write a block with a trailing copy of its total length.
fn write_block(
    out: &mut Vec<u8>,
    order: ByteOrder,
    block_type: u32,
    body: &[u8],
) -> Result<(), String> {
    if !body.len().is_multiple_of(4) {
        return Err(format!(
            "block body of {} bytes is not 32-bit aligned",
            body.len()
        ));
    }
    let body_len = u32::try_from(body.len())
        .map_err(|_| format!("block body of {} bytes is too large", body.len()))?;
    let total_len = body_len
        .checked_add(12)
        .ok_or_else(|| "pcapng block length overflow".to_string())?;
    order.put_u32(out, block_type);
    order.put_u32(out, total_len);
    out.extend_from_slice(body);
    order.put_u32(out, total_len);
    Ok(())
}
