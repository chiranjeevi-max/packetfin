//! pcapng reader: multiple sections, per-section byte order, interface
//! timestamp resolution and the enhanced, simple and obsolete packet blocks.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::bytes::{self, Cursor, Endian};
use super::{
    CaptureError, CaptureEvent, CountingReader, FrameData, InterfaceInfo, InterfaceOption,
    MAX_FRAME_SIZE, PacketOption, PacketOptions, RawEvent, SectionInfo, SectionOption, Timestamp,
    TimestampResolution,
};

const SHB_TYPE: u32 = 0x0a0d_0d0a;
const IDB_TYPE: u32 = 0x0000_0001;
const OPB_TYPE: u32 = 0x0000_0002;
const SPB_TYPE: u32 = 0x0000_0003;
const NRB_TYPE: u32 = 0x0000_0004;
const ISB_TYPE: u32 = 0x0000_0005;
const EPB_TYPE: u32 = 0x0000_0006;

const BYTE_ORDER_LE: [u8; 4] = [0x4d, 0x3c, 0x2b, 0x1a];
const BYTE_ORDER_BE: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];

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

const MIN_SECTION_LENGTH: u32 = 28;
const MAX_OPTION_ENTRIES: usize = 4096;
const MAX_INTERFACES: usize = 4096;
const MAX_NAME_RECORDS: usize = 4096;
/// Largest number of name records retained across blocks before a frame is yielded.
const MAX_TOTAL_NAME_RECORDS: usize = 65_536;
/// Longest name retained from one name-resolution record.
const MAX_NAME_LENGTH: usize = 255;

struct Interface {
    link_type: u32,
    snap_len: u32,
    resolution: TimestampResolution,
    offset: i64,
    name: Option<String>,
}

pub(crate) struct State {
    endian: Endian,
    interfaces: Vec<Interface>,
    global_base: u32,
    section_number: u32,
    names: Vec<(std::net::IpAddr, String)>,
}

impl State {
    /// Take the name-resolution records read since the last call.
    pub(crate) fn take_names(&mut self) -> Vec<(std::net::IpAddr, String)> {
        std::mem::take(&mut self.names)
    }
    fn interface(&self, id: u32) -> Result<&Interface, CaptureError> {
        usize::try_from(id)
            .ok()
            .and_then(|index| self.interfaces.get(index))
            .ok_or_else(|| {
                CaptureError::Malformed(format!(
                    "packet block references interface {id}, but the section declares {}",
                    self.interfaces.len()
                ))
            })
    }
}

/// Read the first section header block after its four magic bytes.
pub(crate) fn read_first_section<R: Read>(
    reader: &mut CountingReader<R>,
) -> Result<(State, SectionInfo), CaptureError> {
    let mut header = [0_u8; 8];
    bytes::read_exact_initial(reader, &mut header, "pcapng section header block")?;

    let mut cursor = Cursor::new(&header);
    let length_bytes: [u8; 4] = cursor.array()?;
    let byte_order: [u8; 4] = cursor.array()?;
    let endian = parse_byte_order(byte_order)?;
    let total_len = endian.u32(length_bytes);
    validate_section_length(total_len)?;

    let body_len = block_body_len(total_len)?;
    let remainder = body_len.checked_sub(4).ok_or_else(|| {
        CaptureError::Malformed("pcapng section header block is too short".to_string())
    })?;
    let body = bytes::read_bounded_initial(reader, remainder, "pcapng section header block")?;
    read_trailer_initial(reader, endian, total_len)?;
    let section = parse_section(&body, endian, 1)?;

    Ok((
        State {
            endian,
            interfaces: Vec::new(),
            global_base: 0,
            section_number: 1,
            names: Vec::new(),
        },
        section,
    ))
}

/// Read the next pcapng block and turn it into one event.
///
/// Statistics and unknown blocks are validated and dropped. Frames carry the
/// offset of their block header so callers can implement read-mode
/// `-a filesize` without re-reading the stream.
pub(crate) fn next_event<R: Read>(
    reader: &mut CountingReader<R>,
    state: &mut State,
) -> Result<Option<RawEvent>, CaptureError> {
    loop {
        let source_offset = reader.position();
        let mut header = [0_u8; 8];
        if !bytes::read_full_or_eof(reader, &mut header)? {
            return Ok(None);
        }

        let mut cursor = Cursor::new(&header);
        let type_bytes: [u8; 4] = cursor.array()?;
        let length_bytes: [u8; 4] = cursor.array()?;
        let block_type = state.endian.u32(type_bytes);

        if block_type == SHB_TYPE {
            let mut byte_order = [0_u8; 4];
            bytes::read_exact(reader, &mut byte_order)?;
            let endian = parse_byte_order(byte_order)?;
            let total_len = endian.u32(length_bytes);
            validate_section_length(total_len)?;
            let body_len = block_body_len(total_len)?;
            let remainder = body_len.checked_sub(4).ok_or_else(|| {
                CaptureError::Malformed("pcapng section header block is too short".to_string())
            })?;
            let body = bytes::read_bounded(reader, remainder)?;
            read_trailer(reader, endian, total_len)?;
            let number = state.section_number.saturating_add(1);
            let section = parse_section(&body, endian, number)?;
            state.global_base = state
                .global_base
                .saturating_add(u32::try_from(state.interfaces.len()).unwrap_or(u32::MAX));
            state.endian = endian;
            state.interfaces.clear();
            state.section_number = number;
            return Ok(Some(RawEvent::Event(CaptureEvent::Section(section))));
        }

        let total_len = state.endian.u32(length_bytes);
        validate_block_len(total_len)?;
        let body_len = block_body_len(total_len)?;

        match block_type {
            IDB_TYPE => {
                let body = read_block(reader, body_len, total_len, state.endian)?;
                let info = parse_interface_description(&body, state)?;
                return Ok(Some(RawEvent::Event(CaptureEvent::Interface(info))));
            }
            EPB_TYPE => {
                let body = read_block(reader, body_len, total_len, state.endian)?;
                return Ok(Some(RawEvent::Frame(parse_enhanced_packet(
                    &body,
                    state,
                    source_offset,
                )?)));
            }
            OPB_TYPE => {
                let body = read_block(reader, body_len, total_len, state.endian)?;
                return Ok(Some(RawEvent::Frame(parse_obsolete_packet(
                    &body,
                    state,
                    source_offset,
                )?)));
            }
            SPB_TYPE => {
                let body = read_block(reader, body_len, total_len, state.endian)?;
                return Ok(Some(RawEvent::Frame(parse_simple_packet(
                    &body,
                    state,
                    source_offset,
                )?)));
            }
            NRB_TYPE => {
                let mut body = read_block(reader, body_len, total_len, state.endian)?;
                parse_name_resolution(&mut body, state.endian)?;
                collect_name_records(&body, Endian::Little, &mut state.names)?;
                return Ok(Some(RawEvent::Event(CaptureEvent::NameResolution(body))));
            }
            ISB_TYPE => {
                let body = read_block(reader, body_len, total_len, state.endian)?;
                parse_interface_statistics(&body, state.endian)?;
            }
            _ => {
                bytes::skip_bounded(reader, body_len)?;
                read_trailer(reader, state.endian, total_len)?;
            }
        }
    }
}

fn read_block<R: Read>(
    reader: &mut R,
    body_len: usize,
    total_len: u32,
    endian: Endian,
) -> Result<Vec<u8>, CaptureError> {
    let body = bytes::read_bounded(reader, body_len)?;
    read_trailer(reader, endian, total_len)?;
    Ok(body)
}

fn parse_byte_order(byte_order: [u8; 4]) -> Result<Endian, CaptureError> {
    match byte_order {
        BYTE_ORDER_LE => Ok(Endian::Little),
        BYTE_ORDER_BE => Ok(Endian::Big),
        _ => Err(CaptureError::Malformed(
            "pcapng section header has an invalid byte-order magic".to_string(),
        )),
    }
}

fn validate_block_len(total_len: u32) -> Result<(), CaptureError> {
    let total = usize::try_from(total_len)
        .map_err(|_| CaptureError::LimitExceeded("pcapng block length"))?;
    if total > MAX_FRAME_SIZE {
        return Err(CaptureError::LimitExceeded("pcapng block length"));
    }
    if total < 12 {
        return Err(CaptureError::Malformed(
            "pcapng block length is below 12 bytes".to_string(),
        ));
    }
    if !total.is_multiple_of(4) {
        return Err(CaptureError::Malformed(
            "pcapng block length is not a multiple of four".to_string(),
        ));
    }
    Ok(())
}

fn validate_section_length(total_len: u32) -> Result<(), CaptureError> {
    validate_block_len(total_len)?;
    if total_len < MIN_SECTION_LENGTH {
        return Err(CaptureError::Malformed(format!(
            "pcapng section header block is {total_len} bytes; at least {MIN_SECTION_LENGTH} are required"
        )));
    }
    Ok(())
}

fn block_body_len(total_len: u32) -> Result<usize, CaptureError> {
    usize::try_from(total_len)
        .map_err(|_| CaptureError::LimitExceeded("pcapng block length"))?
        .checked_sub(12)
        .ok_or_else(|| CaptureError::Malformed("pcapng block length is below 12 bytes".to_string()))
}

fn read_trailer<R: Read>(
    reader: &mut R,
    endian: Endian,
    expected: u32,
) -> Result<(), CaptureError> {
    let mut trailer = [0_u8; 4];
    bytes::read_exact(reader, &mut trailer)?;
    check_trailer(trailer, endian, expected)
}

fn read_trailer_initial<R: Read>(
    reader: &mut R,
    endian: Endian,
    expected: u32,
) -> Result<(), CaptureError> {
    let mut trailer = [0_u8; 4];
    bytes::read_exact_initial(reader, &mut trailer, "pcapng block trailer")?;
    check_trailer(trailer, endian, expected)
}

fn check_trailer(trailer: [u8; 4], endian: Endian, expected: u32) -> Result<(), CaptureError> {
    let value = endian.u32(trailer);
    if value != expected {
        return Err(CaptureError::Malformed(format!(
            "pcapng block trailer is {value}, but its header declares {expected}"
        )));
    }
    Ok(())
}

fn parse_section(body: &[u8], endian: Endian, number: u32) -> Result<SectionInfo, CaptureError> {
    let mut cursor = Cursor::new(body);
    let major = cursor.u16(endian)?;
    let minor = cursor.u16(endian)?;
    if major != 1 {
        return Err(CaptureError::Malformed(format!(
            "unsupported pcapng version {major}.{minor}"
        )));
    }
    let _section_length = cursor.i64(endian)?;
    let raw = parse_options(&mut cursor, endian)?;
    let mut options = Vec::new();
    for &(code, value) in &raw {
        let option = match code {
            OPT_COMMENT => SectionOption::Comment(lossy_string(value)),
            OPT_SHB_HARDWARE => SectionOption::Hardware(lossy_string(value)),
            OPT_SHB_OS => SectionOption::Os(lossy_string(value)),
            OPT_SHB_USERAPPL => SectionOption::UserApplication(lossy_string(value)),
            _ => continue,
        };
        options.push(option);
    }
    Ok(SectionInfo { number, options })
}

fn parse_interface_description(
    body: &[u8],
    state: &mut State,
) -> Result<InterfaceInfo, CaptureError> {
    let endian = state.endian;
    let mut cursor = Cursor::new(body);
    let link_type = u32::from(cursor.u16(endian)?);
    let _reserved = cursor.u16(endian)?;
    let snap_len = cursor.u32(endian)?;
    let raw = parse_options(&mut cursor, endian)?;

    let mut resolution = TimestampResolution::default();
    let mut offset = 0_i64;
    let mut name = None;
    let mut options = Vec::new();
    for &(code, value) in &raw {
        match code {
            OPT_COMMENT => options.push(InterfaceOption::Comment(lossy_string(value))),
            OPT_IF_NAME => {
                let text = lossy_string(value);
                if name.is_none() {
                    name = Some(text.clone());
                }
                options.push(InterfaceOption::Name(text));
            }
            OPT_IF_DESCRIPTION => {
                options.push(InterfaceOption::Description(lossy_string(value)));
            }
            OPT_IF_SPEED if value.len() == 8 => {
                let bytes: [u8; 8] = value.try_into().map_err(|_| {
                    CaptureError::Malformed("if_speed has the wrong length".to_string())
                })?;
                options.push(InterfaceOption::Speed(endian.u64(bytes)));
            }
            OPT_IF_TSRESOL if value.len() == 1 => {
                let Some(raw) = value.first().copied() else {
                    continue;
                };
                resolution = if raw & 0x80 != 0 {
                    TimestampResolution::PowerOfTwo(raw & 0x7f)
                } else {
                    TimestampResolution::PowerOfTen(raw)
                };
                options.push(InterfaceOption::TimestampResolution(resolution));
            }
            OPT_IF_OS => options.push(InterfaceOption::Os(lossy_string(value))),
            OPT_IF_FILTER if value.is_empty() => {
                return Err(CaptureError::Malformed(
                    "pcapng if_filter option is empty".to_string(),
                ));
            }
            OPT_IF_FILTER => options.push(InterfaceOption::Filter(value.to_vec())),
            OPT_IF_FCSLEN if value.len() == 1 => {
                let Some(length) = value.first().copied() else {
                    continue;
                };
                options.push(InterfaceOption::FcsLength(length));
            }
            OPT_IF_TSOFFSET if value.len() == 8 => {
                let bytes: [u8; 8] = value.try_into().map_err(|_| {
                    CaptureError::Malformed("if_tsoffset has the wrong length".to_string())
                })?;
                offset = endian.i64(bytes);
                options.push(InterfaceOption::TimestampOffset(offset));
            }
            OPT_IF_HARDWARE => options.push(InterfaceOption::Hardware(lossy_string(value))),
            _ => {}
        }
    }

    if state.interfaces.len() >= MAX_INTERFACES {
        return Err(CaptureError::LimitExceeded("pcapng interfaces per section"));
    }
    let local_index = u32::try_from(state.interfaces.len())
        .map_err(|_| CaptureError::LimitExceeded("interfaces"))?;
    let info = InterfaceInfo {
        global_index: state.global_base.saturating_add(local_index),
        link_type,
        snap_len,
        options,
    };
    state.interfaces.push(Interface {
        link_type,
        snap_len,
        resolution,
        offset,
        name,
    });
    Ok(info)
}

fn parse_enhanced_packet(
    body: &[u8],
    state: &State,
    source_offset: u64,
) -> Result<FrameData, CaptureError> {
    let endian = state.endian;
    let mut cursor = Cursor::new(body);
    let interface_id = cursor.u32(endian)?;
    let high = cursor.u32(endian)?;
    let low = cursor.u32(endian)?;
    let captured_length = cursor.u32(endian)?;
    let original_len = cursor.u32(endian)?;
    let captured = take_packet_data(&mut cursor, captured_length)?;
    let raw = parse_options(&mut cursor, endian)?;
    packet_frame(
        state,
        interface_id,
        (u64::from(high) << 32) | u64::from(low),
        captured,
        original_len,
        packet_options(&raw, endian),
        source_offset,
    )
}

fn parse_obsolete_packet(
    body: &[u8],
    state: &State,
    source_offset: u64,
) -> Result<FrameData, CaptureError> {
    let endian = state.endian;
    let mut cursor = Cursor::new(body);
    let interface_id = u32::from(cursor.u16(endian)?);
    let drop_count = cursor.u16(endian)?;
    let high = cursor.u32(endian)?;
    let low = cursor.u32(endian)?;
    let captured_length = cursor.u32(endian)?;
    let original_len = cursor.u32(endian)?;
    let captured = take_packet_data(&mut cursor, captured_length)?;
    let raw = parse_options(&mut cursor, endian)?;
    let mut options = packet_options(&raw, endian);
    // An obsolete block's 16-bit counter becomes epb_dropcount only when the
    // block did not already carry an explicit option; OPB options use the
    // enhanced option table.
    if options.drop_count().is_none() {
        options
            .options
            .push(PacketOption::DropCount(u64::from(drop_count)));
    }
    packet_frame(
        state,
        interface_id,
        (u64::from(high) << 32) | u64::from(low),
        captured,
        original_len,
        options,
        source_offset,
    )
}

fn parse_simple_packet(
    body: &[u8],
    state: &State,
    source_offset: u64,
) -> Result<FrameData, CaptureError> {
    let endian = state.endian;
    let mut cursor = Cursor::new(body);
    let original_len = cursor.u32(endian)?;
    let interface = state.interface(0)?;

    let captured_limit = if interface.snap_len == 0 {
        u64::from(original_len)
    } else {
        u64::from(original_len.min(interface.snap_len))
    };
    if captured_limit > MAX_FRAME_SIZE as u64 {
        return Err(CaptureError::LimitExceeded("frame captured length"));
    }
    let captured_length = usize::try_from(captured_limit)
        .map_err(|_| CaptureError::LimitExceeded("frame captured length"))?;
    let padded = align4(captured_length)?;
    if cursor.remaining() < padded {
        return Err(CaptureError::Malformed(
            "pcapng simple packet block is shorter than its declared captured length".to_string(),
        ));
    }
    let captured = cursor.take(captured_length)?.to_vec();
    cursor.skip(padded.saturating_sub(captured_length))?;
    if cursor.remaining() != 0 {
        return Err(CaptureError::Malformed(
            "pcapng simple packet block has trailing bytes".to_string(),
        ));
    }

    Ok(FrameData {
        timestamp: None,
        timestamp_precision: interface.resolution.precision(),
        captured,
        original_len,
        link_type: interface.link_type,
        interface_id: 0,
        global_interface: state.global_base,
        timestamp_units: None,
        source_offset,
        interface_name: interface.name.clone(),
        section_number: Some(state.section_number),
        options: PacketOptions::default(),
    })
}

fn packet_frame(
    state: &State,
    interface_id: u32,
    timestamp_units: u64,
    captured: Vec<u8>,
    original_len: u32,
    options: PacketOptions,
    source_offset: u64,
) -> Result<FrameData, CaptureError> {
    let interface = state.interface(interface_id)?;
    let timestamp = decode_timestamp(timestamp_units, interface.resolution, interface.offset)?;
    Ok(FrameData {
        timestamp: Some(timestamp),
        timestamp_precision: interface.resolution.precision(),
        captured,
        original_len,
        link_type: interface.link_type,
        interface_id,
        global_interface: state.global_base.saturating_add(interface_id),
        timestamp_units: Some(timestamp_units),
        source_offset,
        interface_name: interface.name.clone(),
        section_number: Some(state.section_number),
        options,
    })
}

fn take_packet_data(
    cursor: &mut Cursor<'_>,
    captured_length: u32,
) -> Result<Vec<u8>, CaptureError> {
    if u64::from(captured_length) > MAX_FRAME_SIZE as u64 {
        return Err(CaptureError::LimitExceeded("frame captured length"));
    }
    let captured_len = usize::try_from(captured_length)
        .map_err(|_| CaptureError::LimitExceeded("frame captured length"))?;
    let padded = align4(captured_len)?;
    let captured = cursor.take(captured_len)?.to_vec();
    cursor.skip(padded.saturating_sub(captured_len))?;
    Ok(captured)
}

/// Validate a name resolution block body and normalise its headers to
/// little-endian.
///
/// Record types/lengths and option codes/lengths follow the section byte
/// order, but names and addresses are endian-neutral. The output writer emits
/// one little-endian section, so a big-endian source body must be rewritten
/// in place before it is forwarded; otherwise the block cannot be read.
fn parse_name_resolution(body: &mut [u8], endian: Endian) -> Result<(), CaptureError> {
    let mut offset = 0_usize;
    let mut records = 0_usize;
    loop {
        if body.len().saturating_sub(offset) < 4 {
            return Err(CaptureError::Malformed(
                "pcapng name resolution block is missing its end-of-records marker".to_string(),
            ));
        }
        let record_type = read_u16_at(body, offset, endian)?;
        let record_len = read_u16_at(body, offset + 2, endian)?;
        if record_type == 0 && record_len == 0 {
            break;
        }
        if record_type == 0 {
            return Err(CaptureError::Malformed(
                "pcapng name resolution record has type zero but a nonzero length".to_string(),
            ));
        }
        if records >= MAX_NAME_RECORDS {
            return Err(CaptureError::LimitExceeded(
                "pcapng name resolution records",
            ));
        }
        if record_type == 1 && record_len < 4 {
            return Err(CaptureError::Malformed(
                "pcapng IPv4 name record is shorter than its address".to_string(),
            ));
        }
        if record_type == 2 && record_len < 16 {
            return Err(CaptureError::Malformed(
                "pcapng IPv6 name record is shorter than its address".to_string(),
            ));
        }
        let padded = align4(usize::from(record_len))?;
        let end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(padded))
            .filter(|end| *end <= body.len())
            .ok_or_else(|| {
                CaptureError::Malformed(
                    "pcapng name resolution record extends past its block".to_string(),
                )
            })?;
        write_u16_at(body, offset, record_type)?;
        write_u16_at(body, offset + 2, record_len)?;
        offset = end;
        records += 1;
    }

    offset = offset.checked_add(4).ok_or_else(|| {
        CaptureError::Malformed("pcapng name resolution block offset overflow".to_string())
    })?;
    let mut options = 0_usize;
    while offset < body.len() {
        if body.len().saturating_sub(offset) < 4 {
            return Err(CaptureError::Malformed(
                "pcapng option header is incomplete".to_string(),
            ));
        }
        let code = read_u16_at(body, offset, endian)?;
        let length = read_u16_at(body, offset + 2, endian)?;
        if code == OPT_END {
            if length != 0 {
                return Err(CaptureError::Malformed(
                    "pcapng end-of-options marker has a nonzero length".to_string(),
                ));
            }
            return Ok(());
        }
        if options >= MAX_OPTION_ENTRIES {
            return Err(CaptureError::LimitExceeded("pcapng options per block"));
        }
        let padded = align4(usize::from(length))?;
        let end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(padded))
            .filter(|end| *end <= body.len())
            .ok_or_else(|| {
                CaptureError::Malformed(
                    "pcapng option extends past the end of its block".to_string(),
                )
            })?;
        write_u16_at(body, offset, code)?;
        write_u16_at(body, offset + 2, length)?;
        offset = end;
        options += 1;
    }
    Ok(())
}

/// Collect the address/name pairs from an already validated name-resolution
/// body. The normaliser runs first, so headers are little-endian here.
fn collect_name_records(
    body: &[u8],
    endian: Endian,
    names: &mut Vec<(IpAddr, String)>,
) -> Result<(), CaptureError> {
    let mut cursor = Cursor::new(body);
    loop {
        if cursor.remaining() < 4 {
            return Ok(());
        }
        let record_type = cursor.u16(endian)?;
        let record_len = cursor.u16(endian)?;
        if record_type == 0 && record_len == 0 {
            break;
        }
        let value_len = usize::from(record_len);
        let value = cursor.take(value_len)?;
        match record_type {
            1 => {
                if names.len() < MAX_TOTAL_NAME_RECORDS
                    && let Some(name) = name_after(value, 4)
                    && let Some(address) = value.get(..4)
                    && let Ok(bytes) = <[u8; 4]>::try_from(address)
                {
                    names.push((IpAddr::V4(Ipv4Addr::from(bytes)), name));
                }
            }
            2 => {
                if names.len() < MAX_TOTAL_NAME_RECORDS
                    && let Some(name) = name_after(value, 16)
                    && let Some(address) = value.get(..16)
                    && let Ok(bytes) = <[u8; 16]>::try_from(address)
                {
                    names.push((IpAddr::V6(Ipv6Addr::from(bytes)), name));
                }
            }
            _ => {}
        }
        let padded = align4(value_len)?;
        cursor.skip(padded.saturating_sub(value_len))?;
    }
    Ok(())
}

fn read_u16_at(body: &[u8], offset: usize, endian: Endian) -> Result<u16, CaptureError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| CaptureError::Malformed("pcapng offset overflow".to_string()))?;
    let bytes: [u8; 2] = body
        .get(offset..end)
        .ok_or_else(|| {
            CaptureError::Malformed(
                "a field extends past the end of its capture structure".to_string(),
            )
        })?
        .try_into()
        .map_err(|_| CaptureError::Malformed("a fixed field has the wrong length".to_string()))?;
    Ok(endian.u16(bytes))
}

fn write_u16_at(body: &mut [u8], offset: usize, value: u16) -> Result<(), CaptureError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| CaptureError::Malformed("pcapng offset overflow".to_string()))?;
    body.get_mut(offset..end)
        .ok_or_else(|| {
            CaptureError::Malformed(
                "a field extends past the end of its capture structure".to_string(),
            )
        })?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// The first NUL-terminated name after an address in a name record.
fn name_after(value: &[u8], address_length: usize) -> Option<String> {
    let rest = value.get(address_length..)?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    let text = String::from_utf8_lossy(rest.get(..end)?);
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.chars().take(MAX_NAME_LENGTH).collect())
    }
}

fn parse_interface_statistics(body: &[u8], endian: Endian) -> Result<(), CaptureError> {
    let mut cursor = Cursor::new(body);
    let _interface_id = cursor.u32(endian)?;
    let _high = cursor.u32(endian)?;
    let _low = cursor.u32(endian)?;
    parse_options(&mut cursor, endian)?;
    Ok(())
}

fn parse_options<'a>(
    cursor: &mut Cursor<'a>,
    endian: Endian,
) -> Result<Vec<(u16, &'a [u8])>, CaptureError> {
    let mut options = Vec::new();
    while cursor.remaining() >= 4 {
        let code = cursor.u16(endian)?;
        let length = cursor.u16(endian)?;
        if code == OPT_END {
            if length != 0 {
                return Err(CaptureError::Malformed(
                    "pcapng end-of-options marker has a nonzero length".to_string(),
                ));
            }
            return Ok(options);
        }
        if options.len() >= MAX_OPTION_ENTRIES {
            return Err(CaptureError::LimitExceeded("pcapng options per block"));
        }
        let value_len = usize::from(length);
        let value = cursor.take(value_len)?;
        let padded = align4(value_len)?;
        cursor.skip(padded.saturating_sub(value_len))?;
        options.push((code, value));
    }
    if cursor.remaining() != 0 {
        return Err(CaptureError::Malformed(
            "pcapng option header is incomplete".to_string(),
        ));
    }
    Ok(options)
}

/// Decode the known packet options of one enhanced or obsolete block.
///
/// Obsolete packet blocks use the enhanced option table too, so both block
/// kinds share this decoder. Options with a length the field cannot hold are
/// ignored rather than failing the block.
fn packet_options(options: &[(u16, &[u8])], endian: Endian) -> PacketOptions {
    let mut decoded = PacketOptions::default();
    for &(code, value) in options {
        let option = match code {
            OPT_COMMENT => PacketOption::Comment(lossy_string(value)),
            OPT_EPB_FLAGS if value.len() == 4 => {
                let bytes: [u8; 4] = match value.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                PacketOption::Flags(endian.u32(bytes))
            }
            OPT_EPB_HASH if !value.is_empty() => PacketOption::Hash(value.to_vec()),
            OPT_EPB_DROPCOUNT if value.len() == 8 => {
                let bytes: [u8; 8] = match value.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                PacketOption::DropCount(endian.u64(bytes))
            }
            OPT_EPB_PACKETID if value.len() == 8 => {
                let bytes: [u8; 8] = match value.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                PacketOption::PacketId(endian.u64(bytes))
            }
            OPT_EPB_QUEUE if value.len() == 4 => {
                let bytes: [u8; 4] = match value.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                PacketOption::Queue(endian.u32(bytes))
            }
            OPT_EPB_VERDICT if !value.is_empty() => PacketOption::Verdict(value.to_vec()),
            _ => continue,
        };
        decoded.options.push(option);
    }
    decoded
}

fn lossy_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

fn align4(value: usize) -> Result<usize, CaptureError> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| CaptureError::Malformed("declared length overflow".to_string()))
}

fn decode_timestamp(
    raw: u64,
    resolution: TimestampResolution,
    offset: i64,
) -> Result<Timestamp, CaptureError> {
    let (seconds, nanos) = match resolution {
        TimestampResolution::PowerOfTen(exponent) => {
            if exponent == 0 {
                (u128::from(raw), 0_u128)
            } else if let Some(divisor) = 10_u128.checked_pow(u32::from(exponent)) {
                let value = u128::from(raw);
                let remainder = value % divisor;
                (value / divisor, remainder * 1_000_000_000 / divisor)
            } else {
                // 10^exponent exceeds u128. A u64 tick count is far below
                // one such tick, so both parts are zero.
                (0, 0)
            }
        }
        TimestampResolution::PowerOfTwo(exponent) => {
            if let Some(divisor) = 1_u128.checked_shl(u32::from(exponent)) {
                let value = u128::from(raw);
                let remainder = value % divisor;
                (value / divisor, remainder * 1_000_000_000 / divisor)
            } else {
                // A resolution finer than 2^-127 makes every u64 tick far
                // below one nanosecond.
                (0, 0)
            }
        }
    };

    let seconds = i128::try_from(seconds)
        .ok()
        .and_then(|seconds| seconds.checked_add(i128::from(offset)))
        .and_then(|seconds| i64::try_from(seconds).ok())
        .ok_or_else(|| {
            CaptureError::Malformed("pcapng timestamp seconds are out of range".to_string())
        })?;
    let nanos = u32::try_from(nanos).map_err(|_| {
        CaptureError::Malformed("pcapng timestamp nanoseconds are out of range".to_string())
    })?;
    if nanos >= 1_000_000_000 {
        return Err(CaptureError::Malformed(
            "pcapng timestamp nanoseconds are out of range".to_string(),
        ));
    }
    Ok(Timestamp { seconds, nanos })
}

#[cfg(test)]
mod tests {
    use super::{State, decode_timestamp, parse_interface_description};
    use crate::capture::TimestampResolution;

    #[test]
    fn binary_resolution_precision_is_exact() {
        for (exponent, digits) in [(1, 0), (6, 1), (10, 3), (16, 4), (26, 7), (30, 9)] {
            assert_eq!(
                TimestampResolution::PowerOfTwo(exponent).precision(),
                digits
            );
        }
    }
    use crate::capture::Timestamp;
    use crate::capture::bytes::Endian;

    fn decoded(
        raw: u64,
        resolution: TimestampResolution,
        offset: i64,
    ) -> Result<Timestamp, String> {
        decode_timestamp(raw, resolution, offset).map_err(|error| error.to_string())
    }

    #[test]
    fn interface_options_decode_binary_resolution_name_and_offset() -> Result<(), String> {
        let mut body = Vec::new();
        body.extend_from_slice(&1_u16.to_le_bytes()); // link type
        body.extend_from_slice(&0_u16.to_le_bytes()); // reserved
        body.extend_from_slice(&262_144_u32.to_le_bytes()); // snap length
        body.extend_from_slice(&2_u16.to_le_bytes()); // if_name
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&[b'x', 0, 0, 0]);
        body.extend_from_slice(&9_u16.to_le_bytes()); // if_tsresol
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&[0x8a, 0, 0, 0]); // 2^-10 seconds
        body.extend_from_slice(&14_u16.to_le_bytes()); // if_tsoffset
        body.extend_from_slice(&8_u16.to_le_bytes());
        body.extend_from_slice(&100_i64.to_le_bytes());
        body.extend_from_slice(&0_u32.to_le_bytes()); // end of options

        let mut state = State {
            endian: Endian::Little,
            interfaces: Vec::new(),
            global_base: 0,
            section_number: 1,
            names: Vec::new(),
        };
        let info = parse_interface_description(&body, &mut state)
            .map_err(|error| format!("IDB parse failed: {error}"))?;
        assert_eq!(info.global_index, 0);
        assert_eq!(info.link_type, 1);
        assert_eq!(info.snap_len, 262_144);
        assert_eq!(
            info.timestamp_resolution(),
            Some(TimestampResolution::PowerOfTwo(10))
        );
        assert_eq!(info.timestamp_offset(), Some(100));
        assert_eq!(info.name(), Some("x"));
        let interface = state
            .interfaces
            .first()
            .ok_or_else(|| "IDB did not add an interface".to_string())?;
        assert_eq!(interface.resolution, TimestampResolution::PowerOfTwo(10));
        assert_eq!(interface.offset, 100);
        assert_eq!(interface.name.as_deref(), Some("x"));
        assert_eq!(interface.link_type, 1);
        assert_eq!(interface.snap_len, 262_144);
        Ok(())
    }

    #[test]
    fn microseconds_use_the_default_scale() -> Result<(), String> {
        assert_eq!(
            decoded(1_700_000_000_123_456, TimestampResolution::PowerOfTen(6), 0)?,
            Timestamp {
                seconds: 1_700_000_000,
                nanos: 123_456_000,
            }
        );
        Ok(())
    }

    #[test]
    fn nanoseconds_are_kept_exactly() -> Result<(), String> {
        assert_eq!(
            decoded(
                1_700_000_001_200_000_001,
                TimestampResolution::PowerOfTen(9),
                0
            )?,
            Timestamp {
                seconds: 1_700_000_001,
                nanos: 200_000_001,
            }
        );
        Ok(())
    }

    #[test]
    fn sub_nanosecond_resolution_truncates() -> Result<(), String> {
        assert_eq!(
            decoded(
                1_700_000_000_123_456,
                TimestampResolution::PowerOfTen(12),
                0
            )?,
            Timestamp {
                seconds: 1_700,
                nanos: 123,
            }
        );
        Ok(())
    }

    #[test]
    fn binary_resolution_is_exact() -> Result<(), String> {
        assert_eq!(
            decoded(1_536, TimestampResolution::PowerOfTwo(10), 0)?,
            Timestamp {
                seconds: 1,
                nanos: 500_000_000,
            }
        );
        assert_eq!(
            decoded(u64::MAX, TimestampResolution::PowerOfTwo(64), 0)?,
            Timestamp {
                seconds: 0,
                nanos: 999_999_999,
            }
        );
        assert_eq!(
            decoded(u64::MAX, TimestampResolution::PowerOfTwo(127), 0)?,
            Timestamp {
                seconds: 0,
                nanos: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn offsets_shift_the_seconds_field() -> Result<(), String> {
        assert_eq!(
            decoded(1_700_000_000, TimestampResolution::PowerOfTen(0), 100)?,
            Timestamp {
                seconds: 1_700_000_100,
                nanos: 0,
            }
        );
        assert_eq!(
            decoded(1_500_000_000, TimestampResolution::PowerOfTen(9), -100)?,
            Timestamp {
                seconds: -99,
                nanos: 500_000_000,
            }
        );
        Ok(())
    }

    #[test]
    fn an_out_of_range_second_is_an_error() {
        let result = decode_timestamp(u64::MAX, TimestampResolution::PowerOfTen(0), i64::MAX);
        assert!(matches!(
            result,
            Err(crate::capture::CaptureError::Malformed(_))
        ));
    }
}
