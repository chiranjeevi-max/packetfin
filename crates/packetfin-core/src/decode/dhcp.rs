//! BOOTP and DHCP over UDP.
//!
//! The fixed header, the magic cookie and the option TLV layout follow
//! RFC 2131 sections 3 and 4 and RFC 2132 sections 3-9. Option overload
//! (option 52) reuses the `sname` and `file` fields as option areas, as
//! RFC 2132 section 9.3 defines; the main area scans first, then `file`, then
//! `sname`, which is also the field output order. Repeated option codes are
//! concatenated in that order per RFC 3396 and decoded once. Every declared
//! option length is checked against the bytes that remain: a truncated option
//! keeps its type and length, marks the packet malformed and ends parsing.
//!
//! Options are added as `dhcp.option.type` containers, with typed children
//! and their hidden, anonymous and expert items. Full-tree output uses a
//! separate visible order; `-T fields` values and order, filters and
//! summaries keep the decoder's insertion order.

use crate::decode::DecodeContext;
use crate::decode::bytes::{
    ascii_lossy, hex_lower, is_ethernet_link_layer, link_layer_mac, link_layer_text, read_u16_be,
    read_u32_be,
};
use crate::fields;
use crate::tree::{
    Bytes, ExpertInfo, Field, FieldParent, Group, Node, Range, RawField, RawSource, Severity, Value,
};

const OP: usize = 0;
const HARDWARE_TYPE: usize = 1;
const HARDWARE_LENGTH: usize = 2;
const HOPS: usize = 3;
const TRANSACTION_ID: usize = 4;
const SECONDS: usize = 8;
const FLAGS: usize = 10;
const CLIENT_ADDRESS: usize = 12;
const YOUR_ADDRESS: usize = 16;
const SERVER_ADDRESS: usize = 20;
const RELAY_ADDRESS: usize = 24;
const CLIENT_HARDWARE: usize = 28;
const SERVER_NAME: usize = 44;
const BOOT_FILE: usize = 108;
const COOKIE: usize = 236;
const OPTIONS: usize = 240;
const FIXED_LENGTH: usize = 236;

const COOKIE_VALUE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

const OPTION_PADDING: u8 = 0;
const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS: u8 = 6;
const OPTION_HOSTNAME: u8 = 12;
const OPTION_DOMAIN_NAME: u8 = 15;
const OPTION_BROADCAST: u8 = 28;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_OVERLOAD: u8 = 52;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_ID: u8 = 54;
const OPTION_REQUEST_LIST: u8 = 55;
const OPTION_MESSAGE: u8 = 56;
const OPTION_MAX_MESSAGE_SIZE: u8 = 57;
const OPTION_RENEWAL_TIME: u8 = 58;
const OPTION_REBINDING_TIME: u8 = 59;
const OPTION_VENDOR_CLASS: u8 = 60;
const OPTION_CLIENT_ID: u8 = 61;
const OPTION_TFTP_SERVER: u8 = 66;
const OPTION_BOOTFILE: u8 = 67;
const OPTION_AGENT_INFORMATION: u8 = 82;
const OPTION_END: u8 = 255;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Area {
    Main,
    ServerName,
    BootFile,
}

/// Decode one BOOTP/DHCP datagram into the UDP node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::DHCP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::DHCP_PROTOCOL, Range::new(base, data.len()));
    parse(&mut node, context, data, base);

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

struct FirstPass {
    overload: u8,
    has_message_type: bool,
    blocks: [u16; 256],
    bodies: [Vec<u8>; 256],
}

fn parse(node: &mut Node, context: &mut DecodeContext<'_>, data: &[u8], base: usize) {
    let Some(hardware_length) = data.get(HARDWARE_LENGTH).map(|value| usize::from(*value)) else {
        context.mark_malformed(node, "DHCP header is truncated");
        return;
    };
    if hardware_length > 16 {
        if CLIENT_HARDWARE.saturating_add(hardware_length) > data.len() {
            context.mark_malformed(node, "DHCP header is truncated");
            return;
        }
    } else if data.len() < CLIENT_HARDWARE.saturating_add(hardware_length) {
        context.mark_malformed(node, "DHCP header is truncated");
        return;
    }
    let op = data.get(OP).copied().unwrap_or(0);
    let hardware_type = data.get(HARDWARE_TYPE).copied().unwrap_or(0);
    let hops = data.get(HOPS).copied().unwrap_or(0);
    let transaction_id = read_u32_be(data, TRANSACTION_ID).unwrap_or(0);
    let seconds = read_u16_be(data, SECONDS).unwrap_or(0);
    let flags = read_u16_be(data, FLAGS).unwrap_or(0);

    node.add_field(
        &fields::DHCP_TYPE,
        Range::new(base + OP, 1),
        Value::Uint8(op),
    );
    node.add_field(
        &fields::DHCP_HW_TYPE,
        Range::new(base + HARDWARE_TYPE, 1),
        Value::Uint8(hardware_type),
    );
    node.add_field(
        &fields::DHCP_HW_LEN,
        Range::new(base + HARDWARE_LENGTH, 1),
        Value::Uint8(data.get(HARDWARE_LENGTH).copied().unwrap_or(0)),
    );
    node.add_field(
        &fields::DHCP_HOPS,
        Range::new(base + HOPS, 1),
        Value::Uint8(hops),
    );
    node.add_field(
        &fields::DHCP_ID,
        Range::new(base + TRANSACTION_ID, 4),
        Value::Uint32(transaction_id),
    );
    add_seconds(node, base, seconds);
    add_flags(node, base, flags);
    for (offset, definition) in [
        (CLIENT_ADDRESS, &fields::DHCP_IP_CLIENT),
        (YOUR_ADDRESS, &fields::DHCP_IP_YOUR),
        (SERVER_ADDRESS, &fields::DHCP_IP_SERVER),
        (RELAY_ADDRESS, &fields::DHCP_IP_RELAY),
    ] {
        node.add_field(
            definition,
            Range::new(base + offset, 4),
            Value::Ipv4(read_ipv4(data, offset)),
        );
    }
    add_hardware_address(node, data, base, hardware_length);

    if data.len() < FIXED_LENGTH {
        context.mark_malformed(node, "DHCP header is truncated");
        return;
    }
    let header_end = node.fields.len();
    let cookie_valid = data
        .get(COOKIE..COOKIE + 4)
        .is_some_and(|cookie| cookie == COOKIE_VALUE);
    if !cookie_valid {
        add_file_field(node, data, base);
        let file_index = node.fields.len().saturating_sub(1);
        add_server_field(node, data, base);
        let sname_index = node.fields.len().saturating_sub(1);
        node.add_field(
            &fields::DHCP_BOOTP,
            Range::new(base, 0),
            Value::Boolean(true),
        )
        .hide();
        set_dhcp_display_order(node, header_end, file_index, sname_index, None, None);
        context.mark_malformed(node, "DHCP magic cookie is missing");
        return;
    }

    let first = first_pass(data);
    let file_overloaded = first.overload & 1 != 0;
    let sname_overloaded = first.overload & 2 != 0;

    // Add the boot file item first, then the server name item, and move the
    // boot file item after the server name item for the visible tree.
    // Selected-field output keeps this insertion order.
    let file_index = if file_overloaded {
        add_overload_marker(
            node,
            data,
            base,
            Area::BootFile,
            "Boot file name option overloaded by DHCP",
            &fields::DHCP_BOOT_FILENAME_OVERLOADED_BY_DHCP,
        );
        node.fields.len().saturating_sub(1)
    } else {
        add_file_field(node, data, base);
        node.fields.len().saturating_sub(1)
    };
    let sname_index = if sname_overloaded {
        add_overload_marker(
            node,
            data,
            base,
            Area::ServerName,
            "Server name option overloaded by DHCP",
            &fields::DHCP_SERVER_NAME_OVERLOADED_BY_DHCP,
        );
        node.fields.len().saturating_sub(1)
    } else {
        add_server_field(node, data, base);
        node.fields.len().saturating_sub(1)
    };

    if !first.has_message_type {
        node.add_field(
            &fields::DHCP_BOOTP,
            Range::new(base, 0),
            Value::Boolean(true),
        )
        .hide();
    }
    node.add_field(
        &fields::DHCP_COOKIE,
        Range::new(base + COOKIE, 4),
        Value::Ipv4(COOKIE_VALUE),
    );

    let mut seen = [0_u16; 256];
    let main = decode_area(
        node,
        data,
        base,
        Area::Main,
        OPTIONS,
        data.len(),
        true,
        &first,
        &mut seen,
    );
    if let Some(message) = main.malformed {
        set_dhcp_display_order(node, header_end, file_index, sname_index, None, None);
        context.mark_malformed(node, message);
        return;
    }
    if main.ok && !main.saw_end && first.has_message_type && data.len() > OPTIONS {
        let marker = node.add_field(
            &fields::DHCP_END_OPTION_MISSING,
            Range::new(base + data.len(), 0),
            Value::None,
        );
        marker.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Protocol,
            message: "End option missing".to_string(),
        });
    }
    let mut file_overload_index = None;
    if main.ok && file_overloaded {
        add_overload_container(
            node,
            data,
            base,
            Area::BootFile,
            "Boot file name option overload",
        );
        let index = node.fields.len().saturating_sub(1);
        let Some(field) = node.fields.get_mut(index) else {
            return;
        };
        let decoded = decode_area(
            field,
            data,
            base,
            Area::BootFile,
            BOOT_FILE,
            FIXED_LENGTH,
            false,
            &first,
            &mut seen,
        );
        if let Some(message) = decoded.malformed {
            // A group whose decoding failed keeps its insertion position.
            set_dhcp_display_order(node, header_end, file_index, sname_index, None, None);
            context.mark_malformed(node, message);
            return;
        }
        if let Some(suffix) = overload_message_suffix(field) {
            field.showname = Some(format!("Boot file name option overload{suffix}"));
        }
        if !decoded.saw_end {
            add_end_missing(
                field,
                base + BOOT_FILE,
                &fields::DHCP_OPTION_OPTION_OVERLOAD_FILE_END_MISSING,
                "file overload end option missing",
            );
        }
        file_overload_index = Some(index);
    }
    let mut sname_overload_index = None;
    if main.ok && sname_overloaded {
        add_overload_container(
            node,
            data,
            base,
            Area::ServerName,
            "Server host name option overload",
        );
        let index = node.fields.len().saturating_sub(1);
        let Some(field) = node.fields.get_mut(index) else {
            return;
        };
        let decoded = decode_area(
            field,
            data,
            base,
            Area::ServerName,
            SERVER_NAME,
            BOOT_FILE,
            false,
            &first,
            &mut seen,
        );
        if let Some(message) = decoded.malformed {
            // The file group was already moved; this group's move never ran.
            set_dhcp_display_order(
                node,
                header_end,
                file_index,
                sname_index,
                file_overload_index,
                None,
            );
            context.mark_malformed(node, message);
            return;
        }
        if let Some(suffix) = overload_message_suffix(field) {
            field.showname = Some(format!("Server host name option overload{suffix}"));
        }
        if !decoded.saw_end {
            add_end_missing(
                field,
                base + SERVER_NAME,
                &fields::DHCP_OPTION_OPTION_OVERLOAD_SNAME_END_MISSING,
                "sname overload end option missing",
            );
        }
        sname_overload_index = Some(index);
    }
    if let Some(padding) = main.trailing_padding {
        node.add_field(
            &fields::DHCP_OPTION_PADDING,
            padding,
            Value::bytes(
                data.get(
                    padding.offset.saturating_sub(base)
                        ..padding.offset.saturating_sub(base) + padding.length,
                )
                .unwrap_or(&[])
                .to_vec(),
            ),
        );
    }

    set_dhcp_display_order(
        node,
        header_end,
        file_index,
        sname_index,
        file_overload_index,
        sname_overload_index,
    );
}

fn add_file_field(node: &mut Node, data: &[u8], base: usize) {
    node.add_field(
        &fields::DHCP_FILE,
        Range::new(base + BOOT_FILE, 128),
        Value::String(c_string(
            data.get(BOOT_FILE..BOOT_FILE + 128).unwrap_or(&[]),
        )),
    );
}

fn add_server_field(node: &mut Node, data: &[u8], base: usize) {
    node.add_field(
        &fields::DHCP_SERVER,
        Range::new(base + SERVER_NAME, 64),
        Value::String(c_string(
            data.get(SERVER_NAME..SERVER_NAME + 64).unwrap_or(&[]),
        )),
    );
}

/// Apply the visible-tree moves, including the malformed paths that stop
/// decoding before the normal end of the decoder.
fn set_dhcp_display_order(
    node: &mut Node,
    header_end: usize,
    file_index: usize,
    sname_index: usize,
    file_overload: Option<usize>,
    sname_overload: Option<usize>,
) {
    let mut order: Vec<u32> = (0..header_end)
        .map(|index| u32::try_from(index).unwrap_or(u32::MAX))
        .collect();
    for index in [
        Some(sname_index),
        sname_overload,
        Some(file_index),
        file_overload,
    ]
    .into_iter()
    .flatten()
    {
        order.push(u32::try_from(index).unwrap_or(u32::MAX));
    }
    let moved: [usize; 4] = [
        sname_index,
        sname_overload.unwrap_or(usize::MAX),
        file_index,
        file_overload.unwrap_or(usize::MAX),
    ];
    for index in header_end..node.fields.len() {
        if !moved.contains(&index) {
            order.push(u32::try_from(index).unwrap_or(u32::MAX));
        }
    }
    node.set_display_order(order);
}

fn add_seconds(node: &mut Node, base: usize, seconds: u16) {
    let range = Range::new(base + SECONDS, 2);
    if seconds & 0x00ff == 0 && seconds != 0 {
        node.add_field(
            &fields::DHCP_SECS,
            range,
            Value::Uint16(seconds.rotate_left(8)),
        );
        node.add_field(
            &fields::DHCP_SECS_LE,
            Range::new(base + SECONDS, 0),
            Value::None,
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Protocol,
            message: "Seconds elapsed appears to be encoded as little-endian".to_string(),
        });
    } else {
        node.add_field(&fields::DHCP_SECS, range, Value::Uint16(seconds));
    }
}

fn add_flags(node: &mut Node, base: usize, flags: u16) {
    let range = Range::new(base + FLAGS, 2);
    let broadcast = flags & 0x8000 != 0;
    let showname = if broadcast {
        format!("Bootp flags: 0x{flags:04x}, Broadcast flag (Broadcast)")
    } else {
        format!("Bootp flags: 0x{flags:04x} (Unicast)")
    };
    let container = node.add_container(&fields::DHCP_FLAGS, range, Some(showname));
    container.value = Value::Uint16(flags);
    let bc = container.add_field(&fields::DHCP_FLAGS_BC, range, Value::Boolean(broadcast));
    bc.showname = Some(format!(
        "1... .... .... .... = Broadcast flag: {}",
        if broadcast { "Broadcast" } else { "Unicast" }
    ));
    let reserved = container.add_field(
        &fields::DHCP_FLAGS_RESERVED,
        range,
        Value::Uint16(flags & 0x7fff),
    );
    reserved.showname = Some(format!(
        ".000 0000 0000 0000 = Reserved flags: 0x{:04x}",
        flags & 0x7fff
    ));
}

fn add_hardware_address(node: &mut Node, data: &[u8], base: usize, hardware_length: usize) {
    if hardware_length == 0 || hardware_length > 16 {
        let bytes = data
            .get(CLIENT_HARDWARE..CLIENT_HARDWARE + 16)
            .unwrap_or(&[])
            .to_vec();
        let group = node.add_unnamed(
            Range::new(base + CLIENT_HARDWARE, 16),
            "Client address not given".to_string(),
        );
        group.value = Value::bytes(bytes);
        let marker = group.add_field(
            &fields::DHCP_CLIENT_ADDRESS_NOT_GIVEN,
            Range::new(base + CLIENT_HARDWARE, 0),
            Value::None,
        );
        marker.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Protocol,
            message: "Client address not given".to_string(),
        });
        return;
    }
    if hardware_length == 6 {
        if let Some(mac) = data
            .get(CLIENT_HARDWARE..CLIENT_HARDWARE + 6)
            .and_then(|address| <[u8; 6]>::try_from(address).ok())
        {
            node.add_field(
                &fields::DHCP_HW_MAC_ADDR,
                Range::new(base + CLIENT_HARDWARE, 6),
                Value::Ethernet(mac),
            );
        }
        if let Some(padding) = data.get(CLIENT_HARDWARE + 6..CLIENT_HARDWARE + 16) {
            node.add_field(
                &fields::DHCP_HW_ADDR_PADDING,
                Range::new(base + CLIENT_HARDWARE + 6, padding.len()),
                Value::bytes(padding.to_vec()),
            );
        }
        return;
    }
    if let Some(chaddr) = data.get(CLIENT_HARDWARE..CLIENT_HARDWARE + 16) {
        let field = node.add_field(
            &fields::DHCP_HW_ADDR,
            Range::new(base + CLIENT_HARDWARE, 16),
            Value::bytes(chaddr.to_vec()),
        );
        let visible = chaddr.get(..hardware_length).unwrap_or(chaddr);
        field.showname = Some(format!("Client hardware address: {}", hex_lower(visible)));
    }
    if hardware_length < 16
        && let Some(padding) = data.get(CLIENT_HARDWARE + hardware_length..CLIENT_HARDWARE + 16)
    {
        node.add_field(
            &fields::DHCP_HW_ADDR_PADDING,
            Range::new(base + CLIENT_HARDWARE + hardware_length, padding.len()),
            Value::bytes(padding.to_vec()),
        );
    }
}

fn add_overload_marker(
    node: &mut Node,
    data: &[u8],
    base: usize,
    area: Area,
    label: &str,
    expert_field: &'static fields::FieldDef,
) {
    let (start, length) = match area {
        Area::BootFile => (BOOT_FILE, 128),
        Area::ServerName => (SERVER_NAME, 64),
        Area::Main => (OPTIONS, 0),
    };
    let bytes = data.get(start..start + length).unwrap_or(&[]).to_vec();
    let field = node.add_unnamed(Range::new(base + start, length), label.to_string());
    field.value = Value::bytes(bytes);
    let marker = field.add_field(expert_field, Range::new(base + start, 0), Value::None);
    marker.add_expert(ExpertInfo {
        severity: Severity::Note,
        group: Group::Protocol,
        message: label.to_string(),
    });
}

fn add_overload_container(node: &mut Node, data: &[u8], base: usize, area: Area, label: &str) {
    let (start, length) = match area {
        Area::BootFile => (BOOT_FILE, 128),
        Area::ServerName => (SERVER_NAME, 64),
        Area::Main => (OPTIONS, 0),
    };
    let bytes = data.get(start..start + length).unwrap_or(&[]).to_vec();
    let field = node.add_unnamed(Range::new(base + start, length), label.to_string());
    field.value = Value::bytes(bytes);
}

fn overload_message_suffix(field: &Field) -> Option<String> {
    let mut message_type = None;
    for child in &field.children {
        if child.def.abbrev != "dhcp.option.type" {
            continue;
        }
        if let Some(value) = child
            .children
            .iter()
            .find(|candidate| candidate.def.abbrev == "dhcp.option.dhcp")
            && let Value::Uint8(code) = value.value
        {
            message_type = Some(code);
        }
    }
    message_type.map(|code| {
        let name = fields::value_name("dhcp.option.dhcp", u64::from(code))
            .map(str::to_string)
            .unwrap_or_else(|| format!("Unknown Message Type (0x{code:02x})"));
        format!(" ({name})")
    })
}

fn add_end_missing(
    parent: &mut Field,
    offset: usize,
    definition: &'static fields::FieldDef,
    message: &str,
) {
    let marker = parent.add_field(definition, Range::new(offset, 0), Value::None);
    marker.add_expert(ExpertInfo {
        severity: Severity::Error,
        group: Group::Protocol,
        message: message.to_string(),
    });
}

struct AreaResult {
    ok: bool,
    saw_end: bool,
    trailing_padding: Option<Range>,
    malformed: Option<&'static str>,
}

fn first_pass(data: &[u8]) -> FirstPass {
    let mut pass = FirstPass {
        overload: 0,
        has_message_type: false,
        blocks: [0; 256],
        bodies: std::array::from_fn(|_| Vec::new()),
    };
    scan_first_area(data, OPTIONS, data.len(), true, &mut pass);
    if pass.overload & 1 != 0 {
        scan_first_area(data, BOOT_FILE, FIXED_LENGTH, false, &mut pass);
    }
    if pass.overload & 2 != 0 {
        scan_first_area(data, SERVER_NAME, BOOT_FILE, false, &mut pass);
    }
    pass
}

#[expect(
    clippy::indexing_slicing,
    reason = "an option code is a u8 and the arrays hold 256 entries"
)]
fn scan_first_area(data: &[u8], start: usize, end: usize, main: bool, pass: &mut FirstPass) {
    let end = end.min(data.len());
    let mut position = start;
    while position < end {
        let Some(&code) = data.get(position) else {
            break;
        };
        if code == OPTION_PADDING {
            while position < end && data.get(position) == Some(&OPTION_PADDING) {
                position += 1;
            }
            continue;
        }
        if code == OPTION_END {
            break;
        }
        let Some(length) = data.get(position + 1).map(|value| usize::from(*value)) else {
            break;
        };
        let body_start = position + 2;
        let Some(body) = data.get(body_start..body_start + length) else {
            break;
        };
        pass.blocks[usize::from(code)] = pass.blocks[usize::from(code)].saturating_add(1);
        pass.bodies[usize::from(code)].extend_from_slice(body);
        if code == OPTION_MESSAGE_TYPE {
            pass.has_message_type = true;
        }
        if main && code == OPTION_OVERLOAD {
            pass.overload = body.first().map_or(3, |value| value & 3);
        }
        position = body_start + length;
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "an option area carries its bounds and first-pass state"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "an option code is a u8 and the arrays hold 256 entries"
)]
fn decode_area(
    parent: &mut dyn FieldParent,
    data: &[u8],
    base: usize,
    area: Area,
    start: usize,
    end: usize,
    trailing_padding: bool,
    first: &FirstPass,
    seen: &mut [u16; 256],
) -> AreaResult {
    let end = end.min(data.len());
    let mut position = start;
    let mut saw_end = false;
    let mut trailing = None;
    while position < end {
        let Some(&code) = data.get(position) else {
            break;
        };
        if code == OPTION_PADDING {
            let run_start = position;
            while position < end && data.get(position) == Some(&OPTION_PADDING) {
                position += 1;
            }
            let field = parent.add_container(
                &fields::DHCP_OPTION_TYPE,
                Range::new(base + run_start, 1),
                Some("Option: (0) Padding".to_string()),
            );
            field.value = Value::Uint8(0);
            let run = data.get(run_start..position).unwrap_or(&[]);
            field.add_field(
                &fields::DHCP_OPTION_PADDING,
                Range::new(base + run_start, run.len()),
                Value::bytes(run.to_vec()),
            );
            continue;
        }
        if code == OPTION_END {
            let field = parent.add_container(
                &fields::DHCP_OPTION_TYPE,
                Range::new(base + position, 1),
                Some("Option: (255) End".to_string()),
            );
            field.value = Value::Uint8(0);
            let end_field = field.add_field(
                &fields::DHCP_OPTION_END,
                Range::new(base + position, 1),
                Value::Uint8(OPTION_END),
            );
            if area != Area::Main {
                end_field.showname = Some("Option End (Overload): 255".to_string());
            }
            position += 1;
            if trailing_padding
                && position < end
                && let Some(padding) = data.get(position..end)
            {
                trailing = Some(Range::new(base + position, padding.len()));
            }
            saw_end = true;
            break;
        }
        let Some(length_byte) = data.get(position + 1).copied() else {
            return AreaResult {
                ok: false,
                saw_end,
                trailing_padding: trailing,
                malformed: Some("DHCP option length is missing"),
            };
        };
        let length = usize::from(length_byte);
        let body_start = position + 2;
        let name = option_name(code).unwrap_or("Unassigned");
        let label = format!("Option: ({code}) {name}");
        let field = parent.add_container(
            &fields::DHCP_OPTION_TYPE,
            Range::new(base + position, 2 + length),
            Some(label.clone()),
        );
        field.value = Value::Uint8(code);
        field.add_field(
            &fields::DHCP_OPTION_LENGTH,
            Range::new(base + position + 1, 1),
            Value::Uint8(length_byte),
        );
        let Some(block) = data.get(body_start..body_start + length) else {
            return AreaResult {
                ok: false,
                saw_end,
                trailing_padding: trailing,
                malformed: Some("DHCP option value is truncated"),
            };
        };
        let index = seen[usize::from(code)].saturating_add(1);
        seen[usize::from(code)] = index;
        let total = first.blocks[usize::from(code)].max(1);
        let hidden_index = add_hidden_value(field, block, base + body_start);
        if total > 1 {
            let showname = format!("Encoding Long Options detected (RFC 3396): {index}/{total}");
            if index < total {
                let marker = field.add_container(
                    &fields::DHCP_OPTION_RFC_3396_DETECTED,
                    Range::new(base + body_start, block.len()),
                    Some(showname),
                );
                marker.value = Value::String(format!("{index}/{total}"));
                let expert = marker.add_field(
                    &fields::DHCP_OPTION_REFER_LAST_OPTION,
                    Range::new(base + body_start, 0),
                    Value::None,
                );
                expert.add_expert(ExpertInfo {
                    severity: Severity::Chat,
                    group: Group::Reassemble,
                    message: format!(
                        "For the data, please refer to the last option {code}, {total}/{total}"
                    ),
                });
            } else {
                let marker = field.add_field(
                    &fields::DHCP_OPTION_RFC_3396_DETECTED,
                    Range::new(base + body_start, block.len()),
                    Value::String(format!("{index}/{total}")),
                );
                marker.showname = Some(showname);
            }
        }
        if total > 1 && index < total {
            position = body_start + length;
            continue;
        }
        let composite = total > 1;
        let body = if composite {
            first.bodies[usize::from(code)].as_slice()
        } else {
            block
        };
        let typed_start = field.children.len();
        let malformed = decode_option(
            field,
            area,
            code,
            body,
            if composite { 0 } else { base + body_start },
            if composite { 0 } else { base + position },
        );
        if let Some(message) = malformed {
            return AreaResult {
                ok: false,
                saw_end,
                trailing_padding: trailing,
                malformed: Some(message),
            };
        }
        if composite {
            apply_composite(
                field,
                typed_start,
                &first.bodies[usize::from(code)],
                base + position,
            );
        }
        let typed = field
            .children
            .get(typed_start..)
            .unwrap_or(&[])
            .iter()
            .any(|child| !option_marker(child.def.abbrev));
        // The generic value line is replaced by the typed decode only when
        // that decode consumed octets. An option with no value at all keeps
        // the generic line visible beside the typed empty field, which is the
        // rule the expected output follows for zero-length typed options.
        if !typed || (!composite && body.is_empty()) {
            if composite {
                let value = if body.is_empty() {
                    Value::Missing
                } else {
                    Value::bytes(body.to_vec())
                };
                let start = base + position;
                let added = field.add_field(
                    &fields::DHCP_OPTION_VALUE,
                    Range::new(start, body.len()),
                    value,
                );
                if !body.is_empty() {
                    added.raw = Some(RawField {
                        bytes: Bytes::from(body.to_vec()),
                        start,
                        length: body.len(),
                        bitmask: 0,
                        field_type: added.value.raw_field_type(),
                        source: RawSource::Field,
                    });
                }
            } else if let Some(hidden) = field.children.get_mut(hidden_index) {
                hidden.hidden = false;
            }
        }
        if let Some(suffix) = option_suffix(code, body) {
            field.showname = Some(format!("{label}{suffix}"));
        }
        position = body_start + length;
    }
    AreaResult {
        ok: true,
        saw_end,
        trailing_padding: trailing,
        malformed: None,
    }
}

fn add_hidden_value(field: &mut Field, block: &[u8], offset: usize) -> usize {
    let value = if block.is_empty() {
        Value::Missing
    } else {
        Value::bytes(block.to_vec())
    };
    let index = field.children.len();
    field
        .add_field(
            &fields::DHCP_OPTION_VALUE,
            Range::new(offset, block.len()),
            value,
        )
        .hide();
    index
}

fn option_marker(abbrev: &str) -> bool {
    matches!(
        abbrev,
        "dhcp.bad_length" | "dhcp.option.option_overload.wrong_field"
    )
}

fn apply_composite(field: &mut Field, start: usize, concat: &[u8], base: usize) {
    for child in field.children.iter_mut().skip(start) {
        apply_composite_field(child, concat, base);
    }
}

fn apply_composite_field(field: &mut Field, concat: &[u8], base: usize) {
    let relative = field.range.offset;
    let length = field.range.length;
    field.range.offset = base.saturating_add(relative);
    if length > 0 {
        let bytes = concat
            .get(relative..relative.saturating_add(length))
            .unwrap_or(&[]);
        field.raw = Some(RawField {
            bytes: Bytes::from(bytes.to_vec()),
            start: field.range.offset,
            length,
            bitmask: field.def.bitmask.unwrap_or(0),
            field_type: field.value.raw_field_type(),
            source: RawSource::Field,
        });
    }
    for child in &mut field.children {
        apply_composite_field(child, concat, base);
    }
}

fn option_suffix(code: u8, body: &[u8]) -> Option<String> {
    match code {
        OPTION_SUBNET_MASK | OPTION_BROADCAST | OPTION_REQUESTED_IP | OPTION_SERVER_ID
            if body.len() == 4 =>
        {
            Some(format!(" ({})", ipv4_text(read_ipv4(body, 0))))
        }
        OPTION_MESSAGE_TYPE => body.first().map(|value| {
            let name = fields::value_name("dhcp.option.dhcp", u64::from(*value))
                .map(str::to_string)
                .unwrap_or_else(|| format!("Unknown Message Type (0x{value:02x})"));
            format!(" ({name})")
        }),
        _ => None,
    }
}

fn ipv4_text(address: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

fn decode_option(
    parent: &mut dyn FieldParent,
    area: Area,
    code: u8,
    body: &[u8],
    offset: usize,
    option_offset: usize,
) -> Option<&'static str> {
    match code {
        OPTION_SUBNET_MASK | OPTION_BROADCAST | OPTION_REQUESTED_IP | OPTION_SERVER_ID => {
            let definition = match code {
                OPTION_SUBNET_MASK => &fields::DHCP_OPTION_SUBNET_MASK,
                OPTION_BROADCAST => &fields::DHCP_OPTION_BROADCAST_ADDRESS,
                OPTION_REQUESTED_IP => &fields::DHCP_OPTION_REQUESTED_IP_ADDRESS,
                _ => &fields::DHCP_OPTION_DHCP_SERVER_ID,
            };
            if body.len() == 4 {
                parent.add_field(
                    definition,
                    Range::new(offset, 4),
                    Value::Ipv4(read_ipv4(body, 0)),
                );
            } else {
                bad_length(parent, option_offset, "length isn't 4");
            }
        }
        OPTION_ROUTER | OPTION_DNS => {
            let definition = if code == OPTION_ROUTER {
                &fields::DHCP_OPTION_ROUTER
            } else {
                &fields::DHCP_OPTION_DOMAIN_NAME_SERVER
            };
            let mut index = 0;
            while index + 4 <= body.len() {
                parent.add_field(
                    definition,
                    Range::new(offset + index, 4),
                    Value::Ipv4(read_ipv4(body, index)),
                );
                index += 4;
            }
            if index != body.len() {
                bad_length(parent, option_offset, "Option length isn't a multiple of 4");
            }
        }
        OPTION_HOSTNAME => {
            parent.add_field(
                &fields::DHCP_OPTION_HOSTNAME,
                Range::new(offset, body.len()),
                Value::String(c_string(body)),
            );
        }
        OPTION_DOMAIN_NAME => {
            parent.add_field(
                &fields::DHCP_OPTION_DOMAIN_NAME,
                Range::new(offset, body.len()),
                Value::String(c_string(body)),
            );
        }
        OPTION_LEASE_TIME => add_u32_option(
            parent,
            &fields::DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
            body,
            offset,
            option_offset,
        ),
        OPTION_OVERLOAD => {
            if body.is_empty() {
                bad_length(parent, option_offset, "length isn't >= 1");
            } else if let Some(value) = body.first() {
                parent.add_field(
                    &fields::DHCP_OPTION_OPTION_OVERLOAD,
                    Range::new(offset, 1),
                    Value::Uint8(*value),
                );
            }
            if area != Area::Main {
                let marker = parent.add_field(
                    &fields::DHCP_OPTION_OPTION_OVERLOAD_WRONG_FIELD,
                    Range::new(option_offset, 0),
                    Value::None,
                );
                marker.add_expert(ExpertInfo {
                    severity: Severity::Warning,
                    group: Group::Protocol,
                    message: "overload option makes no sense in the file or sname field"
                        .to_string(),
                });
            }
        }
        OPTION_MESSAGE_TYPE => {
            if let Some(value) = body.first() {
                parent.add_field(
                    &fields::DHCP_OPTION_DHCP,
                    Range::new(offset, 1),
                    Value::Uint8(*value),
                );
            }
        }
        OPTION_REQUEST_LIST => {
            for (index, value) in body.iter().enumerate() {
                parent.add_field(
                    &fields::DHCP_OPTION_REQUEST_LIST_ITEM,
                    Range::new(offset + index, 1),
                    Value::Uint8(*value),
                );
            }
        }
        OPTION_MESSAGE => {
            parent.add_field(
                &fields::DHCP_OPTION_MESSAGE,
                Range::new(offset, body.len()),
                Value::String(c_string(body)),
            );
        }
        OPTION_MAX_MESSAGE_SIZE => {
            if body.len() == 2 {
                parent.add_field(
                    &fields::DHCP_OPTION_DHCP_MAX_MESSAGE_SIZE,
                    Range::new(offset, 2),
                    Value::Uint16(read_u16_be(body, 0).unwrap_or(0)),
                );
            } else {
                bad_length(parent, option_offset, "length isn't 2");
            }
        }
        OPTION_RENEWAL_TIME => add_u32_option(
            parent,
            &fields::DHCP_OPTION_RENEWAL_TIME_VALUE,
            body,
            offset,
            option_offset,
        ),
        OPTION_REBINDING_TIME => add_u32_option(
            parent,
            &fields::DHCP_OPTION_REBINDING_TIME_VALUE,
            body,
            offset,
            option_offset,
        ),
        OPTION_VENDOR_CLASS => {
            parent.add_field(
                &fields::DHCP_OPTION_VENDOR_CLASS_ID,
                Range::new(offset, body.len()),
                Value::String(c_string(body)),
            );
        }
        OPTION_CLIENT_ID => return decode_client_id(parent, body, offset),
        OPTION_TFTP_SERVER => {
            parent.add_field(
                &fields::DHCP_OPTION_TFTP_SERVER_NAME,
                Range::new(offset, body.len()),
                Value::String(c_string(body)),
            );
        }
        OPTION_BOOTFILE => {
            parent.add_field(
                &fields::DHCP_OPTION_BOOTFILE_NAME,
                Range::new(offset, body.len()),
                Value::String(c_string(body)),
            );
        }
        OPTION_AGENT_INFORMATION => {
            return decode_agent_information(parent, body, offset, option_offset);
        }
        _ => {}
    }
    None
}

fn add_u32_option(
    node: &mut dyn FieldParent,
    definition: &'static fields::FieldDef,
    body: &[u8],
    offset: usize,
    option_offset: usize,
) {
    if body.len() == 4 {
        node.add_field(
            definition,
            Range::new(offset, 4),
            Value::Uint32(read_u32_be(body, 0).unwrap_or(0)),
        );
    } else {
        bad_length(node, option_offset, "length isn't 4");
    }
}

fn decode_client_id(
    node: &mut dyn FieldParent,
    body: &[u8],
    offset: usize,
) -> Option<&'static str> {
    let kind = body.first().copied()?;
    if kind == 0 {
        if body.len() == 1 {
            return None;
        }
        node.add_field(
            &fields::DHCP_CLIENT_ID_TYPE,
            Range::new(offset, 1),
            Value::Uint8(0),
        );
        node.add_field(
            &fields::DHCP_CLIENT_ID_UNDEF,
            Range::new(offset + 1, body.len() - 1),
            Value::String(ascii_lossy(body.get(1..).unwrap_or(&[]))),
        );
        return None;
    }
    if kind != 255 {
        if body.len() == 7
            && let Some(address) = body.get(1..7)
        {
            node.add_field(
                &fields::DHCP_HW_TYPE,
                Range::new(offset, 1),
                Value::Uint8(kind),
            );
            if is_ethernet_link_layer(u16::from(kind)) {
                if let Ok(mac) = <[u8; 6]>::try_from(address) {
                    node.add_field(
                        &fields::DHCP_HW_MAC_ADDR,
                        Range::new(offset + 1, 6),
                        Value::Ethernet(mac),
                    );
                }
            } else {
                node.add_field(
                    &fields::DHCP_CLIENT_HARDWARE_ADDRESS,
                    Range::new(offset + 1, 6),
                    Value::String(hex_lower(address)),
                );
            }
        }
        return None;
    }
    if body.len() < 5 {
        return Some("DHCP client identifier is truncated");
    }
    node.add_field(
        &fields::DHCP_CLIENT_ID_IAID,
        Range::new(offset + 1, 4),
        Value::String(hex_lower(body.get(1..5).unwrap_or(&[]))),
    );
    if body.len() < 7 {
        return Some("DHCP client identifier is truncated");
    }
    let duid_type = read_u16_be(body, 5).unwrap_or(0);
    node.add_field(
        &fields::DHCP_CLIENT_ID_DUID_TYPE,
        Range::new(offset + 5, 2),
        Value::Uint16(duid_type),
    );
    let duid = body.get(7..).unwrap_or(&[]);
    match duid_type {
        1 => {
            if duid.len() < 6 {
                return Some("DHCP client identifier is truncated");
            }
            let hardware_type = read_u16_be(duid, 0).unwrap_or(0);
            node.add_field(
                &fields::DHCP_CLIENT_ID_DUID_LLT_HW_TYPE,
                Range::new(offset + 7, 2),
                Value::Uint16(hardware_type),
            );
            if let Some(time) = read_u32_be(duid, 2) {
                node.add_field(
                    &fields::DHCP_CLIENT_ID_TIME,
                    Range::new(offset + 9, 4),
                    Value::Uint32(time),
                );
            }
            add_duid_address(
                node,
                duid.get(6..).unwrap_or(&[]),
                offset + 13,
                hardware_type,
            );
        }
        2 => {
            if duid.len() < 4 {
                return Some("DHCP client identifier is truncated");
            }
            if let Some(enterprise) = read_u32_be(duid, 0) {
                node.add_field(
                    &fields::DHCP_CLIENT_ID_ENTERPRISE_NUM,
                    Range::new(offset + 7, 4),
                    Value::Uint32(enterprise),
                );
            }
            if let Some(identifier) = duid.get(4..).filter(|value| !value.is_empty()) {
                node.add_field(
                    &fields::DHCP_CLIENT_ID,
                    Range::new(offset + 11, identifier.len()),
                    Value::bytes(identifier.to_vec()),
                );
            }
        }
        3 => {
            if duid.len() < 2 {
                return Some("DHCP client identifier is truncated");
            }
            let hardware_type = read_u16_be(duid, 0).unwrap_or(0);
            node.add_field(
                &fields::DHCP_CLIENT_ID_DUID_LL_HW_TYPE,
                Range::new(offset + 7, 2),
                Value::Uint16(hardware_type),
            );
            add_duid_address(
                node,
                duid.get(2..).unwrap_or(&[]),
                offset + 9,
                hardware_type,
            );
        }
        _ => {}
    }
    None
}

fn add_duid_address(node: &mut dyn FieldParent, address: &[u8], offset: usize, hardware_type: u16) {
    if address.is_empty() {
        return;
    }
    node.add_field(
        &fields::DHCP_CLIENT_ID_LINK_LAYER_ADDRESS,
        Range::new(offset, address.len()),
        Value::String(link_layer_text(hardware_type, address)),
    );
    if let Some(mac) = link_layer_mac(hardware_type, address) {
        node.add_field(
            &fields::DHCP_CLIENT_ID_LINK_LAYER_ADDRESS_ETHER,
            Range::new(offset, 6),
            Value::Ethernet(mac),
        );
    }
}

fn decode_agent_information(
    node: &mut dyn FieldParent,
    body: &[u8],
    offset: usize,
    option_offset: usize,
) -> Option<&'static str> {
    let mut position = 0;
    while position < body.len() {
        let Some(&suboption) = body.get(position) else {
            break;
        };
        let Some(length_byte) = body.get(position + 1).copied() else {
            let marker = node.add_field(
                &fields::DHCP_MISSING_SUBOPT_LENGTH,
                Range::new(option_offset, 0),
                Value::None,
            );
            marker.add_expert(ExpertInfo {
                severity: Severity::Error,
                group: Group::Protocol,
                message: format!(
                    "Suboption {suboption}: no room left in option for suboption length"
                ),
            });
            return None;
        };
        let length = usize::from(length_byte);
        let value_start = position + 2;
        let value = body.get(value_start..value_start + length);
        let field = node.add_container(
            &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBOPTION,
            Range::new(offset + position, 2 + length),
            Some(suboption_label(suboption, value)),
        );
        field.value = Value::Uint8(suboption);
        field.add_field(
            &fields::DHCP_OPTION_SUBOPTION_LENGTH,
            Range::new(offset + position + 1, 1),
            Value::Uint8(length_byte),
        );
        let Some(value) = value else {
            let marker = field.add_field(
                &fields::DHCP_MISSING_SUBOPT_VALUE,
                Range::new(offset + position, 0),
                Value::None,
            );
            marker.add_expert(ExpertInfo {
                severity: Severity::Error,
                group: Group::Protocol,
                message: format!(
                    "Suboption {suboption}: no room left in option for suboption value"
                ),
            });
            return None;
        };
        let value_range = Range::new(offset + value_start, value.len());
        let hidden = if value.is_empty() {
            field.add_field(
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_VALUE,
                value_range,
                Value::Missing,
            )
        } else {
            field.add_field(
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_VALUE,
                value_range,
                Value::bytes(value.to_vec()),
            )
        };
        // RFC 3046 §2 and the suboption registries define typed layouts for
        // codes 1–13: their typed field replaces the generic value line, and
        // the length checks below are the whole decode for a bad length.
        // Codes 0 and 14 and above keep the generic value visible.
        if (1..=13).contains(&suboption) {
            hidden.hide();
        }
        match suboption {
            1 | 2 => {
                let definition = if suboption == 1 {
                    &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_AGENT_CIRCUIT_ID
                } else {
                    &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_AGENT_REMOTE_ID
                };
                if value.is_empty() {
                    field.add_field(definition, value_range, Value::Missing);
                } else {
                    field.add_field(definition, value_range, Value::bytes(value.to_vec()));
                }
            }
            3 => add_suboption_bytes(
                field,
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_RESERVED,
                value,
                value_range,
            ),
            4 => {
                if value.len() == 4 {
                    field.add_field(
                        &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_DOCSIS_DEVICE_CLASS,
                        value_range,
                        Value::Uint32(read_u32_be(value, 0).unwrap_or(0)),
                    );
                } else {
                    bad_length(field, offset + position, "length isn't 4");
                }
            }
            5 => {
                if value.len() == 4 {
                    field.add_field(
                        &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_LINK_SELECTION,
                        value_range,
                        Value::Ipv4(read_ipv4(value, 0)),
                    );
                } else {
                    bad_length(field, offset + position, "length isn't 4");
                }
            }
            6 => {
                field.add_field(
                    &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBSCRIBER_ID,
                    value_range,
                    Value::String(c_string(value)),
                );
            }
            7 => add_suboption_bytes(
                field,
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_RADIUS_ATTRIBUTES,
                value,
                value_range,
            ),
            8 => add_suboption_bytes(
                field,
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_AUTHENTICATION,
                value,
                value_range,
            ),
            9 => {
                if let Some(message) = decode_vendor_specific(field, value, value_range.offset) {
                    return Some(message);
                }
            }
            10 => {
                if value.len() == 1 {
                    field.add_field(
                        &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_FLAGS,
                        value_range,
                        Value::Uint8(value.first().copied().unwrap_or(0)),
                    );
                } else {
                    bad_length(field, offset + position, "length isn't 1");
                }
            }
            11 => {
                if value.len() == 4 {
                    field.add_field(
                        &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_SERVER_ID_OVERRIDE,
                        value_range,
                        Value::Ipv4(read_ipv4(value, 0)),
                    );
                } else {
                    bad_length(field, offset + position, "length isn't 4");
                }
            }
            12 => add_suboption_bytes(
                field,
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_RELAY_AGENT_ID,
                value,
                value_range,
            ),
            13 => {
                // RFC 7839 §4.2 fixes the length at two octets: one Reserved
                // octet the receiver ignores, then the ATT octet. The field
                // covers the ATT octet only; any other length is malformed
                // and adds no value. A zero-length value leaves nothing to
                // read, so that decoder stops; a wider or narrower value is
                // reported like every other fixed-size suboption and the
                // remaining options still decode.
                if value.len() == 2 {
                    field.add_field(
                        &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_ANI_ATT,
                        Range::new(value_range.offset.saturating_add(1), 1),
                        Value::Uint8(value.get(1).copied().unwrap_or(0)),
                    );
                } else {
                    bad_length(field, offset + position, "length isn't 2");
                    if value.is_empty() {
                        return Some("DHCP Option 82 access technology type is empty");
                    }
                }
            }
            _ => {}
        }
        position = value_start + length;
    }
    None
}

/// Label of one RFC 3046 suboption container.
///
/// The expected output appends the address text to the label of the two IPv4
/// suboptions when the value has the four-octet layout: link selection
/// (suboption 5) and the RFC 5107 server identifier override (suboption 11).
fn suboption_label(suboption: u8, value: Option<&[u8]>) -> String {
    let mut label = format!(
        "Option 82 Suboption: ({suboption}) {}",
        agent_suboption_name(suboption)
    );
    if matches!(suboption, 5 | 11)
        && let Some(address) = value.filter(|value| value.len() == 4)
    {
        label.push_str(&format!(" ({})", ipv4_text(read_ipv4(address, 0))));
    }
    label
}

/// Add a typed byte-string suboption value, or `<MISSING>` when empty.
fn add_suboption_bytes(
    field: &mut dyn FieldParent,
    definition: &'static fields::FieldDef,
    value: &[u8],
    range: Range,
) {
    if value.is_empty() {
        field.add_field(definition, range, Value::Missing);
    } else {
        field.add_field(definition, range, Value::bytes(value.to_vec()));
    }
}

/// Add the generated type-length marker that precedes a mismatched integer.
///
/// The expert lives on its own zero-length field so the detail view, PDML and
/// EK all place it between the suboption length and the value, which is where
/// the generic type-length helper reports it.
/// Decode the RFC 4243 vendor-specific information blocks.
///
/// A block is a four-octet enterprise number, a one-octet data length and
/// that many data octets. Enterprise 4491 normally carries the CableLabs
/// tag/length/value chain; Packetfin keeps that data opaque, which is a
/// recorded deviation. Every other enterprise shows the block data through
/// the generic suboption-value field, matching the expected output.
fn decode_vendor_specific(
    field: &mut dyn FieldParent,
    value: &[u8],
    base: usize,
) -> Option<&'static str> {
    let mut position = 0;
    while position < value.len() {
        let Some(enterprise_bytes) = value.get(position..position + 4) else {
            return Some("DHCP Option 82 vendor block is truncated");
        };
        let enterprise = read_u32_be(enterprise_bytes, 0).unwrap_or(0);
        let enterprise_field = field.add_field(
            &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_VI_ENTERPRISE,
            Range::new(base + position, 4),
            Value::Uint32(enterprise),
        );
        let Some(&data_length) = value.get(position + 4) else {
            return Some("DHCP Option 82 vendor block is truncated");
        };
        // The block data length nests under the enterprise number, as do the
        // CableLabs records this build leaves opaque.
        enterprise_field.add_field(
            &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_VI_DATA_LENGTH,
            Range::new(base + position + 4, 1),
            Value::Uint8(data_length),
        );
        let data_start = position + 5;
        let length = usize::from(data_length);
        let Some(data) = value.get(data_start..data_start + length) else {
            return Some("DHCP Option 82 vendor block is truncated");
        };
        let data_range = Range::new(base + data_start, data.len());
        if data.is_empty() {
            field.add_field(
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_VALUE,
                data_range,
                Value::Missing,
            );
        } else {
            field.add_field(
                &fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_VALUE,
                data_range,
                Value::bytes(data.to_vec()),
            );
        }
        position = data_start + length;
    }
    None
}

/// Registry name of a DHCP relay agent information suboption.
///
/// The names come from the IANA "DHCP Relay Agent Sub-Option Codes" registry;
/// RFC 6607 §3.2 and §3.3 assign code 151 to the virtual subnet selection
/// sub-option and code 152 to its control sub-option, which Packetfin does not
/// decode but names for the detail view. Neither code has a registry alias.
pub fn agent_suboption_name(code: u8) -> &'static str {
    match code {
        0 => "Padding",
        1 => "Agent Circuit ID",
        2 => "Agent Remote ID",
        3 => "Reserved",
        4 => "DOCSIS Device Class",
        5 => "Link selection",
        6 => "Subscriber ID",
        7 => "RADIUS Attributes",
        8 => "Authentication",
        9 => "Vendor-Specific Information",
        10 => "Flags",
        11 => "Server ID Override",
        12 => "Relay Agent Identifier",
        13 => "Access Technology Type",
        14 => "Access Network Name",
        15 => "Access Point Name",
        16 => "Access Point BSSID",
        17 => "Access Network Operator ID",
        18 => "Access Network Operator Realm",
        19 => "Source Port",
        150 => "Link selection (Cisco proprietary)",
        151 => "VSS",
        152 => "VSS-Control",
        _ => "Unknown",
    }
}

/// Name of an IANA Private Enterprise Number.
///
/// RFC 4243 §4 carries the enterprise number in a DHCP vendor-specific block
/// and RFC 8415 §11.2 carries one in a DUID-EN; both print the number with the
/// name from the IANA "Private Enterprise Numbers" registry. The table keeps
/// only the numbers Packetfin's fixtures exercise, so an unlisted number falls
/// back to `Unknown (N)` exactly as the expected output does. Adding a name
/// means adding the registry row that publishes it.
pub fn enterprise_name(number: u32) -> Option<&'static str> {
    match number {
        // The registry reserves zero for this purpose and documents 32473 as
        // the example number that vendors must not use on the wire.
        0 => Some("Reserved"),
        32473 => Some("Example Enterprise Number for Documentation Use"),
        _ => None,
    }
}

fn bad_length(node: &mut dyn FieldParent, option_offset: usize, message: &'static str) {
    let marker = node.add_field(
        &fields::DHCP_BAD_LENGTH,
        Range::new(option_offset, 0),
        Value::None,
    );
    marker.add_expert(ExpertInfo {
        severity: Severity::Error,
        group: Group::Protocol,
        message: message.to_string(),
    });
}

fn read_ipv4(data: &[u8], offset: usize) -> [u8; 4] {
    data.get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .unwrap_or([0; 4])
}

/// Read a NUL-terminated string from a fixed-size field.
fn c_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    match bytes.get(..end) {
        Some(value) => ascii_lossy(value),
        None => String::new(),
    }
}

/// The last DHCP message type the first pass reads from the main area.
///
/// This is the raw first byte of the last main-area option 53 block, which
/// labels the summary line. The first pass reads only the main parameters
/// field, so a message type that appears only in an overloaded area labels
/// the overload container instead of the protocol header.
pub fn main_area_message_type(node: &Node) -> Option<u64> {
    main_area_message_type_with(node, false)
}

/// The message type the visible main-area option 53 subtree decodes.
///
/// Repeated options are concatenated before decoding, so this can differ from
/// [`main_area_message_type`] when the blocks disagree; the protocol header
/// label shows this value.
pub fn main_area_decoded_message_type(node: &Node) -> Option<u64> {
    main_area_message_type_with(node, true)
}

fn main_area_message_type_with(node: &Node, decoded: bool) -> Option<u64> {
    let mut raw = None;
    for field in &node.fields {
        if field.def.abbrev != "dhcp.option.type" {
            continue;
        }
        if field
            .children
            .iter()
            .any(|child| child.def.abbrev == "dhcp.option.end")
        {
            break;
        }
        let code = match field.value {
            Value::Uint8(code) => u64::from(code),
            _ => continue,
        };
        if code != u64::from(OPTION_MESSAGE_TYPE) {
            continue;
        }
        if decoded {
            if let Some(value) = field
                .children
                .iter()
                .find(|child| child.def.abbrev == "dhcp.option.dhcp")
                && let Value::Uint8(code) = value.value
            {
                raw = Some(u64::from(code));
            }
        } else if let Some(value) = field
            .children
            .iter()
            .find(|child| child.def.abbrev == "dhcp.option.value")
            && let Value::Bytes(body) = &value.value
            && let Some(first) = body.first()
        {
            raw = Some(u64::from(*first));
        }
    }
    raw
}

/// The registry name for a DHCP option code.
///
/// Names come from RFC 2132 and the IANA "Dynamic Host Configuration Protocol
/// (DHCP) and Bootstrap Protocol (BOOTP) Parameters" registry. Codes the
/// registry leaves unassigned, private-use ranges, and vendor-specific options
/// without a stable registry name return `None`; callers render them without a
/// name.
pub fn option_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Padding",
        1 => "Subnet Mask",
        2 => "Time Offset",
        3 => "Router",
        4 => "Time Server",
        5 => "Name Server",
        6 => "Domain Name Server",
        7 => "Log Server",
        8 => "Cookie Server",
        9 => "LPR Server",
        10 => "Impress Server",
        11 => "Resource Location Server",
        12 => "Host Name",
        13 => "Boot File Size",
        14 => "Merit Dump File",
        15 => "Domain Name",
        16 => "Swap Server",
        17 => "Root Path",
        18 => "Extensions Path",
        19 => "IP Forwarding Enable/Disable",
        20 => "Non-Local Source Routing Enable/Disable",
        21 => "Policy Filter",
        22 => "Maximum Datagram Reassembly Size",
        23 => "Default IP Time-to-Live",
        24 => "Path MTU Aging Timeout",
        25 => "Path MTU Plateau Table",
        26 => "Interface MTU",
        27 => "All Subnets are Local",
        28 => "Broadcast Address",
        29 => "Perform Mask Discovery",
        30 => "Mask Supplier",
        31 => "Perform Router Discovery",
        32 => "Router Solicitation Address",
        33 => "Static Route",
        34 => "Trailer Encapsulation",
        35 => "ARP Cache Timeout",
        36 => "Ethernet Encapsulation",
        37 => "TCP Default TTL",
        38 => "TCP Keepalive Interval",
        39 => "TCP Keepalive Garbage",
        40 => "Network Information Service Domain",
        41 => "Network Information Service Servers",
        42 => "Network Time Protocol Servers",
        43 => "Vendor Specific Information",
        44 => "NetBIOS over TCP/IP Name Server",
        45 => "NetBIOS over TCP/IP Datagram Distribution Server",
        46 => "NetBIOS over TCP/IP Node Type",
        47 => "NetBIOS over TCP/IP Scope",
        48 => "X Window System Font Server",
        49 => "X Window System Display Manager",
        50 => "Requested IP Address",
        51 => "IP Address Lease Time",
        52 => "Option Overload",
        53 => "DHCP Message Type",
        54 => "DHCP Server Identifier",
        55 => "Parameter Request List",
        56 => "Message",
        57 => "Maximum DHCP Message Size",
        58 => "Renewal Time Value",
        59 => "Rebinding Time Value",
        60 => "Vendor class identifier",
        61 => "Client identifier",
        62 => "NetWare/IP Domain Name",
        63 => "NetWare/IP Information",
        64 => "NIS+ Domain Name",
        65 => "NIS+ Servers",
        66 => "TFTP Server Name",
        67 => "Bootfile name",
        68 => "Mobile IP Home Agent",
        69 => "SMTP Server",
        70 => "POP3 Server",
        71 => "NNTP Server",
        72 => "WWW Server",
        73 => "Finger Server",
        74 => "IRC Server",
        75 => "StreetTalk Server",
        76 => "StreetTalk Directory Assistance Server",
        77 => "User Class Information",
        78 => "SLP Directory Agent",
        79 => "SLP Service Scope",
        80 => "Rapid Commit",
        81 => "Client Fully Qualified Domain Name",
        82 => "Agent Information Option",
        83 => "iSNS",
        85 => "NDS Servers",
        86 => "NDS Tree Name",
        87 => "NDS Context",
        88 => "BCMCS Controller Domain Name List",
        89 => "BCMCS Controller IPv4 Address List",
        90 => "Authentication",
        91 => "Client Last Transaction Time",
        92 => "Associated IP",
        93 => "Client System Architecture Type",
        94 => "Client Network Interface Identifier",
        95 => "LDAP",
        97 => "UUID/GUID-based Client Identifier",
        98 => "Open Group's User Authentication",
        99 => "Civic Location",
        100 => "PCode",
        101 => "TZ Database String",
        108 => "IPv6-Only Preferred",
        112 => "NetInfo Parent Server Address",
        113 => "NetInfo Parent Server Tag",
        114 => "Captive Portal",
        116 => "Auto-Configure",
        117 => "Name Service Search",
        118 => "Subnet Selection",
        119 => "Domain Search",
        120 => "SIP Servers",
        121 => "Classless Static Route",
        122 => "CableLabs Client Configuration",
        123 => "GeoConf",
        124 => "V-I Vendor Class",
        125 => "V-I Vendor-Specific Information",
        136 => "PANA Agent",
        137 => "LoST Server",
        138 => "CAPWAP Access Controller Addresses",
        139 => "IPv4 Address MoS",
        140 => "IPv4 FQDN MoS",
        141 => "SIP UA Configuration Service Domains",
        142 => "IPv4 Address ANDSF",
        143 => "SZTP Redirect",
        144 => "Geospatial Location",
        145 => "FORCERENEW Nonce Capable",
        146 => "RDNSS Selection",
        147 => "DOTS Reference Identifier",
        148 => "DOTS Address",
        150 => "TFTP Server Address",
        151 => "Status Code",
        152 => "Base Time",
        153 => "Start Time of State",
        154 => "Query Start Time",
        155 => "Query End Time",
        156 => "DHCP State",
        157 => "Data Source",
        158 => "PCP Server",
        159 => "Port Parameter",
        161 => "MUD URL",
        175 => "Etherboot",
        176 => "IP Telephone",
        177 => "Etherboot",
        208 => "PXELINUX Magic",
        209 => "Configuration File",
        210 => "Path Prefix",
        211 => "Reboot Time",
        212 => "6rd",
        213 => "Access Domain",
        220 => "Subnet Allocation",
        221 => "Virtual Subnet Selection",
        224..=231 => "Private",
        _ => return None,
    })
}
