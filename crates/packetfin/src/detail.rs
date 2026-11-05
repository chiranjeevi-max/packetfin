//! Packet detail output for `-V` and `-O`.
//!
//! The frame pseudo-protocol block is synthesised from capture metadata; every
//! other line comes from the decoded tree. Display levels are modelled
//! explicitly: protocols in the packet scope stay at column zero, IPv6
//! extension headers indent under IPv6, and a quoted datagram adds one quote
//! level that all protocols inside the quote share.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{self, Write};

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::Packet;
use packetfin_core::fields::value_name;
use packetfin_core::names::service_name;
use packetfin_core::tree::{ExpertInfo, Field, Group, Node, Severity, Value};
use packetfin_core::{Display, FieldDef, FieldType, NameResolution as Resolution};

use crate::hexdump::{offset_width, write_rows};
use crate::record_buffer::RecordBuffer;
use crate::summary::ntp_status_text;

/// Parsed `-V`/`-O` detail options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DetailOptions {
    /// `-O` protocol list, or `None` for `-V`: expand every protocol.
    pub protocols: Option<Vec<String>>,
}

/// One protocol's position in the display tree.
#[derive(Clone, Copy)]
pub(crate) struct Scope {
    /// Indentation level, four spaces per level.
    pub(crate) level: usize,
    /// Whether `-O` can select this protocol independently.
    pub(crate) selectable: bool,
    /// Whether this node is inside a protocol subtree rather than the packet.
    pub(crate) nested: bool,
    /// Display level of the enclosing packet: zero at top level, the quote
    /// level inside a quoted datagram.
    pub(crate) packet_level: usize,
}

/// Renders the per-packet detail tree.
pub struct DetailWriter {
    expand_all: bool,
    protocols: HashSet<String>,
    first_timestamp: Option<Timestamp>,
    previous_captured: Option<Timestamp>,
    previous_displayed: Option<Timestamp>,
    separator: Vec<u8>,
    hexdump_active: bool,
    link_type: u32,
    frame_offset_width: usize,
    text: RecordBuffer,
    resolution: Resolution,
}

impl DetailWriter {
    /// Create a writer for the selected protocols.
    pub fn new(options: &DetailOptions, separator: &[u8], hexdump_active: bool) -> Self {
        let (expand_all, protocols) = match &options.protocols {
            Some(names) => (false, names.iter().cloned().collect()),
            None => (true, HashSet::new()),
        };
        Self {
            expand_all,
            protocols,
            first_timestamp: None,
            previous_captured: None,
            previous_displayed: None,
            separator: separator.to_vec(),
            hexdump_active,
            link_type: 0,
            frame_offset_width: 4,
            text: RecordBuffer::new(),
            resolution: Resolution::default(),
        }
    }

    /// Record a frame that a display filter hides.
    ///
    /// Relative and delta times are measured from every captured
    /// frame, so hidden frames still advance the captured-frame state.
    pub fn observe_hidden(&mut self, frame: &Frame) {
        if let Some(timestamp) = frame.timestamp {
            self.first_timestamp.get_or_insert(timestamp);
            self.previous_captured = Some(timestamp);
        }
    }

    /// Render one displayed packet and its trailing blank line.
    pub fn write_packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
    ) -> io::Result<()> {
        self.text.clear();
        self.link_type = frame.link_type;
        self.resolution = packet.resolution;
        self.frame_offset_width = offset_width(frame.captured.len());
        let frame_expanded = self.expand_all || self.protocols.contains("frame");
        self.write_frame_block(frame, packet, frame_expanded);
        if is_raw_link(frame.link_type) {
            self.text.push_str("Raw packet data\n");
        }
        for child in &packet.tree.frame.children {
            self.write_protocol(
                child,
                Scope {
                    level: 0,
                    selectable: true,
                    nested: false,
                    packet_level: 0,
                },
                false,
            );
        }
        if let Some(length) = root_data_length(packet) {
            self.write_line(
                0,
                &format!(
                    "Data ({length} {})",
                    if length == 1 { "byte" } else { "bytes" }
                ),
            );
        }
        self.text.emit(writer)?;
        writer.write_all(&self.separator)?;
        writer.write_all(b"\n")
    }

    fn selected(&self, node: &Node) -> bool {
        self.protocols.contains(node.protocol.filter_name)
    }

    fn write_line(&mut self, depth: usize, body: &str) {
        for _ in 0..depth {
            self.text.push_str("    ");
        }
        self.text.push_str(body);
        self.text.push('\n');
    }

    fn write_frame_block(&mut self, frame: &Frame, packet: &Packet, expanded: bool) {
        let comments_expanded = self.expand_all || self.protocols.contains("pkt_comment");
        if !frame.comments.is_empty() {
            self.text.push_str("Packet comments\n");
            if comments_expanded {
                for comment in &frame.comments {
                    self.write_comment(comment);
                }
            }
        }
        let bits = u64::from(frame.original_len) * 8;
        let captured = frame.captured.len();
        let captured_bits = captured as u64 * 8;
        let _ = write!(
            self.text,
            "Frame {}: Packet, {} bytes on wire ({} bits), {} bytes captured ({} bits)",
            frame.number, frame.original_len, bits, captured, captured_bits
        );
        let escaped_name = frame.interface_name.as_deref().map(escape_capture_string);
        if frame.section_number.is_some() {
            let name = escaped_name.as_deref().unwrap_or("unknown");
            let _ = write!(self.text, " on interface {name}, id {}", frame.interface_id);
        }
        self.text.push('\n');
        if !expanded {
            return;
        }

        if let Some(section) = frame.section_number {
            self.write_line(1, &format!("Section number: {section}"));
            let name = escaped_name.as_deref().unwrap_or("unknown");
            self.write_line(1, &format!("Interface id: {} ({name})", frame.interface_id));
            self.write_line(2, &format!("Interface name: {name}"));
        }
        let (encapsulation, number) = encapsulation(frame.link_type);
        self.write_line(
            1,
            &format!("Encapsulation type: {encapsulation} ({number})"),
        );

        if let Some(timestamp) = frame.timestamp {
            self.write_line(1, &format!("Arrival Time: {}", absolute_time(timestamp)));
            self.write_line(
                1,
                &format!("UTC Arrival Time: {}", absolute_time(timestamp)),
            );
            self.write_line(1, &format!("Epoch Arrival Time: {}", epoch_time(timestamp)));
            self.write_line(1, "[Time shift for this packet: 0.000000000 seconds]");
            if let Some(previous) = self.previous_captured {
                self.write_line(
                    1,
                    &format!(
                        "[Time delta from previous captured frame: {}]",
                        delta(previous, timestamp)
                    ),
                );
            }
            if let Some(previous) = self.previous_displayed {
                self.write_line(
                    1,
                    &format!(
                        "[Time delta from previous displayed frame: {}]",
                        delta(previous, timestamp)
                    ),
                );
            }
            let first = *self.first_timestamp.get_or_insert(timestamp);
            self.write_line(
                1,
                &format!(
                    "[Time since reference or first frame: {}]",
                    delta(first, timestamp)
                ),
            );
            self.previous_captured = Some(timestamp);
            self.previous_displayed = Some(timestamp);
        }

        self.write_line(1, &format!("Frame Number: {}", frame.number));
        self.write_line(
            1,
            &format!("Frame Length: {} bytes ({} bits)", frame.original_len, bits),
        );
        self.write_line(
            1,
            &format!("Capture Length: {captured} bytes ({captured_bits} bits)"),
        );
        self.write_line(1, "[Frame is marked: False]");
        self.write_line(1, "[Frame is ignored: False]");
        self.write_line(
            1,
            &format!(
                "[Protocols in frame: {}]",
                protocols_in_frame(packet, frame)
            ),
        );
        self.write_line(1, "Character encoding: ASCII (0)");
    }

    /// Render one `pkt_comment` body.
    ///
    /// A comment with line breaks prints its first line with a ` [...]`
    /// marker, then every line, including the first, indented two levels.
    fn write_comment(&mut self, comment: &str) {
        let mut lines = comment.split('\n');
        let first = lines.next().unwrap_or_default();
        if lines.clone().next().is_none() {
            let mut text = String::with_capacity(first.len());
            write_escaped(&mut text, first);
            self.write_line(1, &text);
            return;
        }
        let mut text = String::with_capacity(first.len() + 6);
        write_escaped(&mut text, first);
        text.push_str(" [...]");
        self.write_line(1, &text);
        for line in comment.split('\n') {
            let mut text = String::with_capacity(line.len());
            write_escaped(&mut text, line);
            self.write_line(2, &text);
        }
    }

    /// Render one protocol node and its selectable descendants.
    fn write_protocol(&mut self, node: &Node, scope: Scope, owner_expanded: bool) {
        let expanded = if scope.selectable {
            self.expand_all || self.selected(node)
        } else {
            owner_expanded
        };
        let visible = scope.selectable || owner_expanded;
        let malformed = malformed_expert(node);

        let malformed_only = node.fields.is_empty() && node.children.is_empty();
        let replaced_header = visible && malformed_only && malformed.is_some();
        if visible {
            if replaced_header {
                self.write_malformed_line(node);
            } else {
                let header = protocol_header(node, self.link_type, self.resolution);
                self.write_line(scope.level, &header);
                if expanded {
                    self.write_fields(node, scope.level + 1);
                    let has_checksum = node
                        .fields
                        .iter()
                        .any(|field| field.def.abbrev.ends_with(".checksum"));
                    for expert in &node.experts {
                        if expert.group == Group::Protocol
                            && !(has_checksum && expert.message.contains("checksum"))
                        {
                            self.write_expert(expert, scope.level + 1);
                        }
                    }
                }
            }
        }
        if visible && !expanded {
            // A packet-scope helper node still prints its container
            // label when its owner is collapsed by `-O`.
            for field in &node.fields {
                if field.packet_scoped() {
                    self.write_container(node, field, scope.level + 1, false);
                }
            }
        }
        if let Some(expert) = malformed {
            // A visible malformed-only node replaced its header; otherwise the
            // line follows the header/fields (or a hidden nested subtree).
            if !replaced_header {
                self.write_malformed_line(node);
            }
            // `-O` expansion never prints the expert block; only `-V` does.
            if expanded && self.expand_all && (visible || scope.nested) {
                let message = if expert.group == Group::Malformed
                    && (expert.message.contains("truncated")
                        || expert.message.contains("is empty")
                        || expert.message.contains("shorter than"))
                {
                    "Malformed Packet (Exception occurred)"
                } else {
                    &expert.message
                };
                self.write_expert_message(expert.severity, expert.group, message, 1);
            }
        }

        for child in &node.children {
            let child_scope = child_scope(node, child, scope);
            self.write_protocol(child, child_scope, expanded);
        }
        if expanded {
            for field in node
                .fields
                .iter()
                .filter(|field| trailing_after_children(field))
            {
                self.write_field(node, field, scope.level + 1);
            }
        }
    }

    /// Render every field of an expanded protocol, folding checksum status,
    /// calculated values and experts into the checksum line.
    fn write_fields(&mut self, node: &Node, depth: usize) {
        for field in node.display_fields() {
            if trailing_after_children(field) {
                continue;
            }
            self.write_field(node, field, depth);
        }
        self.write_data_subtree(node, depth);
    }

    /// Render one field occurrence. Containers print their own label and
    /// recurse; leaves keep the flat-field rendering used before containers
    /// existed.
    fn write_field(&mut self, node: &Node, field: &Field, depth: usize) {
        if field.hidden
            || hidden(field.def.abbrev)
            || packetfin_core::expert_label_only(field.def.abbrev)
        {
            return;
        }
        if field.is_container() {
            let expand_children = !field.packet_scoped() || self.expand_all;
            self.write_container(node, field, depth, expand_children);
            return;
        }
        if !field.experts.is_empty() && matches!(field.value, Value::None | Value::Missing) {
            for expert in &field.experts {
                self.write_expert(expert, depth);
            }
            return;
        }
        self.write_leaf(node, field, depth);
        for expert in &field.experts {
            self.write_expert(expert, depth + 1);
        }
    }

    fn write_leaf(&mut self, node: &Node, field: &Field, depth: usize) {
        if handled_with_checksum(node, field) {
            return;
        }
        if checksum_protocol(field.def.abbrev).is_some() {
            self.write_checksum(node, field, depth);
            return;
        }
        if field.def.abbrev == "dhcpv6.status_msg"
            && matches!(&field.value, Value::String(text) if text.is_empty())
        {
            return;
        }
        let mut body = String::with_capacity(48);
        if field.generated {
            body.push('[');
        }
        if let Some(showname) = field.showname_text() {
            body.push_str(&showname);
        } else if let Some(text) = special_showname(node, field, self.resolution) {
            body.push_str(&text);
        } else if let Value::Bytes(bytes) = &field.value {
            let mut prefix = String::with_capacity(field.def.name.len() + 8);
            if field.generated {
                prefix.push('[');
            }
            prefix.push_str(field.def.name);
            prefix.push_str(": ");
            self.write_bytes_line(
                depth,
                &prefix,
                bytes,
                if field.generated { "]" } else { "" },
            );
            return;
        } else {
            body.push_str(field.def.name);
            body.push_str(": ");
            write_value(&mut body, field);
        }
        if field.generated {
            body.push(']');
        }
        self.write_line(depth, &body);
    }

    /// Write one line whose value is a byte string, streaming its hex.
    fn write_bytes_line(&mut self, depth: usize, prefix: &str, bytes: &[u8], suffix: &str) {
        for _ in 0..depth {
            self.text.push_str("    ");
        }
        self.text.push_str(prefix);
        self.text.write_hex(bytes, false);
        self.text.push_str(suffix);
        self.text.push('\n');
    }

    /// Render a container label and its children. A packet-scoped container
    /// such as `tcp.segments` starts at column zero even when its owning
    /// protocol is indented; every other container follows the field depth.
    fn write_container(&mut self, node: &Node, field: &Field, depth: usize, expand_children: bool) {
        let container_depth = if field.packet_scoped() { 0 } else { depth };
        let child_depth = container_depth + 1;
        let mut body = String::with_capacity(96);
        if field.generated {
            body.push('[');
        }
        match &field.showname {
            Some(showname) => body.push_str(showname),
            None if matches!(field.value, Value::None | Value::Missing) => {
                body.push_str(field.def.name);
            }
            None => {
                body.push_str(field.def.name);
                body.push_str(": ");
                write_value(&mut body, field);
            }
        }
        if field.generated {
            body.push(']');
        }
        self.write_line(container_depth, &body);
        if !expand_children {
            return;
        }
        for child in &field.children {
            self.write_field(node, child, child_depth);
        }
        for child in &field.nodes {
            self.write_protocol(
                child,
                Scope {
                    level: child_depth,
                    selectable: true,
                    nested: true,
                    packet_level: 0,
                },
                true,
            );
        }
        for expert in &field.experts {
            self.write_expert(expert, child_depth);
        }
    }

    /// The nested `Data (n bytes)` subtree for undecoded payload.
    fn write_data_subtree(&mut self, node: &Node, depth: usize) {
        let Some(bytes) = node.fields.iter().find_map(|field| {
            if matches!(field.def.abbrev, "icmp.data" | "icmpv6.data") {
                match &field.value {
                    Value::Bytes(bytes) if !bytes.is_empty() => Some(bytes.as_slice()),
                    _ => None,
                }
            } else {
                None
            }
        }) else {
            return;
        };
        self.write_line(
            depth,
            &format!(
                "Data ({} {})",
                bytes.len(),
                if bytes.len() == 1 { "byte" } else { "bytes" }
            ),
        );
        if !self.hexdump_active {
            self.text.push('\n');
            write_rows(
                &mut self.text,
                bytes,
                offset_width(bytes.len()),
                true,
                false,
            );
        }
        let mut hex = String::with_capacity(bytes.len() * 2 + 7);
        hex.push_str("Data: ");
        for byte in bytes {
            let _ = write!(hex, "{byte:02x}");
        }
        self.write_line(depth + 1, &hex);
        self.write_line(depth + 1, &format!("[Length: {}]", bytes.len()));
    }

    fn write_checksum(&mut self, node: &Node, field: &Field, depth: usize) {
        let abrv = field.def.abbrev;
        let Some((status_abbrev, calculated_abbrev, family)) = checksum_protocol(abrv) else {
            return;
        };
        let status = field_u64(node, status_abbrev);
        let calculated = field_u64(node, calculated_abbrev);
        let mut body = String::with_capacity(64);
        if family == ChecksumFamily::Other
            && let Some(showname) = field.showname_text()
        {
            body.push_str(&showname);
        } else {
            body.push_str(field.def.name);
            body.push_str(": ");
            write_value(&mut body, field);
            if let Some(suffix) = checksum_suffix(node, field) {
                body.push_str(&suffix);
            }
        }
        self.write_line(depth, &body);

        if let Some(expert) = node
            .experts
            .iter()
            .find(|expert| expert.group == Group::Checksum)
            .or_else(|| {
                (abrv == "gre.checksum")
                    .then(|| {
                        node.experts
                            .iter()
                            .find(|expert| expert.group == Group::Protocol)
                    })
                    .flatten()
            })
        {
            self.write_expert(expert, depth + 1);
        }
        let Some(status) = status else {
            return;
        };
        let calculated_text =
            calculated.map(|value| format!("[Calculated Checksum: 0x{value:04x}]"));
        match status {
            0 => {
                if family == ChecksumFamily::Ip {
                    self.write_status(node, status_abbrev, status, depth);
                    if let Some(text) = calculated_text {
                        self.write_line(depth, &text);
                    }
                } else {
                    if matches!(family, ChecksumFamily::Udp | ChecksumFamily::Tcp)
                        && let Some(text) = calculated_text
                    {
                        self.write_line(depth + 1, &text);
                    }
                    self.write_status(node, status_abbrev, status, depth);
                }
            }
            1 => {
                if family == ChecksumFamily::Ip {
                    self.write_status(node, status_abbrev, status, depth);
                    if let Some(text) = calculated_text {
                        self.write_line(depth, &text);
                    }
                } else {
                    if matches!(family, ChecksumFamily::Udp | ChecksumFamily::Tcp)
                        && let Some(text) = calculated_text
                    {
                        self.write_line(depth + 1, &text);
                    }
                    self.write_status(node, status_abbrev, status, depth);
                }
            }
            3 | 4 => self.write_status(node, status_abbrev, status, depth + 1),
            _ => self.write_status(node, status_abbrev, status, depth),
        }
    }

    fn write_status(&mut self, node: &Node, abbrev: &str, status: u64, depth: usize) {
        let name = node
            .fields
            .iter()
            .find(|field| field.def.abbrev == abbrev)
            .map(|field| field.def.name)
            .unwrap_or("Checksum Status");
        let value = match value_name(abbrev, status) {
            Some(value) => value.to_string(),
            None => status.to_string(),
        };
        self.write_line(depth, &format!("[{name}: {value}]"));
    }

    fn write_malformed_line(&mut self, node: &Node) {
        self.text.push_str("[Malformed Packet: ");
        self.text.push_str(node.protocol.short_name);
        self.text.push_str("]\n");
    }

    fn write_expert(&mut self, expert: &ExpertInfo, depth: usize) {
        self.write_expert_message(expert.severity, expert.group, &expert.message, depth);
    }

    fn write_expert_message(
        &mut self,
        severity: Severity,
        group: Group,
        message: &str,
        depth: usize,
    ) {
        self.write_line(
            depth,
            &format!(
                "[Expert Info ({}/{}): {message}]",
                severity_name(severity),
                group_name(group)
            ),
        );
        self.write_line(depth + 1, &format!("[{message}]"));
        self.write_line(
            depth + 1,
            &format!("[Severity level: {}]", severity_name(severity)),
        );
        self.write_line(depth + 1, &format!("[Group: {}]", group_name(group)));
    }
}

/// The encapsulation name and number shown for a link type.
pub(crate) fn encapsulation(link_type: u32) -> (&'static str, u32) {
    match link_type {
        0 => ("NULL/Loopback", 15),
        1 => ("Ethernet", 1),
        12 | 14 | 101 => ("Raw IP", 7),
        108 => ("OpenBSD loopback", 174),
        228 => ("Raw IPv4", 129),
        229 => ("Raw IPv6", 130),
        113 => ("Linux cooked-mode capture v1", 25),
        276 => ("Linux cooked-mode capture v2", 210),
        other => ("Unknown", other),
    }
}

fn is_raw_link(link_type: u32) -> bool {
    matches!(link_type, 12 | 14 | 101 | 228 | 229)
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Comment => "Comment",
        Severity::Chat => "Chat",
        Severity::Note => "Note",
        Severity::Warning => "Warning",
        Severity::Error => "Error",
    }
}

fn group_name(group: Group) -> &'static str {
    match group {
        Group::Comment => "Comment",
        Group::Malformed => "Malformed",
        Group::Checksum => "Checksum",
        Group::Sequence => "Sequence",
        Group::Protocol => "Protocol",
        Group::Deprecated => "Deprecated",
        Group::Response => "Response",
        Group::Request => "Request",
        Group::Undecoded => "Undecoded",
        Group::Reassemble => "Reassemble",
    }
}

/// The protocol scope of a child node.
pub(crate) fn child_scope(parent: &Node, child: &Node, scope: Scope) -> Scope {
    let child_name = child.protocol.filter_name;
    let parent_name = parent.protocol.filter_name;
    if scope.nested {
        // Inside a quote or protocol subtree.
        if is_extension(parent_name) && is_extension(child_name) {
            return Scope {
                level: scope.level,
                selectable: false,
                nested: true,
                packet_level: scope.packet_level,
            };
        }
        if is_quote(parent_name) {
            let level = scope.level + 1;
            return Scope {
                level,
                selectable: false,
                nested: true,
                packet_level: level,
            };
        }
        if is_extension(parent_name) {
            // The next-header dissector returns to the enclosing packet. In a
            // quote that is the quote level and stays non-selectable; only a
            // top-level chain becomes packet scope again.
            return Scope {
                level: scope.packet_level,
                selectable: scope.packet_level == 0,
                nested: scope.packet_level != 0,
                packet_level: scope.packet_level,
            };
        }
        if parent_name == "ipv6" && is_extension(child_name) {
            return Scope {
                level: scope.level + 1,
                selectable: false,
                nested: true,
                packet_level: scope.packet_level,
            };
        }
        return Scope {
            level: scope.level,
            selectable: false,
            nested: true,
            packet_level: scope.packet_level,
        };
    }
    if parent_name == "ipv6" && is_extension(child_name) {
        return Scope {
            level: scope.level + 1,
            selectable: false,
            nested: true,
            packet_level: scope.level,
        };
    }
    if is_quote(parent_name) {
        let level = scope.level + 1;
        return Scope {
            level,
            selectable: false,
            nested: true,
            packet_level: level,
        };
    }
    Scope {
        level: 0,
        selectable: true,
        nested: false,
        packet_level: 0,
    }
}

pub(crate) fn is_extension(name: &str) -> bool {
    matches!(
        name,
        "ipv6.hopopts" | "ipv6.dstopts" | "ipv6.routing" | "ipv6.fraghdr"
    )
}

fn is_quote(name: &str) -> bool {
    matches!(name, "icmp" | "icmpv6")
}

fn malformed_expert(node: &Node) -> Option<&ExpertInfo> {
    if !node.protocol_exception {
        return None;
    }
    node.experts
        .iter()
        .find(|expert| expert.group == Group::Malformed)
}

/// Whether a field prints after the protocol's child subtrees.
fn trailing_after_children(field: &Field) -> bool {
    field.def.abbrev == "ipv6.reassembled.in"
}

/// Fields kept out of the detail view.
pub(crate) fn hidden(abbrev: &str) -> bool {
    matches!(
        abbrev,
        "eth.addr"
            | "ipv6.addr"
            | "eth.src_resolved"
            | "eth.dst_resolved"
            | "eth.src.oui_resolved"
            | "eth.dst.oui_resolved"
            | "ip.src_host"
            | "ip.dst_host"
            | "ipv6.src_host"
            | "ipv6.dst_host"
            | "udp.port"
            | "tcp.port"
            | "frame.time_delta"
            | "frame.time_relative"
            | "icmp.checksum_calculated"
            | "icmpv6.checksum_calculated"
            | "dhcp.bootp"
            | "dhcp.secs_le"
            | "icmp.data"
            | "icmpv6.data"
            | "gre.checksum.incorrect"
            | "erspan.version.unknown"
            | "geneve.version.unknown"
            | "geneve.option.length.invalid"
            | "dns.retransmit_request"
            | "dns.retransmit_response"
            | "dns.response_missing"
            | "http.request"
            | "http.response"
            | "http.request.line"
            | "http.response.line"
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChecksumFamily {
    Ip,
    Udp,
    Tcp,
    Icmp,
    Icmpv6,
    Gre,
    Other,
}

/// The status and calculated abbreviations of one checksum field.
fn checksum_protocol(abbrev: &str) -> Option<(&'static str, &'static str, ChecksumFamily)> {
    Some(match abbrev {
        "ip.checksum" => (
            "ip.checksum.status",
            "ip.checksum_calculated",
            ChecksumFamily::Ip,
        ),
        "gre.checksum" => (
            "gre.checksum.status",
            "gre.checksum_calculated",
            ChecksumFamily::Gre,
        ),
        "udp.checksum" => (
            "udp.checksum.status",
            "udp.checksum_calculated",
            ChecksumFamily::Udp,
        ),
        "tcp.checksum" => (
            "tcp.checksum.status",
            "tcp.checksum_calculated",
            ChecksumFamily::Tcp,
        ),
        "icmp.checksum" => (
            "icmp.checksum.status",
            "icmp.checksum_calculated",
            ChecksumFamily::Icmp,
        ),
        "icmpv6.checksum" => (
            "icmpv6.checksum.status",
            "icmpv6.checksum_calculated",
            ChecksumFamily::Icmpv6,
        ),
        "vrrp.checksum" => ("vrrp.checksum.status", "", ChecksumFamily::Other),
        _ => return None,
    })
}

/// The status text appended to a checksum field's display name.
///
/// This is shared by the detail view and PDML so both render the same
/// `[correct]`, `[validation disabled]` and bad-checksum wording.
pub(crate) fn checksum_suffix(node: &Node, field: &Field) -> Option<String> {
    let (status_abbrev, calculated_abbrev, family) = checksum_protocol(field.def.abbrev)?;
    let status = field_u64(node, status_abbrev)?;
    let calculated = field_u64(node, calculated_abbrev);
    let mut suffix = String::new();
    match status {
        0 => {
            if let Some(expected) = calculated {
                let _ = write!(suffix, " incorrect, should be 0x{expected:04x}");
                if family == ChecksumFamily::Ip {
                    suffix.push_str("(may be caused by \"IP checksum offload\"?)");
                } else if family == ChecksumFamily::Udp {
                    suffix.push_str(" (maybe caused by \"UDP checksum offload\"?)");
                } else if family == ChecksumFamily::Tcp {
                    suffix.push_str("(maybe caused by \"TCP checksum offload\"?)");
                }
            }
        }
        1 => suffix.push_str(" [correct]"),
        _ if family == ChecksumFamily::Ip => suffix.push_str(" [validation disabled]"),
        3 => suffix.push_str(" [zero-value ignored]"),
        4 => suffix.push_str(" [zero-value illegal]"),
        _ => suffix.push_str(" [unverified]"),
    }
    Some(suffix)
}

fn handled_with_checksum(node: &Node, field: &Field) -> bool {
    let abbrev = field.def.abbrev;
    if !(abbrev.ends_with(".checksum.status") || abbrev.ends_with(".checksum_calculated")) {
        return false;
    }
    node.fields.iter().any(|candidate| {
        checksum_protocol(candidate.def.abbrev)
            .is_some_and(|(status, calculated, _)| abbrev == status || abbrev == calculated)
    })
}

pub(crate) fn field_u64(node: &Node, abbrev: &str) -> Option<u64> {
    node.fields
        .iter()
        .find(|field| field.def.abbrev == abbrev)
        .and_then(|field| match &field.value {
            Value::Uint8(value) => Some(u64::from(*value)),
            Value::Uint16(value) => Some(u64::from(*value)),
            Value::Uint24(value) => Some(u64::from(*value)),
            Value::Uint32(value) => Some(u64::from(*value)),
            Value::Uint64(value) => Some(*value),
            Value::Boolean(value) => Some(u64::from(*value)),
            _ => None,
        })
}

fn field_text(node: &Node, abbrev: &str) -> Option<String> {
    let field = node
        .fields
        .iter()
        .find(|field| field.def.abbrev == abbrev)?;
    Some(field.value.render(Display::None))
}

/// Count field occurrences with `abbrev` in the node's field subtrees.
fn count_fields(node: &Node, abbrev: &str) -> usize {
    let mut count = 0_usize;
    for field in &node.fields {
        field.for_each_in_subtree(&mut |candidate| {
            if candidate.def.abbrev == abbrev {
                count = count.saturating_add(1);
            }
        });
    }
    count
}

/// An Ethernet address rendered the way the protocol header shows it.
///
/// With MAC resolution on, a known OUI contributes `label (raw)` and an
/// unknown one stays `raw (raw)`; with it off only the raw address prints.
fn ethernet_address_text(node: &Node, abbrev: &str, resolution: Resolution) -> Option<String> {
    let raw = field_text(node, abbrev)?;
    if !resolution.mac {
        return Some(raw);
    }
    let resolved = field_text(node, &format!("{abbrev}_resolved")).unwrap_or_else(|| raw.clone());
    if resolved == raw {
        Some(format!("{raw} ({raw})"))
    } else {
        Some(format!("{} ({raw})", escape_text(&resolved)))
    }
}

/// An IP address rendered the way the protocol header shows it.
fn host_text(
    node: &Node,
    raw_abbrev: &str,
    host_abbrev: &str,
    resolution: Resolution,
) -> Option<String> {
    let raw = field_text(node, raw_abbrev)?;
    if !resolution.network {
        return Some(raw);
    }
    let host = field_text(node, host_abbrev).unwrap_or_else(|| raw.clone());
    if host == raw {
        Some(format!("{raw} ({raw})"))
    } else {
        Some(format!("{} ({raw})", escape_text(&host)))
    }
}

/// A transport port with its service name when transport resolution is on.
fn port_value_text(port: u64, tcp: bool, resolution: Resolution) -> String {
    if resolution.transport
        && let Ok(port) = u16::try_from(port)
        && let Some(name) = service_name(port, tcp)
    {
        return format!("{} ({port})", escape_text(name));
    }
    port.to_string()
}

fn escape_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    write_escaped(&mut escaped, text);
    escaped
}

/// Count field occurrences with `abbrev` in the node's field subtrees.
pub(crate) fn protocol_header(node: &Node, link_type: u32, resolution: Resolution) -> String {
    match node.protocol.filter_name {
        "eth" => {
            if node
                .fields
                .iter()
                .any(|field| field.def.abbrev == "eth.len")
            {
                "IEEE 802.3 Ethernet ".to_string()
            } else if invalid_length_type(node) {
                let mut text = "Ethernet Unknown".to_string();
                if let Some(src) = ethernet_address_text(node, "eth.src", resolution) {
                    let _ = write!(text, ", Src: {src}");
                }
                if let Some(dst) = ethernet_address_text(node, "eth.dst", resolution) {
                    let _ = write!(text, ", Dst: {dst}");
                }
                text
            } else {
                let mut text = "Ethernet II".to_string();
                if let Some(src) = ethernet_address_text(node, "eth.src", resolution) {
                    let _ = write!(text, ", Src: {src}");
                }
                if let Some(dst) = ethernet_address_text(node, "eth.dst", resolution) {
                    let _ = write!(text, ", Dst: {dst}");
                }
                text
            }
        }
        "llc" => "Logical-Link Control".to_string(),
        "vlan" => format!(
            "802.1Q Virtual LAN, PRI: {}, DEI: {}, ID: {}",
            field_u64(node, "vlan.priority").unwrap_or(0),
            field_u64(node, "vlan.dei").unwrap_or(0),
            field_u64(node, "vlan.id").unwrap_or(0)
        ),
        "ieee8021ad" => match (
            field_u64(node, "ieee8021ad.svid"),
            field_u64(node, "ieee8021ad.cvid"),
        ) {
            (Some(svid), Some(cvid)) => format!("IEEE 802.1ad, S-VID: {svid}, C-VID: {cvid}"),
            _ => match field_u64(node, "ieee8021ad.id") {
                Some(id) => format!("IEEE 802.1ad, ID: {id}"),
                None => "IEEE 802.1ad".to_string(),
            },
        },
        "sll" => {
            if link_type == 276 {
                "Linux cooked capture v2".to_string()
            } else {
                "Linux cooked capture v1".to_string()
            }
        }
        "null" => "Null/Loopback".to_string(),
        "arp" => match field_u64(node, "arp.opcode") {
            Some(opcode) => format!(
                "Address Resolution Protocol ({})",
                value_name("arp.opcode", opcode).unwrap_or("unknown")
            ),
            None => "Address Resolution Protocol".to_string(),
        },
        "ip" => {
            let mut text = "Internet Protocol Version 4".to_string();
            if let Some(src) = host_text(node, "ip.src", "ip.src_host", resolution) {
                let _ = write!(text, ", Src: {src}");
            }
            if let Some(dst) = host_text(node, "ip.dst", "ip.dst_host", resolution) {
                let _ = write!(text, ", Dst: {dst}");
            }
            text
        }
        "ipv6" => {
            let mut text = "Internet Protocol Version 6".to_string();
            if let Some(src) = host_text(node, "ipv6.src", "ipv6.src_host", resolution) {
                let _ = write!(text, ", Src: {src}");
            }
            if let Some(dst) = host_text(node, "ipv6.dst", "ipv6.dst_host", resolution) {
                let _ = write!(text, ", Dst: {dst}");
            }
            text
        }
        "ipv6.routing" => {
            let routing_type = field_u64(node, "ipv6.routing.type").unwrap_or(0);
            let name = value_name("ipv6.routing.type", routing_type)
                .map(str::to_string)
                .unwrap_or_else(|| format!("Unknown type {routing_type}"));
            format!("Routing Header for IPv6 ({name})")
        }
        "udp" => {
            let mut text = "User Datagram Protocol".to_string();
            if let Some(port) = field_u64(node, "udp.srcport") {
                let _ = write!(
                    text,
                    ", Src Port: {}",
                    port_value_text(port, false, resolution)
                );
            }
            if let Some(port) = field_u64(node, "udp.dstport") {
                let _ = write!(
                    text,
                    ", Dst Port: {}",
                    port_value_text(port, false, resolution)
                );
            }
            text
        }
        "tcp" => {
            let mut text = "Transmission Control Protocol".to_string();
            if let Some(port) = field_u64(node, "tcp.srcport") {
                let _ = write!(
                    text,
                    ", Src Port: {}",
                    port_value_text(port, true, resolution)
                );
            }
            if let Some(port) = field_u64(node, "tcp.dstport") {
                let _ = write!(
                    text,
                    ", Dst Port: {}",
                    port_value_text(port, true, resolution)
                );
            }
            if let Some(sequence) = field_u64(node, "tcp.seq") {
                let _ = write!(text, ", Seq: {sequence}");
            }
            if field_u64(node, "tcp.flags").is_some_and(|flags| flags & 0x10 != 0)
                && let Some(acknowledgement) = field_u64(node, "tcp.ack")
            {
                let _ = write!(text, ", Ack: {acknowledgement}");
            }
            if let Some(length) = field_u64(node, "tcp.len") {
                let _ = write!(text, ", Len: {length}");
            }
            text
        }
        "dhcp" => {
            let mut text = node.protocol.long_name.to_string();
            if let Some(message_type) =
                packetfin_core::decode::dhcp_main_area_decoded_message_type(node)
            {
                let name = value_name("dhcp.option.dhcp", message_type)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("Unknown ({message_type})"));
                let _ = write!(text, " ({name})");
            }
            text
        }
        "dhcpv6" => node.protocol.long_name.to_string(),
        "ntp" => {
            let flags = field_u64(node, "ntp.flags").unwrap_or(0);
            format!("{} ({})", node.protocol.long_name, ntp_status_text(flags))
        }
        "icmp" => "Internet Control Message Protocol".to_string(),
        "icmpv6" => "Internet Control Message Protocol v6".to_string(),
        "gre" => {
            let Some(protocol) = field_u64(node, "gre.proto") else {
                return "Generic Routing Encapsulation".to_string();
            };
            match value_name("gre.proto", protocol) {
                Some(name) => format!("Generic Routing Encapsulation ({name})"),
                None => format!("Generic Routing Encapsulation (0x{protocol:04X} - unknown)"),
            }
        }
        "erspan" => {
            let mut text = "Encapsulated Remote Switch Packet ANalysis".to_string();
            if node.range.length == 0 {
                text.push_str(" Type I");
            } else {
                match field_u64(node, "erspan.version") {
                    Some(1) => text.push_str(" Type II"),
                    Some(2) => text.push_str(" Type III"),
                    _ => text.push_str(" Unknown"),
                }
            }
            text
        }
        "bfd" => "BFD Control message".to_string(),
        "bfd_echo" => "BFD Echo message".to_string(),
        "vxlan" => "Virtual eXtensible Local Area Network".to_string(),
        "geneve" => {
            let mut text = "Generic Network Virtualization Encapsulation".to_string();
            if let Some(vni) = field_u64(node, "geneve.vni") {
                let oam = node.fields.iter().any(|field| {
                    field.def.abbrev == "geneve.flags.oam" && field.value == Value::Boolean(true)
                });
                let _ = write!(text, ", VNI: 0x{vni:06x}{}", if oam { ", OAM" } else { "" });
            }
            text
        }
        "mpls" => {
            let label = field_u64(node, "mpls.label").unwrap_or(0);
            let mut text = format!("MultiProtocol Label Switching Header, Label: {label}");
            if label <= 15
                && let Some(name) = value_name("mpls.label", label)
            {
                let _ = write!(text, " ({name})");
            }
            let _ = write!(
                text,
                ", Exp: {}, S: {}, TTL: {}",
                field_u64(node, "mpls.exp").unwrap_or(0),
                field_u64(node, "mpls.bottom").unwrap_or(0),
                field_u64(node, "mpls.ttl").unwrap_or(0)
            );
            text
        }
        "dns" | "mdns" | "llmnr" => format!(
            "{} ({})",
            node.protocol.long_name,
            if field_u64(node, "dns.flags.response").unwrap_or(0) == 0 {
                "query"
            } else {
                "response"
            }
        ),
        "http" => {
            let mut text = "Hypertext Transfer Protocol".to_string();
            let chunks = count_fields(node, "http.chunk_size");
            if chunks > 0 {
                let _ = write!(
                    text,
                    ", has {chunks} chunk{} (including last chunk)",
                    if chunks == 1 { "" } else { "s" }
                );
            }
            text
        }
        "bgp" => {
            let kind = field_u64(node, "bgp.type").unwrap_or(0);
            let name = match kind {
                1 => "OPEN Message".to_string(),
                2 => "UPDATE Message".to_string(),
                3 => "NOTIFICATION Message".to_string(),
                4 => "KEEPALIVE Message".to_string(),
                5 => "ROUTE-REFRESH Message".to_string(),
                6 => "CAPABILITY Message".to_string(),
                other => format!("Unknown message type (0x{other:02x})"),
            };
            format!("Border Gateway Protocol - {name}")
        }
        _ => node.protocol.long_name.to_string(),
    }
}

/// The detail/PDML showname for fields with custom value text.
pub(crate) fn special_showname(
    node: &Node,
    field: &Field,
    resolution: Resolution,
) -> Option<String> {
    match field.def.abbrev {
        "eth.src" | "eth.dst" => ethernet_address_text(node, field.def.abbrev, resolution)
            .map(|value| format!("{}: {value}", field.def.name)),
        "ip.src" | "ip.dst" => host_text(
            node,
            field.def.abbrev,
            &format!("{}_host", field.def.abbrev),
            resolution,
        )
        .map(|value| format!("{}: {value}", field.def.name)),
        "ipv6.src" | "ipv6.dst" => host_text(
            node,
            field.def.abbrev,
            &format!("{}_host", field.def.abbrev),
            resolution,
        )
        .map(|value| format!("{}: {value}", field.def.name)),
        "udp.srcport" | "udp.dstport" => field_value_u64(field).map(|port| {
            format!(
                "{}: {}",
                field.def.name,
                port_value_text(port, false, resolution)
            )
        }),
        "tcp.srcport" | "tcp.dstport" => field_value_u64(field).map(|port| {
            format!(
                "{}: {}",
                field.def.name,
                port_value_text(port, true, resolution)
            )
        }),
        "ntp.refid" => {
            let stratum = field_u64(node, "ntp.stratum").unwrap_or(0);
            let text = match &field.value {
                Value::Bytes(bytes) => reference_id_text(bytes, stratum),
                _ => String::new(),
            };
            Some(format!("Reference ID: {text}"))
        }
        "dhcp.server" | "dhcp.file" if matches!(&field.value, Value::String(text) if text.is_empty()) => {
            Some(format!("{} not given", field.def.name))
        }
        "dhcp.cookie" if matches!(field.value, Value::Ipv4([0x63, 0x82, 0x53, 0x63])) => {
            Some("Magic cookie: DHCP".to_string())
        }
        "dhcp.option.request_list_item" => field_value_u64(field).map(|code| {
            let name = packetfin_core::decode::dhcp_option_name(u8::try_from(code).unwrap_or(0))
                .unwrap_or("Unknown");
            format!("{}: ({code}) {name}", field.def.name)
        }),
        "dhcp.option.agent_information_option.suboption" => field_value_u64(field).map(|code| {
            let name = suboption_name(code);
            format!("{}: ({code}) {name}", field.def.name)
        }),
        "dhcpv6.requested_option_code" => field_value_u64(field).map(|code| {
            let name = u16::try_from(code)
                .ok()
                .and_then(packetfin_core::decode::dhcpv6_option_name)
                .unwrap_or("Unknown");
            format!("{}: {name} ({code})", field.def.name)
        }),
        _ => custom_value(field).map(|text| format!("{}: {text}", field.def.name)),
    }
}

fn field_value_u64(field: &Field) -> Option<u64> {
    match &field.value {
        Value::Uint8(value) => Some(u64::from(*value)),
        Value::Uint16(value) => Some(u64::from(*value)),
        Value::Uint24(value) | Value::Uint32(value) => Some(u64::from(*value)),
        Value::Uint64(value) => Some(*value),
        Value::Int8(value) => u64::try_from(*value).ok(),
        Value::Int16(value) => u64::try_from(*value).ok(),
        Value::Int32(value) => u64::try_from(*value).ok(),
        Value::Int64(value) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn suboption_name(code: u64) -> &'static str {
    match code {
        0 => "Padding",
        1 => "Agent Circuit ID",
        2 => "Agent Remote ID",
        3 => "Reserved",
        4 => "DOCSIS Device Class",
        5 => "Link selection",
        6 => "Subscriber ID",
        _ => "Unknown",
    }
}

/// Custom texts for values whose `-T fields` form is numeric.
fn custom_value(field: &Field) -> Option<String> {
    match field.def.abbrev {
        "ntp.ppoll" => match field.value {
            Value::Int8(poll) => Some(poll_text(poll)),
            _ => None,
        },
        "ntp.precision" => match field.value {
            Value::Int8(precision) => Some(precision_text(precision)),
            _ => None,
        },
        "ntp.rootdelay" | "ntp.rootdispersion" => match field.value {
            Value::Uint32(raw) => Some(fixed_point_seconds(raw)),
            _ => None,
        },
        "dhcp.option.ip_address_lease_time"
        | "dhcp.option.renewal_time_value"
        | "dhcp.option.rebinding_time_value" => match field.value {
            Value::Uint32(raw) => Some(duration_text(raw)),
            _ => None,
        },
        "dhcpv6.elapsed_time" => match field.value {
            Value::Uint32(raw) => Some(format!("{raw}ms")),
            _ => None,
        },
        "dhcpv6.duiden.enterprise" | "dhcp.client_id.enterprise_num" => match field.value {
            Value::Uint32(raw) => Some(match raw {
                32473 => "Example Enterprise Number for Documentation Use (32473)".to_string(),
                other => format!("Unknown ({other})"),
            }),
            _ => None,
        },
        "dhcp.cookie" => match field.value {
            Value::Ipv4([0x63, 0x82, 0x53, 0x63]) => Some("DHCP".to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Power-of-two seconds for a signed poll exponent, exact for non-negative
/// exponents and rounded to three decimals otherwise.
fn poll_text(poll: i8) -> String {
    if poll >= 0 {
        let seconds = 1_u128 << u32::from(poll as u8);
        return format!("{poll} ({seconds} seconds)");
    }
    let exponent = u32::from(poll.unsigned_abs());
    let millis = if exponent > 10 {
        0
    } else {
        round_half_even(1000, 1_u128 << exponent)
    };
    format!("{poll} (0.{millis:03} seconds)")
}

fn precision_text(precision: i8) -> String {
    if precision >= 0 {
        let seconds = 1_u128 << u32::from(precision as u8);
        return format!("{precision} ({seconds}.000000000 seconds)");
    }
    let exponent = u32::from(precision.unsigned_abs());
    let nanos = if exponent > 30 {
        0
    } else {
        round_half_even(1_000_000_000, 1_u128 << exponent)
    };
    format!("{precision} (0.{nanos:09} seconds)")
}

/// Divide, rounding halves to even.
fn round_half_even(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        return 0;
    }
    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    match remainder.saturating_mul(2).cmp(&denominator) {
        std::cmp::Ordering::Greater => quotient.saturating_add(1),
        std::cmp::Ordering::Equal if quotient % 2 == 1 => quotient.saturating_add(1),
        _ => quotient,
    }
}

fn fixed_point_seconds(raw: u32) -> String {
    let micros = round_half_even(u128::from(raw) * 1_000_000, 65_536);
    let seconds = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    format!("{seconds}.{fraction:06} seconds")
}

fn duration_text(raw: u32) -> String {
    if raw == u32::MAX {
        return "infinity (-1)".to_string();
    }
    let days = raw / 86_400;
    let hours = (raw % 86_400) / 3_600;
    let minutes = (raw % 3_600) / 60;
    let seconds = raw % 60;
    let mut parts: Vec<String> = Vec::new();
    if days > 0 {
        parts.push(format!("{days} day{}", plural(days.into())));
    }
    if hours > 0 {
        parts.push(format!("{hours} hour{}", plural(hours.into())));
    }
    if minutes > 0 {
        parts.push(format!("{minutes} minute{}", plural(minutes.into())));
    }
    if seconds > 0 || parts.is_empty() {
        parts.push(format!("{seconds} second{}", plural(seconds.into())));
    }
    format!("{} ({raw})", parts.join(", "))
}

const KISS_CODES: &[(&[u8; 4], &str)] = &[
    (b"ACST", "The association belongs to a unicast server"),
    (b"AUTH", "Server authentication failed"),
    (b"AUTO", "Autokey sequence failed"),
    (b"BCST", "The association belongs to a broadcast server"),
    (
        b"CRYP",
        "Cryptographic authentication or identification failed",
    ),
    (b"DENY", "Access denied by remote server"),
    (b"DROP", "Lost peer in symmetric mode"),
    (b"RSTR", "Access denied due to local policy"),
    (
        b"INIT",
        "The association has not yet synchronized for the first time",
    ),
    (
        b"MCST",
        "The association belongs to a dynamically discovered server",
    ),
    (
        b"NKEY",
        "No key found. Either the key was never installed or is not trusted",
    ),
    (
        b"RATE",
        "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold",
    ),
    (
        b"RMOT",
        "Alteration of association from a remote host running ntpdc.",
    ),
    (
        b"STEP",
        "A step change in system time has occurred, but the association has not yet resynchronized",
    ),
];

const REFERENCE_CODES: &[(&[u8; 4], &str)] = &[
    (b"GOES", "Geostationary Orbit Environment Satellite"),
    (b"GPS ", "Global Position System"),
    (b"PPS ", "Generic pulse-per-second"),
    (b"DCF ", "LF Radio DCF77 Mainflingen, DE 77.5 kHz"),
    (b"MSF ", "LF Radio MSF Anthorn, UK 60 kHz"),
    (b"WWV ", "HF Radio WWV Ft. Collins, CO"),
    (b"WWVB", "LF Radio WWVB Ft. Collins, CO 60 kHz"),
    (b"WWVH", "HF Radio WWVH Kauai, HI"),
    (b"NIST", "NIST telephone modem"),
    (b"ACTS", "NIST telephone modem"),
    (b"USNO", "USNO telephone modem"),
    (b"CHU ", "HF Radio CHU Ottawa, Ontario"),
    (b"LOCL", "uncalibrated local clock"),
    (b"CAL ", "calibrated Cesium clock"),
    (b"CESM", "calibrated Cesium clock"),
    (b"RBDM", "calibrated Rubidium clock"),
    (b"IRIG", "Inter-Range Instrumentation Group"),
    (b"TDF ", "MF Radio Allouis, FR 162 kHz"),
    (b"PTB ", "European telephone modem"),
];

fn reference_id_text(bytes: &[u8], stratum: u64) -> String {
    if bytes.iter().all(|byte| *byte == 0) {
        return "NULL".to_string();
    }
    if stratum >= 2 {
        return format!(
            "{}.{}.{}.{}",
            bytes.first().copied().unwrap_or(0),
            bytes.get(1).copied().unwrap_or(0),
            bytes.get(2).copied().unwrap_or(0),
            bytes.get(3).copied().unwrap_or(0)
        );
    }
    let code = code_string(bytes);
    let table = if stratum == 0 {
        KISS_CODES
    } else {
        REFERENCE_CODES
    };
    for (candidate, text) in table {
        if bytes.get(..4) == Some(candidate.as_slice()) {
            return (*text).to_string();
        }
    }
    if stratum == 0 {
        format!("Unidentified Kiss-o'-Death message '{code}'")
    } else {
        format!("Unidentified reference source '{code}'")
    }
}

fn code_string(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes.iter().take_while(|byte| **byte != 0) {
        if (0x20..=0x7e).contains(byte) {
            text.push(char::from(*byte));
        } else {
            let _ = write!(text, "\\x{byte:02x}");
        }
    }
    text
}

/// Render one field value with its detail display form.
pub(crate) fn write_value(text: &mut String, field: &Field) {
    let display = field.def.display;
    match &field.value {
        Value::Uint8(value) => write_uint(text, u64::from(*value), display, field.def),
        Value::Uint16(value) => write_uint(text, u64::from(*value), display, field.def),
        Value::Uint24(value) => write_uint(text, u64::from(*value), display, field.def),
        Value::Uint32(value) => write_uint(text, u64::from(*value), display, field.def),
        Value::Uint64(value) => write_uint(text, *value, display, field.def),
        Value::Int8(value) => {
            let _ = write!(text, "{value}");
        }
        Value::Int16(value) => {
            let _ = write!(text, "{value}");
        }
        Value::Int32(value) => {
            let _ = write!(text, "{value}");
        }
        Value::Int64(value) => {
            let _ = write!(text, "{value}");
        }
        Value::Boolean(value) => {
            let (yes, no) = packetfin_core::fields::true_false_name(field.def.abbrev)
                .unwrap_or(("True", "False"));
            text.push_str(if *value { yes } else { no });
        }
        Value::None => text.push('1'),
        Value::Missing => text.push_str("<MISSING>"),
        Value::Ethernet(address) => {
            let _ = write!(
                text,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                address[0], address[1], address[2], address[3], address[4], address[5]
            );
        }
        Value::Eui64(address) => {
            let _ = write!(
                text,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                address[0],
                address[1],
                address[2],
                address[3],
                address[4],
                address[5],
                address[6],
                address[7]
            );
        }
        Value::Ipv4(address) => {
            let _ = write!(text, "{}", address[0]);
            let _ = write!(text, ".{}.{}.{}", address[1], address[2], address[3]);
        }
        Value::Ipv6(address) => {
            text.push_str(&Value::Ipv6(*address).render(Display::None));
        }
        Value::String(value) => write_escaped(text, value),
        Value::Bytes(bytes) => {
            if bytes.is_empty() {
                text.push_str("<MISSING>");
            } else {
                for byte in bytes.as_slice() {
                    let _ = write!(text, "{byte:02x}");
                }
            }
        }
        Value::AbsoluteTime(timestamp) => match field.def.display {
            Display::IsoTime | Display::IsoTimeZ => text.push_str(&absolute_time(*timestamp)),
            _ => {
                let _ = write!(text, "{}.{:09}", timestamp.seconds, timestamp.nanos);
            }
        },
        Value::Oid(ids) => {
            let dotted = packetfin_core::tree::oid_text(ids);
            let _ = write!(
                text,
                "{dotted} ({})",
                packetfin_core::tree::oid_resolved_text(ids)
            );
        }
        Value::RelativeTime(nanos) => text.push_str(&relative_time_text(*nanos)),
    }
}

/// Human-readable relative-time text: days, hours, minutes and a seconds
/// remainder, or milliseconds below one second.
fn relative_time_text(nanos: i64) -> String {
    let magnitude = nanos.unsigned_abs();
    if magnitude == 0 {
        return "0.000000000 seconds".to_string();
    }
    let seconds = i64::try_from(magnitude / 1_000_000_000).unwrap_or(i64::MAX);
    let remainder = u32::try_from(magnitude % 1_000_000_000).unwrap_or(0);
    let mut text = delta(
        Timestamp {
            seconds: 0,
            nanos: 0,
        },
        Timestamp {
            seconds,
            nanos: remainder,
        },
    );
    if nanos < 0 {
        text.insert(0, '-');
    }
    text
}

fn write_uint(text: &mut String, value: u64, display: Display, def: &FieldDef) {
    let width = hex_width(def);
    if let Some(name) = value_name(def.abbrev, value) {
        if def.abbrev.ends_with(".checksum.status") {
            text.push_str(name);
            return;
        }
        if display == Display::Oui {
            let _ = write!(
                text,
                "{:02x}:{:02x}:{:02x} ({name})",
                (value >> 16) & 0xff,
                (value >> 8) & 0xff,
                value & 0xff
            );
            return;
        }
        match display {
            Display::Hex | Display::HexDec => {
                let _ = write!(text, "{name} (0x{value:0width$x})");
            }
            _ => {
                let _ = write!(text, "{name} ({value})");
            }
        }
        return;
    }
    if is_enum_field(def.abbrev) {
        match display {
            Display::Hex | Display::HexDec => {
                let _ = write!(text, "Unknown (0x{value:0width$x})");
            }
            _ => {
                let _ = write!(text, "Unknown ({value})");
            }
        }
        return;
    }
    match display {
        Display::RelativeTime => text.push_str(&format_relative_detail(value)),
        Display::Decimal | Display::None | Display::BaseNone | Display::IsoTime => {
            let _ = write!(text, "{value}");
        }
        Display::Seconds256 => text.push_str(&packetfin_core::tree::render_seconds_256(value)),
        Display::MaskedHex => {
            let _ = write!(text, "0x{value:08x}");
        }
        Display::DecHex => {
            let _ = write!(text, "{value} (0x{value:0width$x})");
        }
        Display::Hex | Display::HexDec => {
            let _ = write!(text, "0x{value:0width$x}");
            if display == Display::HexDec {
                let _ = write!(text, " ({value})");
            }
        }
        Display::Oui => {
            let _ = write!(
                text,
                "{:02x}:{:02x}:{:02x}",
                (value >> 16) & 0xff,
                (value >> 8) & 0xff,
                value & 0xff
            );
        }
        Display::PortTcp
        | Display::PortUdp
        | Display::Boolean0
        | Display::Boolean6
        | Display::Boolean8
        | Display::Boolean12
        | Display::Boolean16
        | Display::Boolean24
        | Display::Boolean32
        | Display::Custom
        | Display::IsoTimeZ => {
            let _ = write!(text, "{value}");
        }
    }
}

/// Render a nanosecond interval with its detail-view unit.
///
/// Whole seconds print as `N second(s)`; fractional seconds keep nine
/// digits, milliseconds six, microseconds three and smaller values print as
/// whole nanoseconds.
fn format_relative_detail(nanos: u64) -> String {
    if nanos >= 1_000_000_000 {
        let seconds = nanos / 1_000_000_000;
        let remainder = nanos % 1_000_000_000;
        if remainder == 0 {
            if seconds == 1 {
                "1 second".to_string()
            } else {
                format!("{seconds} seconds")
            }
        } else {
            format!("{seconds}.{remainder:09} seconds")
        }
    } else if nanos >= 1_000_000 {
        format!(
            "{}.{:06} milliseconds",
            nanos / 1_000_000,
            nanos % 1_000_000
        )
    } else if nanos >= 1_000 {
        format!("{}.{:03} microseconds", nanos / 1_000, nanos % 1_000)
    } else if nanos == 0 {
        "0.000000000 seconds".to_string()
    } else if nanos == 1 {
        "1 nanosecond".to_string()
    } else {
        format!("{nanos} nanoseconds")
    }
}

/// Detail hex pads to the field's bit span, not its storage width.
fn hex_width(def: &FieldDef) -> usize {
    if let Some(mask) = def.bitmask
        && mask != 0
    {
        let bits = 64 - mask.leading_zeros() - mask.trailing_zeros();
        return usize::try_from(bits.div_ceil(4)).unwrap_or(1).max(1);
    }
    match def.field_type {
        FieldType::Uint8 | FieldType::Int8 | FieldType::Boolean => 2,
        FieldType::Uint16 | FieldType::Int16 => 4,
        FieldType::Uint24 => 6,
        FieldType::Uint32 | FieldType::Int32 | FieldType::FrameNumber => 8,
        FieldType::Uint64 | FieldType::Int64 => 16,
        _ => 2,
    }
}

fn is_enum_field(abbrev: &str) -> bool {
    matches!(
        abbrev,
        "arp.hw.type"
            | "arp.proto.type"
            | "arp.opcode"
            | "eth.type"
            | "vlan.etype"
            | "sll.etype"
            | "sll.ltype"
            | "sll.pkttype"
            | "sll.hatype"
            | "llc.type"
            | "null.family"
            | "ip.proto"
            | "ipv6.nxt"
            | "ipv6.hopopts.nxt"
            | "ipv6.dstopts.nxt"
            | "ipv6.routing.nxt"
            | "ipv6.fraghdr.nxt"
            | "icmp.type"
            | "icmpv6.type"
            | "syslog.facility"
            | "syslog.level"
            | "ipv6.routing.type"
            | "lldp.tlv.type"
            | "lldp.chassis.subtype"
            | "lldp.port.subtype"
            | "lldp.network_address.subtype"
            | "lldp.mgn.address.subtype"
            | "lldp.mgn.interface.subtype"
            | "lldp.ieee.802_1.subtype"
            | "lldp.ieee.802_3.subtype"
            | "lldp.ieee.802_3.pmd_mau_type"
            | "lldp.ieee.802_1.aggregation_status.porttype"
            | "stp.protocol"
            | "stp.version"
            | "stp.type"
            | "stp.flags.port_role"
            | "slow.subtype"
            | "lacp.tlv_type"
            | "marker.tlvType"
            | "dhcp.type"
            | "dhcp.hw.type"
            | "dhcp.option.dhcp"
            | "dhcp.option.option_overload"
            | "ntp.flags.li"
            | "ntp.flags.vn"
            | "ntp.flags.mode"
            | "ntp.stratum"
            | "dhcpv6.msgtype"
            | "dhcpv6.duid.type"
            | "dhcpv6.status_code"
            | "dhcpv6.duidllt.hwtype"
            | "dhcpv6.duidll.hwtype"
            | "dhcp.client_id.duid_type"
            | "dhcp.client_id.duid_llt_hw_type"
            | "dhcp.client_id.duid_ll_hw_type"
            | "erspan.version"
            | "erspan.encap"
            | "erspan.bso"
            | "erspan.truncated"
            | "erspan.ft"
            | "erspan.gra"
            | "geneve.proto_type"
            | "gre.proto"
            | "gre.flags.version"
            | "mpls.label"
            | "ospf.msg"
            | "ospf.lsa"
            | "ospf.auth.type"
            | "ospf.v3.lsa.fc"
            | "ospf.v3.lsa.s12"
            | "ospf.v3.lsa.type"
            | "vrrp.type"
            | "vrrp.auth_type"
            | "vrrp.checksum.status"
            | "bfd.diag"
            | "bfd.sta"
            | "bfd.auth.type"
    )
}

pub(crate) fn protocols_in_frame(packet: &Packet, frame: &Frame) -> String {
    let mut text = String::new();
    if is_raw_link(frame.link_type) {
        text.push_str("raw");
    }
    for name in &packet.protocol_stack {
        if !text.is_empty() {
            text.push(':');
        }
        text.push_str(name);
        if let Some(node) = find_last(&packet.tree.frame, name) {
            let dispatches = match *name {
                "eth" => has_field(node, "eth.type"),
                "vlan" => has_field(node, "vlan.etype"),
                "sll" => has_field(node, "sll.etype"),
                "ieee8021ad" => !node.children.is_empty(),
                _ => false,
            };
            if dispatches {
                text.push_str(":ethertype");
            }
        }
    }
    if claims_data(packet) {
        text.push_str(":data");
    }
    text
}

fn find_last<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    let mut found = if node.protocol.filter_name == name {
        Some(node)
    } else {
        None
    };
    for child in &node.children {
        if let Some(candidate) = find_last(child, name) {
            found = Some(candidate);
        }
    }
    found
}

fn invalid_length_type(node: &Node) -> bool {
    node.experts.iter().any(|expert| {
        expert.group == Group::Protocol && expert.message.starts_with("Invalid length/type")
    })
}

fn has_field(node: &Node, abbrev: &str) -> bool {
    node.fields.iter().any(|field| field.def.abbrev == abbrev)
}

/// Whether leftover transport or network payload is attached as `data`.
fn claims_data(packet: &Packet) -> bool {
    let Some(name) = packet.protocol_stack.last() else {
        return false;
    };
    let Some(node) = find_last(&packet.tree.frame, name) else {
        return false;
    };
    match *name {
        "udp" => node.children.is_empty() && payload_nonempty(node, "udp.payload"),
        "icmp" => payload_nonempty(node, "icmp.data"),
        "icmpv6" => {
            payload_nonempty(node, "icmpv6.data")
                || (matches!(field_u64(node, "icmpv6.type"), Some(128 | 129))
                    && node.range.length > 8)
        }
        _ => root_data_length(packet).is_some(),
    }
}

/// The root `data` item appended for unclaimed payload.
///
/// This is the single eligibility and length decision for both the
/// `Protocols in frame` suffix and the synthesised `Data (N bytes)` header.
/// IPv4/IPv6 need a complete captured header and use the smaller of the
/// reported IP payload and the captured bytes after that header, so link
/// padding is excluded and truncated captures keep their real length.
pub(crate) fn root_data_length(packet: &Packet) -> Option<usize> {
    let last_index = packet.protocol_stack.len().checked_sub(1)?;
    if packet
        .protocol_stack
        .iter()
        .take(last_index)
        .any(|name| matches!(*name, "icmp" | "icmpv6"))
    {
        return None;
    }
    let name = packet.protocol_stack.last()?;
    let node = find_last(&packet.tree.frame, name)?;
    if !node.children.is_empty() {
        return None;
    }
    match *name {
        "udp" => field_bytes(node, "udp.payload").filter(|length| *length > 0),
        "ip" => {
            if node.range.length < 20 {
                return None;
            }
            let header = usize::try_from(field_u64(node, "ip.hdr_len").unwrap_or(20)).ok()?;
            let captured = node.range.length.checked_sub(header)?;
            let reported = field_u64(node, "ip.len")?.checked_sub(u64::try_from(header).ok()?)?;
            bounded_payload(reported, captured)
        }
        "ipv6" => {
            if node.range.length < 40 {
                return None;
            }
            let captured = node.range.length.checked_sub(40)?;
            let reported = field_u64(node, "ipv6.plen")?;
            bounded_payload(reported, captured)
        }
        "eth" => {
            if !(has_field(node, "eth.type") || invalid_length_type(node)) {
                return None;
            }
            node.range
                .length
                .checked_sub(14)
                .filter(|length| *length > 0)
        }
        "sll" => {
            let header = if has_field(node, "sll.ifindex") {
                20
            } else {
                16
            };
            node.range
                .length
                .checked_sub(header)
                .filter(|length| *length > 0)
        }
        "null" => node
            .range
            .length
            .checked_sub(4)
            .filter(|length| *length > 0),
        _ => None,
    }
}

/// The payload given to the root data item: the smaller of the
/// reported IP payload and the captured bytes, excluding link padding.
fn bounded_payload(reported: u64, captured: usize) -> Option<usize> {
    if reported == 0 || captured == 0 {
        return None;
    }
    usize::try_from(reported)
        .ok()
        .map(|reported| reported.min(captured))
}

fn field_bytes(node: &Node, abbrev: &str) -> Option<usize> {
    node.fields
        .iter()
        .find(|field| field.def.abbrev == abbrev)
        .and_then(|field| match &field.value {
            Value::Bytes(bytes) => Some(bytes.len()),
            _ => None,
        })
}

fn payload_nonempty(node: &Node, abbrev: &str) -> bool {
    node.fields
        .iter()
        .find(|field| field.def.abbrev == abbrev)
        .is_some_and(|field| match &field.value {
            Value::Bytes(bytes) => !bytes.is_empty(),
            _ => true,
        })
}

/// Escape a capture-provided string for display.
///
/// The C0 controls with C escape names (`\a`, `\b`, `\t`, `\n`, `\v`, `\f`,
/// `\r`) print those names; every other control byte becomes an uppercase
/// `\xNN`. Backslashes and quotes stay unchanged.
fn escape_capture_string(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    write_escaped(&mut escaped, text);
    escaped
}

fn write_escaped(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control.is_control() => {
                let _ = write!(out, "\\x{:02X}", u32::from(control));
            }
            other => out.push(other),
        }
    }
}

pub(crate) fn absolute_time(timestamp: Timestamp) -> String {
    packetfin_core::capture::absolute_time_text(timestamp)
}

pub(crate) fn epoch_time(timestamp: Timestamp) -> String {
    format!("{}.{:09}", timestamp.seconds, timestamp.nanos)
}

/// Delta text: day/hour/minute decomposition, then the remainder in
/// the largest unit that keeps nanosecond exactness.
pub(crate) fn delta(from: Timestamp, to: Timestamp) -> String {
    let seconds = i128::from(to.seconds) - i128::from(from.seconds);
    let nanos = i128::from(to.nanos) - i128::from(from.nanos);
    packetfin_core::time::delta_text(seconds * 1_000_000_000 + nanos)
}

fn plural(value: u128) -> &'static str {
    if value == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetfin_core::fields;
    use packetfin_core::tree::Range;

    fn value_of(def: &'static FieldDef, value: Value) -> String {
        let field = Field {
            def,
            range: Range::default(),
            value,
            generated: false,
            showname: None,
            showname_hex: None,
            children: Vec::new(),
            nodes: Vec::new(),
            experts: Vec::new(),
            expert_field: None,
            container: false,
            hidden: false,
            mask_override: None,
            raw: None,
        };
        let mut text = String::new();
        write_value(&mut text, &field);
        text
    }

    #[test]
    fn hidden_fields_are_omitted_and_unnamed_groups_print_their_label() {
        use packetfin_core::tree::FieldParent;
        let tree = crate::test_support::tcp_tree(|node| {
            let group = node.add_unnamed(Range::new(34, 0), "Unnamed label".to_string());
            group.add_field(&fields::TCP_SEQ, Range::new(34, 4), Value::Uint32(7));
            node.add_field(&fields::TCP_ACK, Range::new(38, 4), Value::Uint32(9))
                .hide();
        });
        let text = render(tree);
        assert!(text.contains("Unnamed label"), "{text}");
        assert!(text.contains("Sequence Number: 7"), "{text}");
        assert!(!text.contains("Acknowledgment Number: 9"), "{text}");
    }

    #[test]
    fn detail_hex_values_use_bit_span() {
        assert_eq!(value_of(&fields::IP_FLAGS, Value::Uint8(2)), "0x2");
        assert_eq!(value_of(&fields::TCP_FLAGS, Value::Uint16(2)), "0x002");
        assert_eq!(value_of(&fields::IPV6_TCLASS, Value::Uint32(0)), "0x00");
        assert_eq!(value_of(&fields::IPV6_FLOW, Value::Uint24(0)), "0x00000");
        assert_eq!(
            value_of(&fields::IP_ID, Value::Uint16(0x1c46)),
            "0x1c46 (7238)"
        );
        assert_eq!(
            value_of(&fields::ICMP_IDENT, Value::Uint16(0x1234)),
            "4660 (0x1234)"
        );
    }

    #[test]
    fn bounded_payload_excludes_zero_and_padding() {
        assert_eq!(bounded_payload(8, 26), Some(8));
        assert_eq!(bounded_payload(0, 26), None);
        assert_eq!(bounded_payload(8, 0), None);
        assert_eq!(bounded_payload(8, 4), Some(4));
    }

    #[test]
    fn raw_link_types_map_to_raw_ip_encapsulations() {
        for link_type in [12, 14, 101] {
            assert_eq!(encapsulation(link_type), ("Raw IP", 7));
            assert!(is_raw_link(link_type));
        }
        assert_eq!(encapsulation(228), ("Raw IPv4", 129));
        assert_eq!(encapsulation(229), ("Raw IPv6", 130));
        assert!(is_raw_link(228));
        assert!(is_raw_link(229));
        assert!(!is_raw_link(1));
    }

    #[test]
    fn value_names_are_exact() {
        assert_eq!(value_name("arp.opcode", 3), Some("reverse request"));
        assert_eq!(value_name("arp.opcode", 4), Some("reverse reply"));
        assert_eq!(value_name("arp.opcode", 8), Some("inverse request"));
        assert_eq!(value_name("arp.opcode", 9), Some("inverse reply"));
        assert_eq!(value_name("arp.opcode", 10), Some("arp nak"));
        assert_eq!(
            value_name("eth.type", 0x88a8),
            Some("802.1ad Provider Bridge (Q-in-Q)")
        );
        assert_eq!(value_name("icmp.checksum.status", 3), Some("Not present"));
        assert_eq!(value_name("icmp.checksum.status", 4), Some("Illegal"));
    }

    fn timestamp(seconds: i64, nanos: u32) -> Timestamp {
        Timestamp { seconds, nanos }
    }

    #[test]
    fn relative_time_text_uses_scaled_units() {
        assert_eq!(relative_time_text(0), "0.000000000 seconds");
        assert_eq!(relative_time_text(999), "999 nanoseconds");
        assert_eq!(relative_time_text(45_000), "45.000 microseconds");
        assert_eq!(relative_time_text(1_001_001), "1.001001 milliseconds");
        assert_eq!(relative_time_text(123_456_789), "123.456789 milliseconds");
        assert_eq!(
            relative_time_text(60_500_000_000),
            "1 minute, 500.000000 milliseconds"
        );
        assert_eq!(
            relative_time_text(3_600_500_000_000),
            "1 hour, 500.000000 milliseconds"
        );
        assert_eq!(relative_time_text(-45_000), "-45.000 microseconds");
    }

    #[test]
    fn delta_uses_scaled_units() {
        let zero = timestamp(0, 0);
        assert_eq!(delta(zero, zero), "0.000000000 seconds");
        assert_eq!(delta(zero, timestamp(60, 0)), "1 minute");
        assert_eq!(
            delta(zero, timestamp(60, 500_000_000)),
            "1 minute, 500.000000 milliseconds"
        );
        assert_eq!(
            delta(zero, timestamp(3600, 500_000_000)),
            "1 hour, 500.000000 milliseconds"
        );
        assert_eq!(delta(zero, timestamp(86_400, 0)), "1 day");
        assert_eq!(
            delta(zero, timestamp(86_400, 123_456_789)),
            "1 day, 123.456789 milliseconds"
        );
        assert_eq!(
            delta(zero, timestamp(3_661, 123_456_789)),
            "1 hour, 1 minute, 1.123456789 seconds"
        );
        assert_eq!(delta(zero, timestamp(0, 1)), "1 nanosecond");
        assert_eq!(delta(zero, timestamp(0, 999)), "999 nanoseconds");
        assert_eq!(delta(zero, timestamp(0, 1_000)), "1.000 microseconds");
        assert_eq!(
            delta(zero, timestamp(0, 1_000_000)),
            "1.000000 milliseconds"
        );
        assert_eq!(delta(timestamp(2, 0), zero), "-2 seconds");
    }

    #[test]
    fn absolute_time_uses_fixed_layout() {
        assert_eq!(
            absolute_time(timestamp(1_700_000_000, 123_456_000)),
            "Nov 14, 2023 22:13:20.123456000 UTC"
        );
    }

    #[test]
    fn capture_strings_use_display_escapes() {
        assert_eq!(
            escape_capture_string("a\tb\nc\rd\u{7}e\u{8}f\u{b}g\u{c}h\u{1b}[31m"),
            "a\\tb\\nc\\rd\\ae\\bf\\vg\\fh\\x1B[31m"
        );
        assert_eq!(
            escape_capture_string("back\\slash \"quote\""),
            "back\\slash \"quote\""
        );
    }

    #[test]
    fn detail_hex_uses_field_bit_span() {
        let flags = packetfin_core::fields::IP_FLAGS;
        assert_eq!(hex_width(&flags), 1);
        let tcp_flags = packetfin_core::fields::TCP_FLAGS;
        assert_eq!(hex_width(&tcp_flags), 3);
        let traffic_class = packetfin_core::fields::IPV6_TCLASS;
        assert_eq!(hex_width(&traffic_class), 2);
        let flow = packetfin_core::fields::IPV6_FLOW;
        assert_eq!(hex_width(&flow), 5);
        let identification = packetfin_core::fields::IP_ID;
        assert_eq!(hex_width(&identification), 4);
    }

    fn render(tree: packetfin_core::Tree) -> String {
        render_with(tree, &DetailOptions::default())
    }

    fn render_with(tree: packetfin_core::Tree, options: &DetailOptions) -> String {
        let mut writer = DetailWriter::new(options, b"", false);
        let mut output = Vec::new();
        assert!(
            writer
                .write_packet(
                    &mut output,
                    &crate::test_support::frame(),
                    &crate::test_support::packet(tree),
                )
                .is_ok()
        );
        String::from_utf8(output).unwrap_or_default()
    }

    #[test]
    fn containers_render_children_and_nested_experts() {
        let text = render(crate::test_support::analysis_tree());
        assert!(
            text.contains(
                "    [SEQ/ACK analysis]\n\
                 \x20       [This is an ACK to the segment in frame: 1]\n\
                 \x20       [TCP Analysis Flags]\n\
                 \x20           [Expert Info (Note/Sequence): This frame is a (suspected) retransmission]\n\
                 \x20               [This frame is a (suspected) retransmission]\n\
                 \x20               [Severity level: Note]\n\
                 \x20               [Group: Sequence]\n\
                 \x20           [The RTO for this segment was: 1]\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn ntp_custom_texts_round_half_even() {
        assert_eq!(fixed_point_seconds(512), "0.007812 seconds");
        assert_eq!(fixed_point_seconds(1536), "0.023438 seconds");
        assert!(precision_text(-10).contains("0.000976562"));
        assert!(precision_text(-30).contains("0.000000001"));
        assert_eq!(poll_text(-4), "-4 (0.062 seconds)");
    }

    #[test]
    fn option_code_shownames_use_registry_names() {
        let mut node = Node::new(&packetfin_core::fields::DHCP_PROTOCOL, Range::default());
        node.add_field(
            &packetfin_core::fields::DHCP_OPTION_REQUEST_LIST_ITEM,
            Range::default(),
            Value::Uint8(6),
        );
        node.add_field(
            &packetfin_core::fields::DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBOPTION,
            Range::default(),
            Value::Uint8(1),
        );
        let fields = &node.fields;
        assert_eq!(
            fields
                .first()
                .and_then(|field| special_showname(&node, field, Resolution::default()))
                .as_deref(),
            Some("Parameter Request List Item: (6) Domain Name Server")
        );
        assert_eq!(
            fields
                .get(1)
                .and_then(|field| special_showname(&node, field, Resolution::default()))
                .as_deref(),
            Some("Option 82 Suboption: (1) Agent Circuit ID")
        );
    }

    #[test]
    fn packet_scoped_container_starts_at_column_zero() {
        let text = render(crate::test_support::segments_tree());
        assert!(
            text.contains(
                "\n[2 Reassembled TCP Segments (31 bytes): #4(10), #5(21)]\n\
                 \x20   [TCP Segment: 4]\n\
                 \x20   [TCP Segment: 5]\n\
                 \x20   [Segment count: 2]\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn collapsed_owner_still_prints_a_packet_scoped_label() {
        let text = render_with(
            crate::test_support::segments_tree(),
            &DetailOptions {
                protocols: Some(vec!["frame".to_string()]),
            },
        );
        assert!(
            text.contains("\n[2 Reassembled TCP Segments (31 bytes): #4(10), #5(21)]\n"),
            "{text}"
        );
        assert!(!text.contains("[TCP Segment: 4]"), "{text}");
    }

    #[test]
    fn selected_owner_expands_inline_but_not_packet_scoped_children() {
        let options = DetailOptions {
            protocols: Some(vec!["tcp".to_string()]),
        };
        let text = render_with(crate::test_support::analysis_tree(), &options);
        assert!(text.contains("    [SEQ/ACK analysis]\n"), "{text}");
        assert!(
            text.contains("        [This is an ACK to the segment in frame: 1]\n"),
            "{text}"
        );

        let text = render_with(crate::test_support::segments_tree(), &options);
        assert!(
            text.contains("\n[2 Reassembled TCP Segments (31 bytes): #4(10), #5(21)]\n"),
            "{text}"
        );
        assert!(!text.contains("[TCP Segment: 4]"), "{text}");
    }

    #[test]
    fn bytes_container_stays_at_field_depth() {
        let text = render(crate::test_support::fragments_tree());
        assert!(
            text.contains(
                "    [2 IPv4 Fragments (32 bytes): #1(16), #2(16)]\n\
                 \x20       [IPv4 Fragment: 1]\n\
                 \x20       [IPv4 Fragment: 2]\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn typed_option_values_are_hidden_but_unknown_values_show() {
        let mut node = Node::new(&packetfin_core::fields::DHCP_PROTOCOL, Range::default());
        let typed = node.add_container(
            &packetfin_core::fields::DHCP_OPTION_TYPE,
            Range::default(),
            Some("Option: (53) DHCP Message Type".to_string()),
        );
        typed
            .add_field(
                &packetfin_core::fields::DHCP_OPTION_VALUE,
                Range::default(),
                Value::bytes(vec![1]),
            )
            .hide();
        assert!(
            node.fields
                .first()
                .and_then(|field| field.children.first())
                .is_some_and(|field| field.hidden)
        );
        let mut unknown = Node::new(&packetfin_core::fields::DHCP_PROTOCOL, Range::default());
        let generic = unknown.add_container(
            &packetfin_core::fields::DHCP_OPTION_TYPE,
            Range::default(),
            Some("Option: (224) Private".to_string()),
        );
        generic.add_field(
            &packetfin_core::fields::DHCP_OPTION_VALUE,
            Range::default(),
            Value::bytes(vec![1]),
        );
        assert!(
            unknown
                .fields
                .first()
                .and_then(|field| field.children.first())
                .is_some_and(|field| !field.hidden)
        );
    }
}
