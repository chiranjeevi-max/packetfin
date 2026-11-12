//! `-T ek` output: Elasticsearch bulk documents.
//!
//! Each displayed packet produces an `index` action and one compact document.
//! The normal body has `timestamp` (epoch milliseconds) and `layers`; `-P`
//! replaces the body with the summary columns. Layers are objects keyed by the
//! protocol name with dots replaced by underscores; fields are flattened the
//! same way and a repeated field becomes an array. Quoted datagrams and IPv6
//! extension headers nest inside their parent protocol.
//!
//! With `-e`, keys follow the command line and every value is an array of
//! display strings. Without it, layers are written in decode order.

use std::fmt::Write as _;
use std::io::{self, Write};

use packetfin_core::tree::Bytes;
use packetfin_core::{Display, Field, FieldDef, Frame, Node, Packet, Timestamp, Value};

use crate::detail::{self, Scope, child_scope};
use crate::json::{self, ProtocolFilter};
use crate::mask;
use crate::render_context::RenderContext;
use crate::summary::{SummaryWriter, TimeOptions};

/// A JSON value in the shapes EK needs.
enum Ek {
    Null,
    Bool(bool),
    String(String),
    /// Bytes rendered as colon-separated hex by the serializer.
    Bytes(Bytes),
    /// Bytes rendered as plain lowercase hex by the serializer.
    Hex(Bytes),
    Array(Vec<Ek>),
    Object(Vec<(String, Ek)>),
}

impl Ek {
    fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    fn filtered(key: &str) -> Self {
        Self::Object(vec![("filtered".to_string(), Self::string(key))])
    }
}

/// Streaming `-T ek` writer for one invocation.
pub struct EkWriter<'a> {
    filter: Option<&'a ProtocolFilter>,
    fields: &'a [&'static FieldDef],
    print_hex: bool,
    summary: Option<SummaryWriter>,
    first_timestamp: Option<Timestamp>,
    previous_captured: Option<Timestamp>,
    previous_displayed: Option<Timestamp>,
}

impl<'a> EkWriter<'a> {
    /// Restart the summary state `-M` resets.
    pub fn reset_session(&mut self) {
        if let Some(summary) = &mut self.summary {
            summary.reset_session();
        }
    }

    /// Prepare a writer for one invocation.
    pub fn new(
        filter: Option<&'a ProtocolFilter>,
        fields: &'a [&'static FieldDef],
        print_hex: bool,
        summary: bool,
        time: TimeOptions,
    ) -> Self {
        Self {
            filter,
            fields,
            print_hex,
            summary: summary.then(|| SummaryWriter::new(time)),
            first_timestamp: None,
            previous_captured: None,
            previous_displayed: None,
        }
    }

    /// Record a frame that the display filter hides.
    pub fn observe_hidden(&mut self, frame: &Frame, packet: &Packet) {
        if let Some(summary) = &mut self.summary {
            summary.observe_hidden(frame, packet, true);
        } else {
            self.advance(frame.timestamp, false);
        }
    }

    /// Write the bulk action and document for one displayed packet.
    pub fn write_packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
    ) -> io::Result<()> {
        let index = json::index_name(frame.timestamp);
        writer.write_all(b"{\"index\":{\"_index\":")?;
        json::write_json_string(writer, &index)?;
        writer.write_all(b"}}\n")?;
        let timestamp = frame.timestamp.map_or(0_u128, |timestamp| {
            let milliseconds =
                i128::from(timestamp.seconds) * 1000 + i128::from(timestamp.nanos) / 1_000_000;
            u128::try_from(milliseconds.max(0)).unwrap_or(0)
        });
        let body = if let Some(summary) = &mut self.summary {
            let columns = summary.columns(frame, packet);
            Ek::Object(vec![
                ("timestamp".to_string(), Ek::string(timestamp.to_string())),
                ("no_".to_string(), Ek::string(columns.number.to_string())),
                ("time".to_string(), Ek::string(columns.time)),
                ("source".to_string(), Ek::string(columns.source)),
                ("destination".to_string(), Ek::string(columns.destination)),
                ("protocol".to_string(), Ek::string(columns.protocol)),
                ("length".to_string(), Ek::string(columns.length.to_string())),
                ("info".to_string(), Ek::string(columns.info)),
            ])
        } else {
            let times = self.advance(frame.timestamp, true);
            let layers = if self.fields.is_empty() {
                self.tree_layers(frame, packet, times.as_ref())
            } else {
                self.specified_layers(packet)
            };
            Ek::Object(vec![
                ("timestamp".to_string(), Ek::string(timestamp.to_string())),
                ("layers".to_string(), layers),
            ])
        };
        write_compact(writer, &body)?;
        writer.write_all(b"\n")
    }

    fn specified_layers(&self, packet: &Packet) -> Ek {
        let mut seen: Vec<usize> = Vec::with_capacity(self.fields.len());
        let mut entries: Vec<(String, Ek)> = Vec::with_capacity(self.fields.len());
        for definition in self.fields {
            if seen.contains(&definition.identity()) {
                continue;
            }
            seen.push(definition.identity());
            let mut values: Vec<Ek> = Vec::new();
            packet
                .tree
                .try_for_each_field(&mut |field| {
                    if field.def.abbrev == definition.abbrev {
                        values.push(Ek::String(field.value.render(field.def.display)));
                    }
                    Ok::<(), ()>(())
                })
                .ok();
            if !values.is_empty() {
                entries.push((flatten_abbrev(definition.abbrev), Ek::Array(values)));
            }
        }
        Ek::Object(entries)
    }

    fn tree_layers(&self, frame: &Frame, packet: &Packet, times: Option<&FrameTimes>) -> Ek {
        let state = match self.filter {
            Some(filter) => ChildState::Active(filter),
            None => ChildState::Off,
        };
        let mut layers: Vec<(String, Ek)> = Vec::new();
        self.comment_layer(&mut layers, frame, state);
        if self.print_hex {
            push_layer(
                &mut layers,
                "frame_raw".to_string(),
                Ek::string(hex_lower(&frame.captured)),
            );
        }
        if self.flag(state, "frame") == Flag::Filtered {
            push_layer(&mut layers, "frame".to_string(), Ek::filtered("frame"));
        } else {
            push_layer(
                &mut layers,
                "frame".to_string(),
                self.frame_layer(frame, packet, times),
            );
        }
        for child in &packet.tree.frame.children {
            let context = FieldContext {
                node: child,
                frame,
                sources: &packet.data_sources,
                filter: state,
            };
            self.emit_packet_protocol(
                &mut layers,
                &context,
                Scope {
                    level: 0,
                    selectable: true,
                    nested: false,
                    packet_level: 0,
                },
            );
        }
        self.data_layer(&mut layers, frame, packet, state);
        if malformed_node(&packet.tree.frame).is_some() {
            if self.flag(state, "_ws.malformed") == Flag::Filtered {
                push_layer(
                    &mut layers,
                    "_ws_malformed".to_string(),
                    Ek::filtered("_ws.malformed"),
                );
            } else {
                push_layer(
                    &mut layers,
                    "_ws_malformed".to_string(),
                    Ek::Object(vec![
                        (
                            "_ws_expert".to_string(),
                            Ek::Object(vec![
                                (
                                    "_ws_expert__ws_expert_severity".to_string(),
                                    Ek::string("8388608"),
                                ),
                                (
                                    "_ws_expert__ws_expert_message".to_string(),
                                    Ek::string("Malformed Packet (Exception occurred)"),
                                ),
                                (
                                    "_ws_expert__ws_expert_group".to_string(),
                                    Ek::string("117440512"),
                                ),
                                ("_ws_malformed__ws_malformed_expert".to_string(), Ek::Null),
                            ]),
                        ),
                        ("_ws_malformed".to_string(), Ek::Object(Vec::new())),
                    ]),
                );
            }
        }
        Ek::Object(layers)
    }

    fn emit_packet_protocol(
        &self,
        out: &mut Vec<(String, Ek)>,
        context: &FieldContext<'_, '_>,
        scope: Scope,
    ) {
        let mut deferred = Deferred::default();
        self.emit_protocol(out, context, scope, &mut deferred);
        for (field, prefix) in deferred.packet_fields {
            self.append_container_fields(out, field, &prefix, context);
        }
        for (escaped_node, escaped_scope) in deferred.nodes {
            let child_context = FieldContext {
                node: escaped_node,
                frame: context.frame,
                sources: context.sources,
                filter: context.filter,
            };
            self.emit_packet_protocol(out, &child_context, escaped_scope);
        }
    }

    fn emit_protocol<'n>(
        &self,
        out: &mut Vec<(String, Ek)>,
        context: &FieldContext<'_, 'n>,
        scope: Scope,
        deferred: &mut Deferred<'n>,
    ) {
        let node = context.node;
        let name = node.protocol.filter_name;
        let key = flatten_abbrev(name);
        let flag = self.flag(context.filter, name);
        let prefix = flatten_abbrev(node.protocol.filter_name);
        for field in &node.fields {
            if field.packet_scoped() {
                deferred.packet_fields.push((field, prefix.clone()));
            }
        }
        if flag == Flag::Filtered {
            push_layer(out, key, Ek::filtered(name));
            for child in &node.children {
                let child_scope = child_scope(node, child, scope);
                if child_scope.nested {
                    if scope.packet_level == 0 {
                        self.collect_escaped(
                            child,
                            child_scope,
                            context.filter,
                            context.frame,
                            &mut deferred.nodes,
                        );
                    }
                } else if scope.nested && scope.packet_level == 0 {
                    deferred.nodes.push((child, child_scope));
                } else {
                    let child_context = FieldContext {
                        node: child,
                        frame: context.frame,
                        sources: context.sources,
                        filter: context.filter,
                    };
                    self.emit_packet_protocol(out, &child_context, child_scope);
                }
            }
            return;
        }
        if self.print_hex {
            let bytes = if node.range.source == 0 && node.source.is_some() {
                let source = node.source.as_deref().unwrap_or(&[]);
                let end = protocol_extent(node, scope, source.len());
                source.get(node.range.offset..end).unwrap_or(&[])
            } else {
                let source_len = crate::raw::source_len(
                    &context.frame.captured,
                    context.sources,
                    node.range.source,
                );
                let end = protocol_extent(node, scope, source_len);
                let length = end.saturating_sub(node.range.offset);
                crate::raw::range_bytes_from(
                    &context.frame.captured,
                    context.sources,
                    node.range.source,
                    node.range.offset,
                    length,
                )
                .unwrap_or(&[])
            };
            if !bytes.is_empty() {
                push_layer(out, format!("{key}_raw"), Ek::string(hex_lower(bytes)));
            }
        }
        let child_state = if matches!(flag, Flag::All | Flag::Expand) {
            ChildState::Off
        } else {
            context.filter
        };
        let fields_context = FieldContext {
            filter: child_state,
            ..*context
        };
        let mut entries: Vec<(String, Ek)> = Vec::with_capacity(node.fields.len());
        for field in node.display_fields() {
            if field.packet_scoped() || omit_from_ek(field.def.abbrev) {
                continue;
            }
            if field.is_container() {
                self.append_container_fields(&mut entries, field, &prefix, &fields_context);
                continue;
            }
            let flat = format!(
                "{}_{}",
                flatten_abbrev(field.def.parent),
                flatten_abbrev(field.def.abbrev)
            );
            self.append_leaf_field(&mut entries, field, &prefix, flat, &fields_context);
        }
        for child in &node.children {
            let child_scope = child_scope(node, child, scope);
            if child_scope.nested && !quote_sibling(child, scope) {
                let child_context = FieldContext {
                    node: child,
                    filter: child_state,
                    ..*context
                };
                self.emit_protocol(&mut entries, &child_context, child_scope, deferred);
            }
        }
        push_layer(out, key, Ek::Object(entries));
        for child in &node.children {
            let child_scope = child_scope(node, child, scope);
            if !child_scope.nested || quote_sibling(child, scope) {
                if scope.nested && scope.packet_level == 0 && !quote_sibling(child, scope) {
                    deferred.nodes.push((child, child_scope));
                } else {
                    let child_context = FieldContext {
                        node: child,
                        filter: child_state,
                        ..*context
                    };
                    self.emit_packet_protocol(out, &child_context, child_scope);
                }
            }
        }
    }

    /// Flatten a container and every descendant into the owning protocol's
    /// object. Each key is prefixed with the protocol name and keeps the
    /// complete field abbreviation, so a child of `tcp.analysis` is
    /// `tcp_tcp_analysis_*` rather than a nested object. EK opens only the
    /// container named with `-J`; its descendants stay under the surrounding
    /// filter state.
    fn append_container_fields(
        &self,
        entries: &mut Vec<(String, Ek)>,
        field: &Field,
        prefix: &str,
        context: &FieldContext<'_, '_>,
    ) {
        if field.def.abbrev.is_empty() {
            self.append_unnamed_container(entries, field, prefix, context);
            return;
        }
        let flag = self.flag(context.filter, field.def.abbrev);
        let flat = format!("{prefix}_{}", flatten_abbrev(field.def.abbrev));
        if flag == Flag::Filtered {
            append_value(entries, flat, Ek::filtered(field.def.abbrev));
            return;
        }
        if self.print_hex
            && let Some(raw) = container_raw(
                field,
                context.frame,
                context.sources,
                context.node.source.as_deref(),
            )
        {
            append_value(entries, format!("{flat}_raw"), raw.into_ek());
        }
        append_value(entries, flat.clone(), ek_value(field));
        let child_state = if flag == Flag::All {
            ChildState::Off
        } else {
            context.filter
        };
        let child_context = FieldContext {
            filter: child_state,
            ..*context
        };
        for child in &field.children {
            if omit_from_ek(child.def.abbrev) || packetfin_core::expert_label_only(child.def.abbrev)
            {
                continue;
            }
            if child.is_container() {
                self.append_container_fields(entries, child, prefix, &child_context);
            } else {
                let flat = format!("{prefix}_{}", flatten_abbrev(child.def.abbrev));
                self.append_leaf_field(entries, child, prefix, flat, &child_context);
            }
        }
        for child in &field.nodes {
            let node_context = FieldContext {
                node: child,
                filter: child_state,
                ..*context
            };
            let nested = self.nested_protocol_entries(&node_context);
            append_value(
                entries,
                flatten_abbrev(child.protocol.filter_name),
                Ek::Object(nested),
            );
        }
        self.append_experts(entries, &field.experts, Some(&flat), child_state);
    }

    /// Flatten a protocol node nested inside a field container.
    fn nested_protocol_entries(&self, context: &FieldContext<'_, '_>) -> Vec<(String, Ek)> {
        let node = context.node;
        let prefix = flatten_abbrev(node.protocol.filter_name);
        let mut entries: Vec<(String, Ek)> = Vec::with_capacity(node.fields.len());
        for field in node.display_fields() {
            if field.packet_scoped() || omit_from_ek(field.def.abbrev) {
                continue;
            }
            if field.is_container() {
                self.append_container_fields(&mut entries, field, &prefix, context);
                continue;
            }
            let flat = format!(
                "{}_{}",
                flatten_abbrev(field.def.parent),
                flatten_abbrev(field.def.abbrev)
            );
            self.append_leaf_field(&mut entries, field, &prefix, flat, context);
        }
        for child in &node.children {
            let node_context = FieldContext {
                node: child,
                frame: context.frame,
                sources: context.sources,
                filter: context.filter,
            };
            let nested = self.nested_protocol_entries(&node_context);
            append_value(
                &mut entries,
                flatten_abbrev(child.protocol.filter_name),
                Ek::Object(nested),
            );
        }
        self.append_experts(&mut entries, &node.experts, None, context.filter);
        entries
    }

    /// Append an unnamed synthetic group.
    ///
    /// Its children flatten into the owning protocol's object exactly
    /// like a named container's children, but the group itself has no key:
    /// its showname is appended to the layer-level `text` array instead. A
    /// nested unnamed group contributes its label at the same position.
    fn append_unnamed_container(
        &self,
        entries: &mut Vec<(String, Ek)>,
        field: &Field,
        prefix: &str,
        context: &FieldContext<'_, '_>,
    ) {
        if self.flag(context.filter, "text") == Flag::Filtered {
            append_value(entries, "text".to_string(), Ek::filtered("text"));
            return;
        }
        if let Some(label) = field.showname_text() {
            append_value(entries, "text".to_string(), Ek::string(label.into_owned()));
        }
        for child in &field.children {
            if omit_from_ek(child.def.abbrev) || packetfin_core::expert_label_only(child.def.abbrev)
            {
                continue;
            }
            if child.is_container() {
                self.append_container_fields(entries, child, prefix, context);
            } else {
                let flat = format!("{prefix}_{}", flatten_abbrev(child.def.abbrev));
                self.append_leaf_field(entries, child, prefix, flat, context);
            }
        }
        for child in &field.nodes {
            let node_context = FieldContext {
                node: child,
                frame: context.frame,
                sources: context.sources,
                filter: context.filter,
            };
            let nested = self.nested_protocol_entries(&node_context);
            append_value(
                entries,
                flatten_abbrev(child.protocol.filter_name),
                Ek::Object(nested),
            );
        }
        let offending = field.expert_field.map(|definition| {
            format!(
                "{}_{}",
                flatten_abbrev(definition.parent),
                flatten_abbrev(definition.abbrev)
            )
        });
        self.append_experts(
            entries,
            &field.experts,
            offending.as_deref(),
            context.filter,
        );
    }

    /// Append one leaf. Container descendants and protocol fields both use
    /// the same flattened key and filter state.
    fn append_leaf_field(
        &self,
        entries: &mut Vec<(String, Ek)>,
        field: &Field,
        prefix: &str,
        flat: String,
        context: &FieldContext<'_, '_>,
    ) {
        let flag = self.flag(context.filter, field.def.abbrev);
        if !field.experts.is_empty() {
            if field.value != Value::None && field.value != Value::Missing {
                self.append_plain_leaf(entries, field, &flat, flag, context);
            }
            let offending = field.expert_field.map_or(flat.clone(), |definition| {
                format!(
                    "{}_{}",
                    flatten_abbrev(definition.parent),
                    flatten_abbrev(definition.abbrev)
                )
            });
            self.append_experts(entries, &field.experts, Some(&offending), context.filter);
            self.append_leaf_children(entries, field, prefix, context);
            return;
        }
        self.append_plain_leaf(entries, field, &flat, flag, context);
        self.append_leaf_children(entries, field, prefix, context);
        if field.def.abbrev.ends_with(".checksum")
            && let Some(expert) = context
                .node
                .experts
                .iter()
                .find(|expert| expert.group == packetfin_core::Group::Checksum)
        {
            let offending = format!(
                "{}_{}",
                flatten_abbrev(context.node.protocol.filter_name),
                flatten_abbrev(&json::checksum_bad_abbrev(field.def.abbrev))
            );
            self.append_experts(
                entries,
                std::slice::from_ref(expert),
                Some(&offending),
                context.filter,
            );
            if let Some(calculated) =
                json::checksum_calculated_abbrev(field.def.abbrev).and_then(|abbrev| {
                    context
                        .node
                        .fields
                        .iter()
                        .find(|candidate| candidate.def.abbrev == abbrev)
                })
            {
                let flat = format!(
                    "{}_{}",
                    flatten_abbrev(calculated.def.parent),
                    flatten_abbrev(calculated.def.abbrev)
                );
                self.append_plain_leaf(entries, calculated, &flat, flag, context);
            }
        }
    }

    /// Flatten a leaf's own children into the protocol object.
    ///
    /// A field can own a subtree: the DHCP option-82 vendor block nests its
    /// data length under the enterprise number. EK keeps every key flat, so a
    /// child repeats the protocol prefix and the child's full abbreviation.
    fn append_leaf_children(
        &self,
        entries: &mut Vec<(String, Ek)>,
        field: &Field,
        prefix: &str,
        context: &FieldContext<'_, '_>,
    ) {
        for child in &field.children {
            if omit_from_ek(child.def.abbrev) || packetfin_core::expert_label_only(child.def.abbrev)
            {
                continue;
            }
            if child.is_container() {
                self.append_container_fields(entries, child, prefix, context);
            } else {
                let flat = format!("{prefix}_{}", flatten_abbrev(child.def.abbrev));
                self.append_leaf_field(entries, child, prefix, flat, context);
            }
        }
    }

    fn append_plain_leaf(
        &self,
        entries: &mut Vec<(String, Ek)>,
        field: &Field,
        flat: &str,
        flag: Flag,
        context: &FieldContext<'_, '_>,
    ) {
        if flag == Flag::Filtered {
            append_value(entries, flat.to_string(), Ek::filtered(field.def.abbrev));
            return;
        }
        if self.print_hex
            && let Some(raw) = raw_field_value(
                field,
                context.frame,
                context.sources,
                context.node.source.as_deref(),
            )
        {
            append_value(entries, format!("{flat}_raw"), raw.into_ek());
        }
        append_value(entries, flat.to_string(), ek_value(field));
    }

    fn append_experts(
        &self,
        entries: &mut Vec<(String, Ek)>,
        experts: &[packetfin_core::tree::ExpertInfo],
        offending: Option<&str>,
        state: ChildState<'_>,
    ) {
        if experts.is_empty() {
            return;
        }
        if self.flag(state, "_ws.expert") == Flag::Filtered {
            append_value(
                entries,
                "_ws_expert".to_string(),
                Ek::filtered("_ws.expert"),
            );
            return;
        }
        for expert in experts {
            append_value(
                entries,
                "_ws_expert".to_string(),
                expert_value(expert, offending),
            );
            if expert.group == packetfin_core::Group::Malformed
                && !entries.iter().any(|(key, _)| key == "_ws_malformed")
            {
                append_value(entries, "_ws_malformed".to_string(), Ek::Object(Vec::new()));
            }
        }
    }

    fn collect_escaped<'n>(
        &self,
        node: &'n Node,
        scope: Scope,
        state: ChildState<'_>,
        frame: &Frame,
        escaped: &mut Vec<(&'n Node, Scope)>,
    ) {
        let _ = (state, frame);
        for child in &node.children {
            let child_scope = child_scope(node, child, scope);
            if child_scope.nested {
                self.collect_escaped(child, child_scope, state, frame, escaped);
            } else {
                escaped.push((child, child_scope));
            }
        }
    }

    fn comment_layer(&self, layers: &mut Vec<(String, Ek)>, frame: &Frame, state: ChildState<'_>) {
        if frame.comments.is_empty() {
            return;
        }
        let flag = self.flag(state, "pkt_comment");
        if flag == Flag::Filtered {
            push_layer(
                layers,
                "pkt_comment".to_string(),
                Ek::filtered("pkt_comment"),
            );
            return;
        }
        let mut entries: Vec<(String, Ek)> = Vec::new();
        if flag == Flag::Open {
            entries.push((
                "frame_frame_comment".to_string(),
                Ek::filtered("frame.comment"),
            ));
        } else {
            let mut values: Vec<Ek> = Vec::new();
            for comment in &frame.comments {
                if comment.contains('\n') {
                    let first = comment.split('\n').next().unwrap_or(comment);
                    values.push(Ek::string(first));
                    for line in comment.split('\n') {
                        values.push(Ek::string(line));
                    }
                    values.push(Ek::string(comment));
                } else {
                    values.push(Ek::string(comment));
                }
            }
            let value = if values.len() == 1 {
                values.pop().unwrap_or(Ek::Null)
            } else {
                Ek::Array(values)
            };
            entries.push(("frame_frame_comment".to_string(), value));
            for comment in &frame.comments {
                let expert = Ek::Object(vec![
                    (
                        "_ws_expert__ws_expert_severity".to_string(),
                        Ek::string("1048576"),
                    ),
                    ("frame_frame_comment_expert".to_string(), Ek::Null),
                    (
                        "_ws_expert__ws_expert_message".to_string(),
                        Ek::string(comment.clone()),
                    ),
                    (
                        "_ws_expert__ws_expert_group".to_string(),
                        Ek::string("184549376"),
                    ),
                ]);
                append_value(&mut entries, "_ws_expert".to_string(), expert);
            }
        }
        push_layer(layers, "pkt_comment".to_string(), Ek::Object(entries));
    }

    fn frame_layer(&self, frame: &Frame, packet: &Packet, times: Option<&FrameTimes>) -> Ek {
        let mut entries: Vec<(String, Ek)> = Vec::new();
        if let Some(section) = frame.section_number {
            entries.push((
                "frame_frame_section_number".to_string(),
                Ek::string(section.to_string()),
            ));
            entries.push((
                "frame_frame_interface_id".to_string(),
                Ek::string(frame.interface_id.to_string()),
            ));
            entries.push((
                "frame_frame_interface_name".to_string(),
                Ek::string(
                    frame
                        .interface_name
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                ),
            ));
        }
        entries.push((
            "frame_frame_encap_type".to_string(),
            Ek::string(detail::encapsulation(frame.link_type).1.to_string()),
        ));
        if let (Some(times), Some(timestamp)) = (times, frame.timestamp) {
            let text = json::absolute_time(timestamp);
            entries.push(("frame_frame_time".to_string(), Ek::string(text.clone())));
            entries.push(("frame_frame_time_utc".to_string(), Ek::string(text.clone())));
            entries.push(("frame_frame_time_epoch".to_string(), Ek::string(text)));
            entries.push((
                "frame_frame_offset_shift".to_string(),
                Ek::string("0.000000000"),
            ));
            if let Some(delta) = &times.delta {
                entries.push((
                    "frame_frame_time_delta".to_string(),
                    Ek::string(delta.clone()),
                ));
            }
            if let Some(delta) = &times.delta_displayed {
                entries.push((
                    "frame_frame_time_delta_displayed".to_string(),
                    Ek::string(delta.clone()),
                ));
            }
            entries.push((
                "frame_frame_time_relative".to_string(),
                Ek::string(times.relative.clone()),
            ));
        }
        entries.push((
            "frame_frame_number".to_string(),
            Ek::string(frame.number.to_string()),
        ));
        entries.push((
            "frame_frame_len".to_string(),
            Ek::string(frame.original_len.to_string()),
        ));
        entries.push((
            "frame_frame_cap_len".to_string(),
            Ek::string(frame.captured.len().to_string()),
        ));
        entries.push(("frame_frame_marked".to_string(), Ek::Bool(false)));
        entries.push(("frame_frame_ignored".to_string(), Ek::Bool(false)));
        entries.push((
            "frame_frame_protocols".to_string(),
            Ek::string(detail::protocols_in_frame(packet, frame)),
        ));
        entries.push(("frame_frame_encoding".to_string(), Ek::string("0")));
        Ek::Object(entries)
    }

    fn data_layer(
        &self,
        layers: &mut Vec<(String, Ek)>,
        frame: &Frame,
        packet: &Packet,
        state: ChildState<'_>,
    ) {
        let Some(length) = detail::root_data_length(packet) else {
            return;
        };
        let Some(offset) = frame.captured.len().checked_sub(length) else {
            return;
        };
        let bytes = frame
            .captured
            .get(offset..offset.saturating_add(length))
            .unwrap_or(&[]);
        let flag = self.flag(state, "data");
        if flag == Flag::Filtered {
            push_layer(layers, "data".to_string(), Ek::filtered("data"));
            return;
        }
        let mut entries = vec![("data_data_len".to_string(), Ek::string(length.to_string()))];
        if self.print_hex {
            entries.push((
                "data_data_data_raw".to_string(),
                Ek::string(hex_lower(bytes)),
            ));
        }
        entries.push(("data_data_data".to_string(), Ek::string(colon_hex(bytes))));
        push_layer(layers, "data".to_string(), Ek::Object(entries));
    }

    fn advance(&mut self, timestamp: Option<Timestamp>, displayed: bool) -> Option<FrameTimes> {
        let Some(timestamp) = timestamp else {
            self.previous_captured = None;
            self.previous_displayed = None;
            return None;
        };
        let relative = match self.first_timestamp {
            Some(first) => json::relative_time(timestamp, first),
            None => {
                self.first_timestamp = Some(timestamp);
                "0.000000000".to_string()
            }
        };
        let delta = self
            .previous_captured
            .map(|previous| json::relative_time(timestamp, previous));
        let delta_displayed = if displayed {
            self.previous_displayed
                .map(|previous| json::relative_time(timestamp, previous))
        } else {
            None
        };
        self.previous_captured = Some(timestamp);
        if displayed {
            self.previous_displayed = Some(timestamp);
        }
        Some(FrameTimes {
            relative,
            delta,
            delta_displayed,
        })
    }

    fn flag(&self, state: ChildState<'_>, name: &str) -> Flag {
        match state {
            ChildState::Off => Flag::All,
            ChildState::Active(filter) => match filter.flags(name) {
                None => Flag::Filtered,
                Some(true) => Flag::Expand,
                Some(false) => Flag::Open,
            },
        }
    }
}

struct FrameTimes {
    relative: String,
    delta: Option<String>,
    delta_displayed: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flag {
    All,
    Open,
    Expand,
    Filtered,
}

#[derive(Clone, Copy, Debug)]
enum ChildState<'a> {
    Off,
    Active(&'a ProtocolFilter),
}

/// The node, frame and filter state shared by the EK field walk.
type FieldContext<'a, 'n> = RenderContext<'a, 'n, ChildState<'a>>;

/// Work deferred until the current protocol subtree is complete.
#[derive(Default)]
struct Deferred<'n> {
    nodes: Vec<(&'n Node, Scope)>,
    packet_fields: Vec<(&'n Field, String)>,
}

/// Add a layer, merging a repeated protocol key into the existing object.
fn push_layer(layers: &mut Vec<(String, Ek)>, key: String, value: Ek) {
    if let Some((_, existing)) = layers.iter_mut().find(|(stored, _)| *stored == key) {
        if let (Ek::Object(existing), Ek::Object(added)) = (existing, value) {
            existing.extend(added);
        }
        return;
    }
    layers.push((key, value));
}

/// Add a value under a flattened key, turning a repeat into an array.
fn append_value(entries: &mut Vec<(String, Ek)>, key: String, value: Ek) {
    if let Some((_, existing)) = entries.iter_mut().find(|(stored, _)| *stored == key) {
        match existing {
            Ek::Array(values) => values.push(value),
            previous => {
                let first = std::mem::replace(previous, Ek::Null);
                *previous = Ek::Array(vec![first, value]);
            }
        }
    } else {
        entries.push((key, value));
    }
}

fn ek_value(field: &Field) -> Ek {
    match &field.value {
        Value::Boolean(value) => Ek::Bool(*value),
        Value::None => Ek::Null,
        Value::Missing => Ek::string(String::new()),
        Value::AbsoluteTime(timestamp) => Ek::String(json::absolute_time(*timestamp)),
        Value::Uint8(value) => Ek::string(value.to_string()),
        Value::Uint16(value) => Ek::string(value.to_string()),
        Value::Uint24(value) => Ek::string(value.to_string()),
        Value::Uint32(value) => Ek::string(value.to_string()),
        Value::Uint64(value) => Ek::string(value.to_string()),
        Value::Int8(value) => Ek::string(value.to_string()),
        Value::Int16(value) => Ek::string(value.to_string()),
        Value::Int32(value) => Ek::string(value.to_string()),
        Value::Int64(value) => Ek::string(value.to_string()),
        Value::Bytes(bytes) => Ek::Bytes(bytes.clone()),
        value => Ek::string(value.render(Display::None)),
    }
}

enum RawValue {
    Bytes(Bytes),
    Text(String),
}

impl RawValue {
    fn into_ek(self) -> Ek {
        match self {
            Self::Bytes(bytes) => Ek::Hex(bytes),
            Self::Text(text) => Ek::string(text),
        }
    }
}

fn container_raw(
    field: &Field,
    frame: &Frame,
    sources: &[Bytes],
    node_source: Option<&[u8]>,
) -> Option<RawValue> {
    if let Some(raw) = &field.raw {
        return (raw.length > 0 || !raw.bytes.is_empty())
            .then(|| RawValue::Bytes(raw.bytes.clone()));
    }
    if let Value::Bytes(bytes) = &field.value
        && !bytes.is_empty()
    {
        return Some(RawValue::Bytes(bytes.clone()));
    }
    raw_field_value(field, frame, sources, node_source)
}

fn expert_value(expert: &packetfin_core::tree::ExpertInfo, offending: Option<&str>) -> Ek {
    let mut entries = Vec::with_capacity(4);
    if let Some(offending) = offending {
        entries.push((offending.to_string(), Ek::Null));
    }
    entries.push((
        "_ws_expert__ws_expert_message".to_string(),
        Ek::string(expert.message.clone()),
    ));
    entries.push((
        "_ws_expert__ws_expert_severity".to_string(),
        Ek::string(json::severity_value(expert.severity).to_string()),
    ));
    entries.push((
        "_ws_expert__ws_expert_group".to_string(),
        Ek::string(json::group_value(expert.group).to_string()),
    ));
    Ek::Object(entries)
}

fn raw_field_value(
    field: &Field,
    frame: &Frame,
    sources: &[Bytes],
    node_source: Option<&[u8]>,
) -> Option<RawValue> {
    if let Some(raw) = &field.raw {
        return (raw.length > 0 || !raw.bytes.is_empty())
            .then(|| RawValue::Bytes(raw.bytes.clone()));
    }
    let source = if field.range.source != 0 {
        field
            .range
            .source
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| sources.get(index))
            .map(|bytes| bytes.as_slice())
    } else {
        node_source
    };
    if !mask::pattern_only(field.def.abbrev)
        && let Some(masked) = mask::masked_field(field, frame, source)
    {
        return Some(RawValue::Text(masked.value));
    }
    if field.range.source == 0
        && let Some(bytes) = node_source
    {
        let end = field
            .range
            .offset
            .saturating_add(field.range.length)
            .min(bytes.len());
        return Some(RawValue::Bytes(Bytes::from(
            bytes.get(field.range.offset..end).unwrap_or(&[]).to_vec(),
        )));
    }
    Some(RawValue::Bytes(Bytes::from(crate::raw::raw_bytes(
        frame,
        sources,
        field.range,
    ))))
}

fn quote_sibling(child: &Node, scope: Scope) -> bool {
    scope.nested && scope.packet_level > 0 && !detail::is_extension(child.protocol.filter_name)
}

fn protocol_extent(node: &Node, scope: Scope, captured_len: usize) -> usize {
    let captured_len = node
        .source
        .as_ref()
        .map_or(captured_len, |source| source.len());
    let start = node.range.offset;
    let mut end = if detail::is_extension(node.protocol.filter_name) {
        extension_extent(node, scope, captured_len)
    } else {
        json::fields_end(node)
    };
    for child in &node.children {
        let child_scope = child_scope(node, child, scope);
        if child_scope.nested && !quote_sibling(child, scope) {
            end = end.max(nested_extent(child, child_scope, captured_len));
        }
    }
    end.min(captured_len.max(start))
}

fn nested_extent(node: &Node, scope: Scope, captured_len: usize) -> usize {
    let captured_len = node
        .source
        .as_ref()
        .map_or(captured_len, |source| source.len());
    if detail::is_extension(node.protocol.filter_name) {
        extension_extent(node, scope, captured_len)
    } else {
        node.range
            .offset
            .saturating_add(node.range.length)
            .min(captured_len)
    }
}

fn extension_extent(node: &Node, scope: Scope, captured_len: usize) -> usize {
    let captured_len = node
        .source
        .as_ref()
        .map_or(captured_len, |source| source.len());
    let start = node.range.offset;
    let mut end = json::fields_end(node);
    if let Some(declared) = json::extension_declared_length(node) {
        end = end.min(start.saturating_add(declared));
    }
    end = end.min(captured_len).max(start);
    for child in &node.children {
        let child_scope = child_scope(node, child, scope);
        if detail::is_extension(child.protocol.filter_name) {
            end = end.max(extension_extent(child, child_scope, captured_len));
        }
    }
    end
}

fn malformed_node(node: &Node) -> Option<&Node> {
    if node.protocol_exception {
        return Some(node);
    }
    node.children.iter().find_map(malformed_node)
}

fn flatten_abbrev(abbrev: &str) -> String {
    abbrev.replace('.', "_")
}

fn omit_from_ek(abbrev: &str) -> bool {
    abbrev.ends_with(".checksum_calculated") || packetfin_core::expert_label_only(abbrev)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn colon_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            text.push(':');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn write_compact(writer: &mut impl Write, value: &Ek) -> io::Result<()> {
    match value {
        Ek::Null => writer.write_all(b"null"),
        Ek::Bool(value) => writer.write_all(if *value { b"true" } else { b"false" }),
        Ek::String(text) => json::write_json_string(writer, text),
        Ek::Bytes(bytes) => {
            writer.write_all(b"\"")?;
            json::write_colon_hex(writer, bytes.as_slice())?;
            writer.write_all(b"\"")
        }
        Ek::Hex(bytes) => {
            writer.write_all(b"\"")?;
            json::write_hex_lower(writer, bytes.as_slice())?;
            writer.write_all(b"\"")
        }
        Ek::Array(values) => {
            writer.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    writer.write_all(b",")?;
                }
                write_compact(writer, value)?;
            }
            writer.write_all(b"]")
        }
        Ek::Object(entries) => {
            writer.write_all(b"{")?;
            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    writer.write_all(b",")?;
                }
                json::write_json_string(writer, key)?;
                writer.write_all(b":")?;
                write_compact(writer, value)?;
            }
            writer.write_all(b"}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetfin_core::tree::FieldParent;

    fn render_ek(tree: packetfin_core::Tree, fields: &'static [&'static FieldDef]) -> String {
        render_ek_options(tree, fields, false, &[])
    }

    fn render_ek_options(
        tree: packetfin_core::Tree,
        fields: &'static [&'static FieldDef],
        print_hex: bool,
        names: &[(&str, bool)],
    ) -> String {
        let tokens: Vec<(String, bool)> = names
            .iter()
            .map(|(name, children)| ((*name).to_string(), *children))
            .collect();
        let filter = ProtocolFilter::new(&tokens);
        let frame = crate::test_support::frame();
        let packet = crate::test_support::packet(tree);
        let mut writer = EkWriter::new(
            filter.as_ref(),
            fields,
            print_hex,
            false,
            TimeOptions::default(),
        );
        let mut output = Vec::new();
        assert!(writer.write_packet(&mut output, &frame, &packet).is_ok());
        String::from_utf8(output).unwrap_or_default()
    }

    fn layer_depth(text: &str, needle: &str) -> usize {
        const LAYERS: &str = "\"layers\":{";
        let Some(start) = text.find(LAYERS).map(|index| index + LAYERS.len()) else {
            return 0;
        };
        let Some(position) = text.find(needle) else {
            return 0;
        };
        let Some(slice) = text.get(start..position) else {
            return 0;
        };
        let mut depth = 1_usize;
        for byte in slice.bytes() {
            match byte {
                b'{' => depth += 1,
                b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        depth
    }

    #[test]
    fn dhcp_option_strings_use_ek_escapes() {
        let mut frame_node = Node::new(
            &packetfin_core::fields::FRAME_PROTOCOL,
            packetfin_core::Range::new(0, 64),
        );
        frame_node.add_field(
            &packetfin_core::fields::FRAME_NUMBER,
            packetfin_core::Range::new(0, 0),
            Value::Uint32(1),
        );
        let mut dhcp = Node::new(
            &packetfin_core::fields::DHCP_PROTOCOL,
            packetfin_core::Range::new(42, 20),
        );
        let option = dhcp.add_container(
            &packetfin_core::fields::DHCP_OPTION_TYPE,
            packetfin_core::Range::new(42, 10),
            Some("Option: (12) Host Name".to_string()),
        );
        option.value = Value::Uint8(12);
        option.add_field(
            &packetfin_core::fields::DHCP_OPTION_HOSTNAME,
            packetfin_core::Range::new(44, 6),
            Value::String("a\"b\\c\n".to_string()),
        );
        frame_node.add_child(dhcp);
        let text = render_ek(packetfin_core::Tree::new(frame_node), &[]);
        assert!(
            text.contains(r#""dhcp_dhcp_option_hostname":"a\"b\\c\n""#),
            "{text}"
        );
    }

    #[test]
    fn unnamed_groups_contribute_text_and_hidden_fields_stay() {
        let tree = crate::test_support::tcp_tree(|node| {
            let group = node.add_unnamed(packetfin_core::Range::new(34, 0), "A \"B\"".to_string());
            group.add_field(
                &packetfin_core::fields::TCP_SEQ,
                packetfin_core::Range::new(34, 4),
                Value::Uint32(7),
            );
            node.add_field(
                &packetfin_core::fields::TCP_ACK,
                packetfin_core::Range::new(38, 4),
                Value::Uint32(9),
            )
            .hide();
        });
        let text = render_ek(tree, &[]);
        assert!(text.contains("\"text\":\"A \\\"B\\\"\""), "{text}");
        assert!(text.contains("\"tcp_tcp_seq\":[\"1\",\"7\"]"), "{text}");
        assert!(text.contains("\"tcp_tcp_ack\":\"9\""), "{text}");
    }

    #[test]
    fn container_children_flatten_into_the_tcp_layer() {
        let text = render_ek(crate::test_support::analysis_tree(), &[]);
        assert!(text.contains("\"tcp_tcp_analysis\":null"), "{text}");
        assert!(
            text.contains("\"tcp_tcp_analysis_acks_frame\":\"1\""),
            "{text}"
        );
        assert!(text.contains("\"tcp_tcp_analysis_flags\":null"), "{text}");
        assert!(text.contains("\"tcp_tcp_analysis_rto\":\"1\""), "{text}");
        assert!(
            text.contains(
                "\"_ws_expert\":{\"tcp_tcp_analysis_retransmission\":null,\"_ws_expert__ws_expert_message\":\"This frame is a (suspected) retransmission\",\"_ws_expert__ws_expert_severity\":\"4194304\",\"_ws_expert__ws_expert_group\":\"33554432\"}"
            ),
            "{text}"
        );
    }

    #[test]
    fn bytes_container_keeps_its_value_and_children() {
        let text = render_ek(crate::test_support::fragments_tree(), &[]);
        assert!(
            text.contains(
                "\"ip_ip_fragments\":\"00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f\""
            ),
            "{text}"
        );
        assert!(text.contains("\"ip_ip_fragment\":[\"1\",\"2\"]"), "{text}");
    }

    #[test]
    fn packet_scoped_container_is_a_layer_root_key() {
        let text = render_ek(crate::test_support::segments_tree(), &[]);
        assert!(text.contains("\"tcp_tcp_segments\":null"), "{text}");
        assert!(text.contains("\"tcp_tcp_segment\":[\"4\",\"5\"]"), "{text}");
        assert_eq!(layer_depth(&text, "\"tcp_tcp_segments\""), 1);
        assert_eq!(layer_depth(&text, "\"tcp_tcp_seq\""), 2);
    }

    #[test]
    fn selected_fields_flatten_to_their_parent_keys() {
        static FIELDS: [&FieldDef; 3] = [
            &crate::test_support::SEGMENTS,
            &crate::test_support::SEGMENT,
            &crate::test_support::SEGMENT_COUNT,
        ];
        let text = render_ek(crate::test_support::segments_tree(), &FIELDS);
        assert!(text.contains("\"tcp_segments\":[\"1\"]"), "{text}");
        assert!(text.contains("\"tcp_segment\":[\"4\",\"5\"]"), "{text}");
        assert!(text.contains("\"tcp_segment_count\":[\"2\"]"), "{text}");
    }

    #[test]
    fn container_raw_uses_the_synthetic_bytes() {
        let fragments = render_ek_options(crate::test_support::fragments_tree(), &[], true, &[]);
        assert!(
            fragments.contains(
                "\"ip_ip_fragments_raw\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\""
            ),
            "{fragments}"
        );
        assert!(
            fragments.contains("\"ip_ip_fragment_raw\":[\"000102030405060708090a0b0c0d0e0f\",\"101112131415161718191a1b1c1d1e1f\"]"),
            "{fragments}"
        );

        let segments = render_ek_options(crate::test_support::segments_tree(), &[], true, &[]);
        assert!(
            segments.contains(
                "\"tcp_tcp_segments_raw\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e\""
            ),
            "{segments}"
        );
    }

    #[test]
    fn ek_filters_container_fields_by_name() {
        let filtered = render_ek_options(
            crate::test_support::analysis_tree(),
            &[],
            false,
            &[("tcp", false)],
        );
        assert!(
            filtered.contains("\"tcp_tcp_analysis\":{\"filtered\":\"tcp.analysis\"}"),
            "{filtered}"
        );
        assert!(
            !filtered.contains("tcp_tcp_analysis_acks_frame"),
            "{filtered}"
        );

        let open = render_ek_options(
            crate::test_support::analysis_tree(),
            &[],
            false,
            &[("tcp", false), ("tcp.analysis", false)],
        );
        assert!(open.contains("\"tcp_tcp_analysis\":null"), "{open}");
        assert!(
            open.contains(
                "\"tcp_tcp_analysis_acks_frame\":{\"filtered\":\"tcp.analysis.acks_frame\"}"
            ),
            "{open}"
        );

        let expanded = render_ek_options(
            crate::test_support::analysis_tree(),
            &[],
            false,
            &[("tcp", true)],
        );
        assert!(
            expanded.contains("\"tcp_tcp_analysis_acks_frame\":\"1\""),
            "{expanded}"
        );
        assert!(
            expanded.contains("\"tcp_tcp_analysis_retransmission\":null"),
            "{expanded}"
        );
    }

    #[test]
    fn ek_filters_experts_with_the_expert_pseudo_field() {
        let text = render_ek_options(
            crate::test_support::analysis_tree(),
            &[],
            false,
            &[
                ("tcp", false),
                ("tcp.analysis", false),
                ("tcp.analysis.flags", false),
            ],
        );
        assert!(
            text.contains("\"_ws_expert\":{\"filtered\":\"_ws.expert\"}"),
            "{text}"
        );
    }

    #[test]
    fn ek_filters_packet_scoped_container_by_outer_state() {
        for names in [
            &[("tcp", false)][..],
            &[("tcp", true)][..],
            &[("dns", false)][..],
        ] {
            let text = render_ek_options(crate::test_support::segments_tree(), &[], false, names);
            assert!(
                text.contains("\"tcp_tcp_segments\":{\"filtered\":\"tcp.segments\"}"),
                "{text}"
            );
        }

        let one_level = render_ek_options(
            crate::test_support::segments_tree(),
            &[],
            false,
            &[("tcp", false), ("tcp.segments", true)],
        );
        assert!(
            one_level.contains("\"tcp_tcp_segments\":null"),
            "{one_level}"
        );
        assert!(
            one_level.contains("\"tcp_tcp_segment\":[{\"filtered\":\"tcp.segment\"},{\"filtered\":\"tcp.segment\"}]"),
            "{one_level}"
        );
    }
}
