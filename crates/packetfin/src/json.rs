//! `-T json` and `-T jsonraw` output.
//!
//! The output is a pretty-printed array of packets. Each packet has an
//! Elasticsearch-style envelope: `_index`, `_score` and `_source.layers`,
//! where `layers` holds one entry per protocol in decode order. Repeated keys
//! stay repeated unless `--no-duplicate-keys` merges them into arrays, and
//! `jsonraw` replaces every value with
//! `[value, start, length, bitmask, type, source]`.
//!
//! Packetfin serialises its own decoded tree, so generated helpers that are
//! not part of this tree (address trees, host aliases, stream indexes, field
//! subtrees and DNS record groups) have no keys. The frame layer is
//! synthesised from capture metadata because Packetfin's frame node keeps only
//! the fields the decoders need.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, Write};

use packetfin_core::tree::Bytes;
use packetfin_core::{
    DataSourceKind, Display, Field, FieldDef, FieldType, Frame, Node, Packet, Timestamp, Tree,
    Value, field_by_abbrev,
};

use crate::detail::{self, Scope, child_scope};
use crate::render_context::RenderContext;
use crate::summary::{capture_limited, civil_time};

/// Which JSON flavour the invocation requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonMode {
    /// `-T json`: display strings.
    Json,
    /// `-T jsonraw`: raw value arrays.
    JsonRaw,
}

/// The `-j`/`-J` protocol selection.
///
/// A name maps to the flag its last occurrence supplied: `true` expands the
/// whole subtree (`-J`), `false` expands only the named level (`-j`). An
/// absent name filters the node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolFilter {
    entries: Vec<(String, bool)>,
}

impl ProtocolFilter {
    /// Build a filter from already validated `(name, include children)` pairs.
    ///
    /// Returns `None` when no names were supplied, which means no protocol
    /// filter; an empty filter list does not filter anything.
    pub fn new(tokens: &[(String, bool)]) -> Option<Self> {
        if tokens.is_empty() {
            return None;
        }
        let mut entries: Vec<(String, bool)> = Vec::with_capacity(tokens.len());
        for (name, include_children) in tokens {
            match entries.iter_mut().find(|(existing, _)| existing == name) {
                Some((_, flags)) => *flags = *include_children,
                None => entries.push((name.clone(), *include_children)),
            }
        }
        Some(Self { entries })
    }

    /// The flag recorded for `name`, with the last occurrence winning.
    pub(crate) fn flags(&self, name: &str) -> Option<bool> {
        self.entries
            .iter()
            .find(|(existing, _)| existing == name)
            .map(|(_, include_children)| *include_children)
    }
}

/// Whether a node's children are written or replaced by a `filtered` marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flag {
    /// Write the node and keep filtering its children.
    Open,
    /// Write the node and every descendant (`-J`).
    ExpandChildren,
    /// Replace the node with `{ "filtered": "<key>" }`.
    Filtered,
}

/// The filter state that applies to one node's children.
#[derive(Clone, Copy, Debug)]
enum ChildState<'a> {
    /// No protocol filter is active.
    Off,
    /// Names not in the filter are hidden.
    Active(&'a ProtocolFilter),
}

/// A JSON value in the shapes this writer needs.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Null,
    String(String),
    /// Bytes rendered as colon-separated lowercase hex by the serializer.
    Bytes(Bytes),
    /// Bytes rendered as plain lowercase hex by the serializer.
    Hex(Bytes),
    Number(String),
    Array(Vec<Json>),
    Object {
        entries: Vec<(String, Json)>,
        merge_keys: bool,
    },
}

impl From<String> for Json {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl Json {
    fn object(entries: Vec<(String, Json)>, merge_keys: bool) -> Self {
        Self::Object {
            entries,
            merge_keys,
        }
    }

    fn filtered(key: &str) -> Self {
        Self::object(
            vec![("filtered".to_string(), Self::String(key.to_string()))],
            false,
        )
    }

    fn number(value: impl ToString) -> Self {
        Self::Number(value.to_string())
    }
}

/// One protocol layer and the protocol subtrees written inside it.
///
/// Packetfin nests protocols by decoder call order. JSON output puts a
/// normal next-layer protocol at the top level of `layers`, and only keeps
/// IPv6 extension headers and quoted datagrams inside their parent. The
/// scope rules below mirror the detail view's indentation rules, so both
/// outputs agree on what is a layer and what is a subtree.
struct Layer<'n> {
    node: &'n Node,
    nested: Vec<Layer<'n>>,
}

/// Build the top-level layer list from the frame node's children.
///
/// The flat walk records each protocol's display level. Nodes whose level is
/// deeper than their parent belong inside that parent's object; nodes at the
/// same or a shallower level are siblings in the nearest matching container.
/// This makes an IPv6 extension chain and a quoted transport appear beside
/// their peers instead of nesting by decoder call order.
fn build_top_layers(children: &[Node]) -> Vec<Layer<'_>> {
    let mut flat: Vec<(&Node, usize)> = Vec::new();
    let scope = Scope {
        level: 0,
        selectable: true,
        nested: false,
        packet_level: 0,
    };
    for child in children {
        walk_layers(child, scope, &mut flat);
    }

    let mut top: Vec<Layer<'_>> = Vec::new();
    let mut stack: Vec<Layer<'_>> = Vec::new();
    for (node, level) in flat {
        finish_layers(&mut stack, &mut top, level);
        stack.push(Layer {
            node,
            nested: Vec::new(),
        });
    }
    finish_layers(&mut stack, &mut top, 0);
    top
}

/// Record every protocol node with its display level, in preorder.
fn walk_layers<'n>(node: &'n Node, scope: Scope, flat: &mut Vec<(&'n Node, usize)>) {
    flat.push((node, scope.level));
    for child in &node.children {
        walk_layers(child, child_scope(node, child, scope), flat);
    }
}

/// Close every layer at `level` or deeper into its parent container.
fn finish_layers<'n>(stack: &mut Vec<Layer<'n>>, top: &mut Vec<Layer<'n>>, level: usize) {
    while stack.len() > level {
        if let Some(finished) = stack.pop() {
            match stack.last_mut() {
                Some(parent) => parent.nested.push(finished),
                None => top.push(finished),
            }
        }
    }
}

/// Frame timing values that depend on the frames read and displayed so far.
struct FrameTimes {
    relative: String,
    delta: Option<String>,
    delta_displayed: Option<String>,
}

/// Streaming `-T json`/`-T jsonraw` writer for one invocation.
pub struct JsonWriter<'a> {
    mode: JsonMode,
    filter: Option<&'a ProtocolFilter>,
    merge_keys: bool,
    /// Requested `-e` fields; empty means the whole tree.
    fields: &'a [&'static FieldDef],
    /// `-x`/`--hexdump`: plain JSON also emits each field's raw array.
    print_hex: bool,
    started: bool,
    first_timestamp: Option<Timestamp>,
    previous_captured: Option<Timestamp>,
    previous_displayed: Option<Timestamp>,
}

/// Filter state plus the data-source kinds needed by raw JSON values.
#[derive(Clone, Copy)]
struct FieldFilter<'a> {
    state: ChildState<'a>,
    kinds: &'a [DataSourceKind],
}

/// The node, frame and filter state shared by the JSON field walk.
type FieldContext<'a, 'n> = RenderContext<'a, 'n, FieldFilter<'a>>;

impl<'a> JsonWriter<'a> {
    /// Prepare a writer for one invocation.
    pub fn new(
        mode: JsonMode,
        filter: Option<&'a ProtocolFilter>,
        merge_keys: bool,
        fields: &'a [&'static FieldDef],
        print_hex: bool,
    ) -> Self {
        Self {
            mode,
            filter,
            merge_keys,
            fields,
            print_hex,
            started: false,
            first_timestamp: None,
            previous_captured: None,
            previous_displayed: None,
        }
    }

    /// Record a frame that the display filter hides.
    ///
    /// Hidden frames still advance the captured-frame delta used by later
    /// frames, but not the displayed-frame delta.
    pub fn observe_hidden(&mut self, frame: &Frame) {
        self.advance(frame.timestamp, false);
    }

    /// Write one displayed packet.
    pub fn write_packet(
        &mut self,
        writer: &mut impl Write,
        frame: &Frame,
        packet: &Packet,
    ) -> io::Result<()> {
        let times = self.advance(frame.timestamp, true);
        if self.started {
            writer.write_all(b",")?;
        } else {
            writer.write_all(b"[")?;
            self.started = true;
        }
        writer.write_all(b"\n  ")?;
        let layers = if self.fields.is_empty() {
            self.packet_layers(frame, packet, times.as_ref())
        } else {
            specified_fields_object(&packet.tree, self.fields, self.merge_keys)
        };
        let object = envelope(frame, layers);
        write_json(writer, &object, 1)
    }

    /// Close the packet array.
    pub fn finish(&mut self, writer: &mut impl Write) -> io::Result<()> {
        if self.started {
            writer.write_all(b"\n]\n")
        } else {
            writer.write_all(b"[]\n")
        }
    }

    fn writes_text(&self) -> bool {
        self.mode == JsonMode::Json
    }

    fn writes_raw(&self) -> bool {
        self.mode == JsonMode::JsonRaw || self.print_hex
    }

    fn field_writes_raw(&self, field: &Field) -> bool {
        self.mode == JsonMode::JsonRaw || (self.print_hex && field_raw_has_data(field))
    }

    fn advance(&mut self, timestamp: Option<Timestamp>, displayed: bool) -> Option<FrameTimes> {
        let Some(timestamp) = timestamp else {
            // A frame without a timestamp breaks both delta chains: the next
            // frame omits its deltas instead of spanning the gap.
            self.previous_captured = None;
            self.previous_displayed = None;
            return None;
        };
        let relative = match self.first_timestamp {
            Some(first) => relative_time(timestamp, first),
            None => {
                self.first_timestamp = Some(timestamp);
                "0.000000000".to_string()
            }
        };
        let delta = self
            .previous_captured
            .map(|previous| relative_time(timestamp, previous));
        let delta_displayed = if displayed {
            self.previous_displayed
                .map(|previous| relative_time(timestamp, previous))
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

    fn packet_layers(&self, frame: &Frame, packet: &Packet, times: Option<&FrameTimes>) -> Json {
        let state = match self.filter {
            Some(filter) => ChildState::Active(filter),
            None => ChildState::Off,
        };
        let mut layers: Vec<(String, Json)> = Vec::new();
        if !frame.comments.is_empty() {
            self.comment_entries(&mut layers, frame, state);
        }
        self.frame_entries(&mut layers, frame, packet, times, state);
        for layer in &build_top_layers(&packet.tree.frame.children) {
            let context = FieldContext {
                node: layer.node,
                frame,
                sources: &packet.data_sources,
                filter: FieldFilter {
                    state,
                    kinds: &packet.data_source_kinds,
                },
            };
            self.protocol_entries(&mut layers, layer, &context);
        }
        if !matches!(
            packet.protocol_stack.last().copied(),
            Some("icmp" | "icmpv6")
        ) && let Some(length) = detail::root_data_length(packet)
            && let Some(offset) = frame.captured.len().checked_sub(length)
        {
            self.data_entries(&mut layers, frame, offset, length, state);
        }
        if malformed_visible(packet) {
            self.malformed_entries(&mut layers, state);
        }
        if capture_limited(frame, packet) {
            if self.writes_text() {
                layers.push((
                    "_ws.short".to_string(),
                    Json::String("[Packet size limited during capture]".to_string()),
                ));
            }
            if self.mode == JsonMode::JsonRaw {
                layers.push((
                    "_ws.short_raw".to_string(),
                    raw_array(String::new(), 0, 0, 0, 1),
                ));
            }
        }
        Json::object(layers, self.merge_keys)
    }

    fn flag(&self, state: ChildState<'_>, key: &str) -> Flag {
        match state {
            ChildState::Off => Flag::Open,
            ChildState::Active(filter) => match filter.flags(key) {
                None => Flag::Filtered,
                Some(true) => Flag::ExpandChildren,
                Some(false) => Flag::Open,
            },
        }
    }

    fn child_state<'b>(&self, state: ChildState<'b>, flag: Flag) -> ChildState<'b> {
        match flag {
            Flag::ExpandChildren => ChildState::Off,
            Flag::Open | Flag::Filtered => state,
        }
    }

    fn malformed_entries(&self, entries: &mut Vec<(String, Json)>, state: ChildState<'_>) {
        if self.mode == JsonMode::JsonRaw {
            entries.push((
                "_ws.malformed_raw".to_string(),
                raw_array(String::new(), 0, 0, 0, 1),
            ));
        }
        let flag = self.flag(state, "_ws.malformed");
        if flag == Flag::Filtered {
            entries.push(("_ws.malformed".to_string(), Json::filtered("_ws.malformed")));
            return;
        }
        let child_state = self.child_state(state, flag);
        let expert = match self.flag(child_state, "_ws.expert") {
            Flag::Filtered => Json::filtered("_ws.expert"),
            Flag::Open | Flag::ExpandChildren => match self.mode {
                JsonMode::Json => Json::object(
                    vec![
                        (
                            "_ws.malformed.expert".to_string(),
                            Json::String(String::new()),
                        ),
                        (
                            "_ws.expert.message".to_string(),
                            Json::String("Malformed Packet (Exception occurred)".to_string()),
                        ),
                        (
                            "_ws.expert.severity".to_string(),
                            Json::String("8388608".to_string()),
                        ),
                        (
                            "_ws.expert.group".to_string(),
                            Json::String("117440512".to_string()),
                        ),
                    ],
                    self.merge_keys,
                ),
                JsonMode::JsonRaw => Json::object(
                    vec![
                        (
                            "_ws.malformed.expert_raw".to_string(),
                            raw_array_with_source(String::new(), 0, 0, 0, 0, Source::Null),
                        ),
                        (
                            "_ws.expert.message_raw".to_string(),
                            raw_array_with_source(String::new(), 0, 0, 0, 26, Source::Null),
                        ),
                        (
                            "_ws.expert.severity_raw".to_string(),
                            raw_array_with_source(String::new(), 0, 0, 0, 7, Source::Null),
                        ),
                        (
                            "_ws.expert.group_raw".to_string(),
                            raw_array_with_source(String::new(), 0, 0, 0, 7, Source::Null),
                        ),
                    ],
                    self.merge_keys,
                ),
            },
        };
        let children = match self.mode {
            JsonMode::Json => vec![
                ("_ws.expert".to_string(), expert),
                (
                    "_ws.malformed".to_string(),
                    Json::String("Malformed Packet".to_string()),
                ),
            ],
            JsonMode::JsonRaw => vec![
                (
                    "_ws.expert_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 1, Source::Null),
                ),
                ("_ws.expert".to_string(), expert),
                (
                    "_ws.malformed_raw".to_string(),
                    raw_array(String::new(), 0, 0, 0, 26),
                ),
            ],
        };
        entries.push((
            "_ws.malformed".to_string(),
            Json::object(children, self.merge_keys),
        ));
    }

    fn expert_entries_for(
        &self,
        entries: &mut Vec<(String, Json)>,
        experts: &[packetfin_core::tree::ExpertInfo],
        state: ChildState<'_>,
    ) {
        for expert in experts {
            let flag = self.flag(state, "_ws.expert");
            if self.mode == JsonMode::JsonRaw {
                entries.push((
                    "_ws.expert_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 1, Source::Null),
                ));
            }
            if flag == Flag::Filtered {
                entries.push(("_ws.expert".to_string(), Json::filtered("_ws.expert")));
                continue;
            }
            let mut values = Vec::new();
            self.expert_message_entries(&mut values, expert);
            entries.push((
                "_ws.expert".to_string(),
                Json::object(values, self.merge_keys),
            ));
        }
    }

    fn expert_message_entries(
        &self,
        values: &mut Vec<(String, Json)>,
        expert: &packetfin_core::tree::ExpertInfo,
    ) {
        let severity = severity_value(expert.severity);
        let group = group_value(expert.group);
        match self.mode {
            JsonMode::Json => {
                values.push((
                    "_ws.expert.message".to_string(),
                    Json::String(expert.message.clone()),
                ));
                values.push((
                    "_ws.expert.severity".to_string(),
                    Json::String(severity.to_string()),
                ));
                values.push((
                    "_ws.expert.group".to_string(),
                    Json::String(group.to_string()),
                ));
            }
            JsonMode::JsonRaw => {
                values.push((
                    "_ws.expert.message_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 26, Source::Null),
                ));
                values.push((
                    "_ws.expert.severity_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 7, Source::Null),
                ));
                values.push((
                    "_ws.expert.group_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 7, Source::Null),
                ));
            }
        }
    }

    fn data_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        frame: &Frame,
        offset: usize,
        length: usize,
        state: ChildState<'_>,
    ) {
        let bytes = frame
            .captured
            .get(offset..offset.saturating_add(length))
            .unwrap_or(&[]);
        if self.writes_raw() {
            entries.push((
                "data_raw".to_string(),
                raw_array(hex_lower(bytes), offset, length, 0, 1),
            ));
        }
        let flag = self.flag(state, "data");
        if flag == Flag::Filtered {
            entries.push(("data".to_string(), Json::filtered("data")));
            return;
        }
        let mut children = Vec::new();
        if self.mode == JsonMode::JsonRaw || (self.print_hex && length > 0) {
            children.push((
                "data.data_raw".to_string(),
                raw_array(hex_lower(bytes), offset, length, 0, 30),
            ));
        }
        if self.writes_text() {
            children.push(("data.data".to_string(), Json::String(colon_hex(bytes))));
            children.push(("data.len".to_string(), Json::String(length.to_string())));
        }
        if self.mode == JsonMode::JsonRaw {
            children.push((
                "data.len_raw".to_string(),
                raw_array(String::new(), offset, 0, 0, 15),
            ));
        }
        entries.push(("data".to_string(), Json::object(children, self.merge_keys)));
    }

    fn push_field(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
    ) {
        if field.is_container() || !field.children.is_empty() {
            self.push_container(entries, field, context);
        } else if !field.experts.is_empty() {
            self.push_expert_field(entries, field, context);
        } else if let Some(tree) = checksum_tree(context.node, field) {
            self.push_checksum_tree(entries, field, context, tree);
        } else {
            self.push_value_entries(entries, field, context);
        }
    }

    /// Emit a checksum field whose tree holds the expert and, for TCP/UDP,
    /// the calculated checksum. IPv4's calculated field is a sibling instead.
    fn push_checksum_tree(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
        tree: ChecksumTree<'_>,
    ) {
        self.push_value_entries(entries, field, context);
        let key = format!("{}_tree", field.def.abbrev);
        if self.flag(context.filter.state, field.def.abbrev) == Flag::Filtered {
            entries.push((key, Json::filtered(field.def.abbrev)));
            return;
        }
        let mut values: Vec<(String, Json)> = Vec::new();
        if self.mode == JsonMode::JsonRaw && tree.expert.is_some() {
            values.push((
                "_ws.expert_raw".to_string(),
                raw_array_with_source(String::new(), 0, 0, 0, 1, Source::Null),
            ));
        }
        if let Some(expert) = tree.expert {
            let mut expert_values: Vec<(String, Json)> = Vec::new();
            if self.writes_text() {
                expert_values.push((
                    checksum_bad_abbrev(field.def.abbrev),
                    Json::String(String::new()),
                ));
            } else {
                expert_values.push((
                    format!("{}_raw", checksum_bad_abbrev(field.def.abbrev)),
                    raw_array_with_source(String::new(), 0, 0, 0, 0, Source::Null),
                ));
            }
            self.expert_message_entries(&mut expert_values, expert);
            values.push((
                "_ws.expert".to_string(),
                Json::object(expert_values, self.merge_keys),
            ));
        }
        if let Some(calculated) = tree.calculated {
            if self.mode == JsonMode::JsonRaw {
                values.push((
                    format!("{}_raw", calculated.def.abbrev),
                    field_raw(
                        calculated,
                        context.node,
                        &context.frame.captured,
                        context.sources,
                        context.filter.kinds,
                    ),
                ));
            } else if self.writes_text() {
                values.push((
                    calculated.def.abbrev.to_string(),
                    json_value(calculated.def, &calculated.value),
                ));
            }
        }
        entries.push((key, Json::object(values, self.merge_keys)));
    }

    /// Add one leaf's raw and display value, raw first.
    fn push_value_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
    ) {
        if self.field_writes_raw(field) {
            entries.push((
                format!("{}_raw", field.def.abbrev),
                field_raw(
                    field,
                    context.node,
                    &context.frame.captured,
                    context.sources,
                    context.filter.kinds,
                ),
            ));
        }
        if self.writes_text() {
            entries.push((
                field.def.abbrev.to_string(),
                json_value(field.def, &field.value),
            ));
        }
    }

    /// Add a container and its nested keys.
    ///
    /// A value-bearing container is named by its field abbreviation and
    /// followed by an `<abbrev>_tree` object; a value-less container is
    /// only the object under its abbreviation. A container the protocol
    /// filter does not name keeps its value but replaces the tree with a
    /// filtered marker.
    fn push_container(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
    ) {
        if field.def.abbrev.is_empty() {
            self.push_unnamed_container(entries, field, context);
            return;
        }
        let flag = self.flag(context.filter.state, field.def.abbrev);
        let value_bearing = !matches!(field.value, Value::None | Value::Missing);
        if self.field_writes_raw(field) {
            entries.push((
                format!("{}_raw", field.def.abbrev),
                field_raw(
                    field,
                    context.node,
                    &context.frame.captured,
                    context.sources,
                    context.filter.kinds,
                ),
            ));
        }
        if self.writes_text() && value_bearing {
            entries.push((
                field.def.abbrev.to_string(),
                json_value(field.def, &field.value),
            ));
        }
        let key = if value_bearing {
            format!("{}_tree", field.def.abbrev)
        } else {
            field.def.abbrev.to_string()
        };
        if flag == Flag::Filtered {
            entries.push((key, Json::filtered(field.def.abbrev)));
            return;
        }
        let child_state = self.child_state(context.filter.state, flag);
        let child_context = FieldContext {
            filter: FieldFilter {
                state: child_state,
                kinds: context.filter.kinds,
            },
            ..*context
        };
        let mut children: Vec<(String, Json)> =
            Vec::with_capacity(field.children.len() + field.experts.len());
        for child in &field.children {
            if hidden_from_json(child.def.abbrev)
                || packetfin_core::expert_label_only(child.def.abbrev)
            {
                continue;
            }
            self.push_field(&mut children, child, &child_context);
        }
        for child in &field.nodes {
            let layer = Layer {
                node: child,
                nested: build_top_layers(&child.children),
            };
            let node_context = FieldContext {
                node: child,
                frame: context.frame,
                sources: context.sources,
                filter: child_context.filter,
            };
            self.protocol_entries(&mut children, &layer, &node_context);
        }
        self.expert_entries_for(&mut children, &field.experts, child_state);
        entries.push((key, Json::object(children, self.merge_keys)));
    }

    /// Add an unnamed synthetic group.
    ///
    /// The group has no registered abbreviation: JSON uses its complete
    /// showname as the object key, emits no value and keeps the ordered
    /// children. The same key can appear more than once, so the normal
    /// duplicate-key rule applies.
    fn push_unnamed_container(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
    ) {
        let key = field.showname_text().unwrap_or_default().into_owned();
        if self.flag(context.filter.state, "text") == Flag::Filtered {
            entries.push((key.clone(), Json::filtered(&key)));
            return;
        }
        let mut children: Vec<(String, Json)> =
            Vec::with_capacity(field.children.len() + field.experts.len());
        for child in &field.children {
            if hidden_from_json(child.def.abbrev)
                || packetfin_core::expert_label_only(child.def.abbrev)
            {
                continue;
            }
            self.push_field(&mut children, child, context);
        }
        for child in &field.nodes {
            let layer = Layer {
                node: child,
                nested: build_top_layers(&child.children),
            };
            let node_context = FieldContext {
                node: child,
                frame: context.frame,
                sources: context.sources,
                filter: context.filter,
            };
            self.protocol_entries(&mut children, &layer, &node_context);
        }
        self.field_expert_entries(&mut children, field, context);
        entries.push((key, Json::object(children, self.merge_keys)));
    }

    /// Add a leaf with experts. A value-bearing field keeps its value and
    /// puts the expert in its tree; an FT_NONE flag is replaced by the
    /// `_ws.expert` object at its key position.
    fn push_expert_field(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
    ) {
        let value_bearing = !matches!(field.value, Value::None | Value::Missing);
        if !value_bearing {
            self.field_expert_entries(entries, field, context);
            return;
        }
        let flag = self.flag(context.filter.state, field.def.abbrev);
        self.push_value_entries(entries, field, context);
        let key = format!("{}_tree", field.def.abbrev);
        if flag == Flag::Filtered {
            entries.push((key, Json::filtered(field.def.abbrev)));
            return;
        }
        let mut tree = Vec::with_capacity(field.experts.len());
        self.field_expert_entries(&mut tree, field, context);
        entries.push((key, Json::object(tree, self.merge_keys)));
    }

    fn field_expert_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        field: &Field,
        context: &FieldContext<'_, '_>,
    ) {
        let offending = packetfin_core::expert_offending(field);
        let offending_value = if field.expert_field.is_some() {
            Value::None
        } else {
            field.value.clone()
        };
        for expert in &field.experts {
            let flag = self.flag(context.filter.state, "_ws.expert");
            if self.mode == JsonMode::JsonRaw {
                entries.push((
                    "_ws.expert_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 1, Source::Null),
                ));
            }
            if flag == Flag::Filtered {
                entries.push(("_ws.expert".to_string(), Json::filtered("_ws.expert")));
                continue;
            }
            let mut values: Vec<(String, Json)> = Vec::new();
            if self.field_writes_raw(field) {
                if field.expert_field.is_some() {
                    values.push((
                        format!("{}_raw", offending.abbrev),
                        raw_array_with_source(String::new(), 0, 0, 0, 0, Source::Null),
                    ));
                } else {
                    values.push((
                        format!("{}_raw", field.def.abbrev),
                        field_raw(
                            field,
                            context.node,
                            &context.frame.captured,
                            context.sources,
                            context.filter.kinds,
                        ),
                    ));
                }
            }
            if self.writes_text() {
                values.push((
                    offending.abbrev.to_string(),
                    json_value(offending, &offending_value),
                ));
            }
            self.expert_message_entries(&mut values, expert);
            entries.push((
                "_ws.expert".to_string(),
                Json::object(values, self.merge_keys),
            ));
            if expert.group == packetfin_core::Group::Malformed {
                entries.push((
                    "_ws.malformed".to_string(),
                    Json::String("Malformed Packet".to_string()),
                ));
            }
        }
    }

    fn protocol_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        layer: &Layer<'_>,
        context: &FieldContext<'_, '_>,
    ) {
        let node = layer.node;
        let key = node.protocol.filter_name;
        let extent = protocol_end(
            layer,
            crate::raw::source_len(&context.frame.captured, context.sources, node.range.source),
        );
        let emit_raw = match self.mode {
            JsonMode::JsonRaw => extent > node.range.offset || zero_length_raw_allowed(key),
            JsonMode::Json => self.print_hex && extent > node.range.offset,
        };
        if emit_raw {
            entries.push((
                format!("{key}_raw"),
                protocol_raw(
                    node,
                    layer,
                    &context.frame.captured,
                    context.sources,
                    context.filter.kinds,
                ),
            ));
        }
        let flag = self.flag(context.filter.state, key);
        match flag {
            Flag::Filtered => entries.push((key.to_string(), Json::filtered(key))),
            Flag::Open | Flag::ExpandChildren => {
                let children = self.child_state(context.filter.state, flag);
                let child_context = FieldContext {
                    filter: FieldFilter {
                        state: children,
                        kinds: context.filter.kinds,
                    },
                    ..*context
                };
                let mut node_entries: Vec<(String, Json)> = Vec::with_capacity(node.fields.len());
                for field in node.display_fields() {
                    if field.packet_scoped()
                        || hidden_from_json(field.def.abbrev)
                        || packetfin_core::expert_label_only(field.def.abbrev)
                        || field.def.abbrev == "ipv6.reassembled.in"
                        || calculated_belongs_to_tree(node, field)
                    {
                        continue;
                    }
                    self.push_field(&mut node_entries, field, &child_context);
                }
                for nested in &layer.nested {
                    let node_context = FieldContext {
                        node: nested.node,
                        frame: context.frame,
                        sources: context.sources,
                        filter: child_context.filter,
                    };
                    self.protocol_entries(&mut node_entries, nested, &node_context);
                }
                if let Some(field) = node
                    .fields
                    .iter()
                    .find(|field| field.def.abbrev == "ipv6.reassembled.in")
                {
                    self.push_field(&mut node_entries, field, &child_context);
                }
                let has_checksum_field = node
                    .fields
                    .iter()
                    .any(|field| field.def.abbrev.ends_with(".checksum"));
                let experts: Vec<packetfin_core::tree::ExpertInfo> = node
                    .experts
                    .iter()
                    .filter(|expert| {
                        !(has_checksum_field && expert.group == packetfin_core::Group::Checksum)
                            && !(node.protocol_exception
                                && expert.group == packetfin_core::Group::Malformed)
                    })
                    .cloned()
                    .collect();
                self.expert_entries_for(&mut node_entries, &experts, children);
                entries.push((key.to_string(), Json::object(node_entries, self.merge_keys)));
            }
        }
        // `tcp.segments` is packet-scoped, so JSON places its object beside
        // `tcp` and filters it with the packet-level state even when `tcp`
        // itself is filtered.
        for field in &node.fields {
            if field.packet_scoped() {
                self.push_container(entries, field, context);
            }
        }
    }

    fn frame_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        frame: &Frame,
        packet: &Packet,
        times: Option<&FrameTimes>,
        state: ChildState<'_>,
    ) {
        if self.writes_raw() && (self.mode == JsonMode::JsonRaw || !frame.captured.is_empty()) {
            entries.push((
                "frame_raw".to_string(),
                raw_array(hex_lower(&frame.captured), 0, frame.captured.len(), 0, 1),
            ));
        }
        let flag = self.flag(state, "frame");
        if flag == Flag::Filtered {
            entries.push(("frame".to_string(), Json::filtered("frame")));
            return;
        }
        let child_state = self.child_state(state, flag);
        let mut frame_entries: Vec<(String, Json)> =
            Vec::with_capacity(if frame.section_number.is_some() {
                20
            } else {
                17
            });
        if frame.section_number.is_some() {
            self.frame_field(
                &mut frame_entries,
                "frame.section_number",
                frame.section_number.unwrap_or(0).to_string(),
                7,
            );
            self.frame_field(
                &mut frame_entries,
                "frame.interface_id",
                frame.interface_id.to_string(),
                7,
            );
            self.interface_name_entries(&mut frame_entries, frame, child_state);
        }
        self.frame_field(
            &mut frame_entries,
            "frame.encap_type",
            detail::encapsulation(frame.link_type).1.to_string(),
            13,
        );
        if let Some(times) = times {
            if let Some(timestamp) = frame.timestamp {
                let text = absolute_time(timestamp);
                self.frame_field(&mut frame_entries, "frame.time", text.clone(), 24);
                self.frame_field(&mut frame_entries, "frame.time_utc", text.clone(), 24);
                self.frame_field(&mut frame_entries, "frame.time_epoch", text, 24);
            }
            self.frame_field(
                &mut frame_entries,
                "frame.offset_shift",
                "0.000000000".to_string(),
                25,
            );
            if let Some(delta) = &times.delta {
                self.frame_field(&mut frame_entries, "frame.time_delta", delta.clone(), 25);
            }
            if let Some(delta) = &times.delta_displayed {
                self.frame_field(
                    &mut frame_entries,
                    "frame.time_delta_displayed",
                    delta.clone(),
                    25,
                );
            }
            self.frame_field(
                &mut frame_entries,
                "frame.time_relative",
                times.relative.clone(),
                25,
            );
        }
        self.frame_field(
            &mut frame_entries,
            "frame.number",
            frame.number.to_string(),
            7,
        );
        self.frame_field(
            &mut frame_entries,
            "frame.len",
            frame.original_len.to_string(),
            7,
        );
        self.frame_field(
            &mut frame_entries,
            "frame.cap_len",
            frame.captured.len().to_string(),
            7,
        );
        self.frame_field(&mut frame_entries, "frame.marked", "0".to_string(), 2);
        self.frame_field(&mut frame_entries, "frame.ignored", "0".to_string(), 2);
        self.frame_field(
            &mut frame_entries,
            "frame.protocols",
            detail::protocols_in_frame(packet, frame),
            26,
        );
        self.frame_field(&mut frame_entries, "frame.encoding", "0".to_string(), 7);
        entries.push((
            "frame".to_string(),
            Json::object(frame_entries, self.merge_keys),
        ));
    }

    fn frame_field(&self, entries: &mut Vec<(String, Json)>, key: &str, value: String, ftype: u32) {
        if self.writes_text() {
            entries.push((key.to_string(), Json::String(value)));
        } else {
            entries.push((
                format!("{key}_raw"),
                raw_array(String::new(), 0, 0, 0, ftype),
            ));
        }
    }

    fn interface_name_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        frame: &Frame,
        state: ChildState<'_>,
    ) {
        let flag = self.flag(state, "frame.interface_id");
        if flag == Flag::Filtered {
            entries.push((
                "frame.interface_id_tree".to_string(),
                Json::filtered("frame.interface_id"),
            ));
            return;
        }
        let name = frame.interface_name.as_deref().unwrap_or("unknown");
        let children = if self.writes_text() {
            vec![(
                "frame.interface_name".to_string(),
                Json::String(name.to_string()),
            )]
        } else {
            vec![(
                "frame.interface_name_raw".to_string(),
                raw_array(String::new(), 0, 0, 0, 26),
            )]
        };
        entries.push((
            "frame.interface_id_tree".to_string(),
            Json::object(children, self.merge_keys),
        ));
    }

    fn comment_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        frame: &Frame,
        state: ChildState<'_>,
    ) {
        if self.mode == JsonMode::JsonRaw {
            entries.push((
                "pkt_comment_raw".to_string(),
                raw_array(String::new(), 0, 0, 0, 1),
            ));
        }
        let flag = self.flag(state, "pkt_comment");
        if flag == Flag::Filtered {
            entries.push(("pkt_comment".to_string(), Json::filtered("pkt_comment")));
            return;
        }
        let child_state = self.child_state(state, flag);
        let mut comments: Vec<(String, Json)> = Vec::new();
        for comment in &frame.comments {
            let first_line = comment.split('\n').next().unwrap_or(comment);
            comments.push(comment_value(first_line, self.mode == JsonMode::JsonRaw));
            let tree_flag = self.flag(child_state, "frame.comment");
            if tree_flag == Flag::Filtered {
                comments.push((
                    "frame.comment_tree".to_string(),
                    Json::filtered("frame.comment"),
                ));
                continue;
            }
            let tree_children = self.child_state(child_state, tree_flag);
            let mut tree: Vec<(String, Json)> = Vec::new();
            let lines = comment_lines(comment);
            if !lines.is_empty() {
                for line in lines {
                    tree.push(comment_value(line, self.mode == JsonMode::JsonRaw));
                }
                tree.push(comment_value(comment, self.mode == JsonMode::JsonRaw));
            }
            self.expert_entries(&mut tree, comment, tree_children);
            comments.push((
                "frame.comment_tree".to_string(),
                Json::object(tree, self.merge_keys),
            ));
        }
        entries.push((
            "pkt_comment".to_string(),
            Json::object(comments, self.merge_keys),
        ));
    }

    fn expert_entries(
        &self,
        entries: &mut Vec<(String, Json)>,
        message: &str,
        state: ChildState<'_>,
    ) {
        let flag = self.flag(state, "_ws.expert");
        if self.mode == JsonMode::JsonRaw {
            entries.push((
                "_ws.expert_raw".to_string(),
                raw_array_with_source(String::new(), 0, 0, 0, 1, Source::Null),
            ));
        }
        if flag == Flag::Filtered {
            entries.push(("_ws.expert".to_string(), Json::filtered("_ws.expert")));
            return;
        }
        let expert = match self.mode {
            JsonMode::Json => vec![
                (
                    "frame.comment.expert".to_string(),
                    Json::String(String::new()),
                ),
                (
                    "_ws.expert.message".to_string(),
                    Json::String(message.to_string()),
                ),
                (
                    "_ws.expert.severity".to_string(),
                    Json::String("1048576".to_string()),
                ),
                (
                    "_ws.expert.group".to_string(),
                    Json::String("184549376".to_string()),
                ),
            ],
            JsonMode::JsonRaw => vec![
                (
                    "frame.comment.expert_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 0, Source::Null),
                ),
                (
                    "_ws.expert.message_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 26, Source::Null),
                ),
                (
                    "_ws.expert.severity_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 7, Source::Null),
                ),
                (
                    "_ws.expert.group_raw".to_string(),
                    raw_array_with_source(String::new(), 0, 0, 0, 7, Source::Null),
                ),
            ],
        };
        entries.push((
            "_ws.expert".to_string(),
            Json::object(expert, self.merge_keys),
        ));
    }
}

/// The line entries added to a comment's tree.
///
/// Only a multi-line comment repeats lines, and a trailing newline does not
/// add an empty final line.
fn comment_lines(comment: &str) -> Vec<&str> {
    if !comment.contains('\n') {
        return Vec::new();
    }
    let mut lines: Vec<&str> = comment.split('\n').collect();
    if comment.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// Add one packet-comment value.
///
/// Comments have no data source, so jsonraw carries an empty value array;
/// text mode and `-x` mixed mode print the visible string.
fn comment_value(text: &str, raw: bool) -> (String, Json) {
    if raw {
        (
            "frame.comment_raw".to_string(),
            raw_array(String::new(), 0, 0, 0, 26),
        )
    } else {
        ("frame.comment".to_string(), Json::String(text.to_string()))
    }
}

/// Whether the top-level malformed pseudo-protocol is shown.
///
/// Field-level malformed experts do not add it. The innermost protocol's
/// non-"Bad length value" malformed expert is the same signal the summary
/// line uses.
fn malformed_visible(packet: &Packet) -> bool {
    let Some(name) = packet.protocol_stack.last() else {
        return false;
    };
    let Some(node) = find_last_node(&packet.tree.frame, name) else {
        return false;
    };
    node.experts.iter().any(|expert| {
        expert.group == packetfin_core::Group::Malformed
            && !expert.message.starts_with("Bad length value")
    })
}

fn find_last_node<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    let mut found = if node.protocol.filter_name == name {
        Some(node)
    } else {
        None
    };
    for child in &node.children {
        if let Some(candidate) = find_last_node(child, name) {
            found = Some(candidate);
        }
    }
    found
}

pub(crate) fn severity_value(severity: packetfin_core::Severity) -> u32 {
    match severity {
        packetfin_core::Severity::Comment => 0x0010_0000,
        packetfin_core::Severity::Chat => 0x0020_0000,
        packetfin_core::Severity::Note => 0x0040_0000,
        packetfin_core::Severity::Warning => 0x0060_0000,
        packetfin_core::Severity::Error => 0x0080_0000,
    }
}

pub(crate) fn group_value(group: packetfin_core::Group) -> u32 {
    match group {
        packetfin_core::Group::Checksum => 0x0100_0000,
        packetfin_core::Group::Sequence => 0x0200_0000,
        packetfin_core::Group::Response => 0x0300_0000,
        packetfin_core::Group::Request => 0x0400_0000,
        packetfin_core::Group::Undecoded => 0x0500_0000,
        packetfin_core::Group::Malformed => 0x0700_0000,
        packetfin_core::Group::Deprecated => 0x0E00_0000,
        packetfin_core::Group::Protocol => 0x0900_0000,
        packetfin_core::Group::Reassemble => 0x0600_0000,
        packetfin_core::Group::Comment => 0x0b00_0000,
    }
}

/// The zero-length companion field for a bad checksum.
pub(crate) fn checksum_bad_abbrev(checksum_abbrev: &str) -> String {
    let parent = checksum_abbrev
        .rsplit_once('.')
        .map_or(checksum_abbrev, |(parent, _)| parent);
    match parent {
        "icmp" => "icmp.checksum_bad".to_string(),
        "udp" => "udp.checksum.bad".to_string(),
        _ => format!("{parent}.checksum_bad.expert"),
    }
}

/// The calculated-checksum companion nested under a bad checksum.
pub(crate) fn checksum_calculated_abbrev(checksum_abbrev: &str) -> Option<&'static str> {
    Some(match checksum_abbrev {
        "ip.checksum" => "ip.checksum_calculated",
        "tcp.checksum" => "tcp.checksum_calculated",
        "udp.checksum" => "udp.checksum_calculated",
        _ => return None,
    })
}

/// TCP and UDP print the calculated checksum inside the checksum tree;
/// IPv4 keeps it beside the checksum and status fields.
pub(crate) fn checksum_calculated_is_nested(checksum_abbrev: &str) -> bool {
    matches!(checksum_abbrev, "tcp.checksum" | "udp.checksum")
}

/// Whether `field` is a calculated checksum rendered inside its checksum
/// container rather than at protocol level.
fn calculated_belongs_to_tree(node: &Node, field: &Field) -> bool {
    let Some(checksum_abbrev) = checksum_for_calculated(field.def.abbrev) else {
        return false;
    };
    checksum_calculated_is_nested(checksum_abbrev)
        && node
            .fields
            .iter()
            .any(|candidate| candidate.def.abbrev == checksum_abbrev)
}

fn checksum_for_calculated(calculated_abbrev: &str) -> Option<&'static str> {
    Some(match calculated_abbrev {
        "ip.checksum_calculated" => "ip.checksum",
        "tcp.checksum_calculated" => "tcp.checksum",
        "udp.checksum_calculated" => "udp.checksum",
        _ => return None,
    })
}

pub(crate) struct ChecksumTree<'a> {
    pub(crate) expert: Option<&'a packetfin_core::tree::ExpertInfo>,
    pub(crate) calculated: Option<&'a Field>,
}

pub(crate) fn checksum_tree<'a>(node: &'a Node, field: &Field) -> Option<ChecksumTree<'a>> {
    if !field.def.abbrev.ends_with(".checksum") {
        return None;
    }
    let expert = node
        .experts
        .iter()
        .find(|expert| expert.group == packetfin_core::Group::Checksum);
    let calculated = checksum_calculated_abbrev(field.def.abbrev)
        .filter(|_| checksum_calculated_is_nested(field.def.abbrev))
        .and_then(|abbrev| {
            node.fields
                .iter()
                .find(|candidate| candidate.def.abbrev == abbrev)
        });
    if expert.is_none() && calculated.is_none() {
        return None;
    }
    Some(ChecksumTree { expert, calculated })
}

/// Fields Packetfin keeps for its own detail view but leaves out of JSON.
pub(crate) fn hidden_from_json(abbrev: &str) -> bool {
    matches!(
        abbrev,
        "icmp.checksum_calculated" | "icmpv6.checksum_calculated"
    )
}

fn envelope(frame: &Frame, layers: Json) -> Json {
    Json::object(
        vec![
            (
                "_index".to_string(),
                Json::String(index_name(frame.timestamp)),
            ),
            ("_score".to_string(), Json::Null),
            (
                "_source".to_string(),
                Json::object(vec![("layers".to_string(), layers)], false),
            ),
        ],
        false,
    )
}

fn specified_fields_object(tree: &Tree, fields: &[&'static FieldDef], merge_keys: bool) -> Json {
    let collected: Vec<&Field> = tree.fields().collect();
    let mut entries: Vec<(String, Json)> = Vec::with_capacity(fields.len());
    for definition in fields {
        if hidden_from_json(definition.abbrev)
            || entries
                .iter()
                .any(|(existing, _)| existing == definition.abbrev)
        {
            continue;
        }
        let mut values: Vec<Json> = Vec::new();
        for field in &collected {
            if field.def.abbrev == definition.abbrev {
                values.push(Json::String(field.value.render(definition.display)));
            }
        }
        if !values.is_empty() {
            entries.push((definition.abbrev.to_string(), Json::Array(values)));
        }
    }
    Json::object(entries, merge_keys)
}

fn json_value(definition: &FieldDef, value: &Value) -> Json {
    match value {
        Value::Boolean(value) => Json::String(if *value { "1" } else { "0" }.to_string()),
        Value::None | Value::Missing => Json::String(String::new()),
        Value::Bytes(bytes) => Json::Bytes(bytes.clone()),
        Value::String(text) => Json::String(text.clone()),
        Value::AbsoluteTime(timestamp) => Json::String(absolute_time(*timestamp)),
        other => Json::String(other.render(definition.display)),
    }
}

fn field_raw_has_data(field: &Field) -> bool {
    if let Some(raw) = &field.raw {
        return raw.length > 0 || !raw.bytes.is_empty();
    }
    if field.def.bitmask.is_some_and(|mask| mask != 0) {
        return true;
    }
    let abbrev = field.def.abbrev;
    if abbrev.ends_with(".checksum.status") || abbrev == "tcp.nxtseq" {
        return false;
    }
    if abbrev == "tcp.flags.str" || abbrev == "tcp.options.wscale.multiplier" {
        return true;
    }
    !(field.generated && field.range.length == 0) && field.range.length > 0
}

fn field_raw(
    field: &Field,
    node: &Node,
    captured: &[u8],
    sources: &[Bytes],
    kinds: &[DataSourceKind],
) -> Json {
    if let Some(raw) = &field.raw {
        let source = match raw.source {
            packetfin_core::tree::RawSource::Field => Source::Zero,
            packetfin_core::tree::RawSource::Frame => Source::One,
            packetfin_core::tree::RawSource::Plaintext => Source::Id(2),
            packetfin_core::tree::RawSource::None => Source::Null,
        };
        return raw_array_with_source(
            Json::Hex(raw.bytes.clone()),
            raw.start,
            raw.length,
            raw.bitmask,
            raw.field_type,
            source,
        );
    }
    let source = if field.range.source == 0 && node.source.is_some() {
        Source::One
    } else {
        source_id(field.range.source, kinds)
    };
    let raw_array = |value: String, start: usize, length: usize, bitmask: u64, ftype: u32| {
        raw_array_with_source(value, start, length, bitmask, ftype, source)
    };
    let start = field.range.offset;
    let length = field.range.length;
    let bitmask = field.def.bitmask.unwrap_or(0);
    let ftype = ftenum(&field.value);
    if bitmask != 0 {
        let text = match masked_value(&field.value) {
            Some(value) => format!("{value:X}"),
            None => String::new(),
        };
        let (start, length) = masked_location(field, bitmask);
        return raw_array_with_source(text, start, length, bitmask, ftype, source);
    }
    let abbrev = field.def.abbrev;
    if abbrev.ends_with(".checksum.status") {
        return raw_array_with_source(String::new(), start, 0, 0, ftype, source);
    }
    if abbrev == "tcp.nxtseq" {
        return raw_array_with_source(String::new(), node.range.offset, 0, 0, ftype, source);
    }
    if abbrev == "tcp.flags.str"
        && let Some(flags) = node
            .fields
            .iter()
            .find(|candidate| candidate.def.abbrev == "tcp.flags")
    {
        let bytes = if flags.range.source == 0 {
            node.source.as_deref().map_or_else(
                || crate::raw::raw_bytes_from(captured, sources, flags.range),
                |source| {
                    let end = flags
                        .range
                        .offset
                        .saturating_add(flags.range.length)
                        .min(source.len());
                    source.get(flags.range.offset..end).unwrap_or(&[])
                },
            )
        } else {
            crate::raw::raw_bytes_from(captured, sources, flags.range)
        };
        return raw_array(
            hex_lower(bytes),
            flags.range.offset,
            flags.range.length,
            0,
            ftype,
        );
    }
    if abbrev == "tcp.options.wscale.multiplier"
        && let Some(shift) = node
            .fields
            .iter()
            .find(|candidate| candidate.def.abbrev == "tcp.options.wscale.shift")
    {
        let bytes = if shift.range.source == 0 {
            node.source.as_deref().map_or_else(
                || crate::raw::raw_bytes_from(captured, sources, shift.range),
                |source| {
                    let end = shift
                        .range
                        .offset
                        .saturating_add(shift.range.length)
                        .min(source.len());
                    source.get(shift.range.offset..end).unwrap_or(&[])
                },
            )
        } else {
            crate::raw::raw_bytes_from(captured, sources, shift.range)
        };
        return raw_array(
            hex_lower(bytes),
            shift.range.offset,
            shift.range.length,
            0,
            ftype,
        );
    }
    if field.generated && length == 0 {
        let start = if start == 0 { node.range.offset } else { start };
        return raw_array_with_source(String::new(), start, 0, 0, ftype, source);
    }
    let node_fallback = if field.range.source == 0 {
        node.source.as_deref()
    } else {
        None
    };
    let value = match if let Some(source) = node_fallback {
        let end = start.saturating_add(length).min(source.len());
        source
            .get(start..end)
            .map(|bytes| Bytes::from(bytes.to_vec()))
    } else {
        shared_bytes_at(captured, sources, field.range.source, start, length)
    } {
        Some(bytes) => Json::Hex(bytes),
        None if length == 0 => Json::String(String::new()),
        None => Json::String("field length invalid!".to_string()),
    };
    raw_array_with_source(value, start, length, bitmask, ftype, source)
}

/// The stored start and length of a masked subfield.
///
/// Ordinary masked values report the parent field's byte span.
/// A 12-bit TCP flag is the exception: its parent is two bytes, and each
/// subfield names the single byte that contains its bits.
fn masked_location(field: &Field, bitmask: u64) -> (usize, usize) {
    if matches!(field.def.abbrev, "syslog.facility" | "syslog.level") {
        return (field.range.offset, field.range.length);
    }
    let parent_width = field
        .def
        .abbrev
        .rsplit_once('.')
        .and_then(|(parent, _)| field_by_abbrev(parent))
        .and_then(|definition| field_type_width(definition.field_type));
    let boolean_display = matches!(
        field.def.display,
        Display::Boolean0
            | Display::Boolean6
            | Display::Boolean8
            | Display::Boolean12
            | Display::Boolean16
            | Display::Boolean24
            | Display::Boolean32
    );
    let width = parent_width
        .or_else(|| {
            if boolean_display {
                None
            } else {
                field_type_width(field.def.field_type)
            }
        })
        .unwrap_or(field.range.length)
        .max(1);
    let high_byte = (u64::BITS - 1 - bitmask.leading_zeros()) as usize / 8;
    let low_byte = bitmask.trailing_zeros() as usize / 8;
    if matches!(field.def.display, Display::Boolean12) {
        let parent = width.max(1);
        let offset = parent.saturating_sub(1).saturating_sub(high_byte);
        return (field.range.offset + offset, high_byte - low_byte + 1);
    }
    if boolean_display {
        return (field.range.offset, width);
    }
    let shift = field.range.length.saturating_sub(width).min(high_byte);
    (field.range.offset + shift, width)
}

fn field_type_width(field_type: FieldType) -> Option<usize> {
    Some(match field_type {
        FieldType::Uint8 | FieldType::Int8 | FieldType::Boolean => 1,
        FieldType::Uint16 | FieldType::Int16 => 2,
        FieldType::Uint24 => 3,
        FieldType::Uint32 | FieldType::Int32 | FieldType::FrameNumber => 4,
        FieldType::Uint64 | FieldType::Int64 => 8,
        _ => return None,
    })
}

fn zero_length_raw_allowed(protocol: &str) -> bool {
    matches!(protocol, "ipv6" | "llc")
}

/// The JSON source id: frame 0, reassembled 1, plaintext 2.
fn source_id(source: u32, kinds: &[DataSourceKind]) -> Source {
    if source == 0 {
        return Source::Zero;
    }
    let index = usize::try_from(source.saturating_sub(1)).unwrap_or(usize::MAX);
    match kinds.get(index) {
        Some(DataSourceKind::Reassembled) => Source::Id(1),
        Some(DataSourceKind::Plaintext) => Source::Id(2),
        None => Source::Zero,
    }
}

/// Bytes for a range, sharing an allocated data source instead of copying.
fn shared_bytes_at(
    captured: &[u8],
    sources: &[Bytes],
    source: u32,
    start: usize,
    length: usize,
) -> Option<Bytes> {
    if source == 0 {
        return crate::raw::range_bytes_from(captured, sources, 0, start, length)
            .map(|bytes| Bytes::from(bytes.to_vec()));
    }
    let index = usize::try_from(source).ok()?.checked_sub(1)?;
    sources
        .get(index)
        .map(|bytes| bytes.subslice(start, length))
}

fn protocol_raw(
    node: &Node,
    layer: &Layer<'_>,
    captured: &[u8],
    sources: &[Bytes],
    kinds: &[DataSourceKind],
) -> Json {
    let start = node.range.offset;
    let end = protocol_end(
        layer,
        crate::raw::source_len(captured, sources, node.range.source),
    );
    let length = end.saturating_sub(start);
    let value = match shared_bytes_at(captured, sources, node.range.source, start, length) {
        Some(bytes) => Json::Hex(bytes),
        None if length == 0 => Json::String(String::new()),
        None => Json::String("field length invalid!".to_string()),
    };
    raw_array_with_source(
        value,
        start,
        length,
        0,
        1,
        source_id(node.range.source, kinds),
    )
}

/// The end offset of a protocol item, including quoted and extension
/// subtrees kept inside it.
fn protocol_end(layer: &Layer<'_>, captured_len: usize) -> usize {
    let mut end = if is_extension(layer.node.protocol.filter_name) {
        extension_end(layer, captured_len)
    } else {
        fields_end(layer.node)
    };
    for nested in &layer.nested {
        end = end.max(nested_extent(nested, captured_len));
    }
    end.min(captured_len.max(layer.node.range.offset))
}

/// The bytes a nested subtree contributes to its parent's protocol item.
///
/// An IPv6 extension node's stored range spans the following transport, but
/// the extension item covers only the extension bytes, so its field
/// extent is authoritative. A quoted protocol instead contributes its whole
/// quoted datagram, which is why ICMP's item includes the quote.
fn nested_extent(layer: &Layer<'_>, captured_len: usize) -> usize {
    if is_extension(layer.node.protocol.filter_name) {
        extension_end(layer, captured_len)
    } else {
        layer
            .node
            .range
            .offset
            .saturating_add(layer.node.range.length)
            .min(captured_len)
    }
}

/// The end of an extension header, capped at its declared `(len + 1) * 8`
/// bytes and the captured bytes. Option fields may run past the header.
fn extension_end(layer: &Layer<'_>, captured_len: usize) -> usize {
    let node = layer.node;
    let start = node.range.offset;
    let mut end = fields_end(node);
    if let Some(declared) = extension_declared_length(node) {
        end = end.min(start.saturating_add(declared));
    }
    end = end.min(captured_len).max(start);
    for nested in &layer.nested {
        if is_extension(nested.node.protocol.filter_name) {
            end = end.max(extension_end(nested, captured_len));
        }
    }
    end
}

pub(crate) fn extension_declared_length(node: &Node) -> Option<usize> {
    let name = node.protocol.filter_name;
    if !matches!(name, "ipv6.hopopts" | "ipv6.dstopts" | "ipv6.routing") {
        return None;
    }
    let length = node
        .fields
        .iter()
        .find(|field| field.def.abbrev == format!("{name}.len"))?
        .value
        .render(Display::Decimal)
        .parse::<usize>()
        .ok()?;
    length.checked_add(1)?.checked_mul(8)
}

fn is_extension(name: &str) -> bool {
    matches!(
        name,
        "ipv6.hopopts" | "ipv6.dstopts" | "ipv6.routing" | "ipv6.fraghdr"
    )
}

pub(crate) fn fields_end(node: &Node) -> usize {
    node.fields
        .iter()
        .filter(|field| !field.is_container())
        .filter(|field| !hidden_from_json(field.def.abbrev))
        .filter(|field| !field.def.abbrev.ends_with(".payload"))
        .filter_map(|field| field.range.offset.checked_add(field.range.length))
        .max()
        .unwrap_or(node.range.offset)
        .max(node.range.offset)
}

fn masked_value(value: &Value) -> Option<u64> {
    match value {
        Value::Uint8(value) => Some(u64::from(*value)),
        Value::Uint16(value) => Some(u64::from(*value)),
        Value::Uint24(value) | Value::Uint32(value) => Some(u64::from(*value)),
        Value::Uint64(value) => Some(*value),
        Value::Int8(value) => Some(u64::from(*value as u8)),
        Value::Int16(value) => Some(u64::from(*value as u16)),
        Value::Int32(value) => Some(u64::from(*value as u32)),
        Value::Int64(value) => Some(*value as u64),
        Value::Boolean(value) => Some(u64::from(*value)),
        _ => None,
    }
}

fn ftenum(value: &Value) -> u32 {
    match value {
        Value::None => 0,
        Value::Boolean(_) => 2,
        Value::Uint8(_) => 4,
        Value::Uint16(_) => 5,
        Value::Uint24(_) => 6,
        Value::Uint32(_) => 7,
        Value::Uint64(_) => 11,
        Value::Int8(_) => 12,
        Value::Int16(_) => 13,
        Value::Int32(_) => 15,
        Value::Int64(_) => 19,
        Value::AbsoluteTime(_) => 24,
        Value::String(_) => 26,
        Value::Ethernet(_) => 29,
        Value::Bytes(_) | Value::Missing => 30,
        Value::Ipv4(_) => 32,
        Value::Ipv6(_) => 33,
        Value::Eui64(_) => 38,
        Value::RelativeTime(_) => 25,
        Value::Oid(_) => 37,
    }
}

#[derive(Clone, Copy)]
enum Source {
    Zero,
    One,
    Id(u32),
    Null,
}

fn raw_array(value: String, start: usize, length: usize, bitmask: u64, ftype: u32) -> Json {
    raw_array_with_source(
        Json::String(value),
        start,
        length,
        bitmask,
        ftype,
        Source::Zero,
    )
}

fn raw_array_with_source(
    value: impl Into<Json>,
    start: usize,
    length: usize,
    bitmask: u64,
    ftype: u32,
    source: Source,
) -> Json {
    let value = value.into();
    let source = match source {
        Source::Zero => Json::Number("0".to_string()),
        Source::One => Json::Number("1".to_string()),
        Source::Id(id) => Json::Number(id.to_string()),
        Source::Null => Json::Null,
    };
    Json::Array(vec![
        value,
        Json::number(start),
        Json::number(length),
        Json::number(bitmask),
        Json::number(ftype),
        source,
    ])
}

pub(crate) fn index_name(timestamp: Option<Timestamp>) -> String {
    let seconds = timestamp.map_or(0, |timestamp| timestamp.seconds);
    let (year, month, day, _, _, _) = civil_time(seconds);
    format!("packets-{year:04}-{month:02}-{day:02}")
}

pub(crate) fn absolute_time(timestamp: Timestamp) -> String {
    let (year, month, day, hour, minute, second) = civil_time(timestamp.seconds);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:09}Z",
        timestamp.nanos
    )
}

pub(crate) fn relative_time(later: Timestamp, earlier: Timestamp) -> String {
    let later_total = i128::from(later.seconds) * 1_000_000_000 + i128::from(later.nanos);
    let earlier_total = i128::from(earlier.seconds) * 1_000_000_000 + i128::from(earlier.nanos);
    let difference = later_total - earlier_total;
    let negative = difference < 0;
    let magnitude = difference.unsigned_abs();
    let seconds = magnitude / 1_000_000_000;
    let nanos = magnitude % 1_000_000_000;
    let sign = if negative { "-" } else { "" };
    format!("{sign}{seconds}.{nanos:09}")
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Write `bytes` as colon-separated lowercase hex without building a string.
/// Write `bytes` as plain lowercase hex without building a string.
pub(crate) fn write_hex_lower(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buffer = Vec::with_capacity(2 * 4096);
    for chunk in bytes.chunks(4096) {
        buffer.clear();
        for byte in chunk {
            buffer.push(DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
            buffer.push(
                DIGITS
                    .get(usize::from(byte & 0x0f))
                    .copied()
                    .unwrap_or(b'0'),
            );
        }
        writer.write_all(&buffer)?;
    }
    Ok(())
}

pub(crate) fn write_colon_hex(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut buffer = Vec::with_capacity(3 * 4096);
    let mut first = true;
    for chunk in bytes.chunks(4096) {
        buffer.clear();
        for byte in chunk {
            if !first {
                buffer.push(b':');
            }
            first = false;
            buffer.push(DIGITS.get(usize::from(byte >> 4)).copied().unwrap_or(b'0'));
            buffer.push(
                DIGITS
                    .get(usize::from(byte & 0x0f))
                    .copied()
                    .unwrap_or(b'0'),
            );
        }
        writer.write_all(&buffer)?;
    }
    Ok(())
}

pub(crate) fn colon_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            text.push(':');
        }
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Serialize one JSON value in pretty-printed form.
fn write_json(writer: &mut impl Write, value: &Json, depth: usize) -> io::Result<()> {
    match value {
        Json::Null => writer.write_all(b"null"),
        Json::Number(value) => writer.write_all(value.as_bytes()),
        Json::String(value) => write_json_string(writer, value),
        Json::Bytes(value) => {
            writer.write_all(b"\"")?;
            write_colon_hex(writer, value.as_slice())?;
            writer.write_all(b"\"")
        }
        Json::Hex(value) => {
            writer.write_all(b"\"")?;
            write_hex_lower(writer, value.as_slice())?;
            writer.write_all(b"\"")
        }
        Json::Array(values) => {
            if values.is_empty() {
                return writer.write_all(b"[]");
            }
            writer.write_all(b"[")?;
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    writer.write_all(b",")?;
                }
                writer.write_all(b"\n")?;
                write_indent(writer, depth + 1)?;
                write_json(writer, value, depth + 1)?;
            }
            writer.write_all(b"\n")?;
            write_indent(writer, depth)?;
            writer.write_all(b"]")
        }
        Json::Object {
            entries,
            merge_keys,
        } => {
            let merged: Vec<(String, Json)>;
            let entries = if *merge_keys {
                merged = merge_entries(entries);
                merged.as_slice()
            } else {
                entries.as_slice()
            };
            if entries.is_empty() {
                return writer.write_all(b"{}");
            }
            writer.write_all(b"{")?;
            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    writer.write_all(b",")?;
                }
                writer.write_all(b"\n")?;
                write_indent(writer, depth + 1)?;
                write_json_string(writer, key)?;
                writer.write_all(b": ")?;
                write_json(writer, value, depth + 1)?;
            }
            writer.write_all(b"\n")?;
            write_indent(writer, depth)?;
            writer.write_all(b"}")
        }
    }
}

fn merge_entries(entries: &[(String, Json)]) -> Vec<(String, Json)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<Json>> = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        match groups.get_mut(key) {
            Some(values) => values.push(value.clone()),
            None => {
                order.push(key.clone());
                groups.insert(key.clone(), vec![value.clone()]);
            }
        }
    }
    let mut merged: Vec<(String, Json)> = Vec::with_capacity(order.len());
    for key in order {
        let mut values = groups.remove(&key).unwrap_or_default();
        let value = if values.len() == 1 {
            values.pop().unwrap_or(Json::Null)
        } else {
            Json::Array(values)
        };
        merged.push((key, value));
    }
    merged
}

fn write_indent(writer: &mut impl Write, depth: usize) -> io::Result<()> {
    for _ in 0..depth {
        writer.write_all(b"  ")?;
    }
    Ok(())
}

pub(crate) fn write_json_string(writer: &mut impl Write, text: &str) -> io::Result<()> {
    writer.write_all(b"\"")?;
    let mut previous = '\0';
    for character in text.chars() {
        match character {
            '"' => writer.write_all(b"\\\"")?,
            '\\' => writer.write_all(b"\\\\")?,
            '\u{8}' => writer.write_all(b"\\b")?,
            '\t' => writer.write_all(b"\\t")?,
            '\n' => writer.write_all(b"\\n")?,
            '\u{c}' => writer.write_all(b"\\f")?,
            '\r' => writer.write_all(b"\\r")?,
            control if (control as u32) < 0x20 => {
                write!(writer, "\\u{:04x}", control as u32)?;
            }
            '/' if previous == '<' => writer.write_all(b"\\/")?,
            other => {
                let mut buffer = [0_u8; 4];
                writer.write_all(other.encode_utf8(&mut buffer).as_bytes())?;
            }
        }
        previous = character;
    }
    writer.write_all(b"\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetfin_core::field_by_abbrev;
    use packetfin_core::tree::FieldParent;

    fn escape(text: &str) -> String {
        let mut bytes = Vec::new();
        if let Err(error) = write_json_string(&mut bytes, text) {
            eprintln!("write failed: {error}");
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn strings_use_display_escapes() {
        assert_eq!(escape("plain"), "\"plain\"");
        assert_eq!(escape("\"\\"), "\"\\\"\\\\\"");
        assert_eq!(
            escape("\u{1}\u{7}\u{8}\t\n\u{b}\u{c}\r\u{1b}"),
            "\"\\u0001\\u0007\\b\\t\\n\\u000b\\f\\r\\u001b\""
        );
        assert_eq!(escape("</script>"), "\"<\\/script>\"");
        assert_eq!(escape("\u{7f}café"), "\"\u{7f}café\"");
    }

    #[test]
    fn duplicate_keys_keep_first_position() {
        let entries = vec![
            ("a".to_string(), Json::String("1".to_string())),
            ("b".to_string(), Json::String("2".to_string())),
            ("a".to_string(), Json::String("3".to_string())),
        ];
        let merged = merge_entries(&entries);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged.first().map(|(key, _)| key.as_str()), Some("a"));
        assert_eq!(
            merged.first().map(|(_, value)| value),
            Some(&Json::Array(vec![
                Json::String("1".to_string()),
                Json::String("3".to_string())
            ]))
        );
    }

    #[test]
    fn values_follow_json_forms() {
        let Some(flag) = field_by_abbrev("ip.flags.df") else {
            return;
        };
        assert_eq!(
            json_value(flag, &Value::Boolean(true)),
            Json::String("1".to_string())
        );
        assert_eq!(json_value(flag, &Value::None), Json::String(String::new()));
        assert_eq!(
            json_value(flag, &Value::bytes(vec![0xde, 0xad])),
            Json::Bytes(Bytes::from(vec![0xde, 0xad]))
        );
        assert_eq!(
            json_value(
                flag,
                &Value::AbsoluteTime(Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 123_456_000,
                })
            ),
            Json::String("2023-11-14T22:13:20.123456000Z".to_string())
        );
    }

    #[test]
    fn checksum_companions_use_protocol_placement() {
        let tree = crate::test_support::ip_tree(|ip| {
            ip.add_field(
                &packetfin_core::fields::IP_CHECKSUM,
                packetfin_core::Range::new(24, 2),
                Value::Uint16(0xcd4b),
            );
            ip.add_field(
                &packetfin_core::fields::IP_CHECKSUM_STATUS,
                packetfin_core::Range::new(24, 2),
                Value::Uint8(0),
            );
            ip.add_field(
                &packetfin_core::fields::IP_CHECKSUM_CALCULATED,
                packetfin_core::Range::new(24, 2),
                Value::Uint16(0x324b),
            );
            ip.add_expert(packetfin_core::tree::ExpertInfo {
                severity: packetfin_core::tree::Severity::Error,
                group: packetfin_core::tree::Group::Checksum,
                message: "Bad checksum [should be 0x324b]".to_string(),
            });
        });
        let text = squash(&render_json(tree, JsonMode::Json, &[], false));
        let tree_pos = text.find("\"ip.checksum_tree\"").unwrap_or(0);
        let status_pos = text.find("\"ip.checksum.status\"").unwrap_or(0);
        let calculated_pos = text.find("\"ip.checksum_calculated\"").unwrap_or(0);
        assert!(
            tree_pos < status_pos && status_pos < calculated_pos,
            "{text}"
        );

        let tree = crate::test_support::tcp_tree(|tcp| {
            tcp.add_field(
                &packetfin_core::fields::TCP_CHECKSUM,
                packetfin_core::Range::new(50, 2),
                Value::Uint16(0x757f),
            );
            tcp.add_field(
                &packetfin_core::fields::TCP_CHECKSUM_STATUS,
                packetfin_core::Range::new(50, 2),
                Value::Uint8(1),
            );
            tcp.add_field(
                &packetfin_core::fields::TCP_CHECKSUM_CALCULATED,
                packetfin_core::Range::new(50, 2),
                Value::Uint16(0x757f),
            );
        });
        let text = squash(&render_json(tree, JsonMode::Json, &[], false));
        assert!(
            text.contains("\"tcp.checksum_tree\":{\"tcp.checksum_calculated\":\"0x757f\"}"),
            "{text}"
        );
        assert_eq!(text.matches("\"tcp.checksum_calculated\"").count(), 1);
    }

    #[test]
    fn jsonraw_expert_markers_use_the_marker_abbreviation() {
        use packetfin_core::tree::{ExpertInfo, Group, Severity};

        let mut frame_node = Node::new(
            &packetfin_core::fields::FRAME_PROTOCOL,
            packetfin_core::Range::new(0, 128),
        );
        frame_node.add_field(
            &packetfin_core::fields::FRAME_NUMBER,
            packetfin_core::Range::new(0, 0),
            Value::Uint32(1),
        );
        let mut ospf = Node::new(
            &packetfin_core::fields::OSPF_PROTOCOL,
            packetfin_core::Range::new(34, 20),
        );
        let reserved = ospf.add_field(
            &packetfin_core::fields::OSPF_RESERVED,
            packetfin_core::Range::new(70, 1),
            Value::bytes(vec![1]),
        );
        reserved.add_expert_for(
            ExpertInfo {
                severity: Severity::Warning,
                group: Group::Protocol,
                message: "incorrect, should be 0".to_string(),
            },
            &packetfin_core::fields::OSPF_RESERVED_NOT_ZERO,
        );
        frame_node.add_child(ospf);
        let text = render_json(Tree::new(frame_node), JsonMode::JsonRaw, &[], false);
        assert!(text.contains("\"ospf.reserved.not_zero_raw\": ["), "{text}");
    }

    #[test]
    fn dhcp_option_strings_use_json_escapes() {
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
        let text = render_json(
            packetfin_core::Tree::new(frame_node),
            JsonMode::Json,
            &[],
            false,
        );
        assert!(
            text.contains(r#""dhcp.option.hostname": "a\"b\\c\n""#),
            "{text}"
        );
    }

    fn field_definition(abbrev: &str) -> &'static FieldDef {
        match field_by_abbrev(abbrev) {
            Some(field) => field,
            None => {
                eprintln!("missing field {abbrev}");
                std::process::exit(1);
            }
        }
    }

    fn node() -> Node {
        let protocol = packetfin_core::protocols()
            .iter()
            .find(|protocol| protocol.filter_name == "tcp")
            .copied()
            .unwrap_or_else(|| {
                eprintln!("missing tcp protocol");
                std::process::exit(1);
            });
        Node::new(protocol, packetfin_core::Range::new(34, 20))
    }

    #[test]
    fn masked_fields_report_parent_byte_spans() {
        let ip_flag = field_definition("ip.flags.df");
        let field = Field {
            def: ip_flag,
            range: packetfin_core::Range::new(20, 2),
            value: Value::Boolean(true),
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
        assert_eq!(masked_location(&field, 0x40), (20, 1));

        let tcp_syn = field_definition("tcp.flags.syn");
        let field = Field {
            def: tcp_syn,
            range: packetfin_core::Range::new(46, 2),
            value: Value::Boolean(true),
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
        assert_eq!(masked_location(&field, 0x02), (47, 1));
        assert_eq!(masked_location(&field, 0x10), (47, 1));

        let vlan_dei = field_definition("vlan.dei");
        let field = Field {
            def: vlan_dei,
            range: packetfin_core::Range::new(14, 2),
            value: Value::Boolean(false),
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
        assert_eq!(masked_location(&field, 0x1000), (14, 2));

        let ip_flags = field_definition("ip.flags");
        let field = Field {
            def: ip_flags,
            range: packetfin_core::Range::new(20, 2),
            value: Value::Uint8(2),
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
        assert_eq!(masked_location(&field, 0xe0), (20, 1));

        let tclass = field_definition("ipv6.tclass");
        let field = Field {
            def: tclass,
            range: packetfin_core::Range::new(14, 4),
            value: Value::Uint32(0),
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
        assert_eq!(masked_location(&field, 0x0ff0_0000), (14, 4));

        let flow = field_definition("ipv6.flow");
        let field = Field {
            def: flow,
            range: packetfin_core::Range::new(14, 4),
            value: Value::Uint32(0),
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
        assert_eq!(masked_location(&field, 0x000f_ffff), (15, 3));
    }

    #[test]
    fn comment_lines_drop_a_trailing_empty_segment() {
        assert_eq!(comment_lines("a\n"), vec!["a"]);
        assert_eq!(comment_lines("\n"), vec![""]);
        assert!(comment_lines("a").is_empty());
    }

    #[test]
    fn tcp_flags_string_raw_reuses_flags_bytes() {
        let mut node = node();
        let flags = field_definition("tcp.flags");
        node.add_field(
            flags,
            packetfin_core::Range::new(46, 2),
            Value::Uint16(0x6002),
        );
        let string = field_definition("tcp.flags.str");
        let field = Field {
            def: string,
            range: packetfin_core::Range::new(0, 0),
            value: Value::String("\\\"'".to_string()),
            generated: true,
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
        let mut captured = [0_u8; 64];
        for (index, byte) in [0x60_u8, 0x02].into_iter().enumerate() {
            if let Some(slot) = captured.get_mut(46 + index) {
                *slot = byte;
            }
        }
        assert_eq!(
            field_raw(&field, &node, &captured, &[], &[]),
            Json::Array(vec![
                Json::String("6002".to_string()),
                Json::number(46),
                Json::number(2),
                Json::number(0),
                Json::number(26),
                Json::number(0),
            ])
        );
    }

    #[test]
    fn computed_fields_use_empty_metadata() {
        let status = field_definition("ip.checksum.status");
        let field = Field {
            def: status,
            range: packetfin_core::Range::new(24, 2),
            value: Value::Uint8(2),
            generated: true,
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
        let raw = field_raw(&field, &node(), &[0_u8; 64], &[], &[]);
        assert_eq!(
            raw,
            Json::Array(vec![
                Json::String(String::new()),
                Json::number(24),
                Json::number(0),
                Json::number(0),
                Json::number(4),
                Json::number(0),
            ])
        );

        let next = field_definition("tcp.nxtseq");
        let field = Field {
            def: next,
            range: packetfin_core::Range::new(0, 0),
            value: Value::Uint32(1),
            generated: true,
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
        let raw = field_raw(&field, &node(), &[0_u8; 64], &[], &[]);
        assert_eq!(
            raw,
            Json::Array(vec![
                Json::String(String::new()),
                Json::number(34),
                Json::number(0),
                Json::number(0),
                Json::number(7),
                Json::number(0),
            ])
        );
    }

    #[test]
    fn relative_times_have_nine_digits_and_sign() {
        assert_eq!(
            relative_time(
                Timestamp {
                    seconds: 2,
                    nanos: 0
                },
                Timestamp {
                    seconds: 1,
                    nanos: 999_999_000
                }
            ),
            "0.000001000"
        );
        assert_eq!(
            relative_time(
                Timestamp {
                    seconds: 1,
                    nanos: 0
                },
                Timestamp {
                    seconds: 2,
                    nanos: 0
                }
            ),
            "-1.000000000"
        );
    }

    fn render_json(
        tree: packetfin_core::Tree,
        mode: JsonMode,
        fields: &[&'static FieldDef],
        print_hex: bool,
    ) -> String {
        let frame = crate::test_support::frame();
        let packet = crate::test_support::packet(tree);
        let mut writer = JsonWriter::new(mode, None, false, fields, print_hex);
        let mut output = Vec::new();
        assert!(writer.write_packet(&mut output, &frame, &packet).is_ok());
        assert!(writer.finish(&mut output).is_ok());
        String::from_utf8(output).unwrap_or_default()
    }

    /// Remove whitespace outside JSON strings, keeping strings intact.
    fn squash(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut in_string = false;
        let mut escaped = false;
        for character in text.chars() {
            if in_string {
                out.push(character);
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
            } else if character == '"' {
                in_string = true;
                out.push(character);
            } else if !character.is_whitespace() {
                out.push(character);
            }
        }
        out
    }

    fn render_json_filter(
        tree: packetfin_core::Tree,
        mode: JsonMode,
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
        let mut writer = JsonWriter::new(mode, filter.as_ref(), false, &[], print_hex);
        let mut output = Vec::new();
        assert!(writer.write_packet(&mut output, &frame, &packet).is_ok());
        assert!(writer.finish(&mut output).is_ok());
        String::from_utf8(output).unwrap_or_default()
    }

    #[test]
    fn unnamed_groups_use_escaped_showname_keys_and_hidden_fields_stay() {
        let tree = crate::test_support::tcp_tree(|node| {
            let group = node.add_unnamed(packetfin_core::Range::new(34, 0), "A \"B\"".to_string());
            group.add_field(
                field_definition("tcp.seq"),
                packetfin_core::Range::new(34, 4),
                Value::Uint32(7),
            );
            node.add_field(
                field_definition("tcp.ack"),
                packetfin_core::Range::new(38, 4),
                Value::Uint32(9),
            )
            .hide();
        });
        let text = render_json(tree, JsonMode::Json, &[], false);
        assert!(text.contains("\"A \\\"B\\\"\": {"), "{text}");
        assert!(text.contains("\"tcp.seq\": \"7\""), "{text}");
        assert!(text.contains("\"tcp.ack\": \"9\""), "{text}");
    }

    #[test]
    fn containers_nest_children_under_their_own_keys() {
        let text = render_json(
            crate::test_support::analysis_tree(),
            JsonMode::Json,
            &[],
            false,
        );
        assert!(text.contains("\"tcp.analysis\": {"), "{text}");
        assert!(
            text.contains("\"tcp.analysis.acks_frame\": \"1\""),
            "{text}"
        );
        assert!(text.contains("\"tcp.analysis.flags\": {"), "{text}");
        assert!(
            squash(&text).contains(
                "\"_ws.expert\":{\"tcp.analysis.retransmission\":\"\",\"_ws.expert.message\":\"This frame is a (suspected) retransmission\",\"_ws.expert.severity\":\"4194304\",\"_ws.expert.group\":\"33554432\"}"
            ),
            "{text}"
        );
        assert!(text.contains("\"tcp.analysis.rto\": \"1\""), "{text}");
        assert!(!text.contains("tcp.analysis_tree"));
    }

    #[test]
    fn bytes_containers_keep_value_and_add_a_tree() {
        let text = render_json(
            crate::test_support::fragments_tree(),
            JsonMode::Json,
            &[],
            false,
        );
        assert!(text.contains(
            "\"ip.fragments\": \"00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f\""
        ));
        assert!(text.contains("\"ip.fragments_tree\": {"));
        assert!(text.contains("\"ip.fragment\": \"1\""));
        assert!(text.contains("\"ip.fragment\": \"2\""));
    }

    #[test]
    fn packet_scoped_container_is_a_sibling_layer() {
        let text = render_json(
            crate::test_support::segments_tree(),
            JsonMode::Json,
            &[],
            false,
        );
        assert!(text.contains("\n        \"tcp.segments\": {\n"));
        assert!(text.contains("\"tcp.segment.count\": \"2\""));
    }

    #[test]
    fn jsonraw_keeps_container_raw_and_tree_keys() {
        let text = render_json(
            crate::test_support::analysis_tree(),
            JsonMode::JsonRaw,
            &[],
            false,
        );
        let compact_text = squash(&text);
        assert!(compact_text.contains("\"tcp.analysis_raw\":[\"\",34,0,0,0,0]"));
        assert!(compact_text.contains("\"tcp.analysis\":{"));
        assert!(compact_text.contains("\"_ws.expert_raw\":["));
        assert!(
            compact_text.contains("\"tcp.analysis.retransmission_raw\":[\"\",0,0,0,0,null]"),
            "{text}"
        );

        let fragments = render_json(
            crate::test_support::fragments_tree(),
            JsonMode::JsonRaw,
            &[],
            false,
        );
        assert!(
            squash(&fragments).contains(
                "\"ip.fragments_raw\":[\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",0,32,0,30,1]"
            ),
            "{fragments}"
        );
        assert!(fragments.contains("\"ip.fragments_tree\": {"));

        let completeness = render_json(
            crate::test_support::completeness_tree(),
            JsonMode::JsonRaw,
            &[],
            false,
        );
        assert!(
            squash(&completeness).contains("\"tcp.completeness_raw\":[\"\",0,0,0,4,null]"),
            "{completeness}"
        );
    }

    #[test]
    fn json_filters_container_trees_by_name() {
        let filtered = render_json_filter(
            crate::test_support::analysis_tree(),
            JsonMode::Json,
            false,
            &[("tcp", false)],
        );
        assert!(
            squash(&filtered).contains("\"tcp.analysis\":{\"filtered\":\"tcp.analysis\"}"),
            "{filtered}"
        );
        assert!(!filtered.contains("tcp.analysis.acks_frame"), "{filtered}");

        let open = render_json_filter(
            crate::test_support::analysis_tree(),
            JsonMode::Json,
            false,
            &[("tcp", false), ("tcp.analysis", false)],
        );
        assert!(
            open.contains("\"tcp.analysis.acks_frame\": \"1\""),
            "{open}"
        );
        assert!(
            squash(&open).contains("\"tcp.analysis.flags\":{\"filtered\":\"tcp.analysis.flags\"}"),
            "{open}"
        );

        let bytes = render_json_filter(
            crate::test_support::fragments_tree(),
            JsonMode::Json,
            false,
            &[("ip", false)],
        );
        assert!(bytes.contains("\"ip.fragments\": \"00:01"), "{bytes}");
        assert!(
            squash(&bytes).contains("\"ip.fragments_tree\":{\"filtered\":\"ip.fragments\"}"),
            "{bytes}"
        );
    }

    #[test]
    fn json_packet_scoped_container_keeps_its_filtered_key() {
        for names in [
            &[("tcp", false)][..],
            &[("tcp", true)][..],
            &[("dns", false)][..],
        ] {
            let text = render_json_filter(
                crate::test_support::segments_tree(),
                JsonMode::Json,
                false,
                names,
            );
            assert!(
                squash(&text).contains("\"tcp.segments\":{\"filtered\":\"tcp.segments\"}"),
                "{text}"
            );
        }

        let open = render_json_filter(
            crate::test_support::segments_tree(),
            JsonMode::Json,
            false,
            &[("tcp", false), ("tcp.segments", false)],
        );
        assert!(open.contains("\"tcp.segment\": \"4\""), "{open}");
        assert!(
            !squash(&open).contains("\"tcp.segments\":{\"filtered\""),
            "{open}"
        );
    }

    #[test]
    fn selected_containers_keep_flat_json_values() {
        let fields = [
            &crate::test_support::ANALYSIS,
            &crate::test_support::ANALYSIS_ACKS_FRAME,
        ];
        let text = render_json(
            crate::test_support::analysis_tree(),
            JsonMode::Json,
            &fields,
            false,
        );
        assert!(text.contains("\"tcp.analysis\": [\n          \"1\"\n        ]"));
        assert!(text.contains("\"tcp.analysis.acks_frame\": [\n          \"1\"\n        ]"));
        assert!(!text.contains("_tree"));
    }
}
