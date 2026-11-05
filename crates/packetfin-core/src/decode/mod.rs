//! Frame decoding: dispatch, summary columns and the decoded packet.
//!
//! [`decode_frame`] is the entry point used by output modes. It builds the
//! frame node, then walks the registry's link-type table and lets each
//! decoder add its protocol node and fields.

mod arp;
mod bfd;
mod bgp;
mod bytes;
mod cflow;
mod checksum;
mod dhcp;
mod dhcpv6;
mod dns;
mod erspan;
mod ethernet;
mod fragment;
mod frame;
mod geneve;
mod gre;
mod http;
mod icmp;
mod icmpv6;
mod ipv4;
mod ipv6;
mod lacp;
mod llc;
mod lldp;
mod marker;
mod mpls;
mod ntp;
mod null;
mod ospf;
pub mod policy;
mod raw;
mod sflow;
mod sll;
mod slow;
mod snmp;
mod stp;
mod syslog;
mod tcp;
pub(crate) mod tls;
mod udp;
mod vlan;
mod vrrp;
mod vxlan;

pub(crate) use arp::decode as arp;
pub(crate) use bfd::{decode_control as bfd, decode_echo as bfd_echo};
pub(crate) use bgp::decode as bgp;
pub use bytes::hex_lower;
pub(crate) use cflow::decode as cflow;
pub(crate) use dhcp::decode as dhcp;
pub use dhcp::main_area_decoded_message_type as dhcp_main_area_decoded_message_type;
pub use dhcp::main_area_message_type as dhcp_main_area_message_type;
pub use dhcp::option_name as dhcp_option_name;
pub(crate) use dhcpv6::decode as dhcpv6;
pub use dhcpv6::option_name as dhcpv6_option_name;
pub(crate) use dns::{
    decode_dns as dns, decode_llmnr as llmnr, decode_mdns as mdns, decode_tcp as dns_tcp,
    looks_like_dns,
};
pub use dns::{opcode_text, rcode_text, type_text};
pub(crate) use erspan::{decode as erspan, decode_type_one as erspan_type_one};
pub(crate) use ethernet::decode as ethernet;
pub(crate) use fragment::{
    add_ipv4_fields as ipv4_fragment_fields, add_ipv6_fields as ipv6_fragment_fields,
    annotate_reassembled_fields,
};
pub(crate) use geneve::decode as geneve;
pub(crate) use gre::decode as gre;
pub(crate) use http::{decode as http, looks_like_http_prefix, looks_like_http_stream_prefix};
pub(crate) use icmp::decode as icmp;
pub(crate) use icmpv6::decode as icmpv6;
pub(crate) use ipv4::decode as ipv4;
pub(crate) use ipv6::{
    decode as ipv6, decode_dstopts_standalone as ipv6_dstopts,
    decode_fraghdr_standalone as ipv6_fraghdr, decode_hopopts_standalone as ipv6_hopopts,
    decode_routing_standalone as ipv6_routing,
};
pub(crate) use lacp::decode as lacp;
pub(crate) use llc::decode as llc;
pub(crate) use lldp::decode as lldp;
pub(crate) use marker::decode as marker;
pub(crate) use mpls::decode as mpls;
pub(crate) use ntp::decode as ntp;
pub(crate) use null::{decode_loopback as loopback, decode_null as null};
pub(crate) use ospf::decode as ospf;
pub(crate) use raw::{decode as raw_ip, decode_ipv4 as raw_ipv4, decode_ipv6 as raw_ipv6};
pub(crate) use sflow::decode as sflow;
pub(crate) use sll::{decode_v1 as sll, decode_v2 as sll2};
pub(crate) use slow::decode as slow;
pub(crate) use snmp::decode as snmp;
pub(crate) use stp::decode as stp;
pub(crate) use syslog::decode as syslog;
pub(crate) use tcp::decode as tcp;
pub(crate) use tls::decode as tls;
pub use tls::{ExportedKey, KeyLog};
pub(crate) use udp::decode as udp;
pub(crate) use vlan::{decode as vlan, decode_8021ad as ieee8021ad};
pub(crate) use vrrp::decode as vrrp;
pub(crate) use vxlan::decode as vxlan;

use crate::capture::{Frame, Timestamp};
use crate::fields::{self, Protocol};
use crate::names::{NameResolver, Resolution};
use crate::state::{
    ConversationKey, FrameInfo, NoopObserver, PassMode, SessionState, StreamObserver,
};
use crate::tree::{Bytes, ExpertInfo, Group, Node, Range, Severity, Tree};

pub use policy::{
    DecodeAsEntry, DecodeAsError, DecodeAsTable, DecodeOptions, HEURISTICS, HeuristicDef,
    LayerType, PREF_DEFS, PrefDef, PrefError, PrefKind, Preferences, ProtocolPolicy, Selector,
    apply_preference, forced_decoder, heuristic, heuristic_decoder, nameres_from_flags,
    parse_decode_as, parse_selector,
};

/// Deepest protocol nesting the decoders will follow.
///
/// Tunnels and encapsulated protocols recurse through the dispatch tables;
/// this limit keeps hostile captures from exhausting the stack.
pub const MAX_DECODE_DEPTH: usize = 16;

/// Summary-column values for one packet.
///
/// Output formats own their rendering; the decoder fills the typed values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Columns {
    /// Frame number.
    pub number: Option<u64>,
    /// Capture time.
    pub time: Option<Timestamp>,
    /// Source address, when the link layer supplies one.
    pub source: Option<String>,
    /// Destination address, when the link layer supplies one.
    pub destination: Option<String>,
    /// Protocol summary, such as `0x1234` or `Ethernet`.
    pub protocol: Option<String>,
    /// One-line packet description.
    pub info: Option<String>,
    /// Original frame length.
    pub length: Option<u32>,
}

/// The innermost network layer, for transport decoders.
///
/// IPv4 and IPv6 fill this before handing their payload to a protocol
/// decoder. The fragment flag is set when the packet is part of a fragmented
/// datagram, in which case no transport decoder is called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkContext {
    /// An IPv4 datagram.
    Ipv4 {
        /// Source address.
        source: [u8; 4],
        /// Destination address.
        destination: [u8; 4],
        /// Protocol number from the IPv4 header.
        protocol: u8,
        /// Whether the datagram is fragmented.
        fragmented: bool,
    },
    /// An IPv6 datagram.
    Ipv6 {
        /// Source address.
        source: [u8; 16],
        /// Destination address.
        destination: [u8; 16],
        /// Final next-header value, after any extension headers.
        next_header: u8,
        /// Whether a fragment header marks the datagram as fragmented.
        fragmented: bool,
    },
}

/// Ports of the innermost transport layer being decoded.
///
/// Application decoders that keep state need the source port as part of
/// their stream key; the UDP and TCP decoders set this before dispatching
/// their payload and restore the previous value afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportContext {
    /// Transport source port.
    pub source_port: u16,
    /// Transport destination port.
    pub destination_port: u16,
    /// IP protocol number of the transport (17 for UDP, 6 for TCP).
    pub protocol: u8,
}

impl NetworkContext {
    /// The destination IP address, for name learning.
    pub fn destination_ip(self) -> std::net::IpAddr {
        match self {
            Self::Ipv4 { destination, .. } => {
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(destination))
            }
            Self::Ipv6 { destination, .. } => {
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(destination))
            }
        }
    }
}

/// State shared by the decoders while one packet is decoded.
pub struct DecodeContext<'a> {
    /// Capture metadata for the frame being decoded.
    pub frame: FrameInfo,
    /// Cross-packet state for the decode session.
    pub state: &'a mut SessionState,
    /// Address and port names for this session.
    pub names: &'a mut NameResolver,
    /// Summary columns to fill.
    pub columns: &'a mut Columns,
    /// Filter names of the protocols decoded so far, outermost first.
    pub protocol_stack: &'a mut Vec<&'static str>,
    /// Set when any decoder finds malformed or truncated data.
    pub malformed: &'a mut bool,
    /// Options that change which fields the decoders produce.
    pub options: &'a DecodeOptions,
    /// Innermost network layer, for transport decoders.
    pub network: &'a mut Option<NetworkContext>,
    /// Innermost transport ports, for application decoders that key state.
    pub transport: &'a mut Option<TransportContext>,
    /// Set when a `-d ...,data` entry replaced a table dispatching a payload.
    pub forced_data: &'a mut bool,
    /// Number of protocol layers currently being decoded.
    pub depth: usize,
    /// Whether the payload being decoded is decrypted TLS application data.
    ///
    /// HTTP uses this to report `https://` in `http.request.full_uri`.
    pub(crate) tls_plaintext: bool,
    /// Data source holding a reassembled PDU's ciphertext, when the caller
    /// decodes one from the TCP reassembly buffer instead of a frame.
    pub(crate) tls_record_source: Option<u32>,
    /// The reassembly buffer backing the current HTTP PDU.
    ///
    /// A body slice of this buffer is shared into the field tree instead of
    /// copied, so a multi-MiB object has one retained allocation.
    pub(crate) pdu_bytes: Option<Bytes>,
    /// Whether this frame only updates cross-packet state.
    ///
    /// The two-pass output pass decodes read-filter-rejected frames so split
    /// stream PDUs still reassemble, but they must not feed response-link
    /// state, which comes only from displayed frames.
    pub observe_only: bool,
    /// Which analysis pass this decode belongs to.
    pub pass: PassMode,
    /// Ports of the UDP datagram whose payload is being decoded, when the
    /// current layer is inside one. DNS transaction keys include them.
    pub udp_ports: Option<(u16, u16)>,
    /// Whether decoding a header quoted inside an ICMP error message.
    ///
    /// Truncation inside a quoted header is reported without marking the
    /// packet malformed and without the warnings that apply to the outermost
    /// headers, so the network and transport decoders suppress those entries
    /// while this flag is set.
    pub quoted: bool,
    /// Ports of the enclosing transport segment, for conversation state.
    pub(crate) transport_ports: Option<(u16, u16)>,
    /// Stream number assigned to the enclosing TCP segment.
    pub(crate) tcp_stream: Option<crate::state::StreamAssignment>,
    /// Header sequence number of the enclosing TCP segment.
    pub(crate) tcp_sequence: Option<u32>,
    /// Reported length of the transport payload being decoded.
    ///
    /// The enclosing IP header declares how long its payload is, while the
    /// frame may hold fewer bytes. The minimum is the length the transport
    /// layer reports; a capture cut inside the payload is not a malformed
    /// message and its checksum is unverified.
    pub reported_length: usize,
    /// Original length of the whole frame on the wire.
    pub frame_reported_length: usize,
    /// Object-export sink for `--export-objects`, when enabled.
    pub objects: Option<&'a mut (dyn crate::export::ObjectSink + 'static)>,
    /// Follow-statistics sink; decoders never inspect it.
    pub(crate) observer: &'a mut dyn StreamObserver,
    /// Request URI of the last HTTP message decoded in this frame.
    ///
    /// A same-frame continuation object takes its name from the message that
    /// preceded it; a continuation in a new frame has no association and uses
    /// the `object<frame>` fallback.
    pub(crate) http_last_uri: Option<String>,
    /// Offset of the current HTTP PDU within the enclosing TCP payload.
    pub(crate) http_pdu_offset: usize,
    /// The current HTTP PDU is continuation file data.
    pub(crate) http_continuation: bool,
    /// The current HTTP PDU was completed at end of stream.
    pub(crate) http_fin: bool,
    /// Decrypted plaintext buffers produced by this frame's decoders.
    ///
    /// A [`Range`] with a nonzero source indexes this vector one-based; the
    /// bytes are retained for PDML raw values while the capture itself stays
    /// untouched.
    pub data_sources: &'a mut Vec<Bytes>,
    /// What each data source holds, in the one-based order of the JSON `_raw`
    /// source ids (`1` reassembled, `2` decrypted plaintext).
    pub data_source_kinds: &'a mut Vec<DataSourceKind>,
}

/// The origin of a [`Packet::data_sources`] buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataSourceKind {
    /// A PDU reassembled from TCP segments.
    Reassembled,
    /// Decrypted TLS content.
    Plaintext,
}

impl DecodeContext<'_> {
    /// Mark the packet malformed and attach an expert-info entry to the node
    /// that found the problem.
    ///
    /// Inside a quoted header the expert and the packet flag are both
    /// suppressed, because a short quoted copy is expected data, not a
    /// malformed packet.
    pub fn mark_malformed(&mut self, node: &mut Node, message: &'static str) {
        if self.quoted {
            return;
        }
        *self.malformed = true;
        node.protocol_exception = true;
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Malformed,
            message: message.to_string(),
        });
    }

    /// The direction-independent conversation tuple for a transport segment.
    ///
    /// A fragmented datagram is not handed to the transport decoder until
    /// reassembly, so it has no conversation. A header quoted inside an ICMP
    /// error still gets a conversation: the quote consumes a stream number and
    /// a later flow on a new tuple gets the next one.
    pub(crate) fn conversation_key(
        &self,
        source_port: u16,
        destination_port: u16,
    ) -> Option<(ConversationKey, usize)> {
        match self.network.as_ref()? {
            NetworkContext::Ipv4 {
                source,
                destination,
                fragmented: false,
                ..
            } => Some(ConversationKey::ipv4(
                *source,
                source_port,
                *destination,
                destination_port,
            )),
            NetworkContext::Ipv6 {
                source,
                destination,
                fragmented: false,
                ..
            } => Some(ConversationKey::ipv6(
                *source,
                source_port,
                *destination,
                destination_port,
            )),
            _ => None,
        }
    }

    /// Reserve a decrypted TLS plaintext data source.
    pub(crate) fn reserve_plaintext_source(&mut self) -> u32 {
        self.reserve_data_source(DataSourceKind::Plaintext)
    }

    /// Reserve a reassembled-PDU data source.
    pub(crate) fn reserve_reassembled_source(&mut self) -> u32 {
        self.reserve_data_source(DataSourceKind::Reassembled)
    }

    fn reserve_data_source(&mut self, kind: DataSourceKind) -> u32 {
        let id = self.data_sources.len().saturating_add(1);
        self.data_sources.push(Bytes::default());
        self.data_source_kinds.push(kind);
        u32::try_from(id).unwrap_or(u32::MAX)
    }

    /// Store the bytes for a reserved data source.
    pub(crate) fn set_data_source(&mut self, source: u32, bytes: Bytes) {
        let Some(index) = source.checked_sub(1).map(usize::try_from) else {
            return;
        };
        let Ok(index) = index else {
            return;
        };
        if let Some(slot) = self.data_sources.get_mut(index) {
            *slot = bytes;
        }
    }

    /// Attach a malformed expert to the offending field instead of reporting a
    /// protocol exception.
    pub fn mark_field_malformed(&mut self, node: &mut Node, message: &'static str) {
        if self.quoted {
            return;
        }
        *self.malformed = true;
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Malformed,
            message: message.to_string(),
        });
    }

    /// Attach a truncation expert and mark the packet malformed unless the
    /// node is inside a quoted header.
    ///
    /// IPv6 adds a malformed expert even for a quoted short copy, while the
    /// packet-level flag still only follows the outer headers.
    pub fn mark_truncation(&mut self, node: &mut Node, message: &'static str) {
        node.protocol_exception = true;
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Malformed,
            message: message.to_string(),
        });
        if !self.quoted {
            *self.malformed = true;
        }
    }
}

/// Hand one layer's payload to a registered decoder.
///
/// The policy is checked here so decoders that call `dispatch` directly
/// (GRE, slow protocols, ERSPAN and LLC) cannot bypass it. The depth limit is
/// checked before the call: at the limit the payload stays opaque and the
/// calling node gains a malformed expert entry.
pub(crate) fn dispatch(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    protocol: Option<Protocol>,
    data: &[u8],
    base: usize,
) {
    let Some(protocol) = protocol else {
        return;
    };
    dispatch_override(context, parent, protocol, protocol.decoder(), data, base);
}

/// Dispatch with an explicit decoder for a protocol whose entry point depends
/// on packet context (GRE's ERSPAN type selection).
pub(crate) fn dispatch_override(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    protocol: Protocol,
    decoder: fields::Decoder,
    data: &[u8],
    base: usize,
) {
    if !context.options.policy.enabled(protocol) {
        return;
    }
    if protocol == Protocol::Data {
        *context.forced_data = true;
    }
    if context.depth >= MAX_DECODE_DEPTH {
        context.mark_truncation(parent, "Decoding depth limit reached");
        return;
    }
    decoder(context, parent, data, base);
}

/// The shared dispatch path for tables that support `-d` and heuristics.
fn dispatch_layer(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    layer: LayerType,
    values: &[u32],
    normal: Option<Protocol>,
    data: &[u8],
    base: usize,
) {
    if let Some(forced) = context.options.decode_as.lookup(layer, values) {
        if !context.options.policy.enabled(forced) {
            return;
        }
        if forced == Protocol::Data {
            *context.forced_data = true;
        }
        if let Some(decoder) = forced_decoder(forced, layer, data) {
            if context.depth >= MAX_DECODE_DEPTH {
                context.mark_truncation(parent, "Decoding depth limit reached");
            } else {
                decoder(context, parent, data, base);
            }
            return;
        }
    }

    if let Some(protocol) = normal {
        if !context.options.policy.enabled(protocol) {
            return;
        }
        if context.depth >= MAX_DECODE_DEPTH {
            context.mark_truncation(parent, "Decoding depth limit reached");
            return;
        }
        let decoder = if layer == LayerType::TcpPort && protocol == Protocol::Dns {
            dns_tcp
        } else {
            protocol.decoder()
        };
        decoder(context, parent, data, base);
        return;
    }

    for heuristic in HEURISTICS
        .iter()
        .filter(|heuristic| heuristic.layer == layer)
    {
        if !context.options.policy.heuristic_enabled(heuristic)
            || !context.options.policy.enabled(heuristic.protocol)
        {
            continue;
        }
        let Some(decoder) = heuristic_decoder(heuristic.protocol, layer, data) else {
            continue;
        };
        if context.depth >= MAX_DECODE_DEPTH {
            context.mark_truncation(parent, "Decoding depth limit reached");
        } else {
            decoder(context, parent, data, base);
        }
        return;
    }
}

/// Dispatch a payload by EtherType.
pub(crate) fn dispatch_ethertype(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    ethertype: u16,
    data: &[u8],
    base: usize,
) {
    dispatch_layer(
        context,
        parent,
        LayerType::Ethertype,
        &[u32::from(ethertype)],
        fields::registry().protocol_for_ethertype(ethertype),
        data,
        base,
    );
}

/// Dispatch a payload by IP version nibble.
pub(crate) fn dispatch_ip_version(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    version: u8,
    data: &[u8],
    base: usize,
) {
    dispatch(
        context,
        parent,
        fields::registry().protocol_for_ip_version(version),
        data,
        base,
    );
}

/// Dispatch a payload by IP protocol number.
///
/// The table holds the registered transport decoders; a packet with an
/// unregistered protocol simply keeps its network layer.
pub(crate) fn dispatch_ip_protocol(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    protocol: u8,
    data: &[u8],
    base: usize,
) {
    dispatch_layer(
        context,
        parent,
        LayerType::IpProto,
        &[u32::from(protocol)],
        fields::registry().protocol_for_ip_protocol(protocol),
        data,
        base,
    );
}

/// Dispatch a UDP payload by either port, then by the DNS heuristic.
pub(crate) fn dispatch_udp_ports(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    source: u16,
    destination: u16,
    data: &[u8],
    base: usize,
) {
    let preferences = &context.options.preferences;
    let netflow = &preferences.cflow_netflow_ports;
    let ipfix = &preferences.cflow_ipfix_ports;
    // Registered port decoders keep their table priority. The cflow
    // preference lists are a fallback, so `-o cflow.netflow.ports:53` cannot
    // steal a DNS datagram from the DNS port table.
    let normal = fields::udp_port_protocol(source, destination).or_else(|| {
        if netflow.contains(&source)
            || netflow.contains(&destination)
            || ipfix.contains(&source)
            || ipfix.contains(&destination)
        {
            Some(Protocol::Cflow)
        } else {
            None
        }
    });
    dispatch_layer(
        context,
        parent,
        LayerType::UdpPort,
        &[u32::from(source), u32::from(destination)],
        normal,
        data,
        base,
    );
}

/// Decode a TCP payload by port, then by the HTTP heuristic.
///
/// The port decoders run first and claim the payload by adding a protocol
/// node; a decoder that rejects the bytes (an invalid BGP marker, a TLS port
/// carrying plain text) leaves the node list unchanged, and the strict HTTP
/// start-line check gets the payload afterwards. That check applies on any
/// port, which is how plain HTTP on 443 or 179 is decoded.
pub(crate) fn dispatch_tcp_payload(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    ports: (u16, u16),
    stream: Option<crate::state::StreamAssignment>,
    sequence: Option<u32>,
    data: &[u8],
    base: usize,
) {
    let saved_ports = context.transport_ports;
    let saved_stream = context.tcp_stream;
    let saved_sequence = context.tcp_sequence;
    context.transport_ports = Some(ports);
    context.tcp_stream = stream;
    context.tcp_sequence = sequence;
    let before = parent.children.len();
    dispatch_layer(
        context,
        parent,
        LayerType::TcpPort,
        &[u32::from(ports.0), u32::from(ports.1)],
        fields::tcp_port_decoder(ports.0, ports.1),
        data,
        base,
    );
    if parent.children.len() == before && context.depth < MAX_DECODE_DEPTH {
        if context.options.policy.enabled(Protocol::Http) && http::looks_like_http(data) {
            http::decode(context, parent, data, base);
        } else if context.options.policy.enabled(Protocol::Tls)
            && crate::decode::tls::looks_like_tls(data)
        {
            crate::decode::tls::decode(context, parent, data, base);
        }
    }
    context.transport_ports = saved_ports;
    context.tcp_stream = saved_stream;
    context.tcp_sequence = saved_sequence;
}

/// Decode a datagram quoted inside an ICMP error message.
///
/// The quoted copy is dispatched by its IP version nibble, with the outer
/// packet's network context and columns left untouched. `context.quoted`
/// stays set while the copy decodes so the network and transport decoders
/// suppress outer-header warnings and checksum validation.
pub(crate) fn dispatch_quoted(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    quoted: &[u8],
    base: usize,
) {
    let saved_network = *context.network;
    let saved_transport = *context.transport;
    let saved_quoted = context.quoted;
    let saved_reported = context.reported_length;
    // A quoted header is data carried inside a packet: analysis and
    // reassembly state stay out of it. Conversation stream numbers are still
    // assigned, because the quoted transport is classified the same way as
    // ordinary traffic.
    let saved_suspended = context.state.set_suspended(true);
    context.quoted = true;
    let version = quoted.first().copied().unwrap_or(0) >> 4;
    // Dispatch into a scratch parent so every node produced by the quoted
    // copy can be marked without touching the enclosing protocol's fields.
    let mut scratch = Node::new(parent.protocol, Range::new(0, 0));
    dispatch_ip_version(context, &mut scratch, version, quoted, base);
    for mut child in scratch.children.drain(..) {
        child.mark_quoted();
        parent.add_child(child);
    }
    context.state.set_suspended(saved_suspended);
    *context.network = saved_network;
    *context.transport = saved_transport;
    context.quoted = saved_quoted;
    context.reported_length = saved_reported;
}

/// One decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Protocol tree rooted at the frame pseudo-protocol.
    pub tree: Tree,
    /// Summary-column values.
    pub columns: Columns,
    /// Filter names of decoded protocols, outermost first.
    pub protocol_stack: Vec<&'static str>,
    /// Whether any decoder found malformed or truncated data.
    pub malformed: bool,
    /// Innermost network layer, when one was decoded.
    pub network: Option<NetworkContext>,
    /// Whether a forced `data` entry suppressed a table's payload decoder.
    pub forced_data: bool,
    /// The name-resolution switches used while decoding.
    pub resolution: Resolution,
    /// Decrypted plaintext buffers referenced by nonzero range sources.
    pub data_sources: Vec<Bytes>,
    /// The origin of each data-source buffer, parallel to `data_sources`.
    pub data_source_kinds: Vec<DataSourceKind>,
}

/// Decode one captured frame into a protocol tree and summary columns.
///
/// This is [`decode_frame_with_options`] with the default preferences.
pub fn decode_frame(frame: &Frame) -> Packet {
    decode_frame_with_options(frame, DecodeOptions::default())
}

/// Decode one captured frame with explicit decoder options.
///
/// Decoding never fails: a decoder that runs out of bytes keeps the fields it
/// already added, records an expert-info entry and clears the malformed flag's
/// silence by setting [`Packet::malformed`]. An unregistered link type still
/// produces the frame node and its frame fields.
///
/// Each call starts a fresh one-frame session, so callers that decode a
/// sequence of frames with shared state use [`crate::state::DecodeSession`].
pub fn decode_frame_with_options(frame: &Frame, mut options: DecodeOptions) -> Packet {
    let hosts = std::mem::take(&mut options.hosts);
    let mut names = NameResolver::new(options.preferences.nameres, hosts);
    let mut state = SessionState::new(crate::state::DEFAULT_STATE_BUDGET);
    let info = FrameInfo::single(frame);
    decode_frame_inner(
        frame,
        &options,
        &mut names,
        &mut state,
        info,
        None,
        &mut NoopObserver,
        PassMode::One,
        false,
    )
}

/// Decode one frame into a packet using caller-owned session state.
#[expect(
    clippy::too_many_arguments,
    reason = "packet, options, state, frame info, sinks and pass mode are independent"
)]
pub(crate) fn decode_frame_inner(
    frame: &Frame,
    options: &DecodeOptions,
    names: &mut NameResolver,
    state: &mut SessionState,
    info: FrameInfo,
    objects: Option<&mut (dyn crate::export::ObjectSink + 'static)>,
    observer: &mut dyn StreamObserver,
    pass: PassMode,
    observe_only: bool,
) -> Packet {
    let mut columns = Columns::default();
    let mut protocol_stack = Vec::new();
    let mut malformed = false;
    let mut network = None;
    let mut transport = None;
    let mut forced_data = false;
    let mut data_sources = Vec::new();
    let mut data_source_kinds = Vec::new();
    let mut root = Node::new(&fields::FRAME_PROTOCOL, Range::new(0, frame.captured.len()));
    frame::decode(&mut root, frame, info, &mut columns);

    {
        let mut context = DecodeContext {
            frame: info,
            state,
            names,
            columns: &mut columns,
            protocol_stack: &mut protocol_stack,
            malformed: &mut malformed,
            options,
            network: &mut network,
            transport: &mut transport,
            forced_data: &mut forced_data,
            depth: 0,
            tls_plaintext: false,
            tls_record_source: None,
            pdu_bytes: None,
            observe_only,
            quoted: false,
            transport_ports: None,
            tcp_stream: None,
            tcp_sequence: None,
            reported_length: frame.captured.len(),
            frame_reported_length: usize::try_from(frame.original_len)
                .unwrap_or(usize::MAX)
                .max(frame.captured.len()),
            objects,
            observer,
            http_last_uri: None,
            http_pdu_offset: 0,
            http_continuation: false,
            http_fin: false,
            data_sources: &mut data_sources,
            data_source_kinds: &mut data_source_kinds,
            pass,
            udp_ports: None,
        };
        if let Some((protocol, decoder)) = fields::registry().link_decoder(frame.link_type)
            && protocol.is_none_or(|protocol| options.policy.enabled(protocol))
        {
            decoder(&mut context, &mut root, &frame.captured, 0);
        }
    }

    Packet {
        tree: Tree::new(root),
        columns,
        protocol_stack,
        malformed,
        network,
        forced_data,
        resolution: options.preferences.nameres.resolution(),
        data_sources,
        data_source_kinds,
    }
}
