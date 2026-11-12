//! The protocol and field registry.
//!
//! Every protocol decoder declares its fields here, in the order the
//! `-G fields` report prints them. The registry is built once, on first use,
//! and serves field lookup, the protocol list and the decoder dispatch
//! tables. Field definitions are static so a decoded tree can refer to the
//! definition without copying it.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::decode::{self, DecodeContext};
use crate::tree::Node;

/// The type of a field's value.
///
/// The names follow the field types the `-G fields` report prints, so a
/// registry entry can be reported without a second table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// Unsigned 8-bit integer (`FT_UINT8`).
    Uint8,
    /// Unsigned 16-bit integer (`FT_UINT16`).
    Uint16,
    /// Unsigned 24-bit integer (`FT_UINT24`).
    Uint24,
    /// Unsigned 32-bit integer (`FT_UINT32`).
    Uint32,
    /// Unsigned 64-bit integer (`FT_UINT64`).
    Uint64,
    /// Signed 8-bit integer (`FT_INT8`).
    Int8,
    /// Signed 16-bit integer (`FT_INT16`).
    Int16,
    /// Signed 32-bit integer (`FT_INT32`).
    Int32,
    /// Signed 64-bit integer (`FT_INT64`).
    Int64,
    /// Boolean (`FT_BOOLEAN`).
    Boolean,
    /// 48-bit IEEE 802 MAC address (`FT_ETHER`).
    Ethernet,
    /// 64-bit IEEE EUI-64 address (`FT_EUI64`).
    Eui64,
    /// IPv4 address (`FT_IPv4`).
    Ipv4,
    /// IPv6 address (`FT_IPv6`).
    Ipv6,
    /// UTF-8 string (`FT_STRING`).
    String,
    /// NUL-terminated UTF-8 string (`FT_STRINGZ`).
    StringZ,
    /// NUL-padded string (`FT_STRINGZPAD`).
    StringzPad,
    /// Object identifier (`FT_OID`).
    Oid,
    /// Double-precision floating point (`FT_DOUBLE`).
    Double,
    /// Uninterpreted bytes (`FT_BYTES`).
    Bytes,
    /// A field with no value (`FT_NONE`).
    None,
    /// Absolute capture time (`FT_ABSOLUTE_TIME`).
    AbsoluteTime,
    /// Relative time in nanoseconds (`FT_RELATIVE_TIME`).
    ///
    /// The value is stored as [`crate::tree::Value::RelativeTime`]; the
    /// renderer prints seconds with nine fractional digits, and filters
    /// compare it in seconds.
    RelativeTime,
    /// A one-based frame number reference (`FT_FRAMENUM`).
    FrameNumber,
}

impl FieldType {
    /// The field-type name the `-G fields` report uses.
    pub const fn abbreviation(self) -> &'static str {
        match self {
            Self::Uint8 => "FT_UINT8",
            Self::Uint16 => "FT_UINT16",
            Self::Uint24 => "FT_UINT24",
            Self::Uint32 => "FT_UINT32",
            Self::Uint64 => "FT_UINT64",
            Self::Int8 => "FT_INT8",
            Self::Int16 => "FT_INT16",
            Self::Int32 => "FT_INT32",
            Self::Int64 => "FT_INT64",
            Self::Boolean => "FT_BOOLEAN",
            Self::Ethernet => "FT_ETHER",
            Self::Eui64 => "FT_EUI64",
            Self::Ipv4 => "FT_IPv4",
            Self::Ipv6 => "FT_IPv6",
            Self::String => "FT_STRING",
            Self::StringZ => "FT_STRINGZ",
            Self::StringzPad => "FT_STRINGZPAD",
            Self::Oid => "FT_OID",
            Self::Double => "FT_DOUBLE",
            Self::Bytes => "FT_BYTES",
            Self::None => "FT_NONE",
            Self::AbsoluteTime => "FT_ABSOLUTE_TIME",
            Self::RelativeTime => "FT_RELATIVE_TIME",
            Self::FrameNumber => "FT_FRAMENUM",
        }
    }
}

/// How a numeric field value is displayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Display {
    /// Base 10, reported as `BASE_DEC`.
    Decimal,
    /// Base 10 with a hexadecimal form in the detail view, reported as
    /// `BASE_DEC_HEX`. `-T fields` prints the decimal value.
    DecHex,
    /// Base 16 with a `0x` prefix, reported as `BASE_HEX`.
    Hex,
    /// Base 16 with a `0x` prefix for an integer reported as
    /// `BASE_HEX_DEC`.
    HexDec,
    /// Organizationally Unique Identifier, reported as `BASE_OUI`. `-T fields`
    /// prints the numeric value in base 10.
    Oui,
    /// TCP port number, reported as `BASE_PT_TCP`.
    PortTcp,
    /// UDP port number, reported as `BASE_PT_UDP`.
    PortUdp,
    /// Boolean field whose report column is zero, as printed for a flag that
    /// is not tied to a named parent width.
    Boolean0,
    /// Boolean field whose report column names a 6-bit parent, such as
    /// `bfd.flags.c`.
    Boolean6,
    /// Boolean field whose report column names an 8-bit parent, such as
    /// `ip.flags.df`.
    Boolean8,
    /// Boolean field whose report column names a 12-bit parent, such as
    /// `tcp.flags.syn`.
    Boolean12,
    /// Boolean field whose report column names the parent bit width, such as
    /// `vlan.dei`.
    Boolean16,
    /// Boolean field whose report column names a 24-bit parent, such as
    /// `ospf.v3.options.e`.
    Boolean24,
    /// Boolean field whose report column names a 32-bit parent, such as
    /// `icmpv6.nd.na.flag.r`.
    Boolean32,
    /// No explicit display base, reported as an empty display column.
    None,
    /// `BASE_NONE`, which still renders numerically.
    BaseNone,
    /// A 16-bit STP timer in 1/256-second units, reported without a base.
    Seconds256,
    /// `BASE_CUSTOM`: the detail view adds a unit-specific text.
    Custom,
    /// An absolute time in ISO 8601 with a numeric UTC offset. The
    /// `-G fields` row has an empty display column for these fields.
    IsoTime,
    /// An absolute time rendered as ISO 8601 with a `Z` zone.
    IsoTimeZ,
    /// An integer rendered as eight hexadecimal digits in `-T fields` while
    /// its `-G fields` row says `BASE_DEC`, such as
    /// `sflow.flow_sample.output_interface`.
    MaskedHex,
    /// A relative time, rendered as seconds with nine fractional digits.
    RelativeTime,
}

impl Display {
    /// The display name the `-G fields` report uses.
    pub const fn report_name(self) -> &'static str {
        match self {
            Self::Decimal => "BASE_DEC",
            Self::DecHex => "BASE_DEC_HEX",
            Self::Hex => "BASE_HEX",
            Self::HexDec => "BASE_HEX_DEC",
            Self::Oui => "BASE_OUI",
            Self::PortTcp => "BASE_PT_TCP",
            Self::PortUdp => "BASE_PT_UDP",
            Self::Boolean0 => "0",
            Self::Boolean6 => "6",
            Self::Boolean8 => "8",
            Self::Boolean12 => "12",
            Self::Boolean16 => "16",
            Self::Boolean24 => "24",
            Self::Boolean32 => "32",
            Self::None | Self::RelativeTime => "",
            Self::BaseNone => "BASE_NONE",
            Self::Seconds256 => "",
            Self::MaskedHex => "BASE_DEC",
            Self::Custom => "BASE_CUSTOM",
            Self::IsoTime | Self::IsoTimeZ => "",
        }
    }
}

/// One field that a decoder can add to the packet tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldDef {
    /// Display-filter abbreviation, such as `eth.type`.
    pub abbrev: &'static str,
    /// Human-readable name, such as `Type`.
    pub name: &'static str,
    /// Type of the values the field carries.
    pub field_type: FieldType,
    /// Filter name of the protocol that owns the field.
    pub parent: &'static str,
    /// Display base for numeric values.
    pub display: Display,
    /// Mask for a bit field, as `-G fields` reports it.
    pub bitmask: Option<u64>,
    /// Description shown by field reports.
    pub blurb: &'static str,
    /// Whether the field is computed rather than read from packet bytes.
    pub generated: bool,
}

impl FieldDef {
    /// An address-based identity for this registry definition.
    ///
    /// Registry definitions are unique statics, so the address tells them
    /// apart without comparing abbreviation strings.
    pub fn identity(&'static self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

/// One protocol and the fields it declares, in report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolDef {
    /// Display-filter name, such as `eth`.
    pub filter_name: &'static str,
    /// Long name, such as `Ethernet`.
    pub long_name: &'static str,
    /// Short name, such as `Ethernet`.
    pub short_name: &'static str,
    /// Fields in `-G fields` order.
    pub fields: &'static [&'static FieldDef],
}

impl ProtocolDef {
    /// An address-based identity for this registry definition.
    pub fn identity(&'static self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

/// The definition shared by unnamed synthetic groups.
///
/// These nodes have no registered field: PDML writes
/// `name=""`, JSON uses the showname as the object key and EK appends the
/// label to the layer's `text` array. The definition is deliberately not in a
/// protocol's field list, so it cannot appear in `-G fields` or be selected
/// by a display filter.
pub static UNNAMED_CONTAINER: FieldDef = FieldDef {
    abbrev: "",
    name: "",
    field_type: FieldType::None,
    parent: "",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// A decoder entry point.
///
/// `data` holds the layer's bytes and `base` is the offset of `data[0]` from
/// the start of the frame, so field ranges stay frame-relative. The node is
/// the layer's parent in the packet tree; the decoder creates its own child
/// node under it.
pub type Decoder = fn(&mut DecodeContext<'_>, &mut Node, &[u8], usize);

/// One protocol that can appear in the packet tree.
///
/// The variants are the dispatch-table and policy identity for a protocol.
/// They are separate from [`ProtocolDef`], which carries the display and
/// field-registry metadata, because the opaque `data` pseudo-protocol has no
/// registered fields and some protocols share a decoder entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// The frame pseudo-protocol.
    Frame,
    /// Ethernet II and IEEE 802.3.
    Ethernet,
    /// Logical Link Control.
    Llc,
    /// IEEE 802.1Q VLAN tag.
    Vlan,
    /// IEEE 802.1ad provider tag.
    Ieee8021ad,
    /// Linux cooked capture.
    Sll,
    /// Null/loopback link layer.
    Null,
    /// Address Resolution Protocol.
    Arp,
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
    /// IPv6 hop-by-hop options.
    Ipv6Hopopts,
    /// IPv6 destination options.
    Ipv6Dstopts,
    /// IPv6 routing header.
    Ipv6Routing,
    /// IPv6 fragment header.
    Ipv6Fraghdr,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// DNS.
    Dns,
    /// BGP.
    Bgp,
    /// HTTP/1.x.
    Http,
    /// TLS.
    Tls,
    /// mDNS.
    Mdns,
    /// LLMNR.
    Llmnr,
    /// DHCP/BOOTP.
    Dhcp,
    /// DHCPv6.
    Dhcpv6,
    /// NTP.
    Ntp,
    /// ICMP.
    Icmp,
    /// ICMPv6.
    Icmpv6,
    /// ERSPAN.
    Erspan,
    /// Geneve.
    Geneve,
    /// GRE.
    Gre,
    /// MPLS.
    Mpls,
    /// VXLAN.
    Vxlan,
    /// BFD control.
    Bfd,
    /// BFD echo.
    BfdEcho,
    /// OSPF.
    Ospf,
    /// VRRP.
    Vrrp,
    /// LACP.
    Lacp,
    /// LLDP.
    Lldp,
    /// Link Aggregation Marker.
    Marker,
    /// IEEE 802.3 slow protocols.
    Slow,
    /// Spanning Tree Protocol.
    Stp,
    /// NetFlow/IPFIX.
    Cflow,
    /// sFlow.
    Sflow,
    /// SNMP.
    Snmp,
    /// Syslog.
    Syslog,
    /// Opaque payload forced with `-d ...,data`.
    Data,
}

impl Protocol {
    /// Every protocol dispatch can select.
    pub const ALL: &'static [Protocol] = &[
        Self::Frame,
        Self::Ethernet,
        Self::Llc,
        Self::Vlan,
        Self::Ieee8021ad,
        Self::Sll,
        Self::Null,
        Self::Arp,
        Self::Ipv4,
        Self::Ipv6,
        Self::Ipv6Hopopts,
        Self::Ipv6Dstopts,
        Self::Ipv6Routing,
        Self::Ipv6Fraghdr,
        Self::Tcp,
        Self::Udp,
        Self::Dns,
        Self::Bgp,
        Self::Http,
        Self::Tls,
        Self::Mdns,
        Self::Llmnr,
        Self::Dhcp,
        Self::Dhcpv6,
        Self::Ntp,
        Self::Icmp,
        Self::Icmpv6,
        Self::Erspan,
        Self::Geneve,
        Self::Gre,
        Self::Mpls,
        Self::Vxlan,
        Self::Bfd,
        Self::BfdEcho,
        Self::Ospf,
        Self::Vrrp,
        Self::Lacp,
        Self::Lldp,
        Self::Marker,
        Self::Slow,
        Self::Stp,
        Self::Cflow,
        Self::Sflow,
        Self::Snmp,
        Self::Syslog,
        Self::Data,
    ];

    /// Registry metadata for this protocol.
    pub fn def(self) -> &'static ProtocolDef {
        match self {
            Self::Frame => &FRAME_PROTOCOL,
            Self::Ethernet => &ETH_PROTOCOL,
            Self::Llc => &LLC_PROTOCOL,
            Self::Vlan => &VLAN_PROTOCOL,
            Self::Ieee8021ad => &IEEE8021AD_PROTOCOL,
            Self::Sll => &SLL_PROTOCOL,
            Self::Null => &NULL_PROTOCOL,
            Self::Arp => &ARP_PROTOCOL,
            Self::Ipv4 => &IP_PROTOCOL,
            Self::Ipv6 => &IPV6_PROTOCOL,
            Self::Ipv6Hopopts => &IPV6_HOPOPTS_PROTOCOL,
            Self::Ipv6Dstopts => &IPV6_DSTOPTS_PROTOCOL,
            Self::Ipv6Routing => &IPV6_ROUTING_PROTOCOL,
            Self::Ipv6Fraghdr => &IPV6_FRAGHDR_PROTOCOL,
            Self::Tcp => &TCP_PROTOCOL,
            Self::Udp => &UDP_PROTOCOL,
            Self::Dns => &DNS_PROTOCOL,
            Self::Bgp => &BGP_PROTOCOL,
            Self::Http => &HTTP_PROTOCOL,
            Self::Tls => &TLS_PROTOCOL,
            Self::Mdns => &MDNS_PROTOCOL,
            Self::Llmnr => &LLMNR_PROTOCOL,
            Self::Dhcp => &DHCP_PROTOCOL,
            Self::Dhcpv6 => &DHCPV6_PROTOCOL,
            Self::Ntp => &NTP_PROTOCOL,
            Self::Icmp => &ICMP_PROTOCOL,
            Self::Icmpv6 => &ICMPV6_PROTOCOL,
            Self::Erspan => &ERSPAN_PROTOCOL,
            Self::Geneve => &GENEVE_PROTOCOL,
            Self::Gre => &GRE_PROTOCOL,
            Self::Mpls => &MPLS_PROTOCOL,
            Self::Vxlan => &VXLAN_PROTOCOL,
            Self::Bfd => &BFD_PROTOCOL,
            Self::BfdEcho => &BFD_ECHO_PROTOCOL,
            Self::Ospf => &OSPF_PROTOCOL,
            Self::Vrrp => &VRRP_PROTOCOL,
            Self::Lacp => &LACP_PROTOCOL,
            Self::Lldp => &LLDP_PROTOCOL,
            Self::Marker => &MARKER_PROTOCOL,
            Self::Slow => &SLOW_PROTOCOL,
            Self::Stp => &STP_PROTOCOL,
            Self::Cflow => &CFLOW_PROTOCOL,
            Self::Sflow => &SFLOW_PROTOCOL,
            Self::Snmp => &SNMP_PROTOCOL,
            Self::Syslog => &SYSLOG_PROTOCOL,
            Self::Data => &DATA_PROTOCOL,
        }
    }

    /// Display-filter name of the protocol.
    pub fn filter_name(self) -> &'static str {
        self.def().filter_name
    }

    /// The protocol's decoder entry point. The frame pseudo-protocol and the
    /// opaque payload are not decoded through the dispatch tables.
    pub fn decoder(self) -> Decoder {
        match self {
            Self::Frame | Self::Data => no_decoder,
            Self::Ipv6Hopopts => decode::ipv6_hopopts,
            Self::Ipv6Dstopts => decode::ipv6_dstopts,
            Self::Ipv6Routing => decode::ipv6_routing,
            Self::Ipv6Fraghdr => decode::ipv6_fraghdr,
            Self::Ethernet => decode::ethernet,
            Self::Llc => decode::llc,
            Self::Vlan => decode::vlan,
            Self::Ieee8021ad => decode::ieee8021ad,
            Self::Sll => decode::sll,
            Self::Null => decode::null,
            Self::Arp => decode::arp,
            Self::Ipv4 => decode::ipv4,
            Self::Ipv6 => decode::ipv6,
            Self::Tcp => decode::tcp,
            Self::Udp => decode::udp,
            Self::Dns => decode::dns,
            Self::Bgp => decode::bgp,
            Self::Http => decode::http,
            Self::Tls => decode::tls,
            Self::Mdns => decode::mdns,
            Self::Llmnr => decode::llmnr,
            Self::Dhcp => decode::dhcp,
            Self::Dhcpv6 => decode::dhcpv6,
            Self::Ntp => decode::ntp,
            Self::Icmp => decode::icmp,
            Self::Icmpv6 => decode::icmpv6,
            Self::Erspan => decode::erspan,
            Self::Geneve => decode::geneve,
            Self::Gre => decode::gre,
            Self::Mpls => decode::mpls,
            Self::Vxlan => decode::vxlan,
            Self::Bfd => decode::bfd,
            Self::BfdEcho => decode::bfd_echo,
            Self::Ospf => decode::ospf,
            Self::Vrrp => decode::vrrp,
            Self::Lacp => decode::lacp,
            Self::Lldp => decode::lldp,
            Self::Marker => decode::marker,
            Self::Slow => decode::slow,
            Self::Stp => decode::stp,
            Self::Cflow => decode::cflow,
            Self::Sflow => decode::sflow,
            Self::Snmp => decode::snmp,
            Self::Syslog => decode::syslog,
        }
    }

    /// Policy bit index. The enum has fewer than 64 variants.
    pub fn index(self) -> u8 {
        self as u8
    }

    /// The protocol registered under `name`, if any.
    pub fn from_filter_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|protocol| protocol.filter_name() == name)
    }
}

fn no_decoder(_: &mut DecodeContext<'_>, _: &mut Node, _: &[u8], _: usize) {}

/// The opaque `data` pseudo-protocol.
///
/// Packetfin synthesises the data block in its output, so this
/// definition exists only so `-d ...,data` and protocol-name lookups have a
/// stable identity; it is not part of [`protocols`].
pub static DATA_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "data",
    long_name: "Data",
    short_name: "Data",
    fields: &[],
};

/// `frame.time_epoch`.
pub static FRAME_TIME_EPOCH: FieldDef = FieldDef {
    abbrev: "frame.time_epoch",
    name: "Epoch Arrival Time",
    field_type: FieldType::AbsoluteTime,
    parent: "frame",
    display: Display::None,
    bitmask: None,
    blurb: "Absolute time when this frame was captured, in Epoch time (also known as Unix time)",
    generated: true,
};

/// `frame.time_delta`.
pub static FRAME_TIME_DELTA: FieldDef = FieldDef {
    abbrev: "frame.time_delta",
    name: "Time delta from previous captured frame",
    field_type: FieldType::RelativeTime,
    parent: "frame",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `frame.time_relative`.
pub static FRAME_TIME_RELATIVE: FieldDef = FieldDef {
    abbrev: "frame.time_relative",
    name: "Time since reference or first frame",
    field_type: FieldType::RelativeTime,
    parent: "frame",
    display: Display::None,
    bitmask: None,
    blurb: "Time relative to time reference or first frame",
    generated: true,
};

/// `frame.number`.
pub static FRAME_NUMBER: FieldDef = FieldDef {
    abbrev: "frame.number",
    name: "Frame Number",
    field_type: FieldType::Uint32,
    parent: "frame",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `frame.len`.
pub static FRAME_LEN: FieldDef = FieldDef {
    abbrev: "frame.len",
    name: "Frame Length",
    field_type: FieldType::Uint32,
    parent: "frame",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Frame length on the wire",
    generated: true,
};

/// `frame.cap_len`.
pub static FRAME_CAP_LEN: FieldDef = FieldDef {
    abbrev: "frame.cap_len",
    name: "Capture Length",
    field_type: FieldType::Uint32,
    parent: "frame",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Frame length stored into the capture file",
    generated: true,
};

/// `frame.interface_id`.
pub static FRAME_INTERFACE_ID: FieldDef = FieldDef {
    abbrev: "frame.interface_id",
    name: "Interface id",
    field_type: FieldType::Uint32,
    parent: "frame",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `frame.interface_name`.
pub static FRAME_INTERFACE_NAME: FieldDef = FieldDef {
    abbrev: "frame.interface_name",
    name: "Interface name",
    field_type: FieldType::String,
    parent: "frame",
    display: Display::None,
    bitmask: None,
    blurb: "The friendly name for this interface",
    generated: true,
};

static FRAME_FIELDS: &[&FieldDef] = &[
    &FRAME_TIME_EPOCH,
    &FRAME_TIME_DELTA,
    &FRAME_TIME_RELATIVE,
    &FRAME_NUMBER,
    &FRAME_LEN,
    &FRAME_CAP_LEN,
    &FRAME_INTERFACE_ID,
    &FRAME_INTERFACE_NAME,
];

/// `eth.dst`.
pub static ETH_DST: FieldDef = FieldDef {
    abbrev: "eth.dst",
    name: "Destination",
    field_type: FieldType::Ethernet,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Destination Hardware Address",
    generated: false,
};

/// `eth.dst_resolved`.
pub static ETH_DST_RESOLVED: FieldDef = FieldDef {
    abbrev: "eth.dst_resolved",
    name: "Destination (resolved)",
    field_type: FieldType::String,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Destination Hardware Address (resolved)",
    generated: false,
};

/// `eth.dst.oui_resolved`.
pub static ETH_DST_OUI_RESOLVED: FieldDef = FieldDef {
    abbrev: "eth.dst.oui_resolved",
    name: "Destination OUI (resolved)",
    field_type: FieldType::String,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Destination Organizationally Unique Identifier (resolved)",
    generated: false,
};

/// `eth.src`.
pub static ETH_SRC: FieldDef = FieldDef {
    abbrev: "eth.src",
    name: "Source",
    field_type: FieldType::Ethernet,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Source Hardware Address",
    generated: false,
};

/// `eth.src_resolved`.
pub static ETH_SRC_RESOLVED: FieldDef = FieldDef {
    abbrev: "eth.src_resolved",
    name: "Source (resolved)",
    field_type: FieldType::String,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Source Hardware Address (resolved)",
    generated: false,
};

/// `eth.src.oui_resolved`.
pub static ETH_SRC_OUI_RESOLVED: FieldDef = FieldDef {
    abbrev: "eth.src.oui_resolved",
    name: "Source OUI (resolved)",
    field_type: FieldType::String,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Source Organizationally Unique Identifier (resolved)",
    generated: false,
};

/// `eth.len`.
pub static ETH_LEN: FieldDef = FieldDef {
    abbrev: "eth.len",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "eth",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `eth.type`.
pub static ETH_TYPE: FieldDef = FieldDef {
    abbrev: "eth.type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "eth",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `eth.addr`; added once for the destination and once for the source.
pub static ETH_ADDR: FieldDef = FieldDef {
    abbrev: "eth.addr",
    name: "Address",
    field_type: FieldType::Ethernet,
    parent: "eth",
    display: Display::None,
    bitmask: None,
    blurb: "Source or Destination Hardware Address",
    generated: false,
};

static ETH_FIELDS: &[&FieldDef] = &[
    &ETH_DST,
    &ETH_DST_RESOLVED,
    &ETH_DST_OUI_RESOLVED,
    &ETH_SRC,
    &ETH_SRC_RESOLVED,
    &ETH_SRC_OUI_RESOLVED,
    &ETH_LEN,
    &ETH_TYPE,
    &ETH_ADDR,
];

/// `llc.dsap`.
pub static LLC_DSAP: FieldDef = FieldDef {
    abbrev: "llc.dsap",
    name: "DSAP",
    field_type: FieldType::Uint8,
    parent: "llc",
    display: Display::Hex,
    bitmask: None,
    blurb: "Destination Service Access Point",
    generated: false,
};

/// `llc.ssap`.
pub static LLC_SSAP: FieldDef = FieldDef {
    abbrev: "llc.ssap",
    name: "SSAP",
    field_type: FieldType::Uint8,
    parent: "llc",
    display: Display::Hex,
    bitmask: None,
    blurb: "Source Service Access Point",
    generated: false,
};

/// `llc.control`.
pub static LLC_CONTROL: FieldDef = FieldDef {
    abbrev: "llc.control",
    name: "Control",
    field_type: FieldType::Uint16,
    parent: "llc",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `llc.type`.
pub static LLC_TYPE: FieldDef = FieldDef {
    abbrev: "llc.type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "llc",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `llc.oui`.
pub static LLC_OUI: FieldDef = FieldDef {
    abbrev: "llc.oui",
    name: "Organization Code",
    field_type: FieldType::Uint24,
    parent: "llc",
    display: Display::Oui,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `llc.pid`.
pub static LLC_PID: FieldDef = FieldDef {
    abbrev: "llc.pid",
    name: "Protocol ID",
    field_type: FieldType::Uint16,
    parent: "llc",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `llc.cisco_pid`.
pub static LLC_CISCO_PID: FieldDef = FieldDef {
    abbrev: "llc.cisco_pid",
    name: "PID",
    field_type: FieldType::Uint16,
    parent: "llc",
    display: Display::Hex,
    bitmask: None,
    blurb: "Protocol ID",
    generated: false,
};

static LLC_FIELDS: &[&FieldDef] = &[
    &LLC_DSAP,
    &LLC_SSAP,
    &LLC_CONTROL,
    &LLC_TYPE,
    &LLC_OUI,
    &LLC_PID,
    &LLC_CISCO_PID,
];

/// `vlan.priority`.
pub static VLAN_PRIORITY: FieldDef = FieldDef {
    abbrev: "vlan.priority",
    name: "Priority",
    field_type: FieldType::Uint16,
    parent: "vlan",
    display: Display::Decimal,
    bitmask: Some(0xe000),
    blurb: "Descriptions are recommendations from IEEE standard 802.1D-2004",
    generated: false,
};

/// `vlan.dei`.
pub static VLAN_DEI: FieldDef = FieldDef {
    abbrev: "vlan.dei",
    name: "DEI",
    field_type: FieldType::Boolean,
    parent: "vlan",
    display: Display::Boolean16,
    bitmask: Some(0x1000),
    blurb: "Drop Eligible Indicator",
    generated: false,
};

/// `vlan.id`.
pub static VLAN_ID: FieldDef = FieldDef {
    abbrev: "vlan.id",
    name: "ID",
    field_type: FieldType::Uint16,
    parent: "vlan",
    display: Display::Decimal,
    bitmask: Some(0x0fff),
    blurb: "VLAN ID",
    generated: false,
};

/// `vlan.etype`.
pub static VLAN_ETYPE: FieldDef = FieldDef {
    abbrev: "vlan.etype",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "vlan",
    display: Display::Hex,
    bitmask: None,
    blurb: "Ethertype",
    generated: false,
};

/// `vlan.len`.
pub static VLAN_LEN: FieldDef = FieldDef {
    abbrev: "vlan.len",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "vlan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

static VLAN_FIELDS: &[&FieldDef] = &[&VLAN_PRIORITY, &VLAN_DEI, &VLAN_ID, &VLAN_ETYPE, &VLAN_LEN];

/// `ieee8021ad.priority`.
pub static IEEE8021AD_PRIORITY: FieldDef = FieldDef {
    abbrev: "ieee8021ad.priority",
    name: "Priority",
    field_type: FieldType::Uint16,
    parent: "ieee8021ad",
    display: Display::Decimal,
    bitmask: Some(0xe000),
    blurb: "",
    generated: false,
};

/// `ieee8021ad.dei`.
pub static IEEE8021AD_DEI: FieldDef = FieldDef {
    abbrev: "ieee8021ad.dei",
    name: "DEI",
    field_type: FieldType::Uint16,
    parent: "ieee8021ad",
    display: Display::Decimal,
    bitmask: Some(0x1000),
    blurb: "Drop Eligibility",
    generated: false,
};

/// `ieee8021ad.id`.
pub static IEEE8021AD_ID: FieldDef = FieldDef {
    abbrev: "ieee8021ad.id",
    name: "ID",
    field_type: FieldType::Uint16,
    parent: "ieee8021ad",
    display: Display::Decimal,
    bitmask: Some(0x0fff),
    blurb: "Vlan ID",
    generated: false,
};

/// `ieee8021ad.svid`.
pub static IEEE8021AD_SVID: FieldDef = FieldDef {
    abbrev: "ieee8021ad.svid",
    name: "ID",
    field_type: FieldType::Uint16,
    parent: "ieee8021ad",
    display: Display::Decimal,
    bitmask: Some(0x0fff),
    blurb: "S-Vlan ID",
    generated: false,
};

/// `ieee8021ad.cvid`.
pub static IEEE8021AD_CVID: FieldDef = FieldDef {
    abbrev: "ieee8021ad.cvid",
    name: "ID",
    field_type: FieldType::Uint16,
    parent: "ieee8021ad",
    display: Display::Decimal,
    bitmask: Some(0x0fff),
    blurb: "C-Vlan ID",
    generated: false,
};

static IEEE8021AD_FIELDS: &[&FieldDef] = &[
    &IEEE8021AD_PRIORITY,
    &IEEE8021AD_DEI,
    &IEEE8021AD_ID,
    &IEEE8021AD_SVID,
    &IEEE8021AD_CVID,
];

/// `sll.pkttype`.
pub static SLL_PKTTYPE: FieldDef = FieldDef {
    abbrev: "sll.pkttype",
    name: "Packet type",
    field_type: FieldType::Uint16,
    parent: "sll",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sll.hatype`.
pub static SLL_HATYPE: FieldDef = FieldDef {
    abbrev: "sll.hatype",
    name: "Link-layer address type",
    field_type: FieldType::Uint16,
    parent: "sll",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sll.halen`.
pub static SLL_HALEN: FieldDef = FieldDef {
    abbrev: "sll.halen",
    name: "Link-layer address length",
    field_type: FieldType::Uint16,
    parent: "sll",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sll.src.eth`.
pub static SLL_SRC_ETH: FieldDef = FieldDef {
    abbrev: "sll.src.eth",
    name: "Source",
    field_type: FieldType::Ethernet,
    parent: "sll",
    display: Display::None,
    bitmask: None,
    blurb: "Source link-layer address",
    generated: false,
};

/// `sll.src.ipv4`.
pub static SLL_SRC_IPV4: FieldDef = FieldDef {
    abbrev: "sll.src.ipv4",
    name: "Source",
    field_type: FieldType::Ipv4,
    parent: "sll",
    display: Display::None,
    bitmask: None,
    blurb: "Source link-layer address",
    generated: false,
};

/// `sll.src.other`.
pub static SLL_SRC_OTHER: FieldDef = FieldDef {
    abbrev: "sll.src.other",
    name: "Source",
    field_type: FieldType::Bytes,
    parent: "sll",
    display: Display::None,
    bitmask: None,
    blurb: "Source link-layer address",
    generated: false,
};

/// `sll.unused`.
pub static SLL_UNUSED: FieldDef = FieldDef {
    abbrev: "sll.unused",
    name: "Unused",
    field_type: FieldType::Bytes,
    parent: "sll",
    display: Display::None,
    bitmask: None,
    blurb: "Unused bytes",
    generated: false,
};

/// `sll.ltype`.
pub static SLL_LTYPE: FieldDef = FieldDef {
    abbrev: "sll.ltype",
    name: "Protocol",
    field_type: FieldType::Uint16,
    parent: "sll",
    display: Display::Hex,
    bitmask: None,
    blurb: "Linux protocol type",
    generated: false,
};

/// `sll.etype`.
pub static SLL_ETYPE: FieldDef = FieldDef {
    abbrev: "sll.etype",
    name: "Protocol",
    field_type: FieldType::Uint16,
    parent: "sll",
    display: Display::Hex,
    bitmask: None,
    blurb: "Ethernet protocol type",
    generated: false,
};

/// `sll.ifindex`.
pub static SLL_IFINDEX: FieldDef = FieldDef {
    abbrev: "sll.ifindex",
    name: "Interface index",
    field_type: FieldType::Uint32,
    parent: "sll",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sll.reserved`.
pub static SLL_RESERVED: FieldDef = FieldDef {
    abbrev: "sll.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "sll",
    display: Display::None,
    bitmask: None,
    blurb: "Reserved bytes",
    generated: false,
};

static SLL_FIELDS: &[&FieldDef] = &[
    &SLL_PKTTYPE,
    &SLL_HATYPE,
    &SLL_HALEN,
    &SLL_SRC_ETH,
    &SLL_SRC_IPV4,
    &SLL_SRC_OTHER,
    &SLL_UNUSED,
    &SLL_LTYPE,
    &SLL_ETYPE,
    &SLL_IFINDEX,
    &SLL_RESERVED,
];

/// `null.type`.
pub static NULL_TYPE: FieldDef = FieldDef {
    abbrev: "null.type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "null",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `null.family`.
pub static NULL_FAMILY: FieldDef = FieldDef {
    abbrev: "null.family",
    name: "Family",
    field_type: FieldType::Uint32,
    parent: "null",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

static NULL_FIELDS: &[&FieldDef] = &[&NULL_TYPE, &NULL_FAMILY];

/// `arp.hw.type`.
pub static ARP_HW_TYPE: FieldDef = FieldDef {
    abbrev: "arp.hw.type",
    name: "Hardware type",
    field_type: FieldType::Uint16,
    parent: "arp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.proto.type`.
pub static ARP_PROTO_TYPE: FieldDef = FieldDef {
    abbrev: "arp.proto.type",
    name: "Protocol type",
    field_type: FieldType::Uint16,
    parent: "arp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.hw.size`.
pub static ARP_HW_SIZE: FieldDef = FieldDef {
    abbrev: "arp.hw.size",
    name: "Hardware size",
    field_type: FieldType::Uint8,
    parent: "arp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.proto.size`.
pub static ARP_PROTO_SIZE: FieldDef = FieldDef {
    abbrev: "arp.proto.size",
    name: "Protocol size",
    field_type: FieldType::Uint8,
    parent: "arp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.opcode`.
pub static ARP_OPCODE: FieldDef = FieldDef {
    abbrev: "arp.opcode",
    name: "Opcode",
    field_type: FieldType::Uint16,
    parent: "arp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.src.hw`; added when the hardware address is not a MAC address.
pub static ARP_SRC_HW: FieldDef = FieldDef {
    abbrev: "arp.src.hw",
    name: "Sender hardware address",
    field_type: FieldType::Bytes,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.src.hw_mac`.
pub static ARP_SRC_HW_MAC: FieldDef = FieldDef {
    abbrev: "arp.src.hw_mac",
    name: "Sender MAC address",
    field_type: FieldType::Ethernet,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.dst.hw`; added when the hardware address is not a MAC address.
pub static ARP_DST_HW: FieldDef = FieldDef {
    abbrev: "arp.dst.hw",
    name: "Target hardware address",
    field_type: FieldType::Bytes,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.dst.hw_mac`.
pub static ARP_DST_HW_MAC: FieldDef = FieldDef {
    abbrev: "arp.dst.hw_mac",
    name: "Target MAC address",
    field_type: FieldType::Ethernet,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.src.proto`; added when the protocol address is not an IPv4 address.
pub static ARP_SRC_PROTO: FieldDef = FieldDef {
    abbrev: "arp.src.proto",
    name: "Sender protocol address",
    field_type: FieldType::Bytes,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.src.proto_ipv4`.
pub static ARP_SRC_PROTO_IPV4: FieldDef = FieldDef {
    abbrev: "arp.src.proto_ipv4",
    name: "Sender IP address",
    field_type: FieldType::Ipv4,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.dst.proto`; added when the protocol address is not an IPv4 address.
pub static ARP_DST_PROTO: FieldDef = FieldDef {
    abbrev: "arp.dst.proto",
    name: "Target protocol address",
    field_type: FieldType::Bytes,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `arp.dst.proto_ipv4`.
pub static ARP_DST_PROTO_IPV4: FieldDef = FieldDef {
    abbrev: "arp.dst.proto_ipv4",
    name: "Target IP address",
    field_type: FieldType::Ipv4,
    parent: "arp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static ARP_FIELDS: &[&FieldDef] = &[
    &ARP_HW_TYPE,
    &ARP_PROTO_TYPE,
    &ARP_HW_SIZE,
    &ARP_PROTO_SIZE,
    &ARP_OPCODE,
    &ARP_SRC_HW,
    &ARP_SRC_HW_MAC,
    &ARP_DST_HW,
    &ARP_DST_HW_MAC,
    &ARP_SRC_PROTO,
    &ARP_SRC_PROTO_IPV4,
    &ARP_DST_PROTO,
    &ARP_DST_PROTO_IPV4,
];

/// `ip.version`.
pub static IP_VERSION: FieldDef = FieldDef {
    abbrev: "ip.version",
    name: "Version",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.hdr_len`.
pub static IP_HDR_LEN: FieldDef = FieldDef {
    abbrev: "ip.hdr_len",
    name: "Header Length",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Header length in 32-bit words",
    generated: false,
};

/// `ip.dsfield`.
pub static IP_DSFIELD: FieldDef = FieldDef {
    abbrev: "ip.dsfield",
    name: "Differentiated Services Field",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.dsfield.dscp`.
pub static IP_DSFIELD_DSCP: FieldDef = FieldDef {
    abbrev: "ip.dsfield.dscp",
    name: "Differentiated Services Codepoint",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: Some(0xfc),
    blurb: "",
    generated: false,
};

/// `ip.dsfield.ecn`.
pub static IP_DSFIELD_ECN: FieldDef = FieldDef {
    abbrev: "ip.dsfield.ecn",
    name: "Explicit Congestion Notification",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: Some(0x03),
    blurb: "",
    generated: false,
};

/// `ip.len`.
pub static IP_LEN: FieldDef = FieldDef {
    abbrev: "ip.len",
    name: "Total Length",
    field_type: FieldType::Uint16,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.id`.
pub static IP_ID: FieldDef = FieldDef {
    abbrev: "ip.id",
    name: "Identification",
    field_type: FieldType::Uint16,
    parent: "ip",
    display: Display::HexDec,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.flags`.
pub static IP_FLAGS: FieldDef = FieldDef {
    abbrev: "ip.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Hex,
    bitmask: Some(0xe0),
    blurb: "",
    generated: false,
};

/// `ip.flags.rb`.
pub static IP_FLAGS_RB: FieldDef = FieldDef {
    abbrev: "ip.flags.rb",
    name: "Reserved bit",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `ip.flags.df`.
pub static IP_FLAGS_DF: FieldDef = FieldDef {
    abbrev: "ip.flags.df",
    name: "Don't fragment",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `ip.flags.mf`.
pub static IP_FLAGS_MF: FieldDef = FieldDef {
    abbrev: "ip.flags.mf",
    name: "More fragments",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `ip.frag_offset`.
pub static IP_FRAG_OFFSET: FieldDef = FieldDef {
    abbrev: "ip.frag_offset",
    name: "Fragment Offset",
    field_type: FieldType::Uint16,
    parent: "ip",
    display: Display::Decimal,
    bitmask: Some(0x1fff),
    blurb: "",
    generated: false,
};

/// `ip.ttl`.
pub static IP_TTL: FieldDef = FieldDef {
    abbrev: "ip.ttl",
    name: "Time to Live",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.proto`.
pub static IP_PROTO: FieldDef = FieldDef {
    abbrev: "ip.proto",
    name: "Protocol",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.checksum`.
pub static IP_CHECKSUM: FieldDef = FieldDef {
    abbrev: "ip.checksum",
    name: "Header Checksum",
    field_type: FieldType::Uint16,
    parent: "ip",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.checksum_calculated`.
pub static IP_CHECKSUM_CALCULATED: FieldDef = FieldDef {
    abbrev: "ip.checksum_calculated",
    name: "Calculated Checksum",
    field_type: FieldType::Uint16,
    parent: "ip",
    display: Display::Hex,
    bitmask: None,
    blurb: "The expected IP checksum field as calculated from the IP datagram",
    generated: true,
};

/// `ip.checksum.status`.
pub static IP_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "ip.checksum.status",
    name: "Header checksum status",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ip.src`.
pub static IP_SRC: FieldDef = FieldDef {
    abbrev: "ip.src",
    name: "Source Address",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.src_host`.
pub static IP_SRC_HOST: FieldDef = FieldDef {
    abbrev: "ip.src_host",
    name: "Source Host",
    field_type: FieldType::String,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.dst`.
pub static IP_DST: FieldDef = FieldDef {
    abbrev: "ip.dst",
    name: "Destination Address",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.dst_host`.
pub static IP_DST_HOST: FieldDef = FieldDef {
    abbrev: "ip.dst_host",
    name: "Destination Host",
    field_type: FieldType::String,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.opt.type`.
pub static IP_OPT_TYPE: FieldDef = FieldDef {
    abbrev: "ip.opt.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.opt.type.copy`.
pub static IP_OPT_TYPE_COPY: FieldDef = FieldDef {
    abbrev: "ip.opt.type.copy",
    name: "Copy on fragmentation",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `ip.opt.type.class`.
pub static IP_OPT_TYPE_CLASS: FieldDef = FieldDef {
    abbrev: "ip.opt.type.class",
    name: "Class",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: Some(0x60),
    blurb: "",
    generated: false,
};

/// `ip.opt.type.number`.
pub static IP_OPT_TYPE_NUMBER: FieldDef = FieldDef {
    abbrev: "ip.opt.type.number",
    name: "Number",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: Some(0x1f),
    blurb: "",
    generated: false,
};

/// `ip.opt.len`.
pub static IP_OPT_LEN: FieldDef = FieldDef {
    abbrev: "ip.opt.len",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.opt.data`.
pub static IP_OPT_DATA: FieldDef = FieldDef {
    abbrev: "ip.opt.data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.opt.ptr`.
pub static IP_OPT_PTR: FieldDef = FieldDef {
    abbrev: "ip.opt.ptr",
    name: "Pointer",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.fragment.overlap`.
pub static IP_FRAGMENT_OVERLAP: FieldDef = FieldDef {
    abbrev: "ip.fragment.overlap",
    name: "Fragment overlap",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Fragment overlaps with other fragments",
    generated: true,
};

/// `ip.fragment.overlap.conflict`.
pub static IP_FRAGMENT_OVERLAP_CONFLICT: FieldDef = FieldDef {
    abbrev: "ip.fragment.overlap.conflict",
    name: "Conflicting data in fragment overlap",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Overlapping fragments contained conflicting data",
    generated: true,
};

/// `ip.fragment.multipletails`.
pub static IP_FRAGMENT_MULTIPLETAILS: FieldDef = FieldDef {
    abbrev: "ip.fragment.multipletails",
    name: "Multiple tail fragments found",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Several tails were found when defragmenting the packet",
    generated: true,
};

/// `ip.fragment.toolongfragment`.
pub static IP_FRAGMENT_TOOLONGFRAGMENT: FieldDef = FieldDef {
    abbrev: "ip.fragment.toolongfragment",
    name: "Fragment too long",
    field_type: FieldType::Boolean,
    parent: "ip",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Fragment contained data past end of packet",
    generated: true,
};

/// `ip.fragment.error`.
pub static IP_FRAGMENT_ERROR: FieldDef = FieldDef {
    abbrev: "ip.fragment.error",
    name: "Defragmentation error",
    field_type: FieldType::FrameNumber,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "Defragmentation error due to illegal fragments",
    generated: true,
};

/// `ip.fragment.count`.
pub static IP_FRAGMENT_COUNT: FieldDef = FieldDef {
    abbrev: "ip.fragment.count",
    name: "Fragment count",
    field_type: FieldType::Uint32,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ip.fragment`.
pub static IP_FRAGMENT: FieldDef = FieldDef {
    abbrev: "ip.fragment",
    name: "IPv4 Fragment",
    field_type: FieldType::FrameNumber,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ip.fragments`.
pub static IP_FRAGMENTS: FieldDef = FieldDef {
    abbrev: "ip.fragments",
    name: "IPv4 Fragments",
    field_type: FieldType::Bytes,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ip.reassembled_in`.
pub static IP_REASSEMBLED_IN: FieldDef = FieldDef {
    abbrev: "ip.reassembled_in",
    name: "Reassembled IPv4 in frame",
    field_type: FieldType::FrameNumber,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "This IPv4 packet is reassembled in this frame",
    generated: true,
};

/// `ip.reassembled.length`.
pub static IP_REASSEMBLED_LENGTH: FieldDef = FieldDef {
    abbrev: "ip.reassembled.length",
    name: "Reassembled IPv4 length",
    field_type: FieldType::Uint32,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The total length of the reassembled payload",
    generated: true,
};

/// `ip.reassembled.data`.
pub static IP_REASSEMBLED_DATA: FieldDef = FieldDef {
    abbrev: "ip.reassembled.data",
    name: "Reassembled IPv4 data",
    field_type: FieldType::Bytes,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "The reassembled payload",
    generated: true,
};

/// `ip.opt.overflow`.
pub static IP_OPT_OVERFLOW: FieldDef = FieldDef {
    abbrev: "ip.opt.overflow",
    name: "Overflow",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Decimal,
    bitmask: Some(0xf0),
    blurb: "",
    generated: false,
};

/// `ip.opt.flag`.
pub static IP_OPT_FLAG: FieldDef = FieldDef {
    abbrev: "ip.opt.flag",
    name: "Flag",
    field_type: FieldType::Uint8,
    parent: "ip",
    display: Display::Hex,
    bitmask: Some(0x0f),
    blurb: "",
    generated: false,
};

/// `ip.opt.time_stamp`.
pub static IP_OPT_TIME_STAMP: FieldDef = FieldDef {
    abbrev: "ip.opt.time_stamp",
    name: "Time stamp",
    field_type: FieldType::Uint32,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.opt.time_stamp_addr`.
pub static IP_OPT_TIME_STAMP_ADDR: FieldDef = FieldDef {
    abbrev: "ip.opt.time_stamp_addr",
    name: "Address",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.opt.ra`.
pub static IP_OPT_RA: FieldDef = FieldDef {
    abbrev: "ip.opt.ra",
    name: "Router Alert",
    field_type: FieldType::Uint16,
    parent: "ip",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.rec_rt`.
pub static IP_REC_RT: FieldDef = FieldDef {
    abbrev: "ip.rec_rt",
    name: "Recorded Route",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.cur_rt`.
pub static IP_CUR_RT: FieldDef = FieldDef {
    abbrev: "ip.cur_rt",
    name: "Current Route",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.src_rt`.
pub static IP_SRC_RT: FieldDef = FieldDef {
    abbrev: "ip.src_rt",
    name: "Source Route",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ip.empty_rt`.
pub static IP_EMPTY_RT: FieldDef = FieldDef {
    abbrev: "ip.empty_rt",
    name: "Empty Route",
    field_type: FieldType::Ipv4,
    parent: "ip",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static IP_FIELDS: &[&FieldDef] = &[
    &IP_VERSION,
    &IP_HDR_LEN,
    &IP_DSFIELD,
    &IP_DSFIELD_DSCP,
    &IP_DSFIELD_ECN,
    &IP_LEN,
    &IP_ID,
    &IP_FLAGS,
    &IP_FLAGS_RB,
    &IP_FLAGS_DF,
    &IP_FLAGS_MF,
    &IP_FRAG_OFFSET,
    &IP_TTL,
    &IP_PROTO,
    &IP_CHECKSUM,
    &IP_CHECKSUM_CALCULATED,
    &IP_CHECKSUM_STATUS,
    &IP_DST,
    &IP_DST_HOST,
    &IP_SRC,
    &IP_SRC_HOST,
    &IP_OPT_TYPE,
    &IP_OPT_TYPE_COPY,
    &IP_OPT_TYPE_CLASS,
    &IP_OPT_TYPE_NUMBER,
    &IP_OPT_LEN,
    &IP_OPT_DATA,
    &IP_OPT_PTR,
    &IP_OPT_OVERFLOW,
    &IP_OPT_FLAG,
    &IP_OPT_TIME_STAMP,
    &IP_OPT_TIME_STAMP_ADDR,
    &IP_OPT_RA,
    &IP_REC_RT,
    &IP_CUR_RT,
    &IP_SRC_RT,
    &IP_EMPTY_RT,
    &IP_FRAGMENT_OVERLAP,
    &IP_FRAGMENT_OVERLAP_CONFLICT,
    &IP_FRAGMENT_MULTIPLETAILS,
    &IP_FRAGMENT_TOOLONGFRAGMENT,
    &IP_FRAGMENT_ERROR,
    &IP_FRAGMENT_COUNT,
    &IP_FRAGMENT,
    &IP_FRAGMENTS,
    &IP_REASSEMBLED_IN,
    &IP_REASSEMBLED_LENGTH,
    &IP_REASSEMBLED_DATA,
];

/// `ipv6.version`.
pub static IPV6_VERSION: FieldDef = FieldDef {
    abbrev: "ipv6.version",
    name: "Version",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.tclass`.
pub static IPV6_TCLASS: FieldDef = FieldDef {
    abbrev: "ipv6.tclass",
    name: "Traffic Class",
    field_type: FieldType::Uint32,
    parent: "ipv6",
    display: Display::Hex,
    bitmask: Some(0x0ff0_0000),
    blurb: "",
    generated: false,
};

/// `ipv6.tclass.dscp`.
pub static IPV6_TCLASS_DSCP: FieldDef = FieldDef {
    abbrev: "ipv6.tclass.dscp",
    name: "Differentiated Services Codepoint",
    field_type: FieldType::Uint32,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: Some(0x0fc0_0000),
    blurb: "",
    generated: false,
};

/// `ipv6.tclass.ecn`.
pub static IPV6_TCLASS_ECN: FieldDef = FieldDef {
    abbrev: "ipv6.tclass.ecn",
    name: "Explicit Congestion Notification",
    field_type: FieldType::Uint32,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: Some(0x0030_0000),
    blurb: "",
    generated: false,
};

/// `ipv6.flow`.
pub static IPV6_FLOW: FieldDef = FieldDef {
    abbrev: "ipv6.flow",
    name: "Flow Label",
    field_type: FieldType::Uint24,
    parent: "ipv6",
    display: Display::Hex,
    bitmask: Some(0x000f_ffff),
    blurb: "",
    generated: false,
};

/// `ipv6.plen`.
pub static IPV6_PLEN: FieldDef = FieldDef {
    abbrev: "ipv6.plen",
    name: "Payload Length",
    field_type: FieldType::Uint16,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.nxt`.
pub static IPV6_NXT: FieldDef = FieldDef {
    abbrev: "ipv6.nxt",
    name: "Next Header",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.hlim`.
pub static IPV6_HLIM: FieldDef = FieldDef {
    abbrev: "ipv6.hlim",
    name: "Hop Limit",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.src`.
pub static IPV6_SRC: FieldDef = FieldDef {
    abbrev: "ipv6.src",
    name: "Source Address",
    field_type: FieldType::Ipv6,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "Source IPv6 Address",
    generated: false,
};

/// `ipv6.src_host`.
pub static IPV6_SRC_HOST: FieldDef = FieldDef {
    abbrev: "ipv6.src_host",
    name: "Source Host",
    field_type: FieldType::String,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "Source IPv6 Host",
    generated: false,
};

/// `ipv6.dst`.
pub static IPV6_DST: FieldDef = FieldDef {
    abbrev: "ipv6.dst",
    name: "Destination Address",
    field_type: FieldType::Ipv6,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "Destination IPv6 Address",
    generated: false,
};

/// `ipv6.dst_host`.
pub static IPV6_DST_HOST: FieldDef = FieldDef {
    abbrev: "ipv6.dst_host",
    name: "Destination Host",
    field_type: FieldType::String,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "Destination IPv6 Host",
    generated: false,
};

/// `ipv6.addr`; added once for the source and once for the destination.
pub static IPV6_ADDR: FieldDef = FieldDef {
    abbrev: "ipv6.addr",
    name: "Source or Destination Address",
    field_type: FieldType::Ipv6,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.opt.type`.
pub static IPV6_OPT_TYPE: FieldDef = FieldDef {
    abbrev: "ipv6.opt.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "Option type",
    generated: false,
};

/// `ipv6.opt.type.action`.
pub static IPV6_OPT_TYPE_ACTION: FieldDef = FieldDef {
    abbrev: "ipv6.opt.type.action",
    name: "Action",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: Some(0xc0),
    blurb: "Action for unrecognized option type",
    generated: false,
};

/// `ipv6.opt.type.change`.
pub static IPV6_OPT_TYPE_CHANGE: FieldDef = FieldDef {
    abbrev: "ipv6.opt.type.change",
    name: "May Change",
    field_type: FieldType::Boolean,
    parent: "ipv6",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "Whether the option data may change en-route",
    generated: false,
};

/// `ipv6.opt.type.rest`.
pub static IPV6_OPT_TYPE_REST: FieldDef = FieldDef {
    abbrev: "ipv6.opt.type.rest",
    name: "Low-Order Bits",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Hex,
    bitmask: Some(0x1f),
    blurb: "Remaining low-order bits",
    generated: false,
};

/// `ipv6.opt.length`.
pub static IPV6_OPT_LENGTH: FieldDef = FieldDef {
    abbrev: "ipv6.opt.length",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option length in octets",
    generated: false,
};

/// `ipv6.opt.pad1`.
pub static IPV6_OPT_PAD1: FieldDef = FieldDef {
    abbrev: "ipv6.opt.pad1",
    name: "Pad1",
    field_type: FieldType::None,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "Pad1 Option",
    generated: false,
};

/// `ipv6.opt.padn`.
pub static IPV6_OPT_PADN: FieldDef = FieldDef {
    abbrev: "ipv6.opt.padn",
    name: "PadN",
    field_type: FieldType::Bytes,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "PadN Option",
    generated: false,
};

/// `ipv6.opt.router_alert`.
pub static IPV6_OPT_ROUTER_ALERT: FieldDef = FieldDef {
    abbrev: "ipv6.opt.router_alert",
    name: "Router Alert",
    field_type: FieldType::Uint16,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Router Alert Option",
    generated: false,
};

/// `ipv6.opt.jumbo`.
pub static IPV6_OPT_JUMBO: FieldDef = FieldDef {
    abbrev: "ipv6.opt.jumbo",
    name: "Payload Length",
    field_type: FieldType::Uint32,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "IPv6 (Jumbo) Payload Length",
    generated: false,
};

/// `ipv6.fragment`.
pub static IPV6_FRAGMENT: FieldDef = FieldDef {
    abbrev: "ipv6.fragment",
    name: "IPv6 Fragment",
    field_type: FieldType::FrameNumber,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ipv6.fragment.overlap`.
pub static IPV6_FRAGMENT_OVERLAP: FieldDef = FieldDef {
    abbrev: "ipv6.fragment.overlap",
    name: "Fragment overlap",
    field_type: FieldType::Boolean,
    parent: "ipv6",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Fragment overlaps with other fragments",
    generated: true,
};

/// `ipv6.fragment.overlap.conflict`.
pub static IPV6_FRAGMENT_OVERLAP_CONFLICT: FieldDef = FieldDef {
    abbrev: "ipv6.fragment.overlap.conflict",
    name: "Conflicting data in fragment overlap",
    field_type: FieldType::Boolean,
    parent: "ipv6",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Overlapping fragments contained conflicting data",
    generated: true,
};

/// `ipv6.fragment.multipletails`.
pub static IPV6_FRAGMENT_MULTIPLETAILS: FieldDef = FieldDef {
    abbrev: "ipv6.fragment.multipletails",
    name: "Multiple tail fragments found",
    field_type: FieldType::Boolean,
    parent: "ipv6",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Several tails were found when defragmenting the packet",
    generated: true,
};

/// `ipv6.fragment.toolongfragment`.
pub static IPV6_FRAGMENT_TOOLONGFRAGMENT: FieldDef = FieldDef {
    abbrev: "ipv6.fragment.toolongfragment",
    name: "Fragment too long",
    field_type: FieldType::Boolean,
    parent: "ipv6",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Fragment contained data past end of packet",
    generated: true,
};

/// `ipv6.fragment.error`.
pub static IPV6_FRAGMENT_ERROR: FieldDef = FieldDef {
    abbrev: "ipv6.fragment.error",
    name: "Defragmentation error",
    field_type: FieldType::FrameNumber,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "Defragmentation error due to illegal fragments",
    generated: true,
};

/// `ipv6.fragment.count`.
pub static IPV6_FRAGMENT_COUNT: FieldDef = FieldDef {
    abbrev: "ipv6.fragment.count",
    name: "Fragment count",
    field_type: FieldType::Uint32,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ipv6.fragments`.
pub static IPV6_FRAGMENTS: FieldDef = FieldDef {
    abbrev: "ipv6.fragments",
    name: "IPv6 Fragments",
    field_type: FieldType::None,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ipv6.reassembled.in`.
pub static IPV6_REASSEMBLED_IN: FieldDef = FieldDef {
    abbrev: "ipv6.reassembled.in",
    name: "Reassembled IPv6 in frame",
    field_type: FieldType::FrameNumber,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "This IPv6 packet is reassembled in this frame",
    generated: true,
};

/// `ipv6.reassembled.length`.
pub static IPV6_REASSEMBLED_LENGTH: FieldDef = FieldDef {
    abbrev: "ipv6.reassembled.length",
    name: "Reassembled IPv6 length",
    field_type: FieldType::Uint32,
    parent: "ipv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The total length of the reassembled payload",
    generated: true,
};

/// `ipv6.reassembled.data`.
pub static IPV6_REASSEMBLED_DATA: FieldDef = FieldDef {
    abbrev: "ipv6.reassembled.data",
    name: "Reassembled IPv6 data",
    field_type: FieldType::Bytes,
    parent: "ipv6",
    display: Display::None,
    bitmask: None,
    blurb: "The reassembled payload",
    generated: true,
};

/// `ipv6.hopopts.nxt`.
pub static IPV6_HOPOPTS_NXT: FieldDef = FieldDef {
    abbrev: "ipv6.hopopts.nxt",
    name: "Next Header",
    field_type: FieldType::Uint8,
    parent: "ipv6.hopopts",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.hopopts.len`.
pub static IPV6_HOPOPTS_LEN: FieldDef = FieldDef {
    abbrev: "ipv6.hopopts.len",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "ipv6.hopopts",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Extension header length in 8-octet words (minus 1)",
    generated: false,
};

/// `ipv6.hopopts.len_oct`.
pub static IPV6_HOPOPTS_LEN_OCT: FieldDef = FieldDef {
    abbrev: "ipv6.hopopts.len_oct",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "ipv6.hopopts",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Extension header length in octets",
    generated: false,
};

/// `ipv6.dstopts.nxt`.
pub static IPV6_DSTOPTS_NXT: FieldDef = FieldDef {
    abbrev: "ipv6.dstopts.nxt",
    name: "Next Header",
    field_type: FieldType::Uint8,
    parent: "ipv6.dstopts",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.dstopts.len`.
pub static IPV6_DSTOPTS_LEN: FieldDef = FieldDef {
    abbrev: "ipv6.dstopts.len",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "ipv6.dstopts",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Extension header length in 8-octet words (minus 1)",
    generated: false,
};

/// `ipv6.dstopts.len_oct`.
pub static IPV6_DSTOPTS_LEN_OCT: FieldDef = FieldDef {
    abbrev: "ipv6.dstopts.len_oct",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "ipv6.dstopts",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Extension header length in octets",
    generated: false,
};

/// `ipv6.routing.nxt`.
pub static IPV6_ROUTING_NXT: FieldDef = FieldDef {
    abbrev: "ipv6.routing.nxt",
    name: "Next Header",
    field_type: FieldType::Uint8,
    parent: "ipv6.routing",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.routing.len`.
pub static IPV6_ROUTING_LEN: FieldDef = FieldDef {
    abbrev: "ipv6.routing.len",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "ipv6.routing",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Extension header length in 8-octet words (minus 1)",
    generated: false,
};

/// `ipv6.routing.len_oct`.
pub static IPV6_ROUTING_LEN_OCT: FieldDef = FieldDef {
    abbrev: "ipv6.routing.len_oct",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "ipv6.routing",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Extension header length in octets",
    generated: false,
};

/// `ipv6.routing.type`.
pub static IPV6_ROUTING_TYPE: FieldDef = FieldDef {
    abbrev: "ipv6.routing.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "ipv6.routing",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Routing Header Type",
    generated: false,
};

/// `ipv6.routing.segleft`.
pub static IPV6_ROUTING_SEGLEFT: FieldDef = FieldDef {
    abbrev: "ipv6.routing.segleft",
    name: "Segments Left",
    field_type: FieldType::Uint8,
    parent: "ipv6.routing",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Routing Header Segments Left",
    generated: false,
};

/// `ipv6.routing.unknown_data`.
pub static IPV6_ROUTING_UNKNOWN_DATA: FieldDef = FieldDef {
    abbrev: "ipv6.routing.unknown_data",
    name: "Type-Specific Data",
    field_type: FieldType::Bytes,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "Unknown routing header type-specific data",
    generated: false,
};

/// `ipv6.routing.src.reserved`.
pub static IPV6_ROUTING_SRC_RESERVED: FieldDef = FieldDef {
    abbrev: "ipv6.routing.src.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "Must be zero",
    generated: false,
};

/// `ipv6.routing.src.addr`.
pub static IPV6_ROUTING_SRC_ADDR: FieldDef = FieldDef {
    abbrev: "ipv6.routing.src.addr",
    name: "Address",
    field_type: FieldType::Ipv6,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "Source Routing Header Address",
    generated: false,
};

/// `ipv6.routing.mipv6.reserved`.
pub static IPV6_ROUTING_MIPV6_RESERVED: FieldDef = FieldDef {
    abbrev: "ipv6.routing.mipv6.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "Must be zero",
    generated: false,
};

/// `ipv6.routing.mipv6.home_address`.
pub static IPV6_ROUTING_MIPV6_HOME_ADDRESS: FieldDef = FieldDef {
    abbrev: "ipv6.routing.mipv6.home_address",
    name: "Home Address",
    field_type: FieldType::Ipv6,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.routing.srh.last_entry`.
pub static IPV6_ROUTING_SRH_LAST_ENTRY: FieldDef = FieldDef {
    abbrev: "ipv6.routing.srh.last_entry",
    name: "Last Entry",
    field_type: FieldType::Uint8,
    parent: "ipv6.routing",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Index (zero based) of the last element of the Segment List",
    generated: false,
};

/// `ipv6.routing.srh.flags`.
pub static IPV6_ROUTING_SRH_FLAGS: FieldDef = FieldDef {
    abbrev: "ipv6.routing.srh.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "ipv6.routing",
    display: Display::Hex,
    bitmask: None,
    blurb: "Unused, 8 bits of flags",
    generated: false,
};

/// `ipv6.routing.srh.tag`.
pub static IPV6_ROUTING_SRH_TAG: FieldDef = FieldDef {
    abbrev: "ipv6.routing.srh.tag",
    name: "Tag",
    field_type: FieldType::Bytes,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "Tag a packet as part of a class or group of packets",
    generated: false,
};

/// `ipv6.routing.srh.addr`.
pub static IPV6_ROUTING_SRH_ADDR: FieldDef = FieldDef {
    abbrev: "ipv6.routing.srh.addr",
    name: "Address",
    field_type: FieldType::Ipv6,
    parent: "ipv6.routing",
    display: Display::None,
    bitmask: None,
    blurb: "Segment address",
    generated: false,
};

/// `ipv6.fraghdr.nxt`.
pub static IPV6_FRAGHDR_NXT: FieldDef = FieldDef {
    abbrev: "ipv6.fraghdr.nxt",
    name: "Next header",
    field_type: FieldType::Uint8,
    parent: "ipv6.fraghdr",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ipv6.fraghdr.reserved_octet`.
pub static IPV6_FRAGHDR_RESERVED_OCTET: FieldDef = FieldDef {
    abbrev: "ipv6.fraghdr.reserved_octet",
    name: "Reserved octet",
    field_type: FieldType::Uint8,
    parent: "ipv6.fraghdr",
    display: Display::Hex,
    bitmask: None,
    blurb: "Should always be 0",
    generated: false,
};

/// `ipv6.fraghdr.offset`.
pub static IPV6_FRAGHDR_OFFSET: FieldDef = FieldDef {
    abbrev: "ipv6.fraghdr.offset",
    name: "Offset",
    field_type: FieldType::Uint16,
    parent: "ipv6.fraghdr",
    display: Display::Decimal,
    bitmask: Some(0xfff8),
    blurb: "Fragment Offset",
    generated: false,
};

/// `ipv6.fraghdr.reserved_bits`.
pub static IPV6_FRAGHDR_RESERVED_BITS: FieldDef = FieldDef {
    abbrev: "ipv6.fraghdr.reserved_bits",
    name: "Reserved bits",
    field_type: FieldType::Uint16,
    parent: "ipv6.fraghdr",
    display: Display::Decimal,
    bitmask: Some(0x0006),
    blurb: "",
    generated: false,
};

/// `ipv6.fraghdr.more`.
pub static IPV6_FRAGHDR_MORE: FieldDef = FieldDef {
    abbrev: "ipv6.fraghdr.more",
    name: "More Fragments",
    field_type: FieldType::Boolean,
    parent: "ipv6.fraghdr",
    display: Display::Boolean16,
    bitmask: Some(0x0001),
    blurb: "",
    generated: false,
};

/// `ipv6.fraghdr.ident`.
pub static IPV6_FRAGHDR_IDENT: FieldDef = FieldDef {
    abbrev: "ipv6.fraghdr.ident",
    name: "Identification",
    field_type: FieldType::Uint32,
    parent: "ipv6.fraghdr",
    display: Display::Hex,
    bitmask: None,
    blurb: "Fragment Identification",
    generated: false,
};

static IPV6_FIELDS: &[&FieldDef] = &[
    &IPV6_VERSION,
    &IPV6_TCLASS,
    &IPV6_TCLASS_DSCP,
    &IPV6_TCLASS_ECN,
    &IPV6_FLOW,
    &IPV6_PLEN,
    &IPV6_NXT,
    &IPV6_HLIM,
    &IPV6_SRC,
    &IPV6_SRC_HOST,
    &IPV6_DST,
    &IPV6_DST_HOST,
    &IPV6_ADDR,
    &IPV6_OPT_TYPE,
    &IPV6_OPT_TYPE_ACTION,
    &IPV6_OPT_TYPE_CHANGE,
    &IPV6_OPT_TYPE_REST,
    &IPV6_OPT_LENGTH,
    &IPV6_OPT_PAD1,
    &IPV6_OPT_PADN,
    &IPV6_OPT_ROUTER_ALERT,
    &IPV6_OPT_JUMBO,
    &IPV6_FRAGMENT,
    &IPV6_FRAGMENT_OVERLAP,
    &IPV6_FRAGMENT_OVERLAP_CONFLICT,
    &IPV6_FRAGMENT_MULTIPLETAILS,
    &IPV6_FRAGMENT_TOOLONGFRAGMENT,
    &IPV6_FRAGMENT_ERROR,
    &IPV6_FRAGMENT_COUNT,
    &IPV6_FRAGMENTS,
    &IPV6_REASSEMBLED_IN,
    &IPV6_REASSEMBLED_LENGTH,
    &IPV6_REASSEMBLED_DATA,
];

static IPV6_HOPOPTS_FIELDS: &[&FieldDef] =
    &[&IPV6_HOPOPTS_NXT, &IPV6_HOPOPTS_LEN, &IPV6_HOPOPTS_LEN_OCT];

static IPV6_DSTOPTS_FIELDS: &[&FieldDef] =
    &[&IPV6_DSTOPTS_NXT, &IPV6_DSTOPTS_LEN, &IPV6_DSTOPTS_LEN_OCT];

static IPV6_ROUTING_FIELDS: &[&FieldDef] = &[
    &IPV6_ROUTING_NXT,
    &IPV6_ROUTING_LEN,
    &IPV6_ROUTING_LEN_OCT,
    &IPV6_ROUTING_TYPE,
    &IPV6_ROUTING_SEGLEFT,
    &IPV6_ROUTING_UNKNOWN_DATA,
    &IPV6_ROUTING_SRC_RESERVED,
    &IPV6_ROUTING_SRC_ADDR,
    &IPV6_ROUTING_MIPV6_RESERVED,
    &IPV6_ROUTING_MIPV6_HOME_ADDRESS,
    &IPV6_ROUTING_SRH_LAST_ENTRY,
    &IPV6_ROUTING_SRH_FLAGS,
    &IPV6_ROUTING_SRH_TAG,
    &IPV6_ROUTING_SRH_ADDR,
];

static IPV6_FRAGHDR_FIELDS: &[&FieldDef] = &[
    &IPV6_FRAGHDR_NXT,
    &IPV6_FRAGHDR_RESERVED_OCTET,
    &IPV6_FRAGHDR_OFFSET,
    &IPV6_FRAGHDR_RESERVED_BITS,
    &IPV6_FRAGHDR_MORE,
    &IPV6_FRAGHDR_IDENT,
];

/// `tcp.srcport`.
pub static TCP_SRC_PORT: FieldDef = FieldDef {
    abbrev: "tcp.srcport",
    name: "Source Port",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::PortTcp,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.dstport`.
pub static TCP_DST_PORT: FieldDef = FieldDef {
    abbrev: "tcp.dstport",
    name: "Destination Port",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::PortTcp,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.port`; added once for the source and once for the destination.
pub static TCP_PORT: FieldDef = FieldDef {
    abbrev: "tcp.port",
    name: "Source or Destination Port",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::PortTcp,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.stream`.
pub static TCP_STREAM: FieldDef = FieldDef {
    abbrev: "tcp.stream",
    name: "Stream index",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.stream.pnum`.
pub static TCP_STREAM_PNUM: FieldDef = FieldDef {
    abbrev: "tcp.stream.pnum",
    name: "Stream Packet Number",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Relative packet number in this TCP stream",
    generated: true,
};

/// `tcp.seq`.
pub static TCP_SEQ: FieldDef = FieldDef {
    abbrev: "tcp.seq",
    name: "Sequence Number",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.seq_raw`.
pub static TCP_SEQ_RAW: FieldDef = FieldDef {
    abbrev: "tcp.seq_raw",
    name: "Sequence Number (raw)",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "This shows the raw value of the sequence number",
    generated: false,
};

/// `tcp.nxtseq`.
pub static TCP_NXTSEQ: FieldDef = FieldDef {
    abbrev: "tcp.nxtseq",
    name: "Next Sequence Number",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.ack`.
pub static TCP_ACK: FieldDef = FieldDef {
    abbrev: "tcp.ack",
    name: "Acknowledgment Number",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.ack_raw`.
pub static TCP_ACK_RAW: FieldDef = FieldDef {
    abbrev: "tcp.ack_raw",
    name: "Acknowledgment number (raw)",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "This shows the raw value of the acknowledgment number",
    generated: false,
};

/// `tcp.hdr_len`.
pub static TCP_HDR_LEN: FieldDef = FieldDef {
    abbrev: "tcp.hdr_len",
    name: "Header Length",
    field_type: FieldType::Uint8,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Data offset in 32-bit words",
    generated: false,
};

/// `tcp.flags`.
pub static TCP_FLAGS: FieldDef = FieldDef {
    abbrev: "tcp.flags",
    name: "Flags",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Hex,
    bitmask: Some(0xfff),
    blurb: "",
    generated: false,
};

/// `tcp.flags.res`.
pub static TCP_FLAGS_RES: FieldDef = FieldDef {
    abbrev: "tcp.flags.res",
    name: "Reserved",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0xe00),
    blurb: "Three reserved bits (must be zero)",
    generated: false,
};

/// `tcp.flags.ae`.
pub static TCP_FLAGS_AE: FieldDef = FieldDef {
    abbrev: "tcp.flags.ae",
    name: "Accurate ECN",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x100),
    blurb: "",
    generated: false,
};

/// `tcp.flags.cwr`.
pub static TCP_FLAGS_CWR: FieldDef = FieldDef {
    abbrev: "tcp.flags.cwr",
    name: "Congestion Window Reduced",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `tcp.flags.ece`.
pub static TCP_FLAGS_ECE: FieldDef = FieldDef {
    abbrev: "tcp.flags.ece",
    name: "ECN-Echo",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `tcp.flags.urg`.
pub static TCP_FLAGS_URG: FieldDef = FieldDef {
    abbrev: "tcp.flags.urg",
    name: "Urgent",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `tcp.flags.ack`.
pub static TCP_FLAGS_ACK: FieldDef = FieldDef {
    abbrev: "tcp.flags.ack",
    name: "Acknowledgment",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `tcp.flags.push`.
pub static TCP_FLAGS_PUSH: FieldDef = FieldDef {
    abbrev: "tcp.flags.push",
    name: "Push",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `tcp.flags.reset`.
pub static TCP_FLAGS_RESET: FieldDef = FieldDef {
    abbrev: "tcp.flags.reset",
    name: "Reset",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `tcp.flags.syn`.
pub static TCP_FLAGS_SYN: FieldDef = FieldDef {
    abbrev: "tcp.flags.syn",
    name: "Syn",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `tcp.flags.fin`.
pub static TCP_FLAGS_FIN: FieldDef = FieldDef {
    abbrev: "tcp.flags.fin",
    name: "Fin",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean12,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `tcp.flags.str`.
pub static TCP_FLAGS_STR: FieldDef = FieldDef {
    abbrev: "tcp.flags.str",
    name: "TCP Flags",
    field_type: FieldType::String,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.window_size_value`.
pub static TCP_WINDOW_SIZE_VALUE: FieldDef = FieldDef {
    abbrev: "tcp.window_size_value",
    name: "Window",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The window size value from the TCP header",
    generated: false,
};

/// `tcp.checksum`.
pub static TCP_CHECKSUM: FieldDef = FieldDef {
    abbrev: "tcp.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Checksum over the pseudo-header, TCP header and data (RFC 9293)",
    generated: false,
};

/// `tcp.checksum.status`.
pub static TCP_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "tcp.checksum.status",
    name: "Checksum Status",
    field_type: FieldType::Uint8,
    parent: "tcp",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.checksum_calculated`.
pub static TCP_CHECKSUM_CALCULATED: FieldDef = FieldDef {
    abbrev: "tcp.checksum_calculated",
    name: "Calculated Checksum",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "The expected TCP checksum field as calculated from the TCP segment",
    generated: true,
};

/// `tcp.len`.
pub static TCP_LEN: FieldDef = FieldDef {
    abbrev: "tcp.len",
    name: "TCP Segment Len",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.urgent_pointer`.
pub static TCP_URGENT_POINTER: FieldDef = FieldDef {
    abbrev: "tcp.urgent_pointer",
    name: "Urgent Pointer",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.option_kind`.
pub static TCP_OPTION_KIND: FieldDef = FieldDef {
    abbrev: "tcp.option_kind",
    name: "Kind",
    field_type: FieldType::Uint8,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "This TCP option's kind",
    generated: false,
};

/// `tcp.option_len`.
pub static TCP_OPTION_LEN: FieldDef = FieldDef {
    abbrev: "tcp.option_len",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of this TCP option in bytes (including kind and length fields)",
    generated: false,
};

/// `tcp.options`.
pub static TCP_OPTIONS: FieldDef = FieldDef {
    abbrev: "tcp.options",
    name: "TCP Options",
    field_type: FieldType::Bytes,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.options.mss_val`.
pub static TCP_OPTIONS_MSS_VALUE: FieldDef = FieldDef {
    abbrev: "tcp.options.mss_val",
    name: "MSS Value",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.options.wscale.shift`.
pub static TCP_OPTIONS_WSCALE_SHIFT: FieldDef = FieldDef {
    abbrev: "tcp.options.wscale.shift",
    name: "Shift count",
    field_type: FieldType::Uint8,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Logarithmically encoded power of 2 scale factor",
    generated: false,
};

/// `tcp.options.wscale.multiplier`.
pub static TCP_OPTIONS_WSCALE_MULTIPLIER: FieldDef = FieldDef {
    abbrev: "tcp.options.wscale.multiplier",
    name: "Multiplier",
    field_type: FieldType::Uint16,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Multiply segment window size by this for scaled window size",
    generated: false,
};

/// `tcp.options.sack_le`.
pub static TCP_OPTIONS_SACK_LE: FieldDef = FieldDef {
    abbrev: "tcp.options.sack_le",
    name: "TCP SACK Left Edge",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.options.sack_re`.
pub static TCP_OPTIONS_SACK_RE: FieldDef = FieldDef {
    abbrev: "tcp.options.sack_re",
    name: "TCP SACK Right Edge",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tcp.options.sack.count`.
pub static TCP_OPTIONS_SACK_COUNT: FieldDef = FieldDef {
    abbrev: "tcp.options.sack.count",
    name: "TCP SACK Count",
    field_type: FieldType::Uint8,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.options.timestamp.tsval`.
pub static TCP_OPTIONS_TIMESTAMP_TSVAL: FieldDef = FieldDef {
    abbrev: "tcp.options.timestamp.tsval",
    name: "Timestamp value",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Value of sending machine's timestamp clock",
    generated: false,
};

/// `tcp.options.timestamp.tsecr`.
pub static TCP_OPTIONS_TIMESTAMP_TSECR: FieldDef = FieldDef {
    abbrev: "tcp.options.timestamp.tsecr",
    name: "Timestamp echo reply",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Echoed timestamp from remote machine",
    generated: false,
};

/// `tcp.payload`.
pub static TCP_PAYLOAD: FieldDef = FieldDef {
    abbrev: "tcp.payload",
    name: "TCP payload",
    field_type: FieldType::Bytes,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "The TCP payload of this packet",
    generated: false,
};

/// `tcp.option.len.invalid`.
pub static TCP_OPTION_LEN_INVALID: FieldDef = FieldDef {
    abbrev: "tcp.option.len.invalid",
    name: "Invalid length for option",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.window_size`.
pub static TCP_WINDOW_SIZE: FieldDef = FieldDef {
    abbrev: "tcp.window_size",
    name: "Calculated window size",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The scaled window size (if scaling has been used)",
    generated: true,
};

/// `tcp.window_size_scalefactor`.
pub static TCP_WINDOW_SIZE_SCALEFACTOR: FieldDef = FieldDef {
    abbrev: "tcp.window_size_scalefactor",
    name: "Window size scaling factor",
    field_type: FieldType::Int32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The window size scaling factor (-1 when unknown, -2 when no scaling is used)",
    generated: true,
};

/// `tcp.analysis`.
pub static TCP_ANALYSIS: FieldDef = FieldDef {
    abbrev: "tcp.analysis",
    name: "SEQ/ACK analysis",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "This frame has some of the TCP analysis shown",
    generated: true,
};

/// `tcp.analysis.flags`.
pub static TCP_ANALYSIS_FLAGS: FieldDef = FieldDef {
    abbrev: "tcp.analysis.flags",
    name: "TCP Analysis Flags",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "This frame has some of the TCP analysis flags set",
    generated: true,
};

/// `tcp.analysis.duplicate_ack`.
pub static TCP_ANALYSIS_DUPLICATE_ACK: FieldDef = FieldDef {
    abbrev: "tcp.analysis.duplicate_ack",
    name: "Duplicate ACK",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "This is a duplicate ACK",
    generated: true,
};

/// `tcp.analysis.duplicate_ack_num`.
pub static TCP_ANALYSIS_DUPLICATE_ACK_NUM: FieldDef = FieldDef {
    abbrev: "tcp.analysis.duplicate_ack_num",
    name: "Duplicate ACK #",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "This is duplicate ACK number #",
    generated: true,
};

/// `tcp.analysis.duplicate_ack_frame`.
pub static TCP_ANALYSIS_DUPLICATE_ACK_FRAME: FieldDef = FieldDef {
    abbrev: "tcp.analysis.duplicate_ack_frame",
    name: "Duplicate to the ACK in frame",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "This is a duplicate to the ACK in frame #",
    generated: true,
};

/// `tcp.analysis.acks_frame`.
pub static TCP_ANALYSIS_ACKS_FRAME: FieldDef = FieldDef {
    abbrev: "tcp.analysis.acks_frame",
    name: "This is an ACK to the segment in frame",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "Which previous segment is this an ACK for",
    generated: true,
};

/// `tcp.analysis.bytes_in_flight`.
pub static TCP_ANALYSIS_BYTES_IN_FLIGHT: FieldDef = FieldDef {
    abbrev: "tcp.analysis.bytes_in_flight",
    name: "Bytes in flight",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "How many bytes are now in flight for this connection",
    generated: true,
};

/// `tcp.analysis.push_bytes_sent`.
pub static TCP_ANALYSIS_PUSH_BYTES_SENT: FieldDef = FieldDef {
    abbrev: "tcp.analysis.push_bytes_sent",
    name: "Bytes sent since last PSH flag",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "How many bytes have been sent since the last PSH flag",
    generated: true,
};

/// `tcp.analysis.ack_rtt`.
pub static TCP_ANALYSIS_ACK_RTT: FieldDef = FieldDef {
    abbrev: "tcp.analysis.ack_rtt",
    name: "The RTT to ACK the segment was",
    field_type: FieldType::RelativeTime,
    parent: "tcp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "How long time it took to ACK the segment (RTT)",
    generated: true,
};

/// `tcp.analysis.initial_rtt`.
pub static TCP_ANALYSIS_INITIAL_RTT: FieldDef = FieldDef {
    abbrev: "tcp.analysis.initial_rtt",
    name: "iRTT",
    field_type: FieldType::RelativeTime,
    parent: "tcp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "How long it took for the SYN to ACK handshake (iRTT)",
    generated: true,
};

/// `tcp.analysis.rto`.
pub static TCP_ANALYSIS_RTO: FieldDef = FieldDef {
    abbrev: "tcp.analysis.rto",
    name: "The RTO for this segment was",
    field_type: FieldType::RelativeTime,
    parent: "tcp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "How long transmission was delayed before this segment was retransmitted (RTO)",
    generated: true,
};

/// `tcp.analysis.rto_frame`.
pub static TCP_ANALYSIS_RTO_FRAME: FieldDef = FieldDef {
    abbrev: "tcp.analysis.rto_frame",
    name: "RTO based on delta from frame",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "This is the frame we measure the RTO from",
    generated: true,
};

/// `tcp.segment.overlap`.
pub static TCP_SEGMENT_OVERLAP: FieldDef = FieldDef {
    abbrev: "tcp.segment.overlap",
    name: "Segment overlap",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Segment overlaps with other segments",
    generated: true,
};

/// `tcp.segment.overlap.conflict`.
pub static TCP_SEGMENT_OVERLAP_CONFLICT: FieldDef = FieldDef {
    abbrev: "tcp.segment.overlap.conflict",
    name: "Conflicting data in segment overlap",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Overlapping segments contained conflicting data",
    generated: true,
};

/// `tcp.segment.multipletails`.
pub static TCP_SEGMENT_MULTIPLETAILS: FieldDef = FieldDef {
    abbrev: "tcp.segment.multipletails",
    name: "Multiple tail segments found",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Several tails were found when reassembling the pdu",
    generated: true,
};

/// `tcp.segment.toolongfragment`.
pub static TCP_SEGMENT_TOOLONGFRAGMENT: FieldDef = FieldDef {
    abbrev: "tcp.segment.toolongfragment",
    name: "Segment too long",
    field_type: FieldType::Boolean,
    parent: "tcp",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "Segment contained data past end of the pdu",
    generated: true,
};

/// `tcp.segment.error`.
pub static TCP_SEGMENT_ERROR: FieldDef = FieldDef {
    abbrev: "tcp.segment.error",
    name: "Reassembling error",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "Reassembling error due to illegal segments",
    generated: true,
};

/// `tcp.segment.count`.
pub static TCP_SEGMENT_COUNT: FieldDef = FieldDef {
    abbrev: "tcp.segment.count",
    name: "Segment count",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.segment`.
pub static TCP_SEGMENT: FieldDef = FieldDef {
    abbrev: "tcp.segment",
    name: "TCP Segment",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.segments`.
pub static TCP_SEGMENTS: FieldDef = FieldDef {
    abbrev: "tcp.segments",
    name: "Reassembled TCP Segments",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.reassembled_in`.
pub static TCP_REASSEMBLED_IN: FieldDef = FieldDef {
    abbrev: "tcp.reassembled_in",
    name: "Reassembled PDU in frame",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "The PDU that doesn't end in this segment is reassembled in this frame",
    generated: true,
};

/// `tcp.reassembled.length`.
pub static TCP_REASSEMBLED_LENGTH: FieldDef = FieldDef {
    abbrev: "tcp.reassembled.length",
    name: "Reassembled TCP length",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The total length of the reassembled payload",
    generated: true,
};

/// `tcp.reassembled.data`.
pub static TCP_REASSEMBLED_DATA: FieldDef = FieldDef {
    abbrev: "tcp.reassembled.data",
    name: "Reassembled TCP Data",
    field_type: FieldType::Bytes,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "The reassembled payload",
    generated: true,
};

/// `tcp.pdu.time`.
pub static TCP_PDU_TIME: FieldDef = FieldDef {
    abbrev: "tcp.pdu.time",
    name: "Time until the last segment of this PDU",
    field_type: FieldType::RelativeTime,
    parent: "tcp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "How long time has passed until the last frame of this PDU",
    generated: true,
};

/// `tcp.pdu.size`.
pub static TCP_PDU_SIZE: FieldDef = FieldDef {
    abbrev: "tcp.pdu.size",
    name: "PDU Size",
    field_type: FieldType::Uint32,
    parent: "tcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The size of this PDU",
    generated: true,
};

/// `tcp.pdu.last_frame`.
pub static TCP_PDU_LAST_FRAME: FieldDef = FieldDef {
    abbrev: "tcp.pdu.last_frame",
    name: "Last frame of this PDU",
    field_type: FieldType::FrameNumber,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "This is the last frame of the PDU starting in this segment",
    generated: true,
};

/// The `[Timestamps]` container, which carries a label rather than a name.
///
/// The definition is not part of the TCP registry list: the container itself
/// is not a reported field, only its two relative-time children are.
pub(crate) static TCP_TIMESTAMPS: FieldDef = FieldDef {
    abbrev: "Timestamps",
    name: "Timestamps",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.time_relative`.
pub static TCP_TIME_RELATIVE: FieldDef = FieldDef {
    abbrev: "tcp.time_relative",
    name: "Time since first frame in this TCP stream",
    field_type: FieldType::RelativeTime,
    parent: "tcp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "Time relative to first frame in this TCP stream",
    generated: true,
};

/// `tcp.time_delta`.
pub static TCP_TIME_DELTA: FieldDef = FieldDef {
    abbrev: "tcp.time_delta",
    name: "Time since previous frame in this TCP stream",
    field_type: FieldType::RelativeTime,
    parent: "tcp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "Time delta from previous frame in this TCP stream",
    generated: true,
};

/// `tcp.segment_data`.
pub static TCP_SEGMENT_DATA: FieldDef = FieldDef {
    abbrev: "tcp.segment_data",
    name: "TCP segment data",
    field_type: FieldType::Bytes,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "A data segment used in reassembly of an upper-layer protocol (ULP)",
    generated: false,
};

/// `tcp.analysis.retransmission`.
pub static TCP_ANALYSIS_RETRANSMISSION: FieldDef = FieldDef {
    abbrev: "tcp.analysis.retransmission",
    name: "This frame is a (suspected) retransmission",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.fast_retransmission`.
pub static TCP_ANALYSIS_FAST_RETRANSMISSION: FieldDef = FieldDef {
    abbrev: "tcp.analysis.fast_retransmission",
    name: "This frame is a (suspected) fast retransmission",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.spurious_retransmission`.
pub static TCP_ANALYSIS_SPURIOUS_RETRANSMISSION: FieldDef = FieldDef {
    abbrev: "tcp.analysis.spurious_retransmission",
    name: "This frame is a (suspected) spurious retransmission",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.out_of_order`.
pub static TCP_ANALYSIS_OUT_OF_ORDER: FieldDef = FieldDef {
    abbrev: "tcp.analysis.out_of_order",
    name: "This frame is a (suspected) out-of-order segment",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.reused_ports`.
pub static TCP_ANALYSIS_REUSED_PORTS: FieldDef = FieldDef {
    abbrev: "tcp.analysis.reused_ports",
    name: "A new tcp session is started with the same ports as an earlier session in this trace",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.lost_segment`.
pub static TCP_ANALYSIS_LOST_SEGMENT: FieldDef = FieldDef {
    abbrev: "tcp.analysis.lost_segment",
    name: "Previous segment(s) not captured (common at capture start)",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.ack_lost_segment`.
pub static TCP_ANALYSIS_ACK_LOST_SEGMENT: FieldDef = FieldDef {
    abbrev: "tcp.analysis.ack_lost_segment",
    name: "ACKed segment that wasn't captured (common at capture start)",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.window_update`.
pub static TCP_ANALYSIS_WINDOW_UPDATE: FieldDef = FieldDef {
    abbrev: "tcp.analysis.window_update",
    name: "TCP window update",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.window_full`.
pub static TCP_ANALYSIS_WINDOW_FULL: FieldDef = FieldDef {
    abbrev: "tcp.analysis.window_full",
    name: "TCP window specified by the receiver is now completely full",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.keep_alive`.
pub static TCP_ANALYSIS_KEEP_ALIVE: FieldDef = FieldDef {
    abbrev: "tcp.analysis.keep_alive",
    name: "TCP keep-alive segment",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.keep_alive_ack`.
pub static TCP_ANALYSIS_KEEP_ALIVE_ACK: FieldDef = FieldDef {
    abbrev: "tcp.analysis.keep_alive_ack",
    name: "ACK to a TCP keep-alive segment",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.zero_window_probe`.
pub static TCP_ANALYSIS_ZERO_WINDOW_PROBE: FieldDef = FieldDef {
    abbrev: "tcp.analysis.zero_window_probe",
    name: "TCP Zero Window Probe",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.zero_window`.
pub static TCP_ANALYSIS_ZERO_WINDOW: FieldDef = FieldDef {
    abbrev: "tcp.analysis.zero_window",
    name: "TCP Zero Window segment",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.analysis.zero_window_probe_ack`.
pub static TCP_ANALYSIS_ZERO_WINDOW_PROBE_ACK: FieldDef = FieldDef {
    abbrev: "tcp.analysis.zero_window_probe_ack",
    name: "ACK to a TCP Zero Window Probe",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.options.mss.absent`.
pub static TCP_OPTIONS_MSS_ABSENT: FieldDef = FieldDef {
    abbrev: "tcp.options.mss.absent",
    name: "The SYN packet does not contain a MSS option",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tcp.options.sack_perm.absent`.
pub static TCP_OPTIONS_SACK_PERM_ABSENT: FieldDef = FieldDef {
    abbrev: "tcp.options.sack_perm.absent",
    name: "The SYN packet does not contain a SACK PERM option",
    field_type: FieldType::None,
    parent: "tcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

static TCP_FIELDS: &[&FieldDef] = &[
    &TCP_SRC_PORT,
    &TCP_DST_PORT,
    &TCP_PORT,
    &TCP_STREAM,
    &TCP_STREAM_PNUM,
    &TCP_SEQ,
    &TCP_SEQ_RAW,
    &TCP_NXTSEQ,
    &TCP_ACK,
    &TCP_ACK_RAW,
    &TCP_HDR_LEN,
    &TCP_FLAGS,
    &TCP_FLAGS_RES,
    &TCP_FLAGS_AE,
    &TCP_FLAGS_CWR,
    &TCP_FLAGS_ECE,
    &TCP_FLAGS_URG,
    &TCP_FLAGS_ACK,
    &TCP_FLAGS_PUSH,
    &TCP_FLAGS_RESET,
    &TCP_FLAGS_SYN,
    &TCP_FLAGS_FIN,
    &TCP_FLAGS_STR,
    &TCP_WINDOW_SIZE_VALUE,
    &TCP_WINDOW_SIZE,
    &TCP_WINDOW_SIZE_SCALEFACTOR,
    &TCP_CHECKSUM,
    &TCP_CHECKSUM_STATUS,
    &TCP_CHECKSUM_CALCULATED,
    &TCP_ANALYSIS,
    &TCP_ANALYSIS_FLAGS,
    &TCP_ANALYSIS_DUPLICATE_ACK,
    &TCP_ANALYSIS_DUPLICATE_ACK_NUM,
    &TCP_ANALYSIS_DUPLICATE_ACK_FRAME,
    &TCP_LEN,
    &TCP_ANALYSIS_ACKS_FRAME,
    &TCP_ANALYSIS_BYTES_IN_FLIGHT,
    &TCP_ANALYSIS_PUSH_BYTES_SENT,
    &TCP_ANALYSIS_ACK_RTT,
    &TCP_ANALYSIS_INITIAL_RTT,
    &TCP_ANALYSIS_RTO,
    &TCP_ANALYSIS_RTO_FRAME,
    &TCP_URGENT_POINTER,
    &TCP_SEGMENT_OVERLAP,
    &TCP_SEGMENT_OVERLAP_CONFLICT,
    &TCP_SEGMENT_MULTIPLETAILS,
    &TCP_SEGMENT_TOOLONGFRAGMENT,
    &TCP_SEGMENT_ERROR,
    &TCP_SEGMENT_COUNT,
    &TCP_SEGMENT,
    &TCP_SEGMENTS,
    &TCP_REASSEMBLED_IN,
    &TCP_REASSEMBLED_LENGTH,
    &TCP_REASSEMBLED_DATA,
    &TCP_OPTION_KIND,
    &TCP_OPTION_LEN,
    &TCP_OPTIONS,
    &TCP_OPTIONS_MSS_VALUE,
    &TCP_OPTIONS_WSCALE_SHIFT,
    &TCP_OPTIONS_WSCALE_MULTIPLIER,
    &TCP_OPTIONS_SACK_LE,
    &TCP_OPTIONS_SACK_RE,
    &TCP_OPTIONS_SACK_COUNT,
    &TCP_OPTIONS_TIMESTAMP_TSVAL,
    &TCP_OPTIONS_TIMESTAMP_TSECR,
    &TCP_PDU_TIME,
    &TCP_PDU_SIZE,
    &TCP_PDU_LAST_FRAME,
    &TCP_TIME_RELATIVE,
    &TCP_TIME_DELTA,
    &TCP_SEGMENT_DATA,
    &TCP_PAYLOAD,
    &TCP_OPTION_LEN_INVALID,
    &TCP_ANALYSIS_RETRANSMISSION,
    &TCP_ANALYSIS_FAST_RETRANSMISSION,
    &TCP_ANALYSIS_SPURIOUS_RETRANSMISSION,
    &TCP_ANALYSIS_OUT_OF_ORDER,
    &TCP_ANALYSIS_REUSED_PORTS,
    &TCP_ANALYSIS_LOST_SEGMENT,
    &TCP_ANALYSIS_ACK_LOST_SEGMENT,
    &TCP_ANALYSIS_WINDOW_UPDATE,
    &TCP_ANALYSIS_WINDOW_FULL,
    &TCP_ANALYSIS_KEEP_ALIVE,
    &TCP_ANALYSIS_KEEP_ALIVE_ACK,
    &TCP_ANALYSIS_ZERO_WINDOW_PROBE,
    &TCP_ANALYSIS_ZERO_WINDOW,
    &TCP_ANALYSIS_ZERO_WINDOW_PROBE_ACK,
    &TCP_OPTIONS_MSS_ABSENT,
    &TCP_OPTIONS_SACK_PERM_ABSENT,
];

/// `udp.srcport`.
pub static UDP_SRC_PORT: FieldDef = FieldDef {
    abbrev: "udp.srcport",
    name: "Source Port",
    field_type: FieldType::Uint16,
    parent: "udp",
    display: Display::PortUdp,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `udp.dstport`.
pub static UDP_DST_PORT: FieldDef = FieldDef {
    abbrev: "udp.dstport",
    name: "Destination Port",
    field_type: FieldType::Uint16,
    parent: "udp",
    display: Display::PortUdp,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `udp.port`; added once for the source and once for the destination.
pub static UDP_PORT: FieldDef = FieldDef {
    abbrev: "udp.port",
    name: "Source or Destination Port",
    field_type: FieldType::Uint16,
    parent: "udp",
    display: Display::PortUdp,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `udp.stream`.
pub static UDP_STREAM: FieldDef = FieldDef {
    abbrev: "udp.stream",
    name: "Stream index",
    field_type: FieldType::Uint32,
    parent: "udp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `udp.stream.pnum`.
pub static UDP_STREAM_PNUM: FieldDef = FieldDef {
    abbrev: "udp.stream.pnum",
    name: "Stream Packet Number",
    field_type: FieldType::Uint32,
    parent: "udp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Relative packet number in this UDP stream",
    generated: true,
};

/// `udp.length`.
pub static UDP_LENGTH: FieldDef = FieldDef {
    abbrev: "udp.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "udp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length in octets including this header and the data",
    generated: false,
};

/// `udp.checksum`.
pub static UDP_CHECKSUM: FieldDef = FieldDef {
    abbrev: "udp.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "udp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Checksum over the pseudo-header, UDP header and data (RFC 768)",
    generated: false,
};

/// `udp.checksum_calculated`.
pub static UDP_CHECKSUM_CALCULATED: FieldDef = FieldDef {
    abbrev: "udp.checksum_calculated",
    name: "Calculated Checksum",
    field_type: FieldType::Uint16,
    parent: "udp",
    display: Display::Hex,
    bitmask: None,
    blurb: "The expected UDP checksum field as calculated from the UDP packet",
    generated: true,
};

/// `udp.checksum.status`.
pub static UDP_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "udp.checksum.status",
    name: "Checksum Status",
    field_type: FieldType::Uint8,
    parent: "udp",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `udp.time_relative`.
pub static UDP_TIME_RELATIVE: FieldDef = FieldDef {
    abbrev: "udp.time_relative",
    name: "Time since first frame",
    field_type: FieldType::RelativeTime,
    parent: "udp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "Time relative to first frame in this UDP stream",
    generated: true,
};

/// `udp.time_delta`.
pub static UDP_TIME_DELTA: FieldDef = FieldDef {
    abbrev: "udp.time_delta",
    name: "Time since previous frame",
    field_type: FieldType::RelativeTime,
    parent: "udp",
    display: Display::RelativeTime,
    bitmask: None,
    blurb: "Time delta from previous frame in UDP stream",
    generated: true,
};

/// `udp.payload`.
pub static UDP_PAYLOAD: FieldDef = FieldDef {
    abbrev: "udp.payload",
    name: "Payload",
    field_type: FieldType::Bytes,
    parent: "udp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static UDP_FIELDS: &[&FieldDef] = &[
    &UDP_SRC_PORT,
    &UDP_DST_PORT,
    &UDP_PORT,
    &UDP_STREAM,
    &UDP_STREAM_PNUM,
    &UDP_LENGTH,
    &UDP_CHECKSUM,
    &UDP_CHECKSUM_CALCULATED,
    &UDP_CHECKSUM_STATUS,
    &UDP_TIME_RELATIVE,
    &UDP_TIME_DELTA,
    &UDP_PAYLOAD,
];

/// `dns.length`.
pub static DNS_LENGTH: FieldDef = FieldDef {
    abbrev: "dns.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of DNS-over-TCP request or response",
    generated: false,
};

/// `dns.id`.
pub static DNS_ID: FieldDef = FieldDef {
    abbrev: "dns.id",
    name: "Transaction ID",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: None,
    blurb: "Identification of transaction",
    generated: false,
};

/// `dns.flags`.
pub static DNS_FLAGS: FieldDef = FieldDef {
    abbrev: "dns.flags",
    name: "Flags",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.flags.response`.
pub static DNS_FLAGS_RESPONSE: FieldDef = FieldDef {
    abbrev: "dns.flags.response",
    name: "Response",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "Is the message a response?",
    generated: false,
};

/// `dns.flags.opcode`.
pub static DNS_FLAGS_OPCODE: FieldDef = FieldDef {
    abbrev: "dns.flags.opcode",
    name: "Opcode",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: Some(0x7800),
    blurb: "Operation code",
    generated: false,
};

/// `dns.flags.authoritative`.
pub static DNS_FLAGS_AUTHORITATIVE: FieldDef = FieldDef {
    abbrev: "dns.flags.authoritative",
    name: "Authoritative",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x400),
    blurb: "Is the server is an authority for the domain?",
    generated: false,
};

/// `dns.flags.conflict`.
pub static DNS_FLAGS_CONFLICT: FieldDef = FieldDef {
    abbrev: "dns.flags.conflict",
    name: "Conflict",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x400),
    blurb: "Did we receive multiple responses to a query?",
    generated: false,
};

/// `dns.flags.truncated`.
pub static DNS_FLAGS_TRUNCATED: FieldDef = FieldDef {
    abbrev: "dns.flags.truncated",
    name: "Truncated",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x200),
    blurb: "Is the message truncated?",
    generated: false,
};

/// `dns.flags.recdesired`.
pub static DNS_FLAGS_RECDESIRED: FieldDef = FieldDef {
    abbrev: "dns.flags.recdesired",
    name: "Recursion desired",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x100),
    blurb: "Do query recursively?",
    generated: false,
};

/// `dns.flags.recavail`.
pub static DNS_FLAGS_RECAVAIL: FieldDef = FieldDef {
    abbrev: "dns.flags.recavail",
    name: "Recursion available",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x80),
    blurb: "Can the server do recursive queries?",
    generated: false,
};

/// `dns.flags.z`.
pub static DNS_FLAGS_Z: FieldDef = FieldDef {
    abbrev: "dns.flags.z",
    name: "Z",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x40),
    blurb: "Z flag",
    generated: false,
};

/// `dns.flags.authenticated`.
pub static DNS_FLAGS_AUTHENTICATED: FieldDef = FieldDef {
    abbrev: "dns.flags.authenticated",
    name: "Answer authenticated",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x20),
    blurb: "Was the reply data authenticated by the server?",
    generated: false,
};

/// `dns.flags.checkdisable`.
pub static DNS_FLAGS_CHECKDISABLE: FieldDef = FieldDef {
    abbrev: "dns.flags.checkdisable",
    name: "Non-authenticated data",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x10),
    blurb: "Is non-authenticated data acceptable?",
    generated: false,
};

/// `dns.flags.rcode`.
pub static DNS_FLAGS_RCODE: FieldDef = FieldDef {
    abbrev: "dns.flags.rcode",
    name: "Reply code",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: Some(0xf),
    blurb: "",
    generated: false,
};

/// `dns.count.queries`.
pub static DNS_COUNT_QUERIES: FieldDef = FieldDef {
    abbrev: "dns.count.queries",
    name: "Questions",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of queries in packet",
    generated: false,
};

/// `dns.count.answers`.
pub static DNS_COUNT_ANSWERS: FieldDef = FieldDef {
    abbrev: "dns.count.answers",
    name: "Answer RRs",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of answers in packet",
    generated: false,
};

/// `dns.count.auth_rr`.
pub static DNS_COUNT_AUTH_RR: FieldDef = FieldDef {
    abbrev: "dns.count.auth_rr",
    name: "Authority RRs",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of authoritative records in packet",
    generated: false,
};

/// `dns.count.add_rr`.
pub static DNS_COUNT_ADD_RR: FieldDef = FieldDef {
    abbrev: "dns.count.add_rr",
    name: "Additional RRs",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of additional records in packet",
    generated: false,
};

/// `dns.count.zones`.
pub static DNS_COUNT_ZONES: FieldDef = FieldDef {
    abbrev: "dns.count.zones",
    name: "Zones",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of zones in packet",
    generated: false,
};

/// `dns.count.prerequisites`.
pub static DNS_COUNT_PREREQUISITES: FieldDef = FieldDef {
    abbrev: "dns.count.prerequisites",
    name: "Prerequisites",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of prerequisites in packet",
    generated: false,
};

/// `dns.count.updates`.
pub static DNS_COUNT_UPDATES: FieldDef = FieldDef {
    abbrev: "dns.count.updates",
    name: "Updates",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of updates records in packet",
    generated: false,
};

/// `dns.qry.name`.
pub static DNS_QRY_NAME: FieldDef = FieldDef {
    abbrev: "dns.qry.name",
    name: "Name",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Query Name",
    generated: false,
};

/// `dns.qry.name.len`.
pub static DNS_QRY_NAME_LEN: FieldDef = FieldDef {
    abbrev: "dns.qry.name.len",
    name: "Name Length",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Query Name Len",
    generated: false,
};

/// `dns.count.labels`.
pub static DNS_COUNT_LABELS: FieldDef = FieldDef {
    abbrev: "dns.count.labels",
    name: "Label Count",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Query Label Count",
    generated: false,
};

/// `dns.qry.type`.
pub static DNS_QRY_TYPE: FieldDef = FieldDef {
    abbrev: "dns.qry.type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Query Type",
    generated: false,
};

/// `dns.qry.class`.
pub static DNS_QRY_CLASS: FieldDef = FieldDef {
    abbrev: "dns.qry.class",
    name: "Class",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: None,
    blurb: "Query Class",
    generated: false,
};

/// `dns.qry.qu`.
pub static DNS_QRY_QU: FieldDef = FieldDef {
    abbrev: "dns.qry.qu",
    name: "\"QU\" question",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "QU flag",
    generated: false,
};

/// `dns.resp.name`.
pub static DNS_RESP_NAME: FieldDef = FieldDef {
    abbrev: "dns.resp.name",
    name: "Name",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Response Name",
    generated: false,
};

/// `dns.resp.type`.
pub static DNS_RESP_TYPE: FieldDef = FieldDef {
    abbrev: "dns.resp.type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Response Type",
    generated: false,
};

/// `dns.resp.class`.
pub static DNS_RESP_CLASS: FieldDef = FieldDef {
    abbrev: "dns.resp.class",
    name: "Class",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: None,
    blurb: "Response Class",
    generated: false,
};

/// `dns.resp.cache_flush`.
pub static DNS_RESP_CACHE_FLUSH: FieldDef = FieldDef {
    abbrev: "dns.resp.cache_flush",
    name: "Cache flush",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "Cache flush flag",
    generated: false,
};

/// `dns.resp.ttl`.
pub static DNS_RESP_TTL: FieldDef = FieldDef {
    abbrev: "dns.resp.ttl",
    name: "Time to live",
    field_type: FieldType::Uint32,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Response TTL",
    generated: false,
};

/// `dns.resp.len`.
pub static DNS_RESP_LEN: FieldDef = FieldDef {
    abbrev: "dns.resp.len",
    name: "Data length",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Response Length",
    generated: false,
};

/// `dns.rr.udp_payload_size` for a plain DNS OPT record.
pub static DNS_RR_UDP_PAYLOAD_SIZE: FieldDef = FieldDef {
    abbrev: "dns.rr.udp_payload_size",
    name: "UDP payload size",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.rr.udp_payload_size` for an mDNS OPT record, where the class also
/// carries the cache-flush bit.
pub static DNS_RR_UDP_PAYLOAD_SIZE_MDNS: FieldDef = FieldDef {
    abbrev: "dns.rr.udp_payload_size",
    name: "UDP payload size",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: Some(0x7fff),
    blurb: "",
    generated: false,
};

/// `dns.resp.ext_rcode`.
pub static DNS_RESP_EXT_RCODE: FieldDef = FieldDef {
    abbrev: "dns.resp.ext_rcode",
    name: "Higher bits in extended RCODE",
    field_type: FieldType::Uint8,
    parent: "dns",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.resp.edns0_version`.
pub static DNS_RESP_EDNS0_VERSION: FieldDef = FieldDef {
    abbrev: "dns.resp.edns0_version",
    name: "EDNS0 version",
    field_type: FieldType::Uint8,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.resp.z`.
pub static DNS_RESP_Z: FieldDef = FieldDef {
    abbrev: "dns.resp.z",
    name: "Z",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.resp.z.do`.
pub static DNS_RESP_Z_DO: FieldDef = FieldDef {
    abbrev: "dns.resp.z.do",
    name: "DO bit",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "DNSSEC OK",
    generated: false,
};

/// `dns.resp.z.reserved`.
pub static DNS_RESP_Z_RESERVED: FieldDef = FieldDef {
    abbrev: "dns.resp.z.reserved",
    name: "Reserved",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Hex,
    bitmask: Some(0x7fff),
    blurb: "",
    generated: false,
};

/// `dns.a`.
pub static DNS_A: FieldDef = FieldDef {
    abbrev: "dns.a",
    name: "Address",
    field_type: FieldType::Ipv4,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Response IPv4 Address",
    generated: false,
};

/// `dns.aaaa`.
pub static DNS_AAAA: FieldDef = FieldDef {
    abbrev: "dns.aaaa",
    name: "AAAA Address",
    field_type: FieldType::Ipv6,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "AAAA Response Address",
    generated: false,
};

/// `dns.cname`.
pub static DNS_CNAME: FieldDef = FieldDef {
    abbrev: "dns.cname",
    name: "CNAME",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Response Primary Name",
    generated: false,
};

/// `dns.ns`.
pub static DNS_NS: FieldDef = FieldDef {
    abbrev: "dns.ns",
    name: "Name Server",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.ptr.domain_name`.
pub static DNS_PTR_DOMAIN_NAME: FieldDef = FieldDef {
    abbrev: "dns.ptr.domain_name",
    name: "Domain Name",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.mx.preference`.
pub static DNS_MX_PREFERENCE: FieldDef = FieldDef {
    abbrev: "dns.mx.preference",
    name: "Preference",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.mx.mail_exchange`.
pub static DNS_MX_MAIL_EXCHANGE: FieldDef = FieldDef {
    abbrev: "dns.mx.mail_exchange",
    name: "Mail Exchange",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.mname`.
pub static DNS_SOA_MNAME: FieldDef = FieldDef {
    abbrev: "dns.soa.mname",
    name: "Primary name server",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.rname`.
pub static DNS_SOA_RNAME: FieldDef = FieldDef {
    abbrev: "dns.soa.rname",
    name: "Responsible authority's mailbox",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.rname.name`.
pub static DNS_SOA_RNAME_NAME: FieldDef = FieldDef {
    abbrev: "dns.soa.rname.name",
    name: "Responsible authority's mailbox name",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.serial_number`.
pub static DNS_SOA_SERIAL_NUMBER: FieldDef = FieldDef {
    abbrev: "dns.soa.serial_number",
    name: "Serial Number",
    field_type: FieldType::Uint32,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.refresh_interval`.
pub static DNS_SOA_REFRESH_INTERVAL: FieldDef = FieldDef {
    abbrev: "dns.soa.refresh_interval",
    name: "Refresh Interval",
    field_type: FieldType::Uint32,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.retry_interval`.
pub static DNS_SOA_RETRY_INTERVAL: FieldDef = FieldDef {
    abbrev: "dns.soa.retry_interval",
    name: "Retry Interval",
    field_type: FieldType::Uint32,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.expire_limit`.
pub static DNS_SOA_EXPIRE_LIMIT: FieldDef = FieldDef {
    abbrev: "dns.soa.expire_limit",
    name: "Expire limit",
    field_type: FieldType::Uint32,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.soa.minimum_ttl`.
pub static DNS_SOA_MINIMUM_TTL: FieldDef = FieldDef {
    abbrev: "dns.soa.minimum_ttl",
    name: "Minimum TTL",
    field_type: FieldType::Uint32,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.txt.length`.
pub static DNS_TXT_LENGTH: FieldDef = FieldDef {
    abbrev: "dns.txt.length",
    name: "TXT Length",
    field_type: FieldType::Uint8,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.txt`.
pub static DNS_TXT: FieldDef = FieldDef {
    abbrev: "dns.txt",
    name: "TXT",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.srv.instance`.
pub static DNS_SRV_INSTANCE: FieldDef = FieldDef {
    abbrev: "dns.srv.instance",
    name: "Instance",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Desired service instance",
    generated: false,
};

/// `dns.srv.service`.
pub static DNS_SRV_SERVICE: FieldDef = FieldDef {
    abbrev: "dns.srv.service",
    name: "Service",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Desired service",
    generated: false,
};

/// `dns.srv.proto`.
pub static DNS_SRV_PROTO: FieldDef = FieldDef {
    abbrev: "dns.srv.proto",
    name: "Protocol",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Desired protocol",
    generated: false,
};

/// `dns.srv.name`.
pub static DNS_SRV_NAME: FieldDef = FieldDef {
    abbrev: "dns.srv.name",
    name: "Name",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "Domain this resource record refers to",
    generated: false,
};

/// `dns.srv.priority`.
pub static DNS_SRV_PRIORITY: FieldDef = FieldDef {
    abbrev: "dns.srv.priority",
    name: "Priority",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.srv.weight`.
pub static DNS_SRV_WEIGHT: FieldDef = FieldDef {
    abbrev: "dns.srv.weight",
    name: "Weight",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.srv.port`.
pub static DNS_SRV_PORT: FieldDef = FieldDef {
    abbrev: "dns.srv.port",
    name: "Port",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.srv.target`.
pub static DNS_SRV_TARGET: FieldDef = FieldDef {
    abbrev: "dns.srv.target",
    name: "Target",
    field_type: FieldType::String,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.opt`.
pub static DNS_OPT: FieldDef = FieldDef {
    abbrev: "dns.opt",
    name: "Option",
    field_type: FieldType::None,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.opt.code`.
pub static DNS_OPT_CODE: FieldDef = FieldDef {
    abbrev: "dns.opt.code",
    name: "Option Code",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.opt.len`.
pub static DNS_OPT_LEN: FieldDef = FieldDef {
    abbrev: "dns.opt.len",
    name: "Option Length",
    field_type: FieldType::Uint16,
    parent: "dns",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.opt.data`.
pub static DNS_OPT_DATA: FieldDef = FieldDef {
    abbrev: "dns.opt.data",
    name: "Option Data",
    field_type: FieldType::Bytes,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.opt.padding`.
pub static DNS_OPT_PADDING: FieldDef = FieldDef {
    abbrev: "dns.opt.padding",
    name: "Padding",
    field_type: FieldType::Bytes,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "The PADDING octets SHOULD be set to 0x00",
    generated: false,
};

/// `dns.response_in`.
pub static DNS_RESPONSE_IN: FieldDef = FieldDef {
    abbrev: "dns.response_in",
    name: "Response In",
    field_type: FieldType::FrameNumber,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "The response to this DNS query is in this frame",
    generated: true,
};

/// `dns.response_to`.
pub static DNS_RESPONSE_TO: FieldDef = FieldDef {
    abbrev: "dns.response_to",
    name: "Request In",
    field_type: FieldType::FrameNumber,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "This is a response to the DNS query in this frame",
    generated: true,
};

/// `dns.retransmission`.
pub static DNS_RETRANSMISSION: FieldDef = FieldDef {
    abbrev: "dns.retransmission",
    name: "Retransmission",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "This is a retransmission",
    generated: true,
};

/// `dns.retransmit_request_in`.
pub static DNS_RETRANSMIT_REQUEST_IN: FieldDef = FieldDef {
    abbrev: "dns.retransmit_request_in",
    name: "Retransmitted request. Original request in",
    field_type: FieldType::FrameNumber,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "This is a retransmitted DNS query",
    generated: true,
};

/// `dns.retransmit_response_in`.
pub static DNS_RETRANSMIT_RESPONSE_IN: FieldDef = FieldDef {
    abbrev: "dns.retransmit_response_in",
    name: "Retransmitted response. Original response in",
    field_type: FieldType::FrameNumber,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "This is a retransmitted DNS response",
    generated: true,
};

/// `dns.time`.
pub static DNS_TIME: FieldDef = FieldDef {
    abbrev: "dns.time",
    name: "Time",
    field_type: FieldType::RelativeTime,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "The time between the Query and the Response",
    generated: true,
};

/// `dns.data`.
pub static DNS_DATA: FieldDef = FieldDef {
    abbrev: "dns.data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dns.retransmit_request`.
///
/// The expert label for a retransmitted query; it carries no value and
/// appears only inside the expert block.
pub static DNS_RETRANSMIT_REQUEST: FieldDef = FieldDef {
    abbrev: "dns.retransmit_request",
    name: "DNS query retransmission",
    field_type: FieldType::None,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `dns.retransmit_response`.
///
/// The expert label for a retransmitted response; see
/// [`DNS_RETRANSMIT_REQUEST`].
pub static DNS_RETRANSMIT_RESPONSE: FieldDef = FieldDef {
    abbrev: "dns.retransmit_response",
    name: "DNS response retransmission",
    field_type: FieldType::None,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `dns.response_missing`.
///
/// The expert label for a query that two-pass analysis leaves
/// unanswered; it carries no value and appears only inside the expert block.
pub static DNS_RESPONSE_MISSING: FieldDef = FieldDef {
    abbrev: "dns.response_missing",
    name: "DNS response missing",
    field_type: FieldType::None,
    parent: "dns",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `dns.unsolicited`.
pub static DNS_UNSOLICITED: FieldDef = FieldDef {
    abbrev: "dns.unsolicited",
    name: "Unsolicited",
    field_type: FieldType::Boolean,
    parent: "dns",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "This is an unsolicited response",
    generated: true,
};

static DNS_FIELDS: &[&FieldDef] = &[
    &DNS_LENGTH,
    &DNS_ID,
    &DNS_FLAGS,
    &DNS_FLAGS_RESPONSE,
    &DNS_FLAGS_OPCODE,
    &DNS_FLAGS_AUTHORITATIVE,
    &DNS_FLAGS_CONFLICT,
    &DNS_FLAGS_TRUNCATED,
    &DNS_FLAGS_RECDESIRED,
    &DNS_FLAGS_RECAVAIL,
    &DNS_FLAGS_Z,
    &DNS_FLAGS_AUTHENTICATED,
    &DNS_FLAGS_CHECKDISABLE,
    &DNS_FLAGS_RCODE,
    &DNS_COUNT_QUERIES,
    &DNS_COUNT_ZONES,
    &DNS_COUNT_ANSWERS,
    &DNS_COUNT_PREREQUISITES,
    &DNS_COUNT_AUTH_RR,
    &DNS_COUNT_UPDATES,
    &DNS_COUNT_ADD_RR,
    &DNS_QRY_NAME,
    &DNS_QRY_NAME_LEN,
    &DNS_COUNT_LABELS,
    &DNS_QRY_TYPE,
    &DNS_QRY_CLASS,
    &DNS_QRY_QU,
    &DNS_RESP_NAME,
    &DNS_RESP_TYPE,
    &DNS_RESP_CLASS,
    &DNS_RESP_CACHE_FLUSH,
    &DNS_RESP_TTL,
    &DNS_RESP_LEN,
    &DNS_RR_UDP_PAYLOAD_SIZE,
    &DNS_RR_UDP_PAYLOAD_SIZE_MDNS,
    &DNS_RESP_EXT_RCODE,
    &DNS_RESP_EDNS0_VERSION,
    &DNS_RESP_Z,
    &DNS_RESP_Z_DO,
    &DNS_RESP_Z_RESERVED,
    &DNS_A,
    &DNS_AAAA,
    &DNS_CNAME,
    &DNS_NS,
    &DNS_PTR_DOMAIN_NAME,
    &DNS_MX_PREFERENCE,
    &DNS_MX_MAIL_EXCHANGE,
    &DNS_SOA_MNAME,
    &DNS_SOA_RNAME,
    &DNS_SOA_RNAME_NAME,
    &DNS_SOA_SERIAL_NUMBER,
    &DNS_SOA_REFRESH_INTERVAL,
    &DNS_SOA_RETRY_INTERVAL,
    &DNS_SOA_EXPIRE_LIMIT,
    &DNS_SOA_MINIMUM_TTL,
    &DNS_TXT_LENGTH,
    &DNS_TXT,
    &DNS_SRV_INSTANCE,
    &DNS_SRV_SERVICE,
    &DNS_SRV_PROTO,
    &DNS_SRV_NAME,
    &DNS_SRV_PRIORITY,
    &DNS_SRV_WEIGHT,
    &DNS_SRV_PORT,
    &DNS_SRV_TARGET,
    &DNS_OPT,
    &DNS_OPT_CODE,
    &DNS_OPT_LEN,
    &DNS_OPT_DATA,
    &DNS_OPT_PADDING,
    &DNS_RESPONSE_IN,
    &DNS_RESPONSE_TO,
    &DNS_RETRANSMISSION,
    &DNS_RETRANSMIT_REQUEST_IN,
    &DNS_RETRANSMIT_RESPONSE_IN,
    &DNS_TIME,
    &DNS_UNSOLICITED,
    &DNS_DATA,
    &DNS_RETRANSMIT_REQUEST,
    &DNS_RETRANSMIT_RESPONSE,
    &DNS_RESPONSE_MISSING,
];

/// Domain Name System.
pub static DNS_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "dns",
    long_name: "Domain Name System",
    short_name: "DNS",
    fields: DNS_FIELDS,
};

/// Multicast DNS.
pub static MDNS_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "mdns",
    long_name: "Multicast Domain Name System",
    short_name: "mDNS",
    fields: &[],
};

/// Link-Local Multicast Name Resolution.
pub static LLMNR_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "llmnr",
    long_name: "Link-local Multicast Name Resolution",
    short_name: "LLMNR",
    fields: &[],
};

// ---------------------------------------------------------------- DHCP
/// `dhcp.bootp`.
pub static DHCP_BOOTP: FieldDef = FieldDef {
    abbrev: "dhcp.bootp",
    name: "Frame is BOOTP",
    field_type: FieldType::Boolean,
    parent: "dhcp",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.type`.
pub static DHCP_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.type",
    name: "Message type",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.hw.type`.
pub static DHCP_HW_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.hw.type",
    name: "Hardware type",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.hw.len`.
pub static DHCP_HW_LEN: FieldDef = FieldDef {
    abbrev: "dhcp.hw.len",
    name: "Hardware address length",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.hops`.
pub static DHCP_HOPS: FieldDef = FieldDef {
    abbrev: "dhcp.hops",
    name: "Hops",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.id`.
pub static DHCP_ID: FieldDef = FieldDef {
    abbrev: "dhcp.id",
    name: "Transaction ID",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.secs`.
pub static DHCP_SECS: FieldDef = FieldDef {
    abbrev: "dhcp.secs",
    name: "Seconds elapsed",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.flags`.
pub static DHCP_FLAGS: FieldDef = FieldDef {
    abbrev: "dhcp.flags",
    name: "Bootp flags",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.flags.bc`.
pub static DHCP_FLAGS_BC: FieldDef = FieldDef {
    abbrev: "dhcp.flags.bc",
    name: "Broadcast flag",
    field_type: FieldType::Boolean,
    parent: "dhcp",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `dhcp.flags.reserved`.
pub static DHCP_FLAGS_RESERVED: FieldDef = FieldDef {
    abbrev: "dhcp.flags.reserved",
    name: "Reserved flags",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Hex,
    bitmask: Some(0x7fff),
    blurb: "",
    generated: false,
};

/// `dhcp.ip.client`.
pub static DHCP_IP_CLIENT: FieldDef = FieldDef {
    abbrev: "dhcp.ip.client",
    name: "Client IP address",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.ip.your`.
pub static DHCP_IP_YOUR: FieldDef = FieldDef {
    abbrev: "dhcp.ip.your",
    name: "Your (client) IP address",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.ip.server`.
pub static DHCP_IP_SERVER: FieldDef = FieldDef {
    abbrev: "dhcp.ip.server",
    name: "Next server IP address",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.ip.relay`.
pub static DHCP_IP_RELAY: FieldDef = FieldDef {
    abbrev: "dhcp.ip.relay",
    name: "Relay agent IP address",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.hw.addr`.
pub static DHCP_HW_ADDR: FieldDef = FieldDef {
    abbrev: "dhcp.hw.addr",
    name: "Client hardware address",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.hw.addr_padding`.
pub static DHCP_HW_ADDR_PADDING: FieldDef = FieldDef {
    abbrev: "dhcp.hw.addr_padding",
    name: "Client hardware address padding",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.hw.mac_addr`.
pub static DHCP_HW_MAC_ADDR: FieldDef = FieldDef {
    abbrev: "dhcp.hw.mac_addr",
    name: "Client MAC address",
    field_type: FieldType::Ethernet,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.server`.
pub static DHCP_SERVER: FieldDef = FieldDef {
    abbrev: "dhcp.server",
    name: "Server host name",
    field_type: FieldType::String,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.file`.
pub static DHCP_FILE: FieldDef = FieldDef {
    abbrev: "dhcp.file",
    name: "Boot file name",
    field_type: FieldType::String,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.cookie`.
pub static DHCP_COOKIE: FieldDef = FieldDef {
    abbrev: "dhcp.cookie",
    name: "Magic cookie",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_hardware_address`.
pub static DHCP_CLIENT_HARDWARE_ADDRESS: FieldDef = FieldDef {
    abbrev: "dhcp.client_hardware_address",
    name: "Client hardware address",
    field_type: FieldType::String,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.iaid`.
pub static DHCP_CLIENT_ID_IAID: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.iaid",
    name: "IAID",
    field_type: FieldType::String,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.duid_type`.
pub static DHCP_CLIENT_ID_DUID_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.duid_type",
    name: "DUID Type",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.duid_llt_hw_type`.
pub static DHCP_CLIENT_ID_DUID_LLT_HW_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.duid_llt_hw_type",
    name: "Hardware type",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Client Identifier DUID LLT Hardware type",
    generated: false,
};

/// `dhcp.client_id.duid_ll_hw_type`.
pub static DHCP_CLIENT_ID_DUID_LL_HW_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.duid_ll_hw_type",
    name: "Hardware type",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Client Identifier DUID LL Hardware type",
    generated: false,
};

/// `dhcp.client_id.time`.
pub static DHCP_CLIENT_ID_TIME: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.time",
    name: "Time",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.link_layer_address`.
pub static DHCP_CLIENT_ID_LINK_LAYER_ADDRESS: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.link_layer_address",
    name: "Link layer address",
    field_type: FieldType::String,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.link_layer_address_ether`.
pub static DHCP_CLIENT_ID_LINK_LAYER_ADDRESS_ETHER: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.link_layer_address_ether",
    name: "Link layer address (Ethernet)",
    field_type: FieldType::Ethernet,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.enterprise_num`.
pub static DHCP_CLIENT_ID_ENTERPRISE_NUM: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.enterprise_num",
    name: "Enterprise-number",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Custom,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id`.
pub static DHCP_CLIENT_ID: FieldDef = FieldDef {
    abbrev: "dhcp.client_id",
    name: "Identifier",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.type`.
pub static DHCP_CLIENT_ID_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_id.undef`.
pub static DHCP_CLIENT_ID_UNDEF: FieldDef = FieldDef {
    abbrev: "dhcp.client_id.undef",
    name: "Client Identifier",
    field_type: FieldType::String,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.type`.
pub static DHCP_OPTION_TYPE: FieldDef = FieldDef {
    abbrev: "dhcp.option.type",
    name: "Option",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "DHCP/BOOTP option type",
    generated: false,
};

/// `dhcp.option.length`.
pub static DHCP_OPTION_LENGTH: FieldDef = FieldDef {
    abbrev: "dhcp.option.length",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "DHCP/BOOTP option length",
    generated: false,
};

/// `dhcp.option.suboption_length`.
pub static DHCP_OPTION_SUBOPTION_LENGTH: FieldDef = FieldDef {
    abbrev: "dhcp.option.suboption_length",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Suboption length",
    generated: false,
};

/// `dhcp.option.value`.
pub static DHCP_OPTION_VALUE: FieldDef = FieldDef {
    abbrev: "dhcp.option.value",
    name: "Value",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "DHCP/BOOTP option value",
    generated: false,
};

/// `dhcp.option.rfc_3396_detected`.
pub static DHCP_OPTION_RFC_3396_DETECTED: FieldDef = FieldDef {
    abbrev: "dhcp.option.rfc_3396_detected",
    name: "Encoding Long Options detected (RFC 3396)",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.padding`.
pub static DHCP_OPTION_PADDING: FieldDef = FieldDef {
    abbrev: "dhcp.option.padding",
    name: "Padding",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 0: Padding",
    generated: false,
};

/// `dhcp.option.subnet_mask`.
pub static DHCP_OPTION_SUBNET_MASK: FieldDef = FieldDef {
    abbrev: "dhcp.option.subnet_mask",
    name: "Subnet Mask",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 1: Subnet Mask",
    generated: false,
};

/// `dhcp.option.router`.
pub static DHCP_OPTION_ROUTER: FieldDef = FieldDef {
    abbrev: "dhcp.option.router",
    name: "Router",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 3: Router",
    generated: false,
};

/// `dhcp.option.domain_name_server`.
pub static DHCP_OPTION_DOMAIN_NAME_SERVER: FieldDef = FieldDef {
    abbrev: "dhcp.option.domain_name_server",
    name: "Domain Name Server",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 6: Domain Name Server",
    generated: false,
};

/// `dhcp.option.hostname`.
pub static DHCP_OPTION_HOSTNAME: FieldDef = FieldDef {
    abbrev: "dhcp.option.hostname",
    name: "Host Name",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 12: Host Name",
    generated: false,
};

/// `dhcp.option.domain_name`.
pub static DHCP_OPTION_DOMAIN_NAME: FieldDef = FieldDef {
    abbrev: "dhcp.option.domain_name",
    name: "Domain Name",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 15: Domain Name",
    generated: false,
};

/// `dhcp.option.broadcast_address`.
pub static DHCP_OPTION_BROADCAST_ADDRESS: FieldDef = FieldDef {
    abbrev: "dhcp.option.broadcast_address",
    name: "Broadcast Address",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 28: Broadcast Address",
    generated: false,
};

/// `dhcp.option.requested_ip_address`.
pub static DHCP_OPTION_REQUESTED_IP_ADDRESS: FieldDef = FieldDef {
    abbrev: "dhcp.option.requested_ip_address",
    name: "Requested IP Address",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 50: Requested IP Address",
    generated: false,
};

/// `dhcp.option.ip_address_lease_time`.
pub static DHCP_OPTION_IP_ADDRESS_LEASE_TIME: FieldDef = FieldDef {
    abbrev: "dhcp.option.ip_address_lease_time",
    name: "IP Address Lease Time",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Custom,
    bitmask: None,
    blurb: "Option 51: IP Address Lease Time",
    generated: false,
};

/// `dhcp.option.option_overload`.
pub static DHCP_OPTION_OPTION_OVERLOAD: FieldDef = FieldDef {
    abbrev: "dhcp.option.option_overload",
    name: "Option Overload",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 52: Option Overload",
    generated: false,
};

/// `dhcp.option.dhcp`.
pub static DHCP_OPTION_DHCP: FieldDef = FieldDef {
    abbrev: "dhcp.option.dhcp",
    name: "DHCP",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 53: DHCP option",
    generated: false,
};

/// `dhcp.option.dhcp_server_id`.
pub static DHCP_OPTION_DHCP_SERVER_ID: FieldDef = FieldDef {
    abbrev: "dhcp.option.dhcp_server_id",
    name: "DHCP Server Identifier",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 54: DHCP Server Identifier",
    generated: false,
};

/// `dhcp.option.request_list_item`.
pub static DHCP_OPTION_REQUEST_LIST_ITEM: FieldDef = FieldDef {
    abbrev: "dhcp.option.request_list_item",
    name: "Parameter Request List Item",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 55: Parameter Request List Item",
    generated: false,
};

/// `dhcp.option.message`.
pub static DHCP_OPTION_MESSAGE: FieldDef = FieldDef {
    abbrev: "dhcp.option.message",
    name: "Message",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 56: Option message",
    generated: false,
};

/// `dhcp.option.dhcp_max_message_size`.
pub static DHCP_OPTION_DHCP_MAX_MESSAGE_SIZE: FieldDef = FieldDef {
    abbrev: "dhcp.option.dhcp_max_message_size",
    name: "Maximum DHCP Message Size",
    field_type: FieldType::Uint16,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 57: Maximum DHCP Message Size",
    generated: false,
};

/// `dhcp.option.renewal_time_value`.
pub static DHCP_OPTION_RENEWAL_TIME_VALUE: FieldDef = FieldDef {
    abbrev: "dhcp.option.renewal_time_value",
    name: "Renewal Time Value",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Custom,
    bitmask: None,
    blurb: "Option 58: Renewal Time Value",
    generated: false,
};

/// `dhcp.option.rebinding_time_value`.
pub static DHCP_OPTION_REBINDING_TIME_VALUE: FieldDef = FieldDef {
    abbrev: "dhcp.option.rebinding_time_value",
    name: "Rebinding Time Value",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Custom,
    bitmask: None,
    blurb: "Option 59: Rebinding Time Value",
    generated: false,
};

/// `dhcp.option.vendor_class_id`.
pub static DHCP_OPTION_VENDOR_CLASS_ID: FieldDef = FieldDef {
    abbrev: "dhcp.option.vendor_class_id",
    name: "Vendor class identifier",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 60: Vendor class identifier",
    generated: false,
};

/// `dhcp.option.tftp_server_name`.
pub static DHCP_OPTION_TFTP_SERVER_NAME: FieldDef = FieldDef {
    abbrev: "dhcp.option.tftp_server_name",
    name: "TFTP Server Name",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 66: TFTP Server Name",
    generated: false,
};

/// `dhcp.option.bootfile_name`.
pub static DHCP_OPTION_BOOTFILE_NAME: FieldDef = FieldDef {
    abbrev: "dhcp.option.bootfile_name",
    name: "Bootfile name",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 67: Bootfile name",
    generated: false,
};

/// `dhcp.option.agent_information_option.suboption`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBOPTION: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.suboption",
    name: "Option 82 Suboption",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 82: Suboption",
    generated: false,
};

/// `dhcp.option.agent_information_option.value`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_VALUE: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.value",
    name: "Value",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82: Suboption value",
    generated: false,
};

/// `dhcp.option.agent_information_option.agent_circuit_id`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_AGENT_CIRCUIT_ID: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.agent_circuit_id",
    name: "Agent Circuit ID",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:1 Agent Circuit ID",
    generated: false,
};

/// `dhcp.option.agent_information_option.agent_remote_id`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_AGENT_REMOTE_ID: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.agent_remote_id",
    name: "Agent Remote ID",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:2 Agent Remote ID",
    generated: false,
};

/// `dhcp.option.agent_information_option.reserved`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_RESERVED: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:3 Reserved",
    generated: false,
};

/// `dhcp.option.agent_information_option.docsis_device_class`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_DOCSIS_DEVICE_CLASS: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.docsis_device_class",
    name: "DOCSIS Device Class",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Option 82:4 DOCSIS Device Class",
    generated: false,
};

/// `dhcp.option.agent_information_option.link_selection`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_LINK_SELECTION: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.link_selection",
    name: "Link selection",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:5 Link selection",
    generated: false,
};

/// `dhcp.option.agent_information_option.subscriber_id`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBSCRIBER_ID: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.subscriber_id",
    name: "Subscriber ID",
    field_type: FieldType::StringZ,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:6 Subscriber ID",
    generated: false,
};

/// `dhcp.option.agent_information_option.radius_attributes`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_RADIUS_ATTRIBUTES: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.radius_attributes",
    name: "RADIUS Attributes",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:7 RADIUS Attributes",
    generated: false,
};

/// `dhcp.option.agent_information_option.authentication`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_AUTHENTICATION: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.authentication",
    name: "Authentication",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:8 Authentication",
    generated: false,
};

/// `dhcp.option.agent_information_option.vi`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_VI: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.vi",
    name: "Vendor-Specific Information",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:9 Vendor-Specific Information",
    generated: false,
};

/// `dhcp.option.agent_information_option.vi.enterprise`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_VI_ENTERPRISE: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.vi.enterprise",
    name: "Enterprise",
    field_type: FieldType::Uint32,
    parent: "dhcp",
    display: Display::Custom,
    bitmask: None,
    blurb: "Option 82:9 VI Enterprise",
    generated: false,
};

/// `dhcp.option.agent_information_option.vi.data_length`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_VI_DATA_LENGTH: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.vi.data_length",
    name: "Data Length",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 82:9 VI Data Length",
    generated: false,
};

/// `dhcp.option.agent_information_option.flags`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_FLAGS: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Option 82:10 Flags",
    generated: false,
};

/// `dhcp.option.agent_information_option.server_id_override`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_SERVER_ID_OVERRIDE: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.server_id_override",
    name: "Server ID Override",
    field_type: FieldType::Ipv4,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:11 Server ID Override",
    generated: false,
};

/// `dhcp.option.agent_information_option.relay_agent_id`.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_RELAY_AGENT_ID: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.relay_agent_id",
    name: "Relay Agent Identifier",
    field_type: FieldType::Bytes,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "Option 82:12 Relay Agent Identifier",
    generated: false,
};

/// `dhcp.option.agent_information_option.ani_att`.
///
/// RFC 7839 §5 defines the access-technology type as the whole suboption
/// value; the width is 1–4 octets on the wire, so the occurrence range can be
/// longer than the one-octet registry type.
pub static DHCP_OPTION_AGENT_INFORMATION_OPTION_ANI_ATT: FieldDef = FieldDef {
    abbrev: "dhcp.option.agent_information_option.ani_att",
    name: "Access Technology Type",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 82:13 Access Technology Type",
    generated: false,
};

/// `_ws.type_length.mismatch`: the zero-length marker used when a suboption
/// value is too short for the integer it carries.
///
/// The generic type-length helper registers two generated entries,
/// `_ws.type_length.mismatch` (error) and `_ws.type_length.mismatch_warn`
/// (warning). Packetfin models them as tree markers so the expert block and
/// its offending field keep their registry names; they are not part of any
/// protocol's `-G fields` report.
pub(crate) static TYPE_LENGTH_MISMATCH: FieldDef = FieldDef {
    abbrev: "_ws.type_length.mismatch",
    name: "Trying to fetch X with length Y",
    field_type: FieldType::None,
    parent: "_ws.type_length",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `_ws.type_length.mismatch_warn`: the warning variant of
/// [`TYPE_LENGTH_MISMATCH`], used when a longer value is still displayed.
pub(crate) static TYPE_LENGTH_MISMATCH_WARN: FieldDef = FieldDef {
    abbrev: "_ws.type_length.mismatch_warn",
    name: "Trying to fetch X with length Y",
    field_type: FieldType::None,
    parent: "_ws.type_length",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `_ws.string.trailing_stray_characters`: the zero-length marker named by a
/// terminated-string expert.
///
/// A NUL-terminated option string that keeps octets after the terminator
/// reports the trailing data through this generated field instead of the
/// string field itself.
pub(crate) static TRAILING_STRAY_CHARACTERS: FieldDef = FieldDef {
    abbrev: "_ws.string.trailing_stray_characters",
    name: "Trailing stray characters",
    field_type: FieldType::None,
    parent: "_ws.string",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.end`.
pub static DHCP_OPTION_END: FieldDef = FieldDef {
    abbrev: "dhcp.option.end",
    name: "Option End",
    field_type: FieldType::Uint8,
    parent: "dhcp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option 255: End",
    generated: false,
};

/// `dhcp.missing_subopt_value`.
pub static DHCP_MISSING_SUBOPT_VALUE: FieldDef = FieldDef {
    abbrev: "dhcp.missing_subopt_value",
    name: "no room left in option for suboption value",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.missing_subopt_length`.
pub static DHCP_MISSING_SUBOPT_LENGTH: FieldDef = FieldDef {
    abbrev: "dhcp.missing_subopt_length",
    name: "no room left in option for suboption length",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.bad_length`.
pub static DHCP_BAD_LENGTH: FieldDef = FieldDef {
    abbrev: "dhcp.bad_length",
    name: "length isn't 0",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.refer_last_option`.
pub static DHCP_OPTION_REFER_LAST_OPTION: FieldDef = FieldDef {
    abbrev: "dhcp.option.refer_last_option",
    name: "For the data, please refer to the last option of this type",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.option_overload.wrong_field`.
pub static DHCP_OPTION_OPTION_OVERLOAD_WRONG_FIELD: FieldDef = FieldDef {
    abbrev: "dhcp.option.option_overload.wrong_field",
    name: "overload option makes no sense in the file or sname field",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.option_overload.file_end_missing`.
pub static DHCP_OPTION_OPTION_OVERLOAD_FILE_END_MISSING: FieldDef = FieldDef {
    abbrev: "dhcp.option.option_overload.file_end_missing",
    name: "file overload end option missing",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.option.option_overload.sname_end_missing`.
pub static DHCP_OPTION_OPTION_OVERLOAD_SNAME_END_MISSING: FieldDef = FieldDef {
    abbrev: "dhcp.option.option_overload.sname_end_missing",
    name: "sname overload end option missing",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.secs_le`.
pub static DHCP_SECS_LE: FieldDef = FieldDef {
    abbrev: "dhcp.secs_le",
    name: "Seconds elapsed appears to be encoded as little-endian",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.end_option_missing`.
pub static DHCP_END_OPTION_MISSING: FieldDef = FieldDef {
    abbrev: "dhcp.end_option_missing",
    name: "End option missing",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.client_address_not_given`.
pub static DHCP_CLIENT_ADDRESS_NOT_GIVEN: FieldDef = FieldDef {
    abbrev: "dhcp.client_address_not_given",
    name: "Client address not given",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.server_name_overloaded_by_dhcp`.
pub static DHCP_SERVER_NAME_OVERLOADED_BY_DHCP: FieldDef = FieldDef {
    abbrev: "dhcp.server_name_overloaded_by_dhcp",
    name: "Server name option overloaded by DHCP",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcp.boot_filename_overloaded_by_dhcp`.
pub static DHCP_BOOT_FILENAME_OVERLOADED_BY_DHCP: FieldDef = FieldDef {
    abbrev: "dhcp.boot_filename_overloaded_by_dhcp",
    name: "Boot file name option overloaded by DHCP",
    field_type: FieldType::None,
    parent: "dhcp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static DHCP_FIELDS: &[&FieldDef] = &[
    &DHCP_BOOTP,
    &DHCP_TYPE,
    &DHCP_HW_TYPE,
    &DHCP_HW_LEN,
    &DHCP_HOPS,
    &DHCP_ID,
    &DHCP_SECS,
    &DHCP_FLAGS,
    &DHCP_FLAGS_BC,
    &DHCP_FLAGS_RESERVED,
    &DHCP_IP_CLIENT,
    &DHCP_IP_YOUR,
    &DHCP_IP_SERVER,
    &DHCP_IP_RELAY,
    &DHCP_HW_ADDR,
    &DHCP_HW_ADDR_PADDING,
    &DHCP_HW_MAC_ADDR,
    &DHCP_SERVER,
    &DHCP_FILE,
    &DHCP_COOKIE,
    &DHCP_CLIENT_HARDWARE_ADDRESS,
    &DHCP_CLIENT_ID_IAID,
    &DHCP_CLIENT_ID_DUID_TYPE,
    &DHCP_CLIENT_ID_DUID_LLT_HW_TYPE,
    &DHCP_CLIENT_ID_DUID_LL_HW_TYPE,
    &DHCP_CLIENT_ID_TIME,
    &DHCP_CLIENT_ID_LINK_LAYER_ADDRESS,
    &DHCP_CLIENT_ID_LINK_LAYER_ADDRESS_ETHER,
    &DHCP_CLIENT_ID_ENTERPRISE_NUM,
    &DHCP_CLIENT_ID,
    &DHCP_CLIENT_ID_TYPE,
    &DHCP_CLIENT_ID_UNDEF,
    &DHCP_OPTION_TYPE,
    &DHCP_OPTION_LENGTH,
    &DHCP_OPTION_SUBOPTION_LENGTH,
    &DHCP_OPTION_VALUE,
    &DHCP_OPTION_PADDING,
    &DHCP_OPTION_RFC_3396_DETECTED,
    &DHCP_OPTION_SUBNET_MASK,
    &DHCP_OPTION_ROUTER,
    &DHCP_OPTION_DOMAIN_NAME_SERVER,
    &DHCP_OPTION_HOSTNAME,
    &DHCP_OPTION_DOMAIN_NAME,
    &DHCP_OPTION_BROADCAST_ADDRESS,
    &DHCP_OPTION_REQUESTED_IP_ADDRESS,
    &DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
    &DHCP_OPTION_OPTION_OVERLOAD,
    &DHCP_OPTION_DHCP,
    &DHCP_OPTION_DHCP_SERVER_ID,
    &DHCP_OPTION_REQUEST_LIST_ITEM,
    &DHCP_OPTION_MESSAGE,
    &DHCP_OPTION_DHCP_MAX_MESSAGE_SIZE,
    &DHCP_OPTION_RENEWAL_TIME_VALUE,
    &DHCP_OPTION_REBINDING_TIME_VALUE,
    &DHCP_OPTION_VENDOR_CLASS_ID,
    &DHCP_OPTION_TFTP_SERVER_NAME,
    &DHCP_OPTION_BOOTFILE_NAME,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBOPTION,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_VALUE,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_AGENT_CIRCUIT_ID,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_AGENT_REMOTE_ID,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_RESERVED,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_DOCSIS_DEVICE_CLASS,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_LINK_SELECTION,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_SUBSCRIBER_ID,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_RADIUS_ATTRIBUTES,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_AUTHENTICATION,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_VI,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_VI_ENTERPRISE,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_VI_DATA_LENGTH,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_FLAGS,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_SERVER_ID_OVERRIDE,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_RELAY_AGENT_ID,
    &DHCP_OPTION_AGENT_INFORMATION_OPTION_ANI_ATT,
    &DHCP_OPTION_END,
    &DHCP_BAD_LENGTH,
    &DHCP_MISSING_SUBOPT_VALUE,
    &DHCP_MISSING_SUBOPT_LENGTH,
    &DHCP_OPTION_REFER_LAST_OPTION,
    &DHCP_OPTION_OPTION_OVERLOAD_WRONG_FIELD,
    &DHCP_OPTION_OPTION_OVERLOAD_FILE_END_MISSING,
    &DHCP_OPTION_OPTION_OVERLOAD_SNAME_END_MISSING,
    &DHCP_SECS_LE,
    &DHCP_END_OPTION_MISSING,
    &DHCP_CLIENT_ADDRESS_NOT_GIVEN,
    &DHCP_SERVER_NAME_OVERLOADED_BY_DHCP,
    &DHCP_BOOT_FILENAME_OVERLOADED_BY_DHCP,
];

/// Dynamic Host Configuration Protocol (BOOTP compatible).
pub static DHCP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "dhcp",
    long_name: "Dynamic Host Configuration Protocol",
    short_name: "DHCP/BOOTP",
    fields: DHCP_FIELDS,
};

// -------------------------------------------------------------- DHCPv6
/// `dhcpv6.msgtype`.
pub static DHCPV6_MSGTYPE: FieldDef = FieldDef {
    abbrev: "dhcpv6.msgtype",
    name: "Message type",
    field_type: FieldType::Uint8,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.hopcount`.
pub static DHCPV6_HOPCOUNT: FieldDef = FieldDef {
    abbrev: "dhcpv6.hopcount",
    name: "Hopcount",
    field_type: FieldType::Uint8,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.xid`.
pub static DHCPV6_XID: FieldDef = FieldDef {
    abbrev: "dhcpv6.xid",
    name: "Transaction ID",
    field_type: FieldType::Uint24,
    parent: "dhcpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.linkaddr`.
pub static DHCPV6_LINKADDR: FieldDef = FieldDef {
    abbrev: "dhcpv6.linkaddr",
    name: "Link address",
    field_type: FieldType::Ipv6,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.peeraddr`.
pub static DHCPV6_PEERADDR: FieldDef = FieldDef {
    abbrev: "dhcpv6.peeraddr",
    name: "Peer address",
    field_type: FieldType::Ipv6,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.option.type`.
pub static DHCPV6_OPTION_TYPE: FieldDef = FieldDef {
    abbrev: "dhcpv6.option.type",
    name: "Option",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.option.length`.
pub static DHCPV6_OPTION_LENGTH: FieldDef = FieldDef {
    abbrev: "dhcpv6.option.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.option.type_str`.
pub static DHCPV6_OPTION_TYPE_STR: FieldDef = FieldDef {
    abbrev: "dhcpv6.option.type_str",
    name: "Option",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.option.data`.
pub static DHCPV6_OPTION_DATA: FieldDef = FieldDef {
    abbrev: "dhcpv6.option.data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duid.bytes`.
pub static DHCPV6_DUID_BYTES: FieldDef = FieldDef {
    abbrev: "dhcpv6.duid.bytes",
    name: "DUID",
    field_type: FieldType::Bytes,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duid.type`.
pub static DHCPV6_DUID_TYPE: FieldDef = FieldDef {
    abbrev: "dhcpv6.duid.type",
    name: "DUID Type",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duidllt.time`.
pub static DHCPV6_DUIDLLT_TIME: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidllt.time",
    name: "DUID Time",
    field_type: FieldType::AbsoluteTime,
    parent: "dhcpv6",
    display: Display::IsoTime,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duidllt.link_layer_addr`.
pub static DHCPV6_DUIDLLT_LINK_LAYER_ADDR: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidllt.link_layer_addr",
    name: "Link-layer address",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duidllt.link_layer_addr_ether`.
pub static DHCPV6_DUIDLLT_LINK_LAYER_ADDR_ETHER: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidllt.link_layer_addr_ether",
    name: "Link-layer address (Ethernet)",
    field_type: FieldType::Ethernet,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duidllt.hwtype`.
pub static DHCPV6_DUIDLLT_HWTYPE: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidllt.hwtype",
    name: "Hardware type",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "DUID LLT Hardware Type",
    generated: false,
};

/// `dhcpv6.duidll.hwtype`.
pub static DHCPV6_DUIDLL_HWTYPE: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidll.hwtype",
    name: "Hardware type",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "DUID LL Hardware Type",
    generated: false,
};

/// `dhcpv6.duiden.enterprise`.
pub static DHCPV6_DUIDEN_ENTERPRISE: FieldDef = FieldDef {
    abbrev: "dhcpv6.duiden.enterprise",
    name: "Enterprise ID",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Custom,
    bitmask: None,
    blurb: "DUID EN Enterprise Number",
    generated: false,
};

/// `dhcpv6.duiden.identifier`.
pub static DHCPV6_DUIDEN_IDENTIFIER: FieldDef = FieldDef {
    abbrev: "dhcpv6.duiden.identifier",
    name: "Identifier",
    field_type: FieldType::Bytes,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duidll.link_layer_addr`.
pub static DHCPV6_DUIDLL_LINK_LAYER_ADDR: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidll.link_layer_addr",
    name: "Link-layer address",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duidll.link_layer_addr_ether`.
pub static DHCPV6_DUIDLL_LINK_LAYER_ADDR_ETHER: FieldDef = FieldDef {
    abbrev: "dhcpv6.duidll.link_layer_addr_ether",
    name: "Link-layer address (Ethernet)",
    field_type: FieldType::Ethernet,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.duiduuid.bytes`.
pub static DHCPV6_DUIDUUID_BYTES: FieldDef = FieldDef {
    abbrev: "dhcpv6.duiduuid.bytes",
    name: "UUID",
    field_type: FieldType::Bytes,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaid`.
pub static DHCPV6_IAID: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaid",
    name: "IAID",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaid.t1`.
pub static DHCPV6_IAID_T1: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaid.t1",
    name: "T1",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaid.t2`.
pub static DHCPV6_IAID_T2: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaid.t2",
    name: "T2",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iata`.
pub static DHCPV6_IATA: FieldDef = FieldDef {
    abbrev: "dhcpv6.iata",
    name: "IATA",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaaddr.ip`.
pub static DHCPV6_IAADDR_IP: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaaddr.ip",
    name: "IPv6 address",
    field_type: FieldType::Ipv6,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaaddr.pref_lifetime`.
pub static DHCPV6_IAADDR_PREF_LIFETIME: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaaddr.pref_lifetime",
    name: "Preferred lifetime",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaaddr.valid_lifetime`.
pub static DHCPV6_IAADDR_VALID_LIFETIME: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaaddr.valid_lifetime",
    name: "Valid lifetime",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.requested_option_code`.
pub static DHCPV6_REQUESTED_OPTION_CODE: FieldDef = FieldDef {
    abbrev: "dhcpv6.requested_option_code",
    name: "Requested Option code",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.option_preference`.
pub static DHCPV6_OPTION_PREFERENCE: FieldDef = FieldDef {
    abbrev: "dhcpv6.option_preference",
    name: "Pref-value",
    field_type: FieldType::Uint8,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.elapsed_time`.
pub static DHCPV6_ELAPSED_TIME: FieldDef = FieldDef {
    abbrev: "dhcpv6.elapsed_time",
    name: "Elapsed time",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.status_code`.
pub static DHCPV6_STATUS_CODE: FieldDef = FieldDef {
    abbrev: "dhcpv6.status_code",
    name: "Status Code",
    field_type: FieldType::Uint16,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.status_msg`.
pub static DHCPV6_STATUS_MSG: FieldDef = FieldDef {
    abbrev: "dhcpv6.status_msg",
    name: "Status Message",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.interface_id`.
pub static DHCPV6_INTERFACE_ID: FieldDef = FieldDef {
    abbrev: "dhcpv6.interface_id",
    name: "Interface-ID",
    field_type: FieldType::Bytes,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.reconf_msg`.
pub static DHCPV6_RECONF_MSG: FieldDef = FieldDef {
    abbrev: "dhcpv6.reconf_msg",
    name: "Reconfigure message type",
    field_type: FieldType::Uint8,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.dns_server`.
pub static DHCPV6_DNS_SERVER: FieldDef = FieldDef {
    abbrev: "dhcpv6.dns_server",
    name: "DNS server address",
    field_type: FieldType::Ipv6,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.search_list_entry`.
pub static DHCPV6_SEARCH_LIST_ENTRY: FieldDef = FieldDef {
    abbrev: "dhcpv6.search_list_entry",
    name: "List entry",
    field_type: FieldType::String,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaprefix.pref_lifetime`.
pub static DHCPV6_IAPREFIX_PREF_LIFETIME: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaprefix.pref_lifetime",
    name: "Preferred lifetime",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaprefix.valid_lifetime`.
pub static DHCPV6_IAPREFIX_VALID_LIFETIME: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaprefix.valid_lifetime",
    name: "Valid lifetime",
    field_type: FieldType::Uint32,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaprefix.pref_len`.
pub static DHCPV6_IAPREFIX_PREF_LEN: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaprefix.pref_len",
    name: "Prefix length",
    field_type: FieldType::Uint8,
    parent: "dhcpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.iaprefix.pref_addr`.
pub static DHCPV6_IAPREFIX_PREF_ADDR: FieldDef = FieldDef {
    abbrev: "dhcpv6.iaprefix.pref_addr",
    name: "Prefix address",
    field_type: FieldType::Ipv6,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.obsoleted_option`.
pub static DHCPV6_OBSOLETED_OPTION: FieldDef = FieldDef {
    abbrev: "dhcpv6.obsoleted_option",
    name: "Obsoleted option",
    field_type: FieldType::None,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `dhcpv6.malformed_option`.
pub static DHCPV6_MALFORMED_OPTION: FieldDef = FieldDef {
    abbrev: "dhcpv6.malformed_option",
    name: "Malformed option",
    field_type: FieldType::None,
    parent: "dhcpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static DHCPV6_FIELDS: &[&FieldDef] = &[
    &DHCPV6_MSGTYPE,
    &DHCPV6_HOPCOUNT,
    &DHCPV6_XID,
    &DHCPV6_LINKADDR,
    &DHCPV6_PEERADDR,
    &DHCPV6_OPTION_TYPE,
    &DHCPV6_OPTION_LENGTH,
    &DHCPV6_OPTION_TYPE_STR,
    &DHCPV6_OPTION_DATA,
    &DHCPV6_DUID_BYTES,
    &DHCPV6_DUID_TYPE,
    &DHCPV6_DUIDLLT_TIME,
    &DHCPV6_DUIDLLT_LINK_LAYER_ADDR,
    &DHCPV6_DUIDLLT_LINK_LAYER_ADDR_ETHER,
    &DHCPV6_DUIDLLT_HWTYPE,
    &DHCPV6_DUIDLL_HWTYPE,
    &DHCPV6_DUIDEN_ENTERPRISE,
    &DHCPV6_DUIDEN_IDENTIFIER,
    &DHCPV6_DUIDLL_LINK_LAYER_ADDR,
    &DHCPV6_DUIDLL_LINK_LAYER_ADDR_ETHER,
    &DHCPV6_DUIDUUID_BYTES,
    &DHCPV6_IAID,
    &DHCPV6_IAID_T1,
    &DHCPV6_IAID_T2,
    &DHCPV6_IATA,
    &DHCPV6_IAADDR_IP,
    &DHCPV6_IAADDR_PREF_LIFETIME,
    &DHCPV6_IAADDR_VALID_LIFETIME,
    &DHCPV6_REQUESTED_OPTION_CODE,
    &DHCPV6_OPTION_PREFERENCE,
    &DHCPV6_ELAPSED_TIME,
    &DHCPV6_STATUS_CODE,
    &DHCPV6_STATUS_MSG,
    &DHCPV6_INTERFACE_ID,
    &DHCPV6_RECONF_MSG,
    &DHCPV6_DNS_SERVER,
    &DHCPV6_SEARCH_LIST_ENTRY,
    &DHCPV6_IAPREFIX_PREF_LIFETIME,
    &DHCPV6_IAPREFIX_VALID_LIFETIME,
    &DHCPV6_IAPREFIX_PREF_LEN,
    &DHCPV6_IAPREFIX_PREF_ADDR,
    &DHCPV6_MALFORMED_OPTION,
    &DHCPV6_OBSOLETED_OPTION,
];

/// Dynamic Host Configuration Protocol for IPv6.
pub static DHCPV6_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "dhcpv6",
    long_name: "DHCPv6",
    short_name: "DHCPv6",
    fields: DHCPV6_FIELDS,
};

// ----------------------------------------------------------------- NTP
/// `ntp.flags`.
pub static NTP_FLAGS: FieldDef = FieldDef {
    abbrev: "ntp.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "ntp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Flags (Leap/Version/Mode)",
    generated: false,
};

/// `ntp.flags.li`.
pub static NTP_FLAGS_LI: FieldDef = FieldDef {
    abbrev: "ntp.flags.li",
    name: "Leap Indicator",
    field_type: FieldType::Uint8,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: Some(0xc0),
    blurb: "Warning of an impending leap second to be inserted or deleted in the last minute of the current month",
    generated: false,
};

/// `ntp.flags.vn`.
pub static NTP_FLAGS_VN: FieldDef = FieldDef {
    abbrev: "ntp.flags.vn",
    name: "Version number",
    field_type: FieldType::Uint8,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: Some(0x38),
    blurb: "",
    generated: false,
};

/// `ntp.flags.mode`.
pub static NTP_FLAGS_MODE: FieldDef = FieldDef {
    abbrev: "ntp.flags.mode",
    name: "Mode",
    field_type: FieldType::Uint8,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: Some(0x7),
    blurb: "",
    generated: false,
};

/// `ntp.stratum`.
pub static NTP_STRATUM: FieldDef = FieldDef {
    abbrev: "ntp.stratum",
    name: "Peer Clock Stratum",
    field_type: FieldType::Uint8,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ntp.ppoll`.
pub static NTP_PPOLL: FieldDef = FieldDef {
    abbrev: "ntp.ppoll",
    name: "Peer Polling Interval",
    field_type: FieldType::Int8,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Maximum interval between successive messages",
    generated: false,
};

/// `ntp.precision`.
pub static NTP_PRECISION: FieldDef = FieldDef {
    abbrev: "ntp.precision",
    name: "Peer Clock Precision",
    field_type: FieldType::Int8,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The precision of the system clock",
    generated: false,
};

/// `ntp.rootdelay`.
pub static NTP_ROOTDELAY: FieldDef = FieldDef {
    abbrev: "ntp.rootdelay",
    name: "Root Delay",
    field_type: FieldType::Uint32,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Total round-trip delay to the reference clock",
    generated: false,
};

/// `ntp.rootdispersion`.
pub static NTP_ROOTDISPERSION: FieldDef = FieldDef {
    abbrev: "ntp.rootdispersion",
    name: "Root Dispersion",
    field_type: FieldType::Uint32,
    parent: "ntp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Total dispersion to the reference clock",
    generated: false,
};

/// `ntp.refid`.
pub static NTP_REFID: FieldDef = FieldDef {
    abbrev: "ntp.refid",
    name: "Reference ID",
    field_type: FieldType::Bytes,
    parent: "ntp",
    display: Display::None,
    bitmask: None,
    blurb: "Particular server or reference clock being used",
    generated: false,
};

/// `ntp.reftime`.
pub static NTP_REFTIME: FieldDef = FieldDef {
    abbrev: "ntp.reftime",
    name: "Reference Timestamp",
    field_type: FieldType::AbsoluteTime,
    parent: "ntp",
    display: Display::IsoTimeZ,
    bitmask: None,
    blurb: "Time when the system clock was last set or corrected",
    generated: false,
};

/// `ntp.org`.
pub static NTP_ORG: FieldDef = FieldDef {
    abbrev: "ntp.org",
    name: "Origin Timestamp",
    field_type: FieldType::AbsoluteTime,
    parent: "ntp",
    display: Display::IsoTimeZ,
    bitmask: None,
    blurb: "Time at the client when the request departed for the server",
    generated: false,
};

/// `ntp.rec`.
pub static NTP_REC: FieldDef = FieldDef {
    abbrev: "ntp.rec",
    name: "Receive Timestamp",
    field_type: FieldType::AbsoluteTime,
    parent: "ntp",
    display: Display::IsoTimeZ,
    bitmask: None,
    blurb: "Time at the server when the request arrived from the client",
    generated: false,
};

/// `ntp.xmt`.
pub static NTP_XMT: FieldDef = FieldDef {
    abbrev: "ntp.xmt",
    name: "Transmit Timestamp",
    field_type: FieldType::AbsoluteTime,
    parent: "ntp",
    display: Display::IsoTimeZ,
    bitmask: None,
    blurb: "Time at the server when the response left for the client",
    generated: false,
};

/// `ntp.keyid`.
pub static NTP_KEYID: FieldDef = FieldDef {
    abbrev: "ntp.keyid",
    name: "Key ID",
    field_type: FieldType::Bytes,
    parent: "ntp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ntp.mac`.
pub static NTP_MAC: FieldDef = FieldDef {
    abbrev: "ntp.mac",
    name: "Message Authentication Code",
    field_type: FieldType::Bytes,
    parent: "ntp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static NTP_FIELDS: &[&FieldDef] = &[
    &NTP_FLAGS,
    &NTP_FLAGS_LI,
    &NTP_FLAGS_VN,
    &NTP_FLAGS_MODE,
    &NTP_STRATUM,
    &NTP_PPOLL,
    &NTP_PRECISION,
    &NTP_ROOTDELAY,
    &NTP_ROOTDISPERSION,
    &NTP_REFID,
    &NTP_REFTIME,
    &NTP_ORG,
    &NTP_REC,
    &NTP_XMT,
    &NTP_KEYID,
    &NTP_MAC,
];

/// Network Time Protocol.
pub static NTP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ntp",
    long_name: "Network Time Protocol",
    short_name: "NTP",
    fields: NTP_FIELDS,
};

/// `icmp.type`.
pub static ICMP_TYPE: FieldDef = FieldDef {
    abbrev: "icmp.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.code`.
pub static ICMP_CODE: FieldDef = FieldDef {
    abbrev: "icmp.code",
    name: "Code",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.checksum`.
pub static ICMP_CHECKSUM: FieldDef = FieldDef {
    abbrev: "icmp.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.checksum.status`.
pub static ICMP_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "icmp.checksum.status",
    name: "Checksum Status",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// The checksum this ICMP message should carry.
///
/// The expected value appears in the bad-checksum text, but ICMP has no
/// registered calculated field; this definition stays out of the protocol's
/// field list and serves the detail renderer only.
pub static ICMP_CHECKSUM_CALCULATED: FieldDef = FieldDef {
    abbrev: "icmp.checksum_calculated",
    name: "Calculated Checksum",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `icmp.unused`.
pub static ICMP_UNUSED: FieldDef = FieldDef {
    abbrev: "icmp.unused",
    name: "Unused",
    field_type: FieldType::Bytes,
    parent: "icmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.ident`.
pub static ICMP_IDENT: FieldDef = FieldDef {
    abbrev: "icmp.ident",
    name: "Identifier (BE)",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "Identifier (big endian representation)",
    generated: false,
};

/// `icmp.ident_le`.
pub static ICMP_IDENT_LE: FieldDef = FieldDef {
    abbrev: "icmp.ident_le",
    name: "Identifier (LE)",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "Identifier (little endian representation)",
    generated: false,
};

/// `icmp.seq`.
pub static ICMP_SEQ: FieldDef = FieldDef {
    abbrev: "icmp.seq",
    name: "Sequence Number (BE)",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "Sequence Number (big endian representation)",
    generated: false,
};

/// `icmp.seq_le`.
pub static ICMP_SEQ_LE: FieldDef = FieldDef {
    abbrev: "icmp.seq_le",
    name: "Sequence Number (LE)",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "Sequence Number (little endian representation)",
    generated: false,
};

/// `icmp.mtu`.
pub static ICMP_MTU: FieldDef = FieldDef {
    abbrev: "icmp.mtu",
    name: "MTU of next hop",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.num_addrs`.
pub static ICMP_NUM_ADDRS: FieldDef = FieldDef {
    abbrev: "icmp.num_addrs",
    name: "Number of addresses",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.addr_entry_size`.
pub static ICMP_ADDR_ENTRY_SIZE: FieldDef = FieldDef {
    abbrev: "icmp.addr_entry_size",
    name: "Address entry size",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.lifetime`.
pub static ICMP_LIFETIME: FieldDef = FieldDef {
    abbrev: "icmp.lifetime",
    name: "Lifetime",
    field_type: FieldType::Uint16,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.pointer`.
pub static ICMP_POINTER: FieldDef = FieldDef {
    abbrev: "icmp.pointer",
    name: "Pointer",
    field_type: FieldType::Uint32,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.originate_timestamp`.
pub static ICMP_ORIGINATE_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "icmp.originate_timestamp",
    name: "Originate Timestamp",
    field_type: FieldType::Uint32,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.receive_timestamp`.
pub static ICMP_RECEIVE_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "icmp.receive_timestamp",
    name: "Receive Timestamp",
    field_type: FieldType::Uint32,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.transmit_timestamp`.
pub static ICMP_TRANSMIT_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "icmp.transmit_timestamp",
    name: "Transmit Timestamp",
    field_type: FieldType::Uint32,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.address_mask`.
pub static ICMP_ADDRESS_MASK: FieldDef = FieldDef {
    abbrev: "icmp.address_mask",
    name: "Address Mask",
    field_type: FieldType::Ipv4,
    parent: "icmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.redir_gw`.
pub static ICMP_REDIR_GW: FieldDef = FieldDef {
    abbrev: "icmp.redir_gw",
    name: "Gateway Address",
    field_type: FieldType::Ipv4,
    parent: "icmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmp.length`.
pub static ICMP_LENGTH: FieldDef = FieldDef {
    abbrev: "icmp.length",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The length of the original datagram",
    generated: false,
};

/// `icmp.length.original_datagram`.
pub static ICMP_LENGTH_ORIGINAL: FieldDef = FieldDef {
    abbrev: "icmp.length.original_datagram",
    name: "Length of original datagram",
    field_type: FieldType::Uint8,
    parent: "icmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The length of the original datagram (length * 4)",
    generated: false,
};

/// `icmp.data`.
pub static ICMP_DATA: FieldDef = FieldDef {
    abbrev: "icmp.data",
    name: "ICMP Data",
    field_type: FieldType::Bytes,
    parent: "icmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static ICMP_FIELDS: &[&FieldDef] = &[
    &ICMP_TYPE,
    &ICMP_CODE,
    &ICMP_CHECKSUM,
    &ICMP_CHECKSUM_STATUS,
    &ICMP_UNUSED,
    &ICMP_IDENT,
    &ICMP_IDENT_LE,
    &ICMP_SEQ,
    &ICMP_SEQ_LE,
    &ICMP_MTU,
    &ICMP_NUM_ADDRS,
    &ICMP_ADDR_ENTRY_SIZE,
    &ICMP_LIFETIME,
    &ICMP_POINTER,
    &ICMP_ORIGINATE_TIMESTAMP,
    &ICMP_RECEIVE_TIMESTAMP,
    &ICMP_TRANSMIT_TIMESTAMP,
    &ICMP_ADDRESS_MASK,
    &ICMP_REDIR_GW,
    &ICMP_LENGTH,
    &ICMP_LENGTH_ORIGINAL,
    &ICMP_DATA,
];

/// Internet Control Message Protocol.
pub static ICMP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "icmp",
    long_name: "Internet Control Message Protocol",
    short_name: "ICMP",
    fields: ICMP_FIELDS,
};

/// `icmpv6.type`.
pub static ICMPV6_TYPE: FieldDef = FieldDef {
    abbrev: "icmpv6.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Indicates the type of the message",
    generated: false,
};

/// `icmpv6.code`.
pub static ICMPV6_CODE: FieldDef = FieldDef {
    abbrev: "icmpv6.code",
    name: "Code",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Depends on the message type.  It is used to create an additional level of message granularity",
    generated: false,
};

/// `icmpv6.checksum`.
pub static ICMPV6_CHECKSUM: FieldDef = FieldDef {
    abbrev: "icmpv6.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "icmpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "Used to detect data corruption in the ICMPv6 message and parts of the IPv6 header",
    generated: false,
};

/// `icmpv6.checksum.status`.
pub static ICMPV6_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "icmpv6.checksum.status",
    name: "Checksum Status",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// The checksum this ICMPv6 message should carry; see
/// [`ICMP_CHECKSUM_CALCULATED`].
pub static ICMPV6_CHECKSUM_CALCULATED: FieldDef = FieldDef {
    abbrev: "icmpv6.checksum_calculated",
    name: "Calculated Checksum",
    field_type: FieldType::Uint16,
    parent: "icmpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `icmpv6.reserved`.
pub static ICMPV6_RESERVED: FieldDef = FieldDef {
    abbrev: "icmpv6.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "Must be Zero",
    generated: false,
};

/// `icmpv6.data`.
pub static ICMPV6_DATA: FieldDef = FieldDef {
    abbrev: "icmpv6.data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.unknown_data`.
pub static ICMPV6_UNKNOWN_DATA: FieldDef = FieldDef {
    abbrev: "icmpv6.unknown_data",
    name: "Unknown Data",
    field_type: FieldType::Bytes,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "Not interpreted Data",
    generated: false,
};

/// `icmpv6.mtu`.
pub static ICMPV6_MTU: FieldDef = FieldDef {
    abbrev: "icmpv6.mtu",
    name: "MTU",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The Maximum Transmission Unit of the next-hop link",
    generated: false,
};

/// `icmpv6.pointer`.
pub static ICMPV6_POINTER: FieldDef = FieldDef {
    abbrev: "icmpv6.pointer",
    name: "Pointer",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Identifies the octet offset within the invoking packet where the error was detected",
    generated: false,
};

/// `icmpv6.echo.identifier`.
pub static ICMPV6_ECHO_IDENTIFIER: FieldDef = FieldDef {
    abbrev: "icmpv6.echo.identifier",
    name: "Identifier",
    field_type: FieldType::Uint16,
    parent: "icmpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "An identifier to aid in matching with Request and Reply",
    generated: false,
};

/// `icmpv6.echo.sequence_number`.
pub static ICMPV6_ECHO_SEQUENCE: FieldDef = FieldDef {
    abbrev: "icmpv6.echo.sequence_number",
    name: "Sequence",
    field_type: FieldType::Uint16,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "A sequence number to aid in matching Echo Replies to this Echo Request",
    generated: false,
};

/// `icmpv6.nd.ra.cur_hop_limit`.
pub static ICMPV6_ND_RA_CUR_HOP_LIMIT: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.cur_hop_limit",
    name: "Cur hop limit",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The default value that should be placed in the Hop Count field of the IP header for outgoing IP packets",
    generated: false,
};

/// `icmpv6.nd.ra.flag`.
pub static ICMPV6_ND_RA_FLAG: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.nd.ra.flag.m`.
pub static ICMPV6_ND_RA_FLAG_M: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.m",
    name: "Managed address configuration",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "When set, it indicates that addresses are available via DHCPv6",
    generated: false,
};

/// `icmpv6.nd.ra.flag.o`.
pub static ICMPV6_ND_RA_FLAG_O: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.o",
    name: "Other configuration",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "When set, it indicates that other configuration information is available via DHCPv6",
    generated: false,
};

/// `icmpv6.nd.ra.flag.h`.
pub static ICMPV6_ND_RA_FLAG_H: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.h",
    name: "Home Agent",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "When set, it indicate that the router sending this Router Advertisement is also functioning as a Mobile IPv6 home agent on this link",
    generated: false,
};

/// `icmpv6.nd.ra.flag.prf`.
pub static ICMPV6_ND_RA_FLAG_PRF: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.prf",
    name: "Prf (Default Router Preference)",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: Some(0x18),
    blurb: "Indicates whether to prefer this router over other default routers",
    generated: false,
};

/// `icmpv6.nd.ra.flag.p`.
pub static ICMPV6_ND_RA_FLAG_P: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.p",
    name: "ND Proxy",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "Neighbor Discovery Proxy (Experimental - RFC4389)",
    generated: false,
};

/// `icmpv6.nd.ra.flag.s`.
pub static ICMPV6_ND_RA_FLAG_S: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.s",
    name: "SNAC Router",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "Indicates whether the router operates as Stub Network Auto-Configuring (SNAC) router",
    generated: false,
};

/// `icmpv6.nd.ra.flag.rsv`.
pub static ICMPV6_ND_RA_FLAG_RSV: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.flag.rsv",
    name: "Reserved",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: Some(0x1),
    blurb: "Must be Zero",
    generated: false,
};

/// `icmpv6.nd.ra.router_lifetime`.
pub static ICMPV6_ND_RA_ROUTER_LIFETIME: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.router_lifetime",
    name: "Router lifetime (s)",
    field_type: FieldType::Uint16,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The lifetime associated with the default router",
    generated: false,
};

/// `icmpv6.nd.ra.reachable_time`.
pub static ICMPV6_ND_RA_REACHABLE_TIME: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.reachable_time",
    name: "Reachable time (ms)",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The time that a node assumes a neighbor is reachable after having received a reachability confirmation",
    generated: false,
};

/// `icmpv6.nd.ra.retrans_timer`.
pub static ICMPV6_ND_RA_RETRANS_TIMER: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ra.retrans_timer",
    name: "Retrans timer (ms)",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The time between retransmitted Neighbor Solicitation messages",
    generated: false,
};

/// `icmpv6.nd.ns.target_address`.
pub static ICMPV6_ND_NS_TARGET_ADDRESS: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.ns.target_address",
    name: "Target Address",
    field_type: FieldType::Ipv6,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "The IP address of the target of the solicitation",
    generated: false,
};

/// `icmpv6.nd.na.flag`.
pub static ICMPV6_ND_NA_FLAG: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.na.flag",
    name: "Flags",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.nd.na.flag.r`.
pub static ICMPV6_ND_NA_FLAG_R: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.na.flag.r",
    name: "Router",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean32,
    bitmask: Some(0x8000_0000),
    blurb: "When set, it indicates that the sender is a router",
    generated: false,
};

/// `icmpv6.nd.na.flag.s`.
pub static ICMPV6_ND_NA_FLAG_S: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.na.flag.s",
    name: "Solicited",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean32,
    bitmask: Some(0x4000_0000),
    blurb: "When set, it indicates that the advertisement was sent in response to a Neighbor Solicitation from the Destination address",
    generated: false,
};

/// `icmpv6.nd.na.flag.o`.
pub static ICMPV6_ND_NA_FLAG_O: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.na.flag.o",
    name: "Override",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean32,
    bitmask: Some(0x2000_0000),
    blurb: "When set, it indicates that the advertisement should override an existing cache entry and update the cached link-layer address",
    generated: false,
};

/// `icmpv6.nd.na.flag.rsv`.
pub static ICMPV6_ND_NA_FLAG_RSV: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.na.flag.rsv",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: Some(0x1fff_ffff),
    blurb: "Must be Zero",
    generated: false,
};

/// `icmpv6.nd.na.target_address`.
pub static ICMPV6_ND_NA_TARGET_ADDRESS: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.na.target_address",
    name: "Target Address",
    field_type: FieldType::Ipv6,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "the Target Address field in the Neighbor Solicitation message that prompted this advertisement",
    generated: false,
};

/// `icmpv6.nd.rd.target_address`.
pub static ICMPV6_ND_RD_TARGET_ADDRESS: FieldDef = FieldDef {
    abbrev: "icmpv6.nd.rd.target_address",
    name: "Target Address",
    field_type: FieldType::Ipv6,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "An IP address that is a better first hop to use for the ICMP Destination Address",
    generated: false,
};

/// `icmpv6.rd.na.destination_address`.
pub static ICMPV6_RD_NA_DESTINATION_ADDRESS: FieldDef = FieldDef {
    abbrev: "icmpv6.rd.na.destination_address",
    name: "Destination Address",
    field_type: FieldType::Ipv6,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "The IP address of the destination that is redirected to the target",
    generated: false,
};

/// `icmpv6.opt`.
pub static ICMPV6_OPT: FieldDef = FieldDef {
    abbrev: "icmpv6.opt",
    name: "ICMPv6 Option",
    field_type: FieldType::None,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.type`.
pub static ICMPV6_OPT_TYPE: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Options type",
    generated: false,
};

/// `icmpv6.opt.length`.
pub static ICMPV6_OPT_LENGTH: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.length",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The length (in units of 8 bytes) of the option (including the Type and Length fields)",
    generated: false,
};

/// `icmpv6.opt.reserved`.
pub static ICMPV6_OPT_RESERVED: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.reserved",
    name: "Reserved",
    field_type: FieldType::None,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "Reserved (Must be 0)",
    generated: false,
};

/// `icmpv6.opt.padding`.
pub static ICMPV6_OPT_PADDING: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.padding",
    name: "Padding",
    field_type: FieldType::None,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "Padding (Must be 0)",
    generated: false,
};

/// `icmpv6.opt.linkaddr`.
pub static ICMPV6_OPT_LINKADDR: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.linkaddr",
    name: "Link-layer address",
    field_type: FieldType::Bytes,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.src_linkaddr`.
pub static ICMPV6_OPT_SRC_LINKADDR: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.src_linkaddr",
    name: "Source Link-layer address",
    field_type: FieldType::Bytes,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.target_linkaddr`.
pub static ICMPV6_OPT_TARGET_LINKADDR: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.target_linkaddr",
    name: "Target Link-layer address",
    field_type: FieldType::Bytes,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.linkaddr_eui64`.
pub static ICMPV6_OPT_LINKADDR_EUI64: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.linkaddr_eui64",
    name: "Link-layer address",
    field_type: FieldType::Eui64,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.src_linkaddr_eui64`.
pub static ICMPV6_OPT_SRC_LINKADDR_EUI64: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.src_linkaddr_eui64",
    name: "Source Link-layer address",
    field_type: FieldType::Eui64,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.target_linkaddr_eui64`.
pub static ICMPV6_OPT_TARGET_LINKADDR_EUI64: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.target_linkaddr_eui64",
    name: "Target Link-layer address",
    field_type: FieldType::Eui64,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.prefix.length`.
pub static ICMPV6_OPT_PREFIX_LENGTH: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.length",
    name: "Prefix Length",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The number of leading bits in the Prefix that are valid",
    generated: false,
};

/// `icmpv6.opt.prefix.flag`.
pub static ICMPV6_OPT_PREFIX_FLAG: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.flag",
    name: "Flag",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.prefix.flag.l`.
pub static ICMPV6_OPT_PREFIX_FLAG_L: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.flag.l",
    name: "On-link Flag (L)",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "When set, indicates that this prefix can be used for on-link determination, and traffic to those destinations is sent directly (not via routers)",
    generated: false,
};

/// `icmpv6.opt.prefix.flag.a`.
pub static ICMPV6_OPT_PREFIX_FLAG_A: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.flag.a",
    name: "Autonomous Address Configuration Flag (A)",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "When set, indicates that this prefix can be used for stateless address configuration",
    generated: false,
};

/// `icmpv6.opt.prefix.flag.r`.
pub static ICMPV6_OPT_PREFIX_FLAG_R: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.flag.r",
    name: "Router Address Flag (R)",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "When set, indicates that the Prefix field contains a complete IP address assigned to the sending router",
    generated: false,
};

/// `icmpv6.opt.prefix.flag.p`.
pub static ICMPV6_OPT_PREFIX_FLAG_P: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.flag.p",
    name: "DHCPv6-PD Preferred Flag (P)",
    field_type: FieldType::Boolean,
    parent: "icmpv6",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "When set, indicates that the network prefers that clients use Prefix Delegation (PD) instead of acquiring individual addresses via SLAAC or DHCPv6 address assignment.",
    generated: false,
};

/// `icmpv6.opt.prefix.flag.reserved`.
pub static ICMPV6_OPT_PREFIX_FLAG_RESERVED: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.flag.reserved",
    name: "Reserved",
    field_type: FieldType::Uint8,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: Some(0xf),
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.prefix.valid_lifetime`.
pub static ICMPV6_OPT_PREFIX_VALID_LIFETIME: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.valid_lifetime",
    name: "Valid Lifetime",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The length of time in seconds that the prefix is valid for the purpose of on-link determination",
    generated: false,
};

/// `icmpv6.opt.prefix.preferred_lifetime`.
pub static ICMPV6_OPT_PREFIX_PREFERRED_LIFETIME: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix.preferred_lifetime",
    name: "Preferred Lifetime",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The length of time in seconds that addresses generated from the prefix via stateless address autoconfiguration remain preferred",
    generated: false,
};

/// `icmpv6.opt.prefix`.
pub static ICMPV6_OPT_PREFIX: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.prefix",
    name: "Prefix",
    field_type: FieldType::Ipv6,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "An IP address or a prefix of an IP address",
    generated: false,
};

/// `icmpv6.opt.redirected_packet`.
pub static ICMPV6_OPT_REDIRECTED_PACKET: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.redirected_packet",
    name: "Redirected Packet",
    field_type: FieldType::None,
    parent: "icmpv6",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `icmpv6.opt.mtu`.
pub static ICMPV6_OPT_MTU: FieldDef = FieldDef {
    abbrev: "icmpv6.opt.mtu",
    name: "MTU",
    field_type: FieldType::Uint32,
    parent: "icmpv6",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The recommended MTU for the link",
    generated: false,
};

static ICMPV6_FIELDS: &[&FieldDef] = &[
    &ICMPV6_TYPE,
    &ICMPV6_CODE,
    &ICMPV6_CHECKSUM,
    &ICMPV6_CHECKSUM_STATUS,
    &ICMPV6_RESERVED,
    &ICMPV6_DATA,
    &ICMPV6_UNKNOWN_DATA,
    &ICMPV6_MTU,
    &ICMPV6_POINTER,
    &ICMPV6_ECHO_IDENTIFIER,
    &ICMPV6_ECHO_SEQUENCE,
    &ICMPV6_ND_RA_CUR_HOP_LIMIT,
    &ICMPV6_ND_RA_FLAG,
    &ICMPV6_ND_RA_FLAG_M,
    &ICMPV6_ND_RA_FLAG_O,
    &ICMPV6_ND_RA_FLAG_H,
    &ICMPV6_ND_RA_FLAG_PRF,
    &ICMPV6_ND_RA_FLAG_P,
    &ICMPV6_ND_RA_FLAG_S,
    &ICMPV6_ND_RA_FLAG_RSV,
    &ICMPV6_ND_RA_ROUTER_LIFETIME,
    &ICMPV6_ND_RA_REACHABLE_TIME,
    &ICMPV6_ND_RA_RETRANS_TIMER,
    &ICMPV6_ND_NS_TARGET_ADDRESS,
    &ICMPV6_ND_NA_FLAG,
    &ICMPV6_ND_NA_FLAG_R,
    &ICMPV6_ND_NA_FLAG_S,
    &ICMPV6_ND_NA_FLAG_O,
    &ICMPV6_ND_NA_FLAG_RSV,
    &ICMPV6_ND_NA_TARGET_ADDRESS,
    &ICMPV6_ND_RD_TARGET_ADDRESS,
    &ICMPV6_RD_NA_DESTINATION_ADDRESS,
    &ICMPV6_OPT,
    &ICMPV6_OPT_TYPE,
    &ICMPV6_OPT_LENGTH,
    &ICMPV6_OPT_RESERVED,
    &ICMPV6_OPT_PADDING,
    &ICMPV6_OPT_LINKADDR,
    &ICMPV6_OPT_SRC_LINKADDR,
    &ICMPV6_OPT_TARGET_LINKADDR,
    &ICMPV6_OPT_LINKADDR_EUI64,
    &ICMPV6_OPT_SRC_LINKADDR_EUI64,
    &ICMPV6_OPT_TARGET_LINKADDR_EUI64,
    &ICMPV6_OPT_PREFIX_LENGTH,
    &ICMPV6_OPT_PREFIX_FLAG,
    &ICMPV6_OPT_PREFIX_FLAG_L,
    &ICMPV6_OPT_PREFIX_FLAG_A,
    &ICMPV6_OPT_PREFIX_FLAG_R,
    &ICMPV6_OPT_PREFIX_FLAG_P,
    &ICMPV6_OPT_PREFIX_FLAG_RESERVED,
    &ICMPV6_OPT_PREFIX_VALID_LIFETIME,
    &ICMPV6_OPT_PREFIX_PREFERRED_LIFETIME,
    &ICMPV6_OPT_PREFIX,
    &ICMPV6_OPT_REDIRECTED_PACKET,
    &ICMPV6_OPT_MTU,
];

/// `erspan.version`.
pub static ERSPAN_VERSION: FieldDef = FieldDef {
    abbrev: "erspan.version",
    name: "Version",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0xf000),
    blurb: "",
    generated: false,
};

/// `erspan.vlan`.
pub static ERSPAN_VLAN: FieldDef = FieldDef {
    abbrev: "erspan.vlan",
    name: "Vlan",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0fff),
    blurb: "",
    generated: false,
};

/// `erspan.cos`.
pub static ERSPAN_COS: FieldDef = FieldDef {
    abbrev: "erspan.cos",
    name: "COS",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0xe000),
    blurb: "",
    generated: false,
};

/// `erspan.encap`.
pub static ERSPAN_ENCAP: FieldDef = FieldDef {
    abbrev: "erspan.encap",
    name: "Encap",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x1800),
    blurb: "",
    generated: false,
};

/// `erspan.bso`.
pub static ERSPAN_BSO: FieldDef = FieldDef {
    abbrev: "erspan.bso",
    name: "Bad/Short/Oversized",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x1800),
    blurb: "",
    generated: false,
};

/// `erspan.truncated`.
pub static ERSPAN_TRUNCATED: FieldDef = FieldDef {
    abbrev: "erspan.truncated",
    name: "Truncated",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0400),
    blurb: "ERSPAN packet exceeded the MTU size",
    generated: false,
};

/// `erspan.spanid`.
pub static ERSPAN_SPANID: FieldDef = FieldDef {
    abbrev: "erspan.spanid",
    name: "SpanID",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03ff),
    blurb: "",
    generated: false,
};

/// `erspan.reserved`.
pub static ERSPAN_RESERVED: FieldDef = FieldDef {
    abbrev: "erspan.reserved",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0xfff0_0000),
    blurb: "",
    generated: false,
};

/// `erspan.index`.
pub static ERSPAN_INDEX: FieldDef = FieldDef {
    abbrev: "erspan.index",
    name: "Index",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x000f_ffff),
    blurb: "",
    generated: false,
};

/// `erspan.timestamp`.
pub static ERSPAN_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "erspan.timestamp",
    name: "Timestamp",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `erspan.sgt`.
pub static ERSPAN_SGT: FieldDef = FieldDef {
    abbrev: "erspan.sgt",
    name: "Security Group Tag",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `erspan.p`.
pub static ERSPAN_P: FieldDef = FieldDef {
    abbrev: "erspan.p",
    name: "Has Ethernet PDU",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `erspan.ft`.
pub static ERSPAN_FT: FieldDef = FieldDef {
    abbrev: "erspan.ft",
    name: "Frame Type",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x7c00),
    blurb: "",
    generated: false,
};

/// `erspan.hw`.
pub static ERSPAN_HW: FieldDef = FieldDef {
    abbrev: "erspan.hw",
    name: "Hardware ID",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03f0),
    blurb: "",
    generated: false,
};

/// `erspan.gra`.
pub static ERSPAN_GRA: FieldDef = FieldDef {
    abbrev: "erspan.gra",
    name: "Timestamp granularity",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0006),
    blurb: "",
    generated: false,
};

/// `erspan.direction`.
pub static ERSPAN_DIRECTION: FieldDef = FieldDef {
    abbrev: "erspan.direction",
    name: "Direction",
    field_type: FieldType::Boolean,
    parent: "erspan",
    display: Display::Boolean16,
    bitmask: Some(0x0008),
    blurb: "",
    generated: false,
};

/// `erspan.o`.
pub static ERSPAN_O: FieldDef = FieldDef {
    abbrev: "erspan.o",
    name: "Optional Sub headers",
    field_type: FieldType::Uint16,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0001),
    blurb: "",
    generated: false,
};

/// `erspan.platid`.
pub static ERSPAN_PLATID: FieldDef = FieldDef {
    abbrev: "erspan.platid",
    name: "Platform ID",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0xfc00_0000),
    blurb: "",
    generated: false,
};

/// `erspan.pid1.rsvd1`.
pub static ERSPAN_PID1_RSVD1: FieldDef = FieldDef {
    abbrev: "erspan.pid1.rsvd1",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03ff_f000),
    blurb: "",
    generated: false,
};

/// `erspan.pid1.vsmid`.
pub static ERSPAN_PID1_VSMID: FieldDef = FieldDef {
    abbrev: "erspan.pid1.vsmid",
    name: "VSM Domain ID",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0000_0fff),
    blurb: "",
    generated: false,
};

/// `erspan.pid1.port_index`.
pub static ERSPAN_PID1_PORT_INDEX: FieldDef = FieldDef {
    abbrev: "erspan.pid1.port_index",
    name: "Port ID/Index",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `erspan.pid3.rsvd1`.
pub static ERSPAN_PID3_RSVD1: FieldDef = FieldDef {
    abbrev: "erspan.pid3.rsvd1",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03ff_c000),
    blurb: "",
    generated: false,
};

/// `erspan.pid3.port_index`.
pub static ERSPAN_PID3_PORT_INDEX: FieldDef = FieldDef {
    abbrev: "erspan.pid3.port_index",
    name: "Port ID/Index",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0000_3fff),
    blurb: "",
    generated: false,
};

/// `erspan.pid3.timestamp`.
pub static ERSPAN_PID3_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "erspan.pid3.timestamp",
    name: "Upper 32-bit Timestamp",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `erspan.pid4.rsvd1`.
pub static ERSPAN_PID4_RSVD1: FieldDef = FieldDef {
    abbrev: "erspan.pid4.rsvd1",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03ff_c000),
    blurb: "",
    generated: false,
};

/// `erspan.pid4.rsvd2`.
pub static ERSPAN_PID4_RSVD2: FieldDef = FieldDef {
    abbrev: "erspan.pid4.rsvd2",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0000_3fff),
    blurb: "",
    generated: false,
};

/// `erspan.pid4.rsvd3`.
pub static ERSPAN_PID4_RSVD3: FieldDef = FieldDef {
    abbrev: "erspan.pid4.rsvd3",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0xffff_ffff),
    blurb: "",
    generated: false,
};

/// `erspan.pid5.switchid`.
pub static ERSPAN_PID5_SWITCHID: FieldDef = FieldDef {
    abbrev: "erspan.pid5.switchid",
    name: "Switch ID",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03ff_0000),
    blurb: "",
    generated: false,
};

/// `erspan.pid5.port_index`.
pub static ERSPAN_PID5_PORT_INDEX: FieldDef = FieldDef {
    abbrev: "erspan.pid5.port_index",
    name: "Port ID/Index",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x0000_ffff),
    blurb: "",
    generated: false,
};

/// `erspan.pid5.timestamp`.
pub static ERSPAN_PID5_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "erspan.pid5.timestamp",
    name: "Timestamp (seconds)",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `erspan.pid7.rsvd1`.
pub static ERSPAN_PID7_RSVD1: FieldDef = FieldDef {
    abbrev: "erspan.pid7.rsvd1",
    name: "Reserved",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03f0_0000),
    blurb: "",
    generated: false,
};

/// `erspan.pid7.source_index`.
pub static ERSPAN_PID7_SOURCE_INDEX: FieldDef = FieldDef {
    abbrev: "erspan.pid7.source_index",
    name: "Source Index",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x000f_ffff),
    blurb: "",
    generated: false,
};

/// `erspan.pid7.timestamp`.
pub static ERSPAN_PID7_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "erspan.pid7.timestamp",
    name: "Upper 32-bit Timestamp",
    field_type: FieldType::Uint32,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `erspan.pid.rsvd`.
pub static ERSPAN_PID_RSVD: FieldDef = FieldDef {
    abbrev: "erspan.pid.rsvd",
    name: "Reserved",
    field_type: FieldType::Uint64,
    parent: "erspan",
    display: Display::Decimal,
    bitmask: Some(0x03ff_ffff),
    blurb: "",
    generated: false,
};

/// `erspan.version.unknown`.
pub static ERSPAN_VERSION_UNKNOWN: FieldDef = FieldDef {
    abbrev: "erspan.version.unknown",
    name: "Unknown version, please report or test to use fake ERSPAN preference",
    field_type: FieldType::None,
    parent: "erspan",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static ERSPAN_FIELDS: &[&FieldDef] = &[
    &ERSPAN_VERSION,
    &ERSPAN_VLAN,
    &ERSPAN_COS,
    &ERSPAN_ENCAP,
    &ERSPAN_BSO,
    &ERSPAN_TRUNCATED,
    &ERSPAN_SPANID,
    &ERSPAN_RESERVED,
    &ERSPAN_INDEX,
    &ERSPAN_TIMESTAMP,
    &ERSPAN_SGT,
    &ERSPAN_P,
    &ERSPAN_FT,
    &ERSPAN_HW,
    &ERSPAN_GRA,
    &ERSPAN_DIRECTION,
    &ERSPAN_O,
    &ERSPAN_PLATID,
    &ERSPAN_PID1_RSVD1,
    &ERSPAN_PID1_VSMID,
    &ERSPAN_PID1_PORT_INDEX,
    &ERSPAN_PID3_RSVD1,
    &ERSPAN_PID3_PORT_INDEX,
    &ERSPAN_PID3_TIMESTAMP,
    &ERSPAN_PID4_RSVD1,
    &ERSPAN_PID4_RSVD2,
    &ERSPAN_PID4_RSVD3,
    &ERSPAN_PID5_SWITCHID,
    &ERSPAN_PID5_PORT_INDEX,
    &ERSPAN_PID5_TIMESTAMP,
    &ERSPAN_PID7_RSVD1,
    &ERSPAN_PID7_SOURCE_INDEX,
    &ERSPAN_PID7_TIMESTAMP,
    &ERSPAN_PID_RSVD,
    &ERSPAN_VERSION_UNKNOWN,
];

/// `geneve.version`.
pub static GENEVE_VERSION: FieldDef = FieldDef {
    abbrev: "geneve.version",
    name: "Version",
    field_type: FieldType::Uint8,
    parent: "geneve",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.flags`.
pub static GENEVE_FLAGS: FieldDef = FieldDef {
    abbrev: "geneve.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "geneve",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.flags.oam`.
pub static GENEVE_FLAGS_OAM: FieldDef = FieldDef {
    abbrev: "geneve.flags.oam",
    name: "Operations, Administration and Management Frame",
    field_type: FieldType::Boolean,
    parent: "geneve",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `geneve.flags.critical`.
pub static GENEVE_FLAGS_CRITICAL: FieldDef = FieldDef {
    abbrev: "geneve.flags.critical",
    name: "Critical Options Present",
    field_type: FieldType::Boolean,
    parent: "geneve",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `geneve.flags.reserved`.
pub static GENEVE_FLAGS_RESERVED: FieldDef = FieldDef {
    abbrev: "geneve.flags.reserved",
    name: "Reserved",
    field_type: FieldType::Boolean,
    parent: "geneve",
    display: Display::Boolean8,
    bitmask: Some(0x3f),
    blurb: "",
    generated: false,
};

/// `geneve.proto_type`.
pub static GENEVE_PROTO_TYPE: FieldDef = FieldDef {
    abbrev: "geneve.proto_type",
    name: "Protocol Type",
    field_type: FieldType::Uint16,
    parent: "geneve",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.vni`.
pub static GENEVE_VNI: FieldDef = FieldDef {
    abbrev: "geneve.vni",
    name: "Virtual Network Identifier (VNI)",
    field_type: FieldType::Uint24,
    parent: "geneve",
    display: Display::HexDec,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.reserved`.
pub static GENEVE_RESERVED: FieldDef = FieldDef {
    abbrev: "geneve.reserved",
    name: "Reserved",
    field_type: FieldType::Uint8,
    parent: "geneve",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.options`.
pub static GENEVE_OPTIONS: FieldDef = FieldDef {
    abbrev: "geneve.options",
    name: "Geneve Options",
    field_type: FieldType::Bytes,
    parent: "geneve",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option.class`.
pub static GENEVE_OPTION_CLASS: FieldDef = FieldDef {
    abbrev: "geneve.option.class",
    name: "Class",
    field_type: FieldType::Uint16,
    parent: "geneve",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option.type`.
pub static GENEVE_OPTION_TYPE: FieldDef = FieldDef {
    abbrev: "geneve.option.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "geneve",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option.type.critical`.
pub static GENEVE_OPTION_TYPE_CRITICAL: FieldDef = FieldDef {
    abbrev: "geneve.option.type.critical",
    name: "Critical Option",
    field_type: FieldType::Boolean,
    parent: "geneve",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `geneve.option.flags`.
pub static GENEVE_OPTION_FLAGS: FieldDef = FieldDef {
    abbrev: "geneve.option.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "geneve",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option.flags.reserved`.
pub static GENEVE_OPTION_FLAGS_RESERVED: FieldDef = FieldDef {
    abbrev: "geneve.option.flags.reserved",
    name: "Reserved",
    field_type: FieldType::Boolean,
    parent: "geneve",
    display: Display::Boolean8,
    bitmask: Some(0xe0),
    blurb: "",
    generated: false,
};

/// `geneve.option.length`.
pub static GENEVE_OPTION_LENGTH: FieldDef = FieldDef {
    abbrev: "geneve.option.length",
    name: "Length",
    field_type: FieldType::Uint8,
    parent: "geneve",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option`.
pub static GENEVE_OPTION: FieldDef = FieldDef {
    abbrev: "geneve.option",
    name: "Option",
    field_type: FieldType::Bytes,
    parent: "geneve",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option.unknown.data`.
pub static GENEVE_OPTION_UNKNOWN_DATA: FieldDef = FieldDef {
    abbrev: "geneve.option.unknown.data",
    name: "Unknown Option Data",
    field_type: FieldType::Bytes,
    parent: "geneve",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.version.unknown`.
pub static GENEVE_VERSION_UNKNOWN: FieldDef = FieldDef {
    abbrev: "geneve.version.unknown",
    name: "Unknown version",
    field_type: FieldType::None,
    parent: "geneve",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `geneve.option.length.invalid`.
pub static GENEVE_OPTION_LENGTH_INVALID: FieldDef = FieldDef {
    abbrev: "geneve.option.length.invalid",
    name: "Invalid length for option",
    field_type: FieldType::None,
    parent: "geneve",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static GENEVE_FIELDS: &[&FieldDef] = &[
    &GENEVE_VERSION,
    &GENEVE_FLAGS,
    &GENEVE_FLAGS_OAM,
    &GENEVE_FLAGS_CRITICAL,
    &GENEVE_FLAGS_RESERVED,
    &GENEVE_PROTO_TYPE,
    &GENEVE_VNI,
    &GENEVE_RESERVED,
    &GENEVE_OPTIONS,
    &GENEVE_OPTION_CLASS,
    &GENEVE_OPTION_TYPE,
    &GENEVE_OPTION_TYPE_CRITICAL,
    &GENEVE_OPTION_FLAGS,
    &GENEVE_OPTION_FLAGS_RESERVED,
    &GENEVE_OPTION_LENGTH,
    &GENEVE_OPTION,
    &GENEVE_OPTION_UNKNOWN_DATA,
    &GENEVE_VERSION_UNKNOWN,
    &GENEVE_OPTION_LENGTH_INVALID,
];

/// `gre.proto`.
pub static GRE_PROTO: FieldDef = FieldDef {
    abbrev: "gre.proto",
    name: "Protocol Type",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Hex,
    bitmask: None,
    blurb: "The protocol that is GRE encapsulated",
    generated: false,
};

/// `gre.flags_and_version`.
pub static GRE_FLAGS_AND_VERSION: FieldDef = FieldDef {
    abbrev: "gre.flags_and_version",
    name: "Flags and Version",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Hex,
    bitmask: None,
    blurb: "The GRE flags are encoded in the first two octets",
    generated: false,
};

/// `gre.flags.checksum`.
pub static GRE_FLAGS_CHECKSUM: FieldDef = FieldDef {
    abbrev: "gre.flags.checksum",
    name: "Checksum Bit",
    field_type: FieldType::Boolean,
    parent: "gre",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "Indicates if the Checksum field is present",
    generated: false,
};

/// `gre.flags.routing`.
pub static GRE_FLAGS_ROUTING: FieldDef = FieldDef {
    abbrev: "gre.flags.routing",
    name: "Routing Bit",
    field_type: FieldType::Boolean,
    parent: "gre",
    display: Display::Boolean16,
    bitmask: Some(0x4000),
    blurb: "Indicates if the Routing and Checksum/Offset field are present",
    generated: false,
};

/// `gre.flags.key`.
pub static GRE_FLAGS_KEY: FieldDef = FieldDef {
    abbrev: "gre.flags.key",
    name: "Key Bit",
    field_type: FieldType::Boolean,
    parent: "gre",
    display: Display::Boolean16,
    bitmask: Some(0x2000),
    blurb: "Indicates if the Key field is present",
    generated: false,
};

/// `gre.flags.sequence_number`.
pub static GRE_FLAGS_SEQUENCE_NUMBER: FieldDef = FieldDef {
    abbrev: "gre.flags.sequence_number",
    name: "Sequence Number Bit",
    field_type: FieldType::Boolean,
    parent: "gre",
    display: Display::Boolean16,
    bitmask: Some(0x1000),
    blurb: "Indicates if the Sequence Number field is present",
    generated: false,
};

/// `gre.flags.strict_source_route`.
pub static GRE_FLAGS_STRICT_SOURCE_ROUTE: FieldDef = FieldDef {
    abbrev: "gre.flags.strict_source_route",
    name: "Strict Source Route Bit",
    field_type: FieldType::Boolean,
    parent: "gre",
    display: Display::Boolean16,
    bitmask: Some(0x0800),
    blurb: "",
    generated: false,
};

/// `gre.flags.recursion_control`.
pub static GRE_FLAGS_RECURSION_CONTROL: FieldDef = FieldDef {
    abbrev: "gre.flags.recursion_control",
    name: "Recursion control",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: Some(0x0700),
    blurb: "",
    generated: false,
};

/// `gre.flags.ack`.
pub static GRE_FLAGS_ACK: FieldDef = FieldDef {
    abbrev: "gre.flags.ack",
    name: "Acknowledgment",
    field_type: FieldType::Boolean,
    parent: "gre",
    display: Display::Boolean16,
    bitmask: Some(0x0080),
    blurb: "Indicates if the packet contains an Acknowledgment Number to be used for acknowledging previously transmitted data",
    generated: false,
};

/// `gre.flags.reserved`.
pub static GRE_FLAGS_RESERVED: FieldDef = FieldDef {
    abbrev: "gre.flags.reserved",
    name: "Flags (Reserved)",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: Some(0x00f8),
    blurb: "",
    generated: false,
};

/// `gre.flags.version`.
pub static GRE_FLAGS_VERSION: FieldDef = FieldDef {
    abbrev: "gre.flags.version",
    name: "Version",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: Some(0x0007),
    blurb: "",
    generated: false,
};

/// `gre.checksum`.
pub static GRE_CHECKSUM: FieldDef = FieldDef {
    abbrev: "gre.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Hex,
    bitmask: None,
    blurb: "The Checksum field contains the IP (one's complement) checksum of the GRE header and the payload packet",
    generated: false,
};

/// `gre.checksum.status`.
pub static GRE_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "gre.checksum.status",
    name: "Checksum Status",
    field_type: FieldType::Uint8,
    parent: "gre",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `gre.offset`.
pub static GRE_OFFSET: FieldDef = FieldDef {
    abbrev: "gre.offset",
    name: "Offset",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The offset field indicates the octet offset from the start of the Routing field to the first octet of the active Source Route Entry to be examined",
    generated: false,
};

/// `gre.key`.
pub static GRE_KEY: FieldDef = FieldDef {
    abbrev: "gre.key",
    name: "Key",
    field_type: FieldType::Uint32,
    parent: "gre",
    display: Display::Hex,
    bitmask: None,
    blurb: "The Key field contains a four octet number which was inserted by the encapsulator",
    generated: false,
};

/// `gre.key.payload_length`.
pub static GRE_KEY_PAYLOAD_LENGTH: FieldDef = FieldDef {
    abbrev: "gre.key.payload_length",
    name: "Payload Length",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Size of the payload, not including the GRE header",
    generated: false,
};

/// `gre.key.call_id`.
pub static GRE_KEY_CALL_ID: FieldDef = FieldDef {
    abbrev: "gre.key.call_id",
    name: "Call ID",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Contains the Peer's Call ID for the session to which this packet belongs.",
    generated: false,
};

/// `gre.sequence_number`.
pub static GRE_SEQUENCE_NUMBER: FieldDef = FieldDef {
    abbrev: "gre.sequence_number",
    name: "Sequence Number",
    field_type: FieldType::Uint32,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The Sequence Number field contains an unsigned 32 bit integer which is inserted by the encapsulator",
    generated: false,
};

/// `gre.ack_number`.
pub static GRE_ACK_NUMBER: FieldDef = FieldDef {
    abbrev: "gre.ack_number",
    name: "Acknowledgment Number",
    field_type: FieldType::Uint32,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Contains the sequence number of the highest numbered GRE packet received by the sending peer for this user session",
    generated: false,
};

/// `gre.routing`.
pub static GRE_ROUTING: FieldDef = FieldDef {
    abbrev: "gre.routing",
    name: "Routing",
    field_type: FieldType::None,
    parent: "gre",
    display: Display::None,
    bitmask: None,
    blurb: "The Routing field is a list of Source Route Entries (SREs)",
    generated: false,
};

/// `gre.routing.address_family`.
pub static GRE_ROUTING_ADDRESS_FAMILY: FieldDef = FieldDef {
    abbrev: "gre.routing.address_family",
    name: "Address Family",
    field_type: FieldType::Uint16,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The Address Family field contains a two octet value which indicates the syntax and semantics of the Routing Information field",
    generated: false,
};

/// `gre.routing.sre_offset`.
pub static GRE_ROUTING_SRE_OFFSET: FieldDef = FieldDef {
    abbrev: "gre.routing.sre_offset",
    name: "SRE Offset",
    field_type: FieldType::Uint8,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The Address Family field contains a two octet value which indicates the syntax and semantics of the Routing Information field",
    generated: false,
};

/// `gre.routing.src_length`.
pub static GRE_ROUTING_SRC_LENGTH: FieldDef = FieldDef {
    abbrev: "gre.routing.src_length",
    name: "SRE Length",
    field_type: FieldType::Uint8,
    parent: "gre",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The SRE Length field contains the number of octets in the SRE",
    generated: false,
};

/// `gre.routing.information`.
pub static GRE_ROUTING_INFORMATION: FieldDef = FieldDef {
    abbrev: "gre.routing.information",
    name: "Routing Information",
    field_type: FieldType::Bytes,
    parent: "gre",
    display: Display::None,
    bitmask: None,
    blurb: "The Routing Information field contains data which may be used in routing this packet",
    generated: false,
};

/// `gre.checksum.incorrect`.
pub static GRE_CHECKSUM_INCORRECT: FieldDef = FieldDef {
    abbrev: "gre.checksum.incorrect",
    name: "Incorrect GRE Checksum",
    field_type: FieldType::None,
    parent: "gre",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static GRE_FIELDS: &[&FieldDef] = &[
    &GRE_PROTO,
    &GRE_FLAGS_AND_VERSION,
    &GRE_FLAGS_CHECKSUM,
    &GRE_FLAGS_ROUTING,
    &GRE_FLAGS_KEY,
    &GRE_FLAGS_SEQUENCE_NUMBER,
    &GRE_FLAGS_STRICT_SOURCE_ROUTE,
    &GRE_FLAGS_RECURSION_CONTROL,
    &GRE_FLAGS_ACK,
    &GRE_FLAGS_RESERVED,
    &GRE_FLAGS_VERSION,
    &GRE_CHECKSUM,
    &GRE_CHECKSUM_STATUS,
    &GRE_OFFSET,
    &GRE_KEY,
    &GRE_KEY_PAYLOAD_LENGTH,
    &GRE_KEY_CALL_ID,
    &GRE_SEQUENCE_NUMBER,
    &GRE_ACK_NUMBER,
    &GRE_ROUTING,
    &GRE_ROUTING_ADDRESS_FAMILY,
    &GRE_ROUTING_SRE_OFFSET,
    &GRE_ROUTING_SRC_LENGTH,
    &GRE_ROUTING_INFORMATION,
    &GRE_CHECKSUM_INCORRECT,
];

/// `mpls.label`.
pub static MPLS_LABEL: FieldDef = FieldDef {
    abbrev: "mpls.label",
    name: "MPLS Label",
    field_type: FieldType::Uint32,
    parent: "mpls",
    display: Display::DecHex,
    bitmask: Some(0xffff_f000),
    blurb: "",
    generated: false,
};

/// `mpls.exp`.
pub static MPLS_EXP: FieldDef = FieldDef {
    abbrev: "mpls.exp",
    name: "MPLS Experimental Bits",
    field_type: FieldType::Uint32,
    parent: "mpls",
    display: Display::Decimal,
    bitmask: Some(0x0000_0e00),
    blurb: "",
    generated: false,
};

/// `mpls.bottom`.
pub static MPLS_BOTTOM: FieldDef = FieldDef {
    abbrev: "mpls.bottom",
    name: "MPLS Bottom Of Label Stack",
    field_type: FieldType::Uint32,
    parent: "mpls",
    display: Display::Decimal,
    bitmask: Some(0x0000_0100),
    blurb: "",
    generated: false,
};

/// `mpls.ttl`.
pub static MPLS_TTL: FieldDef = FieldDef {
    abbrev: "mpls.ttl",
    name: "MPLS TTL",
    field_type: FieldType::Uint32,
    parent: "mpls",
    display: Display::Decimal,
    bitmask: Some(0x0000_00ff),
    blurb: "",
    generated: false,
};

static MPLS_FIELDS: &[&FieldDef] = &[&MPLS_LABEL, &MPLS_EXP, &MPLS_BOTTOM, &MPLS_TTL];

/// `vxlan.flags`.
pub static VXLAN_FLAGS: FieldDef = FieldDef {
    abbrev: "vxlan.flags",
    name: "Flags",
    field_type: FieldType::Uint16,
    parent: "vxlan",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `vxlan.flags_reserved`.
pub static VXLAN_FLAGS_RESERVED: FieldDef = FieldDef {
    abbrev: "vxlan.flags_reserved",
    name: "Reserved(R)",
    field_type: FieldType::Uint16,
    parent: "vxlan",
    display: Display::Hex,
    bitmask: Some(0x77b7),
    blurb: "",
    generated: false,
};

/// `vxlan.flag_g`.
pub static VXLAN_FLAG_G: FieldDef = FieldDef {
    abbrev: "vxlan.flag_g",
    name: "GBP Extension",
    field_type: FieldType::Boolean,
    parent: "vxlan",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `vxlan.flag_i`.
pub static VXLAN_FLAG_I: FieldDef = FieldDef {
    abbrev: "vxlan.flag_i",
    name: "VXLAN Network ID (VNI)",
    field_type: FieldType::Boolean,
    parent: "vxlan",
    display: Display::Boolean16,
    bitmask: Some(0x0800),
    blurb: "",
    generated: false,
};

/// `vxlan.flag_d`.
pub static VXLAN_FLAG_D: FieldDef = FieldDef {
    abbrev: "vxlan.flag_d",
    name: "Don't Learn",
    field_type: FieldType::Boolean,
    parent: "vxlan",
    display: Display::Boolean16,
    bitmask: Some(0x0040),
    blurb: "",
    generated: false,
};

/// `vxlan.flag_a`.
pub static VXLAN_FLAG_A: FieldDef = FieldDef {
    abbrev: "vxlan.flag_a",
    name: "Policy Applied",
    field_type: FieldType::Boolean,
    parent: "vxlan",
    display: Display::Boolean16,
    bitmask: Some(0x0008),
    blurb: "",
    generated: false,
};

/// `vxlan.gbp`.
pub static VXLAN_GBP: FieldDef = FieldDef {
    abbrev: "vxlan.gbp",
    name: "Group Policy ID",
    field_type: FieldType::Uint16,
    parent: "vxlan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `vxlan.vni`.
pub static VXLAN_VNI: FieldDef = FieldDef {
    abbrev: "vxlan.vni",
    name: "VXLAN Network Identifier (VNI)",
    field_type: FieldType::Uint24,
    parent: "vxlan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `vxlan.reserved8`.
pub static VXLAN_RESERVED8: FieldDef = FieldDef {
    abbrev: "vxlan.reserved8",
    name: "Reserved",
    field_type: FieldType::Uint8,
    parent: "vxlan",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

static VXLAN_FIELDS: &[&FieldDef] = &[
    &VXLAN_FLAGS,
    &VXLAN_FLAGS_RESERVED,
    &VXLAN_FLAG_G,
    &VXLAN_FLAG_I,
    &VXLAN_FLAG_D,
    &VXLAN_FLAG_A,
    &VXLAN_GBP,
    &VXLAN_VNI,
    &VXLAN_RESERVED8,
];

/// Encapsulated Remote Switch Packet Analysis.
pub static ERSPAN_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "erspan",
    long_name: "Encapsulated Remote Switch Packet ANalysis",
    short_name: "ERSPAN",
    fields: ERSPAN_FIELDS,
};

/// Generic Network Virtualization Encapsulation.
pub static GENEVE_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "geneve",
    long_name: "Generic Network Virtualization Encapsulation",
    short_name: "Geneve",
    fields: GENEVE_FIELDS,
};

/// Generic Routing Encapsulation.
pub static GRE_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "gre",
    long_name: "Generic Routing Encapsulation",
    short_name: "GRE",
    fields: GRE_FIELDS,
};

/// MultiProtocol Label Switching.
pub static MPLS_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "mpls",
    long_name: "MultiProtocol Label Switching Header",
    short_name: "MPLS",
    fields: MPLS_FIELDS,
};

/// Virtual eXtensible Local Area Network.
pub static VXLAN_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "vxlan",
    long_name: "Virtual eXtensible Local Area Network",
    short_name: "VXLAN",
    fields: VXLAN_FIELDS,
};

// LLDP fields
/// `lldp.tlv.type`.
pub static LLDP_TLV_TYPE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.type",
    name: "TLV Type",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: Some(0xfe00),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.len`.
pub static LLDP_TLV_LEN: FieldDef = FieldDef {
    abbrev: "lldp.tlv.len",
    name: "TLV Length",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: Some(0x1ff),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap`.
pub static LLDP_TLV_SYSTEM_CAP: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap",
    name: "Capabilities",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.other`.
pub static LLDP_TLV_SYSTEM_CAP_OTHER: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.other",
    name: "Other",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.repeater`.
pub static LLDP_TLV_SYSTEM_CAP_REPEATER: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.repeater",
    name: "Repeater",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.bridge`.
pub static LLDP_TLV_SYSTEM_CAP_BRIDGE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.bridge",
    name: "Bridge",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.wlan_access_pt`.
pub static LLDP_TLV_SYSTEM_CAP_WLAN_ACCESS_PT: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.wlan_access_pt",
    name: "WLAN access point",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.router`.
pub static LLDP_TLV_SYSTEM_CAP_ROUTER: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.router",
    name: "Router",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.telephone`.
pub static LLDP_TLV_SYSTEM_CAP_TELEPHONE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.telephone",
    name: "Telephone",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.docsis_cable_device`.
pub static LLDP_TLV_SYSTEM_CAP_DOCSIS_CABLE_DEVICE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.docsis_cable_device",
    name: "DOCSIS cable device",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.station_only`.
pub static LLDP_TLV_SYSTEM_CAP_STATION_ONLY: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.station_only",
    name: "Station only",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.cvlan`.
pub static LLDP_TLV_SYSTEM_CAP_CVLAN: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.cvlan",
    name: "C-VLAN component",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x100),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.svlan`.
pub static LLDP_TLV_SYSTEM_CAP_SVLAN: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.svlan",
    name: "S-VLAN component",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x200),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system_cap.tpmr`.
pub static LLDP_TLV_SYSTEM_CAP_TPMR: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system_cap.tpmr",
    name: "TPMR component",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x400),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system.name`.
pub static LLDP_TLV_SYSTEM_NAME: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system.name",
    name: "System Name",
    field_type: FieldType::String,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.tlv.system.desc`.
pub static LLDP_TLV_SYSTEM_DESC: FieldDef = FieldDef {
    abbrev: "lldp.tlv.system.desc",
    name: "System Description",
    field_type: FieldType::String,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap",
    name: "Enabled Capabilities",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.other`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_OTHER: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.other",
    name: "Other",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.repeater`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_REPEATER: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.repeater",
    name: "Repeater",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.bridge`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_BRIDGE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.bridge",
    name: "Bridge",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.wlan_access_pt`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_WLAN_ACCESS_PT: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.wlan_access_pt",
    name: "WLAN access point",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.router`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_ROUTER: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.router",
    name: "Router",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.telephone`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_TELEPHONE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.telephone",
    name: "Telephone",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.docsis_cable_device`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_DOCSIS_CABLE_DEVICE: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.docsis_cable_device",
    name: "DOCSIS cable device",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.station_only`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_STATION_ONLY: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.station_only",
    name: "Station only",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.cvlan`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_CVLAN: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.cvlan",
    name: "C-VLAN component",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x100),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.svlan`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_SVLAN: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.svlan",
    name: "S-VLAN component",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x200),
    blurb: "",
    generated: false,
};

/// `lldp.tlv.enable_system_cap.tpmr`.
pub static LLDP_TLV_ENABLE_SYSTEM_CAP_TPMR: FieldDef = FieldDef {
    abbrev: "lldp.tlv.enable_system_cap.tpmr",
    name: "TPMR component",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x400),
    blurb: "",
    generated: false,
};

/// `lldp.chassis.subtype`.
pub static LLDP_CHASSIS_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.chassis.subtype",
    name: "Chassis Id Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.chassis.id`.
pub static LLDP_CHASSIS_ID: FieldDef = FieldDef {
    abbrev: "lldp.chassis.id",
    name: "Chassis Id",
    field_type: FieldType::Bytes,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.chassis.id.mac`.
pub static LLDP_CHASSIS_ID_MAC: FieldDef = FieldDef {
    abbrev: "lldp.chassis.id.mac",
    name: "Chassis Id",
    field_type: FieldType::Ethernet,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.chassis.id.ip4`.
pub static LLDP_CHASSIS_ID_IP4: FieldDef = FieldDef {
    abbrev: "lldp.chassis.id.ip4",
    name: "Chassis Id",
    field_type: FieldType::Ipv4,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.chassis.id.ip6`.
pub static LLDP_CHASSIS_ID_IP6: FieldDef = FieldDef {
    abbrev: "lldp.chassis.id.ip6",
    name: "Chassis Id",
    field_type: FieldType::Ipv6,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.port.subtype`.
pub static LLDP_PORT_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.port.subtype",
    name: "Port Id Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.port.id`.
pub static LLDP_PORT_ID: FieldDef = FieldDef {
    abbrev: "lldp.port.id",
    name: "Port Id",
    field_type: FieldType::String,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.port.desc`.
pub static LLDP_PORT_DESC: FieldDef = FieldDef {
    abbrev: "lldp.port.desc",
    name: "Port Description",
    field_type: FieldType::String,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.port.id.mac`.
pub static LLDP_PORT_ID_MAC: FieldDef = FieldDef {
    abbrev: "lldp.port.id.mac",
    name: "Port Id",
    field_type: FieldType::Ethernet,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.network_address.subtype`.
pub static LLDP_NETWORK_ADDRESS_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.network_address.subtype",
    name: "Network Address family",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.port.id.ip4`.
pub static LLDP_PORT_ID_IP4: FieldDef = FieldDef {
    abbrev: "lldp.port.id.ip4",
    name: "Port Id",
    field_type: FieldType::Ipv4,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.port.id.ip6`.
pub static LLDP_PORT_ID_IP6: FieldDef = FieldDef {
    abbrev: "lldp.port.id.ip6",
    name: "Port Id",
    field_type: FieldType::Ipv6,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.time_to_live`.
pub static LLDP_TIME_TO_LIVE: FieldDef = FieldDef {
    abbrev: "lldp.time_to_live",
    name: "Seconds",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.pdu_type`.
pub static LLDP_PDU_TYPE: FieldDef = FieldDef {
    abbrev: "lldp.pdu_type",
    name: "PDU Type",
    field_type: FieldType::None,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.address.len`.
pub static LLDP_MGN_ADDRESS_LEN: FieldDef = FieldDef {
    abbrev: "lldp.mgn.address.len",
    name: "Address String Length",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.address.subtype`.
pub static LLDP_MGN_ADDRESS_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.mgn.address.subtype",
    name: "Address Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Undefined",
    generated: false,
};

/// `lldp.mgn.addr.ip4`.
pub static LLDP_MGN_ADDR_IP4: FieldDef = FieldDef {
    abbrev: "lldp.mgn.addr.ip4",
    name: "Management Address",
    field_type: FieldType::Ipv4,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.addr.ip6`.
pub static LLDP_MGN_ADDR_IP6: FieldDef = FieldDef {
    abbrev: "lldp.mgn.addr.ip6",
    name: "Management Address",
    field_type: FieldType::Ipv6,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.addr.hex`.
pub static LLDP_MGN_ADDR_HEX: FieldDef = FieldDef {
    abbrev: "lldp.mgn.addr.hex",
    name: "Management Address",
    field_type: FieldType::Bytes,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.interface.subtype`.
pub static LLDP_MGN_INTERFACE_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.mgn.interface.subtype",
    name: "Interface Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Undefined",
    generated: false,
};

/// `lldp.mgn.interface.number`.
pub static LLDP_MGN_INTERFACE_NUMBER: FieldDef = FieldDef {
    abbrev: "lldp.mgn.interface.number",
    name: "Interface Number",
    field_type: FieldType::Uint32,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.obj.len`.
pub static LLDP_MGN_OBJ_LEN: FieldDef = FieldDef {
    abbrev: "lldp.mgn.obj.len",
    name: "OID String Length",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.mgn.obj.id`.
pub static LLDP_MGN_OBJ_ID: FieldDef = FieldDef {
    abbrev: "lldp.mgn.obj.id",
    name: "Object Identifier",
    field_type: FieldType::Oid,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.orgtlv.oui`.
pub static LLDP_ORGTLV_OUI: FieldDef = FieldDef {
    abbrev: "lldp.orgtlv.oui",
    name: "Organization Unique Code",
    field_type: FieldType::Uint24,
    parent: "lldp",
    display: Display::Oui,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.subtype`.
pub static LLDP_IEEE_802_1_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.subtype",
    name: "IEEE 802.1 Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.port_and_vlan_id_flag`.
pub static LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.port_and_vlan_id_flag",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.port_and_vlan_id_flag.supported`.
pub static LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG_SUPPORTED: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.port_and_vlan_id_flag.supported",
    name: "Port and Protocol VLAN",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.port_and_vlan_id_flag.enabled`.
pub static LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG_ENABLED: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.port_and_vlan_id_flag.enabled",
    name: "Port and Protocol VLAN",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.port_vlan.id`.
pub static LLDP_IEEE_802_1_PORT_VLAN_ID: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.port_vlan.id",
    name: "Port VLAN Identifier",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.port_proto_vlan.id`.
pub static LLDP_IEEE_802_1_PORT_PROTO_VLAN_ID: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.port_proto_vlan.id",
    name: "Port and Protocol VLAN Identifier",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.vlan.id`.
pub static LLDP_IEEE_802_1_VLAN_ID: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.vlan.id",
    name: "VLAN Identifier",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::DecHex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.vlan.name_len`.
pub static LLDP_IEEE_802_1_VLAN_NAME_LEN: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.vlan.name_len",
    name: "VLAN Name Length",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.vlan.name`.
pub static LLDP_IEEE_802_1_VLAN_NAME: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.vlan.name",
    name: "VLAN Name",
    field_type: FieldType::StringZ,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.proto.id_length`.
pub static LLDP_IEEE_802_1_PROTO_ID_LENGTH: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.proto.id_length",
    name: "Protocol Identity Length",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.proto.id`.
pub static LLDP_IEEE_802_1_PROTO_ID: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.proto.id",
    name: "Protocol Identity",
    field_type: FieldType::Bytes,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.aggregation_status`.
pub static LLDP_IEEE_802_1_AGGREGATION_STATUS: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.aggregation_status",
    name: "Aggregation Status",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.aggregation_status.cap`.
pub static LLDP_IEEE_802_1_AGGREGATION_STATUS_CAP: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.aggregation_status.cap",
    name: "Aggregation Capability",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.aggregation_status.enabled`.
pub static LLDP_IEEE_802_1_AGGREGATION_STATUS_ENABLED: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.aggregation_status.enabled",
    name: "Aggregation Status",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.aggregation_status.porttype`.
pub static LLDP_IEEE_802_1_AGGREGATION_STATUS_PORTTYPE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.aggregation_status.porttype",
    name: "Aggregation Status",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: Some(0xc),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_1.aggregated_port_id`.
pub static LLDP_IEEE_802_1_AGGREGATED_PORT_ID: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_1.aggregated_port_id",
    name: "Aggregated Port Id",
    field_type: FieldType::Uint32,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.subtype`.
pub static LLDP_IEEE_802_3_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.subtype",
    name: "IEEE 802.3 Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.mac_phy_auto_neg_status`.
pub static LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.mac_phy_auto_neg_status",
    name: "Auto-Negotiation Support/Status",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.mac_phy_auto_neg_status.supported`.
pub static LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS_SUPPORTED: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.mac_phy_auto_neg_status.supported",
    name: "Auto-Negotiation",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.mac_phy_auto_neg_status.enabled`.
pub static LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS_ENABLED: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.mac_phy_auto_neg_status.enabled",
    name: "Auto-Negotiation",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps",
    name: "PMD Auto-Negotiation Advertised Capability",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_tfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_TFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_tfd",
    name: "1000BASE-T (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_t`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_T: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_t",
    name: "1000BASE-T (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_xfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_XFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_xfd",
    name: "1000BASE-X (-LX, -SX, -CX full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_x`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_X: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_x",
    name: "1000BASE-X (-LX, -SX, -CX half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_bpause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_BPAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_bpause",
    name: "Asymmetric and Symmetric PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_spause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_SPAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_spause",
    name: "Symmetric PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_apause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_APAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_apause",
    name: "Asymmetric PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_pause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_PAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_pause",
    name: "PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2fd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T2FD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2fd",
    name: "100BASE-T2 (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x100),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T2: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2",
    name: "100BASE-T2 (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x200),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_txfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_TXFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_txfd",
    name: "100BASE-TX (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x400),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_tx`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_TX: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_tx",
    name: "100BASE-TX (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x800),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t4`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T4: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t4",
    name: "100BASE-T4",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x1000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_tfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_10BASE_TFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_tfd",
    name: "10BASE-T (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x2000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_t`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_10BASE_T: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_t",
    name: "10BASE-T (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x4000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps.other`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_OTHER: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.other",
    name: "Other or unknown",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_tfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_TFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_tfd",
    name: "1000BASE-T (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_t`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_T: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_t",
    name: "1000BASE-T (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x4000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_xfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_XFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_xfd",
    name: "1000BASE-X (-LX, -SX, -CX full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x2000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_x`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_X: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_x",
    name: "1000BASE-X (-LX, -SX, -CX half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x1000),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_bpause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_BPAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_bpause",
    name: "Asymmetric and Symmetric PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x800),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_spause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_SPAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_spause",
    name: "Symmetric PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x400),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_apause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_APAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_apause",
    name: "Asymmetric PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x200),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_pause`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_PAUSE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_pause",
    name: "PAUSE (for full-duplex links)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x100),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2fd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T2FD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2fd",
    name: "100BASE-T2 (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T2: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2",
    name: "100BASE-T2 (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_txfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_TXFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_txfd",
    name: "100BASE-TX (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_tx`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_TX: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_tx",
    name: "100BASE-TX (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t4`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T4: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t4",
    name: "100BASE-T4",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_tfd`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_10BASE_TFD: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_tfd",
    name: "10BASE-T (full duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_t`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_10BASE_T: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_t",
    name: "10BASE-T (half duplex mode)",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.other`.
pub static LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_OTHER: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.other",
    name: "Other or unknown",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean16,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.pmd_mau_type`.
pub static LLDP_IEEE_802_3_PMD_MAU_TYPE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.pmd_mau_type",
    name: "Operational MAU Type",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Unknown",
    generated: false,
};

/// `lldp.ieee.802_3.aggregation_status`.
pub static LLDP_IEEE_802_3_AGGREGATION_STATUS: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.aggregation_status",
    name: "Aggregation Status",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.aggregation_status.cap`.
pub static LLDP_IEEE_802_3_AGGREGATION_STATUS_CAP: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.aggregation_status.cap",
    name: "Aggregation Capability",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.aggregation_status.enabled`.
pub static LLDP_IEEE_802_3_AGGREGATION_STATUS_ENABLED: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.aggregation_status.enabled",
    name: "Aggregation Status",
    field_type: FieldType::Boolean,
    parent: "lldp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.aggregated_port_id`.
pub static LLDP_IEEE_802_3_AGGREGATED_PORT_ID: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.aggregated_port_id",
    name: "Aggregated Port Id",
    field_type: FieldType::Uint32,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.ieee.802_3.max_frame_size`.
pub static LLDP_IEEE_802_3_MAX_FRAME_SIZE: FieldDef = FieldDef {
    abbrev: "lldp.ieee.802_3.max_frame_size",
    name: "Maximum Frame Size",
    field_type: FieldType::Uint16,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.unknown_subtype`.
pub static LLDP_UNKNOWN_SUBTYPE: FieldDef = FieldDef {
    abbrev: "lldp.unknown_subtype",
    name: "Unknown Subtype",
    field_type: FieldType::Uint8,
    parent: "lldp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.unknown_subtype.content`.
pub static LLDP_UNKNOWN_SUBTYPE_CONTENT: FieldDef = FieldDef {
    abbrev: "lldp.unknown_subtype.content",
    name: "Unknown Subtype Content",
    field_type: FieldType::Bytes,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.incorrect_length`.
pub static LLDP_INCORRECT_LENGTH: FieldDef = FieldDef {
    abbrev: "lldp.incorrect_length",
    name: "Invalid length, too short",
    field_type: FieldType::None,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.excess_length`.
pub static LLDP_EXCESS_LENGTH: FieldDef = FieldDef {
    abbrev: "lldp.excess_length",
    name: "Invalid length, greater than expected",
    field_type: FieldType::None,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

// LACP fields
/// `lldp.excess_tlv`.
pub static LLDP_EXCESS_TLV: FieldDef = FieldDef {
    abbrev: "lldp.excess_tlv",
    name: "Excess TLV in Shutdown PDU",
    field_type: FieldType::None,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.bad_type`.
pub static LLDP_BAD_TYPE: FieldDef = FieldDef {
    abbrev: "lldp.bad_type",
    name: "Incorrect type",
    field_type: FieldType::None,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lldp.tlv_deprecated`.
pub static LLDP_TLV_DEPRECATED: FieldDef = FieldDef {
    abbrev: "lldp.tlv_deprecated",
    name: "TLV has been deprecated",
    field_type: FieldType::None,
    parent: "lldp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.version`.
pub static LACP_VERSION: FieldDef = FieldDef {
    abbrev: "lacp.version",
    name: "LACP Version",
    field_type: FieldType::Uint8,
    parent: "lacp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.tlv_type`.
pub static LACP_TLV_TYPE: FieldDef = FieldDef {
    abbrev: "lacp.tlv_type",
    name: "TLV Type",
    field_type: FieldType::Uint8,
    parent: "lacp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.tlv_length`.
pub static LACP_TLV_LENGTH: FieldDef = FieldDef {
    abbrev: "lacp.tlv_length",
    name: "TLV Length",
    field_type: FieldType::Uint8,
    parent: "lacp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.sys_priority`.
pub static LACP_ACTOR_SYS_PRIORITY: FieldDef = FieldDef {
    abbrev: "lacp.actor.sys_priority",
    name: "Actor System Priority",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.sysid`.
pub static LACP_ACTOR_SYSID: FieldDef = FieldDef {
    abbrev: "lacp.actor.sysid",
    name: "Actor System ID",
    field_type: FieldType::Ethernet,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.key`.
pub static LACP_ACTOR_KEY: FieldDef = FieldDef {
    abbrev: "lacp.actor.key",
    name: "Actor Key",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.port_priority`.
pub static LACP_ACTOR_PORT_PRIORITY: FieldDef = FieldDef {
    abbrev: "lacp.actor.port_priority",
    name: "Actor Port Priority",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.port`.
pub static LACP_ACTOR_PORT: FieldDef = FieldDef {
    abbrev: "lacp.actor.port",
    name: "Actor Port",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.state`.
pub static LACP_ACTOR_STATE: FieldDef = FieldDef {
    abbrev: "lacp.actor.state",
    name: "Actor State",
    field_type: FieldType::Uint8,
    parent: "lacp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.actor.state_str`.
pub static LACP_ACTOR_STATE_STR: FieldDef = FieldDef {
    abbrev: "lacp.actor.state_str",
    name: "Actor State Flags",
    field_type: FieldType::String,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `lacp.actor.state.activity`.
pub static LACP_ACTOR_STATE_ACTIVITY: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.activity",
    name: "LACP Activity",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lacp.actor.state.timeout`.
pub static LACP_ACTOR_STATE_TIMEOUT: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.timeout",
    name: "LACP Timeout",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lacp.actor.state.aggregation`.
pub static LACP_ACTOR_STATE_AGGREGATION: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.aggregation",
    name: "Aggregation",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lacp.actor.state.synchronization`.
pub static LACP_ACTOR_STATE_SYNCHRONIZATION: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.synchronization",
    name: "Synchronization",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `lacp.actor.state.collecting`.
pub static LACP_ACTOR_STATE_COLLECTING: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.collecting",
    name: "Collecting",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `lacp.actor.state.distributing`.
pub static LACP_ACTOR_STATE_DISTRIBUTING: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.distributing",
    name: "Distributing",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `lacp.actor.state.defaulted`.
pub static LACP_ACTOR_STATE_DEFAULTED: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.defaulted",
    name: "Defaulted",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU",
    generated: false,
};

/// `lacp.actor.state.expired`.
pub static LACP_ACTOR_STATE_EXPIRED: FieldDef = FieldDef {
    abbrev: "lacp.actor.state.expired",
    name: "Expired",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `lacp.actor.reserved`.
pub static LACP_ACTOR_RESERVED: FieldDef = FieldDef {
    abbrev: "lacp.actor.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.partner.sys_priority`.
pub static LACP_PARTNER_SYS_PRIORITY: FieldDef = FieldDef {
    abbrev: "lacp.partner.sys_priority",
    name: "Partner System Priority",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.partner.sysid`.
pub static LACP_PARTNER_SYSID: FieldDef = FieldDef {
    abbrev: "lacp.partner.sysid",
    name: "Partner System",
    field_type: FieldType::Ethernet,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.partner.key`.
pub static LACP_PARTNER_KEY: FieldDef = FieldDef {
    abbrev: "lacp.partner.key",
    name: "Partner Key",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.partner.port_priority`.
pub static LACP_PARTNER_PORT_PRIORITY: FieldDef = FieldDef {
    abbrev: "lacp.partner.port_priority",
    name: "Partner Port Priority",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.partner.port`.
pub static LACP_PARTNER_PORT: FieldDef = FieldDef {
    abbrev: "lacp.partner.port",
    name: "Partner Port",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The port number associated with this link assigned to the port by the Partner (via Management or Admin)",
    generated: false,
};

/// `lacp.partner.state`.
pub static LACP_PARTNER_STATE: FieldDef = FieldDef {
    abbrev: "lacp.partner.state",
    name: "Partner State",
    field_type: FieldType::Uint8,
    parent: "lacp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.partner.state_str`.
pub static LACP_PARTNER_STATE_STR: FieldDef = FieldDef {
    abbrev: "lacp.partner.state_str",
    name: "Partner State Flags",
    field_type: FieldType::String,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `lacp.partner.state.activity`.
pub static LACP_PARTNER_STATE_ACTIVITY: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.activity",
    name: "LACP Activity",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `lacp.partner.state.timeout`.
pub static LACP_PARTNER_STATE_TIMEOUT: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.timeout",
    name: "LACP Timeout",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `lacp.partner.state.aggregation`.
pub static LACP_PARTNER_STATE_AGGREGATION: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.aggregation",
    name: "Aggregation",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `lacp.partner.state.synchronization`.
pub static LACP_PARTNER_STATE_SYNCHRONIZATION: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.synchronization",
    name: "Synchronization",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `lacp.partner.state.collecting`.
pub static LACP_PARTNER_STATE_COLLECTING: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.collecting",
    name: "Collecting",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `lacp.partner.state.distributing`.
pub static LACP_PARTNER_STATE_DISTRIBUTING: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.distributing",
    name: "Distributing",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `lacp.partner.state.defaulted`.
pub static LACP_PARTNER_STATE_DEFAULTED: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.defaulted",
    name: "Defaulted",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "1 = Actor Rx machine is using DEFAULT Partner info, 0 = using info in Rx'd LACPDU",
    generated: false,
};

/// `lacp.partner.state.expired`.
pub static LACP_PARTNER_STATE_EXPIRED: FieldDef = FieldDef {
    abbrev: "lacp.partner.state.expired",
    name: "Expired",
    field_type: FieldType::Boolean,
    parent: "lacp",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `lacp.partner.reserved`.
pub static LACP_PARTNER_RESERVED: FieldDef = FieldDef {
    abbrev: "lacp.partner.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.collector.max_delay`.
pub static LACP_COLLECTOR_MAX_DELAY: FieldDef = FieldDef {
    abbrev: "lacp.collector.max_delay",
    name: "Collector Max Delay",
    field_type: FieldType::Uint16,
    parent: "lacp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The max delay of the station sending the LACPDU (in tens of usecs)",
    generated: false,
};

/// `lacp.coll_reserved`.
pub static LACP_COLL_RESERVED: FieldDef = FieldDef {
    abbrev: "lacp.coll_reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.wrong_tlv_type`.
pub static LACP_WRONG_TLV_TYPE: FieldDef = FieldDef {
    abbrev: "lacp.wrong_tlv_type",
    name: "TLV is not expected type",
    field_type: FieldType::None,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `lacp.wrong_tlv_length`.
pub static LACP_WRONG_TLV_LENGTH: FieldDef = FieldDef {
    abbrev: "lacp.wrong_tlv_length",
    name: "TLV is not expected length",
    field_type: FieldType::None,
    parent: "lacp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

// MARKER fields
/// `marker.version`.
pub static MARKER_VERSION: FieldDef = FieldDef {
    abbrev: "marker.version",
    name: "Version Number",
    field_type: FieldType::Uint8,
    parent: "marker",
    display: Display::Hex,
    bitmask: None,
    blurb: "Marker protocol version",
    generated: false,
};

/// `marker.tlvType`.
pub static MARKER_TLV_TYPE: FieldDef = FieldDef {
    abbrev: "marker.tlvType",
    name: "TLV Type",
    field_type: FieldType::Uint8,
    parent: "marker",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.tlvLen`.
pub static MARKER_TLV_LEN: FieldDef = FieldDef {
    abbrev: "marker.tlvLen",
    name: "TLV Length",
    field_type: FieldType::Uint8,
    parent: "marker",
    display: Display::Hex,
    bitmask: None,
    blurb: "Length of the Actor TLV",
    generated: false,
};

/// `marker.requesterPort`.
pub static MARKER_REQUESTER_PORT: FieldDef = FieldDef {
    abbrev: "marker.requesterPort",
    name: "Requester Port",
    field_type: FieldType::Uint16,
    parent: "marker",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.requesterSystem`.
pub static MARKER_REQUESTER_SYSTEM: FieldDef = FieldDef {
    abbrev: "marker.requesterSystem",
    name: "Requester System",
    field_type: FieldType::Ethernet,
    parent: "marker",
    display: Display::None,
    bitmask: None,
    blurb: "Requester System ID encoded as a MAC address",
    generated: false,
};

/// `marker.requesterTransId`.
pub static MARKER_REQUESTER_TRANS_ID: FieldDef = FieldDef {
    abbrev: "marker.requesterTransId",
    name: "Requester Transaction ID",
    field_type: FieldType::Uint32,
    parent: "marker",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.requesterPad`.
pub static MARKER_REQUESTER_PAD: FieldDef = FieldDef {
    abbrev: "marker.requesterPad",
    name: "Requester Pad",
    field_type: FieldType::Uint32,
    parent: "marker",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.reserved`.
pub static MARKER_RESERVED: FieldDef = FieldDef {
    abbrev: "marker.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "marker",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.wrong_tlv_type`.
pub static MARKER_WRONG_TLV_TYPE: FieldDef = FieldDef {
    abbrev: "marker.wrong_tlv_type",
    name: "TLV is not expected type",
    field_type: FieldType::None,
    parent: "marker",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.wrong_tlv_length`.
pub static MARKER_WRONG_TLV_LENGTH: FieldDef = FieldDef {
    abbrev: "marker.wrong_tlv_length",
    name: "TLV is not expected length",
    field_type: FieldType::None,
    parent: "marker",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `marker.wrong_pad_value`.
pub static MARKER_WRONG_PAD_VALUE: FieldDef = FieldDef {
    abbrev: "marker.wrong_pad_value",
    name: "pad value is not 0",
    field_type: FieldType::None,
    parent: "marker",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

// SLOW fields
/// `slow.subtype`.
pub static SLOW_SUBTYPE: FieldDef = FieldDef {
    abbrev: "slow.subtype",
    name: "Slow Protocols subtype",
    field_type: FieldType::Uint8,
    parent: "slow",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

// STP fields
/// `stp.protocol`.
pub static STP_PROTOCOL_ID: FieldDef = FieldDef {
    abbrev: "stp.protocol",
    name: "Protocol Identifier",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.version`.
pub static STP_VERSION: FieldDef = FieldDef {
    abbrev: "stp.version",
    name: "Protocol Version Identifier",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.type`.
pub static STP_TYPE: FieldDef = FieldDef {
    abbrev: "stp.type",
    name: "BPDU Type",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.flags`.
pub static STP_FLAGS: FieldDef = FieldDef {
    abbrev: "stp.flags",
    name: "BPDU flags",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.flags.tcack`.
pub static STP_FLAGS_TCACK: FieldDef = FieldDef {
    abbrev: "stp.flags.tcack",
    name: "Topology Change Acknowledgment",
    field_type: FieldType::Boolean,
    parent: "stp",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `stp.flags.agreement`.
pub static STP_FLAGS_AGREEMENT: FieldDef = FieldDef {
    abbrev: "stp.flags.agreement",
    name: "Agreement",
    field_type: FieldType::Boolean,
    parent: "stp",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `stp.flags.forwarding`.
pub static STP_FLAGS_FORWARDING: FieldDef = FieldDef {
    abbrev: "stp.flags.forwarding",
    name: "Forwarding",
    field_type: FieldType::Boolean,
    parent: "stp",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `stp.flags.learning`.
pub static STP_FLAGS_LEARNING: FieldDef = FieldDef {
    abbrev: "stp.flags.learning",
    name: "Learning",
    field_type: FieldType::Boolean,
    parent: "stp",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `stp.flags.port_role`.
pub static STP_FLAGS_PORT_ROLE: FieldDef = FieldDef {
    abbrev: "stp.flags.port_role",
    name: "Port Role",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: Some(0xc),
    blurb: "",
    generated: false,
};

/// `stp.flags.proposal`.
pub static STP_FLAGS_PROPOSAL: FieldDef = FieldDef {
    abbrev: "stp.flags.proposal",
    name: "Proposal",
    field_type: FieldType::Boolean,
    parent: "stp",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `stp.flags.tc`.
pub static STP_FLAGS_TC: FieldDef = FieldDef {
    abbrev: "stp.flags.tc",
    name: "Topology Change",
    field_type: FieldType::Boolean,
    parent: "stp",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `stp.root.prio`.
pub static STP_ROOT_PRIO: FieldDef = FieldDef {
    abbrev: "stp.root.prio",
    name: "Root Bridge Priority",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.root.ext`.
pub static STP_ROOT_EXT: FieldDef = FieldDef {
    abbrev: "stp.root.ext",
    name: "Root Bridge System ID Extension",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.root.hw`.
pub static STP_ROOT_HW: FieldDef = FieldDef {
    abbrev: "stp.root.hw",
    name: "Root Bridge System ID",
    field_type: FieldType::Ethernet,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.root.cost`.
pub static STP_ROOT_COST: FieldDef = FieldDef {
    abbrev: "stp.root.cost",
    name: "Root Path Cost",
    field_type: FieldType::Uint32,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.bridge.prio`.
pub static STP_BRIDGE_PRIO: FieldDef = FieldDef {
    abbrev: "stp.bridge.prio",
    name: "Bridge Priority",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.bridge.ext`.
pub static STP_BRIDGE_EXT: FieldDef = FieldDef {
    abbrev: "stp.bridge.ext",
    name: "Bridge System ID Extension",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.bridge.hw`.
pub static STP_BRIDGE_HW: FieldDef = FieldDef {
    abbrev: "stp.bridge.hw",
    name: "Bridge System ID",
    field_type: FieldType::Ethernet,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.port`.
pub static STP_PORT: FieldDef = FieldDef {
    abbrev: "stp.port",
    name: "Port identifier",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.msg_age`.
pub static STP_MSG_AGE: FieldDef = FieldDef {
    abbrev: "stp.msg_age",
    name: "Message Age",
    field_type: FieldType::Double,
    parent: "stp",
    display: Display::Seconds256,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.max_age`.
pub static STP_MAX_AGE: FieldDef = FieldDef {
    abbrev: "stp.max_age",
    name: "Max Age",
    field_type: FieldType::Double,
    parent: "stp",
    display: Display::Seconds256,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.hello`.
pub static STP_HELLO: FieldDef = FieldDef {
    abbrev: "stp.hello",
    name: "Hello Time",
    field_type: FieldType::Double,
    parent: "stp",
    display: Display::Seconds256,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.forward`.
pub static STP_FORWARD: FieldDef = FieldDef {
    abbrev: "stp.forward",
    name: "Forward Delay",
    field_type: FieldType::Double,
    parent: "stp",
    display: Display::Seconds256,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.version_1_length`.
pub static STP_VERSION_1_LENGTH: FieldDef = FieldDef {
    abbrev: "stp.version_1_length",
    name: "Version 1 Length",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `stp.type.unknown`.
pub static STP_TYPE_UNKNOWN: FieldDef = FieldDef {
    abbrev: "stp.type.unknown",
    name: "Unknown BPDU type data",
    field_type: FieldType::None,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.version_3_length`.
pub static MSTP_VERSION_3_LENGTH: FieldDef = FieldDef {
    abbrev: "mstp.version_3_length",
    name: "Version 3 Length",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.config_format_selector`.
pub static MSTP_CONFIG_FORMAT_SELECTOR: FieldDef = FieldDef {
    abbrev: "mstp.config_format_selector",
    name: "MST Config ID format selector",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.config_name`.
pub static MSTP_CONFIG_NAME: FieldDef = FieldDef {
    abbrev: "mstp.config_name",
    name: "MST Config name",
    field_type: FieldType::StringzPad,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.config_revision_level`.
pub static MSTP_CONFIG_REVISION_LEVEL: FieldDef = FieldDef {
    abbrev: "mstp.config_revision_level",
    name: "MST Config revision",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.config_digest`.
pub static MSTP_CONFIG_DIGEST: FieldDef = FieldDef {
    abbrev: "mstp.config_digest",
    name: "MST Config digest",
    field_type: FieldType::Bytes,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.cist_internal_root_path_cost`.
pub static MSTP_CIST_INTERNAL_ROOT_PATH_COST: FieldDef = FieldDef {
    abbrev: "mstp.cist_internal_root_path_cost",
    name: "CIST Internal Root Path Cost",
    field_type: FieldType::Uint32,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.cist_bridge.prio`.
pub static MSTP_CIST_BRIDGE_PRIO: FieldDef = FieldDef {
    abbrev: "mstp.cist_bridge.prio",
    name: "CIST Bridge Priority",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.cist_bridge.ext`.
pub static MSTP_CIST_BRIDGE_EXT: FieldDef = FieldDef {
    abbrev: "mstp.cist_bridge.ext",
    name: "CIST Bridge Identifier System ID Extension",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.cist_bridge.hw`.
pub static MSTP_CIST_BRIDGE_HW: FieldDef = FieldDef {
    abbrev: "mstp.cist_bridge.hw",
    name: "CIST Bridge Identifier System ID",
    field_type: FieldType::Ethernet,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.cist_remaining_hops`.
pub static MSTP_CIST_REMAINING_HOPS: FieldDef = FieldDef {
    abbrev: "mstp.cist_remaining_hops",
    name: "CIST Remaining hops",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.msti.flags`.
pub static MSTP_MSTI_FLAGS: FieldDef = FieldDef {
    abbrev: "mstp.msti.flags",
    name: "MSTI flags",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.msti.priority`.
pub static MSTP_MSTI_PRIORITY: FieldDef = FieldDef {
    abbrev: "mstp.msti.priority",
    name: "Priority",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Hex,
    bitmask: Some(0xf0),
    blurb: "",
    generated: false,
};

/// `mstp.msti.msti_id`.
pub static MSTP_MSTI_MSTI_ID: FieldDef = FieldDef {
    abbrev: "mstp.msti.msti_id",
    name: "MSTID",
    field_type: FieldType::Uint16,
    parent: "stp",
    display: Display::Decimal,
    bitmask: Some(0xfff),
    blurb: "",
    generated: false,
};

/// `mstp.msti.root.hw`.
pub static MSTP_MSTI_ROOT_HW: FieldDef = FieldDef {
    abbrev: "mstp.msti.root.hw",
    name: "Regional Root",
    field_type: FieldType::Ethernet,
    parent: "stp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.msti.root_cost`.
pub static MSTP_MSTI_ROOT_COST: FieldDef = FieldDef {
    abbrev: "mstp.msti.root_cost",
    name: "Internal root path cost",
    field_type: FieldType::Uint32,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.msti.bridge_priority`.
pub static MSTP_MSTI_BRIDGE_PRIORITY: FieldDef = FieldDef {
    abbrev: "mstp.msti.bridge_priority",
    name: "Bridge Identifier Priority",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.msti.port_priority`.
pub static MSTP_MSTI_PORT_PRIORITY: FieldDef = FieldDef {
    abbrev: "mstp.msti.port_priority",
    name: "Port identifier priority",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `mstp.msti.remaining_hops`.
pub static MSTP_MSTI_REMAINING_HOPS: FieldDef = FieldDef {
    abbrev: "mstp.msti.remaining_hops",
    name: "Remaining hops",
    field_type: FieldType::Uint8,
    parent: "stp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// Internet Control Message Protocol v6.
pub static ICMPV6_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "icmpv6",
    long_name: "Internet Control Message Protocol v6",
    short_name: "ICMPv6",
    fields: ICMPV6_FIELDS,
};

/// `bfd.version`.
pub static BFD_VERSION: FieldDef = FieldDef {
    abbrev: "bfd.version",
    name: "Protocol Version",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: Some(0xe0),
    blurb: "The version number of the BFD protocol",
    generated: false,
};

/// `bfd.diag`.
pub static BFD_DIAG: FieldDef = FieldDef {
    abbrev: "bfd.diag",
    name: "Diagnostic Code",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Hex,
    bitmask: Some(0x1f),
    blurb: "This field give the reason for a BFD session failure",
    generated: false,
};

/// `bfd.sta`.
pub static BFD_STA: FieldDef = FieldDef {
    abbrev: "bfd.sta",
    name: "Session State",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Hex,
    bitmask: Some(0xc0),
    blurb: "The BFD state as seen by the transmitting system",
    generated: false,
};

/// `bfd.flags`.
pub static BFD_FLAGS: FieldDef = FieldDef {
    abbrev: "bfd.flags",
    name: "Message Flags",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `bfd.flags.h`.
pub static BFD_FLAGS_H: FieldDef = FieldDef {
    abbrev: "bfd.flags.h",
    name: "I hear you",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `bfd.flags.d`.
pub static BFD_FLAGS_D: FieldDef = FieldDef {
    abbrev: "bfd.flags.d",
    name: "Demand",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `bfd.flags.p`.
pub static BFD_FLAGS_P: FieldDef = FieldDef {
    abbrev: "bfd.flags.p",
    name: "Poll",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `bfd.flags.f`.
pub static BFD_FLAGS_F: FieldDef = FieldDef {
    abbrev: "bfd.flags.f",
    name: "Final",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `bfd.flags.c`.
pub static BFD_FLAGS_C: FieldDef = FieldDef {
    abbrev: "bfd.flags.c",
    name: "Control Plane Independent",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean6,
    bitmask: Some(0x8),
    blurb: "If set, the BFD implementation is implemented in the forwarding plane",
    generated: false,
};

/// `bfd.flags.a`.
pub static BFD_FLAGS_A: FieldDef = FieldDef {
    abbrev: "bfd.flags.a",
    name: "Authentication Present",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean6,
    bitmask: Some(0x4),
    blurb: "The Authentication Section is present",
    generated: false,
};

/// `bfd.flags.m`.
pub static BFD_FLAGS_M: FieldDef = FieldDef {
    abbrev: "bfd.flags.m",
    name: "Multipoint",
    field_type: FieldType::Boolean,
    parent: "bfd",
    display: Display::Boolean6,
    bitmask: Some(0x1),
    blurb: "Reserved for future point-to-multipoint extensions",
    generated: false,
};

/// `bfd.detect_time_multiplier`.
pub static BFD_DETECT_TIME_MULTIPLIER: FieldDef = FieldDef {
    abbrev: "bfd.detect_time_multiplier",
    name: "Detect Time Multiplier",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The transmit interval multiplied by this value is the failure detection time",
    generated: false,
};

/// `bfd.message_length`.
pub static BFD_MESSAGE_LENGTH: FieldDef = FieldDef {
    abbrev: "bfd.message_length",
    name: "Message Length",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of the BFD Control packet, in bytes",
    generated: false,
};

/// `bfd.my_discriminator`.
pub static BFD_MY_DISCRIMINATOR: FieldDef = FieldDef {
    abbrev: "bfd.my_discriminator",
    name: "My Discriminator",
    field_type: FieldType::Uint32,
    parent: "bfd",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `bfd.your_discriminator`.
pub static BFD_YOUR_DISCRIMINATOR: FieldDef = FieldDef {
    abbrev: "bfd.your_discriminator",
    name: "Your Discriminator",
    field_type: FieldType::Uint32,
    parent: "bfd",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `bfd.desired_min_tx_interval`.
pub static BFD_DESIRED_MIN_TX_INTERVAL: FieldDef = FieldDef {
    abbrev: "bfd.desired_min_tx_interval",
    name: "Desired Min TX Interval",
    field_type: FieldType::Uint32,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The minimum interval to use when transmitting BFD Control packets",
    generated: false,
};

/// `bfd.required_min_rx_interval`.
pub static BFD_REQUIRED_MIN_RX_INTERVAL: FieldDef = FieldDef {
    abbrev: "bfd.required_min_rx_interval",
    name: "Required Min RX Interval",
    field_type: FieldType::Uint32,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The minimum interval between received BFD Control packets that this system can support",
    generated: false,
};

/// `bfd.required_min_echo_interval`.
pub static BFD_REQUIRED_MIN_ECHO_INTERVAL: FieldDef = FieldDef {
    abbrev: "bfd.required_min_echo_interval",
    name: "Required Min Echo Interval",
    field_type: FieldType::Uint32,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The minimum interval between received BFD Echo packets that this system can support",
    generated: false,
};

/// `bfd.checksum`.
pub static BFD_CHECKSUM: FieldDef = FieldDef {
    abbrev: "bfd.checksum",
    name: "Checksum",
    field_type: FieldType::Bytes,
    parent: "bfd",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `bfd.auth.type`.
pub static BFD_AUTH_TYPE: FieldDef = FieldDef {
    abbrev: "bfd.auth.type",
    name: "Authentication Type",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The type of authentication in use on this session",
    generated: false,
};

/// `bfd.auth.len`.
pub static BFD_AUTH_LEN: FieldDef = FieldDef {
    abbrev: "bfd.auth.len",
    name: "Authentication Length",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The length, in bytes, of the authentication section",
    generated: false,
};

/// `bfd.auth.key`.
pub static BFD_AUTH_KEY: FieldDef = FieldDef {
    abbrev: "bfd.auth.key",
    name: "Authentication Key ID",
    field_type: FieldType::Uint8,
    parent: "bfd",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The Authentication Key ID, identifies which password is in use for this packet",
    generated: false,
};

/// `bfd.auth.password`.
pub static BFD_AUTH_PASSWORD: FieldDef = FieldDef {
    abbrev: "bfd.auth.password",
    name: "Password",
    field_type: FieldType::String,
    parent: "bfd",
    display: Display::None,
    bitmask: None,
    blurb: "The simple password in use on this session",
    generated: false,
};

/// `bfd.auth.seq_num`.
pub static BFD_AUTH_SEQ_NUM: FieldDef = FieldDef {
    abbrev: "bfd.auth.seq_num",
    name: "Sequence Number",
    field_type: FieldType::Uint32,
    parent: "bfd",
    display: Display::Hex,
    bitmask: None,
    blurb: "The Sequence Number is periodically incremented to prevent replay attacks",
    generated: false,
};

/// `bfd.auth.len.invalid`.
pub static BFD_AUTH_LEN_INVALID: FieldDef = FieldDef {
    abbrev: "bfd.auth.len.invalid",
    name: "Length of authentication section is invalid",
    field_type: FieldType::None,
    parent: "bfd",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `bfd.auth.no_data`.
pub static BFD_AUTH_NO_DATA: FieldDef = FieldDef {
    abbrev: "bfd.auth.no_data",
    name: "Authentication flag is set in a BFD packet, but no authentication data is present",
    field_type: FieldType::None,
    parent: "bfd",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ospf.header`.
pub static OSPF_HEADER: FieldDef = FieldDef {
    abbrev: "ospf.header",
    name: "OSPF Header",
    field_type: FieldType::None,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.version`.
pub static OSPF_VERSION: FieldDef = FieldDef {
    abbrev: "ospf.version",
    name: "Version",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.msg`.
pub static OSPF_MSG: FieldDef = FieldDef {
    abbrev: "ospf.msg",
    name: "Message Type",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.packet_length`.
pub static OSPF_PACKET_LENGTH: FieldDef = FieldDef {
    abbrev: "ospf.packet_length",
    name: "Packet Length",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.srcrouter`.
pub static OSPF_SRCROUTER: FieldDef = FieldDef {
    abbrev: "ospf.srcrouter",
    name: "Source OSPF Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.area_id`.
pub static OSPF_AREA_ID: FieldDef = FieldDef {
    abbrev: "ospf.area_id",
    name: "Area ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.checksum`.
pub static OSPF_CHECKSUM: FieldDef = FieldDef {
    abbrev: "ospf.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.instance_id`.
pub static OSPF_INSTANCE_ID: FieldDef = FieldDef {
    abbrev: "ospf.instance_id",
    name: "Instance ID",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.type`.
pub static OSPF_AUTH_TYPE: FieldDef = FieldDef {
    abbrev: "ospf.auth.type",
    name: "Auth Type",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.none`.
pub static OSPF_AUTH_NONE: FieldDef = FieldDef {
    abbrev: "ospf.auth.none",
    name: "Auth Data (none)",
    field_type: FieldType::Bytes,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.simple`.
pub static OSPF_AUTH_SIMPLE: FieldDef = FieldDef {
    abbrev: "ospf.auth.simple",
    name: "Auth Data (Simple)",
    field_type: FieldType::String,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.crypt.key_id`.
pub static OSPF_AUTH_CRYPT_KEY_ID: FieldDef = FieldDef {
    abbrev: "ospf.auth.crypt.key_id",
    name: "Auth Crypt Key id",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.crypt.data_length`.
pub static OSPF_AUTH_CRYPT_DATA_LENGTH: FieldDef = FieldDef {
    abbrev: "ospf.auth.crypt.data_length",
    name: "Auth Crypt Data Length",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.crypt.seq_nbr`.
pub static OSPF_AUTH_CRYPT_SEQ_NBR: FieldDef = FieldDef {
    abbrev: "ospf.auth.crypt.seq_nbr",
    name: "Auth Crypt Sequence Number",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.crypt.data`.
pub static OSPF_AUTH_CRYPT_DATA: FieldDef = FieldDef {
    abbrev: "ospf.auth.crypt.data",
    name: "Auth Crypt Data",
    field_type: FieldType::Bytes,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.auth.unknown`.
pub static OSPF_AUTH_UNKNOWN: FieldDef = FieldDef {
    abbrev: "ospf.auth.unknown",
    name: "Auth Unknown",
    field_type: FieldType::Bytes,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.instance_id`.
pub static OSPF_V3_INSTANCE_ID: FieldDef = FieldDef {
    abbrev: "ospf.v3.instance_id",
    name: "Instance ID",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.reserved`.
pub static OSPF_RESERVED: FieldDef = FieldDef {
    abbrev: "ospf.reserved",
    name: "Reserved",
    field_type: FieldType::Bytes,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "Must be zero",
    generated: false,
};

/// `ospf.msg.hello`.
pub static OSPF_MSG_HELLO: FieldDef = FieldDef {
    abbrev: "ospf.msg.hello",
    name: "Hello",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.msg.dbdesc`.
pub static OSPF_MSG_DBDESC: FieldDef = FieldDef {
    abbrev: "ospf.msg.dbdesc",
    name: "Database Description",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.msg.lsreq`.
pub static OSPF_MSG_LSREQ: FieldDef = FieldDef {
    abbrev: "ospf.msg.lsreq",
    name: "Link State Adv Request",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.msg.lsupdate`.
pub static OSPF_MSG_LSUPDATE: FieldDef = FieldDef {
    abbrev: "ospf.msg.lsupdate",
    name: "Link State Adv Update",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.msg.lsack`.
pub static OSPF_MSG_LSACK: FieldDef = FieldDef {
    abbrev: "ospf.msg.lsack",
    name: "Link State Adv Acknowledgement",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello`.
pub static OSPF_HELLO: FieldDef = FieldDef {
    abbrev: "ospf.hello",
    name: "OSPF Hello Packet",
    field_type: FieldType::None,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.network_mask`.
pub static OSPF_HELLO_NETWORK_MASK: FieldDef = FieldDef {
    abbrev: "ospf.hello.network_mask",
    name: "Network Mask",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.interface_id`.
pub static OSPF_HELLO_INTERFACE_ID: FieldDef = FieldDef {
    abbrev: "ospf.hello.interface_id",
    name: "Interface ID",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.hello_interval`.
pub static OSPF_HELLO_HELLO_INTERVAL: FieldDef = FieldDef {
    abbrev: "ospf.hello.hello_interval",
    name: "Hello Interval [sec]",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.router_priority`.
pub static OSPF_HELLO_ROUTER_PRIORITY: FieldDef = FieldDef {
    abbrev: "ospf.hello.router_priority",
    name: "Router Priority",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.router_dead_interval`.
pub static OSPF_HELLO_ROUTER_DEAD_INTERVAL: FieldDef = FieldDef {
    abbrev: "ospf.hello.router_dead_interval",
    name: "Router Dead Interval [sec]",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.designated_router`.
pub static OSPF_HELLO_DESIGNATED_ROUTER: FieldDef = FieldDef {
    abbrev: "ospf.hello.designated_router",
    name: "Designated Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.backup_designated_router`.
pub static OSPF_HELLO_BACKUP_DESIGNATED_ROUTER: FieldDef = FieldDef {
    abbrev: "ospf.hello.backup_designated_router",
    name: "Backup Designated Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.hello.active_neighbor`.
pub static OSPF_HELLO_ACTIVE_NEIGHBOR: FieldDef = FieldDef {
    abbrev: "ospf.hello.active_neighbor",
    name: "Active Neighbor",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa`.
pub static OSPF_LSA: FieldDef = FieldDef {
    abbrev: "ospf.lsa",
    name: "LS Type",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.age`.
pub static OSPF_LSA_AGE: FieldDef = FieldDef {
    abbrev: "ospf.lsa.age",
    name: "LS Age (seconds)",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: Some(0xffffffffffff7fff),
    blurb: "",
    generated: false,
};

/// `ospf.lsa.donotage`.
pub static OSPF_LSA_DONOTAGE: FieldDef = FieldDef {
    abbrev: "ospf.lsa.donotage",
    name: "Do Not Age Flag",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `ospf.lsa.id`.
pub static OSPF_LSA_ID: FieldDef = FieldDef {
    abbrev: "ospf.lsa.id",
    name: "Link State ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.seqnum`.
pub static OSPF_LSA_SEQNUM: FieldDef = FieldDef {
    abbrev: "ospf.lsa.seqnum",
    name: "Sequence Number",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.chksum`.
pub static OSPF_LSA_CHKSUM: FieldDef = FieldDef {
    abbrev: "ospf.lsa.chksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.length`.
pub static OSPF_LSA_LENGTH: FieldDef = FieldDef {
    abbrev: "ospf.lsa.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.router`.
pub static OSPF_LSA_ROUTER: FieldDef = FieldDef {
    abbrev: "ospf.lsa.router",
    name: "Router LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.router.linktype`.
pub static OSPF_LSA_ROUTER_LINKTYPE: FieldDef = FieldDef {
    abbrev: "ospf.lsa.router.linktype",
    name: "Link Type",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.router.linkid`.
pub static OSPF_LSA_ROUTER_LINKID: FieldDef = FieldDef {
    abbrev: "ospf.lsa.router.linkid",
    name: "Link ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.router.linkdata`.
pub static OSPF_LSA_ROUTER_LINKDATA: FieldDef = FieldDef {
    abbrev: "ospf.lsa.router.linkdata",
    name: "Link Data",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.router.nummetrics`.
pub static OSPF_LSA_ROUTER_NUMMETRICS: FieldDef = FieldDef {
    abbrev: "ospf.lsa.router.nummetrics",
    name: "Number of Metrics",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.router.metric0`.
pub static OSPF_LSA_ROUTER_METRIC0: FieldDef = FieldDef {
    abbrev: "ospf.lsa.router.metric0",
    name: "0 Metric",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.network`.
pub static OSPF_LSA_NETWORK: FieldDef = FieldDef {
    abbrev: "ospf.lsa.network",
    name: "Network LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.network.netmask`.
pub static OSPF_LSA_NETWORK_NETMASK: FieldDef = FieldDef {
    abbrev: "ospf.lsa.network.netmask",
    name: "Netmask",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.network.attchrtr`.
pub static OSPF_LSA_NETWORK_ATTCHRTR: FieldDef = FieldDef {
    abbrev: "ospf.lsa.network.attchrtr",
    name: "Attached Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.summary`.
pub static OSPF_LSA_SUMMARY: FieldDef = FieldDef {
    abbrev: "ospf.lsa.summary",
    name: "Summary LSA (IP Network)",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asbr`.
pub static OSPF_LSA_ASBR: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asbr",
    name: "Summary LSA (ASBR)",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asbr.netmask`.
pub static OSPF_LSA_ASBR_NETMASK: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asbr.netmask",
    name: "Netmask",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asext`.
pub static OSPF_LSA_ASEXT: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asext",
    name: "AS-External LSA (ASBR)",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asext.netmask`.
pub static OSPF_LSA_ASEXT_NETMASK: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asext.netmask",
    name: "Netmask",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asext.fwdaddr`.
pub static OSPF_LSA_ASEXT_FWDADDR: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asext.fwdaddr",
    name: "Forwarding Address",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asext.extrttag`.
pub static OSPF_LSA_ASEXT_EXTRTTAG: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asext.extrttag",
    name: "External Route Tag",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa`.
pub static OSPF_V3_LSA: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa",
    name: "LS Type",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.u`.
pub static OSPF_V3_LSA_U: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.u",
    name: "LSA Handling",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.s12`.
pub static OSPF_V3_LSA_S12: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.s12",
    name: "Flooding Scope",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Hex,
    bitmask: Some(0x6000),
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.fc`.
pub static OSPF_V3_LSA_FC: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.fc",
    name: "Function Code",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: Some(0x1fff),
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.router`.
pub static OSPF_V3_LSA_ROUTER: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.router",
    name: "Router-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.network`.
pub static OSPF_V3_LSA_NETWORK: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.network",
    name: "Network-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.interprefix`.
pub static OSPF_V3_LSA_INTERPREFIX: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.interprefix",
    name: "Inter-Area-Prefix-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.interrouter`.
pub static OSPF_V3_LSA_INTERROUTER: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.interrouter",
    name: "Inter-Area-Router-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.asext`.
pub static OSPF_V3_LSA_ASEXT: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.asext",
    name: "AS-External-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.link`.
pub static OSPF_V3_LSA_LINK: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.link",
    name: "Link-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.intraprefix`.
pub static OSPF_V3_LSA_INTRAPREFIX: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.intraprefix",
    name: "Intra-Area-Prefix-LSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.advrouter`.
pub static OSPF_ADVROUTER: FieldDef = FieldDef {
    abbrev: "ospf.advrouter",
    name: "Advertising Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v2.options`.
pub static OSPF_V2_OPTIONS: FieldDef = FieldDef {
    abbrev: "ospf.v2.options",
    name: "Options",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.mt`.
pub static OSPF_V2_OPTIONS_MT: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.mt",
    name: "(MT) Multi-Topology Routing",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.e`.
pub static OSPF_V2_OPTIONS_E: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.e",
    name: "(E) External Routing",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.mc`.
pub static OSPF_V2_OPTIONS_MC: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.mc",
    name: "(MC) Multicast",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.n`.
pub static OSPF_V2_OPTIONS_N: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.n",
    name: "(N) NSSA",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.p`.
pub static OSPF_V2_OPTIONS_P: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.p",
    name: "(P) Propagate",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.l`.
pub static OSPF_V2_OPTIONS_L: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.l",
    name: "(L) LLS Data block",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.dc`.
pub static OSPF_V2_OPTIONS_DC: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.dc",
    name: "(DC) Demand Circuits",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.o`.
pub static OSPF_V2_OPTIONS_O: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.o",
    name: "(O) Opaque",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `ospf.v2.options.dn`.
pub static OSPF_V2_OPTIONS_DN: FieldDef = FieldDef {
    abbrev: "ospf.v2.options.dn",
    name: "DN",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options`.
pub static OSPF_V3_OPTIONS: FieldDef = FieldDef {
    abbrev: "ospf.v3.options",
    name: "Options",
    field_type: FieldType::Uint24,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.v6`.
pub static OSPF_V3_OPTIONS_V6: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.v6",
    name: "V6",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.e`.
pub static OSPF_V3_OPTIONS_E: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.e",
    name: "E",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.mc`.
pub static OSPF_V3_OPTIONS_MC: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.mc",
    name: "MC",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.n`.
pub static OSPF_V3_OPTIONS_N: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.n",
    name: "N",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.r`.
pub static OSPF_V3_OPTIONS_R: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.r",
    name: "R",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.dc`.
pub static OSPF_V3_OPTIONS_DC: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.dc",
    name: "DC",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.af`.
pub static OSPF_V3_OPTIONS_AF: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.af",
    name: "AF",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x100),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.l`.
pub static OSPF_V3_OPTIONS_L: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.l",
    name: "L",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x200),
    blurb: "",
    generated: false,
};

/// `ospf.v3.options.at`.
pub static OSPF_V3_OPTIONS_AT: FieldDef = FieldDef {
    abbrev: "ospf.v3.options.at",
    name: "AT",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean24,
    bitmask: Some(0x400),
    blurb: "",
    generated: false,
};

/// `ospf.dbd`.
pub static OSPF_DBD: FieldDef = FieldDef {
    abbrev: "ospf.dbd",
    name: "DB Description",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.dbd.r`.
pub static OSPF_DBD_R: FieldDef = FieldDef {
    abbrev: "ospf.dbd.r",
    name: "(R) OOBResync",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.dbd.i`.
pub static OSPF_DBD_I: FieldDef = FieldDef {
    abbrev: "ospf.dbd.i",
    name: "(I) Init",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.dbd.m`.
pub static OSPF_DBD_M: FieldDef = FieldDef {
    abbrev: "ospf.dbd.m",
    name: "(M) More",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.dbd.ms`.
pub static OSPF_DBD_MS: FieldDef = FieldDef {
    abbrev: "ospf.dbd.ms",
    name: "(MS) Master",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags`.
pub static OSPF_V2_ROUTER_LSA_FLAGS: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.b`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_B: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.b",
    name: "(B) Area border router",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.e`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_E: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.e",
    name: "(E) AS boundary router",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.v`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_V: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.v",
    name: "(V) Virtual link endpoint",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.w`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_W: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.w",
    name: "(W) Wild-card multicast receiver",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.n`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_N: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.n",
    name: "(N) NSSA translation",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.s`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_S: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.s",
    name: "(S) Shortcut-capable ABR",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `ospf.v2.router.lsa.flags.h`.
pub static OSPF_V2_ROUTER_LSA_FLAGS_H: FieldDef = FieldDef {
    abbrev: "ospf.v2.router.lsa.flags.h",
    name: "(H) Host",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `ospf.v3.router.lsa.flags`.
pub static OSPF_V3_ROUTER_LSA_FLAGS: FieldDef = FieldDef {
    abbrev: "ospf.v3.router.lsa.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.router.lsa.flags.b`.
pub static OSPF_V3_ROUTER_LSA_FLAGS_B: FieldDef = FieldDef {
    abbrev: "ospf.v3.router.lsa.flags.b",
    name: "(B) Area border router",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v3.router.lsa.flags.e`.
pub static OSPF_V3_ROUTER_LSA_FLAGS_E: FieldDef = FieldDef {
    abbrev: "ospf.v3.router.lsa.flags.e",
    name: "(E) AS boundary router",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.v3.router.lsa.flags.v`.
pub static OSPF_V3_ROUTER_LSA_FLAGS_V: FieldDef = FieldDef {
    abbrev: "ospf.v3.router.lsa.flags.v",
    name: "(V) Virtual link endpoint",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.v3.router.lsa.flags.w`.
pub static OSPF_V3_ROUTER_LSA_FLAGS_W: FieldDef = FieldDef {
    abbrev: "ospf.v3.router.lsa.flags.w",
    name: "(W) Wild-card multicast receiver",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.v3.as.external.flags`.
pub static OSPF_V3_AS_EXTERNAL_FLAGS: FieldDef = FieldDef {
    abbrev: "ospf.v3.as.external.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.as.external.flags.t`.
pub static OSPF_V3_AS_EXTERNAL_FLAGS_T: FieldDef = FieldDef {
    abbrev: "ospf.v3.as.external.flags.t",
    name: "(T) External Route Tag",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v3.as.external.flags.f`.
pub static OSPF_V3_AS_EXTERNAL_FLAGS_F: FieldDef = FieldDef {
    abbrev: "ospf.v3.as.external.flags.f",
    name: "(F) Forwarding Address",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.v3.as.external.flags.e`.
pub static OSPF_V3_AS_EXTERNAL_FLAGS_E: FieldDef = FieldDef {
    abbrev: "ospf.v3.as.external.flags.e",
    name: "(E) External Metric",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.v3.prefix.options`.
pub static OSPF_V3_PREFIX_OPTIONS: FieldDef = FieldDef {
    abbrev: "ospf.v3.prefix.options",
    name: "PrefixOptions",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.prefix.options.nu`.
pub static OSPF_V3_PREFIX_OPTIONS_NU: FieldDef = FieldDef {
    abbrev: "ospf.v3.prefix.options.nu",
    name: "(NU) NoUnicast",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `ospf.v3.prefix.options.la`.
pub static OSPF_V3_PREFIX_OPTIONS_LA: FieldDef = FieldDef {
    abbrev: "ospf.v3.prefix.options.la",
    name: "(LA) Local Address",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `ospf.v3.prefix.options.mc`.
pub static OSPF_V3_PREFIX_OPTIONS_MC: FieldDef = FieldDef {
    abbrev: "ospf.v3.prefix.options.mc",
    name: "(MC) Multicast",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `ospf.v3.prefix.options.p`.
pub static OSPF_V3_PREFIX_OPTIONS_P: FieldDef = FieldDef {
    abbrev: "ospf.v3.prefix.options.p",
    name: "(P) Propagate",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `ospf.db.interface_mtu`.
pub static OSPF_DB_INTERFACE_MTU: FieldDef = FieldDef {
    abbrev: "ospf.db.interface_mtu",
    name: "Interface MTU",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.db.dd_sequence`.
pub static OSPF_DB_DD_SEQUENCE: FieldDef = FieldDef {
    abbrev: "ospf.db.dd_sequence",
    name: "DD Sequence",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.link_state_id`.
pub static OSPF_LINK_STATE_ID: FieldDef = FieldDef {
    abbrev: "ospf.link_state_id",
    name: "Link State ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.ls.number_of_lsas`.
pub static OSPF_LS_NUMBER_OF_LSAS: FieldDef = FieldDef {
    abbrev: "ospf.ls.number_of_lsas",
    name: "Number of LSAs",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.number_of_links`.
pub static OSPF_LSA_NUMBER_OF_LINKS: FieldDef = FieldDef {
    abbrev: "ospf.lsa.number_of_links",
    name: "Number of Links",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.do_not_age`.
pub static OSPF_V3_LSA_DO_NOT_AGE: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.do_not_age",
    name: "Do Not Age",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.interface_id`.
pub static OSPF_V3_LSA_INTERFACE_ID: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.interface_id",
    name: "Interface ID",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.neighbor_interface_id`.
pub static OSPF_V3_LSA_NEIGHBOR_INTERFACE_ID: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.neighbor_interface_id",
    name: "Neighbor Interface ID",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.neighbor_router_id`.
pub static OSPF_V3_LSA_NEIGHBOR_ROUTER_ID: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.neighbor_router_id",
    name: "Neighbor Router ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.attached_router`.
pub static OSPF_V3_LSA_ATTACHED_ROUTER: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.attached_router",
    name: "Attached Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.destination_router_id`.
pub static OSPF_V3_LSA_DESTINATION_ROUTER_ID: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.destination_router_id",
    name: "Destination Router ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.referenced_ls_type`.
pub static OSPF_V3_LSA_REFERENCED_LS_TYPE: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.referenced_ls_type",
    name: "Referenced LS type",
    field_type: FieldType::Uint16,
    parent: "ospf",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.forwarding_address.ipv6`.
pub static OSPF_V3_LSA_FORWARDING_ADDRESS_IPV6: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.forwarding_address.ipv6",
    name: "Forwarding Address",
    field_type: FieldType::Ipv6,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.external_route_tag`.
pub static OSPF_V3_LSA_EXTERNAL_ROUTE_TAG: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.external_route_tag",
    name: "External Route Tag",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.referenced_link_state_id`.
pub static OSPF_V3_LSA_REFERENCED_LINK_STATE_ID: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.referenced_link_state_id",
    name: "Referenced Link State ID",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.router_priority`.
pub static OSPF_V3_LSA_ROUTER_PRIORITY: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.router_priority",
    name: "Router Priority",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.link_local_interface_address.ipv6`.
pub static OSPF_V3_LSA_LINK_LOCAL_INTERFACE_ADDRESS_IPV6: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.link_local_interface_address.ipv6",
    name: "Link-local Interface Address",
    field_type: FieldType::Ipv6,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.referenced_advertising_router`.
pub static OSPF_V3_LSA_REFERENCED_ADVERTISING_ROUTER: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.referenced_advertising_router",
    name: "Referenced Advertising Router",
    field_type: FieldType::Ipv4,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.lsa.asext.type`.
pub static OSPF_LSA_ASEXT_TYPE: FieldDef = FieldDef {
    abbrev: "ospf.lsa.asext.type",
    name: "External Type",
    field_type: FieldType::Boolean,
    parent: "ospf",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `ospf.lsa.tos`.
pub static OSPF_LSA_TOS: FieldDef = FieldDef {
    abbrev: "ospf.lsa.tos",
    name: "TOS",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.type`.
pub static OSPF_V3_LSA_TYPE: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.metric`.
pub static OSPF_METRIC: FieldDef = FieldDef {
    abbrev: "ospf.metric",
    name: "Metric",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.prefix_length`.
pub static OSPF_PREFIX_LENGTH: FieldDef = FieldDef {
    abbrev: "ospf.prefix_length",
    name: "PrefixLength",
    field_type: FieldType::Uint8,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.ls.metric`.
pub static OSPF_LS_METRIC: FieldDef = FieldDef {
    abbrev: "ospf.ls.metric",
    name: "Metric",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.lsa.num_prefixes`.
pub static OSPF_V3_LSA_NUM_PREFIXES: FieldDef = FieldDef {
    abbrev: "ospf.v3.lsa.num_prefixes",
    name: "# prefixes",
    field_type: FieldType::Uint32,
    parent: "ospf",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.v3.address_prefix.ipv6`.
pub static OSPF_V3_ADDRESS_PREFIX_IPV6: FieldDef = FieldDef {
    abbrev: "ospf.v3.address_prefix.ipv6",
    name: "Address Prefix",
    field_type: FieldType::Ipv6,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `ospf.reserved.not_zero`.
pub static OSPF_RESERVED_NOT_ZERO: FieldDef = FieldDef {
    abbrev: "ospf.reserved.not_zero",
    name: "incorrect, should be 0",
    field_type: FieldType::None,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ospf.lsa.invalid_length`.
pub static OSPF_LSA_INVALID_LENGTH: FieldDef = FieldDef {
    abbrev: "ospf.lsa.invalid_length",
    name: "Invalid length",
    field_type: FieldType::None,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `ospf.lsa.unknown_type`.
pub static OSPF_LSA_UNKNOWN_TYPE: FieldDef = FieldDef {
    abbrev: "ospf.lsa.unknown_type",
    name: "Unknown LSA Type",
    field_type: FieldType::None,
    parent: "ospf",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `vrrp.typever`.
pub static VRRP_TYPEVER: FieldDef = FieldDef {
    abbrev: "vrrp.typever",
    name: "VRRP message version and type",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `vrrp.version`.
pub static VRRP_VERSION: FieldDef = FieldDef {
    abbrev: "vrrp.version",
    name: "VRRP protocol version",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: Some(0xf0),
    blurb: "",
    generated: false,
};

/// `vrrp.type`.
pub static VRRP_TYPE: FieldDef = FieldDef {
    abbrev: "vrrp.type",
    name: "VRRP packet type",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: Some(0xf),
    blurb: "",
    generated: false,
};

/// `vrrp.virt_rtr_id`.
pub static VRRP_VIRT_RTR_ID: FieldDef = FieldDef {
    abbrev: "vrrp.virt_rtr_id",
    name: "Virtual Rtr ID",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Virtual router this packet is reporting status for",
    generated: false,
};

/// `vrrp.prio`.
pub static VRRP_PRIO: FieldDef = FieldDef {
    abbrev: "vrrp.prio",
    name: "Priority",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Sending VRRP router's priority for the virtual router",
    generated: false,
};

/// `vrrp.addr_count`.
pub static VRRP_ADDR_COUNT: FieldDef = FieldDef {
    abbrev: "vrrp.addr_count",
    name: "Addr Count",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The number of addresses contained in this VRRP advertisement",
    generated: false,
};

/// `vrrp.checksum`.
pub static VRRP_CHECKSUM: FieldDef = FieldDef {
    abbrev: "vrrp.checksum",
    name: "Checksum",
    field_type: FieldType::Uint16,
    parent: "vrrp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Used to detect data corruption in the VRRP message",
    generated: false,
};

/// `vrrp.checksum.status`.
pub static VRRP_CHECKSUM_STATUS: FieldDef = FieldDef {
    abbrev: "vrrp.checksum.status",
    name: "Checksum Status",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::BaseNone,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `vrrp.auth_type`.
pub static VRRP_AUTH_TYPE: FieldDef = FieldDef {
    abbrev: "vrrp.auth_type",
    name: "Auth Type",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The authentication method being utilized",
    generated: false,
};

/// `vrrp.adver_int`.
pub static VRRP_ADVER_INT: FieldDef = FieldDef {
    abbrev: "vrrp.adver_int",
    name: "Adver Int",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Time interval (in seconds) between ADVERTISEMENTS",
    generated: false,
};

/// `vrrp.reserved_mbz`.
pub static VRRP_RESERVED_MBZ: FieldDef = FieldDef {
    abbrev: "vrrp.reserved_mbz",
    name: "Reserved",
    field_type: FieldType::Uint8,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: Some(0xf0),
    blurb: "Must be zero",
    generated: false,
};

/// `vrrp.short_adver_int`.
pub static VRRP_SHORT_ADVER_INT: FieldDef = FieldDef {
    abbrev: "vrrp.short_adver_int",
    name: "Adver Int",
    field_type: FieldType::Uint16,
    parent: "vrrp",
    display: Display::Decimal,
    bitmask: Some(0xfff),
    blurb: "Time interval (in centiseconds) between ADVERTISEMENTS",
    generated: false,
};

/// `vrrp.ip_addr`.
pub static VRRP_IP_ADDR: FieldDef = FieldDef {
    abbrev: "vrrp.ip_addr",
    name: "IP Address",
    field_type: FieldType::Ipv4,
    parent: "vrrp",
    display: Display::None,
    bitmask: None,
    blurb: "IP address associated with the virtual router",
    generated: false,
};

/// `vrrp.ipv6_addr`.
pub static VRRP_IPV6_ADDR: FieldDef = FieldDef {
    abbrev: "vrrp.ipv6_addr",
    name: "IPv6 Address",
    field_type: FieldType::Ipv6,
    parent: "vrrp",
    display: Display::None,
    bitmask: None,
    blurb: "IPv6 address associated with the virtual router",
    generated: false,
};

/// `vrrp.auth_string`.
pub static VRRP_AUTH_STRING: FieldDef = FieldDef {
    abbrev: "vrrp.auth_string",
    name: "Authentication String",
    field_type: FieldType::String,
    parent: "vrrp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `vrrp.md5_auth_data`.
pub static VRRP_MD5_AUTH_DATA: FieldDef = FieldDef {
    abbrev: "vrrp.md5_auth_data",
    name: "MD5 Authentication Data",
    field_type: FieldType::Bytes,
    parent: "vrrp",
    display: Display::None,
    bitmask: None,
    blurb: "MD5 digest string is contained.",
    generated: false,
};

/// `vrrp.checksum_bad.expert`.
pub static VRRP_CHECKSUM_BAD_EXPERT: FieldDef = FieldDef {
    abbrev: "vrrp.checksum_bad.expert",
    name: "Bad checksum",
    field_type: FieldType::None,
    parent: "vrrp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `bfd_echo.packet`.
pub static BFD_ECHO_PACKET: FieldDef = FieldDef {
    abbrev: "bfd_echo.packet",
    name: "Echo",
    field_type: FieldType::Bytes,
    parent: "bfd_echo",
    display: Display::None,
    bitmask: None,
    blurb: "Originator specific echo packet",
    generated: false,
};

static BFD_FIELDS: &[&FieldDef] = &[
    &BFD_VERSION,
    &BFD_DIAG,
    &BFD_STA,
    &BFD_FLAGS,
    &BFD_FLAGS_H,
    &BFD_FLAGS_D,
    &BFD_FLAGS_P,
    &BFD_FLAGS_F,
    &BFD_FLAGS_C,
    &BFD_FLAGS_A,
    &BFD_FLAGS_M,
    &BFD_DETECT_TIME_MULTIPLIER,
    &BFD_MESSAGE_LENGTH,
    &BFD_MY_DISCRIMINATOR,
    &BFD_YOUR_DISCRIMINATOR,
    &BFD_DESIRED_MIN_TX_INTERVAL,
    &BFD_REQUIRED_MIN_RX_INTERVAL,
    &BFD_REQUIRED_MIN_ECHO_INTERVAL,
    &BFD_CHECKSUM,
    &BFD_AUTH_TYPE,
    &BFD_AUTH_LEN,
    &BFD_AUTH_KEY,
    &BFD_AUTH_PASSWORD,
    &BFD_AUTH_SEQ_NUM,
    &BFD_AUTH_LEN_INVALID,
    &BFD_AUTH_NO_DATA,
];

static OSPF_FIELDS: &[&FieldDef] = &[
    &OSPF_HEADER,
    &OSPF_VERSION,
    &OSPF_MSG,
    &OSPF_PACKET_LENGTH,
    &OSPF_SRCROUTER,
    &OSPF_AREA_ID,
    &OSPF_CHECKSUM,
    &OSPF_INSTANCE_ID,
    &OSPF_AUTH_TYPE,
    &OSPF_AUTH_NONE,
    &OSPF_AUTH_SIMPLE,
    &OSPF_AUTH_CRYPT_KEY_ID,
    &OSPF_AUTH_CRYPT_DATA_LENGTH,
    &OSPF_AUTH_CRYPT_SEQ_NBR,
    &OSPF_AUTH_CRYPT_DATA,
    &OSPF_AUTH_UNKNOWN,
    &OSPF_V3_INSTANCE_ID,
    &OSPF_RESERVED,
    &OSPF_MSG_HELLO,
    &OSPF_MSG_DBDESC,
    &OSPF_MSG_LSREQ,
    &OSPF_MSG_LSUPDATE,
    &OSPF_MSG_LSACK,
    &OSPF_HELLO,
    &OSPF_HELLO_NETWORK_MASK,
    &OSPF_HELLO_INTERFACE_ID,
    &OSPF_HELLO_HELLO_INTERVAL,
    &OSPF_HELLO_ROUTER_PRIORITY,
    &OSPF_HELLO_ROUTER_DEAD_INTERVAL,
    &OSPF_HELLO_DESIGNATED_ROUTER,
    &OSPF_HELLO_BACKUP_DESIGNATED_ROUTER,
    &OSPF_HELLO_ACTIVE_NEIGHBOR,
    &OSPF_LSA,
    &OSPF_LSA_AGE,
    &OSPF_LSA_DONOTAGE,
    &OSPF_LSA_ID,
    &OSPF_LSA_SEQNUM,
    &OSPF_LSA_CHKSUM,
    &OSPF_LSA_LENGTH,
    &OSPF_LSA_ROUTER,
    &OSPF_LSA_ROUTER_LINKTYPE,
    &OSPF_LSA_ROUTER_LINKID,
    &OSPF_LSA_ROUTER_LINKDATA,
    &OSPF_LSA_ROUTER_NUMMETRICS,
    &OSPF_LSA_ROUTER_METRIC0,
    &OSPF_LSA_NETWORK,
    &OSPF_LSA_NETWORK_NETMASK,
    &OSPF_LSA_NETWORK_ATTCHRTR,
    &OSPF_LSA_SUMMARY,
    &OSPF_LSA_ASBR,
    &OSPF_LSA_ASBR_NETMASK,
    &OSPF_LSA_ASEXT,
    &OSPF_LSA_ASEXT_NETMASK,
    &OSPF_LSA_ASEXT_FWDADDR,
    &OSPF_LSA_ASEXT_EXTRTTAG,
    &OSPF_V3_LSA,
    &OSPF_V3_LSA_U,
    &OSPF_V3_LSA_S12,
    &OSPF_V3_LSA_FC,
    &OSPF_V3_LSA_ROUTER,
    &OSPF_V3_LSA_NETWORK,
    &OSPF_V3_LSA_INTERPREFIX,
    &OSPF_V3_LSA_INTERROUTER,
    &OSPF_V3_LSA_ASEXT,
    &OSPF_V3_LSA_LINK,
    &OSPF_V3_LSA_INTRAPREFIX,
    &OSPF_ADVROUTER,
    &OSPF_V2_OPTIONS,
    &OSPF_V2_OPTIONS_MT,
    &OSPF_V2_OPTIONS_E,
    &OSPF_V2_OPTIONS_MC,
    &OSPF_V2_OPTIONS_N,
    &OSPF_V2_OPTIONS_P,
    &OSPF_V2_OPTIONS_L,
    &OSPF_V2_OPTIONS_DC,
    &OSPF_V2_OPTIONS_O,
    &OSPF_V2_OPTIONS_DN,
    &OSPF_V3_OPTIONS,
    &OSPF_V3_OPTIONS_V6,
    &OSPF_V3_OPTIONS_E,
    &OSPF_V3_OPTIONS_MC,
    &OSPF_V3_OPTIONS_N,
    &OSPF_V3_OPTIONS_R,
    &OSPF_V3_OPTIONS_DC,
    &OSPF_V3_OPTIONS_AF,
    &OSPF_V3_OPTIONS_L,
    &OSPF_V3_OPTIONS_AT,
    &OSPF_DBD,
    &OSPF_DBD_R,
    &OSPF_DBD_I,
    &OSPF_DBD_M,
    &OSPF_DBD_MS,
    &OSPF_V2_ROUTER_LSA_FLAGS,
    &OSPF_V2_ROUTER_LSA_FLAGS_B,
    &OSPF_V2_ROUTER_LSA_FLAGS_E,
    &OSPF_V2_ROUTER_LSA_FLAGS_V,
    &OSPF_V2_ROUTER_LSA_FLAGS_W,
    &OSPF_V2_ROUTER_LSA_FLAGS_N,
    &OSPF_V2_ROUTER_LSA_FLAGS_S,
    &OSPF_V2_ROUTER_LSA_FLAGS_H,
    &OSPF_V3_ROUTER_LSA_FLAGS,
    &OSPF_V3_ROUTER_LSA_FLAGS_B,
    &OSPF_V3_ROUTER_LSA_FLAGS_E,
    &OSPF_V3_ROUTER_LSA_FLAGS_V,
    &OSPF_V3_ROUTER_LSA_FLAGS_W,
    &OSPF_V3_AS_EXTERNAL_FLAGS,
    &OSPF_V3_AS_EXTERNAL_FLAGS_T,
    &OSPF_V3_AS_EXTERNAL_FLAGS_F,
    &OSPF_V3_AS_EXTERNAL_FLAGS_E,
    &OSPF_V3_PREFIX_OPTIONS,
    &OSPF_V3_PREFIX_OPTIONS_NU,
    &OSPF_V3_PREFIX_OPTIONS_LA,
    &OSPF_V3_PREFIX_OPTIONS_MC,
    &OSPF_V3_PREFIX_OPTIONS_P,
    &OSPF_DB_INTERFACE_MTU,
    &OSPF_DB_DD_SEQUENCE,
    &OSPF_LINK_STATE_ID,
    &OSPF_LS_NUMBER_OF_LSAS,
    &OSPF_LSA_NUMBER_OF_LINKS,
    &OSPF_V3_LSA_DO_NOT_AGE,
    &OSPF_V3_LSA_INTERFACE_ID,
    &OSPF_V3_LSA_NEIGHBOR_INTERFACE_ID,
    &OSPF_V3_LSA_NEIGHBOR_ROUTER_ID,
    &OSPF_V3_LSA_ATTACHED_ROUTER,
    &OSPF_V3_LSA_DESTINATION_ROUTER_ID,
    &OSPF_V3_LSA_REFERENCED_LS_TYPE,
    &OSPF_V3_LSA_FORWARDING_ADDRESS_IPV6,
    &OSPF_V3_LSA_EXTERNAL_ROUTE_TAG,
    &OSPF_V3_LSA_REFERENCED_LINK_STATE_ID,
    &OSPF_V3_LSA_ROUTER_PRIORITY,
    &OSPF_V3_LSA_LINK_LOCAL_INTERFACE_ADDRESS_IPV6,
    &OSPF_V3_LSA_REFERENCED_ADVERTISING_ROUTER,
    &OSPF_LSA_ASEXT_TYPE,
    &OSPF_LSA_TOS,
    &OSPF_V3_LSA_TYPE,
    &OSPF_METRIC,
    &OSPF_PREFIX_LENGTH,
    &OSPF_LS_METRIC,
    &OSPF_V3_LSA_NUM_PREFIXES,
    &OSPF_V3_ADDRESS_PREFIX_IPV6,
    &OSPF_RESERVED_NOT_ZERO,
    &OSPF_LSA_INVALID_LENGTH,
    &OSPF_LSA_UNKNOWN_TYPE,
];

static VRRP_FIELDS: &[&FieldDef] = &[
    &VRRP_TYPEVER,
    &VRRP_VERSION,
    &VRRP_TYPE,
    &VRRP_VIRT_RTR_ID,
    &VRRP_PRIO,
    &VRRP_ADDR_COUNT,
    &VRRP_CHECKSUM,
    &VRRP_CHECKSUM_STATUS,
    &VRRP_AUTH_TYPE,
    &VRRP_ADVER_INT,
    &VRRP_RESERVED_MBZ,
    &VRRP_SHORT_ADVER_INT,
    &VRRP_IP_ADDR,
    &VRRP_IPV6_ADDR,
    &VRRP_AUTH_STRING,
    &VRRP_MD5_AUTH_DATA,
    &VRRP_CHECKSUM_BAD_EXPERT,
];

static BFD_ECHO_FIELDS: &[&FieldDef] = &[&BFD_ECHO_PACKET];

/// Bidirectional Forwarding Detection control message.
pub static BFD_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "bfd",
    long_name: "Bidirectional Forwarding Detection Control Message",
    short_name: "BFD Control",
    fields: BFD_FIELDS,
};

/// Bidirectional Forwarding Detection echo packet.
pub static BFD_ECHO_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "bfd_echo",
    long_name: "Bidirectional Forwarding Detection Echo Packet",
    short_name: "BFD Echo",
    fields: BFD_ECHO_FIELDS,
};

/// Open Shortest Path First, versions 2 and 3.
pub static OSPF_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ospf",
    long_name: "Open Shortest Path First",
    short_name: "OSPF",
    fields: OSPF_FIELDS,
};

/// Virtual Router Redundancy Protocol, versions 2 and 3.
pub static VRRP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "vrrp",
    long_name: "Virtual Router Redundancy Protocol",
    short_name: "VRRP",
    fields: VRRP_FIELDS,
};

/// Transmission Control Protocol.
pub static TCP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "tcp",
    long_name: "Transmission Control Protocol",
    short_name: "TCP",
    fields: TCP_FIELDS,
};

/// User Datagram Protocol.
pub static UDP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "udp",
    long_name: "User Datagram Protocol",
    short_name: "UDP",
    fields: UDP_FIELDS,
};

/// The frame pseudo-protocol.
pub static FRAME_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "frame",
    long_name: "Frame",
    short_name: "Frame",
    fields: FRAME_FIELDS,
};

/// Ethernet II.
pub static ETH_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "eth",
    long_name: "Ethernet",
    short_name: "Ethernet",
    fields: ETH_FIELDS,
};

/// Logical Link Control.
pub static LLC_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "llc",
    long_name: "Logical-Link Control",
    short_name: "LLC",
    fields: LLC_FIELDS,
};

/// IEEE 802.1Q VLAN.
pub static VLAN_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "vlan",
    long_name: "802.1Q Virtual LAN",
    short_name: "VLAN",
    fields: VLAN_FIELDS,
};

/// IEEE 802.1ad provider bridging.
pub static IEEE8021AD_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ieee8021ad",
    long_name: "IEEE 802.1ad",
    short_name: "IEEE 802.1AD",
    fields: IEEE8021AD_FIELDS,
};

/// Linux cooked-mode capture, versions 1 and 2.
pub static SLL_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "sll",
    long_name: "Linux cooked-mode capture",
    short_name: "SLL",
    fields: SLL_FIELDS,
};

/// Null/loopback encapsulation.
pub static NULL_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "null",
    long_name: "Null/Loopback",
    short_name: "Null",
    fields: NULL_FIELDS,
};

/// Address Resolution Protocol.
pub static ARP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "arp",
    long_name: "Address Resolution Protocol",
    short_name: "ARP/RARP",
    fields: ARP_FIELDS,
};

/// Internet Protocol version 4.
pub static IP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ip",
    long_name: "Internet Protocol Version 4",
    short_name: "IPv4",
    fields: IP_FIELDS,
};

/// Internet Protocol version 6.
pub static IPV6_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ipv6",
    long_name: "Internet Protocol Version 6",
    short_name: "IPv6",
    fields: IPV6_FIELDS,
};

/// IPv6 hop-by-hop options.
pub static IPV6_HOPOPTS_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ipv6.hopopts",
    long_name: "IPv6 Hop-by-Hop Option",
    short_name: "IPv6 Hop-by-Hop",
    fields: IPV6_HOPOPTS_FIELDS,
};

/// IPv6 destination options.
pub static IPV6_DSTOPTS_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ipv6.dstopts",
    long_name: "Destination Options for IPv6",
    short_name: "IPv6 Destination",
    fields: IPV6_DSTOPTS_FIELDS,
};

/// IPv6 routing header.
pub static IPV6_ROUTING_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ipv6.routing",
    long_name: "Routing Header for IPv6",
    short_name: "IPv6 Routing",
    fields: IPV6_ROUTING_FIELDS,
};

/// IPv6 fragment header.
pub static IPV6_FRAGHDR_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "ipv6.fraghdr",
    long_name: "Fragment Header for IPv6",
    short_name: "IPv6 Fragment",
    fields: IPV6_FRAGHDR_FIELDS,
};

/// Link Aggregation Control Protocol.
pub static LACP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "lacp",
    long_name: "Link Aggregation Control Protocol",
    short_name: "LACP",
    fields: LACP_FIELDS,
};

/// Link Layer Discovery Protocol.
pub static LLDP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "lldp",
    long_name: "Link Layer Discovery Protocol",
    short_name: "LLDP",
    fields: LLDP_FIELDS,
};

/// Link Aggregation Marker Protocol.
pub static MARKER_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "marker",
    long_name: "Link Aggregation Marker Protocol",
    short_name: "Marker",
    fields: MARKER_FIELDS,
};

/// IEEE 802.3 slow protocols.
pub static SLOW_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "slow",
    long_name: "802.3 Slow protocols",
    short_name: "Slow Protocols",
    fields: SLOW_FIELDS,
};

/// Spanning Tree Protocol, including RSTP and MSTP.
pub static STP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "stp",
    long_name: "Spanning Tree Protocol",
    short_name: "STP",
    fields: STP_FIELDS,
};

// LLDP fields
static LLDP_FIELDS: &[&FieldDef] = &[
    &LLDP_TLV_TYPE,
    &LLDP_TLV_LEN,
    &LLDP_TLV_SYSTEM_CAP,
    &LLDP_TLV_SYSTEM_CAP_OTHER,
    &LLDP_TLV_SYSTEM_CAP_REPEATER,
    &LLDP_TLV_SYSTEM_CAP_BRIDGE,
    &LLDP_TLV_SYSTEM_CAP_WLAN_ACCESS_PT,
    &LLDP_TLV_SYSTEM_CAP_ROUTER,
    &LLDP_TLV_SYSTEM_CAP_TELEPHONE,
    &LLDP_TLV_SYSTEM_CAP_DOCSIS_CABLE_DEVICE,
    &LLDP_TLV_SYSTEM_CAP_STATION_ONLY,
    &LLDP_TLV_SYSTEM_CAP_CVLAN,
    &LLDP_TLV_SYSTEM_CAP_SVLAN,
    &LLDP_TLV_SYSTEM_CAP_TPMR,
    &LLDP_TLV_SYSTEM_NAME,
    &LLDP_TLV_SYSTEM_DESC,
    &LLDP_TLV_ENABLE_SYSTEM_CAP,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_OTHER,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_REPEATER,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_BRIDGE,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_WLAN_ACCESS_PT,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_ROUTER,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_TELEPHONE,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_DOCSIS_CABLE_DEVICE,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_STATION_ONLY,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_CVLAN,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_SVLAN,
    &LLDP_TLV_ENABLE_SYSTEM_CAP_TPMR,
    &LLDP_CHASSIS_SUBTYPE,
    &LLDP_CHASSIS_ID,
    &LLDP_CHASSIS_ID_MAC,
    &LLDP_CHASSIS_ID_IP4,
    &LLDP_CHASSIS_ID_IP6,
    &LLDP_PORT_SUBTYPE,
    &LLDP_PORT_ID,
    &LLDP_PORT_DESC,
    &LLDP_PORT_ID_MAC,
    &LLDP_NETWORK_ADDRESS_SUBTYPE,
    &LLDP_PORT_ID_IP4,
    &LLDP_PORT_ID_IP6,
    &LLDP_TIME_TO_LIVE,
    &LLDP_PDU_TYPE,
    &LLDP_MGN_ADDRESS_LEN,
    &LLDP_MGN_ADDRESS_SUBTYPE,
    &LLDP_MGN_ADDR_IP4,
    &LLDP_MGN_ADDR_IP6,
    &LLDP_MGN_ADDR_HEX,
    &LLDP_MGN_INTERFACE_SUBTYPE,
    &LLDP_MGN_INTERFACE_NUMBER,
    &LLDP_MGN_OBJ_LEN,
    &LLDP_MGN_OBJ_ID,
    &LLDP_ORGTLV_OUI,
    &LLDP_IEEE_802_1_SUBTYPE,
    &LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG,
    &LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG_SUPPORTED,
    &LLDP_IEEE_802_1_PORT_AND_VLAN_ID_FLAG_ENABLED,
    &LLDP_IEEE_802_1_PORT_VLAN_ID,
    &LLDP_IEEE_802_1_PORT_PROTO_VLAN_ID,
    &LLDP_IEEE_802_1_VLAN_ID,
    &LLDP_IEEE_802_1_VLAN_NAME_LEN,
    &LLDP_IEEE_802_1_VLAN_NAME,
    &LLDP_IEEE_802_1_PROTO_ID_LENGTH,
    &LLDP_IEEE_802_1_PROTO_ID,
    &LLDP_IEEE_802_1_AGGREGATION_STATUS,
    &LLDP_IEEE_802_1_AGGREGATION_STATUS_CAP,
    &LLDP_IEEE_802_1_AGGREGATION_STATUS_ENABLED,
    &LLDP_IEEE_802_1_AGGREGATION_STATUS_PORTTYPE,
    &LLDP_IEEE_802_1_AGGREGATED_PORT_ID,
    &LLDP_IEEE_802_3_SUBTYPE,
    &LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS,
    &LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS_SUPPORTED,
    &LLDP_IEEE_802_3_MAC_PHY_AUTO_NEG_STATUS_ENABLED,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_TFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_T,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_XFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_1000BASE_X,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_BPAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_SPAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_APAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_FDX_PAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T2FD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T2,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_TXFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_TX,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_100BASE_T4,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_10BASE_TFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_10BASE_T,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_OTHER,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_TFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_T,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_XFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_1000BASE_X,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_BPAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_SPAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_APAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_FDX_PAUSE,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T2FD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T2,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_TXFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_TX,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_100BASE_T4,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_10BASE_TFD,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_10BASE_T,
    &LLDP_IEEE_802_3_PMD_AUTO_NEG_ADVERTISED_CAPS_INV_OTHER,
    &LLDP_IEEE_802_3_PMD_MAU_TYPE,
    &LLDP_IEEE_802_3_AGGREGATION_STATUS,
    &LLDP_IEEE_802_3_AGGREGATION_STATUS_CAP,
    &LLDP_IEEE_802_3_AGGREGATION_STATUS_ENABLED,
    &LLDP_IEEE_802_3_AGGREGATED_PORT_ID,
    &LLDP_IEEE_802_3_MAX_FRAME_SIZE,
    &LLDP_UNKNOWN_SUBTYPE,
    &LLDP_UNKNOWN_SUBTYPE_CONTENT,
    &LLDP_INCORRECT_LENGTH,
    &LLDP_EXCESS_LENGTH,
    &LLDP_EXCESS_TLV,
    &LLDP_BAD_TYPE,
    &LLDP_TLV_DEPRECATED,
];

static LACP_FIELDS: &[&FieldDef] = &[
    &LACP_VERSION,
    &LACP_TLV_TYPE,
    &LACP_TLV_LENGTH,
    &LACP_ACTOR_SYS_PRIORITY,
    &LACP_ACTOR_SYSID,
    &LACP_ACTOR_KEY,
    &LACP_ACTOR_PORT_PRIORITY,
    &LACP_ACTOR_PORT,
    &LACP_ACTOR_STATE,
    &LACP_ACTOR_STATE_STR,
    &LACP_ACTOR_STATE_ACTIVITY,
    &LACP_ACTOR_STATE_TIMEOUT,
    &LACP_ACTOR_STATE_AGGREGATION,
    &LACP_ACTOR_STATE_SYNCHRONIZATION,
    &LACP_ACTOR_STATE_COLLECTING,
    &LACP_ACTOR_STATE_DISTRIBUTING,
    &LACP_ACTOR_STATE_DEFAULTED,
    &LACP_ACTOR_STATE_EXPIRED,
    &LACP_ACTOR_RESERVED,
    &LACP_PARTNER_SYS_PRIORITY,
    &LACP_PARTNER_SYSID,
    &LACP_PARTNER_KEY,
    &LACP_PARTNER_PORT_PRIORITY,
    &LACP_PARTNER_PORT,
    &LACP_PARTNER_STATE,
    &LACP_PARTNER_STATE_STR,
    &LACP_PARTNER_STATE_ACTIVITY,
    &LACP_PARTNER_STATE_TIMEOUT,
    &LACP_PARTNER_STATE_AGGREGATION,
    &LACP_PARTNER_STATE_SYNCHRONIZATION,
    &LACP_PARTNER_STATE_COLLECTING,
    &LACP_PARTNER_STATE_DISTRIBUTING,
    &LACP_PARTNER_STATE_DEFAULTED,
    &LACP_PARTNER_STATE_EXPIRED,
    &LACP_PARTNER_RESERVED,
    &LACP_COLLECTOR_MAX_DELAY,
    &LACP_COLL_RESERVED,
    &LACP_WRONG_TLV_TYPE,
    &LACP_WRONG_TLV_LENGTH,
];

static MARKER_FIELDS: &[&FieldDef] = &[
    &MARKER_VERSION,
    &MARKER_TLV_TYPE,
    &MARKER_TLV_LEN,
    &MARKER_REQUESTER_PORT,
    &MARKER_REQUESTER_SYSTEM,
    &MARKER_REQUESTER_TRANS_ID,
    &MARKER_REQUESTER_PAD,
    &MARKER_RESERVED,
    &MARKER_WRONG_TLV_TYPE,
    &MARKER_WRONG_TLV_LENGTH,
    &MARKER_WRONG_PAD_VALUE,
];

static SLOW_FIELDS: &[&FieldDef] = &[&SLOW_SUBTYPE];

static STP_FIELDS: &[&FieldDef] = &[
    &STP_PROTOCOL_ID,
    &STP_VERSION,
    &STP_TYPE,
    &STP_FLAGS,
    &STP_FLAGS_TCACK,
    &STP_FLAGS_AGREEMENT,
    &STP_FLAGS_FORWARDING,
    &STP_FLAGS_LEARNING,
    &STP_FLAGS_PORT_ROLE,
    &STP_FLAGS_PROPOSAL,
    &STP_FLAGS_TC,
    &STP_ROOT_PRIO,
    &STP_ROOT_EXT,
    &STP_ROOT_HW,
    &STP_ROOT_COST,
    &STP_BRIDGE_PRIO,
    &STP_BRIDGE_EXT,
    &STP_BRIDGE_HW,
    &STP_PORT,
    &STP_MSG_AGE,
    &STP_MAX_AGE,
    &STP_HELLO,
    &STP_FORWARD,
    &STP_VERSION_1_LENGTH,
    &STP_TYPE_UNKNOWN,
    &MSTP_VERSION_3_LENGTH,
    &MSTP_CONFIG_FORMAT_SELECTOR,
    &MSTP_CONFIG_NAME,
    &MSTP_CONFIG_REVISION_LEVEL,
    &MSTP_CONFIG_DIGEST,
    &MSTP_CIST_INTERNAL_ROOT_PATH_COST,
    &MSTP_CIST_BRIDGE_PRIO,
    &MSTP_CIST_BRIDGE_EXT,
    &MSTP_CIST_BRIDGE_HW,
    &MSTP_CIST_REMAINING_HOPS,
    &MSTP_MSTI_FLAGS,
    &MSTP_MSTI_PRIORITY,
    &MSTP_MSTI_MSTI_ID,
    &MSTP_MSTI_ROOT_HW,
    &MSTP_MSTI_ROOT_COST,
    &MSTP_MSTI_BRIDGE_PRIORITY,
    &MSTP_MSTI_PORT_PRIORITY,
    &MSTP_MSTI_REMAINING_HOPS,
];

// ---- syslog ----
/// `syslog.facility`.
pub static SYSLOG_FACILITY: FieldDef = FieldDef {
    abbrev: "syslog.facility",
    name: "Facility",
    field_type: FieldType::Uint16,
    parent: "syslog",
    display: Display::Decimal,
    bitmask: Some(0x3f8),
    blurb: "Message facility",
    generated: false,
};

/// `syslog.level`.
pub static SYSLOG_LEVEL: FieldDef = FieldDef {
    abbrev: "syslog.level",
    name: "Level",
    field_type: FieldType::Uint16,
    parent: "syslog",
    display: Display::Decimal,
    bitmask: Some(0x7),
    blurb: "Message level",
    generated: false,
};

/// `syslog.version`.
pub static SYSLOG_VERSION: FieldDef = FieldDef {
    abbrev: "syslog.version",
    name: "Version",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "Syslog version",
    generated: false,
};

/// `syslog.timestamp`.
pub static SYSLOG_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "syslog.timestamp",
    name: "Timestamp",
    field_type: FieldType::AbsoluteTime,
    parent: "syslog",
    display: Display::IsoTime,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `syslog.timestamp_rfc3164`.
pub static SYSLOG_TIMESTAMP_RFC3164: FieldDef = FieldDef {
    abbrev: "syslog.timestamp_rfc3164",
    name: "Timestamp (RFC3164)",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `syslog.hostname`.
pub static SYSLOG_HOSTNAME: FieldDef = FieldDef {
    abbrev: "syslog.hostname",
    name: "Hostname",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "The hostname that generated this message",
    generated: false,
};

/// `syslog.appname`.
pub static SYSLOG_APPNAME: FieldDef = FieldDef {
    abbrev: "syslog.appname",
    name: "App Name",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "The name of the app that generated this message",
    generated: false,
};

/// `syslog.procid`.
pub static SYSLOG_PROCID: FieldDef = FieldDef {
    abbrev: "syslog.procid",
    name: "Process ID",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "The ID of the process that generated this message",
    generated: false,
};

/// `syslog.msg`.
pub static SYSLOG_MSG: FieldDef = FieldDef {
    abbrev: "syslog.msg",
    name: "Message",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `syslog.msgid`.
pub static SYSLOG_MSGID: FieldDef = FieldDef {
    abbrev: "syslog.msgid",
    name: "Message ID",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `syslog.sd`.
pub static SYSLOG_SD: FieldDef = FieldDef {
    abbrev: "syslog.sd",
    name: "Structured Data",
    field_type: FieldType::None,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `syslog.sd.element`.
pub static SYSLOG_SD_ELEMENT: FieldDef = FieldDef {
    abbrev: "syslog.sd.element",
    name: "Element",
    field_type: FieldType::None,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "Structured Data Element",
    generated: false,
};

/// `syslog.sd.element.name`.
pub static SYSLOG_SD_ELEMENT_NAME: FieldDef = FieldDef {
    abbrev: "syslog.sd.element.name",
    name: "Element Name",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "Structured Data Element Name",
    generated: false,
};

/// `syslog.sd.param`.
pub static SYSLOG_SD_PARAM: FieldDef = FieldDef {
    abbrev: "syslog.sd.param",
    name: "Parameter",
    field_type: FieldType::None,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "Structured Data Parameter",
    generated: false,
};

/// `syslog.sd.param.name`.
pub static SYSLOG_SD_PARAM_NAME: FieldDef = FieldDef {
    abbrev: "syslog.sd.param.name",
    name: "Parameter Name",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "Structured Data Parameter Name",
    generated: false,
};

/// `syslog.sd.param.value`.
pub static SYSLOG_SD_PARAM_VALUE: FieldDef = FieldDef {
    abbrev: "syslog.sd.param.value",
    name: "Parameter Value",
    field_type: FieldType::String,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "Structured Data Parameter Value",
    generated: false,
};

/// `syslog.msg.nonconformant`.
pub static SYSLOG_MSG_NONCONFORMANT: FieldDef = FieldDef {
    abbrev: "syslog.msg.nonconformant",
    name: "Message conforms to neither RFC 5424 nor RFC 3164; trailing data appended",
    field_type: FieldType::None,
    parent: "syslog",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static SYSLOG_FIELDS: &[&FieldDef] = &[
    &SYSLOG_FACILITY,
    &SYSLOG_LEVEL,
    &SYSLOG_VERSION,
    &SYSLOG_TIMESTAMP,
    &SYSLOG_TIMESTAMP_RFC3164,
    &SYSLOG_HOSTNAME,
    &SYSLOG_APPNAME,
    &SYSLOG_PROCID,
    &SYSLOG_MSG,
    &SYSLOG_MSGID,
    &SYSLOG_SD,
    &SYSLOG_SD_ELEMENT,
    &SYSLOG_SD_ELEMENT_NAME,
    &SYSLOG_SD_PARAM,
    &SYSLOG_SD_PARAM_NAME,
    &SYSLOG_SD_PARAM_VALUE,
    &SYSLOG_MSG_NONCONFORMANT,
];

// ---- cflow ----
/// `cflow.version`.
pub static CFLOW_VERSION: FieldDef = FieldDef {
    abbrev: "cflow.version",
    name: "Version",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "NetFlow Version",
    generated: false,
};

/// `cflow.count`.
pub static CFLOW_COUNT: FieldDef = FieldDef {
    abbrev: "cflow.count",
    name: "Count",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Count of PDUs",
    generated: false,
};

/// `cflow.sysuptime`.
pub static CFLOW_SYSUPTIME: FieldDef = FieldDef {
    abbrev: "cflow.sysuptime",
    name: "SysUptime",
    field_type: FieldType::RelativeTime,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Time since router booted (in seconds)",
    generated: false,
};

/// `cflow.timestamp`.
pub static CFLOW_TIMESTAMP: FieldDef = FieldDef {
    abbrev: "cflow.timestamp",
    name: "Timestamp",
    field_type: FieldType::AbsoluteTime,
    parent: "cflow",
    display: Display::IsoTime,
    bitmask: None,
    blurb: "Current seconds since epoch",
    generated: false,
};

/// `cflow.unix_secs`.
pub static CFLOW_UNIX_SECS: FieldDef = FieldDef {
    abbrev: "cflow.unix_secs",
    name: "CurrentSecs",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Current seconds since epoch",
    generated: false,
};

/// `cflow.unix_nsecs`.
pub static CFLOW_UNIX_NSECS: FieldDef = FieldDef {
    abbrev: "cflow.unix_nsecs",
    name: "CurrentNSecs",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Residual nanoseconds since epoch",
    generated: false,
};

/// `cflow.samplingmode`.
pub static CFLOW_SAMPLINGMODE: FieldDef = FieldDef {
    abbrev: "cflow.samplingmode",
    name: "SamplingMode",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: Some(0xc000),
    blurb: "Sampling Mode of exporter",
    generated: false,
};

/// `cflow.samplerate`.
pub static CFLOW_SAMPLERATE: FieldDef = FieldDef {
    abbrev: "cflow.samplerate",
    name: "SampleRate",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: Some(0x3fff),
    blurb: "Sample Frequency of exporter",
    generated: false,
};

/// `cflow.sequence`.
pub static CFLOW_SEQUENCE: FieldDef = FieldDef {
    abbrev: "cflow.sequence",
    name: "FlowSequence",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Sequence number of flows seen",
    generated: false,
};

/// `cflow.engine_type`.
pub static CFLOW_ENGINE_TYPE: FieldDef = FieldDef {
    abbrev: "cflow.engine_type",
    name: "EngineType",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Flow switching engine type",
    generated: false,
};

/// `cflow.engine_id`.
pub static CFLOW_ENGINE_ID: FieldDef = FieldDef {
    abbrev: "cflow.engine_id",
    name: "EngineId",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Slot number of switching engine",
    generated: false,
};

/// `cflow.source_id`.
pub static CFLOW_SOURCE_ID: FieldDef = FieldDef {
    abbrev: "cflow.source_id",
    name: "SourceId",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Identifier for export device",
    generated: false,
};

/// `cflow.srcaddr`.
pub static CFLOW_SRCADDR: FieldDef = FieldDef {
    abbrev: "cflow.srcaddr",
    name: "SrcAddr",
    field_type: FieldType::Ipv4,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Flow Source Address (IPv4)",
    generated: false,
};

/// `cflow.dstaddr`.
pub static CFLOW_DSTADDR: FieldDef = FieldDef {
    abbrev: "cflow.dstaddr",
    name: "DstAddr",
    field_type: FieldType::Ipv4,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Flow Destination Address (IPv4)",
    generated: false,
};

/// `cflow.nexthop`.
pub static CFLOW_NEXTHOP: FieldDef = FieldDef {
    abbrev: "cflow.nexthop",
    name: "NextHop",
    field_type: FieldType::Ipv4,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Router nexthop (IPv4)",
    generated: false,
};

/// `cflow.inputint`.
pub static CFLOW_INPUTINT: FieldDef = FieldDef {
    abbrev: "cflow.inputint",
    name: "InputInt",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Flow Input Interface",
    generated: false,
};

/// `cflow.outputint`.
pub static CFLOW_OUTPUTINT: FieldDef = FieldDef {
    abbrev: "cflow.outputint",
    name: "OutputInt",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Flow Output Interface",
    generated: false,
};

/// `cflow.packets`.
pub static CFLOW_PACKETS: FieldDef = FieldDef {
    abbrev: "cflow.packets",
    name: "Packets",
    field_type: FieldType::Uint64,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Count of packets in flow",
    generated: false,
};

/// `cflow.octets`.
pub static CFLOW_OCTETS: FieldDef = FieldDef {
    abbrev: "cflow.octets",
    name: "Octets",
    field_type: FieldType::Uint64,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Count of bytes in flow",
    generated: false,
};

/// `cflow.timedelta`.
pub static CFLOW_TIMEDELTA: FieldDef = FieldDef {
    abbrev: "cflow.timedelta",
    name: "Duration",
    field_type: FieldType::RelativeTime,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Duration of flow sample (end - start) in seconds",
    generated: false,
};

/// `cflow.timestart`.
pub static CFLOW_TIMESTART: FieldDef = FieldDef {
    abbrev: "cflow.timestart",
    name: "StartTime",
    field_type: FieldType::RelativeTime,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Uptime at start of flow",
    generated: false,
};

/// `cflow.timeend`.
pub static CFLOW_TIMEEND: FieldDef = FieldDef {
    abbrev: "cflow.timeend",
    name: "EndTime",
    field_type: FieldType::RelativeTime,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Uptime at end of flow",
    generated: false,
};

/// `cflow.srcport`.
pub static CFLOW_SRCPORT: FieldDef = FieldDef {
    abbrev: "cflow.srcport",
    name: "SrcPort",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Flow Source Port",
    generated: false,
};

/// `cflow.dstport`.
pub static CFLOW_DSTPORT: FieldDef = FieldDef {
    abbrev: "cflow.dstport",
    name: "DstPort",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Flow Destination Port",
    generated: false,
};

/// `cflow.protocol`.
pub static CFLOW_IP_PROTOCOL: FieldDef = FieldDef {
    abbrev: "cflow.protocol",
    name: "Protocol",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "IP Protocol",
    generated: false,
};

/// `cflow.tos`.
pub static CFLOW_TOS: FieldDef = FieldDef {
    abbrev: "cflow.tos",
    name: "IP ToS",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Hex,
    bitmask: None,
    blurb: "IP Type of Service",
    generated: false,
};

/// `cflow.tcpflags`.
pub static CFLOW_TCPFLAGS: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags",
    name: "TCP Flags",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `cflow.srcas`.
pub static CFLOW_SRCAS: FieldDef = FieldDef {
    abbrev: "cflow.srcas",
    name: "SrcAS",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Source AS",
    generated: false,
};

/// `cflow.dstas`.
pub static CFLOW_DSTAS: FieldDef = FieldDef {
    abbrev: "cflow.dstas",
    name: "DstAS",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Destination AS",
    generated: false,
};

/// `cflow.srcmask`.
pub static CFLOW_SRCMASK: FieldDef = FieldDef {
    abbrev: "cflow.srcmask",
    name: "SrcMask",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Source Prefix Mask",
    generated: false,
};

/// `cflow.dstmask`.
pub static CFLOW_DSTMASK: FieldDef = FieldDef {
    abbrev: "cflow.dstmask",
    name: "DstMask",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Destination Prefix Mask",
    generated: false,
};

/// `cflow.padding`.
pub static CFLOW_PADDING: FieldDef = FieldDef {
    abbrev: "cflow.padding",
    name: "Padding",
    field_type: FieldType::Bytes,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

// ---- cflow version 9 and IPFIX (RFC 3954, RFC 7011) ----

/// `cflow.len`.
pub static CFLOW_LEN: FieldDef = FieldDef {
    abbrev: "cflow.len",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of PDUs",
    generated: false,
};

/// `cflow.exporttime`.
pub static CFLOW_EXPORTTIME: FieldDef = FieldDef {
    abbrev: "cflow.exporttime",
    name: "ExportTime",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Time when the flow has been exported",
    generated: false,
};

/// `cflow.flowset_id`.
pub static CFLOW_FLOWSET_ID: FieldDef = FieldDef {
    abbrev: "cflow.flowset_id",
    name: "FlowSet Id",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `cflow.flowset_length`.
pub static CFLOW_FLOWSET_LENGTH: FieldDef = FieldDef {
    abbrev: "cflow.flowset_length",
    name: "FlowSet Length",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "FlowSet Length in bytes",
    generated: false,
};

/// `cflow.template_id`.
pub static CFLOW_TEMPLATE_ID: FieldDef = FieldDef {
    abbrev: "cflow.template_id",
    name: "Template Id",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `cflow.template_field_count`.
pub static CFLOW_TEMPLATE_FIELD_COUNT: FieldDef = FieldDef {
    abbrev: "cflow.template_field_count",
    name: "Field Count",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Template field count",
    generated: false,
};

/// `cflow.template_field_type`.
pub static CFLOW_TEMPLATE_FIELD_TYPE: FieldDef = FieldDef {
    abbrev: "cflow.template_field_type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Template field type",
    generated: false,
};

/// `cflow.template_field_length`.
pub static CFLOW_TEMPLATE_FIELD_LENGTH: FieldDef = FieldDef {
    abbrev: "cflow.template_field_length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Template field length",
    generated: false,
};

/// `cflow.option_scope_length`.
pub static CFLOW_OPTION_SCOPE_LENGTH: FieldDef = FieldDef {
    abbrev: "cflow.option_scope_length",
    name: "Option Scope Length",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `cflow.option_length`.
pub static CFLOW_OPTION_LENGTH: FieldDef = FieldDef {
    abbrev: "cflow.option_length",
    name: "Option Length",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `cflow.scope_field_type`.
pub static CFLOW_SCOPE_FIELD_TYPE: FieldDef = FieldDef {
    abbrev: "cflow.scope_field_type",
    name: "Scope Type",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Scope field type",
    generated: false,
};

/// `cflow.srcaddrv6`.
pub static CFLOW_SRCADDRV6: FieldDef = FieldDef {
    abbrev: "cflow.srcaddrv6",
    name: "SrcAddr",
    field_type: FieldType::Ipv6,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Flow Source Address (IPv6)",
    generated: false,
};

/// `cflow.dstaddrv6`.
pub static CFLOW_DSTADDRV6: FieldDef = FieldDef {
    abbrev: "cflow.dstaddrv6",
    name: "DstAddr",
    field_type: FieldType::Ipv6,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Flow Destination Address (IPv6)",
    generated: false,
};

/// `cflow.bgpnexthop`.
pub static CFLOW_BGPNEXTHOP: FieldDef = FieldDef {
    abbrev: "cflow.bgpnexthop",
    name: "BGPNextHop",
    field_type: FieldType::Ipv4,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "BGP Router Nexthop (IPv4)",
    generated: false,
};

/// `cflow.tcpflags.fin`.
pub static CFLOW_TCPFLAGS_FIN: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.fin",
    name: "FIN",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean8,
    bitmask: Some(0x01),
    blurb: "",
    generated: false,
};

/// `cflow.tcpflags.syn`.
pub static CFLOW_TCPFLAGS_SYN: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.syn",
    name: "SYN",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean8,
    bitmask: Some(0x02),
    blurb: "",
    generated: false,
};

/// `cflow.tcpflags.rst`.
pub static CFLOW_TCPFLAGS_RST: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.rst",
    name: "RST",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean8,
    bitmask: Some(0x04),
    blurb: "",
    generated: false,
};

/// `cflow.tcpflags.psh`.
pub static CFLOW_TCPFLAGS_PSH: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.psh",
    name: "PSH",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean8,
    bitmask: Some(0x08),
    blurb: "",
    generated: false,
};

/// `cflow.tcpflags.ack`.
pub static CFLOW_TCPFLAGS_ACK: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.ack",
    name: "ACK",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `cflow.tcpflags.urg`.
pub static CFLOW_TCPFLAGS_URG: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.urg",
    name: "URG",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `cflow.tcpflags.reserved`.
pub static CFLOW_TCPFLAGS_RESERVED: FieldDef = FieldDef {
    abbrev: "cflow.tcpflags.reserved",
    name: "Reserved",
    field_type: FieldType::Uint8,
    parent: "cflow",
    display: Display::Hex,
    bitmask: Some(0xc0),
    blurb: "",
    generated: false,
};

/// `cflow.od_id`.
pub static CFLOW_OD_ID: FieldDef = FieldDef {
    abbrev: "cflow.od_id",
    name: "Observation Domain Id",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Identifier of an Observation Domain that is locally unique to an Exporting Process",
    generated: false,
};

/// `cflow.abstimestart`.
pub static CFLOW_ABSTIMESTART: FieldDef = FieldDef {
    abbrev: "cflow.abstimestart",
    name: "StartTime",
    field_type: FieldType::AbsoluteTime,
    parent: "cflow",
    display: Display::IsoTime,
    bitmask: None,
    blurb: "Uptime at start of flow",
    generated: false,
};

/// `cflow.abstimeend`.
pub static CFLOW_ABSTIMEEND: FieldDef = FieldDef {
    abbrev: "cflow.abstimeend",
    name: "EndTime",
    field_type: FieldType::AbsoluteTime,
    parent: "cflow",
    display: Display::IsoTime,
    bitmask: None,
    blurb: "Uptime at end of flow",
    generated: false,
};

/// `cflow.scope_system`.
pub static CFLOW_SCOPE_SYSTEM: FieldDef = FieldDef {
    abbrev: "cflow.scope_system",
    name: "ScopeSystem",
    field_type: FieldType::Bytes,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Option Scope System",
    generated: false,
};

/// `cflow.scope_interface`.
pub static CFLOW_SCOPE_INTERFACE: FieldDef = FieldDef {
    abbrev: "cflow.scope_interface",
    name: "ScopeInterface",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option Scope Interface",
    generated: false,
};

/// `cflow.scope_linecard`.
pub static CFLOW_SCOPE_LINECARD: FieldDef = FieldDef {
    abbrev: "cflow.scope_linecard",
    name: "ScopeLinecard",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Option Scope Linecard",
    generated: false,
};

/// `cflow.scope_cache`.
pub static CFLOW_SCOPE_CACHE: FieldDef = FieldDef {
    abbrev: "cflow.scope_cache",
    name: "ScopeCache",
    field_type: FieldType::Bytes,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Option Scope Cache",
    generated: false,
};

/// `cflow.scope_template`.
pub static CFLOW_SCOPE_TEMPLATE: FieldDef = FieldDef {
    abbrev: "cflow.scope_template",
    name: "ScopeTemplate",
    field_type: FieldType::Bytes,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "Option Scope Template",
    generated: false,
};

/// `cflow.unknown_field_type`.
pub static CFLOW_UNKNOWN_FIELD_TYPE: FieldDef = FieldDef {
    abbrev: "cflow.unknown_field_type",
    name: "Unknown Field Type",
    field_type: FieldType::Bytes,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `cflow.template_ipfix_total_field_count`.
pub static CFLOW_TEMPLATE_IPFIX_TOTAL_FIELD_COUNT: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_total_field_count",
    name: "Total Field Count",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "IPFIX Options Template Total Field Count",
    generated: false,
};

/// `cflow.template_ipfix_scope_field_count`.
pub static CFLOW_TEMPLATE_IPFIX_SCOPE_FIELD_COUNT: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_scope_field_count",
    name: "Scope Field Count",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "IPFIX Options Template Scope Field Count",
    generated: false,
};

/// `cflow.template_ipfix_pen_provided`.
pub static CFLOW_TEMPLATE_IPFIX_PEN_PROVIDED: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_pen_provided",
    name: "Pen provided",
    field_type: FieldType::Boolean,
    parent: "cflow",
    display: Display::Boolean16,
    bitmask: Some(0x8000),
    blurb: "Is Template Enterprise Specific",
    generated: false,
};

/// `cflow.template_ipfix_field_type`.
pub static CFLOW_TEMPLATE_IPFIX_FIELD_TYPE: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_field_type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: Some(0x7fff),
    blurb: "Template field type",
    generated: false,
};

/// `cflow.template_cisco_field_type`.
pub static CFLOW_TEMPLATE_CISCO_FIELD_TYPE: FieldDef = FieldDef {
    abbrev: "cflow.template_cisco_field_type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: Some(0x7fff),
    blurb: "Template field type",
    generated: false,
};

/// `cflow.template_ipfix_field_type_enterprise`.
pub static CFLOW_TEMPLATE_IPFIX_FIELD_TYPE_ENTERPRISE: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_field_type_enterprise",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: Some(0x7fff),
    blurb: "Template field type",
    generated: false,
};

/// `cflow.template_ipfix_field_pen`.
pub static CFLOW_TEMPLATE_IPFIX_FIELD_PEN: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_field_pen",
    name: "PEN",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "IPFIX Private Enterprise Number",
    generated: false,
};

/// `cflow.sequence_analysis.expected_sn`.
pub static CFLOW_EXPECTED_SN: FieldDef = FieldDef {
    abbrev: "cflow.sequence_analysis.expected_sn",
    name: "Expected Sequence Number",
    field_type: FieldType::Uint32,
    parent: "cflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.sequence_analysis.previous_frame`.
pub static CFLOW_PREVIOUS_FRAME: FieldDef = FieldDef {
    abbrev: "cflow.sequence_analysis.previous_frame",
    name: "Previous Frame in Sequence",
    field_type: FieldType::FrameNumber,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.template_frame`.
pub static CFLOW_TEMPLATE_FRAME: FieldDef = FieldDef {
    abbrev: "cflow.template_frame",
    name: "Template Frame",
    field_type: FieldType::FrameNumber,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.flowset_length.invalid`.
pub static CFLOW_FLOWSET_LENGTH_INVALID: FieldDef = FieldDef {
    abbrev: "cflow.flowset_length.invalid",
    name: "Flow length invalid",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.no_flow_information`.
pub static CFLOW_NO_FLOW_INFORMATION: FieldDef = FieldDef {
    abbrev: "cflow.no_flow_information",
    name: "No flow information",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.template_ipfix_scope_field_count.none`.
pub static CFLOW_IPFIX_SCOPE_NONE: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_scope_field_count.none",
    name: "No scope fields",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.template_ipfix_scope_field_count.too_many`.
pub static CFLOW_IPFIX_SCOPE_TOO_MANY: FieldDef = FieldDef {
    abbrev: "cflow.template_ipfix_scope_field_count.too_many",
    name: "More IPFIX scopes than can be handled",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.options.too_many`.
pub static CFLOW_OPTIONS_TOO_MANY: FieldDef = FieldDef {
    abbrev: "cflow.options.too_many",
    name: "More options than can be handled",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.scopes.too_many`.
pub static CFLOW_SCOPES_TOO_MANY: FieldDef = FieldDef {
    abbrev: "cflow.scopes.too_many",
    name: "More scopes than can be handled",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.entries.too_many`.
pub static CFLOW_ENTRIES_TOO_MANY: FieldDef = FieldDef {
    abbrev: "cflow.entries.too_many",
    name: "More entries than can be handled",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.flowsets.impossible`.
pub static CFLOW_FLOWSETS_IMPOSSIBLE: FieldDef = FieldDef {
    abbrev: "cflow.flowsets.impossible",
    name: "FlowSets impossible",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.no_template_found`.
pub static CFLOW_NO_TEMPLATE_FOUND: FieldDef = FieldDef {
    abbrev: "cflow.no_template_found",
    name: "No template found",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `cflow.unexpected_sequence_number`.
pub static CFLOW_UNEXPECTED_SEQUENCE: FieldDef = FieldDef {
    abbrev: "cflow.unexpected_sequence_number",
    name: "Unexpected flow sequence for domain ID",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

// Anonymous containers for flow-set, template and record nodes. They have no
// filter name and are absent from the registry.

/// The nameless container for one flow set or IPFIX set.
pub static CFLOW_FLOWSET: FieldDef = FieldDef {
    abbrev: "",
    name: "FlowSet",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// The nameless container for one template record.
pub static CFLOW_TEMPLATE: FieldDef = FieldDef {
    abbrev: "",
    name: "Template",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// The nameless container for one template field description.
pub static CFLOW_TEMPLATE_FIELD: FieldDef = FieldDef {
    abbrev: "",
    name: "Field",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// The nameless container for one data record.
pub static CFLOW_FLOW: FieldDef = FieldDef {
    abbrev: "",
    name: "Flow",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// The nameless container for a whole-message diagnostic label.
pub static CFLOW_MESSAGE: FieldDef = FieldDef {
    abbrev: "",
    name: "Message",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// The nameless `Data (N bytes), no template found` container.
pub static CFLOW_DATA: FieldDef = FieldDef {
    abbrev: "",
    name: "Data",
    field_type: FieldType::None,
    parent: "cflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static CFLOW_FIELDS: &[&FieldDef] = &[
    &CFLOW_VERSION,
    &CFLOW_LEN,
    &CFLOW_COUNT,
    &CFLOW_SYSUPTIME,
    &CFLOW_EXPORTTIME,
    &CFLOW_TIMESTAMP,
    &CFLOW_UNIX_SECS,
    &CFLOW_UNIX_NSECS,
    &CFLOW_SAMPLINGMODE,
    &CFLOW_SAMPLERATE,
    &CFLOW_SEQUENCE,
    &CFLOW_ENGINE_TYPE,
    &CFLOW_ENGINE_ID,
    &CFLOW_SOURCE_ID,
    &CFLOW_FLOWSET_ID,
    &CFLOW_FLOWSET_LENGTH,
    &CFLOW_TEMPLATE_ID,
    &CFLOW_TEMPLATE_FIELD_COUNT,
    &CFLOW_TEMPLATE_FIELD_TYPE,
    &CFLOW_TEMPLATE_FIELD_LENGTH,
    &CFLOW_OPTION_SCOPE_LENGTH,
    &CFLOW_OPTION_LENGTH,
    &CFLOW_SCOPE_FIELD_TYPE,
    &CFLOW_SRCADDR,
    &CFLOW_SRCADDRV6,
    &CFLOW_DSTADDR,
    &CFLOW_DSTADDRV6,
    &CFLOW_NEXTHOP,
    &CFLOW_BGPNEXTHOP,
    &CFLOW_INPUTINT,
    &CFLOW_OUTPUTINT,
    &CFLOW_PACKETS,
    &CFLOW_OCTETS,
    &CFLOW_TIMEDELTA,
    &CFLOW_TIMESTART,
    &CFLOW_TIMEEND,
    &CFLOW_SRCPORT,
    &CFLOW_DSTPORT,
    &CFLOW_IP_PROTOCOL,
    &CFLOW_TOS,
    &CFLOW_TCPFLAGS,
    &CFLOW_TCPFLAGS_FIN,
    &CFLOW_TCPFLAGS_SYN,
    &CFLOW_TCPFLAGS_RST,
    &CFLOW_TCPFLAGS_PSH,
    &CFLOW_TCPFLAGS_ACK,
    &CFLOW_TCPFLAGS_URG,
    &CFLOW_TCPFLAGS_RESERVED,
    &CFLOW_SRCAS,
    &CFLOW_DSTAS,
    &CFLOW_SRCMASK,
    &CFLOW_DSTMASK,
    &CFLOW_OD_ID,
    &CFLOW_ABSTIMESTART,
    &CFLOW_ABSTIMEEND,
    &CFLOW_SCOPE_SYSTEM,
    &CFLOW_SCOPE_INTERFACE,
    &CFLOW_SCOPE_LINECARD,
    &CFLOW_SCOPE_CACHE,
    &CFLOW_SCOPE_TEMPLATE,
    &CFLOW_PADDING,
    &CFLOW_UNKNOWN_FIELD_TYPE,
    &CFLOW_TEMPLATE_IPFIX_TOTAL_FIELD_COUNT,
    &CFLOW_TEMPLATE_IPFIX_SCOPE_FIELD_COUNT,
    &CFLOW_TEMPLATE_IPFIX_PEN_PROVIDED,
    &CFLOW_TEMPLATE_IPFIX_FIELD_TYPE,
    &CFLOW_TEMPLATE_CISCO_FIELD_TYPE,
    &CFLOW_TEMPLATE_IPFIX_FIELD_TYPE_ENTERPRISE,
    &CFLOW_TEMPLATE_IPFIX_FIELD_PEN,
    &CFLOW_EXPECTED_SN,
    &CFLOW_PREVIOUS_FRAME,
    &CFLOW_TEMPLATE_FRAME,
    &CFLOW_FLOWSET_LENGTH_INVALID,
    &CFLOW_NO_FLOW_INFORMATION,
    &CFLOW_IPFIX_SCOPE_NONE,
    &CFLOW_IPFIX_SCOPE_TOO_MANY,
    &CFLOW_OPTIONS_TOO_MANY,
    &CFLOW_SCOPES_TOO_MANY,
    &CFLOW_ENTRIES_TOO_MANY,
    &CFLOW_FLOWSETS_IMPOSSIBLE,
    &CFLOW_NO_TEMPLATE_FOUND,
    &CFLOW_UNEXPECTED_SEQUENCE,
];

// ---- snmp ----
/// `snmp.noSuchObject`.
pub static SNMP_NOSUCHOBJECT: FieldDef = FieldDef {
    abbrev: "snmp.noSuchObject",
    name: "noSuchObject",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.noSuchInstance`.
pub static SNMP_NOSUCHINSTANCE: FieldDef = FieldDef {
    abbrev: "snmp.noSuchInstance",
    name: "noSuchInstance",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.endOfMibView`.
pub static SNMP_ENDOFMIBVIEW: FieldDef = FieldDef {
    abbrev: "snmp.endOfMibView",
    name: "endOfMibView",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.int`.
pub static SNMP_VALUE_INT: FieldDef = FieldDef {
    abbrev: "snmp.value.int",
    name: "Value (Integer32)",
    field_type: FieldType::Int64,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.octets`.
pub static SNMP_VALUE_OCTETS: FieldDef = FieldDef {
    abbrev: "snmp.value.octets",
    name: "Value (OctetString)",
    field_type: FieldType::Bytes,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.oid`.
pub static SNMP_VALUE_OID: FieldDef = FieldDef {
    abbrev: "snmp.value.oid",
    name: "Value (OID)",
    field_type: FieldType::Oid,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.null`.
pub static SNMP_VALUE_NULL: FieldDef = FieldDef {
    abbrev: "snmp.value.null",
    name: "Value (Null)",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.ipv4`.
pub static SNMP_VALUE_IPV4: FieldDef = FieldDef {
    abbrev: "snmp.value.ipv4",
    name: "Value (IpAddress)",
    field_type: FieldType::Ipv4,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.ipv6`.
pub static SNMP_VALUE_IPV6: FieldDef = FieldDef {
    abbrev: "snmp.value.ipv6",
    name: "Value (IpAddress)",
    field_type: FieldType::Ipv6,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.addr`.
pub static SNMP_VALUE_ADDR: FieldDef = FieldDef {
    abbrev: "snmp.value.addr",
    name: "Value (IpAddress)",
    field_type: FieldType::Bytes,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.u32`.
pub static SNMP_VALUE_U32: FieldDef = FieldDef {
    abbrev: "snmp.value.u32",
    name: "Value (Unsigned32)",
    field_type: FieldType::Int64,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.g32`.
pub static SNMP_VALUE_G32: FieldDef = FieldDef {
    abbrev: "snmp.value.g32",
    name: "Value (Gauge32)",
    field_type: FieldType::Int64,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.unk`.
pub static SNMP_VALUE_UNK: FieldDef = FieldDef {
    abbrev: "snmp.value.unk",
    name: "Value (Unknown)",
    field_type: FieldType::Bytes,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.counter`.
pub static SNMP_VALUE_COUNTER: FieldDef = FieldDef {
    abbrev: "snmp.value.counter",
    name: "Value (Counter32)",
    field_type: FieldType::Uint64,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.nsap`.
pub static SNMP_VALUE_NSAP: FieldDef = FieldDef {
    abbrev: "snmp.value.nsap",
    name: "Value (NSAP)",
    field_type: FieldType::Uint64,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.timeticks`.
pub static SNMP_VALUE_TIMETICKS: FieldDef = FieldDef {
    abbrev: "snmp.value.timeticks",
    name: "Value (Timeticks)",
    field_type: FieldType::Uint64,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.value.opaque`.
pub static SNMP_VALUE_OPAQUE: FieldDef = FieldDef {
    abbrev: "snmp.value.opaque",
    name: "Value (Opaque)",
    field_type: FieldType::Bytes,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.name`.
pub static SNMP_NAME: FieldDef = FieldDef {
    abbrev: "snmp.name",
    name: "Object Name",
    field_type: FieldType::Oid,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.var-bind_str`.
pub static SNMP_VAR_BIND_STR: FieldDef = FieldDef {
    abbrev: "snmp.var-bind_str",
    name: "Variable-binding-string",
    field_type: FieldType::String,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.version`.
pub static SNMP_VERSION: FieldDef = FieldDef {
    abbrev: "snmp.version",
    name: "version",
    field_type: FieldType::Int32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.community`.
pub static SNMP_COMMUNITY: FieldDef = FieldDef {
    abbrev: "snmp.community",
    name: "community",
    field_type: FieldType::String,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.data`.
pub static SNMP_DATA: FieldDef = FieldDef {
    abbrev: "snmp.data",
    name: "data",
    field_type: FieldType::Uint32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "PDUs",
    generated: false,
};

/// `snmp.get_request_element`.
pub static SNMP_GET_REQUEST_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.get_request_element",
    name: "get-request",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "GetRequest_PDU",
    generated: false,
};

/// `snmp.get_next_request_element`.
pub static SNMP_GET_NEXT_REQUEST_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.get_next_request_element",
    name: "get-next-request",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "GetNextRequest_PDU",
    generated: false,
};

/// `snmp.get_response_element`.
pub static SNMP_GET_RESPONSE_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.get_response_element",
    name: "get-response",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "GetResponse_PDU",
    generated: false,
};

/// `snmp.set_request_element`.
pub static SNMP_SET_REQUEST_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.set_request_element",
    name: "set-request",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "SetRequest_PDU",
    generated: false,
};

/// `snmp.trap_element`.
pub static SNMP_TRAP_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.trap_element",
    name: "trap",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "Trap_PDU",
    generated: false,
};

/// `snmp.getBulkRequest_element`.
pub static SNMP_GETBULKREQUEST_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.getBulkRequest_element",
    name: "getBulkRequest",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "GetBulkRequest_PDU",
    generated: false,
};

/// `snmp.informRequest_element`.
pub static SNMP_INFORMREQUEST_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.informRequest_element",
    name: "informRequest",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "InformRequest_PDU",
    generated: false,
};

/// `snmp.snmpV2_trap_element`.
pub static SNMP_SNMPV2_TRAP_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.snmpV2_trap_element",
    name: "snmpV2-trap",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "SNMPv2_Trap_PDU",
    generated: false,
};

/// `snmp.report_element`.
pub static SNMP_REPORT_ELEMENT: FieldDef = FieldDef {
    abbrev: "snmp.report_element",
    name: "report",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "Report_PDU",
    generated: false,
};

/// `snmp.request_id`.
/// `snmp.response_in`.
pub static SNMP_RESPONSE_IN: FieldDef = FieldDef {
    abbrev: "snmp.response_in",
    name: "Response In",
    field_type: FieldType::FrameNumber,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "The response to this SNMP request is in this frame",
    generated: true,
};

/// `snmp.response_to`.
pub static SNMP_RESPONSE_TO: FieldDef = FieldDef {
    abbrev: "snmp.response_to",
    name: "Response To",
    field_type: FieldType::FrameNumber,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "This is a response to the SNMP request in this frame",
    generated: true,
};

/// `snmp.time`.
pub static SNMP_TIME: FieldDef = FieldDef {
    abbrev: "snmp.time",
    name: "Time",
    field_type: FieldType::RelativeTime,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "The time between the Request and the Response",
    generated: true,
};

pub static SNMP_REQUEST_ID: FieldDef = FieldDef {
    abbrev: "snmp.request_id",
    name: "request-id",
    field_type: FieldType::Int32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "T_request_id",
    generated: false,
};

/// `snmp.error_status`.
pub static SNMP_ERROR_STATUS: FieldDef = FieldDef {
    abbrev: "snmp.error_status",
    name: "error-status",
    field_type: FieldType::Int32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `snmp.error_index`.
pub static SNMP_ERROR_INDEX: FieldDef = FieldDef {
    abbrev: "snmp.error_index",
    name: "error-index",
    field_type: FieldType::Int32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "INTEGER",
    generated: false,
};

/// `snmp.variable_bindings`.
pub static SNMP_VARIABLE_BINDINGS: FieldDef = FieldDef {
    abbrev: "snmp.variable_bindings",
    name: "variable-bindings",
    field_type: FieldType::Uint32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "VarBindList",
    generated: false,
};

/// `snmp.non_repeaters`.
pub static SNMP_NON_REPEATERS: FieldDef = FieldDef {
    abbrev: "snmp.non_repeaters",
    name: "non-repeaters",
    field_type: FieldType::Uint32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "INTEGER_0_2147483647",
    generated: false,
};

/// `snmp.max_repetitions`.
pub static SNMP_MAX_REPETITIONS: FieldDef = FieldDef {
    abbrev: "snmp.max_repetitions",
    name: "max-repetitions",
    field_type: FieldType::Uint32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "INTEGER_0_2147483647",
    generated: false,
};

/// `snmp.enterprise`.
pub static SNMP_ENTERPRISE: FieldDef = FieldDef {
    abbrev: "snmp.enterprise",
    name: "enterprise",
    field_type: FieldType::Oid,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "EnterpriseOID",
    generated: false,
};

/// `snmp.agent_addr`.
pub static SNMP_AGENT_ADDR: FieldDef = FieldDef {
    abbrev: "snmp.agent_addr",
    name: "agent-addr",
    field_type: FieldType::Ipv4,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "NetworkAddress",
    generated: false,
};

/// `snmp.generic_trap`.
pub static SNMP_GENERIC_TRAP: FieldDef = FieldDef {
    abbrev: "snmp.generic_trap",
    name: "generic-trap",
    field_type: FieldType::Int32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "GenericTrap",
    generated: false,
};

/// `snmp.specific_trap`.
pub static SNMP_SPECIFIC_TRAP: FieldDef = FieldDef {
    abbrev: "snmp.specific_trap",
    name: "specific-trap",
    field_type: FieldType::Int32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "SpecificTrap",
    generated: false,
};

/// `snmp.time_stamp`.
pub static SNMP_TIME_STAMP: FieldDef = FieldDef {
    abbrev: "snmp.time_stamp",
    name: "time-stamp",
    field_type: FieldType::Uint32,
    parent: "snmp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "TimeTicks",
    generated: false,
};

/// `snmp.varbind.wrong_tag`.
pub static SNMP_VARBIND_WRONG_TAG: FieldDef = FieldDef {
    abbrev: "snmp.varbind.wrong_tag",
    name: "Wrong tag for SNMP VarBind error value",
    field_type: FieldType::None,
    parent: "snmp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static SNMP_FIELDS: &[&FieldDef] = &[
    &SNMP_RESPONSE_IN,
    &SNMP_RESPONSE_TO,
    &SNMP_TIME,
    &SNMP_NOSUCHOBJECT,
    &SNMP_NOSUCHINSTANCE,
    &SNMP_ENDOFMIBVIEW,
    &SNMP_VALUE_INT,
    &SNMP_VALUE_OCTETS,
    &SNMP_VALUE_OID,
    &SNMP_VALUE_NULL,
    &SNMP_VALUE_IPV4,
    &SNMP_VALUE_IPV6,
    &SNMP_VALUE_ADDR,
    &SNMP_VALUE_U32,
    &SNMP_VALUE_G32,
    &SNMP_VALUE_UNK,
    &SNMP_VALUE_COUNTER,
    &SNMP_VALUE_NSAP,
    &SNMP_VALUE_TIMETICKS,
    &SNMP_VALUE_OPAQUE,
    &SNMP_NAME,
    &SNMP_VAR_BIND_STR,
    &SNMP_VERSION,
    &SNMP_COMMUNITY,
    &SNMP_DATA,
    &SNMP_GET_REQUEST_ELEMENT,
    &SNMP_GET_NEXT_REQUEST_ELEMENT,
    &SNMP_GET_RESPONSE_ELEMENT,
    &SNMP_SET_REQUEST_ELEMENT,
    &SNMP_TRAP_ELEMENT,
    &SNMP_GETBULKREQUEST_ELEMENT,
    &SNMP_INFORMREQUEST_ELEMENT,
    &SNMP_SNMPV2_TRAP_ELEMENT,
    &SNMP_REPORT_ELEMENT,
    &SNMP_REQUEST_ID,
    &SNMP_ERROR_STATUS,
    &SNMP_ERROR_INDEX,
    &SNMP_VARIABLE_BINDINGS,
    &SNMP_NON_REPEATERS,
    &SNMP_MAX_REPETITIONS,
    &SNMP_ENTERPRISE,
    &SNMP_AGENT_ADDR,
    &SNMP_GENERIC_TRAP,
    &SNMP_SPECIFIC_TRAP,
    &SNMP_TIME_STAMP,
    &SNMP_VARBIND_WRONG_TAG,
];

// ---- sflow ----
/// `sflow_245.version`.
pub static SFLOW_245_VERSION: FieldDef = FieldDef {
    abbrev: "sflow_245.version",
    name: "Datagram version",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "sFlow datagram version",
    generated: false,
};

/// `sflow_245.agenttype`.
pub static SFLOW_245_AGENTTYPE: FieldDef = FieldDef {
    abbrev: "sflow_245.agenttype",
    name: "Agent address type",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "sFlow agent address type",
    generated: false,
};

/// `sflow_245.agent`.
pub static SFLOW_245_AGENT: FieldDef = FieldDef {
    abbrev: "sflow_245.agent",
    name: "Agent address",
    field_type: FieldType::Ipv4,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "sFlow Agent IP address",
    generated: false,
};

/// `sflow_245.agent.v6`.
pub static SFLOW_245_AGENT_V6: FieldDef = FieldDef {
    abbrev: "sflow_245.agent.v6",
    name: "Agent address",
    field_type: FieldType::Ipv6,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "sFlow Agent IPv6 address",
    generated: false,
};

/// `sflow_245.sub_agent_id`.
pub static SFLOW_245_SUB_AGENT_ID: FieldDef = FieldDef {
    abbrev: "sflow_245.sub_agent_id",
    name: "Sub-agent ID",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "sFlow sub-agent ID",
    generated: false,
};

/// `sflow_5.sample_length`.
pub static SFLOW_5_SAMPLE_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow_5.sample_length",
    name: "Sample length (byte)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "sFlow sample length",
    generated: false,
};

/// `sflow_5.flow_data_length`.
pub static SFLOW_5_FLOW_DATA_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow_5.flow_data_length",
    name: "Flow data length (byte)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "sFlow flow data length",
    generated: false,
};

/// `sflow_245.sequence_number`.
pub static SFLOW_245_SEQUENCE_NUMBER: FieldDef = FieldDef {
    abbrev: "sflow_245.sequence_number",
    name: "Sequence number",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "sFlow datagram sequence number",
    generated: false,
};

/// `sflow_245.sysuptime`.
pub static SFLOW_245_SYSUPTIME: FieldDef = FieldDef {
    abbrev: "sflow_245.sysuptime",
    name: "SysUptime",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "System Uptime",
    generated: false,
};

/// `sflow_245.numsamples`.
pub static SFLOW_245_NUMSAMPLES: FieldDef = FieldDef {
    abbrev: "sflow_245.numsamples",
    name: "NumSamples",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Number of samples in sFlow datagram",
    generated: false,
};

/// `sflow_245.sampletype`.
pub static SFLOW_245_SAMPLETYPE: FieldDef = FieldDef {
    abbrev: "sflow_245.sampletype",
    name: "sFlow sample type",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Type of sFlow sample",
    generated: false,
};

/// `sflow_245.ipv4_precedence_type`.
pub static SFLOW_245_IPV4_PRECEDENCE_TYPE: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_precedence_type",
    name: "Precedence",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xe0),
    blurb: "IPv4 Precedence Type",
    generated: false,
};

/// `sflow_245.flow_record_format`.
pub static SFLOW_245_FLOW_RECORD_FORMAT: FieldDef = FieldDef {
    abbrev: "sflow_245.flow_record_format",
    name: "Format",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xfff),
    blurb: "Format of sFlow flow record",
    generated: false,
};

/// `sflow_245.counters_record_format`.
pub static SFLOW_245_COUNTERS_RECORD_FORMAT: FieldDef = FieldDef {
    abbrev: "sflow_245.counters_record_format",
    name: "Format",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xfff),
    blurb: "Format of sFlow counters record",
    generated: false,
};

/// `sflow_245.header_protocol`.
pub static SFLOW_245_HEADER_PROTOCOL: FieldDef = FieldDef {
    abbrev: "sflow_245.header_protocol",
    name: "Header protocol",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Protocol of sampled header",
    generated: false,
};

/// `sflow_245.header`.
pub static SFLOW_245_HEADER: FieldDef = FieldDef {
    abbrev: "sflow_245.header",
    name: "Header of sampled packet",
    field_type: FieldType::Bytes,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Data from sampled header",
    generated: false,
};

/// `sflow_245.vlan.in`.
pub static SFLOW_245_VLAN_IN: FieldDef = FieldDef {
    abbrev: "sflow_245.vlan.in",
    name: "Incoming 802.1Q VLAN",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Incoming VLAN ID",
    generated: false,
};

/// `sflow_245.vlan.out`.
pub static SFLOW_245_VLAN_OUT: FieldDef = FieldDef {
    abbrev: "sflow_245.vlan.out",
    name: "Outgoing 802.1Q VLAN",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Outgoing VLAN ID",
    generated: false,
};

/// `sflow_245.pri.in`.
pub static SFLOW_245_PRI_IN: FieldDef = FieldDef {
    abbrev: "sflow_245.pri.in",
    name: "Incoming 802.1p priority",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.pri.out`.
pub static SFLOW_245_PRI_OUT: FieldDef = FieldDef {
    abbrev: "sflow_245.pri.out",
    name: "Outgoing 802.1p priority",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.nexthop`.
pub static SFLOW_245_NEXTHOP: FieldDef = FieldDef {
    abbrev: "sflow_245.nexthop",
    name: "Next hop",
    field_type: FieldType::Ipv4,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Next hop address",
    generated: false,
};

/// `sflow_245.ipv4_src`.
pub static SFLOW_245_IPV4_SRC: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_src",
    name: "Source IP address",
    field_type: FieldType::Ipv4,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Source IPv4 address",
    generated: false,
};

/// `sflow_245.ipv4_dst`.
pub static SFLOW_245_IPV4_DST: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_dst",
    name: "Destination IP address",
    field_type: FieldType::Ipv4,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Destination IPv4 address",
    generated: false,
};

/// `sflow_245.nexthop.v6`.
pub static SFLOW_245_NEXTHOP_V6: FieldDef = FieldDef {
    abbrev: "sflow_245.nexthop.v6",
    name: "Next hop",
    field_type: FieldType::Ipv6,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Next hop address",
    generated: false,
};

/// `sflow_245.ipv6_src`.
pub static SFLOW_245_IPV6_SRC: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv6_src",
    name: "Source IP address",
    field_type: FieldType::Ipv6,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Source IPv6 address",
    generated: false,
};

/// `sflow_245.ipv6_dst`.
pub static SFLOW_245_IPV6_DST: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv6_dst",
    name: "Destination IP address",
    field_type: FieldType::Ipv6,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "Destination IPv6 address",
    generated: false,
};

/// `sflow_245.nexthop.src_mask`.
pub static SFLOW_245_NEXTHOP_SRC_MASK: FieldDef = FieldDef {
    abbrev: "sflow_245.nexthop.src_mask",
    name: "Next hop source mask",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Next hop source mask bits",
    generated: false,
};

/// `sflow_245.nexthop.dst_mask`.
pub static SFLOW_245_NEXTHOP_DST_MASK: FieldDef = FieldDef {
    abbrev: "sflow_245.nexthop.dst_mask",
    name: "Next hop destination mask",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Next hop destination mask bits",
    generated: false,
};

/// `sflow_245.ifindex`.
pub static SFLOW_245_IFINDEX: FieldDef = FieldDef {
    abbrev: "sflow_245.ifindex",
    name: "Interface index",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.iftype`.
pub static SFLOW_245_IFTYPE: FieldDef = FieldDef {
    abbrev: "sflow_245.iftype",
    name: "Interface Type",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifspeed`.
pub static SFLOW_245_IFSPEED: FieldDef = FieldDef {
    abbrev: "sflow_245.ifspeed",
    name: "Interface Speed",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifdirection`.
pub static SFLOW_245_IFDIRECTION: FieldDef = FieldDef {
    abbrev: "sflow_245.ifdirection",
    name: "Interface Direction",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifadmin_status`.
pub static SFLOW_245_IFADMIN_STATUS: FieldDef = FieldDef {
    abbrev: "sflow_245.ifadmin_status",
    name: "IfAdminStatus",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `sflow_245.ifoper_status`.
pub static SFLOW_245_IFOPER_STATUS: FieldDef = FieldDef {
    abbrev: "sflow_245.ifoper_status",
    name: "IfOperStatus",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `sflow_245.ifinoct`.
pub static SFLOW_245_IFINOCT: FieldDef = FieldDef {
    abbrev: "sflow_245.ifinoct",
    name: "Input Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifinpkt`.
pub static SFLOW_245_IFINPKT: FieldDef = FieldDef {
    abbrev: "sflow_245.ifinpkt",
    name: "Input Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifinmcast`.
pub static SFLOW_245_IFINMCAST: FieldDef = FieldDef {
    abbrev: "sflow_245.ifinmcast",
    name: "Input Multicast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifinbcast`.
pub static SFLOW_245_IFINBCAST: FieldDef = FieldDef {
    abbrev: "sflow_245.ifinbcast",
    name: "Input Broadcast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifindisc`.
pub static SFLOW_245_IFINDISC: FieldDef = FieldDef {
    abbrev: "sflow_245.ifindisc",
    name: "Input Discarded Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifinerr`.
pub static SFLOW_245_IFINERR: FieldDef = FieldDef {
    abbrev: "sflow_245.ifinerr",
    name: "Input Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifinunk`.
pub static SFLOW_245_IFINUNK: FieldDef = FieldDef {
    abbrev: "sflow_245.ifinunk",
    name: "Input Unknown Protocol Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifoutoct`.
pub static SFLOW_245_IFOUTOCT: FieldDef = FieldDef {
    abbrev: "sflow_245.ifoutoct",
    name: "Output Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifoutpkt`.
pub static SFLOW_245_IFOUTPKT: FieldDef = FieldDef {
    abbrev: "sflow_245.ifoutpkt",
    name: "Output Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifoutmcast`.
pub static SFLOW_245_IFOUTMCAST: FieldDef = FieldDef {
    abbrev: "sflow_245.ifoutmcast",
    name: "Output Multicast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifoutbcast`.
pub static SFLOW_245_IFOUTBCAST: FieldDef = FieldDef {
    abbrev: "sflow_245.ifoutbcast",
    name: "Output Broadcast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifoutdisc`.
pub static SFLOW_245_IFOUTDISC: FieldDef = FieldDef {
    abbrev: "sflow_245.ifoutdisc",
    name: "Output Discarded Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifouterr`.
pub static SFLOW_245_IFOUTERR: FieldDef = FieldDef {
    abbrev: "sflow_245.ifouterr",
    name: "Output Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ifpromisc`.
pub static SFLOW_245_IFPROMISC: FieldDef = FieldDef {
    abbrev: "sflow_245.ifpromisc",
    name: "Promiscuous Mode",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.dot3StatsAlignmentErrors`.
pub static SFLOW_245_DOT3STATSALIGNMENTERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsAlignmentErrors",
    name: "Alignment Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Alignment Errors",
    generated: false,
};

/// `sflow_245.dot3StatsFCSErrors`.
pub static SFLOW_245_DOT3STATSFCSERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsFCSErrors",
    name: "FCS Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats FCS Errors",
    generated: false,
};

/// `sflow_245.dot3StatsSingleCollisionFrames`.
pub static SFLOW_245_DOT3STATSSINGLECOLLISIONFRAMES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsSingleCollisionFrames",
    name: "Single Collision Frames",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Single Collision Frames",
    generated: false,
};

/// `sflow_245.dot3StatsMultipleCollisionFrames`.
pub static SFLOW_245_DOT3STATSMULTIPLECOLLISIONFRAMES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsMultipleCollisionFrames",
    name: "Multiple Collision Frames",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Multiple Collision Frames",
    generated: false,
};

/// `sflow_245.dot3StatsSQETestErrors`.
pub static SFLOW_245_DOT3STATSSQETESTERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsSQETestErrors",
    name: "SQE Test Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats SQE Test Errors",
    generated: false,
};

/// `sflow_245.dot3StatsDeferredTransmissions`.
pub static SFLOW_245_DOT3STATSDEFERREDTRANSMISSIONS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsDeferredTransmissions",
    name: "Deferred Transmissions",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Deferred Transmissions",
    generated: false,
};

/// `sflow_245.dot3StatsLateCollisions`.
pub static SFLOW_245_DOT3STATSLATECOLLISIONS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsLateCollisions",
    name: "Late Collisions",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Late Collisions",
    generated: false,
};

/// `sflow_245.dot3StatsExcessiveCollisions`.
pub static SFLOW_245_DOT3STATSEXCESSIVECOLLISIONS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsExcessiveCollisions",
    name: "Excessive Collisions",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Excessive Collisions",
    generated: false,
};

/// `sflow_245.dot3StatsInternalMacTransmitErrors`.
pub static SFLOW_245_DOT3STATSINTERNALMACTRANSMITERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsInternalMacTransmitErrors",
    name: "Internal Mac Transmit Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Internal Mac Transmit Errors",
    generated: false,
};

/// `sflow_245.dot3StatsCarrierSenseErrors`.
pub static SFLOW_245_DOT3STATSCARRIERSENSEERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsCarrierSenseErrors",
    name: "Carrier Sense Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Carrier Sense Errors",
    generated: false,
};

/// `sflow_245.dot3StatsFrameTooLongs`.
pub static SFLOW_245_DOT3STATSFRAMETOOLONGS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsFrameTooLongs",
    name: "Frame Too Longs",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Frame Too Longs",
    generated: false,
};

/// `sflow_245.dot3StatsInternalMacReceiveErrors`.
pub static SFLOW_245_DOT3STATSINTERNALMACRECEIVEERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsInternalMacReceiveErrors",
    name: "Internal Mac Receive Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Internal Mac Receive Errors",
    generated: false,
};

/// `sflow_245.dot3StatsSymbolErrors`.
pub static SFLOW_245_DOT3STATSSYMBOLERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot3StatsSymbolErrors",
    name: "Symbol Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot3 Stats Symbol Errors",
    generated: false,
};

/// `sflow_245.dot5StatsLineErrors`.
pub static SFLOW_245_DOT5STATSLINEERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsLineErrors",
    name: "Line Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Line Errors",
    generated: false,
};

/// `sflow_245.dot5StatsBurstErrors`.
pub static SFLOW_245_DOT5STATSBURSTERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsBurstErrors",
    name: "Burst Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Burst Errors",
    generated: false,
};

/// `sflow_245.dot5StatsACErrors`.
pub static SFLOW_245_DOT5STATSACERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsACErrors",
    name: "AC Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats AC Errors",
    generated: false,
};

/// `sflow_245.dot5StatsAbortTransErrors`.
pub static SFLOW_245_DOT5STATSABORTTRANSERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsAbortTransErrors",
    name: "Abort Trans Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Abort Trans Errors",
    generated: false,
};

/// `sflow_245.dot5StatsInternalErrors`.
pub static SFLOW_245_DOT5STATSINTERNALERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsInternalErrors",
    name: "Internal Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Internal Errors",
    generated: false,
};

/// `sflow_245.dot5StatsLostFrameErrors`.
pub static SFLOW_245_DOT5STATSLOSTFRAMEERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsLostFrameErrors",
    name: "Lost Frame Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Lost Frame Errors",
    generated: false,
};

/// `sflow_245.dot5StatsReceiveCongestions`.
pub static SFLOW_245_DOT5STATSRECEIVECONGESTIONS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsReceiveCongestions",
    name: "Receive Congestions",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Receive Congestions",
    generated: false,
};

/// `sflow_245.dot5StatsFrameCopiedErrors`.
pub static SFLOW_245_DOT5STATSFRAMECOPIEDERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsFrameCopiedErrors",
    name: "Frame Copied Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Frame Copied Errors",
    generated: false,
};

/// `sflow_245.dot5StatsTokenErrors`.
pub static SFLOW_245_DOT5STATSTOKENERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsTokenErrors",
    name: "Token Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Token Errors",
    generated: false,
};

/// `sflow_245.dot5StatsSoftErrors`.
pub static SFLOW_245_DOT5STATSSOFTERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsSoftErrors",
    name: "Soft Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Soft Errors",
    generated: false,
};

/// `sflow_245.dot5StatsHardErrors`.
pub static SFLOW_245_DOT5STATSHARDERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsHardErrors",
    name: "Hard Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Hard Errors",
    generated: false,
};

/// `sflow_245.dot5StatsSignalLoss`.
pub static SFLOW_245_DOT5STATSSIGNALLOSS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsSignalLoss",
    name: "Signal Loss",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Signal Loss",
    generated: false,
};

/// `sflow_245.dot5StatsTransmitBeacons`.
pub static SFLOW_245_DOT5STATSTRANSMITBEACONS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsTransmitBeacons",
    name: "Transmit Beacons",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Transmit Beacons",
    generated: false,
};

/// `sflow_245.dot5StatsRecoveries`.
pub static SFLOW_245_DOT5STATSRECOVERIES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsRecoveries",
    name: "Recoveries",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Recoveries",
    generated: false,
};

/// `sflow_245.dot5StatsLobeWires`.
pub static SFLOW_245_DOT5STATSLOBEWIRES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsLobeWires",
    name: "Lobe Wires",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Lobe Wires",
    generated: false,
};

/// `sflow_245.dot5StatsRemoves`.
pub static SFLOW_245_DOT5STATSREMOVES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsRemoves",
    name: "Removes",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Removes",
    generated: false,
};

/// `sflow_245.dot5StatsSingles`.
pub static SFLOW_245_DOT5STATSSINGLES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsSingles",
    name: "Singles",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Singles",
    generated: false,
};

/// `sflow_245.dot5StatsFreqErrors`.
pub static SFLOW_245_DOT5STATSFREQERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot5StatsFreqErrors",
    name: "Freq Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot5 Stats Freq Errors",
    generated: false,
};

/// `sflow_245.dot12InHighPriorityFrames`.
pub static SFLOW_245_DOT12INHIGHPRIORITYFRAMES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InHighPriorityFrames",
    name: "In High Priority Frames",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input High Priority Frames",
    generated: false,
};

/// `sflow_245.dot12InHighPriorityOctets`.
pub static SFLOW_245_DOT12INHIGHPRIORITYOCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InHighPriorityOctets",
    name: "In High Priority Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input High Priority Octets",
    generated: false,
};

/// `sflow_245.dot12InNormPriorityFrames`.
pub static SFLOW_245_DOT12INNORMPRIORITYFRAMES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InNormPriorityFrames",
    name: "In Normal Priority Frames",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input Normal Priority Frames",
    generated: false,
};

/// `sflow_245.dot12InNormPriorityOctets`.
pub static SFLOW_245_DOT12INNORMPRIORITYOCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InNormPriorityOctets",
    name: "In Normal Priority Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input Normal Priority Octets",
    generated: false,
};

/// `sflow_245.dot12InIPMErrors`.
pub static SFLOW_245_DOT12INIPMERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InIPMErrors",
    name: "In IPM Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input IPM Errors",
    generated: false,
};

/// `sflow_245.dot12InOversizeFrameErrors`.
pub static SFLOW_245_DOT12INOVERSIZEFRAMEERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InOversizeFrameErrors",
    name: "In Oversize Frame Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input Oversize Frame Errors",
    generated: false,
};

/// `sflow_245.dot12InDataErrors`.
pub static SFLOW_245_DOT12INDATAERRORS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InDataErrors",
    name: "In Data Errors",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input Data Errors",
    generated: false,
};

/// `sflow_245.dot12InNullAddressedFrames`.
pub static SFLOW_245_DOT12INNULLADDRESSEDFRAMES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12InNullAddressedFrames",
    name: "In Null Addressed Frames",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Input Null Addressed Frames",
    generated: false,
};

/// `sflow_245.dot12OutHighPriorityFrames`.
pub static SFLOW_245_DOT12OUTHIGHPRIORITYFRAMES: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12OutHighPriorityFrames",
    name: "Out High Priority Frames",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Output High Priority Frames",
    generated: false,
};

/// `sflow_245.dot12OutHighPriorityOctets`.
pub static SFLOW_245_DOT12OUTHIGHPRIORITYOCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12OutHighPriorityOctets",
    name: "Out High Priority Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Out High Priority Octets",
    generated: false,
};

/// `sflow_245.dot12TransitionIntoTrainings`.
pub static SFLOW_245_DOT12TRANSITIONINTOTRAININGS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12TransitionIntoTrainings",
    name: "Transition Into Trainings",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 Transition Into Trainings",
    generated: false,
};

/// `sflow_245.dot12HCInHighPriorityOctets`.
pub static SFLOW_245_DOT12HCINHIGHPRIORITYOCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12HCInHighPriorityOctets",
    name: "HC In High Priority Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 HC Input High Priority Octets",
    generated: false,
};

/// `sflow_245.dot12HCInNormPriorityOctets`.
pub static SFLOW_245_DOT12HCINNORMPRIORITYOCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12HCInNormPriorityOctets",
    name: "HC In Normal Priority Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 HC Input Normal Priority Octets",
    generated: false,
};

/// `sflow_245.dot12HCOutHighPriorityOctets`.
pub static SFLOW_245_DOT12HCOUTHIGHPRIORITYOCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.dot12HCOutHighPriorityOctets",
    name: "HC Out High Priority Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "dot12 HC Output High Priority Octets",
    generated: false,
};

/// `sflow_245.vlan_id`.
pub static SFLOW_245_VLAN_ID: FieldDef = FieldDef {
    abbrev: "sflow_245.vlan_id",
    name: "VLAN ID",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.octets`.
pub static SFLOW_245_OCTETS: FieldDef = FieldDef {
    abbrev: "sflow_245.octets",
    name: "Octets",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ucastPkts`.
pub static SFLOW_245_UCASTPKTS: FieldDef = FieldDef {
    abbrev: "sflow_245.ucastPkts",
    name: "Unicast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.multicastPkts`.
pub static SFLOW_245_MULTICASTPKTS: FieldDef = FieldDef {
    abbrev: "sflow_245.multicastPkts",
    name: "Multicast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.broadcastPkts`.
pub static SFLOW_245_BROADCASTPKTS: FieldDef = FieldDef {
    abbrev: "sflow_245.broadcastPkts",
    name: "Broadcast Packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.discards`.
pub static SFLOW_245_DISCARDS: FieldDef = FieldDef {
    abbrev: "sflow_245.discards",
    name: "Discards",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_5.cpu_5s`.
pub static SFLOW_5_CPU_5S: FieldDef = FieldDef {
    abbrev: "sflow_5.cpu_5s",
    name: "5s CPU Load (100 = 1%)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Average CPU Load Over 5 Seconds (100 = 1%)",
    generated: false,
};

/// `sflow_5.cpu_1m`.
pub static SFLOW_5_CPU_1M: FieldDef = FieldDef {
    abbrev: "sflow_5.cpu_1m",
    name: "1m CPU Load (100 = 1%)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Average CPU Load Over 1 Minute (100 = 1%)",
    generated: false,
};

/// `sflow_5.cpu_5m`.
pub static SFLOW_5_CPU_5M: FieldDef = FieldDef {
    abbrev: "sflow_5.cpu_5m",
    name: "5m CPU Load (100 = 1%)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Average CPU Load Over 5 Minutes (100 = 1%)",
    generated: false,
};

/// `sflow_5.total_memory`.
pub static SFLOW_5_TOTAL_MEMORY: FieldDef = FieldDef {
    abbrev: "sflow_5.total_memory",
    name: "Total Memory",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_5.free_memory`.
pub static SFLOW_5_FREE_MEMORY: FieldDef = FieldDef {
    abbrev: "sflow_5.free_memory",
    name: "Free Memory",
    field_type: FieldType::Uint64,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.header.frame_length`.
pub static SFLOW_245_HEADER_FRAME_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow_245.header.frame_length",
    name: "Frame Length",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.header.payload_stripped`.
pub static SFLOW_245_HEADER_PAYLOAD_STRIPPED: FieldDef = FieldDef {
    abbrev: "sflow_245.header.payload_stripped",
    name: "Payload stripped",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.header.sampled_header_length`.
pub static SFLOW_245_HEADER_SAMPLED_HEADER_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow_245.header.sampled_header_length",
    name: "Sampled header length",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ethernet.length`.
pub static SFLOW_245_ETHERNET_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow_245.ethernet.length",
    name: "Length of MAC Packet",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ethernet.source_mac_address`.
pub static SFLOW_245_ETHERNET_SOURCE_MAC_ADDRESS: FieldDef = FieldDef {
    abbrev: "sflow_245.ethernet.source_mac_address",
    name: "Source MAC Address",
    field_type: FieldType::Ethernet,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ethernet.destination_mac_address`.
pub static SFLOW_245_ETHERNET_DESTINATION_MAC_ADDRESS: FieldDef = FieldDef {
    abbrev: "sflow_245.ethernet.destination_mac_address",
    name: "Destination MAC Address",
    field_type: FieldType::Ethernet,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ethernet.packet_type`.
pub static SFLOW_245_ETHERNET_PACKET_TYPE: FieldDef = FieldDef {
    abbrev: "sflow_245.ethernet.packet_type",
    name: "Ethernet Packet Type",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.length`.
pub static SFLOW_245_IP_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.length",
    name: "Length of IP Packet",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.source_port`.
pub static SFLOW_245_IP_SOURCE_PORT: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.source_port",
    name: "Source Port",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.ip.destination_port`.
pub static SFLOW_IP_DESTINATION_PORT: FieldDef = FieldDef {
    abbrev: "sflow.ip.destination_port",
    name: "Destination Port",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.cwr`.
pub static SFLOW_245_IP_TCP_FLAG_CWR: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.cwr",
    name: "TCP Flag (CWR)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.ece`.
pub static SFLOW_245_IP_TCP_FLAG_ECE: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.ece",
    name: "TCP Flag (ECE)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.urg`.
pub static SFLOW_245_IP_TCP_FLAG_URG: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.urg",
    name: "TCP Flag (URG)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.ack`.
pub static SFLOW_245_IP_TCP_FLAG_ACK: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.ack",
    name: "TCP Flag (ACK)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.psh`.
pub static SFLOW_245_IP_TCP_FLAG_PSH: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.psh",
    name: "TCP Flag (PSH)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.rst`.
pub static SFLOW_245_IP_TCP_FLAG_RST: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.rst",
    name: "TCP Flag (RST)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.syn`.
pub static SFLOW_245_IP_TCP_FLAG_SYN: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.syn",
    name: "TCP Flag (SYN)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `sflow_245.ip.tcp_flag.fin`.
pub static SFLOW_245_IP_TCP_FLAG_FIN: FieldDef = FieldDef {
    abbrev: "sflow_245.ip.tcp_flag.fin",
    name: "TCP Flag (FIN)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x1),
    blurb: "",
    generated: false,
};

/// `sflow_245.ipv4_delay`.
pub static SFLOW_245_IPV4_DELAY: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_delay",
    name: "Delay",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

/// `sflow_245.ipv4_throughput`.
pub static SFLOW_245_IPV4_THROUGHPUT: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_throughput",
    name: "Throughput",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x8),
    blurb: "",
    generated: false,
};

/// `sflow_245.ipv4_reliability`.
pub static SFLOW_245_IPV4_RELIABILITY: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_reliability",
    name: "Reliability",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x4),
    blurb: "",
    generated: false,
};

/// `sflow_245.ipv4_cost`.
pub static SFLOW_245_IPV4_COST: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv4_cost",
    name: "Cost (RFC1349)",
    field_type: FieldType::Boolean,
    parent: "sflow",
    display: Display::Boolean32,
    bitmask: Some(0x2),
    blurb: "",
    generated: false,
};

/// `sflow_245.ipv6_priority`.
pub static SFLOW_245_IPV6_PRIORITY: FieldDef = FieldDef {
    abbrev: "sflow_245.ipv6_priority",
    name: "Priority",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.sequence_number`.
pub static SFLOW_FLOW_SAMPLE_SEQUENCE_NUMBER: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.sequence_number",
    name: "Sequence number",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.source_id_class`.
pub static SFLOW_FLOW_SAMPLE_SOURCE_ID_CLASS: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.source_id_class",
    name: "Source ID class",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xff000000),
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.sampling_rate`.
pub static SFLOW_FLOW_SAMPLE_SAMPLING_RATE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.sampling_rate",
    name: "Sampling rate",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.sample_pool`.
pub static SFLOW_FLOW_SAMPLE_SAMPLE_POOL: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.sample_pool",
    name: "Sample pool",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.dropped_packets`.
pub static SFLOW_FLOW_SAMPLE_DROPPED_PACKETS: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.dropped_packets",
    name: "Dropped packets",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.input_interface`.
pub static SFLOW_FLOW_SAMPLE_INPUT_INTERFACE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.input_interface",
    name: "Input interface (ifIndex)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface.expanded.format`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_FORMAT: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface.expanded.format",
    name: "Output interface expanded format",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface",
    name: "Output interface (ifIndex)",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::MaskedHex,
    bitmask: Some(0x7fffffff),
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface_format`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_FORMAT: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface_format",
    name: "Output interface format",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xc0000000),
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface_value`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_VALUE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface_value",
    name: "Output interface value",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0x3fffffff),
    blurb: "",
    generated: false,
};

/// `sflow.enterprise`.
pub static SFLOW_ENTERPRISE: FieldDef = FieldDef {
    abbrev: "sflow.enterprise",
    name: "Enterprise",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xfffff000),
    blurb: "",
    generated: false,
};

/// `sflow.enterprise.length`.
pub static SFLOW_ENTERPRISE_LENGTH: FieldDef = FieldDef {
    abbrev: "sflow.enterprise.length",
    name: "Length",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.enterprise.data`.
pub static SFLOW_ENTERPRISE_DATA: FieldDef = FieldDef {
    abbrev: "sflow.enterprise.data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.flow_record`.
pub static SFLOW_FLOW_SAMPLE_FLOW_RECORD: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.flow_record",
    name: "Flow record",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.source_id_type`.
pub static SFLOW_FLOW_SAMPLE_SOURCE_ID_TYPE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.source_id_type",
    name: "Source ID type",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.source_id_index`.
pub static SFLOW_FLOW_SAMPLE_SOURCE_ID_INDEX: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.source_id_index",
    name: "Source ID index",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.input_interface_format`.
pub static SFLOW_FLOW_SAMPLE_INPUT_INTERFACE_FORMAT: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.input_interface_format",
    name: "Input interface format",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.input_interface_value`.
pub static SFLOW_FLOW_SAMPLE_INPUT_INTERFACE_VALUE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.input_interface_value",
    name: "Input interface value",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface_expanded.value`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_VALUE: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface_expanded.value",
    name: "Output interface expanded value",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface_expanded.value_discarded`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_VALUE_DISCARDED: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface_expanded.value_discarded",
    name: "Output interface packet discarded",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface_expanded.number`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_NUMBER: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface_expanded.number",
    name: "Output inferface number of interfaces",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.output_interface_expanded.ifindex`.
pub static SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_IFINDEX: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.output_interface_expanded.ifindex",
    name: "Output interface ifIndex",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.counters_sample.sequence_number`.
pub static SFLOW_COUNTERS_SAMPLE_SEQUENCE_NUMBER: FieldDef = FieldDef {
    abbrev: "sflow.counters_sample.sequence_number",
    name: "Sequence number",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.counters_sample.source_id_class`.
pub static SFLOW_COUNTERS_SAMPLE_SOURCE_ID_CLASS: FieldDef = FieldDef {
    abbrev: "sflow.counters_sample.source_id_class",
    name: "Source ID class",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xff000000),
    blurb: "",
    generated: false,
};

/// `sflow.counters_sample.source_id_type`.
pub static SFLOW_COUNTERS_SAMPLE_SOURCE_ID_TYPE: FieldDef = FieldDef {
    abbrev: "sflow.counters_sample.source_id_type",
    name: "Source ID type",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xff000000),
    blurb: "",
    generated: false,
};

/// `sflow.counters_sample.source_id_index`.
pub static SFLOW_COUNTERS_SAMPLE_SOURCE_ID_INDEX: FieldDef = FieldDef {
    abbrev: "sflow.counters_sample.source_id_index",
    name: "Source ID index",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xffffff),
    blurb: "",
    generated: false,
};

/// `sflow.counters_sample.counters_records`.
pub static SFLOW_COUNTERS_SAMPLE_COUNTERS_RECORDS: FieldDef = FieldDef {
    abbrev: "sflow.counters_sample.counters_records",
    name: "Counters records",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.ip_protocol`.
pub static SFLOW_IP_PROTOCOL: FieldDef = FieldDef {
    abbrev: "sflow.ip_protocol",
    name: "IP Protocol",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.flow_sample.index`.
pub static SFLOW_FLOW_SAMPLE_INDEX: FieldDef = FieldDef {
    abbrev: "sflow.flow_sample.index",
    name: "Index",
    field_type: FieldType::Uint32,
    parent: "sflow",
    display: Display::Decimal,
    bitmask: Some(0xffffff),
    blurb: "",
    generated: false,
};

/// `sflow.invalid_address_type`.
pub static SFLOW_INVALID_ADDRESS_TYPE: FieldDef = FieldDef {
    abbrev: "sflow.invalid_address_type",
    name: "Unknown/invalid address type",
    field_type: FieldType::None,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `sflow.unknown_record_format`.
pub static SFLOW_UNKNOWN_RECORD_FORMAT: FieldDef = FieldDef {
    abbrev: "sflow.unknown_record_format",
    name: "Unknown/invalid record type",
    field_type: FieldType::None,
    parent: "sflow",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static SFLOW_FIELDS: &[&FieldDef] = &[
    &SFLOW_245_VERSION,
    &SFLOW_245_AGENTTYPE,
    &SFLOW_245_AGENT,
    &SFLOW_245_AGENT_V6,
    &SFLOW_245_SUB_AGENT_ID,
    &SFLOW_5_SAMPLE_LENGTH,
    &SFLOW_5_FLOW_DATA_LENGTH,
    &SFLOW_245_SEQUENCE_NUMBER,
    &SFLOW_245_SYSUPTIME,
    &SFLOW_245_NUMSAMPLES,
    &SFLOW_245_SAMPLETYPE,
    &SFLOW_245_IPV4_PRECEDENCE_TYPE,
    &SFLOW_245_FLOW_RECORD_FORMAT,
    &SFLOW_245_COUNTERS_RECORD_FORMAT,
    &SFLOW_245_HEADER_PROTOCOL,
    &SFLOW_245_HEADER,
    &SFLOW_245_VLAN_IN,
    &SFLOW_245_VLAN_OUT,
    &SFLOW_245_PRI_IN,
    &SFLOW_245_PRI_OUT,
    &SFLOW_245_NEXTHOP,
    &SFLOW_245_IPV4_SRC,
    &SFLOW_245_IPV4_DST,
    &SFLOW_245_NEXTHOP_V6,
    &SFLOW_245_IPV6_SRC,
    &SFLOW_245_IPV6_DST,
    &SFLOW_245_NEXTHOP_SRC_MASK,
    &SFLOW_245_NEXTHOP_DST_MASK,
    &SFLOW_245_IFINDEX,
    &SFLOW_245_IFTYPE,
    &SFLOW_245_IFSPEED,
    &SFLOW_245_IFDIRECTION,
    &SFLOW_245_IFADMIN_STATUS,
    &SFLOW_245_IFOPER_STATUS,
    &SFLOW_245_IFINOCT,
    &SFLOW_245_IFINPKT,
    &SFLOW_245_IFINMCAST,
    &SFLOW_245_IFINBCAST,
    &SFLOW_245_IFINDISC,
    &SFLOW_245_IFINERR,
    &SFLOW_245_IFINUNK,
    &SFLOW_245_IFOUTOCT,
    &SFLOW_245_IFOUTPKT,
    &SFLOW_245_IFOUTMCAST,
    &SFLOW_245_IFOUTBCAST,
    &SFLOW_245_IFOUTDISC,
    &SFLOW_245_IFOUTERR,
    &SFLOW_245_IFPROMISC,
    &SFLOW_245_DOT3STATSALIGNMENTERRORS,
    &SFLOW_245_DOT3STATSFCSERRORS,
    &SFLOW_245_DOT3STATSSINGLECOLLISIONFRAMES,
    &SFLOW_245_DOT3STATSMULTIPLECOLLISIONFRAMES,
    &SFLOW_245_DOT3STATSSQETESTERRORS,
    &SFLOW_245_DOT3STATSDEFERREDTRANSMISSIONS,
    &SFLOW_245_DOT3STATSLATECOLLISIONS,
    &SFLOW_245_DOT3STATSEXCESSIVECOLLISIONS,
    &SFLOW_245_DOT3STATSINTERNALMACTRANSMITERRORS,
    &SFLOW_245_DOT3STATSCARRIERSENSEERRORS,
    &SFLOW_245_DOT3STATSFRAMETOOLONGS,
    &SFLOW_245_DOT3STATSINTERNALMACRECEIVEERRORS,
    &SFLOW_245_DOT3STATSSYMBOLERRORS,
    &SFLOW_245_DOT5STATSLINEERRORS,
    &SFLOW_245_DOT5STATSBURSTERRORS,
    &SFLOW_245_DOT5STATSACERRORS,
    &SFLOW_245_DOT5STATSABORTTRANSERRORS,
    &SFLOW_245_DOT5STATSINTERNALERRORS,
    &SFLOW_245_DOT5STATSLOSTFRAMEERRORS,
    &SFLOW_245_DOT5STATSRECEIVECONGESTIONS,
    &SFLOW_245_DOT5STATSFRAMECOPIEDERRORS,
    &SFLOW_245_DOT5STATSTOKENERRORS,
    &SFLOW_245_DOT5STATSSOFTERRORS,
    &SFLOW_245_DOT5STATSHARDERRORS,
    &SFLOW_245_DOT5STATSSIGNALLOSS,
    &SFLOW_245_DOT5STATSTRANSMITBEACONS,
    &SFLOW_245_DOT5STATSRECOVERIES,
    &SFLOW_245_DOT5STATSLOBEWIRES,
    &SFLOW_245_DOT5STATSREMOVES,
    &SFLOW_245_DOT5STATSSINGLES,
    &SFLOW_245_DOT5STATSFREQERRORS,
    &SFLOW_245_DOT12INHIGHPRIORITYFRAMES,
    &SFLOW_245_DOT12INHIGHPRIORITYOCTETS,
    &SFLOW_245_DOT12INNORMPRIORITYFRAMES,
    &SFLOW_245_DOT12INNORMPRIORITYOCTETS,
    &SFLOW_245_DOT12INIPMERRORS,
    &SFLOW_245_DOT12INOVERSIZEFRAMEERRORS,
    &SFLOW_245_DOT12INDATAERRORS,
    &SFLOW_245_DOT12INNULLADDRESSEDFRAMES,
    &SFLOW_245_DOT12OUTHIGHPRIORITYFRAMES,
    &SFLOW_245_DOT12OUTHIGHPRIORITYOCTETS,
    &SFLOW_245_DOT12TRANSITIONINTOTRAININGS,
    &SFLOW_245_DOT12HCINHIGHPRIORITYOCTETS,
    &SFLOW_245_DOT12HCINNORMPRIORITYOCTETS,
    &SFLOW_245_DOT12HCOUTHIGHPRIORITYOCTETS,
    &SFLOW_245_VLAN_ID,
    &SFLOW_245_OCTETS,
    &SFLOW_245_UCASTPKTS,
    &SFLOW_245_MULTICASTPKTS,
    &SFLOW_245_BROADCASTPKTS,
    &SFLOW_245_DISCARDS,
    &SFLOW_5_CPU_5S,
    &SFLOW_5_CPU_1M,
    &SFLOW_5_CPU_5M,
    &SFLOW_5_TOTAL_MEMORY,
    &SFLOW_5_FREE_MEMORY,
    &SFLOW_245_HEADER_FRAME_LENGTH,
    &SFLOW_245_HEADER_PAYLOAD_STRIPPED,
    &SFLOW_245_HEADER_SAMPLED_HEADER_LENGTH,
    &SFLOW_245_ETHERNET_LENGTH,
    &SFLOW_245_ETHERNET_SOURCE_MAC_ADDRESS,
    &SFLOW_245_ETHERNET_DESTINATION_MAC_ADDRESS,
    &SFLOW_245_ETHERNET_PACKET_TYPE,
    &SFLOW_245_IP_LENGTH,
    &SFLOW_245_IP_SOURCE_PORT,
    &SFLOW_IP_DESTINATION_PORT,
    &SFLOW_245_IP_TCP_FLAG_CWR,
    &SFLOW_245_IP_TCP_FLAG_ECE,
    &SFLOW_245_IP_TCP_FLAG_URG,
    &SFLOW_245_IP_TCP_FLAG_ACK,
    &SFLOW_245_IP_TCP_FLAG_PSH,
    &SFLOW_245_IP_TCP_FLAG_RST,
    &SFLOW_245_IP_TCP_FLAG_SYN,
    &SFLOW_245_IP_TCP_FLAG_FIN,
    &SFLOW_245_IPV4_DELAY,
    &SFLOW_245_IPV4_THROUGHPUT,
    &SFLOW_245_IPV4_RELIABILITY,
    &SFLOW_245_IPV4_COST,
    &SFLOW_245_IPV6_PRIORITY,
    &SFLOW_FLOW_SAMPLE_SEQUENCE_NUMBER,
    &SFLOW_FLOW_SAMPLE_SOURCE_ID_CLASS,
    &SFLOW_FLOW_SAMPLE_SAMPLING_RATE,
    &SFLOW_FLOW_SAMPLE_SAMPLE_POOL,
    &SFLOW_FLOW_SAMPLE_DROPPED_PACKETS,
    &SFLOW_FLOW_SAMPLE_INPUT_INTERFACE,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_FORMAT,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_FORMAT,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_VALUE,
    &SFLOW_ENTERPRISE,
    &SFLOW_ENTERPRISE_LENGTH,
    &SFLOW_ENTERPRISE_DATA,
    &SFLOW_FLOW_SAMPLE_FLOW_RECORD,
    &SFLOW_FLOW_SAMPLE_SOURCE_ID_TYPE,
    &SFLOW_FLOW_SAMPLE_SOURCE_ID_INDEX,
    &SFLOW_FLOW_SAMPLE_INPUT_INTERFACE_FORMAT,
    &SFLOW_FLOW_SAMPLE_INPUT_INTERFACE_VALUE,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_VALUE,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_VALUE_DISCARDED,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_NUMBER,
    &SFLOW_FLOW_SAMPLE_OUTPUT_INTERFACE_EXPANDED_IFINDEX,
    &SFLOW_COUNTERS_SAMPLE_SEQUENCE_NUMBER,
    &SFLOW_COUNTERS_SAMPLE_SOURCE_ID_CLASS,
    &SFLOW_COUNTERS_SAMPLE_SOURCE_ID_TYPE,
    &SFLOW_COUNTERS_SAMPLE_SOURCE_ID_INDEX,
    &SFLOW_COUNTERS_SAMPLE_COUNTERS_RECORDS,
    &SFLOW_IP_PROTOCOL,
    &SFLOW_FLOW_SAMPLE_INDEX,
    &SFLOW_INVALID_ADDRESS_TYPE,
    &SFLOW_UNKNOWN_RECORD_FORMAT,
];

// ---- BGP fields (-G fields order) ----

pub static BGP_MARKER: FieldDef = FieldDef {
    abbrev: "bgp.marker",
    name: "Marker",
    field_type: FieldType::Bytes,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "Must be set to all ones (16 Bytes)",
    generated: false,
};

pub static BGP_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The total length of the message, including the header in octets",
    generated: false,
};

pub static BGP_PREFIX_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.prefix_length",
    name: "Prefix Length",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_TYPE: FieldDef = FieldDef {
    abbrev: "bgp.type",
    name: "Type",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "BGP message type",
    generated: false,
};

pub static BGP_OPEN_VERSION: FieldDef = FieldDef {
    abbrev: "bgp.open.version",
    name: "Version",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The protocol version number",
    generated: false,
};

pub static BGP_OPEN_MYAS: FieldDef = FieldDef {
    abbrev: "bgp.open.myas",
    name: "My AS",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The Autonomous System number of the sender",
    generated: false,
};

pub static BGP_OPEN_HOLDTIME: FieldDef = FieldDef {
    abbrev: "bgp.open.holdtime",
    name: "Hold Time",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The number of seconds the sender proposes for Hold Time",
    generated: false,
};

pub static BGP_OPEN_IDENTIFIER: FieldDef = FieldDef {
    abbrev: "bgp.open.identifier",
    name: "BGP Identifier",
    field_type: FieldType::Ipv4,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "The BGP Identifier of the sender",
    generated: false,
};

pub static BGP_OPEN_OPT_LEN: FieldDef = FieldDef {
    abbrev: "bgp.open.opt.len",
    name: "Optional Parameters Length",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "The total length of the Optional Parameters field in octets",
    generated: false,
};

pub static BGP_OPEN_OPT: FieldDef = FieldDef {
    abbrev: "bgp.open.opt",
    name: "Optional Parameters",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "List of optional parameters",
    generated: false,
};

pub static BGP_OPEN_OPT_PARAM: FieldDef = FieldDef {
    abbrev: "bgp.open.opt.param",
    name: "Optional Parameter",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_OPEN_OPT_PARAM_TYPE: FieldDef = FieldDef {
    abbrev: "bgp.open.opt.param.type",
    name: "Parameter Type",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Unambiguously identifies individual parameters",
    generated: false,
};

pub static BGP_OPEN_OPT_PARAM_LEN: FieldDef = FieldDef {
    abbrev: "bgp.open.opt.param.len",
    name: "Parameter Length",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of the Parameter Value",
    generated: false,
};

pub static BGP_OPEN_OPT_PARAM_AUTH: FieldDef = FieldDef {
    abbrev: "bgp.open.opt.param.auth",
    name: "Authentication Data",
    field_type: FieldType::Bytes,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "Deprecated",
    generated: false,
};

pub static BGP_OPEN_OPT_PARAM_UNKNOWN: FieldDef = FieldDef {
    abbrev: "bgp.open.opt.param.unknown",
    name: "Unknown",
    field_type: FieldType::Bytes,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "Unknown Parameter",
    generated: false,
};

pub static BGP_NOTIFY_MAJOR_ERROR: FieldDef = FieldDef {
    abbrev: "bgp.notify.major_error",
    name: "Major error Code",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error",
    name: "Minor error Code (Message Header)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_OPEN: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_open",
    name: "Minor error Code (Open Message)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_UPDATE: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_update",
    name: "Minor error Code (Update Message)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_EXPIRED: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_expired",
    name: "Minor error Code (Hold Timer Expired)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_STATE: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_state",
    name: "Minor error Code (State Machine)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_CEASE: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_cease",
    name: "Minor error Code (Cease)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_ROUTE_REFRESH: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_route_refresh",
    name: "Minor error Code (Route-Refresh message)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_ERROR_UNKNOWN: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_error_unknown",
    name: "Minor error Code (Unknown)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NOTIFY_MINOR_DATA: FieldDef = FieldDef {
    abbrev: "bgp.notify.minor_data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_ROUTE_REFRESH_AFI: FieldDef = FieldDef {
    abbrev: "bgp.route_refresh.afi",
    name: "Address family identifier (AFI)",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_ROUTE_REFRESH_SUBTYPE: FieldDef = FieldDef {
    abbrev: "bgp.route_refresh.subtype",
    name: "Subtype",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_ROUTE_REFRESH_SAFI: FieldDef = FieldDef {
    abbrev: "bgp.route_refresh.safi",
    name: "Subsequent address family identifier (SAFI)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_WITHDRAWN_ROUTES_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.update.withdrawn_routes.length",
    name: "Withdrawn Routes Length",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_WITHDRAWN_ROUTES: FieldDef = FieldDef {
    abbrev: "bgp.update.withdrawn_routes",
    name: "Withdrawn Routes",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AGGREGATOR_AS: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.aggregator_as",
    name: "Aggregator AS",
    field_type: FieldType::Uint32,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTES: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attributes",
    name: "Path attributes",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTES_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attributes.length",
    name: "Total Path Attribute Length",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AGGREGATOR_ORIGIN: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.aggregator_origin",
    name: "Aggregator origin",
    field_type: FieldType::Ipv4,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.as_path_segment",
    name: "AS Path segment",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_TYPE: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.as_path_segment.type",
    name: "Segment type",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.as_path_segment.length",
    name: "Segment length (number of ASN)",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_AS2: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.as_path_segment.as2",
    name: "AS2",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_AS4: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.as_path_segment.as4",
    name: "AS4",
    field_type: FieldType::Uint32,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITIES: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.communities",
    name: "Communities",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.community",
    name: "Community",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_WELLKNOWN: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.community_wellknown",
    name: "Community Well-known",
    field_type: FieldType::Uint32,
    parent: "bgp",
    display: Display::Hex,
    bitmask: None,
    blurb: "Reserved",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_AS: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.community_as",
    name: "Community AS",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_VALUE: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.community_value",
    name: "Community value",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_LOCAL_PREF: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.local_pref",
    name: "Local preference",
    field_type: FieldType::Uint32,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_MULTI_EXIT_DISC: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.multi_exit_disc",
    name: "Multiple exit discriminator",
    field_type: FieldType::Uint32,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_NEXT_HOP: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.next_hop",
    name: "Next hop",
    field_type: FieldType::Ipv4,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_ORIGIN: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.origin",
    name: "Origin",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute",
    name: "Path Attribute",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_FLAGS: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.flags",
    name: "Flags",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_OPTIONAL: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.flags.optional",
    name: "Optional",
    field_type: FieldType::Boolean,
    parent: "bgp",
    display: Display::Boolean8,
    bitmask: Some(0x80),
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_TRANSITIVE: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.flags.transitive",
    name: "Transitive",
    field_type: FieldType::Boolean,
    parent: "bgp",
    display: Display::Boolean8,
    bitmask: Some(0x40),
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_PARTIAL: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.flags.partial",
    name: "Partial",
    field_type: FieldType::Boolean,
    parent: "bgp",
    display: Display::Boolean8,
    bitmask: Some(0x20),
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_EXTENDED_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.flags.extended_length",
    name: "Extended-Length",
    field_type: FieldType::Boolean,
    parent: "bgp",
    display: Display::Boolean8,
    bitmask: Some(0x10),
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_UNUSED: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.flags.unused",
    name: "Unused",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Hex,
    bitmask: Some(0xf),
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_TYPE_CODE: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.type_code",
    name: "Type Code",
    field_type: FieldType::Uint8,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_PATH_ATTRIBUTE_LENGTH: FieldDef = FieldDef {
    abbrev: "bgp.update.path_attribute.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "bgp",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_WITHDRAWN_PREFIX: FieldDef = FieldDef {
    abbrev: "bgp.withdrawn_prefix",
    name: "Withdrawn prefix",
    field_type: FieldType::Ipv4,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_UPDATE_NLRI: FieldDef = FieldDef {
    abbrev: "bgp.update.nlri",
    name: "Network Layer Reachability Information (NLRI)",
    field_type: FieldType::None,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static BGP_NLRI_PREFIX: FieldDef = FieldDef {
    abbrev: "bgp.nlri_prefix",
    name: "NLRI prefix",
    field_type: FieldType::Ipv4,
    parent: "bgp",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static BGP_FIELDS: &[&FieldDef] = &[
    &BGP_MARKER,
    &BGP_LENGTH,
    &BGP_PREFIX_LENGTH,
    &BGP_TYPE,
    &BGP_OPEN_VERSION,
    &BGP_OPEN_MYAS,
    &BGP_OPEN_HOLDTIME,
    &BGP_OPEN_IDENTIFIER,
    &BGP_OPEN_OPT_LEN,
    &BGP_OPEN_OPT,
    &BGP_OPEN_OPT_PARAM,
    &BGP_OPEN_OPT_PARAM_TYPE,
    &BGP_OPEN_OPT_PARAM_LEN,
    &BGP_OPEN_OPT_PARAM_AUTH,
    &BGP_OPEN_OPT_PARAM_UNKNOWN,
    &BGP_NOTIFY_MAJOR_ERROR,
    &BGP_NOTIFY_MINOR_ERROR,
    &BGP_NOTIFY_MINOR_ERROR_OPEN,
    &BGP_NOTIFY_MINOR_ERROR_UPDATE,
    &BGP_NOTIFY_MINOR_ERROR_EXPIRED,
    &BGP_NOTIFY_MINOR_ERROR_STATE,
    &BGP_NOTIFY_MINOR_ERROR_CEASE,
    &BGP_NOTIFY_MINOR_ERROR_ROUTE_REFRESH,
    &BGP_NOTIFY_MINOR_ERROR_UNKNOWN,
    &BGP_NOTIFY_MINOR_DATA,
    &BGP_ROUTE_REFRESH_AFI,
    &BGP_ROUTE_REFRESH_SUBTYPE,
    &BGP_ROUTE_REFRESH_SAFI,
    &BGP_UPDATE_WITHDRAWN_ROUTES_LENGTH,
    &BGP_UPDATE_WITHDRAWN_ROUTES,
    &BGP_UPDATE_PATH_ATTRIBUTE_AGGREGATOR_AS,
    &BGP_UPDATE_PATH_ATTRIBUTES,
    &BGP_UPDATE_PATH_ATTRIBUTES_LENGTH,
    &BGP_UPDATE_PATH_ATTRIBUTE_AGGREGATOR_ORIGIN,
    &BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT,
    &BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_TYPE,
    &BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_LENGTH,
    &BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_AS2,
    &BGP_UPDATE_PATH_ATTRIBUTE_AS_PATH_SEGMENT_AS4,
    &BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITIES,
    &BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY,
    &BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_WELLKNOWN,
    &BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_AS,
    &BGP_UPDATE_PATH_ATTRIBUTE_COMMUNITY_VALUE,
    &BGP_UPDATE_PATH_ATTRIBUTE_LOCAL_PREF,
    &BGP_UPDATE_PATH_ATTRIBUTE_MULTI_EXIT_DISC,
    &BGP_UPDATE_PATH_ATTRIBUTE_NEXT_HOP,
    &BGP_UPDATE_PATH_ATTRIBUTE_ORIGIN,
    &BGP_UPDATE_PATH_ATTRIBUTE,
    &BGP_UPDATE_PATH_ATTRIBUTE_FLAGS,
    &BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_OPTIONAL,
    &BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_TRANSITIVE,
    &BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_PARTIAL,
    &BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_EXTENDED_LENGTH,
    &BGP_UPDATE_PATH_ATTRIBUTE_FLAGS_UNUSED,
    &BGP_UPDATE_PATH_ATTRIBUTE_TYPE_CODE,
    &BGP_UPDATE_PATH_ATTRIBUTE_LENGTH,
    &BGP_WITHDRAWN_PREFIX,
    &BGP_UPDATE_NLRI,
    &BGP_NLRI_PREFIX,
];

// ---- HTTP fields (-G fields order) ----

pub static HTTP_RESPONSE: FieldDef = FieldDef {
    abbrev: "http.response",
    name: "Response",
    field_type: FieldType::Boolean,
    parent: "http",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "true if HTTP response",
    generated: true,
};

pub static HTTP_REQUEST: FieldDef = FieldDef {
    abbrev: "http.request",
    name: "Request",
    field_type: FieldType::Boolean,
    parent: "http",
    display: Display::Boolean0,
    bitmask: None,
    blurb: "true if HTTP request",
    generated: true,
};

pub static HTTP_RESPONSE_LINE: FieldDef = FieldDef {
    abbrev: "http.response.line",
    name: "Response line",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static HTTP_REQUEST_LINE: FieldDef = FieldDef {
    abbrev: "http.request.line",
    name: "Request line",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static HTTP_REQUEST_METHOD: FieldDef = FieldDef {
    abbrev: "http.request.method",
    name: "Request Method",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Request Method",
    generated: false,
};

pub static HTTP_REQUEST_URI: FieldDef = FieldDef {
    abbrev: "http.request.uri",
    name: "Request URI",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Request-URI",
    generated: false,
};

pub static HTTP_REQUEST_VERSION: FieldDef = FieldDef {
    abbrev: "http.request.version",
    name: "Request Version",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Request HTTP-Version",
    generated: false,
};

pub static HTTP_RESPONSE_VERSION: FieldDef = FieldDef {
    abbrev: "http.response.version",
    name: "Response Version",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Response HTTP-Version",
    generated: false,
};

pub static HTTP_REQUEST_FULL_URI: FieldDef = FieldDef {
    abbrev: "http.request.full_uri",
    name: "Full request URI",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "The full requested URI (including host name)",
    generated: false,
};

pub static HTTP_RESPONSE_CODE: FieldDef = FieldDef {
    abbrev: "http.response.code",
    name: "Status Code",
    field_type: FieldType::Uint24,
    parent: "http",
    display: Display::Decimal,
    bitmask: None,
    blurb: "HTTP Response Status Code",
    generated: false,
};

pub static HTTP_RESPONSE_CODE_DESC: FieldDef = FieldDef {
    abbrev: "http.response.code.desc",
    name: "Status Code Description",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Response Status Code Description",
    generated: false,
};

pub static HTTP_RESPONSE_PHRASE: FieldDef = FieldDef {
    abbrev: "http.response.phrase",
    name: "Response Phrase",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Response Reason Phrase",
    generated: false,
};

pub static HTTP_CONTENT_TYPE: FieldDef = FieldDef {
    abbrev: "http.content_type",
    name: "Content-Type",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Content-Type header",
    generated: false,
};

pub static HTTP_CONTENT_LENGTH_HEADER: FieldDef = FieldDef {
    abbrev: "http.content_length_header",
    name: "Content-Length",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Content-Length header",
    generated: false,
};

pub static HTTP_CONTENT_LENGTH: FieldDef = FieldDef {
    abbrev: "http.content_length",
    name: "Content length",
    field_type: FieldType::Uint64,
    parent: "http",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static HTTP_CONTENT_ENCODING: FieldDef = FieldDef {
    abbrev: "http.content_encoding",
    name: "Content-Encoding",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Content-Encoding header",
    generated: false,
};

pub static HTTP_TRANSFER_ENCODING: FieldDef = FieldDef {
    abbrev: "http.transfer_encoding",
    name: "Transfer-Encoding",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Transfer-Encoding header",
    generated: false,
};

pub static HTTP_USER_AGENT: FieldDef = FieldDef {
    abbrev: "http.user_agent",
    name: "User-Agent",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP User-Agent header",
    generated: false,
};

pub static HTTP_HOST: FieldDef = FieldDef {
    abbrev: "http.host",
    name: "Host",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Host",
    generated: false,
};

pub static HTTP_CONNECTION: FieldDef = FieldDef {
    abbrev: "http.connection",
    name: "Connection",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Connection",
    generated: false,
};

pub static HTTP_ACCEPT: FieldDef = FieldDef {
    abbrev: "http.accept",
    name: "Accept",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Accept",
    generated: false,
};

pub static HTTP_ACCEPT_LANGUAGE: FieldDef = FieldDef {
    abbrev: "http.accept_language",
    name: "Accept-Language",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Accept Language",
    generated: false,
};

pub static HTTP_ACCEPT_ENCODING: FieldDef = FieldDef {
    abbrev: "http.accept_encoding",
    name: "Accept Encoding",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Accept Encoding",
    generated: false,
};

pub static HTTP_SERVER: FieldDef = FieldDef {
    abbrev: "http.server",
    name: "Server",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "HTTP Server",
    generated: false,
};

pub static HTTP_REQUEST_IN: FieldDef = FieldDef {
    abbrev: "http.request_in",
    name: "Request in frame",
    field_type: FieldType::FrameNumber,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "This packet is a response to the packet with this number",
    generated: true,
};

pub static HTTP_RESPONSE_IN: FieldDef = FieldDef {
    abbrev: "http.response_in",
    name: "Response in frame",
    field_type: FieldType::FrameNumber,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "This packet will be responded in the packet with this number",
    generated: true,
};

pub static HTTP_TIME: FieldDef = FieldDef {
    abbrev: "http.time",
    name: "Time since request",
    field_type: FieldType::RelativeTime,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "Time since the request was sent",
    generated: true,
};

pub static HTTP_CHUNKED_TRAILER_PART: FieldDef = FieldDef {
    abbrev: "http.chunked_trailer_part",
    name: "trailer-part",
    field_type: FieldType::String,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "Optional trailer in a chunked body",
    generated: false,
};

pub static HTTP_CHUNK_BOUNDARY: FieldDef = FieldDef {
    abbrev: "http.chunk_boundary",
    name: "Chunk boundary",
    field_type: FieldType::Bytes,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static HTTP_CHUNK_SIZE: FieldDef = FieldDef {
    abbrev: "http.chunk_size",
    name: "Chunk size",
    field_type: FieldType::Uint32,
    parent: "http",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static HTTP_CHUNK_DATA: FieldDef = FieldDef {
    abbrev: "http.chunk_data",
    name: "Chunk data",
    field_type: FieldType::Bytes,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static HTTP_FILE_DATA: FieldDef = FieldDef {
    abbrev: "http.file_data",
    name: "File Data",
    field_type: FieldType::Bytes,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static HTTP_EXCESS_DATA: FieldDef = FieldDef {
    abbrev: "http.excess_data",
    name: "Excess data after a body (not a new request/response), previous Content-Length bogus?",
    field_type: FieldType::None,
    parent: "http",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

static HTTP_FIELDS: &[&FieldDef] = &[
    &HTTP_RESPONSE,
    &HTTP_REQUEST,
    &HTTP_RESPONSE_LINE,
    &HTTP_REQUEST_LINE,
    &HTTP_REQUEST_METHOD,
    &HTTP_REQUEST_URI,
    &HTTP_REQUEST_VERSION,
    &HTTP_RESPONSE_VERSION,
    &HTTP_REQUEST_FULL_URI,
    &HTTP_RESPONSE_CODE,
    &HTTP_RESPONSE_CODE_DESC,
    &HTTP_RESPONSE_PHRASE,
    &HTTP_CONTENT_TYPE,
    &HTTP_CONTENT_LENGTH_HEADER,
    &HTTP_CONTENT_LENGTH,
    &HTTP_CONTENT_ENCODING,
    &HTTP_TRANSFER_ENCODING,
    &HTTP_USER_AGENT,
    &HTTP_HOST,
    &HTTP_CONNECTION,
    &HTTP_ACCEPT,
    &HTTP_ACCEPT_LANGUAGE,
    &HTTP_ACCEPT_ENCODING,
    &HTTP_SERVER,
    &HTTP_REQUEST_IN,
    &HTTP_RESPONSE_IN,
    &HTTP_TIME,
    &HTTP_CHUNKED_TRAILER_PART,
    &HTTP_CHUNK_BOUNDARY,
    &HTTP_CHUNK_SIZE,
    &HTTP_CHUNK_DATA,
    &HTTP_FILE_DATA,
    &HTTP_EXCESS_DATA,
];

// ---- TLS fields (-G fields order) ----

pub static TLS_STREAM: FieldDef = FieldDef {
    abbrev: "tls.stream",
    name: "Stream index",
    field_type: FieldType::Uint32,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_RECORD: FieldDef = FieldDef {
    abbrev: "tls.record",
    name: "Record Layer",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_RECORD_CONTENT_TYPE: FieldDef = FieldDef {
    abbrev: "tls.record.content_type",
    name: "Content Type",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

/// `tls.record.opaque_type`.
pub static TLS_RECORD_OPAQUE_TYPE: FieldDef = FieldDef {
    abbrev: "tls.record.opaque_type",
    name: "Opaque Type",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Always set to value 23, actual content type is known after decryption",
    generated: false,
};

pub static TLS_RECORD_VERSION: FieldDef = FieldDef {
    abbrev: "tls.record.version",
    name: "Version",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Hex,
    bitmask: None,
    blurb: "Record layer version",
    generated: false,
};

pub static TLS_RECORD_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.record.length",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of TLS record data",
    generated: false,
};

pub static TLS_RECORD_SEQUENCE_NUMBER: FieldDef = FieldDef {
    abbrev: "tls.record.sequence_number",
    name: "Sequence Number",
    field_type: FieldType::Uint64,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_RECORD_PADDING_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.record.padding_length",
    name: "Padding Length",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of padding at end of record",
    generated: true,
};

pub static TLS_RECORD_LENGTH_INVALID: FieldDef = FieldDef {
    abbrev: "tls.record.length.invalid",
    name: "Record fragment length is too small or too large",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_APP_DATA_PROTO: FieldDef = FieldDef {
    abbrev: "tls.app_data_proto",
    name: "Application Data Protocol",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_APP_DATA: FieldDef = FieldDef {
    abbrev: "tls.app_data",
    name: "Encrypted Application Data",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Payload is encrypted application data",
    generated: false,
};

pub static TLS_ALERT_MESSAGE: FieldDef = FieldDef {
    abbrev: "tls.alert_message",
    name: "Alert Message",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_ALERT_MESSAGE_LEVEL: FieldDef = FieldDef {
    abbrev: "tls.alert_message.level",
    name: "Level",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Alert message level",
    generated: false,
};

pub static TLS_ALERT_MESSAGE_DESC: FieldDef = FieldDef {
    abbrev: "tls.alert_message.desc",
    name: "Description",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Alert message description",
    generated: false,
};

pub static TLS_HANDSHAKE: FieldDef = FieldDef {
    abbrev: "tls.handshake",
    name: "Handshake Protocol",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Handshake protocol message",
    generated: false,
};

pub static TLS_HANDSHAKE_TYPE: FieldDef = FieldDef {
    abbrev: "tls.handshake.type",
    name: "Handshake Type",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Type of handshake message",
    generated: false,
};

pub static TLS_HANDSHAKE_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.length",
    name: "Length",
    field_type: FieldType::Uint24,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of handshake message",
    generated: false,
};

pub static TLS_HANDSHAKE_VERIFY_DATA: FieldDef = FieldDef {
    abbrev: "tls.handshake.verify_data",
    name: "Verify Data",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Opaque verification data",
    generated: false,
};

pub static TLS_HANDSHAKE_KEY_UPDATE_REQUEST: FieldDef = FieldDef {
    abbrev: "tls.handshake.key_update.request_update",
    name: "Key Update Request",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Whether the receiver should also update its keys",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_TICKET_LIFETIME_HINT: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_ticket_lifetime_hint",
    name: "Session Ticket Lifetime Hint",
    field_type: FieldType::Uint32,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "New Session Ticket Lifetime Hint",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_TICKET_AGE_ADD: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_ticket_age_add",
    name: "Session Ticket Age Add",
    field_type: FieldType::Uint32,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Random 32-bit value to obscure age of ticket",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_TICKET_NONCE_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_ticket_nonce_length",
    name: "Session Ticket Nonce Length",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_TICKET_NONCE: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_ticket_nonce",
    name: "Session Ticket Nonce",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "A unique per-ticket value",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_TICKET_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_ticket_length",
    name: "Session Ticket Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "New Session Ticket Length",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_TICKET: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_ticket",
    name: "Session Ticket",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "New Session Ticket",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_ID_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_id_length",
    name: "Session ID Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of session ID field",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_length",
    name: "Extensions Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of hello extensions",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSION: FieldDef = FieldDef {
    abbrev: "tls.handshake.extension",
    name: "Extension",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Hello extension",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSION_TYPE: FieldDef = FieldDef {
    abbrev: "tls.handshake.extension.type",
    name: "Type",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Hello extension type",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSION_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.extension.len",
    name: "Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of a hello extension",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSION_DATA: FieldDef = FieldDef {
    abbrev: "tls.handshake.extension.data",
    name: "Data",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Hello Extension data",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUPS_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_supported_groups_length",
    name: "Supported Groups List Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUPS: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_supported_groups",
    name: "Supported Groups List",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "List of supported groups (formerly Supported Elliptic Curves)",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUP: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_supported_group",
    name: "Supported Group",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMATS_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_ec_point_formats_length",
    name: "EC point formats Length",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of elliptic curves point formats field",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMATS: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_ec_point_formats",
    name: "EC point formats",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "List of elliptic curves point format",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMAT: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_ec_point_format",
    name: "EC point format",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Elliptic curves point format",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_ALPN_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_alpn_len",
    name: "ALPN Extension Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of the ALPN Extension",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_ALPN_LIST: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_alpn_list",
    name: "ALPN Protocol",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_ALPN_STR_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_alpn_str_len",
    name: "ALPN string length",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of ALPN string",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_ALPN_STR: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_alpn_str",
    name: "ALPN Next Protocol",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_CLIENT_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_key_share_client_length",
    name: "Client Key Share Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_GROUP: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_key_share_group",
    name: "Group",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_key_share_key_exchange_length",
    name: "Key Exchange Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_key_share_key_exchange",
    name: "Key Exchange",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_SELECTED_GROUP: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_key_share_selected_group",
    name: "Selected Group",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSIONS_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions.supported_versions_len",
    name: "Supported Versions length",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSION: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions.supported_version",
    name: "Supported Version",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_LIST_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_server_name_list_len",
    name: "Server Name list length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of server name list",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_server_name_len",
    name: "Server Name length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of server name string",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_TYPE: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_server_name_type",
    name: "Server Name Type",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME: FieldDef = FieldDef {
    abbrev: "tls.handshake.extensions_server_name",
    name: "Server Name",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_SIG_HASH_ALG_LEN: FieldDef = FieldDef {
    abbrev: "tls.handshake.sig_hash_alg_len",
    name: "Signature Hash Algorithms Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of Signature Hash Algorithms",
    generated: false,
};

pub static TLS_HANDSHAKE_SIG_HASH_ALGS: FieldDef = FieldDef {
    abbrev: "tls.handshake.sig_hash_algs",
    name: "Signature Algorithms",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "List of supported Signature Algorithms",
    generated: false,
};

pub static TLS_HANDSHAKE_SIG_HASH_ALG: FieldDef = FieldDef {
    abbrev: "tls.handshake.sig_hash_alg",
    name: "Signature Algorithm",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_SIG_HASH_HASH: FieldDef = FieldDef {
    abbrev: "tls.handshake.sig_hash_hash",
    name: "Signature Hash Algorithm Hash",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Hash algorithm (TLS 1.2)",
    generated: false,
};

pub static TLS_HANDSHAKE_SIG_HASH_SIG: FieldDef = FieldDef {
    abbrev: "tls.handshake.sig_hash_sig",
    name: "Signature Hash Algorithm Signature",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Signature algorithm (TLS 1.2)",
    generated: false,
};

pub static TLS_HANDSHAKE_RANDOM: FieldDef = FieldDef {
    abbrev: "tls.handshake.random",
    name: "Random",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Random values used for deriving keys",
    generated: false,
};

pub static TLS_HANDSHAKE_RANDOM_TIME: FieldDef = FieldDef {
    abbrev: "tls.handshake.random_time",
    name: "GMT Unix Time",
    field_type: FieldType::AbsoluteTime,
    parent: "tls",
    display: Display::IsoTime,
    bitmask: None,
    blurb: "Unix time field of random structure",
    generated: false,
};

pub static TLS_HANDSHAKE_RANDOM_BYTES: FieldDef = FieldDef {
    abbrev: "tls.handshake.random_bytes",
    name: "Random Bytes",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Random values used for deriving keys",
    generated: false,
};

pub static TLS_HANDSHAKE_SESSION_ID: FieldDef = FieldDef {
    abbrev: "tls.handshake.session_id",
    name: "Session ID",
    field_type: FieldType::Bytes,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "Identifies the SSL session, allowing later resumption",
    generated: false,
};

pub static TLS_HANDSHAKE_VERSION: FieldDef = FieldDef {
    abbrev: "tls.handshake.version",
    name: "Version",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Hex,
    bitmask: None,
    blurb: "Maximum version supported by client [legacy_version if supported_versions ext is present]",
    generated: false,
};

pub static TLS_HANDSHAKE_CIPHER_SUITES_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.cipher_suites_length",
    name: "Cipher Suites Length",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of cipher suites field",
    generated: false,
};

pub static TLS_HANDSHAKE_CIPHERSUITES: FieldDef = FieldDef {
    abbrev: "tls.handshake.ciphersuites",
    name: "Cipher Suites",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "List of cipher suites supported by client",
    generated: false,
};

pub static TLS_HANDSHAKE_CIPHERSUITE: FieldDef = FieldDef {
    abbrev: "tls.handshake.ciphersuite",
    name: "Cipher Suite",
    field_type: FieldType::Uint16,
    parent: "tls",
    display: Display::Hex,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_COMP_METHODS_LENGTH: FieldDef = FieldDef {
    abbrev: "tls.handshake.comp_methods_length",
    name: "Compression Methods Length",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "Length of compression methods field",
    generated: false,
};

pub static TLS_HANDSHAKE_COMP_METHODS: FieldDef = FieldDef {
    abbrev: "tls.handshake.comp_methods",
    name: "Compression Methods",
    field_type: FieldType::None,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "List of compression methods supported by client",
    generated: false,
};

pub static TLS_HANDSHAKE_COMP_METHOD: FieldDef = FieldDef {
    abbrev: "tls.handshake.comp_method",
    name: "Compression Method",
    field_type: FieldType::Uint8,
    parent: "tls",
    display: Display::Decimal,
    bitmask: None,
    blurb: "",
    generated: false,
};

pub static TLS_HANDSHAKE_JA3_FULL: FieldDef = FieldDef {
    abbrev: "tls.handshake.ja3_full",
    name: "JA3 Fullstring",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_HANDSHAKE_JA3: FieldDef = FieldDef {
    abbrev: "tls.handshake.ja3",
    name: "JA3",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_HANDSHAKE_JA3S_FULL: FieldDef = FieldDef {
    abbrev: "tls.handshake.ja3s_full",
    name: "JA3S Fullstring",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_HANDSHAKE_JA3S: FieldDef = FieldDef {
    abbrev: "tls.handshake.ja3s",
    name: "JA3S",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_HANDSHAKE_JA4: FieldDef = FieldDef {
    abbrev: "tls.handshake.ja4",
    name: "JA4",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

pub static TLS_HANDSHAKE_JA4_R: FieldDef = FieldDef {
    abbrev: "tls.handshake.ja4_r",
    name: "JA4_r",
    field_type: FieldType::String,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "",
    generated: true,
};

/// `tls.reassembled_in`.
pub static TLS_REASSEMBLED_IN: FieldDef = FieldDef {
    abbrev: "tls.reassembled_in",
    name: "Reassembled PDU in frame",
    field_type: FieldType::FrameNumber,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "The PDU that doesn't end in this segment is reassembled in this frame",
    generated: true,
};

/// `tls.handshake.reassembled_in`.
///
/// This one prints without brackets, so the definition is not marked
/// generated.
pub static TLS_HANDSHAKE_REASSEMBLED_IN: FieldDef = FieldDef {
    abbrev: "tls.handshake.reassembled_in",
    name: "Reassembled Handshake Message in frame",
    field_type: FieldType::FrameNumber,
    parent: "tls",
    display: Display::None,
    bitmask: None,
    blurb: "The handshake message is fully reassembled in this frame",
    generated: false,
};

static TLS_FIELDS: &[&FieldDef] = &[
    &TLS_STREAM,
    &TLS_RECORD,
    &TLS_RECORD_CONTENT_TYPE,
    &TLS_RECORD_OPAQUE_TYPE,
    &TLS_RECORD_VERSION,
    &TLS_RECORD_LENGTH,
    &TLS_RECORD_SEQUENCE_NUMBER,
    &TLS_RECORD_PADDING_LENGTH,
    &TLS_RECORD_LENGTH_INVALID,
    &TLS_APP_DATA,
    &TLS_APP_DATA_PROTO,
    &TLS_ALERT_MESSAGE,
    &TLS_ALERT_MESSAGE_LEVEL,
    &TLS_ALERT_MESSAGE_DESC,
    &TLS_HANDSHAKE,
    &TLS_HANDSHAKE_TYPE,
    &TLS_HANDSHAKE_LENGTH,
    &TLS_HANDSHAKE_VERIFY_DATA,
    &TLS_HANDSHAKE_KEY_UPDATE_REQUEST,
    &TLS_HANDSHAKE_SESSION_TICKET_LIFETIME_HINT,
    &TLS_HANDSHAKE_SESSION_TICKET_AGE_ADD,
    &TLS_HANDSHAKE_SESSION_TICKET_NONCE_LENGTH,
    &TLS_HANDSHAKE_SESSION_TICKET_NONCE,
    &TLS_HANDSHAKE_SESSION_TICKET_LENGTH,
    &TLS_HANDSHAKE_SESSION_TICKET,
    &TLS_HANDSHAKE_SESSION_ID_LENGTH,
    &TLS_HANDSHAKE_EXTENSIONS_LENGTH,
    &TLS_HANDSHAKE_EXTENSION,
    &TLS_HANDSHAKE_EXTENSION_TYPE,
    &TLS_HANDSHAKE_EXTENSION_LEN,
    &TLS_HANDSHAKE_EXTENSION_DATA,
    &TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUPS_LENGTH,
    &TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUPS,
    &TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_GROUP,
    &TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMATS_LENGTH,
    &TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMATS,
    &TLS_HANDSHAKE_EXTENSIONS_EC_POINT_FORMAT,
    &TLS_HANDSHAKE_EXTENSIONS_ALPN_LEN,
    &TLS_HANDSHAKE_EXTENSIONS_ALPN_LIST,
    &TLS_HANDSHAKE_EXTENSIONS_ALPN_STR_LEN,
    &TLS_HANDSHAKE_EXTENSIONS_ALPN_STR,
    &TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_CLIENT_LENGTH,
    &TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_GROUP,
    &TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE_LENGTH,
    &TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_KEY_EXCHANGE,
    &TLS_HANDSHAKE_EXTENSIONS_KEY_SHARE_SELECTED_GROUP,
    &TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSIONS_LEN,
    &TLS_HANDSHAKE_EXTENSIONS_SUPPORTED_VERSION,
    &TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_LIST_LEN,
    &TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_LEN,
    &TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME_TYPE,
    &TLS_HANDSHAKE_EXTENSIONS_SERVER_NAME,
    &TLS_HANDSHAKE_SIG_HASH_ALG_LEN,
    &TLS_HANDSHAKE_SIG_HASH_ALGS,
    &TLS_HANDSHAKE_SIG_HASH_ALG,
    &TLS_HANDSHAKE_SIG_HASH_HASH,
    &TLS_HANDSHAKE_SIG_HASH_SIG,
    &TLS_HANDSHAKE_RANDOM,
    &TLS_HANDSHAKE_RANDOM_TIME,
    &TLS_HANDSHAKE_RANDOM_BYTES,
    &TLS_HANDSHAKE_SESSION_ID,
    &TLS_HANDSHAKE_VERSION,
    &TLS_HANDSHAKE_CIPHER_SUITES_LENGTH,
    &TLS_HANDSHAKE_CIPHERSUITES,
    &TLS_HANDSHAKE_CIPHERSUITE,
    &TLS_HANDSHAKE_COMP_METHODS_LENGTH,
    &TLS_HANDSHAKE_COMP_METHODS,
    &TLS_HANDSHAKE_COMP_METHOD,
    &TLS_REASSEMBLED_IN,
    &TLS_HANDSHAKE_REASSEMBLED_IN,
    &TLS_HANDSHAKE_JA3_FULL,
    &TLS_HANDSHAKE_JA3,
    &TLS_HANDSHAKE_JA3S_FULL,
    &TLS_HANDSHAKE_JA3S,
    &TLS_HANDSHAKE_JA4,
    &TLS_HANDSHAKE_JA4_R,
];

/// Syslog messages.
pub static SYSLOG_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "syslog",
    long_name: "Syslog Message",
    short_name: "Syslog",
    fields: SYSLOG_FIELDS,
};

/// Cisco NetFlow version 5 flow export.
pub static CFLOW_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "cflow",
    long_name: "Cisco NetFlow/IPFIX",
    short_name: "CFLOW",
    fields: CFLOW_FIELDS,
};

/// InMon sFlow version 5.
pub static SFLOW_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "sflow",
    long_name: "InMon sFlow",
    short_name: "sFlow",
    fields: SFLOW_FIELDS,
};

/// SNMP version 1 and 2c.
pub static SNMP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "snmp",
    long_name: "Simple Network Management Protocol",
    short_name: "SNMP",
    fields: SNMP_FIELDS,
};
/// Border Gateway Protocol version 4.
pub static BGP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "bgp",
    long_name: "Border Gateway Protocol",
    short_name: "BGP",
    fields: BGP_FIELDS,
};

/// Hypertext Transfer Protocol version 1.
pub static HTTP_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "http",
    long_name: "Hypertext Transfer Protocol",
    short_name: "HTTP",
    fields: HTTP_FIELDS,
};

/// Transport Layer Security record and handshake protocol.
pub static TLS_PROTOCOL: ProtocolDef = ProtocolDef {
    filter_name: "tls",
    long_name: "Transport Layer Security",
    short_name: "TLS",
    fields: TLS_FIELDS,
};

static PROTOCOLS: &[&ProtocolDef] = &[
    &FRAME_PROTOCOL,
    &ETH_PROTOCOL,
    &LLC_PROTOCOL,
    &VLAN_PROTOCOL,
    &IEEE8021AD_PROTOCOL,
    &SLL_PROTOCOL,
    &NULL_PROTOCOL,
    &ARP_PROTOCOL,
    &IP_PROTOCOL,
    &IPV6_PROTOCOL,
    &IPV6_HOPOPTS_PROTOCOL,
    &IPV6_DSTOPTS_PROTOCOL,
    &IPV6_ROUTING_PROTOCOL,
    &IPV6_FRAGHDR_PROTOCOL,
    &TCP_PROTOCOL,
    &UDP_PROTOCOL,
    &DNS_PROTOCOL,
    &MDNS_PROTOCOL,
    &LLMNR_PROTOCOL,
    &DHCP_PROTOCOL,
    &DHCPV6_PROTOCOL,
    &NTP_PROTOCOL,
    &ICMP_PROTOCOL,
    &ICMPV6_PROTOCOL,
    &ERSPAN_PROTOCOL,
    &GENEVE_PROTOCOL,
    &GRE_PROTOCOL,
    &MPLS_PROTOCOL,
    &VXLAN_PROTOCOL,
    &BFD_PROTOCOL,
    &BFD_ECHO_PROTOCOL,
    &OSPF_PROTOCOL,
    &VRRP_PROTOCOL,
    &LACP_PROTOCOL,
    &LLDP_PROTOCOL,
    &MARKER_PROTOCOL,
    &SLOW_PROTOCOL,
    &STP_PROTOCOL,
    &CFLOW_PROTOCOL,
    &SFLOW_PROTOCOL,
    &SNMP_PROTOCOL,
    &SYSLOG_PROTOCOL,
    &BGP_PROTOCOL,
    &HTTP_PROTOCOL,
    &TLS_PROTOCOL,
];

/// One link-layer dispatch entry.
///
/// Raw-IP link types carry no protocol of their own; their wrapper picks IPv4
/// or IPv6 from the version nibble and checks the policy there, so `protocol`
/// is absent for those entries.
#[derive(Debug)]
struct LinkTypeEntry {
    link_type: u32,
    protocol: Option<Protocol>,
    decoder: Decoder,
}

static LINK_TYPE_DECODERS: &[LinkTypeEntry] = &[
    LinkTypeEntry {
        link_type: 0,
        protocol: Some(Protocol::Null),
        decoder: decode::null,
    },
    LinkTypeEntry {
        link_type: 1,
        protocol: Some(Protocol::Ethernet),
        decoder: decode::ethernet,
    },
    LinkTypeEntry {
        link_type: 12,
        protocol: None,
        decoder: decode::raw_ip,
    },
    LinkTypeEntry {
        link_type: 14,
        protocol: None,
        decoder: decode::raw_ip,
    },
    LinkTypeEntry {
        link_type: 101,
        protocol: None,
        decoder: decode::raw_ip,
    },
    LinkTypeEntry {
        link_type: 228,
        protocol: Some(Protocol::Ipv4),
        decoder: decode::raw_ipv4,
    },
    LinkTypeEntry {
        link_type: 229,
        protocol: Some(Protocol::Ipv6),
        decoder: decode::raw_ipv6,
    },
    LinkTypeEntry {
        link_type: 108,
        protocol: Some(Protocol::Null),
        decoder: decode::loopback,
    },
    LinkTypeEntry {
        link_type: 113,
        protocol: Some(Protocol::Sll),
        decoder: decode::sll,
    },
    LinkTypeEntry {
        link_type: 276,
        protocol: Some(Protocol::Sll),
        decoder: decode::sll2,
    },
];

/// Ethernet payload decoders, keyed by EtherType. A link decoder hands the
/// payload to a registered decoder when one exists.
static ETHERTYPE_DECODERS: &[(u16, Protocol)] = &[
    (0x0800, Protocol::Ipv4),
    (0x0806, Protocol::Arp),
    (0x6558, Protocol::Ethernet),
    (0x8100, Protocol::Vlan),
    (0x86dd, Protocol::Ipv6),
    (0x8809, Protocol::Slow),
    (0x8847, Protocol::Mpls),
    (0x8848, Protocol::Mpls),
    (0x88a8, Protocol::Ieee8021ad),
    (0x88cc, Protocol::Lldp),
    (0x9100, Protocol::Vlan),
];

/// IP payload decoders, keyed by the version nibble. Raw-IP and null/loopback
/// link layers select an entry from this table.
static IP_VERSION_DECODERS: &[(u8, Protocol)] = &[(4, Protocol::Ipv4), (6, Protocol::Ipv6)];

/// Transport decoders, keyed by IP protocol number. IPv4's protocol field and
/// IPv6's final next-header value select an entry from this table.
static IP_PROTOCOL_DECODERS: &[(u8, Protocol)] = &[
    (1, Protocol::Icmp),
    (4, Protocol::Ipv4),
    (6, Protocol::Tcp),
    (17, Protocol::Udp),
    (41, Protocol::Ipv6),
    (47, Protocol::Gre),
    (58, Protocol::Icmpv6),
    (89, Protocol::Ospf),
    (112, Protocol::Vrrp),
];

/// UDP payload decoders, keyed by well-known service port. A datagram is
/// matched on either port; the table order is the dispatch priority, so DNS
/// wins over mDNS and LLMNR when a packet carries more than one of them.
/// NetFlow/IPFIX ports are preference-driven (`cflow.netflow.ports` and
/// `cflow.ipfix.ports`) and are handled by the UDP decoder.
static UDP_PORT_DECODERS: &[(u16, Protocol)] = &[
    (53, Protocol::Dns),
    (67, Protocol::Dhcp),
    (68, Protocol::Dhcp),
    (123, Protocol::Ntp),
    (546, Protocol::Dhcpv6),
    (547, Protocol::Dhcpv6),
    (4789, Protocol::Vxlan),
    (5353, Protocol::Mdns),
    (5355, Protocol::Llmnr),
    (6081, Protocol::Geneve),
    (8472, Protocol::Vxlan),
    (3784, Protocol::Bfd),
    (3785, Protocol::BfdEcho),
    (4784, Protocol::Bfd),
    (6784, Protocol::Bfd),
    (7784, Protocol::Bfd),
    (161, Protocol::Snmp),
    (162, Protocol::Snmp),
    (514, Protocol::Syslog),
    (6343, Protocol::Sflow),
    (8161, Protocol::Snmp),
];

/// Select a UDP payload protocol by either port, in table priority order.
pub(crate) fn udp_port_protocol(source: u16, destination: u16) -> Option<Protocol> {
    UDP_PORT_DECODERS
        .iter()
        .find(|(port, _)| *port == source || *port == destination)
        .map(|(_, protocol)| *protocol)
}

/// The protocols a decode-as entry may select for a UDP port.
pub(crate) fn udp_port_protocols() -> impl Iterator<Item = Protocol> {
    UDP_PORT_DECODERS
        .iter()
        .map(|(_, protocol)| *protocol)
        .chain(std::iter::once(Protocol::Cflow))
        .chain(std::iter::once(Protocol::Dns))
}

/// The protocols a decode-as entry may select for an EtherType.
pub(crate) fn ethertype_protocols() -> impl Iterator<Item = Protocol> {
    ETHERTYPE_DECODERS
        .iter()
        .map(|(_, protocol)| *protocol)
        .chain([Protocol::Llc, Protocol::Stp, Protocol::Lacp])
}

/// The protocols a decode-as entry may select for an IP protocol number.
pub(crate) fn ip_protocol_protocols() -> impl Iterator<Item = Protocol> {
    IP_PROTOCOL_DECODERS
        .iter()
        .map(|(_, protocol)| *protocol)
        .chain([
            Protocol::Ipv6Hopopts,
            Protocol::Ipv6Dstopts,
            Protocol::Ipv6Routing,
            Protocol::Ipv6Fraghdr,
        ])
}

/// TCP payload decoders, keyed by service port.
///
/// The table order is the dispatch priority: DNS on 53 before mDNS on 5353,
/// TLS on its registered ports and BGP on 179. HTTP is not in the table: it
/// is a heuristic applied after these decoders reject the payload, so HTTP
/// decodes on any port whose bytes form a request or response line.
static TCP_PORT_DECODERS: &[(u16, Protocol)] = &[
    (53, Protocol::Dns),
    (179, Protocol::Bgp),
    (443, Protocol::Tls),
    (4443, Protocol::Tls),
    (465, Protocol::Tls),
    (636, Protocol::Tls),
    (993, Protocol::Tls),
    (995, Protocol::Tls),
    (5061, Protocol::Tls),
    (8443, Protocol::Tls),
    (9443, Protocol::Tls),
    (5353, Protocol::Dns),
    (5986, Protocol::Tls),
];

/// Select a TCP payload protocol by either port, in table priority order.
pub(crate) fn tcp_port_decoder(source: u16, destination: u16) -> Option<Protocol> {
    TCP_PORT_DECODERS
        .iter()
        .find(|(port, _)| *port == source || *port == destination)
        .map(|(_, protocol)| *protocol)
}

/// Every registered protocol, in report order.
/// Every registered protocol, in report order.
pub fn protocols() -> &'static [&'static ProtocolDef] {
    PROTOCOLS
}

/// Protocol metadata registered under a display-filter name.
pub fn protocol_by_name(name: &str) -> Option<Protocol> {
    Protocol::ALL
        .iter()
        .copied()
        .find(|protocol| protocol.filter_name() == name)
}

/// The registry, built on first use.
#[derive(Debug)]
pub struct Registry {
    fields: Vec<&'static FieldDef>,
    fields_by_abbrev: BTreeMap<&'static str, &'static FieldDef>,
    shared_abbrevs: BTreeMap<&'static str, Vec<&'static FieldDef>>,
    link_types: BTreeMap<u32, &'static LinkTypeEntry>,
    ethertypes: BTreeMap<u16, Protocol>,
    ip_versions: BTreeMap<u8, Protocol>,
    ip_protocols: BTreeMap<u8, Protocol>,
}

impl Registry {
    fn build() -> Self {
        let mut fields = Vec::new();
        let mut fields_by_abbrev = BTreeMap::new();
        let mut shared_abbrevs: BTreeMap<&'static str, Vec<&'static FieldDef>> = BTreeMap::new();
        for protocol in PROTOCOLS {
            for field in protocol.fields.iter().copied() {
                fields.push(field);
                if let Some(first) = fields_by_abbrev.get(field.abbrev).copied() {
                    shared_abbrevs
                        .entry(field.abbrev)
                        .or_insert_with(|| vec![first])
                        .push(field);
                } else {
                    fields_by_abbrev.insert(field.abbrev, field);
                }
            }
        }
        Self {
            fields,
            fields_by_abbrev,
            shared_abbrevs,
            link_types: LINK_TYPE_DECODERS
                .iter()
                .map(|entry| (entry.link_type, entry))
                .collect(),
            ethertypes: ETHERTYPE_DECODERS.iter().copied().collect(),
            ip_versions: IP_VERSION_DECODERS.iter().copied().collect(),
            ip_protocols: IP_PROTOCOL_DECODERS.iter().copied().collect(),
        }
    }

    /// Find a field by its display-filter abbreviation.
    pub fn field(&self, abbrev: &str) -> Option<&'static FieldDef> {
        self.fields_by_abbrev.get(abbrev).copied()
    }

    /// Every definition registered under one abbreviation, canonical first.
    ///
    /// A few protocols (mDNS reusing DNS names) register more than one
    /// definition for one abbreviation. Output selection expands a name to all
    /// of them; this list includes the canonical definition [`Self::field`]
    /// returns, so callers may insert it unconditionally without duplicates.
    pub fn shared_abbrev_fields(&self, abbrev: &str) -> &[&'static FieldDef] {
        self.shared_abbrevs
            .get(abbrev)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Every registered field, in protocol and declaration order.
    pub fn fields(&self) -> &[&'static FieldDef] {
        &self.fields
    }

    /// The policy identity and decoder for a link type.
    ///
    /// A `None` policy identity belongs to raw-IP wrappers, which check the
    /// IPv4/IPv6 policy when they know the version nibble.
    pub fn link_decoder(&self, link_type: u32) -> Option<(Option<Protocol>, Decoder)> {
        self.link_types
            .get(&link_type)
            .map(|entry| (entry.protocol, entry.decoder))
    }

    /// The protocol for an EtherType, if one is registered.
    pub fn protocol_for_ethertype(&self, ethertype: u16) -> Option<Protocol> {
        self.ethertypes.get(&ethertype).copied()
    }

    /// The protocol for an IP version nibble, if one is registered.
    pub fn protocol_for_ip_version(&self, version: u8) -> Option<Protocol> {
        self.ip_versions.get(&version).copied()
    }

    /// The protocol for an IP protocol number, if one is registered.
    pub fn protocol_for_ip_protocol(&self, protocol: u8) -> Option<Protocol> {
        self.ip_protocols.get(&protocol).copied()
    }
}

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::build);

/// The process-wide field and protocol registry.
pub fn registry() -> &'static Registry {
    &REGISTRY
}

/// Find a field by abbreviation in the global registry.
pub fn field_by_abbrev(abbrev: &str) -> Option<&'static FieldDef> {
    registry().field(abbrev)
}

/// The display name for an enumerated field value.
///
/// Names are the ones `-V` prints and `-G values` reports. The ARP hardware,
/// protocol and opcode names follow the IANA "Address Resolution Protocol
/// (ARP) Parameters" registry; the remaining entries match the golden output
/// for the committed fixtures. Unknown values return `None` and callers render
/// them numerically.
pub fn value_name(abbrev: &str, value: u64) -> Option<&'static str> {
    Some(match abbrev {
        "icmp.checksum.status"
        | "icmpv6.checksum.status"
        | "udp.checksum.status"
        | "tcp.checksum.status"
        | "ip.checksum.status"
        | "gre.checksum.status" => match value {
            0 => "Bad",
            1 => "Good",
            2 => "Unverified",
            3 => "Not present",
            4 => "Illegal",
            _ => return None,
        },
        "arp.hw.type"
        | "dhcp.hw.type"
        | "dhcp.client_id.duid_llt_hw_type"
        | "dhcp.client_id.duid_ll_hw_type"
        | "dhcpv6.duidllt.hwtype"
        | "dhcpv6.duidll.hwtype" => match value {
            0 => "NET/ROM pseudo",
            1 => "Ethernet",
            2 => "Experimental Ethernet",
            3 => "AX.25",
            4 => "ProNET",
            5 => "Chaos",
            6 => "IEEE 802",
            7 => "ARCNET",
            8 => "Hyperchannel",
            9 => "Lanstar",
            10 => "Autonet Short Address",
            11 => "Localtalk",
            12 => "LocalNet",
            13 => "Ultra link",
            14 => "SMDS",
            15 => "Frame Relay DLCI",
            16 => "ATM",
            17 => "HDLC",
            18 => "Fibre Channel",
            19 => "ATM (RFC 2225)",
            20 => "Serial Line",
            27 => "EUI-64",
            32 => "InfiniBand",
            _ => return None,
        },
        "arp.proto.type" => match value {
            0x0800 => "IPv4",
            0x0806 => "ARP",
            0x8035 => "RARP",
            0x8100 => "802.1Q Virtual LAN",
            0x86dd => "IPv6",
            _ => return None,
        },
        "dhcp.type" => match value {
            1 => "Boot Request",
            2 => "Boot Reply",
            _ => return None,
        },
        "dhcp.option.dhcp" => match value {
            1 => "Discover",
            2 => "Offer",
            3 => "Request",
            4 => "Decline",
            5 => "ACK",
            6 => "NAK",
            7 => "Release",
            8 => "Inform",
            9 => "Force Renew",
            10 => "Lease query",
            11 => "Lease Unassigned",
            12 => "Lease Unknown",
            13 => "Lease Active",
            14 => "Bulk Lease Query",
            15 => "Lease Query Done",
            16 => "Active LeaseQuery",
            17 => "Lease Query Status",
            18 => "TLS",
            _ => return None,
        },
        "dhcp.option.option_overload" => match value {
            1 => "Boot file name holds options",
            2 => "Server host name holds options",
            3 => "Boot file and server host names hold options",
            _ => return None,
        },
        "ntp.flags.li" => match value {
            0 => "no warning",
            1 => "last minute of the day has 61 seconds",
            2 => "last minute of the day has 59 seconds",
            3 => "unknown (clock unsynchronized)",
            _ => return None,
        },
        "ntp.flags.vn" => match value {
            0 | 5..=7 => "reserved",
            1 => "NTP Version 1",
            2 => "NTP Version 2",
            3 => "NTP Version 3",
            4 => "NTP Version 4",
            _ => return None,
        },
        "ntp.flags.mode" => match value {
            0 => "reserved",
            1 => "symmetric active",
            2 => "symmetric passive",
            3 => "client",
            4 => "server",
            5 => "broadcast",
            6 => "reserved for NTP control message",
            7 => "reserved for private use",
            _ => return None,
        },
        "ntp.stratum" => match value {
            0 => "unspecified or invalid",
            1 => "primary reference",
            2..=15 => "secondary reference",
            16 => "unsynchronized",
            17..=255 => "reserved",
            _ => return None,
        },
        "dhcpv6.msgtype" => match value {
            1 => "Solicit",
            2 => "Advertise",
            3 => "Request",
            4 => "Confirm",
            5 => "Renew",
            6 => "Rebind",
            7 => "Reply",
            8 => "Release",
            9 => "Decline",
            10 => "Reconfigure",
            11 => "Information-request",
            12 => "Relay-forw",
            13 => "Relay-reply",
            14 => "Leasequery",
            15 => "Leasequery-reply",
            16 => "Leasequery-done",
            17 => "Leasequery-data",
            18 => "Reconfigure-request",
            19 => "Reconfigure-reply",
            20 => "4o6 Query",
            21 => "4o6 Response",
            36 => "Address Registration Inform",
            37 => "Address Registration Reply",
            _ => return None,
        },
        "dhcpv6.duid.type" | "dhcp.client_id.duid_type" => match value {
            1 => "link-layer address plus time",
            2 => "assigned by vendor based on Enterprise number",
            3 => "link-layer address",
            4 => "Universally Unique IDentifier (UUID)",
            _ => return None,
        },
        "dhcpv6.status_code" => match value {
            0 => "Success",
            1 => "UnspecFail",
            2 => "NoAddrsAvail",
            3 => "NoBinding",
            4 => "NotOnLink",
            5 => "UseMulticast (obsolete)",
            6 => "NoPrefixAvail",
            7 => "UnknownQueryType",
            8 => "MalformedQuery",
            9 => "NotConfigured",
            10 => "NotAllowed",
            11 => "QueryTerminated",
            12 => "DataMissing",
            13 => "CatchUpComplete",
            14 => "NotSupported",
            15 => "TLSConnectionRefused",
            16 => "AddressInUse",
            17 => "ConfigurationConflict",
            18 => "MissingBindingInformation",
            19 => "OutdatedBindingInformation",
            20 => "ServerShuttingDown",
            21 => "DNSUpdateNotSupported",
            22 => "ExcessiveTimeSkew",
            _ => return None,
        },
        "arp.opcode" => match value {
            1 => "request",
            2 => "reply",
            3 => "reverse request",
            4 => "reverse reply",
            5 => "drarp request",
            6 => "drarp reply",
            7 => "drarp error",
            8 => "inverse request",
            9 => "inverse reply",
            10 => "arp nak",
            11 => "mars request",
            _ => return None,
        },
        "eth.type" | "vlan.etype" | "sll.etype" | "llc.type" => match value {
            0x0800 => "IPv4",
            0x8809 => "Slow Protocols",
            0x88cc => "802.1 Link Layer Discovery Protocol (LLDP)",
            0x0806 => "ARP",
            0x6558 => "Transparent Ethernet bridging",
            0x8100 => "802.1Q Virtual LAN",
            0x86dd => "IPv6",
            0x8847 => "MPLS label switched packet",
            0x8848 => "MPLS multicast label switched packet",
            0x88a8 => "802.1ad Provider Bridge (Q-in-Q)",
            0x9100 => "QinQ: old non-standard 802.1ad",
            _ => return None,
        },
        "gre.proto" => match value {
            0x0000 => "Possible GRE keepalive packet",
            0x0800 => "IP",
            0x0806 => "ARP",
            0x6558 => "Transparent Ethernet bridging",
            0x86dd => "IPv6",
            0x880b => "PPP",
            0x8847 => "MPLS label switched packet",
            0x883e => "WCCP",
            0x88be => "ERSPAN",
            0x22eb => "ERSPAN III",
            _ => return None,
        },
        "geneve.proto_type" => match value {
            0x0800 => "IPv4",
            0x0806 => "ARP",
            0x6558 => "Transparent Ethernet bridging",
            0x8100 => "802.1Q Virtual LAN",
            0x86dd => "IPv6",
            0x8847 => "MPLS label switched packet",
            0x8848 => "MPLS multicast label switched packet",
            0x88a8 => "802.1ad Provider Bridge (Q-in-Q)",
            0x9100 => "QinQ: old non-standard 802.1ad",
            _ => return None,
        },
        "mpls.label" => match value {
            0 => "IPv4 Explicit-Null",
            1 => "Router Alert",
            2 => "IPv6 Explicit-Null",
            3 => "Implicit-Null",
            7 => "Entropy Label Indicator (ELI)",
            13 => "Generic Associated Channel Label (GAL)",
            14 => "OAM Alert",
            _ => return None,
        },
        "gre.flags.version" => match value {
            0 => "GRE",
            1 => "Enhanced GRE",
            _ => return None,
        },
        "erspan.version" => match value {
            1 => "Type II",
            2 => "Type III",
            _ => return None,
        },
        "erspan.encap" => match value {
            0 => "Originally without VLAN tag",
            1 => "Originally ISL encapsulated",
            2 => "Originally 802.1Q encapsulated",
            3 => "VLAN tag preserved in frame",
            _ => return None,
        },
        "erspan.bso" => match value {
            0 => "Good or unknown integrity",
            1 => "Short frame",
            2 => "Oversized frame",
            3 => "CRC or alignment error",
            _ => return None,
        },
        "erspan.truncated" => match value {
            0 => "Not truncated",
            1 => "Truncated",
            _ => return None,
        },
        "erspan.ft" => match value {
            0 => "Ethernet",
            2 => "IP",
            _ => return None,
        },
        "erspan.gra" => match value {
            0 => "100 microseconds",
            1 => "100 nanoseconds",
            2 => "IEEE 1588",
            3 => "Custom granularity",
            _ => return None,
        },
        "sll.ltype" => match value {
            0x0004 => "802.2 LLC",
            _ => return None,
        },
        "sll.pkttype" => match value {
            0 => "Unicast to us",
            1 => "Broadcast",
            2 => "Multicast",
            3 => "Unicast to another host",
            4 => "Sent by us",
            _ => return None,
        },
        "sll.hatype" => match value {
            0 => "NET/ROM pseudo",
            1 => "Ethernet",
            6 => "IEEE 802",
            _ => return None,
        },
        "null.family" => match value {
            2 => "IP",
            24 | 28 | 30 => "IPv6",
            _ => return None,
        },
        "ip.proto" => match value {
            1 => "ICMP",
            4 => "IPIP",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            47 => "Generic Routing Encapsulation",
            58 => "ICMPv6",
            89 => "OSPF IGP",
            112 => "VRRP",
            _ => return None,
        },
        "ipv6.nxt" | "ipv6.hopopts.nxt" | "ipv6.dstopts.nxt" | "ipv6.routing.nxt"
        | "ipv6.fraghdr.nxt" => match value {
            0 => "IPv6 Hop-by-Hop Option",
            4 => "IPIP",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            43 => "Routing Header for IPv6",
            44 => "Fragment Header for IPv6",
            47 => "Generic Routing Encapsulation",
            58 => "ICMPv6",
            89 => "OSPF IGP",
            112 => "VRRP",
            59 => "No Next Header for IPv6",
            60 => "Destination Options for IPv6",
            _ => return None,
        },
        "icmp.type" => match value {
            0 => "Echo (ping) reply",
            3 => "Destination unreachable",
            5 => "Redirect",
            8 => "Echo (ping) request",
            11 => "Time-to-live exceeded",
            12 => "Parameter problem",
            13 => "Timestamp request",
            14 => "Timestamp reply",
            _ => return None,
        },
        "icmpv6.type" => match value {
            1 => "Destination Unreachable",
            2 => "Packet Too Big",
            3 => "Time Exceeded",
            4 => "Parameter Problem",
            128 => "Echo (ping) request",
            129 => "Echo (ping) reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => "Neighbor Solicitation",
            136 => "Neighbor Advertisement",
            137 => "Redirect",
            _ => return None,
        },
        "ipv6.routing.type" => match value {
            0 => "Source Route",
            2 => "Type 2 Routing",
            4 => "Segment Routing",
            _ => return None,
        },
        "ospf.msg" => match value {
            1 => "Hello Packet",
            2 => "DB Description",
            3 => "LS Request",
            4 => "LS Update",
            5 => "LS Acknowledge",
            _ => return None,
        },
        "ospf.instance_id" => match value {
            0 => "Base IPv4 Unicast Instance",
            1 => "Base IPv4 Multicast Instance",
            2 => "Base IPv4 In-band Management Instance",
            _ => return None,
        },
        "ospf.v3.instance_id" => match value {
            0 => "Base IPv6 Unicast AF",
            32 => "Base IPv6 Multicast",
            64 => "Base IPv4 Unicast AF",
            96 => "Base IPv4 Multicast",
            _ => return None,
        },
        "ospf.auth.type" => match value {
            0 => "Null",
            1 => "Simple password",
            2 => "Cryptographic",
            _ => return None,
        },
        "ospf.lsa" => match value {
            1 => "Router-LSA",
            2 => "Network-LSA",
            3 => "Summary-LSA (IP network)",
            4 => "Summary-LSA (ASBR)",
            5 => "AS-External-LSA (ASBR)",
            6 => "Group Membership LSA",
            7 => "NSSA AS-External-LSA",
            8 => "External Attributes LSA",
            9 => "Opaque LSA, Link-local scope",
            10 => "Opaque LSA, Area-local scope",
            11 => "Opaque LSA, AS-local scope",
            _ => return None,
        },
        "ospf.v3.lsa.fc" => match value {
            1 => "Router-LSA",
            2 => "Network-LSA",
            3 => "Inter-Area-Prefix-LSA",
            4 => "Inter-Area-Router-LSA",
            5 => "AS-External-LSA",
            6 => "Group-Membership-LSA",
            7 => "NSSA-LSA",
            8 => "Link-LSA",
            9 => "Intra-Area-Prefix-LSA",
            10 => "Intra-Area-TE-LSA",
            11 => "GRACE-LSA",
            12 => "Router Information Opaque-LSA",
            13 => "Inter-AS-TE-V3 LSA",
            14 => "OSPFv3 L1VPN LSA",
            15 => "OSPFv3 Autoconfiguration LSA",
            16 => "OSPFv3 Dynamic Flooding LSA",
            35 => "E-Inter-Area-Prefix-LSA",
            37 => "E-AS-External-LSA",
            40 => "E-Link-LSA",
            41 => "E-Intra-Area-Prefix-LSA",
            _ => return None,
        },
        "ospf.v3.lsa.s12" => match value {
            0 => "Link-Local Scoping - Flooded only on originating link",
            1 => "Area Scoping - Flooded only in originating area",
            2 => "AS Scoping - Flooded throughout AS",
            3 => "Reserved",
            _ => return None,
        },
        "ospf.v3.lsa.type" => match value {
            1 => "Point-to-point connection to another router",
            2 => "Connection to a transit network",
            3 => "Connection to a stub network",
            4 => "Virtual link",
            _ => return None,
        },
        "vrrp.type" => match value {
            1 => "Advertisement",
            _ => return None,
        },
        "vrrp.auth_type" => match value {
            0 => "No Authentication",
            1 => "Simple Text Authentication [RFC 2338] / Reserved [RFC 3768]",
            2 => "IP Authentication Header [RFC 2338] / Reserved [RFC 3768]",
            254 => "Cisco VRRP MD5 authentication",
            _ => return None,
        },
        "vrrp.checksum.status" => match value {
            0 => "Bad",
            1 => "Good",
            2 => "Unverified",
            3 => "Not present",
            4 => "Illegal",
            _ => return None,
        },
        "bfd.diag" => match value {
            0 => "No Diagnostic",
            1 => "Control Detection Time Expired",
            2 => "Echo Function Failed",
            3 => "Neighbor Signaled Session Down",
            4 => "Forwarding Plane Reset",
            5 => "Path Down",
            6 => "Concatenated Path Down",
            7 => "Administratively Down",
            8 => "Reverse Concatenated Path Down",
            9 => "Mis-Connectivity Defect",
            _ => return None,
        },
        "bfd.sta" => match value {
            0 => "AdminDown",
            1 => "Down",
            2 => "Init",
            3 => "Up",
            _ => return None,
        },
        "bfd.auth.type" => match value {
            1 => "Simple Password",
            2 => "Keyed MD5",
            3 => "Meticulous Keyed MD5",
            4 => "Keyed SHA1",
            5 => "Meticulous Keyed SHA1",
            _ => return None,
        },
        "llc.oui" => match value {
            0x00000c => "Cisco Systems, Inc",
            _ => return None,
        },
        "llc.cisco_pid" => match value {
            0x010b => "PVSTP+",
            _ => return None,
        },
        "lldp.tlv.type" => match value {
            0 => "End of LLDPDU",
            1 => "Chassis Id",
            2 => "Port Id",
            3 => "Time to Live",
            4 => "Port Description",
            5 => "System Name",
            6 => "System Description",
            7 => "System Capabilities",
            8 => "Management Address",
            127 => "Organization Specific",
            _ => return None,
        },
        "lldp.chassis.subtype" => match value {
            0 => "Reserved",
            1 => "Chassis component",
            2 => "Interface alias",
            3 => "Port component",
            4 => "MAC address",
            5 => "Network address",
            6 => "Interface name",
            7 => "Locally assigned",
            _ => return None,
        },
        "lldp.port.subtype" => match value {
            0 => "Reserved",
            1 => "Interface alias",
            2 => "Port component",
            3 => "MAC address",
            4 => "Network address",
            5 => "Interface name",
            6 => "Agent circuit ID",
            7 => "Locally assigned",
            _ => return None,
        },
        "lldp.network_address.subtype" | "lldp.mgn.address.subtype" => match value {
            0 => "Reserved",
            1 => "IPv4",
            2 => "IPv6",
            6 => "802 (includes all 802 media plus Ethernet)",
            _ => return None,
        },
        "lldp.mgn.interface.subtype" => match value {
            1 => "Unknown",
            2 => "ifIndex",
            3 => "System port number",
            _ => return None,
        },
        "lldp.orgtlv.oui" => match value {
            0x00120f => "IEEE 802.3 Working Group",
            0x0080c2 => "IEEE 802.1 Chair",
            _ => return None,
        },
        "lldp.ieee.802_1.subtype" => match value {
            1 => "Port VLAN ID",
            2 => "Port and Protocol VLAN ID",
            3 => "VLAN Name",
            4 => "Protocol Identity",
            5 => "VID Usage Digest",
            7 => "Link Aggregation",
            8 => "Congestion Notification",
            9 => "ETS Configuration",
            _ => return None,
        },
        "lldp.ieee.802_3.subtype" => match value {
            1 => "MAC/PHY Configuration/Status",
            2 => "Power Via MDI",
            3 => "Link Aggregation",
            4 => "Maximum Frame Size",
            5 => "EEE (Energy-Efficient Ethernet)",
            _ => return None,
        },
        "lldp.ieee.802_3.pmd_mau_type" => match value {
            0x0001 => "AUI - no internal MAU, view from AUI",
            0x0002 => "10Base5 - thick coax MAU",
            0x0003 => "Foirl - FOIRL MAU",
            0x0010 => "100BaseTXFD - 2 pair category 5 UTP, full duplex mode",
            0x0020 => "10GigBaseLX4 - X fiber over WWDM optics",
            _ => return None,
        },
        "lldp.ieee.802_1.aggregation_status.porttype" => match value {
            0 => "Not specified",
            1 => "From aggregation port",
            2 => "From aggregator",
            3 => "From single-port aggregator",
            _ => return None,
        },
        "stp.protocol" => match value {
            0 => "Spanning Tree Protocol",
            _ => return None,
        },
        "stp.version" => match value {
            0 => "Spanning Tree",
            2 => "Rapid Spanning Tree",
            3 => "Multiple Spanning Tree",
            _ => return None,
        },
        "stp.type" => match value {
            0 => "Configuration",
            2 => "Rapid/Multiple Spanning Tree",
            0x80 => "Topology Change Notification",
            _ => return None,
        },
        "stp.flags.port_role" => match value {
            0 => "Unknown",
            1 => "Alternate or Backup",
            2 => "Root",
            3 => "Designated",
            _ => return None,
        },
        "slow.subtype" => match value {
            1 => "LACP",
            2 => "Marker Protocol",
            3 => "OAM",
            _ => return None,
        },
        "lacp.tlv_type" => match value {
            0 => "Terminator",
            1 => "Actor Information",
            2 => "Partner Information",
            3 => "Collector Information",
            _ => return None,
        },
        "marker.tlvType" => match value {
            0 => "Marker Terminator",
            1 => "Marker Information",
            2 => "Marker Response Information",
            _ => return None,
        },
        "syslog.facility" => match value {
            0 => "KERN - kernel messages",
            1 => "USER - random user-level messages",
            2 => "MAIL - mail system",
            3 => "DAEMON - system daemons",
            4 => "AUTH - security/authorization messages",
            5 => "SYSLOG - messages generated internally by syslogd",
            6 => "LPR - line printer subsystem",
            7 => "NEWS - network news subsystem",
            8 => "UUCP - UUCP subsystem",
            9 => "CRON - clock daemon (BSD, Linux)",
            10 => "AUTHPRIV - security/authorization messages (private)",
            11 => "FTP - ftp daemon",
            12 => "NTP - ntp subsystem",
            13 => "LOGAUDIT - log audit",
            14 => "LOGALERT - log alert",
            15 => "CRON - clock daemon (Solaris)",
            16 => "LOCAL0 - reserved for local use",
            17 => "LOCAL1 - reserved for local use",
            18 => "LOCAL2 - reserved for local use",
            19 => "LOCAL3 - reserved for local use",
            20 => "LOCAL4 - reserved for local use",
            21 => "LOCAL5 - reserved for local use",
            22 => "LOCAL6 - reserved for local use",
            23 => "LOCAL7 - reserved for local use",
            _ => return None,
        },
        "syslog.level" => match value {
            0 => "EMERG - system is unusable",
            1 => "ALERT - action must be taken immediately",
            2 => "CRIT - critical conditions",
            3 => "ERR - error conditions",
            4 => "WARNING - warning conditions",
            5 => "NOTICE - normal but significant condition",
            6 => "INFO - informational",
            7 => "DEBUG - debug-level messages",
            _ => return None,
        },
        "snmp.version" => match value {
            0 => "version-1",
            1 => "v2c",
            2 => "v2u",
            3 => "snmpv3",
            _ => return None,
        },
        "snmp.data" => match value {
            0 => "get-request",
            1 => "get-next-request",
            2 => "get-response",
            3 => "set-request",
            4 => "trap",
            5 => "getBulkRequest",
            6 => "informRequest",
            7 => "snmpV2-trap",
            8 => "report",
            _ => return None,
        },
        "snmp.error_status" => match value {
            0 => "noError",
            1 => "tooBig",
            2 => "noSuchName",
            3 => "badValue",
            4 => "readOnly",
            5 => "genErr",
            6 => "noAccess",
            7 => "wrongType",
            8 => "wrongLength",
            9 => "wrongEncoding",
            10 => "wrongValue",
            11 => "noCreation",
            12 => "inconsistentValue",
            13 => "resourceUnavailable",
            14 => "commitFailed",
            15 => "undoFailed",
            16 => "authorizationError",
            17 => "notWritable",
            18 => "inconsistentName",
            _ => return None,
        },
        "snmp.generic_trap" => match value {
            0 => "coldStart",
            1 => "warmStart",
            2 => "linkDown",
            3 => "linkUp",
            4 => "authenticationFailure",
            5 => "egpNeighborLoss",
            6 => "enterpriseSpecific",
            _ => return None,
        },
        "cflow.engine_type" => match value {
            0 => "RP",
            1 => "VIP/Linecard",
            2 => "PFC/DFC",
            _ => return None,
        },
        "cflow.samplingmode" => match value {
            0 => "No sampling mode configured",
            1 => "Packet Interval sampling mode configured",
            2 => "Random sampling mode configured",
            _ => return None,
        },
        "cflow.protocol" => match value {
            0 => "IPv6 Hop-by-Hop Option",
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            58 => "ICMPv6",
            _ => return None,
        },
        "sflow_245.agenttype" => match value {
            1 => "IPv4",
            2 => "IPv6",
            _ => return None,
        },
        "sflow_245.sampletype" => match value {
            1 => "Flow sample",
            2 => "Counters sample",
            3 => "Expanded flow sample",
            4 => "Expanded counters sample",
            7 => "Lag Port stats",
            _ => return None,
        },
        "sflow_245.ipv4_precedence_type" => match value {
            0 => "Routine",
            1 => "Priority",
            2 => "Immediate",
            3 => "Flash",
            4 => "Flash Override",
            5 => "CRITIC/ECP",
            6 => "Internetwork Control",
            7 => "Network Control",
            _ => return None,
        },
        "sflow_245.flow_record_format" => match value {
            1 => "Raw packet header",
            2 => "Ethernet frame data",
            3 => "IPv4 data",
            4 => "IPv6 data",
            1001 => "Extended switch data",
            1002 => "Extended router data",
            1003 => "Extended gateway data",
            1004 => "Extended user data",
            1005 => "Extended URL data",
            1006 => "Extended MPLS data",
            1007 => "Extended NAT data",
            1008 => "Extended MPLS tunnel data",
            1009 => "Extended MPLS VC data",
            1010 => "Extended MPLS FEC data",
            1011 => "Extended MPLS LVP FEC data",
            1012 => "Extended VLAN tunnel",
            1013 => "Extended 802.11 payload",
            1014 => "Extended 802.11 RX",
            1015 => "Extended 802.11 TX",
            1016 => "Extended 802.11 aggregation",
            _ => return None,
        },
        "sflow_245.counters_record_format" => match value {
            1 => "Generic interface counters",
            2 => "Ethernet interface counters",
            3 => "Token ring counters",
            4 => "100 Base VG interface counters",
            5 => "VLAN counters",
            6 => "IEEE 802.11 counters",
            7 => "LAG counters",
            1001 => "Processor information",
            1002 => "Radio utilization",
            _ => return None,
        },
        "sflow_245.header_protocol" => match value {
            1 => "Ethernet",
            2 => "Token Bus",
            3 => "Token Ring",
            4 => "FDDI",
            5 => "Frame Relay",
            6 => "X.25",
            7 => "PPP",
            8 => "SMDS",
            9 => "ATM AAL5",
            10 => "ATM AAL5-IP (e.g., Cisco AAL5 mux)",
            11 => "IPv4",
            12 => "IPv6",
            13 => "MPLS",
            14 => "PPP over SONET/SDH (RFC 1662, 2615)",
            15 => "802.11 MAC",
            16 => "802.11n Aggregated MPDU",
            17 => "A-MSDU Subframe",
            _ => return None,
        },
        "sflow_245.ifdirection" => match value {
            1 => "Full-Duplex",
            2 => "Half-Duplex",
            3 => "In",
            4 => "Out",
            _ => return None,
        },
        _ => return None,
    })
}

/// True and false strings for the fields whose `-V` text differs from the
/// generic forms.
///
/// Only the boolean fields Packetfin decodes are listed; everything else
/// keeps the default `True`/`False` rendering.
pub fn true_false_name(abbrev: &str) -> Option<(&'static str, &'static str)> {
    Some(match abbrev {
        "lldp.tlv.system_cap.other"
        | "lldp.tlv.system_cap.repeater"
        | "lldp.tlv.system_cap.bridge"
        | "lldp.tlv.system_cap.wlan_access_pt"
        | "lldp.tlv.system_cap.router"
        | "lldp.tlv.system_cap.telephone"
        | "lldp.tlv.system_cap.docsis_cable_device"
        | "lldp.tlv.system_cap.station_only"
        | "lldp.tlv.system_cap.cvlan"
        | "lldp.tlv.system_cap.svlan"
        | "lldp.tlv.system_cap.tpmr"
        | "lldp.tlv.enable_system_cap.other"
        | "lldp.tlv.enable_system_cap.repeater"
        | "lldp.tlv.enable_system_cap.bridge"
        | "lldp.tlv.enable_system_cap.wlan_access_pt"
        | "lldp.tlv.enable_system_cap.router"
        | "lldp.tlv.enable_system_cap.telephone"
        | "lldp.tlv.enable_system_cap.docsis_cable_device"
        | "lldp.tlv.enable_system_cap.station_only"
        | "lldp.tlv.enable_system_cap.cvlan"
        | "lldp.tlv.enable_system_cap.svlan"
        | "lldp.tlv.enable_system_cap.tpmr"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_tfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_t"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_xfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.1000base_x"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_bpause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_spause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_apause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.fdx_pause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2fd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t2"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_txfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_tx"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.100base_t4"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_tfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.10base_t"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps.other"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_tfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_t"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_xfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.1000base_x"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_bpause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_spause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_apause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.fdx_pause"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2fd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t2"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_txfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_tx"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.100base_t4"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_tfd"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.10base_t"
        | "lldp.ieee.802_3.pmd_auto_neg_advertised_caps_inv.other" => ("Capable", "Not capable"),
        "lldp.ieee.802_1.port_and_vlan_id_flag.supported"
        | "lldp.ieee.802_3.mac_phy_auto_neg_status.supported" => ("Supported", "Not supported"),
        "lldp.ieee.802_1.port_and_vlan_id_flag.enabled"
        | "lldp.ieee.802_1.aggregation_status.enabled"
        | "lldp.ieee.802_3.aggregation_status.enabled"
        | "lldp.ieee.802_3.mac_phy_auto_neg_status.enabled" => ("Enabled", "Disabled"),
        "lldp.ieee.802_1.aggregation_status.cap" | "lldp.ieee.802_3.aggregation_status.cap" => {
            ("Yes", "No")
        }
        "lacp.actor.state.activity" | "lacp.partner.state.activity" => ("Active", "Passive"),
        "lacp.actor.state.timeout" | "lacp.partner.state.timeout" => {
            ("Short Timeout", "Long Timeout")
        }
        "lacp.actor.state.aggregation" | "lacp.partner.state.aggregation" => {
            ("Aggregatable", "Individual")
        }
        "lacp.actor.state.synchronization" | "lacp.partner.state.synchronization" => {
            ("In Sync", "Out of Sync")
        }
        "lacp.actor.state.collecting"
        | "lacp.partner.state.collecting"
        | "lacp.actor.state.distributing"
        | "lacp.partner.state.distributing" => ("Enabled", "Disabled"),
        "lacp.actor.state.defaulted" | "lacp.partner.state.defaulted" => ("Yes", "No"),
        "lacp.actor.state.expired" | "lacp.partner.state.expired" => ("Yes", "No"),
        "stp.flags.tcack"
        | "stp.flags.agreement"
        | "stp.flags.forwarding"
        | "stp.flags.learning"
        | "stp.flags.proposal"
        | "stp.flags.tc" => ("Yes", "No"),
        _ => return None,
    })
}
