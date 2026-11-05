//! Common NetFlow v9 and IPFIX information elements.
//!
//! Packetfin decodes the elements listed here and falls back to
//! `cflow.unknown_field_type` for every other ID, keeping the wire bytes
//! visible. The IDs and wire widths come from RFC 3954 section 8 and the IANA
//! IPFIX Information Elements registry.

/// How a known information element is decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Element {
    /// Byte counter (`octetDeltaCount`).
    Octets,
    /// Packet counter (`packetDeltaCount`).
    Packets,
    /// IP protocol number.
    Protocol,
    /// Source transport port.
    SourcePort,
    /// Destination transport port.
    DestinationPort,
    /// Source IPv4 address.
    SourceIpv4,
    /// Destination IPv4 address.
    DestinationIpv4,
    /// Source IPv6 address.
    SourceIpv6,
    /// Destination IPv6 address.
    DestinationIpv6,
    /// IPv4 type of service.
    Tos,
    /// TCP control bits.
    TcpFlags,
    /// Ingress interface (`INPUT_SNMP`).
    InputInterface,
    /// Egress interface (`OUTPUT_SNMP`).
    OutputInterface,
    /// IPv4 next hop.
    NextHop,
    /// IPv4 BGP next hop.
    BgpNextHop,
    /// Source autonomous system number.
    SourceAs,
    /// Destination autonomous system number.
    DestinationAs,
    /// Source prefix mask length.
    SourceMask,
    /// Destination prefix mask length.
    DestinationMask,
    /// Flow end uptime in milliseconds (`LAST_SWITCHED`).
    EndSwitched,
    /// Flow start uptime in milliseconds (`FIRST_SWITCHED`).
    StartSwitched,
    /// Absolute flow start time in the given unit.
    AbsoluteStart(TimeScale),
    /// Absolute flow end time in the given unit.
    AbsoluteEnd(TimeScale),
}

/// Unit of an absolute flow timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TimeScale {
    /// Unix seconds (`flowStartSeconds`).
    Seconds,
    /// Unix milliseconds (`flowStartMilliseconds`).
    Milliseconds,
    /// NTP 64-bit timestamp (`flowStartMicroseconds`).
    Microseconds,
    /// NTP 64-bit timestamp (`flowStartNanoseconds`).
    Nanoseconds,
}

/// One known information element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ElementSpec {
    /// Template display name.
    pub name: &'static str,
    /// Decoding rule.
    pub element: Element,
}

/// Look up a standard information element.
pub(super) fn element(id: u16) -> Option<ElementSpec> {
    let (name, element) = match id {
        1 => ("BYTES", Element::Octets),
        2 => ("PKTS", Element::Packets),
        4 => ("PROTOCOL", Element::Protocol),
        5 => ("IP_TOS", Element::Tos),
        6 => ("TCP_FLAGS", Element::TcpFlags),
        7 => ("L4_SRC_PORT", Element::SourcePort),
        8 => ("IP_SRC_ADDR", Element::SourceIpv4),
        9 => ("SRC_MASK", Element::SourceMask),
        10 => ("INPUT_SNMP", Element::InputInterface),
        11 => ("L4_DST_PORT", Element::DestinationPort),
        12 => ("IP_DST_ADDR", Element::DestinationIpv4),
        13 => ("DST_MASK", Element::DestinationMask),
        14 => ("OUTPUT_SNMP", Element::OutputInterface),
        15 => ("IP_NEXT_HOP", Element::NextHop),
        16 => ("SRC_AS", Element::SourceAs),
        17 => ("DST_AS", Element::DestinationAs),
        18 => ("BGP_NEXT_HOP", Element::BgpNextHop),
        21 => ("LAST_SWITCHED", Element::EndSwitched),
        22 => ("FIRST_SWITCHED", Element::StartSwitched),
        27 => ("IPV6_SRC_ADDR", Element::SourceIpv6),
        28 => ("IPV6_DST_ADDR", Element::DestinationIpv6),
        150 => (
            "flowStartSeconds",
            Element::AbsoluteStart(TimeScale::Seconds),
        ),
        151 => ("flowEndSeconds", Element::AbsoluteEnd(TimeScale::Seconds)),
        152 => (
            "flowStartMilliseconds",
            Element::AbsoluteStart(TimeScale::Milliseconds),
        ),
        153 => (
            "flowEndMilliseconds",
            Element::AbsoluteEnd(TimeScale::Milliseconds),
        ),
        154 => (
            "flowStartMicroseconds",
            Element::AbsoluteStart(TimeScale::Microseconds),
        ),
        155 => (
            "flowEndMicroseconds",
            Element::AbsoluteEnd(TimeScale::Microseconds),
        ),
        156 => (
            "flowStartNanoseconds",
            Element::AbsoluteStart(TimeScale::Nanoseconds),
        ),
        157 => (
            "flowEndNanoseconds",
            Element::AbsoluteEnd(TimeScale::Nanoseconds),
        ),
        _ => return None,
    };
    Some(ElementSpec { name, element })
}

/// How a v9 options scope field is decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    /// `cflow.scope_system`; opaque bytes.
    System,
    /// `cflow.scope_interface`; unsigned integer.
    Interface,
    /// `cflow.scope_linecard`; unsigned integer.
    LineCard,
    /// `cflow.scope_cache`; opaque bytes.
    Cache,
    /// `cflow.scope_template`; opaque bytes.
    Template,
}

/// Template display name for one v9 scope field type.
pub(super) fn scope_name(id: u16) -> &'static str {
    match id {
        1 => "System",
        2 => "Interface",
        3 => "Line Card",
        4 => "NetFlow Cache",
        5 => "Template",
        _ => "Unknown",
    }
}

/// Decoding rule for one v9 scope field type.
pub(super) fn scope(id: u16) -> Option<Scope> {
    match id {
        1 => Some(Scope::System),
        2 => Some(Scope::Interface),
        3 => Some(Scope::LineCard),
        4 => Some(Scope::Cache),
        5 => Some(Scope::Template),
        _ => None,
    }
}

/// Vendor name for a private enterprise number.
///
/// Only IANA's first enterprise entry is needed by the committed fixtures;
/// unknown PENs print as `(Unknown)`.
pub(super) fn enterprise_name(pen: u32) -> &'static str {
    match pen {
        9 => "ciscoSystems",
        _ => "(Unknown)",
    }
}
