//! Domain Name System over UDP, shared by DNS, mDNS and LLMNR.
//!
//! Layout and name compression follow RFC 1035 sections 3.1, 4.1.1-4.1.4;
//! EDNS(0) follows RFC 6891 section 6.2; mDNS adds the cache-flush and QU
//! bits of RFC 6762 section 18, and LLMNR adds the conflict bit of RFC 4795
//! section 2.1.1.
//!
//! Names are expanded with a hard jump limit and a 255-octet limit. A
//! truncated name, a reserved label type or an out-of-range pointer stops the
//! message and marks it malformed; a compression loop or an over-long name
//! becomes a placeholder name so the rest of the message still decodes. Rdata
//! is bounded by its declared length.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::decode::bytes::{read_u16_be, read_u32_be};
use crate::decode::{DecodeContext, NetworkContext};
use crate::fields;
use crate::state::{DnsTransactionKey, PassMode, add_request_link, add_retransmission, add_time};
use crate::tree::{Node, Range, Value};

const HEADER_LENGTH: usize = 12;
const MAX_NAME_LENGTH: usize = 255;
const MAX_POINTER_JUMPS: usize = 128;
/// Largest number of address-to-name pairs collected from one message.
const MAX_LEARNED_ADDRESSES: usize = 4096;

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const TYPE_OPT: u16 = 41;
const TYPE_ANY: u16 = 255;

const CLASS_IN: u16 = 1;

const OPTION_PADDING: u16 = 12;

/// Which of the three UDP names carries the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Dns,
    Mdns,
    Llmnr,
}

impl Flavor {
    fn protocol(self) -> &'static fields::ProtocolDef {
        match self {
            Self::Dns => &fields::DNS_PROTOCOL,
            Self::Mdns => &fields::MDNS_PROTOCOL,
            Self::Llmnr => &fields::LLMNR_PROTOCOL,
        }
    }

    fn is_mdns(self) -> bool {
        self == Self::Mdns
    }

    fn is_llmnr(self) -> bool {
        self == Self::Llmnr
    }
}

/// Decode one DNS message into the UDP node.
pub(crate) fn decode_dns(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    decode(context, parent, data, base, Flavor::Dns);
}

/// Decode one mDNS message into the UDP node.
pub(crate) fn decode_mdns(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    decode(context, parent, data, base, Flavor::Mdns);
}

/// Decode one LLMNR message into the UDP node.
pub(crate) fn decode_llmnr(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    decode(context, parent, data, base, Flavor::Llmnr);
}

/// Whether a payload looks enough like DNS for the heuristic and for a
/// forced decode-as entry to accept it.
///
/// The check is deliberately structural: a 12-byte header with a known
/// opcode, plausible section counts and, when there is a question, one
/// complete name and its type/class. Malformed messages with a plausible
/// header still reach the DNS decoder, where they produce the same fields and
/// expert entries as a port-dispatched message.
pub fn looks_like_dns(data: &[u8]) -> bool {
    if data.len() < HEADER_LENGTH {
        return false;
    }
    let (Some(flags), Some(questions), Some(answers)) = (
        read_u16_be(data, 2),
        read_u16_be(data, 4),
        read_u16_be(data, 6),
    ) else {
        return false;
    };
    if (flags >> 11) & 0xf > 5 {
        return false;
    }
    if questions > 16 || answers > 256 {
        return false;
    }
    if questions == 0 && answers == 0 {
        return false;
    }
    if questions > 0 {
        let Ok(name) = read_name(data, HEADER_LENGTH, data.len()) else {
            return false;
        };
        let Some(end) = name.consumed.checked_add(4) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
    }
    true
}

fn decode(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
    flavor: Flavor,
) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context.protocol_stack.push(flavor.protocol().filter_name);

    let mut node = Node::new(flavor.protocol(), Range::new(base, data.len()));
    let mut learned = Vec::new();
    let learn = context.names.dns_learning_enabled() && !context.quoted;
    let parsed = parse_message(&mut node, data, base, flavor, &mut learned, learn);
    if !parsed {
        context.mark_malformed(&mut node, "Malformed DNS message");
    }
    for (address, name) in learned {
        context.names.learn_dns(address, &name);
    }
    if let (Some(id), Some(flags)) = (read_u16_be(data, 0), read_u16_be(data, 2)) {
        if parsed {
            track_transaction(context, &mut node, base, id, flags, flavor);
        } else {
            // A malformed response keeps the query link but adds no
            // response-side fields, and a malformed query starts no
            // transaction.
            track_malformed_response(context, id, flags, flavor);
        }
    }

    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Parse the header and every section. `false` means a hard error stopped the
/// message; fields decoded before it stay in the node.
fn parse_message(
    node: &mut Node,
    data: &[u8],
    base: usize,
    flavor: Flavor,
    learned: &mut Vec<(IpAddr, String)>,
    learn: bool,
) -> bool {
    if data.len() < 4 {
        return false;
    }
    let id = read_u16_be(data, 0).unwrap_or(0);
    let flags = read_u16_be(data, 2).unwrap_or(0);
    node.add_field(&fields::DNS_ID, Range::new(base, 2), Value::Uint16(id));
    node.add_field(
        &fields::DNS_FLAGS,
        Range::new(base + 2, 2),
        Value::Uint16(flags),
    );
    add_flags(node, base, flags, flavor);

    let opcode = (flags >> 11) & 0xf;
    let count_fields = if opcode == 5 {
        [
            &fields::DNS_COUNT_ZONES,
            &fields::DNS_COUNT_PREREQUISITES,
            &fields::DNS_COUNT_UPDATES,
        ]
    } else {
        [
            &fields::DNS_COUNT_QUERIES,
            &fields::DNS_COUNT_ANSWERS,
            &fields::DNS_COUNT_AUTH_RR,
        ]
    };
    let questions = add_count(node, data, base, 4, count_fields[0]);
    let answers = add_count(node, data, base, 6, count_fields[1]);
    let authority = add_count(node, data, base, 8, count_fields[2]);
    let additional = add_count(node, data, base, 10, &fields::DNS_COUNT_ADD_RR);
    let (Some(questions), Some(answers), Some(authority), Some(additional)) =
        (questions, answers, authority, additional)
    else {
        return false;
    };

    let mut offset = HEADER_LENGTH;
    for _ in 0..questions {
        match parse_question(node, data, base, offset, flavor) {
            Ok(next) => offset = next,
            Err(()) => return false,
        }
    }
    for _ in 0..answers {
        match parse_record(node, data, base, offset, flavor, learned, learn) {
            Ok(next) => offset = next,
            Err(()) => return false,
        }
    }
    for _ in 0..authority {
        match parse_record(node, data, base, offset, flavor, learned, learn) {
            Ok(next) => offset = next,
            Err(()) => return false,
        }
    }
    for _ in 0..additional {
        match parse_record(node, data, base, offset, flavor, learned, learn) {
            Ok(next) => offset = next,
            Err(()) => return false,
        }
    }
    true
}

fn add_count(
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    field: &'static fields::FieldDef,
) -> Option<u16> {
    let value = read_u16_be(data, offset)?;
    node.add_field(field, Range::new(base + offset, 2), Value::Uint16(value));
    Some(value)
}

fn add_flags(node: &mut Node, base: usize, flags: u16, flavor: Flavor) {
    let range = Range::new(base + 2, 2);
    let response = flags & 0x8000 != 0;
    node.add_field(&fields::DNS_FLAGS_RESPONSE, range, Value::Boolean(response));
    node.add_field(
        &fields::DNS_FLAGS_OPCODE,
        range,
        Value::Uint16((flags >> 11) & 0xf),
    );
    if flavor.is_llmnr() {
        node.add_field(
            &fields::DNS_FLAGS_CONFLICT,
            range,
            Value::Boolean(flags & 0x0400 != 0),
        );
        node.add_field(
            &fields::DNS_FLAGS_TRUNCATED,
            range,
            Value::Boolean(flags & 0x0200 != 0),
        );
        if response {
            node.add_field(&fields::DNS_FLAGS_RCODE, range, Value::Uint16(flags & 0xf));
        }
        return;
    }

    if response {
        node.add_field(
            &fields::DNS_FLAGS_AUTHORITATIVE,
            range,
            Value::Boolean(flags & 0x0400 != 0),
        );
    }
    node.add_field(
        &fields::DNS_FLAGS_TRUNCATED,
        range,
        Value::Boolean(flags & 0x0200 != 0),
    );
    node.add_field(
        &fields::DNS_FLAGS_RECDESIRED,
        range,
        Value::Boolean(flags & 0x0100 != 0),
    );
    if response {
        node.add_field(
            &fields::DNS_FLAGS_RECAVAIL,
            range,
            Value::Boolean(flags & 0x0080 != 0),
        );
    }
    node.add_field(
        &fields::DNS_FLAGS_Z,
        range,
        Value::Boolean(flags & 0x0040 != 0),
    );
    if response {
        node.add_field(
            &fields::DNS_FLAGS_AUTHENTICATED,
            range,
            Value::Boolean(flags & 0x0020 != 0),
        );
    }
    node.add_field(
        &fields::DNS_FLAGS_CHECKDISABLE,
        range,
        Value::Boolean(flags & 0x0010 != 0),
    );
    if response {
        node.add_field(&fields::DNS_FLAGS_RCODE, range, Value::Uint16(flags & 0xf));
    }
}

/// Parse one question and return the offset after it.
fn parse_question(
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    flavor: Flavor,
) -> Result<usize, ()> {
    let name = read_name(data, offset, data.len())?;
    let fixed = name.consumed.checked_add(4).ok_or(())?;
    if fixed > data.len() {
        return Err(());
    }
    let qtype = read_u16_be(data, name.consumed).ok_or(())?;
    let qclass = read_u16_be(data, name.consumed.checked_add(2).ok_or(())?).ok_or(())?;
    add_name_fields(node, base, offset, &name, true);
    node.add_field(
        &fields::DNS_QRY_TYPE,
        Range::new(base + name.consumed, 2),
        Value::Uint16(qtype),
    );
    let class_range = Range::new(base + name.consumed.checked_add(2).ok_or(())?, 2);
    if flavor.is_mdns() {
        node.add_field(
            &fields::DNS_QRY_CLASS,
            class_range,
            Value::Uint16(qclass & 0x7fff),
        );
        node.add_field(
            &fields::DNS_QRY_QU,
            class_range,
            Value::Boolean(qclass & 0x8000 != 0),
        );
    } else {
        node.add_field(&fields::DNS_QRY_CLASS, class_range, Value::Uint16(qclass));
    }
    Ok(fixed)
}

/// Parse one resource record and return the offset after it.
fn parse_record(
    node: &mut Node,
    data: &[u8],
    base: usize,
    offset: usize,
    flavor: Flavor,
    learned: &mut Vec<(IpAddr, String)>,
    learn: bool,
) -> Result<usize, ()> {
    let name = read_name(data, offset, data.len())?;
    let fixed = name.consumed.checked_add(10).ok_or(())?;
    if fixed > data.len() {
        return Err(());
    }
    let rtype = read_u16_be(data, name.consumed).ok_or(())?;
    let rclass = read_u16_be(data, name.consumed.checked_add(2).ok_or(())?).ok_or(())?;
    let ttl = read_u32_be(data, name.consumed.checked_add(4).ok_or(())?).ok_or(())?;
    let rdlength = read_u16_be(data, name.consumed.checked_add(8).ok_or(())?).ok_or(())?;
    let rdata_start = fixed;
    let rdata_end = rdata_start.checked_add(usize::from(rdlength)).ok_or(())?;
    let available_end = rdata_end.min(data.len());

    if learn && rclass == CLASS_IN && rtype == TYPE_A && rdlength == 4 && rdata_end <= data.len() {
        if let Some(address) = data.get(rdata_start..rdata_end)
            && let [a, b, c, d] = address
            && learned.len() < MAX_LEARNED_ADDRESSES
        {
            learned.push((IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)), name.text.clone()));
        }
    } else if learn
        && rclass == CLASS_IN
        && rtype == TYPE_AAAA
        && rdlength == 16
        && rdata_end <= data.len()
        && learned.len() < MAX_LEARNED_ADDRESSES
        && let Some(address) = data.get(rdata_start..rdata_end)
        && let Ok(bytes) = <[u8; 16]>::try_from(address)
    {
        learned.push((IpAddr::V6(Ipv6Addr::from(bytes)), name.text.clone()));
    }

    if rtype == TYPE_OPT {
        node.add_field(
            &fields::DNS_RESP_NAME,
            Range::new(base + offset, name.consumed.saturating_sub(offset)),
            Value::String(name.text.clone()),
        );
        node.add_field(
            &fields::DNS_RESP_TYPE,
            Range::new(base + name.consumed, 2),
            Value::Uint16(rtype),
        );
        let class_range = Range::new(base + name.consumed.checked_add(2).ok_or(())?, 2);
        if flavor.is_mdns() {
            node.add_field(
                &fields::DNS_RR_UDP_PAYLOAD_SIZE_MDNS,
                class_range,
                Value::Uint16(rclass & 0x7fff),
            );
            node.add_field(
                &fields::DNS_RESP_CACHE_FLUSH,
                class_range,
                Value::Boolean(rclass & 0x8000 != 0),
            );
        } else {
            node.add_field(
                &fields::DNS_RR_UDP_PAYLOAD_SIZE,
                class_range,
                Value::Uint16(rclass),
            );
        }
        let ttl_offset = name.consumed.checked_add(4).ok_or(())?;
        let ttl_range = Range::new(base + ttl_offset, 4);
        node.add_field(
            &fields::DNS_RESP_EXT_RCODE,
            Range::new(base + ttl_offset, 1),
            Value::Uint8(u8::try_from(ttl >> 24).unwrap_or(0)),
        );
        node.add_field(
            &fields::DNS_RESP_EDNS0_VERSION,
            Range::new(base + ttl_offset.saturating_add(1), 1),
            Value::Uint8(u8::try_from((ttl >> 16) & 0xff).unwrap_or(0)),
        );
        let z = u16::try_from(ttl & 0xffff).unwrap_or(0);
        node.add_field(&fields::DNS_RESP_Z, ttl_range, Value::Uint16(z));
        node.add_field(
            &fields::DNS_RESP_Z_DO,
            ttl_range,
            Value::Boolean(z & 0x8000 != 0),
        );
        node.add_field(
            &fields::DNS_RESP_Z_RESERVED,
            ttl_range,
            Value::Uint16(z & 0x7fff),
        );
        node.add_field(
            &fields::DNS_RESP_LEN,
            Range::new(base + name.consumed.checked_add(8).ok_or(())?, 2),
            Value::Uint16(rdlength),
        );
        parse_options(node, data, base, rdata_start, rdata_end)?;
        return fixed.checked_add(usize::from(rdlength)).ok_or(());
    }

    if rtype == TYPE_SRV {
        add_srv_owner(node, base, offset, &name);
    } else {
        node.add_field(
            &fields::DNS_RESP_NAME,
            Range::new(base + offset, name.consumed.saturating_sub(offset)),
            Value::String(name.text.clone()),
        );
    }
    node.add_field(
        &fields::DNS_RESP_TYPE,
        Range::new(base + name.consumed, 2),
        Value::Uint16(rtype),
    );
    let class_range = Range::new(base + name.consumed.checked_add(2).ok_or(())?, 2);
    if flavor.is_mdns() {
        node.add_field(
            &fields::DNS_RESP_CLASS,
            class_range,
            Value::Uint16(rclass & 0x7fff),
        );
        node.add_field(
            &fields::DNS_RESP_CACHE_FLUSH,
            class_range,
            Value::Boolean(rclass & 0x8000 != 0),
        );
    } else {
        node.add_field(&fields::DNS_RESP_CLASS, class_range, Value::Uint16(rclass));
    }
    node.add_field(
        &fields::DNS_RESP_TTL,
        Range::new(base + name.consumed.checked_add(4).ok_or(())?, 4),
        Value::Uint32(ttl),
    );
    node.add_field(
        &fields::DNS_RESP_LEN,
        Range::new(base + name.consumed.checked_add(8).ok_or(())?, 2),
        Value::Uint16(rdlength),
    );

    let effective_class = if flavor.is_mdns() {
        rclass & 0x7fff
    } else {
        rclass
    };
    parse_rdata(
        node,
        data,
        base,
        rtype,
        effective_class,
        rdata_start,
        rdata_end,
        available_end,
    )?;
    fixed.checked_add(usize::from(rdlength)).ok_or(())
}

fn add_srv_owner(node: &mut Node, base: usize, offset: usize, name: &ParsedName) {
    let range = Range::new(base + offset, name.consumed.saturating_sub(offset));
    let use_instance =
        name.labels.len() >= 3 && name.labels.get(2).is_some_and(|l| l.starts_with('_'));
    let (instance, service, proto, rest) = if use_instance {
        (
            name.labels.first(),
            name.labels.get(1),
            name.labels.get(2),
            name.labels.get(3..).unwrap_or(&[]),
        )
    } else {
        (
            None,
            name.labels.first(),
            name.labels.get(1),
            name.labels.get(2..).unwrap_or(&[]),
        )
    };
    if name.labels.is_empty() {
        node.add_field(
            &fields::DNS_SRV_SERVICE,
            range,
            Value::String(name.text.clone()),
        );
        return;
    }
    if let Some(instance) = instance {
        node.add_field(
            &fields::DNS_SRV_INSTANCE,
            range,
            Value::String(instance.clone()),
        );
    }
    if let Some(service) = service {
        node.add_field(
            &fields::DNS_SRV_SERVICE,
            range,
            Value::String(service.clone()),
        );
    }
    if let Some(proto) = proto {
        node.add_field(&fields::DNS_SRV_PROTO, range, Value::String(proto.clone()));
    }
    if !rest.is_empty() {
        node.add_field(&fields::DNS_SRV_NAME, range, Value::String(rest.join(".")));
    }
}

/// Decode typed rdata, bounded by the declared length and the captured bytes.
#[expect(
    clippy::too_many_arguments,
    reason = "rdata handling needs the record type, class and three offsets"
)]
fn parse_rdata(
    node: &mut Node,
    data: &[u8],
    base: usize,
    rtype: u16,
    rclass: u16,
    start: usize,
    declared_end: usize,
    available_end: usize,
) -> Result<(), ()> {
    let declared = declared_end.saturating_sub(start);
    if declared == 0 {
        return Ok(());
    }
    let range = Range::new(base + start, available_end.saturating_sub(start));
    match rtype {
        TYPE_A if rclass == CLASS_IN => {
            let end = start.saturating_add(4);
            if end > available_end {
                return Err(());
            }
            let address = data.get(start..end).ok_or(())?;
            node.add_field(
                &fields::DNS_A,
                range,
                Value::Ipv4(<[u8; 4]>::try_from(address).map_err(|_| ())?),
            );
            Ok(())
        }
        TYPE_AAAA if rclass == CLASS_IN => {
            let end = start.saturating_add(16);
            if end > available_end {
                return Err(());
            }
            let address = data.get(start..end).ok_or(())?;
            node.add_field(
                &fields::DNS_AAAA,
                range,
                Value::Ipv6(<[u8; 16]>::try_from(address).map_err(|_| ())?),
            );
            Ok(())
        }
        TYPE_CNAME | TYPE_NS | TYPE_PTR => {
            let name = read_name(data, start, available_end)?;
            let field = match rtype {
                TYPE_CNAME => &fields::DNS_CNAME,
                TYPE_NS => &fields::DNS_NS,
                _ => &fields::DNS_PTR_DOMAIN_NAME,
            };
            let name_range = Range::new(base + start, name.consumed.saturating_sub(start));
            node.add_field(field, name_range, Value::String(name.text));
            Ok(())
        }
        TYPE_MX => {
            if start.saturating_add(2) > available_end {
                return Err(());
            }
            let preference = read_u16_be(data, start).ok_or(())?;
            let name = read_name(data, start.saturating_add(2), available_end)?;
            node.add_field(
                &fields::DNS_MX_PREFERENCE,
                Range::new(base + start, 2),
                Value::Uint16(preference),
            );
            node.add_field(
                &fields::DNS_MX_MAIL_EXCHANGE,
                Range::new(
                    base + start.saturating_add(2),
                    name.consumed.saturating_sub(start.saturating_add(2)),
                ),
                Value::String(name.text),
            );
            Ok(())
        }
        TYPE_SOA => {
            let mname = read_name(data, start, available_end)?;
            node.add_field(
                &fields::DNS_SOA_MNAME,
                Range::new(base + start, mname.consumed.saturating_sub(start)),
                Value::String(mname.text),
            );
            let rname = read_name(data, mname.consumed, available_end)?;
            let rname_range = Range::new(
                base + mname.consumed,
                rname.consumed.saturating_sub(mname.consumed),
            );
            let mailbox = if rname.labels.len() >= 2 {
                let mut mailbox = rname.labels.first().cloned().unwrap_or_default();
                mailbox.push('@');
                mailbox.push_str(&rname.labels.get(1..).unwrap_or(&[]).join("."));
                mailbox
            } else {
                rname.text.clone()
            };
            node.add_field(
                &fields::DNS_SOA_RNAME_NAME,
                rname_range,
                Value::String(mailbox),
            );
            node.add_field(
                &fields::DNS_SOA_RNAME,
                rname_range,
                Value::String(rname.text),
            );
            let numbers = rname.consumed;
            for (index, field) in [
                &fields::DNS_SOA_SERIAL_NUMBER,
                &fields::DNS_SOA_REFRESH_INTERVAL,
                &fields::DNS_SOA_RETRY_INTERVAL,
                &fields::DNS_SOA_EXPIRE_LIMIT,
                &fields::DNS_SOA_MINIMUM_TTL,
            ]
            .iter()
            .enumerate()
            {
                let offset = numbers
                    .checked_add(index.checked_mul(4).ok_or(())?)
                    .ok_or(())?;
                let value = read_u32_be(data, offset)
                    .filter(|_| offset.saturating_add(4) <= available_end)
                    .ok_or(())?;
                node.add_field(field, Range::new(base + offset, 4), Value::Uint32(value));
            }
            Ok(())
        }
        TYPE_TXT => {
            let mut offset = start;
            while offset < declared_end {
                let length = usize::from(*data.get(offset).ok_or(())?);
                node.add_field(
                    &fields::DNS_TXT_LENGTH,
                    Range::new(base + offset, 1),
                    Value::Uint8(u8::try_from(length).unwrap_or(0)),
                );
                let next = offset
                    .checked_add(1)
                    .and_then(|v| v.checked_add(length))
                    .ok_or(())?;
                if next > declared_end || next > available_end {
                    return Err(());
                }
                let text = data.get(offset.saturating_add(1)..next).ok_or(())?;
                node.add_field(
                    &fields::DNS_TXT,
                    Range::new(base + offset.saturating_add(1), length),
                    Value::String(String::from_utf8_lossy(text).into_owned()),
                );
                offset = next;
            }
            Ok(())
        }
        TYPE_SRV => {
            for (index, field) in [
                &fields::DNS_SRV_PRIORITY,
                &fields::DNS_SRV_WEIGHT,
                &fields::DNS_SRV_PORT,
            ]
            .iter()
            .enumerate()
            {
                let offset = start
                    .checked_add(index.checked_mul(2).ok_or(())?)
                    .ok_or(())?;
                if offset.saturating_add(2) > available_end {
                    return Err(());
                }
                let value = read_u16_be(data, offset).ok_or(())?;
                node.add_field(field, Range::new(base + offset, 2), Value::Uint16(value));
            }
            let fixed_end = start.saturating_add(6);
            let target = read_name(data, fixed_end, available_end)?;
            node.add_field(
                &fields::DNS_SRV_TARGET,
                Range::new(base + fixed_end, target.consumed.saturating_sub(fixed_end)),
                Value::String(target.text),
            );
            Ok(())
        }
        _ => {
            if available_end < declared_end {
                return Err(());
            }
            node.add_field(
                &fields::DNS_DATA,
                range,
                Value::bytes(data.get(start..declared_end).ok_or(())?.to_vec()),
            );
            Ok(())
        }
    }
}

/// Decode the EDNS(0) option list; `end` is bounded by the captured bytes.
fn parse_options(
    node: &mut Node,
    data: &[u8],
    base: usize,
    start: usize,
    end: usize,
) -> Result<(), ()> {
    let mut offset = start;
    while offset < end {
        let header_end = offset.checked_add(4).ok_or(())?;
        if header_end > end {
            return Err(());
        }
        let code = read_u16_be(data, offset).ok_or(())?;
        let length = read_u16_be(data, offset.saturating_add(2)).ok_or(())?;
        let data_start = header_end;
        let data_end = data_start.checked_add(usize::from(length)).ok_or(())?;
        node.add_field(&fields::DNS_OPT, Range::new(base + offset, 4), Value::None);
        node.add_field(
            &fields::DNS_OPT_CODE,
            Range::new(base + offset, 2),
            Value::Uint16(code),
        );
        node.add_field(
            &fields::DNS_OPT_LEN,
            Range::new(base + offset.saturating_add(2), 2),
            Value::Uint16(length),
        );
        if data_end > end {
            return Err(());
        }
        let value = if length == 0 {
            Value::Missing
        } else {
            Value::bytes(data.get(data_start..data_end).ok_or(())?.to_vec())
        };
        node.add_field(
            &fields::DNS_OPT_DATA,
            Range::new(base + data_start, usize::from(length)),
            value.clone(),
        );
        if code == OPTION_PADDING {
            node.add_field(
                &fields::DNS_OPT_PADDING,
                Range::new(base + data_start, usize::from(length)),
                value,
            );
        }
        offset = data_end;
    }
    Ok(())
}

/// A name decoded from the message.
struct ParsedName {
    /// Display form, with control octets escaped.
    text: String,
    /// Escaped labels, used for SRV owner decomposition.
    labels: Vec<String>,
    /// Length of the raw, unescaped name text.
    raw_length: usize,
    /// Label count, derived from the raw text.
    label_count: u16,
    /// Offset just after the name's first, uncompressed part.
    consumed: usize,
}

/// Render one label, escaping control octets as C-style escapes.
fn escape_label(label: &[u8]) -> String {
    // Decode the whole label first so multi-octet UTF-8 characters survive,
    // then escape the ASCII controls in the decoded text.
    let decoded = String::from_utf8_lossy(label);
    let mut text = String::with_capacity(decoded.len());
    for character in decoded.chars() {
        match character {
            '\u{0a}' => text.push_str("\\n"),
            '\u{09}' => text.push_str("\\t"),
            '\u{0d}' => text.push_str("\\r"),
            '\u{07}' => text.push_str("\\a"),
            '\u{08}' => text.push_str("\\b"),
            '\u{0b}' => text.push_str("\\v"),
            '\u{0c}' => text.push_str("\\f"),
            character if (character as u32) < 0x20 || character == '\u{7f}' => {
                let _ = write!(text, "\\{:03o}", character as u32);
            }
            character => text.push(character),
        }
    }
    text
}

fn label_count_for(raw_length: usize, dots: usize) -> u16 {
    let count = dots.saturating_add(usize::from(raw_length > 1));
    u16::try_from(count).unwrap_or(u16::MAX)
}

fn build_name(labels: &[Vec<u8>], consumed: usize) -> ParsedName {
    let mut raw = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            raw.push(b'.');
        }
        raw.extend_from_slice(label);
    }
    let dots = raw.iter().filter(|byte| **byte == b'.').count();
    if labels.is_empty() {
        return ParsedName {
            text: "<Root>".to_string(),
            labels: Vec::new(),
            raw_length: "<Root>".len(),
            label_count: 1,
            consumed,
        };
    }
    let escaped: Vec<String> = labels.iter().map(|label| escape_label(label)).collect();
    ParsedName {
        text: escaped.join("."),
        labels: escaped,
        raw_length: raw.len(),
        label_count: label_count_for(raw.len(), dots),
        consumed,
    }
}

/// Read a domain name starting at `start`, bounded by `bound` for the first
/// segment. Compression pointers may target anywhere in the message.
fn read_name(data: &[u8], start: usize, bound: usize) -> Result<ParsedName, ()> {
    let mut position = start;
    let mut limit = bound.min(data.len());
    let mut jumped = false;
    let mut consumed = start;
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut length: usize = 1; // the root label
    let mut jumps: usize = 0;
    let mut too_long = false;

    loop {
        if position >= limit {
            return Err(());
        }
        let marker = *data.get(position).ok_or(())?;
        if marker == 0 {
            if !jumped {
                consumed = position.saturating_add(1);
            }
            if too_long {
                return Ok(placeholder_name("<Name too long>", consumed));
            }
            return Ok(build_name(&labels, consumed));
        }
        match marker & 0xc0 {
            0x00 => {
                let label_length = usize::from(marker);
                let next = position
                    .checked_add(1)
                    .and_then(|value| value.checked_add(label_length))
                    .ok_or(())?;
                if next > limit {
                    return Err(());
                }
                length = length.saturating_add(1).saturating_add(label_length);
                if length > MAX_NAME_LENGTH {
                    // Keep scanning so the caller still finds the end of the
                    // name, but stop growing the label list.
                    too_long = true;
                } else {
                    let label = data.get(position.saturating_add(1)..next).ok_or(())?;
                    labels.push(label.to_vec());
                }
                position = next;
            }
            0xc0 => {
                let second = position.checked_add(1).ok_or(())?;
                if second >= limit {
                    return Err(());
                }
                let low = usize::from(*data.get(second).ok_or(())?);
                let target = (usize::from(marker & 0x3f) << 8) | low;
                if !jumped {
                    consumed = second.saturating_add(1);
                    jumped = true;
                }
                if target >= data.len() {
                    return Err(());
                }
                jumps = jumps.saturating_add(1);
                if jumps > MAX_POINTER_JUMPS {
                    return Ok(placeholder_name(
                        "<Name contains a pointer that loops>",
                        consumed,
                    ));
                }
                position = target;
                limit = data.len();
            }
            _ => return Err(()),
        }
    }
}

fn placeholder_name(text: &str, consumed: usize) -> ParsedName {
    ParsedName {
        text: text.to_string(),
        labels: Vec::new(),
        raw_length: text.len(),
        label_count: label_count_for(text.len(), 0),
        consumed,
    }
}

/// Add a name and, for questions, its name-length and label-count
/// companion fields. A placeholder name reports one label.
fn add_name_fields(node: &mut Node, base: usize, offset: usize, name: &ParsedName, question: bool) {
    let range = Range::new(base + offset, name.consumed.saturating_sub(offset));
    node.add_field(
        &fields::DNS_QRY_NAME,
        range,
        Value::String(name.text.clone()),
    );
    if !question {
        return;
    }
    // Both companion values come from the raw name text before escaping, so
    // a one-octet name contributes neither.
    let length = if name.raw_length > 1 {
        name.raw_length
    } else {
        0
    };
    node.add_field(
        &fields::DNS_QRY_NAME_LEN,
        range,
        Value::Uint16(u16::try_from(length).unwrap_or(u16::MAX)),
    );
    node.add_field(
        &fields::DNS_COUNT_LABELS,
        range,
        Value::Uint16(name.label_count),
    );
}

/// The Display-filter value name for a DNS RR type.
pub(crate) fn type_name(rtype: u16) -> Option<&'static str> {
    match rtype {
        TYPE_A => Some("A"),
        TYPE_NS => Some("NS"),
        TYPE_CNAME => Some("CNAME"),
        TYPE_SOA => Some("SOA"),
        TYPE_PTR => Some("PTR"),
        TYPE_MX => Some("MX"),
        TYPE_TXT => Some("TXT"),
        TYPE_AAAA => Some("AAAA"),
        TYPE_SRV => Some("SRV"),
        TYPE_OPT => Some("OPT"),
        TYPE_ANY => Some("ANY"),
        _ => None,
    }
}

/// The presentation name for a type, using `Unknown (N)` when unregistered.
pub fn type_text(rtype: u16) -> String {
    type_name(rtype).map_or_else(|| format!("Unknown ({rtype})"), |name| name.to_string())
}

/// Rcode presentation names used by the summary line.
pub fn rcode_text(rcode: u16) -> Option<&'static str> {
    match rcode {
        1 => Some("Format error"),
        2 => Some("Server failure"),
        3 => Some("No such name"),
        4 => Some("Not implemented"),
        5 => Some("Refused"),
        6 => Some("Name exists"),
        7 => Some("RRset exists"),
        8 => Some("RRset does not exist"),
        9 => Some("Not authoritative"),
        10 => Some("Name out of zone"),
        11 => Some("DSO-Type not implemented"),
        12..=15 => None,
        _ => None,
    }
}

/// Opcode presentation names used by the summary line.
pub fn opcode_text(opcode: u16) -> String {
    match opcode {
        0 => "Standard query".to_string(),
        1 => "Inverse query".to_string(),
        2 => "Server status request".to_string(),
        4 => "Zone change notification".to_string(),
        5 => "Dynamic update".to_string(),
        6 => "DNS Stateful operations (DSO)".to_string(),
        other => format!("Unknown operation ({other})"),
    }
}

/// The `dns.retransmission_timer` default: a repeated query is only a
/// retransmission strictly inside this window. At exactly five seconds a new
/// query starts a new transaction and the old one is reported missing.
const RETRANSMISSION_WINDOW_NS: i64 = 5_000_000_000;

/// Update DNS transaction state and add the links this message knows now.
///
/// One pass and the recording pass both classify a response against the
/// pending query and a repeated query or response against its original. The
/// recording pass additionally writes annotations for the output pass, which
/// may not decode either counterpart.
fn track_transaction(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    base: usize,
    id: u16,
    flags: u16,
    flavor: Flavor,
) {
    if context.observe_only {
        return;
    }
    let Some(key) = transaction_key(context, id, flags, flavor) else {
        return;
    };
    let now = frame_time_ns(context);
    // Tree fields carry the pass-one display number; annotations key the
    // capture frame number.
    let current = u32::try_from(context.frame.number).unwrap_or(u32::MAX);
    let current_file = u32::try_from(context.frame.file_number).unwrap_or(u32::MAX);
    let response = flags & 0x8000 != 0;
    let recording = context.pass == PassMode::First;
    // Request links and missing-response flags travel as annotations from
    // the recording pass. The output pass recomputes retransmission
    // classification from only the frames it accepted.
    let output_pass = context.pass == PassMode::Second;
    let mut transaction = context.state.dns_take(key).unwrap_or_default();
    if response {
        if transaction.pending_frame != 0 {
            let request = transaction.pending_frame;
            let delay = now.saturating_sub(transaction.pending_time_ns);
            if !output_pass {
                add_request_link(node, base, request);
                add_time(node, base, delay);
            }
            if recording {
                let annotations = context.state.annotations_mut();
                annotations.link_response(
                    u64::from(current_file),
                    u64::from(transaction.pending_file),
                    delay,
                );
                for request in transaction.request_files() {
                    annotations.link_response_in(u64::from(*request), u64::from(current_file));
                }
            }
            transaction.clear_pending(current);
        } else if transaction.last_response_frame != 0 {
            add_retransmission(node, base, true, transaction.last_response_frame);
            if recording && transaction.original_request_file != 0 {
                let delay = now.saturating_sub(transaction.original_request_time_ns);
                context.state.annotations_mut().link_response(
                    u64::from(current_file),
                    u64::from(transaction.original_request_file),
                    delay,
                );
            }
        } else {
            // An unsolicited response that the recording pass linked to a
            // request still establishes the last response, so a later
            // response to the transaction is a retransmission.
            if output_pass
                && context
                    .state
                    .annotation(context.frame.file_number)
                    .is_some_and(|annotation| annotation.request_in != 0)
            {
                transaction.last_response_frame = current;
            }
        }
    } else if transaction.pending_frame != 0 {
        let elapsed = now.saturating_sub(transaction.pending_time_ns);
        if elapsed < RETRANSMISSION_WINDOW_NS {
            add_retransmission(node, base, false, transaction.pending_frame);
            transaction.push_request(current, current_file);
        } else {
            if recording {
                let annotations = context.state.annotations_mut();
                for request in transaction.request_files() {
                    annotations.mark_response_missing(u64::from(*request));
                }
            }
            transaction.start(current, current_file, now);
        }
    } else {
        transaction.start(current, current_file, now);
    }
    // An unsolicited response with no earlier response leaves nothing worth
    // keeping; skipping the insert keeps hostile response floods from
    // charging the state budget.
    if transaction.pending_frame != 0 || transaction.last_response_frame != 0 {
        context.state.dns_put(key, transaction);
    }
}

/// Build the transaction key for one decoded message.
fn transaction_key(
    context: &DecodeContext<'_>,
    id: u16,
    flags: u16,
    flavor: Flavor,
) -> Option<DnsTransactionKey> {
    if context.quoted {
        return None;
    }
    let (source, destination) = network_addresses(context.network.as_ref())?;
    let (source_port, destination_port) = context.udp_ports?;
    if flavor.is_llmnr() {
        Some(DnsTransactionKey::llmnr(
            source,
            source_port,
            destination,
            destination_port,
            id,
            flags & 0x8000 != 0,
        ))
    } else {
        Some(DnsTransactionKey::pair(
            source,
            source_port,
            destination,
            destination_port,
            id,
        ))
    }
}

/// Keep the pass-one query link for a malformed response.
///
/// A malformed response is decoded far enough to answer the pending query,
/// but emits no response-side request link or time; a malformed query starts
/// no transaction.
fn track_malformed_response(context: &mut DecodeContext<'_>, id: u16, flags: u16, flavor: Flavor) {
    if context.observe_only || context.pass != PassMode::First || flags & 0x8000 == 0 {
        return;
    }
    let Some(key) = transaction_key(context, id, flags, flavor) else {
        return;
    };
    let Some(mut transaction) = context.state.dns_take(key) else {
        return;
    };
    if transaction.pending_frame == 0 {
        return;
    }
    let current = u32::try_from(context.frame.number).unwrap_or(u32::MAX);
    let current_file = u32::try_from(context.frame.file_number).unwrap_or(u32::MAX);
    let annotations = context.state.annotations_mut();
    for request in transaction.request_files() {
        annotations.link_response_in(u64::from(*request), u64::from(current_file));
    }
    transaction.clear_pending(current);
    context.state.dns_put(key, transaction);
}

/// The frame's capture time in nanoseconds, or zero when it has none.
fn frame_time_ns(context: &DecodeContext<'_>) -> i64 {
    context.frame.timestamp.map_or(0, |timestamp| {
        timestamp
            .seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(i64::from(timestamp.nanos))
    })
}

/// Source and destination addresses of the innermost network layer.
fn network_addresses(network: Option<&NetworkContext>) -> Option<(IpAddr, IpAddr)> {
    match network? {
        NetworkContext::Ipv4 {
            source,
            destination,
            ..
        } => Some((
            IpAddr::V4(Ipv4Addr::from(*source)),
            IpAddr::V4(Ipv4Addr::from(*destination)),
        )),
        NetworkContext::Ipv6 {
            source,
            destination,
            ..
        } => Some((
            IpAddr::V6(Ipv6Addr::from(*source)),
            IpAddr::V6(Ipv6Addr::from(*destination)),
        )),
    }
}
/// Decode the DNS messages carried by one TCP segment.
///
/// RFC 1035 section 4.2.2 prefixes every message with a two-octet length
/// that excludes the prefix itself. Each complete message in the segment is
/// decoded and the rest is left for reassembly, so a segment that does not
/// hold the first complete message produces no DNS fields and the payload
/// stays TCP. TCP reassembly joins the remaining bytes through the stream
/// buffer.
pub(crate) fn decode_tcp(
    context: &mut DecodeContext<'_>,
    parent: &mut Node,
    data: &[u8],
    base: usize,
) {
    // Without one complete PDU there is no DNS node; a later segment may
    // complete it through TCP reassembly.

    let Some(first_length) = read_u16_be(data, 0) else {
        return;
    };
    let Some(first_end) = 2_usize.checked_add(usize::from(first_length)) else {
        return;
    };
    if first_end > data.len() {
        return;
    }

    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::DNS_PROTOCOL.filter_name);
    let conversation = context
        .transport_ports
        .and_then(|(source, destination)| context.conversation_key(source, destination))
        .map(|(key, _)| key);

    let mut offset = 0_usize;
    while let Some(length) = read_u16_be(data, offset) {
        let Some(end) = offset
            .checked_add(2)
            .and_then(|start| start.checked_add(usize::from(length)))
        else {
            break;
        };
        if end > data.len() {
            break;
        }
        let message = data.get(offset.saturating_add(2)..end).unwrap_or(&[]);
        let mut node = Node::new(
            &fields::DNS_PROTOCOL,
            Range::new(base.saturating_add(offset), end.saturating_sub(offset)),
        );
        // The fixed header is read before any field is added, so a message
        // shorter than four octets (id plus flags) keeps no fields at all.
        if message.len() >= 4 {
            node.add_field(
                &fields::DNS_LENGTH,
                Range::new(base.saturating_add(offset), 2),
                Value::Uint16(length),
            );
        }
        let mut learned = Vec::new();
        let learn = context.names.dns_learning_enabled() && !context.quoted;
        if !parse_message(
            &mut node,
            message,
            base.saturating_add(offset).saturating_add(2),
            Flavor::Dns,
            &mut learned,
            learn,
        ) {
            context.mark_malformed(&mut node, "Malformed DNS message");
        }
        for (address, name) in learned {
            context.names.learn_dns(address, &name);
        }
        if let Some(conversation) = conversation
            && !context.quoted
        {
            add_tcp_state(context, &mut node, message, conversation);
        }
        parent.add_child(node);
        offset = end;
    }

    context.depth = context.depth.saturating_sub(1);
}

/// Add the transaction state fields to one DNS-over-TCP message.
///
/// The state is one-pass measurable: a response that follows its query links
/// backwards, and repeated queries or responses inside the five-second window
/// become retransmissions. `dns.response_in` points forwards, so the recording
/// pass stores it as an annotation for the output pass.
fn add_tcp_state(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    message: &[u8],
    conversation: crate::state::ConversationKey,
) {
    let (Some(id), Some(flags)) = (read_u16_be(message, 0), read_u16_be(message, 2)) else {
        return;
    };
    let response = flags & 0x8000 != 0;
    if context.observe_only {
        // The output pass still closes TCP DNS transactions from rejected
        // response frames, but learns no query from rejected ones.
        if response {
            let frame = context.frame.number;
            let time = context.frame.timestamp;
            let _ = context
                .state
                .dns_tcp_response(conversation, id, frame, time);
        }
        return;
    }
    let frame = context.frame.number;
    let file = context.frame.file_number;
    let time = context.frame.timestamp;
    let range = Range::new(0, 0);
    if response {
        match context
            .state
            .dns_tcp_response(conversation, id, frame, time)
        {
            crate::state::DnsResponseOutcome::Matched {
                request_frame,
                request_file,
                request_files,
                request_file_count,
                elapsed_nanos,
            } => {
                if context.pass == PassMode::First {
                    let annotations = context.state.annotations_mut();
                    for request in request_files.iter().take(usize::from(request_file_count)) {
                        annotations.link_response_in(u64::from(*request), file);
                    }
                    if let Some(elapsed) = elapsed_nanos {
                        annotations.link_response(file, request_file, elapsed);
                    }
                }
                // The output pass reads both links from the recording pass,
                // which keeps them correct when the request frame is skipped.
                if context.pass != PassMode::Second {
                    node.add_field(
                        &fields::DNS_RESPONSE_TO,
                        range,
                        Value::Uint32(u32::try_from(request_frame).unwrap_or(u32::MAX)),
                    );
                    if let Some(elapsed) = elapsed_nanos {
                        node.add_field(&fields::DNS_TIME, range, Value::RelativeTime(elapsed));
                    }
                }
            }
            crate::state::DnsResponseOutcome::Retransmission { response_frame } => {
                node.add_field(&fields::DNS_RETRANSMISSION, range, Value::Boolean(true));
                node.add_field(
                    &fields::DNS_RETRANSMIT_RESPONSE_IN,
                    range,
                    Value::Uint32(u32::try_from(response_frame).unwrap_or(u32::MAX)),
                );
                node.add_expert(crate::tree::ExpertInfo {
                    severity: crate::tree::Severity::Warning,
                    group: crate::tree::Group::Protocol,
                    message: format!(
                        "DNS response retransmission. Original response in frame {response_frame}"
                    ),
                });
            }
            crate::state::DnsResponseOutcome::Unsolicited => {
                node.add_field(&fields::DNS_UNSOLICITED, range, Value::Boolean(true));
            }
        }
        return;
    }

    let multiple_responses =
        first_question_type(node).is_some_and(|kind| kind == 251 || kind == 252);
    match context
        .state
        .dns_tcp_request(conversation, id, frame, file, time, multiple_responses)
    {
        crate::state::DnsRequestOutcome::New => {}
        crate::state::DnsRequestOutcome::Retransmission { original_frame } => {
            node.add_field(&fields::DNS_RETRANSMISSION, range, Value::Boolean(true));
            node.add_field(
                &fields::DNS_RETRANSMIT_REQUEST_IN,
                range,
                Value::Uint32(u32::try_from(original_frame).unwrap_or(u32::MAX)),
            );
            node.add_expert(crate::tree::ExpertInfo {
                severity: crate::tree::Severity::Warning,
                group: crate::tree::Group::Protocol,
                message: format!(
                    "DNS query retransmission. Original request in frame {original_frame}"
                ),
            });
        }
    }
}

/// The type of the first question, when one was decoded.
fn first_question_type(node: &Node) -> Option<u16> {
    node.fields.iter().find_map(|field| {
        if field.def.abbrev == "dns.qry.type" {
            match field.value {
                Value::Uint16(kind) => Some(kind),
                _ => None,
            }
        } else {
            None
        }
    })
}
