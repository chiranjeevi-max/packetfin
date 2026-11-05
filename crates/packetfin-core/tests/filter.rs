//! Display-filter parsing and evaluation against hand-built protocol trees.
//!
//! The trees are built from the real registry so a test fails if a field or
//! protocol definition disappears.

use packetfin_core::fields::{FRAME_NUMBER, FRAME_PROTOCOL, protocols, registry};
use packetfin_core::{
    FieldDef, FieldSelection, Filter, Node, ProtocolDef, ProtocolSelection, Range, Timestamp, Tree,
    Value, filter::FilterError,
};

fn field(name: &str) -> &'static FieldDef {
    let resolved = registry().field(name);
    assert!(resolved.is_some(), "missing field {name}");
    resolved.unwrap_or(&FRAME_NUMBER)
}

fn protocol(name: &str) -> &'static ProtocolDef {
    let resolved = protocols()
        .iter()
        .copied()
        .find(|protocol| protocol.filter_name == name);
    assert!(resolved.is_some(), "missing protocol {name}");
    resolved.unwrap_or(&FRAME_PROTOCOL)
}

fn node(name: &str) -> Node {
    Node::new(protocol(name), Range::default())
}

fn add(node: &mut Node, name: &str, value: Value) {
    node.add_field(field(name), Range::default(), value);
}

fn matches(filter: &str, tree: &Tree) -> bool {
    let parsed = Filter::parse(filter);
    assert!(
        parsed.is_ok(),
        "{filter:?} failed to parse: {:?}",
        parsed.as_ref().err()
    );
    parsed.map(|parsed| parsed.matches(tree)).unwrap_or(false)
}

fn parse_error(filter: &str) -> Option<FilterError> {
    let parsed = Filter::parse(filter);
    assert!(parsed.is_err(), "{filter:?} unexpectedly parsed");
    parsed.err()
}

/// Ethernet/IPv4/TCP with two `ip.src` occurrences and a false TCP flag.
fn packet() -> Tree {
    let mut frame = node("frame");
    add(&mut frame, "frame.number", Value::Uint32(1));
    add(&mut frame, "frame.len", Value::Uint32(60));
    add(
        &mut frame,
        "frame.interface_name",
        Value::String("eth0".to_string()),
    );
    add(
        &mut frame,
        "frame.time_epoch",
        Value::AbsoluteTime(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
    );

    let mut eth = node("eth");
    add(
        &mut eth,
        "eth.dst",
        Value::Ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
    );
    add(
        &mut eth,
        "eth.src",
        Value::Ethernet([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
    );
    add(&mut eth, "eth.type", Value::Uint16(0x0800));

    let mut ip = node("ip");
    add(&mut ip, "ip.src", Value::Ipv4([192, 0, 2, 1]));
    add(&mut ip, "ip.src", Value::Ipv4([10, 0, 0, 1]));
    add(&mut ip, "ip.dst", Value::Ipv4([198, 51, 100, 2]));
    add(&mut ip, "ip.len", Value::Uint16(40));

    let mut tcp = node("tcp");
    add(&mut tcp, "tcp.srcport", Value::Uint16(40000));
    add(&mut tcp, "tcp.flags.syn", Value::Boolean(true));
    add(&mut tcp, "tcp.flags.ack", Value::Boolean(false));
    ip.add_child(tcp);
    eth.add_child(ip);
    frame.add_child(eth);
    Tree::new(frame)
}

/// Two equal `ip.src` occurrences, for the all-occurrence operators.
fn packet_with_repeated_equal_values() -> Tree {
    let mut frame = node("frame");
    let mut ip = node("ip");
    add(&mut ip, "ip.src", Value::Ipv4([192, 0, 2, 1]));
    add(&mut ip, "ip.src", Value::Ipv4([192, 0, 2, 1]));
    frame.add_child(ip);
    Tree::new(frame)
}

fn packet_ipv6() -> Tree {
    let mut frame = node("frame");
    let mut ipv6 = node("ipv6");
    add(
        &mut ipv6,
        "ipv6.src",
        Value::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    );
    frame.add_child(ipv6);
    Tree::new(frame)
}

fn packet_bytes() -> Tree {
    let mut frame = node("frame");
    let mut sll = node("sll");
    add(&mut sll, "sll.unused", Value::bytes(vec![0, 0]));
    frame.add_child(sll);
    Tree::new(frame)
}

#[test]
fn empty_and_whitespace_filters_match_every_packet() {
    let tree = packet();
    assert!(matches("", &tree));
    assert!(matches("   \t ", &tree));
}

#[test]
fn unknown_field_reports_its_token_position() {
    let Some(error) = parse_error("ip.nope == 1") else {
        return;
    };
    assert_eq!(error.offset(), 0);
    assert_eq!(error.length(), Some(7));
    assert!(error.message().contains("ip.nope"), "{error}");
}

#[test]
fn unknown_protocol_reports_its_token_position() {
    let Some(error) = parse_error("frame.number == 1 and nope") else {
        return;
    };
    assert_eq!(error.offset(), 22);
    assert_eq!(error.length(), Some(4));
    assert!(error.message().contains("nope"), "{error}");
}

#[test]
fn invalid_character_reports_its_position() {
    let Some(error) = parse_error("ip.src = 192.0.2.1") else {
        return;
    };
    assert_eq!(error.offset(), 7);
    assert_eq!(error.length(), Some(1));
}

#[test]
fn end_of_input_errors_report_the_filter_length() {
    let text = "ip.src ==";
    let Some(error) = parse_error(text) else {
        return;
    };
    assert_eq!(error.offset(), text.len());
    assert_eq!(error.length(), None);

    let text = "frame.number == 1 and";
    let Some(error) = parse_error(text) else {
        return;
    };
    assert_eq!(error.offset(), text.len());
    assert_eq!(error.length(), None);
}

#[test]
fn unterminated_string_reports_the_end() {
    let text = "ip.src == \"unterminated";
    let Some(error) = parse_error(text) else {
        return;
    };
    assert_eq!(error.offset(), text.len());
    assert!(error.message().contains("quote"), "{error}");
}

#[test]
fn protocol_and_field_existence_match_the_decoded_tree() {
    let tree = packet();
    for (filter, expected) in [
        ("frame", true),
        ("eth", true),
        ("ip", true),
        ("tcp", true),
        ("udp", false),
        ("ipv6", false),
        ("ip.src", true),
        ("tcp.flags.ack", true),
        ("udp.srcport", false),
        ("!udp", true),
        ("!udp.srcport", true),
        ("not ipv6", true),
        ("ip and tcp", true),
        ("ip and udp", false),
        ("ip or udp", true),
        ("ip xor udp", true),
        ("ip xor tcp", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn missing_fields_make_comparisons_false_but_negation_true() {
    let tree = packet();
    for filter in [
        "udp.srcport == 53",
        "udp.srcport != 53",
        "udp.srcport < 53",
        "udp.srcport === 53",
        "udp.srcport any_ne 53",
        "udp.srcport all_ne 53",
    ] {
        assert!(!matches(filter, &tree), "{filter}");
    }
    assert!(matches("!udp.srcport", &tree));
}

#[test]
fn multiple_occurrences_use_any_eq_all_ne_and_all_eq() {
    let tree = packet();
    for (filter, expected) in [
        ("ip.src == 192.0.2.1", true),
        ("ip.src == 10.0.0.1", true),
        ("ip.src == 198.51.100.1", false),
        ("ip.src != 192.0.2.1", false),
        ("ip.src != 198.51.100.1", true),
        ("ip.src all_ne 198.51.100.1", true),
        ("ip.src any_ne 192.0.2.1", true),
        ("ip.src all_ne 192.0.2.1", false),
        ("ip.src === 192.0.2.1", false),
        ("ip.src all_eq 192.0.2.1", false),
        ("ip.src any_eq 10.0.0.1", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let equal = packet_with_repeated_equal_values();
    assert!(matches("ip.src === 192.0.2.1", &equal));
    assert!(!matches("ip.src != 192.0.2.1", &equal));
    assert!(matches("ip.src all_eq 192.0.2.1", &equal));
}

#[test]
fn ordering_comparisons_use_any_occurrence() {
    let tree = packet();
    for (filter, expected) in [
        ("ip.len == 40", true),
        ("ip.len eq 40", true),
        ("ip.len != 40", false),
        ("ip.len ne 40", false),
        ("ip.len > 39", true),
        ("ip.len gt 39", true),
        ("ip.len > 40", false),
        ("ip.len >= 40", true),
        ("ip.len ge 40", true),
        ("ip.len < 41", true),
        ("ip.len lt 41", true),
        ("ip.len <= 40", true),
        ("ip.len le 40", true),
        ("ip.len <= 39", false),
        ("ip.src > 10.0.0.1", true),
        ("ip.src < 10.0.0.1", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn boolean_fields_compare_as_set_and_not_set() {
    let tree = packet();
    for (filter, expected) in [
        ("tcp.flags.syn == true", true),
        ("tcp.flags.syn == TRUE", true),
        ("tcp.flags.syn == 1", true),
        ("tcp.flags.syn == 2", true),
        ("tcp.flags.syn == Set", true),
        ("tcp.flags.syn != false", true),
        ("tcp.flags.ack == false", true),
        ("tcp.flags.ack == 0", true),
        ("tcp.flags.ack == true", false),
        ("tcp.flags.ack == \"not set\"", true),
        ("tcp.flags.syn and tcp.flags.ack", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn string_values_compare_case_sensitively() {
    let tree = packet();
    for (filter, expected) in [
        ("frame.interface_name == \"eth0\"", true),
        ("frame.interface_name == \"ETH0\"", false),
        ("frame.interface_name == eth0", true),
        ("frame.interface_name !== \"ETH0\"", true),
        ("frame.interface_name < \"eth1\"", true),
        ("frame.interface_name > \"eth0\"", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn mac_and_ipv4_literals_accept_supported_forms() {
    let tree = packet();
    for (filter, expected) in [
        ("eth.dst == 00:11:22:33:44:55", true),
        ("eth.dst == 00-11-22-33-44-55", true),
        ("eth.dst == 0:11:22:33:44:55", true),
        ("eth.dst == 0011.2233.4455", true),
        ("eth.dst == 0.11.22.33.44.55", true),
        ("eth.dst == 00:11:22:33:44:56", false),
        ("eth.dst > 00:11:22:33:44:54", true),
        ("eth.dst < 00:11:22:33:44:56", true),
        ("ip.src == 192.0.2.1", true),
        ("ip.src == 192.000.002.001", true),
        ("ip.src == 192.0.2.2", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn ipv6_literals_compare_canonically() {
    let tree = packet_ipv6();
    for (filter, expected) in [
        ("ipv6.src == 2001:db8::1", true),
        ("ipv6.src == 2001:0db8:0000:0000:0000:0000:0000:0001", true),
        ("ipv6.src == 2001:db8::2", false),
        ("ipv6.src > 2001:db8::0", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn byte_literals_compare_as_hex_groups() {
    let tree = packet_bytes();
    for (filter, expected) in [
        ("sll.unused == 00:00", true),
        ("sll.unused == 0:0", true),
        ("sll.unused == 00-00", true),
        ("sll.unused == 00:00:00", false),
        ("sll.unused == 0", false),
        ("sll.unused > 00", true),
        ("sll.unused < 00:00:01", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn absolute_time_literals_compare_and_order() {
    let tree = packet();
    for (filter, expected) in [
        ("frame.time_epoch == 1700000000.123456", true),
        ("frame.time_epoch == 1700000000.123456000", true),
        ("frame.time_epoch == \"1700000000.123456\"", true),
        ("frame.time_epoch == 2023-11-14T22:13:20.123456", true),
        ("frame.time_epoch == \"2023-11-14 22:13:20.123456\"", true),
        ("frame.time_epoch == \"Nov 14, 2023 22:13:20.123456\"", true),
        (
            "frame.time_epoch == \"2023-11-14 22:13:20.123456+00:00\"",
            true,
        ),
        (
            "frame.time_epoch == \"2023-11-14 22:13:20.123456+05:30\"",
            false,
        ),
        ("frame.time_epoch == \"2023-11-14\"", false),
        ("frame.time_epoch > 1700000000", true),
        ("frame.time_epoch < 1700000001", true),
        ("frame.time_epoch != 1700000000.123456", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn operator_precedence_follows_the_grammar() {
    let tree = packet();
    for (filter, expected) in [
        // `and` binds tighter than `or`.
        ("ip or udp and udp", true),
        // `xor` binds tighter than `or`.
        ("ip or udp xor ip", true),
        // `and` binds tighter than `xor`.
        ("ip and udp xor tcp", true),
        ("not (ip and udp)", true),
        ("not ip and udp", false),
        ("not (ip or udp)", false),
        ("not ip or tcp", true),
        ("ip and not udp", true),
        ("ip && tcp", true),
        ("ip || udp", true),
        ("ip ^^ tcp", false),
        ("!ip", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn not_applies_to_a_whole_comparison() {
    let tree = packet();
    assert!(!matches("not ip.len == 40", &tree));
    assert!(!matches("!ip.len == 40", &tree));
    assert!(matches("not ip.len == 41", &tree));
}

#[test]
fn symbol_and_word_operators_agree() {
    let tree = packet();
    for (symbol, word) in [
        ("ip.len == 40", "ip.len eq 40"),
        ("ip.len != 40", "ip.len ne 40"),
        ("ip.len > 39", "ip.len gt 39"),
        ("ip.len < 41", "ip.len lt 41"),
        ("ip.len >= 40", "ip.len ge 40"),
        ("ip.len <= 40", "ip.len le 40"),
        ("ip && tcp", "ip and tcp"),
        ("ip || udp", "ip or udp"),
        ("ip ^^ udp", "ip xor udp"),
        ("!udp", "not udp"),
    ] {
        assert_eq!(matches(symbol, &tree), matches(word, &tree), "{symbol}");
    }
}

#[test]
fn literal_conversion_errors_point_at_the_literal() {
    for (filter, offset) in [
        ("ip.len == \"abc\"", 10),
        ("ip.len == 65536", 10),
        ("ip.len == 1.5", 10),
        ("ip.src == \"192.0.2.1\"", 10),
        ("eth.dst == 00:11:22:33:44", 11),
        ("tcp.flags.syn == yes", 17),
        ("ip.src == 2001:db8::1", 10),
    ] {
        let Some(error) = parse_error(filter) else {
            return;
        };
        assert_eq!(error.offset(), offset, "{filter}: {error}");
    }
}

#[test]
fn label_fields_cannot_be_compared() {
    let Some(error) = parse_error("icmpv6.opt.padding == 1") else {
        return;
    };
    assert_eq!(error.offset(), 0);
    assert_eq!(error.length(), Some("icmpv6.opt.padding".len()));
    assert!(error.message().contains("cannot be compared"), "{error}");
}

#[test]
fn protocols_cannot_be_compared() {
    let Some(error) = parse_error("ip == 1") else {
        return;
    };
    assert_eq!(error.offset(), 6);
    assert!(error.message().contains("protocol"), "{error}");
}

#[test]
fn field_references_compare_every_occurrence() {
    let tree = packet();
    for (filter, expected) in [
        ("ip.src == ip.dst", false),
        ("ip.src != ip.dst", true),
        ("ip.src == ip.src", true),
        ("ip.src === ip.src", false),
        ("ip.src !== ip.src", true),
        ("ip.len == ip.len", true),
        ("ip.len > 1", true),
        ("1 < ip.len", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    assert!(Filter::parse("ip.src == dns.qry.name").is_err());
}

#[test]
fn chained_comparisons_are_conjoined_pairwise() {
    let tree = packet();
    for (filter, expected) in [
        ("ip.len == 40 == ip.len", true),
        ("ip.len == 40 == ip.len", true),
        ("1 < ip.len < 100", true),
        ("1 < ip.len < 40", false),
        ("100 > ip.len > 1", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    assert!(Filter::parse("ip.len == 40 == 40").is_err());
}

#[test]
fn protocol_comparisons_use_node_identity() {
    let tree = packet();
    assert!(matches("ip == ip", &tree));
    assert!(!matches("eth == ip", &tree));
    assert!(matches("eth != ip", &tree));
    assert!(!matches("ip !== ip", &tree));
    assert!(!matches("ip != ip", &tree));
    assert!(!matches("frame == eth", &tree));
}

#[test]
fn slices_select_characters_bytes_and_address_parts() {
    let tree = packet();
    for (filter, expected) in [
        ("eth.src[0:3] == 66:77:88", true),
        ("eth.src[:3] == 66:77:88", true),
        ("eth.src[3:] == 99:aa:bb", true),
        ("eth.src[-1:] == bb", true),
        ("eth.src[-3:] == 99:aa:bb", true),
        ("eth.src[0] == 0x66", true),
        ("eth.src[0:7] == 66:77:88:99:aa:bb:00", false),
        ("eth.src[6:] == \"\"", true),
        ("ip.src[0:2] == c0:00", true),
        ("ip.src[0:1] == 192", true),
        ("ip.src[-1:] == 01", true),
        ("len(eth.src[0:3]) == 3", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    assert!(Filter::parse("eth.src[0:0] == 66").is_err());
    assert!(Filter::parse("eth.src[:-1] == 66").is_err());
    assert!(Filter::parse("ip.len[0:1] == 0").is_err());
    assert!(Filter::parse("frame.time_epoch[0:1] == 0").is_err());
}

#[test]
fn functions_cover_len_count_case_conversions_hex_and_extrema() {
    let tree = packet();
    for (filter, expected) in [
        ("len(eth.src) == 6", true),
        ("len(ip.src) == 4", true),
        ("len(frame.interface_name) == 4", true),
        ("count(ip.src) == 2", true),
        ("count(udp.srcport) == 0", true),
        ("upper(frame.interface_name) == \"ETH0\"", true),
        ("lower(frame.interface_name) == \"eth0\"", true),
        ("string(ip.len) == \"40\"", true),
        ("string(ip.src) == \"192.0.2.1\"", true),
        ("hex(eth.type) == \"0x0800\"", true),
        ("max(ip.src) == 192.0.2.1", true),
        ("min(ip.src) == 10.0.0.1", true),
        ("abs(ip.len - 100) == 60", true),
        ("-ip.len == -40", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    assert!(Filter::parse("len(ip.len) == 1").is_err());
    assert!(Filter::parse("upper(\"abc\") == \"ABC\"").is_err());
    assert!(Filter::parse("string(ip.flags.syn) == \"1\"").is_err());
}

#[test]
fn arithmetic_uses_left_operand_types_and_checked_results() {
    let tree = packet();
    assert!(matches("ip.len + 2 * 3 == 46", &tree));
    assert!(matches("ip.len * 2 + 3 == 83", &tree));
    assert!(matches("ip.len / 3 == 13", &tree));
    assert!(matches("ip.len % 3 == 1", &tree));
    assert!(matches("ip.len & 1 == 0", &tree));
    assert!(matches("ip.len + 1 & 1 == 1", &tree));
    assert!(!matches("ip.len + -1 == 39", &tree));
    assert!(!matches("ip.len / 0 == 0", &tree));
    assert!(!matches("ip.len * 65535 == 0", &tree));
    assert!(!matches("ip.len - 100 == 65496", &tree));
    assert!(matches("ip.len - 100 == -60", &tree));
    assert!(matches("abs(0 - ip.len) == 40", &tree));
    assert!(matches("ip.len + 1", &tree));
    assert!(!matches("ip.len - 40", &tree));
    assert!(matches("ip.len - 39", &tree));
}

#[test]
fn matches_uses_case_insensitive_pcre2_byte_semantics() {
    let mut frame = node("frame");
    let mut dns = node("dns");
    add(
        &mut dns,
        "dns.qry.name",
        Value::String("Example.COM".to_string()),
    );
    add(&mut dns, "dns.qry.name", Value::String("café".to_string()));
    frame.add_child(dns);
    let tree = Tree::new(frame);
    for (filter, expected) in [
        ("dns.qry.name matches \"example.com\"", true),
        ("dns.qry.name ~ \"EXAMPLE\"", true),
        ("dns.qry.name matches \"(?-i)EXAMPLE\"", false),
        ("dns.qry.name matches \"caf.$\"", false),
        ("dns.qry.name matches \"caf.+$\"", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    assert!(Filter::parse("dns.qry.name matches \"(\"").is_err());
    assert!(Filter::parse("dns.qry.name matches \"(?=caf)\"").is_err());
    assert!(Filter::parse("ip.len matches \"1\"").is_err());
}
fn bytes_packet(bytes: Vec<u8>) -> Tree {
    let mut frame = node("frame");
    let mut sll = node("sll");
    add(&mut sll, "sll.unused", Value::bytes(bytes));
    frame.add_child(sll);
    Tree::new(frame)
}

#[test]
fn quoted_escapes_keep_raw_bytes() {
    let raw = bytes_packet(vec![0xbe, 0xef]);
    assert!(matches("sll.unused == \"\\xbe\\xef\"", &raw));
    assert!(matches("sll.unused == be:ef", &raw));
    assert!(!matches("sll.unused == \"\\xbe\"", &raw));

    let controls = bytes_packet(vec![0x07, 0x08, 0x0c, 0x0b]);
    assert!(matches("sll.unused == \"\\a\\b\\f\\v\"", &controls));

    let unicode = bytes_packet(vec![0xc3, 0xa9]);
    assert!(matches("sll.unused == \"\\u00e9\"", &unicode));
}

#[test]
fn byte_literals_accept_hex_groupings() {
    let mut frame = node("frame");
    let mut sll = node("sll");
    add(
        &mut sll,
        "sll.unused",
        Value::bytes(vec![0x1e, 0x04, 0xaa, 0xbb]),
    );
    frame.add_child(sll);
    let tree = Tree::new(frame);
    assert!(matches("sll.unused == 1e04aabb", &tree));
    assert!(matches("sll.unused == 1e:04:aa:bb", &tree));
    assert!(Filter::parse("sll.unused == ffff:ffff").is_ok());
    assert!(Filter::parse("sll.unused == 0x0102").is_err());
}

#[test]
fn quoted_boolean_literals_require_set_and_not_set() {
    let tree = packet();
    assert!(matches("tcp.flags.syn == \"Set\"", &tree));
    assert!(matches("tcp.flags.ack == \"not set\"", &tree));
    for filter in [
        "tcp.flags.syn == \"True\"",
        "tcp.flags.syn == \"False\"",
        "tcp.flags.syn == \"1\"",
        "tcp.flags.syn == \"0\"",
        "tcp.flags.syn == -1",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
    assert!(matches("tcp.flags.syn == true", &tree));
}

#[test]
fn negative_unsigned_literals_are_bounded_by_magnitude() {
    assert!(Filter::parse("ip.len == -65535").is_ok());
    assert!(Filter::parse("ip.len == -65536").is_err());
    assert!(Filter::parse("ip.len == -1").is_ok());
}

#[test]
fn value_string_literals_are_not_supported() {
    let error = parse_error("icmp.type == \"Echo (ping) request\"");
    assert!(error.is_some());
}

#[test]
fn expression_depth_is_bounded() {
    let nested = format!("{}ip", "not ".repeat(127));
    assert!(Filter::parse(&nested).is_ok());
    let nested = format!("{}ip", "not ".repeat(200));
    assert!(Filter::parse(&nested).is_err());
    let flat = format!("{}ip", "ip or ".repeat(200));
    assert!(Filter::parse(&flat).is_err());
}
fn layered_packet() -> Tree {
    let mut frame = node("frame");
    let mut eth = node("eth");
    add(
        &mut eth,
        "eth.dst",
        Value::Ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
    );
    add(
        &mut eth,
        "eth.src",
        Value::Ethernet([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
    );
    add(
        &mut eth,
        "eth.addr",
        Value::Ethernet([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
    );
    add(
        &mut eth,
        "eth.addr",
        Value::Ethernet([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]),
    );
    let mut outer = node("ip");
    add(&mut outer, "ip.src", Value::Ipv4([192, 0, 2, 1]));
    add(&mut outer, "ip.dst", Value::Ipv4([198, 51, 100, 2]));
    add(&mut outer, "ip.len", Value::Uint16(64));
    let mut icmp = node("icmp");
    let mut inner = node("ip");
    add(&mut inner, "ip.src", Value::Ipv4([10, 0, 0, 1]));
    add(&mut inner, "ip.dst", Value::Ipv4([10, 0, 0, 2]));
    icmp.add_child(inner);
    outer.add_child(icmp);
    eth.add_child(outer);
    frame.add_child(eth);
    Tree::new(frame)
}

fn repeated_bytes_packet() -> Tree {
    let mut frame = node("frame");
    let mut sll = node("sll");
    add(&mut sll, "sll.unused", Value::bytes(vec![0, 0]));
    add(&mut sll, "sll.unused", Value::bytes(vec![0x1e, 0x04]));
    frame.add_child(sll);
    Tree::new(frame)
}

#[test]
fn contains_strings_are_case_sensitive_and_empty_is_false() {
    let tree = packet();
    for (filter, expected) in [
        ("frame.interface_name contains \"th\"", true),
        ("frame.interface_name contains \"TH\"", false),
        ("frame.interface_name contains \"eth0\"", true),
        ("frame.interface_name contains \"eth0x\"", false),
        ("frame.interface_name contains \"\"", false),
        ("frame.interface_name contains eth0", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn contains_bytes_and_ethernet_values() {
    let tree = bytes_packet(vec![0x1e, 0x04, 0xaa, 0xbb]);
    for (filter, expected) in [
        ("sll.unused contains 1e:04", true),
        ("sll.unused contains \"\\x1e\\x04\"", true),
        ("sll.unused contains 04:aa", true),
        ("sll.unused contains 05", false),
        ("sll.unused contains \"\"", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let ethernet = packet();
    for (filter, expected) in [
        ("eth.dst contains 00:11", true),
        ("eth.dst contains 11:22", true),
        ("eth.dst contains 00:00", false),
    ] {
        assert_eq!(matches(filter, &ethernet), expected, "{filter}");
    }
}

#[test]
fn contains_uses_any_occurrence() {
    let tree = repeated_bytes_packet();
    assert!(matches("sll.unused contains 1e:04", &tree));
    assert!(matches("sll.unused contains 00:00", &tree));
    assert!(!matches("sll.unused contains 04:1e", &tree));
}

#[test]
fn in_lists_ranges_and_cidr() {
    let tree = packet();
    for (filter, expected) in [
        ("ip.src in {192.0.2.0/24}", true),
        ("ip.src in {10.0.0.0/8}", true),
        ("ip.src in {203.0.113.0/24}", false),
        ("ip.src in {192.0.2.1, 10.0.0.1}", true),
        ("ip.src in {198.51.100.1}", false),
        ("ip.src in {10.0.0.0/8..192.0.2.128/24}", true),
        ("ip.src in {192.0.2.129..192.0.2.255}", false),
        ("frame.number in {1..3}", true),
        ("frame.number in {2..3}", false),
        ("frame.number in {5..1}", false),
        ("frame.number in {0, 1}", true),
        ("frame.number in {1, 3..5}", true),
        ("tcp.flags.syn in {0..1}", true),
        ("tcp.flags.syn in {0}", false),
        ("frame.interface_name in {\"eth0\"..\"eth1\"}", true),
        ("frame.interface_name in {\"eth1\"..\"eth2\"}", false),
        ("frame.interface_name in {eth0}", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let bytes = bytes_packet(vec![0, 0]);
    for (filter, expected) in [
        ("sll.unused in {00:00, 00:01}", true),
        ("sll.unused in {00:01..00:ff}", false),
        ("sll.unused in {00:00..00:00}", true),
        ("eth.dst in {00:11:22:33:44:55}", false),
    ] {
        assert_eq!(matches(filter, &bytes), expected, "{filter}");
    }

    let ethernet = packet();
    assert!(matches("eth.dst in {00:11:22:33:44:55}", &ethernet));
    assert!(!matches("eth.dst in {00:11:22:33:44:56}", &ethernet));

    let ipv6 = packet_ipv6();
    assert!(matches("ipv6.src in {2001:db8::/32}", &ipv6));
    assert!(!matches("ipv6.src in {2001:db9::/32}", &ipv6));
    assert!(matches("ipv6.src in {::1, 2001:db8::/32}", &ipv6));
}

#[test]
fn layer_selector_counts_layers_not_values() {
    let tree = layered_packet();
    for (filter, expected) in [
        ("ip.src#1 == 192.0.2.1", true),
        ("ip.src#2 == 10.0.0.1", true),
        ("ip.src#3 == 10.0.0.1", false),
        ("ip.src#0 == 192.0.2.1", false),
        ("ip#1", true),
        ("ip#2", true),
        ("ip#3", false),
        ("ip.src#2 in {10.0.0.0/8}", true),
        ("ip.src#1 in {10.0.0.0/8}", false),
        ("eth.addr#1", true),
        ("eth.addr#2", false),
        ("eth.addr#1 contains 00:11", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn set_and_contains_syntax_errors_point_at_the_offender() {
    for (filter, offset) in [
        ("frame.number in {}", 17),
        ("frame.number in {1,}", 19),
        ("ip.src in {192.0.2.0/33}", 11),
        ("frame.number in {1..}", 20),
        ("frame.number in {..3}", 17),
        ("frame.number in 1..3", 16),
        ("frame.number contains 1", 0),
        ("ip.src contains 192.0.2", 0),
        ("frame.interface_name contains ip", 30),
        ("ip.src in {192.0.2.0/24, 1}", 25),
        ("eth.dst in {00:11:22:33:44:55/48}", 12),
    ] {
        let Some(error) = parse_error(filter) else {
            return;
        };
        assert_eq!(error.offset(), offset, "{filter}: {error}");
    }
}

#[test]
fn layer_selector_syntax_errors_are_reported() {
    for filter in ["ip.src#", "ip.src##1", "ip#1#2", "ip.src#-1", "#ip"] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
}

#[test]
fn pruning_keeps_filter_fields_and_protocol_nodes() {
    let mut tree = packet();
    let output = field("frame.number");
    let filter_field = field("tcp.flags.syn");
    let selection = FieldSelection::new(&[output, filter_field]);
    tree.prune_keeping(&selection, &ProtocolSelection::default());
    assert!(tree.field_values("ip.src").is_empty());
    assert!(tree.child("eth").is_some());
    assert!(Filter::parse("tcp.flags.syn == 1").is_ok());
    assert!(matches("tcp.flags.syn == 1", &tree));
    assert_eq!(tree.field_values("frame.number").len(), 1);

    let mut protocol_tree = packet();
    let only_output = FieldSelection::new(&[output]);
    let protocols = ProtocolSelection::new(&[protocol("ip")]);
    protocol_tree.prune_keeping(&only_output, &protocols);
    let eth = protocol_tree.child("eth");
    assert!(eth.is_some());
    let Some(eth) = eth else {
        return;
    };
    let ip = eth.child("ip");
    assert!(ip.is_some());
    let Some(ip) = ip else {
        return;
    };
    assert!(ip.fields.is_empty());
    assert!(ip.children.is_empty());
    assert!(matches("ip", &protocol_tree));
    assert!(!matches("tcp", &protocol_tree));
}
#[test]
fn contains_address_needles_follow_the_field_type() {
    let tree = packet();
    for (filter, expected) in [
        ("eth.dst contains 0011.2233.4455", true),
        ("eth.dst contains 0200.0000.0002", false),
        ("eth.dst contains 00:11", true),
        ("eth.dst contains 11:22", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    for filter in [
        "eth.dst contains 0",
        "eth.dst contains 00",
        "eth.dst contains 0x00",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
}

#[test]
fn sixteen_bit_mac_groups_compare_as_six_bytes() {
    let tree = packet();
    for filter in [
        "eth.dst == 0011:2233:4455",
        "eth.dst == 0011-2233-4455",
        "eth.dst in {0011:2233:4455}",
        "eth.dst in {0011-2233-4455}",
    ] {
        assert!(matches(filter, &tree), "{filter}");
    }
}

#[test]
fn string_literals_reject_numbers_operators_and_names() {
    let tree = packet();
    for filter in [
        "frame.interface_name == eth0",
        "frame.interface_name == true",
        "frame.interface_name == Set",
        "frame.interface_name == 1.2.3.4",
    ] {
        assert!(Filter::parse(filter).is_ok(), "{filter}");
    }
    for filter in [
        "frame.interface_name == 123",
        "frame.interface_name == 1e04",
        "frame.interface_name == and",
        "frame.interface_name == ip",
        "frame.interface_name contains 0",
        "frame.interface_name contains and",
        "frame.interface_name in {0}",
        "frame.interface_name in {ip}",
        "frame.interface_name in {and}",
        "frame.interface_name in {1..3}",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
    assert!(matches("frame.interface_name == eth0", &tree));
}

#[test]
fn time_fraction_precision_depends_on_literal_form() {
    let tree = packet();
    assert!(matches("frame.time_epoch == 1700000000.1234560000", &tree));
    assert!(!matches(
        "frame.time_epoch == \"2023-11-14 22:13:20.1234560000\"",
        &tree
    ));
    assert!(!matches(
        "frame.time_epoch == \"2023-11-14 22:13:20.12345678901\"",
        &tree
    ));
    assert!(matches(
        "frame.time_epoch == \"2023-11-14 22:13:20.123456000\"",
        &tree
    ));
    assert!(matches(
        "frame.time_epoch == \"Nov 14, 2023 22:13:20.123456000\"",
        &tree
    ));
    assert!(matches(
        "frame.time_epoch == \"Nov 14, 2023 22:13:20.1234560000\"",
        &tree
    ));
    assert!(Filter::parse("frame.time_epoch == \"Nov 14, 2023 22:13:20.123456789012\"").is_err());
    assert!(Filter::parse("frame.time_epoch == 1700000000.12345678901").is_err());
    assert!(matches("frame.time_epoch == 1700000000.1234560000", &tree));
}

#[test]
fn layer_count_and_cidr_prefixes_are_bounded() {
    assert!(Filter::parse("ip.src#2147483647").is_ok());
    assert!(Filter::parse("ip.src#2147483648").is_err());
    assert!(Filter::parse("ip.src in {192.0.2.0/24}").is_ok());
    assert!(Filter::parse("ip.src in {192.0.2.0/+24}").is_err());
}

#[test]
fn layer_qualified_fields_reference_their_parent_protocol() {
    let Some(filter) = Filter::parse("ip.src#2").ok() else {
        return;
    };
    let (fields, protocols) = filter.references();
    assert!(fields.iter().any(|field| field.abbrev == "ip.src"));
    assert!(
        protocols
            .iter()
            .any(|protocol| protocol.filter_name == "ip")
    );

    let Some(plain) = Filter::parse("ip.src").ok() else {
        return;
    };
    let (_, protocols) = plain.references();
    assert!(protocols.is_empty());
}
fn eui64_packet() -> Tree {
    let mut frame = node("frame");
    let mut icmpv6 = node("icmpv6");
    add(
        &mut icmpv6,
        "icmpv6.opt.src_linkaddr_eui64",
        Value::Eui64([0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]),
    );
    frame.add_child(icmpv6);
    Tree::new(frame)
}

#[test]
fn eui64_literals_accept_integer_dotted_and_grouped_forms() {
    let tree = eui64_packet();
    for (filter, expected) in [
        (
            "icmpv6.opt.src_linkaddr_eui64 == 02.00.00.00.00.01.02.03",
            true,
        ),
        (
            "icmpv6.opt.src_linkaddr_eui64 == 02:00:00:00:00:01:02:03",
            true,
        ),
        (
            "icmpv6.opt.src_linkaddr_eui64 in {02.00.00.00.00.01.02.03}",
            true,
        ),
        ("icmpv6.opt.src_linkaddr_eui64 == 0", false),
        ("icmpv6.opt.src_linkaddr_eui64 == 1", false),
        ("icmpv6.opt.src_linkaddr_eui64 == 0x0102", false),
        (
            "icmpv6.opt.src_linkaddr_eui64 contains 0200.0000.0001",
            true,
        ),
        (
            "icmpv6.opt.src_linkaddr_eui64 contains 02.00.00.00.00.01.02.03",
            true,
        ),
        (
            "icmpv6.opt.src_linkaddr_eui64 contains 0200:0000:0001",
            true,
        ),
        ("icmpv6.opt.src_linkaddr_eui64 contains 0", false),
        ("icmpv6.opt.src_linkaddr_eui64 contains 00", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
    for filter in [
        "icmpv6.opt.src_linkaddr_eui64 == 0200.0000.0001",
        "icmpv6.opt.src_linkaddr_eui64 == 02:00:00:00:00:01",
        "icmpv6.opt.src_linkaddr_eui64 == 18446744073709551616",
        "icmpv6.opt.src_linkaddr_eui64 == -1",
        "icmpv6.opt.src_linkaddr_eui64 == ff",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
}

#[test]
fn invalid_octal_and_leading_zero_exponents_stay_strings() {
    for filter in [
        "frame.interface_name == 08",
        "frame.interface_name == 09",
        "frame.interface_name == 018",
        "frame.interface_name == 09e1",
        "frame.interface_name == 0e1",
        "frame.interface_name == 00e1",
        "frame.interface_name contains 08",
        "frame.interface_name in {018}",
    ] {
        assert!(Filter::parse(filter).is_ok(), "{filter}");
    }
    for filter in [
        "frame.interface_name == 007",
        "frame.interface_name == 08.5",
        "frame.interface_name == 1e04",
        "frame.interface_name == 123",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
}
#[test]
fn address_contains_rejects_quoted_and_overlong_needles() {
    let ethernet = packet();
    for filter in [
        "eth.dst contains \"\"",
        "eth.dst contains \"\\x02\"",
        "eth.dst contains 02:00:00:00:00:02:03",
        "eth.dst contains 0200:0000:0002:0000",
        "eth.dst contains 0200.0000.0002.0000",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
    assert!(matches("eth.dst contains 00:11", &ethernet));

    let eui64 = eui64_packet();
    for filter in [
        "icmpv6.opt.src_linkaddr_eui64 contains \"\"",
        "icmpv6.opt.src_linkaddr_eui64 contains \"\\x02\"",
        "icmpv6.opt.src_linkaddr_eui64 contains 00:00:00:00:00:00:00:00:00",
        "icmpv6.opt.src_linkaddr_eui64 contains 02.00.00.00.00.01.02.03.04",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
    assert!(matches(
        "icmpv6.opt.src_linkaddr_eui64 contains 0200.0000.0001",
        &eui64
    ));
}

#[test]
fn signed_string_tokens_are_rejected_and_0o_stays_a_string() {
    for filter in [
        "frame.interface_name == -08",
        "frame.interface_name == -abc",
        "frame.interface_name contains -abc",
        "frame.interface_name in {-08}",
        "frame.interface_name in {-08..\"eth1\"}",
        "ip.len == 0o10",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
    for filter in [
        "frame.interface_name == 0o10",
        "frame.interface_name contains 0o10",
        "frame.interface_name in {0o10}",
        "frame.interface_name == +08",
    ] {
        assert!(Filter::parse(filter).is_ok(), "{filter}");
    }
}
#[test]
fn unary_plus_is_rejected_with_contains_or_no_operand() {
    for filter in [
        "sll.unused contains +0",
        "frame.interface_name contains +eth0",
        "frame.interface_name contains +0o10",
        "frame.interface_name == +",
        "frame.interface_name in {+}",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
    for filter in [
        "frame.interface_name == +eth0",
        "frame.interface_name in {+eth0}",
        "frame.interface_name == +08",
        "frame.interface_name == +0o10",
    ] {
        assert!(Filter::parse(filter).is_ok(), "{filter}");
    }
}

#[test]
fn arithmetic_chains_resolve_without_exponential_work() {
    use std::time::Instant;
    let tree = packet();
    let mut thirty = String::from("ip.len");
    for _ in 0..29 {
        thirty.push_str(" + 1");
    }
    thirty.push_str(" == 69");
    let start = Instant::now();
    assert!(matches(&thirty, &tree), "30-term chain");
    assert!(
        start.elapsed().as_secs() < 1,
        "30-term chain took {:?}",
        start.elapsed()
    );

    let mut hundred = String::from("ip.len");
    for _ in 0..99 {
        hundred.push_str(" + 1");
    }
    hundred.push_str(" == 139");
    let start = Instant::now();
    assert!(matches(&hundred, &tree), "100-term chain");
    assert!(
        start.elapsed().as_secs() < 1,
        "100-term chain took {:?}",
        start.elapsed()
    );

    let mut capped = String::from("ip.len");
    for _ in 0..127 {
        capped.push_str(" + 1");
    }
    capped.push_str(" == 167");
    let start = Instant::now();
    assert!(
        Filter::parse(&capped).is_err(),
        "128-term chain must hit the cap"
    );
    assert!(
        start.elapsed().as_secs() < 1,
        "capped chain took {:?}",
        start.elapsed()
    );
}

#[test]
fn hostile_deep_chains_return_errors_without_aborting() {
    use std::time::Instant;
    let unary = format!("{}ip.len == 0", "-".repeat(5_000));
    let slices = format!("eth.src{} == 0", "[0:1]".repeat(5_000));
    let comparisons = format!("ip.len{}", " == 1".repeat(5_000));
    let nots = format!("{}ip.len", "not ".repeat(5_000));
    let ands = format!("ip{}", " and ip".repeat(5_000));
    let arithmetic = format!("ip.len{}", " + 1".repeat(5_000));
    let parentheses = format!("{}ip{}", "(".repeat(5_000), ")".repeat(5_000));
    for filter in [
        unary,
        slices,
        comparisons,
        nots,
        ands,
        arithmetic,
        parentheses,
    ] {
        let start = Instant::now();
        assert!(Filter::parse(&filter).is_err());
        assert!(
            start.elapsed().as_secs() < 1,
            "deep chain took {:?}",
            start.elapsed()
        );
    }
}

#[test]
fn protocol_identity_and_ordering() {
    let tree = packet();
    for (filter, expected) in [
        ("eth < ip", true),
        ("eth > ip", false),
        ("eth <= ip", true),
        ("eth >= ip", false),
        ("eth < frame", true),
        ("frame < eth", false),
        ("eth == eth", true),
        ("eth == ip", false),
        ("eth != ip", true),
        ("ip == ip", true),
        ("ip != ip", false),
        ("ip !== ip", false),
        ("ip === ip", true),
        ("ip < ip", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let mut frame = node("frame");
    let mut eth = node("eth");
    let mut ip = node("ip");
    let mut udp = node("udp");
    let mut dns = node("dns");
    add(
        &mut dns,
        "dns.qry.name",
        Value::String("example.com".to_string()),
    );
    udp.add_child(dns);
    ip.add_child(udp);
    eth.add_child(ip);
    frame.add_child(eth);
    let tree = Tree::new(frame);
    for (filter, expected) in [
        ("frame > dns", true),
        ("dns > ip", true),
        ("ip > eth", true),
        ("eth > udp", true),
        ("udp < ip", true),
        ("ip < udp", false),
        ("frame < dns", false),
        ("dns < ip", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let mut frame = node("frame");
    let mut outer = node("ip");
    let mut inner = node("ip");
    add(&mut inner, "ip.src", Value::Ipv4([10, 0, 0, 1]));
    outer.add_child(inner);
    frame.add_child(outer);
    let tree = Tree::new(frame);
    for (filter, expected) in [
        ("ip === ip", false),
        ("ip !== ip", true),
        ("ip == ip", true),
        ("ip != ip", false),
        ("ip < ip", true),
        ("ip > ip", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let mut frame = node("frame");
    let mut eth = node("eth");
    let mut ip = node("ip");
    let mut tcp = node("tcp");
    let mut icmp = node("icmp");
    add(&mut icmp, "icmp.type", Value::Uint8(8));
    add(&mut tcp, "tcp.srcport", Value::Uint16(80));
    add(&mut ip, "ip.src", Value::Ipv4([192, 0, 2, 1]));
    ip.add_child(tcp);
    ip.add_child(icmp);
    eth.add_child(ip);
    frame.add_child(eth);
    let tree = Tree::new(frame);
    for (filter, expected) in [
        ("icmp > tcp", true),
        ("tcp > ip", true),
        ("icmp > ip", true),
        ("icmp < tcp", false),
        ("tcp < ip", false),
        ("icmp < ip", false),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn out_of_range_slices_yield_empty_values() {
    let tree = packet();
    for filter in [
        "ip.src[0:20] == \"\"",
        "ip.src[20:1] == \"\"",
        "ip.src[-20:] == \"\"",
        "eth.src[0:7] == \"\"",
        "eth.src[6:] == \"\"",
    ] {
        assert!(matches(filter, &tree), "{filter}");
    }
    let mut frame = node("frame");
    let mut dns = node("dns");
    add(
        &mut dns,
        "dns.qry.name",
        Value::String("example.com".to_string()),
    );
    frame.add_child(dns);
    let tree = Tree::new(frame);
    for filter in [
        "dns.qry.name[0:20] == \"\"",
        "dns.qry.name[20:1] == \"\"",
        "dns.qry.name[-20:] == \"\"",
    ] {
        assert!(matches(filter, &tree), "{filter}");
    }
}

#[test]
fn byte_slice_truthiness_is_presence_not_nonzero() {
    let mut frame = node("frame");
    let mut sll = node("sll");
    add(&mut sll, "sll.unused", Value::bytes(vec![0, 0]));
    frame.add_child(sll);
    let tree = Tree::new(frame);
    assert!(matches("sll.unused[0:1]", &tree));
    assert!(!matches("!sll.unused[0:1]", &tree));
    assert!(!matches("sll.unused[2:1]", &tree));
    assert!(matches("sll.unused[2:1] == \"\"", &tree));
}

#[test]
fn extension_headers_and_snap_llc_report_header_lengths() {
    let mut frame = node("frame");
    let mut ipv6 = node("ipv6");
    let mut hopopts = node("ipv6.hopopts");
    add(&mut hopopts, "ipv6.hopopts.len", Value::Uint8(0));
    hopopts.range.length = 40;
    ipv6.add_child(hopopts);
    let mut routing = node("ipv6.routing");
    routing.add_field(
        field("ipv6.routing.nxt"),
        Range::new(0, 1),
        Value::Uint8(43),
    );
    routing.add_field(field("ipv6.routing.len"), Range::new(1, 1), Value::Uint8(2));
    routing.add_field(
        field("ipv6.routing.type"),
        Range::new(2, 1),
        Value::Uint8(0),
    );
    routing.range.length = 3;
    ipv6.add_child(routing);
    let mut fraghdr = node("ipv6.fraghdr");
    for (abbrev, offset, length, value) in [
        ("ipv6.fraghdr.nxt", 0_usize, 1_usize, Value::Uint8(59)),
        ("ipv6.fraghdr.reserved_octet", 1, 1, Value::Uint8(0)),
        ("ipv6.fraghdr.offset", 2, 2, Value::Uint16(0)),
        ("ipv6.fraghdr.more", 4, 1, Value::Boolean(false)),
        ("ipv6.fraghdr.ident", 5, 3, Value::Uint32(1)),
    ] {
        fraghdr.add_field(field(abbrev), Range::new(offset, length), value);
    }
    fraghdr.range.length = 8;
    ipv6.add_child(fraghdr);
    frame.add_child(ipv6);
    let mut llc = node("llc");
    add(&mut llc, "llc.oui", Value::Uint24(0));
    frame.add_child(llc);
    let mut partial = node("llc");
    add(&mut partial, "llc.dsap", Value::Uint8(0xaa));
    add(&mut partial, "llc.ssap", Value::Uint8(0xaa));
    frame.add_child(partial);
    let tree = Tree::new(frame);
    for (filter, expected) in [
        ("len(ipv6.hopopts) == 8", true),
        ("len(ipv6.routing) == 3", true),
        ("len(ipv6.routing) == 24", false),
        ("len(ipv6.fraghdr) == 8", true),
        ("len(llc) == 8", true),
        ("len(ipv6) == 59", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }

    let mut frame = node("frame");
    let mut llc = node("llc");
    add(&mut llc, "llc.dsap", Value::Uint8(0x42));
    add(&mut llc, "llc.ssap", Value::Uint8(0x42));
    add(&mut llc, "llc.control", Value::Uint16(3));
    frame.add_child(llc);
    let tree = Tree::new(frame);
    assert!(matches("len(llc) == 3", &tree));
}

#[test]
fn matches_translates_pcre2_escapes_and_byte_patterns() {
    let mut frame = node("frame");
    let mut dns = node("dns");
    add(&mut dns, "dns.qry.name", Value::String("abc\n".to_string()));
    add(&mut dns, "dns.qry.name", Value::String("a b".to_string()));
    add(&mut dns, "dns.qry.name", Value::String("a\nb".to_string()));
    add(&mut dns, "dns.qry.name", Value::String("a.b".to_string()));
    add(&mut dns, "dns.qry.name", Value::String("café".to_string()));
    let mut sll = node("sll");
    add(&mut sll, "sll.unused", Value::bytes(vec![0xff]));
    frame.add_child(dns);
    frame.add_child(sll);
    let tree = Tree::new(frame);
    for (filter, expected) in [
        ("dns.qry.name matches \"abc\\\\Z\"", true),
        ("dns.qry.name matches \"\\\\Gabc\"", true),
        ("dns.qry.name matches \"a\\\\hb\"", true),
        ("dns.qry.name matches \"a\\\\Hb\"", true),
        ("dns.qry.name matches \"a\\\\Nb\"", true),
        ("dns.qry.name matches \"a\\\\Vb\"", true),
        ("dns.qry.name matches \"\\\\Qa.b\\\\E\"", true),
        ("dns.qry.name matches \"abc\\\\E\"", true),
        ("dns.qry.name matches \"caf\\\\xc3\\\\xa9\"", true),
        ("dns.qry.name matches \"café\"", true),
        ("sll.unused matches \"\\\\xFF\"", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn string_ipv6_uses_embedded_ipv4_notation() {
    let mut frame = node("frame");
    let mut ipv6 = node("ipv6");
    for address in [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        add(&mut ipv6, "ipv6.src", Value::Ipv6(address));
    }
    frame.add_child(ipv6);
    let tree = Tree::new(frame);
    for text in [
        "::ffff:0.0.0.0",
        "::ffff:192.0.2.1",
        "::2",
        "::201",
        "::ffff",
        "::192.0.2.2",
        "::1",
    ] {
        assert!(
            matches(&format!("string(ipv6.src) == \"{text}\""), &tree),
            "{text}"
        );
    }
}

#[test]
fn negative_intermediate_arithmetic_keeps_signed_values() {
    let tree = packet();
    for (filter, expected) in [
        ("-ip.len + 1 == -39", true),
        ("0 - ip.len + 1 == -39", true),
        ("-ip.len * 2 == -80", true),
        ("-ip.len / -2 == 20", true),
        ("-ip.len % -3 == -1", true),
        ("-ip.len + -1 == -41", true),
        ("0 - ip.len + -1 == -41", true),
        ("ip.len - 100 + -1 == -61", true),
        ("ip.len + -1 == 39", false),
        ("ip.len - 100 + 100 == 40", true),
        ("abs(ip.len + 100 - 200) == 60", true),
    ] {
        assert_eq!(matches(filter, &tree), expected, "{filter}");
    }
}

#[test]
fn literal_left_signed_right_arithmetic() {
    let tree = packet();
    for filter in [
        "1 + -ip.len == -39",
        "1 - -ip.len == 41",
        "1 * -ip.len == -40",
        "2 + -ip.len == -38",
        "0 + -ip.len == -40",
    ] {
        assert!(!matches(filter, &tree), "{filter}");
    }
    for filter in ["1 / -ip.len == 0", "1 % -ip.len == 1", "1 & -ip.len == 0"] {
        assert!(matches(filter, &tree), "{filter}");
    }
}

#[test]
fn literal_left_uses_the_negated_function_width() {
    for filter in [
        "1 + -max(frame.len) == 70000",
        "1 + -max(frame.len) == 65536",
        "1 + -max(frame.len) == 4294967295",
        "1 + -abs(frame.len) == 65536",
        "1 + -count(ip.src) == 65536",
        "1 + -len(frame.interface_name) == 65536",
        "1 + -len(ip) == 70000",
        "1 + -max(ip.len) == 65535",
    ] {
        assert!(Filter::parse(filter).is_ok(), "{filter}");
    }
    for filter in [
        "1 + -abs(ip.proto) == 256",
        "1 + -max(ip.proto) == 256",
        "1 + -min(ip.ttl) == 256",
        "1 + -max(ip.len) == 65536",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
}

#[test]
fn literal_left_uses_the_negated_field_width() {
    for filter in [
        "1 + -frame.len == 70000",
        "1 + -frame.len == 4000000000",
        "1 + -tcp.seq == 4294967295",
        "1 + -ipv6.flow == 16777215",
        "70000 + -frame.len == 69940",
        "1 + -ip.len == 65535",
    ] {
        assert!(Filter::parse(filter).is_ok(), "{filter}");
    }
    for filter in [
        "1 + -ip.proto == 256",
        "1 + -ip.ttl == 256",
        "1 + -ip.len == 65536",
        "1 + -frame.len == 4294967296",
        "1 + -ipv6.flow == 16777216",
    ] {
        assert!(Filter::parse(filter).is_err(), "{filter}");
    }
}

#[test]
fn layer_qualified_ordering_uses_preorder() {
    let mut frame = node("frame");
    let mut outer = node("ip");
    let mut inner = node("ip");
    add(&mut inner, "ip.src", Value::Ipv4([10, 0, 0, 1]));
    outer.add_child(inner);
    frame.add_child(outer);
    let tree = Tree::new(frame);
    assert!(matches("ip#1 < ip#2", &tree));
    assert!(!matches("ip#1 > ip#2", &tree));
    assert!(!matches("ip#1 == ip#2", &tree));
}

#[test]
fn hostile_regexes_are_bounded() {
    use std::time::Instant;
    let long = format!("dns.qry.name matches \"{}\"", "a".repeat(5_000));
    let start = Instant::now();
    assert!(Filter::parse(&long).is_err());
    assert!(
        start.elapsed().as_secs() < 1,
        "long pattern took {:?}",
        start.elapsed()
    );

    let artifact = "dns.qry.name matches\"(x ei|||p||^B|l.en)atcp.srcport in {30778}^Qor umle^*\"";
    let start = Instant::now();
    let _ = Filter::parse(artifact);
    assert!(
        start.elapsed().as_secs() < 1,
        "artifact took {:?}",
        start.elapsed()
    );

    let start = Instant::now();
    assert!(Filter::parse("dns.qry.name matches \"a{100000}\"").is_err());
    assert!(
        start.elapsed().as_secs() < 1,
        "counted repetition took {:?}",
        start.elapsed()
    );
}
