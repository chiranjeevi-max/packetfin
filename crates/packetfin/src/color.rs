//! Summary and XML colour rules.
//!
//! Packetfin ships a curated rule set for the protocols it decodes. Rules are
//! evaluated in order and the first matching rule wins.
//! A frame that matches nothing is uncoloured. Rules for protocols Packetfin
//! does not decode are intentionally absent, so adding such a decoder should
//! also add its rule here.

use std::sync::LazyLock;

use packetfin_core::{Filter, Tree};

/// One colour rule with its terminal and XML colours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColorRule {
    /// Rule name.
    pub name: &'static str,
    /// Foreground red, green, blue.
    pub foreground: (u8, u8, u8),
    /// Background red, green, blue.
    pub background: (u8, u8, u8),
}

struct CompiledRule {
    rule: ColorRule,
    filter: Filter,
}

static RULES: &[(&str, &str, ColorRule)] = &[
    (
        "ARP",
        "arp",
        ColorRule {
            name: "ARP",
            foreground: (18, 39, 46),
            background: (250, 240, 215),
        },
    ),
    (
        "ICMP errors",
        "icmp.type == 3 || icmp.type == 4 || icmp.type == 5 || icmp.type == 11 || icmp.type == 12",
        ColorRule {
            name: "ICMP errors",
            foreground: (183, 247, 116),
            background: (18, 39, 46),
        },
    ),
    (
        "ICMP",
        "icmp",
        ColorRule {
            name: "ICMP",
            foreground: (18, 39, 46),
            background: (252, 224, 255),
        },
    ),
    (
        "TCP SYN/FIN",
        "tcp.flags.syn == 1 || tcp.flags.fin == 1",
        ColorRule {
            name: "TCP SYN/FIN",
            foreground: (18, 39, 46),
            background: (160, 160, 160),
        },
    ),
    (
        "DNS",
        "dns",
        ColorRule {
            name: "DNS",
            foreground: (18, 39, 46),
            background: (218, 238, 255),
        },
    ),
    (
        "TCP",
        "tcp",
        ColorRule {
            name: "TCP",
            foreground: (18, 39, 46),
            background: (231, 230, 255),
        },
    ),
    (
        "UDP",
        "udp",
        ColorRule {
            name: "UDP",
            foreground: (18, 39, 46),
            background: (218, 238, 255),
        },
    ),
];

static COMPILED: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    RULES
        .iter()
        .filter_map(|(_, expression, rule)| {
            let filter = Filter::parse(expression).ok()?;
            Some(CompiledRule {
                rule: *rule,
                filter,
            })
        })
        .collect()
});

/// The first rule whose filter matches `tree`.
pub fn rule_for(tree: &Tree) -> Option<ColorRule> {
    COMPILED
        .iter()
        .find(|compiled| compiled.filter.matches(tree))
        .map(|compiled| compiled.rule)
}

/// The terminal prefix for one summary line.
pub fn terminal_prefix(rule: &ColorRule) -> String {
    let (foreground_red, foreground_green, foreground_blue) = rule.foreground;
    let (background_red, background_green, background_blue) = rule.background;
    format!(
        "\u{1b}[38;2;{foreground_red};{foreground_green};{foreground_blue}m\
         \u{1b}[48;2;{background_red};{background_green};{background_blue}m"
    )
}

/// The lowercase `#rrggbb` XML form of a colour.
pub fn hex(color: (u8, u8, u8)) -> String {
    let (red, green, blue) = color;
    format!("#{red:02x}{green:02x}{blue:02x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetfin_core::capture::{Frame, Timestamp};
    use packetfin_core::decode::decode_frame;

    fn frame(captured: Vec<u8>) -> Frame {
        Frame {
            number: 1,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            timestamp_precision: 6,
            original_len: captured.len() as u32,
            captured,
            link_type: 1,
            interface_id: 0,
            global_interface: 0,
            timestamp_units: None,
            source_offset: 0,
            interface_name: None,
            section_number: None,
            comments: Vec::new(),
            options: Default::default(),
        }
    }

    fn ethernet_udp() -> Frame {
        let mut bytes = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        bytes.extend_from_slice(&[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
        ]);
        bytes.extend_from_slice(&[0x04, 0xd2, 0x00, 0x50, 0x00, 0x08, 0, 0]);
        frame(bytes)
    }

    fn ethernet_arp() -> Frame {
        let mut bytes = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x06,
        ];
        bytes.extend_from_slice(&[
            0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2,
        ]);
        frame(bytes)
    }

    #[test]
    fn rule_colours_are_preserved() {
        assert_eq!(hex((18, 39, 46)), "#12272e");
        assert_eq!(hex((250, 240, 215)), "#faf0d7");
        let rule = ColorRule {
            name: "test",
            foreground: (1, 2, 3),
            background: (4, 5, 6),
        };
        assert_eq!(
            terminal_prefix(&rule),
            "\u{1b}[38;2;1;2;3m\u{1b}[48;2;4;5;6m"
        );
    }

    #[test]
    fn udp_frames_match_the_udp_rule_and_arp_frames_match_arp() {
        let udp = decode_frame(&ethernet_udp());
        assert_eq!(rule_for(&udp.tree).map(|rule| rule.name), Some("UDP"));

        let arp = decode_frame(&ethernet_arp());
        assert_eq!(rule_for(&arp.tree).map(|rule| rule.name), Some("ARP"));
    }
}
