#![no_main]

//! Fuzz the name tables, hosts parser, `-d` and `-o` parsers and the policy
//! state that dispatch consults. The input is arbitrary bytes; every parse is
//! allowed to fail, but none may panic, hang or grow the resolver without
//! bound.

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use packetfin_core::decode::{
    DecodeOptions, Preferences, apply_preference, heuristic, nameres_from_flags, parse_decode_as,
};
use packetfin_core::names::{
    NameResolver, client_hello_sni, mac_organization, mac_short_label, parse_hosts, service_name,
};
use packetfin_core::{NameResPrefs, protocol_by_name};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    let mut preferences = Preferences::default();
    for line in text.lines().take(16) {
        let _ = apply_preference(line, &mut preferences);
    }
    if let Some(flags) = nameres_from_flags(&text) {
        preferences.nameres = flags;
    }

    let mut options = DecodeOptions::default();
    for line in text.lines().skip(16).take(16) {
        let _ = parse_decode_as(line, &mut options.decode_as);
    }
    for word in text
        .split(|character: char| character.is_whitespace() || character == ',' || character == '=')
    {
        if let Some(protocol) = protocol_by_name(word) {
            if word.len() % 2 == 0 {
                options.policy.enable(protocol);
            } else {
                options.policy.disable(protocol);
            }
        }
        if let Some(heuristic) = heuristic(word) {
            if word.len() % 2 == 0 {
                options.policy.enable_heuristic(heuristic);
            } else {
                options.policy.disable_heuristic(heuristic);
            }
        }
    }
    options.policy.finalize();

    let parsed = parse_hosts(Cursor::new(data)).unwrap_or_default();
    let mut resolver = NameResolver::new(
        NameResPrefs {
            network_name: true,
            dns_pkt_addr_resolution: true,
            handshake_sni_addr_resolution: true,
            ..NameResPrefs::default()
        },
        parsed.entries,
    );
    for (index, line) in text.lines().take(64).enumerate() {
        let address = IpAddr::V4(Ipv4Addr::new(
            198,
            51,
            100,
            u8::try_from(index % 250).unwrap_or(0),
        ));
        resolver.learn_dns(address, line);
        resolver.learn_sni(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index as u16)),
            line,
        );
    }
    resolver.add_capture_names(data.chunks(18).take(128).filter_map(|chunk| {
        let address = chunk.first().copied()?;
        let name = String::from_utf8_lossy(chunk.get(1..)?).into_owned();
        Some((IpAddr::V4(Ipv4Addr::new(203, 0, 113, address)), name))
    }));
    let _ = resolver.take_dropped();

    for window in data.windows(6).take(256) {
        let Ok(address) = <[u8; 6]>::try_from(window) else {
            continue;
        };
        let _ = mac_short_label(address);
        let _ = mac_organization(address);
        let _ = resolver.resolved_mac(address);
        let _ = resolver.mac_organization(address);
        let value = u32::from_be_bytes([
            0,
            address.first().copied().unwrap_or(0),
            address.get(1).copied().unwrap_or(0),
            address.get(2).copied().unwrap_or(0),
        ]);
        let lookup = IpAddr::V4(Ipv4Addr::from(value.to_be_bytes()));
        let _ = resolver.host(&lookup);
    }
    for window in data.windows(2).take(256) {
        let port = u16::from_be_bytes([
            window.first().copied().unwrap_or(0),
            window.get(1).copied().unwrap_or(0),
        ]);
        let _ = service_name(port, true);
        let _ = service_name(port, false);
    }
    let _ = client_hello_sni(data);
    let _ = std::hint::black_box(options);
});
