//! Load and bound checks for the NetFlow v9/IPFIX template cache.
//!
//! These tests build raw Ethernet/IPv4/UDP datagrams and decode them through
//! one [`DecodeSession`]. They assert the template cache stays inside its
//! entry and metadata bounds and that a template flood leaves the session
//! usable; the eprintln lines record wall time.

use std::time::Instant;

use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{DecodeOptions, Packet};
use packetfin_core::{DEFAULT_STATE_BUDGET, DecodeSession};

// The state ledger charges a measured per-entry bookkeeping overhead on top of
// the inline template/sequence values, so 10,000 exporter streams cost more
// than those values alone. Keep a bound far below the global 256 MiB budget
// while covering the bookkeeping.
const TEMPLATE_BUDGET: usize = 32 * 1024 * 1024;

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*chunk)));
    }
    if let [last] = remainder {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([*last, 0])));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let [_, _, high, low] = sum.to_be_bytes();
    !u16::from_be_bytes([high, low])
}

fn frame(number: u64, source: [u8; 4], source_port: u16, payload: &[u8]) -> Frame {
    let mut captured = Vec::with_capacity(42 + payload.len());
    captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    captured.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    captured.extend_from_slice(&0x0800_u16.to_be_bytes());
    let ip_start = captured.len();
    captured.extend_from_slice(&[0x45, 0]);
    let total = u16::try_from(20 + 8 + payload.len()).unwrap_or(u16::MAX);
    captured.extend_from_slice(&total.to_be_bytes());
    captured.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    captured.extend_from_slice(&source);
    captured.extend_from_slice(&[198, 51, 100, 2]);
    let ip_checksum = checksum(captured.get(ip_start..ip_start + 20).unwrap_or(&[]));
    if let Some(bytes) = captured.get_mut(ip_start + 10..ip_start + 12) {
        bytes.copy_from_slice(&ip_checksum.to_be_bytes());
    }
    captured.extend_from_slice(&source_port.to_be_bytes());
    captured.extend_from_slice(&2055_u16.to_be_bytes());
    let udp_length = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    captured.extend_from_slice(&udp_length.to_be_bytes());
    captured.extend_from_slice(&[0, 0]);
    captured.extend_from_slice(payload);
    Frame {
        number,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000 + i64::try_from(number).unwrap_or(i64::MAX),
            nanos: 0,
        }),
        timestamp_precision: 6,
        captured,
        original_len: u32::try_from(42 + payload.len()).unwrap_or(u32::MAX),
        link_type: 1,
        interface_id: 0,
        global_interface: 0,
        interface_name: None,
        timestamp_units: None,
        source_offset: 0,
        section_number: None,
        comments: Vec::new(),
        options: Default::default(),
    }
}

fn v9_message(count: u16, sequence: u32, domain: u32, sets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = 9_u16.to_be_bytes().to_vec();
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&1000_u32.to_be_bytes());
    out.extend_from_slice(&1_700_000_000_u32.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&domain.to_be_bytes());
    for set in sets {
        out.extend_from_slice(set);
    }
    out
}

fn template_set(template_id: u16) -> Vec<u8> {
    let mut body = template_id.to_be_bytes().to_vec();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&8_u16.to_be_bytes());
    body.extend_from_slice(&4_u16.to_be_bytes());
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let mut out = 0_u16.to_be_bytes().to_vec();
    out.extend_from_slice(
        &u16::try_from(4 + body.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(&body);
    out
}

fn data_set(set_id: u16) -> Vec<u8> {
    let mut body = vec![10, 0, 0, 1];
    while body.len() % 4 != 0 {
        body.push(0);
    }
    let mut out = set_id.to_be_bytes().to_vec();
    out.extend_from_slice(
        &u16::try_from(4 + body.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(&body);
    out
}

fn has(packet: &Packet, abbrev: &str) -> bool {
    packet.tree.fields().any(|field| field.def.abbrev == abbrev)
}

#[test]
fn a_template_flood_evicts_old_entries_within_the_metadata_bound() {
    let started = Instant::now();
    let mut session = DecodeSession::new(DecodeOptions::default());
    let mut number = 1_u64;
    let mut next_template = 256_u16;
    // 5000 templates in ten datagrams of 500 sets each.
    for _ in 0..10 {
        let mut sets = Vec::with_capacity(500);
        for _ in 0..500 {
            sets.push(template_set(next_template));
            next_template = next_template.saturating_add(1);
        }
        let message = v9_message(500, 1, 7, &sets);
        let packet = session.decode(&frame(number, [192, 0, 2, 1], 40_000, &message));
        assert!(!packet.malformed);
        number += 1;
        assert!(session.budget_used() <= TEMPLATE_BUDGET);
    }
    let evicted = session.decode(&frame(
        number,
        [192, 0, 2, 1],
        40_000,
        &v9_message(1, 2, 7, &[data_set(256)]),
    ));
    assert!(has(&evicted, "cflow.no_template_found"));
    let newest = u16::try_from(256_u32 + 4999).unwrap_or(u16::MAX);
    let retained = session.decode(&frame(
        number + 1,
        [192, 0, 2, 1],
        40_000,
        &v9_message(1, 3, 7, &[data_set(newest)]),
    ));
    assert!(has(&retained, "cflow.srcaddr"));
    assert!(session.budget_used() <= TEMPLATE_BUDGET);
    eprintln!(
        "template flood: 5000 templates, {} state bytes, {:?}",
        session.budget_used(),
        started.elapsed()
    );
}

#[test]
fn many_exporters_stay_inside_the_global_state_budget() {
    let started = Instant::now();
    let mut session = DecodeSession::new(DecodeOptions::default());
    for index in 0..10_000_u32 {
        let octets = index.to_be_bytes();
        let source = [10, 1, octets[2], octets[3]];
        let message = v9_message(1, 1, 7, &[template_set(256)]);
        let packet = session.decode(&frame(u64::from(index) + 1, source, 40_000, &message));
        assert!(!packet.malformed);
        assert!(session.budget_used() <= DEFAULT_STATE_BUDGET);
    }
    let used = session.budget_used();
    eprintln!(
        "many exporters: 10000 streams, {used} state bytes, {:?}",
        started.elapsed()
    );
    assert!(
        used <= TEMPLATE_BUDGET,
        "template metadata exceeded its bound"
    );
}
