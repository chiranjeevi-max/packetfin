#![no_main]

use libfuzzer_sys::fuzz_target;
use packetfin_core::FieldSelection;
use packetfin_core::capture::{Frame, Timestamp};
use packetfin_core::decode::{
    DecodeOptions, Preferences, ProtocolPolicy, decode_frame, decode_frame_with_options,
    parse_decode_as,
};
use packetfin_core::fields::Protocol;

/// Link types the decoder registers, plus one unknown value.
///
/// Corpus seeds are `[selector] + captured frame`, where `selector` is an
/// index into this array.
const LINK_TYPES: [u32; 7] = [1, 0, 108, 101, 113, 276, 999];

fuzz_target!(|data: &[u8]| {
    // The first byte selects the link type; the rest is the captured frame.
    let (link_type, captured) = match data.split_first() {
        Some((selector, rest)) => (
            LINK_TYPES
                .get(usize::from(*selector) % LINK_TYPES.len())
                .copied()
                .unwrap_or(1),
            rest,
        ),
        None => (1, data),
    };
    let frame = Frame {
        number: 1,
        timestamp: Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 123_456_000,
        }),
        timestamp_precision: 6,
        captured: captured.to_vec(),
        original_len: u32::try_from(captured.len()).unwrap_or(u32::MAX),
        link_type,
        interface_id: 0,
        global_interface: 0,
        timestamp_units: None,
        source_offset: 0,
        interface_name: None,
        section_number: None,
        comments: Vec::new(),
        options: Default::default(),
    };
    let mut packet = decode_frame(&frame);

    let mut rendered = 0_usize;
    for field in packet.tree.fields() {
        rendered =
            rendered.saturating_add(field.value.formatted(field.def.display).to_string().len());
    }

    let all_fields = packetfin_core::fields::registry().fields();
    packet.tree.prune(&FieldSelection::new(all_fields));
    let mut pruned = 0_usize;
    for field in packet.tree.fields() {
        pruned = pruned.saturating_add(field.value.formatted(field.def.display).to_string().len());
    }

    // Exercise the policy, decode-as and name-resolution paths with values
    // derived from the input while keeping the frame bytes unchanged.
    let mut policy = ProtocolPolicy::new();
    policy.disable(Protocol::Dns);
    policy.enable(Protocol::Udp);
    policy.disable_heuristic(
        packetfin_core::decode::heuristic("dns_udp")
            .unwrap_or(&packetfin_core::decode::HEURISTICS[0]),
    );
    policy.finalize();
    let mut options = DecodeOptions {
        preferences: Preferences {
            udp_check_checksum: true,
            tcp_check_checksum: true,
            ..Preferences::default()
        },
        policy,
        ..DecodeOptions::default()
    };
    if let Some(port) = captured.first().copied() {
        let rule = format!("udp.port=={port},data");
        let _ = parse_decode_as(&rule, &mut options.decode_as);
    }
    options.preferences.nameres.network_name = true;
    options.preferences.nameres.handshake_sni_addr_resolution = true;

    let validated = decode_frame_with_options(&frame, options);
    let mut validated_rendered = 0_usize;
    for field in validated.tree.fields() {
        validated_rendered = validated_rendered
            .saturating_add(field.value.formatted(field.def.display).to_string().len());
    }

    let _ = (
        rendered,
        pruned,
        validated_rendered,
        packet.columns,
        packet.malformed,
        packet.protocol_stack,
        packet.network,
        validated.malformed,
        validated.protocol_stack,
        validated.network,
        validated.resolution,
    );
});
