//! Transmission Control Protocol.
//!
//! The decoder builds the TCP header incrementally: both ports must be captured
//! before a TCP node appears, the fixed fields are added as their bytes are
//! present, and a data offset below 20 stops the decode with a protocol
//! expert after the sequence number. Options are parsed inside the declared
//! header length, bounded by the captured bytes; a truncated option keeps the
//! fields decoded so far and stops the option scan.
//!
//! Sequence numbers and window sizes are stateful: the decoder asks the
//! session for the conversation's relative bases, scaled window and analysis
//! result before it writes the fields. Quoted headers still take a stream
//! number but do not seed analysis or reassembly state.
//!
//! Reassembly follows the upper protocol recognised on the transport ports.
//! The completed PDU is decoded with `base = 0` in its own reassembled buffer,
//! by the DNS, TLS, BGP or HTTP decoder.

use crate::decode::bytes::{byte_count_text, read_u16_be, read_u32_be};
use crate::decode::{DecodeContext, LayerType, NetworkContext};
use crate::decode::{bgp, checksum, dns, http, looks_like_http_prefix, tls};
use crate::fields;
use crate::state::{
    ConversationKey, PduAction, TcpAnalysisOptions, TcpObservation, TcpPacketState, TcpSegment, Ulp,
};
use crate::state::{StreamAddress, StreamKey};
use crate::tree::{ExpertInfo, Field, Group, Node, Range, RawField, RawSource, Severity, Value};

const MIN_HEADER_LENGTH: usize = 20;
const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const SEQUENCE_OFFSET: usize = 4;
const ACKNOWLEDGEMENT_OFFSET: usize = 8;
const DATA_OFFSET_OFFSET: usize = 12;
const WINDOW_OFFSET: usize = 14;
const CHECKSUM_OFFSET: usize = 16;
const URGENT_OFFSET: usize = 18;
const OPTIONS_OFFSET: usize = 20;
const HEADER_WITH_FLAGS_LENGTH: usize = 14;

/// Most Info text one frame accumulates from reassembled PDUs.
const MAX_INFO_BYTES: usize = 64 * 1024;

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
fn truncate_utf8(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default()
}

const FLAG_FIN: u16 = 0x001;
const FLAG_SYN: u16 = 0x002;
const FLAG_RST: u16 = 0x004;
const FLAG_PSH: u16 = 0x008;
const FLAG_ACK: u16 = 0x010;
const FLAG_URG: u16 = 0x020;
const FLAG_ECE: u16 = 0x040;
const FLAG_CWR: u16 = 0x080;
const FLAG_AE: u16 = 0x100;
const FLAG_RESERVED: u16 = 0xe00;

const OPTION_EOL: u8 = 0;
const OPTION_NOP: u8 = 1;
const OPTION_MSS: u8 = 2;
const OPTION_WINDOW_SCALE: u8 = 3;
const OPTION_SACK_PERMITTED: u8 = 4;
const OPTION_SACK: u8 = 5;
const OPTION_TIMESTAMPS: u8 = 8;

/// Decode one TCP segment into the parent node.
pub(crate) fn decode(context: &mut DecodeContext<'_>, parent: &mut Node, data: &[u8], base: usize) {
    if data.is_empty() {
        return;
    }
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::TCP_PROTOCOL.filter_name);

    let mut node = Node::new(&fields::TCP_PROTOCOL, Range::new(base, data.len()));
    let (Some(source_port), Some(destination_port)) = (
        read_u16_be(data, SOURCE_PORT_OFFSET),
        read_u16_be(data, DESTINATION_PORT_OFFSET),
    ) else {
        context.mark_malformed(&mut node, "TCP header is shorter than its ports");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    node.add_field(
        &fields::TCP_SRC_PORT,
        Range::new(base + SOURCE_PORT_OFFSET, 2),
        Value::Uint16(source_port),
    );
    node.add_field(
        &fields::TCP_DST_PORT,
        Range::new(base + DESTINATION_PORT_OFFSET, 2),
        Value::Uint16(destination_port),
    );
    node.add_field(
        &fields::TCP_PORT,
        Range::new(base + SOURCE_PORT_OFFSET, 2),
        Value::Uint16(source_port),
    );
    node.add_field(
        &fields::TCP_PORT,
        Range::new(base + DESTINATION_PORT_OFFSET, 2),
        Value::Uint16(destination_port),
    );

    if data.len() < HEADER_WITH_FLAGS_LENGTH {
        context.mark_malformed(&mut node, "TCP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    let Some(sequence) = read_u32_be(data, SEQUENCE_OFFSET) else {
        context.mark_malformed(&mut node, "TCP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let Some(acknowledgement) = read_u32_be(data, ACKNOWLEDGEMENT_OFFSET) else {
        context.mark_malformed(&mut node, "TCP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let Some(offset_byte) = data.get(DATA_OFFSET_OFFSET).copied() else {
        context.mark_malformed(&mut node, "TCP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let Some(flags_word) = read_u16_be(data, DATA_OFFSET_OFFSET) else {
        context.mark_malformed(&mut node, "TCP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    };
    let header_length = usize::from(offset_byte >> 4) * 4;
    let flags = flags_word & 0x0fff;
    let syn = flags & FLAG_SYN != 0;
    let fin = flags & FLAG_FIN != 0;
    let rst = flags & FLAG_RST != 0;
    // The IP layer reports how many transport bytes the frame claims, while a
    // snaplen-truncated capture may hold fewer. `tcp.len` and the
    // sequence-space accounting use the reported length; the captured bytes
    // still feed the protocol decoders and reassembly. The frame remainder
    // keeps a forced TCP decode on a UDP payload from counting the UDP header.
    let reported_transport_length = if context.network.is_some() {
        context
            .reported_length
            .min(context.frame_reported_length.saturating_sub(base))
    } else {
        data.len()
    };
    let reported_segment_length = reported_transport_length.saturating_sub(header_length);
    let segment_length = if data.len() >= header_length {
        Some(reported_segment_length)
    } else {
        None
    };

    let window = read_u16_be(data, WINDOW_OFFSET);
    let option_summary = option_summary(data, header_length);
    let wscale = option_summary.wscale;
    let has_sack = option_summary.sack_blocks > 0;
    let sack_delivered = option_summary.sack_delivered;
    let payload = if header_length >= MIN_HEADER_LENGTH {
        data.get(header_length..).unwrap_or(&[])
    } else {
        &[]
    };
    let detected_ulp = if context.quoted {
        None
    } else {
        ulp_for_ports(source_port, destination_port, payload)
    };
    // Only the client sends the connection preface; once either direction of
    // the conversation has HTTP/2 state, the other direction's frames belong
    // to the same connection (RFC 9113 section 3.4).
    let detected_ulp = if detected_ulp.is_none()
        && !context.quoted
        && !payload.is_empty()
        && let Some((key, _)) = conversation_key(context, source_port, destination_port)
        && context.state.http2_known(key)
    {
        Some(Ulp::Http2)
    } else {
        detected_ulp
    };
    // Turning desegmentation off leaves each segment a PDU on its own: no
    // buffering and no segment data, but a complete fixed header still
    // yields `tcp.pdu.size`.
    let ulp = if context.options.preferences.tcp_desegment_tcp_streams {
        detected_ulp
    } else {
        None
    };
    let analysis_enabled = data.len() >= MIN_HEADER_LENGTH
        && header_length >= MIN_HEADER_LENGTH
        && header_length <= data.len();
    let mut packet_state: Option<TcpPacketState> = None;
    let mut packet_direction: Option<usize> = None;
    if let Some((key, direction)) = conversation_key(context, source_port, destination_port) {
        packet_direction = Some(direction);
        if analysis_enabled {
            let observation = TcpObservation {
                direction,
                sequence,
                acknowledgement,
                window: window.unwrap_or(0),
                payload_len: u32::try_from(segment_length.unwrap_or(0)).unwrap_or(u32::MAX),
                syn,
                ack: flags & FLAG_ACK != 0,
                fin,
                rst,
                psh: flags & FLAG_PSH != 0,
                wscale,
                has_sack,
                sack_delivered,
                frame: context.frame.number,
                timestamp: context.frame.timestamp,
                ulp,
                payload: payload.to_vec(),
            };
            let options = TcpAnalysisOptions {
                analyze: context.options.preferences.tcp_analyze_sequence_numbers,
                relative: context.options.preferences.tcp_relative_sequence_numbers,
                track_bytes_in_flight: context.options.preferences.tcp_track_bytes_in_flight,
                reassemble_out_of_order: context.options.preferences.tcp_reassemble_out_of_order,
                default_window_scaling: context.options.preferences.tcp_default_window_scaling,
                fastrt_supersedes_ooo: context.options.preferences.tcp_fastrt_supersedes_ooo,
            };
            let mut state = context.state.tcp_observe(
                key,
                observation,
                options,
                context.frame.file_number,
                context.quoted,
            );
            if !context.options.preferences.tcp_desegment_tcp_streams {
                state.standalone_pdu_size = context.state.tcp_standalone_pdu(
                    key,
                    direction,
                    sequence,
                    detected_ulp,
                    payload,
                );
            }
            packet_state = Some(state);
        } else {
            let segment = TcpSegment {
                direction,
                sequence,
                acknowledgement,
                syn,
                ack: flags & FLAG_ACK != 0,
                fin,
                rst,
            };
            let stream = context.state.tcp_stream(key, segment, context.quoted);
            let (forward, reverse) = context.state.tcp_relative_bases(key, direction);
            let relative = |value: u32, base: Option<u32>| {
                if context.options.preferences.tcp_analyze_sequence_numbers
                    && context.options.preferences.tcp_relative_sequence_numbers
                    && !context.quoted
                {
                    base.map(|base| value.wrapping_sub(base))
                } else {
                    None
                }
            };
            packet_state = Some(TcpPacketState {
                stream: stream.index,
                packet_number: stream.packet_number,
                relative_seq: relative(sequence, forward),
                relative_ack: relative(acknowledgement, reverse),
                window_size: window.map(u32::from),
                ..TcpPacketState::default()
            });
        }
    }

    if let Some(state) = &packet_state {
        node.add_field(
            &fields::TCP_STREAM,
            Range::new(base, 0),
            Value::Uint32(state.stream),
        );
        node.add_field(
            &fields::TCP_STREAM_PNUM,
            Range::new(base, 0),
            Value::Uint32(state.packet_number),
        );
    }

    if let Some(segment_length) = segment_length {
        node.add_field(
            &fields::TCP_LEN,
            Range::new(0, 0),
            Value::Uint32(u32::try_from(segment_length).unwrap_or(u32::MAX)),
        );
    }
    let displayed_sequence = packet_state
        .as_ref()
        .and_then(|state| state.relative_seq)
        .unwrap_or(sequence);
    let sequence_field = node.add_field(
        &fields::TCP_SEQ,
        Range::new(base + SEQUENCE_OFFSET, 4),
        Value::Uint32(displayed_sequence),
    );
    if packet_state
        .as_ref()
        .is_some_and(|state| state.relative_seq.is_some())
    {
        sequence_field.showname = Some(format!(
            "Sequence Number: {displayed_sequence}    (relative sequence number)"
        ));
    }
    if !context.quoted {
        node.add_field(
            &fields::TCP_SEQ_RAW,
            Range::new(base + SEQUENCE_OFFSET, 4),
            Value::Uint32(sequence),
        );
    }

    if header_length < MIN_HEADER_LENGTH {
        node.add_field(
            &fields::TCP_HDR_LEN,
            Range::new(base + DATA_OFFSET_OFFSET, 1),
            Value::Uint8(u8::try_from(header_length).unwrap_or(u8::MAX)),
        );
        node.add_expert(ExpertInfo {
            severity: Severity::Error,
            group: Group::Protocol,
            message: format!("Bogus TCP header length ({header_length}, must be at least 20)"),
        });
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if segment_length.is_some()
        && let Some(next) = packet_state.as_ref().and_then(|state| state.next_sequence)
    {
        let field = node.add_field(&fields::TCP_NXTSEQ, Range::new(0, 0), Value::Uint32(next));
        if packet_state
            .as_ref()
            .is_some_and(|state| state.relative_seq.is_some())
        {
            field.showname = Some(format!(
                "Next Sequence Number: {next}    (relative sequence number)"
            ));
        }
    }
    let displayed_ack = packet_state
        .as_ref()
        .and_then(|state| state.relative_ack)
        .unwrap_or(acknowledgement);
    let ack_field = node.add_field(
        &fields::TCP_ACK,
        Range::new(base + ACKNOWLEDGEMENT_OFFSET, 4),
        Value::Uint32(displayed_ack),
    );
    if packet_state
        .as_ref()
        .is_some_and(|state| state.relative_ack.is_some())
    {
        ack_field.showname = Some(format!(
            "Acknowledgment Number: {displayed_ack}    (relative ack number)"
        ));
    }
    node.add_field(
        &fields::TCP_ACK_RAW,
        Range::new(base + ACKNOWLEDGEMENT_OFFSET, 4),
        Value::Uint32(acknowledgement),
    );
    node.add_field(
        &fields::TCP_HDR_LEN,
        Range::new(base + DATA_OFFSET_OFFSET, 1),
        Value::Uint8(u8::try_from(header_length).unwrap_or(u8::MAX)),
    );

    let flags_range = Range::new(base + DATA_OFFSET_OFFSET, 2);
    node.add_field(&fields::TCP_FLAGS, flags_range, Value::Uint16(flags));
    node.add_field(
        &fields::TCP_FLAGS_RES,
        flags_range,
        Value::Boolean(flags & FLAG_RESERVED != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_AE,
        flags_range,
        Value::Boolean(flags & FLAG_AE != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_CWR,
        flags_range,
        Value::Boolean(flags & FLAG_CWR != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_ECE,
        flags_range,
        Value::Boolean(flags & FLAG_ECE != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_URG,
        flags_range,
        Value::Boolean(flags & FLAG_URG != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_ACK,
        flags_range,
        Value::Boolean(flags & FLAG_ACK != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_PUSH,
        flags_range,
        Value::Boolean(flags & FLAG_PSH != 0),
    );
    node.add_field(
        &fields::TCP_FLAGS_RESET,
        flags_range,
        Value::Boolean(flags & FLAG_RST != 0),
    );
    let syn_field = node.add_field(&fields::TCP_FLAGS_SYN, flags_range, Value::Boolean(syn));
    if syn {
        let message = if flags & FLAG_ACK != 0 {
            format!("Connection establish acknowledge (SYN+ACK): server port {source_port}")
        } else {
            format!("Connection establish request (SYN): server port {destination_port}")
        };
        syn_field.add_expert(ExpertInfo {
            severity: Severity::Chat,
            group: Group::Sequence,
            message,
        });
    }
    node.add_field(&fields::TCP_FLAGS_FIN, flags_range, Value::Boolean(fin));
    node.add_field(
        &fields::TCP_FLAGS_STR,
        flags_range,
        Value::String(flags_string(flags)),
    );

    if let Some(window) = window {
        node.add_field(
            &fields::TCP_WINDOW_SIZE_VALUE,
            Range::new(base + WINDOW_OFFSET, 2),
            Value::Uint16(window),
        );
        if let Some(state) = &packet_state {
            if let Some(scaled) = state.window_size {
                let field = node.add_field(
                    &fields::TCP_WINDOW_SIZE,
                    Range::new(base + WINDOW_OFFSET, 2),
                    Value::Uint32(scaled),
                );
                field.raw = Some(raw_field(
                    window.to_be_bytes().to_vec(),
                    base + WINDOW_OFFSET,
                    2,
                    7,
                    RawSource::Field,
                ));
            }
            if let Some(factor) = state.scale_factor {
                let field = node.add_field(
                    &fields::TCP_WINDOW_SIZE_SCALEFACTOR,
                    Range::new(base + WINDOW_OFFSET, 2),
                    Value::Int32(factor),
                );
                let text = match factor {
                    -2 => "Window size scaling factor: -2 (no window scaling used)".to_string(),
                    -1 => "Window size scaling factor: -1 (unknown)".to_string(),
                    other => format!("Window size scaling factor: {other}"),
                };
                field.showname = Some(text);
                field.raw = Some(raw_field(
                    window.to_be_bytes().to_vec(),
                    base + WINDOW_OFFSET,
                    2,
                    4,
                    RawSource::Field,
                ));
            }
        }
    }
    if let Some(stored) = read_u16_be(data, CHECKSUM_OFFSET) {
        node.add_field(
            &fields::TCP_CHECKSUM,
            Range::new(base + CHECKSUM_OFFSET, 2),
            Value::Uint16(stored),
        );
        checksum::report(
            &mut node,
            checksum::ChecksumFields {
                status: &fields::TCP_CHECKSUM_STATUS,
                calculated: Some(&fields::TCP_CHECKSUM_CALCULATED),
            },
            Range::new(base + CHECKSUM_OFFSET, 2),
            stored,
            calculated_checksum(context, data, reported_transport_length),
            checksum::ZeroChecksum::Validate,
            Severity::Error,
            false,
        );
    }
    if let Some(urgent) = read_u16_be(data, URGENT_OFFSET) {
        node.add_field(
            &fields::TCP_URGENT_POINTER,
            Range::new(base + URGENT_OFFSET, 2),
            Value::Uint16(urgent),
        );
    }

    if data.len() < MIN_HEADER_LENGTH {
        add_short_segment(&mut node);
        context.mark_malformed(&mut node, "TCP header is truncated");
        parent.add_child(node);
        context.depth = context.depth.saturating_sub(1);
        return;
    }

    if header_length > MIN_HEADER_LENGTH {
        let declared = header_length.saturating_sub(OPTIONS_OFFSET);
        let captured_end = header_length.min(data.len());
        let captured = data.get(OPTIONS_OFFSET..captured_end).unwrap_or(&[]);
        let value = if captured.is_empty() {
            Value::Missing
        } else {
            Value::bytes(captured.to_vec())
        };
        node.add_field(
            &fields::TCP_OPTIONS,
            Range::new(base + OPTIONS_OFFSET, captured.len()),
            value,
        );
        if !captured.is_empty() {
            let relative_sack_base = packet_state.as_ref().and_then(|state| {
                state
                    .relative_ack
                    .map(|relative| acknowledgement.wrapping_sub(relative))
            });
            parse_options(
                context,
                &mut node,
                captured,
                declared,
                base + OPTIONS_OFFSET,
                relative_sack_base,
            );
            if syn {
                if !tcp_has_option(captured, OPTION_MSS) {
                    let field = node.add_field(
                        &fields::TCP_OPTIONS_MSS_ABSENT,
                        Range::new(base + OPTIONS_OFFSET, 0),
                        Value::None,
                    );
                    field.showname =
                        Some("The SYN packet does not contain a MSS option".to_string());
                    field.add_expert(ExpertInfo {
                        severity: Severity::Note,
                        group: Group::Protocol,
                        message: "The SYN packet does not contain a MSS option".to_string(),
                    });
                }
                if !tcp_has_option(captured, OPTION_SACK_PERMITTED) {
                    let field = node.add_field(
                        &fields::TCP_OPTIONS_SACK_PERM_ABSENT,
                        Range::new(base + OPTIONS_OFFSET, 0),
                        Value::None,
                    );
                    field.showname =
                        Some("The SYN packet does not contain a SACK PERM option".to_string());
                    field.add_expert(ExpertInfo {
                        severity: Severity::Note,
                        group: Group::Protocol,
                        message: "The SYN packet does not contain a SACK PERM option".to_string(),
                    });
                }
            }
        }
    }

    if header_length > data.len() {
        add_short_segment(&mut node);
        context.mark_malformed(&mut node, "TCP header is truncated");
    }

    if let Some(state) = &packet_state
        && context.options.preferences.tcp_calculate_timestamps
        && (state.time_relative_ns.is_some() || state.time_delta_ns.is_some())
    {
        let container = node.add_container(
            &fields::TCP_TIMESTAMPS,
            Range::new(base, 0),
            Some("Timestamps".to_string()),
        );
        container.raw = Some(raw_field(Vec::new(), base, 0, 0, RawSource::Field));
        if let Some(nanos) = state.time_relative_ns {
            let field = container.add_field(
                &fields::TCP_TIME_RELATIVE,
                Range::new(base, 0),
                Value::Uint64(nanos),
            );
            field.raw = Some(raw_field(Vec::new(), base, 0, 25, RawSource::Field));
        }
        if let Some(nanos) = state.time_delta_ns {
            let field = container.add_field(
                &fields::TCP_TIME_DELTA,
                Range::new(base, 0),
                Value::Uint64(nanos),
            );
            field.raw = Some(raw_field(Vec::new(), base, 0, 25, RawSource::Field));
        }
    }
    if let Some(state) = &packet_state {
        add_analysis_fields(&mut node, base, state);
    }

    let forced_tcp = context
        .options
        .decode_as
        .lookup(
            LayerType::TcpPort,
            &[u32::from(source_port), u32::from(destination_port)],
        )
        .is_some();
    if let Some(payload) = data.get(header_length..)
        && !payload.is_empty()
        && !rst
    {
        let field = node.add_field(
            &fields::TCP_PAYLOAD,
            Range::new(base + header_length, payload.len()),
            Value::bytes(payload.to_vec()),
        );
        field.showname = Some(format!("TCP payload ({})", byte_count_text(payload.len())));
        if !context.quoted
            && !forced_tcp
            && let Some(server_name) = crate::names::client_hello_sni(payload)
            && let Some(network) = context.network.as_ref()
        {
            context
                .names
                .learn_sni(network.destination_ip(), server_name);
        }
    }

    if detected_ulp.is_none()
        && context.options.preferences.tcp_desegment_tcp_streams
        && !payload.is_empty()
        && !rst
        && let Some(state) = &packet_state
        && !state.ulp_known
        && state.analysis.flags.retransmission
    {
        // A retransmission in a direction that never recognised an upper
        // protocol is still reported as TCP segment data.
        let offset = base + header_length;
        let field = node.add_field(
            &fields::TCP_SEGMENT_DATA,
            Range::new(offset, payload.len()),
            Value::bytes(payload.to_vec()),
        );
        field.showname = Some(format!("TCP segment data ({} bytes)", payload.len()));
        field.raw = Some(raw_field(
            payload.to_vec(),
            offset,
            payload.len(),
            30,
            RawSource::Field,
        ));
    }
    if let Some(state) = &packet_state {
        let assignment = crate::state::StreamAssignment {
            index: state.stream,
            packet_number: state.packet_number,
        };
        let saved_ports = context.transport_ports;
        let saved_stream = context.tcp_stream;
        let saved_sequence = context.tcp_sequence;
        context.transport_ports = Some((source_port, destination_port));
        context.tcp_stream = Some(assignment);
        context.tcp_sequence = Some(sequence);
        if !context.quoted
            && analysis_enabled
            && let Some(direction) = packet_direction
            && let Some(key) = stream_key(context, state.stream, source_port, destination_port)
        {
            context.observer.tcp_payload(
                key,
                u8::try_from(direction).unwrap_or(1),
                sequence.wrapping_add(u32::from(syn)),
                acknowledgement,
                payload,
            );
        }
        // A forced decode-as replaces the port table and the stream framing,
        // so the bytes go to the selected decoder directly.
        if !forced_tcp {
            add_reassembly_fields(
                context,
                &mut node,
                base,
                base + header_length,
                payload,
                state,
            );
        }
        if fin
            && !rst
            && !context.quoted
            && context.options.preferences.tcp_desegment_tcp_streams
            && let Some((key, direction)) = conversation_key(context, source_port, destination_port)
            && let Some(info) =
                crate::decode::tls::finish_plaintext(context, &mut node, key, direction)
        {
            context.columns.info = Some(info);
        }
        context.transport_ports = saved_ports;
        context.tcp_stream = saved_stream;
        context.tcp_sequence = saved_sequence;
        // Desegmentation off leaves each segment a PDU on its own, a quoted
        // header never seeds stream state, and a forced decode-as bypasses
        // the stream buffer; all three decode the bytes directly.
        if forced_tcp || context.quoted || !context.options.preferences.tcp_desegment_tcp_streams {
            crate::decode::dispatch_tcp_payload(
                context,
                &mut node,
                (source_port, destination_port),
                Some(assignment),
                Some(sequence),
                payload,
                base + header_length,
            );
        }
        if detected_ulp == Some(Ulp::Http)
            && (context.quoted || !context.options.preferences.tcp_desegment_tcp_streams)
        {
            notify_http(context, state.stream, payload);
        }
    }
    parent.add_child(node);
    context.depth = context.depth.saturating_sub(1);
}

/// Forward one complete HTTP message to the follow observer.
fn notify_http_pdu(context: &mut DecodeContext<'_>, message: &[u8]) {
    let Some(index) = context.tcp_stream.map(|assignment| assignment.index) else {
        return;
    };
    notify_http(context, index, message);
}

fn notify_http(context: &mut DecodeContext<'_>, index: u32, message: &[u8]) {
    let Some((source_port, destination_port)) = context.transport_ports else {
        return;
    };
    let Some(key) = stream_key(context, index, source_port, destination_port) else {
        return;
    };
    let Some((_, direction)) = conversation_key(context, source_port, destination_port) else {
        return;
    };
    context
        .observer
        .http_message(key, u8::try_from(direction).unwrap_or(1), message);
}

/// The follow-visible key for a transport segment.
fn stream_key(
    context: &DecodeContext<'_>,
    index: u32,
    source_port: u16,
    destination_port: u16,
) -> Option<StreamKey> {
    let (source, destination) = match context.network.as_ref()? {
        NetworkContext::Ipv4 {
            source,
            destination,
            ..
        } => (
            StreamAddress::Ipv4(*source),
            StreamAddress::Ipv4(*destination),
        ),
        NetworkContext::Ipv6 {
            source,
            destination,
            ..
        } => (
            StreamAddress::Ipv6(*source),
            StreamAddress::Ipv6(*destination),
        ),
    };
    Some(StreamKey {
        index,
        source,
        source_port,
        destination,
        destination_port,
    })
}

/// Add the warning for a capture that does not hold a full fixed header.
fn add_short_segment(node: &mut Node) {
    node.add_expert(ExpertInfo {
        severity: Severity::Warning,
        group: Group::Malformed,
        message: "Short segment. Segment/fragment does not contain a full TCP header (might be NMAP or someone else deliberately sending unusual packets)".to_string(),
    });
}

/// The TCP option facts analysis needs before the option fields are built.
#[derive(Clone, Copy, Debug, Default)]
struct OptionSummary {
    /// Valid window-scale shift from a SYN or SYN+ACK.
    wscale: Option<u8>,
    /// Number of complete SACK blocks.
    sack_blocks: u8,
    /// Bytes covered by those SACK blocks.
    sack_delivered: u32,
}

/// Scan the option area for the window scale and SACK facts.
fn option_summary(data: &[u8], header_length: usize) -> OptionSummary {
    let mut summary = OptionSummary::default();
    if header_length <= OPTIONS_OFFSET {
        return summary;
    }
    let captured_end = header_length.min(data.len());
    let options = data.get(OPTIONS_OFFSET..captured_end).unwrap_or(&[]);
    let mut offset = 0_usize;
    while offset < options.len() {
        let Some(&kind) = options.get(offset) else {
            break;
        };
        if kind == OPTION_EOL {
            break;
        }
        if kind == OPTION_NOP {
            offset = offset.saturating_add(1);
            continue;
        }
        let Some(&length_byte) = options.get(offset.saturating_add(1)) else {
            break;
        };
        let length = usize::from(length_byte);
        if length < 2 || offset.saturating_add(length) > options.len() {
            break;
        }
        if kind == OPTION_WINDOW_SCALE && length == 3 {
            summary.wscale = options.get(offset.saturating_add(2)).copied();
        }
        if kind == OPTION_SACK && length >= 10 {
            let blocks = u8::try_from((length - 2) / 8).unwrap_or(u8::MAX);
            summary.sack_blocks = summary.sack_blocks.saturating_add(blocks);
            let mut block_offset = 0_usize;
            while block_offset.saturating_add(8) <= length - 2 {
                let left = options.get(offset + 2 + block_offset..offset + 6 + block_offset);
                let right = options.get(offset + 6 + block_offset..offset + 10 + block_offset);
                if let (Some(left), Some(right)) = (left, right)
                    && let (Ok(left), Ok(right)) =
                        (<[u8; 4]>::try_from(left), <[u8; 4]>::try_from(right))
                {
                    let left = u32::from_be_bytes(left);
                    let right = u32::from_be_bytes(right);
                    summary.sack_delivered = summary
                        .sack_delivered
                        .saturating_add(right.saturating_sub(left));
                }
                block_offset = block_offset.saturating_add(8);
            }
        }
        offset = offset.saturating_add(length);
    }
    summary
}

/// Recognise the upper protocol whose data the stream carries.
///
/// The port decoders are tried in the registry priority order and a decoder
/// that rejects the bytes leaves the payload to the HTTP heuristic, which
/// applies on every port. A split BGP message whose first segment lacks the
/// sixteen-octet marker is not BGP.
fn ulp_for_ports(source: u16, destination: u16, payload: &[u8]) -> Option<Ulp> {
    if payload.is_empty() {
        return None;
    }
    let ports = [source, destination];
    // TCP_PORT_DECODERS order: DNS 53, BGP 179, TLS ports, DNS 5353.
    const PRIORITY: [u16; 12] = [
        53, 179, 443, 465, 636, 993, 995, 5061, 8443, 9443, 5353, 5986,
    ];
    for port in PRIORITY {
        if !ports.contains(&port) {
            continue;
        }
        match port {
            53 | 5353 => return Some(Ulp::Dns),
            179 => {
                if payload.len() >= 16 && payload.iter().take(16).all(|byte| *byte == 0xff) {
                    return Some(Ulp::Bgp);
                }
                break;
            }
            _ => {
                let content_type = payload.first().copied().unwrap_or(0);
                if matches!(content_type, 20..=24) {
                    return Some(Ulp::Tls);
                }
                break;
            }
        }
    }
    if http_port(ports) && http_prefix(payload) {
        return Some(Ulp::Http);
    }
    // The connection preface is the only cleartext HTTP/2 heuristic: a frame
    // shape alone is not enough, because every frame type shares the same
    // nine-octet header (RFC 9113 section 4.1).
    if crate::decode::http2::looks_like_http2_prefix(payload) {
        return Some(Ulp::Http2);
    }
    looks_like_http_prefix(payload).then_some(Ulp::Http)
}

/// Whether a payload starts like an HTTP/1.x message before the version token
/// has arrived.
///
/// Port-registered HTTP claims a request or status line prefix, so a request
/// split in the middle of its version still reassembles; the heuristic on
/// other ports waits for the version token.
fn http_prefix(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
        b"PATCH ",
    ];
    if payload.starts_with(b"HTTP/1.")
        || b"HTTP/1.1".starts_with(payload)
        || b"HTTP/1.0".starts_with(payload)
    {
        return true;
    }
    METHODS.iter().any(|method| {
        let length = payload.len().min(method.len());
        payload.get(..length) == method.get(..length)
    })
}

/// Whether either port is registered for HTTP.
fn http_port(ports: [u16; 2]) -> bool {
    ports
        .iter()
        .any(|port| matches!(port, 80 | 3128 | 3132 | 5985 | 8080 | 8088 | 11371))
}
fn raw_field(
    bytes: impl Into<crate::tree::Bytes>,
    start: usize,
    length: usize,
    field_type: u32,
    source: RawSource,
) -> RawField {
    RawField {
        bytes: bytes.into(),
        start,
        length,
        bitmask: 0,
        field_type,
        source,
    }
}

/// Add the `tcp.analysis` tree in the field order of the expected output.
fn add_analysis_fields(node: &mut Node, base: usize, state: &TcpPacketState) {
    let analysis = &state.analysis;
    let flags = analysis.flags;
    let has_analysis = analysis.acks_frame.is_some()
        || analysis.ack_rtt_ns.is_some()
        || analysis.initial_rtt_ns.is_some()
        || analysis.bytes_in_flight.is_some()
        || analysis.push_bytes_sent.is_some()
        || analysis.duplicate.is_some()
        || analysis.rto_ns.is_some()
        || flags.any();
    if !has_analysis {
        return;
    }
    let container = node.add_container(
        &fields::TCP_ANALYSIS,
        Range::new(base, 0),
        Some("SEQ/ACK analysis".to_string()),
    );
    container.raw = Some(raw_field(Vec::new(), base, 0, 0, RawSource::Field));
    if let Some(frame) = analysis.acks_frame {
        let field = container.add_field(
            &fields::TCP_ANALYSIS_ACKS_FRAME,
            Range::new(base, 0),
            Value::Uint32(u32::try_from(frame).unwrap_or(u32::MAX)),
        );
        field.raw = Some(raw_field(Vec::new(), base, 0, 35, RawSource::Field));
    }
    if let Some(nanos) = analysis.ack_rtt_ns {
        let field = container.add_field(
            &fields::TCP_ANALYSIS_ACK_RTT,
            Range::new(base, 0),
            Value::Uint64(nanos),
        );
        field.raw = Some(raw_field(Vec::new(), base, 0, 25, RawSource::Field));
    }
    if let Some(nanos) = analysis.initial_rtt_ns {
        let field = container.add_field(
            &fields::TCP_ANALYSIS_INITIAL_RTT,
            Range::new(base, 0),
            Value::Uint64(nanos),
        );
        field.raw = Some(raw_field(Vec::new(), base, 0, 25, RawSource::Field));
    }
    if let Some(bytes) = analysis.bytes_in_flight {
        let field = container.add_field(
            &fields::TCP_ANALYSIS_BYTES_IN_FLIGHT,
            Range::new(base, 0),
            Value::Uint32(bytes),
        );
        field.raw = Some(raw_field(Vec::new(), base, 0, 7, RawSource::Field));
    }
    if let Some(bytes) = analysis.push_bytes_sent {
        let field = container.add_field(
            &fields::TCP_ANALYSIS_PUSH_BYTES_SENT,
            Range::new(base, 0),
            Value::Uint32(bytes),
        );
        field.raw = Some(raw_field(Vec::new(), base, 0, 7, RawSource::Field));
    }
    if flags.any() || analysis.duplicate.is_some() || analysis.rto_ns.is_some() {
        let flags_container = container.add_container(
            &fields::TCP_ANALYSIS_FLAGS,
            Range::new(base, 0),
            Some("TCP Analysis Flags".to_string()),
        );
        flags_container.raw = Some(raw_field(Vec::new(), base, 0, 0, RawSource::Field));
        let add_flag = |node: &mut crate::tree::Field, def, message: &str, severity| {
            let field = node.add_field(def, Range::new(base, 0), Value::None);
            field.raw = Some(raw_field(Vec::new(), base, 0, 0, RawSource::Field));
            field.add_expert(ExpertInfo {
                severity,
                group: Group::Sequence,
                message: message.to_string(),
            });
        };
        if flags.spurious_retransmission {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_SPURIOUS_RETRANSMISSION,
                "This frame is a (suspected) spurious retransmission",
                Severity::Note,
            );
        }
        if flags.fast_retransmission {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_FAST_RETRANSMISSION,
                "This frame is a (suspected) fast retransmission",
                Severity::Note,
            );
        }
        if flags.out_of_order {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_OUT_OF_ORDER,
                "This frame is a (suspected) out-of-order segment",
                Severity::Warning,
            );
        }
        if flags.retransmission {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_RETRANSMISSION,
                "This frame is a (suspected) retransmission",
                Severity::Note,
            );
        }
        if flags.keep_alive {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_KEEP_ALIVE,
                "TCP keep-alive segment",
                Severity::Note,
            );
        }
        if flags.keep_alive_ack {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_KEEP_ALIVE_ACK,
                "ACK to a TCP keep-alive segment",
                Severity::Note,
            );
        }
        if flags.lost_segment {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_LOST_SEGMENT,
                "Previous segment(s) not captured (common at capture start)",
                Severity::Warning,
            );
        }
        if flags.ack_lost_segment {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_ACK_LOST_SEGMENT,
                "ACKed segment that wasn't captured (common at capture start)",
                Severity::Warning,
            );
        }
        if flags.zero_window_probe {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_ZERO_WINDOW_PROBE,
                "TCP Zero Window Probe",
                Severity::Note,
            );
        }
        if flags.zero_window {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_ZERO_WINDOW,
                "TCP Zero Window segment",
                Severity::Warning,
            );
        }
        if flags.zero_window_probe_ack {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_ZERO_WINDOW_PROBE_ACK,
                "ACK to a TCP Zero Window Probe",
                Severity::Note,
            );
        }
        if flags.window_update {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_WINDOW_UPDATE,
                "TCP window update",
                Severity::Chat,
            );
        }
        if flags.reused_ports {
            add_flag(
                flags_container,
                &fields::TCP_ANALYSIS_REUSED_PORTS,
                "A new tcp session is started with the same ports as an earlier session in this trace",
                Severity::Note,
            );
        }
        if analysis.duplicate.is_some() {
            let field = flags_container.add_field(
                &fields::TCP_ANALYSIS_DUPLICATE_ACK,
                Range::new(base, 0),
                Value::None,
            );
            field.showname = Some("This is a TCP duplicate ack".to_string());
            field.raw = Some(raw_field(Vec::new(), base, 0, 0, RawSource::Field));
        }
        if let Some(nanos) = analysis.rto_ns {
            let field = flags_container.add_field(
                &fields::TCP_ANALYSIS_RTO,
                Range::new(base, 0),
                Value::Uint64(nanos),
            );
            field.raw = Some(raw_field(Vec::new(), base, 0, 25, RawSource::Field));
        }
        if let Some(frame) = analysis.rto_frame {
            let field = flags_container.add_field(
                &fields::TCP_ANALYSIS_RTO_FRAME,
                Range::new(base, 0),
                Value::Uint32(u32::try_from(frame).unwrap_or(u32::MAX)),
            );
            field.raw = Some(raw_field(Vec::new(), base, 0, 35, RawSource::Field));
        }
    }
    if let Some((number, frame)) = analysis.duplicate {
        let field = container.add_field(
            &fields::TCP_ANALYSIS_DUPLICATE_ACK_NUM,
            Range::new(base, 0),
            Value::Uint32(number),
        );
        field.raw = Some(raw_field(Vec::new(), base, 0, 7, RawSource::Field));
        let frame_field = container.add_field(
            &fields::TCP_ANALYSIS_DUPLICATE_ACK_FRAME,
            Range::new(base, 0),
            Value::Uint32(u32::try_from(frame).unwrap_or(u32::MAX)),
        );
        frame_field.raw = Some(raw_field(Vec::new(), base, 0, 35, RawSource::Field));
        let flag = frame_field.add_field(
            &fields::TCP_ANALYSIS_DUPLICATE_ACK,
            Range::new(base, 0),
            Value::None,
        );
        flag.showname = Some(format!("Duplicate ACK (#{number})"));
        flag.raw = Some(raw_field(Vec::new(), 0, 0, 0, RawSource::None));
        flag.add_expert(ExpertInfo {
            severity: Severity::Note,
            group: Group::Sequence,
            message: format!("Duplicate ACK (#{number})"),
        });
    }
}

/// Add `tcp.pdu.size`, `tcp.segment_data` and the `tcp.segments` container.
///
/// One segment can touch several PDUs: the tail of a reassembled message,
/// complete messages that fit the segment, and the head of the next message.
/// The PDU size and segment data come first for each touched PDU in wire
/// order, then the reassembled containers, then the upper-layer nodes.
fn add_reassembly_fields(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    base: usize,
    payload_offset: usize,
    payload: &[u8],
    state: &TcpPacketState,
) {
    let report = &state.reassembly;
    if let Some(limit) = report.oversized {
        node.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Sequence,
            message: format!("TCP PDU exceeds the {limit} reassembly limit"),
        });
    }
    if report.limit_reached {
        node.add_expert(ExpertInfo {
            severity: Severity::Warning,
            group: Group::Sequence,
            message: "TCP PDU count limit reached; excess messages dropped".to_string(),
        });
    }
    if let Some(message) = report.malformed {
        context.mark_malformed(node, message);
    }
    let has_reassembled = report
        .actions
        .iter()
        .any(|action| matches!(action, PduAction::Reassembled { .. }));
    if report.error
        && !has_reassembled
        && let Some(frame) = report.error_frame
    {
        let container = node.add_container(
            &fields::TCP_SEGMENTS,
            Range::new(base, 0),
            Some("Reassembled TCP Segments".to_string()),
        );
        container.raw = Some(raw_field(Vec::new(), 0, 0, 0, RawSource::Frame));
        add_segment_error(container, base, frame);
    }
    if let Some(size) = state.standalone_pdu_size {
        let length = usize::try_from(size).unwrap_or(0).min(payload.len());
        let bytes = payload.get(..length).unwrap_or_default().to_vec();
        let field = node.add_field(
            &fields::TCP_PDU_SIZE,
            Range::new(payload_offset, bytes.len()),
            Value::Uint32(size),
        );
        field.raw = Some(raw_field(
            bytes,
            payload_offset,
            length,
            7,
            RawSource::Frame,
        ));
    }
    for action in &report.actions {
        match action {
            PduAction::Standalone {
                data,
                offset,
                pdu_size,
                ..
            } => {
                if let Some(size) = pdu_size {
                    let field = node.add_field(
                        &fields::TCP_PDU_SIZE,
                        Range::new(payload_offset.saturating_add(*offset), data.len()),
                        Value::Uint32(*size),
                    );
                    field.raw = Some(raw_field(
                        data.clone(),
                        payload_offset.saturating_add(*offset),
                        data.len(),
                        7,
                        RawSource::Frame,
                    ));
                }
            }
            PduAction::Reassembled {
                pdu,
                segment_data,
                pdu_size,
                ..
            } => {
                if let Some(size) = pdu_size {
                    let field = node.add_field(
                        &fields::TCP_PDU_SIZE,
                        Range::new(base, pdu.data.len()),
                        Value::Uint32(*size),
                    );
                    field.raw = Some(raw_field(
                        pdu.data.clone(),
                        base,
                        pdu.data.len(),
                        7,
                        RawSource::Frame,
                    ));
                }
                add_segment_data(node, payload_offset, segment_data);
            }
            PduAction::Partial { segment_data, .. } | PduAction::SegmentData { segment_data } => {
                add_segment_data(node, payload_offset, segment_data);
            }
        }
    }
    for action in &report.actions {
        if let PduAction::Reassembled { pdu, .. } = action {
            if context.pass == crate::state::PassMode::First {
                let completing = context.frame.file_number;
                for segment in &pdu.segments {
                    if segment.file != completing {
                        context
                            .state
                            .annotations_mut()
                            .link_tcp_reassembled(segment.file, completing);
                    }
                }
            }
            add_reassembled_container(node, pdu);
        }
    }
    decode_stream_pdus(context, node, payload_offset, payload, report);
}

/// Add one `tcp.segment_data` field.
fn add_segment_data(
    node: &mut Node,
    payload_offset: usize,
    piece: &crate::state::SegmentDataPiece,
) {
    if piece.bytes.is_empty() {
        return;
    }
    let offset = payload_offset.saturating_add(piece.offset);
    let field = node.add_field(
        &fields::TCP_SEGMENT_DATA,
        Range::new(offset, piece.bytes.len()),
        Value::bytes(piece.bytes.clone()),
    );
    field.showname = Some(if piece.retransmitted {
        format!(
            "Retransmitted TCP segment data ({} bytes)",
            piece.bytes.len()
        )
    } else {
        format!("TCP segment data ({} bytes)", piece.bytes.len())
    });
    field.raw = Some(raw_field(
        piece.bytes.clone(),
        offset,
        piece.bytes.len(),
        30,
        RawSource::Field,
    ));
}

/// Add the `tcp.segment.error` frame reference.
fn add_segment_error(container: &mut crate::tree::Field, base: usize, frame: u64) {
    let field = container.add_field(
        &fields::TCP_SEGMENT_ERROR,
        Range::new(base, 0),
        Value::Uint32(u32::try_from(frame).unwrap_or(u32::MAX)),
    );
    field.raw = Some(raw_field(Vec::new(), base, 0, 35, RawSource::Frame));
}

/// Add the `tcp.segments` container for one reassembled PDU.
fn add_reassembled_container(node: &mut Node, pdu: &crate::state::ReassembledPdu) {
    let (view_data, view_segments) = match &pdu.grouped {
        Some(grouped) => (&grouped.data, &grouped.segments),
        None => (&pdu.data, &pdu.segments),
    };
    let count = view_segments.len();
    let summary = view_segments
        .iter()
        .map(|segment| format!("#{}({})", segment.frame, segment.length))
        .collect::<Vec<_>>()
        .join(", ");
    let container = node.add_container(
        &fields::TCP_SEGMENTS,
        Range::new(0, view_data.len()),
        Some(format!(
            "{count} Reassembled TCP Segments ({} bytes): {summary}",
            view_data.len()
        )),
    );
    container.raw = Some(raw_field(
        view_data.clone(),
        0,
        view_data.len(),
        0,
        RawSource::Frame,
    ));
    for segment in view_segments {
        let definition = if segment.conflict {
            &fields::TCP_SEGMENT_ERROR
        } else {
            &fields::TCP_SEGMENT
        };
        let field = container.add_field(
            definition,
            Range::new(segment.offset, segment.length),
            Value::Uint32(u32::try_from(segment.frame).unwrap_or(u32::MAX)),
        );
        if segment.length == 0 {
            field.showname = Some(format!("Frame: {} (no data)", segment.frame));
        } else {
            let end = segment
                .offset
                .saturating_add(segment.length)
                .saturating_sub(1);
            field.showname = Some(format!(
                "Frame: {}, payload: {}-{} ({} bytes)",
                segment.frame, segment.offset, end, segment.length
            ));
        }
        field.raw = Some(raw_field(
            segment.data.clone(),
            segment.offset,
            segment.length,
            35,
            RawSource::Frame,
        ));
        if segment.overlap {
            let child = field.add_field(
                &fields::TCP_SEGMENT_OVERLAP,
                Range::new(segment.offset, 0),
                Value::Boolean(true),
            );
            child.raw = Some(raw_field(
                Vec::new(),
                segment.offset,
                0,
                2,
                RawSource::Frame,
            ));
        }
        if segment.conflict {
            let child = field.add_field(
                &fields::TCP_SEGMENT_OVERLAP_CONFLICT,
                Range::new(segment.offset, 0),
                Value::Boolean(true),
            );
            child.raw = Some(raw_field(
                Vec::new(),
                segment.offset,
                0,
                2,
                RawSource::Frame,
            ));
        }
        if segment.overlap || segment.conflict {
            field.container = true;
        }
        if segment.multipletails {
            let child = field.add_field(
                &fields::TCP_SEGMENT_MULTIPLETAILS,
                Range::new(segment.offset, 0),
                Value::Boolean(true),
            );
            child.raw = Some(raw_field(
                Vec::new(),
                segment.offset,
                0,
                2,
                RawSource::Frame,
            ));
        }
        if segment.toolong {
            let child = field.add_field(
                &fields::TCP_SEGMENT_TOOLONGFRAGMENT,
                Range::new(segment.offset, 0),
                Value::Boolean(true),
            );
            child.raw = Some(raw_field(
                Vec::new(),
                segment.offset,
                0,
                2,
                RawSource::Frame,
            ));
        }
    }
    let count_field = container.add_field(
        &fields::TCP_SEGMENT_COUNT,
        Range::new(0, 0),
        Value::Uint32(u32::try_from(count).unwrap_or(u32::MAX)),
    );
    count_field.raw = Some(raw_field(Vec::new(), 0, 0, 7, RawSource::Frame));
    let length_field = container.add_field(
        &fields::TCP_REASSEMBLED_LENGTH,
        Range::new(0, 0),
        Value::Uint32(u32::try_from(view_data.len()).unwrap_or(u32::MAX)),
    );
    length_field.raw = Some(raw_field(Vec::new(), 0, 0, 7, RawSource::Frame));
    let data_field = container.add_field(
        &fields::TCP_REASSEMBLED_DATA,
        Range::new(0, view_data.len()),
        Value::bytes(view_data.clone()),
    );
    data_field.raw = Some(raw_field(
        view_data.clone(),
        0,
        view_data.len(),
        30,
        RawSource::Frame,
    ));
}

/// Decode every complete application PDU this segment produced.
///
/// Reassembled PDUs decode with `base = 0` in their own buffer; a PDU that
/// fits one segment keeps its frame offset. TLS needs the segment's partial
/// tail too, because the output has one TLS node per contiguous record run
/// and reports `tls.segment_data` for an incomplete trailing record.
fn decode_stream_pdus(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    payload_offset: usize,
    payload: &[u8],
    report: &crate::state::ReassemblyReport,
) {
    if report.actions.is_empty() {
        return;
    }
    if context.transport_ports.is_none() || context.tcp_stream.is_none() {
        return;
    }
    let segment_sequence = context.tcp_sequence.unwrap_or(0);
    let mut info: Option<String> = None;
    let mut index = 0_usize;
    while index < report.actions.len() {
        match report.actions.get(index) {
            Some(PduAction::Standalone {
                ulp,
                data,
                offset,
                continuation,
                fin,
                ..
            }) => {
                context.http_pdu_offset = *offset;
                context.http_continuation = *continuation;
                context.http_fin = *fin;
                if *ulp == Ulp::Tls {
                    // A run of complete TLS records is one TLS node: hand the
                    // rest of the segment tail to the record loop, which also
                    // adds `tls.segment_data` for a partial trailing record.
                    let tail = payload.get(*offset..).unwrap_or_default();
                    run_decoder(
                        context,
                        node,
                        Ulp::Tls,
                        tail,
                        payload_offset.saturating_add(*offset),
                        segment_sequence.saturating_add(*offset as u32),
                        &mut info,
                    );
                    break;
                }
                run_decoder(
                    context,
                    node,
                    *ulp,
                    data,
                    payload_offset.saturating_add(*offset),
                    segment_sequence.saturating_add(*offset as u32),
                    &mut info,
                );
                if *ulp == Ulp::Http {
                    notify_http_pdu(context, data);
                }
            }
            Some(PduAction::Reassembled {
                pdu,
                continuation,
                fin,
                ..
            }) => {
                context.http_pdu_offset = 0;
                context.http_continuation = *continuation;
                context.http_fin = *fin;
                let saved_source = context.tls_record_source;
                let saved_pdu = context.pdu_bytes.take();
                if pdu.ulp == Ulp::Http {
                    context.pdu_bytes = Some(pdu.data.clone());
                }
                let record_source = if matches!(pdu.ulp, Ulp::Tls | Ulp::Http2) {
                    // The PDU bytes are the reassembly buffer, not the frame
                    // at offset zero; record fields must read this source.
                    let source = context.reserve_reassembled_source();
                    context.set_data_source(source, pdu.data.clone());
                    if pdu.ulp == Ulp::Tls {
                        context.tls_record_source = Some(source);
                    }
                    Some(source)
                } else {
                    None
                };
                let before = node.children.len();
                run_decoder(
                    context,
                    node,
                    pdu.ulp,
                    &pdu.data,
                    0,
                    segment_sequence,
                    &mut info,
                );
                context.tls_record_source = saved_source;
                context.pdu_bytes = saved_pdu;
                if let Some(source) = record_source
                    && let Some(children) = node.children.get_mut(before..)
                {
                    // Ranges decoded from the reassembly buffer must read
                    // that buffer, not the frame at the same offset.
                    for child in children {
                        fill_unset_source(child, source);
                    }
                }
                let view_segments = match &pdu.grouped {
                    Some(grouped) => &grouped.segments,
                    None => &pdu.segments,
                };
                if pdu.ulp == Ulp::Http {
                    notify_http_pdu(context, &pdu.data);
                    if view_segments.iter().any(|segment| segment.conflict) {
                        append_info(context, "[Illegal Segments]");
                        info = context.columns.info.clone();
                    }
                }
                if pdu.ulp == Ulp::Tls {
                    // The remainder of the segment is a separate TLS node.
                    if let Some(next) = report.actions.get(index + 1) {
                        let offset = match next {
                            PduAction::Partial { offset, .. }
                            | PduAction::Standalone { offset, .. } => *offset,
                            PduAction::Reassembled { .. } | PduAction::SegmentData { .. } => 0,
                        };
                        let tail = payload.get(offset..).unwrap_or_default();
                        if !tail.is_empty() {
                            run_decoder(
                                context,
                                node,
                                Ulp::Tls,
                                tail,
                                payload_offset.saturating_add(offset),
                                segment_sequence.saturating_add(offset as u32),
                                &mut info,
                            );
                        }
                        break;
                    }
                }
            }
            Some(PduAction::Partial {
                ulp,
                segment_data,
                offset,
                started_here,
                pdu_start,
            }) => {
                match ulp {
                    Ulp::Tls => {
                        if *started_here {
                            let tail = payload.get(*offset..).unwrap_or_default();
                            run_decoder(
                                context,
                                node,
                                Ulp::Tls,
                                tail,
                                payload_offset.saturating_add(*offset),
                                segment_sequence.saturating_add(*offset as u32),
                                &mut info,
                            );
                        } else {
                            decode_tls_partial(
                                context,
                                node,
                                &segment_data.bytes,
                                payload_offset.saturating_add(segment_data.offset),
                            );
                        }
                    }
                    Ulp::Http => {
                        let start = if *started_here {
                            &segment_data.bytes
                        } else {
                            pdu_start
                        };
                        if let Some(current) = http::partial_info(start) {
                            // Name the PDU in the Info column of a
                            // continuation segment and append the frame
                            // that currently holds its last byte.
                            let current = if *started_here {
                                current
                            } else {
                                format!(
                                    "{current} [TCP PDU reassembled in {}]",
                                    context.frame.number
                                )
                            };
                            info = Some(match info.take() {
                                Some(previous) => {
                                    let mut joined = String::new();
                                    joined.push_str(&previous);
                                    let remaining = MAX_INFO_BYTES.saturating_sub(joined.len());
                                    joined.push_str(
                                        current
                                            .get(..remaining.min(current.len()))
                                            .unwrap_or(&current),
                                    );
                                    joined
                                }
                                None => truncate_utf8(&current, MAX_INFO_BYTES).to_string(),
                            });
                        }
                    }
                    Ulp::Bgp => {
                        // A BGP message whose fixed header is present but
                        // whose body is split clears the Info column while
                        // the protocol column stays TCP. A complete message
                        // earlier in the same segment keeps its summary.
                        if *started_here && info.is_none() {
                            info = Some(String::new());
                        }
                    }
                    Ulp::Dns => {}
                    Ulp::Http2 => {
                        // A frame that is not complete yet has no node and no
                        // Info text; it decodes once, when its last byte
                        // arrives.
                    }
                }
            }
            Some(PduAction::SegmentData { .. }) => {}
            None => break,
        }
        index = index.saturating_add(1);
    }
    if let Some(info) = info {
        context.columns.info = Some(info);
    }
}

/// Append a bracketed TCP tag to the Info column with one separating space.
/// Run one upper-layer decoder and join its Info column with earlier PDUs.
fn run_decoder(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    ulp: Ulp,
    data: &[u8],
    base: usize,
    sequence: u32,
    info: &mut Option<String>,
) {
    let previous = context.columns.info.take();
    let saved_sequence = context.tcp_sequence;
    context.tcp_sequence = Some(sequence);
    decode_ulp(context, node, ulp, data, base);
    context.tcp_sequence = saved_sequence;
    if let Some(current) = context.columns.info.take() {
        // HTTP appends each message's start line with no separator, while
        // TLS and BGP join their messages with a comma.
        let separator = if ulp == Ulp::Http { "" } else { ", " };
        *info = Some(match info.take() {
            Some(previous) => {
                let mut joined =
                    String::with_capacity(previous.len() + separator.len() + current.len());
                joined.push_str(&previous);
                joined.push_str(separator);
                let remaining = MAX_INFO_BYTES.saturating_sub(joined.len());
                joined.push_str(
                    current
                        .get(..remaining.min(current.len()))
                        .unwrap_or(&current),
                );
                joined
            }
            None => truncate_utf8(&current, MAX_INFO_BYTES).to_string(),
        });
        context.columns.info = info.clone();
    } else {
        context.columns.info = previous;
    }
}

/// Decode one complete application PDU with the transport context set.
fn decode_ulp(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    ulp: Ulp,
    data: &[u8],
    base: usize,
) {
    match ulp {
        Ulp::Dns => dns::decode_tcp(context, node, data, base),
        Ulp::Tls => tls(context, node, data, base),
        Ulp::Bgp => bgp(context, node, data, base),
        Ulp::Http => http(context, node, data, base),
        Ulp::Http2 => crate::decode::http2::decode(context, node, data, base),
    }
}

/// Add the minimal TLS node for a continued partial record.
fn decode_tls_partial(context: &mut DecodeContext<'_>, node: &mut Node, data: &[u8], base: usize) {
    // The two-pass output keeps a partial-only TLS segment as plain TCP; the
    // one-pass tree still shows the TLS segment node.
    if context.pass == crate::state::PassMode::Second {
        return;
    }
    let Some(stream_assignment) = context.tcp_stream else {
        return;
    };
    context.depth = context.depth.saturating_add(1);
    context
        .protocol_stack
        .push(fields::TLS_PROTOCOL.filter_name);
    let mut tls_node = Node::new(&fields::TLS_PROTOCOL, Range::new(base, data.len()));
    tls_node.add_field(
        &fields::TLS_STREAM,
        Range::new(base, 0),
        Value::Uint32(stream_assignment.index),
    );
    tls::add_partial_segment_data(&mut tls_node, data, base);
    node.add_child(tls_node);
    context.columns.protocol = Some("SSL".to_string());
    context.depth = context.depth.saturating_sub(1);
}

/// Append a bracketed TCP tag to the Info column with one separating space.
fn append_info(context: &mut DecodeContext<'_>, tag: &str) {
    let mut previous = context.columns.info.take().unwrap_or_default();
    while previous.ends_with(' ') {
        previous.pop();
    }
    context.columns.info = Some(if previous.is_empty() {
        tag.to_string()
    } else {
        format!("{previous} {tag}")
    });
}

/// Point every unstamped range in a reassembled protocol at its buffer.
///
/// Decrypted plaintext ranges already carry their own source and are left
/// untouched; the TLS record and plaintext-handshake fields decoded from the
/// reassembly buffer would otherwise read the frame at the same offset.
fn fill_unset_source(node: &mut Node, source: u32) {
    if node.range.source == 0 {
        node.range.source = source;
    }
    for field in &mut node.fields {
        fill_unset_field_source(field, source);
    }
    for child in &mut node.children {
        fill_unset_source(child, source);
    }
}

fn fill_unset_field_source(field: &mut Field, source: u32) {
    if field.range.source == 0 {
        field.range.source = source;
    }
    for child in &mut field.children {
        fill_unset_field_source(child, source);
    }
}

/// The conversation tuple for this segment.
///
/// A fragmented datagram is not handed to the transport decoder until
/// reassembly, so it has no conversation. A header quoted inside an ICMP
/// error still gets a conversation: the quote consumes a stream number and
/// a later flow on a new tuple gets the next one.
fn conversation_key(
    context: &DecodeContext<'_>,
    source_port: u16,
    destination_port: u16,
) -> Option<(ConversationKey, usize)> {
    match context.network.as_ref()? {
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

/// The checksum the segment should carry, or `None` when validation is
/// disabled or the network layer is unknown.
fn calculated_checksum(
    context: &DecodeContext<'_>,
    data: &[u8],
    reported_transport_length: usize,
) -> Option<u16> {
    if !context.options.preferences.tcp_check_checksum {
        return None;
    }
    // A snaplen-truncated segment cannot be validated: report its checksum
    // as unverified rather than computing over the captured prefix.
    if reported_transport_length > data.len() {
        return None;
    }
    match context.network.as_ref()? {
        NetworkContext::Ipv4 {
            source,
            destination,
            ..
        } => Some(checksum::ipv4_transport(
            *source,
            *destination,
            6,
            u32::try_from(data.len()).unwrap_or(u32::MAX),
            data,
            CHECKSUM_OFFSET,
        )),
        NetworkContext::Ipv6 {
            source,
            destination,
            ..
        } => Some(checksum::ipv6_transport(
            *source,
            *destination,
            6,
            u32::try_from(data.len()).unwrap_or(u32::MAX),
            data,
            CHECKSUM_OFFSET,
        )),
    }
}

/// Render the twelve-character TCP flags string.
fn flags_string(flags: u16) -> String {
    const LABELS: [char; 12] = ['R', 'R', 'R', 'A', 'C', 'E', 'U', 'A', 'P', 'R', 'S', 'F'];
    let mut text = String::with_capacity(LABELS.len());
    for (index, label) in LABELS.iter().enumerate() {
        let bit = 11_u32.saturating_sub(u32::try_from(index).unwrap_or(11));
        if flags & (1_u16 << bit) != 0 {
            text.push(*label);
        } else {
            text.push('\u{00b7}');
        }
    }
    text
}

/// Whether the captured option area contains a valid option of `kind`.
fn tcp_has_option(captured: &[u8], kind: u8) -> bool {
    let mut offset = 0_usize;
    while offset < captured.len() {
        let Some(&current) = captured.get(offset) else {
            return false;
        };
        if current == OPTION_EOL {
            return false;
        }
        if current == OPTION_NOP {
            offset = offset.saturating_add(1);
            continue;
        }
        let Some(&length) = captured.get(offset.saturating_add(1)) else {
            return false;
        };
        let length = usize::from(length);
        if length < 2 || offset.saturating_add(length) > captured.len() {
            return false;
        }
        if current == kind {
            return true;
        }
        offset = offset.saturating_add(length);
    }
    false
}

/// Parse the option area, which is bounded by the declared header length and
/// the captured bytes.
fn parse_options(
    context: &mut DecodeContext<'_>,
    node: &mut Node,
    captured: &[u8],
    declared_length: usize,
    base: usize,
    sack_base: Option<u32>,
) {
    let mut offset = 0_usize;
    while offset < captured.len() {
        let Some(&kind) = captured.get(offset) else {
            return;
        };
        if kind == OPTION_EOL {
            add_option_kind(node, base, offset, kind);
            offset = offset.saturating_add(1);
            match captured.get(offset) {
                None => return,
                Some(0) => continue,
                Some(_) => {
                    node.add_expert(ExpertInfo {
                        severity: Severity::Error,
                        group: Group::Protocol,
                        message: "Non-zero header padding".to_string(),
                    });
                    return;
                }
            }
        }
        if kind == OPTION_NOP {
            add_option_kind(node, base, offset, kind);
            offset = offset.saturating_add(1);
            continue;
        }

        let Some(&length_byte) = captured.get(offset.saturating_add(1)) else {
            if offset.saturating_add(1) >= declared_length {
                add_invalid_option(node, base, offset);
            }
            return;
        };
        let length = usize::from(length_byte);
        if length < 2 {
            add_invalid_option(node, base, offset);
            return;
        }
        let Some(end) = offset.checked_add(length) else {
            add_invalid_option(node, base, offset);
            return;
        };
        if end > declared_length {
            add_invalid_option(node, base, offset);
            return;
        }
        add_option_kind(node, base, offset, kind);
        node.add_field(
            &fields::TCP_OPTION_LEN,
            Range::new(base + offset + 1, 1),
            Value::Uint8(length_byte),
        );

        let complete = end <= captured.len();
        let captured_end = end.min(captured.len());
        let option_data = captured
            .get(offset.saturating_add(2)..captured_end)
            .unwrap_or(&[]);
        let option_base = base + offset + 2;
        match kind {
            OPTION_MSS => {
                if length == 4 {
                    if complete && let Some(value) = read_u16_be(option_data, 0) {
                        node.add_field(
                            &fields::TCP_OPTIONS_MSS_VALUE,
                            Range::new(option_base, 2),
                            Value::Uint16(value),
                        );
                    }
                } else {
                    add_invalid_option(node, base, offset);
                }
            }
            OPTION_WINDOW_SCALE => {
                if length == 3 {
                    if complete && let Some(&shift) = option_data.first() {
                        node.add_field(
                            &fields::TCP_OPTIONS_WSCALE_SHIFT,
                            Range::new(option_base, 1),
                            Value::Uint8(shift),
                        );
                        let multiplier = 1_u16.checked_shl(u32::from(shift).min(14)).unwrap_or(1);
                        node.add_field(
                            &fields::TCP_OPTIONS_WSCALE_MULTIPLIER,
                            Range::new(0, 0),
                            Value::Uint16(multiplier),
                        );
                    }
                } else {
                    add_invalid_option(node, base, offset);
                }
            }
            OPTION_SACK_PERMITTED => {
                if length != 2 {
                    add_invalid_option(node, base, offset);
                }
            }
            OPTION_SACK => {
                parse_sack(node, option_data, option_base, complete, sack_base);
                if complete && option_data.len() < 8 {
                    return;
                }
            }
            OPTION_TIMESTAMPS => {
                if length == 10 {
                    if let Some(value) = read_u32_be(option_data, 0) {
                        node.add_field(
                            &fields::TCP_OPTIONS_TIMESTAMP_TSVAL,
                            Range::new(option_base, 4),
                            Value::Uint32(value),
                        );
                    }
                    if let Some(value) = read_u32_be(option_data, 4) {
                        node.add_field(
                            &fields::TCP_OPTIONS_TIMESTAMP_TSECR,
                            Range::new(option_base + 4, 4),
                            Value::Uint32(value),
                        );
                    }
                } else {
                    add_invalid_option(node, base, offset);
                }
            }
            _ => {}
        }
        if !complete {
            context.mark_malformed(node, "TCP option is truncated");
            return;
        }
        offset = end;
    }
}

/// Parse the SACK blocks inside one option. Full blocks have both edges; a
/// trailing partial block keeps its left edge.
fn parse_sack(
    node: &mut Node,
    data: &[u8],
    base: usize,
    complete: bool,
    relative_base: Option<u32>,
) {
    let mut offset = 0_usize;
    let mut count = 0_u8;
    while let Some(block) = data.get(offset..offset.saturating_add(8)) {
        if let Some(left) = read_u32_be(block, 0) {
            let displayed = relative_base.map_or(left, |base| left.wrapping_sub(base));
            node.add_field(
                &fields::TCP_OPTIONS_SACK_LE,
                Range::new(base + offset, 4),
                Value::Uint32(displayed),
            );
        }
        if let Some(right) = read_u32_be(block, 4) {
            let displayed = relative_base.map_or(right, |base| right.wrapping_sub(base));
            node.add_field(
                &fields::TCP_OPTIONS_SACK_RE,
                Range::new(base + offset + 4, 4),
                Value::Uint32(displayed),
            );
        }
        count = count.saturating_add(1);
        offset = offset.saturating_add(8);
    }
    if let Some(left) = data.get(offset..offset.saturating_add(4))
        && let Some(value) = read_u32_be(left, 0)
    {
        let displayed = relative_base.map_or(value, |base| value.wrapping_sub(base));
        node.add_field(
            &fields::TCP_OPTIONS_SACK_LE,
            Range::new(base + offset, 4),
            Value::Uint32(displayed),
        );
    }
    if complete {
        node.add_field(
            &fields::TCP_OPTIONS_SACK_COUNT,
            Range::new(0, 0),
            Value::Uint8(count),
        );
    }
}

fn add_option_kind(node: &mut Node, base: usize, offset: usize, kind: u8) {
    node.add_field(
        &fields::TCP_OPTION_KIND,
        Range::new(base + offset, 1),
        Value::Uint8(kind),
    );
}

fn add_invalid_option(node: &mut Node, base: usize, offset: usize) {
    node.add_field(
        &fields::TCP_OPTION_LEN_INVALID,
        Range::new(base + offset, 1),
        Value::None,
    );
}
