//! Per-direction TCP sequence analysis and window scaling.
//!
//! Each direction keeps the expected next sequence, the highest sequence seen,
//! the last acknowledgement it sent, its advertised window, duplicate-ACK
//! count and the unacknowledged ranges used for ACK attribution, the in-flight
//! span and the retransmission timeout. Sequence comparisons use wrapping arithmetic, as
//! RFC 9293 section 3.4 requires for the 32-bit sequence space.
//!
//! Precedence: spurious retransmission supersedes fast
//! retransmission, out-of-order and retransmission; fast retransmission
//! supersedes out-of-order and retransmission; keep-alive supersedes the
//! retransmission family. The flag fields carry the exact expert messages;
//! the summary tags are rendered separately.

use std::collections::VecDeque;
use std::mem::size_of;

use crate::capture::Timestamp;

use super::stream::{ConversationStreams, ReassemblyReport, Ulp};

/// One TCP segment's facts, as the decoder observed them.
#[derive(Clone, Debug)]
pub(crate) struct TcpObservation {
    /// Canonical endpoint direction of the sender.
    pub(crate) direction: usize,
    /// Sequence number from the header.
    pub(crate) sequence: u32,
    /// Acknowledgement number from the header.
    pub(crate) acknowledgement: u32,
    /// Advertised receive window.
    pub(crate) window: u16,
    /// Payload bytes after the declared header.
    pub(crate) payload_len: u32,
    /// SYN flag.
    pub(crate) syn: bool,
    /// ACK flag.
    pub(crate) ack: bool,
    /// FIN flag.
    pub(crate) fin: bool,
    /// RST flag.
    pub(crate) rst: bool,
    /// PSH flag.
    pub(crate) psh: bool,
    /// Valid window-scale shift from this segment's options.
    pub(crate) wscale: Option<u8>,
    /// Whether a valid SACK block is present.
    pub(crate) has_sack: bool,
    /// Bytes acknowledged by those SACK blocks.
    pub(crate) sack_delivered: u32,
    /// Frame number.
    pub(crate) frame: u64,
    /// Capture time.
    pub(crate) timestamp: Option<Timestamp>,
    /// Upper protocol recognised for this direction, if any.
    pub(crate) ulp: Option<Ulp>,
    /// Payload bytes, for reassembly.
    pub(crate) payload: Vec<u8>,
}

/// Analysis preferences that change the computed fields.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TcpAnalysisOptions {
    /// `tcp.analyze_sequence_numbers`.
    pub(crate) analyze: bool,
    /// `tcp.relative_sequence_numbers`.
    pub(crate) relative: bool,
    /// `tcp.track_bytes_in_flight`.
    pub(crate) track_bytes_in_flight: bool,
    /// `tcp.reassemble_out_of_order`.
    pub(crate) reassemble_out_of_order: bool,
    /// `tcp.default_window_scaling`: `-1` means "Not known".
    pub(crate) default_window_scaling: i8,
    /// `tcp.fastrt_supersedes_ooo`.
    pub(crate) fastrt_supersedes_ooo: bool,
}

/// The analysis flags one segment triggered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AnalysisFlags {
    pub(crate) retransmission: bool,
    pub(crate) fast_retransmission: bool,
    pub(crate) spurious_retransmission: bool,
    pub(crate) out_of_order: bool,
    pub(crate) reused_ports: bool,
    pub(crate) lost_segment: bool,
    pub(crate) ack_lost_segment: bool,
    pub(crate) window_update: bool,
    pub(crate) keep_alive: bool,
    pub(crate) keep_alive_ack: bool,
    pub(crate) zero_window_probe: bool,
    pub(crate) zero_window: bool,
    pub(crate) zero_window_probe_ack: bool,
}

impl AnalysisFlags {
    /// Whether any analysis flag is set.
    pub(crate) fn any(self) -> bool {
        self.retransmission
            || self.fast_retransmission
            || self.spurious_retransmission
            || self.out_of_order
            || self.reused_ports
            || self.lost_segment
            || self.ack_lost_segment
            || self.window_update
            || self.keep_alive
            || self.keep_alive_ack
            || self.zero_window_probe
            || self.zero_window
            || self.zero_window_probe_ack
    }
}

/// The values the decoder adds under `tcp.analysis`.
#[derive(Clone, Debug, Default)]
pub(crate) struct AnalysisOutcome {
    pub(crate) acks_frame: Option<u64>,
    pub(crate) ack_rtt_ns: Option<u64>,
    pub(crate) initial_rtt_ns: Option<u64>,
    pub(crate) bytes_in_flight: Option<u32>,
    pub(crate) push_bytes_sent: Option<u32>,
    pub(crate) rto_ns: Option<u64>,
    pub(crate) rto_frame: Option<u64>,
    /// Duplicate ACK number and the first frame that sent that ACK value.
    pub(crate) duplicate: Option<(u32, u64)>,
    pub(crate) flags: AnalysisFlags,
}

/// Everything one segment produces for the decoder.
#[derive(Clone, Debug, Default)]
pub(crate) struct TcpPacketState {
    pub(crate) stream: u32,
    pub(crate) packet_number: u32,
    /// Relative sequence, or `None` when the base is unknown (quoted header).
    pub(crate) relative_seq: Option<u32>,
    /// Relative acknowledgement, or `None` when the peer base is unknown.
    pub(crate) relative_ack: Option<u32>,
    /// Displayed next sequence, absent for a quoted header.
    pub(crate) next_sequence: Option<u32>,
    pub(crate) window_size: Option<u32>,
    pub(crate) scale_factor: Option<i32>,
    pub(crate) analysis: AnalysisOutcome,
    pub(crate) reassembly: ReassemblyReport,
    /// `tcp.pdu.size` a segment declares when desegmentation is disabled.
    pub(crate) standalone_pdu_size: Option<u32>,
    /// Whether the direction has recognised an upper protocol.
    pub(crate) ulp_known: bool,
    /// Time since the first frame in this TCP stream.
    pub(crate) time_relative_ns: Option<u64>,
    /// Time since the previous frame in this TCP stream.
    pub(crate) time_delta_ns: Option<u64>,
}

/// One unacknowledged range, kept for the in-flight span and RTO.
#[derive(Clone, Copy, Debug)]
struct UnackedRange {
    sequence: u32,
    end: u32,
    frame: u64,
    time: Option<Timestamp>,
}

/// Per-direction TCP state.
#[derive(Debug, Default)]
pub(crate) struct TcpDirection {
    /// Sequence base for relative numbering.
    base: Option<u32>,
    /// Next expected sequence number.
    next_seq: Option<u32>,
    /// Highest `sequence + length + SYN/FIN` seen.
    max_end: Option<u32>,
    /// Last acknowledgement number this direction sent.
    last_ack: Option<u32>,
    /// First frame that sent the current acknowledgement value.
    last_ack_frame: Option<u64>,
    /// Last advertised window.
    last_window: Option<u16>,
    /// Largest advertised window seen.
    max_window: u16,
    /// Last frame and time in this direction.
    last_frame: Option<u64>,
    last_time: Option<Timestamp>,
    /// Consecutive duplicate acknowledgements.
    dup_ack_count: u32,
    /// Whether this direction sent a SYN, which fixes window-scaling state.
    seen_syn: bool,
    /// Valid window-scale shift advertised in the SYN.
    wscale: Option<u8>,
    /// Bytes since the last PSH.
    push_bytes: u32,
    /// Whether the last segment this direction sent was a keep-alive.
    last_keep_alive: bool,
    /// Whether the last segment this direction sent was a zero-window probe.
    last_zero_window_probe: bool,
    /// The direction's reassembly frontier when it first left the sequence
    /// space expected by the peer.
    max_seqtobeacked: Option<u32>,
    /// Whether in-flight bytes may be reported: false until the peer sends
    /// an ACK, and again after an unacknowledged gap.
    valid_bif: bool,
    /// Whether the previous data segment carried PSH.
    push_set_last: bool,
    /// Payload length of the segment that last advanced the sequence.
    last_ack_len: u32,
    /// SACK bytes the peer reported in its latest segment.
    sack_delivered: u32,
    /// Ranges sent and not yet acknowledged, oldest first.
    unacked: VecDeque<UnackedRange>,
    /// Frame and time that last advanced the expected sequence.
    next_seq_frame: Option<u64>,
    next_seq_time: Option<Timestamp>,
}

impl TcpDirection {
    /// The sequence base for this direction.
    pub(crate) fn base(&self) -> Option<u32> {
        self.base
    }

    /// Seed the sequence base from the first segment.
    fn seed_base(&mut self, sequence: u32, syn: bool) {
        if self.base.is_none() {
            self.base = Some(if syn {
                sequence
            } else {
                sequence.wrapping_sub(1)
            });
        }
    }

    fn heap_bytes(&self) -> usize {
        self.unacked.capacity() * size_of::<UnackedRange>()
    }
}

/// Per-conversation TCP analysis and reassembly state.
#[derive(Debug, Default)]
pub(crate) struct TcpAnalysisState {
    pub(crate) directions: [TcpDirection; 2],
    streams: ConversationStreams,
    /// Frame and time of the initial SYN per direction.
    syn: [Option<(u64, Option<Timestamp>)>; 2],
    /// Completed handshake round-trip time.
    initial_rtt_ns: Option<u64>,
    /// Receiving a SYN with a new ISN started a new stream.
    reused_ports: bool,
    /// First and last capture times seen in this stream.
    first_time: Option<Timestamp>,
    last_time: Option<Timestamp>,
    /// Per-direction start of the next PDU when desegmentation is off.
    pdu_next: [Option<u32>; 2],
}

impl TcpAnalysisState {
    /// Bytes retained outside the inline structure.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.directions
            .iter()
            .map(TcpDirection::heap_bytes)
            .sum::<usize>()
            + self.streams.heap_bytes()
    }

    /// Direction state for tests and base assertions.
    pub(crate) fn direction(&self, direction: usize) -> Option<&TcpDirection> {
        self.directions.get(direction)
    }

    /// Seed one direction's sequence base when it has none.
    pub(crate) fn seed_base(&mut self, direction: usize, sequence: u32, syn: bool) {
        if let Some(endpoint) = self.directions.get_mut(direction.min(1)) {
            endpoint.seed_base(sequence, syn);
        }
    }

    /// Seed the peer's base from the acknowledgement of the first ACK.
    pub(crate) fn seed_reverse_base(&mut self, direction: usize, acknowledgement: u32) {
        if let Some(endpoint) = self.directions.get_mut(direction.min(1) ^ 1)
            && endpoint.base.is_none()
        {
            endpoint.base = Some(acknowledgement.wrapping_sub(1));
        }
    }

    /// The PDU size a segment declares when desegmentation is disabled.
    ///
    /// The fixed header of a segment that starts a PDU is still read and its
    /// size reported, but segments are never joined. A segment that does not
    /// start where the previous PDU ended is a continuation and reports
    /// nothing.
    pub(crate) fn standalone_pdu_size(
        &mut self,
        direction: usize,
        sequence: u32,
        ulp: Option<Ulp>,
        payload: &[u8],
    ) -> Option<u32> {
        let direction = direction.min(1);
        let expected = self.pdu_next.get(direction).copied().flatten();
        if expected.is_some_and(|expected| expected != sequence) {
            return None;
        }
        let size = match ulp {
            Some(Ulp::Dns) => read_u16(payload, 0).map(|length| 2 + u32::from(length)),
            Some(Ulp::Bgp)
                if payload.len() >= 19 && payload.iter().take(16).all(|byte| *byte == 0xff) =>
            {
                read_u16(payload, 16).map(u32::from)
            }
            _ => None,
        };
        if let Some(slot) = self.pdu_next.get_mut(direction) {
            *slot = size.map(|size| sequence.wrapping_add(size));
        }
        size
    }

    /// Record the conversation restart before the new state replaces it.
    pub(crate) fn mark_reused_ports(&mut self) {
        self.reused_ports = true;
    }

    /// Analyse one segment and update the direction state.
    ///
    /// `stream` and `packet_number` come from the conversation numbering;
    /// `quoted` suppresses the analysis of a header quoted inside an ICMP
    /// error.
    #[cfg(test)]
    pub(crate) fn observe(
        &mut self,
        observation: TcpObservation,
        options: TcpAnalysisOptions,
        stream: u32,
        packet_number: u32,
        quoted: bool,
    ) -> TcpPacketState {
        let file = observation.frame;
        self.observe_with_file(observation, options, stream, packet_number, file, quoted)
    }

    /// Analyse one segment and retain its capture frame number.
    pub(crate) fn observe_with_file(
        &mut self,
        observation: TcpObservation,
        options: TcpAnalysisOptions,
        stream: u32,
        packet_number: u32,
        file: u64,
        quoted: bool,
    ) -> TcpPacketState {
        let direction = observation.direction.min(1);
        let reassembly = if quoted {
            ReassemblyReport::default()
        } else {
            self.reassemble(&observation, options, file)
        };
        if self.first_time.is_none() {
            self.first_time = observation.timestamp;
        }
        let time_relative_ns = elapsed(observation.timestamp, self.first_time);
        let time_delta_ns = elapsed(observation.timestamp, self.last_time)
            .or_else(|| observation.timestamp.map(|_| 0));
        self.last_time = observation.timestamp.or(self.last_time);
        let (fwd, rev) = split_directions(&mut self.directions, direction);
        if !quoted {
            fwd.seed_base(observation.sequence, observation.syn);
            if observation.syn
                && !observation.ack
                && let Some(slot) = self.syn.get_mut(direction)
            {
                // The SYN timestamp is the most recent SYN without ACK, so a
                // retransmitted SYN moves the iRTT start.
                *slot = Some((observation.frame, observation.timestamp));
            }
        }
        let (window_size, scale_factor) = if quoted {
            read_window_scaling(fwd, &observation, options.default_window_scaling)
        } else {
            window_scaling(fwd, &observation, options.default_window_scaling)
        };
        let relative_seq = if options.analyze && options.relative && !quoted {
            fwd.base()
                .map(|base| observation.sequence.wrapping_sub(base))
        } else {
            None
        };
        let relative_ack = if options.analyze && options.relative && !quoted {
            rev.base()
                .map(|base| observation.acknowledgement.wrapping_sub(base))
        } else {
            None
        };
        let next_sequence = (!quoted).then(|| {
            let sequence = relative_seq.unwrap_or(observation.sequence);
            // A FIN carried on a SYN takes no sequence space.
            let extra = u32::from(observation.syn) + u32::from(observation.fin && !observation.syn);
            sequence
                .wrapping_add(observation.payload_len)
                .wrapping_add(extra)
        });

        if quoted {
            self.reused_ports = false;
            return TcpPacketState {
                stream,
                packet_number,
                relative_seq: None,
                relative_ack: None,
                next_sequence: None,
                window_size,
                scale_factor,
                analysis: AnalysisOutcome::default(),
                reassembly: ReassemblyReport::default(),
                standalone_pdu_size: None,
                ulp_known: false,
                time_relative_ns,
                time_delta_ns,
            };
        }

        let analysis = if options.analyze {
            analyse_segment(
                fwd,
                rev,
                &observation,
                options,
                direction,
                &mut self.syn,
                &mut self.initial_rtt_ns,
            )
        } else {
            AnalysisOutcome::default()
        };
        // Window and acknowledgement tracking happen even with analysis
        // disabled, so the window fields stay correct either way.
        update_ack_and_window(fwd, &observation);
        let analysis = AnalysisOutcome {
            flags: AnalysisFlags {
                reused_ports: self.reused_ports && options.analyze,
                ..analysis.flags
            },
            ..analysis
        };
        self.reused_ports = false;
        TcpPacketState {
            stream,
            packet_number,
            relative_seq,
            relative_ack,
            next_sequence,
            window_size,
            scale_factor,
            analysis,
            reassembly,
            standalone_pdu_size: None,
            ulp_known: self.streams.direction(direction).has_ulp(),
            time_relative_ns,
            time_delta_ns,
        }
    }

    fn reassemble(
        &mut self,
        observation: &TcpObservation,
        options: TcpAnalysisOptions,
        file: u64,
    ) -> ReassemblyReport {
        let direction = observation.direction.min(1);
        if let Some(ulp) = observation.ulp {
            self.streams.direction_mut(direction).set_ulp(ulp);
            if ulp == Ulp::Http {
                self.streams
                    .observe_http_request(direction, &observation.payload);
            }
        }
        let report = self
            .streams
            .direction_mut(direction)
            .insert_with_file_and_fin(
                observation.sequence,
                &observation.payload,
                observation.frame,
                file,
                options.reassemble_out_of_order,
                observation.fin,
            );
        self.streams
            .observe_http_actions(direction, &report.actions);
        report
    }
}

/// Split the direction array into the sender's and peer's state.
fn split_directions(
    directions: &mut [TcpDirection; 2],
    direction: usize,
) -> (&mut TcpDirection, &mut TcpDirection) {
    let (first, second) = directions.split_at_mut(1);
    if direction == 0 {
        let (Some(fwd), Some(rev)) = (first.first_mut(), second.first_mut()) else {
            unreachable!("two directions were just split");
        };
        (fwd, rev)
    } else {
        let (Some(rev), Some(fwd)) = (first.first_mut(), second.first_mut()) else {
            unreachable!("two directions were just split");
        };
        (fwd, rev)
    }
}

/// Read the scaled window without changing the direction state.
fn read_window_scaling(
    fwd: &TcpDirection,
    observation: &TcpObservation,
    default_scaling: i8,
) -> (Option<u32>, Option<i32>) {
    let raw = u32::from(observation.window);
    if observation.syn {
        return (Some(raw), None);
    }
    let factor = if fwd.seen_syn {
        fwd.wscale
            .map_or(-2, |shift| 1_i32 << u32::from(shift.min(14)))
    } else if default_scaling >= 0 {
        1_i32 << u32::from(default_scaling.min(14) as u8)
    } else {
        -1
    };
    let scaled = if factor > 1 {
        raw.saturating_mul(u32::try_from(factor).unwrap_or(1))
    } else {
        raw
    };
    (Some(scaled), Some(factor))
}

/// Compute the scaled window and its factor for one segment.
fn window_scaling(
    fwd: &mut TcpDirection,
    observation: &TcpObservation,
    default_scaling: i8,
) -> (Option<u32>, Option<i32>) {
    let raw = u32::from(observation.window);
    if observation.syn {
        fwd.seen_syn = true;
        if let Some(shift) = observation.wscale {
            fwd.wscale = Some(shift);
        }
        // The SYN window is never scaled, and the factor is not printed.
        return (Some(raw), None);
    }
    let factor = if fwd.seen_syn {
        fwd.wscale
            .map_or(-2, |shift| 1_i32 << u32::from(shift.min(14)))
    } else if default_scaling >= 0 {
        1_i32 << u32::from(default_scaling.min(14) as u8)
    } else {
        -1
    };
    let scaled = if factor > 1 {
        raw.saturating_mul(u32::try_from(factor).unwrap_or(1))
    } else {
        raw
    };
    (Some(scaled), Some(factor))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

fn sequence_before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

fn sequence_after(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) > 0
}

/// Analyse one segment and derive its analysis flags.
///
/// The expected sequence is the highest end seen: it advances on every
/// segment except a zero-window probe. `max_end` remains the retransmission
/// reference, and `max_seqtobeacked` is the frontier the peer is allowed to
/// acknowledge.
fn analyse_segment(
    fwd: &mut TcpDirection,
    rev: &mut TcpDirection,
    observation: &TcpObservation,
    options: TcpAnalysisOptions,
    direction: usize,
    syn: &mut [Option<(u64, Option<Timestamp>)>; 2],
    initial_rtt: &mut Option<u64>,
) -> AnalysisOutcome {
    let mut outcome = AnalysisOutcome::default();
    let mut flags = AnalysisFlags::default();
    let payload = observation.payload_len;
    let sequence = observation.sequence;
    let syn_flag = observation.syn;
    let fin = observation.fin;
    let rst = observation.rst;
    let sequence_space = u32::from(syn_flag) + u32::from(fin && !syn_flag);
    let end = sequence.wrapping_add(payload).wrapping_add(sequence_space);
    let max_end = fwd.max_end;
    let next_seq = fwd.next_seq.unwrap_or(sequence);
    let previous_window = fwd.last_window;
    let peer_last_window = rev.last_window;
    let peer_last_ack = rev.last_ack;
    let peer_dup_acks = rev.dup_ack_count;
    let peer_was_keepalive = rev.last_keep_alive;
    let peer_was_probe = rev.last_zero_window_probe;

    // Keep-alive: zero or one data byte, one before the expected sequence.
    let keep_alive = payload <= 1
        && !syn_flag
        && !fin
        && !rst
        && next_seq.wrapping_sub(1) == sequence
        && fwd.max_end.is_some();

    let zero_window = observation.window == 0 && !syn_flag && !fin && !rst;

    let zero_window_probe = payload == 1
        && !syn_flag
        && !fin
        && !rst
        && sequence == next_seq
        && peer_last_window == Some(0);

    let zero_window_probe_ack = payload == 0
        && observation.window == 0
        && !syn_flag
        && !fin
        && !rst
        && sequence == next_seq
        && observation.ack
        && fwd.last_ack.is_some_and(|last| {
            observation.acknowledgement == last
                || observation.acknowledgement == last.wrapping_add(1)
        })
        && peer_was_probe;

    let keep_alive_ack = payload == 0
        && observation.window != 0
        && Some(observation.window) == previous_window
        && !syn_flag
        && !fin
        && !rst
        && sequence == next_seq
        && observation.ack
        && Some(observation.acknowledgement) == fwd.last_ack
        && peer_was_keepalive;

    let duplicate_ack = payload == 0
        && observation.window != 0
        && !syn_flag
        && !fin
        && !rst
        && observation.ack
        && observation.acknowledgement != 0
        && Some(observation.acknowledgement) == fwd.last_ack
        && sequence == next_seq
        && fwd.max_end.is_some()
        && !keep_alive
        && !keep_alive_ack
        && !zero_window_probe_ack
        && !zero_window_probe
        && (previous_window == Some(observation.window) || observation.has_sack);

    let window_update = payload == 0
        && observation.window != 0
        && previous_window.is_some()
        && previous_window != Some(observation.window)
        && !observation.has_sack
        && !syn_flag
        && !fin
        && !rst
        && sequence == next_seq
        && observation.ack
        && (Some(observation.acknowledgement) == fwd.last_ack || peer_was_probe);

    // Retransmission family. A segment below the highest end seen repeats
    // sequence space; a segment above it leaves a gap.
    let retransmission_candidate = !keep_alive
        && !(syn_flag && fin)
        && (payload > 0 || syn_flag || fin)
        && fwd
            .next_seq
            .is_some_and(|next| sequence_before(sequence, next));

    // A dropped zero-window probe byte makes the next transmission start at
    // the probe sequence with more than one byte; that segment is not part
    // of the retransmission family.
    let probe_drop = payload > 1 && next_seq == sequence.wrapping_add(1);

    // Spurious retransmission is decided on payload bytes before the FIN
    // sequence-space adjustment and does not depend on the retransmission
    // pre-check (a dropped zero-window probe can still be spurious).
    let spurious = payload > 0
        && peer_last_ack.is_some_and(|ack| !sequence_after(sequence.wrapping_add(payload), ack));

    let family = retransmission_candidate && !spurious && !probe_drop;

    let fast = family
        && payload > 0
        && peer_dup_acks >= 2
        && peer_last_ack == Some(sequence)
        && within_ack_window(observation.timestamp, rev.last_time);

    let lost = !rst
        && fwd
            .next_seq
            .is_some_and(|next| sequence_after(sequence, next));

    let ack_lost = observation.ack
        && !zero_window_probe_ack
        && rev
            .max_seqtobeacked
            .is_some_and(|frontier| sequence_after(observation.acknowledgement, frontier));

    let previously_seen = fwd.unacked.iter().any(|range| {
        !sequence_before(sequence, range.sequence)
            && !sequence_after(sequence.wrapping_add(payload), range.end)
    });
    let out_of_order = family
        && within_out_of_order_threshold(observation.timestamp, rev.last_time, *initial_rtt)
        && !previously_seen
        && (fwd.next_seq != Some(end) || fwd.last_ack_len == 0);

    // Fast retransmission supersedes out-of-order by default; the preference
    // flips that interpretation.
    let (fast, out_of_order) = if fast && out_of_order {
        if options.fastrt_supersedes_ooo {
            (true, false)
        } else {
            (false, true)
        }
    } else {
        (fast, out_of_order)
    };

    flags.retransmission = (family && !out_of_order) || spurious;
    flags.fast_retransmission = fast;
    flags.spurious_retransmission = spurious;
    flags.out_of_order = out_of_order;
    flags.lost_segment = lost;
    flags.ack_lost_segment = ack_lost;
    flags.window_update = window_update;
    flags.keep_alive = keep_alive;
    flags.keep_alive_ack = keep_alive_ack;
    flags.zero_window = zero_window;
    flags.zero_window_probe = zero_window_probe;
    flags.zero_window_probe_ack = zero_window_probe_ack;
    if keep_alive {
        flags.retransmission = false;
        flags.fast_retransmission = false;
        flags.spurious_retransmission = false;
        flags.out_of_order = false;
    }
    if flags.keep_alive_ack || flags.zero_window_probe_ack {
        flags.retransmission = false;
        flags.fast_retransmission = false;
        flags.spurious_retransmission = false;
        flags.out_of_order = false;
    }

    // ACK attribution: a full ACK matches the segment whose end it equals; a
    // partial ACK lies strictly inside a segment. The oldest matching segment
    // is the original, even when retransmissions share the same range.
    if observation.ack {
        if let Some(latest) = rev
            .unacked
            .iter()
            .find(|range| range.end == observation.acknowledgement)
            .or_else(|| {
                rev.unacked.iter().find(|range| {
                    sequence_before(range.sequence, observation.acknowledgement)
                        && sequence_before(observation.acknowledgement, range.end)
                })
            })
        {
            outcome.acks_frame = Some(latest.frame);
            outcome.ack_rtt_ns =
                elapsed(observation.timestamp, latest.time).filter(|nanos| *nanos > 0);
        }
        if initial_rtt.is_none()
            && !syn_flag
            && let Some((_, Some(syn_time))) = syn.get(direction).copied().flatten()
        {
            *initial_rtt = elapsed(observation.timestamp, Some(syn_time));
        }
    }
    outcome.initial_rtt_ns = initial_rtt.filter(|nanos| *nanos > 0);

    if zero_window_probe_ack
        && fwd
            .last_ack
            .is_some_and(|last| observation.acknowledgement == last.wrapping_add(1))
    {
        // The receiver consumed the probe byte; advance the sender's
        // expected sequence so the next data segment is not called lost.
        rev.next_seq = Some(observation.acknowledgement);
        rev.max_seqtobeacked = Some(observation.acknowledgement);
    }

    if duplicate_ack {
        fwd.dup_ack_count = fwd.dup_ack_count.saturating_add(1);
        outcome.duplicate = Some((
            fwd.dup_ack_count,
            fwd.last_ack_frame.unwrap_or(observation.frame),
        ));
    }

    // RTO: walk the unacked list from newest to oldest and keep the last
    // segment whose start is at or beyond the retransmitted sequence.
    // Fast, spurious and out-of-order segments are not timed.
    if flags.retransmission
        && !flags.fast_retransmission
        && !flags.spurious_retransmission
        && !flags.out_of_order
    {
        let mut original: Option<UnackedRange> = None;
        for range in fwd.unacked.iter().rev() {
            if !sequence_before(range.sequence, sequence) {
                original = Some(*range);
            }
        }
        let (time, frame) = match original {
            Some(range) => (range.time, Some(range.frame)),
            None => (fwd.next_seq_time, fwd.next_seq_frame),
        };
        outcome.rto_ns = elapsed(observation.timestamp, time).filter(|nanos| *nanos > 0);
        outcome.rto_frame = outcome.rto_ns.and(frame);
    }

    // Unacked ranges: the peer's current ACK retires or trims its ranges,
    // then this segment joins the sender's ranges for the in-flight span.
    if observation.ack {
        trim_unacked(&mut rev.unacked, observation.acknowledgement);
        fwd.sack_delivered = observation.sack_delivered;
    }
    if payload > 0 || syn_flag || fin {
        if fwd.unacked.len() >= 256 {
            fwd.unacked.clear();
            fwd.valid_bif = false;
        }
        fwd.unacked.push_back(UnackedRange {
            sequence,
            end,
            frame: observation.frame,
            time: observation.timestamp,
        });
    }

    // Bytes in flight span the unacknowledged ranges the sender still has
    // outstanding, minus SACKed bytes and the SYN/FIN virtual byte.
    let sequence_bytes = syn_flag as u32 + u32::from(fin && !syn_flag);
    if payload > 0 {
        if observation.psh && !fwd.push_set_last {
            fwd.push_bytes = fwd.push_bytes.saturating_add(payload);
            fwd.push_set_last = true;
        } else if observation.psh {
            fwd.push_bytes = payload;
            fwd.push_set_last = true;
        } else if fwd.push_set_last {
            fwd.push_bytes = payload;
            fwd.push_set_last = false;
        } else {
            fwd.push_bytes = fwd.push_bytes.saturating_add(payload);
        }
        if options.track_bytes_in_flight && fwd.valid_bif && !lost {
            let first = fwd.unacked.iter().fold(None, |first, range| match first {
                None => Some(range.sequence),
                Some(first) if sequence_before(range.sequence, first) => Some(range.sequence),
                Some(first) => Some(first),
            });
            let last = fwd.unacked.iter().fold(None, |last, range| match last {
                None => Some(range.end),
                Some(last) if sequence_after(range.end, last) => Some(range.end),
                Some(last) => Some(last),
            });
            if let (Some(first), Some(last)) = (first, last)
                && sequence_after(last, first)
            {
                let in_flight = last
                    .wrapping_sub(first)
                    .saturating_sub(rev.sack_delivered)
                    .saturating_sub(sequence_bytes);
                if in_flight > 0 {
                    outcome.bytes_in_flight = Some(in_flight);
                }
            }
            outcome.push_bytes_sent = Some(fwd.push_bytes);
        }
    }

    // State updates.
    fwd.last_keep_alive = flags.keep_alive;
    fwd.last_zero_window_probe = flags.zero_window_probe;
    if lost {
        fwd.valid_bif = false;
    }
    if observation.ack {
        rev.valid_bif = true;
    }
    if fwd.next_seq.is_none_or(|next| sequence_after(end, next)) {
        fwd.last_ack_len = payload;
    }
    if !flags.zero_window_probe {
        fwd.next_seq = Some(match fwd.next_seq {
            Some(next) if sequence_after(end, next) => {
                fwd.next_seq_frame = Some(observation.frame);
                fwd.next_seq_time = observation.timestamp;
                end
            }
            Some(next) => next,
            None => {
                fwd.next_seq_frame = Some(observation.frame);
                fwd.next_seq_time = observation.timestamp;
                end
            }
        });
    }
    if max_end.is_none_or(|max| sequence_after(end, max)) {
        fwd.max_end = Some(end);
    }
    let frontier_advanced = match fwd.max_seqtobeacked {
        None => true,
        Some(frontier) => sequence == frontier,
    };
    if frontier_advanced && !flags.zero_window_probe {
        fwd.max_seqtobeacked = fwd.next_seq;
    }
    outcome.flags = flags;
    // An ordinary segment after a loss carries no analysis when the BIF is
    // invalid and no flag applies; the iRTT goes with it.
    let has_content = flags.any()
        || outcome.acks_frame.is_some()
        || outcome.bytes_in_flight.is_some()
        || outcome.push_bytes_sent.is_some()
        || outcome.duplicate.is_some()
        || outcome.rto_ns.is_some();
    if (!fwd.valid_bif && !has_content)
        || (observation.ack
            && fwd
                .last_ack
                .is_some_and(|last| sequence_before(observation.acknowledgement, last))
            && !has_content)
    {
        outcome.initial_rtt_ns = None;
    }
    outcome
}

/// Retire fully acknowledged ranges and trim a partially acknowledged one.
fn trim_unacked(unacked: &mut VecDeque<UnackedRange>, acknowledgement: u32) {
    let mut index = 0_usize;
    while index < unacked.len() {
        let Some(range) = unacked.get(index).copied() else {
            break;
        };
        if !sequence_before(acknowledgement, range.end) {
            unacked.remove(index);
            continue;
        }
        if sequence_before(range.sequence, acknowledgement)
            && let Some(range) = unacked.get_mut(index)
        {
            range.sequence = acknowledgement;
        }
        index = index.saturating_add(1);
    }
}

/// Update the acknowledgement and window bookkeeping shared by all modes.
fn update_ack_and_window(fwd: &mut TcpDirection, observation: &TcpObservation) {
    if observation.ack && fwd.last_ack != Some(observation.acknowledgement) {
        fwd.last_ack = Some(observation.acknowledgement);
        fwd.last_ack_frame = Some(observation.frame);
        fwd.dup_ack_count = 0;
    }
    fwd.last_window = Some(observation.window);
    fwd.max_window = fwd.max_window.max(observation.window);
    fwd.last_frame = Some(observation.frame);
    fwd.last_time = observation.timestamp;
}

/// Whether the peer's last acknowledgement arrived within the 20 ms
/// fast-retransmission window.
fn within_ack_window(now: Option<Timestamp>, last_ack: Option<Timestamp>) -> bool {
    elapsed(now, last_ack).is_some_and(|nanos| nanos < 20_000_000)
}

/// Whether the previous segment arrived within the out-of-order
/// threshold: the iRTT when known, otherwise 3 ms.
fn within_out_of_order_threshold(
    now: Option<Timestamp>,
    previous: Option<Timestamp>,
    initial_rtt: Option<u64>,
) -> bool {
    elapsed(now, previous).is_some_and(|nanos| nanos < initial_rtt.unwrap_or(3_000_000))
}

/// Nanoseconds between two capture times, when `later` follows `earlier`.
fn elapsed(later: Option<Timestamp>, earlier: Option<Timestamp>) -> Option<u64> {
    let (later, earlier) = (later?, earlier?);
    let seconds = later.seconds.checked_sub(earlier.seconds)?;
    let nanos = i128::from(seconds)
        .checked_mul(1_000_000_000)?
        .checked_add(i128::from(later.nanos))?
        .checked_sub(i128::from(earlier.nanos))?;
    u64::try_from(nanos).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(direction: usize, sequence: u32, payload_len: u32) -> TcpObservation {
        TcpObservation {
            direction,
            sequence,
            acknowledgement: 0,
            window: 65_535,
            payload_len,
            syn: false,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            wscale: None,
            has_sack: false,
            sack_delivered: 0,
            frame: 1,
            timestamp: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            ulp: None,
            payload: Vec::new(),
        }
    }

    fn options() -> TcpAnalysisOptions {
        TcpAnalysisOptions {
            analyze: true,
            relative: true,
            track_bytes_in_flight: true,
            reassemble_out_of_order: false,
            default_window_scaling: -1,
            fastrt_supersedes_ooo: true,
        }
    }

    fn syn(direction: usize, sequence: u32) -> TcpObservation {
        TcpObservation {
            syn: true,
            ..observation(direction, sequence, 0)
        }
    }

    fn ack(direction: usize, sequence: u32, acknowledgement: u32) -> TcpObservation {
        TcpObservation {
            ack: true,
            acknowledgement,
            ..observation(direction, sequence, 0)
        }
    }

    #[test]
    fn relative_sequence_and_window_factor_follow_the_handshake() {
        let mut state = TcpAnalysisState::default();
        let mut options = options();
        options.default_window_scaling = -1;
        let first = state.observe(
            TcpObservation {
                wscale: Some(7),
                ..syn(0, 1_000)
            },
            options,
            0,
            1,
            false,
        );
        assert_eq!(first.relative_seq, Some(0));
        assert_eq!(first.window_size, Some(65_535));
        assert_eq!(first.scale_factor, None);
        let second = state.observe(
            TcpObservation {
                syn: true,
                ack: true,
                acknowledgement: 1_001,
                wscale: Some(2),
                window: 2_048,
                ..observation(1, 5_000, 0)
            },
            options,
            0,
            2,
            false,
        );
        assert_eq!(second.relative_seq, Some(0));
        assert_eq!(second.relative_ack, Some(1));
        assert_eq!(second.scale_factor, None);
        let third = state.observe(ack(0, 1_001, 5_001), options, 0, 3, false);
        assert_eq!(third.relative_seq, Some(1));
        assert_eq!(third.relative_ack, Some(1));
        assert_eq!(third.scale_factor, Some(128));
        assert_eq!(third.analysis.initial_rtt_ns, None);
    }

    #[test]
    fn sequence_numbers_wrap_across_the_32_bit_space() {
        let mut state = TcpAnalysisState::default();
        let options = options();
        let base = 0xffff_fff8_u32;
        let _ = state.observe(
            TcpObservation {
                syn: true,
                wscale: Some(7),
                ..observation(0, base, 0)
            },
            options,
            0,
            1,
            false,
        );
        let _ = state.observe(
            TcpObservation {
                syn: true,
                ack: true,
                acknowledgement: base.wrapping_add(1),
                ..observation(1, 1_000, 0)
            },
            options,
            0,
            2,
            false,
        );
        let _ = state.observe(ack(0, base.wrapping_add(1), 1_001), options, 0, 3, false);
        let data = state.observe(
            TcpObservation {
                ack: true,
                psh: true,
                acknowledgement: 1_001,
                payload_len: 10,
                ..observation(0, base.wrapping_add(1), 10)
            },
            options,
            0,
            4,
            false,
        );
        assert_eq!(data.relative_seq, Some(1));
        assert_eq!(data.next_sequence, Some(11));
        assert!(!data.analysis.flags.retransmission);
        assert!(!data.analysis.flags.lost_segment);
        let retransmission = state.observe(
            TcpObservation {
                ack: true,
                psh: true,
                acknowledgement: 1_001,
                payload_len: 10,
                frame: 5,
                ..observation(0, base.wrapping_add(1), 10)
            },
            options,
            0,
            5,
            false,
        );
        assert!(retransmission.analysis.flags.retransmission);
    }

    #[test]
    fn the_largest_window_scale_stays_within_u32() {
        let mut state = TcpAnalysisState::default();
        let options = options();
        let _ = state.observe(
            TcpObservation {
                syn: true,
                wscale: Some(14),
                window: 65_535,
                ..observation(0, 1_000, 0)
            },
            options,
            0,
            1,
            false,
        );
        let _ = state.observe(
            TcpObservation {
                syn: true,
                ack: true,
                acknowledgement: 1_001,
                ..observation(1, 5_000, 0)
            },
            options,
            0,
            2,
            false,
        );
        let packet = state.observe(
            TcpObservation {
                ack: true,
                window: 65_535,
                ..observation(0, 1_001, 0)
            },
            options,
            0,
            3,
            false,
        );
        assert_eq!(packet.scale_factor, Some(16_384));
        assert_eq!(packet.window_size, Some(65_535 * 16_384));
    }

    #[test]
    fn reassembly_growth_never_exceeds_a_small_session_budget() {
        use crate::state::{ConversationKey, SessionState};
        let mut session = SessionState::new(8_192);
        let mut options = options();
        options.analyze = true;
        for conversation in 0_u16..4 {
            let source = [192, 0, 2, 1];
            let destination = [198, 51, 100, 2];
            let (key, direction) =
                ConversationKey::ipv4(source, 40_000 + conversation, destination, 80);
            for frame in 0..8_u64 {
                let observation = TcpObservation {
                    direction,
                    sequence: 1_000 + u32::try_from(frame).unwrap_or(0) * 1_000,
                    acknowledgement: 5_000,
                    window: 65_535,
                    payload_len: 1_000,
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                    psh: true,
                    wscale: None,
                    has_sack: false,
                    sack_delivered: 0,
                    frame: frame + 1,
                    timestamp: Some(Timestamp {
                        seconds: 1_700_000_000 + i64::try_from(frame).unwrap_or(0),
                        nanos: 0,
                    }),
                    ulp: Some(Ulp::Http),
                    payload: vec![0x41; 1_000],
                };
                let _ = session.tcp_observe(key, observation, options, 1, false);
                assert!(
                    session.used() <= 8_192,
                    "session used {} bytes",
                    session.used()
                );
            }
        }
    }

    fn time(seconds: i64, nanos: u32) -> Timestamp {
        Timestamp { seconds, nanos }
    }

    fn with_time(
        mut observation: TcpObservation,
        seconds: i64,
        nanos: u32,
        frame: u64,
    ) -> TcpObservation {
        observation.timestamp = Some(time(seconds, nanos));
        observation.frame = frame;
        observation
    }

    #[test]
    fn an_out_of_order_segment_uses_the_irtt_threshold() {
        let mut state = TcpAnalysisState::default();
        let options = options();
        let step = |state: &mut TcpAnalysisState, observation: TcpObservation, frame: u64| {
            state.observe(
                observation,
                options,
                0,
                u32::try_from(frame).unwrap_or(u32::MAX),
                false,
            )
        };
        let _ = step(&mut state, with_time(syn(0, 1_000), 0, 0, 1), 1);
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    syn: true,
                    ack: true,
                    acknowledgement: 1_001,
                    ..observation(1, 5_000, 0)
                },
                0,
                1_000_000,
                2,
            ),
            2,
        );
        let _ = step(
            &mut state,
            with_time(ack(0, 1_001, 5_001), 0, 2_000_000, 3),
            3,
        );
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_001, 10)
                },
                0,
                3_000_000,
                4,
            ),
            4,
        );
        let lost = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_021, 10)
                },
                0,
                4_000_000,
                5,
            ),
            5,
        );
        assert!(lost.analysis.flags.lost_segment);
        let _ = step(&mut state, with_time(ack(1, 1, 1_011), 0, 5_000_000, 6), 6);
        let reordered = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_011, 10)
                },
                0,
                5_500_000,
                7,
            ),
            7,
        );
        assert!(reordered.analysis.flags.out_of_order);
        assert!(!reordered.analysis.flags.retransmission);
        assert!(reordered.analysis.rto_ns.is_none());
    }

    #[test]
    fn fast_retransmission_requires_a_recent_ack() {
        let mut state = TcpAnalysisState::default();
        let options = options();
        let step = |state: &mut TcpAnalysisState, observation: TcpObservation, frame: u64| {
            state.observe(
                observation,
                options,
                0,
                u32::try_from(frame).unwrap_or(u32::MAX),
                false,
            )
        };
        let _ = step(&mut state, with_time(syn(0, 1_000), 0, 0, 1), 1);
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    syn: true,
                    ack: true,
                    acknowledgement: 1_001,
                    ..observation(1, 5_000, 0)
                },
                0,
                1_000_000,
                2,
            ),
            2,
        );
        let _ = step(
            &mut state,
            with_time(ack(0, 1_001, 5_001), 0, 2_000_000, 3),
            3,
        );
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_001, 10)
                },
                0,
                3_000_000,
                4,
            ),
            4,
        );
        for frame in 5..8_u64 {
            let nanos = 4_000_000 + u32::try_from(frame - 5).unwrap_or(0) * 100_000;
            let _ = step(
                &mut state,
                with_time(
                    TcpObservation {
                        ack: true,
                        acknowledgement: 1_001,
                        ..observation(1, 5_001, 0)
                    },
                    0,
                    nanos,
                    frame,
                ),
                frame,
            );
        }
        let late = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_001, 10)
                },
                0,
                30_000_000,
                8,
            ),
            8,
        );
        assert!(late.analysis.flags.retransmission);
        assert!(!late.analysis.flags.fast_retransmission);
    }

    #[test]
    fn ack_attribution_uses_the_original_and_rejects_beyond_seen_data() {
        let mut state = TcpAnalysisState::default();
        let options = options();
        let step = |state: &mut TcpAnalysisState, observation: TcpObservation, frame: u64| {
            state.observe(
                observation,
                options,
                0,
                u32::try_from(frame).unwrap_or(u32::MAX),
                false,
            )
        };
        let _ = step(&mut state, with_time(syn(0, 1_000), 0, 0, 1), 1);
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    syn: true,
                    ack: true,
                    acknowledgement: 1_001,
                    ..observation(1, 5_000, 0)
                },
                0,
                1_000_000,
                2,
            ),
            2,
        );
        let _ = step(
            &mut state,
            with_time(ack(0, 1_001, 5_001), 0, 2_000_000, 3),
            3,
        );
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_001, 10)
                },
                0,
                3_000_000,
                4,
            ),
            4,
        );
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_001, 10)
                },
                0,
                4_000_000,
                5,
            ),
            5,
        );
        let acknowledgement = step(
            &mut state,
            with_time(ack(1, 5_001, 1_011), 0, 6_000_000, 6),
            6,
        );
        assert_eq!(acknowledgement.analysis.acks_frame, Some(4));
        assert_eq!(acknowledgement.analysis.ack_rtt_ns, Some(3_000_000));
        let beyond = step(
            &mut state,
            with_time(ack(1, 5_001, 6_001), 0, 7_000_000, 7),
            7,
        );
        assert!(beyond.analysis.acks_frame.is_none());
        assert!(beyond.analysis.flags.ack_lost_segment);
    }

    #[test]
    fn in_flight_bytes_pause_after_a_gap_and_resume_after_an_ack() {
        let mut state = TcpAnalysisState::default();
        let options = options();
        let step = |state: &mut TcpAnalysisState, observation: TcpObservation, frame: u64| {
            state.observe(
                observation,
                options,
                0,
                u32::try_from(frame).unwrap_or(u32::MAX),
                false,
            )
        };
        let _ = step(&mut state, with_time(syn(0, 1_000), 0, 0, 1), 1);
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    syn: true,
                    ack: true,
                    acknowledgement: 1_001,
                    ..observation(1, 5_000, 0)
                },
                0,
                1_000_000,
                2,
            ),
            2,
        );
        let _ = step(
            &mut state,
            with_time(ack(0, 1_001, 5_001), 0, 2_000_000, 3),
            3,
        );
        let first = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_001, 10)
                },
                0,
                3_000_000,
                4,
            ),
            4,
        );
        assert_eq!(first.analysis.bytes_in_flight, Some(10));
        let _ = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_021, 10)
                },
                0,
                4_000_000,
                5,
            ),
            5,
        );
        let fill = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_011, 10)
                },
                0,
                5_000_000,
                6,
            ),
            6,
        );
        assert!(fill.analysis.bytes_in_flight.is_none());
        let _ = step(
            &mut state,
            with_time(ack(1, 5_001, 1_031), 0, 6_000_000, 7),
            7,
        );
        let resumed = step(
            &mut state,
            with_time(
                TcpObservation {
                    ack: true,
                    psh: true,
                    acknowledgement: 5_001,
                    payload_len: 10,
                    ..observation(0, 1_031, 10)
                },
                0,
                7_000_000,
                8,
            ),
            8,
        );
        assert_eq!(resumed.analysis.bytes_in_flight, Some(10));
    }

    #[test]
    fn a_midstream_direction_has_an_unknown_window_factor() {
        let mut state = TcpAnalysisState::default();
        let packet = state.observe(observation(0, 7_777, 5), options(), 0, 1, false);
        assert_eq!(packet.relative_seq, Some(1));
        assert_eq!(packet.scale_factor, Some(-1));
        assert_eq!(packet.window_size, Some(65_535));
    }

    #[test]
    fn quoted_headers_do_not_seed_or_analyse_state() {
        let mut state = TcpAnalysisState::default();
        let packet = state.observe(observation(0, 7_777, 5), options(), 0, 1, true);
        assert_eq!(packet.relative_seq, None);
        assert!(packet.analysis.flags == AnalysisFlags::default());
        assert_eq!(packet.scale_factor, Some(-1));
        assert!(state.direction(0).and_then(TcpDirection::base).is_none());
    }

    #[test]
    fn a_retransmission_is_flagged_and_times_the_original() {
        let mut state = TcpAnalysisState::default();
        let mut options = options();
        options.reassemble_out_of_order = false;
        let _ = state.observe(syn(0, 1_000), options, 0, 1, false);
        let _ = state.observe(
            TcpObservation {
                syn: true,
                ack: true,
                acknowledgement: 1_001,
                ..observation(1, 5_000, 0)
            },
            options,
            0,
            2,
            false,
        );
        let _ = state.observe(ack(0, 1_001, 5_001), options, 0, 3, false);
        let first = state.observe(
            TcpObservation {
                ack: true,
                psh: true,
                acknowledgement: 5_001,
                payload_len: 10,
                frame: 4,
                timestamp: Some(Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 0,
                }),
                ..observation(0, 1_001, 10)
            },
            options,
            0,
            4,
            false,
        );
        assert!(!first.analysis.flags.retransmission);
        let retransmission = state.observe(
            TcpObservation {
                ack: true,
                psh: true,
                acknowledgement: 5_001,
                payload_len: 10,
                frame: 5,
                timestamp: Some(Timestamp {
                    seconds: 1_700_000_002,
                    nanos: 0,
                }),
                ..observation(0, 1_001, 10)
            },
            options,
            0,
            5,
            false,
        );
        assert!(retransmission.analysis.flags.retransmission);
        assert_eq!(retransmission.analysis.rto_frame, Some(4));
        assert_eq!(retransmission.analysis.rto_ns, Some(1_000_000_000));
    }
}
