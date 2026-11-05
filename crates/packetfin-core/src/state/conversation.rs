//! TCP and UDP conversations and their stream numbers.
//!
//! A conversation is the direction-independent transport tuple: both IP
//! addresses and both ports, under the IP version they arrived on.
//!
//! Stream numbers are assigned in first-seen order and never reused. TCP
//! keeps one sequence base per direction and remembers whether a FIN or RST
//! ended the conversation. A SYN starts a new conversation/stream only when
//! that direction already has a base and either its sequence differs from the
//! base or the previous conversation was reset or closed. An ACK seeds the
//! reverse direction's base from its acknowledgement number, so a capture
//! that begins with a SYN+ACK or a bare ACK still classifies a later SYN as a
//! retransmission or a reused port.
//!
//! Quoted ICMP headers still take part in stream assignment, but they never
//! initialise the analysis bases: a quoted SYN consumes a stream number
//! without seeding sequence state.

use super::SessionState;
use super::budget::StateValue;
use super::tcp::{TcpAnalysisOptions, TcpAnalysisState, TcpObservation, TcpPacketState};
use crate::capture::Timestamp;

/// One direction-independent conversation key.
///
/// The endpoints are sorted, so the two directions of a tuple build the same
/// key. IPv4 and IPv6 keys never compare equal even when their bytes do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ConversationKey {
    /// Two IPv4 endpoints, ordered by address and then port.
    Ipv4 {
        /// The lower endpoint.
        low: Endpoint4,
        /// The higher endpoint.
        high: Endpoint4,
    },
    /// Two IPv6 endpoints, ordered by address and then port.
    Ipv6 {
        /// The lower endpoint.
        low: Endpoint6,
        /// The higher endpoint.
        high: Endpoint6,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Endpoint4 {
    address: [u8; 4],
    port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Endpoint6 {
    address: [u8; 16],
    port: u16,
}

impl ConversationKey {
    /// Build an IPv4 conversation key and identify the source's direction.
    ///
    /// The direction is zero when the source is the canonical lower endpoint
    /// and one when it is the higher one. A tuple whose endpoints are equal
    /// has one direction only.
    pub(crate) fn ipv4(
        source: [u8; 4],
        source_port: u16,
        destination: [u8; 4],
        destination_port: u16,
    ) -> (Self, usize) {
        let source = Endpoint4 {
            address: source,
            port: source_port,
        };
        let destination = Endpoint4 {
            address: destination,
            port: destination_port,
        };
        if destination < source {
            (
                Self::Ipv4 {
                    low: destination,
                    high: source,
                },
                1,
            )
        } else {
            (
                Self::Ipv4 {
                    low: source,
                    high: destination,
                },
                0,
            )
        }
    }

    /// Build an IPv6 conversation key and identify the source's direction.
    pub(crate) fn ipv6(
        source: [u8; 16],
        source_port: u16,
        destination: [u8; 16],
        destination_port: u16,
    ) -> (Self, usize) {
        let source = Endpoint6 {
            address: source,
            port: source_port,
        };
        let destination = Endpoint6 {
            address: destination,
            port: destination_port,
        };
        if destination < source {
            (
                Self::Ipv6 {
                    low: destination,
                    high: source,
                },
                1,
            )
        } else {
            (
                Self::Ipv6 {
                    low: source,
                    high: destination,
                },
                0,
            )
        }
    }
}

/// One TCP segment's sequence, acknowledgement, flags and direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TcpSegment {
    /// Canonical endpoint direction of the sender.
    pub(crate) direction: usize,
    /// Sequence number from the header.
    pub(crate) sequence: u32,
    /// Acknowledgement number from the header.
    pub(crate) acknowledgement: u32,
    /// SYN flag.
    pub(crate) syn: bool,
    /// ACK flag.
    pub(crate) ack: bool,
    /// FIN flag.
    pub(crate) fin: bool,
    /// RST flag.
    pub(crate) rst: bool,
}

/// The stream number and packet number assigned to one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamAssignment {
    /// Zero-based stream index; never reused within a session.
    pub(crate) index: u32,
    /// One-based packet number within the stream, including this packet.
    pub(crate) packet_number: u32,
}

/// State retained for one TCP conversation.
#[derive(Debug)]
pub(crate) struct TcpConversation {
    stream: u32,
    packets: u32,
    /// Sequence bases, analysis and reassembly for the two endpoints.
    ///
    /// Boxed so a conversation keeps its inline size (and the per-entry
    /// charge shared with UDP) unchanged; the boxed allocation is part of
    /// `state_bytes`.
    analysis: Box<TcpAnalysisState>,
    /// Whether this conversation has seen a FIN or RST.
    saw_rst_or_fin: bool,
}

/// Whether a SYN continues the existing conversation or starts a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// Keep the existing stream number and state.
    Keep,
    /// Replace the conversation with a new stream number.
    Restart,
}

impl TcpConversation {
    fn new(stream: u32) -> Self {
        Self {
            stream,
            packets: 0,
            analysis: Box::new(TcpAnalysisState::default()),
            saw_rst_or_fin: false,
        }
    }

    /// Record one segment and report whether its SYN reuses the ports.
    ///
    /// The restart check runs even for quoted headers, so a reused tuple is
    /// detected inside an ICMP error. Quoted headers skip the analysis
    /// updates (bases and the FIN/RST marker) because they are not traffic.
    fn observe(&mut self, segment: TcpSegment, quoted: bool) -> Disposition {
        if segment.syn
            && let Some(base) = self
                .analysis
                .direction(segment.direction)
                .and_then(|endpoint| endpoint.base())
            && (segment.sequence != base || self.saw_rst_or_fin)
        {
            return Disposition::Restart;
        }
        if !quoted {
            self.analysis
                .seed_base(segment.direction, segment.sequence, segment.syn);
            if segment.ack {
                self.analysis
                    .seed_reverse_base(segment.direction, segment.acknowledgement);
            }
            // A FIN on a SYN packet is invalid and does not terminate the
            // conversation, but a RST still ends it. A standalone FIN or RST
            // always marks the conversation closed.
        }
        // A FIN only closes a conversation when it acknowledges data; a bare
        // FIN is ignored. RST always closes. Quoted headers contribute this
        // closure state even though they do not seed sequence bases.
        self.saw_rst_or_fin |= segment.rst || (segment.fin && segment.ack);
        Disposition::Keep
    }
}

impl StateValue for TcpConversation {
    fn state_bytes(&self) -> usize {
        std::mem::size_of::<TcpAnalysisState>() + self.analysis.heap_bytes()
    }
}

/// State retained for one UDP conversation.
#[derive(Debug)]
pub(crate) struct UdpConversation {
    stream: u32,
    packets: u32,
    /// First captured timestamp in this conversation, as epoch nanoseconds.
    ///
    /// `NO_UDP_TIME` means the conversation has no timestamped datagram yet.
    first_time: u64,
    /// Previous captured timestamp, as epoch nanoseconds.
    last_time: u64,
}

/// Sentinel for a UDP conversation without a captured timestamp.
const NO_UDP_TIME: u64 = u64::MAX;

/// Per-stream timing values for one UDP datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UdpTimes {
    /// Time since the first timestamped datagram in the stream.
    pub(crate) relative: Option<i64>,
    /// Time since the previous timestamped datagram in the stream.
    pub(crate) delta: Option<i64>,
}

/// Convert a capture timestamp to epoch nanoseconds for stream timing.
fn timestamp_nanos(timestamp: Timestamp) -> Option<u64> {
    let nanos = i128::from(timestamp.seconds)
        .checked_mul(1_000_000_000)?
        .checked_add(i128::from(timestamp.nanos))?;
    u64::try_from(nanos).ok()
}

impl UdpConversation {
    /// Fold one datagram's timestamp into the stream timing values.
    fn observe_time(&mut self, time: Option<u64>) -> UdpTimes {
        let Some(time) = time else {
            return UdpTimes::default();
        };
        let relative = if self.first_time == NO_UDP_TIME {
            self.first_time = time;
            0
        } else {
            signed_difference(time, self.first_time)
        };
        let delta = if self.last_time == NO_UDP_TIME {
            0
        } else {
            signed_difference(time, self.last_time)
        };
        self.last_time = time;
        UdpTimes {
            relative: Some(relative),
            delta: Some(delta),
        }
    }
}

fn signed_difference(later: u64, earlier: u64) -> i64 {
    let difference = i128::from(later) - i128::from(earlier);
    i64::try_from(difference).unwrap_or(if difference < 0 { i64::MIN } else { i64::MAX })
}

impl StateValue for UdpConversation {
    fn state_bytes(&self) -> usize {
        0
    }
}

/// Conversation kind and tuple, so TCP and UDP share one LRU and budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ConversationStateKey {
    /// A TCP conversation.
    Tcp(ConversationKey),
    /// A UDP conversation.
    Udp(ConversationKey),
}

/// A retained TCP or UDP conversation.
#[derive(Debug)]
pub(crate) enum ConversationState {
    /// TCP sequencing and stream state.
    Tcp(TcpConversation),
    /// UDP stream state.
    Udp(UdpConversation),
}

impl StateValue for ConversationState {
    fn state_bytes(&self) -> usize {
        match self {
            Self::Tcp(conversation) => conversation.state_bytes(),
            Self::Udp(conversation) => conversation.state_bytes(),
        }
    }
}

impl SessionState {
    /// Analyse one TCP segment, returning its stream number, relative
    /// sequence facts, analysis flags and reassembly result.
    ///
    /// This is the decoder path: one conversation lookup serves stream
    /// numbering, analysis and reassembly. The conversation is recharged
    /// after the update because reassembly can grow its retained bytes.
    pub(crate) fn tcp_observe(
        &mut self,
        key: ConversationKey,
        observation: TcpObservation,
        options: TcpAnalysisOptions,
        file: u64,
        quoted: bool,
    ) -> TcpPacketState {
        let direction = observation.direction.min(1);
        let segment = TcpSegment {
            direction,
            sequence: observation.sequence,
            acknowledgement: observation.acknowledgement,
            syn: observation.syn,
            ack: observation.ack,
            fin: observation.fin,
            rst: observation.rst,
        };
        let Self {
            budget,
            conversations,
            next_tcp_stream,
            ..
        } = self;
        let store_key = ConversationStateKey::Tcp(key);
        if let Some(ConversationState::Tcp(conversation)) =
            conversations.get_mut_for_conversation(budget, &store_key)
        {
            if conversation.observe(segment, quoted) == Disposition::Keep {
                conversation.packets = conversation.packets.saturating_add(1);
                let stream = conversation.stream;
                let packet_number = conversation.packets;
                let state = conversation.analysis.observe_with_file(
                    observation,
                    options,
                    stream,
                    packet_number,
                    file,
                    quoted,
                );
                conversations.recharge_for_conversation(budget, &store_key);
                conversations.shrink_to_fit(budget, &store_key);
                return state;
            }
            conversations.take_for_conversation(budget, &store_key);
            let mut replacement = TcpConversation::new(next_stream(next_tcp_stream));
            replacement.observe(segment, quoted);
            replacement.analysis.mark_reused_ports();
            replacement.packets = 1;
            let state = replacement.analysis.observe_with_file(
                observation,
                options,
                replacement.stream,
                replacement.packets,
                file,
                quoted,
            );
            let state = TcpPacketState {
                stream: replacement.stream,
                packet_number: replacement.packets,
                ..state
            };
            conversations.put_for_conversation(
                budget,
                store_key,
                ConversationState::Tcp(replacement),
            );
            return state;
        }

        let mut conversation = TcpConversation::new(next_stream(next_tcp_stream));
        conversation.observe(segment, quoted);
        conversation.packets = 1;
        let state = conversation.analysis.observe_with_file(
            observation,
            options,
            conversation.stream,
            conversation.packets,
            file,
            quoted,
        );
        conversations.put_for_conversation(budget, store_key, ConversationState::Tcp(conversation));
        state
    }

    /// The PDU size a segment declares when desegmentation is disabled.
    pub(crate) fn tcp_standalone_pdu(
        &mut self,
        key: ConversationKey,
        direction: usize,
        sequence: u32,
        ulp: Option<crate::state::Ulp>,
        payload: &[u8],
    ) -> Option<u32> {
        let Self {
            budget,
            conversations,
            ..
        } = self;
        let store_key = ConversationStateKey::Tcp(key);
        let Some(ConversationState::Tcp(conversation)) =
            conversations.get_mut_for_conversation(budget, &store_key)
        else {
            return None;
        };
        conversation
            .analysis
            .standalone_pdu_size(direction, sequence, ulp, payload)
    }

    /// The sequence bases for one segment's conversation direction.
    ///
    /// Used when a header is too short for full analysis but still carries
    /// the sequence and acknowledgement fields, which are numbered relative
    /// to the conversation.
    pub(crate) fn tcp_relative_bases(
        &mut self,
        key: ConversationKey,
        direction: usize,
    ) -> (Option<u32>, Option<u32>) {
        let Self {
            budget,
            conversations,
            ..
        } = self;
        let store_key = ConversationStateKey::Tcp(key);
        let Some(ConversationState::Tcp(conversation)) =
            conversations.get_mut_for_conversation(budget, &store_key)
        else {
            return (None, None);
        };
        let direction = direction.min(1);
        let forward = conversation
            .analysis
            .direction(direction)
            .and_then(|endpoint| endpoint.base());
        let reverse = conversation
            .analysis
            .direction(direction ^ 1)
            .and_then(|endpoint| endpoint.base());
        (forward, reverse)
    }

    /// Return the TCP stream assignment for one segment.
    ///
    /// Quoted ICMP headers are still classified: the TCP header inside an
    /// error message is assigned a stream number and consumes it, so the
    /// quoted gate covers analysis and reassembly state only.
    pub(crate) fn tcp_stream(
        &mut self,
        key: ConversationKey,
        segment: TcpSegment,
        quoted: bool,
    ) -> StreamAssignment {
        let Self {
            budget,
            conversations,
            next_tcp_stream,
            ..
        } = self;
        let store_key = ConversationStateKey::Tcp(key);
        if let Some(ConversationState::Tcp(conversation)) =
            conversations.get_mut_for_conversation(budget, &store_key)
        {
            if conversation.observe(segment, quoted) == Disposition::Keep {
                conversation.packets = conversation.packets.saturating_add(1);
                return StreamAssignment {
                    index: conversation.stream,
                    packet_number: conversation.packets,
                };
            }
            // A SYN reused the ports: the old stream ends here and a new one
            // starts, without ever reusing the old number.
            conversations.take_for_conversation(budget, &store_key);
            let mut replacement = TcpConversation::new(next_stream(next_tcp_stream));
            replacement.observe(segment, quoted);
            replacement.packets = 1;
            let assignment = StreamAssignment {
                index: replacement.stream,
                packet_number: replacement.packets,
            };
            conversations.put_for_conversation(
                budget,
                store_key,
                ConversationState::Tcp(replacement),
            );
            return assignment;
        }

        let mut conversation = TcpConversation::new(next_stream(next_tcp_stream));
        conversation.observe(segment, quoted);
        conversation.packets = 1;
        let assignment = StreamAssignment {
            index: conversation.stream,
            packet_number: conversation.packets,
        };
        conversations.put_for_conversation(budget, store_key, ConversationState::Tcp(conversation));
        assignment
    }

    /// Return the UDP stream assignment for one datagram.
    ///
    /// A quoted header creates or joins its conversation and takes a stream
    /// number, but it does not count as a stream packet: the quote emits no
    /// packet number and the next real datagram is packet one.
    #[cfg(test)]
    pub(crate) fn udp_stream(&mut self, key: ConversationKey, quoted: bool) -> StreamAssignment {
        self.udp_stream_timed(key, quoted, None).0
    }

    /// Return the UDP stream assignment and stream timing for one datagram.
    ///
    /// A quoted header creates or joins its conversation and takes a stream
    /// number, but it does not count as a stream packet and does not advance
    /// the stream's timing.
    pub(crate) fn udp_stream_timed(
        &mut self,
        key: ConversationKey,
        quoted: bool,
        timestamp: Option<Timestamp>,
    ) -> (StreamAssignment, UdpTimes) {
        let time = if quoted {
            None
        } else {
            timestamp.and_then(timestamp_nanos)
        };
        let Self {
            budget,
            conversations,
            next_udp_stream,
            ..
        } = self;
        let store_key = ConversationStateKey::Udp(key);
        if let Some(ConversationState::Udp(conversation)) =
            conversations.get_mut_for_conversation(budget, &store_key)
        {
            if !quoted {
                conversation.packets = conversation.packets.saturating_add(1);
            }
            let times = conversation.observe_time(time);
            return (
                StreamAssignment {
                    index: conversation.stream,
                    packet_number: conversation.packets,
                },
                times,
            );
        }

        let mut conversation = UdpConversation {
            stream: next_stream(next_udp_stream),
            packets: u32::from(!quoted),
            first_time: NO_UDP_TIME,
            last_time: NO_UDP_TIME,
        };
        let times = conversation.observe_time(time);
        let assignment = StreamAssignment {
            index: conversation.stream,
            packet_number: conversation.packets,
        };
        conversations.put_for_conversation(budget, store_key, ConversationState::Udp(conversation));
        (assignment, times)
    }
}

/// Take the next stream number from a session counter.
fn next_stream(counter: &mut u32) -> u32 {
    let stream = *counter;
    *counter = counter.saturating_add(1);
    stream
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DEFAULT_STATE_BUDGET, SessionState, StateStore};

    const SOURCE: [u8; 4] = [192, 0, 2, 1];
    const DESTINATION: [u8; 4] = [198, 51, 100, 2];
    const OTHER: [u8; 4] = [203, 0, 113, 9];
    const SOURCE6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DESTINATION6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    fn tcp_key(source_port: u16, destination_port: u16) -> (ConversationKey, usize) {
        ConversationKey::ipv4(SOURCE, source_port, DESTINATION, destination_port)
    }

    fn reverse_tcp_key(source_port: u16, destination_port: u16) -> (ConversationKey, usize) {
        ConversationKey::ipv4(DESTINATION, source_port, SOURCE, destination_port)
    }

    fn plain(direction: usize, sequence: u32) -> TcpSegment {
        TcpSegment {
            direction,
            sequence,
            acknowledgement: 0,
            syn: false,
            ack: false,
            fin: false,
            rst: false,
        }
    }

    fn syn(direction: usize, sequence: u32) -> TcpSegment {
        TcpSegment {
            syn: true,
            ..plain(direction, sequence)
        }
    }

    fn syn_ack(direction: usize, sequence: u32, acknowledgement: u32) -> TcpSegment {
        TcpSegment {
            syn: true,
            ack: true,
            acknowledgement,
            ..plain(direction, sequence)
        }
    }

    fn ack(direction: usize, sequence: u32, acknowledgement: u32) -> TcpSegment {
        TcpSegment {
            ack: true,
            acknowledgement,
            ..plain(direction, sequence)
        }
    }

    fn finish(direction: usize, sequence: u32, reset: bool) -> TcpSegment {
        TcpSegment {
            ack: true,
            fin: !reset,
            rst: reset,
            acknowledgement: 9_001,
            ..plain(direction, sequence)
        }
    }

    fn assignment(
        state: &mut SessionState,
        key: ConversationKey,
        segment: TcpSegment,
        quoted: bool,
    ) -> StreamAssignment {
        state.tcp_stream(key, segment, quoted)
    }

    fn base(conversation: &TcpConversation, direction: usize) -> Option<u32> {
        conversation
            .analysis
            .direction(direction)
            .and_then(|endpoint| endpoint.base())
    }

    #[test]
    fn ipv4_keys_are_direction_independent() {
        let (forward, forward_direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assert_eq!(forward, reverse);
        assert_eq!(forward_direction, 0);
        assert_eq!(reverse_direction, 1);
    }

    #[test]
    fn ipv4_and_ipv6_keys_never_collide() {
        let (v4, _) = ConversationKey::ipv4(SOURCE, 1, DESTINATION, 2);
        let (v6, _) = ConversationKey::ipv6(SOURCE6, 1, DESTINATION6, 2);
        assert_ne!(v4, v6);
        let (v6_reverse, _) = ConversationKey::ipv6(DESTINATION6, 2, SOURCE6, 1);
        assert_eq!(v6, v6_reverse);
    }

    #[test]
    fn the_reverse_direction_shares_a_stream() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assert_eq!(
            assignment(
                &mut state,
                reverse,
                syn_ack(reverse_direction, 9_000, 1_001),
                false
            ),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
        assert_eq!(
            assignment(&mut state, key, ack(direction, 1_001, 9_001), false),
            StreamAssignment {
                index: 0,
                packet_number: 3
            }
        );
    }

    #[test]
    fn a_retransmitted_syn_keeps_its_stream_and_a_new_isn_restarts() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false).index,
            0
        );
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
        assert_eq!(
            assignment(&mut state, key, syn(direction, 2_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn a_fin_on_a_syn_does_not_end_the_conversation_but_a_rst_does() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let syn_fin = TcpSegment {
            syn: true,
            fin: true,
            ..plain(direction, 1_000)
        };
        assert_eq!(
            assignment(&mut state, key, syn_fin, false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        assert_eq!(
            assignment(&mut state, key, syn_fin, false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 3
            }
        );

        let mut reset = SessionState::new(1 << 20);
        let syn_rst = TcpSegment {
            syn: true,
            rst: true,
            ..plain(direction, 1_000)
        };
        assignment(&mut reset, key, syn_rst, false);
        assert_eq!(
            assignment(&mut reset, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn a_bare_fin_does_not_close_the_conversation() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assignment(&mut state, key, syn(direction, 1_000), false);
        assignment(
            &mut state,
            reverse,
            syn_ack(reverse_direction, 9_000, 1_001),
            false,
        );
        assignment(&mut state, key, ack(direction, 1_001, 9_001), false);
        assignment(
            &mut state,
            key,
            TcpSegment {
                fin: true,
                ..plain(direction, 1_001)
            },
            false,
        );
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 5
            }
        );
    }

    #[test]
    fn a_syn_fin_ack_closes_the_conversation() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let syn_fin_ack = TcpSegment {
            syn: true,
            fin: true,
            ack: true,
            ..plain(direction, 1_000)
        };
        assignment(&mut state, key, syn_fin_ack, false);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn a_quoted_fin_ack_closes_the_conversation() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assignment(&mut state, key, syn(direction, 1_000), false);
        assignment(
            &mut state,
            reverse,
            syn_ack(reverse_direction, 9_000, 1_001),
            false,
        );
        assignment(&mut state, key, ack(direction, 1_001, 9_001), false);
        assignment(&mut state, key, finish(direction, 1_001, false), true);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn a_quoted_rst_closes_the_conversation() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assignment(&mut state, key, syn(direction, 1_000), false);
        assignment(
            &mut state,
            reverse,
            syn_ack(reverse_direction, 9_000, 1_001),
            false,
        );
        assignment(&mut state, key, ack(direction, 1_001, 9_001), false);
        assignment(&mut state, key, finish(direction, 1_001, true), true);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn a_half_open_syn_ack_seeds_the_reverse_base() {
        let mut state = SessionState::new(1 << 20);
        let (key, _) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assert_eq!(
            assignment(
                &mut state,
                reverse,
                syn_ack(reverse_direction, 9_000, 1_001),
                false
            ),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        let (_, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 5_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn an_ack_seeds_both_direction_bases() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        assignment(&mut state, key, ack(direction, 1_001, 1_001), false);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
    }

    #[test]
    fn a_matching_syn_after_data_stays_in_the_conversation() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assignment(
            &mut state,
            reverse,
            syn_ack(reverse_direction, 9_000, 1_001),
            false,
        );
        assignment(&mut state, key, ack(direction, 1_001, 0), false);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 3
            }
        );
    }

    #[test]
    fn a_fin_makes_a_repeated_syn_start_a_new_stream() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assignment(&mut state, key, syn(direction, 1_000), false);
        assignment(
            &mut state,
            reverse,
            syn_ack(reverse_direction, 9_000, 1_001),
            false,
        );
        assignment(&mut state, key, ack(direction, 1_001, 9_001), false);
        assignment(&mut state, key, finish(direction, 1_001, false), false);
        assignment(&mut state, key, ack(direction, 1_002, 9_001), false);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn an_rst_makes_a_repeated_syn_start_a_new_stream() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        let (reverse, reverse_direction) = reverse_tcp_key(443, 40_000);
        assignment(&mut state, key, syn(direction, 1_000), false);
        assignment(
            &mut state,
            reverse,
            syn_ack(reverse_direction, 9_000, 1_001),
            false,
        );
        assignment(&mut state, key, ack(direction, 1_001, 9_001), false);
        assignment(&mut state, key, finish(direction, 1_001, true), false);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
    }

    #[test]
    fn midstream_bases_come_from_sequence_and_ack() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = ConversationKey::ipv4(OTHER, 40_000, DESTINATION, 7_777);
        assert_eq!(
            assignment(&mut state, key, ack(direction, 7_777, 5_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        let stored = state
            .conversations
            .peek(&ConversationStateKey::Tcp(key))
            .and_then(|state| match state {
                ConversationState::Tcp(conversation) => Some(conversation),
                ConversationState::Udp(_) => None,
            });
        assert!(stored.is_some(), "conversation is retained");
        let Some(stored) = stored else {
            return;
        };
        assert_eq!(base(stored, direction), Some(7_776));
        assert_eq!(base(stored, direction ^ 1), Some(4_999));

        assert_eq!(
            assignment(&mut state, key, ack(direction ^ 1, 8_888, 7_780), false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
        let stored = state
            .conversations
            .peek(&ConversationStateKey::Tcp(key))
            .and_then(|state| match state {
                ConversationState::Tcp(conversation) => Some(conversation),
                ConversationState::Udp(_) => None,
            });
        assert!(stored.is_some(), "conversation disappeared");
        let Some(stored) = stored else {
            return;
        };
        assert_eq!(base(stored, direction), Some(7_776));
        assert_eq!(base(stored, direction ^ 1), Some(4_999));
    }

    #[test]
    fn quoted_syns_do_not_seed_bases() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), true),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        assert_eq!(
            assignment(&mut state, key, syn(direction, 2_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );

        let mut repeated = SessionState::new(1 << 20);
        assignment(&mut repeated, key, syn(direction, 1_000), true);
        assignment(&mut repeated, key, syn(direction, 2_000), true);
        assert_eq!(
            assignment(&mut repeated, key, syn(direction, 3_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 3
            }
        );

        let mut after_ack = SessionState::new(1 << 20);
        assignment(&mut after_ack, key, ack(direction, 1_001, 1_001), false);
        assert_eq!(
            assignment(&mut after_ack, key, syn(direction, 1_000), true),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );

        let mut after_syn = SessionState::new(1 << 20);
        assignment(&mut after_syn, key, syn(direction, 1_000), false);
        assert_eq!(
            assignment(&mut after_syn, key, syn(direction, 2_000), true),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
        assert_eq!(
            assignment(&mut after_syn, key, syn(direction, 3_000), false),
            StreamAssignment {
                index: 1,
                packet_number: 2
            }
        );
    }

    #[test]
    fn udp_changes_the_key_and_the_reverse_direction_shares() {
        let mut state = SessionState::new(1 << 20);
        let (key, _) = tcp_key(5_000, 6_000);
        assert_eq!(
            state.udp_stream(key, false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        let (reverse, _) = reverse_tcp_key(6_000, 5_000);
        assert_eq!(
            state.udp_stream(reverse, false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
        let (new_port, _) = tcp_key(5_000, 6_001);
        assert_eq!(
            state.udp_stream(new_port, false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
        let (moved, _) = ConversationKey::ipv4(OTHER, 5_000, DESTINATION, 6_000);
        assert_eq!(
            state.udp_stream(moved, false),
            StreamAssignment {
                index: 2,
                packet_number: 1
            }
        );
    }

    #[test]
    fn tcp_and_udp_counters_are_separate() {
        let mut state = SessionState::new(1 << 20);
        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 100), false).index,
            0
        );
        assert_eq!(state.udp_stream(key, false).index, 0);
    }

    #[test]
    fn a_tcp_put_evicts_an_older_udp_conversation() {
        let udp_charge = StateStore::<ConversationStateKey, ConversationState>::charge_for(
            &ConversationState::Udp(UdpConversation {
                stream: 0,
                packets: 0,
                first_time: NO_UDP_TIME,
                last_time: NO_UDP_TIME,
            }),
        );
        let tcp_charge = StateStore::<ConversationStateKey, ConversationState>::charge_for(
            &ConversationState::Tcp(TcpConversation::new(0)),
        );
        let budget = udp_charge
            .saturating_mul(2)
            .saturating_add(tcp_charge)
            .saturating_sub(1);
        let mut state = SessionState::new(budget);
        for offset in 0..2_u16 {
            let (key, _) = tcp_key(5_000 + offset, 6_000);
            state.udp_stream(key, false);
        }
        assert_eq!(state.used(), udp_charge.saturating_mul(2));

        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        assert_eq!(
            assignment(&mut state, key, ack(direction, 1_001, 0), false),
            StreamAssignment {
                index: 0,
                packet_number: 2
            }
        );
        assert!(state.used() <= budget);
        assert!(!state.take_dropped());
    }

    #[test]
    fn an_evicted_conversation_gets_a_new_stream_number() {
        let mut state = SessionState::new(4_096);
        for port in 0_u16..200 {
            let (key, direction) = tcp_key(1_000 + port, 80);
            assert_eq!(
                assignment(&mut state, key, syn(direction, u32::from(port)), false).index,
                u32::from(port)
            );
        }
        assert!(state.used() <= 4_096);
        assert!(state.used() > 0);

        let (first, direction) = tcp_key(1_000, 80);
        assert_eq!(
            assignment(&mut state, first, syn(direction, 0), false),
            StreamAssignment {
                index: 200,
                packet_number: 1
            }
        );
        assert!(state.used() <= 4_096);
    }

    #[test]
    fn a_zero_budget_starts_a_new_stream_for_every_packet() {
        let mut state = SessionState::new(0);
        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        assert_eq!(
            assignment(&mut state, key, ack(direction, 1_001, 0), false),
            StreamAssignment {
                index: 1,
                packet_number: 1
            }
        );
        assert_eq!(state.used(), 0);
        assert!(!state.take_dropped(), "disabled retention is not a loss");
    }

    #[test]
    fn a_conversation_larger_than_the_budget_is_dropped() {
        let mut state = SessionState::new(1);
        let (key, direction) = tcp_key(40_000, 443);
        assert_eq!(
            assignment(&mut state, key, syn(direction, 1_000), false),
            StreamAssignment {
                index: 0,
                packet_number: 1
            }
        );
        assert_eq!(state.used(), 0);
        assert!(state.take_dropped());
    }

    #[test]
    fn a_million_conversations_exceed_the_default_budget() {
        let udp_charge = StateStore::<ConversationStateKey, ConversationState>::charge_for(
            &ConversationState::Udp(UdpConversation {
                stream: 0,
                packets: 0,
                first_time: NO_UDP_TIME,
                last_time: NO_UDP_TIME,
            }),
        );
        assert_eq!(
            udp_charge, 768,
            "recalibrate MAP_ENTRY_OVERHEAD and the flood benchmark when sizes change"
        );
        assert!(
            udp_charge.saturating_mul(1_000_000) > DEFAULT_STATE_BUDGET,
            "1M conversations must be evicted before the default budget is exceeded"
        );
    }
}
