//! HTTP/2 connection state.
//!
//! Two tables carry the cross-frame state one HTTP/2 connection needs:
//!
//! * [`Http2Key`] identifies one direction of a TCP conversation. Each
//!   direction has its own HPACK dynamic table, because header compression
//!   contexts are independent per direction (RFC 7541 section 2.2), and its
//!   own flow-control windows and pending header block (RFC 9113 sections
//!   5.2 and 6.10).
//! * [`Http2Streams`] is shared by both directions of a conversation. A
//!   stream's request arrives in one direction and its response in the other,
//!   so request/response linkage and the DATA body cannot live in a
//!   direction.
//!
//! Every retained byte is reported by `state_bytes`, and every table has a
//! declared bound: [`MAX_STREAMS`] streams per conversation,
//! [`MAX_BODY_BYTES`] of reassembled DATA per stream and
//! [`MAX_BLOCK_BYTES`] of buffered header block per direction. Exceeding a
//! bound drops the oldest or largest value and reports it, so a hostile
//! capture cannot grow the tables without limit.

use std::collections::VecDeque;

use crate::capture::Timestamp;
use crate::decode::http2::hpack::{Block, DynamicTable, MAX_TABLE_SIZE};
use crate::decode::http2::{DEFAULT_MAX_FRAME_SIZE, MAX_MAX_FRAME_SIZE};
use crate::state::budget::StateValue;
use crate::state::{ConversationKey, SessionState};

/// Streams one conversation retains.
///
/// RFC 9113 section 6.5.2 lets an endpoint announce a concurrent-stream
/// limit; absent one, a peer may open an unbounded number. The cap keeps the
/// table bounded and evicts the least recently used stream, which only loses
/// request/response linkage for a stream that has been idle the longest.
pub(crate) const MAX_STREAMS: usize = 256;

/// DATA bytes reassembled for one stream body.
///
/// The reference keeps a whole body to print it on the completing frame; the
/// cap matches Packetfin's per-PDU reassembly limit so one stream cannot cost
/// more than a TCP PDU.
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;

/// DATA fragments whose frame and offset metadata one direction retains.
///
/// The body itself is kept whole in one buffer; only the per-fragment view
/// the completing frame prints is capped. A 1 MiB body in 4 KiB DATA frames
/// needs 256 entries, so a flood of one-octet DATA frames keeps its bytes and
/// bounds its metadata. Beyond the cap the frame and offset are dropped,
/// [`DataOutcome::truncated`] reports it on the completing frame, and the
/// body bytes still reassemble.
pub(crate) const MAX_BODY_FRAGMENTS: usize = 256;

/// Header-block bytes buffered between HEADERS and its CONTINUATION frames.
///
/// A single frame is bounded by its 24-bit length, but a CONTINUATION chain
/// can be arbitrarily long; the cap is the same 1 MiB the reassembly layer
/// uses for a non-HTTP PDU.
pub(crate) const MAX_BLOCK_BYTES: usize = 1024 * 1024;

/// SETTINGS frames one direction may have outstanding at once.
///
/// RFC 9113 section 6.5.3: a sender may rely on a SETTINGS value only after
/// the recipient acknowledges the frame, so the announced values are queued
/// until the ACK arrives (RFC 9113 section 6.5). A capture can omit the ACK,
/// so the queue is bounded and drops the oldest frame, which loses at most
/// the limits of frames the peer never acknowledged.
const MAX_OUTSTANDING_SETTINGS: usize = 8;

/// One direction of an HTTP/2 connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Http2Key {
    /// The direction-independent transport tuple.
    pub(crate) conversation: ConversationKey,
    /// Zero or one, as [`ConversationKey`] assigns it.
    pub(crate) direction: u8,
}

/// Where a header block started and what it promises.
///
/// RFC 9113 section 6.10 lets a block span CONTINUATION frames, so the
/// promised stream identifier and the frame that carried it belong to the
/// block, not to the frame that completes it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BlockStart {
    /// Whether this is a PUSH_PROMISE block.
    pub(crate) push: bool,
    /// The promised stream identifier of a PUSH_PROMISE block, else zero.
    pub(crate) promised: u32,
    /// Display frame number that opened the block.
    pub(crate) frame: u32,
    /// Capture frame number that opened the block.
    pub(crate) file: u32,
    /// Capture time of the frame that opened the block.
    pub(crate) time: Option<Timestamp>,
}

/// Where a header-block fragment came from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BlockOrigin {
    /// Display frame number of the fragment's frame.
    pub(crate) frame: u32,
    /// Capture frame number of the fragment's frame.
    pub(crate) file: u32,
    /// Capture time of the fragment's frame.
    pub(crate) time: Option<Timestamp>,
}

/// Which frame type carries a header-block fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockFragment {
    /// A HEADERS frame, which opens a request or response block.
    Headers,
    /// A PUSH_PROMISE frame, which opens a block for the promised stream.
    PushPromise {
        /// The promised stream identifier in the frame payload.
        promised: u32,
    },
    /// A CONTINUATION frame, which continues the open block on its stream.
    Continuation,
}

/// A header block whose END_HEADERS has not arrived.
#[derive(Debug)]
struct PendingBlock {
    stream_id: u32,
    start: BlockStart,
    bytes: Vec<u8>,
}

/// Flow-control windows for one direction.
///
/// RFC 9113 section 6.9 starts every window at 65535. The reference reports
/// the window before and after each DATA or WINDOW_UPDATE from the value the
/// *frame* started with, so the snapshot and the pending deltas are kept
/// apart from the persistent values.
#[derive(Debug)]
struct Windows {
    /// Capture frame the snapshot belongs to.
    file_frame: u64,
    /// Persistent connection window.
    connection: i32,
    /// Persistent per-stream windows.
    streams: Vec<(u32, i32)>,
    /// Connection window when the current frame started.
    snapshot_connection: i32,
    /// Per-stream windows when the current frame started.
    snapshot_streams: Vec<(u32, i32)>,
    /// Connection bytes consumed or granted during the current frame.
    pending_connection: i32,
    /// Per-stream bytes consumed or granted during the current frame.
    pending_streams: Vec<(u32, i32)>,
    /// SETTINGS_INITIAL_WINDOW_SIZE the peer announced in this direction.
    ///
    /// RFC 9113 section 6.9.2: a stream that has no window of its own starts
    /// at this value, and a change to it adjusts every open stream window.
    initial_stream_window: i32,
}

impl Default for Windows {
    fn default() -> Self {
        Self {
            file_frame: 0,
            connection: 65535,
            streams: Vec::new(),
            snapshot_connection: 65535,
            snapshot_streams: Vec::new(),
            pending_connection: 0,
            pending_streams: Vec::new(),
            initial_stream_window: 65535,
        }
    }
}

impl Windows {
    fn state_bytes(&self) -> usize {
        let entry = size_of::<(u32, i32)>();
        self.streams
            .capacity()
            .saturating_mul(entry)
            .saturating_add(self.snapshot_streams.capacity().saturating_mul(entry))
            .saturating_add(self.pending_streams.capacity().saturating_mul(entry))
    }

    /// Flush the previous frame's deltas and snapshot the current values.
    fn begin_frame(&mut self, file_frame: u64) {
        if self.file_frame == file_frame && self.file_frame != 0 {
            return;
        }
        self.connection = self.connection.saturating_add(self.pending_connection);
        self.pending_connection = 0;
        for (id, delta) in std::mem::take(&mut self.pending_streams) {
            match self.streams.iter_mut().find(|(stream, _)| *stream == id) {
                Some((_, window)) => *window = window.saturating_add(delta),
                None => self
                    .streams
                    .push((id, self.initial_stream_window.saturating_add(delta))),
            }
        }
        self.snapshot_connection = self.connection;
        self.snapshot_streams.clone_from(&self.streams);
        self.file_frame = file_frame;
    }

    /// The window a stream starts the current frame with.
    fn snapshot_stream(&self, stream_id: u32) -> i32 {
        self.snapshot_streams
            .iter()
            .find(|(id, _)| *id == stream_id)
            .map(|(_, window)| *window)
            .or_else(|| {
                self.streams
                    .iter()
                    .find(|(id, _)| *id == stream_id)
                    .map(|(_, window)| *window)
            })
            .unwrap_or(self.initial_stream_window)
    }

    /// Apply a SETTINGS_INITIAL_WINDOW_SIZE change to every open stream.
    ///
    /// RFC 9113 section 6.9.2: a receiver adjusts all stream windows by the
    /// difference between the new and the old initial size. The connection
    /// window is unchanged.
    fn set_initial_stream_window(&mut self, value: i32) {
        let delta = value.saturating_sub(self.initial_stream_window);
        self.initial_stream_window = value;
        for (_, window) in &mut self.streams {
            *window = window.saturating_add(delta);
        }
        self.snapshot_streams.clear();
    }

    fn add_connection(&mut self, delta: i32) {
        self.pending_connection = self.pending_connection.saturating_add(delta);
    }

    fn add_stream(&mut self, stream_id: u32, delta: i32) {
        match self
            .pending_streams
            .iter_mut()
            .find(|(id, _)| *id == stream_id)
        {
            Some((_, pending)) => *pending = pending.saturating_add(delta),
            None => self.pending_streams.push((stream_id, delta)),
        }
    }
}

/// One SETTINGS frame whose ACK has not arrived.
///
/// RFC 9113 section 6.5.3 makes the whole frame wait for its ACK. The values
/// here bound what the peer may announce and send, so they take effect only
/// when the peer acknowledges the frame: SETTINGS_HEADER_TABLE_SIZE bounds
/// the dynamic table size of its header blocks (RFC 7541 section 6.3) and
/// SETTINGS_MAX_FRAME_SIZE bounds their payload lengths (RFC 9113 section
/// 6.5.2).
#[derive(Clone, Copy, Debug, Default)]
struct PendingSettings {
    /// SETTINGS_HEADER_TABLE_SIZE announced by this frame, if any.
    header_table_size: Option<u32>,
    /// SETTINGS_MAX_FRAME_SIZE announced by this frame, if any.
    max_frame_size: Option<u32>,
}

/// The per-direction HTTP/2 state.
#[derive(Debug)]
pub(crate) struct Http2Direction {
    table: DynamicTable,
    /// Largest dynamic table size a block received in this direction may use.
    peer_table_limit: usize,
    /// Largest frame payload this direction may send.
    ///
    /// SETTINGS_MAX_FRAME_SIZE announces the largest frame the sender is
    /// willing to receive (RFC 9113 section 6.5.2), so a value from the
    /// opposite direction bounds this one's frames.
    peer_max_frame_size: u32,
    /// SETTINGS frames this direction sent, oldest first, until each ACK.
    pending_settings: VecDeque<PendingSettings>,
    /// SETTINGS frames dropped because the outstanding queue was full.
    ///
    /// Their values are never applied, but each still receives an ACK, so
    /// the count consumes later ACKs without growing the queue.
    discarded_settings: u32,
    /// Whether the newest SETTINGS frame was dropped instead of queued.
    last_settings_discarded: bool,
    pending: Option<PendingBlock>,
    windows: Windows,
}

impl Default for Http2Direction {
    fn default() -> Self {
        Self {
            table: DynamicTable::new(),
            peer_table_limit: crate::decode::http2::hpack::DEFAULT_TABLE_SIZE,
            peer_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            pending_settings: VecDeque::new(),
            discarded_settings: 0,
            last_settings_discarded: false,
            pending: None,
            windows: Windows::default(),
        }
    }
}

impl Http2Direction {
    /// Queue one SETTINGS frame this direction is sending.
    ///
    /// A frame beyond the cap is counted instead of queueing, so the ACK it
    /// later receives consumes no queued value and the queue never grows.
    fn push_pending_settings(&mut self) -> bool {
        // A frame sent after any discarded frame must also be discarded until
        // the count drains: otherwise it enters a slot freed by an earlier
        // ACK and the next ACK would pair with the wrong frame.
        if self.discarded_settings > 0 || self.pending_settings.len() >= MAX_OUTSTANDING_SETTINGS {
            self.discarded_settings = self.discarded_settings.saturating_add(1);
            false
        } else {
            self.pending_settings.push_back(PendingSettings::default());
            true
        }
    }
}

impl StateValue for Http2Direction {
    fn state_bytes(&self) -> usize {
        self.table
            .state_bytes()
            .saturating_add(
                self.pending
                    .as_ref()
                    .map_or(0, |pending| pending.bytes.capacity()),
            )
            .saturating_add(self.windows.state_bytes())
            .saturating_add(
                self.pending_settings
                    .capacity()
                    .saturating_mul(size_of::<PendingSettings>()),
            )
    }
}

/// One DATA fragment's position in a stream body.
///
/// The octets live in the body's single buffer, not here: keeping a `Vec` per
/// fragment made a flood of one-octet DATA frames cost more metadata than
/// payload.
#[derive(Clone, Copy, Debug)]
struct BodyFragment {
    /// Display frame number of the contributing DATA frame.
    frame: u64,
    /// Capture frame number, for two-pass annotations.
    file: u64,
    /// Offset of the fragment within the body.
    offset: usize,
    /// Fragment length.
    length: usize,
}

/// One direction of a stream body assembled from its DATA frames.
///
/// Request and response bodies never share a buffer: one stream carries both
/// directions, and the completing frame prints only its own direction's body.
#[derive(Debug, Default)]
struct Body {
    /// The whole body, appended in wire order.
    bytes: Vec<u8>,
    /// Bounded fragment metadata, in wire order.
    fragments: Vec<BodyFragment>,
    /// DATA frames that carried at least one octet.
    fragment_count: usize,
    /// Body octets retained, including those past the metadata cap.
    total: usize,
    /// END_STREAM arrived for this direction.
    complete: bool,
    /// The body exceeded [`MAX_BODY_BYTES`] and is not retained.
    dropped: bool,
    /// Fragment metadata was dropped past [`MAX_BODY_FRAGMENTS`].
    truncated: bool,
}

impl Body {
    /// Forget this direction's body for a new message.
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn state_bytes(&self) -> usize {
        self.bytes.capacity().saturating_add(
            self.fragments
                .capacity()
                .saturating_mul(size_of::<BodyFragment>()),
        )
    }
}

/// Request/response state and the DATA bodies of one stream.
#[derive(Debug, Default)]
pub(crate) struct Http2Stream {
    id: u32,
    request_frame: u32,
    request_file: u32,
    request_time: Option<Timestamp>,
    request_uri: Option<String>,
    response_frame: u32,
    /// One body per direction, indexed by [`Http2Key::direction`].
    bodies: [Body; 2],
    /// Least-recently-used stamp for [`MAX_STREAMS`] eviction.
    touch: u64,
}

impl Http2Stream {
    fn state_bytes(&self) -> usize {
        self.request_uri
            .as_ref()
            .map_or(0, |uri| uri.capacity())
            .saturating_add(self.bodies.iter().map(Body::state_bytes).sum::<usize>())
    }
}

/// Every stream of one conversation.
#[derive(Debug, Default)]
pub(crate) struct Http2Streams {
    streams: Vec<Http2Stream>,
    clock: u64,
}

impl StateValue for Http2Streams {
    fn state_bytes(&self) -> usize {
        self.streams
            .capacity()
            .saturating_mul(size_of::<Http2Stream>())
            .saturating_add(
                self.streams
                    .iter()
                    .map(Http2Stream::state_bytes)
                    .sum::<usize>(),
            )
    }
}

impl Http2Streams {
    fn find(&mut self, stream_id: u32) -> Option<&mut Http2Stream> {
        self.clock = self.clock.saturating_add(1);
        let clock = self.clock;
        let stream = self
            .streams
            .iter_mut()
            .find(|stream| stream.id == stream_id)?;
        stream.touch = clock;
        Some(stream)
    }

    /// Find or create a stream, evicting the least recently used one when the
    /// table is full.
    fn find_or_insert(&mut self, stream_id: u32) -> (Option<&mut Http2Stream>, bool) {
        self.clock = self.clock.saturating_add(1);
        let clock = self.clock;
        let mut evicted = false;
        if !self.streams.iter().any(|stream| stream.id == stream_id)
            && self.streams.len() >= MAX_STREAMS
            && let Some(index) = self
                .streams
                .iter()
                .enumerate()
                .min_by_key(|(_, stream)| stream.touch)
                .map(|(index, _)| index)
        {
            self.streams.swap_remove(index);
            evicted = true;
        }
        let position = self
            .streams
            .iter()
            .position(|stream| stream.id == stream_id);
        if let Some(position) = position {
            if let Some(stream) = self.streams.get_mut(position) {
                stream.touch = clock;
                return (Some(stream), evicted);
            }
            return (None, evicted);
        }
        self.streams.push(Http2Stream {
            id: stream_id,
            touch: clock,
            ..Http2Stream::default()
        });
        (self.streams.last_mut(), evicted)
    }
}

/// One DATA frame's per-frame inputs.
///
/// `flow_length` is the whole frame payload, including the Pad Length and
/// Padding fields, which RFC 9113 section 6.1 includes in flow control;
/// `data` is only the reassembled body octets.
pub(crate) struct Http2Data<'a> {
    /// Stream the DATA frame belongs to.
    pub(crate) stream_id: u32,
    /// Unpadded body octets.
    pub(crate) data: &'a [u8],
    /// Whole frame payload length, padding included.
    pub(crate) flow_length: usize,
    /// END_STREAM arrived on this frame.
    pub(crate) end_stream: bool,
    /// Display frame number of the DATA frame.
    pub(crate) frame: u64,
    /// Capture frame number of the DATA frame.
    pub(crate) file: u64,
}

/// What one header fragment did to the connection.
#[derive(Debug)]
pub(crate) struct FragmentResult {
    /// The decoded block, present when END_HEADERS arrived.
    pub(crate) block: Option<Block>,
    /// A CONTINUATION arrived on a stream that had no open block.
    pub(crate) unexpected: bool,
    /// The buffered block exceeded [`MAX_BLOCK_BYTES`] and was dropped.
    pub(crate) overflow: bool,
    /// The frame and promise the completed block started with.
    pub(crate) start: Option<BlockStart>,
}

/// One DATA frame's effect on the stream.
#[derive(Debug)]
pub(crate) struct DataOutcome {
    /// Connection window before this frame's bytes.
    pub(crate) connection_before: i32,
    /// Connection window after this frame's bytes.
    pub(crate) connection_after: i32,
    /// Stream window before this frame's bytes.
    pub(crate) stream_before: i32,
    /// Stream window after this frame's bytes.
    pub(crate) stream_after: i32,
    /// The body fragments to show on the completing frame.
    pub(crate) fragments: Vec<BodyFragmentView>,
    /// DATA frames that carried at least one octet.
    pub(crate) fragment_count: usize,
    /// Reassembled body bytes when this frame ended the stream.
    pub(crate) data: Option<Vec<u8>>,
    /// Total body octets retained.
    pub(crate) total: usize,
    /// The body exceeded [`MAX_BODY_BYTES`] and is not retained.
    pub(crate) dropped: bool,
    /// Fragment metadata was dropped past [`MAX_BODY_FRAGMENTS`].
    pub(crate) truncated: bool,
    /// A stream was evicted to make room for this one.
    pub(crate) evicted: bool,
}

/// One body fragment as the field tree shows it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BodyFragmentView {
    /// Display frame number.
    pub(crate) frame: u64,
    /// Capture frame number, for two-pass annotations.
    pub(crate) file: u64,
    /// Offset within the reassembled body.
    pub(crate) offset: usize,
    /// Fragment length.
    pub(crate) length: usize,
}

/// The request a response stream answered.
#[derive(Clone, Debug)]
pub(crate) struct Http2RequestInfo {
    /// Display frame number of the request HEADERS.
    pub(crate) frame: u32,
    /// Capture frame number of the request HEADERS.
    pub(crate) file: u32,
    /// Capture time of the request HEADERS.
    pub(crate) time: Option<Timestamp>,
}

impl SessionState {
    /// Whether either direction of a conversation has HTTP/2 state.
    ///
    /// Only the client sends the connection preface, so the server's first
    /// frame has no preface of its own; the conversation's existing state is
    /// what claims that direction.
    pub(crate) fn http2_known(&self, conversation: ConversationKey) -> bool {
        if self.budget.suspended() {
            return false;
        }
        self.http2.contains_key(&Http2Key {
            conversation,
            direction: 0,
        }) || self.http2.contains_key(&Http2Key {
            conversation,
            direction: 1,
        })
    }

    /// Mark a conversation as HTTP/2 when its preface is decoded.
    pub(crate) fn http2_mark(&mut self, key: Http2Key) {
        if self.budget.suspended() {
            return;
        }
        if !self.http2.contains_key(&key) {
            self.http2
                .put_with(&mut self.budget, key, Http2Direction::default());
        }
    }

    /// Buffer one header-block fragment and decode the block at END_HEADERS.
    ///
    /// A block that never reaches END_HEADERS is dropped with the direction's
    /// state. A CONTINUATION on a stream with no open block is decoded on its
    /// own, which is what the expected output does and what keeps a stray
    /// fragment visible. A CONTINUATION inherits the open block's kind and
    /// promised stream identifier, so a fragmented PUSH_PROMISE stays a
    /// PUSH_PROMISE through its last frame (RFC 9113 section 6.10).
    pub(crate) fn http2_fragment(
        &mut self,
        key: Http2Key,
        stream_id: u32,
        fragment_kind: BlockFragment,
        origin: BlockOrigin,
        fragment: &[u8],
        end_headers: bool,
    ) -> FragmentResult {
        let mut direction = self
            .http2
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        let mut unexpected = false;
        let mut overflow = false;
        match fragment_kind {
            // RFC 9113 section 6.10 requires CONTINUATION on the same stream;
            // an interleaved block is a connection error. The reference keeps
            // decoding, so the abandoned block is dropped and the fragment is
            // treated as a block of its own.
            BlockFragment::Continuation => {
                let same_stream = direction
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.stream_id == stream_id);
                if direction.pending.is_some() && !same_stream {
                    direction.pending = None;
                    // The abandoned block's table mutations never reached
                    // the decoder, so the replacement block must not resolve
                    // a dynamic index against the stale table (RFC 7541
                    // section 2.2 makes header blocks stateful).
                    direction.table.mark_lost();
                    unexpected = true;
                }
            }
            // A new block cannot start before the open one ends.
            BlockFragment::Headers | BlockFragment::PushPromise { .. } => {
                if direction.pending.take().is_some() {
                    // Marked before the replacement block decodes below, so
                    // its dynamic references cannot resolve stale entries.
                    direction.table.mark_lost();
                    unexpected = true;
                }
            }
        }
        let started = match fragment_kind {
            BlockFragment::Headers => BlockStart {
                push: false,
                promised: 0,
                frame: origin.frame,
                file: origin.file,
                time: origin.time,
            },
            BlockFragment::PushPromise { promised } => BlockStart {
                push: true,
                promised,
                frame: origin.frame,
                file: origin.file,
                time: origin.time,
            },
            BlockFragment::Continuation => direction
                .pending
                .as_ref()
                .map(|pending| pending.start)
                .unwrap_or(BlockStart {
                    push: false,
                    promised: 0,
                    frame: origin.frame,
                    file: origin.file,
                    time: origin.time,
                }),
        };
        let mut block = None;
        let mut start = None;
        if end_headers {
            let bytes = match direction.pending.take() {
                Some(pending) => {
                    let mut bytes = pending.bytes;
                    bytes.extend_from_slice(fragment);
                    bytes
                }
                None => fragment.to_vec(),
            };
            if bytes.len() > MAX_BLOCK_BYTES {
                overflow = true;
            } else {
                block = Some(crate::decode::http2::hpack::decode_block(
                    &bytes,
                    &mut direction.table,
                    direction.peer_table_limit,
                ));
                start = Some(started);
            }
        } else {
            let pending = direction.pending.get_or_insert_with(|| PendingBlock {
                stream_id,
                start: started,
                bytes: Vec::new(),
            });
            if pending.bytes.len().saturating_add(fragment.len()) > MAX_BLOCK_BYTES {
                direction.pending = None;
                overflow = true;
            } else {
                pending.bytes.extend_from_slice(fragment);
            }
        }
        if overflow {
            // A block was dropped, so its table mutations never reached the
            // decoder; later dynamic references cannot be trusted.
            direction.table.mark_lost();
        }
        self.http2.put_with(&mut self.budget, key, direction);
        FragmentResult {
            block,
            unexpected,
            overflow,
            start,
        }
    }

    /// Note that this direction is sending one SETTINGS frame.
    ///
    /// RFC 9113 section 6.5.3: a SETTINGS value is not relied on until the
    /// recipient acknowledges the frame, so each frame takes one slot in the
    /// bounded outstanding queue until [`Self::http2_settings_ack`] matches
    /// it.
    pub(crate) fn http2_settings_frame(&mut self, key: Http2Key) {
        let mut direction = self
            .http2
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        direction.last_settings_discarded = !direction.push_pending_settings();
        self.http2.put_with(&mut self.budget, key, direction);
    }

    /// Mark a direction's HPACK table out of step after a skipped frame.
    ///
    /// A blocked HEADERS, PUSH_PROMISE or CONTINUATION payload may have
    /// carried table mutations, so later dynamic references cannot be
    /// resolved (RFC 7541 section 2.2). A pending block is dropped with it.
    pub(crate) fn http2_mark_table_lost(&mut self, key: Http2Key) {
        let mut direction = self
            .http2
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        direction.table.mark_lost();
        direction.pending = None;
        self.http2.put_with(&mut self.budget, key, direction);
    }

    /// Apply the values of the acknowledged SETTINGS frame.
    ///
    /// RFC 9113 section 6.5: a recipient acknowledges a SETTINGS frame with
    /// an empty frame carrying the ACK flag. The ACK arrives in `key`'s
    /// direction, so it acknowledges the oldest frame the opposite direction
    /// sent, and the acknowledged SETTINGS_HEADER_TABLE_SIZE (RFC 7541
    /// section 6.3) and SETTINGS_MAX_FRAME_SIZE (RFC 9113 section 6.5.2)
    /// then bound the blocks and frames this direction sends.
    pub(crate) fn http2_settings_ack(&mut self, key: Http2Key) {
        let peer = Http2Key {
            conversation: key.conversation,
            direction: 1_u8.saturating_sub(key.direction.min(1)),
        };
        let Some(mut settings) = self.http2.take_with(&mut self.budget, &peer) else {
            return;
        };
        let acknowledged = settings.pending_settings.pop_front();
        if acknowledged.is_none() && settings.discarded_settings > 0 {
            // RFC 9113 section 6.5: this ACK acknowledges a frame whose
            // values were dropped past the queue cap, so it consumes the
            // count and applies nothing.
            settings.discarded_settings = settings.discarded_settings.saturating_sub(1);
        }
        self.http2.put_with(&mut self.budget, peer, settings);
        let Some(acknowledged) = acknowledged else {
            return;
        };
        if acknowledged.header_table_size.is_none() && acknowledged.max_frame_size.is_none() {
            return;
        }
        let mut direction = self
            .http2
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        if let Some(value) = acknowledged.header_table_size {
            direction.peer_table_limit = usize::try_from(value)
                .unwrap_or(MAX_TABLE_SIZE)
                .min(MAX_TABLE_SIZE);
        }
        if let Some(value) = acknowledged.max_frame_size
            && (DEFAULT_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value)
        {
            direction.peer_max_frame_size = value;
        }
        self.http2.put_with(&mut self.budget, key, direction);
    }

    /// Record one SETTINGS value.
    ///
    /// The values that change how later frames behave belong to the peer's
    /// sends, so they are applied to the *opposite* direction:
    /// SETTINGS_HEADER_TABLE_SIZE bounds the size update that encoder may
    /// send (RFC 7541 section 6.3), SETTINGS_MAX_FRAME_SIZE bounds the frames
    /// it may send (RFC 9113 section 6.5.2), and
    /// SETTINGS_INITIAL_WINDOW_SIZE sets the initial stream window of the
    /// data it sends (RFC 9113 section 6.9.2). The header table size stays
    /// queued until the frame is acknowledged (RFC 9113 section 6.5.3).
    pub(crate) fn http2_settings(&mut self, key: Http2Key, id: u16, value: u32) {
        let peer = Http2Key {
            conversation: key.conversation,
            direction: 1_u8.saturating_sub(key.direction.min(1)),
        };
        match id {
            1 => {
                let capped = u32::try_from(
                    usize::try_from(value)
                        .unwrap_or(MAX_TABLE_SIZE)
                        .min(MAX_TABLE_SIZE),
                )
                .unwrap_or(u32::MAX);
                let mut direction = self
                    .http2
                    .take_with(&mut self.budget, &key)
                    .unwrap_or_default();
                if !direction.last_settings_discarded {
                    if direction.pending_settings.is_empty() {
                        // A caller that recorded no frame boundary still
                        // queues this value so a later ACK can activate it.
                        direction.push_pending_settings();
                    }
                    if let Some(pending) = direction.pending_settings.back_mut() {
                        pending.header_table_size = Some(capped);
                    }
                }
                self.http2.put_with(&mut self.budget, key, direction);
            }
            4 => {
                let mut direction = self
                    .http2
                    .take_with(&mut self.budget, &peer)
                    .unwrap_or_default();
                let window = i32::try_from(value).unwrap_or(i32::MAX);
                direction.windows.set_initial_stream_window(window);
                self.http2.put_with(&mut self.budget, peer, direction);
            }
            5 => {
                // RFC 9113 section 6.5.2: a value outside 16384..=16777215 is
                // a connection error, so it is kept but not applied by the
                // ACK.
                let mut direction = self
                    .http2
                    .take_with(&mut self.budget, &key)
                    .unwrap_or_default();
                if !direction.last_settings_discarded {
                    if direction.pending_settings.is_empty() {
                        direction.push_pending_settings();
                    }
                    if let Some(pending) = direction.pending_settings.back_mut() {
                        pending.max_frame_size = Some(value);
                    }
                }
                self.http2.put_with(&mut self.budget, key, direction);
            }
            _ => {}
        }
    }

    /// The largest frame payload the direction `key` may send.
    ///
    /// This is the acknowledged SETTINGS_MAX_FRAME_SIZE announced by the
    /// opposite direction, or the 16384 default before any (RFC 9113 section
    /// 6.5.2).
    pub(crate) fn http2_peer_max_frame_size(&mut self, key: Http2Key) -> u32 {
        self.http2
            .get_with(&mut self.budget, &key)
            .map_or(DEFAULT_MAX_FRAME_SIZE, |direction| {
                direction.peer_max_frame_size
            })
    }

    /// Account one DATA frame and retain its body fragment.
    pub(crate) fn http2_data(&mut self, key: Http2Key, input: Http2Data<'_>) -> DataOutcome {
        let Http2Data {
            stream_id,
            data,
            flow_length,
            end_stream,
            frame,
            file,
        } = input;
        let mut direction = self
            .http2
            .take_with(&mut self.budget, &key)
            .unwrap_or_default();
        direction.windows.begin_frame(file);
        let connection_before = direction.windows.snapshot_connection;
        let stream_before = direction.windows.snapshot_stream(stream_id);
        let length = i32::try_from(flow_length).unwrap_or(i32::MAX);
        // RFC 9113 section 6.9.1: sending DATA consumes the sender's
        // connection and stream windows, and section 6.1 charges the entire
        // frame payload, padding included, so the persistent deltas debit.
        direction.windows.add_connection(-length);
        direction.windows.add_stream(stream_id, -length);
        let connection_after = connection_before.saturating_sub(length);
        let stream_after = stream_before.saturating_sub(length);
        self.http2.put_with(&mut self.budget, key, direction);

        let mut streams = self
            .http2_streams
            .take_with(&mut self.budget, &key.conversation)
            .unwrap_or_default();
        let (stream, evicted) = streams.find_or_insert(stream_id);
        let mut outcome = DataOutcome {
            connection_before,
            connection_after,
            stream_before,
            stream_after,
            fragments: Vec::new(),
            fragment_count: 0,
            data: None,
            total: 0,
            dropped: false,
            truncated: false,
            evicted,
        };
        if let Some(stream) = stream
            && let Some(body) = stream.bodies.get_mut(usize::from(key.direction & 1))
        {
            if body.complete {
                body.reset();
            }
            if !body.dropped {
                let offset = body.total;
                let next = offset.saturating_add(data.len());
                if next > MAX_BODY_BYTES {
                    body.dropped = true;
                    body.fragments.clear();
                    body.bytes.clear();
                    body.bytes.shrink_to_fit();
                    body.total = 0;
                } else {
                    body.total = next;
                    body.bytes.extend_from_slice(data);
                    if !data.is_empty() {
                        body.fragment_count = body.fragment_count.saturating_add(1);
                        if body.fragments.len() < MAX_BODY_FRAGMENTS {
                            body.fragments.push(BodyFragment {
                                frame,
                                file,
                                offset,
                                length: data.len(),
                            });
                        } else {
                            body.truncated = true;
                        }
                    }
                }
            }
            outcome.total = body.total;
            outcome.dropped = body.dropped;
            outcome.fragment_count = body.fragment_count;
            outcome.truncated = body.truncated;
            if end_stream {
                body.complete = true;
                if !body.dropped {
                    // The views are built once, on the frame that prints
                    // them; a partial frame only appends its bytes.
                    outcome.fragments = body
                        .fragments
                        .iter()
                        .map(|fragment| BodyFragmentView {
                            frame: fragment.frame,
                            file: fragment.file,
                            offset: fragment.offset,
                            length: fragment.length,
                        })
                        .collect();
                    outcome.data = Some(std::mem::take(&mut body.bytes));
                }
            }
        }
        self.http2_streams
            .put_with(&mut self.budget, key.conversation, streams);
        outcome
    }

    /// Account one WINDOW_UPDATE and return the window before and after.
    ///
    /// RFC 9113 section 6.9: a WINDOW_UPDATE sent by one endpoint grants send
    /// credit to its peer, so the increment belongs to the opposite
    /// direction's windows.
    pub(crate) fn http2_window_update(
        &mut self,
        key: Http2Key,
        stream_id: u32,
        increment: u32,
        file: u64,
    ) -> (i32, i32) {
        let peer = Http2Key {
            conversation: key.conversation,
            direction: 1_u8.saturating_sub(key.direction.min(1)),
        };
        let mut direction = self
            .http2
            .take_with(&mut self.budget, &peer)
            .unwrap_or_default();
        direction.windows.begin_frame(file);
        let delta = i32::try_from(increment).unwrap_or(i32::MAX);
        let (before, after) = if stream_id == 0 {
            direction.windows.add_connection(delta);
            (
                direction.windows.snapshot_connection,
                direction.windows.snapshot_connection.saturating_add(delta),
            )
        } else {
            direction.windows.add_stream(stream_id, delta);
            let before = direction.windows.snapshot_stream(stream_id);
            (before, before.saturating_add(delta))
        };
        self.http2.put_with(&mut self.budget, peer, direction);
        (before, after)
    }

    /// Record the request a stream carries.
    pub(crate) fn http2_record_request(
        &mut self,
        conversation: ConversationKey,
        stream_id: u32,
        frame: u32,
        file: u32,
        time: Option<Timestamp>,
        uri: Option<String>,
    ) {
        let mut streams = self
            .http2_streams
            .take_with(&mut self.budget, &conversation)
            .unwrap_or_default();
        let (stream, _) = streams.find_or_insert(stream_id);
        if let Some(stream) = stream {
            stream.request_frame = frame;
            stream.request_file = file;
            stream.request_time = time;
            stream.request_uri = uri;
        }
        self.http2_streams
            .put_with(&mut self.budget, conversation, streams);
    }

    /// Record the first response frame of a stream and return its request.
    pub(crate) fn http2_record_response(
        &mut self,
        conversation: ConversationKey,
        stream_id: u32,
        frame: u32,
    ) -> Option<Http2RequestInfo> {
        let mut streams = self
            .http2_streams
            .take_with(&mut self.budget, &conversation)
            .unwrap_or_default();
        let (stream, _) = streams.find_or_insert(stream_id);
        let info = stream.as_ref().and_then(|stream| {
            if stream.request_frame == 0 {
                return None;
            }
            Some(Http2RequestInfo {
                frame: stream.request_frame,
                file: stream.request_file,
                time: stream.request_time,
            })
        });
        if let Some(stream) = stream {
            stream.response_frame = frame;
        }
        self.http2_streams
            .put_with(&mut self.budget, conversation, streams);
        info
    }

    /// The request URI associated with a stream, for response frames.
    pub(crate) fn http2_stream_uri(
        &mut self,
        conversation: ConversationKey,
        stream_id: u32,
    ) -> Option<String> {
        let mut streams = self
            .http2_streams
            .take_with(&mut self.budget, &conversation)
            .unwrap_or_default();
        let uri = streams
            .find(stream_id)
            .and_then(|stream| stream.request_uri.clone());
        self.http2_streams
            .put_with(&mut self.budget, conversation, streams);
        uri
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::decode::http2::hpack::Stop;

    /// One conversation and the two directions' keys.
    fn keys() -> (Http2Key, Http2Key) {
        let (conversation, _) = ConversationKey::ipv4([192, 0, 2, 1], 40_000, [192, 0, 2, 2], 8080);
        (
            Http2Key {
                conversation,
                direction: 0,
            },
            Http2Key {
                conversation,
                direction: 1,
            },
        )
    }

    #[test]
    fn fragment_views_are_built_only_when_the_body_completes() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, _) = keys();
        let outcome = state.http2_data(client, data_input(b"a", 1, false, 1));
        assert!(
            outcome.fragments.is_empty(),
            "a partial frame emits no fragment views"
        );
    }

    #[test]
    fn body_fragment_metadata_is_bounded_and_the_body_survives() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, _) = keys();
        let frames = 300_usize;
        let mut last = None;
        for index in 0..frames {
            let end = index + 1 == frames;
            last = Some(state.http2_data(
                client,
                data_input(b"x", 1, end, u64::try_from(index).unwrap_or(0) + 1),
            ));
        }
        let outcome = last.unwrap_or_else(|| unreachable!("one outcome"));
        let body = outcome
            .data
            .unwrap_or_else(|| unreachable!("the body is retained whole"));
        assert_eq!(body.len(), frames, "every DATA octet survives");
        assert!(
            outcome.fragments.len() <= 256,
            "fragment metadata is bounded, got {}",
            outcome.fragments.len()
        );
        assert_eq!(outcome.fragments.len(), 256);
    }

    #[test]
    fn request_and_response_bodies_stay_separate() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        let _ = state.http2_data(client, data_input(b"A", 1, false, 1));
        let _ = state.http2_data(server, data_input(b"B", 1, false, 2));
        let request = state.http2_data(client, data_input(b"C", 1, true, 3));
        let response = state.http2_data(server, data_input(b"D", 1, true, 4));
        assert_eq!(request.data.as_deref(), Some(b"AC".as_slice()));
        assert_eq!(response.data.as_deref(), Some(b"BD".as_slice()));
    }

    #[test]
    fn data_debits_the_persistent_window() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, _) = keys();
        let first = state.http2_data(client, data_input(b"a", 1, false, 1));
        assert_eq!(
            (first.connection_before, first.connection_after),
            (65535, 65534)
        );
        let second = state.http2_data(client, data_input(b"b", 1, false, 2));
        assert_eq!(
            (second.connection_before, second.connection_after),
            (65534, 65533)
        );
        assert_eq!((second.stream_before, second.stream_after), (65534, 65533));
    }

    #[test]
    fn a_window_update_credits_the_peer_direction() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        let (before, after) = state.http2_window_update(client, 0, 100, 1);
        assert_eq!((before, after), (65535, 65635));
        let data = state.http2_data(server, data_input(b"a", 1, false, 2));
        assert_eq!(data.connection_before, 65635);
    }

    #[test]
    fn initial_window_size_changes_the_peer_stream_windows() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        state.http2_settings(client, 4, 1000);
        let data = state.http2_data(server, data_input(b"a", 1, false, 1));
        assert_eq!(data.stream_before, 1000);
        state.http2_settings(client, 4, 900);
        let next = state.http2_data(server, data_input(b"b", 1, false, 2));
        // The one octet already sent came out of the new 900 window.
        assert_eq!((next.stream_before, next.stream_after), (899, 898));
    }

    #[test]
    fn a_tiny_fragment_flood_charges_bounded_state() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, _) = keys();
        for index in 0..4096_u64 {
            let _ = state.http2_data(client, data_input(b"x", 1, false, index + 1));
        }
        assert!(
            state.used() < 64 * 1024,
            "fragment metadata is charged to the ledger, used {}",
            state.used()
        );
    }

    /// A header-block origin for the state tests.
    fn origin(frame: u32) -> BlockOrigin {
        BlockOrigin {
            frame,
            file: frame,
            time: None,
        }
    }

    /// Inputs for one DATA frame on stream 1.
    fn data_input(data: &[u8], flow_length: usize, end_stream: bool, frame: u64) -> Http2Data<'_> {
        Http2Data {
            stream_id: 1,
            data,
            flow_length,
            end_stream,
            frame,
            file: frame,
        }
    }

    #[test]
    fn a_padded_data_frame_debits_the_full_payload() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, _) = keys();
        // One Pad Length octet, five body octets and three padding octets:
        // RFC 9113 section 6.1 charges all nine octets to flow control while
        // the body keeps only the five unpadded octets.
        let outcome = state.http2_data(client, data_input(b"hello", 9, true, 1));
        assert_eq!(
            (outcome.connection_before, outcome.connection_after),
            (65535, 65526)
        );
        assert_eq!(
            (outcome.stream_before, outcome.stream_after),
            (65535, 65526)
        );
        assert_eq!(outcome.data.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn window_state_charges_each_buffer_by_its_capacity() {
        let windows = Windows {
            streams: Vec::with_capacity(8),
            snapshot_streams: Vec::with_capacity(1),
            pending_streams: Vec::with_capacity(2),
            ..Windows::default()
        };
        let entry = size_of::<(u32, i32)>();
        assert_eq!(
            windows.state_bytes(),
            windows
                .streams
                .capacity()
                .saturating_add(windows.snapshot_streams.capacity())
                .saturating_add(windows.pending_streams.capacity())
                .saturating_mul(entry)
        );
        assert_ne!(
            windows.state_bytes(),
            windows
                .streams
                .capacity()
                .saturating_mul(entry)
                .saturating_mul(3),
            "the snapshot and pending capacities are charged separately"
        );
    }

    #[test]
    fn an_oversized_frame_is_measured_against_the_acknowledged_limit() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        assert_eq!(
            state.http2_peer_max_frame_size(client),
            DEFAULT_MAX_FRAME_SIZE
        );
        // SETTINGS from the server bound the frames the client sends, but
        // RFC 9113 section 6.5.3 keeps the raise pending until the ACK: a
        // 20000-octet client frame is still measured against 16384.
        state.http2_settings_frame(server);
        state.http2_settings(server, 5, 32_768);
        assert_eq!(
            state.http2_peer_max_frame_size(client),
            DEFAULT_MAX_FRAME_SIZE
        );
        state.http2_settings_ack(client);
        assert_eq!(state.http2_peer_max_frame_size(client), 32_768);
        // The server lowers the limit again; the client's in-flight frames
        // stay measured against 32768 until the lowering is acknowledged.
        state.http2_settings_frame(server);
        state.http2_settings(server, 5, 16_384);
        assert_eq!(state.http2_peer_max_frame_size(client), 32_768);
        state.http2_settings_ack(client);
        assert_eq!(state.http2_peer_max_frame_size(client), 16_384);
        // A value outside 16384..=16777215 is a connection error and never
        // changes the limit (RFC 9113 section 6.5.2).
        state.http2_settings_frame(server);
        state.http2_settings(server, 5, 1_000);
        state.http2_settings_ack(client);
        assert_eq!(state.http2_peer_max_frame_size(client), 16_384);
        // The reverse direction keeps the default.
        assert_eq!(
            state.http2_peer_max_frame_size(server),
            DEFAULT_MAX_FRAME_SIZE
        );
    }

    #[test]
    fn an_abandoned_block_cannot_resolve_a_stale_dynamic_entry() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, _) = keys();
        // A completed block inserts one entry at dynamic index 62.
        let inserted = state.http2_fragment(
            client,
            1,
            BlockFragment::Headers,
            origin(1),
            &[0x40, 0x01, b'a', 0x01, b'1'],
            true,
        );
        assert_eq!(
            inserted.block.as_ref().map(|block| block.stop),
            Some(Stop::Complete)
        );
        assert_eq!(
            inserted.block.as_ref().map(|block| block.header_count),
            Some(1)
        );
        // A block that never reaches END_HEADERS would insert a second entry
        // and shift the first one; it is abandoned by the next HEADERS.
        let buffered = state.http2_fragment(
            client,
            1,
            BlockFragment::Headers,
            origin(2),
            &[0x40, 0x01, b'b', 0x01, b'2'],
            false,
        );
        assert!(buffered.block.is_none());
        // Indexing entry 62 would resolve the stale first entry if the
        // abandoned block had not marked the table lost.
        let replacement =
            state.http2_fragment(client, 3, BlockFragment::Headers, origin(3), &[0xbe], true);
        assert!(replacement.unexpected, "the open block was abandoned");
        assert_eq!(
            replacement.block.as_ref().map(|block| block.stop),
            Some(Stop::Desynchronized),
            "the replacement must not resolve a stale entry"
        );
    }

    #[test]
    fn a_header_table_size_reduction_waits_for_the_ack() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        // The server announces that the client's encoder may use no dynamic
        // table octets.
        state.http2_settings_frame(server);
        state.http2_settings(server, 1, 0);
        // RFC 9113 section 6.5.3: until the client acknowledges the frame,
        // the previous 4096-octet limit stays active.
        let before = state.http2_fragment(
            client,
            1,
            BlockFragment::Headers,
            origin(1),
            &[0x3f, 0xe1, 0x1f, 0x82],
            true,
        );
        assert_eq!(
            before.block.map(|block| block.stop),
            Some(Stop::Complete),
            "the old table size stays usable before the ACK"
        );
        state.http2_settings_ack(client);
        let after = state.http2_fragment(
            client,
            3,
            BlockFragment::Headers,
            origin(2),
            &[0x3f, 0xe1, 0x1f, 0x82],
            true,
        );
        assert_eq!(
            after.block.map(|block| block.stop),
            Some(Stop::Invalid),
            "a size update above the acknowledged limit is invalid"
        );
        let zero = state.http2_fragment(
            client,
            5,
            BlockFragment::Headers,
            origin(3),
            &[0x20, 0x82],
            true,
        );
        assert_eq!(zero.block.map(|block| block.stop), Some(Stop::Complete));
    }

    #[test]
    fn a_header_table_size_increase_waits_for_the_ack() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        state.http2_settings_frame(server);
        state.http2_settings(server, 1, 8192);
        // 0x3f 0xe1 0x3f encodes a table size update to 8192.
        let before = state.http2_fragment(
            client,
            1,
            BlockFragment::Headers,
            origin(1),
            &[0x3f, 0xe1, 0x3f, 0x82],
            true,
        );
        assert_eq!(
            before.block.map(|block| block.stop),
            Some(Stop::Invalid),
            "the increase is not active before the ACK"
        );
        state.http2_settings_ack(client);
        let after = state.http2_fragment(
            client,
            3,
            BlockFragment::Headers,
            origin(2),
            &[0x3f, 0xe1, 0x3f, 0x82],
            true,
        );
        assert_eq!(after.block.map(|block| block.stop), Some(Stop::Complete));
    }

    #[test]
    fn settings_sent_while_discarding_do_not_shift_acks() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        for _ in 0..MAX_OUTSTANDING_SETTINGS {
            state.http2_settings_frame(server);
        }
        // Frame nine is discarded. Frame ten arrives after ACK one frees a
        // queue slot; it must stay discarded too, or ACK nine would apply it.
        state.http2_settings_frame(server);
        state.http2_settings(server, 5, 32_768);
        state.http2_settings_ack(client);
        state.http2_settings_frame(server);
        state.http2_settings(server, 5, 49_152);
        for _ in 0..MAX_OUTSTANDING_SETTINGS - 1 {
            state.http2_settings_ack(client);
        }
        // ACKs nine and ten consume the two discarded frames.
        state.http2_settings_ack(client);
        state.http2_settings_ack(client);
        assert_eq!(
            state.http2_peer_max_frame_size(client),
            DEFAULT_MAX_FRAME_SIZE,
            "neither discarded frame may be applied"
        );
    }

    #[test]
    fn settings_beyond_the_outstanding_queue_are_discarded() {
        let mut state = SessionState::new(64 * 1024 * 1024);
        let (client, server) = keys();
        for _ in 0..MAX_OUTSTANDING_SETTINGS {
            state.http2_settings_frame(server);
        }
        // The ninth frame is dropped with its value; it still receives an ACK.
        state.http2_settings_frame(server);
        state.http2_settings(server, 5, 32_768);
        for _ in 0..MAX_OUTSTANDING_SETTINGS {
            state.http2_settings_ack(client);
            assert_eq!(
                state.http2_peer_max_frame_size(client),
                DEFAULT_MAX_FRAME_SIZE,
                "the eight queued frames carry no value"
            );
        }
        // The eighth ACK must not activate the discarded ninth frame; the
        // ninth ACK consumes its count and still applies nothing.
        state.http2_settings_ack(client);
        assert_eq!(
            state.http2_peer_max_frame_size(client),
            DEFAULT_MAX_FRAME_SIZE,
            "the overflow value is never applied"
        );
    }
}
