//! Inputs shared by one packet subtree while its fields are rendered.
//!
//! JSON, EK and PDML walk the same decoded tree with the same frame, byte
//! sources and protocol filter. Each writer supplies its own filter and
//! visibility policy; the remaining walk inputs live here so the rendering
//! helpers take one reference instead of repeating the same argument list.

use packetfin_core::tree::Bytes;
use packetfin_core::{Frame, Node};

/// One node of a packet tree and the state its field walk shares.
#[derive(Clone, Copy)]
pub(crate) struct RenderContext<'a, 'n, F> {
    /// The protocol node or container whose fields are being rendered.
    pub(crate) node: &'n Node,
    /// The frame that owns the decoded tree.
    pub(crate) frame: &'a Frame,
    /// Byte sources for raw field values.
    pub(crate) sources: &'a [Bytes],
    /// The writer's filter and visibility policy.
    pub(crate) filter: F,
}
