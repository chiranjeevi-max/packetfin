//! `io,phs`: protocol hierarchy statistics.
//!
//! Each protocol node is counted once per frame that contains it. The byte
//! count is the original frame length, so a snaplen-truncated capture still
//! reports the wire length. Children are listed in first-seen order and
//! duplicate protocols (IPv4-in-IPv4) nest under their parent.

use std::fmt;

use super::facts::FrameFacts;
use super::{Budget, Notices, StatsFilter};

/// One row of the hierarchy tree.
struct PhsNode {
    name: &'static str,
    frames: u64,
    bytes: u64,
    children: Vec<usize>,
}

/// Approximate bytes for one hierarchy row and one child link.
///
/// The arena grows geometrically, so a row costs up to twice its inline size
/// while the old vector is still alive; the child vector has the same slack.
const NODE_CHARGE: usize = std::mem::size_of::<PhsNode>() * 2 + 64;
const EDGE_CHARGE: usize = std::mem::size_of::<usize>() * 4;

/// Accumulated hierarchy for one `io,phs` specification.
#[derive(Default)]
pub struct State {
    nodes: Vec<PhsNode>,
    capped: bool,
}

impl State {
    pub(crate) fn observe(
        &mut self,
        facts: &FrameFacts<'_>,
        filter: &StatsFilter,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        if !filter.matches(facts.tree) {
            return;
        }
        if self.nodes.is_empty() {
            if !budget.reserve(NODE_CHARGE) {
                self.note_cap(notices);
                return;
            }
            self.nodes.push(PhsNode {
                name: "",
                frames: 0,
                bytes: 0,
                children: Vec::new(),
            });
        }
        let bytes = u64::from(facts.frame.original_len);
        // `path[d]` is the arena index of the node at protocol depth `d`.
        // The root pseudo-node sits at index 0 and is never printed.
        let mut path: Vec<usize> = vec![0];
        for fact in &facts.protocols {
            // The hierarchy skips a datagram quoted inside an ICMP error and
            // a message decoded inside a field: neither starts a protocol
            // layer, so the enclosing layer already counted the frame.
            if fact.quoted || fact.nested_in_field {
                continue;
            }
            let depth = fact.depth;
            path.truncate(depth + 1);
            let parent = if depth == 0 {
                0
            } else {
                path.get(depth - 1).copied().unwrap_or(0)
            };
            let name = fact.node.protocol.filter_name;
            let child = match self.nodes.get(parent) {
                Some(node) => node
                    .children
                    .iter()
                    .copied()
                    .find(|index| self.nodes.get(*index).is_some_and(|row| row.name == name)),
                None => None,
            };
            let index = match child {
                Some(index) => index,
                None => {
                    if !budget.reserve(NODE_CHARGE.saturating_add(EDGE_CHARGE)) {
                        self.note_cap(notices);
                        return;
                    }
                    let index = self.nodes.len();
                    self.nodes.push(PhsNode {
                        name,
                        frames: 0,
                        bytes: 0,
                        children: Vec::new(),
                    });
                    if let Some(node) = self.nodes.get_mut(parent) {
                        node.children.push(index);
                    }
                    index
                }
            };
            if let Some(node) = self.nodes.get_mut(index) {
                node.frames = node.frames.saturating_add(1);
                node.bytes = node.bytes.saturating_add(bytes);
            }
            path.truncate(depth);
            path.push(index);
        }
    }

    fn note_cap(&mut self, notices: &mut Notices) {
        if self.capped {
            return;
        }
        self.capped = true;
        notices.once(
            "io-phs-budget",
            "statistics budget reached; additional protocol hierarchy rows were dropped",
        );
    }

    pub(crate) fn finish(
        &mut self,
        filter: &StatsFilter,
        output: &mut dyn fmt::Write,
    ) -> fmt::Result {
        writeln!(output)?;
        writeln!(
            output,
            "==================================================================="
        )?;
        writeln!(output, "Protocol Hierarchy Statistics")?;
        writeln!(
            output,
            "Filter: {}",
            filter.header_text().unwrap_or_default()
        )?;
        writeln!(output)?;
        let Some(root) = self.nodes.first() else {
            writeln!(
                output,
                "==================================================================="
            )?;
            return Ok(());
        };
        // Iterative preorder so a hostile tunnel depth cannot exhaust the
        // renderer's stack.
        let mut pending: Vec<(usize, usize)> = root
            .children
            .iter()
            .rev()
            .map(|index| (*index, 0))
            .collect();
        while let Some((index, depth)) = pending.pop() {
            let Some(node) = self.nodes.get(index) else {
                continue;
            };
            let mut label = String::new();
            for level in 0..depth {
                if level > 15 {
                    label.push_str("...");
                    break;
                }
                label.push_str("  ");
            }
            label.push_str(node.name);
            writeln!(
                output,
                "{label:<40} frames:{} bytes:{}",
                node.frames, node.bytes
            )?;
            for child in node.children.iter().rev() {
                pending.push((*child, depth + 1));
            }
        }
        writeln!(
            output,
            "==================================================================="
        )?;
        Ok(())
    }
}
