//! The ordered counter tree shared by `dns,tree` and `http,tree`.
//!
//! Layout and arithmetic:
//! a node ticks per event, a value node keeps count/sum/min/max, the rate is
//! the count over the capture duration in milliseconds, the percentage is
//! against the parent's count, and the burst is the peak number of events in
//! any 100 ms window divided by 100. Bursts group events into 5 ms buckets.
//! The table width is computed from the widest name; every numerical column
//! is 13 characters wide after its leading space.
//!
//! Root children keep their registration order unless a tree asks for the
//! HTTP ordering, where the root is sorted too. Every other group sorts its
//! children by count descending and then by bytewise name descending. Node
//! creation is charged to the statistics budget and capped, so a hostile
//! capture cannot grow the tree without bound.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use super::{Budget, Notices};

/// Burst bucket length in nanoseconds (5 ms).
const BURST_RESOLUTION_NS: i128 = 5_000_000;
/// Burst window in buckets (100 ms at the 5 ms resolution).
const BURST_BUCKETS: i128 = 20;
/// Most nodes one tree keeps; beyond this a notice is printed.
const MAX_NODES: usize = 1_000_000;

/// One counter tree.
pub(crate) struct Tree {
    title: &'static str,
    nodes: Vec<Node>,
    root: usize,
    created: usize,
    sort_root: bool,
    first_ns: Option<i64>,
    last_ns: i64,
}

struct Node {
    name: String,
    parent: Option<usize>,
    depth: usize,
    children: Vec<usize>,
    index: Option<HashMap<String, usize>>,
    count: u64,
    average: Option<Average>,
    burst: Bursts,
}

enum Average {
    Integer { total: i128, min: i64, max: i64 },
    Float { total: f64, min: f64, max: f64 },
}

struct Bursts {
    buckets: VecDeque<Bucket>,
    count: u64,
    max: u64,
    start_ns: i64,
}

struct Bucket {
    number: i128,
    count: u64,
    start_ns: i64,
}

impl Tree {
    /// Create a tree with its title and a root pseudo-node.
    pub(crate) fn new(title: &'static str, sort_root: bool) -> Self {
        let root = Node {
            name: String::new(),
            parent: None,
            depth: 0,
            children: Vec::new(),
            index: None,
            count: 0,
            average: None,
            burst: Bursts::default(),
        };
        Self {
            title,
            nodes: vec![root],
            root: 0,
            created: 1,
            sort_root,
            first_ns: None,
            last_ns: 0,
        }
    }

    /// Create a fixed root child.
    pub(crate) fn root_child(&mut self, name: &'static str) -> usize {
        self.insert(self.root, name, false)
    }

    /// Create a fixed child.
    pub(crate) fn child(&mut self, parent: usize, name: &'static str) -> usize {
        self.insert(parent, name, false)
    }

    /// Look up or create one lazily-created pivot child.
    pub(crate) fn pivot_child(
        &mut self,
        parent: usize,
        name: &str,
        budget: &mut Budget,
        notices: &mut Notices,
    ) -> Option<usize> {
        if self.nodes.get(parent)?.index.is_none() {
            let mut map = HashMap::new();
            let children = self.nodes.get(parent)?.children.clone();
            for child in children {
                if let Some(node) = self.nodes.get(child) {
                    map.insert(node.name.clone(), child);
                }
            }
            if let Some(node) = self.nodes.get_mut(parent) {
                node.index = Some(map);
            }
        }
        if let Some(index) = self.nodes.get(parent)?.index.as_ref()
            && let Some(node) = index.get(name)
        {
            return Some(*node);
        }
        if self.created >= MAX_NODES {
            notices.once(
                "stat-tree-nodes",
                "statistics tree node limit reached; further rows were dropped",
            );
            return None;
        }
        let bytes = size_of_node(name);
        if !budget.reserve(bytes) {
            notices.once(
                "stat-tree-budget",
                "statistics budget reached; further tree rows were dropped",
            );
            return None;
        }
        Some(self.insert(parent, name, true))
    }

    fn insert(&mut self, parent: usize, name: &str, indexed: bool) -> usize {
        let index = self.nodes.len();
        let depth = self
            .nodes
            .get(parent)
            .map(|node| node.depth.saturating_add(1))
            .unwrap_or(0);
        self.nodes.push(Node {
            name: name.to_string(),
            parent: Some(parent),
            depth,
            children: Vec::new(),
            index: indexed.then(HashMap::new),
            count: 0,
            average: None,
            burst: Bursts::default(),
        });
        self.created = self.created.saturating_add(1);
        if let Some(parent) = self.nodes.get_mut(parent) {
            parent.children.push(index);
            if let Some(map) = parent.index.as_mut() {
                map.insert(name.to_string(), index);
            }
        }
        index
    }

    /// Track one event time; the rate spans the first and last tap event.
    fn observe_time(&mut self, time_ns: i64) -> i64 {
        self.first_ns.get_or_insert(time_ns);
        self.last_ns = time_ns.max(self.last_ns);
        time_ns
    }

    /// Count one event.
    pub(crate) fn tick(&mut self, node: usize, time_ns: i64) {
        let time_ns = self.observe_time(time_ns);
        if let Some(node) = self.nodes.get_mut(node) {
            node.count = node.count.saturating_add(1);
            node.burst.add(time_ns, 1);
        }
    }

    /// Tick a pivot parent and its child row.
    pub(crate) fn tick_pivot(
        &mut self,
        parent: usize,
        name: &str,
        time_ns: i64,
        budget: &mut Budget,
        notices: &mut Notices,
    ) -> bool {
        let Some(child) = self.pivot_child(parent, name, budget, notices) else {
            return false;
        };
        let time_ns = self.observe_time(time_ns);
        if let Some(node) = self.nodes.get_mut(parent) {
            node.count = node.count.saturating_add(1);
            node.burst.add(time_ns, 1);
        }
        if let Some(node) = self.nodes.get_mut(child) {
            node.count = node.count.saturating_add(1);
            node.burst.add(time_ns, 1);
        }
        true
    }

    /// Count one integer value.
    pub(crate) fn add_int(&mut self, node: usize, value: i64, time_ns: i64) {
        let time_ns = self.observe_time(time_ns);
        if let Some(node) = self.nodes.get_mut(node) {
            node.count = node.count.saturating_add(1);
            node.burst.add(time_ns, 1);
            match &mut node.average {
                Some(Average::Integer { total, min, max }) => {
                    *total = total.saturating_add(i128::from(value));
                    *min = (*min).min(value);
                    *max = (*max).max(value);
                }
                Some(Average::Float { .. }) => {}
                None => {
                    node.average = Some(Average::Integer {
                        total: i128::from(value),
                        min: value,
                        max: value,
                    });
                }
            }
        }
    }

    /// Count one floating-point value.
    pub(crate) fn add_float(&mut self, node: usize, value: f64, time_ns: i64) {
        let time_ns = self.observe_time(time_ns);
        if let Some(node) = self.nodes.get_mut(node) {
            node.count = node.count.saturating_add(1);
            node.burst.add(time_ns, 1);
            match &mut node.average {
                Some(Average::Float { total, min, max }) => {
                    *total += value;
                    *min = min.min(value);
                    *max = max.max(value);
                }
                Some(Average::Integer { .. }) => {}
                None => {
                    node.average = Some(Average::Float {
                        total: value,
                        min: value,
                        max: value,
                    });
                }
            }
        }
    }

    /// Render the plain table.
    pub(crate) fn finish(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        let width = self
            .nodes
            .iter()
            .map(|node| node.depth.saturating_add(node.name.len()))
            .max()
            .unwrap_or(0);
        let separator = width + 8 * 14;
        write!(output, "\n{}", "=".repeat(separator))?;
        writeln!(output, "\n{}:", self.title)?;
        const HEADERS: [&str; 8] = [
            "Count",
            "Average",
            "Min Val",
            "Max Val",
            "Rate (ms)",
            "Percent",
            "Burst Rate",
            "Burst Start",
        ];
        write!(output, "{:<width$}", "Packet Type", width = width)?;
        for header in HEADERS {
            write!(output, " {header:<13}")?;
        }
        writeln!(output)?;
        writeln!(output, "{}", "-".repeat(separator))?;
        let first = self.first_ns.unwrap_or(0);
        let duration_ms = (self.last_ns - first) as f64 / 1_000_000.0;
        let mut children = self.root_children();
        if self.sort_root {
            self.sort_children(&mut children);
        }
        for child in children {
            self.render_node(child, width, duration_ms, output)?;
        }
        writeln!(output)?;
        writeln!(output, "{}", "-".repeat(separator))
    }

    fn root_children(&self) -> Vec<usize> {
        self.nodes
            .get(self.root)
            .map(|node| node.children.clone())
            .unwrap_or_default()
    }

    fn render_node(
        &self,
        node: usize,
        width: usize,
        duration_ms: f64,
        output: &mut dyn fmt::Write,
    ) -> fmt::Result {
        let Some(current) = self.nodes.get(node) else {
            return Ok(());
        };
        let indent = current.depth.saturating_sub(1);
        let mut name = " ".repeat(indent);
        name.push_str(&current.name);
        let count = current.count.to_string();
        let (average, minimum, maximum) = match &current.average {
            Some(Average::Integer { total, min, max }) => {
                if current.count == 0 {
                    ("-".to_string(), "-".to_string(), "-".to_string())
                } else {
                    (
                        format!("{:.2}", *total as f64 / current.count as f64),
                        min.to_string(),
                        max.to_string(),
                    )
                }
            }
            Some(Average::Float { total, min, max }) => {
                if current.count == 0 {
                    ("-".to_string(), "-".to_string(), "-".to_string())
                } else {
                    (
                        format!("{:.2}", total / current.count as f64),
                        format!("{min:.6}"),
                        format!("{max:.6}"),
                    )
                }
            }
            None => (String::new(), String::new(), String::new()),
        };
        let rate = if duration_ms > 0.0 {
            format!("{:.4}", current.count as f64 / duration_ms)
        } else {
            String::new()
        };
        let percent = match current.parent {
            Some(parent) if parent == self.root => "100%".to_string(),
            Some(parent) => match self.nodes.get(parent) {
                Some(parent) if parent.count > 0 => {
                    format!("{:.2}%", current.count as f64 * 100.0 / parent.count as f64)
                }
                _ => String::new(),
            },
            None => "100%".to_string(),
        };
        let (burst_rate, burst_start) = if current.burst.max > 0 {
            (
                format!("{:.4}", current.burst.max as f64 / 100.0),
                format!("{:.3}", current.burst.start_ns as f64 / 1_000_000_000.0),
            )
        } else {
            ("-".to_string(), "-".to_string())
        };
        write!(output, "{name:<width$}", width = width)?;
        for value in [
            count,
            average,
            minimum,
            maximum,
            rate,
            percent,
            burst_rate,
            burst_start,
        ] {
            write!(output, " {value:<13}")?;
        }
        writeln!(output)?;
        let mut children = current.children.clone();
        if node != self.root {
            self.sort_children(&mut children);
        }
        for child in children {
            self.render_node(child, width, duration_ms, output)?;
        }
        Ok(())
    }
}

impl Tree {
    fn sort_children(&self, children: &mut [usize]) {
        children.sort_by(|left, right| {
            let left = self.nodes.get(*left);
            let right = self.nodes.get(*right);
            let left_count = left.map_or(0, |node| node.count);
            let right_count = right.map_or(0, |node| node.count);
            right_count.cmp(&left_count).then_with(|| {
                let left_name = left.map(|node| node.name.as_str());
                let right_name = right.map(|node| node.name.as_str());
                right_name.cmp(&left_name)
            })
        });
    }
}

impl Default for Bursts {
    fn default() -> Self {
        Self {
            buckets: VecDeque::from([Bucket {
                number: 0,
                count: 0,
                start_ns: 0,
            }]),
            count: 0,
            max: 0,
            start_ns: 0,
        }
    }
}

impl Bursts {
    fn add(&mut self, time_ns: i64, value: u64) {
        let number = i128::from(time_ns).div_euclid(BURST_RESOLUTION_NS);
        let Some(front) = self.buckets.front() else {
            self.buckets.push_back(Bucket {
                number,
                count: value,
                start_ns: time_ns,
            });
            self.count = value;
            self.record();
            return;
        };
        let back = self
            .buckets
            .back()
            .map(|bucket| bucket.number)
            .unwrap_or(number);
        if number > back {
            self.buckets.push_back(Bucket {
                number,
                count: value,
                start_ns: time_ns,
            });
            self.count = self.count.saturating_add(value);
            while number
                >= self.buckets.front().map_or(number, |bucket| bucket.number) + BURST_BUCKETS
            {
                let Some(bucket) = self.buckets.pop_front() else {
                    break;
                };
                self.count = self.count.saturating_sub(bucket.count);
            }
        } else if number < front.number {
            if number + BURST_BUCKETS > back {
                self.buckets.push_front(Bucket {
                    number,
                    count: value,
                    start_ns: time_ns,
                });
                self.count = self.count.saturating_add(value);
            } else {
                return;
            }
        } else {
            let position = self
                .buckets
                .iter()
                .position(|bucket| bucket.number >= number)
                .unwrap_or(self.buckets.len());
            if let Some(bucket) = self.buckets.get_mut(position)
                && bucket.number == number
            {
                bucket.count = bucket.count.saturating_add(value);
                bucket.start_ns = bucket.start_ns.min(time_ns);
            } else {
                self.buckets.insert(
                    position,
                    Bucket {
                        number,
                        count: value,
                        start_ns: time_ns,
                    },
                );
            }
            self.count = self.count.saturating_add(value);
        }
        self.record();
    }

    fn record(&mut self) {
        if self.count > self.max {
            self.max = self.count;
            self.start_ns = self.buckets.front().map_or(0, |bucket| bucket.start_ns);
        }
    }
}

fn size_of_node(name: &str) -> usize {
    // A pivot node is indexed by its parent, so its name is stored twice.
    // The burst ring can reach BURST_BUCKETS entries, and the arena and
    // child vectors grow geometrically.
    std::mem::size_of::<Node>()
        + name.len().saturating_mul(2)
        + BURST_BUCKETS as usize * std::mem::size_of::<Bucket>()
        + 128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{Budget, Notices};

    #[test]
    fn children_sort_by_count_then_bytewise_name_descending() {
        let mut tree = Tree::new("Test", true);
        let parent = tree.root_child("Parent");
        let first = tree.child(parent, "alpha");
        let second = tree.child(parent, "Beta");
        let third = tree.child(parent, "gamma");
        tree.tick(first, 0);
        tree.tick(first, 0);
        tree.tick(second, 0);
        tree.tick(third, 0);
        let mut output = String::new();
        tree.finish(&mut output).unwrap_or(());
        let alpha = output.find("alpha").unwrap_or(usize::MAX);
        let beta = output.find("Beta").unwrap_or(usize::MAX);
        let gamma = output.find("gamma").unwrap_or(usize::MAX);
        assert!(alpha < gamma && gamma < beta, "{output}");
    }

    #[test]
    fn burst_uses_the_hundred_millisecond_window() {
        let mut tree = Tree::new("Test", false);
        let node = tree.root_child("Events");
        tree.tick(node, 0);
        tree.tick(node, 10_000_000);
        tree.tick(node, 200_000_000);
        let mut output = String::new();
        tree.finish(&mut output).unwrap_or(());
        assert!(output.contains("0.0200"), "{output}");
        assert!(output.contains("0.000"), "{output}");
    }

    #[test]
    fn a_million_pivot_nodes_hit_the_cap() {
        let mut tree = Tree::new("Test", false);
        let parent = tree.root_child("Events");
        let mut budget = Budget::new(usize::MAX);
        let mut notices = Notices::default();
        for index in 0..=MAX_NODES {
            tree.pivot_child(parent, &format!("row {index}"), &mut budget, &mut notices);
        }
        assert!(tree.created <= MAX_NODES);
        assert!(
            notices
                .messages
                .iter()
                .any(|notice| notice.contains("node limit"))
        );
    }

    #[test]
    fn a_tiny_budget_stops_new_pivot_rows() {
        let mut tree = Tree::new("Test", false);
        let parent = tree.root_child("Events");
        let mut budget = Budget::new(1);
        let mut notices = Notices::default();
        assert!(
            tree.pivot_child(parent, "row", &mut budget, &mut notices)
                .is_none()
        );
        assert!(!notices.messages.is_empty());
    }
}
