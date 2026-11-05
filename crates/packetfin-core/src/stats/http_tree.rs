//! `-z http,tree`: the HTTP packet counter tree.
//!
//! The schema: Total HTTP Packets, the request-method pivot,
//! Response Packets with the 1xx/2xx/3xx/4xx/5xx and broken classes, the
//! status-code rows below those classes, and Other HTTP Packets. A response
//! code is classified by its three-digit class (below 100 and at or above 600
//! are broken); the status row prints `<code> <reason>` from the IANA table,
//! not the reason text found on the wire.

use std::fmt;

use crate::tree::Value;

use super::facts::{FrameFacts, ProtocolFact};
use super::stat_tree::Tree;
use super::{Budget, Clock, Notices, StatsFilter};

/// Fields the HTTP tree reads from the decoded frame.
pub(crate) const FIELDS: &[&str] = &["http.request.method", "http.response.code"];

/// Aggregation state for one `http,tree` specification.
pub(crate) struct State {
    tree: Tree,
    total: usize,
    requests: usize,
    responses: usize,
    broken: usize,
    classes: [usize; 5],
    other: usize,
}

impl Default for State {
    fn default() -> Self {
        let mut tree = Tree::new("HTTP / Packet Counter", true);
        let total = tree.root_child("Total HTTP Packets");
        let requests = tree.child(total, "HTTP Request Packets");
        let responses = tree.child(total, "HTTP Response Packets");
        let broken = tree.child(responses, "???: broken");
        let classes = [
            tree.child(responses, "1xx: Informational"),
            tree.child(responses, "2xx: Success"),
            tree.child(responses, "3xx: Redirection"),
            tree.child(responses, "4xx: Client Error"),
            tree.child(responses, "5xx: Server Error"),
        ];
        let other = tree.child(total, "Other HTTP Packets");
        Self {
            tree,
            total,
            requests,
            responses,
            broken,
            classes,
            other,
        }
    }
}

impl State {
    /// Observe one frame.
    pub(crate) fn observe(
        &mut self,
        facts: &FrameFacts<'_>,
        filter: &StatsFilter,
        clock: &Clock,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        if !filter.matches(facts.tree) {
            return;
        }
        let time = clock.relative_ns;
        for fact in facts
            .protocols
            .iter()
            .filter(|fact| fact.node.protocol.filter_name == "http" && !fact.quoted)
        {
            self.observe_message(facts, fact, time, budget, notices);
        }
    }

    fn observe_message(
        &mut self,
        facts: &FrameFacts<'_>,
        fact: &ProtocolFact<'_>,
        time: i64,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        self.tree.tick(self.total, time);
        let code = facts
            .fact_first_field(fact, "http.response.code")
            .and_then(value_u16)
            .filter(|code| *code != 0);
        if let Some(code) = code {
            self.tree.tick(self.responses, time);
            let group = if !(100..600).contains(&code) {
                self.broken
            } else {
                let index = usize::from(code / 100).saturating_sub(1).min(4);
                self.classes.get(index).copied().unwrap_or(self.broken)
            };
            self.tree.tick(group, time);
            let status = format!("{code} {}", status_reason(code));
            if let Some(node) = self.tree.pivot_child(group, &status, budget, notices) {
                self.tree.tick(node, time);
            }
        } else if let Some(method) = facts
            .fact_first_field(fact, "http.request.method")
            .and_then(value_text)
        {
            self.tree
                .tick_pivot(self.requests, method, time, budget, notices);
        } else {
            self.tree.tick(self.other, time);
        }
    }

    /// Render the tree.
    pub(crate) fn finish(&self, output: &mut dyn fmt::Write) -> fmt::Result {
        self.tree.finish(output)
    }
}

fn value_u16(value: &Value) -> Option<u16> {
    match value {
        Value::Uint8(value) => Some(u16::from(*value)),
        Value::Uint16(value) => Some(*value),
        Value::Uint24(value) | Value::Uint32(value) => u16::try_from(*value).ok(),
        Value::Uint64(value) => u16::try_from(*value).ok(),
        Value::Int8(value) => u16::try_from(*value).ok(),
        Value::Int16(value) => u16::try_from(*value).ok(),
        Value::Int32(value) => u16::try_from(*value).ok(),
        Value::Int64(value) => u16::try_from(*value).ok(),
        _ => None,
    }
}

fn value_text(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) => Some(text.as_str()),
        _ => None,
    }
}

/// The IANA reason phrase the status table prints for a code.
fn status_reason(code: u16) -> String {
    let reason = match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        // Only the unassigned x99 code of each class, 199 through 599, gets
        // a class fallback. Every other unassigned code, including 209 and
        // 596, prints Unknown.
        _ => {
            let class_other = code % 100 == 99 && (100..=599).contains(&code);
            if !class_other {
                return format!("Unknown ({code})");
            }
            return match code / 100 {
                1 => "Informational - Others".to_string(),
                2 => "Success - Others".to_string(),
                3 => "Redirection - Others".to_string(),
                4 => "Client Error - Others".to_string(),
                5 => "Server Error - Others".to_string(),
                _ => format!("Unknown ({code})"),
            };
        }
    };
    reason.to_string()
}
