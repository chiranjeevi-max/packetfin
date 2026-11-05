//! `-z expert`: aggregated expert-info frequencies.
//!
//! Entries are grouped by severity and deduplicated on protocol plus summary
//! text, keeping the group of the first occurrence. Sections print in
//! severity order (Errors, Warns, Notes, Chats, Comments) and rows keep first
//! appearance order. Packet comments participate as Comment/Packet entries.

use std::collections::HashMap;
use std::fmt;

use crate::tree::{Group, Severity};

use super::facts::{ExpertFact, FrameFacts};
use super::{Budget, Notices, StatsFilter};

const MAX_KEYS: usize = 100_000;

/// Hash-table bucket and growth slack beyond the stored entry and key.
const MAP_OVERHEAD: usize = 128;

struct Entry {
    severity: Severity,
    group: Group,
    protocol: &'static str,
    summary: String,
    frequency: u64,
}

/// Parse `expert[,severity][,filter]`.
pub(crate) fn parse(text: &str) -> Result<(Severity, StatsFilter), String> {
    let args = text.strip_prefix("expert").unwrap_or(text);
    let mut minimum = Severity::Comment;
    let mut consumed = 0_usize;
    for (name, severity) in [
        (",error", Severity::Error),
        (",warn", Severity::Warning),
        (",note", Severity::Note),
        (",chat", Severity::Chat),
        (",comment", Severity::Comment),
    ] {
        if args
            .get(..name.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
        {
            minimum = severity;
            consumed = name.len();
            break;
        }
    }
    let rest = args.get(consumed..).unwrap_or_default();
    let filter = match rest.strip_prefix(',') {
        Some(filter) => StatsFilter::compile(filter, "Expert tap error (", ")!")?,
        None => StatsFilter::none(),
    };
    Ok((minimum, filter))
}

/// Aggregated expert entries for one `-z expert` specification.
#[derive(Default)]
pub struct State {
    entries: Vec<Entry>,
    index: HashMap<(Severity, &'static str, String), usize>,
    capped: bool,
}

impl State {
    pub(crate) fn observe(
        &mut self,
        facts: &FrameFacts<'_>,
        minimum: Severity,
        filter: &StatsFilter,
        budget: &mut Budget,
        notices: &mut Notices,
    ) {
        if !filter.matches(facts.tree) {
            return;
        }
        let comments = facts
            .frame
            .comments
            .iter()
            .map(|comment| ExpertFact {
                severity: Severity::Comment,
                group: Group::Comment,
                protocol: "Packet",
                summary: comment,
            })
            .collect::<Vec<_>>();
        for expert in comments.iter().chain(facts.experts.iter()) {
            if expert.severity < minimum {
                continue;
            }
            self.add(expert, budget, notices);
        }
    }

    fn add(&mut self, expert: &ExpertFact<'_>, budget: &mut Budget, notices: &mut Notices) {
        let key = (expert.severity, expert.protocol, expert.summary.to_string());
        if let Some(index) = self.index.get(&key) {
            if let Some(entry) = self.entries.get_mut(*index) {
                entry.frequency = entry.frequency.saturating_add(1);
            }
            return;
        }
        if self.entries.len() >= MAX_KEYS {
            self.note_cap(notices);
            return;
        }
        let charge = std::mem::size_of::<Entry>()
            + expert.summary.len()
            + expert.summary.len()
            + std::mem::size_of::<(Severity, &'static str, String)>()
            + MAP_OVERHEAD;
        if !budget.reserve(charge) {
            self.note_cap(notices);
            return;
        }
        let index = self.entries.len();
        self.entries.push(Entry {
            severity: expert.severity,
            group: expert.group,
            protocol: expert.protocol,
            summary: expert.summary.to_string(),
            frequency: 1,
        });
        self.index.insert(key, index);
    }

    fn note_cap(&mut self, notices: &mut Notices) {
        if self.capped {
            return;
        }
        self.capped = true;
        notices.once(
            "expert-keys",
            "statistics budget reached; additional expert entries were dropped",
        );
    }

    pub(crate) fn finish(
        &mut self,
        minimum: Severity,
        filter: &StatsFilter,
        output: &mut dyn fmt::Write,
    ) -> fmt::Result {
        let _ = (minimum, filter);
        for (severity, label) in [
            (Severity::Error, "Errors"),
            (Severity::Warning, "Warns"),
            (Severity::Note, "Notes"),
            (Severity::Chat, "Chats"),
            (Severity::Comment, "Comments"),
        ] {
            let entries: Vec<&Entry> = self
                .entries
                .iter()
                .filter(|entry| entry.severity == severity)
                .collect();
            if entries.is_empty() {
                continue;
            }
            let total: u64 = entries
                .iter()
                .map(|entry| entry.frequency)
                .fold(0_u64, u64::saturating_add);
            writeln!(output)?;
            writeln!(output, "{label} ({total})")?;
            writeln!(output, "=============")?;
            writeln!(
                output,
                "   Frequency      Group           Protocol  Summary"
            )?;
            for entry in entries {
                writeln!(
                    output,
                    "{:>12} {:>10} {:>18}  {}",
                    entry.frequency,
                    entry.group.name(),
                    entry.protocol,
                    entry.summary
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_filters_do_not_split_a_character() {
        assert!(parse("expert,é").is_err());
    }

    #[test]
    fn severity_names_are_case_insensitive_and_ordered() {
        let Ok((minimum, filter)) = parse("expert,WARN") else {
            eprintln!("expert,WARN did not parse");
            return;
        };
        assert_eq!(minimum, Severity::Warning);
        assert!(filter.filter.is_none());
        let Ok((minimum, filter)) = parse("expert,error,tcp") else {
            eprintln!("expert,error,tcp did not parse");
            return;
        };
        assert_eq!(minimum, Severity::Error);
        assert_eq!(filter.text.as_deref(), Some("tcp"));
    }

    #[test]
    fn a_tiny_budget_keeps_new_expert_keys_bounded() {
        let mut state = State::default();
        let mut budget = Budget::new(0);
        let mut notices = Notices::default();
        for index in 0..1_000 {
            let summary = format!("summary {index}");
            let expert = ExpertFact {
                severity: Severity::Note,
                group: Group::Sequence,
                protocol: "TCP",
                summary: &summary,
            };
            state.add(&expert, &mut budget, &mut notices);
        }
        assert!(state.entries.is_empty());
        assert!(
            notices
                .messages
                .iter()
                .any(|message| message.contains("expert entries")),
            "{:?}",
            notices.messages
        );
    }
}
