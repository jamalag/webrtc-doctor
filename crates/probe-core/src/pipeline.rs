//! Pipeline runner and aggregated `Report`.
//!
//! Checks run sequentially against a single mutable [`ProbeContext`]. Each
//! check declares its prerequisites via [`Check::requires`]; if any
//! prerequisite did not pass, the runner records a `Skip` without invoking
//! `run`, so a failed DNS resolution cascades cleanly into "STUN skipped".

use std::collections::HashSet;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::check::{Check, ProbeContext};
use crate::result::{CheckResult, CheckStatus};

/// Final verdict for a complete pipeline run. Maps to the process exit code
/// the CLI returns: `Healthy → 0`, `Warnings → 2`, `Failed → 1`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Healthy,
    Warnings,
    Failed,
}

impl Verdict {
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Healthy => 0,
            Verdict::Failed => 1,
            Verdict::Warnings => 2,
        }
    }
}

/// Aggregated outcome of a pipeline run.
///
/// `Serialize` is hand-rolled to inject the computed `verdict` field at the
/// top of the JSON object — convenient for `jq` consumers and TSDB
/// scrapers that want a single field to alert on, without having to fold
/// over `results[].status`.
#[derive(Debug, Clone)]
pub struct Report {
    pub results: Vec<CheckResult>,
    /// Total wall-clock time across the whole pipeline, in milliseconds.
    pub total_ms: u64,
}

impl Serialize for Report {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Field order is preserved by serde_json — put the summary fields
        // (verdict, total_ms) first so a human reading the JSON sees the
        // outcome before scrolling through per-check detail.
        let mut s = serializer.serialize_struct("Report", 3)?;
        s.serialize_field("verdict", &self.verdict())?;
        s.serialize_field("total_ms", &self.total_ms)?;
        s.serialize_field("results", &self.results)?;
        s.end()
    }
}

impl Report {
    pub fn verdict(&self) -> Verdict {
        let mut any_warn = false;
        for r in &self.results {
            match r.status {
                CheckStatus::Fail => return Verdict::Failed,
                CheckStatus::Warn => any_warn = true,
                _ => {}
            }
        }
        if any_warn {
            Verdict::Warnings
        } else {
            Verdict::Healthy
        }
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut p = 0;
        let mut w = 0;
        let mut f = 0;
        let mut s = 0;
        for r in &self.results {
            match r.status {
                CheckStatus::Pass => p += 1,
                CheckStatus::Warn => w += 1,
                CheckStatus::Fail => f += 1,
                CheckStatus::Skip => s += 1,
            }
        }
        (p, w, f, s)
    }
}

/// Linear pipeline of named checks.
#[derive(Default)]
pub struct Pipeline {
    checks: Vec<Box<dyn Check>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a check to the pipeline. Named `push` (not `add`) to mirror
    /// `Vec::push` semantics and to avoid shadowing `std::ops::Add::add`,
    /// which `clippy::should_implement_trait` flags as a builder-pattern
    /// pitfall.
    pub fn push<C: Check + 'static>(mut self, check: C) -> Self {
        self.checks.push(Box::new(check));
        self
    }

    /// Run every check sequentially, honoring [`Check::requires`].
    pub async fn run(&self, ctx: &mut ProbeContext) -> Report {
        let started = std::time::Instant::now();
        let mut results: Vec<CheckResult> = Vec::with_capacity(self.checks.len());
        // IDs of prior checks that passed — used to decide whether a check's
        // prerequisites are satisfied.
        let mut passed: HashSet<&'static str> = HashSet::new();

        for check in &self.checks {
            let missing: Vec<&'static str> = check
                .requires()
                .iter()
                .copied()
                .filter(|id| !passed.contains(id))
                .collect();

            let result = if missing.is_empty() {
                check.run(ctx).await
            } else {
                CheckResult::skip(
                    check.id(),
                    check.name(),
                    format!("prerequisite not satisfied: {}", missing.join(", ")),
                )
            };

            if result.status == CheckStatus::Pass {
                passed.insert(check.id());
            }
            results.push(result);
        }

        Report {
            results,
            total_ms: started.elapsed().as_millis() as u64,
        }
    }
}
