//! Structured outcome of a single check. This is the JSON contract that the
//! SaaS orchestrator will persist later — keep it stable.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    /// Skipped because a prerequisite check failed or the target wasn't supplied.
    Skip,
}

impl CheckStatus {
    pub fn is_failure(self) -> bool {
        matches!(self, CheckStatus::Fail)
    }
}

/// Outcome of a single check in a probe pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Stable identifier, e.g. "turn.alloc.udp". Used by JSON consumers.
    pub id: String,
    /// Human-readable name, e.g. "TURN allocation (UDP)".
    pub name: String,
    pub status: CheckStatus,
    /// Wall-clock duration of the check in milliseconds.
    pub latency_ms: u64,
    /// One-line summary suitable for the pretty report.
    pub summary: String,
    /// Optional structured detail (raw addresses, headers, error chains).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl CheckResult {
    pub fn pass(id: &str, name: &str, latency_ms: u64, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status: CheckStatus::Pass,
            latency_ms,
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn fail(id: &str, name: &str, latency_ms: u64, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status: CheckStatus::Fail,
            latency_ms,
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn warn(id: &str, name: &str, latency_ms: u64, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status: CheckStatus::Warn,
            latency_ms,
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn skip(id: &str, name: &str, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            status: CheckStatus::Skip,
            latency_ms: 0,
            summary: summary.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}
