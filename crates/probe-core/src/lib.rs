//! WebRTC connectivity probe engine.
//!
//! Runs a pipeline of named checks (DNS, STUN, TURN alloc, TURN echo, DTLS,
//! ICE gathering, signaling) against a target and emits structured results.
//!
//! See `docs/PLAN.md` at the repo root for the design and roadmap.

use serde::{Deserialize, Serialize};

/// Outcome of a single check in a probe pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Stable identifier, e.g. "turn.alloc.udp". Used for JSON consumers.
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

/// A check is a single named diagnostic that runs against a target.
#[async_trait::async_trait]
pub trait Check: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    async fn run(&self, ctx: &ProbeContext) -> CheckResult;
}

/// Shared state passed into every check.
#[derive(Debug, Default)]
pub struct ProbeContext {
    // Populated by the CLI from clap; filled in as checks need it.
}

/// Placeholder API surface. Real engine wiring lands in the MVP build.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
