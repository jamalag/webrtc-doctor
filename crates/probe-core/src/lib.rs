//! WebRTC connectivity probe engine.
//!
//! Runs a pipeline of named checks (DNS, STUN, TURN alloc, TURN echo, DTLS,
//! ICE gathering, signaling) against a target and emits structured results.
//!
//! See `docs/PLAN.md` at the repo root for the design and roadmap.

pub mod check;
pub mod checks;
pub mod pipeline;
pub mod result;
pub mod stun_codec;

pub use check::{Check, ProbeContext, TurnSession};
pub use pipeline::{Pipeline, Report, Verdict};
pub use result::{CheckResult, CheckStatus};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
