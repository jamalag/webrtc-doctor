//! The Check trait and the shared context passed through a pipeline run.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::result::CheckResult;

/// Shared state passed into every check. Mutable because the pipeline runs
/// checks sequentially and later checks consume earlier ones' output
/// (DNS resolves the host; STUN uses the IP).
#[derive(Debug, Default)]
pub struct ProbeContext {
    /// Per-check timeout. Individual checks may override.
    pub default_timeout: Duration,
    /// Hostname being probed (`stun.l.google.com`), if applicable.
    pub host: Option<String>,
    /// Port being probed.
    pub port: Option<u16>,
    /// IPs the DNS check resolved. Populated by `dns`, read by `stun`/`turn`.
    pub resolved_ips: Vec<IpAddr>,
    /// TURN credentials, when supplied.
    pub turn_user: Option<String>,
    pub turn_pass: Option<String>,
    /// Arbitrary key/value bag for cross-check state we haven't promoted to a
    /// typed field yet.
    pub scratch: HashMap<String, String>,
}

impl ProbeContext {
    pub fn new() -> Self {
        Self {
            default_timeout: Duration::from_secs(5),
            ..Self::default()
        }
    }
}

/// A single named diagnostic.
#[async_trait::async_trait]
pub trait Check: Send + Sync {
    /// Stable identifier, e.g. `"dns"`, `"stun.binding"`. Used by JSON
    /// consumers and as the dependency key for [`Check::requires`].
    fn id(&self) -> &'static str;

    /// Human-readable display name.
    fn name(&self) -> &'static str;

    /// IDs of checks that must have passed before this one runs. If any are
    /// missing or did not pass, the pipeline marks this check `Skip` without
    /// invoking `run`.
    fn requires(&self) -> &'static [&'static str] {
        &[]
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult;
}
