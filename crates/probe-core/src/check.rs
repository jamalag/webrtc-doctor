//! The Check trait and the shared context passed through a pipeline run.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

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
    /// Post-allocation TURN session state. Populated by `turn.alloc.udp` and
    /// consumed by `turn.echo.udp` so the echo check can reuse the same
    /// authenticated socket (and same nonce/key) instead of allocating again.
    pub turn_session: Option<TurnSession>,
    /// Arbitrary key/value bag for cross-check state we haven't promoted to a
    /// typed field yet.
    pub scratch: HashMap<String, String>,
}

/// Everything a downstream TURN check needs to send authenticated requests
/// against the existing allocation (CreatePermission, Refresh, ChannelBind…)
/// without redoing the long-term-credential handshake.
#[derive(Debug, Clone)]
pub struct TurnSession {
    /// The UDP socket that already established the 5-tuple with the TURN
    /// server. `Arc` because the allocator owned it briefly and downstream
    /// checks need shared access; the socket itself is `Send`/`Sync`.
    pub socket: Arc<UdpSocket>,
    /// The TURN server's address we've been talking to.
    pub server: SocketAddr,
    /// The relay address the server allocated for us.
    pub relayed: SocketAddr,
    /// Realm the server requested in its 401 challenge (used in MI key).
    pub realm: String,
    /// Most recent nonce the server gave us. May need rotation on 438 Stale
    /// Nonce; that handling lives in the check that hits the staleness.
    pub nonce: Vec<u8>,
    /// Long-term credential key — `MD5(user:realm:pass)`.
    pub key: [u8; 16],
    /// Username we authenticated with (echoed back in every MI-protected
    /// request against this allocation).
    pub username: String,
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
