//! TURN allocation check (UDP transport).
//!
//! Sends an `Allocate` request to `ctx.host:ctx.port`. Without credentials,
//! the server replies `401 Unauthorized` with REALM and NONCE — we accept
//! that as a soft signal ("server speaks TURN") and report `Warn`. With
//! credentials, we follow the long-term credential dance (RFC 5389 §10.2 +
//! RFC 5766 §6.2): retry the Allocate with USERNAME/REALM/NONCE/
//! MESSAGE-INTEGRITY and parse `XOR-RELAYED-ADDRESS` from the success
//! response.
//!
//! Wire-level message building, MI attachment, key derivation, and the
//! Allocate response parser live in [`crate::turn_codec`] — same code
//! drives `turns_alloc` (the TLS transport) and the auth helpers used
//! by `turn_echo`.
//!
//! We do not verify the server's MESSAGE-INTEGRITY on the response in MVP;
//! the relay address itself is the operational signal. Verification lands
//! when we have a paranoid-mode flag.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::check::{Check, ProbeContext, TurnSession};
use crate::result::CheckResult;
use crate::turn_codec::{
    build_allocate_authed, build_allocate_unauth, long_term_key, parse_allocate_response,
    AllocateOutcome,
};

const ID: &str = "turn.alloc.udp";
const NAME: &str = "TURN allocation (UDP)";

pub struct TurnAllocateCheck;

#[async_trait::async_trait]
impl Check for TurnAllocateCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn requires(&self) -> &'static [&'static str] {
        &["dns"]
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let port = match ctx.port {
            Some(p) => p,
            None => return CheckResult::skip(ID, NAME, "no port supplied"),
        };
        let ip = match ctx.resolved_ips.first().copied() {
            Some(ip) => ip,
            None => return CheckResult::skip(ID, NAME, "no resolved IP"),
        };

        let server = SocketAddr::new(ip, port);
        let started = Instant::now();

        let local_bind: SocketAddr = match ip {
            IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            IpAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        // Wrap in Arc up front so we can hand it to ctx.turn_session for
        // turn_echo to reuse without a second allocation round-trip.
        let sock = match UdpSocket::bind(local_bind).await {
            Ok(s) => Arc::new(s),
            Err(e) => return fail_now(started, format!("local UDP bind failed: {e}")),
        };

        let recv_timeout = if ctx.default_timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            ctx.default_timeout
        };

        // Round 1: unauthenticated Allocate. Always expected to be rejected
        // with 401 — that's the protocol's challenge step.
        let (txid1, req1) = build_allocate_unauth();
        if let Err(e) = sock.send_to(&req1, server).await {
            return fail_now(started, format!("send (unauth) to {server} failed: {e}"));
        }
        let mut buf = [0u8; 1500];
        let n1 = match timeout(recv_timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => n,
            Ok(Err(e)) => return fail_now(started, format!("recv (unauth) failed: {e}")),
            Err(_) => {
                return fail_now(
                    started,
                    format!("no Allocate response from {server} in {:?}", recv_timeout),
                )
            }
        };

        let outcome1 = match parse_allocate_response(&buf[..n1], &txid1) {
            Ok(o) => o,
            Err(e) => return fail_now(started, format!("malformed Allocate response: {e}")),
        };

        let (realm, nonce) = match outcome1 {
            AllocateOutcome::Unauthorized { realm, nonce } => (realm, nonce),
            AllocateOutcome::Success { relayed, .. } => {
                // Some non-standard relays accept anonymous allocations. Take it.
                let ms = started.elapsed().as_millis() as u64;
                ctx.scratch.insert("relayed".into(), relayed.to_string());
                return CheckResult::pass(
                    ID,
                    NAME,
                    ms,
                    format!("relay {relayed} (anonymous alloc, {ms} ms)"),
                )
                .with_detail(json!({
                    "server": server.to_string(),
                    "relayed": relayed.to_string(),
                    "auth": "none",
                }));
            }
            AllocateOutcome::Error { code, reason } => {
                let ms = started.elapsed().as_millis() as u64;
                return CheckResult::fail(ID, NAME, ms, format!("server returned {code} {reason}"));
            }
        };

        // No credentials? That's still a useful signal: the server is alive
        // and speaks TURN. Surface the realm so the user knows what to auth
        // against.
        let (user, pass) = match (ctx.turn_user.as_ref(), ctx.turn_pass.as_ref()) {
            (Some(u), Some(p)) => (u.clone(), p.clone()),
            _ => {
                let ms = started.elapsed().as_millis() as u64;
                return CheckResult::warn(
                    ID,
                    NAME,
                    ms,
                    format!("auth challenge from realm \"{realm}\" — no --user/--pass supplied"),
                )
                .with_detail(json!({
                    "server": server.to_string(),
                    "realm": realm,
                    "auth": "challenge-only",
                }));
            }
        };

        // Round 2: authenticated Allocate.
        let key = long_term_key(&user, &realm, &pass);
        let (txid2, req2) = build_allocate_authed(&user, &realm, &nonce, &key);
        if let Err(e) = sock.send_to(&req2, server).await {
            return fail_now(started, format!("send (authed) to {server} failed: {e}"));
        }
        let n2 = match timeout(recv_timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => n,
            Ok(Err(e)) => return fail_now(started, format!("recv (authed) failed: {e}")),
            Err(_) => {
                return fail_now(
                    started,
                    format!("no authed Allocate response in {:?}", recv_timeout),
                )
            }
        };

        let outcome2 = match parse_allocate_response(&buf[..n2], &txid2) {
            Ok(o) => o,
            Err(e) => return fail_now(started, format!("malformed authed Allocate response: {e}")),
        };

        let ms = started.elapsed().as_millis() as u64;
        match outcome2 {
            AllocateOutcome::Success { relayed, lifetime } => {
                ctx.scratch.insert("relayed".into(), relayed.to_string());
                // Save the live session for downstream checks (turn_echo).
                ctx.turn_session = Some(TurnSession {
                    socket: sock.clone(),
                    server,
                    relayed,
                    realm: realm.clone(),
                    nonce: nonce.clone(),
                    key,
                    username: user.clone(),
                });
                CheckResult::pass(
                    ID,
                    NAME,
                    ms,
                    format!("relay {relayed} (lifetime {lifetime}s, {ms} ms)"),
                )
                .with_detail(json!({
                    "server": server.to_string(),
                    "relayed": relayed.to_string(),
                    "lifetime_s": lifetime,
                    "realm": realm,
                    "auth": "long-term",
                }))
            }
            AllocateOutcome::Unauthorized { .. } => CheckResult::fail(
                ID,
                NAME,
                ms,
                "server rejected long-term credentials (401 after auth)".to_string(),
            ),
            AllocateOutcome::Error { code, reason } => {
                CheckResult::fail(ID, NAME, ms, format!("allocate rejected: {code} {reason}"))
            }
        }
    }
}

fn fail_now(started: Instant, msg: String) -> CheckResult {
    CheckResult::fail(ID, NAME, started.elapsed().as_millis() as u64, msg)
}

// All wire-level builders, MI attachment, key derivation, and response
// parsing live in `crate::turn_codec` now; unit tests for them are in
// that module. This file's behaviour is covered by integration runs
// against real TURN servers (see README and the v0.x release notes).
