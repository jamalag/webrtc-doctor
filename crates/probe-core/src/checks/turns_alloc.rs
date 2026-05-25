//! TURN allocation over TLS (TURNS).
//!
//! Same allocation dance as `turn_alloc` (Allocate Request → 401 challenge
//! → Allocate Request with USERNAME/REALM/NONCE/MESSAGE-INTEGRITY →
//! Allocate Success), but the control channel runs over TLS-over-TCP
//! instead of plain UDP. Default port 5349; many production deployments
//! also expose TURNS on 443 to look like ordinary HTTPS for corporate-
//! firewall traversal (the whole point of TURNS).
//!
//! Wire framing differs from the UDP path: TCP is a byte stream, so each
//! STUN/TURN message is prefixed by a 2-byte length in network byte order
//! (RFC 4571 / RFC 5389 §7.2.2). That length-framing is local to this
//! module; everything STUN/TURN-wire-level (message builders, MI, key
//! derivation, response parser) is shared with the UDP path via
//! [`crate::turn_codec`].
//!
//! The relay plane stays UDP (REQUESTED-TRANSPORT = 17). TURN-over-TCP
//! relay allocations (RFC 6062) are a separate, rarer case — not MVP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;
use crate::turn_codec::{
    build_allocate_authed, build_allocate_unauth, long_term_key, parse_allocate_response,
    AllocateOutcome,
};

const ID: &str = "turn.alloc.tls";
const NAME: &str = "TURN allocation (TLS)";

pub struct TurnsAllocateCheck;

#[async_trait::async_trait]
impl Check for TurnsAllocateCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn requires(&self) -> &'static [&'static str] {
        // Need a resolved IP. We don't require stun.binding because the
        // TURNS control path doesn't establish a srflx — it's TCP.
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
        let host = match ctx.host.as_deref() {
            Some(h) => h.to_string(),
            // SNI requires a hostname. If only an IP was given (no DNS
            // step ran), we can't safely validate the cert; skip.
            None => return CheckResult::skip(ID, NAME, "no hostname for SNI"),
        };

        let server_addr = SocketAddr::new(ip, port);
        let started = Instant::now();

        let recv_timeout = if ctx.default_timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            // TLS handshake + two TURN round-trips deserves the same
            // headroom as the signaling check, not the 5s UDP default.
            ctx.default_timeout.max(Duration::from_secs(10))
        };

        // ── TLS setup ────────────────────────────────────────────────
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_config));

        let server_name = match ServerName::try_from(host.clone()) {
            Ok(sn) => sn,
            Err(_) => return fail_now(started, format!("`{host}` is not a valid TLS server name")),
        };

        // ── TCP connect ──────────────────────────────────────────────
        let tls_started = Instant::now();
        let tcp = match timeout(recv_timeout, TcpStream::connect(server_addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return fail_now(started, format!("TCP connect to {server_addr} failed: {e}"))
            }
            Err(_) => return fail_now(started, format!("TCP connect to {server_addr} timeout")),
        };

        // ── TLS handshake ────────────────────────────────────────────
        let mut tls = match timeout(recv_timeout, connector.connect(server_name, tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return fail_now(started, format!("TLS handshake failed: {e}")),
            Err(_) => return fail_now(started, "TLS handshake timeout".to_string()),
        };
        let tls_ms = tls_started.elapsed().as_millis() as u64;

        // ── Round 1: unauthenticated Allocate (expect 401). ──────────
        let (txid1, req1) = build_allocate_unauth();
        if let Err(e) = send_framed(&mut tls, &req1).await {
            return fail_now(started, format!("send (unauth) failed: {e}"));
        }
        let resp1 = match timeout(recv_timeout, recv_framed(&mut tls)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return fail_now(started, format!("recv (unauth) failed: {e}")),
            Err(_) => {
                return fail_now(started, format!("no Allocate response in {recv_timeout:?}"))
            }
        };

        let outcome1 = match parse_allocate_response(&resp1, &txid1) {
            Ok(o) => o,
            Err(e) => return fail_now(started, format!("malformed Allocate response: {e}")),
        };

        let (realm, nonce) = match outcome1 {
            AllocateOutcome::Unauthorized { realm, nonce } => (realm, nonce),
            AllocateOutcome::Success { relayed, lifetime } => {
                // Some non-standard relays accept anonymous; take it.
                let ms = started.elapsed().as_millis() as u64;
                ctx.scratch.insert("relayed".into(), relayed.to_string());
                return CheckResult::pass(
                    ID,
                    NAME,
                    ms,
                    format!("relay {relayed} (anonymous alloc, TLS {tls_ms} ms, total {ms} ms)"),
                )
                .with_detail(json!({
                    "server": server_addr.to_string(),
                    "sni": host,
                    "relayed": relayed.to_string(),
                    "lifetime_s": lifetime,
                    "tls_handshake_ms": tls_ms,
                    "auth": "none",
                }));
            }
            AllocateOutcome::Error { code, reason } => {
                let ms = started.elapsed().as_millis() as u64;
                return CheckResult::fail(ID, NAME, ms, format!("server returned {code} {reason}"));
            }
        };

        // No credentials: report Warn with realm, same as turn.alloc.udp.
        let (user, pass) = match (ctx.turn_user.as_ref(), ctx.turn_pass.as_ref()) {
            (Some(u), Some(p)) => (u.clone(), p.clone()),
            _ => {
                let ms = started.elapsed().as_millis() as u64;
                return CheckResult::warn(
                    ID,
                    NAME,
                    ms,
                    format!("auth challenge from realm \"{realm}\" — no --user/--pass supplied (TLS {tls_ms} ms)"),
                )
                .with_detail(json!({
                    "server": server_addr.to_string(),
                    "sni": host,
                    "realm": realm,
                    "tls_handshake_ms": tls_ms,
                    "auth": "challenge-only",
                }));
            }
        };

        // ── Round 2: authenticated Allocate. ─────────────────────────
        let key = long_term_key(&user, &realm, &pass);
        let (txid2, req2) = build_allocate_authed(&user, &realm, &nonce, &key);
        if let Err(e) = send_framed(&mut tls, &req2).await {
            return fail_now(started, format!("send (authed) failed: {e}"));
        }
        let resp2 = match timeout(recv_timeout, recv_framed(&mut tls)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return fail_now(started, format!("recv (authed) failed: {e}")),
            Err(_) => {
                return fail_now(
                    started,
                    format!("no authed Allocate response in {recv_timeout:?}"),
                )
            }
        };
        let outcome2 = match parse_allocate_response(&resp2, &txid2) {
            Ok(o) => o,
            Err(e) => return fail_now(started, format!("malformed authed Allocate response: {e}")),
        };

        let ms = started.elapsed().as_millis() as u64;
        match outcome2 {
            AllocateOutcome::Success { relayed, lifetime } => {
                ctx.scratch.insert("relayed".into(), relayed.to_string());
                CheckResult::pass(
                    ID,
                    NAME,
                    ms,
                    format!(
                        "relay {relayed} (lifetime {lifetime}s, TLS {tls_ms} ms, total {ms} ms)"
                    ),
                )
                .with_detail(json!({
                    "server": server_addr.to_string(),
                    "sni": host,
                    "relayed": relayed.to_string(),
                    "lifetime_s": lifetime,
                    "realm": realm,
                    "tls_handshake_ms": tls_ms,
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

// ───── TCP framing for STUN/TURN over TLS ───────────────────────────────

async fn send_framed<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &[u8]) -> std::io::Result<()> {
    let len = (msg.len() as u16).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(msg).await?;
    w.flush().await
}

async fn recv_framed<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;
    let mut msg = vec![0u8; msg_len];
    r.read_exact(&mut msg).await?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The wire-level builders and parser have unit tests in
    // `crate::turn_codec`. This module only owns the 2-byte length
    // framing, so that's all we exercise here.

    #[tokio::test]
    async fn framing_roundtrip() {
        let payload = b"hello-stun";
        let mut framed = Vec::new();
        send_framed(&mut framed, payload).await.unwrap();
        assert_eq!(framed.len(), 2 + payload.len());
        assert_eq!(
            u16::from_be_bytes([framed[0], framed[1]]),
            payload.len() as u16
        );
        assert_eq!(&framed[2..], payload);

        let mut cursor = std::io::Cursor::new(framed);
        let decoded = recv_framed(&mut cursor).await.unwrap();
        assert_eq!(decoded, payload);
    }

    #[tokio::test]
    async fn framing_handles_multiple_messages_in_stream() {
        let a = b"first-message".to_vec();
        let b = b"second".to_vec();
        let mut framed = Vec::new();
        send_framed(&mut framed, &a).await.unwrap();
        send_framed(&mut framed, &b).await.unwrap();

        let mut cursor = std::io::Cursor::new(framed);
        let got_a = recv_framed(&mut cursor).await.unwrap();
        let got_b = recv_framed(&mut cursor).await.unwrap();
        assert_eq!(got_a, a);
        assert_eq!(got_b, b);
    }
}
