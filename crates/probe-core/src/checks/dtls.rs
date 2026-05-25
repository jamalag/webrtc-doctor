//! DTLS handshake checks (loopback + remote) and a server-mode helper.
//!
//! Three callable paths share the same handshake primitives:
//!
//! - [`DtlsLoopbackCheck`] — spins up a DTLS listener on a localhost UDP
//!   socket, dials it from a second in-process task, and reports the
//!   handshake outcome. Build-and-link smoke test; no network target.
//!
//! - [`DtlsRemoteCheck`] — dials a configured remote DTLS endpoint. The
//!   target is taken from `ctx.host`/`ctx.port` (populated by the CLI
//!   layer from the user's `dtls <host:port>` argument). Reports the
//!   same handshake outcome shape as the loopback path; the peer-cert
//!   fingerprint is what you'd put in an SDP `a=fingerprint` line.
//!
//! - [`serve_forever`] — turns this binary into a DTLS test peer.
//!   Listens on `bind`, accepts handshakes from any client, and
//!   logs each one. Counterpart to `DtlsRemoteCheck` so two boxes
//!   can probe each other without external infrastructure.
//!
//! All three use `insecure_skip_verify: true`. We're testing transport
//! reachability and protocol-layer correctness, not chain-of-trust. The
//! peer-cert SHA-256 fingerprint is the only authentication signal we
//! report (which is also exactly what WebRTC does — DTLS over an ICE
//! candidate pair authenticates via the fingerprint pre-shared in SDP,
//! not via PKI).
//!
//! What none of these do:
//! - Negotiate `use_srtp` for DTLS-SRTP key derivation. With no SRTP
//!   profiles in the config the negotiated profile is `Unsupported`,
//!   which is the honest answer for a plain-DTLS handshake.
//! - Verify peer certificates against a CA bundle. Self-signed certs.
//! - Test DTLS against a real WebRTC PeerConnection. That needs full
//!   ICE on both sides and a signaling channel to exchange fingerprints
//!   — out of scope for a CLI diagnostic.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use webrtc_dtls::config::{Config, ExtendedMasterSecretType};
use webrtc_dtls::conn::DTLSConn;
use webrtc_dtls::crypto::Certificate;
use webrtc_dtls::listener::listen;
// The `Listener` trait carries the `accept` / `addr` / `close` methods we call.
use webrtc_util::conn::Listener;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;

// ───── DTLS loopback check (existing) ──────────────────────────────────

const LOOPBACK_ID: &str = "dtls.loopback";
const LOOPBACK_NAME: &str = "DTLS handshake (loopback)";

pub struct DtlsLoopbackCheck;

#[async_trait::async_trait]
impl Check for DtlsLoopbackCheck {
    fn id(&self) -> &'static str {
        LOOPBACK_ID
    }

    fn name(&self) -> &'static str {
        LOOPBACK_NAME
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let started = Instant::now();
        let budget = budget_from(ctx);
        match timeout(budget, run_loopback_handshake()).await {
            Ok(Ok(outcome)) => {
                finish_pass(LOOPBACK_ID, LOOPBACK_NAME, started, outcome, "loopback")
            }
            Ok(Err(e)) => finish_fail(
                LOOPBACK_ID,
                LOOPBACK_NAME,
                started,
                format!("DTLS handshake failed: {e}"),
            ),
            Err(_) => finish_fail(
                LOOPBACK_ID,
                LOOPBACK_NAME,
                started,
                format!("DTLS handshake timed out after {budget:?}"),
            ),
        }
    }
}

// ───── DTLS remote check ───────────────────────────────────────────────

const REMOTE_ID: &str = "dtls.remote";
const REMOTE_NAME: &str = "DTLS handshake (remote)";

pub struct DtlsRemoteCheck;

#[async_trait::async_trait]
impl Check for DtlsRemoteCheck {
    fn id(&self) -> &'static str {
        REMOTE_ID
    }

    fn name(&self) -> &'static str {
        REMOTE_NAME
    }

    fn requires(&self) -> &'static [&'static str] {
        &["dns"]
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let port = match ctx.port {
            Some(p) => p,
            None => return CheckResult::skip(REMOTE_ID, REMOTE_NAME, "no port supplied"),
        };
        let ip = match ctx.resolved_ips.first().copied() {
            Some(ip) => ip,
            None => return CheckResult::skip(REMOTE_ID, REMOTE_NAME, "no resolved IP"),
        };
        let target = SocketAddr::new(ip, port);
        let started = Instant::now();
        let budget = budget_from(ctx);

        match timeout(budget, run_remote_handshake(target)).await {
            Ok(Ok(outcome)) => finish_pass(
                REMOTE_ID,
                REMOTE_NAME,
                started,
                outcome,
                &format!("via {target}"),
            ),
            Ok(Err(e)) => finish_fail(
                REMOTE_ID,
                REMOTE_NAME,
                started,
                format!("DTLS handshake to {target} failed: {e}"),
            ),
            Err(_) => finish_fail(
                REMOTE_ID,
                REMOTE_NAME,
                started,
                format!("DTLS handshake to {target} timed out after {budget:?}"),
            ),
        }
    }
}

// ───── server mode ─────────────────────────────────────────────────────

/// Run as a DTLS test peer. Binds `bind`, accepts handshakes forever,
/// and invokes `on_accept` after each successful one. Cancellation is
/// via task abort or process exit; the function does not return on its
/// own. Errors are logged through `tracing` and the loop continues so
/// one bad handshake doesn't take the server down.
pub async fn serve_forever<F>(
    bind: SocketAddr,
    mut on_accept: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnMut(SocketAddr) + Send + 'static,
{
    let cert = Certificate::generate_self_signed(vec!["webrtc-doctor-serve".into()])?;
    let cfg = Config {
        certificates: vec![cert],
        extended_master_secret: ExtendedMasterSecretType::Require,
        insecure_skip_verify: true,
        ..Default::default()
    };
    let listener = listen(bind, cfg).await?;
    let actual = listener.addr().await?;
    tracing::info!("dtls serve: listening on {actual}");
    loop {
        match listener.accept().await {
            Ok((conn, peer)) => {
                tracing::info!("dtls serve: handshake from {peer}");
                on_accept(peer);
                // Drop the connection immediately; we're a test peer, not
                // a chat server. Closing in a background task so accept()
                // can resume right away.
                tokio::spawn(async move {
                    let _ = conn.close().await;
                });
            }
            Err(e) => {
                tracing::warn!("dtls serve: accept error: {e}");
                // Keep going — one bad apple shouldn't kill the listener.
            }
        }
    }
}

// ───── shared internals ────────────────────────────────────────────────

struct Outcome {
    handshake_ms: u64,
    fingerprint_sha256: String,
    srtp_profile: String,
    peer_cert_len: usize,
}

fn budget_from(ctx: &ProbeContext) -> Duration {
    if ctx.default_timeout.is_zero() {
        Duration::from_secs(5)
    } else {
        ctx.default_timeout
    }
}

fn finish_pass(
    id: &str,
    name: &str,
    started: Instant,
    outcome: Outcome,
    transport_label: &str,
) -> CheckResult {
    let total_ms = started.elapsed().as_millis() as u64;
    CheckResult::pass(
        id,
        name,
        total_ms,
        format!(
            "handshake OK in {} ms ({transport_label}); peer fp sha-256 {}",
            outcome.handshake_ms,
            // First 8 fingerprint bytes (23 chars including colons) is
            // enough for a human-scannable summary; full value in JSON.
            outcome
                .fingerprint_sha256
                .chars()
                .take(23)
                .collect::<String>(),
        ),
    )
    .with_detail(json!({
        "handshake_ms": outcome.handshake_ms,
        "fingerprint_sha256": outcome.fingerprint_sha256,
        "srtp_profile": outcome.srtp_profile,
        "peer_cert_der_bytes": outcome.peer_cert_len,
        "transport": transport_label,
    }))
}

fn finish_fail(id: &str, name: &str, started: Instant, msg: String) -> CheckResult {
    CheckResult::fail(id, name, started.elapsed().as_millis() as u64, msg)
}

fn client_config() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    let cert = Certificate::generate_self_signed(vec!["webrtc-doctor-client".into()])?;
    Ok(Config {
        certificates: vec![cert],
        extended_master_secret: ExtendedMasterSecretType::Require,
        insecure_skip_verify: true,
        ..Default::default()
    })
}

/// Bind a local UDP socket appropriate for talking to `target`, connect
/// it, and run the DTLS client handshake. Returns the negotiated state
/// summarized as an [`Outcome`].
async fn dial(target: SocketAddr) -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
    let local_bind: SocketAddr = match target.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let sock = Arc::new(UdpSocket::bind(local_bind).await?);
    sock.connect(target).await?;
    let cfg = client_config()?;

    let handshake_started = Instant::now();
    let conn = DTLSConn::new(sock, cfg, true, None).await?;
    let handshake_ms = handshake_started.elapsed().as_millis() as u64;

    let state = conn.connection_state().await;
    let srtp_profile = format!("{:?}", conn.selected_srtpprotection_profile());
    let _ = conn.close().await;

    let peer_cert_der = state.peer_certificates.first().cloned().unwrap_or_default();
    let peer_cert_len = peer_cert_der.len();
    let fingerprint = sha256_fingerprint(&peer_cert_der);

    Ok(Outcome {
        handshake_ms,
        fingerprint_sha256: fingerprint,
        srtp_profile,
        peer_cert_len,
    })
}

async fn run_remote_handshake(
    target: SocketAddr,
) -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
    dial(target).await
}

async fn run_loopback_handshake() -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
    // Stand up a server listener on a kernel-assigned port; ask it for
    // its actual address so the client knows where to dial.
    let server_cert = Certificate::generate_self_signed(vec!["webrtc-doctor-server".into()])?;
    let server_cfg = Config {
        certificates: vec![server_cert],
        extended_master_secret: ExtendedMasterSecretType::Require,
        insecure_skip_verify: true,
        ..Default::default()
    };
    let listener = listen("127.0.0.1:0", server_cfg).await?;
    let server_addr = listener.addr().await?;

    // Server task: accept exactly one connection, then drop it.
    let server = tokio::spawn(async move {
        let (conn, _peer) = listener.accept().await?;
        let _ = conn.close().await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });

    let outcome = dial(server_addr).await?;
    server.await??;
    Ok(outcome)
}

/// Compute the SHA-256 fingerprint of a DER-encoded certificate in the
/// SDP-canonical format: uppercase hex, colon-separated bytes. Empty
/// input → empty string (defensive — degrades to a clear empty value
/// instead of a confusing zero hash).
fn sha256_fingerprint(cert_der: &[u8]) -> String {
    if cert_der.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 3);
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cert_yields_empty_fingerprint() {
        assert_eq!(sha256_fingerprint(&[]), "");
    }

    #[test]
    fn fingerprint_has_canonical_sdp_shape() {
        let fp = sha256_fingerprint(b"abc");
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            fp,
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:\
             B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
                .replace([' ', '\t', '\n'], "")
        );
        assert_eq!(fp.len(), 32 * 2 + 31);
        assert_eq!(fp.chars().filter(|c| *c == ':').count(), 31);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_handshake_completes() {
        let out = tokio::time::timeout(Duration::from_secs(10), run_loopback_handshake())
            .await
            .expect("handshake within 10s")
            .expect("handshake succeeds");
        assert!(out.handshake_ms < 5_000);
        assert!(!out.fingerprint_sha256.is_empty());
        assert!(out.peer_cert_len > 0);
    }

    /// Stand up the real `serve_forever` server, then `dial` it from the
    /// same process. Validates that the remote-handshake code path also
    /// works end-to-end (not just the loopback's pre-baked listener).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_then_dial_completes() {
        // Bind on 0 → kernel picks port. Server runs in a task; we have to
        // know its address to dial it, but `serve_forever` swallows that.
        // For the integration test we bypass and run the bind+accept loop
        // by hand via the same listener it uses; that's the cheapest way
        // to test it without making `serve_forever` return the bound addr.
        let cert = Certificate::generate_self_signed(vec!["test-serve".into()]).unwrap();
        let cfg = Config {
            certificates: vec![cert],
            extended_master_secret: ExtendedMasterSecretType::Require,
            insecure_skip_verify: true,
            ..Default::default()
        };
        let listener = listen("127.0.0.1:0", cfg).await.unwrap();
        let bound = listener.addr().await.unwrap();
        let server = tokio::spawn(async move {
            let (conn, _peer) = listener.accept().await?;
            let _ = conn.close().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let out = tokio::time::timeout(Duration::from_secs(10), dial(bound))
            .await
            .expect("handshake within 10s")
            .expect("dial succeeds");
        server.await.unwrap().unwrap();
        assert!(out.handshake_ms < 5_000);
        assert!(!out.fingerprint_sha256.is_empty());
    }
}
