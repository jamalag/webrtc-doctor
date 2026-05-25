//! DTLS handshake loopback check.
//!
//! Spins up a DTLS listener on a localhost UDP socket, connects to it
//! from another in-process task, and reports whether the handshake
//! completes — plus the peer-certificate SHA-256 fingerprint in the
//! exact format SDP uses (`a=fingerprint:sha-256 AA:BB:CC:...`).
//!
//! This is a build-and-link smoke test, not a connectivity check
//! against any external endpoint. It catches a meaningful class of
//! breakage the rest of the suite doesn't:
//!
//! - The DTLS implementation is actually wired into the binary, not
//!   feature-gated out.
//! - Self-signed cert generation works.
//! - Both client- and server-side handshake state machines complete
//!   without deadlocking each other.
//! - The peer-cert fingerprint can be computed (so an SDP-style
//!   `a=fingerprint` line could be derived from a real session later).
//!
//! What this does NOT do:
//! - Test DTLS against the user's actual TURN / signaling endpoint.
//!   Real WebRTC DTLS happens *after* ICE picks a candidate pair; we
//!   have no way to set that up against a third party from a CLI
//!   without a full PeerConnection on the other side.
//! - Negotiate `use_srtp` for DTLS-SRTP key derivation. With no SRTP
//!   profiles in the config the negotiated profile is `Unsupported`,
//!   which is the honest answer for a plain-DTLS handshake.
//! - Verify peer certificates. The handshake uses `insecure_skip_verify`
//!   on both sides because the certs are self-signed and the whole
//!   point is to prove the protocol layer works.

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
// The `Listener` trait carries the `accept` / `addr` methods we call.
// webrtc-dtls re-exports it via util::conn::Listener; importing it
// directly keeps the listener handle's interface visible.
use webrtc_util::conn::Listener;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;

const ID: &str = "dtls.loopback";
const NAME: &str = "DTLS handshake (loopback)";

pub struct DtlsLoopbackCheck;

#[async_trait::async_trait]
impl Check for DtlsLoopbackCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let started = Instant::now();
        let budget = if ctx.default_timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            ctx.default_timeout
        };

        match timeout(budget, run_handshake()).await {
            Ok(Ok(outcome)) => {
                let total_ms = started.elapsed().as_millis() as u64;
                CheckResult::pass(
                    ID,
                    NAME,
                    total_ms,
                    format!(
                        "handshake OK in {} ms; peer fp sha-256 {}",
                        outcome.handshake_ms,
                        // First 16 hex chars (8 bytes) is enough for a
                        // human-scannable summary; full fingerprint in
                        // JSON detail.
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
                    "transport": "127.0.0.1 UDP loopback",
                }))
            }
            Ok(Err(e)) => CheckResult::fail(
                ID,
                NAME,
                started.elapsed().as_millis() as u64,
                format!("DTLS handshake failed: {e}"),
            ),
            Err(_) => CheckResult::fail(
                ID,
                NAME,
                started.elapsed().as_millis() as u64,
                format!("DTLS handshake timed out after {budget:?}"),
            ),
        }
    }
}

struct Outcome {
    handshake_ms: u64,
    fingerprint_sha256: String,
    srtp_profile: String,
    peer_cert_len: usize,
}

async fn run_handshake() -> Result<Outcome, Box<dyn std::error::Error + Send + Sync>> {
    // One self-signed cert each — the client and server use independent
    // certs so the fingerprint we extract really is the peer's, not our
    // own cert reflected back.
    let server_cert = Certificate::generate_self_signed(vec!["webrtc-doctor-server".into()])?;
    let client_cert = Certificate::generate_self_signed(vec!["webrtc-doctor-client".into()])?;

    let server_cfg = Config {
        certificates: vec![server_cert],
        extended_master_secret: ExtendedMasterSecretType::Require,
        insecure_skip_verify: true,
        ..Default::default()
    };
    let client_cfg = Config {
        certificates: vec![client_cert],
        extended_master_secret: ExtendedMasterSecretType::Require,
        insecure_skip_verify: true,
        ..Default::default()
    };

    // Bind server listener on a kernel-assigned port; ask it for the
    // actual address so the client knows where to dial.
    let listener = listen("127.0.0.1:0", server_cfg).await?;
    let server_addr = listener.addr().await?;

    // Server task: accept exactly one connection, then drop it. The
    // accept() return is `Arc<dyn util::Conn>` — the generic transport
    // trait — which doesn't expose DTLS-specific state. We don't need
    // it: the client side's `connection_state()` already carries the
    // server's certificate (as `peer_certificates`), which is exactly
    // what we want to fingerprint.
    let server = tokio::spawn(async move {
        let (conn, _peer) = listener.accept().await?;
        let _ = conn.close().await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });

    // Client side runs on the current task. Bind, connect to server,
    // run the DTLS handshake.
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    client_sock.connect(server_addr).await?;

    let handshake_started = Instant::now();
    let client_conn = DTLSConn::new(client_sock, client_cfg, true, None).await?;
    let handshake_ms = handshake_started.elapsed().as_millis() as u64;

    // Pull the negotiated state from both sides. The server-side state
    // is the more interesting one for our diagnostic (it carries the
    // *client's* cert as peer_certificates), but we use the client-side
    // state because that's what a real WebRTC client cares about: the
    // remote (server) peer's fingerprint.
    let client_state = client_conn.connection_state().await;
    let srtp_profile = format!("{:?}", client_conn.selected_srtpprotection_profile());
    // Close the client cleanly so the server's accept-loop task can
    // wake up and finish.
    let _ = client_conn.close().await;

    let peer_certs = client_state.peer_certificates;
    let peer_cert_der = peer_certs.first().cloned().unwrap_or_default();
    let peer_cert_len = peer_cert_der.len();
    let fingerprint = sha256_fingerprint(&peer_cert_der);

    // Join the server task so we surface any error it produced.
    server.await??;

    Ok(Outcome {
        handshake_ms,
        fingerprint_sha256: fingerprint,
        srtp_profile,
        peer_cert_len,
    })
}

/// Compute the SHA-256 fingerprint of a DER-encoded certificate in the
/// SDP-canonical format: uppercase hex, colon-separated bytes. Returns
/// an empty string for an empty input rather than panicking, so a
/// cert-less peer (PSK handshake; not what we use here, but defensive)
/// degrades to a clear empty value instead of a confusing zero hash.
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
        // Uppercase, two hex chars per byte — same as `openssl x509 -fingerprint`.
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
        // SHA-256 of the empty string isn't useful as a test vector (we
        // short-circuit on empty), so hash a known short input instead.
        let fp = sha256_fingerprint(b"abc");
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            fp,
            "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:\
             B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD"
                .replace([' ', '\t', '\n'], "")
        );
        // 32 bytes → 32 hex pairs → 31 separators → 95 chars total.
        assert_eq!(fp.len(), 32 * 2 + 31);
        // Exactly 31 colons.
        assert_eq!(fp.chars().filter(|c| *c == ':').count(), 31);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_handshake_completes() {
        let out = tokio::time::timeout(Duration::from_secs(10), run_handshake())
            .await
            .expect("handshake within 10s")
            .expect("handshake succeeds");
        assert!(out.handshake_ms > 0);
        assert!(out.handshake_ms < 5_000);
        assert!(!out.fingerprint_sha256.is_empty());
        assert!(out.peer_cert_len > 0);
    }
}
