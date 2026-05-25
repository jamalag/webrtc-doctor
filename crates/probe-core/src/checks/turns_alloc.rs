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
//! (RFC 4571 / RFC 5389 §7.2.2).
//!
//! The relay plane stays UDP (REQUESTED-TRANSPORT = 17). TURN-over-TCP
//! relay allocations (RFC 6062) are a separate, rarer case — not MVP.
//!
//! Note: there is duplicated code with `turn_alloc.rs` (message builders,
//! MI attachment, key derivation, response parser). When a third use case
//! lands (plain TCP, Refresh, ChannelBind, etc.) the shared bits move to
//! a `turn_codec` module — explicit follow-up.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use serde_json::json;
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;
use crate::stun_codec::{self as codec, attr};

const ID: &str = "turn.alloc.tls";
const NAME: &str = "TURN allocation (TLS)";

const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;

/// REQUESTED-TRANSPORT = UDP (IANA protocol number 17). The control plane
/// is TLS; the relay plane is still UDP. RFC 6062 (TCP relay) is rarer
/// and not in this check.
const TRANSPORT_UDP: u32 = 17 << 24;

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
        // Mozilla's CA roots, no client auth. Build the config once per
        // check invocation; rustls is happy with that.
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

        // ── Round 1: unauthenticated Allocate. Always expected to be
        //          rejected with 401.
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

        // ── Round 2: authenticated Allocate.
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

// ───── message builders (duplicated from turn_alloc; refactor pending) ──

fn build_allocate_unauth() -> ([u8; 12], Vec<u8>) {
    let txid = codec::new_txid();
    let mut msg = stun_header(ALLOCATE_REQUEST, &txid);
    append_attr(
        &mut msg,
        attr::REQUESTED_TRANSPORT,
        &TRANSPORT_UDP.to_be_bytes(),
    );
    set_attrs_length(&mut msg);
    (txid, msg)
}

fn build_allocate_authed(
    username: &str,
    realm: &str,
    nonce: &[u8],
    key: &[u8; 16],
) -> ([u8; 12], Vec<u8>) {
    let txid = codec::new_txid();
    let mut msg = stun_header(ALLOCATE_REQUEST, &txid);
    append_attr(
        &mut msg,
        attr::REQUESTED_TRANSPORT,
        &TRANSPORT_UDP.to_be_bytes(),
    );
    append_attr(&mut msg, attr::USERNAME, username.as_bytes());
    append_attr(&mut msg, attr::REALM, realm.as_bytes());
    append_attr(&mut msg, attr::NONCE, nonce);
    attach_message_integrity(&mut msg, key);
    (txid, msg)
}

fn stun_header(method: u16, txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&method.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

fn append_attr(msg: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    msg.extend_from_slice(&attr_type.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    for _ in 0..pad {
        msg.push(0);
    }
}

fn set_attrs_length(msg: &mut [u8]) {
    let attrs_len = (msg.len() - 20) as u16;
    msg[2..4].copy_from_slice(&attrs_len.to_be_bytes());
}

fn attach_message_integrity(msg: &mut Vec<u8>, key: &[u8; 16]) {
    let length_with_mi = (msg.len() - 20 + 24) as u16;
    msg[2..4].copy_from_slice(&length_with_mi.to_be_bytes());
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let digest = mac.finalize().into_bytes();
    msg.extend_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&20u16.to_be_bytes());
    msg.extend_from_slice(&digest);
}

fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    let out = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&out);
    key
}

// ───── response parsing (duplicated; refactor pending) ──────────────────

#[derive(Debug)]
enum AllocateOutcome {
    Success { relayed: SocketAddr, lifetime: u32 },
    Unauthorized { realm: String, nonce: Vec<u8> },
    Error { code: u16, reason: String },
}

#[derive(Debug, thiserror::Error)]
enum AllocateError {
    #[error("{0}")]
    Codec(#[from] codec::CodecError),
    #[error("unexpected message type 0x{0:04x}")]
    WrongType(u16),
    #[error("missing required attribute {0}")]
    MissingAttr(&'static str),
}

fn parse_allocate_response(buf: &[u8], txid: &[u8; 12]) -> Result<AllocateOutcome, AllocateError> {
    let header = codec::parse_header(buf, txid)?;
    let attrs = codec::walk_attrs(buf, header.attrs_len)?;

    match header.msg_type {
        ALLOCATE_SUCCESS => {
            let mut relayed: Option<SocketAddr> = None;
            let mut lifetime: u32 = 0;
            for a in &attrs {
                match a.attr_type {
                    attr::XOR_RELAYED_ADDRESS => {
                        relayed = Some(codec::parse_xor_address(a.value, txid)?);
                    }
                    attr::LIFETIME if a.value.len() >= 4 => {
                        lifetime =
                            u32::from_be_bytes([a.value[0], a.value[1], a.value[2], a.value[3]]);
                    }
                    _ => {}
                }
            }
            let relayed = relayed.ok_or(AllocateError::MissingAttr("XOR-RELAYED-ADDRESS"))?;
            Ok(AllocateOutcome::Success { relayed, lifetime })
        }
        ALLOCATE_ERROR => {
            let mut code = 0u16;
            let mut reason = String::new();
            let mut realm: Option<String> = None;
            let mut nonce: Option<Vec<u8>> = None;
            for a in &attrs {
                match a.attr_type {
                    attr::ERROR_CODE => {
                        let ec = codec::parse_error_code(a.value)?;
                        code = ec.code;
                        reason = ec.reason;
                    }
                    attr::REALM => {
                        realm = Some(String::from_utf8_lossy(a.value).into_owned());
                    }
                    attr::NONCE => nonce = Some(a.value.to_vec()),
                    _ => {}
                }
            }
            if code == 401 {
                Ok(AllocateOutcome::Unauthorized {
                    realm: realm.ok_or(AllocateError::MissingAttr("REALM"))?,
                    nonce: nonce.ok_or(AllocateError::MissingAttr("NONCE"))?,
                })
            } else {
                Ok(AllocateOutcome::Error { code, reason })
            }
        }
        other => Err(AllocateError::WrongType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The wire-level builders and parser are byte-for-byte identical to
    // their counterparts in `turn_alloc.rs`, which already has thorough
    // unit coverage. We focus this module's tests on the framing helpers
    // and the TLS plumbing assumptions.

    #[tokio::test]
    async fn framing_roundtrip() {
        let payload = b"hello-stun";
        let mut framed = Vec::new();
        send_framed(&mut framed, payload).await.unwrap();
        // 2-byte length prefix + payload bytes
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

    #[test]
    fn allocate_unauth_layout_matches_udp_path() {
        let (_txid, msg) = build_allocate_unauth();
        // Same on-the-wire shape as the UDP allocator's unauth request.
        assert_eq!(&msg[0..2], &ALLOCATE_REQUEST.to_be_bytes());
        let attrs_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(attrs_len, msg.len() - 20);
        assert_eq!(msg.len(), 20 + 8); // header + one 8-byte REQUESTED-TRANSPORT
    }
}
