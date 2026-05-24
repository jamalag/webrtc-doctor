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
//! We do not verify the server's MESSAGE-INTEGRITY on the response in MVP;
//! the relay address itself is the operational signal. Verification lands
//! when we have a paranoid-mode flag.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use serde_json::json;
use sha1::Sha1;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;
use crate::stun_codec::{self as codec, attr};

const ID: &str = "turn.alloc.udp";
const NAME: &str = "TURN allocation (UDP)";

const ALLOCATE_REQUEST: u16 = 0x0003;
const ALLOCATE_SUCCESS: u16 = 0x0103;
const ALLOCATE_ERROR: u16 = 0x0113;

/// REQUESTED-TRANSPORT value for UDP (RFC 5766 §14.7 — IANA protocol number 17).
const TRANSPORT_UDP: u32 = 17 << 24;

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
        let sock = match UdpSocket::bind(local_bind).await {
            Ok(s) => s,
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

#[derive(Debug)]
enum AllocateOutcome {
    Success { relayed: SocketAddr, lifetime: u32 },
    Unauthorized { realm: String, nonce: Vec<u8> },
    Error { code: u16, reason: String },
}

// ───── message builders ─────────────────────────────────────────────────

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
    msg.extend_from_slice(&0u16.to_be_bytes()); // length, fixed up later
    msg.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

/// Append a TLV attribute, padding the value to 4-byte alignment.
fn append_attr(msg: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    msg.extend_from_slice(&attr_type.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    for _ in 0..pad {
        msg.push(0);
    }
}

/// Rewrite the header's `attrs_len` field to reflect the current buffer.
fn set_attrs_length(msg: &mut [u8]) {
    let attrs_len = (msg.len() - 20) as u16;
    msg[2..4].copy_from_slice(&attrs_len.to_be_bytes());
}

/// Append the MESSAGE-INTEGRITY attribute. RFC 5389 §15.4: HMAC-SHA1 is
/// computed over the message *as if MI were already present* (length field
/// must include the 24 bytes the MI attribute will occupy), but the digest
/// is computed across only the bytes *before* MI.
fn attach_message_integrity(msg: &mut Vec<u8>, key: &[u8; 16]) {
    // Predict the length field as if MI (4-byte header + 20-byte digest = 24B)
    // were already appended.
    let length_with_mi = (msg.len() - 20 + 24) as u16;
    msg[2..4].copy_from_slice(&length_with_mi.to_be_bytes());

    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let digest = mac.finalize().into_bytes();

    msg.extend_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&20u16.to_be_bytes());
    msg.extend_from_slice(&digest);
    // No padding needed — 20 is already 4-aligned.
}

/// RFC 5389 §15.4 / §10.2: key = MD5(username ":" realm ":" password).
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

// ───── response parsing ────────────────────────────────────────────────

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
                    attr::LIFETIME => {
                        if a.value.len() >= 4 {
                            lifetime = u32::from_be_bytes([
                                a.value[0], a.value[1], a.value[2], a.value[3],
                            ]);
                        }
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

// ───── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_term_key_matches_rfc_example_shape() {
        // No published vector in the RFC pins to a specific key, but the
        // formula is deterministic; pin a known input/output for regression.
        let k = long_term_key("user", "example.com", "pass");
        // md5("user:example.com:pass"), pinned against the md-5 crate output
        // as a regression guard on the formula (not the digest impl).
        let expected: [u8; 16] = [
            0xc1, 0x9c, 0x4c, 0x6e, 0x32, 0xf9, 0xd8, 0x02, 0x6b, 0x26, 0xba, 0x77, 0xc2, 0x1f,
            0xb8, 0xeb,
        ];
        assert_eq!(k, expected, "long-term key MD5 changed shape");
    }

    #[test]
    fn unauth_allocate_request_layout() {
        let (txid, msg) = build_allocate_unauth();
        // Header
        assert_eq!(&msg[0..2], &ALLOCATE_REQUEST.to_be_bytes());
        let attrs_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(attrs_len, msg.len() - 20);
        assert_eq!(&msg[4..8], &codec::MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&msg[8..20], &txid);
        // Exactly one attribute: REQUESTED-TRANSPORT (4 bytes header + 4 bytes value).
        assert_eq!(msg.len(), 20 + 8);
        assert_eq!(&msg[20..22], &attr::REQUESTED_TRANSPORT.to_be_bytes());
        assert_eq!(&msg[22..24], &4u16.to_be_bytes());
        assert_eq!(&msg[24..28], &TRANSPORT_UDP.to_be_bytes());
    }

    #[test]
    fn parses_401_with_realm_and_nonce() {
        let txid = [7u8; 12];
        // Build an Allocate Error Response with ERROR-CODE=401, REALM, NONCE.
        let mut buf = Vec::new();
        buf.extend_from_slice(&ALLOCATE_ERROR.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);

        // ERROR-CODE attr: reserved(2) + class(1)=4 + number(1)=1 + reason
        let reason = b"Unauthorized";
        append_attr(&mut buf, attr::ERROR_CODE, {
            let mut v = vec![0, 0, 4, 1];
            v.extend_from_slice(reason);
            &v.clone()
        });
        append_attr(&mut buf, attr::REALM, b"example.org");
        append_attr(&mut buf, attr::NONCE, b"abc123nonce");
        set_attrs_length(&mut buf);

        match parse_allocate_response(&buf, &txid).unwrap() {
            AllocateOutcome::Unauthorized { realm, nonce } => {
                assert_eq!(realm, "example.org");
                assert_eq!(nonce, b"abc123nonce");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn parses_allocate_success_with_relayed_address() {
        let txid = [9u8; 12];
        // Manually craft an Allocate Success with XOR-RELAYED-ADDRESS and LIFETIME.
        let target_ip: u32 = 0xCB00_7102; // 203.0.113.2
        let target_port: u16 = 49152;
        let xport = target_port ^ ((codec::MAGIC_COOKIE >> 16) as u16);
        let xaddr = target_ip ^ codec::MAGIC_COOKIE;

        let mut buf = Vec::new();
        buf.extend_from_slice(&ALLOCATE_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        // XOR-RELAYED-ADDRESS
        let mut value = Vec::new();
        value.push(0);
        value.push(0x01); // family v4
        value.extend_from_slice(&xport.to_be_bytes());
        value.extend_from_slice(&xaddr.to_be_bytes());
        append_attr(&mut buf, attr::XOR_RELAYED_ADDRESS, &value);
        // LIFETIME = 600
        append_attr(&mut buf, attr::LIFETIME, &600u32.to_be_bytes());
        set_attrs_length(&mut buf);

        match parse_allocate_response(&buf, &txid).unwrap() {
            AllocateOutcome::Success { relayed, lifetime } => {
                assert_eq!(relayed, "203.0.113.2:49152".parse().unwrap());
                assert_eq!(lifetime, 600);
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[test]
    fn message_integrity_is_appended_with_correct_length() {
        let key = [0xABu8; 16];
        let (_txid, msg) = build_allocate_authed("alice", "realm.tld", b"nonce!", &key);

        // Header attrs_len must include the trailing MI attribute.
        let attrs_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(attrs_len, msg.len() - 20);

        // Last 24 bytes are the MI attribute: 4-byte header + 20-byte digest.
        let mi_start = msg.len() - 24;
        assert_eq!(
            &msg[mi_start..mi_start + 2],
            &attr::MESSAGE_INTEGRITY.to_be_bytes()
        );
        assert_eq!(&msg[mi_start + 2..mi_start + 4], &20u16.to_be_bytes());

        // The digest should match an HMAC-SHA1 over the message-without-MI
        // but with the header length already set to include MI.
        let mut to_sign = msg[..mi_start].to_vec();
        // (length field was already fixed up to include MI before signing)
        let mut mac =
            <Hmac<Sha1> as Mac>::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(&to_sign);
        let digest = mac.finalize().into_bytes();
        assert_eq!(&msg[mi_start + 4..], &digest[..]);
        // Touch `to_sign` so clippy doesn't whine.
        to_sign.clear();
    }
}
