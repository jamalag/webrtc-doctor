//! TURN echo round-trip check.
//!
//! Proves the relay actually relays bytes — not just that it accepted an
//! allocation. The flow against the **existing** allocation
//! (`ctx.turn_session`, populated by `turn_alloc`):
//!
//! 1. **CreatePermission Request** (auth required) tells the server we
//!    intend to send to our own server-reflexive address; permissions are
//!    a TURN prerequisite for any peer⇄client traffic on this allocation.
//! 2. **Send a raw UDP datagram directly to the relay address**, with our
//!    local socket as the source. We're acting as our own peer. The
//!    relay's view of the source is our srflx, which we just permitted in
//!    step 1, so the permission check passes.
//! 3. **The relay wraps that datagram in a `Data Indication`** and sends
//!    it back to the client via the existing control channel (source =
//!    the TURN server's listening port, which our NAT already has a
//!    mapping for). We extract the `DATA` attribute and verify the
//!    payload round-tripped.
//!
//! Why this design — and not the "self-echo via Send Indication" path we
//! tried first:
//!
//! The obvious-looking design (`Send Indication → relay forwards to peer
//! → peer (us) receives`) requires inbound UDP to our srflx from the
//! relay's port, which is a *different* port from the one we've been
//! talking to. Port-restricted NATs (the common home-router default)
//! drop that packet. The "act as own peer" path keeps the inbound traffic
//! on the same 5-tuple we already established with the TURN server, so it
//! works through any NAT type.
//!
//! What this check does *not* attempt in MVP:
//! - Multiple packets for loss / jitter statistics — single round-trip
//!   establishes the binary "relay relays" signal, multi-packet stats are
//!   a follow-up.
//! - Channel binding (4-byte channel header). Send/Data Indications
//!   prove the relay path; channels are a high-rate optimization.
//! - 438 Stale Nonce recovery. If CreatePermission gets a fresh nonce
//!   between alloc and echo, we fail with that exact diagnostic rather
//!   than silently re-handshaking.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde_json::json;
use sha1::Sha1;
use tokio::time::timeout;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;
use crate::stun_codec::{self as codec, attr};

const ID: &str = "turn.echo.udp";
const NAME: &str = "TURN echo (UDP)";

const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
const CREATE_PERMISSION_ERROR: u16 = 0x0118;

/// Data Indication: method 0x007, class indication (0b01 in the type bits).
const DATA_INDICATION: u16 = 0x0017;

/// A small, recognizable payload so we can tell our echo apart from any
/// unsolicited noise the relay might wrap-and-forward (vanishingly unlikely
/// on a fresh allocation, but worth filtering for).
const ECHO_PAYLOAD: &[u8] = b"webrtc-doctor-echo-probe";

pub struct TurnEchoCheck;

#[async_trait::async_trait]
impl Check for TurnEchoCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn requires(&self) -> &'static [&'static str] {
        // Need a live TURN allocation (from turn.alloc.udp) and a known
        // server-reflexive address to feed CreatePermission (from
        // stun.binding).
        &["turn.alloc.udp", "stun.binding"]
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let session = match ctx.turn_session.as_ref() {
            Some(s) => s.clone(),
            // Should be unreachable thanks to requires(), but be defensive.
            None => return CheckResult::skip(ID, NAME, "no TURN session in context"),
        };

        let srflx: SocketAddr = match ctx.scratch.get("srflx").and_then(|s| s.parse().ok()) {
            Some(addr) => addr,
            None => return CheckResult::skip(ID, NAME, "no srflx in context"),
        };

        let started = Instant::now();
        let recv_timeout = if ctx.default_timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            ctx.default_timeout
        };

        // ── Step 1: CreatePermission against the existing allocation,
        //          permitting our own srflx as a peer.
        let (cp_txid, cp_req) = build_create_permission(
            &session.username,
            &session.realm,
            &session.nonce,
            &session.key,
            srflx,
        );
        if let Err(e) = session.socket.send_to(&cp_req, session.server).await {
            return fail_now(started, format!("send CreatePermission failed: {e}"));
        }

        let mut buf = [0u8; 1500];
        let cp_resp_n = match timeout(recv_timeout, session.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => n,
            Ok(Err(e)) => return fail_now(started, format!("recv CreatePermission failed: {e}")),
            Err(_) => {
                return fail_now(
                    started,
                    format!(
                        "no CreatePermission response in {recv_timeout:?} (server: {})",
                        session.server,
                    ),
                )
            }
        };

        match parse_create_permission_response(&buf[..cp_resp_n], &cp_txid) {
            Ok(CpOutcome::Success) => {}
            Ok(CpOutcome::Error { code, reason }) => {
                return fail_now(
                    started,
                    format!("CreatePermission rejected: {code} {reason}"),
                )
            }
            Err(e) => return fail_now(started, format!("malformed CreatePermission resp: {e}")),
        }

        // ── Step 2: Send raw UDP directly to the relay address. We're
        //          acting as our own peer here — the relay sees the
        //          source as our srflx (which we just permitted) and
        //          will wrap the payload in a Data Indication forwarded
        //          back to us via the control channel.
        let echo_started = Instant::now();
        if let Err(e) = session.socket.send_to(ECHO_PAYLOAD, session.relayed).await {
            return fail_now(started, format!("send to relay failed: {e}"));
        }

        // ── Step 3: Wait for the Data Indication on the control channel.
        //          Source must be the TURN server's listening port (where
        //          control-channel traffic comes from). Filter on source
        //          to ignore any stray STUN response that might race.
        loop {
            if started.elapsed() >= recv_timeout {
                return fail_now(started, format!("no echo received within {recv_timeout:?}"));
            }
            let remaining = recv_timeout - started.elapsed();
            let (n, from) = match timeout(remaining, session.socket.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return fail_now(started, format!("recv echo failed: {e}")),
                Err(_) => return fail_now(started, format!("echo timeout after {recv_timeout:?}")),
            };
            if from != session.server {
                // Not from the control channel — ignore (could be stray
                // inbound, though on a fresh allocation this is rare).
                continue;
            }
            match parse_data_indication(&buf[..n]) {
                Ok(Some(data)) if data == ECHO_PAYLOAD => {
                    let echo_ms = echo_started.elapsed().as_millis() as u64;
                    let total_ms = started.elapsed().as_millis() as u64;
                    return CheckResult::pass(
                        ID,
                        NAME,
                        total_ms,
                        format!(
                            "{}-byte round-trip {} ms via {} (peer-as-self path)",
                            data.len(),
                            echo_ms,
                            session.relayed,
                        ),
                    )
                    .with_detail(json!({
                        "server": session.server.to_string(),
                        "relayed": session.relayed.to_string(),
                        "peer": srflx.to_string(),
                        "payload_bytes": data.len(),
                        "round_trip_ms": echo_ms,
                        "path": "client→relay→data-indication",
                    }));
                }
                // Either not a Data Indication, or a Data Indication
                // carrying something other than our payload — keep waiting.
                _ => continue,
            }
        }
    }
}

fn fail_now(started: Instant, msg: String) -> CheckResult {
    CheckResult::fail(ID, NAME, started.elapsed().as_millis() as u64, msg)
}

// ───── message builders ─────────────────────────────────────────────────

fn build_create_permission(
    username: &str,
    realm: &str,
    nonce: &[u8],
    key: &[u8; 16],
    peer: SocketAddr,
) -> ([u8; 12], Vec<u8>) {
    let txid = codec::new_txid();
    let mut msg = stun_header(CREATE_PERMISSION_REQUEST, &txid);
    let peer_attr = codec::build_xor_address(peer, &txid);
    append_attr(&mut msg, attr::XOR_PEER_ADDRESS, &peer_attr);
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

fn append_attr(msg: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    msg.extend_from_slice(&attr_type.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    for _ in 0..pad {
        msg.push(0);
    }
}

/// Same length-fixup trick as turn_alloc::attach_message_integrity.
/// Duplicated here rather than promoted to stun_codec because the
/// helpers in stun_codec are deliberately decode-only; building
/// auth'd requests is a check-level concern.
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

// ───── response parsing ────────────────────────────────────────────────

#[derive(Debug)]
enum CpOutcome {
    Success,
    Error { code: u16, reason: String },
}

#[derive(Debug, thiserror::Error)]
enum CpError {
    #[error("{0}")]
    Codec(#[from] codec::CodecError),
    #[error("unexpected message type 0x{0:04x}")]
    WrongType(u16),
    #[error("missing ERROR-CODE in error response")]
    MissingErrorCode,
}

fn parse_create_permission_response(buf: &[u8], txid: &[u8; 12]) -> Result<CpOutcome, CpError> {
    let header = codec::parse_header(buf, txid)?;
    match header.msg_type {
        CREATE_PERMISSION_SUCCESS => Ok(CpOutcome::Success),
        CREATE_PERMISSION_ERROR => {
            for a in codec::walk_attrs(buf, header.attrs_len)? {
                if a.attr_type == attr::ERROR_CODE {
                    let ec = codec::parse_error_code(a.value)?;
                    return Ok(CpOutcome::Error {
                        code: ec.code,
                        reason: ec.reason,
                    });
                }
            }
            Err(CpError::MissingErrorCode)
        }
        other => Err(CpError::WrongType(other)),
    }
}

/// Parse a Data Indication and return the `DATA` attribute body if present.
/// Returns `Ok(None)` if this isn't actually a Data Indication (a stray
/// other STUN/TURN message arrived), `Err` only on malformed bytes.
///
/// We can't validate the transaction ID — Data Indications carry whatever
/// txid the relay generated, which we have no way to predict. The matching
/// is done by source-address + payload content instead.
fn parse_data_indication(buf: &[u8]) -> Result<Option<Vec<u8>>, codec::CodecError> {
    if buf.len() < 20 {
        return Err(codec::CodecError::Short(buf.len()));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != DATA_INDICATION {
        return Ok(None);
    }
    let attrs_len = u16::from_be_bytes([buf[2], buf[3]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != codec::MAGIC_COOKIE {
        return Err(codec::CodecError::BadCookie(cookie));
    }
    if buf.len() < 20 + attrs_len as usize {
        return Err(codec::CodecError::TruncatedAttr);
    }
    // Reuse the same TLV walker; we just don't care about txid validation.
    let mut i = 20usize;
    let end = 20 + attrs_len as usize;
    while i + 4 <= end {
        let at = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let al = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + al;
        if val_end > end {
            return Err(codec::CodecError::TruncatedAttr);
        }
        if at == attr::DATA {
            return Ok(Some(buf[val_start..val_end].to_vec()));
        }
        i = val_end + ((4 - (al % 4)) % 4);
    }
    Ok(None)
}

// ───── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_permission_carries_required_attrs_and_mi() {
        let key = [0xCDu8; 16];
        let peer: SocketAddr = "198.51.100.7:55555".parse().unwrap();
        let (_txid, msg) = build_create_permission("u", "r.example", b"nonce!", &key, peer);

        assert_eq!(&msg[0..2], &CREATE_PERMISSION_REQUEST.to_be_bytes());
        let attrs_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(attrs_len, msg.len() - 20);

        // MI is always the final 24 bytes when present.
        let mi_start = msg.len() - 24;
        assert_eq!(
            &msg[mi_start..mi_start + 2],
            &attr::MESSAGE_INTEGRITY.to_be_bytes()
        );
        assert_eq!(&msg[mi_start + 2..mi_start + 4], &20u16.to_be_bytes());

        let header = codec::parse_header(&msg, &_txid).unwrap();
        let types: Vec<u16> = codec::walk_attrs(&msg, header.attrs_len)
            .unwrap()
            .iter()
            .map(|a| a.attr_type)
            .collect();
        assert!(types.contains(&attr::XOR_PEER_ADDRESS));
        assert!(types.contains(&attr::USERNAME));
        assert!(types.contains(&attr::REALM));
        assert!(types.contains(&attr::NONCE));
        assert!(types.contains(&attr::MESSAGE_INTEGRITY));
    }

    #[test]
    fn parses_create_permission_success() {
        let txid = [0x42u8; 12];
        let mut buf = Vec::new();
        buf.extend_from_slice(&CREATE_PERMISSION_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        matches!(
            parse_create_permission_response(&buf, &txid).unwrap(),
            CpOutcome::Success
        );
    }

    #[test]
    fn parses_create_permission_438_stale_nonce() {
        let txid = [0x77u8; 12];
        let mut buf = Vec::new();
        buf.extend_from_slice(&CREATE_PERMISSION_ERROR.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        let body_start = buf.len();
        append_attr(&mut buf, attr::ERROR_CODE, {
            let mut v = vec![0, 0, 4, 38]; // class 4, number 38 → 438 Stale Nonce
            v.extend_from_slice(b"Stale Nonce");
            &v.clone()
        });
        let attrs_len = (buf.len() - body_start) as u16;
        buf[2..4].copy_from_slice(&attrs_len.to_be_bytes());
        match parse_create_permission_response(&buf, &txid).unwrap() {
            CpOutcome::Error { code, reason } => {
                assert_eq!(code, 438);
                assert_eq!(reason, "Stale Nonce");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn extracts_data_from_data_indication() {
        // Hand-craft a Data Indication carrying DATA = b"hello".
        let txid = [0x11u8; 12];
        let mut buf = Vec::new();
        buf.extend_from_slice(&DATA_INDICATION.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        let body_start = buf.len();
        append_attr(&mut buf, attr::DATA, b"hello");
        let attrs_len = (buf.len() - body_start) as u16;
        buf[2..4].copy_from_slice(&attrs_len.to_be_bytes());

        let data = parse_data_indication(&buf).unwrap().expect("DATA present");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn non_data_indication_returns_none() {
        // Any other message type shouldn't match.
        let mut buf = Vec::new();
        buf.extend_from_slice(&CREATE_PERMISSION_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&[0u8; 12]);
        assert!(parse_data_indication(&buf).unwrap().is_none());
    }
}
