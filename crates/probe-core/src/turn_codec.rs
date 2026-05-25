//! Shared TURN message-building and response parsing.
//!
//! Parallel to [`crate::stun_codec`] but TURN-specific. Holds the bits
//! that used to be triplicated across `turn_alloc.rs`, `turns_alloc.rs`,
//! and `turn_echo.rs`:
//!
//! - Allocate / CreatePermission method codes.
//! - REQUESTED-TRANSPORT = UDP constant (RFC 5766 §14.7).
//! - STUN header builder, TLV `append_attr`, attrs-length fixup.
//! - MESSAGE-INTEGRITY attachment (HMAC-SHA1 with the length-pre-MI trick
//!   from RFC 5389 §15.4).
//! - Long-term credential key derivation (`MD5(user:realm:pass)`).
//! - The unauthenticated / authenticated Allocate request builders.
//! - The Allocate response parser and its outcome / error types.
//!
//! What *doesn't* live here:
//!
//! - The Allocate flow itself (socket setup, retransmit policy, scratch
//!   updates). Each check owns its transport — UDP socket for
//!   `turn_alloc`, 2-byte-length-framed TLS stream for `turns_alloc`.
//! - The CreatePermission request builder used by `turn_echo`. It still
//!   uses the helpers here (`stun_header`, `append_attr`,
//!   `attach_message_integrity`), but the attribute set is
//!   echo-specific (XOR-PEER-ADDRESS, not REQUESTED-TRANSPORT) so the
//!   high-level builder stays in that module.
//! - Data Indication parsing. That's also echo-only.

use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

use crate::stun_codec::{self as stun, attr};

// ───── method codes ─────────────────────────────────────────────────────

/// Allocate Request (RFC 5766 §6.2).
pub const ALLOCATE_REQUEST: u16 = 0x0003;
/// Allocate Success Response.
pub const ALLOCATE_SUCCESS: u16 = 0x0103;
/// Allocate Error Response.
pub const ALLOCATE_ERROR: u16 = 0x0113;

/// CreatePermission Request (RFC 5766 §9). Used by `turn_echo` only;
/// constants live here so all TURN method codes are in one place.
pub const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub const CREATE_PERMISSION_SUCCESS: u16 = 0x0108;
pub const CREATE_PERMISSION_ERROR: u16 = 0x0118;

/// REQUESTED-TRANSPORT value for UDP (RFC 5766 §14.7 — IANA protocol
/// number 17). The 24 low bits are RFFU (reserved) and must be zero.
pub const TRANSPORT_UDP: u32 = 17 << 24;

// ───── message-building primitives ──────────────────────────────────────

/// Build a 20-byte STUN/TURN header for `method`. The `attrs_len` field
/// is left at zero — call [`set_attrs_length`] (or the higher-level
/// builders) once the body is appended.
pub fn stun_header(method: u16, txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&method.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // length, fixed up later
    msg.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg
}

/// Append a TLV attribute, padding the value to 4-byte alignment per
/// RFC 5389 §15.
pub fn append_attr(msg: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    msg.extend_from_slice(&attr_type.to_be_bytes());
    msg.extend_from_slice(&(value.len() as u16).to_be_bytes());
    msg.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    for _ in 0..pad {
        msg.push(0);
    }
}

/// Rewrite the header's `attrs_len` field to reflect the current buffer.
pub fn set_attrs_length(msg: &mut [u8]) {
    let attrs_len = (msg.len() - 20) as u16;
    msg[2..4].copy_from_slice(&attrs_len.to_be_bytes());
}

/// Append the MESSAGE-INTEGRITY attribute. RFC 5389 §15.4: HMAC-SHA1 is
/// computed over the message *as if MI were already present* (the
/// length field must include the 24 bytes MI will occupy), but the
/// digest itself is computed only over the bytes *before* MI.
pub fn attach_message_integrity(msg: &mut Vec<u8>, key: &[u8; 16]) {
    let length_with_mi = (msg.len() - 20 + 24) as u16;
    msg[2..4].copy_from_slice(&length_with_mi.to_be_bytes());

    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let digest = mac.finalize().into_bytes();

    msg.extend_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
    msg.extend_from_slice(&20u16.to_be_bytes());
    msg.extend_from_slice(&digest);
    // 20 is already 4-aligned — no padding required.
}

/// RFC 5389 §15.4 / RFC 5766 §6.2: `key = MD5(username ":" realm ":" password)`.
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
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

// ───── Allocate request builders ────────────────────────────────────────

/// Build an unauthenticated Allocate request. The server will reject it
/// with 401 carrying REALM + NONCE; that's the protocol's challenge step.
pub fn build_allocate_unauth() -> ([u8; 12], Vec<u8>) {
    let txid = stun::new_txid();
    let mut msg = stun_header(ALLOCATE_REQUEST, &txid);
    append_attr(
        &mut msg,
        attr::REQUESTED_TRANSPORT,
        &TRANSPORT_UDP.to_be_bytes(),
    );
    set_attrs_length(&mut msg);
    (txid, msg)
}

/// Build an authenticated Allocate request following the long-term
/// credential mechanism: USERNAME / REALM / NONCE attributes plus a
/// trailing MESSAGE-INTEGRITY signed with `key` (= [`long_term_key`]).
pub fn build_allocate_authed(
    username: &str,
    realm: &str,
    nonce: &[u8],
    key: &[u8; 16],
) -> ([u8; 12], Vec<u8>) {
    let txid = stun::new_txid();
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

// ───── Allocate response parsing ────────────────────────────────────────

/// Outcome of an Allocate request from the server's perspective.
#[derive(Debug)]
pub enum AllocateOutcome {
    /// The relay address (XOR-RELAYED-ADDRESS) and lifetime the server granted.
    Success { relayed: SocketAddr, lifetime: u32 },
    /// 401 with REALM + NONCE — the long-term-credential challenge step.
    Unauthorized { realm: String, nonce: Vec<u8> },
    /// Any other error response (403, 437, 500…). `reason` is the
    /// server-provided text, useful as-is in the report line.
    Error { code: u16, reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum AllocateError {
    #[error("{0}")]
    Codec(#[from] stun::CodecError),
    #[error("unexpected message type 0x{0:04x}")]
    WrongType(u16),
    #[error("missing required attribute {0}")]
    MissingAttr(&'static str),
}

/// Parse an Allocate Success / Error response. `txid` is the
/// transaction ID we sent so the codec can validate the echo.
pub fn parse_allocate_response(
    buf: &[u8],
    txid: &[u8; 12],
) -> Result<AllocateOutcome, AllocateError> {
    let header = stun::parse_header(buf, txid)?;
    let attrs = stun::walk_attrs(buf, header.attrs_len)?;

    match header.msg_type {
        ALLOCATE_SUCCESS => {
            let mut relayed: Option<SocketAddr> = None;
            let mut lifetime: u32 = 0;
            for a in &attrs {
                match a.attr_type {
                    attr::XOR_RELAYED_ADDRESS => {
                        relayed = Some(stun::parse_xor_address(a.value, txid)?);
                    }
                    // Match guard (not nested `if`) keeps clippy's
                    // collapsible_match family happy and reads as the
                    // single conditional it actually is.
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
                        let ec = stun::parse_error_code(a.value)?;
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
    fn long_term_key_pins_known_md5() {
        // md5("user:example.com:pass") — pinned against the md-5 crate
        // output as a regression guard on the formula (not the digest
        // impl). Same vector used by the prior turn_alloc tests.
        let k = long_term_key("user", "example.com", "pass");
        let expected: [u8; 16] = [
            0xc1, 0x9c, 0x4c, 0x6e, 0x32, 0xf9, 0xd8, 0x02, 0x6b, 0x26, 0xba, 0x77, 0xc2, 0x1f,
            0xb8, 0xeb,
        ];
        assert_eq!(k, expected);
    }

    #[test]
    fn unauth_allocate_request_layout() {
        let (txid, msg) = build_allocate_unauth();
        assert_eq!(&msg[0..2], &ALLOCATE_REQUEST.to_be_bytes());
        let attrs_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(attrs_len, msg.len() - 20);
        assert_eq!(&msg[4..8], &stun::MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&msg[8..20], &txid);
        // Exactly REQUESTED-TRANSPORT (4-byte header + 4-byte value).
        assert_eq!(msg.len(), 20 + 8);
        assert_eq!(&msg[20..22], &attr::REQUESTED_TRANSPORT.to_be_bytes());
        assert_eq!(&msg[22..24], &4u16.to_be_bytes());
        assert_eq!(&msg[24..28], &TRANSPORT_UDP.to_be_bytes());
    }

    #[test]
    fn authed_allocate_carries_mi_with_correct_length() {
        let key = [0xABu8; 16];
        let (_txid, msg) = build_allocate_authed("alice", "realm.tld", b"nonce!", &key);

        // attrs_len must include the trailing MI attribute.
        let attrs_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
        assert_eq!(attrs_len, msg.len() - 20);

        // Last 24 bytes are the MI attribute: 4-byte header + 20-byte digest.
        let mi_start = msg.len() - 24;
        assert_eq!(
            &msg[mi_start..mi_start + 2],
            &attr::MESSAGE_INTEGRITY.to_be_bytes()
        );
        assert_eq!(&msg[mi_start + 2..mi_start + 4], &20u16.to_be_bytes());

        // The digest must match an HMAC-SHA1 over the message-without-MI
        // but with the header length already set to include MI.
        let mut mac =
            <Hmac<Sha1> as Mac>::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(&msg[..mi_start]);
        let digest = mac.finalize().into_bytes();
        assert_eq!(&msg[mi_start + 4..], &digest[..]);
    }

    #[test]
    fn parses_401_unauthorized_with_realm_and_nonce() {
        let txid = [7u8; 12];
        let mut buf = Vec::new();
        buf.extend_from_slice(&ALLOCATE_ERROR.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
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
    fn parses_success_with_relayed_address_and_lifetime() {
        let txid = [9u8; 12];
        let target_ip: u32 = 0xCB00_7102; // 203.0.113.2
        let target_port: u16 = 49152;
        let xport = target_port ^ ((stun::MAGIC_COOKIE >> 16) as u16);
        let xaddr = target_ip ^ stun::MAGIC_COOKIE;

        let mut buf = Vec::new();
        buf.extend_from_slice(&ALLOCATE_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        let mut value = Vec::new();
        value.push(0);
        value.push(0x01); // family v4
        value.extend_from_slice(&xport.to_be_bytes());
        value.extend_from_slice(&xaddr.to_be_bytes());
        append_attr(&mut buf, attr::XOR_RELAYED_ADDRESS, &value);
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
}
