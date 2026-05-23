//! STUN binding check.
//!
//! Sends a single STUN Binding Request to `ctx.host:ctx.port` over UDP and
//! parses the response's `XOR-MAPPED-ADDRESS` to learn the server-reflexive
//! address. The reflexive address is what tells you NAT/firewall actually
//! lets WebRTC's UDP path out — which is the whole point.
//!
//! We hand-roll the wire format (RFC 5389 §6, §15.2) instead of pulling the
//! `stun` crate. A binding request is 20 bytes; a binding response carries a
//! single `XOR-MAPPED-ADDRESS` (0x0020) attribute. This is small enough that
//! a focused implementation is clearer than wrangling an external API, and it
//! gives us a unit-testable parser.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;

const ID: &str = "stun.binding";
const NAME: &str = "STUN binding";

/// RFC 5389 §6: every STUN message starts with this 32-bit constant.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN method | class. Binding Request = method `Binding`(0x001), class `Request`(0b00).
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

/// Attribute types we care about (RFC 5389 §18.2).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Pre-RFC 5389 servers sometimes still send the unencoded form; accept both.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

pub struct StunBindingCheck;

#[async_trait::async_trait]
impl Check for StunBindingCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn requires(&self) -> &'static [&'static str] {
        // Needs an IP to talk to. DNS populates `ctx.resolved_ips`.
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

        let (txid, request) = build_binding_request();

        // Bind the matching address family so a v6-only target works.
        let local_bind: SocketAddr = match ip {
            IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            IpAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let sock = match UdpSocket::bind(local_bind).await {
            Ok(s) => s,
            Err(e) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("local UDP bind failed: {e}"),
                )
            }
        };

        if let Err(e) = sock.send_to(&request, server).await {
            return CheckResult::fail(
                ID,
                NAME,
                started.elapsed().as_millis() as u64,
                format!("send to {server} failed: {e}"),
            );
        }

        let mut buf = [0u8; 1500];
        let recv_timeout = if ctx.default_timeout.is_zero() {
            Duration::from_secs(5)
        } else {
            ctx.default_timeout
        };
        let (n, _from) = match timeout(recv_timeout, sock.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("recv failed: {e}"),
                )
            }
            Err(_) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("no response from {server} in {:?}", recv_timeout),
                )
            }
        };

        let latency_ms = started.elapsed().as_millis() as u64;

        match parse_binding_response(&buf[..n], &txid) {
            Ok(srflx) => {
                ctx.scratch
                    .insert("srflx".to_string(), srflx.to_string());
                CheckResult::pass(
                    ID,
                    NAME,
                    latency_ms,
                    format!("srflx {srflx} ({latency_ms} ms)"),
                )
                .with_detail(json!({
                    "server": server.to_string(),
                    "srflx": srflx.to_string(),
                }))
            }
            Err(e) => CheckResult::fail(ID, NAME, latency_ms, format!("bad response: {e}")),
        }
    }
}

/// Build a Binding Request: 20-byte header, no attributes. Returns the
/// transaction ID we'll match the response against.
fn build_binding_request() -> ([u8; 12], Vec<u8>) {
    let mut txid = [0u8; 12];
    // Tokio's `rand` would pull another dep — use a quick std-only seed.
    // Transaction IDs only need to be unique per outstanding request, not
    // cryptographically random.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    txid[..8].copy_from_slice(&nanos.to_be_bytes());
    // Mix in the address of a stack local for the remaining 4 bytes.
    let stack_addr = (&txid as *const _ as usize) as u32;
    txid[8..].copy_from_slice(&stack_addr.to_be_bytes());

    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes()); // type
    msg.extend_from_slice(&0u16.to_be_bytes()); // length (no attributes)
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txid);
    (txid, msg)
}

#[derive(Debug, thiserror::Error)]
enum ParseError {
    #[error("response shorter than 20-byte header ({0} bytes)")]
    Short(usize),
    #[error("magic cookie mismatch: 0x{0:08x}")]
    BadCookie(u32),
    #[error("transaction id mismatch")]
    TxIdMismatch,
    #[error("message type 0x{0:04x} is not a binding success")]
    WrongType(u16),
    #[error("attribute body shorter than declared length")]
    TruncatedAttr,
    #[error("no mapped-address attribute in response")]
    NoMappedAddress,
    #[error("unknown address family 0x{0:02x}")]
    BadFamily(u8),
}

/// Parse a Binding Response and return the reflexive `SocketAddr`.
fn parse_binding_response(buf: &[u8], expected_txid: &[u8; 12]) -> Result<SocketAddr, ParseError> {
    if buf.len() < 20 {
        return Err(ParseError::Short(buf.len()));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(ParseError::BadCookie(cookie));
    }
    if &buf[8..20] != expected_txid {
        return Err(ParseError::TxIdMismatch);
    }
    if msg_type != BINDING_SUCCESS {
        return Err(ParseError::WrongType(msg_type));
    }
    if buf.len() < 20 + length {
        return Err(ParseError::TruncatedAttr);
    }

    // Walk TLV attributes. Each is: 2B type, 2B length, value, padded to 4-byte boundary.
    let mut i = 20;
    let end = 20 + length;
    while i + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return Err(ParseError::TruncatedAttr);
        }
        let value = &buf[val_start..val_end];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => return parse_xor_mapped_address(value, expected_txid),
            ATTR_MAPPED_ADDRESS => return parse_mapped_address(value),
            _ => {}
        }

        // 4-byte alignment padding.
        i = val_end + ((4 - (attr_len % 4)) % 4);
    }
    Err(ParseError::NoMappedAddress)
}

/// RFC 5389 §15.2 — `XOR-MAPPED-ADDRESS`. Port XORed with high 16 bits of the
/// magic cookie; v4 address XORed with the cookie; v6 address XORed with
/// cookie ++ txid.
fn parse_xor_mapped_address(value: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, ParseError> {
    if value.len() < 4 {
        return Err(ParseError::TruncatedAttr);
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(ParseError::TruncatedAttr);
            }
            let xaddr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = xaddr ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(ParseError::TruncatedAttr);
            }
            // Build a 16-byte XOR mask: magic cookie followed by txid.
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txid);
            let mut addr = [0u8; 16];
            for (i, b) in addr.iter_mut().enumerate() {
                *b = value[4 + i] ^ mask[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        f => Err(ParseError::BadFamily(f)),
    }
}

/// RFC 5389 §15.1 — legacy `MAPPED-ADDRESS` (not XORed).
fn parse_mapped_address(value: &[u8]) -> Result<SocketAddr, ParseError> {
    if value.len() < 4 {
        return Err(ParseError::TruncatedAttr);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(ParseError::TruncatedAttr);
            }
            let addr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(ParseError::TruncatedAttr);
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        f => Err(ParseError::BadFamily(f)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_is_well_formed() {
        let (txid, msg) = build_binding_request();
        assert_eq!(msg.len(), 20);
        assert_eq!(&msg[0..2], &[0x00, 0x01]); // type
        assert_eq!(&msg[2..4], &[0x00, 0x00]); // length
        assert_eq!(&msg[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&msg[8..20], &txid);
    }

    #[test]
    fn parses_xor_mapped_address_v4() {
        // Hand-craft a binding success with one XOR-MAPPED-ADDRESS attribute
        // pointing at 192.0.2.1:1234.
        let txid = [1u8; 12];
        let target_ip: u32 = 0xC000_0201; // 192.0.2.1
        let target_port: u16 = 1234;
        let xport = target_port ^ ((MAGIC_COOKIE >> 16) as u16);
        let xaddr = target_ip ^ MAGIC_COOKIE;

        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&12u16.to_be_bytes()); // attr section length
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        // Attribute: XOR-MAPPED-ADDRESS, length 8, family v4
        buf.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.push(0x00); // reserved
        buf.push(0x01); // family v4
        buf.extend_from_slice(&xport.to_be_bytes());
        buf.extend_from_slice(&xaddr.to_be_bytes());

        let got = parse_binding_response(&buf, &txid).unwrap();
        assert_eq!(got, "192.0.2.1:1234".parse().unwrap());
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let (txid, _) = build_binding_request();
        let mut wrong = txid;
        wrong[0] ^= 0xFF;
        // minimal valid header so the txid check is what fires
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&wrong);
        assert!(matches!(
            parse_binding_response(&buf, &txid),
            Err(ParseError::TxIdMismatch)
        ));
    }
}
