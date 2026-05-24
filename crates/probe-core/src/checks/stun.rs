//! STUN binding check.
//!
//! Sends a STUN Binding Request to `ctx.host:ctx.port` over UDP, parses the
//! response's `XOR-MAPPED-ADDRESS` (or legacy `MAPPED-ADDRESS`) to learn the
//! server-reflexive address. The reflexive address is what proves NAT and
//! firewall let WebRTC's UDP path out — the whole point of probing.
//!
//! Wire-format helpers live in [`crate::stun_codec`]; this module owns the
//! Binding-specific message building and the policy of which attribute we
//! prefer when both forms are present.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;
use crate::stun_codec::{self as codec, attr};

const ID: &str = "stun.binding";
const NAME: &str = "STUN binding";

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

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
                ctx.scratch.insert("srflx".to_string(), srflx.to_string());
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

fn build_binding_request() -> ([u8; 12], Vec<u8>) {
    let txid = codec::new_txid();
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes()); // no attributes
    msg.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&txid);
    (txid, msg)
}

#[derive(Debug, thiserror::Error)]
enum BindingError {
    #[error("{0}")]
    Codec(#[from] codec::CodecError),
    #[error("message type 0x{0:04x} is not a binding success")]
    WrongType(u16),
    #[error("no mapped-address attribute in response")]
    NoMappedAddress,
}

fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, BindingError> {
    let header = codec::parse_header(buf, txid)?;
    if header.msg_type != BINDING_SUCCESS {
        return Err(BindingError::WrongType(header.msg_type));
    }
    for a in codec::walk_attrs(buf, header.attrs_len)? {
        match a.attr_type {
            attr::XOR_MAPPED_ADDRESS => return Ok(codec::parse_xor_address(a.value, txid)?),
            attr::MAPPED_ADDRESS => return Ok(codec::parse_mapped_address(a.value)?),
            _ => {}
        }
    }
    Err(BindingError::NoMappedAddress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_is_well_formed() {
        let (txid, msg) = build_binding_request();
        assert_eq!(msg.len(), 20);
        assert_eq!(&msg[0..2], &[0x00, 0x01]);
        assert_eq!(&msg[2..4], &[0x00, 0x00]);
        assert_eq!(&msg[4..8], &codec::MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&msg[8..20], &txid);
    }

    #[test]
    fn parses_xor_mapped_address_v4() {
        let txid = [1u8; 12];
        let target_ip: u32 = 0xC000_0201;
        let target_port: u16 = 1234;
        let xport = target_port ^ ((codec::MAGIC_COOKIE >> 16) as u16);
        let xaddr = target_ip ^ codec::MAGIC_COOKIE;

        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txid);
        buf.extend_from_slice(&attr::XOR_MAPPED_ADDRESS.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.push(0x00);
        buf.push(0x01);
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
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&codec::MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&wrong);
        assert!(matches!(
            parse_binding_response(&buf, &txid),
            Err(BindingError::Codec(codec::CodecError::TxIdMismatch))
        ));
    }
}
