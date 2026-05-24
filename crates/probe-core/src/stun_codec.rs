//! Shared STUN/TURN wire-format codec (RFC 5389, RFC 5766).
//!
//! Both `checks::stun` and `checks::turn_alloc` produce and consume STUN
//! messages; the header layout, transaction IDs, attribute TLV walking, and
//! the address-attribute family encoding are identical. Keeping a single
//! implementation here avoids drift between the two checks.
//!
//! What this module does NOT do: build full messages or compute
//! MESSAGE-INTEGRITY / FINGERPRINT. Those live in the modules that own those
//! semantics (`turn_alloc.rs`), which use the helpers exposed here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// RFC 5389 §6: every STUN message starts with this 32-bit constant.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Attribute types we read across multiple checks (RFC 5389 §18.2, RFC 5766 §14).
pub mod attr {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const LIFETIME: u16 = 0x000D;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("message shorter than 20-byte header ({0} bytes)")]
    Short(usize),
    #[error("magic cookie mismatch: 0x{0:08x}")]
    BadCookie(u32),
    #[error("transaction id mismatch")]
    TxIdMismatch,
    #[error("attribute body shorter than declared length")]
    TruncatedAttr,
    #[error("unknown address family 0x{0:02x}")]
    BadFamily(u8),
}

/// Parsed view of a STUN message header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub msg_type: u16,
    pub attrs_len: u16,
    pub txid: [u8; 12],
}

/// Parse and validate the 20-byte STUN header, checking cookie and tx ID.
pub fn parse_header(buf: &[u8], expected_txid: &[u8; 12]) -> Result<Header, CodecError> {
    if buf.len() < 20 {
        return Err(CodecError::Short(buf.len()));
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let attrs_len = u16::from_be_bytes([buf[2], buf[3]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(CodecError::BadCookie(cookie));
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    if &txid != expected_txid {
        return Err(CodecError::TxIdMismatch);
    }
    if buf.len() < 20 + attrs_len as usize {
        return Err(CodecError::TruncatedAttr);
    }
    Ok(Header {
        msg_type,
        attrs_len,
        txid,
    })
}

/// A single TLV attribute as it appears on the wire.
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    pub attr_type: u16,
    pub value: &'a [u8],
}

/// Iterate the attribute section, returning each `(type, value)` pair.
/// Padding to 4-byte boundaries is consumed implicitly.
pub fn walk_attrs<'a>(buf: &'a [u8], attrs_len: u16) -> Result<Vec<Attr<'a>>, CodecError> {
    let mut out = Vec::new();
    let mut i = 20usize;
    let end = 20 + attrs_len as usize;
    while i + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return Err(CodecError::TruncatedAttr);
        }
        out.push(Attr {
            attr_type,
            value: &buf[val_start..val_end],
        });
        i = val_end + ((4 - (attr_len % 4)) % 4);
    }
    Ok(out)
}

/// Decode an `XOR-MAPPED-ADDRESS`-style attribute (also used for
/// `XOR-RELAYED-ADDRESS` — same family + XOR mask layout).
pub fn parse_xor_address(value: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, CodecError> {
    if value.len() < 4 {
        return Err(CodecError::TruncatedAttr);
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(CodecError::TruncatedAttr);
            }
            let xaddr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let addr = xaddr ^ MAGIC_COOKIE;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(CodecError::TruncatedAttr);
            }
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txid);
            let mut addr = [0u8; 16];
            for (i, b) in addr.iter_mut().enumerate() {
                *b = value[4 + i] ^ mask[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        f => Err(CodecError::BadFamily(f)),
    }
}

/// Encode a `SocketAddr` as the body of an `XOR-MAPPED-ADDRESS`-style
/// attribute (also used for `XOR-PEER-ADDRESS` and `XOR-RELAYED-ADDRESS`).
/// Layout: 1 byte reserved (0), 1 byte family, 2 bytes XOR-port, then the
/// XOR-address (4 bytes for v4, 16 bytes for v6 with the cookie-plus-txid
/// mask).
pub fn build_xor_address(addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0); // reserved
    let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&xport.to_be_bytes());
            let raw = u32::from(v4);
            let xaddr = raw ^ MAGIC_COOKIE;
            out.extend_from_slice(&xaddr.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&xport.to_be_bytes());
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(txid);
            let raw = v6.octets();
            for i in 0..16 {
                out.push(raw[i] ^ mask[i]);
            }
        }
    }
    out
}

/// Decode a legacy (pre-RFC 5389) `MAPPED-ADDRESS` — no XOR.
pub fn parse_mapped_address(value: &[u8]) -> Result<SocketAddr, CodecError> {
    if value.len() < 4 {
        return Err(CodecError::TruncatedAttr);
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(CodecError::TruncatedAttr);
            }
            let addr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(CodecError::TruncatedAttr);
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        f => Err(CodecError::BadFamily(f)),
    }
}

/// RFC 5389 §15.6 — ERROR-CODE: reserved(2B) + class(1B) + number(1B) + reason(UTF-8).
#[derive(Debug, Clone)]
pub struct ErrorCode {
    pub code: u16,
    pub reason: String,
}

pub fn parse_error_code(value: &[u8]) -> Result<ErrorCode, CodecError> {
    if value.len() < 4 {
        return Err(CodecError::TruncatedAttr);
    }
    let class = (value[2] & 0x07) as u16;
    let number = value[3] as u16;
    let code = class * 100 + number;
    let reason = String::from_utf8_lossy(&value[4..]).into_owned();
    Ok(ErrorCode { code, reason })
}

/// Generate a 12-byte transaction ID. Uniqueness per outstanding request is
/// the only requirement (RFC 5389 §6); not security-sensitive.
pub fn new_txid() -> [u8; 12] {
    let mut txid = [0u8; 12];
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    txid[..8].copy_from_slice(&nanos.to_be_bytes());
    let stack_addr = (&txid as *const _ as usize) as u32;
    txid[8..].copy_from_slice(&stack_addr.to_be_bytes());
    txid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_address_roundtrips_v4() {
        let txid = [0xAAu8; 12];
        let addr: SocketAddr = "192.0.2.5:31415".parse().unwrap();
        let encoded = build_xor_address(addr, &txid);
        let decoded = parse_xor_address(&encoded, &txid).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn xor_address_roundtrips_v6() {
        let txid = [0x55u8; 12];
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let encoded = build_xor_address(addr, &txid);
        let decoded = parse_xor_address(&encoded, &txid).unwrap();
        assert_eq!(decoded, addr);
    }
}
