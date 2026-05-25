//! ICE candidate gathering — presentation-layer aggregator.
//!
//! What a real WebRTC PeerConnection does during gathering:
//!
//! 1. Enumerate every local network interface; for each unicast address,
//!    produce a **host** candidate.
//! 2. Bind a UDP socket per interface, send a STUN Binding Request to the
//!    configured STUN servers, and use the reflexive address it learns
//!    as a **server-reflexive** (srflx) candidate.
//! 3. If any TURN servers are configured, allocate against each and use
//!    the relayed transport address as a **relay** candidate.
//!
//! webrtc-doctor's `ice.gather` does the same enumeration but folds it
//! over the checks the pipeline has already run. By the time we get here:
//!
//! - `stun.binding` (a prerequisite) has populated `ctx.scratch["srflx"]`
//!   with one srflx candidate (binding from the default-route interface
//!   that `0.0.0.0:0` resolves to — same as a single-interface browser).
//! - `turn.alloc.udp`, if it ran, has populated `ctx.turn_session.relayed`.
//! - This check enumerates host candidates via `if-addrs` and emits a
//!   single Pass with the full candidate list in `detail`.
//!
//! What this check does *not* attempt:
//! - Per-interface STUN binding. Real ICE binds per interface so each
//!   gets its own srflx; we report one srflx from the default route.
//!   For "what does my deployment look like to a PeerConnection" that's
//!   the honest single-answer the same way one `curl ifconfig.me` is.
//! - Pre-binding sockets to expose a real port per host candidate.
//!   We list addresses; the port field is `0` to signal "unbound."
//! - mDNS hostname masking (`*.local`). Real Chrome anonymizes private
//!   IPs as mDNS hostnames during gathering; we deliberately show real
//!   addresses because the user asked for a diagnostic.
//! - Peer-reflexive candidates (discovered during connectivity checks,
//!   not during gathering).
//!
//! Filtering rules for host candidates:
//! - IPv4: skip loopback (127.0.0.0/8) and link-local APIPA (169.254/16).
//!   Private RFC 1918 ranges are kept — they're valid host candidates on
//!   a LAN even though useless across the public internet.
//! - IPv6: skip loopback (::1) and link-local (fe80::/10). Global and
//!   ULA are kept.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use serde::Serialize;
use serde_json::json;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;

const ID: &str = "ice.gather";
const NAME: &str = "ICE candidate gathering";

/// A single ICE candidate in our diagnostic output. Not a 1:1 of the SDP
/// `candidate:` attribute — we drop foundation/component/priority/etc.
/// because they're transport machinery for connectivity checks, not part
/// of the gathered-set the user wants to see.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// `host`, `srflx`, or `relay`. Matches the `typ` token in SDP.
    pub kind: &'static str,
    pub address: String,
    /// `0` for host candidates (we don't bind a socket per address) and
    /// the real ephemeral port for srflx/relay (which came from actual
    /// connections in earlier checks).
    pub port: u16,
    /// Best-effort interface label for host candidates. `None` for
    /// srflx/relay where the concept doesn't apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// For srflx/relay: the STUN/TURN URL we learned this from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

pub struct IceGatherCheck;

#[async_trait::async_trait]
impl Check for IceGatherCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn requires(&self) -> &'static [&'static str] {
        // STUN is the minimum prerequisite — without an srflx the
        // candidate list is just host enumeration and doesn't say much
        // about the deployment. TURN is optional and folded in below
        // if a session exists in ctx.
        &["stun.binding"]
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let started = Instant::now();
        let mut candidates: Vec<Candidate> = Vec::new();

        // ── Host candidates: enumerate local interfaces ───────────────
        match if_addrs::get_if_addrs() {
            Ok(addrs) => {
                for ifa in addrs {
                    let ip = ifa.ip();
                    if !is_useful_host_address(&ip) {
                        continue;
                    }
                    candidates.push(Candidate {
                        kind: "host",
                        address: ip.to_string(),
                        port: 0,
                        interface: Some(ifa.name),
                        via: None,
                    });
                }
            }
            Err(e) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("enumerate interfaces failed: {e}"),
                );
            }
        }

        // ── srflx: pulled from ctx.scratch where stun.binding put it ──
        let stun_via = ctx
            .host
            .as_ref()
            .zip(ctx.port)
            .map(|(h, p)| format!("stun:{h}:{p}"));
        if let Some(srflx_str) = ctx.scratch.get("srflx") {
            if let Ok(addr) = srflx_str.parse::<std::net::SocketAddr>() {
                candidates.push(Candidate {
                    kind: "srflx",
                    address: addr.ip().to_string(),
                    port: addr.port(),
                    interface: None,
                    via: stun_via.clone(),
                });
            }
        }

        // ── relay: pulled from the TURN session if one was established ─
        if let Some(session) = ctx.turn_session.as_ref() {
            let turn_via = ctx
                .host
                .as_ref()
                .zip(ctx.port)
                .map(|(h, p)| format!("turn:{h}:{p}"));
            candidates.push(Candidate {
                kind: "relay",
                address: session.relayed.ip().to_string(),
                port: session.relayed.port(),
                interface: None,
                via: turn_via,
            });
        }

        let total_ms = started.elapsed().as_millis() as u64;
        let counts = count_kinds(&candidates);
        let summary = format!(
            "{} candidates ({} host, {} srflx, {} relay)",
            candidates.len(),
            counts.host,
            counts.srflx,
            counts.relay,
        );

        // Always Pass: gathering is informational. The pass/fail signal
        // for connectivity lives in the underlying checks (stun.binding,
        // turn.alloc.udp); this check just presents what they found.
        // Warn only if we somehow ended up with zero candidates total,
        // which would mean STUN passed but srflx got lost AND interface
        // enumeration returned empty — a real anomaly worth surfacing.
        let result = if candidates.is_empty() {
            CheckResult::warn(ID, NAME, total_ms, "no candidates gathered")
        } else {
            CheckResult::pass(ID, NAME, total_ms, summary)
        };

        result.with_detail(json!({
            "candidates": candidates,
            "counts": {
                "host": counts.host,
                "srflx": counts.srflx,
                "relay": counts.relay,
            },
        }))
    }
}

#[derive(Default)]
struct KindCounts {
    host: usize,
    srflx: usize,
    relay: usize,
}

fn count_kinds(cands: &[Candidate]) -> KindCounts {
    let mut k = KindCounts::default();
    for c in cands {
        match c.kind {
            "host" => k.host += 1,
            "srflx" => k.srflx += 1,
            "relay" => k.relay += 1,
            _ => {}
        }
    }
    k
}

/// Filter rules per the module docs. Pulled out so the unit tests can
/// hammer it without spinning up `if-addrs`.
fn is_useful_host_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_useful_v4(v4),
        IpAddr::V6(v6) => is_useful_v6(v6),
    }
}

fn is_useful_v4(v4: &Ipv4Addr) -> bool {
    if v4.is_loopback() {
        return false;
    }
    if v4.is_link_local() {
        // 169.254.0.0/16 — APIPA. Not useful as an ICE candidate.
        return false;
    }
    if v4.is_unspecified() {
        return false;
    }
    if v4.is_multicast() || v4.is_broadcast() {
        return false;
    }
    true
}

fn is_useful_v6(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() {
        return false;
    }
    if v6.is_unspecified() {
        return false;
    }
    if v6.is_multicast() {
        return false;
    }
    // fe80::/10 — link-local. std doesn't expose Ipv6Addr::is_unicast_link_local
    // on stable, so do the prefix test manually.
    let seg0 = v6.segments()[0];
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_filter_keeps_routable_drops_loopback_and_link_local() {
        assert!(is_useful_host_address(&"192.168.1.42".parse().unwrap()));
        assert!(is_useful_host_address(&"10.0.0.5".parse().unwrap()));
        assert!(is_useful_host_address(&"172.16.0.1".parse().unwrap()));
        assert!(is_useful_host_address(&"8.8.8.8".parse().unwrap()));
        assert!(!is_useful_host_address(&"127.0.0.1".parse().unwrap()));
        assert!(!is_useful_host_address(&"169.254.1.1".parse().unwrap()));
        assert!(!is_useful_host_address(&"0.0.0.0".parse().unwrap()));
        assert!(!is_useful_host_address(&"224.0.0.1".parse().unwrap()));
        assert!(!is_useful_host_address(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ipv6_filter_drops_loopback_link_local_keeps_global_and_ula() {
        assert!(!is_useful_host_address(&"::1".parse().unwrap()));
        assert!(!is_useful_host_address(&"::".parse().unwrap()));
        assert!(!is_useful_host_address(&"fe80::1".parse().unwrap()));
        assert!(!is_useful_host_address(&"fe80::a:b:c:d".parse().unwrap()));
        assert!(!is_useful_host_address(&"ff02::1".parse().unwrap()));
        // Global unicast
        assert!(is_useful_host_address(
            &"2603:6010:6c00:abcd::42".parse().unwrap()
        ));
        // ULA (fc00::/7) — kept; useful on a local LAN even if not internet-routable.
        assert!(is_useful_host_address(&"fd12:3456::1".parse().unwrap()));
    }

    #[test]
    fn count_kinds_tallies_correctly() {
        let cands = vec![
            mk("host", "192.168.1.1", 0),
            mk("host", "10.0.0.1", 0),
            mk("srflx", "1.2.3.4", 5555),
            mk("relay", "5.6.7.8", 49152),
        ];
        let k = count_kinds(&cands);
        assert_eq!(k.host, 2);
        assert_eq!(k.srflx, 1);
        assert_eq!(k.relay, 1);
    }

    fn mk(kind: &'static str, addr: &str, port: u16) -> Candidate {
        Candidate {
            kind,
            address: addr.into(),
            port,
            interface: None,
            via: None,
        }
    }
}
