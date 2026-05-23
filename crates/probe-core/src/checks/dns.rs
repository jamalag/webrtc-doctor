//! DNS resolution check.
//!
//! Resolves `ctx.host` through the OS resolver (`getaddrinfo`), records the
//! returned A/AAAA addresses into `ctx.resolved_ips` for downstream checks,
//! and reports per-host latency.
//!
//! We use `tokio::net::lookup_host` (i.e. `getaddrinfo` on a blocking pool)
//! rather than a userspace resolver like hickory because:
//!
//! 1. A diagnostic tool should resolve names the way the user's apps do —
//!    hosts file, mDNS, NRPT / split DNS, IPv6 preference, all included.
//!    A userspace resolver bypasses every one of those.
//! 2. Userspace resolvers wait out their per-server timeout when one of the
//!    OS-configured upstreams is unreachable; `getaddrinfo` short-circuits.
//!    We observed 10s stalls on Windows with hickory because of this.
//! 3. One fewer transitive dependency tree.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use serde_json::json;
use tokio::net::lookup_host;

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;

const ID: &str = "dns";
const NAME: &str = "DNS resolution";

pub struct DnsCheck;

#[async_trait::async_trait]
impl Check for DnsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let host = match ctx.host.as_deref() {
            Some(h) => h.to_string(),
            None => return CheckResult::skip(ID, NAME, "no host supplied"),
        };

        // `lookup_host` requires a port; the port is irrelevant for DNS but
        // tokio mirrors the `getaddrinfo` "service" parameter. Use the real
        // port if we have one (purely cosmetic), 0 otherwise.
        let port = ctx.port.unwrap_or(0);
        let query = format!("{host}:{port}");

        let started = Instant::now();
        let iter = match lookup_host(query.as_str()).await {
            Ok(it) => it,
            Err(e) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("{host} did not resolve: {e}"),
                );
            }
        };

        // `lookup_host` returns `SocketAddr`s — strip the port and dedupe.
        let mut seen = HashSet::new();
        let mut ips: Vec<IpAddr> = Vec::new();
        for sa in iter {
            let ip = sa.ip();
            if seen.insert(ip) {
                ips.push(ip);
            }
        }

        let latency_ms = started.elapsed().as_millis() as u64;

        if ips.is_empty() {
            return CheckResult::fail(
                ID,
                NAME,
                latency_ms,
                format!("{host} resolved to zero addresses"),
            );
        }

        ctx.resolved_ips = ips.clone();

        let summary = if ips.len() == 1 {
            format!("{host} → {} ({} ms)", ips[0], latency_ms)
        } else {
            format!(
                "{host} → {} (+{} more, {} ms)",
                ips[0],
                ips.len() - 1,
                latency_ms,
            )
        };

        CheckResult::pass(ID, NAME, latency_ms, summary).with_detail(json!({
            "host": host,
            "addresses": ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        }))
    }
}
