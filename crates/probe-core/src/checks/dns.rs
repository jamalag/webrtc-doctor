//! DNS resolution check.
//!
//! Resolves `ctx.host` via the system's configured resolvers (read from
//! `/etc/resolv.conf` on Unix and the registry on Windows), records the
//! returned A/AAAA addresses into `ctx.resolved_ips` for downstream checks,
//! and reports per-host latency.

use std::time::Instant;

use hickory_resolver::TokioAsyncResolver;
use serde_json::json;

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

        let started = Instant::now();

        // `from_system_conf` reads OS-level resolver config. On Windows that
        // means the NRPT / interface DNS settings; on Unix, /etc/resolv.conf.
        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(e) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("resolver init failed: {e}"),
                );
            }
        };

        let lookup = match resolver.lookup_ip(host.as_str()).await {
            Ok(l) => l,
            Err(e) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("{host} did not resolve: {e}"),
                );
            }
        };

        let ips: Vec<_> = lookup.iter().collect();
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

        // Mimic the README's `host → ip (Nms)` shape; if multiple, show the
        // first and a `(+N)`.
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
