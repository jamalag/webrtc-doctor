//! Minimal target URL parsing for the CLI subcommands.
//!
//! `stun:`, `turn:`, `turns:` are URI schemes from RFC 7064 / 7065 — they look
//! like `stun:host:port` (no `//`). `wss://` / `ws://` use standard URL form.
//! We only need host + port at this stage; full query-string params (transport
//! hints, etc.) land when the TURN checks need them.

use anyhow::{anyhow, Context, Result};

#[derive(Debug, Clone)]
pub struct Target {
    // Read once the STUN/TURN checks route on it. Kept now so the parser API
    // is stable across the upcoming check landings.
    #[allow(dead_code)]
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

/// Parse a `stun:` / `turn:` / `turns:` URI.
pub fn parse_stun_like(url: &str, default_port: u16) -> Result<Target> {
    let (scheme, rest) = url
        .split_once(':')
        .ok_or_else(|| anyhow!("missing scheme in `{url}` (expected e.g. stun:host:port)"))?;

    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("invalid port in `{url}`"))?;
            (h.trim_matches(|c| c == '[' || c == ']').to_string(), port)
        }
        None => (rest.to_string(), default_port),
    };

    if host.is_empty() {
        return Err(anyhow!("empty host in `{url}`"));
    }
    Ok(Target {
        scheme: scheme.to_string(),
        host,
        port,
    })
}
