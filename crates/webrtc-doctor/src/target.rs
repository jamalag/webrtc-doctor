//! Minimal target URL parsing for the CLI subcommands.
//!
//! `stun:`, `turn:`, `turns:` are URI schemes from RFC 7064 / 7065 — they look
//! like `stun:host:port` (no `//`). `wss://` / `ws://` use standard URL form.
//! We only need host + port at this stage; full query-string params (transport
//! hints, etc.) land when the TURN checks need them.
//!
//! Each subcommand passes the schemes it accepts so we can refuse mismatches
//! at parse time. Otherwise users who paste e.g. a `stun:` URI into the `turn`
//! subcommand get a silently-degenerate run instead of a clear error.

use anyhow::{anyhow, Context, Result};

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Parse a `stun:` / `turn:` / `turns:` URI and validate the scheme is one
/// the caller accepts.
pub fn parse_stun_like(url: &str, allowed_schemes: &[&str], default_port: u16) -> Result<Target> {
    let (scheme, rest) = url
        .split_once(':')
        .ok_or_else(|| anyhow!("missing scheme in `{url}` (expected e.g. stun:host:port)"))?;

    let scheme_lc = scheme.to_ascii_lowercase();
    if !allowed_schemes.iter().any(|s| *s == scheme_lc) {
        let expected = match allowed_schemes {
            [one] => format!("a '{one}:' URI"),
            many => format!(
                "one of: {}",
                many.iter()
                    .map(|s| format!("'{s}:'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        return Err(anyhow!(
            "this subcommand expects {expected}, got '{scheme}:' (in `{url}`)"
        ));
    }

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
    // `scheme_lc` was consumed by the validation above; we don't store it on
    // Target because no downstream check has needed it yet. When TURNS gets
    // its own routing (5349 vs 443 paths), reintroduce it here.
    let _ = scheme_lc;
    Ok(Target { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_stun_uri() {
        let t = parse_stun_like("stun:stun.l.google.com:19302", &["stun"], 3478).unwrap();
        assert_eq!(t.host, "stun.l.google.com");
        assert_eq!(t.port, 19302);
    }

    #[test]
    fn rejects_wrong_scheme_for_subcommand() {
        // The exact case the user hit: stun: URI on the turn subcommand.
        let err = parse_stun_like("stun:host:3478", &["turn"], 3478).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("'turn:'"),
            "msg should name expected scheme: {msg}"
        );
        assert!(
            msg.contains("'stun:'"),
            "msg should name the wrong scheme: {msg}"
        );
    }

    #[test]
    fn lists_all_allowed_schemes_when_multiple() {
        let err = parse_stun_like("wss:host:443", &["turn", "turns"], 3478).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("'turn:'") && msg.contains("'turns:'"),
            "msg: {msg}"
        );
    }

    #[test]
    fn scheme_match_is_case_insensitive() {
        // Pasted from a config file with shouty casing — should still parse.
        let t = parse_stun_like("STUN:host:3478", &["stun"], 3478).unwrap();
        assert_eq!(t.host, "host");
    }

    #[test]
    fn defaults_the_port_when_omitted() {
        let t = parse_stun_like("turn:host", &["turn"], 3478).unwrap();
        assert_eq!(t.port, 3478);
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(parse_stun_like("just-a-host", &["stun"], 3478).is_err());
    }

    #[test]
    fn rejects_empty_host() {
        assert!(parse_stun_like("stun::3478", &["stun"], 3478).is_err());
    }
}
