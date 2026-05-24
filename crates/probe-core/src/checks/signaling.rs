//! Signaling endpoint probe (WebSocket connect).
//!
//! Opens a WebSocket connection to a `ws://` or `wss://` URL, optionally
//! attaching an `Authorization` header, and reports total handshake
//! latency. Then closes the connection cleanly.
//!
//! A successful Open → Close cycle is a strong signal the endpoint is
//! healthy at the WS layer: TCP connect, TLS handshake (if `wss`), HTTP
//! Upgrade, and the 101 Switching Protocols response all happened. We
//! don't try to round-trip any application-level message because every
//! signaling protocol has its own (JSON, protobuf, JSON-RPC, custom);
//! the WebSocket layer itself is what's general.
//!
//! Why we don't depend on the existing `DnsCheck` here: `connect_async`
//! does its own internal DNS resolution as part of opening the connection,
//! so the signaling check is measuring something subtly different (full
//! connect including DNS) than the DnsCheck row (DNS alone). Both rows
//! are useful when both are present, but neither requires the other.

use std::time::{Duration, Instant};

use serde_json::json;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue},
};

use crate::check::{Check, ProbeContext};
use crate::result::CheckResult;

const ID: &str = "signaling";
const NAME: &str = "Signaling endpoint";

/// Extract the host component of a `ws://` / `wss://` (or http(s)://) URL.
/// Lives here because the CLI layer wants to feed `ctx.host` for the DNS
/// check, and we'd rather not republish the transitive `http` crate as a
/// separate direct dep on the binary side.
pub fn host_from_url(url: &str) -> Option<String> {
    tokio_tungstenite::tungstenite::http::Uri::try_from(url)
        .ok()
        .and_then(|u| u.host().map(str::to_string))
}

pub struct SignalingCheck {
    url: String,
    auth_header: Option<String>,
}

impl SignalingCheck {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            auth_header: None,
        }
    }

    /// Attach an `Authorization` header to the WebSocket upgrade request.
    /// Most authenticated signaling endpoints gate on this.
    pub fn with_auth_header(mut self, header: impl Into<String>) -> Self {
        self.auth_header = Some(header.into());
        self
    }
}

#[async_trait::async_trait]
impl Check for SignalingCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn name(&self) -> &'static str {
        NAME
    }

    async fn run(&self, ctx: &mut ProbeContext) -> CheckResult {
        let started = Instant::now();

        let mut request = match self.url.as_str().into_client_request() {
            Ok(r) => r,
            Err(e) => {
                return CheckResult::fail(
                    ID,
                    NAME,
                    started.elapsed().as_millis() as u64,
                    format!("invalid signaling URL: {e}"),
                )
            }
        };

        if let Some(auth) = &self.auth_header {
            match HeaderValue::from_str(auth) {
                Ok(v) => {
                    request.headers_mut().insert("authorization", v);
                }
                Err(e) => {
                    return CheckResult::fail(
                        ID,
                        NAME,
                        started.elapsed().as_millis() as u64,
                        format!("invalid Authorization header value: {e}"),
                    );
                }
            }
        }

        let connect_timeout = if ctx.default_timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            // Signaling can legitimately involve a TLS handshake + HTTP
            // upgrade across continents; allow a bit more headroom than the
            // 5 s default we use for UDP-bounded checks.
            ctx.default_timeout.max(Duration::from_secs(10))
        };

        let scheme = if self.url.starts_with("wss") {
            "wss"
        } else {
            "ws"
        };

        let connect = timeout(connect_timeout, connect_async(request)).await;
        let latency_ms = started.elapsed().as_millis() as u64;

        match connect {
            Ok(Ok((mut ws, response))) => {
                let status = response.status();
                // Polite close — best-effort, ignore any error since the
                // pass/fail signal here is the open, not the close.
                let _ = ws.close(None).await;

                let auth_used = self.auth_header.is_some();
                CheckResult::pass(
                    ID,
                    NAME,
                    latency_ms,
                    format!(
                        "{scheme} connected, HTTP {} ({} ms{})",
                        status.as_u16(),
                        latency_ms,
                        if auth_used { ", auth OK" } else { "" },
                    ),
                )
                .with_detail(json!({
                    "scheme": scheme,
                    "http_status": status.as_u16(),
                    "auth_header": auth_used,
                    "url": self.url,
                }))
            }
            Ok(Err(e)) => {
                CheckResult::fail(ID, NAME, latency_ms, format!("WS handshake failed: {e}"))
            }
            Err(_) => CheckResult::fail(
                ID,
                NAME,
                latency_ms,
                format!("connect timeout after {connect_timeout:?}"),
            ),
        }
    }
}
