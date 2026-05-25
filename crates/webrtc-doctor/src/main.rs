//! webrtc-doctor — CLI entry point.
//!
//! Subcommand-per-target with a `full` mode that chains everything. See
//! `docs/PLAN.md` for the planned check pipeline and CLI shape.

mod render;
mod target;

use clap::{Parser, Subcommand};
use probe_core::{
    checks::{
        dns::DnsCheck,
        dtls::{serve_forever, DtlsLoopbackCheck, DtlsRemoteCheck},
        ice_gather::IceGatherCheck,
        signaling::{host_from_url, SignalingCheck},
        stun::StunBindingCheck,
        turn_alloc::TurnAllocateCheck,
        turn_echo::TurnEchoCheck,
        turns_alloc::TurnsAllocateCheck,
    },
    Pipeline, ProbeContext, Report,
};

#[derive(Parser)]
#[command(
    name = "webrtc-doctor",
    version,
    about = "WebRTC connectivity diagnostic"
)]
struct Cli {
    /// Emit machine-readable JSON instead of the pretty report.
    #[arg(long, global = true)]
    json: bool,

    /// Suppress per-check output; exit code communicates the verdict.
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Probe a STUN server (binding request → reflexive address).
    Stun {
        /// e.g. stun:stun.l.google.com:19302
        url: String,
    },
    /// Probe a TURN server (allocation + echo round-trip).
    Turn {
        /// e.g. turn:turn.example.com:3478
        url: String,
        /// TURN username. Avoid for sensitive creds (visible in process
        /// listings + shell history) — use `--user-stdin` instead.
        #[arg(long, conflicts_with = "user_stdin")]
        user: Option<String>,
        /// TURN password. Same caveat as --user; prefer `--pass-stdin`.
        #[arg(long, conflicts_with = "pass_stdin")]
        pass: Option<String>,
        /// Read TURN username from stdin (one line). When piping both,
        /// stdin order is username first, then password.
        #[arg(long)]
        user_stdin: bool,
        /// Read TURN password from stdin (one line).
        #[arg(long)]
        pass_stdin: bool,
        /// Number of echo packets to send through the relay. Default 10 so
        /// the report carries a loss% figure on a single run; use 1 for a
        /// fast binary pass/fail.
        #[arg(long, default_value_t = 10)]
        echo_count: u32,
    },
    /// Probe a TURN-over-TLS server (TURNS).
    Turns {
        /// e.g. turns:turn.example.com:5349 or :443
        url: String,
        #[arg(long, conflicts_with = "user_stdin")]
        user: Option<String>,
        #[arg(long, conflicts_with = "pass_stdin")]
        pass: Option<String>,
        /// Read TURN username from stdin (one line).
        #[arg(long)]
        user_stdin: bool,
        /// Read TURN password from stdin (one line). When both
        /// `--user-stdin` and `--pass-stdin` are set, stdin order is
        /// username first, then password.
        #[arg(long)]
        pass_stdin: bool,
    },
    /// Probe a signaling endpoint (WS/WSS connect + optional auth).
    Signaling {
        /// e.g. wss://signal.example.com/
        url: String,
        /// Full Authorization header value (e.g. "Bearer eyJ...").
        /// Visible in argv + shell history — prefer `--auth-header-stdin`
        /// for any real token.
        #[arg(long, conflicts_with = "auth_header_stdin")]
        auth_header: Option<String>,
        /// Read the full Authorization header value from stdin (one line).
        #[arg(long)]
        auth_header_stdin: bool,
    },
    /// DTLS handshake: in-process loopback, against a remote peer, or
    /// listen-mode for being someone else's remote.
    ///
    /// With no arguments, runs an in-process loopback handshake — a
    /// build-and-link smoke test that proves the DTLS layer is wired
    /// in.
    ///
    /// With `<target>` (e.g. `dtls.example.com:5684`), dials the
    /// remote DTLS endpoint and reports the handshake outcome plus the
    /// peer-certificate SHA-256 fingerprint in SDP format. Pair with
    /// another instance of webrtc-doctor running in `--serve` mode on
    /// the remote side for a no-third-party round-trip test.
    ///
    /// With `--serve`, becomes a DTLS test peer: listens on `--bind`,
    /// accepts handshakes from any client, logs each, and keeps
    /// running until killed.
    Dtls {
        /// Remote DTLS endpoint to dial, e.g. `host.example.com:5684`.
        /// Omit for loopback mode. Ignored when `--serve` is set.
        target: Option<String>,
        /// Run as a DTLS test peer instead of dialing. Accepts handshakes
        /// from any client until the process is killed.
        #[arg(long, conflicts_with = "target")]
        serve: bool,
        /// Address to listen on in serve mode. Defaults to `0.0.0.0:5684`
        /// (the IANA-assigned port for CoAP-over-DTLS — a convenient
        /// default that doesn't clash with the common 4444 / 5349 / 3478
        /// ports the other subcommands use).
        #[arg(long, default_value = "0.0.0.0:5684", requires = "serve")]
        bind: String,
    },
    /// Gather ICE candidates against a STUN or TURN server.
    ///
    /// Enumerates local interface addresses (host candidates), uses STUN
    /// to discover the server-reflexive address (srflx), and — when the
    /// URL uses the `turn:` scheme and credentials are supplied —
    /// allocates a TURN relay candidate. Same three candidate types a
    /// real `RTCPeerConnection` collects during gathering.
    ///
    /// One URL is enough because production TURN servers almost always
    /// serve STUN Binding on the same port (it's a subset of the TURN
    /// protocol). If your TURN doesn't, use the `stun` subcommand to
    /// confirm STUN works, and the `turn` subcommand to confirm TURN
    /// works.
    Ice {
        /// stun:... for host+srflx, or turn:... for host+srflx+relay
        url: String,
        #[arg(long, conflicts_with = "user_stdin")]
        user: Option<String>,
        #[arg(long, conflicts_with = "pass_stdin")]
        pass: Option<String>,
        #[arg(long)]
        user_stdin: bool,
        #[arg(long)]
        pass_stdin: bool,
    },
    /// Run the full suite against a deployment.
    ///
    /// One subcommand to test every layer of a real WebRTC stack you
    /// operate: STUN reachability, TURN allocation + relay echo, TURNS
    /// for firewall traversal, and the signaling endpoint. At least one
    /// of `--stun` / `--turn` / `--turns` / `--signaling` must be given;
    /// each provided URL runs its own sub-pipeline (DNS + the protocol
    /// check) and the results concatenate into a single report.
    ///
    /// Credentials (`--user` / `--pass` and their stdin variants) are
    /// shared between `--turn` and `--turns`, which is the common case
    /// for a single deployment. Run the per-protocol subcommands
    /// directly if you need distinct credentials per URL.
    Full {
        /// STUN URL, e.g. stun:stun.l.google.com:19302
        #[arg(long)]
        stun: Option<String>,
        /// TURN URL, e.g. turn:turn.example.com:3478
        #[arg(long)]
        turn: Option<String>,
        /// TURNS URL, e.g. turns:turn.example.com:5349
        #[arg(long)]
        turns: Option<String>,
        /// Signaling URL, e.g. wss://signal.example.com/
        #[arg(long)]
        signaling: Option<String>,
        /// TURN/TURNS username (shared between --turn and --turns).
        #[arg(long, conflicts_with = "user_stdin")]
        user: Option<String>,
        /// TURN/TURNS password.
        #[arg(long, conflicts_with = "pass_stdin")]
        pass: Option<String>,
        /// Read TURN username from stdin (one line).
        #[arg(long)]
        user_stdin: bool,
        /// Read TURN password from stdin (one line). When both
        /// `--user-stdin` and `--pass-stdin` are set, stdin order is
        /// username first, then password.
        #[arg(long)]
        pass_stdin: bool,
        /// Authorization header for the signaling endpoint, if any.
        #[arg(long, conflicts_with = "auth_header_stdin")]
        auth_header: Option<String>,
        /// Read the Authorization header from stdin (one line).
        /// Read after TURN credentials (if those are also from stdin):
        /// username → password → auth header.
        #[arg(long)]
        auth_header_stdin: bool,
        /// Number of TURN echo packets to send through the relay.
        #[arg(long, default_value_t = 10)]
        echo_count: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // rustls 0.23+ requires the process to choose a CryptoProvider exactly
    // once. Doing it here means the signaling (and future TURNS) checks can
    // open TLS connections without panicking on first use.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (header, mut ctx, pipeline) = match cli.command {
        Command::Stun { url } => {
            let t = target::parse_stun_like(&url, &["stun"], 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            let header = format!("probing {} (stun)", t.host);
            (
                header,
                ctx,
                Pipeline::new().push(DnsCheck).push(StunBindingCheck),
            )
        }
        Command::Turn {
            url,
            user,
            pass,
            user_stdin,
            pass_stdin,
            echo_count,
        } => {
            let t = target::parse_stun_like(&url, &["turn"], 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            ctx.turn_user = resolve_secret(user, user_stdin, "TURN username")?;
            ctx.turn_pass = resolve_secret(pass, pass_stdin, "TURN password")?;
            ctx.echo_count = echo_count;
            let header = format!("probing {} (turn)", t.host);
            (
                header,
                ctx,
                Pipeline::new()
                    .push(DnsCheck)
                    .push(StunBindingCheck)
                    .push(TurnAllocateCheck)
                    .push(TurnEchoCheck),
            )
        }
        Command::Turns {
            url,
            user,
            pass,
            user_stdin,
            pass_stdin,
        } => {
            let t = target::parse_stun_like(&url, &["turns"], 5349)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            ctx.turn_user = resolve_secret(user, user_stdin, "TURN username")?;
            ctx.turn_pass = resolve_secret(pass, pass_stdin, "TURN password")?;
            let header = format!("probing {} (turns)", t.host);
            (
                header,
                ctx,
                Pipeline::new().push(DnsCheck).push(TurnsAllocateCheck),
            )
        }
        Command::Signaling {
            url,
            auth_header,
            auth_header_stdin,
        } => {
            // Validate scheme up front so the user gets a clear error
            // instead of tungstenite's generic "URL scheme not supported"
            // surfacing two checks deep into the pipeline.
            let scheme_ok = url.starts_with("ws://") || url.starts_with("wss://");
            if !scheme_ok {
                anyhow::bail!(
                    "signaling expects a ws:// or wss:// URL, got `{url}` \
                     (example: `wss://signal.example.com/`)"
                );
            }
            // Extract host so DnsCheck has something concrete to resolve.
            let host = host_from_url(&url)
                .ok_or_else(|| anyhow::anyhow!("could not parse host from `{url}`"))?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(host.clone());
            let header = format!("probing {host} (signaling)");

            let auth = resolve_secret(auth_header, auth_header_stdin, "Authorization header")?;
            let mut sig = SignalingCheck::new(&url);
            if let Some(h) = auth {
                sig = sig.with_auth_header(h);
            }
            (header, ctx, Pipeline::new().push(DnsCheck).push(sig))
        }
        Command::Dtls {
            target,
            serve,
            bind,
        } => {
            if serve {
                // Server mode bypasses the pipeline/report machinery
                // entirely — it runs until killed and has no verdict to
                // emit. Initialise tracing first so the listener's
                // `tracing::info!` lines reach the terminal.
                let bind_addr: std::net::SocketAddr = bind.parse().map_err(|e| {
                    anyhow::anyhow!("--bind expects an addr:port, got `{bind}` ({e})")
                })?;
                eprintln!(
                    "webrtc-doctor {} — dtls serve listening on {bind_addr}",
                    probe_core::version()
                );
                eprintln!("(press Ctrl+C to stop)");
                serve_forever(bind_addr, |peer| {
                    eprintln!("  accepted handshake from {peer}");
                })
                .await
                .map_err(|e| anyhow::anyhow!("serve failed: {e}"))?;
                // serve_forever never returns; this is just to satisfy
                // the type system.
                return Ok(());
            }
            if let Some(t) = target {
                // Remote target. Parse host:port, run dns -> dtls.remote.
                let (host, port) = parse_host_port(&t).map_err(|e| {
                    anyhow::anyhow!("dtls target must be `host:port`, got `{t}` ({e})")
                })?;
                let mut ctx = ProbeContext::new();
                ctx.host = Some(host.clone());
                ctx.port = Some(port);
                let header = format!("probing {host}:{port} (dtls)");
                (
                    header,
                    ctx,
                    Pipeline::new().push(DnsCheck).push(DtlsRemoteCheck),
                )
            } else {
                let ctx = ProbeContext::new();
                let header = "dtls loopback (in-process)".to_string();
                (header, ctx, Pipeline::new().push(DtlsLoopbackCheck))
            }
        }
        Command::Ice {
            url,
            user,
            pass,
            user_stdin,
            pass_stdin,
        } => {
            let t = target::parse_stun_like(&url, &["stun", "turn"], 3478)?;
            let is_turn = url.starts_with("turn:");
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            let header = format!("probing {} (ice)", t.host);
            let mut pipeline = Pipeline::new().push(DnsCheck).push(StunBindingCheck);
            if is_turn {
                ctx.turn_user = resolve_secret(user, user_stdin, "TURN username")?;
                ctx.turn_pass = resolve_secret(pass, pass_stdin, "TURN password")?;
                pipeline = pipeline.push(TurnAllocateCheck);
            } else if user.is_some() || pass.is_some() || user_stdin || pass_stdin {
                // Friendly nudge: credentials with a stun: URL get ignored
                // silently otherwise.
                anyhow::bail!(
                    "credentials supplied but URL scheme is `stun:`; use a `turn:` URL \
                     to collect a relay candidate"
                );
            }
            pipeline = pipeline.push(IceGatherCheck);
            (header, ctx, pipeline)
        }
        Command::Full {
            stun,
            turn,
            turns,
            signaling,
            user,
            pass,
            user_stdin,
            pass_stdin,
            auth_header,
            auth_header_stdin,
            echo_count,
        } => {
            // `full` runs multiple sub-pipelines and concatenates their
            // results into one report; it doesn't fit the
            // (ctx, pipeline) -> Report shape the single-target
            // subcommands use. Handle the whole thing here and exit.
            let (header, report) = run_full(
                stun,
                turn,
                turns,
                signaling,
                user,
                pass,
                user_stdin,
                pass_stdin,
                auth_header,
                auth_header_stdin,
                echo_count,
            )
            .await?;
            if cli.json {
                render::json(&report)?;
            } else if !cli.quiet {
                render::pretty(&report, &header);
            }
            std::process::exit(report.verdict().exit_code());
        }
    };

    let report = pipeline.run(&mut ctx).await;

    if cli.json {
        render::json(&report)?;
    } else if !cli.quiet {
        render::pretty(&report, &header);
    }

    std::process::exit(report.verdict().exit_code());
}

/// Run the `full` subcommand: build a sub-pipeline per provided URL,
/// run each in its own `ProbeContext`, and concatenate their results
/// into one report. The single shared verdict reflects the worst
/// outcome across all sub-pipelines (Fail > Warn > Pass).
///
/// Each sub-pipeline does its own DNS step. That's mild duplication
/// when targets share a host, but the alternative — threading a
/// per-target DNS cache through ctx — is far more code for an MVP
/// gain. Live runs against a single deployment usually finish well
/// under a second total.
#[allow(clippy::too_many_arguments)]
async fn run_full(
    stun: Option<String>,
    turn: Option<String>,
    turns: Option<String>,
    signaling: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    user_stdin: bool,
    pass_stdin: bool,
    auth_header: Option<String>,
    auth_header_stdin: bool,
    echo_count: u32,
) -> anyhow::Result<(String, Report)> {
    if stun.is_none() && turn.is_none() && turns.is_none() && signaling.is_none() {
        anyhow::bail!("`full` needs at least one of --stun / --turn / --turns / --signaling");
    }

    // Resolve all secrets up front so we read stdin exactly once, in a
    // documented order (username → password → auth header). Letting each
    // sub-pipeline read stdin on demand would deadlock the second
    // consumer.
    let turn_user = resolve_secret(user, user_stdin, "TURN username")?;
    let turn_pass = resolve_secret(pass, pass_stdin, "TURN password")?;
    let auth = resolve_secret(auth_header, auth_header_stdin, "Authorization header")?;

    let started = std::time::Instant::now();
    let mut all_results = Vec::new();
    let mut header_parts: Vec<String> = Vec::new();

    // Order: signaling first (cheapest, independent), then stun, then
    // turn (which subsumes stun internally via its dns→stun.binding→
    // turn.alloc chain), then turns. Each block is gated on its URL.

    if let Some(url) = signaling.as_deref() {
        if !(url.starts_with("ws://") || url.starts_with("wss://")) {
            anyhow::bail!("--signaling expects a ws:// or wss:// URL, got `{url}`");
        }
        let host = host_from_url(url)
            .ok_or_else(|| anyhow::anyhow!("could not parse host from --signaling `{url}`"))?;
        header_parts.push(format!("signaling {host}"));
        let mut ctx = ProbeContext::new();
        ctx.host = Some(host);
        let mut sig = SignalingCheck::new(url);
        if let Some(h) = auth.clone() {
            sig = sig.with_auth_header(h);
        }
        let pipeline = Pipeline::new().push(DnsCheck).push(sig);
        let report = pipeline.run(&mut ctx).await;
        all_results.extend(report.results);
    }

    if let Some(url) = stun.as_deref() {
        let t = target::parse_stun_like(url, &["stun"], 3478)?;
        header_parts.push(format!("stun {}", t.host));
        let mut ctx = ProbeContext::new();
        ctx.host = Some(t.host.clone());
        ctx.port = Some(t.port);
        let pipeline = Pipeline::new().push(DnsCheck).push(StunBindingCheck);
        let report = pipeline.run(&mut ctx).await;
        all_results.extend(report.results);
    }

    if let Some(url) = turn.as_deref() {
        let t = target::parse_stun_like(url, &["turn"], 3478)?;
        header_parts.push(format!("turn {}", t.host));
        let mut ctx = ProbeContext::new();
        ctx.host = Some(t.host.clone());
        ctx.port = Some(t.port);
        ctx.turn_user = turn_user.clone();
        ctx.turn_pass = turn_pass.clone();
        ctx.echo_count = echo_count;
        let pipeline = Pipeline::new()
            .push(DnsCheck)
            .push(StunBindingCheck)
            .push(TurnAllocateCheck)
            .push(TurnEchoCheck);
        let report = pipeline.run(&mut ctx).await;
        all_results.extend(report.results);
    }

    if let Some(url) = turns.as_deref() {
        let t = target::parse_stun_like(url, &["turns"], 5349)?;
        header_parts.push(format!("turns {}", t.host));
        let mut ctx = ProbeContext::new();
        ctx.host = Some(t.host.clone());
        ctx.port = Some(t.port);
        ctx.turn_user = turn_user.clone();
        ctx.turn_pass = turn_pass.clone();
        let pipeline = Pipeline::new().push(DnsCheck).push(TurnsAllocateCheck);
        let report = pipeline.run(&mut ctx).await;
        all_results.extend(report.results);
    }

    let report = Report {
        results: all_results,
        total_ms: started.elapsed().as_millis() as u64,
    };
    let header = format!("probing {} (full)", header_parts.join(" + "));
    Ok((header, report))
}

/// Resolve a secret either from its CLI flag value or, when the `*-stdin`
/// switch is set, by reading one line from stdin. The CLI layer guarantees
/// (via clap `conflicts_with`) that at most one source is set per secret.
///
/// On a TTY we print a short prompt to stderr so an interactive user knows
/// the binary is waiting on them; on a pipe we stay silent so we don't
/// pollute scripted environments.
fn resolve_secret(
    flag_value: Option<String>,
    from_stdin: bool,
    label: &str,
) -> anyhow::Result<Option<String>> {
    if !from_stdin {
        return Ok(flag_value);
    }
    Ok(Some(read_line_from_stdin(label)?))
}

/// Split a `host:port` string. Accepts bracketed IPv6 literals
/// (`[::1]:5684`) as well as bare hostnames and IPv4. We don't validate
/// the host beyond non-empty; if DNS can't resolve it, the dns check
/// will surface that with a clear error of its own.
fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let close = rest
            .find(']')
            .ok_or("missing closing `]` for IPv6 literal")?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or("expected `:port` after `]`")?;
        (host, port)
    } else {
        // host:port — split on the LAST colon so IPv6 without brackets
        // gets a clear error rather than silent misparse (we still err
        // on the safe side and require brackets for v6 literals).
        let idx = s.rfind(':').ok_or("expected `host:port`")?;
        if s[..idx].contains(':') {
            return Err("IPv6 literal must be bracketed, e.g. `[::1]:5684`".into());
        }
        (&s[..idx], &s[idx + 1..])
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    let port: u16 = port.parse().map_err(|e| format!("bad port: {e}"))?;
    Ok((host.to_string(), port))
}

fn read_line_from_stdin(label: &str) -> anyhow::Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    if std::io::stdin().is_terminal() {
        eprint!("{label}: ");
        std::io::stderr().flush().ok();
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    // Strip the trailing newline (LF on Unix, CRLF on Windows).
    while matches!(line.chars().next_back(), Some('\n' | '\r')) {
        line.pop();
    }
    if line.is_empty() {
        anyhow::bail!("got empty input for {label} on stdin");
    }
    Ok(line)
}
