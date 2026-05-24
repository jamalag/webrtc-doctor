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
        signaling::{host_from_url, SignalingCheck},
        stun::StunBindingCheck,
        turn_alloc::TurnAllocateCheck,
        turn_echo::TurnEchoCheck,
    },
    Pipeline, ProbeContext,
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
        /// Same security caveats as TURN creds — prefer the env-var or
        /// stdin-based variants once those land (tracked).
        #[arg(long)]
        auth_header: Option<String>,
    },
    /// Run the full suite against a deployment.
    Full {
        #[arg(long)]
        stun: Option<String>,
        #[arg(long)]
        turn: Option<String>,
        #[arg(long)]
        signaling: Option<String>,
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
        } => {
            let t = target::parse_stun_like(&url, &["turn"], 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            ctx.turn_user = resolve_secret(user, user_stdin, "TURN username")?;
            ctx.turn_pass = resolve_secret(pass, pass_stdin, "TURN password")?;
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
            // TLS isn't UDP — STUN binding doesn't belong here; checks land
            // alongside the TLS handshake step.
            (header, ctx, Pipeline::new().push(DnsCheck))
        }
        Command::Signaling { url, auth_header } => {
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

            let mut sig = SignalingCheck::new(&url);
            if let Some(h) = auth_header {
                sig = sig.with_auth_header(h);
            }
            (header, ctx, Pipeline::new().push(DnsCheck).push(sig))
        }
        Command::Full { stun, .. } => {
            // Full mode will fan out to multiple sub-pipelines once we have
            // them. For v0.0.1 it runs DNS against whichever target was given.
            let any = stun.ok_or_else(|| {
                anyhow::anyhow!("`full` currently requires --stun; more flags land next")
            })?;
            // `full` will route per-flag once we have more checks; for now
            // it accepts whichever scheme the user gave to --stun.
            let t = target::parse_stun_like(&any, &["stun", "turn", "turns"], 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            let header = format!("probing {} (full)", t.host);
            (header, ctx, Pipeline::new().push(DnsCheck))
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
