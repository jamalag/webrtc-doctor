//! webrtc-doctor — CLI entry point.
//!
//! Subcommand-per-target with a `full` mode that chains everything. See
//! `docs/PLAN.md` for the planned check pipeline and CLI shape.

mod render;
mod target;

use clap::{Parser, Subcommand};
use probe_core::{
    checks::{dns::DnsCheck, stun::StunBindingCheck, turn_alloc::TurnAllocateCheck},
    Pipeline, ProbeContext,
};

#[derive(Parser)]
#[command(name = "webrtc-doctor", version, about = "WebRTC connectivity diagnostic")]
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
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
    },
    /// Probe a TURN-over-TLS server (TURNS).
    Turns {
        /// e.g. turns:turn.example.com:5349 or :443
        url: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
    },
    /// Probe a signaling endpoint (WS/WSS connect + optional auth).
    Signaling {
        /// e.g. wss://signal.example.com/
        url: String,
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

    let (header, mut ctx, pipeline) = match cli.command {
        Command::Stun { url } => {
            let t = target::parse_stun_like(&url, 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            let header = format!("probing {} (stun)", t.host);
            (
                header,
                ctx,
                Pipeline::new().add(DnsCheck).add(StunBindingCheck),
            )
        }
        Command::Turn { url, user, pass } => {
            let t = target::parse_stun_like(&url, 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            ctx.turn_user = user;
            ctx.turn_pass = pass;
            let header = format!("probing {} (turn)", t.host);
            (
                header,
                ctx,
                Pipeline::new()
                    .add(DnsCheck)
                    .add(StunBindingCheck)
                    .add(TurnAllocateCheck),
            )
        }
        Command::Turns { url, user, pass } => {
            let t = target::parse_stun_like(&url, 5349)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            ctx.turn_user = user;
            ctx.turn_pass = pass;
            let header = format!("probing {} (turns)", t.host);
            // TLS isn't UDP — STUN binding doesn't belong here; checks land
            // alongside the TLS handshake step.
            (header, ctx, Pipeline::new().add(DnsCheck))
        }
        Command::Signaling { url } => {
            // Signaling URLs are real URLs; reuse the URL parser later. For
            // now just extract the host via `url::Url` would be ideal, but to
            // avoid pulling in `url` for a placeholder, hand-strip the scheme.
            let host = url
                .trim_start_matches("wss://")
                .trim_start_matches("ws://")
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string();
            let mut ctx = ProbeContext::new();
            ctx.host = Some(host.clone());
            let header = format!("probing {host} (signaling)");
            (header, ctx, Pipeline::new().add(DnsCheck))
        }
        Command::Full { stun, .. } => {
            // Full mode will fan out to multiple sub-pipelines once we have
            // them. For v0.0.1 it runs DNS against whichever target was given.
            let any = stun.ok_or_else(|| {
                anyhow::anyhow!("`full` currently requires --stun; more flags land next")
            })?;
            let t = target::parse_stun_like(&any, 3478)?;
            let mut ctx = ProbeContext::new();
            ctx.host = Some(t.host.clone());
            ctx.port = Some(t.port);
            let header = format!("probing {} (full)", t.host);
            (header, ctx, Pipeline::new().add(DnsCheck))
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
