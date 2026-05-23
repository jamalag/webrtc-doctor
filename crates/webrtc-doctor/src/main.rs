//! webrtc-doctor — CLI entry point.
//!
//! Subcommand-per-target with a `full` mode that chains everything. See
//! `docs/PLAN.md` for the planned check pipeline and CLI shape.

use clap::{Parser, Subcommand};

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

    println!("webrtc-doctor {} — probe-core {}",
        env!("CARGO_PKG_VERSION"),
        probe_core::version());

    match cli.command {
        Command::Stun { url } => println!("TODO: stun probe → {url}"),
        Command::Turn { url, .. } => println!("TODO: turn probe → {url}"),
        Command::Turns { url, .. } => println!("TODO: turns probe → {url}"),
        Command::Signaling { url } => println!("TODO: signaling probe → {url}"),
        Command::Full { .. } => println!("TODO: full suite"),
    }
    if cli.json { /* TODO: JSON renderer */ }
    if cli.quiet { /* TODO: silence pretty output */ }
    Ok(())
}
