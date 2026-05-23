//! Output renderers for a finished [`Report`]. Pretty (colored, TTY) by
//! default; `--json` switches to the machine shape that the future SaaS
//! orchestrator will persist verbatim.

use colored::Colorize;
use probe_core::{CheckStatus, Report, Verdict};

pub fn pretty(report: &Report, header: &str) {
    println!("webrtc-doctor {} — {}", probe_core::version(), header);

    let max_id = report
        .results
        .iter()
        .map(|r| r.id.len())
        .max()
        .unwrap_or(0);

    for r in &report.results {
        let glyph = match r.status {
            CheckStatus::Pass => "✓".green(),
            CheckStatus::Warn => "⚠".yellow(),
            CheckStatus::Fail => "✗".red(),
            CheckStatus::Skip => "·".dimmed(),
        };
        let id = format!("{:<width$}", r.id, width = max_id);
        let line = format!("  {glyph} {id}  {}", r.summary);
        match r.status {
            CheckStatus::Skip => println!("{}", line.dimmed()),
            _ => println!("{line}"),
        }
    }

    let (p, w, f, s) = report.counts();
    let verdict = report.verdict();
    let verdict_str = match verdict {
        Verdict::Healthy => "HEALTHY".green().bold(),
        Verdict::Warnings => "WARNINGS".yellow().bold(),
        Verdict::Failed => "FAILED".red().bold(),
    };
    println!();
    println!(
        "{} pass · {} warn · {} fail · {} skip        verdict: {}",
        p, w, f, s, verdict_str,
    );
}

pub fn json(report: &Report) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(report)?;
    println!("{s}");
    Ok(())
}
