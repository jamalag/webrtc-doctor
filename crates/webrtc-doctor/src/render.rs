//! Output renderers for a finished [`Report`]. Pretty (colored, TTY) by
//! default; `--json` switches to the machine shape that the future SaaS
//! orchestrator will persist verbatim.

use colored::Colorize;
use probe_core::{CheckResult, CheckStatus, Report, Verdict};

pub fn pretty(report: &Report, header: &str) {
    println!("webrtc-doctor {} — {}", probe_core::version(), header);

    let max_id = report.results.iter().map(|r| r.id.len()).max().unwrap_or(0);

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
        // ice.gather carries the candidate list in detail — surface it as
        // indented sub-lines so the user doesn't have to switch to --json
        // to see what was gathered.
        if r.id == "ice.gather" {
            print_candidates(r, max_id);
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

/// Pretty-print the candidate list embedded in an `ice.gather` result.
/// Each candidate becomes one indented sub-line so a TTY reader can scan
/// host / srflx / relay at a glance. JSON consumers use the detail blob
/// directly and ignore this entirely.
fn print_candidates(r: &CheckResult, _max_id: usize) {
    let Some(detail) = r.detail.as_ref() else {
        return;
    };
    let Some(cands) = detail.get("candidates").and_then(|v| v.as_array()) else {
        return;
    };
    if cands.is_empty() {
        return;
    }
    // Two columns: address (with port) + provenance. Width the address
    // column to the widest entry so the suffix lines up.
    let rendered: Vec<(String, String, String)> = cands
        .iter()
        .filter_map(|c| {
            let kind = c.get("kind")?.as_str()?.to_string();
            let addr = c.get("address")?.as_str()?.to_string();
            let port = c.get("port")?.as_u64().unwrap_or(0);
            let endpoint = format_endpoint(&addr, port as u16);
            let suffix = if let Some(iface) = c.get("interface").and_then(|v| v.as_str()) {
                format!("({iface})")
            } else if let Some(via) = c.get("via").and_then(|v| v.as_str()) {
                format!("via {via}")
            } else {
                String::new()
            };
            Some((kind, endpoint, suffix))
        })
        .collect();
    let addr_w = rendered.iter().map(|(_, a, _)| a.len()).max().unwrap_or(0);
    for (kind, endpoint, suffix) in rendered {
        let kind_colored = match kind.as_str() {
            "host" => "host".cyan(),
            "srflx" => "srflx".magenta(),
            "relay" => "relay".blue(),
            _ => kind.normal(),
        };
        let kind_padded = format!("{:<5}", kind_colored);
        // 6 leading spaces aligns the candidate rows under the summary
        // glyph + id column for the typical max_id (~14 chars).
        println!(
            "      {kind_padded}  {endpoint:<addr_w$}  {}",
            suffix.dimmed(),
        );
    }
}

fn format_endpoint(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        // IPv6 — bracket it so the port doesn't read as another segment.
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    }
}

pub fn json(report: &Report) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(report)?;
    println!("{s}");
    Ok(())
}
