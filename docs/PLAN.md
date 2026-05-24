# webrtc-doctor — Design and Roadmap

A single-binary WebRTC connectivity diagnostic. Diagnoses connectivity to any STUN, TURN, TURNS, or signaling target and prints a clear pass/fail report. Also serves as the **engine library** for a future probe-as-a-service product.

This document is the source of truth for what we're building, why, and how. It's written so a future session can pick this up cold without prior context.

---

## Context for a fresh session

**What this is.** An OSS, single-binary, Rust CLI that runs a pipeline of named checks (DNS → STUN → TURN allocation → TURN echo → DTLS → ICE gathering → signaling) against a target and reports pass/fail/warn with timings for each step. Output is pretty by default; `--json` produces a machine-readable report for automation and for a future hosted dashboard.

**Why this exists.** When a WebRTC user reports "it's broken," developers' only diagnostics today are `webrtc-internals` Chrome dumps or Wireshark traces. There's no `dig`/`mtr` equivalent. We're building that.

**Constraints.** `webrtc-doctor` is a fully standalone OSS repo with no path
dependencies on any private codebase. The WebRTC protocol implementations
are either hand-rolled here (STUN binding and the TURN message family —
the wire formats are small and stable) or pulled from the `webrtc-rs`
crates published on crates.io. The Apache-2.0 license applies cleanly to
everything in the tree; downstream consumers don't need to inherit any
other license obligation.

**Strategic role.** Two reasons to ship this first:
1. Public OSS artifact + credibility receipt before going commercial.
2. The `probe-core` library crate is the engine for a future probe-as-a-service SaaS — work compounds.

**License.** Apache-2.0. Patent grant matters because companies will run this on their infra.

**Repo layout decision (already made).** Cargo workspace with two crates:
- `crates/probe-core` — library: check trait, pipeline, results, JSON serialization. Reusable in the SaaS worker later.
- `crates/webrtc-doctor` — binary: clap CLI wrapping `probe-core`.

---

## MVP scope

**In scope**
- DNS resolution check
- UDP reachability + STUN binding (reflexive address discovery)
- TURN allocation over UDP / TCP / TLS-5349 / TLS-443
  - Credentials passed via `--user` / `--pass` only. Fetching short-lived
    creds from a REST endpoint is deliberately a SaaS feature — see
    "Case study: TURN credentials" below.
- TURN echo round-trip (`CreatePermission` → `Send` → `Data`)
- DTLS handshake against a self-loopback peer in the same process
- ICE candidate gathering (host, srflx, relay) with per-type counts and timings
- Signaling endpoint probe (WS connect + optional auth header)
- Path MTU probe
- Output modes: pretty (colored TTY default), `--json`, `--quiet`
- Per-check timeouts + global deadline flag

**Out of MVP (deliberate)**
- Browser-side measurement — that's the commercial SaaS
- Geo-distributed probing — fleet operation, also SaaS territory
- Historical storage / regression diffing
- HTTP daemon mode + `/metrics`

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ CLI / config layer (clap)                            │
│   crates/webrtc-doctor                               │
└────────────┬─────────────────────────────────────────┘
             │
┌────────────▼─────────────────────────────────────────┐
│ probe-core (library)                                 │
│  • Check trait { id, name, run(&ctx) -> Result }     │
│  • Pipeline runner with ordering + dependencies      │
│  • Report aggregator (pretty / JSON renderers)       │
│  • ProbeContext: target URLs, creds, timeouts        │
└────────────┬─────────────────────────────────────────┘
             │ depends on (from crates.io)
┌────────────▼─────────────────────────────────────────┐
│ webrtc-rs ecosystem                                  │
│  webrtc-ice · stun · turn · webrtc-dtls · sctp       │
└──────────────────────────────────────────────────────┘
```

The seam between `probe-core` and the CLI is the unit of reuse for the future SaaS: a server-side worker imports `probe-core`, exposes its own transport (HTTP or WS), persists results to a DB. The CLI never depends on storage or transport — `probe-core` only emits structured results.

## CLI shape

```
webrtc-doctor stun stun:stun.l.google.com:19302
webrtc-doctor turn turn:turn.example.com:3478 --user U --pass P
webrtc-doctor turns turns:turn.example.com:5349 --user U --pass P
webrtc-doctor turns turns:turn.example.com:443  --user U --pass P
webrtc-doctor signaling wss://signal.example.com/

# All-in-one against a single deployment
webrtc-doctor full --config doctor.toml
webrtc-doctor full --stun ... --turn ... --signaling ... --json
```

Pretty output sketch:

```
webrtc-doctor 0.1 — probing turn.example.com
  ✓ dns                 turn.example.com → 203.0.113.10 (12 ms)
  ✓ udp.reachability    UDP/3478 reachable (28 ms)
  ✓ stun.binding        srflx 198.51.100.42:52114 (31 ms)
  ✓ turn.alloc.udp      relay 203.0.113.10:49152 (74 ms)
  ✓ turn.echo.udp       16-byte round-trip 38 ms, 0/10 loss
  ✓ tls.5349            TLSv1.3, ECDHE-X25519, valid 47d
  ✓ turn.alloc.tls      relay via TURNS 5349 (109 ms)
  ⚠ tls.443             port not listening (skipped TURNS:443 checks)
  ✓ dtls.loopback       SRTP profile AES_CM_128_HMAC_SHA1_80 (88 ms)
  ✓ ice.gathering       host(2), srflx(1), relay(1) in 412 ms
  ✓ signaling           wss connected, auth OK (203 ms)

10 pass · 1 warn · 0 fail        verdict: HEALTHY (TURNS:443 disabled)
```

Exit codes: `0` all pass, `1` any fail, `2` warnings only (so CI can treat warnings as soft). Same data shape in `--json`.

## Effort estimate

| Milestone | Scope | Estimate |
|-----------|-------|----------|
| Weekend 1 | Scaffold (done) + DNS + STUN binding + TURN-UDP alloc + pretty renderer | ~2 days |
| Weekend 2 | TURNS (5349 + 443) + TURN echo + DTLS loopback | ~2 days |
| Week after | ICE gathering, signaling probe, JSON renderer, README polish, first `v0.1.0` tag | ~5 days |
| Polish | NAT edge cases, IPv6, packaging (cargo install + GH Releases) | open-ended |

## Open questions (still TBD)

- **Crate name on crates.io.** `webrtc-doctor` likely free. Reserve early once we're ready to publish.
- **GitHub org vs personal repo.** Personal account is fine for v0.1; can transfer later.
- **CI matrix.** GitHub Actions for `ubuntu-latest` + `macos-latest` + `windows-latest`, build + test + clippy + fmt on push.
- **Distribution.** `cargo install webrtc-doctor` from day one. Pre-built binaries via GitHub Releases when there's demand.
- **Self-loopback DTLS.** Need to decide whether to run two `webrtc-rs` peer agents in the same process, or a thin DTLS-only handshake against a small in-process server. The two-agent approach is more realistic, more code.

## Scaffold inventory (what's already in this repo)

- `Cargo.toml` — workspace root with shared deps in `[workspace.dependencies]`.
- `crates/probe-core/` — `lib.rs` with placeholder `CheckResult`, `CheckStatus`, `Check` trait, `ProbeContext`. Compiles but does nothing real yet.
- `crates/webrtc-doctor/` — `main.rs` with clap CLI surface defined (subcommands, `--json`, `--quiet`). Every subcommand currently prints `TODO: ...`.
- `LICENSE-APACHE` — full text, copyright 2026 Amir Eshaq.
- `.gitignore` — `/target`, `Cargo.lock` (we're a workspace of libs+bin; we keep Cargo.lock unignored if the bin becomes the primary product, see below).
- `README.md` — high-level overview pointing to this plan.

**Note on `Cargo.lock`:** currently in `.gitignore`. When `webrtc-doctor` is published as the primary product, we should *commit* `Cargo.lock` for reproducible CLI builds. Flip when ready for v0.1.

## First coding session — concrete next steps

1. `cd webrtc-doctor && cargo check` to confirm the scaffold compiles. Fix any version issues with workspace deps.
2. `git init && git add . && git commit -m "Initial scaffold"`.
3. Implement DNS check (`probe-core`):
   - Add `hickory-resolver = "0.24"` to `probe-core` deps.
   - New module `checks/dns.rs` implementing `Check` trait.
   - Return reflexive resolution time and resolved IPs in `detail`.
4. Implement STUN binding check:
   - Add `stun = "0.6"` to `probe-core` deps.
   - Module `checks/stun.rs`. Send binding request, parse `XOR-MAPPED-ADDRESS`.
5. Wire pretty renderer in the CLI: iterate results, color by status, format the table.
6. Run `webrtc-doctor stun stun:stun.l.google.com:19302` and confirm a real pass result.
7. Tag `v0.0.1` (scaffold + first working check). Push.

After that, follow the milestone table above.

## The SaaS that this OSS tool seeds

The CLI is **half** of the strategy. The other half is a hosted probe-as-a-service that uses the same `probe-core` engine — the OSS work compounds into the commercial work.

### The product

**Pitch.** Like fast.com but for WebRTC. An embeddable JS widget that measures, from a real end-user's browser, the path quality to **your** WebRTC infrastructure: P2P feasibility, ICE candidate success rate, packet loss / jitter to your TURN, browser→browser RTT against geo-distributed probes.

**Differentiator.** Every WebRTC product team has the same blind spot: when a user says "it's broken," they have no diagnostic. Existing options (Twilio Network Test, `webrtc-internals` dumps) are vendor-locked or developer-only — not embeddable in a customer-facing flow.

**Market.** Any company shipping video/voice/screen-share — telehealth, edtech, vertical SaaS, gaming, remote support, contact centers.

**Monetization.** Free embed with a "Powered by" link-back; paid for white-label, REST API, historical dashboards, alerting, multi-region probing, SLA reports.

### Architecture (extension of `probe-core`)

```
┌────────────────────────────────────────────────────────────────┐
│ Customer's site / app                                          │
│  <script src="https://probe.example.com/widget.js"></script>   │
│  Browser runs WebRTC against probe workers + customer's TURN.  │
└──────────────┬─────────────────────────────────────────────────┘
               │ WS (signaling + result reporting)
┌──────────────▼─────────────────────────────────────────────────┐
│ Probe orchestrator (Rust)                                      │
│  • Issues probe jobs to nearest worker                         │
│  • Collects browser-side measurements                          │
│  • Persists runs to DB                                         │
│  • Renders dashboards / serves the JS widget                   │
└──────────────┬─────────────────────────────────────────────────┘
               │ shared library
┌──────────────▼─────────────────────────────────────────────────┐
│ probe-core (THIS REPO)                                         │
│  Same Check trait + pipeline runner as the CLI.                │
└──────────────┬─────────────────────────────────────────────────┘
               │ executed on
┌──────────────▼─────────────────────────────────────────────────┐
│ Probe workers (geo-distributed)                                │
│  3–5 regions (US-East, US-West, EU, APAC, optionally LATAM).   │
│  Each worker is a tiny daemon wrapping probe-core.             │
└────────────────────────────────────────────────────────────────┘
```

The CLI emits the same `CheckResult` JSON shape that the orchestrator persists, so the OSS tool and SaaS produce comparable reports.

### Path from OSS to SaaS (the 4 steps)

1. **Wrap `probe-core` in a WS server.** Browser widget connects, server runs the probe against the **client's** path to your geo-distributed probes (not the other way around — that's the key insight; you can't run real client-side measurement from a server).
2. **Deploy probe workers in 3–5 regions.** Single-binary daemons, run on cheap VPSes. Each worker advertises its region.
3. **Persist results in a DB; render dashboards.** Time-series store (TimescaleDB or just Postgres + partitions for v1). Per-customer views of pass-rate, p50/p95 RTT, top failure modes.
4. **Free embedded widget (badge link) → paid tiers** for white-label, REST API, alerting, multi-region, historical retention.

### Why OSS-first is the right sequencing

- Ships a public artifact in 1–2 weeks vs. the SaaS taking months.
- Validates that the underlying diagnostic logic is correct before scaling it.
- Builds reputation in the WebRTC dev community — they are the same people who'd later buy the SaaS or recommend it to their team.
- The hardest engineering (the probe pipeline itself) is the same code path either way, so the OSS time is not wasted.
- A free OSS CLI also becomes a natural lead-gen funnel: README points at the hosted dashboard for users who want history/multi-region/team views.

### What deliberately does NOT belong in this OSS repo

To keep the OSS/SaaS boundary clean:

- **Authentication / tenancy / billing.** SaaS-only.
- **DB persistence layer.** SaaS-only — the OSS tool emits JSON; that's the contract.
- **Geo orchestration / fleet manager.** SaaS-only.
- **Customer-facing dashboards or widget JS.** SaaS-only.

`probe-core` exports a clean library API. The SaaS imports it without modification.

### Case study: TURN credentials (the boundary, applied)

A concrete decision that proves the boundary holds — recorded here so the next person doesn't relitigate it.

**The situation.** Most real WebRTC deployments don't hand out static TURN passwords. They use the TURN REST API convention (draft-uberti-behave-turn-rest, what COTURN's `use-auth-secret` mode implements): the client signs in, the server returns a `{username, password, ttl}` triple where the username encodes an expiry timestamp and the password is `base64(HMAC-SHA1(shared-secret, username))`. The wire protocol against TURN is unchanged — standard long-term credentials, MESSAGE-INTEGRITY computed against `MD5(username:realm:password)` — but obtaining the creds requires an authenticated HTTP request to the customer's own endpoint.

**The temptation.** Add `--turn-creds-from <URL>` to the OSS CLI. Looks like a small QoL feature.

**Why we do not, in OSS.** Three reasons compound:

1. **Dependency weight.** Pulls in `reqwest` plus a TLS stack (`rustls` or `native-tls`), `hyper`, `h2`, et al. — a real bump for a single-binary diagnostic whose runtime deps today are `tokio` + `serde` + small crypto primitives.
2. **No universal schema.** Twilio returns `{username, credential, urls[]}`. COTURN admins ship `{username, password, ttl}`. Cloudflare uses gRPC-ish wrapped shapes. Auth varies (bearer, cookie, basic, OAuth, mTLS, signed JWTs). Supporting "fetch creds from a URL" honestly means supporting *N* customer-specific flows — a per-customer adapter problem.
3. **Wrong audience for the OSS.** The OSS user is an operator with shell access who can `curl | jq | xargs webrtc-doctor`. The README documents that recipe. Unix composition is the OSS-friendly answer; we don't build what `curl` already does.

**Why it is first-class in the SaaS.** Same feature, completely different value proposition:

1. **Per-customer credential provider** is config in the orchestrator: URL template, vault-stored auth secret, expected JSON schema (or a small adapter per weird customer). Operationally normal for a SaaS, painful for a CLI.
2. **Refresh logic** — cache creds until TTL minus a safety margin, refetch transparently. Mandatory for a probe running every 60 seconds; nonsense for a one-shot CLI invocation.
3. **It is the moat.** Anyone can pipe `curl` into `webrtc-doctor`. Almost nobody wants to wire up authenticated, refreshing, multi-region probes against a TURN with REST-style creds. That work is exactly what customers will pay to outsource.

**The general principle this case illustrates.** The OSS/SaaS boundary lives at "the wire protocol vs. the operational concerns around running it." `probe-core` owns wire protocols. The SaaS owns auth flows, scheduling, persistence, fleet management, tenancy. Anytime a feature request looks like it sits on that fence, this case is the precedent: keep `probe-core` pure, push the operational layer up into the SaaS.

**Cheap things the OSS can still do** to make it ergonomic to pair with an external creds fetcher (no boundary violation):

- `--user-stdin` / `--pass-stdin` (read secrets from stdin instead of argv, so they don't show in `ps`). ~10 lines, no new deps.
- A README "Fetching short-lived creds" recipe with bash + PowerShell snippets using `curl` / `Invoke-RestMethod` + `jq`.

Both land whenever convenient — they document the boundary by example.

---

## Marketing the OSS release

When v0.1 ships:
- HN "Show HN" post with the example output above.
- Cross-post to r/rust, r/webrtc, r/selfhosted.
- Tweet at the webrtc-rs maintainers — credibility loop.
