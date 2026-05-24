# webrtc-doctor

A single-binary WebRTC connectivity diagnostic. Point it at any STUN, TURN,
TURNS, or signaling endpoint and get a clear pass/fail report with timings
for every step — DNS, UDP reachability, STUN binding, TURN allocation, TURN
echo round-trip, DTLS handshake, ICE candidate gathering, signaling auth.

Like `mtr` or `dig`, but for WebRTC.

<table>
  <tr>
    <td align="center"><b>❌ Authentication broken</b></td>
    <td align="center"><b>✅ Authentication working</b></td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/turn_failed.png" alt="webrtc-doctor pinpointing a 401-after-auth on a real TURN server" /></td>
    <td><img src="docs/screenshots/turn_success.png" alt="webrtc-doctor showing a fully successful TURN allocation with per-step timings" /></td>
  </tr>
</table>

Same command, same target — different outcome. The failure isn't a
generic "ICE failed"; it's the exact protocol-level reason (`401 after
auth`) with the layer that broke clearly named. That's the whole pitch.

## Status

Pre-alpha. The current build implements DNS, STUN binding, and TURN
allocation over UDP (with long-term credential auth). TURNS, TURN echo,
DTLS loopback, ICE gathering, and signaling probes are planned for
v0.1.0 — see [`docs/PLAN.md`](docs/PLAN.md) for the design and roadmap.

## Why

When a WebRTC user says "it's broken," the only existing diagnostics are
`webrtc-internals` Chrome dumps or Wireshark traces. This tool gives ops and
developers a one-shot, copy-pasteable readout of exactly which layer is
failing and where.

## How this differs from browser-based testers

There are good in-browser STUN/TURN testers — [Trickle ICE], Twilio Network
Test, the various "is my TURN server up?" web pages. They run real WebRTC
inside the browser and tell you what the browser experienced. webrtc-doctor
is a different tool for different questions.

[Trickle ICE]: https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/

**Browser testers are good at:** measuring the user's actual experience
(because they use the same `RTCPeerConnection` code path), zero install,
catching browser-specific NAT quirks. **What they can't do:** see the
underlying STUN/TURN wire protocol, distinguish *why* a failure happened,
run on a server, run in CI, run unattended, run on a schedule.

**webrtc-doctor is good at:** protocol-level visibility (real STUN/TURN
error codes, not just "ICE failed"), per-step timings, scriptability,
exit codes, JSON output, running anywhere a binary runs.
**What it can't do:** measure what an actual end-user's browser sees, since
it doesn't run in a browser — it tells you whether the *server* is doing
the right thing, not whether a specific human can reach it.

Mnemonic: **browser testers answer "does it work for this human?"
webrtc-doctor answers "is the server doing the right thing?"**

| You want to know…                                          | Use                                |
|------------------------------------------------------------|------------------------------------|
| "Is my TURN server up right now?"                          | webrtc-doctor (run from cron)      |
| "Did my last COTURN config change break auth?"             | webrtc-doctor in CI                |
| "Why did this specific allocation fail?"                   | webrtc-doctor `--json`, read the error code |
| "What's the p50 / p95 TURN alloc latency from us-east?"    | webrtc-doctor on a VPS → TSDB      |
| "Does this user's Chrome generate srflx candidates?"       | Trickle ICE in their browser       |
| "Does my customer in Singapore actually reach my TURN?"    | Browser tester (or, eventually, an embedded probe in your app) |
| "Is my user behind a symmetric NAT that breaks P2P?"       | Browser tester                     |

If you debug WebRTC bug reports one at a time, the existing browser tools
are probably enough. The moment you want to **monitor** your infra,
**alert** when it breaks, **catch regressions in CI**, or see protocol-
level error codes instead of "ICE failed," there's no good existing tool
in that quadrant. That's the gap webrtc-doctor fills.

## Build

```sh
cargo build --release
./target/release/webrtc-doctor --help
```

## Usage

### Probe a public STUN server

The quickest sanity check — confirms DNS and outbound UDP work, and tells
you your public IP as the world sees it:

```sh
webrtc-doctor stun stun:stun.l.google.com:19302
```

Expected output:

```
webrtc-doctor 0.1.0 — probing stun.l.google.com (stun)
  ✓ dns           stun.l.google.com → 74.125.250.129 (15 ms)
  ✓ stun.binding  srflx 203.0.113.42:52114 (89 ms)

2 pass · 0 warn · 0 fail · 0 skip        verdict: HEALTHY
```

### Probe a TURN server with static credentials

If your TURN server uses fixed username/password (`lt-cred-mech` in COTURN,
or any classic long-term credential setup):

```sh
webrtc-doctor turn turn:turn.example.com:3478 --user alice --pass s3cret
```

Expected output on success:

```
webrtc-doctor 0.1.0 — probing turn.example.com (turn)
  ✓ dns             turn.example.com → 203.0.113.10 (12 ms)
  ✓ stun.binding    srflx 198.51.100.42:52114 (31 ms)
  ✓ turn.alloc.udp  relay 203.0.113.10:49152 (lifetime 600s, 74 ms)

3 pass · 0 warn · 0 fail · 0 skip        verdict: HEALTHY
```

Run with no `--user` / `--pass` and you'll still get a useful signal:
the server's `401 Unauthorized` is reported as a warning with the auth
realm surfaced — confirming the server is alive and telling you which
realm to authenticate against.

### Probe a TURN server with short-lived REST-style credentials

Most production WebRTC deployments don't hand out static passwords. Instead
they implement the TURN REST API convention (the `use-auth-secret` flow in
COTURN, also used by Twilio, Cloudflare, and most ICE-server-as-a-service
providers): your web app signs in to its own backend, which returns a
short-lived `{username, password, ttl}` triple usable for a few minutes.

webrtc-doctor doesn't speak your app's auth flow — that's deliberately
out of scope. (See the OSS/SaaS boundary case study in
[`docs/PLAN.md`](docs/PLAN.md) for the reasoning.) But because the wire
protocol is identical once you have the creds, the test is a two-step
recipe: fetch creds, then run the probe. Both steps need to happen inside
the credential TTL — typically a few minutes — so don't get interrupted.

**Step 1 — fetch fresh creds from your app's frontend:**

1. Open your WebRTC app's frontend in Chrome or Edge and sign in.
2. Open DevTools → Network tab. Filter by `Fetch/XHR` to cut noise.
3. Trigger whatever your app does to start a session — that's what
   provisions TURN credentials.
4. Find the response containing the TURN creds. Look for JSON like:
   ```json
   {
     "username": "1748121600:user-id-here",
     "password": "base64stuff=",
     "ttl": 3600,
     "uris": ["turn:turn.example.com:3478?transport=udp", "..."]
   }
   ```
   Variations: `credential` instead of `password`, `urls` instead of
   `uris`. The colon in the username is the unix expiry timestamp — that's
   the normal REST-API convention, not a typo.

5. Copy three things: the full `username`, the `password` / `credential`,
   and one `turn:host:port` URI (strip any `?transport=…` query string —
   the current build only supports UDP/3478).

**Step 2 — run webrtc-doctor immediately:**

```sh
webrtc-doctor turn "turn:turn.example.com:3478" \
  --user "1748121600:user-id-here" \
  --pass "base64stuff="
```

On Windows PowerShell, wrap each argument in double quotes — usernames
contain `:` and passwords are usually base64 with `+` / `=` / `/`, all
of which the shell would otherwise mangle.

If the cred TTL expires between step 1 and step 2, repeat step 1 and try
again; expect a `✗ server rejected long-term credentials (401 after auth)`
— that's exactly the left-hand screenshot at the top of this README, and
the same recipe with fresh creds is what produces the right-hand one.

#### Scripted version

Once you've done it manually, a tiny wrapper makes it repeatable. PowerShell:

```powershell
# Replace the URL and any auth headers with your app's actual flow.
$c = Invoke-RestMethod "https://yourapp.example.com/api/turn-creds" `
       -Headers @{ Authorization = "Bearer $env:APP_TOKEN" }
.\webrtc-doctor.exe turn "$($c.uris[0] -replace '\?.*','')" `
  --user $c.username --pass $c.password
```

bash + jq:

```sh
creds=$(curl -s -H "Authorization: Bearer $APP_TOKEN" \
          https://yourapp.example.com/api/turn-creds)
webrtc-doctor turn "$(jq -r '.uris[0]' <<<"$creds" | sed 's/?.*//')" \
  --user "$(jq -r .username <<<"$creds")" \
  --pass "$(jq -r .password <<<"$creds")"
```

### Machine-readable output

Add `--json` to any subcommand to get the structured report:

```sh
webrtc-doctor --json stun stun:stun.l.google.com:19302
```

The JSON shape is stable and intended for CI pipelines and dashboards.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All checks passed (verdict `HEALTHY`) |
| `1`  | One or more checks failed (verdict `FAILED`) |
| `2`  | Warnings only, no hard failures (verdict `WARNINGS`) |

CI scripts can therefore treat warnings as soft (`exit-code ≤ 2 → continue`)
or strict (`exit-code == 0 → continue`) depending on policy.

## Reading the output

Common results and what they mean:

| Output                                                       | Likely cause                                                      |
|--------------------------------------------------------------|-------------------------------------------------------------------|
| `✓ stun.binding  srflx <ip>:<port>`                          | Outbound UDP works; the printed address is your NAT-mapped IP    |
| `⚠ turn.alloc.udp  auth challenge from realm "X"`            | Server alive, no creds supplied — pass `--user`/`--pass`         |
| `✗ turn.alloc.udp  401 after auth`                           | Creds wrong or expired (refresh and retry within the TTL)        |
| `✗ turn.alloc.udp  no Allocate response from … in 5s`        | UDP/3478 isn't reachable from here, or server is TCP/TLS only    |
| `✗ turn.alloc.udp  allocate rejected: 403 Forbidden`         | Auth accepted but allocation denied (quota, IP restriction, etc.) |
| `✗ turn.alloc.udp  allocate rejected: 437 Allocation Mismatch` | Stale allocation from same 5-tuple — wait a minute and retry    |

## Project layout

```
crates/
├── probe-core/      # Library: check pipeline, results, JSON serialization.
└── webrtc-doctor/   # Binary: clap CLI over probe-core.
docs/
└── PLAN.md          # Design, MVP scope, roadmap, OSS/SaaS boundary notes.
```

## Contributing

This is pre-alpha and the check surface is changing weekly. If you have a
WebRTC connectivity bug you'd like the tool to diagnose, opening an issue
with the failure case is more valuable than a PR right now.

## License

Apache-2.0. See [`LICENSE-APACHE`](LICENSE-APACHE).
