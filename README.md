# webrtc-doctor

[![CI](https://github.com/jamalag/webrtc-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/jamalag/webrtc-doctor/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)

A single-binary WebRTC connectivity diagnostic. Point it at any STUN, TURN,
TURNS, or signaling endpoint and get a clear pass/fail report with timings
for every step — DNS, UDP reachability, STUN binding, TURN allocation, TURN
echo round-trip, DTLS handshake, ICE candidate gathering, signaling auth.

Like `mtr` or `dig`, but for WebRTC.

**❌ Authentication broken** (expired or wrong credentials):

```text
webrtc-doctor 0.1.0 — probing turn.example.com (turn)
  ✓ dns             turn.example.com → 203.0.113.10 (7 ms)
  ✓ stun.binding    srflx 198.51.100.42:64070 (181 ms)
  ✗ turn.alloc.udp  server rejected long-term credentials (401 after auth)

2 pass · 0 warn · 1 fail · 0 skip        verdict: FAILED
```

**✅ Authentication working** (fresh credentials, full data-plane round-trip):

```text
webrtc-doctor 0.1.0 — probing turn.example.com (turn)
  ✓ dns             turn.example.com → 203.0.113.10 (7 ms)
  ✓ stun.binding    srflx 198.51.100.42:53440 (171 ms)
  ✓ turn.alloc.udp  relay 203.0.113.10:49171 (lifetime 600s, 349 ms)
  ✓ turn.echo.udp   10/10 echoes, loss 0%, rtt min/avg/max = 162/169/178 ms via 203.0.113.10:49171

4 pass · 0 warn · 0 fail · 0 skip        verdict: HEALTHY
```

Same command, same target — different outcome. The failure isn't a
generic "ICE failed"; it's the exact protocol-level reason
(`401 after auth`) with the layer that broke clearly named. That's
the whole pitch. (Addresses above use [RFC 5737] documentation
prefixes — real runs print real ones, in ANSI color on a TTY.)

[RFC 5737]: https://datatracker.ietf.org/doc/html/rfc5737

## Status

Latest release is v0.4.0; `main` is moving toward v0.5.0. Working
checks today: DNS, STUN binding, TURN allocation over UDP (long-term
credentials), multi-packet TURN echo (data-plane loss/jitter stats),
TURN allocation over TLS (TURNS), signaling WS/WSS connect, ICE
candidate gathering (host + srflx + relay), and DTLS handshake
loopback (in-process smoke test). The MVP roadmap from
[`docs/PLAN.md`](docs/PLAN.md) is essentially complete.

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

For anything that isn't a throwaway local test, prefer piping the
credentials so they don't end up in shell history or process listings
(see [Avoid putting secrets in argv](#avoid-putting-secrets-in-argv)
below):

```sh
printf '%s\n%s\n' "$USER" "$PASS" \
  | webrtc-doctor turn turn:turn.example.com:3478 --user-stdin --pass-stdin
```

Expected output on success:

```
webrtc-doctor 0.1.0 — probing turn.example.com (turn)
  ✓ dns             turn.example.com → 203.0.113.10 (12 ms)
  ✓ stun.binding    srflx 198.51.100.42:52114 (31 ms)
  ✓ turn.alloc.udp  relay 203.0.113.10:49152 (lifetime 600s, 74 ms)
  ✓ turn.echo.udp   10/10 echoes, loss 0%, rtt min/avg/max = 162/169/178 ms via 203.0.113.10:49152

4 pass · 0 warn · 0 fail · 0 skip        verdict: HEALTHY
```

The `turn.echo.udp` step actually moves bytes through the relay
(CreatePermission → datagrams → Data Indications round-trip), so a green
row here proves the data plane works — not just that allocation
succeeded. By default it sends 10 packets so a single run carries a
loss% figure; pass `--echo-count 1` for a fast pass/fail signal, or
`--echo-count 50` (etc.) to characterize a flaky relay. Any non-zero
loss downgrades the row to a yellow warning so partial-loss conditions
don't masquerade as healthy.

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
— that's exactly the **Authentication broken** block at the top of this
README, and the same recipe with fresh creds is what produces the
**Authentication working** one.

#### Avoid putting secrets in argv

Anything you pass via `--user` / `--pass` is visible to:

- Other users on the host via `ps` / `Get-Process`.
- Your shell history (`~/.bash_history`, PowerShell's `ConsoleHost_history.txt`).
- Most log aggregators that record process invocations.

For anything beyond a quick local test, use `--user-stdin` and
`--pass-stdin` instead. The flags read one line each from stdin, in
that order:

```sh
# Both credentials on stdin (username first, then password):
printf '%s\n%s\n' "$USER" "$PASS" | webrtc-doctor turn turn:turn.example.com:3478 \
  --user-stdin --pass-stdin

# Or pipe just the password, keep username on the command line:
printf '%s\n' "$PASS" | webrtc-doctor turn turn:turn.example.com:3478 \
  --user alice --pass-stdin
```

`--user` and `--user-stdin` are mutually exclusive (clap rejects the
combination at parse time); same for `--pass` / `--pass-stdin`.

#### Scripted version

Once you've done it manually, a tiny wrapper makes it repeatable, with
secrets piped rather than baked into argv. PowerShell:

```powershell
# Replace the URL and any auth headers with your app's actual flow.
$c = Invoke-RestMethod "https://yourapp.example.com/api/turn-creds" `
       -Headers @{ Authorization = "Bearer $env:APP_TOKEN" }
"$($c.username)`n$($c.password)" | `
  .\webrtc-doctor.exe turn "$($c.uris[0] -replace '\?.*','')" `
    --user-stdin --pass-stdin
```

bash + jq:

```sh
creds=$(curl -s -H "Authorization: Bearer $APP_TOKEN" \
          https://yourapp.example.com/api/turn-creds)
printf '%s\n%s\n' \
  "$(jq -r .username <<<"$creds")" \
  "$(jq -r .password <<<"$creds")" \
| webrtc-doctor turn "$(jq -r '.uris[0]' <<<"$creds" | sed 's/?.*//')" \
    --user-stdin --pass-stdin
```

### Probe a TURN-over-TLS server (TURNS)

Most production WebRTC deployments expose TURNS — TURN tunneled over
TLS-over-TCP — so the relay path can survive corporate firewalls that
block UDP and proxy-aware setups that only allow `:443`. The wire
protocol is the same as plain TURN; the transport is TLS-over-TCP with
a 2-byte length prefix per STUN/TURN message.

```sh
# Default TURNS port (5349):
webrtc-doctor turns turns:turn.example.com:5349 --user alice --pass s3cret

# Or :443 for firewall traversal:
webrtc-doctor turns turns:turn.example.com:443 --user-stdin --pass-stdin
```

The check reports total time and a `tls_handshake_ms` breakdown in
the `--json` detail, so you can see whether slowness is in the TLS
setup vs the TURN allocation itself.

### Probe a signaling endpoint (WS / WSS)

A WebRTC deployment fails just as easily at the signaling layer as at
the TURN/STUN layer. The `signaling` subcommand opens a WebSocket
connection (TCP connect → TLS handshake if `wss://` → HTTP Upgrade →
101 Switching Protocols), reports total handshake latency, and closes
cleanly. Optional `--auth-header` attaches an Authorization header for
gated endpoints.

```sh
webrtc-doctor signaling wss://echo.websocket.org
webrtc-doctor signaling wss://signal.example.com/ \
  --auth-header "Bearer eyJhbGciOi..."
```

Expected output:

```
webrtc-doctor 0.1.0 — probing signal.example.com (signaling)
  ✓ dns        signal.example.com → 203.0.113.30 (15 ms)
  ✓ signaling  wss connected, HTTP 101 (203 ms, auth OK)

2 pass · 0 warn · 0 fail · 0 skip        verdict: HEALTHY
```

The Authorization header has the same secret-handling caveats as TURN
credentials (visible in argv, shell history, process listings). For
any real token, use `--auth-header-stdin` instead:

```sh
printf '%s\n' "Bearer $TOKEN" \
  | webrtc-doctor signaling wss://signal.example.com/ --auth-header-stdin
```

`--auth-header` and `--auth-header-stdin` are mutually exclusive
(clap rejects the combination at parse time).

### Gather ICE candidates

A real `RTCPeerConnection` builds a list of candidate transport
addresses before it can connect — host (local interface), srflx
(public address learned via STUN), and relay (TURN-allocated). The
`ice` subcommand enumerates the same three types so you can see
exactly what a browser would see, without opening DevTools:

```sh
# host candidates + srflx via STUN
webrtc-doctor ice stun:stun.l.google.com:19302

# host + srflx + relay (single URL — production TURN servers also
# serve STUN binding on the same port)
webrtc-doctor ice turn:turn.example.com:3478 \
  --user-stdin --pass-stdin <<<$'USERNAME\nPASSWORD'
```

Expected output:

```
webrtc-doctor 0.3.0 — probing turn.example.com (ice)
  ✓ dns             turn.example.com → 203.0.113.10 (8 ms)
  ✓ stun.binding    srflx 198.51.100.42:49768 (35 ms)
  ✓ turn.alloc.udp  relay 203.0.113.10:49165 (lifetime 600s, 281 ms)
  ✓ ice.gather      4 candidates (2 host, 1 srflx, 1 relay)
      host   192.168.1.42:0                (Ethernet)
      host   [2603:6010:6c00:abcd::42]:0   (Ethernet)
      srflx  198.51.100.42:49768           via stun:turn.example.com:3478
      relay  203.0.113.10:49165            via turn:turn.example.com:3478

4 pass · 0 warn · 0 fail · 0 skip        verdict: HEALTHY
```

Host ports show as `:0` because `ice.gather` enumerates addresses
rather than binding a socket per candidate; the srflx and relay
ports are real (those came from actual connections in the earlier
checks). Loopback, IPv4 link-local APIPA (169.254/16), and IPv6
link-local (`fe80::/10`) are filtered out — they're never useful
ICE candidates. Private RFC 1918 ranges and IPv6 ULA *are* kept;
they're valid host candidates on a LAN even though useless across
the public internet.

### DTLS handshake

`webrtc-doctor dtls` covers three modes through one subcommand. In all
of them the output reports the negotiated peer-certificate SHA-256
fingerprint in SDP format (`a=fingerprint:sha-256 AA:BB:CC:...`) plus
the handshake duration.

**Loopback (no arguments)** — in-process smoke test. Spins up a DTLS
server on one task and a client on another, both talking over
`127.0.0.1`. Proves the DTLS layer is wired in and works without
needing any network target.

```sh
webrtc-doctor dtls
```

```
webrtc-doctor 0.5.0 — dtls loopback (in-process)
  ✓ dtls.loopback  handshake OK in 3 ms (loopback); peer fp sha-256 28:D0:C8:F3:99:42:08:4F
```

**Against a remote peer** — dial a DTLS endpoint, report the result.
Useful when you control the other side (or know it speaks DTLS).

```sh
webrtc-doctor dtls dtls.example.com:5684
```

```
webrtc-doctor 0.5.0 — probing dtls.example.com:5684 (dtls)
  ✓ dns          dtls.example.com → 203.0.113.50 (12 ms)
  ✓ dtls.remote  handshake OK in 87 ms (via 203.0.113.50:5684); peer fp sha-256 C4:CA:C4:DA:63:22:EB:A8
```

**Serve mode** — turn `webrtc-doctor` itself into a DTLS test peer so
you can verify the network path without third-party infrastructure.
Run on a VPS / lab box, then dial it from anywhere:

```sh
# on the remote box
webrtc-doctor dtls --serve --bind 0.0.0.0:5684

# on the client
webrtc-doctor dtls remote.example.com:5684
```

The server logs the source address of every accepted handshake so you
can confirm the client actually reached you (and from which NAT). It
keeps running until killed.

All three modes use self-signed certificates and `insecure_skip_verify`
— this is a transport-reachability + protocol-correctness diagnostic,
not a chain-of-trust validator. That mirrors what WebRTC itself does
over an ICE candidate pair: DTLS authenticates via the SHA-256
fingerprint pre-shared in SDP, not via a CA bundle.

`--json` exposes the full 32-byte fingerprint, peer-cert DER byte
length, and the negotiated SRTP protection profile (`Unsupported`
here, because we don't configure `use_srtp` — honest answer for a
plain-DTLS handshake). For diagnosing a *real* WebRTC DTLS failure
against an actual `RTCPeerConnection` you still need full ICE on both
sides; webrtc-doctor's DTLS check is the network-and-protocol layer,
not a browser substitute.

### Machine-readable output

Add `--json` to any subcommand to get the structured report:

```sh
webrtc-doctor --json turn turn:turn.example.com:3478 --user alice --pass s3cret
```

The output shape is the contract — stable across versions, intended for CI
pipelines, time-series dashboards, and the future hosted probe service.
Every check has a stable `id`, a `status` (`pass` / `warn` / `fail` / `skip`),
a `latency_ms`, a one-line `summary`, and a check-specific `detail` object
that carries the structured fields the pretty output doesn't show
(resolved IPs, server-reflexive address, allocated relay address, auth
realm, allocation lifetime, etc.).

<details>
<summary>Example JSON output (click to expand)</summary>

```json
{
  "verdict": "healthy",
  "total_ms": 684,
  "results": [
    {
      "id": "dns",
      "name": "DNS resolution",
      "status": "pass",
      "latency_ms": 6,
      "summary": "turn.example.com → 203.0.113.10 (6 ms)",
      "detail": {
        "addresses": [
          "203.0.113.10"
        ],
        "host": "turn.example.com"
      }
    },
    {
      "id": "stun.binding",
      "name": "STUN binding",
      "status": "pass",
      "latency_ms": 169,
      "summary": "srflx 198.51.100.42:52948 (169 ms)",
      "detail": {
        "server": "203.0.113.10:3478",
        "srflx": "198.51.100.42:52948"
      }
    },
    {
      "id": "turn.alloc.udp",
      "name": "TURN allocation (UDP)",
      "status": "pass",
      "latency_ms": 339,
      "summary": "relay 203.0.113.10:49161 (lifetime 600s, 339 ms)",
      "detail": {
        "auth": "long-term",
        "lifetime_s": 600,
        "realm": "turn.example.com",
        "relayed": "203.0.113.10:49161",
        "server": "203.0.113.10:3478"
      }
    },
    {
      "id": "turn.echo.udp",
      "name": "TURN echo (UDP)",
      "status": "pass",
      "latency_ms": 1872,
      "summary": "10/10 echoes, loss 0%, rtt min/avg/max = 162/169/178 ms via 203.0.113.10:49161",
      "detail": {
        "path": "client→relay→data-indication",
        "sent": 10,
        "received": 10,
        "duplicates": 0,
        "loss_pct": 0.0,
        "rtt_ms": [168, 162, 171, 169, 165, 178, 167, 170, 169, 171],
        "peer": "198.51.100.42:52948",
        "relayed": "203.0.113.10:49161",
        "server": "203.0.113.10:3478"
      }
    }
  ]
}
```

The IPs above use [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)
documentation prefixes — `203.0.113.0/24` for the server side,
`198.51.100.0/24` for the client side. A real run substitutes real addresses.

</details>

For most scripting, the **process exit code** is the right signal: `0`
healthy, `1` failed, `2` warnings (see below). When you need more,
`--json | jq` gives you the same outcome as a field
(`jq -r .verdict` → `"healthy"` / `"warnings"` / `"failed"`) plus
per-check detail you can pull into a TSDB — e.g.
`jq '.results[] | select(.id=="turn.alloc.udp") | .latency_ms'`.
The pretty output is for humans, the JSON is for everything else.

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
