# STUN, TURN, and why webrtc-doctor hand-rolls them

This doc covers the two RFCs that webrtc-doctor implements directly on the wire — **RFC 5389 (STUN)** and **RFC 5766 (TURN)** — and explains why those codecs are written by hand rather than pulled in from `webrtc-rs` or another high-level library.

It's aimed at two audiences:

- **WebRTC newcomers** who want to understand what STUN and TURN actually do, with analogies that don't require networking expertise.
- **Engineers evaluating webrtc-doctor** who want to understand the design trade-off behind hand-rolling the wire layer.

The protocol explanations come first; the design rationale is in the second half.

---

## Part 1 — What STUN and TURN actually do

### The underlying problem: NAT

Almost every device on the internet today sits behind **Network Address Translation (NAT)**. Your laptop has a local address like `192.168.1.42` that's only meaningful inside your home or office. When you visit a website, your router rewrites the packet to use the router's *public* address (something like `203.0.113.42`) and remembers the mapping so the reply can be sent back to your laptop.

**Layman analogy:** think of a large apartment building with one street address (`123 Main St`) and a front desk that handles mail. When you send a letter, the front desk puts the building's return address on it; when a letter arrives addressed to the building, the front desk routes it to your apartment based on a numbered slot they assigned to your outgoing mail. The outside world never sees apartment numbers — only the building.

This works perfectly for client-server traffic (you initiate, the server responds) because the router knows where the reply belongs. But it breaks peer-to-peer:

- Your laptop wants to send video directly to a friend's phone.
- Your friend's phone has its own NAT in front of it.
- Neither side knows the other's public address.
- Even if they did, neither router has a mapping that allows unsolicited inbound traffic from the other side.

WebRTC needs to solve this every single time two browsers establish a call. That's what STUN and TURN are for.

---

### RFC 5389 — STUN (the "what's my public address?" protocol)

**Full name:** Session Traversal Utilities for NAT.

**One-line summary:** STUN is a tiny request/reply protocol where you ask a public server "what address are you seeing this request come from?" and the server tells you.

**Layman analogy:** you're in that apartment building from earlier and you don't know the building's street address. You write a letter to a friend across town saying "please write back and tell me the return address you're seeing on this envelope." Their reply tells you `123 Main St, Apt #4F` — which is what the outside world sees you as. That's STUN. You needed an outsider to tell you something you couldn't see for yourself.

**Why WebRTC needs it:** before two browsers can attempt a direct peer-to-peer connection, each one must learn its own externally-visible address (called the **server-reflexive address**, or **srflx**). Without that, they have nothing to give each other to connect to.

**How it works on the wire:**

A STUN message is dead simple — a 20-byte header followed by zero or more attributes:

```
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |0 0|     STUN Message Type     |         Message Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Magic Cookie                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  |                     Transaction ID (96 bits)                  |
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Message Type** — what kind of request this is. The one webrtc-doctor uses most is `0x0001` (Binding Request).
- **Magic Cookie** — always `0x2112A442`. Distinguishes RFC 5389 STUN from the older RFC 3489 version, which omitted it.
- **Transaction ID** — a 96-bit random number that ties a response back to its request, since UDP doesn't guarantee ordering.
- **Attributes** — type-length-value triples following the header. The server's reply attaches an `XOR-MAPPED-ADDRESS` attribute carrying your srflx.

A Binding Request is roughly 20 bytes on the wire. The reply is maybe 40 bytes. Round-trip time over the internet is usually 10–200 ms.

**What can go wrong (and what webrtc-doctor reports):**

- DNS for the STUN host failed → no Binding Request gets sent.
- Server unreachable (firewall blocking UDP, server down) → no reply within timeout.
- Server replied but the response is malformed → parse error with the bad bytes.
- All good → reports the srflx address and how long it took.

That last line is the entire `stun.binding` check.

---

### RFC 5766 — TURN (the "please relay this for me" protocol)

**Full name:** Traversal Using Relays around NAT.

**One-line summary:** when two peers can't reach each other directly (because one or both sit behind NAT types that won't allow inbound traffic), TURN provides a public-internet **relay** that both peers *can* reach. The relay forwards traffic between them.

**Layman analogy:** you and a pen pal want to exchange letters but both your apartment buildings have strict rules: outgoing mail only, no unsolicited inbound. The workaround is to rent a PO box at a downtown post office that both of you *can* reach. You send your letters to the PO box; your pen pal sends theirs to the same PO box; the post office holds and forwards. That's TURN. The PO box has its own address (the **relayed transport address**), the post office charges rent (the allocation has a **lifetime** and must be refreshed), and you need to show ID to open the box (TURN authentication).

**Why WebRTC needs it:** roughly 10–20% of WebRTC connections cannot be established directly even with STUN — typical case is two users on symmetric/port-restricted NATs (corporate networks, cellular carriers, hotel Wi-Fi). For those connections, TURN is the only way calls work. About 60% of "ICE Failed" production tickets trace back to a misconfigured TURN server — which is exactly why webrtc-doctor exists.

**How it works on the wire:**

TURN is an extension of STUN — it uses the same 20-byte header and TLV-attribute format, just with new message types. The methods webrtc-doctor exercises:

| Method | Code | What it does |
|---|---|---|
| Allocate | `0x003` | "Give me a relay address." Server responds with a `RELAYED-ADDRESS` and a lifetime in seconds. |
| CreatePermission | `0x008` | "Expecting traffic from peer X — let it through." |
| Send Indication | `0x016` | Wraps an outbound data packet destined for a permitted peer. |
| Data Indication | `0x017` | Wraps an inbound data packet that arrived from a permitted peer. |
| Refresh | `0x004` | "Extend the allocation before it expires." |
| ChannelBind | `0x009` | Optimization: shortens the framing overhead for hot peer pairs. |

**The authentication dance:**

TURN servers don't hand out relay addresses to anonymous clients (relay bandwidth costs money). Authentication uses the **long-term credential mechanism**:

1. Client sends `Allocate` with no credentials.
2. Server replies `401 Unauthorized` and includes two attributes: `REALM` (e.g. `"example.org"`) and `NONCE` (a server-chosen one-time string).
3. Client retries `Allocate`, this time including:
   - `USERNAME` (configured user)
   - `REALM` and `NONCE` (echoed from the server's challenge)
   - `MESSAGE-INTEGRITY` — an HMAC-SHA1 hash over the entire message, keyed by `MD5(username:realm:password)`.
4. Server validates the HMAC. If it matches, the allocation succeeds.

**Layman analogy of the auth dance:** you walk into the post office and ask to rent a PO box. They say "we don't know you — fill out this form with your name, the branch ID (`realm`), and this one-time reference number (`nonce`), then sign it with a secret handshake only you and we know." You go away, fill out the form, do the handshake, come back. Now they know you're you.

**What can go wrong (and what webrtc-doctor reports — these are the messages that make the tool useful):**

- `401 after auth` — credentials were sent and rejected. Almost always wrong username or password.
- `438 Stale Nonce` — the nonce expired between challenge and retry; client should retry with the new nonce.
- `441 Wrong Credentials` — username/realm combo doesn't match any known account.
- `Allocate rejected, no realm in challenge` — server's 401 didn't include a `REALM` attribute (rare, indicates a broken or non-standard TURN server).
- `Server reachable but no Allocate response` — UDP packet got there but the server isn't speaking TURN on that port.
- Success → reports the relay address, lifetime, and allocation time.

**The TURN echo round-trip** (webrtc-doctor's `turn.echo.udp` check):

Once an allocation succeeds, the tool proves the data plane actually works by:

1. Creating a permission for a peer address (a clever trick: it uses *its own* srflx address as the "peer," so it doesn't need a second machine).
2. Sending a small UDP payload wrapped in a Send Indication to the relay.
3. The relay forwards the payload to the "peer" (which is itself).
4. The packet arrives back wrapped in a Data Indication on the original control socket.
5. Measures the round-trip time.

Repeated 10 times by default — gives you `loss%` and `min/avg/max RTT`. If even one packet round-trips, you have proof that the entire allocate-relay-permission-data stack works against this server.

**NAT-friendly design note:** the "peer-as-self" trick matters because it keeps all inbound traffic on the same 5-tuple as the original TURN control session. An earlier design tried using a Send Indication to a separate peer port, which fails on symmetric NATs because the relay's outbound source port differs from the TURN server's listening port and the NAT drops it. The peer-as-self design works through every NAT type.

---

### RFC 5766 over TLS — TURNS

TURNS is just TURN with a TLS-wrapped TCP transport instead of UDP. Same protocol, same auth dance, same wire format — but inside a TLS stream and length-prefixed for framing (because TCP is a stream and doesn't have packet boundaries the way UDP does).

TURNS exists because some networks (corporate firewalls, hotel Wi-Fi, mobile carriers) block UDP entirely. Wrapping TURN in TLS-on-port-443 makes the traffic look like HTTPS to a firewall.

webrtc-doctor's `turn.alloc.tls` check exercises the TLS handshake plus the framed Allocate dance. The protocol bytes inside the TLS stream are byte-identical to the UDP path.

---

### How the pieces fit together in a real call

When two browsers establish a WebRTC call:

1. Each browser asks one or more STUN servers for its srflx address.
2. Each browser also asks a TURN server to allocate a relay address.
3. Each browser ends up with a list of **ICE candidates**: its own local addresses (`host`), its srflx address from STUN, and its relayed address from TURN.
4. The two browsers exchange these candidate lists via the signaling channel (a WebSocket to a server they both know).
5. The browsers run **ICE** (RFC 8445) to try every plausible pairing of `(my candidate, your candidate)` and pick the best one that works.
6. Direct peer-to-peer is preferred (lower latency, no relay cost). TURN is fallback.

webrtc-doctor's job is to verify that each of those steps would succeed if a real browser tried it — without actually being a browser.

---

## Part 2 — Why webrtc-doctor hand-rolls these codecs

The decision: write the STUN and TURN wire format by hand against the RFCs (extracted into `crates/probe-core/src/stun_codec.rs` and `turn_codec.rs`) instead of pulling in `webrtc-rs` or another high-level library.

Four reasons, in order of weight.

### Reason 1 — The whole point is surfacing wire-level errors that high-level libraries hide

This is the dominant reason and the others are downstream of it.

`webrtc-rs` exposes a `PeerConnection`-style API modeled on the browser's `RTCPeerConnection`. That API was designed to make WebRTC easy for app developers, which means it goes out of its way to *hide* the details of which layer failed. When TURN authentication fails inside `webrtc-rs`, the error that bubbles up to the caller is something like `"ICE gathering failed"` or `"agent connection failed"` — semantically identical to the opaque "ICE Failed" that drove building this tool in the first place.

**Layman analogy:** imagine you want to build a tool that diagnoses why a car won't start. You could buy a fancy diagnostic dongle that just shows a red "engine fault" light, or you could read the OBD-II codes directly and tell the user "cylinder 3 misfire detected, probably a bad spark plug." The fancy dongle is easier to use, but it's the wrong tool for the diagnostic job. webrtc-doctor wants to be the OBD-II reader, not the red light.

Concretely, hand-rolling means the codec returns:

- The literal STUN error code (`401`, `438`, `441`) the server sent.
- The `REALM` and `NONCE` the server included in its challenge.
- The exact bytes of the response if parsing fails.
- The transaction ID for correlation with Wireshark captures.

A high-level library would surface none of these things, and reaching past its abstraction to get them would be uglier than just writing the codec.

### Reason 2 — The protocols are tiny

The actual wire format of STUN is one diagram on page 9 of RFC 5389. The rest of the 51-page RFC is rationale, security considerations, and the registry of standard attributes. TURN adds a handful of method codes and the auth dance described above.

webrtc-doctor's full STUN + TURN codec footprint in `crates/probe-core`:

- `stun_codec.rs` — ~250 lines, including comments and tests.
- `turn_codec.rs` — ~300 lines, including the message-building helpers.

That's it. A dependency would not meaningfully reduce that.

**Layman analogy:** you wouldn't pull in a 10MB image-processing library to write a one-line script that reads a PNG header and prints its width and height. The cost of the dependency exceeds the cost of just reading the file format spec yourself. STUN and TURN are at that scale.

### Reason 3 — `webrtc-rs` is heavyweight for a CLI

`webrtc-rs` is a full WebRTC implementation — it includes:

- The complete ICE agent state machine (RFC 8445).
- SRTP for media encryption (RFC 3711).
- SCTP for data channels (RFC 4960).
- The full peer-connection lifecycle (offer/answer, renegotiation, ICE restart).
- A media engine.

webrtc-doctor needs *none* of that. It sends a Binding Request, parses the response, exits. The dependency would inflate compile times, binary size, and surface area for security advisories — all for code that's never executed.

**Layman analogy:** `webrtc-rs` is a fully assembled car. webrtc-doctor needs a single bolt. You don't buy the car to harvest the bolt.

### Reason 4 — Hand-rolling preserves the things being measured

webrtc-doctor reports several measurements that depend on direct control of the wire:

- **Exact bytes sent and received** — so users can correlate webrtc-doctor's output with a Wireshark capture of the same connection.
- **Per-step latency** — DNS time, first STUN response time, Allocate time, first echo round-trip — separately, not bundled.
- **Failure mode at the layer where it happened** — `Allocate returned 401 with realm=example.org` rather than `ICE failed`.
- **NAT-friendly echo design** — the peer-as-self trick (see TURN section above) only works because the codec controls exactly which 5-tuple each packet uses.

A high-level library obscures every one of these.

### Where webrtc-doctor *does* take a dependency

The hand-rolling decision is not dogmatic — webrtc-doctor uses standard crates wherever the dependency saves real work and doesn't obscure diagnostically-useful detail:

| Crate | Used for | Why depend rather than hand-roll |
|---|---|---|
| `tokio` | Async I/O runtime | Hand-rolling an async runtime is a multi-year project. |
| `tokio-rustls` | TLS for TURNS and WSS | TLS is a real cryptographic protocol; hand-rolling it is dangerous. |
| `tokio-tungstenite` | WebSocket for the signaling check | WebSocket framing is finicky and the failure modes aren't diagnostically interesting for this tool. |
| `webrtc-dtls` | DTLS handshake | DTLS is hard and the wire-level errors aren't actionable for users — "the handshake failed" is what you'd report either way. |
| `hmac` + `md5` | Auth-dance crypto | Implementing HMAC-SHA1 or MD5 from scratch is the wrong kind of work. |
| `clap` | CLI argument parsing | Saves a few hundred lines for zero loss of fidelity. |
| `if-addrs` | Enumerating local network interfaces for ICE host candidates | Platform-specific syscalls; a dependency is the right call. |

The rule of thumb: **hand-roll where the wire-level detail is the product; depend where the dependency is the cleaner abstraction over something webrtc-doctor doesn't need to interpret.**

---

## Part 3 — The one-liner version

> STUN tells a device its public address; TURN provides a relay when direct peer-to-peer fails; webrtc-doctor implements both by hand because the entire purpose of the tool is surfacing protocol-level error codes that high-level WebRTC libraries deliberately hide.

---

## Further reading

- [RFC 5389 — Session Traversal Utilities for NAT (STUN)](https://datatracker.ietf.org/doc/html/rfc5389) — the protocol spec, 51 pages. Section 6 ("STUN Message Structure") is the wire format.
- [RFC 5766 — Traversal Using Relays around NAT (TURN)](https://datatracker.ietf.org/doc/html/rfc5766) — extends STUN. Section 2 has the architectural overview; section 4 covers the auth dance.
- [RFC 8445 — Interactive Connectivity Establishment (ICE)](https://datatracker.ietf.org/doc/html/rfc8445) — how WebRTC actually uses STUN and TURN to pick a candidate pair. webrtc-doctor doesn't implement the ICE state machine, but the `ice.gather` check produces the candidate list ICE would consume.
- [`crates/probe-core/src/stun_codec.rs`](../crates/probe-core/src/stun_codec.rs) and [`turn_codec.rs`](../crates/probe-core/src/turn_codec.rs) — the actual hand-rolled codecs. ~550 lines combined.
