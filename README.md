# webrtc-doctor

A single-binary WebRTC connectivity diagnostic. Point it at any STUN, TURN,
TURNS, or signaling endpoint and get a clear pass/fail report with timings
for every step — DNS, UDP reachability, STUN binding, TURN allocation, TURN
echo round-trip, DTLS handshake, ICE candidate gathering, signaling auth.

Like `mtr` or `dig`, but for WebRTC.

## Status

Pre-alpha — scaffolding only. See [`docs/PLAN.md`](docs/PLAN.md) for the design,
MVP scope, CLI shape, and roadmap.

## Why

When a WebRTC user says "it's broken," the only existing diagnostics are
`webrtc-internals` Chrome dumps or Wireshark traces. This tool gives ops and
developers a one-shot, copy-pasteable readout of exactly which layer is
failing and where.

## Build

```sh
cargo build --release
./target/release/webrtc-doctor --help
```

## Project layout

```
crates/
├── probe-core/      # Library: check pipeline, results, JSON serialization.
└── webrtc-doctor/   # Binary: CLI wrapper over probe-core.
docs/
└── PLAN.md          # Design, MVP scope, roadmap, continuation notes.
```

## License

Apache-2.0. See [`LICENSE-APACHE`](LICENSE-APACHE).
