# ADR 0034 — A hybrid PQ tunnel under Malachite's libp2p

**Status:** Accepted (research default for validator transport confidentiality; opt-in via `ClusterSpec::with_pq_tunnel`)  
**Date:** 2026-10-25  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0030](0030-pq-hybrid-suites.md) (suite handshake, the "transport stays classical" caveat), [0031](0031-tiered-finality.md).

## Context

ADR 0030 left Malachite's transport classical: libp2p TCP with Noise (X25519) and an Ed25519 peer identity. Recorded validator traffic could be decrypted once X25519 falls (harvest-now-decrypt-later). Forking libp2p to add ML-KEM to Noise is a large upstream change.

## Decision

Wrap the TCP connections instead ([`pq_tunnel.rs`](../../crates/consensus-adapter/src/pq_tunnel.rs)), like WireGuard in front of a service:

```text
Malachite i ──tcp──▶ forwarder(i→j) ══ suite handshake + AEAD ══▶ tunnel j ──tcp──▶ Malachite j
                     (loopback)              (the network)                (loopback)
```

- **Handshake and channel.** The handshake is `crypto_suite::kex` (ADR 0030): X25519 + ML-KEM-768, with the transcript signed by both validators' full suite keys and each peer checked against the validator set. Frames are then XChaCha20-Poly1305 with counter nonces. A frame that fails to open closes the connection.
- **Noise still runs inside.** Reading a recorded session needs **both** the hybrid tunnel and Noise broken.
- **Malachite dials only local forwarders.** Its persistent peers point at the forward ports, and discovery is off, so it never dials a peer's real port. `persistent_peers_only` cannot be set: inbound tunnel connections reach Malachite from loopback, not from a configured peer address. In a deployment, Malachite binds loopback and only the tunnel port faces the network.
- **TCP only** (QUIC is UDP).
- **Ports:** tunnel `base + 3n + i`, forwarders `base + 4n + i·n + j`.

## Tests

`tests/m7_pq_gaps.rs`:

| Test | Result |
|---|---|
| `hybrid_tunnel_cluster_decides` | A tiered hybrid cluster decides through the tunnels; at least 6 tunnel sessions were established. |
| `classical_validator_cannot_tunnel_under_hybrid_policy` | With `[H, H, H, C]` keys under a hybrid policy, the classical validator's handshakes are rejected, and the three hybrid validators still decide. |

## Measurements

Empty heights, n = 4 / 7 / 10, tiered k=1, 20 heights, `PLX_M4_TIERED=1 PLX_M4_TUNNEL=0|1`. Node p50 / p95 in ms:

| n | Direct libp2p | Through the PQ tunnel |
|---|---|---|
| 4 | 42 / 54 | 42 / 52 |
| 7 | 70 / 88 | 67 / 93 |
| 10 | 95 / 124 | 92 / 123 |

No measurable latency cost on localhost. The costs per connection and per frame:
- one hybrid handshake per libp2p connection: 0.74 ms, 13 KB
- 16 B and ~1 µs per sealed chunk (≤ 16 KB)

## What this is not

- The **libp2p peer identity is still Ed25519.** Peer authentication now also rests on the hybrid tunnel handshake, but Malachite's own peer ids and scoring remain classical.
- **No rekeying** within a long-lived connection, and no resumption.
- **Not WAN-measured.** On a real network the extra round trips of the handshake add one RTT per connection setup, not per message.

## Reversibility

High. Opt-in; the cluster config is unchanged without it.
