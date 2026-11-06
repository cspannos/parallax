# M4c transport — QUIC vs TCP

**Date:** 2026-09-30  
**Binary:** `cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned. Same harness as [M4b](m4b-scale.md).  
**Units:** milliseconds. StartedRound → Decided.  
**Mesh:** localhost **broadcast** (M4a/M4b same-test). Full persistent-peer list. Not GossipSub.  
**What is on the wire:** Malachite votes + `ProposalAndParts` for `ConsensusValue` (~178 B).  
**What is not:** the private order/`I` channel (still out of band, ADR 0009); a 1 MB DA blob.

Q-NET-1 says measure QUIC vs TCP; do not assume. This is that measurement on the consensus gossip transport the order/DA mesh would use if `I` rode the same libp2p stack.

`cargo test -p consensus-adapter --test m4c_transport`: n=10 QUIC correctness.

## Cluster (ms)

| n | tcp p50 | quic p50 | tcp p95 | quic p95 | tcp max | quic max | heights |
|---|---|---|---|---|---|---|---|
| 4 | 52 | 48 | 78 | 60 | 78 | 60 | 8 |
| 7 | 78 | 99 | 114 | 118 | 114 | 118 | 8 |
| 10 | 118 | 139 | 176 | 160 | 176 | 160 | 8 |
| 20 | 286 | 316 | 425 | 409 | 425 | 409 | 4 |

## Node (ms)

| n | tcp p50 | quic p50 | tcp p95 | quic p95 | tcp p99 | quic p99 |
|---|---|---|---|---|---|---|
| 4 | 41 | 43 | 67 | 53 | 78 | 60 |
| 7 | 67 | 74 | 90 | 104 | 111 | 106 |
| 10 | 96 | 96 | 133 | 139 | 176 | 148 |
| 20 | 206 | 228 | 395 | 346 | 411 | 369 |

## Reading

QUIC is **not** faster on this localhost broadcast mesh. Cluster p50 is slightly **higher** for QUIC at n=7, 10, and 20 (same band, ~10–25%). Tails are mixed: QUIC cluster max was lower at n=10 and n=20, higher at n=7.

That is not a product pick. Loopback TCP vs QUIC does not stand in for WAN, loss, or a private order topic. n=50/100 were TCP-only (M4b); those runs are scheduler-bound and would not be a transport comparison.

Q-NET-1 stays **open** for a real mesh, an order/`I` topic, and GossipSub.

## Pass

n=10 QUIC nodes decided the same `id(v)` as the TCP tests. Fail conditions unchanged: Engine API is not the value; Arc is not the app.
