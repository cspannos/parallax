# M4b scale — decide percentiles vs validator count

**Date:** 2026-09-30  
**Binary:** `cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned. No frequency lock. `ulimit -n 65536`.  
**Units:** milliseconds.  
**Clock:** first `StartedRound` of the height → `Decided` on that node. Excludes the ConsensusReady peer-wait.  
**Cluster:** max of the node latencies at that height (last voter to see decide).  
**ADR:** [0009](../adr/0009-m4a-full-view-value.md)  
**Pin:** [circlefin/malachite](https://github.com/circlefin/malachite) tag **v0.8.0**

Same test as M4a: full-view voters, `ConsensusValue` (~178 B canonical), `F` in `Validate`, replica WAL on decide, localhost, **broadcast** pubsub, `I` out of band. Not GossipSub. Not 1 MB blocks. Not matching latency (every prevote still walks the full BLAKE3 book — Q-CRY-2).

`cargo test -p consensus-adapter`: n=7 and n=10 TCP correctness. n=20/50/100 are `#[ignore]` (run via the release binary).

## Cluster (ms)

| n | transport | heights | cluster samples | p50 | p95 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|---|---|
| 4 | tcp | 8 | 8 | 52 | 78 | 78 | 78 | 78 |
| 7 | tcp | 8 | 8 | 78 | 114 | 114 | 114 | 114 |
| 10 | tcp | 8 | 8 | 118 | 176 | 176 | 176 | 176 |
| 20 | tcp | 4 | 4 | 286 | 425 | 425 | 425 | 425 |
| 50 | tcp | 2 | 2 | 4108 | 4108 | 4108 | 4108 | 4108 |
| 100 | tcp | 1 | 1 | 178006 | — | — | — | 178006 |

p95/p99/p99.9 collapse toward max when the cluster sample count is small. n=100 has one height: that row is a single observation, not a distribution.

## Node (ms)

Node samples in one height are the **same** decision (gossip lag around one commit). They are not independent trials.

| n | transport | node samples | p50 | p95 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|---|
| 4 | tcp | 32 | 41 | 67 | 78 | 78 | 78 |
| 7 | tcp | 56 | 67 | 90 | 111 | 114 | 114 |
| 10 | tcp | 80 | 96 | 133 | 176 | 176 | 176 |
| 20 | tcp | 80 | 206 | 395 | 411 | 425 | 425 |
| 50 | tcp | 100 | 3399 | 3927 | 4091 | 4108 | 4108 |
| 100 | tcp | 100 | 177124 | 177842 | 177910 | 178006 | 178006 |

## Versus Malachite ~780 ms / 100 / 1 MB

We did **not** reproduce that number.

| | This run | Malachite README |
|---|---|---|
| n=100 cluster | ~178 s (one height, localhost) | ~780 ms |
| Value | ~178 B `ConsensusValue` | 1 MB |
| Topology | 100 processes, one machine, broadcast, full persistent-peer mesh | published experiment (not re-run here) |
| App work per prevote | replay `F` + full BLAKE3 state root + replica WAL on decide | dummy value |

Sub-500 ms finality at 100 validators is **not** supported by this harness. n=20 cluster p50 is 286 ms on this machine with a tiny value; n=50 already multi-second (propose timeouts + 14 cores scheduling 50 engines). n=100 is scheduler-bound, not a BFT-latency claim.

Do not cite these as matching latency or as “faster than Malachite.”

## Pass

Honest nodes at each n finalized one `id(v)` per height. Missing-`I` prevote-nil remains the M4a test (not re-run at n=100). Engine API is not the value. Arc is not the app. TRADING/PUBLIC/COMPLIANCE are not voters. Decide is not `π`.

## Not done

- WAN / multi-host (n=100 on one machine is not a 100-validator measurement — [isolate](m4-isolate.md))
- 1 MB proposal parts
- Incremental commitment on a **loaded** book (Q-CRY-2). Empty-book Validate was not the M4b cost.
- Putting `I` on this transport (still out of band)
