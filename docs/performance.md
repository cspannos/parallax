# Performance

**Status:** Living document  
**Date:** 2026-09-30  
**Rule:** research targets, not claims. Never report only averages. Report p50, p95, p99, p99.9.

M1 numbers: [`docs/benchmarks/m1-clob.md`](benchmarks/m1-clob.md). Insert/match p50 is sub-µs on Apple M4 Pro with commitment walks off. Full Blake3 root is ~0.34 ms at 1k resting, ~3.1 ms at 8k. The incremental treap **is `C'`** (ADR 0013), hashed with **SHA-256** since ADR 0024: one engine insert at 8k **~6.2 µs** p50 (BLAKE3 v1 ~9–11 µs; was ~24 µs before one-path upsert; [`hash-vs-tree.md`](benchmarks/hash-vs-tree.md)). Loaded mixed `I` ([`loaded-batch.md`](benchmarks/loaded-batch.md)): match **~5–8M ev/s**; incremental **~358k ev/s** at 8k, **~303k** at 32k after the 2026-10-17 trace-allocation fix (was ~172k / ~158k) (v1 ~100–117k); full walk of 100 events **~350 ev/s**. WAL ([`q-sto-3-wal.md`](benchmarks/q-sto-3-wal.md)): per-record fsync **~270 ev/s**; one fsync per 10k tape **~32–36k ev/s** (ADR 0012 Height).

## Targets (aspirational)

| Metric | Initial target | Longer-term investigation |
|---|---|---|
| Consensus finality | &lt; 500 ms | Same, at ≥100 validators |
| Native order events | &gt; 100,000 / s | 1M+ / s |
| Insert / match | Microsecond-scale where realistic | Same |
| EVM settlement | Benchmark independently | — |
| Proof generation | Off the fast path | Tiny transition first |

## What public numbers exist (not ours)

| Source | Number | Caveat |
|---|---|---|
| Malachite README | ~780 ms finalize, 100 validators, 1 MB blocks; up to ~2.5 blocks/s or ~13.5 MB/s | Early experiment; not independently verified |
| Arc docs | “3,000+ TPS, 20 validators, &lt;350 ms” | Marketing/docs; not measured in this repo |
| APS whitepaper | ~1070 TPS private transfers on Nitro | Different architecture (enclave pEVM) |

Sub-500 ms finality at 100 validators is **not** supported by Malachite’s published experiment if values are 1 MB. It may be possible with smaller values, fewer validators, or a tuned `target_time`. Measure.

## What we will measure

### Phase 1 (CLOB only)

- insert, cancel, match, partial fill (done: [`m1-clob.md`](benchmarks/m1-clob.md))
- state-root computation (done: full walk + incremental treap, [`q-cry-2-incremental.md`](benchmarks/q-cry-2-incremental.md))
- loaded-book batch `I` (done: [`loaded-batch.md`](benchmarks/loaded-batch.md) — WAL/Malachite off)
- clone vs apply on that tape (done: [`clone-vs-apply.md`](benchmarks/clone-vs-apply.md) — clone ~0.6–3 ms; `F` is treap apply)
- hash vs tree on one upsert (done: [`hash-vs-tree.md`](benchmarks/hash-vs-tree.md) — one-path **19 `node_digest` + 1 prio**; engine insert **~6.2 µs** SHA-256 / ~9–11 µs v1; loaded 10k **~358k ev/s** SHA-256)
- allocation count / bytes (where tooling allows)
- data-structure bake-off: `BTreeMap`, sorted `Vec`, slot-map + price index, etc.

### Phase 2

Correctness (done): [`docs/benchmarks/m2-replica.md`](benchmarks/m2-replica.md) — four nodes agree under delay/crash; truncate/corrupt detected. **Not** a speed claim (`SyncMode::Full` fsyncs every record).

WAL percentiles (done): [`q-sto-3-wal.md`](benchmarks/q-sto-3-wal.md) — Full **~270 ev/s**; height-batch fsync **~32–36k ev/s** at `|I|=10k`.

Still unmeasured:

- four-node identical-input throughput
- restart replay time vs log length

### Phase 4

Application port (done): [`docs/benchmarks/m4a-adapter.md`](benchmarks/m4a-adapter.md) — in-process four-node `Validate`/`Decide`, **not** BFT latency.

Engine linked (done): [`docs/benchmarks/m4b-scale.md`](benchmarks/m4b-scale.md), [`docs/benchmarks/m4c-transport.md`](benchmarks/m4c-transport.md) — StartedRound→Decided percentiles on localhost broadcast. n=20 TCP cluster p50 **286 ms** (tiny value). n=100 **~178 s** (one machine, not Malachite’s ~780 ms / 1 MB). QUIC is not faster than TCP here. `I` is a sealed replicated set (ADR 0016); localhost TCP can share it (ADR 0017); `offer` lives past genesis (ADR 0018); inter-height wait is empty-wait then ACK of `id(set)` (ADR 0019 / 0021), not `ready_delay`. **10k living log:** in-flight wait later last p50 ~192–202 ms (~50–52k); height 2 last ~223–236 ms (~42–45k); 10× peak fits both clocks ([m4-loaded-gossip](benchmarks/m4-loaded-gossip.md), [m4-inter-split](benchmarks/m4-inter-split.md)). WAN is still out of band.

Loaded height (done): [`m4-loaded.md`](benchmarks/m4-loaded.md) — n=4, 8k resting + 10k mixed `I`, treap `C'`, height WAL. Injected `F+wal` **~0.129–0.136 s** (~74–78k; was ~0.156 s before the 2026-10-17 trim) with SHA-256 `C'` (v1 ~0.17–0.19 s, ~55k) after hash-once `tape()`; afternoon ~0.25 s was n log n BLAKE3 in the sort comparator ([m4-started-gap.md](benchmarks/m4-started-gap.md)). Proposer-packed `I` does not get this (Q-CONS-10).

Still unmeasured:

- GossipSub / WAN / 1 MB parts — GossipSub vs broadcast isolated in [`m4-isolate.md`](benchmarks/m4-isolate.md): n=50 broadcast ~4.4–4.7 s vs GossipSub ~1.7–2.0 s (two runs); n=100 is 14 cores vs 100 engines. Dummy Validate did not move n=20 or n=50.
- value size vs finality on a real mesh
- private order/`I` topic (Q-NET-1 remainder)

### Phase 5

Correctness (done): [`docs/benchmarks/m5-settlement.md`](benchmarks/m5-settlement.md) — privileged batch apply, crash atomicity. **Not** an EVM apply speed claim; no live Reth.

Still unmeasured: settlement apply vs matching percentiles (separate plots).

### Phase 6

Correctness (M6b done): [`docs/benchmarks/m6-prove.md`](benchmarks/m6-prove.md) — settlement inert without unlock.

Measured (M6a): same instance (10,7,90) on Apple M4 Pro, **release**:

| Stack | prove | verify | size |
|---|---|---|---|
| Plonky3 AIR (FRI q=2) | 1 ms | <1 ms | 2.1 KB |
| RISC Zero 3.0.6 STARK receipt | 1.6 s | 8 ms | 205 KB |
| SP1 6.8.1 **core** (not Groth16) | 9.2 s | 64 ms | 2.6 MB |

Plonky3 prod FRI (100 queries, 16-bit PoW, official Poseidon2) unless noted. Sizes decimal. Source and commands: [`m6-prove.md`](benchmarks/m6-prove.md).

| Cell | Prove | Proof |
|---|---|---|
| Match-step, FRI-2 | ~0–1 ms | 2500 B |
| Match-step | ~86–105 ms | ~93 KB |
| Two-ask book-step (RISC Zero ~1.6 s; SP1 ~9.3 s) | ~79–95 ms | ~111 KB |
| 8k-ask walk | ~270–272 ms | ~596 KB |
| Mixed-`I` 8k events on 8 slots | ~426–437 ms | |
| One event on an 8k packed book | ~343–366 ms | ~602 KB |
| Eight sequential 8k-book events (eight proofs) | ~2.11–2.13 s | ~4.8 MB |
| Poseidon2-16 path of 20 (upsert count, **not** `C'`) | ~105–119 ms | ~396 KB |
| Poseidon2-16 path of 72 (insert count, **not** `C'`) | ~178 ms | ~506 KB |
| One BLAKE3 `g` | ~100–101 ms | ~233 KB |
| One BLAKE3 compression | ~162–163 ms | ~614 KB |
| BLAKE3 path of 20 dummy `hash64` | ~293 ms | ~899 KB |
| One resting `node_digest` | ~92–93 ms | ~734 KB |
| 19 upsert openings (18 node + 1 prio) | ~902–904 ms | ~1.07 MB |
| That path + two-ask book-step | ~1.12 s | ~1.10 MB |
| One engine Place: 72 openings, insert path edges bound | ~9.40–9.68 s | ~2.94 MB |
| Eight mixed events: 281 openings, hashes only | ~6.63–6.78 s | ~1.30 MB |
| `HeightStatement` 14 map hashes only | ~323–326 ms | ~948 KB |
| `HeightMatch` (19 openings + match-step) | ~1.20–1.21 s (verify ~39 ms) | ~1.59 MB |
| Fill-fragment verify (`Plonky3TinyVerifier`) | verify ~1–2 ms | 84 KB |
| RISC Zero succinct receipt (book-step) | ~7.0–7.6 s | ~223 KB |
| SP1 compressed receipt (book-step) | ~32.3–32.9 s | ~1.27 MB |

Loaded 10k `F` is **363 497 openings** (~3.76×10⁵ BLAKE3s) and **~85 ms** native. There is no single STARK of it at this FRI. None of these cells is `π` of `F`, and none unlocks settlement.

Public DA: 178 B full-download at n=4; n≫4 samples of blobs > 4096 B fetch ~8.7 KB (vs 84 KB) and ~10.8 KB (vs 1.29 MB); 2D RS `k=19 n=38` codes ~370 KB, reconstructs a missing row, and does not reconstruct from 16 samples (9728 B). Sample counts for `2^{-40}` and reconstruct thresholds: [`m6-prove.md`](benchmarks/m6-prove.md#sample-soundness-of-16-public-hits-2026-10-05).

### Phase 7

- sign / verify latency and bytes for classical vs hybrid vs PQ-only

## Metrics to instrument from day one of implementation

Order ingress, matching latency, queue depth, consensus rounds, proposal latency, finality, state-root generation, WAL latency, DA latency, proof generation, proof verification, EVM settlement latency, memory, CPU, network throughput.

Traces follow `intent → propagate → match → transition → consensus → settlement → proof` **without** confidential fields in span attributes.

## Benchmark plan (minimum)

1. Criterion (or equivalent) microbenches in `/benchmarks` for the book.
2. Deterministic replay tests are **correctness**, not performance; do not conflate.
3. Load generator later (Arc’s `spammer` is an idea, not a dependency).
4. Publish env: CPU model, frequency, governor, core count, NIC, fsync device.
5. No comparison to CEX engines without identical hardware and workload.
