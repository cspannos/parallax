# ADR 0025 — `π` of `F`: the matcher runs in a zkVM guest

**Status:** Accepted as the **research default for height validity (Model III)**; CPU-measured, not a production prover  
**Date:** 2026-10-15  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0011](0011-missing-pi-settlement-inert.md) (settlement inert until `π`), [0023](0023-general-c-prime-on-zkvm.md) (zkVM for general `C'`), [0024](0024-sha256-c-prime.md) (SHA-256 `C'`).  
**Does not implement:** a GPU or distributed prover, proposer-included `π`, Groth16, light-client DA of the snapshot.

## Context

ADR 0023 proved that a list of map ops takes `C` to `C'`. It did not prove that the matcher chose those ops. `HeightStatement` asks for more: `C' = Commit(F(Open(C), I))` together with `input_commitment` and `settlement_commitment`.

The resting map is keyed by `OrderId`, not by price. A path witness can show that an order exists. It **cannot** show that the matcher took the *best* price, which needs non-membership in price order. So a witness-only `F` would need a price-ordered commitment, which changes ADR 0013.

## Decision

The guest runs the real `clob::Engine` on the **full committed state**:

1. Input: a canonical [`EngineSnapshot`](../../crates/clob/src/snapshot.rs) (height, `next_time`, instrument specs, nonces, seen ids, resting orders in `time` order) and `I`.
2. `Engine::from_snapshot` rejects non-canonical snapshots: unsorted or duplicate keys, duplicate rest times, unknown instruments. The treap would merge duplicates, so without this the root could match while the book differed. With it, snapshot → INC root is injective over everything the matcher reads.
3. `C` is rebuilt with a linear-time cartesian-tree build ([`HashedMap::from_sorted`](../../crates/commitments/src/hashed_map.rs)): one priority and one node hash per entry, with the same root as upserting.
4. The guest applies `I`, then commits `mode ‖ pre_root ‖ post_root ‖ input_commitment ‖ settlement_commitment` ([`run_f`](../../crates/clob/src/snapshot.rs)). That is exactly the `F` part of `HeightStatement`; `parent` and `height` are consensus metadata.
5. [`Risc0FVerifier`](../../crates/proof-adapter/src/risc0_f.rs) (feature `risc0`) is the first `VerifyPi` with `UNLOCKS_SETTLEMENT = true`. It pins the image ID, requires SHA-256 `C'`, matches the journal to the statement, and is built with `disable-dev-mode`.

## Measurements

Apple M4 Pro, RISC Zero 3.0.6 **CPU prover**, SHA-256 `C'`, `load_places` book then `churn_tape` mixed events. Every journal below equals the natively computed statement fields (asserted by the host).

Guest cycles (executor), after the linear-time rebuild:

| Book (resting) | 0 events | 8 events | 64 events | 512 events |
|---|---|---|---|---|
| 1 000 | 16.7 M | — | — | — |
| 8 000 | **136.1 M** (162 segments) | 137.3 M | 145.0 M | 205.1 M |

The upsert-based rebuild cost 918.7 M cycles at 8k before `from_sorted` (6.7× more). Matching costs **~135 K cycles per event**. The rebuild is ~8.5 K cycles per committed entry, of which only ~1 K is hashing; the rest is decoding, the book's `HashMap` and allocation.

Real succinct proofs (`disable-dev-mode`):

| Height | Segments | Prove | Receipt | Verify |
|---|---|---|---|---|
| M6b crossing (empty book, 2 Places) | 1 | **19.0 s** | 223 484 B | 9 ms |
| 200 resting + 32 events | 8 | **496 s** | 223 484 B | 9 ms |
| 1 000 resting + 8 events | 20 | **1 311 s** | 223 484 B | 10 ms |

**Settlement gate:** with the crossing receipt, [`SettlementGate<Risc0FVerifier>`](../../crates/proof-adapter/tests/risc0_gate.rs) settles the height and balances move. The same proof against a different `I` stays inert (`ProofInvalid`), as do a wrong image ID and flipped receipt bytes.

**Loaded 10k height at 8k (projection, not run):** 136 M + 10 000 × ~135 K ≈ **1.5 × 10⁹ cycles ≈ 1 430 segments ≈ ~24–26 CPU-hours** at the measured ~60–65 s per segment. That is cheaper than the witness-only tape (~36 CPU-hours, ADR 0023), because running the matcher on the full state does not re-hash old paths.

## Consequences

- Settlement can unlock on a validity proof, not only on a full-view certificate. This is the Model III endgame (Q-PRF-6) in prototype form.
- **The proof cost has a state-size term.** Every proof rebuilds `C` from the snapshot: ~136 M cycles at 8k resting orders, linear in entries. The **seen-id set grows forever** (every id ever placed), so this term grows with history unless seen ids expire. That was Q-CLOB-8, **closed by ADR [0026](0026-derived-order-ids.md)**: ids derived from `(owner, nonce)` retire the seen set (8k rebuild 136 → 106 M cycles, ~94 K per event).
- The snapshot is a FULL_VIEW witness. The prover must hold the whole private state; the proof reveals only the statement.
- One guest run per height. RISC Zero splits it into segments that can be proven in parallel; this host proves them one after another.

## Alternatives

| Option | Why not (now) |
|---|---|
| Witness-only `F` (path openings per read) | Cannot show best-price without a price-ordered commitment; cost per read ~2× hashes |
| Price-ordered `C'` (book keyed by side/price/time) | Reopens ADR 0013; worth it if snapshot rebuild dominates at scale |
| Hand-written Plonky3 AIR of the matcher | Weeks of constraint work; no recursion in `p3-uni-stark` 0.6 |

## Security implications

Trust is the RISC Zero proof system plus the guest image (the `clob` code that defines `F`). An image ID that does not pin the network's code makes the proof meaningless; deployments must pin it in configuration. The snapshot canonicity checks are load-bearing (tests: `crates/clob/tests/f_snapshot.rs`). Fake receipts are rejected by `disable-dev-mode`. The verifier refuses `C'` v1 (BLAKE3) journals.

## Reversibility

High. The guest, the verifier and the snapshot codec are additive; the gate still accepts the full-view certificate.

## Guest trimming (2026-10-17)

A cycle profile (`zkvm/risc0/methods/fprof`) showed that hashing and allocation, not matching, dominated the rebuild. Changes (none alters any root; every run asserts journal = native statement):

1. **No trace allocations unless tracing.** Every `node_digest` built a key/value-copying opening and a full preimage for trace buffers nobody was reading. A `TRACING` flag now skips that.
2. **Sort once.** `validate` returns the id-sorted order; the map build reuses it instead of sorting encoded leaves again.
3. **Pre-size** decode vectors (capped by remaining bytes, since the counts are untrusted), the book's `HashMap`, and each 103 B leaf.
4. **One-call SHA-256.** Node and priority preimages are assembled once and hashed in one call. `commitments::set_sha256_impl` lets a guest install its prover's one-call accelerator; the `f` guest installs RISC Zero's `Impl::hash_bytes`. Its output is standard SHA-256, the image pins the choice, and the host checks the journal against the native statement. Through the `sha2` fork, a 216 B node cost ~2.8 K cycles; now ~1.8 K. The rest is byte copies into the preimage.

| 8k resting | Before | After |
|---|---|---|
| Rebuild only | 106.1 M | **58.6 M** (−45%) |
| + 512 events | 154.1 M | **87.6 M** |
| Per event | ~94 K | **~57 K** |
| Real proof, 1 000 + 8 events | 1 311 s (20 segments) | **620 s** (10 segments) |

Loaded 10k now projects to **~0.63 × 10⁹ cycles ≈ 10–11 CPU-hours**. Fix 1 also speeds up the native engine: loaded 10k engine work **58 → 28 ms** (~358k ev/s), and the loaded Malachite height **~0.156 → ~0.13 s**.
