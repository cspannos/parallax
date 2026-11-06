# Roadmap

Research prototype. Each milestone is independently testable. A later phase started only when the previous milestone’s **pass/fail question** was answered.

**v1 prototype: Phases 0–7 complete (2026-11-06).** Figures inside each phase are as measured at the time; later ADRs improved several of them (current numbers: [`ARCHITECTURE.md`](ARCHITECTURE.md#key-measurements)). The next version is proposed in ADRs [0035](docs/adr/0035-clob-as-l2-over-malachite.md) and [0036](docs/adr/0036-ledger-kernel-and-engines.md).

---

## Phase 0 — Research (done)

**Delivered in-tree:** reference study, initial design, Vitalik 2030 alignment note, threat/privacy/DA/PQ/performance models, ADRs 0001–0005.

---

## Phase 1 — Private State Engine (CLOB only)

**Milestone M1 — Deterministic in-memory book (done 2026-09-30)**

- Crates: `protocol-types`, `commitments`, `clob`, `private-state-engine`
- Limit, cancel, partial fill, price/time FIFO, fixed-point, canonical LE encoding
- Two books: `BTreeBook`, `VecBook` — identical receipts in tests
- Replay + adversarial + proptest
- Percentiles: [`docs/benchmarks/m1-clob.md`](docs/benchmarks/m1-clob.md)

**Pass:** identical inputs → byte-identical root, fills, delta (`cargo test --workspace`).  
**Fail condition not hit:** no networking/RFQ/Malachite in this crate.

**Milestone M1b — Adversarial order tests (done with M1)**

- Malformed / duplicate / replay / lot-tick / expiry in `crates/clob/tests/adversarial.rs`
- Property test: random ops, both backends, two replays

**Pass:** no panic on the generated corpus; rejects are deterministic.

---

## Phase 2 — Four-node replication (no BFT yet)

**Milestone M2 — Identical-input replica (done 2026-09-30)**

- Crates: `storage` (append-only XChaCha20-Poly1305 WAL), `replica` (WAL then `apply`)
- Four local processes (`parallax-replica`) and four in-process replicas; same ordered `I`
- Compare root, fills, settlement; injected sleep does not change them
- ADR: [`docs/adr/0007-encrypted-wal.md`](docs/adr/0007-encrypted-wal.md)
- Evidence: [`docs/benchmarks/m2-replica.md`](docs/benchmarks/m2-replica.md)

**Pass:** all four agree after crash/replay/delay (`cargo test --workspace`).  
**Fail condition not hit:** this is not called consensus.

**Milestone M2b — Durability attacks (done with M2)**

- Kill during match (WAL complete, `apply` skipped; restart replays)
- Truncate WAL (incomplete tail detected, discarded, prefix replayed)
- Corrupt bytes (open refused)

**Pass:** truncate/corrupt are visible; a flipped byte is not skipped.

---

## Phase 3 — Selective disclosure experiment

**Milestone M3 — Unequal views (done 2026-09-30)**

Four labelled projections of the same committed height (`crates/disclosure`):

| Node | View |
|---|---|
| A | FULL_VIEW |
| B | TRADING_VIEW |
| C | PUBLIC_VIEW (commitments only) |
| D | COMPLIANCE_VIEW |

**Pass:** Q-CONS-3 is **no**. Honest prevote for execution validity is `FULL_VIEW` only. Same `C'`, naive TRADING matching disagrees with full-view validity. ADR [0008](docs/adr/0008-unequal-view-validity.md). Evidence: [`docs/benchmarks/m3-views.md`](docs/benchmarks/m3-views.md).

**Fail condition not hit:** no Merkle/`π` invented to make `valid(v)` look shared.

**Stop-the-line:** do not proceed to Phase 4 as if Malachite `valid(v)` held for all four. Execution-validity safety is the full-view replica(s) until Q-CONS-4 / `π`.

---

## Phase 4 — Malachite

**Milestone M4a — Four full-view validators (ADR 0009)** (done 2026-09-30)

- Pin: Malachite **v0.8.0** (`circlefin/malachite` git tag). crates.io is still `0.7.0-pre`.
- `crates/consensus-adapter`: `Context::Value` is `ConsensusValue` (`id(v)` = BLAKE3 `plx/cons/value/v1`). Not `TestContext`'s `u64`, not Engine API.
- `app-channel` `EngineBuilder` + `AppMsg` loop. `Validate` replays `F`. Replica WAL/`F` only on decide. Missing `I` → engine `Invalid` (prevote nil).
- Four localhost TCP validators, broadcast pubsub. Evidence: [`docs/benchmarks/m4a-adapter.md`](docs/benchmarks/m4a-adapter.md).

**Fail condition not hit:** Engine API is not the value; Arc is not the app; TRADING/PUBLIC/COMPLIANCE are not voters. Decide is not `π`.

**Milestone M4b — Scale** (done 2026-09-30)

Same test at 7, 10, 20, 50, 100 localhost validators. Percentiles: [`docs/benchmarks/m4b-scale.md`](docs/benchmarks/m4b-scale.md). Did **not** match Malachite’s ~780 ms / 100 / 1 MB (tiny `ConsensusValue`, broadcast, one machine; n=100 cluster ~178 s). Isolate: [`docs/benchmarks/m4-isolate.md`](docs/benchmarks/m4-isolate.md) — n=20 dummy ≈ full cell (both runs); n=50 GossipSub ~1.7–2.0 s vs broadcast ~4.4–4.7 s; n=100 still minutes on 14 cores.

**Milestone M4c — Transport** (done 2026-09-30)

QUIC vs TCP on the same broadcast mesh. Measure, do not assume. Evidence: [`docs/benchmarks/m4c-transport.md`](docs/benchmarks/m4c-transport.md). QUIC is not faster on localhost. `I` is still out of band.

**Pass:** honest nodes never finalize two values; they never prevote without required fragments.  
**Fail condition not hit:** Engine API is not the value type; Arc is not the app.

---

## Phase 5 — Reth settlement

**Milestone M5 — Atomic delta apply** (done 2026-09-30)

- `crates/evm-adapter`: Engine API **adapter** (in-process ledger). Not ExEx. Not Malachite `Value`.
- Privileged batch `new_payload` of `SettlementDelta` (one per height). `eth_get_balance`; no `eth_sendRawTransaction`.
- Separate apply log. Crash after intent is not settled. Evidence: [`docs/benchmarks/m5-settlement.md`](docs/benchmarks/m5-settlement.md). ADR [0010](docs/adr/0010-m5-privileged-apply.md).

**Pass:** a height is locally valid iff `settlement_commitment` matches the deltas and both the PSE root and the settlement root match the apply.  
**Fail condition not hit:** CLOB-in-ExEx; per-order EVM txs; shared replica WAL.

Live Reth JWT/IPC is not shipped; the trait/shape is the seam.

---

## Phase 6 — Asynchronous proofs

**Milestone M6a — Tiny transition benchmark** (done 2026-09-30)

Same tiny `F` on **Plonky3, RISC Zero, and SP1**. Numbers: [`docs/benchmarks/m6-prove.md`](docs/benchmarks/m6-prove.md). No popularity pick. Not height `π`. RISC Zero/SP1 live in `zkvm/` (not `cargo test --workspace`).

**Milestone M6b — Policy for missing `π`** (done 2026-09-30)

ADR [0011](docs/adr/0011-missing-pi-settlement-inert.md). `crates/proof-adapter`: commitment-final, **settlement inert** until verified `π` or a full-view certificate. Decide is not rolled back.

Q-PRF-6: Model III remains the **validity** endgame. A full-view certificate unlocks money for that replica; it is not light-client validity.

**Pass:** we know what happens when proving fails, and we have not confused Malachite decide with world-computer validity. Three stacks measured the same fragment.  
**Fail condition not hit:** “the prover will just work.” Mock receipts were not shipped. Tiny-`F` STARKs are not height `π`. No stack was picked.

**Research defaults after M6 (not a new phase):** ADR [0012](docs/adr/0012-height-batch-wal.md) height-batch WAL; ADR [0013](docs/adr/0013-treap-is-c.md) treap is `C'`; ADR [0014](docs/adr/0014-height-blob-wal.md) one WAL blob per tape; ADR [0015](docs/adr/0015-sequenced-i.md) shared sequenced `I` (not a mempool); ADR [0016](docs/adr/0016-intent-set.md) replicated intent set seals `I`; ADR [0017](docs/adr/0017-intent-gossip.md) localhost intent gossip; ADR [0018](docs/adr/0018-per-height-offer.md) per-height `offer`; ADR [0019](docs/adr/0019-gossip-spread.md) `gossip_spread` ≠ `ready_delay`; ADR [0020](docs/adr/0020-quiesce-after-offer.md) quiesce after first offer; ADR [0021](docs/adr/0021-ack-id-set.md) ACK of `id(set)`. ADR [0022](docs/adr/0022-treap-step-witness.md) treap step witness: a general `C'` change is checked from one search path (plus two spines for remove), not a fixture-shaped trace. ADR [0023](docs/adr/0023-general-c-prime-on-zkvm.md) general `C'` on RISC Zero: any op tape proves in a guest that runs that checker; a height is chunk receipts plus a recursive join (224 KB, ~10 ms verify). Loaded 10k projects to ~93 CPU-hours on an M4 Pro CPU. Still not `F`. ADR [0024](docs/adr/0024-sha256-c-prime.md) `C'` hashes with SHA-256 (hardware SHA natively, accelerated in zkVM guests): ~36 CPU-hours projected; BLAKE3 is kept as `C'` v1 for the Plonky3 circuits. ADR [0025](docs/adr/0025-pi-of-f-on-zkvm.md) **`π` of `F`**: a RISC Zero guest rebuilds the engine from a canonical snapshot and runs the real matcher; its receipt matches `HeightStatement` and **unlocks `SettlementGate`** (`Risc0FVerifier`, feature `risc0`). Real proofs: crossing height 19 s, 1 000 resting + 8 events ~22 min (CPU). ADR [0026](docs/adr/0026-derived-order-ids.md) **derived order ids** (`H(owner, nonce)`) retire the ever-growing seen set, so proof cost no longer grows with history. Guest trimming (2026-10-17) cut rebuild and per-event cost ~45%; loaded 10k projects to ~10–11 CPU-hours. ADR [0027](docs/adr/0027-intent-target-height.md) intents carry a target height, fixing a gossip seal race that stalled ~3 / 8 localhost runs (Q-CONS-11). ADR [0028](docs/adr/0028-e2e-proof-pipeline.md) **end-to-end `π` pipeline**: a local cluster decides heights, a FULL_VIEW follower writes proof jobs, a separate RISC Zero prover answers, and every height settles only through `SettlementGate` on its receipt (small heights ~1 min to prove on CPU). Loaded Malachite height: [`docs/benchmarks/m4-loaded.md`](docs/benchmarks/m4-loaded.md) (n=4, 8k+10k; injected **~0.17–0.19 s** after hash-once `tape()`). Gossip `offer`: [`docs/benchmarks/m4-loaded-gossip.md`](docs/benchmarks/m4-loaded-gossip.md) (in-flight wait later last p50 ~192–202 ms / ~50–52k). Gap: [`docs/benchmarks/m4-started-gap.md`](docs/benchmarks/m4-started-gap.md). Isolate: [`docs/benchmarks/m4-loaded-isolate.md`](docs/benchmarks/m4-loaded-isolate.md).

---

## Phase 7 — PQ hybrid

**Milestone M7** (done 2026-10-24, ADR [0030](docs/adr/0030-pq-hybrid-suites.md))

- `CryptoSuite` / `AlgorithmId` on the wire: `protocol_types::{AlgorithmId, CryptoSuiteId}` (`ClassicalV0`, `HybridV1`).
- Experimental hybrid auth: `crates/crypto-suite`, Ed25519 **and** ML-DSA-65, both must verify; suite inside the signed bytes. Malachite votes and proposals sign under a `SuitePolicy` (`ClusterSpec::hybrid()`).
- ML-KEM on a private channel: intent gossip over an X25519 + ML-KEM-768 handshake, transcript signed by validator keys, frames sealed with XChaCha20-Poly1305 (`with_secure_gossip()`).
- Benchmarks: hybrid sign 64 µs / verify 73 µs / sig 3 379 B; handshake 0.74 ms / 13 KB; localhost consensus latency unchanged within noise; computed vote bandwidth +65.8 MB per height at n=100 (no ML-DSA aggregation, Q-CRY-5).
- Downgrade tests: classical signatures, stripped/relabelled hybrids, 2-of-4 classical quorum, classical or MITM-stripped handshakes, all rejected.

Follow-ups (2026-10-25): ADR [0033](docs/adr/0033-signed-orders.md) signed orders (accounts are suite keys; hybrid checked at admission); ADR [0034](docs/adr/0034-pq-tunnel-under-libp2p.md) hybrid tunnel under Malachite's libp2p. ADR [0032](docs/adr/0032-lazy-c-prime-and-guest-hashing.md) (proving): lazy `C'` + SHA-256 order ids cut a loaded 10k `π` 634 M → 212 M cycles (~3.5–4 CPU-hours).

Follow-up (2026-10-24): ADR [0031](docs/adr/0031-tiered-finality.md) **tiered finality** for Q-CRY-5: classical votes for ordering, one hybrid finality signature per validator per height to k collectors, 2f+1 certificate gates settlement. 4–14× fewer consensus bytes than hybrid votes at n ≤ 20 ([q-cry-5-wire](docs/benchmarks/q-cry-5-wire.md)).

**Pass:** classical-only path still works (default; whole workspace runs classical); downgrade is rejected.  
**Fail condition not hit:** we do not claim the network is post-quantum secure. The libp2p transport is still classical, Malachite's 1 KiB validator-proof cap skips the proof for hybrid keys, and accounts, WAL, hashes, `π` and settlement are untouched.

---

## Explicitly later / not scheduled

- RFQ, auction, transfer, compliance engines (names only)
- External DA L1 (public-tier DAS *technique* may still appear as Q-DA-6 without a DA chain)
- Enclaves / APS-like pEVM
- FOCIL-like inclusion, mixnets, PIR (research questions; not M1)
- Slashing implementation
- Mainnet, token, genesis economics
- Production audit

---

## Documentation cadence

Every milestone updates `ARCHITECTURE.md`, the relevant model doc, `open-questions.md`, and adds an ADR when a question is closed. Benchmark numbers go in `docs/benchmarks/` (create when numbers exist).
