# ADR 0028 — End-to-end `π` pipeline

**Status:** Accepted as the **research default for wiring validity proofs to settlement**  
**Date:** 2026-10-22  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0011](0011-missing-pi-settlement-inert.md) (settlement inert until `π`), [0025](0025-pi-of-f-on-zkvm.md) (`π` of `F` on RISC Zero), [0027](0027-intent-target-height.md) (deterministic `I`).  
**Does not implement:** a distributed or GPU prover, proposer-included `π`, proof DA for light clients, retry or failover policy.

## Context

Every piece of Model III existed, but separately. Validators decided heights; the RISC Zero guest proved `F` from a snapshot; `SettlementGate<Risc0FVerifier>` unlocked settlement on a receipt. The gate test used a stored fixture. Nothing turned a decided height into a proof, or a proof into settlement.

## Decision

Three roles, connected by a directory of files:

1. **Validators** decide heights as before. With `AppOpts::emit_inputs`, each `Decision` also carries the sealed `I(h)` (off by default, so latency benches do not pay for cloning large tapes).
2. **Follower** ([`settlement-pipeline`](../../crates/settlement-pipeline/src/lib.rs)): a FULL_VIEW replica of the settlement operator. Per decided height it:
   - builds the `HeightStatement` from its own pre-state and requires it to bind the decided value (its own `F` must reproduce `state_root`, `input_commitment` and `settlement_commitment`)
   - snapshots the pre-state
   - writes an [`FJob`](../../crates/clob/src/snapshot.rs) (statement + snapshot + `I`)
   - applies `I`
3. **Prover** ([`zkvm/risc0/host/src/bin/prover.rs`](../../zkvm/risc0/host/src/bin/prover.rs)): a separate process in the zkVM workspace. It proves each job in height order with `f_guest` (succinct), checks the journal against the job's statement, and writes the receipt atomically.

When a receipt lands, the follower passes it to `SettlementGate<Risc0FVerifier>`. Until then the height is decided but **inert** (`MissingWitness`).

The job directory (`jobs/`, `receipts/`, tmp-then-rename) is a stand-in for a queue. It keeps the prover a separate service, with its own workspace and hardware, as a GPU or remote prover would be.

## Measurements

`cargo run --release -p settlement-pipeline --features risc0 --bin e2e` (Apple M4 Pro, CPU prover). Four validators with intent gossip, 20 resting orders, a wave of 8 mixed events at each seal (height 1 empty), three loaded heights:

| Height | `I` | Deltas | Prove (prover) | Decide → settled | Outcome |
|---|---|---|---|---|---|
| 1 | 0 | 0 | 32.2 s (0.52 M cycles, 1 segment) | 32.5 s | settled by `π` |
| 2 | 8 | 8 | 63.6 s (1.05 M cycles, 1 segment) | 96.0 s | settled by `π` |
| 3 | 8 | 8 | 60.7 s | 156.6 s | settled by `π` |
| 4 | 8 | 8 | 61.4 s | 218.1 s | settled by `π` |

- Every height was **inert** right after decide (`MissingWitness`), and settled only when its receipt verified.
- Jobs were written 2–14 ms after decide.
- The taker's base balance moved 1 000 000 000 → 999 999 994.
- Decide → settled grows by ~one prove time per height: the cluster decided all four in seconds, while the single in-order prover takes ~1 min each. That is queueing, not pipeline overhead.

Tests: follower jobs reproduce the decided statements over 4 heights (native `run_f`); the follower rejects a value its `F` cannot reproduce and out-of-order heights; the gate test (ADR 0025) covers wrong-height, wrong-image and tampered receipts. The workspace passes 448 / 448, and 101 / 101 with `risc0`.

## Consequences

- Settlement latency is **decide + prove**. On this CPU a small height (20 resting orders, 8 events) takes ~1 min to prove; a loaded 10k height projects to ~10–11 CPU-hours (ADR 0025). The pipeline is unchanged by a faster prover: only the `prover` process moves.
- The prover works in height order, and settlement applies heights in order (the settlement log chains payloads). One slow height delays every later settlement. Parallel provers with an in-order settler are the obvious next step.
- The follower trusts nothing from the prover except the receipt: the gate verifies it against the follower's own statement.
- **Image ID:** the demo reads the prover's `f_guest.id`. A deployment must pin the image ID in configuration (the network's `clob` build), not take it from the prover.

## Reversibility

High. Additive: an opt-in decision field, a new crate and a prover binary.

## Finality certificate (2026-10-25)

The demo now runs tiered finality by default (ADR [0031](0031-tiered-finality.md), `PLX_PIPE_TIERED=0` to disable). A height settles only with its receipt **and** a 2f+1 hybrid finality certificate fetched from the validators. The certificate arrives within ~60 ms of decide, so settlement latency is still decide + prove.

## Parallel provers (2026-10-22)

Any number of `prover` processes can share one job directory. A worker claims the lowest pending job by atomically renaming `jobs/<h>.job` to `jobs/claimed/<h>.<worker>`, so each job is proven exactly once with no coordinator, on one host or many. The settler still applies heights strictly in order, so a receipt that lands early waits for its predecessors. `PLX_PIPE_PROVERS=N` starts N workers in the demo. A worker that dies mid-proof leaves its claim behind; reclaiming is not implemented.

Seven heights (20 resting, 8 events per loaded height), same host:

| | 1 prover | 2 provers |
|---|---|---|
| Per proof | ~60 s | ~120 s (alternating w0 / w1) |
| First decide → last settled | 397.2 s | 392.5 s |

**No gain on one host**: the RISC Zero CPU prover already uses all 14 cores, so a second process halves each one's share. The mechanism is in place for provers on separate machines or GPUs, where N provers cut the queue by about N. Measuring that needs a second host. (A shared tmp-file name in `write_atomic` crashed one of two workers at start; tmp names are now per process.)

### Emulated two machines (cores capped per prover, 2026-10-23)

`PLX_PIPE_THREADS=7` sets `RAYON_NUM_THREADS` for each prover, to emulate N 7-core machines on the 14-core host. Same 7 heights:

| 7 cores per prover | 1 prover | 2 provers |
|---|---|---|
| Per proof | ~91.5 s | ~117 s |
| Queue growth per height | ~91 s | ~58 s |
| First decide → last settled | 595.9 s | **394.4 s (1.51×)** |

The scheduler and claims behave as intended: workers alternate, each job is proven once, and settlement is in order. The shortfall from 2× is shared hardware: memory bandwidth, and only 10 performance cores for two 7-thread provers, so each proof slowed from 91.5 to 117 s. Two provers × 7 cores (394 s) ≈ one prover × 14 cores (397 s): a single host's throughput is fixed. On separate machines each prover keeps its solo speed, so near-2× is expected but not yet measured.

