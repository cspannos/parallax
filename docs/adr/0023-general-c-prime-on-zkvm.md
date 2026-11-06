# ADR 0023 — General `C'` proofs run on the zkVM

**Status:** Accepted as the **research default for a general `C'` proof**; not a stack pick for `π`  
**Date:** 2026-10-15  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0022](0022-treap-step-witness.md) (treap step witness), [0013](0013-treap-is-c.md) (treap is `C'`).  
**Does not implement:** `F` (matching), GPU proving, a Groth16 wrap, Plonky3 of the general step.

## Context

ADR 0022 reduced any `C'` change to a [`TreapStep`](../../crates/commitments/src/treap_witness.rs). Two ways to prove it:

1. **A hand-written Plonky3 AIR.** In this preimage layout every field is byte-misaligned with the AIR's 16-bit limbs: children at bytes 19/83, the OrderId key at byte 59. So every child slot and key needs bit decomposition. The search path needs in-circuit lexicographic key comparison. Insert and merge need 64-bit priority comparison. `p3-uni-stark` 0.6 has no lookups and no recursion. The fixture work (ADR 0022 context) showed what that costs.
2. **The zkVM guest runs `TreapStep::verify` itself.** It is general on day one (any book, any op mix). RISC Zero has recursion (assumptions, succinct receipts), so a height can be chunked and joined.

## Decision

- [`IncTape`](../../crates/commitments/src/inc_tape.rs) is the statement: the pre INC header plus three map roots, `(map, TreapStep)` in apply order, and the post header. `verify` returns `pre_root`, `post_root` and an op-list commitment. `clob::start_inc_step_trace` records it from any engine run.
- The RISC Zero guest `inc_tape` ([`zkvm/risc0/methods/tape`](../../zkvm/risc0/methods/tape/src/main.rs)) runs `IncTape::verify` from the real `commitments` crate (no copy) and commits `pre_root ‖ post_root ‖ ops ‖ steps`.
- A height is **chunks + join**: each chunk tape is proven (succinct); the `inc_join` guest verifies every chunk receipt as an assumption, requires chunk roots to chain, and commits `tape_id ‖ first pre ‖ last post ‖ ops ‖ steps ‖ chunks`. Chunks are independent, so they can be proven in parallel.

## Measurements

Apple M4 Pro, **CPU prover** (`r0vm`, RISC Zero 3.0.6). The Metal GPU prover needs full Xcode (the `metal` compiler); this host has Command Line Tools only. 8k book, `churn_tape` mixed events. Commands: [`zkvm/README.md`](../../zkvm/README.md).

| Cell | Map steps | Node / prio hashes | Guest cycles | Prove | Receipt | Verify |
|---|---|---|---|---|---|---|
| One Place | 3 | 89 / 8 | 0.76 M (1 segment) | ~60–62 s | 282 KB composite, 223 KB succinct | ~10 ms |
| 8 mixed events (execute) | 22 | 498 / 42 | 4.2 M (5 segments) | — | — | — |
| 64 mixed events (execute) | 176 | 4 148 / 305 | 34.8 M (37 segments) | — | — | — |
| Height: 3 chunks × 4 events + join | 33 | — | 7.9 M chunks + 0.13 M join | chunks ~156 / 158 / 203 s, **join ~30 s** | **224 KB** succinct | **~10 ms** |
| Height: 3 chunks × 1 event + join | 9 | — | 3.1 M chunks + 0.13 M join | chunks ~59–61 s each, **join ~28 s** | **224 KB** succinct | **~9 ms** |

The join receipt's journal equals the engine's `C` before the first event and `C'` after the last. With the real chunk receipts attached, re-executing the join on **swapped**, **dropped** or **forged** chunk journals fails.

Guest cycles per hash ([`hashbench`](../../zkvm/risc0/methods/hashbench/src/main.rs), 64 reps):

| Preimage | BLAKE3 (software) | SHA-256 (accelerated) |
|---|---|---|
| 33 B (OrderId prio) | 2 072 | 404 |
| 49 B (OwnerId prio) | 2 084 | 403 |
| 115 B (seen node) | 3 678 | 536 |
| 139 B (nonce node) | 5 229 | 586 |
| 216 B (resting node) | 6 815 | 658 |

**Loaded 10k height (projection, not run):** 27 500 map steps, 674 389 node + 43 092 prio hashes, 50 MB witness. Scaling the 64-event cell gives **~5.7 × 10⁹ cycles ≈ 5 400 segments ≈ ~93 CPU-hours** on this host, plus a join tree. Chunks are independent, so wall-clock time divides by the number of provers. Hashing is ~⅔ of guest cycles today, so swapping BLAKE3 for an accelerated hash cuts the total ~2–3×, not 10×, unless the rest of the guest is optimised too.

**Q-PRF-7 check (SHA-256 `C'` mode, not the default):** with `PLX_HASH=sha256` and the RISC Zero `sha2` fork patched into the tape guest, one Place is **254K cycles** (vs 759K) and proves in **~32 s** succinct (vs ~62 s); 64 mixed events are **13.4M cycles** (vs 35.1M, 2.6×). The journal still equals the engine's (SHA-256) `C` / `C'`. Natively, with ARMv8 SHA instructions, the loaded 10k apply is **57 ms** vs 99 ms for BLAKE3. See [open-questions Q-PRF-7](../open-questions.md).

## Consequences

- `C'` of any height now has a proof path that does not depend on a fixture. The open gap is **`F`**: the ops are committed, not derived from `I` by the matcher.
- The bottleneck is guest BLAKE3 in software. See the hash measurement above; changing `C'` to an accelerated hash would be a new ADR amending 0013.
- Plonky3 stays the fast path for fixed-shape statements. A general Plonky3 treap AIR is not ruled out, but it is not the default.

## Security implications

The same induction as ADR 0022: the first chunk's `pre_root` must be a root reached by proven steps (or genesis). The join verifier must check `tape_id` equals the `inc_tape` image ID. Without that, a receipt from another guest could stand in for a chunk. The CPU prover with `disable-dev-mode` is real; `RISC0_DEV_MODE=1` is refused.

## Reversibility

High. A guest and a witness format. No wire change.
