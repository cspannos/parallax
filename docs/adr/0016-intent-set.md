# ADR 0016 — Replicated intent set produces `I`

**Amended by:** [0027](0027-intent-target-height.md) (intents carry a target height; `id(set)` covers only the next seal).  
**Status:** Accepted as the **research default for how the shared tape is produced**, not the product  
**Date:** 2026-10-02  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0015](0015-sequenced-i.md) remainder (“protocol that produces the tape”).  
**Does not implement:** gossip, a WAN mempool, FOCIL, or a dedicated sequencer.

## Context

ADR 0015: among M4a voters, `I` is shared before `GetValue`. The loaded height still **injects** the same `Vec<Input>` into every `EngineApp`. That is not a production path.

Three ways to *produce* a shared tape:

| Path | Order | Omission |
|---|---|---|
| Malachite proposer packs `I` | Proposer’s list | Time-priority fraud (rejected as default) |
| Dedicated sequencer / FOCIL | That gadget’s list | Remainder |
| Replicated **set**, sealed at height start | Canonical function of the set | An intent every honest voter offered cannot be dropped without a different `input_commitment` |

Arrival order is **not** deterministic across replicas. A CLOB still needs a total order on `I` (fills depend on it) and per-owner nonces must stay increasing or `F` rejects.

## Decision

**Research default:** each full-view replica holds an [`IntentLog`](../../crates/consensus-adapter/src/intent_log.rs).

1. **Offer** is membership in a set, keyed by `id(intent)` = BLAKE3 of canonical `Input` (`plx/intent/id/v1`). Duplicates collapse. A sealed id is **spent**: late gossip of the same intent does not enter a later height.
2. **Seal** at height start emits `I`: sort by **`(owner, nonce, kind, id(intent))`**. Places before cancels before `AdvanceHeight` at the same owner/nonce. `AdvanceHeight` uses owner `0`.
3. **No view** (`IntentLog` hidden) is `InsufficientView` (ADR 0005 / 0009).
4. `GetValue` / speculate / `Validate` / decide read the **sealed** tape, not a proposer-private list.

Per-owner nonce order is preserved. **Cross-owner order is not wall-clock FIFO.** It is owner-id order. Time-priority of *matching* is still `time_seq` inside `F` given that `I`. Time-priority of *submission across owners* is this canonical rule, not arrival. Say that; do not call this FOCIL or price-time of the mempool.

Tests and benches may still **offer the same set to every replica** (localhost injector) with gossip off. That is “everyone saw the gossip,” not a network. **How the set is shared (first cut):** localhost TCP fan-out of canonical `Input` (ADR [0017](0017-intent-gossip.md)). WAN / encryption / anti-eclipse / FOCIL remain remainder.

Height > 1 with no new offers seals **empty** `I` (pending was already consumed). Offers after seal wait for the next height.

## Alternatives

| Option | Why not as this default |
|---|---|
| Preserve injector order | That is out-of-band sequencing (status quo) |
| Sort only by `id(intent)` | Can invert per-owner nonces; `F` rejects |
| Sequencer process now | One-builder inclusion; new trust; not measured |
| FOCIL now | Unspecified; rotation is still not inclusion |

## Consequences

`EngineApp` no longer stores a raw `Option<Vec<Input>>` as the height tape. It offers into `IntentLog` and seals. Opposite offer order → same `I` → same `id(v)`.

Loaded 10k `churn_tape` will apply in **canonical** order, not the generator’s interleave. Same set, different permutation. Engine-only benches that call `apply_all(churn_tape)` are unchanged (they are not the log).

## Security implications

A proposer cannot commit to a subset of a set every voter already offered and collect honest execution prevotes. It can still stall (no proposal). Divergent sets (withhold, delay) → divergent `input_commitment` → no agreement on that value. FOCIL-class inclusion against a Byzantine inclusion majority is **not** claimed.

## Performance implications

Seal hashes each pending intent **once**, then O(|pending| log |pending|) compares of the precomputed key. Hashing `id(intent)` inside the comparator was n log n BLAKE3 and moved injected `F+wal` ~0.18 → ~0.25 s ([m4-started-gap](../benchmarks/m4-started-gap.md)). After the hash-once cut, isolate is back to **~0.17–0.19 s**. `F` still dominates.

## Reversibility

High. A sequencer or FOCIL ADR can replace `seal`’s order function. Hidden/open view stays.
