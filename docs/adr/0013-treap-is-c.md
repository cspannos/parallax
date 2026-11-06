# ADR 0013 — Treap is `C'` (Q-CRY-2)

**Status:** Accepted as the **consensus state root research default**; **hash amended by [0024](0024-sha256-c-prime.md)** (SHA-256; BLAKE3 is `C'` v1)  
**Date:** 2026-10-01  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0006](0006-m1-clob-invariants.md) commitment encoding for `ConsensusValue.state_root` / replica `state_root`. Full-walk Blake3 remains available as `full_walk_root()` (not `id(v)`).

## Context

M1 committed state with a full Blake3 walk of resting orders. At 8k resting that is **~3 ms/apply** (~300 ev/s). A deterministic BLAKE3 **treap** (priority = hash of key; shape depends on the set, not insertion order) is **~24 µs** per mutation and **~40k ev/s** on a mixed 10k tape ([`q-cry-2-incremental.md`](../benchmarks/q-cry-2-incremental.md), [`loaded-batch.md`](../benchmarks/loaded-batch.md)).

`Validate` clones the engine and replays `I`. If `state_root` is still the walk, a loaded height remeasures ~330 ev/s. The treap was an experiment (`INC_DOMAIN`). This ADR makes it **`C'`**.

## Decision

- **`Engine::state_root()`** is the incremental treap forest (`plx/clob/inc/v1`): height, `next_time`, instruments digest, nonce map, seen-id map, resting leaves. Resting leaf encoding is unchanged (`RESTING` tag + fields).
- **`incremental_on_apply` defaults true.** Mutations keep the treap in lockstep. Matcher-only benches may turn it off (and `commit_on_apply`).
- **`full_walk_root()`** is the old O(n) encoding (`plx/clob/state/v1`). Not on `ConsensusValue`. Not a second vote.
- Receipts that commit (`commit_on_apply`) carry the treap root.
- Replay of WAL'd `I` rebuilds the same `C'` (set commitment). Old full-walk transcripts are a different byte string; this is a **versioned protocol change**, not a silent alias.

This is still **not** `π`, not Merkle openings for `TRADING_VIEW` (ADR 0008), not a pick of SMT vs treap vs MMR as the final product scheme.

## Alternatives

| Option | Why not |
|---|---|
| Keep walk as `C'` | Loaded `Validate` cannot carry 10k-event heights |
| Dual-hash and vote both | Bigger `Value`; walk still paid |
| Sparse Merkle / JMT | Not measured; treap is the measured O(log n) set hash |

## Consequences

M1/M2 **equality** tests still hold (identical `I` → identical `C'`). Golden full-walk bytes do not. `GetValue`/`Validate` pay clone + treap updates, not a walk of 8k–32k leaves.

## Security implications

A bug in split/merge can fork roots without forking the book. Tests: insertion-order independence; live updates vs rebuild. Binding is still BLAKE3. Not a validity proof.

## Performance implications

Consensus `C'` is O(log n) per input. Matcher-only microbenches must disable the treap or they measure ~24 µs instead of ~200 ns.

## Reversibility

Medium after WAL transcripts exist. Reverting to the walk is an encoding version bump. Switching to another incremental map is a new ADR.
