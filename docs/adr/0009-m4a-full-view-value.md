# ADR 0009 — M4a research default: full-view set, minimal `Value`

**Status:** Accepted as the **M4a research default**, not the product  
**Date:** 2026-09-30  
**Deciders:** Protocol architecture (research prototype)

## Context

ADR 0008: unequal views cannot share execution `valid(v)` without `π`. Mixed-view Malachite at n=4 with `F` inside `Validate` does not liveness (one `FULL_VIEW` is not ⅔). Q-CONS-1 and Q-CONS-2 were still open, so the adapter had nothing to vote on and no prevote rule.

Three honest shapes exist (see the Phase 4 gate). This ADR picks one for the **first** Malachite bring-up.

## Decision

### Safety set (not Q-CONS-4 closed)

**M4a shape 1:** the Malachite set is **four `FULL_VIEW` replicas**. Every voter can replay `F`. `Validate` **includes** that check. `valid(v)` is identical because the set shares the view `F` needs.

This is a **research default**: prove the app-channel adapter with a real execution check. It is **not** the product.

Unequal-view consensus still needs one of:

- **Shape 2** — mixed views, `Validate` is public-bundle-only (`F` not in the vote), or
- a **full-view committee** large enough to be the safety set (Q-CONS-4), or
- **`π`** of a public statement (Q-PRF-6).

A four-node full-view cluster is a tiny committee. It is not SNARK validity. Do not describe M4a as “selective disclosure among validators.” Privacy in M4a is vs parties **outside** the set (and vs metadata), same as Phase 2.

TRADING / PUBLIC / COMPLIANCE nodes are **not** in the M4a voting set. `InsufficientView` remains on the port: if a listed voter lacks the book (crash, withhold), honest prevote is nil (ADR 0005). That is a fault, not a disclosure role.

### Q-CONS-1 — minimum `Value` to code

The consensus value is **not** the engine, not `ExecutionPayloadV3`, not the book.

M4a `Value` (canonical LE, tag `CVALUE\0\0`, `ENCODING_VERSION`):

| Field | Type | Meaning |
|---|---|---|
| `parent` | 32 bytes | `id(v)` of the previous value; genesis uses 32 zero bytes |
| `height` | `Height` | Engine / chain height for this transition |
| `state_root` | 32 bytes | `C'` — private state commitment after `F` |
| `input_commitment` | 32 bytes | Commitment to the ordered `I` applied at this height |
| `settlement_commitment` | 32 bytes | Commitment to `SettlementDelta` list (body not in the value) |

`id(v)` = domain-separated BLAKE3 of the canonical encoding (`plx/cons/value/v1` in `commitments`). The book is not gossiped.

**Not in M4a `Value`** (no check yet → do not add a field): `suite_id`, public EVM txs, `π` / proof commitment, DA commitment, vote extensions, plaintext orders, EVM state root, `SettlementDelta` bodies.

Those remain Q-CONS-1 remainder, Q-CONS-5, Q-CONS-8, Phase 5–6.

### Q-CONS-2 — before prevote vs after finality (shape 1)

**Before honest prevote** a voter must have:

1. The public `Value` (enough to compute `id(v)`).
2. The **book** required by shape 1: prior state `S` (WAL replay to `parent`) and the ordered `I` for this height, so it can run `F` and recompute `state_root`, `input_commitment`, and `settlement_commitment`.

If (1) is missing → cannot vote. If (1) is present and (2) is missing → `InsufficientView` → prevote nil, even though the node is labelled `FULL_VIEW`.

**After finality:** still **no `π`**. A decided `Value` is Malachite agreement on those bytes (ordering / preconfirmation of `C'`). It is **not** world-computer validity (ADR 0003, Vitalik 2030). Light clients cannot skip full-view re-execution yet.

## Alternatives

| Option | Why not for M4a |
|---|---|
| Shape 2 now (public `Validate` only) | Would measure BFT without testing `F` in the vote. Valid later; not the recommended first cut. |
| Shape 3 (mixed views + `F` in `Validate`) | Liveness-broken at n=4. Forbidden by ADR 0008. |
| Close Q-CONS-4 as “the product is a full-view committee” | Endgame vs committee is still open (Q-PRF-6). |
| Put `π` / DA / EVM txs in `Value` now | Fields without a `Validate` check. |
| Engine / Arc payload as `Value` | ADR 0001 / 0002. |

## Consequences

Phase 4 starts with `consensus-adapter`, this `Value`, four full-view processes, `Validate` = decode + parent/height + replay `F`. Malachite **v0.8.0** is git-pinned; `EngineBuilder` is linked. Fail if TRADING/PUBLIC/COMPLIANCE vote on the book, or if we call decide “valid execution.”

## Security implications

Honest majority of **full-view** voters can finalize a `C'` that a public observer cannot check. That is the Phase 1–2 trust model, now named. Proposer omission of `I` is unchanged (Q-CONS-10). Withholding `I` from a voter forces nil and can stall the height.

## Performance implications

Every prevote replays `F` and walks the full BLAKE3 state root (Q-CRY-2 still open). Do not cite M4a vote latency as matching latency.

## Reversibility

High until mixed-view or proof-carrying values ship. Switching M4a to shape 2 is an adapter change (`Validate` drops `F`). Switching the **product** to a committee or to `π` is a new ADR.
