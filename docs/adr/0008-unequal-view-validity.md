# ADR 0008 — Unequal views do not share `valid(v)` (Phase 3)

**Status:** Accepted  
**Date:** 2026-09-30  
**Deciders:** Protocol architecture (research prototype)

## Context

Malachite requires identical deterministic `valid(v)` among correct processes. The privacy model gives validators different plaintext (`FULL_VIEW`, `TRADING_VIEW`, `PUBLIC_VIEW`, `COMPLIANCE_VIEW`). Q-CONS-3 asks whether those nodes can still implement the same `valid(v)` **without** a validity proof.

Phase 1–2 showed Model I among replicas that share ordered inputs and the full book. Phase 3 withholds fields from the same committed height. Capabilities in this experiment are **labels on a projector that already holds full state** (Q-DIS-1). They are not keys, IBE, or Merkle openings.

## Decision

**Q-CONS-3 is no** for this view taxonomy, this `F`, and no `π`.

Evidence: `crates/disclosure` (`cargo test -p disclosure`). Corpus: same-owner rest-cross (STP) plus a real two-owner fill. Public bundle `C'` is identical for all four nodes.

| Node | Honest prevote (ADR 0005) | Naive check on visible fields |
|---|---|---|
| A `FULL_VIEW` | `Valid` (replay `F`, root matches `C'`) | `Valid` |
| B `TRADING_VIEW` | `InsufficientView` (no owner, no time) | `Invalid` (visible book looks crossed) |
| C `PUBLIC_VIEW` | `InsufficientView` (commitments only; no `π`) | `InsufficientView` |
| D `COMPLIANCE_VIEW` | `InsufficientView` (no price, no side) | `InsufficientView` |

A and B can accept the same `C'` while disagreeing on validity of `S'` if B votes on a naive matching check. Honest B does not prevote.

Further:

- `TRADING_VIEW` as specified is **not** enough to verify price-time matching of the full book (Q-DIS-4). It lacks owner (STP) and time (FIFO).
- Jurisdiction / compliance metadata are **not on the M1 order**. `COMPLIANCE_VIEW` cannot enforce them; neither can `FULL_VIEW`. That is `NotInSchema`, not a passing compliance check.
- Hashing a redacted view is **not** `C'`. This ADR does not introduce view-specific commitments or openings.

### What this does to the safety set

Execution-validity (matching, STP, owner/nonce, “`C' = Commit(F(S, I))`”) is a **`FULL_VIEW` predicate**. Nodes B, C, D are not in that safety set.

They may still check **public** predicates on the bundle (height, parent, suite, “I have these 32 bytes”) in Phase 4. That is a **different** `valid(v)` than execution validity. Do not collapse them.

Q-CONS-4 remains open: whether the product is a full-view committee, or Model III (`π` of a public statement). This ADR does **not** pick. A committee is not SNARK validity (Q-PRF-6).

Model I remains true **among `FULL_VIEW` replicas** (Phase 1–2). It is not true across the four views. Model II / III are not selected here (Q-CLOB-1).

### Phase 4 stop-the-line

Do not wire Malachite so that B, C, and D `Validate` the book. Honest execution-validity without the required fields is `InsufficientView` → prevote nil (ADR 0005). If the consensus set includes unequal views, the set that can validate matching is smaller than the voting set unless `π` exists.

## Alternatives (rejected in this patch)

| Option | Why not |
|---|---|
| Merkle openings so B can prove matching | Invents a protocol to make Q-CONS-3 look like yes. Q-DIS-3 / Q-CRY-2 stay open. |
| Give every validator `FULL_VIEW` and call it privacy | Privacy vs the public only; not the Phase 3 experiment. |
| Treat `C'` as `valid(v)` for everyone | Finalizes a commitment without checking `F`. ADR 0003 already forbids calling that execution validity. |
| Cryptographic capabilities in the same change | Q-DIS-1. Labels were enough to measure. Keys do not by themselves make `valid(v)` identical. |

## Consequences

Phase 4 adapter must split public checks from private `F`. Selective disclosure among **consensus** replicas is not compatible with a single plaintext `Validate`. The next architecture choice is Q-CONS-4 / Q-PRF-6, not “tweak the views until they agree.”

## Security implications

A naive TRADING replica that votes `Invalid` on a legal STP book can stall liveness or, if treated as the safety set, split from full-view replicas. A PUBLIC replica that votes `Valid` on `C'` alone accepts unavailable/unverified private state (ADR 0005).

The projector that redacts is a **full-view trust assumption**. Process isolation of B/C/D is not demonstrated; authorization is modelled, not cryptographically enforced.

## Performance implications

None claimed. Full BLAKE3 walk unchanged (Q-CRY-2 still open).

## Reversibility

High until Phase 4 ships unequal-view validators. Reversing the finding would require a real `π` or a documented full-view committee — a new ADR, not an edit of this one to “yes.”
