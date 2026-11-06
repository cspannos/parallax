# M3 unequal views — result (not a speed claim)

**Date:** 2026-09-30  
**Code:** `cargo test -p disclosure`  
**Corpus:** same-owner rest-cross (STP) + two-owner fill. Same public bundle `C'` for all four.

Capabilities are **labels**. A projector with full state redacts. This is not cryptographic isolation (Q-DIS-1).

## Honest prevote (ADR 0005)

| Node | View | Binding `C'` | Matching / STP / auth | Prevote |
|---|---|---|---|---|
| A | `FULL_VIEW` | Holds (replay `F`) | Holds | `Valid` |
| B | `TRADING_VIEW` | Insufficient | Insufficient (no owner, no time) | `InsufficientView` |
| C | `PUBLIC_VIEW` | Insufficient | Insufficient (no `π`) | `InsufficientView` |
| D | `COMPLIANCE_VIEW` | Insufficient | Insufficient (no price/side) | `InsufficientView` |

## Counterfactual (not a protocol)

If B treats a visible bid ≥ ask as illegal matching (ignoring withheld owner):

- A: `Valid`
- B: `Invalid`
- Same `C'`. Disagreement on validity of `S'`.

That is the Q-CONS-3 exhibit. Honest B does not prevote.

## Other findings

- Hashing the redacted trading book is not `C'`.
- Compliance jurisdiction fields are not on the M1 order (`NotInSchema` for every node).
- Q-DIS-4: `TRADING_VIEW` cannot verify price-time matching of the full book.

ADR: [`docs/adr/0008-unequal-view-validity.md`](../adr/0008-unequal-view-validity.md).
