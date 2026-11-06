# Privacy Model

**Status:** Living document  
**Date:** 2026-09-30

Privacy in this protocol is **not** a bit `public | private` on a transaction. It is a set of **information capabilities**.

This document states the intended model, the leakage we already accept, and the Phase 3 measurement (Q-CONS-3 is no). It does not claim a cryptographic construction.

## Capabilities

A capability is a declared set of fields plus the right to learn them for a defined object (order, fill, position, height).

| Capability | Fields (intent) | Typical holder |
|---|---|---|
| `FULL_VIEW` | instrument, side, quantity, price, owner, compliance metadata, constraints | Matching operator / designated full replica |
| `TRADING_VIEW` | instrument, side, quantity, price | Trading venue / some validators |
| `COMPLIANCE_VIEW` | owner, jurisdiction, compliance metadata, instrument, quantity | Compliance actor |
| `SETTLEMENT_VIEW` | resulting asset deltas | Settlement / EVM observers of public money |
| `PUBLIC_VIEW` | commitments only (`C`, transition commitment, settlement commitment, proofs) | Anyone |

Fields not listed are unauthorized. **Absence of a field is not a proof that the field is empty.**

These views are a starting taxonomy. **M3 implemented them as labels**, not keys (Q-DIS-1). `TRADING_VIEW` without owner is **not** enough to verify price-time matching of the full book (Q-DIS-4, confirmed). `COMPLIANCE_VIEW` cannot enforce jurisdiction: the field is not on the M1 order (Q-ORD-1).

## What privacy is not

- Encrypting an EVM transaction that every validator decrypts (Arc APS-style confidentiality-to-the-public).
- Hiding plaintext in logs while publishing the same data on a DA chain.
- A commitment. Commitments hide bytes; they do not define who may open them.
- A ZK proof. A proof can implement a view; it does not choose the policy.

## Consensus collision

Malachite requires identical deterministic `valid(v)` among correct processes. Capabilities that withhold fields required by `F` make that assumption false.

**Normative research rule:** if a capability withholds a field that `Validate` needs, a holder of only that capability **must not** be treated as a full consensus replica for that check. Either:

1. they vote only on public checks and proofs, or
2. they are not in the safety set for that predicate, or
3. the protocol is redesigned so `Validate` never needs the field.

Phase 3 exists to force this choice with evidence.

## Authorized leakage (accepted if documented)

Even a perfect field-level policy leaks:

- message sizes and rates (order-flow intensity)
- peer-set and timing (who talks to whom)
- public settlement deltas (if not netted or delayed)
- the fact that a height exists and that *some* private activity occurred
- proof sizes and proving latency
- capability-keyed subscriptions (who asked for COMPLIANCE_VIEW)
- **query metadata** unless reads are PIR/proof-based (Q-DIS-6); Vitalik 2030 treats private reads as a separate problem from private writes
- **network-layer metadata** (who talks to whom) unless the intent plane is mixnet-class (Q-DIS-5, Q-NET-5)

The privacy invariant in the research brief is therefore:

> A participant learns no plaintext **beyond its capability**, subject to **clearly documented metadata leakage**.

We will not claim “no leakage.”

## Unauthorized leakage (bugs)

- Plaintext in logs, metrics labels, or traces
- Using instrument ids as gossip topics
- Putting owner bytes in public `id(v)`
- Reusing nonces that allow linking
- Opening the wrong view because of a missing `AlgorithmId` / capability version

## Relationship to Arc Privacy Sector

APS (June 2026 whitepaper): private txs encrypted to a **network** key; **every** honest validator decrypts inside an enclave and re-executes the same pEVM; public sees an encrypted state root. Threat model is host OS + public observer + &lt;⅓ Byzantine validators. It does **not** give validators different plaintext views.

If Parallax ever adopts enclaves, that is a different ADR and a different privacy claim (confidentiality vs host, not vs peer validators).

## Phase 3 experiment (done 2026-09-30)

Four labelled projections of one committed height. Evidence: [`docs/benchmarks/m3-views.md`](benchmarks/m3-views.md), ADR [0008](adr/0008-unequal-view-validity.md).

| Node | Honest prevote | Notes |
|---|---|---|
| A `FULL_VIEW` | `Valid` | Only node that can replay `F` and bind `C'` |
| B `TRADING_VIEW` | `InsufficientView` | Naive “book must not cross” says `Invalid` on a legal STP book |
| C `PUBLIC_VIEW` | `InsufficientView` | Has `C'`; no `π`; no plaintext |
| D `COMPLIANCE_VIEW` | `InsufficientView` | Owner/qty; no price/side; jurisdiction not in schema |

**Q-CONS-3:** honest nodes with these views **cannot** implement identical execution `valid(v)` without a validity proof. They can share the same `C'` and disagree on whether `S'` is a valid transition.

If consensus safety requires matching, STP, or owner authorization, it requires a withheld field for B, C, and D. Those nodes **must not** be treated as full consensus replicas for that check (options 1–3 in Consensus collision, above). Phase 4 must not pretend otherwise.
