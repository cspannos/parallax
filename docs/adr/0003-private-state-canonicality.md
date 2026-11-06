# ADR 0003 — Private State Canonicality

**Status:** Accepted as a *working hypothesis with explicit failure modes*  
**Date:** 2026-09-25  
**Deciders:** Protocol architecture (research prototype)

## Context

The protocol wants a native Private State Engine (PSE) whose first machine is a CLOB. It also wants EVM compatibility. Two different things can be “canonical”:

1. The in-memory book, fills, and private positions.
2. The public balances and contract state that Ethereum tools observe.

dYdX v4 shows a third option used in production: **the book is not canonical at all**. Each validator keeps a local optimistic `MemClob`. Consensus persists a **proposer-authored match tape**. Validators do not share one book. Short-term orders die on restart. This is high-throughput and explicitly unfair (proposer MEV).

Malachite, by contrast, assumes that correct processes evaluate the same deterministic `valid(v)` and decide the same value. If the value *is* the book, every honest validator must be able to validate the book. If the value *is* a commitment to the book, `valid(v)` can only check the commitment (and a proof), not the plaintext.

The working hypothesis:

```text
S[t+1] = F(S[t], I[1..n])          // may be private

consensus observes:
  C[t], C[t+1], Δ[t], π[t]
```

This is **not known to be sound**. Commitments do not prove `F`. Proofs may arrive after finality. Different disclosure views may make `F` unevaluable.

## Decision

Split canonicity by object. Do not declare a single “canonical state.”

| Object | Canonical location | Consensus-visible form |
|---|---|---|
| Order book, resting orders, private positions | PSE | `private_state_commitment` |
| Authorized match/intent sequence for a height | PSE + DA tier that can reconstruct it | `input_commitment` |
| Public asset balances, contracts | Reth/EVM | EVM state root |
| Settlement effects that cross the boundary | Deterministic `SettlementDelta` in the consensus value | `settlement_delta_commitment` |
| “The chain” | The Malachite-decided value (commitments + public fields) | Block / value id |

**Working rules:**

1. **Plaintext private state is never the Malachite `Value`.** The value’s identifying `id(v)` is a commitment over the public bundle. This is required for gossip size and for not publishing the book.
2. **Among replicas that share an authorized view and the same ordered inputs, PSE execution is deterministic.** Phase 1–2 exist to prove this in code.
3. **Among replicas that do not share a view, PSE plaintext is not a consensus object.** Phase 3 exists to measure exactly what each view can validate. If safety requires withheld plaintext, that result is documented, not patched with a fake protocol.
4. **Until a validity proof exists, a finalized commitment is not a claim that `S[t+1] = F(S[t], I)`.** It is a claim that a supermajority voted for that commitment. See ADR 0004 and the async-proof analysis in the initial design.
5. **dYdX’s divergent-book model is not the Phase 1–2 model.** Phase 2 requires four nodes, identical ordered inputs, identical roots. That is Model I (shared-input determinism). Model II (proposer tape) and Model III (commitment + proof) remain on the table after Phase 3.

### Adversarial reading of `C, C', Δ, π`

What must be proven (none of these are proven today):

| Claim | Needed for | Status |
|---|---|---|
| Binding: `C = Commit(S)` cannot be opened to `S' ≠ S` | Safety of “agreeing on state” | Standard if `Commit` is collision-resistant; algorithm not chosen |
| Validity: `π` proves `C' = Commit(F(Open(C), I))` under the circuit’s semantics | Execution validity | Unsolved for this protocol; circuit does not exist |
| Input integrity: `I` is the authorized intent set, not a proposer substitution | Fairness / authorization | Unsolved; Malachite does not provide it |
| Availability: authorized parties can obtain enough of `S` or `I` to verify or recover | Recovery, audit, some proofs | Threat-model dependent (ADR 0005) |
| Disclosure soundness: `π` and `Δ` leak nothing beyond the declared view | Privacy | Unsolved; metadata leaks even if proofs are ZK |
| Non-equivocation of views: two openings of the same `C` under different capabilities are consistent | Selective disclosure | Unsolved |
| Liveness of `π` if proofs are async | Verifiability invariant | Unsolved; failed proof after finality is a critical gap |

**Hypothesis is therefore a research program, not an architecture theorem.**

## Alternatives

### A. Native state is the only canonical state; EVM is a cache

Pros: matching latency unconstrained by trie updates.  
Cons: composability lies; contracts can read stale mirrors; crash recovery of the mirror is a second consensus problem. Rejected as a *total* answer. Accepted for **the book**.

### B. EVM state is the only canonical state; PSE is a cache

Pros: Ethereum tools see the truth.  
Cons: every accepted order becomes an EVM fact, or the book can disagree with balances. Rejected for the book. Accepted for **public balances**.

### C. Shared database between PSE and Reth

Pros: one disk.  
Cons: one crash/consistency domain; couples lifetimes; makes replacement of Reth or PSE a rewrite. Rejected.

### D. dYdX Model II as the only model

Pros: known to run a real CLOB.  
Cons: validators do not share state; privacy of the book is accidental (it’s already divergent); fairness is proposer-defined; Phase 2’s identical-root test would be a lie. Kept as a **fallback** if Model I dies in Phase 3.

### E. Wait for ZK and ship only Model III

Pros: clean `valid(v) = Verify(π, C, C', Δ)`.  
Cons: no prototype for years; proving is not on the sub-second path. Rejected as the *only* path. The async-proof design is Phase 6.

## Consequences

- Phase 1 commits a `state_root` of the in-memory book. That root is a local deterministic artifact, not a BFT decision.
- Phase 4 finalizes commitments. Honest nodes may finalize a commitment they cannot open.
- The verifiability invariant (“every finalized transition must eventually be independently verifiable”) is **not met** until Phase 6 has a proof that actually arrives, or Phase 3 shows that full-view validators are the real safety set.

## Security implications

The most important security implication of this ADR is negative:

> If honest validators have different plaintext, Malachite safety still holds for the *voted value* (the commitment). It does **not** hold for the *implied private state*. Two honest validators can agree on `C'` and disagree on whether any legal `S'` exists.

That is not a bug in Malachite. It is a category error if we treat `Decide(C')` as `Decide(S')`.

Withheld-data attack: a Byzantine proposer publishes `C'` and streams encrypted fragments that only some voters can decrypt. Honest low-view validators must vote `nil` or `InsufficientView`. If the protocol instead treats “I cannot see it” as “I trust the commitment,” the safety set shrinks to the high-view validators. Document that shrinkage; do not hide it.

Compromised disclosure keys: an adversary who obtains a capability key learns that view for all data encrypted to it. Rotation and capability versioning are required before any production claim. Not designed yet.

## Performance implications

Voting on commitments is cheap. Computing `C` over a large book is not. The commitment scheme (Merkle, Verkle, incremental hash, polynomial) is unchosen and must be benchmarked against 100k+ order events/s. Do not assume a full Merkle rebuild per height.

## Reversibility

Medium. Switching the book from Model I to Model II after Phase 3 is an ADR, not a patch. Switching public balances from EVM-canonical to native-canonical is a user-visible break and should be avoided.
