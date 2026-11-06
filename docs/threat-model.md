# Threat Model

**Status:** Living document  
**Date:** 2026-09-25  
**Scope:** Research prototype. Not a certification target.

This document models adversaries against the seven properties in [ADR 0001](adr/0001-protocol-boundaries.md). It does not assume encryption, commitments, BFT, or ZK close those properties.

## Trust starting point (honest, not aspirational)

Until Phase 3 and Phase 6 say otherwise, the prototype’s actual trust model is closer to:

> A permissioned set of validators, fewer than one-third Byzantine by voting power, who **share enough view to evaluate `Validate` identically**, produce a deterministic transition, and use Malachite to order and finalize a commitment to that transition.

Selective disclosure among validators is a **research experiment** (Phase 3), not a granted security property. Arc’s published Privacy Sector is also not our model: APS has every honest validator decrypt the same plaintext inside enclaves.

We do **not** assume:

- hardware enclaves
- an honest majority of *full-view* validators distinct from the consensus set
- a live proving system
- an external DA chain
- post-quantum security of the deployed suite (the suite is not deployed)

## Assets

| Asset | Why it matters |
|---|---|
| Private order plaintext (instrument, side, qty, price, owner) | Market-sensitive; identity-sensitive |
| Compliance metadata / jurisdiction | Regulatory and personal data |
| Positions and settlement deltas | Money |
| Disclosure capability keys | Compromise expands a view permanently for old ciphertext |
| Validator consensus keys | Equivocation, forgeries |
| WAL / persistent private fragments | Restart integrity; leak if decrypted |
| Proofs and commitments | Forgery = fake state |
| Public EVM balances | User-visible money |
| Metadata (timing, sizes, peer graphs) | Often enough to reconstruct flow |

## Adversaries

| Actor | Capabilities |
|---|---|
| Byzantine proposer | Equivocate, omit, reorder, withhold fragments, insert illegal deltas |
| Byzantine validator | Equivocate votes, lie about view, leak granted plaintext, stall |
| Honest-but-curious validator | Follows protocol; tries to infer unauthorized fields from metadata and granted view |
| Network adversary | Partition, delay, replay, observe traffic |
| Compromised participant | Stolen capability or account key |
| Failed prover | Silent, late, or incorrect `π` |
| Quantum adversary (future) | Breaks classical signatures/KEM; harvest-now-decrypt-later on stored ciphertext |
| Operator / host OS | Reads RAM, disk, logs if not isolated (no enclave assumption) |

## Property × attack matrix

The list below is the minimum set from the research brief. Each row states the property under attack and whether Phase 0 has a design or only a test plan.

### Consensus

| Attack | Property | Current posture |
|---|---|---|
| Byzantine proposer | Safety of decided value | Malachite Tendermint: honest nodes decide at most one value per height if &lt;⅓ Byzantine. **Does not validate private semantics.** |
| Byzantine validator | Safety / liveness | Same; equivocation evidence delivered on `Finalize`. Slashing is application-defined and **not designed**. |
| Equivocation | Safety | Detectable by Malachite. Response unspecified. |
| Invalid state commitment | Validity | **Not covered by BFT.** Needs `Validate` and/or `π`. |
| Clock skew | Liveness | Timeouts are local. Malachite is partially synchronous. Measure; do not use wall clock in `F`. |
| Network partition | Liveness | &lt;⅓ can stall; &gt;⅓ Byzantine or severe partition can stall. No safety violation if honest. |
| Slow validator | Liveness | Timeouts advance rounds. May miss views. |
| Validator joining late | Recovery | Value-sync of decided *public* values. Private fragment sync unspecified. |
| PQ downgrade | Crypto agility | Must be in versioned suite IDs. Not implemented. |

### Execution validity

| Attack | Property | Current posture |
|---|---|---|
| Malformed / conflicting / duplicate orders | Validity | Phase 1: reject in the engine; deterministic receipts. |
| Replay / nonce | Validity | Nonce/expiry scheme unchosen (Q-ORD-2). |
| Invalid transition (`C'` does not follow) | Validity | Phase 2: identical inputs. Phase 4+: only as good as `Validate` view. |
| Malicious proof | Validity | Phase 6. Pairing wraps are not PQ-ready. |
| Delayed / failed proof | Verifiability | See async-proof section in initial design. **Unresolved.** |

### Data availability

| Attack | Property | Current posture |
|---|---|---|
| Withheld private data | DA | Honest `InsufficientView` (ADR 0005). Liveness cost. |
| Unavailable DA after vote | DA | Must not vote first. Tests in Phase 4. |
| Validator loses private state | Recovery | WAL replay. If fragments were never received, reconstruction may require other validators — may be unauthorized. |

### Confidentiality

| Attack | Property | Current posture |
|---|---|---|
| Validator receives a different disclosure view | Confidentiality vs consensus | Phase 3 experiment. Likely breaks identical `valid(v)`. |
| Inconsistent disclosure policies | Confidentiality / safety | Must be part of genesis or committed policy. Unspecified. |
| Compromised disclosure key | Confidentiality | No rotation design. |
| Metadata, timing, traffic analysis, order-flow | Confidentiality | **In scope.** Encryption of payloads does not hide size, rate, or peer set. |
| Logs / traces | Confidentiality | Rule: no sensitive plaintext in logs. Instrument IDs and commitments only. |
| Host OS / RAM inspection | Confidentiality | **Out of scope** unless we later adopt enclaves (we do not assume them). |

### Recovery and durability

| Attack | Property | Current posture |
|---|---|---|
| Corrupted WAL | Recovery | Detectable: XChaCha20-Poly1305 (ADR 0007). Open refuses on auth failure. |
| Restart during matching | Recovery / determinism | WAL must contain accepted inputs before acknowledgement. |
| Crash after decide, before persist | Recovery | Malachite WAL + app persist ordering. Arc’s persistence backpressure is the pattern. |

### Settlement

| Attack | Property | Current posture |
|---|---|---|
| Delta not implied by fills | Settlement integrity | Phase 5 atomicity tests. Needs view or `π`. |
| Public EVM tx races reservation | Settlement | Unspecified scheduler (Q-SET-1). |

## Disclosure-specific consensus failure (central)

Malachite’s spec requires `valid(v)` to be deterministic and consistent across correct processes. Selective disclosure creates four honest validators who **cannot** all compute the same predicate on plaintext.

Phase 3 will run exactly:

| Validator | View | Can check |
|---|---|---|
| A | FULL_VIEW | Authorization, matching, compliance, delta |
| B | TRADING_VIEW | Matching given visible book subset; **not** owner/compliance |
| C | PUBLIC_VIEW | Commitments, signatures on public fields, `π` if present |
| D | COMPLIANCE_VIEW | Owner/jurisdiction constraints; **not** price-time completeness |

**Predicted result (confirmed M3, ADR 0008):** safety that depends on price-time matching or owner authorization cannot be evaluated by C, and cannot be fully evaluated by B or D. If those validators still vote, the effective safety set is “whoever has the fields,” which is not the Malachite validator set.

This is a finding we want, not a bug to paper over.

## What BFT does not give us

- Execution validity
- Data availability of private fragments
- Confidentiality
- Fairness of the intent set (proposer can omit)
- Post-quantum security
- Auditability for parties without keys

## Residual risks we will not “solve” in research prose

- Side channels on a validator host
- Regulatory compulsion of a validator to disclose
- Proposer MEV if we adopt a dYdX-style tape
- Harm from a bad fill exceeding any later slash bond
- Language-level bugs in Rust unsafe / FFI (Reth MDBX, RocksDB if ever used)

## Mapping to tests

Adversarial and property tests are listed in [`docs/performance.md`](performance.md) and [`ROADMAP.md`](../ROADMAP.md). Every row above with “unspecified” must appear in [`open-questions.md`](open-questions.md).
