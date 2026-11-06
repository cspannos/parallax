# ADR 0001 — Protocol Boundaries

**Status:** Accepted for Phase 0–1  
**Date:** 2026-09-25  
**Deciders:** Protocol architecture (research prototype)

## Context

A naive construction of this network is:

> Malachite + Reth + encrypted transactions

That construction inherits Arc’s architecture: one public EVM block is the consensus value, Engine API is the only execution interface, and privacy (if any) is a later overlay. It cannot host an in-memory CLOB, selective disclosure, or a Private State Engine without forcing every order through EVM transaction semantics.

Malachite, Reth, and revm each solve a different problem. Mixing those problems into a single crate or a single “block = EVM payload” type couples the protocol to Ethereum’s performance ceiling and to a validation model that assumes every correct replica evaluates the same `valid(v)`.

The protocol must keep these properties separable:

1. Consensus
2. Execution validity
3. Data availability
4. Data confidentiality
5. State recovery
6. Settlement
7. Auditability

## Decision

Define seven replaceable subsystems. No subsystem may silently assume it provides another’s guarantees.

| Subsystem | Owns | Does not own | Initial implementation |
|---|---|---|---|
| **Consensus** | Ordering and irreversible commitment of a *value* | What the value means; execution; DA of private bytes | Malachite (`app-channel`), treated as upstream |
| **Execution validity** | Whether `S[t+1] = F(S[t], I)` | Agreement that a value was chosen; availability of witnesses | Private State Engine + later proofs |
| **Data availability** | That authorized parties can obtain the bytes they need | Confidentiality of those bytes; validity of the transition | Prototype: local/validator replication. No external DA chain |
| **Data confidentiality** | That unauthorized parties do not learn plaintext | Availability; validity; consensus safety | Capability-based disclosure (see privacy model) |
| **State recovery** | Deterministic reconstruction after crash or join | Consensus safety of the reconstructed view | Encrypted WAL + replay tests |
| **Settlement** | Externally visible asset deltas and EVM composability | Matching; private book canonicality | Reth/revm as a settlement environment, not the matching VM |
| **Auditability** | Authorized reconstruction of history and proofs | Public total transparency | Selective views + commitments + (later) proofs |

The consensus value is **not** `ExecutionPayloadV3`. It is a versioned bundle whose minimum public fields are commitments. M4a fields: ADR [0009](0009-m4a-full-view-value.md). Remainder still open.

The execution interface used by consensus is an internal port, not Engine API:

```text
Propose(parent, hints) -> Payload
Validate(payload, local_view) -> Valid | Invalid | InsufficientView
Finalize(payload_id) -> Commit
```

Reth Engine API is an **adapter** used only when a public EVM payload is present in the bundle.

Crate boundaries must allow replacement of Malachite, Reth, storage, proof system, cryptographic algorithms, and DA without rewriting the protocol types.

## Alternatives

### A. Single-process “everything is a Reth node”

**Rejected.** Reth’s mempool, sequential EVM, and Engine API payload jobs are the wrong hot path for a CLOB. Ethereum tooling compatibility does not require every operation to execute inside the EVM.

### B. Arc-shaped two-process node with Engine API as the only seam

**Rejected as the sole seam.** Keep the two-process *idea* for a public EVM sidecar. Do not make `forkchoiceUpdated` / `newPayload` the type of native financial execution.

### C. Custom BFT instead of Malachite

**Rejected for the prototype.** Malachite already provides Tendermint-style deterministic finality, WAL, value-sync, and a pure `Input`/`Effect` core. Replacing it would not solve the private-state validation problem.

### D. No explicit property split

**Rejected.** Conflating confidentiality with DA, or consensus with execution validity, is how invalid or unavailable private state gets finalized.

## Consequences

- Phase 1 can implement the CLOB with no blockchain.
- Phase 4 can attach Malachite to commitments without importing Reth.
- Phase 5 can attach Reth as settlement without putting orders through `eth_sendRawTransaction`.
- The hardest problem — `Validate` under unequal disclosure — is forced into the open as `InsufficientView`, not hidden behind encryption.

## Security implications

Separating properties prevents false confidence:

- BFT agreement on `C[t+1]` is not a validity proof.
- Encryption is not data availability.
- A commitment is not authorization.
- A ZK proof is not (by itself) a disclosure policy.
- EVM compatibility is not EVM execution of the book.

Malachite requires `valid(v)` to be deterministic and identical across correct processes. If our `Validate` returns `InsufficientView` for some honest validators, we **do not have** Malachite’s stated `valid(v)` assumption. That is a first-class protocol problem, not a layering detail.

## Performance implications

Clean boundaries add copies and commits at subsystem edges. That is acceptable. The latency budget belongs inside the Private State Engine and the consensus round, not in a shared god-object. Do not optimize across boundaries before measuring.

## Reversibility

High. The ports are the decision. Implementations behind them can change. Re-merging consensus and execution into an Arc-like Engine API node remains possible if Phase 3–5 show that a native engine cannot be validated under the chosen privacy policy.
