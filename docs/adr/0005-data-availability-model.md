# ADR 0005 — Data Availability Model

**Status:** Accepted as the threat-model-first default; no DA chain  
**Date:** 2026-09-25  
**Deciders:** Protocol architecture (research prototype)

## Context

Data availability is a first-class property, distinct from consensus, validity, and confidentiality.

Public modular DA (Celestia, EigenDA, Avail) publishes bytes so light clients can sample them. That is often the opposite of private finance: even ciphertext leaks size, timing, and participation, and harvest-now-decrypt-later applies if encryption is not post-quantum ready.

Nearby systems:

- Malachite **value-sync** ships decided values + commit certificates. It is not a general DA layer. It does not sync mempools or uncommitted parts.
- Arc uses that sync, plus follow/RPC mode, plus paired CL+EL snapshots.
- Celestia: public blobs, DAS, own PoS set.
- EigenDA: restaked operators, KZG + BLS certificates (pairing, not PQ-ready), historically a centralized disperser for liveness.
- Avail: public KZG + DAS (first-party docs not fully verified in this pass).

The starting proposal was four tiers: public, validator, participant, archival.

## Decision

**Do not add a DA blockchain in the prototype.** First implement availability as protocol rules + local storage + explicit tests for withholding.

### Tiers

| Tier | Who | What | If missing |
|---|---|---|---|
| **Public DA** | Anyone | Headers, `C`, `Δ` commitment, `π` (when it exists), public EVM txs, commit certificates. **M6 object:** canonical [`HeightStatement`](../../crates/protocol-types/src/height_statement.rs) (**178 B** full-download at n=4). n≫4: chunk-Merkle sample if > 4096 B; reconstruct via 2D RS. Not KZG. | Light clients cannot audit the public chain |
| **Validator DA** | Consensus set (possibly capability-partitioned) | Encrypted fragments needed to validate or recover the height under that validator’s policy | Consensus liveness/safety for that height |
| **Participant DA** | Order owners, counterparties, entitled compliance actors | Openings / receipts for *their* orders, fills, positions | They cannot prove their own state against `C` |
| **Archival DA** | Operators, designated archives | Encrypted history, later erasure coding | Compliance / dispute; **not** tip safety |

### Rules for the prototype

1. **Public DA is commitments and public settlement, not the book.** The public blob is `HeightStatement` (`C`, `C'`, committed `I` and `Δ`). `ConsensusValue` is not enough (`C` is missing). `I` bodies stay off this tier.
2. **Validator DA is the safety-critical tier** until proofs exist. A proposer who withholds validator-required fragments must not collect honest votes. Honest `Validate` returns `InsufficientView` / invalid, not “trust `C`.”
3. **Participant DA is not implied by validator DA.** A user must be able to obtain their own openings without learning the rest of the book. How (server, P2P, inclusion of encrypted-to-user blobs) is unsolved (Q-DA-3).
4. **Encryption does not provide DA.** Ciphertext that nobody stores is unavailable. Ciphertext that only the proposer stores is a hostage.
5. **Malachite value-sync is the catch-up transport for decided public values.** Private fragments need a separate channel and access control. Do not put them on the consensus gossip topic.
6. **External DA networks may be reconsidered only for the public tier**, and only after we know we want public blob publication. They do not solve validator or participant DA for private state.
7. **n≫4 public sampling is chunk-Merkle; reconstructability is 2D RS.** [`HeightStatement`](../../crates/protocol-types/src/height_statement.rs) (178 B) full-downloads. Blobs larger than 16×256 B may be sampled. [`Rs2d`](../../crates/proof-adapter/src/rs2d.rs) extends a `k×k` data square to `n=2k` with GF(256) RS (rows then columns). A missing row reconstructs; an erasure square of side `k+1` does not. **16 Merkle samples do not reconstruct** (need `k` shares on a line). Sample indices are a function of `blob_root`, so the encoder knows them: a complement withhold of those 16 cells is accepted by a light client and is unreconstructable. Client-local coins (`sample_indices_hidden`) are not that public set; they catch the public complement and still do not reconstruct at 16 hits. A `2^{-40}` unique-sample count is withhold-specific: **83** vs a `(k+1)` square, **739** vs a missing row, **1211** vs 1-of-100 replica (integer limbs). Keeping those **83** public FS cells accepts and does not reconstruct (**50 464 B**). Tape size class `k=72` encodes (**5 308 416 B** / 16-sample **11 776 B**; missing row reconstructs); `2^{-40}` is **94 / 3620 / 2575**; **94** public FS hits accept (**69 184 B**) and do not reconstruct. Public FS reconstruct is **8621 / 6 345 056 B** (exceeds coded size). Hidden reconstruct for `[1; 32]` is **8421 / 6 197 856 B** (also exceeds coded). Reconstruct for coins `[1; 32]` is **495** cells; public Fiat–Shamir reconstruct is **512**. None of those is 16. 83/94/739/1211 are not reconstruct. 495/512 are not `2^{-40}`. **Recovery research default:** `recover_public_payload` / `recover_hidden_payload` follow `cheaper_*_recovery` = min(coded-grid download, sample-to-reconstruct) and return the payload. Tiny-`F` prefers **PublicSample 512 / 311 296 B** or **HiddenSample 495 / 300 960 B**; tape `k=72` prefers **coded 5 308 416 B** (missing row still reconstructs). Uncoded orig (**84 214 B** / **1 291 000 B**) beats either when offered. Light 16-sample stays detection-only. Not KZG/pairing. Not a DA chain.

### Withholding and unavailability (normative intent)

A height is **not eligible for honest prevote** unless the validator has:

- the public bundle (or enough of it to compute `id(v)`), and
- every fragment its disclosure policy says it must have to evaluate `Validate`, or
- a validity proof `π` that substitutes for those fragments.

If proofs are asynchronous (Phase 6), the second bullet remains mandatory on the fast path. Otherwise we are finalizing unavailable private state.

No slashing implementation in Phase 0–4. Detectability is enough to write tests: “proposer sealed `C'` without publishing the validator fragment.”

## Alternatives

### A. Celestia / Avail / EigenDA as the DA layer

**Rejected for now.** Imports a second consensus, a public data plane, and (EigenDA) pairing assumptions. Does not provide capability-restricted DA. Revisit only for public commitments if self-hosted public DA becomes operationally worse.

### B. Validium-style: proofs on a foreign L1, data held by a consortium

**Rejected as the architecture.** Possible as a later deployment mode. The research question is whether *this* validator set can agree. Moving DA to a consortium just relocates the problem.

### C. Full public replication of plaintext

**Rejected.** Violates the privacy invariant.

### D. Full public replication of ciphertext, keys off-protocol

**Rejected as sufficient.** Helps archival and some recovery. Does not let validators validate, and publishes metadata.

### E. Proposer-only storage (“trust me, I have the book”)

**Rejected.** Classic unavailable-state attack.

## Consequences

- Storage crate must support encrypted blobs with capability labels, not a single public chain store.
- Networking crate must have a DA/sync channel distinct from consensus gossip.
- Phase 2 crash/restart tests are local DA tests. Phase 3 is a DA × disclosure test. Phase 4 must refuse to vote without required fragments.
- Archival erasure coding is out of scope until the threat model for long-term disclosure is written.

## Security implications

| Attack | Addressed by this ADR? |
|---|---|
| Proposer withholds private fragments | Yes: honest non-vote. Liveness suffers |
| Validators store ciphertext they cannot decrypt | Yes: that is allowed; it does not create a view |
| Encrypted blob published, key later compromised | Residual: harvest-now-decrypt-later. PQ-ready encryption is a later ADR |
| Public DA of ciphertext used to traffic-analyze flow | Residual: metadata leakage is in the threat model |
| Lazy validators delete archival history | Residual: not a tip-safety issue; compliance issue |
| Malicious proof claiming availability | Proofs are validity, not DA. Do not conflate |

BFT does not make data available. A ⅔ vote that “we saw `C`” is not a vote that “you can open `C`.”

## Performance implications

Validator DA of a full book replica is the expensive option and the simplest to test (Phase 2). Capability-partitioned fragments reduce bandwidth and increase the number of parties who cannot validate. Measure before partitioning production traffic.

Do not stream private books on gossipsub. Use request-response / direct streams (Malachite already does this for value-sync).

## Reversibility

High in the prototype. Adding Celestia later for *public* blobs is an adapter. Changing the rule “do not vote without required fragments” after mainnet-like operation would be a safety regression and should not be reversed.
