# Post-Quantum Readiness

**Status:** Living document  
**Date:** 2026-09-25  
**Language rule:** say **post-quantum ready**, not “post-quantum secure,” until every relevant surface has been analysed.

## Why agility first

No consensus-critical type should hard-code a single signature algorithm. The protocol identifies algorithms, not “the” algorithm.

```text
AlgorithmId
CryptoSuiteId
ProofSystemId
CommitmentSchemeId
```

Canonical messages include suite identifiers and domain separation. This is to prevent downgrade and cross-protocol replay. **Implemented for validator signatures and the intent-gossip channel** in Phase 7 (ADR [0030](adr/0030-pq-hybrid-suites.md)); `ProofSystemId` / `CommitmentSchemeId` are not.

## Target suite abstraction

```text
CryptoSuite {
    account_signature,
    validator_signature,
    transport_key_establishment,
    encryption,
    commitment_hash,
    proof_system,
}
```

Phases (intent, not a schedule commitment):

| Phase | Intent |
|---|---|
| 0 | Classical only (research prototype) |
| 1 | Classical + PQ hybrid on confidentiality and (optionally) signatures |
| 2 | PQ-preferred |
| 3 | Ability to retire vulnerable classical primitives |

## Phase 7 status (2026-10-24)

ADR [0030](adr/0030-pq-hybrid-suites.md). Phase 1 ("classical + PQ hybrid") exists **experimentally on two surfaces**:

| Surface | Status |
|---|---|
| Validator signatures (votes, proposals, certificates) | `HybridV1` = Ed25519 + ML-DSA-65, both must verify; `SuitePolicy` rejects weaker suites |
| Intent gossip channel | X25519 + ML-KEM-768 handshake, transcript signed with suite keys, XChaCha20-Poly1305 frames |
| Malachite libp2p transport | Classical by default; **opt-in hybrid tunnel** around Noise (ADR [0034](adr/0034-pq-tunnel-under-libp2p.md)). Peer ids stay Ed25519. |
| Validator proof (peer labels) | Skipped for hybrid keys: Malachite caps it at 1 KiB |
| Accounts / orders | **Opt-in signed orders** (ADR [0033](adr/0033-signed-orders.md)): owner = hash of suite key; hybrid accounts checked at admission, attested by the hybrid finality certificate; not in `π` |
| WAL, `C'`, `π`, settlement, HSM | Untouched |

Measured: hybrid sign 64 µs, verify 73 µs, signature 3 379 B, handshake 0.74 ms / 13 KB. Consensus latency on localhost is unchanged within noise; the cost is bandwidth, computed at +65.8 MB of vote traffic per height at n=100.

**Tiered finality** (ADR [0031](adr/0031-tiered-finality.md)) is the bandwidth answer: votes stay classical (ordering), and a hybrid 2f+1 finality certificate per height gates settlement and history. That protects what harvest-now-forge-later can reach (certificates, money), not real-time ordering. 4–14× fewer consensus bytes than hybrid votes at n ≤ 20.

## NIST baselines (sourced sizes)

NIST FIPS 203/204/205 (August 2024). Sizes below are from the FIPS tables or FIPS-aligned implementations cited in the research brief.

### ML-KEM (FIPS 203) — bytes

| Set | Encaps key | Ciphertext | Shared secret |
|---|---|---|---|
| 512 | 800 | 768 | 32 |
| 768 | 1184 | 1088 | 32 |
| 1024 | 1568 | 1568 | 32 |

### ML-DSA (FIPS 204) — bytes

| Set | Public key | Signature |
|---|---|---|
| 44 | 1312 | 2420 |
| 65 | 1952 | 3309 |
| 87 | 2592 | 4627 |

### SLH-DSA (FIPS 205) — bytes

| Set | Public key | Signature |
|---|---|---|
| 128s | 32 | 7,856 |
| 128f | 32 | 17,088 |
| 192s | 48 | 16,224 |
| 256s | 64 | 29,792 |

Arc already ships an EVM precompile for **SLH-DSA-SHA2-128s** (7,856-byte signatures). That is application-layer verify, not Malachite consensus signing. Malachite’s test/app signing today is Ed25519 / optional ECDSA.

## Consequences if we migrate

| Surface | Consequence |
|---|---|
| Address derivation | Hash of `(suite \|\| pk)`, not raw ML-DSA pk |
| Account abstraction | Wallet UX and calldata size; 8 KB SLH-DSA sigs |
| Validator identities | Proof-of-validator messages grow |
| Consensus signatures | No BLS-style aggregation in FIPS 204/205. Votes scale linearly unless we add a non-standard aggregator |
| Bandwidth / block size | Dominated by vote set + any PQ order signatures |
| Networking | Harvest-now-decrypt-later is a **KEM** problem. TLS/QUIC needs ML-KEM hybrids. rust-libp2p support is **unverified** |
| HSM/KMS | Treat as a blocker until measured; not assumed |
| Smart contract verify | Possible via precompile (Arc pattern) at serious gas/calldata cost |
| Proof system | Groth16 / KZG-PLONK over BN254 are **not** PQ-ready. Hash-based STARKs are PQ-ready under hash/ROM conjectures, which are not NIST PQC standards |

## What would have to be true to say “PQ secure”

Every of: account sigs, validator sigs, transport KEM, at-rest encryption, commitments (hash), proof wraps, threshold/recovery shares, and remote-signer channels. We are not there. We will not be there in Phase 0–5.

## Do not invent cryptography

Use NIST algorithms and reviewed libraries. Protocol novelty is in *where* they are plugged in, not in new primitives.
