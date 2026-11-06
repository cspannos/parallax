# ADR 0030 — Crypto suites and an experimental PQ hybrid

**Status:** Accepted as the **research default for crypto agility**; the hybrid suite is **experimental**  
**Date:** 2026-10-24  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [`post-quantum.md`](../post-quantum.md) (agility first, phase 0 → 1), [0017](0017-intent-gossip.md) (intent gossip).  
**Does not claim:** that the network is post-quantum secure. See [What this is not](#what-this-is-not).

## Context

Phase 7 (ROADMAP M7) asks for named suites on the wire, an experimental hybrid for authentication and key establishment, measured cost, and downgrade tests. Before this ADR, validator keys were raw Ed25519 and intent gossip was plaintext TCP.

## Decision

1. **Suites are named on the wire** (`protocol_types::{AlgorithmId, CryptoSuiteId}`). There are two suites:
   - `ClassicalV0`: Ed25519, X25519.
   - `HybridV1`: Ed25519 **and** ML-DSA-65 (FIPS 204), X25519 **and** ML-KEM-768 (FIPS 203).

   Suites are ordered. Unknown codes fail to decode.
2. **Suite-tagged signatures** ([`crypto-suite`](../../crates/crypto-suite/src/lib.rs)). Keys and signatures carry their suite. The signed bytes are `"plx/sig/v1" ‖ suite ‖ len ‖ context ‖ msg`.
   - A hybrid signature is valid only if both components verify.
   - A hybrid key accepts only hybrid signatures.
   - A `SuitePolicy { min }` rejects anything weaker as a **downgrade**.
3. **Consensus signs under a policy.** Malachite's `SigningScheme` is `PlxSuite`. Votes, proposals and certificates carry suite signatures. `ClusterSpec::hybrid()` sets hybrid keys and a hybrid-only policy. Addresses hash the encoded suite key, `blake3(suite ‖ ed ‖ mldsa)[..20]`, which answers Q-CRY-4.
4. **Authenticated hybrid key exchange on intent gossip** ([`kex`](../../crates/crypto-suite/src/kex.rs)). This is a three-message handshake:
   - ephemeral X25519, plus ML-KEM-768 when hybrid
   - both shared secrets feed HKDF-SHA256, salted with the transcript hash
   - both sides sign the transcript with their validator suite keys
   - each side checks that the other's key is in the validator set
   - the responder refuses a hello below its policy; the initiator refuses a reply in another suite
   - every frame is then sealed with XChaCha20-Poly1305 under a counter nonce, so a replayed, dropped or reordered frame fails to open

   Enabled with `ClusterSpec::with_secure_gossip()`. Plaintext gossip is still the default.

The classical path is unchanged in behaviour: a classical key from a seed is today's Ed25519 key, and the classical policy accepts every suite.

## Downgrade tests

| Attack | Result | Test |
|---|---|---|
| Classical signature under a hybrid policy | `Downgrade` | `crypto-suite: classical_rejected_under_hybrid_policy` |
| Strip ML-DSA and relabel a hybrid signature as classical | rejected under any policy | `relabel_and_strip_downgrade_rejected` |
| Ed25519 broken alone: forge the Ed25519 half of a hybrid signature | rejected (ML-DSA fails) | `ed25519_break_alone_does_not_forge_hybrid` |
| 2 of 4 validators classical under a hybrid policy | **no height decides** (below quorum: liveness lost, not safety) | `m7_suites: hybrid_policy_rejects_downgraded_quorum` |
| 1 of 4 classical under a hybrid policy | decides on the 3 hybrid votes | `hybrid_policy_tolerates_one_classical_key` |
| Classical gossip handshake to a hybrid-policy node | `Downgrade`, no frames delivered | `kex: hybrid_responder_rejects_classical_offer`, `intent_gossip: hybrid_listener_rejects_classical_publisher` |
| Man in the middle rewrites a hybrid hello as classical (drops the ML-KEM key) | initiator refuses (`SuiteMismatch`; relabelling the reply breaks it as well) | `stripping_mlkem_from_the_offer_is_detected` |
| Classical responder key under a hybrid initiator | signature `Downgrade` | `classical_responder_key_rejected_by_hybrid_initiator` |
| Tampered share, foreign finish, tampered or reordered frame | rejected | `tampered_transcript_and_frames_rejected` |
| Right suite, key outside the validator set | refused | `secured_listener_rejects_unknown_key` |

Classical-only paths still pass: `classical_policy_accepts_mixed_suites`, `classical_secured_gossip_delivers_intents`, and the whole existing workspace, which runs classical (468 / 468 with Phase 7's 20 new tests).

## Measurements

Apple M4 Pro, release builds, one thread.

**Primitives** (`cargo test -p crypto-suite --release -- --ignored --nocapture`):

| | Classical | Hybrid |
|---|---|---|
| Keygen | 28 µs | 107 µs |
| Sign | 16 µs | 64 µs |
| Verify | 24 µs | 73 µs |
| Public key (encoded) | 38 B | 1 990 B |
| Signature (encoded) | 70 B | 3 379 B (+3 309) |
| Handshake (both sides) | 212 µs | 742 µs |
| Handshake bytes (hello / reply / finish) | 48 / 154 / 116 = 318 B | 1 232 / 6 503 / 5 377 = 13 112 B |
| Sealed frame | +16 B, ~0.8 µs per 100 B seal + open | same |

**Consensus, measured.** Localhost, TCP, `m4-scale`, 20 empty heights. Node p50 / p95 in ms:

| n | Classical | Hybrid |
|---|---|---|
| 4 | 43 / 56 | 51 / 62 |
| 7 | 78 / 100 | 83 / 102 |
| 10 | 99 / 130 | 97 / 135 |
| 20 | 176 / 237 | 167 / 265 |

Loaded gossip height (n=4, 8k resting, 10k intents per height, `PLX_M4_LOADED=1 PLX_M4_GOSSIP=1`), later-heights "last" p50:

| Configuration | Last p50 |
|---|---|
| Classical, plaintext (two runs) | 118 ms, 142 ms |
| Classical keys, sealed gossip | 129 ms |
| Hybrid keys, hybrid sealed gossip | 134 ms |

All of these are inside run-to-run noise. On localhost, signature CPU (tens of µs) and sealing (~7 ms of CPU per 10k frames, spread across the window) are dwarfed by round timeouts and `F`. A small cluster on one host cannot show the bandwidth cost.

**Consensus, computed (bandwidth).** Each signed message grows by 3 309 B. One round, broadcast, no failures: (2n + 1)(n − 1) signed messages per height. Commit certificates hold 2f + 1 signatures.

| n | Extra vote/proposal bytes per height | Extra per commit certificate | Verify CPU per node per height (2n votes) |
|---|---|---|---|
| 4 | 89 KB | 10 KB | 0.6 ms (vs 0.2) |
| 20 | 2.6 MB | 46 KB | 2.9 ms (vs 1.0) |
| 100 | **65.8 MB** | 222 KB | 14.6 ms (vs 4.8) |

At 100 validators, with sub-second heights, that is tens of MB/s per validator before any order traffic. ML-DSA has no aggregation (Q-CRY-5), so this is the real cost of hybrid validator signatures, not the CPU.

## What this is not

- **Not "PQ secure."** It is post-quantum *ready* on two surfaces: validator signatures, and the intent gossip channel's key establishment and authentication.
- **The libp2p transport stays classical.** Malachite's libp2p identity is an Ed25519 keypair, and Noise/TLS/QUIC use classical X25519. Consensus messages are signed hybrid, so they are not forgeable by an Ed25519-only break. But Malachite's channel is not confidential against harvest-now-decrypt-later. Consensus messages are not secret today, so that matters less than for gossip.
- **The validator proof is skipped for hybrid keys.** Malachite caps validator-proof messages at 1 KiB (`validator_proof::codec::MAX_MESSAGE_SIZE`), and a hybrid proof is about 5.4 KB. Hybrid nodes join as plain peers with their address in the identity; only peer-scoring labels are lost. Votes still verify. The fix is upstream.
- **Validator proofs are verified at the classical floor.** At first, proofs used the node's policy. A classical validator under a hybrid policy then had its proof rejected; Malachite dropped and redialled it, and the churn also cut honest hybrid↔hybrid links. The 3-of-4 test, which has no quorum slack, stalled in 2 of 13 runs. The baselines (all hybrid, all classical) show no churn. A proof only labels a peer for scoring, so it now verifies under `SuitePolicy::CLASSICAL`, while votes and proposals stay under the policy. After the change: 0 / 15 failures and no churn. Lesson: a downgraded peer must be refused where it carries weight (votes), not where refusal triggers transport side effects.
- Untouched surfaces:
  - account and order signatures (orders carry no signature yet)
  - WAL encryption (ADR 0007)
  - `C'` and the `π` hashes (SHA-256)
  - the RISC Zero succinct receipt (STARK-based, not analysed for PQ)
  - settlement
  - HSM/KMS (Q-CRY-6)
- No rekeying, resumption or key rotation, and keys come from seeds. Libraries are RustCrypto `ml-dsa` 0.1 and `ml-kem` 0.3, which are not audited.

## Open questions

- **Q-CRY-3:** ML-DSA-65 and ML-KEM-768 were chosen as category 3, the middle option, and the costs above are now measured. SLH-DSA would make votes 7.9–17 KB and is not pursued for validators. ML-KEM-1024 adds about 0.8 KB to the handshake only, which is cheap if wanted. Still open: whether ML-DSA-44 is enough for votes (2 420 B).
- **Q-CRY-5** is the binding constraint: vote bandwidth grows as n² · 3.3 KB. Options include PQ aggregation (research), committee voting, and Ed25519-for-votes with ML-DSA only on commit certificates. They trade security for bandwidth and are not decided.

## Reversibility

High. Additive: the default is still classical. Suites are versioned, so `HybridV1` can be replaced by a `HybridV2` with other parameter sets.
