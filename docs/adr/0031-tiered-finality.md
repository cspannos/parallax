# ADR 0031 — Tiered finality: classical votes, hybrid finality certificate

**Status:** Accepted as the **research default for PQ vote bandwidth** (Q-CRY-5); opt-in via `ClusterSpec::tiered(k)`  
**Date:** 2026-10-24  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0030](0030-pq-hybrid-suites.md) (suites, hybrid signatures, secured gossip), [0011](0011-missing-pi-settlement-inert.md) (settlement inert until unlocked).  
**Does not claim:** that consensus ordering is PQ secure.

## Context

ADR 0030 made every vote and proposal carry a hybrid signature (+3 309 B). Votes are broadcast, so a height costs (2n + 1)(n − 1) signed messages. ML-DSA has no aggregation. Measured at n=20: 2.7 MB per height, against 122 KB classical. Computed at n=100: about 66 MB per height.

Two threats are different in time:

- **Real-time forgery** of a vote needs Ed25519 broken within a round (~100 ms).
- **Harvest-now-forge-later** targets durable artifacts. A future quantum attacker could forge an old commit certificate to feed a fake history to a syncing node or a light client, or to unlock settlement.

Only the second threat is credible for the foreseeable future. It is also the only one that touches money.

## Decision

Split the two jobs:

1. **Ordering (classical).** Malachite votes and proposals sign with the **classical part** of each validator's key (`SuiteSigningKey::classical()`: same Ed25519 key, `ClassicalV0` tag). The validator set holds classical public keys, so addresses and validator proofs are classical-sized; the 1 KiB proof cap is no longer hit.
2. **Finality (hybrid).** After `Decided`, each validator signs `"plx/finality/v1" ‖ height ‖ value_id` **once**, with its full hybrid key (Ed25519 + ML-DSA-65). It sends the signature to `k` collectors over the hybrid-secured gossip channel (ADR 0030).
   - The collectors for height h are `(h + j) mod n` for j < k.
   - A collector verifies each signature as it arrives and emits a `FinalityCertificate` once 2f+1 match ([`finality.rs`](../../crates/consensus-adapter/src/finality.rs)).
   - A signer that signs two values at one height is reported as `Equivocation`.
3. **Settlement waits for finality.** `SettlementGate::require_finality(policy, roster)` makes every height inert (`MissingFinality`) until `on_decided_final` gets a certificate. The certificate must have 2f+1 valid hybrid signatures on this value's id at this height. A valid `π` alone is not enough.

Classical-tagged and hybrid-tagged signatures sign different bytes. A vote signature never verifies as part of a finality signature, and the reverse fails too (test `classical_projection_is_domain_separated`).

## Security argument

- **Certificate safety does not depend on Ed25519.** An honest validator finality-signs only what it decided, and decides at most once per height. Two certificates for different values at one height need two 2f+1 quorums, which share at least f+1 validators, so at least one honest validator would have signed both. That can't happen. This holds even if an adversary forges every classical vote.
- **What a real-time Ed25519 forger can do:**
  - forge votes, so honest nodes' *local* decisions can diverge, and some heights may never gather a certificate (a liveness loss)
  - stall ordering

  None of that settles. Settlement needs the certificate.
- **What an Ed25519-only forger cannot do:** produce a finality signature. These are rejected under the hybrid policy (`classical_or_cross_context_signatures_rejected`).
- **Collectors:**
  - with `k = f + 1`, at least one collector is honest
  - with `k = 1`, a Byzantine or crashed collector can delay a height's certificate; failover (below) routes around it, so it costs latency, never safety
  - collectors are not trusted for correctness, because anyone verifies the certificate against the roster

## Failover and serving (2026-10-25)

Each validator keeps its own finality signature for the last 4 096 heights. Certificates leave collectors only on request, never by broadcast.

| Piece | What it does |
|---|---|
| `Certified { height }` notice | A collector that forms a certificate tells every validator (a 13 B frame). |
| Timeout failover | No notice within `finality_failover` (default 1 s): the validator re-sends its signature to the next round's collectors, `collectors_round(h, n, k, r) = (h + r·k + j) mod n`, up to ⌈n / k⌉ rounds. This handles a **crashed or silent** collector. |
| Cert server ([`finality_net.rs`](../../crates/consensus-adapter/src/finality_net.rs)) | Port `base + 2n + i`. `GET h` returns the certificate; `RECOLLECT h r` makes the validator re-send its signature to round r. Plaintext: the certificate verifies itself, and a recollect only repeats a send. |
| `obtain_certificate` | The consumer (follower, syncing node, light client) fetches from any validator and verifies. If nothing verifies within `wait`, it asks every validator to recollect the next round. This handles a collector that **announces but withholds**, since such a collector also suppresses timeout failover. |

A lying notice can delay a certificate but never fakes one. A withholding collector costs one `wait` plus one recollect. A spurious `RECOLLECT` costs one re-sent signature (~3.4 KB).

**Settlement path.**
- [`tests/tiered_settle.rs`](../../crates/settlement-pipeline/tests/tiered_settle.rs): a 4-validator tiered cluster with gossiped trades. Each height is inert with no certificate and inert with the previous height's certificate. It settles once `obtain_certificate` returns this height's certificate.
- The real-`π` demo (`bin/e2e`, ADR 0028) is tiered by default (`PLX_PIPE_TIERED=1`): settlement needs the RISC Zero receipt **and** the certificate. Run of 2026-10-25 (4 heights, M4 Pro CPU prover):
  - every height's certificate (3 signatures, 10 199 B) was fetched 1–56 ms after decide, so it is never on the critical path next to a ~60 s proof
  - all 4 heights were "settled by π + finality cert"; decide → settled 31.5 / 92.7 / 151.9 / 215.5 s, the same queueing as ADR 0028

| Test | Scenario |
|---|---|
| `m7_suites: tiered_failover_when_collector_down` | k=1; height 2's only collector is shut down. Timeout failover alone produces a valid certificate (no consumer recollect). |
| `m7_suites: tiered_recollect_routes_around_withholding_collector` | Height 2's collector announces but refuses to serve. The consumer recollects, and the next collector serves. |
| `settlement-pipeline: heights_settle_only_with_a_finality_certificate` | The settlement gate above. |

## Measurements

Measured with `PLX_M4_WIRE=1 cargo run -p m4-scale --release` on an Apple M4 Pro:
- localhost TCP, broadcast, 20 empty heights
- secured intent gossip in every mode, so the admit path is identical
- bytes counted at decode, summed over receivers (= bytes sent)

| n | Mode | Signed msgs / h | Votes etc. KB / h | Finality KB / h | Total KB / h | vs hybrid | Node p50 / p95 ms |
|---|---|---|---|---|---|---|---|
| 4 | classical | 27 | 4.5 | — | 4.5 | — | 44 / 54 |
| 4 | hybrid (0030) | 27 | 93.9 | — | 93.9 | 1× | 50 / 64 |
| 4 | tiered k=2 | 27 | 4.5 | 20.4 | 24.9 | **3.8×** | 39 / 54 |
| 4 | tiered k=1 | 27 | 4.5 | 10.3 | 14.8 | **6.3×** | 44 / 54 |
| 7 | classical | 90 | 14.6 | — | 14.6 | — | 75 / 97 |
| 7 | hybrid | 90 | 312.4 | — | 312.4 | 1× | 79 / 100 |
| 7 | tiered k=3 | 90 | 14.6 | 61.3 | 75.9 | **4.1×** | 71 / 90 |
| 7 | tiered k=1 | 90 | 14.6 | 20.6 | 35.2 | **8.9×** | 72 / 93 |
| 10 | classical | 189 | 30.2 | — | 30.2 | — | 97 / 128 |
| 10 | hybrid | 189 | 655.6 | — | 655.6 | 1× | 102 / 129 |
| 10 | tiered k=4 | 189 | 30.2 | 122.0 | 152.2 | **4.3×** | 96 / 130 |
| 10 | tiered k=1 | 189 | 30.2 | 30.5 | 60.7 | **10.8×** | 94 / 119 |
| 20 | classical | 779 | 122.3 | — | 122.3 | — | 178 / 238 |
| 20 | hybrid | 777 | 2 693.4 | — | 2 693.4 | 1× | 178 / 254 |
| 20 | tiered k=7 | 770 | 120.8 | 453.3 | 574.1 | **4.7×** | 180 / 256 |
| 20 | tiered k=1 | 779 | 122.3 | 64.9 | 187.2 | **14.4×** | 185 / 259 |

- The signed-message count matches (2n + 1)(n − 1), which confirms ADR 0030's computed bandwidth: about 3.47 KB per hybrid message and about 157 B per classical one.
- Finality costs about 3.4 KB × k per validator per height, which is **linear in n** for fixed k. Hybrid votes are quadratic.
- Latency is unchanged within noise. The finality signature is produced after decide, off the critical path (64 µs to sign; collectors verify at 73 µs each).
- **Extrapolated to n = 100** (not measured):
  - hybrid votes: ~69 MB per height
  - tiered with k = f + 1 = 34: ~3.1 MB classical votes + ~11.5 MB finality ≈ 14.6 MB (~4.7×)
  - tiered with k = 1: ~3.1 + 0.34 ≈ 3.5 MB (~20×)

  The ceiling is the classical vote traffic itself.
- **Certificate size** (what a light client or syncing node downloads per height) is (2f+1) × ~3.4 KB: 10 KB at n=4, 222 KB at n=100. Pull-only; it is not broadcast.

## Tests

| Test | What it checks |
|---|---|
| `m7_suites: tiered_cluster_certifies_every_height` | 4 validators with k=2; every collector of heights 1–3 emits a certificate on the decided id that verifies under the hybrid policy |
| `finality: certificate_forms_at_quorum_and_verifies` | the certificate forms at quorum; it is rejected with one signature short, with a duplicate signer, or on another value |
| `finality: classical_or_cross_context_signatures_rejected` | Ed25519-only and vote-context signatures are rejected |
| `finality: equivocation_detected` | one signer signing two values at a height is reported |
| `crypto-suite: classical_projection_is_domain_separated` | vote signatures and finality signatures cannot stand in for each other |
| `proof-adapter m6_inert: tiered_finality_gates_settlement` | with the requirement, `π` alone is inert, a wrong-value or short certificate is inert, and certificate + `π` settles |

## What this is not

- **Ordering is classical.** A real-time Ed25519 break stalls or forks honest nodes' local views; only settlement and history stay protected. If real-time quantum forgery becomes credible, switch back to hybrid votes (ADR 0030 mode, still available) and pay the bandwidth.
- **The finality certificate is not aggregated.** It is 2f+1 separate ML-DSA signatures.
- **Not implemented (parked 2026-10-25):**
  - certificates inside Malachite's own sync protocol (they are served on a side port)
  - stake-weighted quorums (equal power assumed)
  - pruning collectors' certificate stores
  - authenticating cert-server clients (not needed for correctness; rate limits would be)
- The transport caveats in ADR 0030 still apply.

## Reversibility

High. Opt-in per cluster. The default and ADR 0030's hybrid mode are unchanged.

## Hardening (2026-11-06)

The cert server admits connections through `consensus_adapter::limits` (per-source-IP token bucket, at most 256 at once, 5 s per request). `RECOLLECT` has a server-wide budget (burst 32, 16 per second), and the validator ignores a recollect for a height it re-sent less than 100 ms ago at the same or an earlier round. The gossip and PQ tunnel listeners use the same gate for their handshakes (64 at once, 5 s deadline).
