# Architecture Decision Records

Format: Context, Decision, Alternatives, Consequences, Security implications, Performance implications, Reversibility.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-protocol-boundaries.md) | Protocol boundaries | Accepted (Phase 0–1) |
| [0002](0002-arc-fork-vs-components.md) | Arc fork vs components | Accepted |
| [0003](0003-private-state-canonicality.md) | Private state canonicality | Working hypothesis |
| [0004](0004-evm-settlement-model.md) | EVM settlement model | Research default |
| [0005](0005-data-availability-model.md) | Data availability model | Research default |
| [0006](0006-m1-clob-invariants.md) | M1 CLOB types, matching, serialization | Accepted (Phase 1) |
| [0007](0007-encrypted-wal.md) | Encrypted append-only WAL | Accepted (Phase 2) |
| [0008](0008-unequal-view-validity.md) | Unequal views vs `valid(v)` | Accepted (Phase 3): Q-CONS-3 is no |
| [0009](0009-m4a-full-view-value.md) | M4a full-view set + minimal `Value` | Accepted (research default, not product) |
| [0010](0010-m5-privileged-apply.md) | M5 privileged settlement apply | Accepted (research default; ABI not frozen) |
| [0011](0011-missing-pi-settlement-inert.md) | Missing `π`: settlement inert | Accepted (research default) |
| [0012](0012-height-batch-wal.md) | Height-batch replica WAL | Accepted (consensus apply default; M2 stays Full) |
| [0013](0013-treap-is-c.md) | Treap is `C'` | Accepted (consensus state root research default); hash amended by 0024 |
| [0014](0014-height-blob-wal.md) | One WAL record per height tape | Accepted (Height persist; M2 submit stays per-input) |
| [0015](0015-sequenced-i.md) | Shared sequenced `I` | Accepted (research default for inclusion; not a mempool) |
| [0016](0016-intent-set.md) | Replicated intent set produces `I` | Accepted (research default for how the tape is produced; not gossip / FOCIL) |
| [0017](0017-intent-gossip.md) | Localhost plaintext intent gossip | Accepted (research default for sharing the set; not WAN / FOCIL) |
| [0018](0018-per-height-offer.md) | Per-height offer and gossip | Accepted (research default for a living log; not a mempool) |
| [0019](0019-gossip-spread.md) | Intent spread is not `ready_delay` | Accepted (research default for the inter-height window; not WAN) |
| [0020](0020-quiesce-after-offer.md) | Quiesce after first offer | Accepted; quiet step amended by 0021 |
| [0021](0021-ack-id-set.md) | ACK of `id(set)` | Accepted (research default for post-offer admission; not 2f+1 / FOCIL) |
| [0022](0022-treap-step-witness.md) | Treap step witness (general `C'` update) | Accepted (research default for proving a `C'` change; native checker, not a STARK) |
| [0023](0023-general-c-prime-on-zkvm.md) | General `C'` proofs run on the zkVM | Accepted (research default; chunks + recursive join; CPU-measured; not `F`) |
| [0024](0024-sha256-c-prime.md) | `C'` hashes with SHA-256 | Accepted (consensus state root default; BLAKE3 kept as `C'` v1 for Plonky3) |
| [0025](0025-pi-of-f-on-zkvm.md) | `π` of `F`: the matcher runs in a zkVM guest | Accepted (research default for height validity; first settlement-unlocking verifier; CPU-measured) |
| [0026](0026-derived-order-ids.md) | Order ids are derived from `(owner, nonce)` | Accepted (order-admission default; seen set retired; client ids are v1) |
| [0027](0027-intent-target-height.md) | Intents carry a target height | Accepted (intent-admission default; fixes the gossip seal race, Q-CONS-11) |
| [0028](0028-e2e-proof-pipeline.md) | End-to-end `π` pipeline | Accepted (decided height → follower job → prover receipt → settlement; CPU-measured) |
| [0029](0029-prover-stack-risc-zero.md) | Prover stack for the `π` pipeline: RISC Zero | Accepted (pipeline default after measuring SP1; revisit on GPU / Airbender) |
| [0030](0030-pq-hybrid-suites.md) | Crypto suites and an experimental PQ hybrid | Accepted (agility default; hybrid Ed25519+ML-DSA-65 / X25519+ML-KEM-768 experimental; not "PQ secure") |
| [0031](0031-tiered-finality.md) | Tiered finality: classical votes, hybrid finality certificate | Accepted (Q-CRY-5 research default, opt-in; 4–14× fewer consensus bytes than hybrid votes at n ≤ 20; ordering stays classical) |
| [0032](0032-lazy-c-prime-and-guest-hashing.md) | Lazy `C'` hashing and SHA-256 order ids | Accepted (`π` of a loaded 10k height 634 M → 212 M cycles, ~3.5–4 CPU-hours; roots unchanged, order-id derivation v2) |
| [0033](0033-signed-orders.md) | Signed orders with suite-key accounts | Accepted (opt-in; owner = hash of suite key; checked at admission, not in `π`; +5.4 KB per hybrid intent) |
| [0034](0034-pq-tunnel-under-libp2p.md) | Hybrid PQ tunnel under Malachite's libp2p | Accepted (opt-in; X25519+ML-KEM-768 tunnel around Noise; no measurable latency on localhost) |
| [0035](0035-clob-as-l2-over-malachite.md) | The CLOB as a private L2 over a commitment-only Malachite L1 | **Proposed** (design only: optimistic settlement with chunk fraud proofs, ZK on demand, committee DA, encrypted disclosure) |
| [0036](0036-ledger-kernel-and-engines.md) | A ledger kernel with pluggable engines | **Proposed** (design only: kernel owns holdings, holds, nonces, policy and the invariants; the CLOB becomes one engine; holdings move into `F` and become private) |

Loaded Malachite height evidence: [m4-loaded](../benchmarks/m4-loaded.md), isolate [m4-loaded-isolate](../benchmarks/m4-loaded-isolate.md) (~0.18 s with shared `I`; ADR 0015). Mixed-view consensus still open (ADR 0008/0009). Live Reth process is a later sidecar swap, not a new matching engine.
