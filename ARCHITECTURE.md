# Architecture

Living summary of the Parallax research prototype. Details: [`docs/architecture/initial-design.md`](docs/architecture/initial-design.md). Decisions: [`docs/adr/`](docs/adr/).

This is not a production specification. Unresolved problems are listed in [`docs/open-questions.md`](docs/open-questions.md).

## Intent

A Rust-native financial execution network in which:

- Malachite orders and finalizes a **consensus value of commitments** (not an EVM payload)
- a Private State Engine executes high-frequency financial transitions (CLOB first)
- Reth/revm applies **settlement deltas** for EVM composability
- participants receive only authorized views
- cryptographic algorithms are versioned and replaceable

The guiding question is whether this works. The answer is not assumed to be yes.

Against Ethereum’s 2030 “cryptographic world computer” ([digest](docs/research/vitalik-cryptographic-world-computer.md)): we are aligned on **structure** (specialized matching off the EVM; compact on-chain claims) and **partly** aligned on **verification**: a zkVM `π` of `F` now exists and can unlock settlement (ADR [0025](docs/adr/0025-pi-of-f-on-zkvm.md)), but it is not yet fast enough to be the validity predicate of every height, and public DA of the snapshot is open. Malachite decide is still treated as **ordering / preconfirmation**; a height becomes valid for settlement when its `π` verifies.

## Diagram

```text
                         CLIENTS
                            │
                   encrypted intents
                            │
                  PRIVATE P2P CHANNELS
                            │
                  PRIVATE STATE ENGINE
                            │
              ┌─────────────┼─────────────┐
              │             │             │
             CLOB          RFQ*        Auction*
              │             │             │
              └─────────────┼─────────────┘
                            │
                 deterministic transition
                            │
           ┌────────────────┴────────────────┐
           │                                 │
    commitments / proofs              settlement delta
           │                                 │
           │                            Reth / revm
           │                                 │
           └────────────────┬────────────────┘
                            │
                     MALACHITE
                 (deterministic BFT)
                            │
                      FINAL VALUE
              (public roots + certificates)
```

`*` RFQ and auction are module names only. They are not in scope until CLOB + commitments + views work.

## Property split

| Property | Mechanism (intent) |
|---|---|
| Consensus | Malachite Tendermint-style decide |
| Execution validity | PSE `F` locally; endgame `π` (SNARK of a public statement). BFT vote ≠ validity |
| Data availability | Tiered; no DA L1 in the prototype |
| Confidentiality | Capabilities; metadata leakage documented |
| Recovery | Encrypted WAL + replay |
| Settlement | System-mediated `SettlementDelta` into Reth |
| Auditability | Authorized openings + public commitments |

BFT agreement on a commitment is not validity, availability, or confidentiality.

## Status (v1 prototype)

Every phase in [`ROADMAP.md`](ROADMAP.md) (0–7) answered its pass/fail question. What exists:

| Component | Crate(s) | What it does |
|---|---|---|
| Canonical types | `protocol-types` | Orders, inputs, consensus value, settlement deltas; versioned little-endian codec; crypto suite ids |
| State commitment `C'` | `commitments` | SHA-256 treap with lazy hashing (ADRs 0013, 0024, 0032); step witnesses for proofs (ADR 0022) |
| Private state engine `F` | `clob`, `private-state-engine` | Deterministic price-time CLOB: limit, cancel, partial fill, expiry; order ids derived from `(owner, nonce)` (ADR 0026) |
| Replication and recovery | `storage`, `replica` | Encrypted append-only WAL (XChaCha20-Poly1305), one fsync per height, crash and replay (ADRs 0007, 0012, 0014) |
| Disclosure experiment | `disclosure` | Labelled views of one height; showed that unequal views cannot share validity without a proof (ADR 0008) |
| Consensus | `consensus-adapter` | Malachite v0.8 deciding a commitment-only value; shared sequenced intent set, gossip and ACK admission (ADRs 0009, 0015–0021, 0027); signed orders (ADR 0033); tiered finality (ADR 0031); connection limits |
| Settlement | `evm-adapter`, `proof-adapter` | Privileged batch apply of settlement deltas (ADR 0010); settlement stays inert until a verified proof or certificate (ADR 0011) |
| Proofs | `proof-adapter`, `settlement-pipeline`, `zkvm/` | RISC Zero proof of the real matcher, `π` of `F` (ADR 0025), unlocks settlement end to end (ADR 0028). Plonky3 circuits for fragments; SP1 compared (ADR 0029) |
| Post-quantum hybrid | `crypto-suite` | Ed25519 + ML-DSA-65 signatures, X25519 + ML-KEM-768 key exchange, downgrade rejection, PQ tunnel under libp2p (ADRs 0030, 0034) |

### Key measurements

All on one Apple M4 Pro (14 cores, 24 GB); multi-validator numbers run every validator on that one machine.

| What | Result |
|---|---|
| Matching engine, one core | ~1.5 M events/s (10k events plus state root in ~6.5 ms) |
| Consensus, 4 validators, 8k-order book, 10k orders per height | ~90 ms per height injected; ~108 ms with gossip (~93k orders/s unsigned) |
| Signed orders decided | ~12k/s hybrid (Ed25519 + ML-DSA-65); ~30–60k/s classical |
| Decided throughput ceiling, one host | ~60–100k orders/s; bigger heights add latency, not throughput ([batch-size](docs/benchmarks/batch-size.md)) |
| `π` of `F`, real proofs on CPU | crossing height 19 s; 1 000 resting + 8 events ~10 min; receipt 224 KB, verify ~10 ms |
| `π` of a loaded height (8k resting, 10k events) | 212 M cycles, ~3.5–4 CPU-hours projected (ADR 0032) |
| Hybrid signature | sign 64 µs, verify 73 µs, 3 379 B |
| Tiered finality bandwidth | 4–14× fewer consensus bytes than hybrid votes at n ≤ 20 ([q-cry-5-wire](docs/benchmarks/q-cry-5-wire.md)) |

Detailed results and methods: [`docs/benchmarks/`](docs/benchmarks/).

### What it is not

- **Not private from validators.** Every validator sees the full order flow; the disclosure views are labels, not encryption (ADR 0008).
- **Not real-time proven.** Proving a loaded height takes hours on CPU; settlement waits for it, or relies on a certificate.
- **Not a funds-checked ledger.** Balances live in the settlement ledger, outside `F` and outside the proof.
- **Not post-quantum secure.** The hybrid suites are experimental, built on pre-1.0 libraries.
- **Not measured across machines** or at 50–100 validators on a real network.

Known gaps: [`docs/open-questions.md`](docs/open-questions.md#known-gaps-v1-prototype).

## Next version (proposed)

Two design ADRs, not implemented:

- [ADR 0035](docs/adr/0035-clob-as-l2-over-malachite.md): execution moves to a private operator committee (an L2); Malachite only orders and settles commitments, with fraud proofs and validity proofs on demand. Validators stop seeing order flow, and proving leaves the critical path.
- [ADR 0036](docs/adr/0036-ledger-kernel-and-engines.md): `F` becomes a ledger kernel (accounts, holdings, holds, policy, conservation) with pluggable engines, the CLOB being one, aimed at institutional ledgers: sub-accounting, funds, transfer agents, omnibus accounts.
