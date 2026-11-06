# Parallax

**A research prototype of a private, high-throughput financial ledger: a deterministic order-book engine under BFT consensus, with zero-knowledge proofs of execution and post-quantum hybrid cryptography.**

> [!WARNING]
> **Prototype only. Not production software.**
> Parallax v1 is a research proof of concept. It has **not been audited**, contains known security gaps, and must not be used to hold, move or secure real assets. It is provided "as is", without warranty of any kind. **You use it entirely at your own risk; the authors accept no liability for any loss, including loss of funds.** See [LICENSE](LICENSE) (sections 7 and 8), [NOTICE](NOTICE) and [SECURITY.md](SECURITY.md).

## What it explores

Parallax asks whether one Rust-native network can combine:

- **BFT finality** with [Malachite](https://github.com/circlefin/malachite), deciding a value made of commitments, not transactions
- a native **private state engine** for high-frequency financial state (a central limit order book first)
- **validity proofs** of the real engine, so settlement does not have to trust the validators
- **selective disclosure** of private state
- **cryptographic agility**, including experimental post-quantum hybrid signatures and key exchange

The question is whether the design works, not how to make the answer yes. Results that came out "no" are recorded as such.

## Independent research

Parallax is an independent, self-directed research project that builds on publicly available research and open-source software. It is not affiliated with or endorsed by any of the projects it uses. Its order-book engine, commitment scheme, Malachite consensus integration, RISC Zero proof pipeline and experimental hybrid cryptography were implemented for this project, on top of established techniques and public libraries. [PROVENANCE](docs/PROVENANCE.md) records what was implemented here, what is upstream, and how to verify the technical claims. `python3 scripts/audit-dependencies.py` checks that each of the 1 067 third-party packages comes from a public source and declares an open-source license.

## Status: v1 prototype

All eight roadmap phases are complete, and each answered its pass/fail question ([ROADMAP](ROADMAP.md)):

| Phase | Question | Result |
|---|---|---|
| 0. Research | What do the upstream systems actually do? | Reference study, threat, privacy, DA and PQ models |
| 1. Private state engine | Do identical inputs always give a byte-identical book, fills and root? | Yes. ~1.5 M matching events/s on one core |
| 2. Replication | Do replicas agree after crashes, replays and delays? | Yes, with an encrypted write-ahead log |
| 3. Selective disclosure | Can nodes with different views agree on validity? | **No**, not without a proof ([ADR 0008](docs/adr/0008-unequal-view-validity.md)) |
| 4. Consensus | Can Malachite decide over the private engine? | Yes. 4–100 validators on one host |
| 5. Settlement | Do settlement deltas apply atomically with each height? | Yes, against an in-process settlement ledger |
| 6. Proofs | Can the real engine be proven, and gate settlement? | Yes. A RISC Zero proof of the matcher unlocks settlement end to end |
| 7. Post-quantum hybrid | Can suites be hybrid, with downgrades rejected? | Yes, experimentally. **Not** post-quantum secure |

Headline measurements, all on one Apple M4 Pro with every validator on the same machine:

- **~93k orders/s** decided by 4 validators unsigned; **~12k/s** with hybrid post-quantum signatures on every order
- **~10 ms** to verify a 224 KB proof of a height; producing one for a loaded height takes **~3.5–4 CPU-hours**
- **4–14× less** consensus bandwidth with tiered finality than with hybrid signatures on every vote

What v1 does **not** do: hide order flow from validators, prove heights in real time, check funds inside the proven engine, or run across multiple machines. The full list is in [ARCHITECTURE.md](ARCHITECTURE.md#what-it-is-not) and [known gaps](docs/open-questions.md#known-gaps-v1-prototype).

## Next version

Two proposed designs, not implemented, address v1's main limits:

- [ADR 0035](docs/adr/0035-clob-as-l2-over-malachite.md) moves execution to a private operator committee, so validators see only commitments and proving leaves the critical path.
- [ADR 0036](docs/adr/0036-ledger-kernel-and-engines.md) generalizes the engine into a ledger kernel with pluggable engines, aimed at institutional ledgers: sub-accounting, funds, transfer agents and omnibus accounts.

## Repository layout

```text
crates/
  protocol-types        canonical types and codec
  commitments           SHA-256 treap state commitment (C')
  clob                  deterministic order-book engine (F)
  private-state-engine  engine API
  storage, replica      encrypted WAL, replication and recovery
  disclosure            unequal-view experiment
  consensus-adapter     Malachite integration, intent gossip, finality, PQ tunnel
  evm-adapter           settlement ledger (privileged batch apply)
  proof-adapter         proof verification and the settlement gate
  proof-plonky3         Plonky3 circuits for engine fragments
  settlement-pipeline   decide → prove → settle pipeline
  crypto-suite          classical and hybrid post-quantum suites
  tiny-f                minimal transition used to compare provers
benchmarks/             engine and consensus benchmark harnesses
scripts/                dependency provenance audit
zkvm/                   RISC Zero and SP1 guests (separate workspaces)
docs/                   architecture, models, ADRs, benchmark results
```

## Building and testing

Requires stable Rust (tested with 1.98) on macOS or Linux.

```bash
cargo test --workspace                  # full suite; the Plonky3 tests are slow in debug builds
cargo run -p clob-bench --release       # engine benchmarks
cargo run -p m4-scale --release         # consensus benchmarks (see the PLX_M4_* knobs in its source)
```

Proofs need the [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install):

```bash
cargo test -p proof-adapter --features risc0                          # verify pinned proof fixtures
RISC0_DEV_MODE=0 cargo run --release -p settlement-pipeline --features risc0 --bin e2e   # local cluster: decide, prove, settle
```

The zkVM guests and the prover comparison are described in [`zkvm/README.md`](zkvm/README.md) and [`docs/benchmarks/m6-prove.md`](docs/benchmarks/m6-prove.md).

## Documentation

Start with [ARCHITECTURE.md](ARCHITECTURE.md), then the [documentation index](docs/README.md). Every significant decision is an [ADR](docs/adr/README.md), with the measurement behind it in [`docs/benchmarks/`](docs/benchmarks/).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions.
