# Documentation

## Start here

| Document | What it covers |
|---|---|
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | Current architecture, components, key measurements, limits |
| [`../ROADMAP.md`](../ROADMAP.md) | Phases 0–7, each with its pass/fail question and result |
| [`open-questions.md`](open-questions.md) | Open research questions and the known gaps of the v1 prototype |
| [`adr/`](adr/README.md) | Architecture decision records 0001–0036, in order |
| [`PROVENANCE.md`](PROVENANCE.md) | What Parallax implemented, what it builds on, and how to verify it |

## Models

| Document | What it covers |
|---|---|
| [`threat-model.md`](threat-model.md) | Adversaries and assumptions |
| [`privacy-model.md`](privacy-model.md) | What each party may learn |
| [`data-availability.md`](data-availability.md) | Availability tiers and recovery without unauthorized disclosure |
| [`post-quantum.md`](post-quantum.md) | Crypto agility and the hybrid suites' status |
| [`performance.md`](performance.md) | Performance targets and the measurement plan |

## Research and design background

| Document | What it covers |
|---|---|
| [`research/reference-architecture.md`](research/reference-architecture.md) | What Malachite, Reth, Arc and related systems actually do |
| [`architecture/initial-design.md`](architecture/initial-design.md) | The Phase 0 design and its stated limits |
| [`research/vitalik-cryptographic-world-computer.md`](research/vitalik-cryptographic-world-computer.md) | Alignment with Ethereum's "cryptographic world computer" direction |
| [`research/airbender-prime.md`](research/airbender-prime.md) | Desk check of the Airbender prover |

The Phase 0 documents record the starting design. Where they differ from later ADRs, the ADRs are authoritative.

## Benchmarks

[`benchmarks/`](benchmarks/) holds the measured results behind each milestone and ADR: method, host, and numbers. Each is cited from the ADR or roadmap phase it supports. All were measured on one Apple M4 Pro (14 cores, 24 GB).
