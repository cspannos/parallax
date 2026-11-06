# Technical provenance

Parallax is an open-source research prototype exploring architectural trade-offs in distributed ledger systems, including deterministic execution, Byzantine fault-tolerant consensus, privacy, verifiable computation, performance, and cryptographic agility.

The project combines established algorithms, publicly available research, and open-source software with implementations and integrations developed specifically for Parallax. It is not affiliated with or endorsed by the upstream projects it uses or references.

This document describes the project's technical components, upstream dependencies, research references, and reproducibility information. It distinguishes implementation work undertaken within Parallax from the libraries, algorithms, and reference architectures on which it builds.

## Research purpose

Parallax investigates architectural trade-offs and limits, including:

- privacy versus independent validation: whether nodes with unequal views can agree on validity (ADR [0008](adr/0008-unequal-view-validity.md) found they cannot without a proof)
- deterministic execution of financial state, and canonical encoding of it
- consensus scalability and finality under BFT
- the cost of proving versus the cost of verifying
- selective disclosure of private state
- cryptographic agility and migration toward post-quantum primitives

It also aims to report reproducibly and transparently, including negative results. It is a prototype: it is unaudited, it does not hide order flow from validators, and it is not post-quantum secure (see [SECURITY.md](../SECURITY.md) and [known gaps](open-questions.md#known-gaps-v1-prototype)).

## Project implementation

The table lists the components implemented for Parallax, and the public technologies and established algorithms each one builds on. The underlying techniques are well established: price-time matching, treap-based commitments, deterministic replicated execution, gossip, BFT consensus, write-ahead logging and hybrid cryptography. Parallax's work lies in the specific implementations, rules and integrations.

| Area | Implemented for Parallax | Builds on |
|---|---|---|
| **Order-book engine** (`clob`, `private-state-engine`, `protocol-types`) | The engine's state-transition rules: price-time matching, cancel, partial fill, expiry, self-trade handling. Also its canonical little-endian codec, derived order ids (ADR 0026) and fixed-point rules (ADR 0006) | Rust standard library collections; the `commitments` crate for state roots. The algorithms are standard exchange-matching practice |
| **State commitment** (`commitments`) | The treap commitment `C'` and its node encoding; lazy hashing (ADR 0032); step witnesses for proofs (ADR 0022) | Treaps and Merkle-style hashing are established structures. Hash implementations come from RustCrypto (`sha2`) and the BLAKE3 team (`blake3`) |
| **Consensus integration** (`consensus-adapter`) | A commitment-only consensus value (ADR 0009); the shared sequenced intent set with gossip and ACK admission (ADRs 0015–0021, 0027); tiered finality certificates (ADR 0031); signed-order admission (ADR 0033); connection limits | Malachite v0.8.0 BFT engine, used through its public application API. The integration follows patterns studied in Arc (see below). Networking is libp2p, via Malachite |
| **Proofs** (`proof-adapter`, `proof-plonky3`, `settlement-pipeline`, `zkvm/`) | Guests that run the project's matching engine inside the zkVM, `π` of `F` (ADR 0025); the settlement gate that keeps unproven heights inert (ADR 0011); the decide → prove → settle pipeline (ADR 0028); Plonky3 circuits (AIRs) for engine fragments | RISC Zero zkVM and its proving system; Plonky3 (FRI, Poseidon2, STARK prover); SP1 for comparison only (ADR 0029). The zkVM host and guest projects were scaffolded from the vendors' templates |
| **Experimental cryptography** (`crypto-suite`, `consensus-adapter/src/pq_tunnel.rs`) | The suite-agility framework and downgrade rules (ADR 0030); the composition of the hybrid signature; the hybrid key-exchange handshake and its transcript binding; the tunnel under libp2p (ADR 0034) | Primitives from RustCrypto (`ml-dsa`, `ml-kem`, `chacha20poly1305`, `hkdf`) and dalek (`ed25519-dalek`, `x25519-dalek`). Hybrid signatures and hybrid KEMs are established constructions. Parallax implements no cryptographic primitive for native use. `proof-plonky3` contains circuit encodings of BLAKE3 compression for proving, not a replacement implementation. The handshake protocol has not been externally reviewed |
| **Replication, disclosure, settlement** (`storage`, `replica`, `disclosure`, `evm-adapter`) | The encrypted height write-ahead log and replay (ADRs 0007, 0012, 0014); the unequal-view experiment (ADR 0008); the settlement apply protocol (ADR 0010) | XChaCha20-Poly1305 (RustCrypto). `evm-adapter` is shaped after Reth's Engine API, but it is an in-process ledger with no Reth dependency |

Project-specific work also includes:
- the way these parts are combined: commitments-only consensus, settlement gated on validity proofs, and hybrid suites across consensus, gossip and transport
- the experimental architecture and the reproducible measurements recorded with each decision

The design record is the [ADR series](adr/README.md); the measurements are in [`benchmarks/`](benchmarks/).

## Upstream software and references

| Upstream | How Parallax uses it |
|---|---|
| Malachite (Circle) | **Dependency**: the BFT consensus engine |
| RISC Zero | **Dependency**: zkVM and prover for `π` of `F` (optional `risc0` feature and `zkvm/risc0`) |
| Plonky3 | **Dependency**: STARK prover for the `proof-plonky3` circuits; also part of the prover comparison |
| RustCrypto, dalek, BLAKE3 | **Dependencies**: hashes, signatures, key exchange, AEAD, KDF |
| libp2p | **Dependency**, via Malachite: validator networking |
| SP1 (Succinct) | **Comparison only**: the prover benchmark in `zkvm/sp1` (ADR 0029); not used by the main workspace |
| Arc (Circle) | **Studied reference**: not a dependency (see below) |
| Reth (Paradigm) | **Studied reference**: the settlement adapter mirrors the shape of its Engine API; not a dependency |
| Ethereum research, dYdX | **Public literature**: cited where relevant |

Notes:

- **Arc** (Circle's open-source node, Apache-2.0) was studied as a reference integration of Malachite. [ADR 0002](adr/0002-arc-fork-vs-components.md) records the decision **not** to fork it. Parallax follows some of Arc's integration patterns, for example the handler structure of Malachite's application message loop, whose shape Malachite's own API largely determines. Arc is not a dependency.
- **Upstream documentation and source** for Malachite, Reth, RISC Zero, SP1 and Plonky3 are summarized in [`research/reference-architecture.md`](research/reference-architecture.md).
- **Public research writing**: Vitalik Buterin's "cryptographic world computer" direction ([digest](research/vitalik-cryptographic-world-computer.md)), and dYdX's order-book design (cited in [open questions](open-questions.md) and the [threat model](threat-model.md)).
- **Project templates.** `zkvm/risc0` and `zkvm/sp1` were scaffolded from the RISC Zero and SP1 project templates. Both are attributed in [NOTICE](../NOTICE).

## Dependency and implementation verification

1. **Dependency sources and declared licenses.** `python3 scripts/audit-dependencies.py` runs `cargo metadata --locked` on the three Cargo workspaces (the root, `zkvm/risc0`, `zkvm/sp1`). It checks each third-party package's source against an allow-list, and its declared SPDX license against a list of open-source licenses. It also checks the sources recorded in the six RISC Zero guest lockfiles. The first run may download crate metadata. Results at the v1 freeze (2026-11-06), unchanged when re-run on the same date:
   - 22 crates in this repository; 1 067 third-party packages in the three workspaces
   - Sources: 1 049 from crates.io, and 18 from Malachite's public GitHub repository. The guest lockfiles add 939 crates.io entries and 3 from RISC Zero's public `sha2` fork
   - Declared licenses: permissive open-source licenses (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0 and similar), plus five packages under MPL-2.0. Every package in the three workspaces declares a license
   - No private registries or private repositories appear, and no `vendor/` directories exist

   **Limits.** This inspects declared license metadata only. It is not a license-compliance audit. It does not check the license texts, notices or attribution obligations of each dependency. It checks only the sources of the guest lockfiles, not their licenses.
2. **Pinned versions.** `Cargo.lock`, `zkvm/risc0/Cargo.lock`, `zkvm/sp1/Cargo.lock` and the guest lockfiles under `zkvm/risc0/methods/*/` pin every dependency to an exact version or commit. Malachite is pinned to tag `v0.8.0` (commit `72143f6c99a98452b587e1c392bdb80944eb2232`).
3. **Upstream modifications.** The only `[patch]` entries replace `sha2` with the zkVM vendors' public accelerated forks. They are in `zkvm/risc0/methods/{f,fprof,tape}/Cargo.toml` (RISC Zero, tag `sha2-v0.10.9-risczero.0`) and `zkvm/sp1/Cargo.toml` (SP1, tag `patch-sha2-0.10.9-sp1-6.2.0`). Malachite and every other dependency are used as published, with no patches, forks or vendored copies.
4. **Implementation, decisions and measurements.** The source, the ADRs (with the reasoning and alternatives behind each decision), and the benchmark methods and results can all be read and re-run. Most benchmark documents record their command and setup. All results were measured on one Apple M4 Pro (14 cores, 24 GB), as noted in the [documentation index](README.md#benchmarks).
5. **Proof fixture.** The RISC Zero guest image ID is pinned in `crates/proof-adapter/tests/fixtures/f_guest.id`. `cargo test -p proof-adapter --features risc0 --test risc0_gate` verifies the committed receipt (`f_crossing.receipt`) against it. Rebuilding the image ID bit for bit from source has not been independently verified.

## Trademarks

Malachite, Arc, RISC Zero, SP1, Plonky3, Reth, Ethereum, dYdX and other names belong to their respective owners. They are used here only to identify the software and work that Parallax uses or studied.
