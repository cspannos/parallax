# Reference Architecture Research

**Date:** 2026-09-25  
**Method:** Read current upstream repositories and specs. APIs not fetched line-for-line are marked **unverified**.  
**Rule:** do not treat this file as an implementation spec. Implementation waits on review of the design docs.

This document answers: what do the reference systems actually do, what can we reuse, and which problems they leave open.

---

## 1. Malachite

**Repo:** [circlefin/malachite](https://github.com/circlefin/malachite)  
**Version read:** `main` / workspace **0.8.0** (release 2026-08-27)  
**License:** Apache-2.0  
**Maturity:** README: alpha, heavy development, **not externally audited**.

### What it is

A Rust BFT engine implementing **Tendermint** (Buchman / Kwon / Milosevic, [arXiv:1807.04938](https://arxiv.org/abs/1807.04938)). Informal Systems lineage (CometBFT lessons); team joined Circle to build Arc. Starknet funded early work; that is provenance, not the algorithm. Only Tendermint is implemented. Specs live in `specs/consensus` (English + Quint).

Published crates are prefixed `arc-malachitebft-*`.

### Application interface (actual names)

There is **no** `Host` or `Application` trait. Integration surfaces:


| Surface            | Crate            | Role                                                                              |
| ------------------ | ---------------- | --------------------------------------------------------------------------------- |
| `Context`          | `core-types`     | Associated types: `Value`, `Proposal`, `Vote`, `ValidatorSet`, `SigningScheme`, … |
| `Input` / `Effect` | `core-consensus` | Pure coroutine: host feeds inputs, handles effects                                |
| `AppMsg`           | `app-channel`    | **Recommended** channel API                                                       |
| `HostMsg`          | `engine`         | Actor-level equivalent                                                            |


`Context` provides `select_proposer`, `new_proposal`, `new_prevote`, `new_precommit`. Signing is `Signer` / `Verifier` in `arc-malachitebft-signing`, not methods on `Context` (ADR-001 in their tree is stale).

Important `Effect`s: `GetValue`, `SignProposal`, `SignVote`, `PublishConsensusMsg`, `Decide`, then `Finalize` (commit certificate + `MisbehaviorEvidence`). Height advances only after the app replies to `Finalize` with `StartHeight`.

Important `AppMsg`s: `ConsensusReady`, `StartedRound`, `GetValue`, `ReceivedProposalPart`, `RestreamProposal`, `Decided`, `Finalized`, `GetDecidedValues`, `ProcessSyncedValue`.

### Consensus values

`Value` is an application type with an `Id`. Consensus votes on `id(v)`, not necessarily the full value. Default mode since 0.8.0: `ProposalAndParts` — proposal carries the id; the app streams parts. `PartsOnly` was removed. `ProposalOnly` is documented as not fully supported.

**The application constructs the value** when Malachite emits `GetValue`. Malachite does not build blocks.

`valid(v)` is **application-defined**, must be **deterministic and identical across correct processes**, and may depend on agreed prior state — not on wall clock. Non-deterministic `valid` can stall a height.

### Validator sets

Malachite does **not** compute membership. Each height the app supplies `HeightParams { validator_set, timeouts, target_time, vote_extension_policy }`. Proposer selection is `Context::select_proposer`. Dynamic sets are an app policy (test middleware `RotateValidators` exists). A catch-up bug with rotating sets was reported (#1240) and claimed fixed in #1177.

### WAL

Crash-recovery, not a chain store. Checkpoint = start of height. Persisted inputs (0.8.0 engine codec): votes/proposals, some timeouts, `ProposedValue`, `PolkaCertificate`. **Not** persisted: `StartHeight`, `Propose`, `RoundCertificate`, `SyncValueResponse`. WAL flush failure can **safety-hang** the node to avoid double-signing. Gap: issue #1445 (certificates / sync responses).

This WAL is **consensus-message durability**, not CLOB durability.

### Synchronization

**Value-sync** of decided heights (status gossip + request-response). Vote-set sync was removed (0.3.0). Does not sync mempools or uncommitted parts. App must persist decided values and validate synced bytes.

### Networking

Bundled engine: **libp2p 0.56** (TCP, QUIC, Noise, Yamux, gossipsub, Kademlia, request-response). Channels: Consensus, ProposalParts, Sync, Liveness. Core consensus is network-agnostic. Channel API **cannot** swap the stack; actor or core-only can.

### State machine

Tendermint rounds: Propose → Prevote → Precommit → Commit. Locks + `validValue` for liveness. Skip-round on `f+1` future-round messages. Threshold <⅓ Byzantine voting power. **Instant finality:** a decide is irreversible. `getValue()` is async; propose timeout runs while the app builds.

`Decide` vs `Finalize`: decide commits the value; finalize waits optional `target_time`, may add precommits, delivers equivocation evidence, then the app starts the next height.

### What Malachite assumes / does not assume

**Assumes:** a `Value` and `id(v)`; deterministic identical `valid(v)`; per-height validator set; app persist for sync; crash-safe signing; host I/O.

**Does not assume:** what a value is; execution; merklization; mempool; how sets evolve; store format; networking (core); WASM/Tokio.

### Performance (theirs, unverified)

~780 ms finality, 100 validators, 1 MB blocks; up to ~2.5 blocks/s or ~13.5 MB/s.

### Reuse

Use as **upstream consensus**. Preferred integration: `app-channel` + our `Context`. Do not modify Malachite in this repository.

### Divergence

`valid(v)` under unequal disclosure is **our** problem. Malachite will not solve it.

---



## 2. Arc

**Repo:** [circlefin/arc-node](https://github.com/circlefin/arc-node)  
**License:** Apache-2.0, `publish = false`  
**Pinned:** Malachite `v0.8.0`, Reth `v2.2.0`  
**What it is:** Permissioned-validator, permissionless-developer, USDC-gas EVM L1. Testnet/alpha; audits in progress.

### How Malachite connects to Reth

Two processes:

```text
arc-node-consensus  (malachite-app)
        Engine API (IPC preferred; JWT HTTP deprecated toward v0.9.0)
arc-node-execution  (Reth ArcNode)
```

Flow:

1. `GetValue` → `forkchoiceUpdatedV3(parent, payload_attributes)` → `getPayloadV4/V5`
2. Self-`newPayloadV4`; stream SSZ `ExecutionPayloadV3` as gossip parts
3. Receivers assemble, `newPayload` (validate, do not canonicalize)
4. Vote on **block hash**
5. `Decided` → `forkchoiceUpdatedV3(head=hash, no attributes)`

Attributes: `prev_randao = 0`, empty withdrawals, `parent_beacon_block_root = parent execution hash`, timestamp non-decreasing. Blobs rejected.

Validator set at height `H` is `eth_call` to ValidatorRegistry at execution block `H-1`. Consensus params similarly from ProtocolConfig. Vote extensions stubbed.

### What to reuse vs reject

See [ADR 0002](../adr/0002-arc-fork-vs-components.md). **Decision: C — patterns, not a fork.**

Reuse: `AppMsg` handler map, hash-as-value + part streaming, validate-before-vote, GetValue reuse, binding checks, value-sync/follow/snapshots as ops ideas, Reth `NodeTypes` injection **if** we keep a public EVM.

Do not reuse: Engine API as the native execution type, USDC genesis, on-chain registry as the only `HeightParams` source, txpool-as-CLOB.

### Arc privacy is not our privacy

Node README: opt-in privacy “coming soon.” APS whitepaper (June 2026): **pEVM in enclaves; every honest validator decrypts the same plaintext**; public sees an encrypted root. That is confidentiality vs the public/host, not selective disclosure among validators.

### Custom Reth extensions (for awareness)

Precompiles `0x1800…0000`–`0004` (native coin, blocklist, accounting, CallFrom, SLH-DSA-SHA2-128s). Fee manager / EWMA. Relaxed timestamp. Still `EthPrimitives` / `EthEngineTypes`.

---



## 3. Reth

**Repo:** [paradigmxyz/reth](https://github.com/paradigmxyz/reth)  
**Docs:** [reth.rs](https://reth.rs/)  
**License:** Apache-2.0 AND MIT  
**Maturity:** Production EL; 2.0 April 2026 (vendor statements).

### Modular architecture / SDK

Assemble a node with `NodeTypes` + component builders:

```text
NodeBuilder
  .with_types::<EthereumNode>()   // or custom
  .with_components(EthereumNode::components().pool(...).executor(...).consensus(...).payload(...))
  .with_add_ons(...)
  .launch()
```

`NodeTypes`: `Primitives`, `ChainSpec`, `Storage`, `Payload`. Arc’s `ArcNode` keeps `EthPrimitives`, `EthStorage`, `EthEngineTypes`, swaps `ArcChainSpec`.

**ExEx** ≠ custom EVM. ExEx consumes canonical notifications for derived state and must not block execution. Wrong place for a CLOB.

Custom EVM: `EvmFactory` / `ConfigureEvm` / `ExecutorBuilder` (official `examples/custom-evm` adds a **precompile**, not a new opcode).

### Engine API

Reth is the EL. Versioned `new_payload`, `fork_choice_updated`, `get_payload`. Payload jobs start from FCU+attributes. 2.0 persistence backpressure if persist lags.

### Pool, storage, net, RPC

- Pool: pending/queued/basefee/blob; nonce/fee/blob rules. Not a CLOB.
- Storage V2 (new DBs): **MDBX** hashed state, **static files** history, **RocksDB** for some indices. Not “RocksDB for everything.”
- Net: discv4/5, `eth` RLPx. In PoS, broadcasting new blocks is a protocol violation.
- RPC: `eth_`, `engine_`, `debug_`, `trace_`, … jsonrpsee.



### Consensus interface

`EthBeaconConsensus` / `FullConsensus`: **header/body/post-execution checks**, not BFT. Fork choice is the external CL.

### Reuse

Reth as **settlement + Ethereum tooling sidecar**. Custom chain spec, privileged apply path, standard `eth_` for wallets.

### Do not put through Reth

Per-order matching, cancel/ack at matching latency, the book in MDBX, `eth_sendRawTransaction` as the order API.

---



## 4. revm

**Repo:** [bluealloy/revm](https://github.com/bluealloy/revm)  
**License:** MIT  
**API note:** current surface is `Context::mainnet().build_mainnet()` + `Journal`. Older `EvmBuilder` / `JournaledState` tutorials are stale.

revm is the EVM library: execute a tx against a `Database`, get a delta. `no_std` / zkVM-friendly. Optimism is the cited custom-handler production example.

### When to use revm without Reth

Simulations, unit tests of settlement deltas, later ZK guests that replay `F` or apply deltas. **Not** as the node if we promised Ethereum RPC/tooling.

### Trade-off


|                          | revm-only           | Reth node                | Reth sidecar        |
| ------------------------ | ------------------- | ------------------------ | ------------------- |
| Tooling                  | You rebuild `eth_`  | Full                     | Full on the sidecar |
| Latency                  | Lowest              | Sequential EVM + persist | Matching can bypass |
| Canonical Ethereum state | You                 | Reth                     | Reth                |
| Closest analog           | Foundry / zk guests | Base / Gnosis Reth       | **Arc**             |


---



## 5. dYdX v4 CLOB

**Repo:** [dydxprotocol/v4-chain](https://github.com/dydxprotocol/v4-chain)  
**Path:** `protocol/x/clob` (Go; no crate README)

### Semantics (do not copy blindly)

Each node has a local optimistic in-memory book (`MemClobPriceTimePriority`): price levels as maps, FIFO doubly-linked lists, O(1) cancel index.

**Consensus is not “everyone rematches the same book.”** The proposer injects `MsgProposedOperations` (a match tape). DeliverTx **replays proposed fills**. ProcessProposal does **not** rematch. Books may diverge. Short-term orders gossip via CheckTx, live in RAM, **die on restart**, appear on-chain only if they participated in a proposed match. Cancels are best-effort. Stateful orders persist, activate **N+1**, survive restart via time-ordered hydration.

Price/time: best price, then FIFO. Integer `Subticks`. Matching is deterministic **given a book + taker**; consensus determinism is **deterministic apply of a proposer tape**.

### Learn

Hot book vs committed fills; integer ticks; cache-then-commit fills; replay leftover intent after a block; hydrate only durable orders; document cancel weakness if cancels are gossip-only.

### Discard / redesign

Cosmos CheckTx/DeliverTx; N+1 stateful delay; sequence numbers; GTB vs GTBT as a Cosmos halt hack (re-evaluate); map+tick-walk for next price; unverified order removals; assuming validators share one book.

### Implication for Parallax Phase 2

Phase 2 requires four nodes, **identical ordered inputs**, **identical roots**. That is **Model I**, not dYdX Model II. If we later need Model II, Phase 2’s test is the wrong invariant for production matching — say so in an ADR.

---



## 6. libp2p (rust-libp2p)

**Repo:** [libp2p/rust-libp2p](https://github.com/libp2p/rust-libp2p)

Malachite/Arc already use gossipsub (consensus, status), request-response (sync), QUIC and TCP, Ed25519/ECDSA peer keys. Gossipsub is best-effort, unordered, no history. Issue #169 in Malachite asked to **benchmark** TCP+TLS+Yamux vs TCP+Noise+Yamux vs QUIC — not to declare a winner.

**QUIC:** 1-RTT handshake, no HoL across streams. On a persistent validator mesh the handshake advantage vanishes. rust-libp2p request-response default upgrade can add an RTT (V1Lazy helped one user ~90→30 ms — **one deployment**). **Measure order-propagation p99.** Do not assume QUIC wins.

Logical channels we likely need (separate topics/streams): consensus, public txs, private intents, encrypted orders, state sync, DA fragments, proofs. Do not share one gossipsub topic.

PQ: harvest-now-decrypt-later is KEM. Hybrid ML-KEM in rust-libp2p QUIC is **unverified**.

---



## 7. Persistence candidates


| Engine      | Who uses it nearby                         | Notes                                                                        |
| ----------- | ------------------------------------------ | ---------------------------------------------------------------------------- |
| **redb**    | Malachite test store; Arc `consensus-db`   | Pure Rust, CoW B+tree, crash-safe default. Precedent for consensus artifacts |
| **MDBX**    | Reth hashed state                          | C, mmap, Reth’s choice for execution state                                   |
| **RocksDB** | Reth V2 **indices** (not default state DB) | LSM, ops-heavy. **Do not commit** until we benchmark our mix                 |
| **fjall**   | —                                          | Pure Rust LSM; default not fsync; not multiprocess-safe                      |
| **sled**    | —                                          | Production status **unverified** this pass                                   |


Phase 2 should abstract a store trait and measure. Consensus WAL (Malachite) ≠ application WAL (orders).

---



## 8. Proving systems (compare only)


|                 | SP1                                             | RISC Zero                                         | Plonky3                                |
| --------------- | ----------------------------------------------- | ------------------------------------------------- | -------------------------------------- |
| Class           | RISC-V zkVM                                     | RISC-V zkVM                                       | AIR/PIOP toolkit                       |
| Rust guest      | Yes                                             | Yes                                               | No (you write circuits)                |
| Recursion       | Yes + optional Groth16/PLONK wrap               | Yes + Groth16 wrap                                | DIY                                    |
| GPU             | CUDA (vendor reqs)                              | CUDA + Metal                                      | README: no GPU backend                 |
| On-chain wrap   | Groth16 ~260 B / PLONK ~868 B (**vendor docs**) | Groth16                                           | You choose                             |
| PQ-ready verify | Inner STARK-family: arguably; **wrap: no**      | STARK receipts: their table says yes; Groth16: no | FRI+hash: ready under hash assumptions |


**Do not pick by popularity.** M6a proved the **same tiny transition** on all three stacks ([`m6-prove.md`](../benchmarks/m6-prove.md)). Still no pick.

STARKs (hash/FRI) ≠ pairing SNARKs. A verifier that only checks Groth16-BN254 is not PQ-ready.

---



## 9. Reusable components (summary)


| Component                           | Reuse                                          |
| ----------------------------------- | ---------------------------------------------- |
| Malachite `app-channel` + `Context` | Yes, upstream                                  |
| Malachite WAL / value-sync / libp2p | Yes for **consensus** artifacts                |
| Arc handler algorithms              | Yes, retyped                                   |
| Arc Engine API value type           | No                                             |
| Reth SDK `NodeTypes`                | Yes, settlement sidecar                        |
| Reth txpool / ExEx as CLOB          | No                                             |
| revm                                | Yes, tests + later guests                      |
| dYdX book *ideas*                   | Yes; not the ABCI split                        |
| rust-libp2p                         | Yes, via Malachite first                       |
| redb                                | Leading candidate for consensus-adjacent store |
| SP1 / R0 / Plonky3                  | M6a measured; no pick                          |
| Celestia / EigenDA / Avail          | Not initially                                  |


---



## 10. Unresolved research this survey cannot close

All of `[docs/open-questions.md](../open-questions.md)`. The load-bearing ones:

1. Identical `valid(v)` under unequal disclosure (Q-CONS-3).
2. Soundness of consensus on `C, C', Δ, π` without `π` on the fast path (Q-PRF-2).
3. Recovery of private fragments without unauthorized disclosure (Q-DA-2).
4. Atomic native fill ↔ EVM balance (Q-SET-1).
5. Whether Model I survives contact with privacy (Q-CLOB-1).

None of these are solved by combining the reference implementations.