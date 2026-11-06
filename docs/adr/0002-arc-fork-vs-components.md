# ADR 0002 — Fork Arc, Build from Malachite + Reth, or Reuse Patterns

**Status:** Accepted  
**Date:** 2026-09-25  
**Deciders:** Protocol architecture (research prototype)

## Context

Circle’s [arc-node](https://github.com/circlefin/arc-node) is the only production-oriented open implementation that already wires:

```text
Malachite (app-channel) → consensus shim → Engine API → Reth
```

It is the correct reference for *how a Malachite application talks to Reth*. It is the wrong product to become.

Arc’s consensus value is an Ethereum `ExecutionPayloadV3`. Validators vote on the execution **block hash**. The CL asks the EL to build and validate that block via `engine_forkchoiceUpdatedV3`, `engine_getPayloadV4/V5`, and `engine_newPayloadV4`. Validator sets and consensus timeouts are read from EVM system contracts. Privacy in the node is “coming soon”; the published Arc Privacy Sector design (June 2026) is a **pEVM inside hardware enclaves in which every honest validator decrypts and re-executes the same plaintext**. That is confidentiality against the public and the host OS, not selective disclosure among validators.

`arc-node` crates are `publish = false`, Apache-2.0, and tightly coupled to USDC-as-gas, Arc genesis allocs, and Ethereum payload types.

Three options were considered:

- **A.** Fork `arc-node` and rename it.
- **B.** Build a node from Malachite + Reth with no Arc lessons.
- **C.** Reuse selected Arc patterns and write a new Malachite application.

## Decision

**C.** Do not fork Arc. Do not start from a blank Malachite+Reth integration as if Arc had not already paid the application-layer cost.

Build a new node whose consensus application speaks Malachite `AppMsg` and whose execution port is protocol-defined. Treat Arc as a reference implementation.

### Reuse as pattern (do not vendor as-is)

| Arc artifact | Reuse how |
|---|---|
| `AppMsg` loop (`ConsensusReady`, `GetValue`, `ReceivedProposalPart`, `Decided`, `Finalized`, `ProcessSyncedValue`) | Copy the *handler map* into `consensus-adapter` |
| Value = hash; payload streamed as parts (ADR-0002 in Arc) | Same shape; different codec |
| Validate-before-vote; canonicalize-on-decide | Keep |
| Deterministic `GetValue` reuse for `(height, round)` | Keep — crash recovery |
| Binding checks (parent, height, predecessor) | Keep |
| Value-sync, follow/RPC sync, snapshots | Ops model, later phases |
| Two-process crash domains | Optional for the Reth sidecar |
| `NodeTypes` injection if a public EVM remains | Reth SDK pattern, not Arc precompiles |
| Hardcoded wire constants vs per-node CLI | Keep the discipline |

### Do not reuse as the protocol

| Arc artifact | Why not |
|---|---|
| `eth-engine` / `ExecutionPayloadV3` as the value | Cannot carry private state, match tape, or disclosure sets |
| `execution-payload` / `execution-txpool` as the order path | Ethereum mempool, not a CLOB |
| On-chain validator registry as the only source of `HeightParams` | Couples consensus to EVM ABI |
| USDC genesis, Fee Manager, native-coin precompiles | Different asset/fee model |
| APS enclaves as the privacy answer | Different threat model (see below) |
| `malachite-app` binary | Arc-specific monolith |

### Dependency versions (current as of this research, 2026-09-25)

- Malachite `v0.8.0` (`arc-malachitebft-*`), Apache-2.0, **alpha, unaudited**
- Reth `v2.2.0` in Arc; upstream Reth 2.0 (April 2026) is the SDK generation to track
- Do not pin until Phase 4/5 implementation

## Alternatives

### A. Fork Arc

**Rejected as the primary path.**

Pros: working two-process node, Engine API already debugged, ops tools (quake, snapshots).

Cons: every CL crate assumes Ethereum payloads and Arc genesis. A fork becomes a permanent rebase on Circle’s L1. Selective disclosure, CLOB, and a native engine would be implemented by deleting the product’s core assumption. Apache-2.0 allows copying with attribution; it does not make crates independently dependable.

A later, optional **EVM-compatibility sidecar** may still copy Arc’s Reth `NodeTypes` wiring. That is extraction, not a product fork.

### B. Malachite + Reth only, ignore Arc

**Rejected as a design method.** Correct as a *dependency* choice (we depend on Malachite and Reth, not on `arc-node`). Incorrect as a *design* choice: we would re-discover streaming large values, GetValue determinism, replay/handshake, binding halt, persistence backpressure, follow mode, and certificate storage.

## Consequences

- New repository, new crate names, new consensus `Context` / `Value`.
- Phase 4 implements a Malachite application from the channel tutorial and Arc’s handler *algorithms*, retyped.
- Phase 5 may run Reth as a sibling process. Engine API is then an adapter, not the protocol.
- Legal: Apache-2.0 attribution if any Arc code is copied. No “Arc” branding.

## Security implications

Forking Arc would import a validation model in which `valid(v)` = `engine_newPayload` on a public block. That model **cannot** express `InsufficientView`. Starting from Arc makes it easy to “solve” privacy by encrypting the same payload every validator already executes — which is APS, not this protocol.

Malachite 0.8.0 is alpha and unaudited. Arc is testnet/alpha. The prototype inherits that risk and must not claim production consensus security.

## Performance implications

Avoiding Arc’s Engine API round-trip on the matching path is the point of the native engine. The cost is that we do not inherit Arc’s measured (docs-claimed, **unverified here**) sub-second EVM block path until we measure our own.

Malachite’s published early experiment (~780 ms finality, 100 validators, 1 MB blocks) is the closest public number. Sub-500 ms is aspirational and must be measured at 4, 7, 10, 20, 50, 100 validators.

## Reversibility

High before Phase 4. After a Malachite application exists, switching to an Arc fork would be a rewrite of the value type and would be justified only if the public EVM *is* the product. Switching individual patterns (e.g. adopting Arc-style follow mode) remains easy.
