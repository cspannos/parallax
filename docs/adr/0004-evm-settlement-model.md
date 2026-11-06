# ADR 0004 — EVM Settlement Model

**Status:** Accepted as the research default. M5 apply protocol: [ADR 0010](0010-m5-privileged-apply.md). Solidity ABI still unfrozen (Q-SET-3).  
**Date:** 2026-09-25  
**Deciders:** Protocol architecture (research prototype)

## Context

Native execution must produce deterministic settlement effects:

```text
SettlementDelta { account, asset, amount }
```

Those effects must eventually reconcile with EVM state so that Ethereum tooling and contracts remain useful. They must not force every order through Solidity.

Five architectures were compared.

| | A. Native canonical; EVM mirrors | B. EVM canonical; native locks | C. Shared DB | D. System contract mediates | E. PSE as Reth ExEx / executor |
|---|---|---|---|---|---|
| **Latency** | Best for matching | Locks and unlocks are EVM txs | Matching blocked on DB | Matching native; settle batched | Matching on the block path |
| **Atomicity** | Hard: mirror can lag | Strong if lock is on-chain first | One commit if you accept the coupling | Strong if delta is in the same consensus value | Strong inside one EVM block; wrong VM |
| **Complexity** | Two ledgers + reconciler | Lock/unlock protocol, griefing | Highest coupling | One well-specified boundary | Fights Reth’s sequential EVM |
| **Composability** | Weak until mirror is fresh | Strong | Strong and dangerous | Strong at the contract | Strong, at CLOB’s expense |
| **Security** | Mirror spoof / stale reads | Lock grief, insufficient lock | Cross-engine corruption | Contract bugs; delta/proof mismatch | Entire book in EL trust domain |
| **Crash recovery** | Two WALs | EVM receipts + native book | One store, two semantics | Replay delta then EVM | Reth persist + ExEx WAL |
| **Reorg/finality** | Malachite: no CL reorg if decided | Same | Same | Same | Engine API still has FCU races during sync |

Arc’s lesson: keep Reth as an EL behind Engine API; do not invent a second Ethereum. Arc’s mistake to avoid: make that EL the *only* execution.

Reth ExEx is for *derived* state (indexers, bridges). It consumes canonical notifications and must not block execution. It is the wrong place to *be* the CLOB.

revm without Reth can execute settlement txs in isolation (Foundry-style). It does not give `eth_` RPC, receipts, or a state trie. Use revm inside tests and (later) proof guests. Use Reth when Ethereum tooling must work.

## Decision

**Hybrid: A for the book, D for the money, B only where a public balance must be reserved before a private order is live.**

1. **Book and matching** live only in the PSE. They are not EVM storage.
2. **Public balances** that contracts and wallets observe live in Reth. EVM is canonical for those balances.
3. **A height’s consensus value** may include a `SettlementDelta` list (or a commitment to it). Honest finalization applies the delta to EVM state in the same decided height — via a **system contract / privileged deposit-withdraw path**, not via user `eth_sendRawTransaction` for each fill.
4. **Collateral for open orders** (Phase 5+, not Phase 1): an account that wants a resting order which can lose money must first lock funds in the settlement contract (`reserve`). The PSE refuses to rest the order without a corresponding reservation commitment. This is **B for reservations only**.
5. **Reth is a settlement sidecar.** Engine API (or an equivalent apply API) applies the settlement payload. The CLOB does not run in an ExEx.
6. **revm is used independently** for: deterministic settlement unit tests, later ZK guests that replay deltas, and simulations. It is not the node.

Phase 1–2 implement `SettlementDelta` as a deterministic output of matching. They do **not** implement Reth. Phase 5 atomicity: [ADR 0010](0010-m5-privileged-apply.md).

### Apply order (implemented locally in M5; ADR 0010)

```text
on Decide(value):
  1. PSE commits private transition (already executed on propose/validate, or replayed)
  2. Verify settlement_delta matches PSE receipts
  3. Apply settlement_delta to EVM via system contract / privileged Engine payload
  4. Require: EVM apply succeeds or the whole height is invalid
  5. Persist both roots; neither is canonical without the other in the decided value
```

If step 3 can fail after step 1 was “accepted” locally, the height is invalid. There is no “PSE succeeded, EVM later.” M5 tests that on an in-process sidecar; `evm_state_root` is not yet in Malachite `id(v)`.

## Alternatives

### Pure A

Rejected for user-visible money. A contract calling `balanceOf` must not read a best-effort mirror.

### Pure B

Rejected for the hot path. Locking USDC (or whatever asset) in the EVM on every place/cancel would make the CLOB an EVM mempool.

### Pure C

Rejected. Shared MDBX/redb between engines couples crash recovery and prevents replacing Reth.

### Pure E

Rejected. Reth ExEx cannot be the matching engine. Custom `ConfigureEvm` / precompiles are acceptable *hooks* for applying a delta, not a place to run price-time matching.

### revm-only node (no Reth)

Rejected if “EVM compatible” includes wallets, explorers, Foundry, and `eth_getLogs`. Accepted for tests and proof guests.

## Consequences

- Two state roots in the block header: `private_state_commitment` and `evm_state_root`.
- Settlement apply protocol is ADR 0010 (`SettlementPayload`). A Solidity system-contract ABI is still unfrozen (Q-SET-3).
- Reservations introduce griefing (locked funds, unplaced orders) and must be specified with timeouts.
- Ethereum users see fills as privileged balance updates, not as their original order txs. Order lifecycle UX is a native API.

## Security implications

- **Double spend:** a fill that spends a balance also spent by a public EVM tx in the same height. Mitigation: reservation + sequential apply order inside the height, or a single scheduler that sees both mempools. Unspecified; M5 has no public EVM txs (Q-SET-1 remainder).
- **Inflation:** a Byzantine proposer includes a delta that does not follow from PSE receipts. Mitigation: validators with enough view to check receipts reject; others need `π`. Same as ADR 0003.
- **Reorgs:** Malachite decide is irreversible. Engine API `ACCEPTED`/`SYNCING` during catch-up must not be treated as final. Arc already treats unexpected `SYNCING` as error after `newPayload`. Copy that discipline.
- **System contract privilege:** the apply path is a fork-choice-critical precompile/admin. Compromise is ledger-breaking. Design it as a pure function of the decided delta, not a key-held “minter.”

## Performance implications

Settlement batch size, not order count, hits Reth. A height with 100k order events and 2k fills should persist 2k deltas (or fewer netted deltas), not 100k EVM txs. Netted vs per-fill deltas is an open question (Q-SET-2): netting is faster and leaks less; per-fill is easier to audit.

Do not put trie updates on the matching path. Measure EVM apply p50/p95/p99 independently of CLOB benchmarks.

## Reversibility

The hybrid can slide toward A (if EVM becomes a read-only mirror) or toward B (if regulators require every reservation on-chain) without changing Phase 1. Changing the system-contract boundary after wallets depend on it is hard. Freeze the ABI only after Phase 5 experiments.
