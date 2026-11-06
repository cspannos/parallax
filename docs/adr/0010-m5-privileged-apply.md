# ADR 0010 — M5 privileged settlement apply (atomicity)

**Status:** Accepted as the **M5 research default**, not a frozen Solidity ABI  
**Date:** 2026-09-30  
**Deciders:** Protocol architecture (research prototype)

## Context

ADR 0004: the book is native; public balances that wallets observe live in an EVM sidecar; a height applies `SettlementDelta` through a **privileged** path, not `eth_sendRawTransaction` per fill. Phase 1–4 produced deterministic deltas and `settlement_commitment` on `ConsensusValue`. They did not apply money.

Roadmap M5: crash between PSE commit and EVM apply must not yield split-brain. Pass: a height is valid iff **both** the private state root and the EVM/settlement root match the apply. Fail: CLOB-in-ExEx; per-order EVM txs; shared DB with the replica WAL.

Q-SET-3 asked for a system-contract ABI before Phase 5. Freezing Solidity now would invent an ABI without an apply experiment. This ADR names the **apply protocol**, not a production contract.

## Decision

### Sidecar, not ExEx, not Engine API as `Value`

Reth (when present) is a **settlement sidecar**. The Malachite value remains `ConsensusValue` (ADR 0009). Engine API is an **adapter** (`new_payload` / `forkchoice_updated` shaped) used only to apply the settlement payload. It is not the consensus type (ADR 0001).

M5 implements that adapter **in-process** (`crates/evm-adapter`) against a privileged balance ledger whose root is domain-separated BLAKE3 (`plx/evm/state/v1`). That is the same *role* as revm/Reth apply: one batch per height, a query port with `eth_getBalance` semantics. A live Reth process, MDBX trie, and JWT Engine API HTTP are **not** shipped in this cut (compile/ops cost; not the atomicity claim). The trait is the seam for a later Reth backend.

revm remains the intended guest/test EVM library (ADR 0004). It is not required to prove crash atomicity.

### Privileged batch (Q-SET-2, Q-SET-3)

**One** `new_payload` per decided height. The payload is the ordered `SettlementDelta` list from PSE receipts (per-fill, as CLOB emits today). Not one EVM tx per fill. Not user `eth_sendRawTransaction`.

Research-default “ABI” is that payload + the ledger apply rules:

- Credit: add `amount` (saturating at `u128::MAX` is invalid).
- Debit: subtract if `balance >= amount`, else the **height is invalid**.
- Empty list: no-op; EVM root unchanged.

Netted deltas (Q-SET-2) and a Solidity system contract (Q-SET-3 freeze) stay open. Reservations, public EVM txs in the same height, and fees (Q-SET-1, Q-SET-4, Q-SET-5) are **not** in M5.

### Two roots, two WALs

| Root | Source |
|---|---|
| Private `state_root` | PSE / `ConsensusValue.state_root` |
| Settlement `evm_state_root` | sidecar after privileged apply |

`settlement_commitment` on the Malachite value must match `commit_list(deltas, plx/clob/receipt/v1)` **before** `new_payload`. If it does not, do not call the sidecar.

`evm_state_root` is **not** added to M4a `ConsensusValue` in this ADR. Putting it in `id(v)` means every voter re-executes the privileged apply in `Validate` (same shape as `F`). M5 proves local atomicity first. Wiring EVM replay into Malachite `Validate` is a later adapter change.

Durability: a **separate** apply log (not the replica WAL, not Reth MDBX). Intent record then commit record.

```text
on Decide(value, deltas):
  1. Check settlement_commitment(deltas) == value.settlement_commitment
  2. WAL intent (value + deltas)     // crash ⇒ height not settled
  3. new_payload(batch); reject SYNCING after decide
  4. If apply fails → height invalid; no commit record; balances unchanged
  5. WAL commit (evm_state_root)
  6. forkchoice_updated(evm_state_root)
```

**Split-brain forbidden:** `eth_getBalance` / `settled()` must not report the new height after intent and before commit. Restart with a dangling intent may **retry** apply (idempotent) or leave the height unsettled; it must not invent a second money state.

### `eth_` for balances

Public query is `eth_get_balance(account, asset)` on the sidecar (settlement token keyed by `OwnerId` + `AssetId`, not a 20-byte Ethereum account). There is no `eth_sendRawTransaction` on this crate.

## Alternatives

| Option | Why not for M5 |
|---|---|
| Full Reth node + JWT Engine API | Ops/compile; does not change the atomicity claim |
| CLOB in ExEx | ADR 0004 rejected |
| Per-fill EVM txs | Roadmap fail; 100k events must not be 100k txs |
| Shared replica WAL / shared MDBX | Roadmap fail |
| Put `evm_state_root` in M4a `Value` now | Couples every voter to EVM replay before the coordinator exists |
| Freeze Solidity ABI | Q-SET-3; no on-chain consumers yet |

## Consequences

Phase 5 starts with `evm-adapter`. Malachite still does not vote on Engine API payloads. Decide is still not `π`. Settlement-inert policy: [ADR 0011](0011-missing-pi-settlement-inert.md).

## Security implications

Debit without funds invalidates the height (local). A Byzantine `ConsensusValue` whose `settlement_commitment` does not match receipts is already `Invalid` under ADR 0009 if the voter has `I`. Applying a matching but economically wrong delta still requires `F` (full-view) or `π`. System-apply privilege is ledger-breaking if the adapter is bypassed.

## Performance implications

EVM/ledger apply is **not** matching latency. Measure independently. M5 does not claim `eth_` RPC p99.

## Reversibility

High until wallets depend on a contract address. Swapping the in-process ledger for a Reth `new_payload` implementation should not change `AtomicApply` sequencing.
