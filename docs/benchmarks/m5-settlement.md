# M5 settlement apply — atomic privileged batch (not Reth-in-process)

**Date:** 2026-09-30  
**Code:** `cargo test -p evm-adapter`  
**ADR:** [0010](../adr/0010-m5-privileged-apply.md)

In-process Engine API **adapter**: one `new_payload` per height applies the PSE `SettlementDelta` list. Malachite `ConsensusValue` is unchanged. Not ExEx. Not per-order EVM txs. Apply log is not the replica WAL.

`eth_get_balance(account, asset)` is the public balance query. There is no `eth_sendRawTransaction`. A live Reth node / JWT HTTP Engine API is **not** in this cut.

## Pass

| Check | Test |
|---|---|
| Both PSE `state_root` and ledger root recorded; one payload for many deltas | `both_roots_match_one_payload_not_per_delta` |
| Bad `settlement_commitment` never calls the sidecar | `mismatch_commitment_does_not_touch_sidecar` |
| Crash after intent: balances unchanged; `settled()` none; retry then commit | `crash_after_intent_is_not_settled_until_retry` |
| Insufficient funds → height invalid | `debit_without_funds_invalidates_height` |
| `SYNCING` after decide is an error | `unexpected_syncing_after_decide_is_error` |

## Not done

- Live Reth process, MDBX trie, JSON-RPC `eth_*` server
- `evm_state_root` inside Malachite `id(v)` (ADR 0010: later Validate replay)
- Reservations / public EVM txs in the same height (Q-SET-1, Q-SET-5)
- Solidity system contract ABI freeze (Q-SET-3)
- Netted deltas (Q-SET-2)
- Settlement apply percentiles vs matching (do not conflate)
