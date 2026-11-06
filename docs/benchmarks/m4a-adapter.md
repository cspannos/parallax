# M4a consensus adapter — engine linked (not a network number)

**Date:** 2026-09-30  
**Code:** `cargo test -p consensus-adapter`  
**ADR:** [0009](../adr/0009-m4a-full-view-value.md)  
**Pin:** [circlefin/malachite](https://github.com/circlefin/malachite) tag **v0.8.0** (crates.io still `0.7.0-pre`)

Four **full-view** validators. `Context::Value` is `ConsensusValue`. `id(v)` is domain-separated BLAKE3 (`plx/cons/value/v1`). `TestContext`'s `u64` value is not used. `GetValue` builds the bundle by replaying `F` on a scratch engine. `Validate` does the same. Replica WAL/`F` runs only on **decide**. Missing `I` maps to engine `Invalid` (prevote nil).

`app-channel` `EngineBuilder` + localhost TCP + **broadcast** pubsub (not GossipSub mesh; n=4). Value-sync of the **public** decided bytes is wired; `I` is still out of band (ADR 0009).

Decide is **not** world-computer validity (no `π`).

## Pass

| Check | Test |
|---|---|
| Four EngineBuilder nodes, same `I` → same `id(v)` | `four_engine_nodes_decide_the_same_id` |
| 3/4 with `I` still decides (withholder prevotes nil) | `missing_i_node_does_not_block_quorum` |
| Port: missing `I` → `InsufficientView` | `missing_i_is_insufficient_view_not_valid` |
| Port: four replicas same `id(v)` without the engine | `four_full_view_nodes_decide_the_same_id` |

## Not measured / not done (moved)

- Scale percentiles: [`m4b-scale.md`](m4b-scale.md)
- QUIC vs TCP: [`m4c-transport.md`](m4c-transport.md)
- Engine API (rejected)

`ConsensusValue.height` is the **consensus** height (1, 2, …), not CLOB GTB `Engine::height`.
