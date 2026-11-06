# ADR 0027 — Intents carry a target height

**Status:** Accepted as the **intent-admission research default**  
**Date:** 2026-10-17  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0016](0016-intent-set.md) (replicated intent set seals `I`), [0021](0021-ack-id-set.md) (ACK of `id(set)`). Closes Q-CONS-11.  
**Does not change:** `I`, `input_commitment`, `HeightStatement`, the all-`n` ACK quorum, the 5 s hard cap.

## Context

`four_nodes_gossip_steady_heights` stalled before height 2 in ~3 of 8 localhost runs, with either `C'` hash. Instrumenting each node's seal showed the cause:

| Node | Sealed `I(2)` |
|---|---|
| node 0 (the offerer) | 8 intents (wave 0) |
| the other three | 16 intents (wave 0 + wave 1) |

The test offers wave 1 right after node 0 seals height 2. The other nodes had not yet reached `StartedRound(2)`. On reaching it, they **ingested pending gossip and then sealed**, so wave 1 entered their `I(2)` but not node 0's. The three agreed among themselves, decided height 2 and continued to height 6; node 0 could never validate `I(2)` and stalled.

The underlying flaw: **which height an intent belongs to was decided by local timing at each node.** The ACK quorum (ADR 0021) narrowed the window but could not close it, because `id(set)` covered *all* pending intents. A new wave changed the id, and nodes reached quorum at slightly different moments.

## Decision

- Every pending intent has a **target height**, fixed once by the node that accepts it from a client and carried in gossip (`GossipFrame::Intent { height, input }`). Receivers file it under that height. The first target seen for an intent wins.
- **Seal of height `h` takes exactly the intents targeted `≤ h`.** Later targets stay pending.
- **`id(set)` and `pending_len` cover only what the next seal will take** (targets `≤` the next unsealed height). Waves for later heights no longer move the set being agreed.
- **Tag rule** at the accepting node: target = the next unsealed height, unless this node has already published an ACK for that height's set, in which case target + 1. A node's intents and its ACK go out on the same per-peer TCP stream, so a peer has every intent the node tagged `h` before it can count that node's ACK for `h`. With the all-`n` quorum, no node seals `h` while any voter's `h`-targeted intents are missing.
- An intent arriving for an already-sealed height (only possible after the 5 s hard-cap fallback) moves to the next open height and is counted (`IntentLog::late`).

Tags are transport metadata: the sealed `I(h)`, `input_commitment` and `HeightStatement` are unchanged.

## Evidence

- Unit tests: a simulation of the observed race seals the same `I(2)` on both nodes, with the wave in `I(3)`. Also: later waves do not change `id(set)`; late intents move forward; the first target wins.
- `four_nodes_gossip_steady_heights`: **20 / 20 passes** (was ~5 / 8). The `m4_loaded` and `m4a_intent_gossip` files pass 5 / 5 full runs each. The full workspace passes **445 / 445**.
- Loaded gossip bench (`PLX_M4_LOADED=1 PLX_M4_GOSSIP=1`, one run): every height seals the full 10k `I`. Later-height last-decide p50 is **189 ms** (~53k ev/s), in line with the documented ~192–202 ms; height 2 is 155 ms.

## Consequences

- An intent accepted just after its node ACKed the current height waits one more height. That is the price of a deterministic boundary.
- The residual divergence path is the 5 s hard cap (ADR 0021). If a voter's ACK never arrives, the others seal without it. That is liveness under faults, and remains open with the all-`n` quorum itself (2f+1 / FOCIL remain the remainder).

## Alternatives

| Option | Why not |
|---|---|
| Seal before ingesting at `StartedRound` | Narrows the window; a frame ingested by the idle loop between admit and `StartedRound` still splits |
| Proposer-packed `I` (Model II) | Rejected by ADRs 0015/0016 for latency and full-view validity |
| Seal at the end of admission | Nodes finish admission at different times; a wave arriving in between still splits |

## Reversibility

High. A frame field and the bucketing in `IntentLog`; `I` and its commitments are unchanged.
