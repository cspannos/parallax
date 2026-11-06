# ADR 0021 — ACK of `id(set)`

**Amended by:** [0027](0027-intent-target-height.md) (intents carry a target height; `id(set)` covers only the next seal).  
**Status:** Accepted as the **research default for post-offer admission**, not the product  
**Date:** 2026-10-03  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0020](0020-quiesce-after-offer.md) (quiet after first offer is a timer, not agreement).  
**Does not implement:** 2f+1 inclusion, proof of possession, WAN RTT, FOCIL, a mempool.

## Context

ADR 0020 waits until `pending_len` is unchanged for `gossip_quiet` (20 ms). That timer is load-bearing: 0 and 10 ms **split** a 10k living log. It is also not agreement. A node can go quiet on a partial set while a peer still has frames in flight.

The product clock that remains after hash-once `tape()` is **inter-decide minus injected StartedRound** (~0.34 s vs ~0.17–0.19 s). The quiet was a candidate for that gap. Finalized desync and the mesh remain.

## Decision

**Research default** at `Finalized` (gossip on), after the ADR 0020 empty-wait:

1. Empty wait unchanged: ingest until pending is nonempty or `gossip_spread` (100 ms). Still empty → start with empty `I`.
2. **`id(set)`** = BLAKE3 of the pending intent ids in sorted order (`plx/intent/set/v1`). Same set, same id, independent of arrival.
3. Each voter publishes a **`SetAck`** `{ voter, id(set), count }` on the intent TCP (tagged frame; not an `Input`).
4. Admit when **every** voter in the M4a set has ACKed **this** node’s current `id(set)`, or 5 s hard cap. A new local offer changes `id(set)` and invalidates matching.
5. **Do not re-fan the pending set at `Finalized` first.** `offer` already published it. ACK the **completed** wave (after a local offer batch, or when local `id(set)` matches a peer ACK). Do not ACK every growing ingest — that was 10k partial ACKs and later heights recovered. A **large** pending set (≥1024) waits ~180 ms for in-flight ACKs before recover (empty height 1 is too short for the first 10k). A small tail still uses the 50 ms peer-ACK grace, then recover.
6. `gossip_quiet` is **not** an admit condition. 0 ms quiet must not split if ACKs agree.

This is **all n**, not 2f+1. Model I needs the same `I` among the full-view committee. A lagging voter that seals a different tape stalls Validate anyway.

An ACK is **not** a proof the voter holds those intents. A liar can ACK a set it never received. Honest localhost is the cell. Possession proofs / 2f+1 / FOCIL remain remainder.

## Alternatives

| Option | Why not as this default |
|---|---|
| Keep 20 ms quiet | Timer, not agreement; 20 ms is still air when the set is already complete |
| 2f+1 matching ACKs | Lagging honest voter seals a different `I` |
| ACK per intent | 10k extra frames; `id(set)` is the membership |
| Originator `SET_COMMIT` only | Any replica can offer; the set is the union |

## Consequences

Intent TCP frames are tagged: `0` = `Input` (unchanged payload), `1` = `SetAck`. Tiny post-decide `offer` still relies on the 100 ms empty-wait. Living-log `offer` at the previous seal should already have the set at `Finalized`; ACK is then one round of 32-byte digests.

## Security implications

Withhold ACK → 5 s then maybe a split (same as 0020 hard cap). Spoofed voter bytes are trusted on localhost. Eclipse / delay still split the set. FOCIL-class inclusion is **not** claimed.

## Performance implications

In-flight wait before large recover: later last p50 **~192–202 ms** (~50–52k). Height 2 last **~223–236 ms** (~42–45k). First-wave re-fan is gone (0 bytes). 10× peak **fits** both clocks. Injected ~0.17–0.19 s is a different cell ([m4-inter-split](../benchmarks/m4-inter-split.md)).

## Reversibility

High. Quiesce can return. `gossip_spread` stays. Seal-at-`StartedRound` stays.
