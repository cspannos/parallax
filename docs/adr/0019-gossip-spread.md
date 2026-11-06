# ADR 0019 — Intent spread is not `ready_delay`

**Status:** Accepted as the **research default for the inter-height gossip window**, not the product  
**Date:** 2026-10-02  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0018](0018-per-height-offer.md) (`Finalized` waited `ready_delay` ≈ 1.8 s at n=4).  
**Does not implement:** wait-until-quorum of the set, WAN RTT, FOCIL.

## Context

ADR 0018 needed a submit window after decide so height 2 could have a real `I`. It reused Malachite `ready_delay` (peer-wait for consensus gossip at `ConsensusReady`: `1500 ms + 80n`). At n=4 that is ~1.8 s **every height**.

That delay is not intent propagation. On localhost, canonical `Input` frames move in milliseconds. Paying 1.8 s of empty air makes a gossip-on 10k tape ~5k ev/s even if `F` is ~0.18 s. The ~55k figure is still **injected, gossip off**. Mixing the two clocks was a lie.

Wait-until-quiescence (stop when pending is unchanged) **cannot** replace a minimum window: at `Finalized` pending is often empty until a client `offer`s. Quiet-exit would seal height 2 empty and break ADR 0018 tests.

## Decision

**Research default:** `ClusterSpec.gossip_spread` (localhost default **100 ms**).

| Event | Wait |
|---|---|
| `ConsensusReady` | `ready_delay` (Malachite mesh). Ingest intents during it. Genesis gossip is covered. If `ready_delay` is zero, wait `gossip_spread` instead. |
| `Finalized` (gossip on) | **`gossip_spread` only.** Not `ready_delay`. Gossip off: no wait. |
| `StartedRound` | Drain, seal. No wait. |

100 ms is a localhost default for **tiny** `I`, not WAN. Do not call it matching latency. **10k after decide does not fit 100 ms** ([m4-loaded-gossip](../benchmarks/m4-loaded-gossip.md)).

## Alternatives

| Option | Why not as this default |
|---|---|
| Keep `ready_delay` at `Finalized` | 1.8 s air; gossip path cannot meet 35k/s |
| Quiesce when pending is unchanged | Empty pending at `Finalized` exits immediately; post-decide `offer` misses the height |
| Zero spread (publish-only) | Race: `StartedRound` seals before TCP arrives |
| Wait until every voter ACKs the set | ADR [0021](0021-ack-id-set.md); empty-wait stays |

## Consequences

Height 2+ gossip-on empty-wait is `gossip_spread` (100 ms) until a first offer; then ADR [0021](0021-ack-id-set.md) waits for ACK of `id(set)`. Tiny tests use 100 ms empty-wait. A 10k `offer` after decide **stalled at a fixed 100 ms** before 0020. Loaded isolate (injected) stays gossip-off.

## Security implications

A shorter window is a tighter lateness bound. Offers after `gossip_spread` are next height. Eclipse / delay still split the set. FOCIL is **not** claimed.

## Performance implications

Inter-height floor is 100 ms only for small `I`. 10k mixed after decide: 100 ms **stalls**; 2 s spread → StartedRound **~0.27–0.30 s**, offer→decide **~2.3–2.5 s**. One flush per peer is shipped; it did not save 100 ms.

## Reversibility

High. WAN can raise `gossip_spread`. An ACK/quiesce ADR can replace the fixed wait. Seal-at-`StartedRound` stays.
