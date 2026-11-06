# ADR 0020 — Quiesce after first offer

**Status:** Accepted as the **research default for inter-height admission**, not the product  
**Date:** 2026-10-02  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0019](0019-gossip-spread.md) (fixed `gossip_spread` at `Finalized` stalled 10k at 100 ms and cost 2 s of air).  
**Does not implement:** WAN RTT, FOCIL, a mempool.  
**Amended by:** [0021](0021-ack-id-set.md) (ACK of `id(set)` replaces the quiet step).

## Context

A fixed wait at `Finalized` has two failures:

| Wait | 10k `offer` after decide |
|---|---|
| 100 ms | Some replicas seal empty/partial `I` → stall |
| 2 s | Full set, but offer→decide **~2.3–2.5 s** (~4k ev/s). Almost all of that is the wait. StartedRound is already **~0.27–0.30 s**. |

ADR 0019 correctly refused *unconditional* quiescence: at `Finalized` pending is often **empty** until a client `offer`s. Quiet-exit then seals empty `I`.

Quiescence **after the first offer** is a different rule. Empty wait is only “is anyone submitting?” Transfer wait is “has the burst stopped?”

## Decision

**Research default** at `Finalized` (gossip on):

1. Connect + fan out current pending (unchanged).
2. **Empty wait:** ingest until `pending` is nonempty or `gossip_spread` (default **100 ms**) elapses. Still empty → start the height with empty `I`.
3. **Quiesce (superseded):** ingest until `pending_len` is unchanged for `gossip_quiet`. **0 / 10 ms split** a 10k living log. ADR [0021](0021-ack-id-set.md) replaces this step with ACK of `id(set)`. Empty-wait stays.

`ConsensusReady` still uses `ready_delay` (Malachite mesh). `StartedRound` still drains and seals. Late after seal is next height.

This is **not** an inclusion quorum. Nodes that time out empty while others received the burst still diverge.

## Alternatives

| Option | Why not as this default |
|---|---|
| Keep a 2 s floor | offer→decide cannot meet 35k/s |
| Keep 100 ms fixed | 10k stalls |
| Quiesce while pending is empty | Post-decide `offer` misses the height (ADR 0019) |
| Voter ACK of `id(set)` | Done as ADR 0021 |

## Consequences

Tiny CI `offer` after decide still fits the 100 ms empty wait. Fan-out encodes once and writes peers in parallel. The 10k cell **`offer`s after height-1 seal** (overlaps height 1) so node 0 already holds the tape when `Finalized` fans out.

## Security implications

A node that sees no offer in 100 ms starts empty. A node that sees a slow drip waits up to 5 s. Split sets still disagree. FOCIL is **not** claimed.

## Performance implications

One-shot 10k: offer→decide **~368–370 ms** (~27k). Steady-state later heights under this quiet: inter-decide **~315–351 ms** (~28–32k). ADR 0021 + skip re-fan-out later last p50 is **~289–298 ms** (~33.5–34.6k) ([m4-loaded-gossip](../benchmarks/m4-loaded-gossip.md)). Hypothesis ~270 ms / 37k was **not** met either way. **`gossip_quiet=0` and `=10` stall** without ACK.

## Reversibility

High. Quiesce can return if ACK stalls. `gossip_spread` stays. Seal-at-`StartedRound` stays.
