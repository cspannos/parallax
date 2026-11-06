# ADR 0017 — Localhost plaintext intent gossip

**Status:** Accepted as the **research default for how the replicated set is shared**, not the product  
**Date:** 2026-10-02  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0016](0016-intent-set.md) remainder (“gossip / WAN / anti-eclipse”).  
**Does not implement:** WAN, mixnet, encrypted `I`, FOCIL, or a Malachite mempool topic.

## Context

ADR 0016 sealed `I` from an `IntentLog`. Spawn still **cloned** the same `Vec<Input>` into every replica. That is not replication.

Malachite `app-channel` `NetworkMsg` has only `PublishProposalPart`. Intents are not proposal parts. Stuffing `Input` into parts would couple inclusion to consensus streams.

## Decision

**Research default:** when `ClusterSpec.intent_gossip` is on, each full-view replica binds a TCP listener on `base_port + n + index` and fans canonical `Input` bytes (u32 LE length + encode) to the other listeners.

1. Offer is still set membership (ADR 0016). A node that was seeded (or that received a frame) `offer`s.
2. After the ConsensusReady barrier, each node **publishes its pending set**, then drains inbound frames during `ready_delay`.
3. `StartedRound` drains again, then **seals**. Late frames after seal sit in pending for the next height.
4. Hidden (`from_batch(None)`) still ignores offers. Open-empty (`Some(vec![])`) is the gossip voter: view, no local seed.
5. Injected tapes (`Some(batch)` on every node, gossip **off**) remain the loaded-bench path. That is still “everyone saw the gossip,” not this ADR.

**Per-height submit** is ADR [0018](0018-per-height-offer.md): `RunningNode::offer` plus a `Finalized` gossip window. This ADR’s genesis-only fan-out is the height-1 special case of that window (`ConsensusReady`).

This is **plaintext localhost**. Not Q-NET-1 WAN. Not Q-NET-5 metadata hiding. Not FOCIL.

## Alternatives

| Option | Why not as this default |
|---|---|
| Keep cloning the tape | 0016 remainder; injector is the protocol |
| Encode `Input` as `ProposalPart` | Consensus stream ≠ inclusion; Fin/is_first lie |
| libp2p / Malachite GossipSub topic | Engine does not expose a custom topic; would be a fork |
| Sequencer / FOCIL now | Unspecified; new trust |

## Consequences

Tests can seed **one** replica (or split the set across replicas). Opposite receive order still seals the same `I` (ADR 0016). Divergent sets still disagree on `input_commitment`.

`tape()` consumes **current pending** at first seal of **any** height, not only height 1. Height > 1 with no new offers is still empty `I`.

## Security implications

Anyone who can reach the intent port can inject plaintext `Input`. That is the Phase 1–2 trust model (full-view committee, no encryption of `I`). Eclipse, delay, and withhold still split the set. FOCIL-class inclusion is **not** claimed.

## Performance implications

Tiny batches on localhost sit inside existing `ready_delay` at genesis. Persistent connections, one encode, parallel write + one flush per peer. Tagged `SetAck` frames (ADR 0021). **10k `offer`:** [m4-loaded-gossip](../benchmarks/m4-loaded-gossip.md) (ACK + skip re-fan-out later last p50 ~289–298 ms).

## Reversibility

High. A real pubsub topic or FOCIL list can replace the TCP fan-out. Seal-at-`StartedRound` stays.
