# ADR 0018 — Per-height offer and gossip

**Status:** Accepted as the **research default for a living intent log**, not the product  
**Date:** 2026-10-02  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0017](0017-intent-gossip.md) (gossip ran once, at `ConsensusReady`).  
**Does not implement:** a mempool, arrival FIFO, WAN, encrypted `I`, or FOCIL.

## Context

ADR 0017 fans canonical `Input` on localhost TCP. Publish happened only at `ConsensusReady`. After height 1 the mesh was idle. Height 2 sealed empty `I`. That is a genesis injector with sockets, not an inclusion path.

Malachite starts the next height on `Finalized` → `Next::Start`. A submit that arrives after that `StartedRound` has sealed is **next height**, not a retry (ADR 0016).

## Decision

**Research default:**

1. **`RunningNode::offer`** sends one `Input` into that replica’s `IntentLog` (set membership) and **publishes immediately** on the intent mesh if gossip is on. Hidden logs still ignore.
2. **`Finalized` (gossip on):** fan out current pending, drain inbound for **`gossip_spread`** (ADR [0019](0019-gossip-spread.md)), then `Next::Start`. That is the submit window between heights. Not `ready_delay`. Gossip **off** does not wait (loaded benches stay the injected path).
3. **`StartedRound`:** drain, then seal. No second wait (the window already ran at `ConsensusReady` / `Finalized`).
4. Late after seal still pending for the next height. Not time-priority. Not FOCIL.

## Alternatives

| Option | Why not as this default |
|---|---|
| Keep genesis-only fan-out | Height 2 is empty; 0017 remainder |
| Wait again inside `StartedRound` | Double-wait at height 1; still loses submits after seal |
| Pause next height until a submit | Sequencer; not a set |

## Consequences

Tests can seed **after** height 1 decide; height 2 is a real `I` if the offer lands in the `Finalized` window. Gossip-on multi-height pays **`gossip_spread`** per height (localhost default 100 ms, ADR 0019), not `ready_delay`. Do not cite that as matching latency.

## Security implications

Unchanged from ADR 0017 (plaintext intent port). A submit after the window is not included this height. That is omission-by-lateness, not FOCIL.

## Performance implications

10k frames: [m4-loaded-gossip](../benchmarks/m4-loaded-gossip.md). Inter-height wait is empty-wait then ACK of `id(set)` (ADR 0019 / 0021). It is **off** when `intent_gossip` is off.

## Reversibility

High. A mempool ADR can replace `offer` + window with a different admission rule. Seal-at-`StartedRound` stays.
