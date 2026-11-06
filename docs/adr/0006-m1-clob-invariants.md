# ADR 0006 — M1 CLOB Types, Matching, and Serialization

**Status:** Accepted for Phase 1 (M1 / M1b); order-id uniqueness amended by [0026](0026-derived-order-ids.md) (ids derived from `(owner, nonce)`, seen set retired)  
**Date:** 2026-09-30  
**Deciders:** Protocol architecture (research prototype)

## Context

Phase 1 must produce a standalone deterministic in-memory CLOB: identical `(S, I)` → byte-identical root, fills, and settlement delta. Several open questions block compilation if left unanswered. This ADR records **M1-only** choices. They are reversible before Phase 4.

## Decision

### Fields (Q-ORD-1)

M1 order:

```text
order_id, instrument, side, quantity, limit_price, owner, expiry, nonce
```

No `jurisdiction`, `counterparty_constraints`, or `compliance_metadata`. Those are disclosure-only candidates and would pollute the matcher.

No signatures. M1 authorization is “cancel `owner` must match resting `owner`.” Cryptographic auth is a later suite.

### Identifiers (Q-CLOB-3)

| Type | Width | Notes |
|---|---|---|
| `OrderId` | 16 bytes | Client-supplied; globally unique in the engine |
| `OwnerId` | 32 bytes | Opaque account id |
| `InstrumentId` | `u32` | Registered in genesis |
| `AssetId` | `u32` | Base/quote on the instrument |

### Fixed-point (Q-ORD-3)

`Qty(u64)` lots and `Price(u64)` ticks. No floats. No hidden decimal scale in the matcher.

Notional quote amount = `(qty as u128) * (price as u128)` (always defined for `u64` factors). Settlement uses `{ amount: u128, debit: bool }` because **`u64×u64` does not fit in `i128`**. Zero qty or zero price is rejected.

Overflow of remaining qty uses checked subtraction and is a bug if it fires (treated as reject/panic-in-debug via `expect` on internal invariants only after checks).

Tick/lot constraints: optional `min_qty` / `tick` on the instrument; qty must be a multiple of `lot_size`, price a multiple of `tick_size`.

### Codec (Q-ORD-4)

Hand-written little-endian canonical encoding with a version `u16` and domain tags. **Not** serde, JSON, protobuf, or SSZ for M1. Serde field order and enum layouts are a determinism hazard.

### Nonce (Q-ORD-2)

Per-owner strictly increasing `u64`. Place and cancel both consume the nonce stream. `nonce <= last` is a replay reject. First nonce for an owner must be `>= 1` (`0` reserved / rejected).

### Expiry (Q-ORD-5)

Good-til-**height**. Engine height is `u64`, never wall clock. Place requires `expiry >= height`. `AdvanceHeight` to `h' > h` expires resting orders with `expiry < h'`. Halt therefore does not extend life (the dYdX GTB motivation).

### Self-trade (Q-CLOB-4)

**Skip** resting orders with the same `owner`. Do not fill them and do not cancel them. The book may be self-crossed. It must not be crossed across different owners after a successful place.

Not dYdX’s cancel-maker. Revisit if self-crossed books break a later invariant.

### Order types (Q-CLOB-5, Q-CLOB-7)

Limit GTC only. Remainder rests at the tail of the price level. No IOC/FOK/post-only, no short-term vs stateful split. Resting state is RAM; durability is replay of WAL'd inputs (ADR 0007).

### Cancel (Q-CLOB-6)

Immediate and complete inside the engine. No gossip, no best-effort. That is the M1 product.

### Fill price

Maker price. Taker limit only gates *whether* a level crosses.

### Time priority

Monotonic `time_seq` assigned when an order **rests**, not wall clock. FIFO = `VecDeque` order, which matches `time_seq` order at a level.

### Data structures (Q-CLOB-2)

Two `Book` backends, same matcher:

1. `BTreeBook` — `BTreeMap<Price, VecDeque<OrderId>>`
2. `VecBook` — sorted `Vec<(Price, VecDeque<OrderId>)>`

`HashMap` is allowed **only** for `OrderId` lookup. Consensus outputs never iterate a `HashMap`.

Q-CLOB-2 stays open until percentile benches pick a default.

### Settlement delta (Q-SET-2 for M1)

Per-fill, not netted: taker/maker, `+base/−quote` or the reverse, at maker notional. Fill order is the receipt order.

### State commitment

Blake3 treap (`plx/clob/inc/v1`) is **`C'`** (ADR 0013): height, time_seq, instruments, per-owner last nonce, seen ids, resting leaves keyed by order id. The O(n) walk (`plx/clob/state/v1`) remains as `full_walk_root()` and is not voted. This is a **hash of the book**, not a validity proof (ADR 0003).

### Engine backends

`Engine<B: Book>`. `PrivateStateEngine` is a thin Phase-2-shaped wrapper over the same apply API.

## Alternatives

- Serde/bincode: rejected for M1 roots.
- Wall-clock expiry: rejected (nondeterministic + halt extends life).
- dYdX cancel-maker STP: deferred.
- Single `BTreeMap` only: rejected; M1 requires two measured structures.

## Consequences

Replay tests can be written now. Phase 3 disclosure does not change these bytes. Phase 5 may net deltas (Q-SET-2) without changing matching.

## Security implications

No signatures: anyone who can submit an `Input` can place for any `OwnerId`. Acceptable only because M1 has no network. Replay protection is nonce-based, not cryptographic.

Skip-self allows a trader to rest both sides and appear to quote a market they do not cross. Documented.

Commitments still do not prove `F`.

## Performance implications

`u64×u64` notionals avoid bigints. Canonical Blake3 walk is O(resting orders) per root and is **not** `C'`. Incremental treap (ADR 0013) is the consensus root.

## Reversibility

High until Phase 4. Changing the codec or nonce rule after transcripts exist requires a version bump (`u16` already in the encoding).
