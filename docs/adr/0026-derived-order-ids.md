# ADR 0026 — Order ids are derived from `(owner, nonce)`

**Status:** Accepted as the **order-admission research default**  
**Date:** 2026-10-16  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0006](0006-m1-clob-invariants.md) (global id uniqueness via a seen set). Closes Q-CLOB-8.  
**Does not change:** matching, cancel-by-id, the INC root layout, the nonce rule.

> **Amended by ADR [0032](0032-lazy-c-prime-and-guest-hashing.md) (2026-10-25):** the derivation now hashes with SHA-256 under `plx/clob/orderid/v2` (accelerated in zkVM guests). The rules are unchanged.

## Context

Order ids were client-chosen. The engine kept `seen_ids`, every id ever accepted, to reject duplicates, and committed it in `C'`. This caused two problems:

1. **Unbounded state.** The set gains one entry per Place, forever. `π` of `F` (ADR [0025](0025-pi-of-f-on-zkvm.md)) rebuilds `C` from the full snapshot every height. At the 300M events/day target (~150M Places), each proof would rebuild ~150M extra entries after a single day: several hundred times the matching work of a loaded height. Native state would also grow by gigabytes a day.
2. **Squatting.** Anyone who saw a pending order's id in gossip could place first with that id and get the victim's order rejected. They could also burn ids in advance.

The set protected three things:

- no two live orders share an id (required: the book, cancel and fills key on id)
- an identical Place cannot be replayed (already guaranteed by per-owner strictly increasing nonces)
- ids are unique forever (useful for receipts and indexers)

## Decision

- **`order_id = derive_order_id(owner, nonce)`**: the first 16 bytes of `Digest::from_bytes(owner ‖ nonce_le, "plx/clob/orderid/v1")` ([`commitments`](../../crates/commitments/src/lib.rs)). The engine rejects a Place whose id differs (`RejectReason::OrderIdMismatch`), without consuming the nonce.
- Each `(owner, nonce)` pair is consumed at most once, so ids are **unique forever without a set**, and an id cannot be squatted: it binds its owner.
- **The seen map stays committed but always empty** under derived ids, so the INC root layout and `IncTape` are unchanged. Snapshots with seen ids under derived ids are rejected (`SnapshotError::SeenUnderDerivedIds`).
- **Backstop:** after the nonce check, a Place whose id collides with a live resting order is rejected (`DuplicateOrderId`). That would need a 128-bit collision; replays are caught earlier as `NonceReplay`.
- `OrderIdRule::DerivedFromOwnerNonce` is the default. `OrderIdRule::ClientChosen` is **v1**, pinned with BLAKE3 `C'` for the Plonky3 and HeightMatch fixtures and tiny-f (`clob::testutil::btree_engine_v1`, `limit_v1`, `load_places_v1`, `churn_tape_v1`).
- **Bound into `π` of `F`:** the snapshot carries the rule, and the claim's flag byte is bit 0 = SHA-256 `C'`, bit 1 = derived ids. `Risc0FVerifier` requires `0b11`. A receipt produced under client ids no longer unlocks settlement (checked: the pre-change fixture is rejected).

**Client impact:** clients compute the id instead of choosing it. They already need `owner` and `nonce` to sign, so this is one hash.

## Measurements

RISC Zero guest cycles for `π` of `F` (SHA-256 `C'`, executor), 8k resting book:

| | Seen set (before) | Derived ids |
|---|---|---|
| Rebuild only | 136.1 M | **106.1 M** (−22%) |
| + 512 events | 205.1 M | **154.1 M** |
| Per event | ~135 K | **~94 K** |
| Snapshot | 936 KB | 808 KB |

The constant improved by less than the seen set's share of entries, because resting leaves cost more per entry than seen ids did. The decisive change is the **growth term**: proof cost no longer grows with history. The rebuild is bounded by book size plus number of owners. Loaded 10k at 8k now projects to **~1.05 × 10⁹ cycles ≈ 17–18 CPU-hours** (was ~24–26).

## Alternatives

| Option | Why not |
|---|---|
| Live-only uniqueness | Ids reused after an order leaves; live ids can be squatted |
| Expiring seen set | Still ~150M entries per day of expiry window; squatting remains |
| Keep the set; prove seen updates with path witnesses | Proof cost bounded, but native state grows forever and squatting remains |

## Security implications

Uniqueness rests on nonce monotonicity plus the collision resistance of a 128-bit truncation. A birthday collision needs ~2⁶⁴ orders; a targeted second preimage needs ~2¹²⁸. The live-collision backstop keeps the book consistent even then. Ids are now **linkable to owners by anyone who knows the owner**: `id = H(owner, nonce)` reveals nothing without the owner, but an owner's own ids are predictable. That matters for the disclosure views (ADR 0008) only if ids were previously assumed unlinkable; they were not.

## Reversibility

Medium. It is a mode switch (`OrderIdRule`), but clients and receipts depend on the id format.
