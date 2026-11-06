# Q-CRY-2 — incremental book commitment

**Date:** 2026-10-01  
**Binary:** `cargo run -p clob-bench --release`  
**Host:** Apple M4 Pro, 14 cores  
**Scheme:** deterministic BLAKE3 treap (`HashedMap`). Priority = BLAKE3 of the key, so the root depends on the key/value **set**, not insertion order.

Not a validity proof. Receipts that commit (`commit_on_apply`) carry this root. The O(n) walk (`plx/clob/state/v1`) is `full_walk_root()`.

ADR [0013](../adr/0013-treap-is-c.md) made this **`C'`**. Matcher-only benches still turn the treap off.

## Results (nanoseconds)

| bench | n | p50 | p95 | p99 |
|---|---|---|---|---|
| `state_root` 1k resting | 2000 | 337 250 (~0.34 ms) | 476 667 | 744 333 |
| `state_root` 8k resting | 500 | 3 061 292 (~3.1 ms) | 4 938 250 | 8 323 500 |
| `inc_root` 1k (read cached) | 2000 | **500** | 542 | 584 |
| `inc_root` 8k (read cached) | 500 | **500** | 542 | 584 |
| full walk **insert** at 8k | 500 | 2 824 250 (~2.8 ms) | 3 362 958 | 3 603 791 |
| full walk **cancel** at 8k | 500 | 2 588 750 (~2.6 ms) | 3 079 375 | 3 763 416 |
| incremental **insert** at 8k | 500 | **23 875 (~24 µs)** | 33 291 | 36 875 |
| incremental **cancel** at 8k | 500 | **12 750 (~13 µs)** | 18 208 | 20 958 |

Incremental apply at 8k was **~24 µs** (split+merge). One-path upsert is **~9 µs** ([hash-vs-tree.md](hash-vs-tree.md)). Matcher insert is still ~170–210 ns.

## Reading

The 8k full walk is still ~3 ms per apply if every receipt hashes the book. That is not a CLOB problem; it is a commitment-scheme problem. A BLAKE3 treap of resting leaves (plus nonce / seen maps) makes one mutation O(log n) hashes.

This does **not**:

- give TRADING_VIEW a matching proof (ADR 0008: openings are not a sneak path to Q-CONS-3 = yes)
- pick Merkle-of-orders vs this treap vs an MMR vs a sparse Merkle tree as *the* product scheme

It does show that “hash 8k resting on every apply” is optional. ADR 0013 made the treap the voted root.

## Pass / fail

| Claim | Status |
|---|---|
| Same set → same incremental root (insertion order) | Tests in `commitments::HashedMap` |
| Live updates match a full rebuild | `crates/clob/tests/incremental.rs` |
| Receipt `state_root` is the treap when tracking is on | ADR 0013; same tests |
| Incremental apply at 8k ≪ full walk | **~24 µs vs ~2.8 ms insert** (now **~9 µs** one-path) |
| That 24 µs is mostly the cartesian tree | **No** — BLAKE3 ([hash-vs-tree.md](hash-vs-tree.md)) |

## Re-measure with SHA-256 `C'` (ADR 0024, 2026-10-15)

`CLOB_BENCH_ONLY=treap cargo run -p clob-bench --release`, same host. Same treap and preimages; only the hash changed (hardware SHA instructions via `sha2` `asm`).

| bench (8k) | p50 | p95 | p99 |
|---|---|---|---|
| map upsert, SHA-256 | **3 250 ns** | 4 667 | 6 042 |
| map upsert, BLAKE3 v1 | 5 084 ns | 7 458 | 8 875 |
| engine insert, SHA-256 | **6 208 ns** | 8 792 | 10 958 |
| engine insert, BLAKE3 v1 | 11 000 ns | 16 000 | 19 791 |
| engine insert, NopRehash | 1 041 ns | 1 250 | 1 375 |

Cite production one-path insert at 8k **~6.2 µs** p50. The earlier **~9 µs** is BLAKE3 v1 (this run measured v1 at ~11 µs p50).
