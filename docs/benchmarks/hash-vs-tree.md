# Hash vs tree — where the 24 µs goes

**Date:** 2026-10-02  
**Binary:** `CLOB_BENCH_ONLY=treap cargo run -p clob-bench --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**Not measured:** WAL, Malachite, alternative hashes, sharded maps.

Q-CRY-2 insert at 8k was **~24 µs** ([q-cry-2-incremental.md](q-cry-2-incremental.md)). This isolate splits BLAKE3 `node_digest` from split/merge/alloc, then cuts path hashes. `NopRehash` keeps BLAKE3 **priority** so tree shape matches production. Alloc-only is `Box` of a 8+32 byte leaf, no tree. **Two independent runs** per column. p50.

Missing-child `empty_digest` is a process-wide `OnceLock`. Upsert is one BST walk + rotations (same cartesian tree). Production `C'` is still BLAKE3.

## Results

| cell | n | split+merge | empty cache | **one-path r1** | **r2** |
|---|---|---|---|---|---|
| BLAKE3 calls / upsert at 8k | 1 | 60 | 50 | **20** | **20** |
| prio / node / empty_blake3 / empty_lookup | 1 | lumped | 1 / 49 / 0 / 10 | **1 / 19 / 0 / 6** | **1 / 19 / 0 / 6** |
| map / blake3 upsert at 8k | 500 | 10.1–10.8 µs | 9.0–10.2 µs | **3.8 µs** | **3.8 µs** |
| map / nop rehash at 8k | 500 | 0.38–0.42 µs | 0.38–0.42 µs | **0.29 µs** | **0.25 µs** |
| alloc / leaf at 8k | 500 | 41 ns | 41 ns | **41 ns** | **41 ns** |
| engine / blake3 insert at 8k | 500 | 26.4–26.6 µs | 20.8–22.6 µs | **9.0 µs** | **8.9 µs** |
| engine / nop rehash insert at 8k | 500 | 1.4–1.8 µs | 1.4–1.6 µs | **1.1 µs** | **1.1 µs** |
| engine / match only at 8k | 500 | 167–208 ns | 166–167 ns | **167 ns** | **167 ns** |

## Reading

One-path upsert is **1 prio + 19 `node_digest`** at 8k (was 1+49). Rotations add a few hashes over `log₂(8000)≈13`. Map upsert **~3.8 µs**. Engine insert **~9 µs**. Engine `C'` is more than one map: insert **72** BLAKE3s, mixed rest/take/cancel **~45 / ~40 / ~14** ([m6-prove](m6-prove.md)). Roots unchanged (insertion-order / rebuild tests).

Nop rehash is still faster (~0.3 µs map): remaining cost is still BLAKE3, just fewer of them. Alloc is **~40 ns**.

Loaded 10k mixed `I` moved with this cut: **~85–87 ms at 8k (~115k ev/s)**, **~94–102 ms at 32k (~98–106k ev/s)** ([loaded-batch.md](loaded-batch.md)). Was ~40k ev/s. Malachite was **not** re-run.

CoW is already ruled out ([clone-vs-apply.md](clone-vs-apply.md)).

## Pass / fail

| Claim | Status |
|---|---|
| Tree walk / alloc is most of `F` | **No** |
| Three hashed splits were extra `node_digest`s | **Yes** (49 → 19) |
| Caching empty digest is a large TPS cut | **No** |
| One-path rehash moves the ~40k ceiling | **Yes** (engine-only ~100k+ ev/s) |
| Matcher is the leftover | **No** (~0.2 µs) |
