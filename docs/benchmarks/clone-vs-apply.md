# Clone vs apply — is `replay` the leftover?

**Date:** 2026-10-02  
**Binary:** `CLOB_BENCH_ONLY=clone cargo run -p clob-bench --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**Not measured:** WAL, Malachite, signatures, `π`.

`port::replay` does `engine.clone()` then `apply_all(I)`. [`loaded-batch.md`](loaded-batch.md) timed apply with clone **outside** the timer. This isolate splits clone, apply, and clone+apply (`replay`). Incremental `C'` on unless `clone/book`. Mixed `|I|=10k` is `churn_tape`. **Two independent runs.** p50.

## Results

| cell | resting | \|I\| | n | run 1 p50 | run 2 p50 |
|---|---|---|---|---|---|
| **clone/inc** | 8k | — | 40 | **0.61 ms** | **0.63 ms** |
| **clone/inc** | 32k | — | 20 | **3.06 ms** | **2.98 ms** |
| clone/book (treap off) | 8k | — | 40 | 59 µs | 61 µs |
| clone/book (treap off) | 32k | — | 20 | 0.22 ms | 0.23 ms |
| **apply/inc** | 8k | 10k | 10 | **219 ms** | **219 ms** |
| **apply/inc** | 32k | 10k | 8 | **249 ms** | **247 ms** |
| **replay (clone+apply)** | 8k | 10k | 10 | **217 ms** | **220 ms** |
| **replay (clone+apply)** | 32k | 10k | 8 | **249 ms** | **252 ms** |

## Reading

Clone of an 8k incremental engine is **~0.6 ms**. At 32k, **~3 ms**. Almost all of that is the three treaps (`clone/inc` ≈ 10× `clone/book`). Apply of 10k mixed `I` is **~219–252 ms**, same as loaded-batch. `replay` ≈ apply: clone is in the noise (~0.3% of `F` at 8k, ~1% at 32k).

CoW / Arc book **is not** the next TPS cut. The 250 ms `F` is treap mutations.

## Pass / fail

| Claim | Status |
|---|---|
| `replay` clone is a large part of loaded `F` | **No** (~0.6–3 ms) |
| CoW is worth doing before cheaper `C'` | **No** |
| Loaded `F` is still ~40k ev/s of treap apply | **Superseded** — one-path upsert ~100k+ ([hash-vs-tree.md](hash-vs-tree.md)) |
