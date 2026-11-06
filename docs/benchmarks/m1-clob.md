# M1 CLOB benches

**Date:** 2026-09-30  
**Binary:** `cargo run -p clob-bench --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned. No frequency lock.  
**Units:** nanoseconds. Matcher benches set `commit_on_apply = false` and `incremental_on_apply = false` so they measure the book, not a commitment.

These are **not** network or consensus numbers. They are not a 100k order/s claim. Max columns include first-touch / allocator outliers.

## Results (`CLOB_BENCH_N=20000`)

| bench | n | p50 | p95 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|
| BTreeBook/insert | 20000 | 208 | 291 | 375 | 1625 | 401458 |
| VecBook/insert | 20000 | 292 | 3083 | 4500 | 13666 | 420458 |
| BTreeBook/match | 20000 | 292 | 458 | 542 | 2250 | 20417 |
| VecBook/match | 20000 | 291 | 417 | 459 | 625 | 16416 |
| BTreeBook/cancel | 20000 | 42 | 125 | 167 | 291 | 10833 |
| VecBook/cancel | 20000 | 42 | 84 | 125 | 209 | 7916 |
| BTreeBook/state_root_1000 | 2000 | 346500 | 498416 | 1026750 | 3279042 | 3357875 |
| VecBook/state_root_1000 | 2000 | 345833 | 524791 | 989708 | 3349250 | 3386416 |
| BTreeBook/state_root_8000 | 500 | 2864959 | 5601750 | 7465167 | 7714292 | 7876958 |
| VecBook/state_root_8000 | 500 | 2867750 | 6760917 | 12640417 | 14425459 | 22752458 |

## Reading

- Insert/match/cancel at p50 are **sub-microsecond** on this machine for this workload (single instrument, integer ticks, no WAL, no crypto on orders).
- `VecBook` insert p95 is ~10× `BTreeBook` when many distinct prices (sorted-vec insert). Match is similar once the book exists.
- State root is **~0.35 ms at 1k resting**, **~2.9 ms p50 at 8k resting**. Full rebuild per receipt will not hit 100k apply/s if every apply hashes the whole book. Q-CRY-2 follow-up: [`q-cry-2-incremental.md`](q-cry-2-incremental.md) (treap insert at 8k ~24 µs; not `C'`).
- Default engine stays `BTreeBook` until a better structure wins a later bake-off (Q-CLOB-2 still open: slot maps, etc.).
