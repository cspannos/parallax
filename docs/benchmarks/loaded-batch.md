# Loaded-book batch `I` (execution path)

**Date:** 2026-10-02  
**Binary:** `CLOB_BENCH_ONLY=batch cargo run -p clob-bench --release`  
**Host:** Apple M4 Pro, 14 cores  
**Not measured:** WAL, Malachite, signatures, `π`, multi-instrument, WAN.

Tape: mixed `I` on a loaded `BTreeBook` (~½ new rests, ~¼ takes, ~¼ cancels). Time is the **whole tape** (plus cached incremental root when the treap is on). Full-walk receipts only on the 8k / `|I|=100` cell.

- 300M position-lifecycle events/day ≈ **3.5k/s** average. A 10× open-hours peak is ~35k/s.
- **Runs:** two independent after one-path upsert. p50 unless noted.

## Results

| mode              | resting | \|I\| | n   | run 1 p50 | run 2 p50  | implied (run 2) |
| ----------------- | ------- | --- | --- | --------- | ---------- | --------------- |
| full Blake3 walk  | 8k      | 100 | 40  | 287 ms    | **275 ms** | **363 ev/s**    |
| match only        | 8k      | 100 | 40  | 13 µs     | 14 µs      | 7.1M ev/s       |
| incremental treap | 8k      | 100 | 40  | 0.86 ms   | **0.87 ms** | **115k ev/s**   |
| match only        | 8k      | 1k  | 20  | 137 µs    | 156 µs     | 6.4M ev/s       |
| incremental       | 8k      | 1k  | 20  | 8.18 ms   | **8.92 ms** | **112k ev/s**   |
| match only        | 8k      | 10k | 10  | 2.20 ms   | 2.10 ms    | 4.8M ev/s       |
| incremental       | 8k      | 10k | 10  | 86.9 ms   | **85.4 ms** | **117k ev/s**   |
| match only        | 32k     | 100 | 20  | 14 µs     | 18 µs      | 5.5M ev/s       |
| incremental       | 32k     | 100 | 20  | 0.99 ms   | **1.07 ms** | **94k ev/s**    |
| match only        | 32k     | 1k  | 10  | 170 µs    | 179 µs     | 5.6M ev/s       |
| incremental       | 32k     | 1k  | 10  | 10.0 ms   | **9.75 ms** | **103k ev/s**   |
| match only        | 32k     | 10k | 8   | 2.03 ms   | 2.13 ms    | 4.7M ev/s       |
| incremental       | 32k     | 10k | 8   | 94.0 ms   | **102 ms** | **98k ev/s**    |

Prior (split+merge upsert): incremental 10k was **~228–258 ms (~40k ev/s)**.

## Reading

Matching a height-sized tape is **not** the problem. `C'` was. One-path BLAKE3 upsert ([hash-vs-tree.md](hash-vs-tree.md)) moved incremental `F` of 10k events to **~85–102 ms (~100–117k ev/s)**. Clone of that engine is still **~0.6–3 ms** ([clone-vs-apply.md](clone-vs-apply.md)).

Average 300M/day and a 10× peak (~35k/s) **fit engine-only** with headroom. Loaded Malachite n=4 with shared `I` is **~0.18 s / ~55k ev/s** ([m4-loaded.md](m4-loaded.md)). This is not a 100k/s **network** claim.

## Pass / fail

| Claim                                         | Status                                                           |
| --------------------------------------------- | ---------------------------------------------------------------- |
| Matcher handles 3.5k–35k/s in-process         | **Yes** (millions/s)                                             |
| Full-walk `C'` handles 300M/day               | **No** (~350 ev/s)                                               |
| Incremental `C'` handles 300M/day average     | **Yes** (~100k ev/s)                                             |
| Incremental `C'` handles 10× peak on one core | **Yes** (engine-only)                                            |
| `F` of \|I\|=10k fits in a ~250 ms height | **Yes** — engine ~85–102 ms; BFT n=4 shared `I` **~0.18 s** ([m4-loaded.md](m4-loaded.md)) |

## Re-measure with SHA-256 `C'` (ADR 0024, 2026-10-15)

`CLOB_BENCH_ONLY=batch cargo run -p clob-bench --release`, same host, `inc` = treap `C'` with SHA-256.

| rest | \|I\| | inc p50 | implied |
|---|---|---|---|
| 8 000 | 100 | 0.56 ms | ~179k ev/s |
| 8 000 | 1 000 | 5.49 ms | ~182k ev/s |
| 8 000 | 10 000 | **58.2 ms** | **~172k ev/s** |
| 32 000 | 10 000 | 63.3 ms | ~158k ev/s |

Cite production loaded 10k engine work **~58 ms** (~172k ev/s). The ~85–102 ms / ~100–117k ev/s above is BLAKE3 v1. Match-only and full-walk rows are unchanged (no treap).

## Re-measure after the trace-allocation fix (2026-10-17)

`node_digest` / priority no longer build trace openings unless a trace is active (ADR 0025, guest trimming). Same binary and host: 8 000 resting + 10 000 events **27.9 ms** (~358k ev/s); 32 000 + 10 000 **33.0 ms** (~303k ev/s). Cite production loaded 10k engine work **~28 ms**.
