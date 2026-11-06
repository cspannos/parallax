# Q-STO-3 — WAL durability vs batch `I`

**Date:** 2026-10-01  
**Binary:** `CLOB_BENCH_ONLY=wal cargo run -p clob-bench --release`  
**Host:** Apple M4 Pro, 14 cores, APFS (not a frequency-locked disk bench)  
**Engine:** incremental treap on, full-walk receipts off. **Malachite off.**

Same mixed tape as [`loaded-batch.md`](loaded-batch.md). Replica path: encrypt + append + apply. Three durability modes:

| mode | Meaning |
|---|---|
| `relaxed` | `flush` only (`SyncMode::Relaxed`) |
| `full` | `sync_all` **after every record** (ADR 0007 M2 default) |
| `height` | Relaxed appends, **one** `sync_all` after the tape |

`height` is `SyncMode::Height` (ADR [0012](../adr/0012-height-batch-wal.md)): crash *during* the tape can lose records; those orders were not decided. M2 tests stay on Full.

## Results (p50, implied events/s)

| mode | resting | \|I\| | n | p50 | implied |
|---|---|---|---|---|---|
| relaxed | 8k | 100 | 20 | 2.69 ms | 37k ev/s |
| height | 8k | 100 | 20 | 7.23 ms | 14k ev/s |
| **full** | 8k | 100 | 16 | **377 ms** | **265 ev/s** |
| relaxed | 8k | 1k | 10 | 27.0 ms | 37k ev/s |
| height | 8k | 1k | 10 | 33.6 ms | 30k ev/s |
| **full** | 8k | 1k | 8 | **3.92 s** | **255 ev/s** |
| relaxed | 8k | 10k | 6 | 274 ms | 36k ev/s |
| height | 8k | 10k | 6 | 275 ms | **36k ev/s** |
| **full** | 8k | 10k | 3 | **37.7 s** | **265 ev/s** |
| relaxed | 32k | 100 | 10 | 3.24 ms | 31k ev/s |
| height | 32k | 100 | 10 | 7.93 ms | 13k ev/s |
| **full** | 32k | 100 | 8 | **349 ms** | **286 ev/s** |
| relaxed | 32k | 1k | 6 | 30.8 ms | 32k ev/s |
| height | 32k | 1k | 6 | 34.7 ms | 29k ev/s |
| **full** | 32k | 1k | 4 | **3.40 s** | **294 ev/s** |
| relaxed | 32k | 10k | 4 | 320 ms | 31k ev/s |
| height | 32k | 10k | 4 | 316 ms | **32k ev/s** |
| **full** | 32k | 10k | 3 | **33.2 s** | **301 ev/s** |

## Reading

Per-record `sync_all` is **~260–300 ev/s** at every `|I|`. That is the same death as full-book BLAKE3 (~330 ev/s). A 10k-event height takes **~33–38 s** of fsync. 300M/day cannot use ADR 0007 Full on the apply path.

One fsync per height **amortizes**. At `|I|=10k` it matches Relaxed (~32–36k ev/s, ~275–320 ms), in band with treap-only apply (~40k) and with n=20 Malachite (~250 ms). At `|I|=100` the single fsync dominates (~5 extra ms) and per-event rate drops to ~13–14k/s — still above 3.5k/s average.

M2 tests stay on Full. Consensus apply uses Height (ADR 0012). A 300M-event/day apply path cannot use Full.

## Pass / fail

| Claim | Status |
|---|---|
| `SyncMode::Full` supports 300M/day | **No** (~270 ev/s) |
| Height-batch fsync supports 300M/day average | **Yes** (~32–36k ev/s at \|I\|=10k) |
| Height-batch fsync fits a ~250–320 ms 10k-event height | **Yes, on this host, WAL+inc, no BFT** |
| Relaxed is production durability | **No** (crash can lose the tail) |
