# M4 loaded height — treap `C'` + height WAL

**Date:** 2026-10-02  
**Binary:** `PLX_M4_LOADED=1 cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**ADRs:** [0012](../adr/0012-height-batch-wal.md), [0013](../adr/0013-treap-is-c.md)

One Malachite height, n=4 localhost TCP broadcast. Every replica preloads 8k resting buys (`SyncMode::Height` WAL), then `GetValue`/`Validate`/`Decide` a 10k mixed `I`. `ConsensusValue.state_root` is the treap. Latency is StartedRound → Decided (same clock as M4b). When `I` is already local, StartedRound speculates the tape; Validate is an `id(v)` check. Voters without a matching scratch still replay.

CI covers a tiny tape (`crates/consensus-adapter/tests/m4_loaded.rs`: 32 resting + `|I|=8`). This file is the 8k + 10k cell. **Two independent isolate runs** (`PLX_M4_ISOLATE=1` `F+wal` cell).

## Results

| run | n | cell | heights | node p50 | cluster |
|---|---|---|---|---|---|
| one-path r1 | 4 | loaded/8000+10000 | 1 | **164** | **173** |
| one-path r2 | 4 | loaded/8000+10000 | 1 | **184** | **184** |
| spec (prior `F`) | 4 | loaded/8000+10000 | 1 | 313–319 | ~0.32 s |
| skip-V (prior) | 4 | loaded/8000+10000 | 1 | 519–522 | ~0.53 s |
| blob WAL (prior) | 4 | loaded/8000+10000 | 1 | 551 | ~0.56 s |
| scratch reuse (prior) | 4 | loaded/8000+10000 | 1 | 715–739 | ~0.73–0.74 s |
| one-apply decide (prior) | 4 | loaded/8000+10000 | 1 | ~1005 | ~1.0 s |
| scratch decide ×2 (prior) | 4 | loaded/8000+10000 | 1 | 1484–1674 | ~1.5–1.7 s |

Implied at the height grain: **~55k ev/s** (10k / ~0.18 s). Afternoon 2026-10-03 ~0.25 s was comparator BLAKE3 in `tape()`; hash-once restored **172 / 187 ms** ([m4-started-gap.md](m4-started-gap.md)).

## Reading

Engine-only 10k mixed `I` on 8k resting is **~85–87 ms** (~115k ev/s) ([loaded-batch.md](loaded-batch.md)). The loaded BFT height is **~0.17–0.19 s** injected ([m4-loaded-isolate.md](m4-loaded-isolate.md)). Same cell was ~1.5 s → ~1.0 s → ~0.74 s → ~0.56 s → ~0.53 s → ~0.32 s → ~0.18 s (afternoon ~0.25 s was a seal-sort tax, not a new `F`). This is a **Model I / sequenced-`I` bound** (ADR [0015](../adr/0015-sequenced-i.md)), not proposer-packed `I`. The engine seals that tape from a replicated set (ADR [0016](../adr/0016-intent-set.md)). **`offer` + mesh** is a different cell ([m4-loaded-gossip.md](m4-loaded-gossip.md)): in-flight wait later last p50 ~192–202 ms (~50–52k); height 2 last ~223–236 ms (~42–45k). 10× peak fits both clocks.

300M/day (~3.5k/s) and 1B/day (~11.6k/s) **fit** both clocks. A 10× open-hours peak (~35k/s) **fits injected StartedRound and living-log last-to-last.** Not 1M validators. Not `π`. Not n=20.

## Pass / fail

| Claim | Status |
|---|---|
| n=4 can decide 8k book + 10k mixed `I` with treap `C'` + height WAL | **Yes** (~0.17–0.19 s injected) |
| That height matches engine-only ~85 ms | **No.** One `F` + floor + persist |
| Shared `I` overlaps the two `F`s | **Yes** |
| That holds for proposer-packed `I` | **No** (Q-CONS-10) |
| 300M/day average at this grain | **Yes** (~55k > 3.5k) |
| 1B/day average at this grain | **Yes** (~55k > 11.6k) |
| 10× peak at this grain | **Yes** on injected StartedRound (~55k) and on living-log later last (~50–52k) and height 2 last (~42–45k) |

## Re-measure with SHA-256 `C'` (ADR 0024, 2026-10-15)

Same binary and host. Two loaded runs: cluster **157 ms** and **156 ms** (~64k ev/s). Isolate (`PLX_M4_ISOLATE=1`, cluster): `F+wal` 176, `stubV+wal` 210, `F+nosync` 139, `F+nowal` 155, `stubV+nowal` 134, `stub+nowal` 49 ms. Cite production loaded height **~0.156–0.157 s** (~64k ev/s); the ~0.17–0.19 s / ~55k above is BLAKE3 v1. These are single-height samples; the stubV cell sits above `F+wal` in this run, so treat cell-to-cell gaps under ~30 ms as noise.

## Re-measure after the trace-allocation fix (2026-10-17)

Two loaded runs: cluster **129 ms** and **136 ms** (~74–78k ev/s). Cite production loaded height **~0.13 s**.
