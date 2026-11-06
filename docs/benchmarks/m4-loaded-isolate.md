# M4 loaded isolate — where the 1.5 s went

**Date:** 2026-10-02  
**Binary:** `PLX_M4_LOADED=1 PLX_M4_ISOLATE=1 cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**Tape:** n=4 localhost TCP broadcast, 8k resting preload, `|I|=10k` mixed, treap `C'`, WAL `Height` unless noted. One height. StartedRound → Decided.

Empty-book isolate ([m4-isolate.md](m4-isolate.md)) found dummy ≈ full at n=20. That does **not** hold on this tape.

| knob | Meaning |
|---|---|
| `F+wal` | GetValue `F`, voter prevote `F` unless a scratch already matches `id(v)`, decide one `PLXTAPE` + install scratch (ADR 0014). StartedRound speculates local `I` when not stubbed (shared-`I` / Model I). |
| `stubV` | prevote skips replay `F` (and skips StartedRound speculate) |
| `stub` | GetValue is a zero-root dummy (implies stubV) |
| `nosync` | `SyncMode::Relaxed` |
| `nowal` | skip replica persist on decide |

Columns are successive decide-path cuts. Latest: **one-path upsert `F`**. Two independent runs after that.

## Cluster latency (ms)

| cell | scratch×2 | one-apply | scratch reuse | blob WAL | skip-V | spec | **one-path r1** | **r2** |
|---|---|---|---|---|---|---|---|---|
| **F+wal** | 1595–1614 | 1006–1009 | 731–740 | 556–562 | 529–531 | 320–323 | **173** | **184** |
| stubV+wal | 1373–1387 | 773–790 | 713–763 | 532–550 | 523–544 | 555–558 | 258 | 261 |
| F+nosync | 1562–1576 | 991–1001 | 737–769 | 528–529 | 511–519 | 293–297 | 166 | 165 |
| **F+nowal** | 528–550 | 518–572 | 528–531 | 514 | 498–526 | 288–309 | **169** | **150** |
| stubV+nowal | 291–292 | 292–298 | 282–291 | 274–296 | 283–296 | 279–281 | 148 | 154 |
| **stub+nowal** | 45–57 | 47 | 34–37 | 37 | 36–42 | 38–39 | **47** | **44** |

## Attribution (one-path, run 2)

| Piece | How | ms |
|---|---|---|
| BFT + 4 processes | `stub+nowal` | **~45** |
| One `F` of wall time | `F+nowal` − floor | **~105** |
| Decide WAL | `F+wal` − `F+nowal` | **~35** (noisy vs run 1) |

`F+nowal` **≈ `stubV+nowal`**. Shared-`I` overlap still holds. Engine-only `F` is **~85–87 ms** ([loaded-batch.md](loaded-batch.md)); four processes speculating on one machine adds a bit.

`stubV+wal` stays ~260 ms: stub knobs skip speculate, so voters pay `F` on decide. That cell is not the shared-`I` path.

This bound **does not** apply if the proposer packs `I` at GetValue (Q-CONS-10). Clone is ~0.6–3 ms ([clone-vs-apply.md](clone-vs-apply.md)).

Implied at the height grain: **~55k ev/s** (10k / ~0.18 s). 300M/day, 1B/day, and 10× peak (~35k/s) **fit** injected StartedRound. Living-log inter-decide does not ([m4-loaded-gossip.md](m4-loaded-gossip.md)).

**2026-10-03 afternoon / evening pre-fix:** isolate `F+wal` **246 / 259** then **290 / 311**. Cause: `tape()` hashed `id(intent)` in every sort compare; stub cells also sealed 10k at `StartedRound` ([m4-started-gap.md](m4-started-gap.md)).

**2026-10-03 evening post-fix** (hash-once + skip stub `inputs_for` at `StartedRound`):

| cell | r1 cluster | r2 cluster |
|---|---|---|
| `F+wal` | **187** | **172** |
| `F+nowal` | **166** | **156** |
| `stub+nowal` \|I\|=10k | **60** | **42** |
| `stub+nowal` \|I\|=2 | **37** | — |
| one-process `tape` \|I\|=10k | **15 ms** | **14 ms** |

Floor growth at 10k is the **~15 ms seal**, not BFT. `F` wall still ~90–115 ms. WAL ~16–21 ms (noisy). Grain is Oct 2 again.

## Pass / fail

| Claim | Status |
|---|---|
| Shared local `I` overlaps GetValue and voter `F` | **Yes** |
| That is available for proposer-packed `I` | **No** (Q-CONS-10) |
| Production cell is ~180 ms | **Yes** after hash-once (172 / 187). Afternoon ~0.25 s was the comparator tax |
| 10× peak on this grain | **Yes** on injected StartedRound (~55k) and living-log later last p50 (~50–52k) |

## What this does not license

- Dropping voter prevote `F` (Q-CONS-2 / ADR 0009). Speculate is still a full execution vote on local `I`.
- Treating Malachite proposer rotation as a sequenced mempool.
- n=20 / WAN / 1M voters, Phase 7, `π`, live Reth.
