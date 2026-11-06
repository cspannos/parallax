# M4 StartedRound gap — injected vs gossip

**Date:** 2026-10-03  
**Binary:** `PLX_M4_LOADED=1 PLX_M4_GAP=1 cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**Also:** `PLX_M4_LOADED=1 PLX_M4_ISOLATE=1` cells `F+wal,F+nowal,stub+nowal`.

**Question:** gossip later-height StartedRound **~256–309 ms** vs the cited injected **~173–184 ms** ([m4-loaded-isolate.md](m4-loaded-isolate.md)). Same n=4, 8k+10k, WAL `Height`.

Two independent `PLX_M4_GAP=1` runs, then isolate attribution of the 0.18 → 0.25 move.

## Engine-only `F` (one process, 7 clones, p50)

| tape | r1 | r2 |
|---|---|---|
| generator 10k on 8k | 87 | 81 |
| seal-sorted 10k on 8k | 87 | 79 |
| sorted wave 1 after sorted wave 0 | 79 | 74 |

Same set. Hash-sort does **not** cost `F`. A second wave on a grown book is **not** slower.

## Injected BFT (cluster StartedRound → Decided)

Gossip **off**. Afternoon numbers are **pre-fix** (hash in the sort comparator). Evening isolate was worse on the same bug. Evening post-fix is hash-once `tape()` plus skip stub `inputs_for` at `StartedRound`.

| cell | afternoon r1 | afternoon r2 | evening pre-fix | evening post-fix r1 | r2 |
|---|---|---|---|---|---|
| isolate `F+wal` | **246** | **259** | 290 / 311 | **187** | **172** |
| isolate `F+nowal` | — | — | 241 / 228 | **166** | **156** |
| isolate `stub+nowal` \|I\|=10k | — | — | 143 / 138 | **60** | **42** (later confirm 70) |
| isolate `stub+nowal` \|I\|=2 | — | — | 45 / 32 | **37** | — |
| one-process `IntentLog::tape` \|I\|=10k | — | — | — | **15 ms** | **14 ms** |
| gap: injected generator, height 1 | 268 / 261 | 266 / 259 | — | — | — |
| gap: injected seal-sorted, height 1 | 255 / 249 | 216 / 242 | — | — | — |
| gap: empty h1 + offer-all sorted, no mesh | 233 / 248 | 250 / 236 | — | — | — |

## Why 0.18 → 0.25

Not BFT. Not `F`. Not WAL. Not gossip.

`IntentLog::tape` hashed `id(intent)` **inside every sort comparison**. Owner/nonce already decide almost every compare, but BLAKE3 still ran n log n times on 10k. Four processes paid that at every `StartedRound`, including stub cells (floor grew from ~45 ms at \|I\|=2 to ~140 ms at \|I\|=10k).

Hash-once: 10k BLAKE3 then `sort_unstable_by` on the precomputed key. One-process seal **14–15 ms**. Stub `StartedRound` no longer calls `inputs_for` (Validate/GetValue still seal). Floor at \|I\|=10k is **42–70 ms** (tape ~15 ms + BFT ~37 ms). `F+wal` is **172 / 187 ms** — Oct 2’s **173 / 184**.

Attribution after the cut (run 2):

| Piece | How | ms |
|---|---|---|
| BFT + 4 processes | `stub+nowal` \|I\|=2 | **~37** |
| Seal of 10k | one-process `tape` / floor growth | **~15** |
| One `F` of wall time | `F+nowal` − floor | **~90–115** |
| Decide WAL | `F+wal` − `F+nowal` | **~16–21** (noisy) |

## Reading

The ~70–130 ms “gossip tax” on StartedRound **is not hash-sort-as-`F`, not a second `F`, not book growth, not the TCP intent mesh.** Afternoon injected ~0.25 s was the comparator-hash tax. Gossip later StartedRound (**~256–309 ms**, [m4-loaded-gossip.md](m4-loaded-gossip.md)) was measured against that inflated cell and was **not** re-run after the cut.

Injected `F+wal` is **~0.17–0.19 s** again (**~53–58k** on StartedRound). Cite **~55k** for injected shared-`I`. Living-log later last p50 is **~192–202 ms (~50–52k)** after in-flight wait; height 2 last **~223–236 ms**. The first-wave 10k re-fan is gone ([m4-inter-split.md](m4-inter-split.md)).

## Pass / fail

| Claim | Status |
|---|---|
| Seal order is why gossip StartedRound is slower | **No** (engine 79–87 ms both ways) |
| Book growth makes later `F` worse | **No** (wave 1 **faster**) |
| Two-height offer-all matches gossip StartedRound | **Yes** on the afternoon (inflated) cell (~230–250 ms) |
| The 0.18 → 0.25 move is comparator BLAKE3 | **Yes** (hash-once restores ~0.18 s) |
| Injected is ~0.18 s today | **Yes** (172 / 187 ms) |
| Gossip StartedRound has a unique ~70 ms mesh tax | **No** on the afternoon evidence; not re-measured after the cut |

## What this does not license

- Treating gossip later last p50 (~33.5–34.6k) as 35k
- WAN / n=20 / FOCIL / Phase 7
