# M4 loaded gossip height — offer + mesh

**Date:** 2026-10-03  
**Binary:** `PLX_M4_LOADED=1 PLX_M4_GOSSIP=1 cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**ADRs:** [0016](../adr/0016-intent-set.md)–[0021](../adr/0021-ack-id-set.md)

n=4 localhost TCP. Every replica preloads 8k resting buys. Height 1 seals **empty** `I`. Node 0 **`offer`s** a 10k mixed wave at each seal; others receive on the intent mesh. Later heights seal that wave (not the generator’s interleave). Fan-out encodes once and writes peers in parallel. Sealed intent ids are spent. After the first offer, admit waits until every voter ACKs `id(set)` (ADR 0021). Empty-wait (`gossip_spread` 100 ms) is unchanged.

CI: `m4_loaded.rs` `four_nodes_gossip_offer_loaded_height` (32+8, one-shot) and `four_nodes_gossip_steady_heights` (32+8, three heights). This file is 8k+10k.

## Clocks

| Clock | What it includes |
|---|---|
| StartedRound → Decided | Same as injected isolate. Not the empty-wait. |
| inter-decide | Last voter decide(h-1) → last voter decide(h). The living-log grain. |
| offer → decide | Offer of that height’s tape (previous seal) → last voter decide(h). Includes leftover previous BFT. |

## One-shot (historical, ADR 0020)

Empty height 1, one 10k offer, height 2 only.

| run | admit | tape | StartedRound cluster | offer→decide |
|---|---|---|---|---|
| fixed 100 ms, offer after all h1 | 100 ms floor | — | **timeout** (180 s) | — |
| r1 | **2 s** floor | full \|I\| | **296 ms** (~34k) | **2542 ms** (~3.9k) |
| r2 | **2 s** floor | full \|I\| | **272 ms** (~37k) | **2281 ms** (~4.4k) |
| r1 | **0020** + sleep overlap | full \|I\| | **249 ms** (~40k) | **368 ms** (~27k) |
| r2 | **0020** + sleep overlap | full \|I\| | **260 ms** (~38k) | **370 ms** (~27k) |

## Steady-state ADR 0020 (historical)

Offer at each seal. Quiet 20 ms. Taken against the afternoon ~0.25 s injected cell (comparator BLAKE3). Later inter **~315–351 ms** (~28–32k). StartedRound **~256–309 ms**.

## Steady-state ADR 0021 (ACK of `id(set)`)

Same offer schedule. Quiet unused. Two independent runs after hash-once `tape()`. Every loaded height sealed the full wave. No stall.

### Run 1

| height | started ms | inter ms | offer ms | ev/s inter | tape |
|---|---|---|---|---|---|
| 2 | 241 | 560 | 676 | 17857 | full \|I\| |
| 3 | 264 | 341 | 578 | 29325 | full \|I\| |
| 4 | 241 | 374 | 634 | 26737 | full \|I\| |
| 5 | 146 | 230 | 465 | 43478 | full \|I\| |

inter p50 (2–5) **374 ms** (~27k). After first loaded (3–5) **341 ms** (~29k).

### Run 2

| height | started ms | inter ms | offer ms | ev/s inter | tape |
|---|---|---|---|---|---|
| 2 | 276 | 578 | 717 | 17301 | full \|I\| |
| 3 | 255 | 348 | 620 | 28735 | full \|I\| |
| 4 | 255 | 359 | 609 | 27855 | full \|I\| |
| 5 | 149 | 277 | 527 | 36101 | full \|I\| |

inter p50 (2–5) **359 ms** (~28k). After first loaded (3–5) **348 ms** (~29k).

Injected shared-`I` (gossip **off**) is **~0.17–0.19 s** ([m4-started-gap.md](m4-started-gap.md)).

## Reading

In-flight wait before large recover: later last p50 **~192–202 ms (~50–52k)**. Height 2 last **~223–236 ms (~42–45k)**. First-wave re-fan is gone. 10× peak **fits** both clocks ([m4-inter-split.md](m4-inter-split.md)). Do not cite ~52k as injected.

StartedRound typical later **~166–217 ms**. Height 5 last can invert. Do not cite the best height as the grain.

| Claim | 0021 later p50 | 0020 later p50 | Injected |
|---|---|---|---|
| 300M/day (~3.5k/s) | **Yes** (~50–52k) | Yes (~28–32k) | Yes (~55k) |
| 1B/day (~11.6k/s) | **Yes** | Yes | Yes |
| 10× peak (~35k/s) | **Yes** on later last and height 2 last | **No** | Yes |

Do not cite p50 of heights 2–5 as the product grain. Do not cite ~55k for `offer`. Do not cite height 5 alone.

## Pass / fail

| Claim | Status |
|---|---|
| 10k `offer` + mesh decides at a fixed 100 ms spread | **No** (stall) |
| 10k `offer` + mesh decides at 2 s spread | **Yes** (~2.4 s offer clock) |
| One-shot 0020 + overlap | **Yes** (~0.37 s offer clock) |
| ACK of `id(set)` admits 10k without quiet | **Yes** (two runs, full tape, no stall) |
| Later-height inter-decide ~270 ms / ~37k | **Superseded.** In-flight wait later last ~192–202 ms / ~50–52k |
| 10× peak on the living-log clock | **Yes** on later last p50 and height 2 last |

## Admit cut (historical, then 0021)

| Rule | Result |
|---|---|
| quiet **0 ms** | **Stall** (partial `I`) |
| quiet **10 ms** | **Stall** |
| quiet **20 ms** | Full set, later inter ~315–351 ms |
| **ACK of `id(set)`** | Full set, later inter ~341–348 ms |

Quiet was load-bearing as a *timer*. ACK replaces the timer with agreement. It does not remove the inter-decide gap.

## What this does not license

- Calling ~29k the injected grain
- Treating height-5 35k+ as the product clock
- WAN, encryption of `I`, FOCIL, n=20
- 2f+1 inclusion (a peer that stays empty for 100 ms still diverges; a liar can ACK a set it does not hold)

## Re-run after ADR 0027 (target-height intents, 2026-10-18)

Same binary. One run: every height sealed the full 10k `I`. Last-decide per height 2 / 3 / 4 / 5 = 155 / 203 / 189 / 100 ms. Later p50 (3–5): last **189 ms** (~53k ev/s), first 198 ms, q 195 ms. Consistent with the in-flight-wait numbers above. Waves are now tagged for the height after the offerer's seal, so a wave can no longer split `I(h)` across nodes.

