# M4 inter-decide split — where the living-log gap sits

**Date:** 2026-10-03  
**Binary:** `PLX_M4_LOADED=1 PLX_M4_GOSSIP=1 cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.  
**ADRs:** [0021](../adr/0021-ack-id-set.md)

Same cell as [m4-loaded-gossip.md](m4-loaded-gossip.md): n=4, 8k+10k, offer at each seal, ACK of `id(set)`. Two independent runs after adding replica clocks.

**Question:** later inter ~340 ms vs injected StartedRound ~0.18 s. Is that last-voter tail, Malachite start, or admit?

## Clocks (new)

| Name | Meaning |
|---|---|
| `started` | StartedRound → Decided (cluster max). Same as before. |
| `last` / `first` / `q` | Inter-decide from replica `decided_at`: last-to-last, first-to-first, 2f+1-to-2f+1. |
| `dF` | This replica’s Decided(h-1) → Finalized(h-1). Cluster max. |
| `Fa` | Finalized → admit return (ACK quorum or empty). Cluster max. **This is `admit_window` wall time.** |
| `aS` | Admit return → StartedRound(h). Cluster max. |

Product clock is still last-to-last until a named switch. These columns do not change that.

## Results

### Run 1 (port 50000)

| height | started | last | first | q | dF | Fa | aS | ev/s last |
|---|---|---|---|---|---|---|---|---|
| 2 | 277 | 591 | 462 | 468 | 0 | **307** | 13 | 16920 |
| 3 | 258 | 361 | 377 | 377 | 0 | **229** | 8 | 27700 |
| 4 | 263 | 402 | 394 | 392 | 0 | **244** | 11 | 24875 |
| 5 | 144 | 247 | 364 | 360 | 0 | **219** | 8 | 40485 |

later p50 (3–5): last **361** (~28k); first **377**; q **377**.

### Run 2 (port 50040)

| height | started | last | first | q | dF | Fa | aS | ev/s last |
|---|---|---|---|---|---|---|---|---|
| 2 | 226 | 527 | 458 | 464 | 0 | **302** | 9 | 18975 |
| 3 | 235 | 397 | 389 | 385 | 0 | **235** | 11 | 25188 |
| 4 | 266 | 429 | 386 | 389 | 0 | **239** | 12 | 23310 |
| 5 | 155 | 249 | 370 | 365 | 0 | **213** | 13 | 40160 |

later p50 (3–5): last **397** (~25k); first **386**; q **385**.

## Reading

| Claim | Status |
|---|---|
| Last-voter tail is the ~80–100 ms | **No.** Later first/q ≈ last (sometimes first is *worse*). Height 5 last looks fast because height 4’s last was a straggler. |
| Decided → Finalized is the gap | **No.** `dF` is **0 ms** (same millisecond). |
| Malachite `Next::Start` is the gap | **No.** `aS` is **8–13 ms**. |
| Admit at Finalized is the gap | **Yes.** `Fa` later **~213–244 ms**. That is almost the whole inter − StartedRound remainder, and on the cold height almost the whole 300 ms. |

`admit_window` still **re-fans the full pending set** at every `Finalized`, then waits for ACK. The wave was already `offer`ed (and published) at the previous seal. The 10k TCP write sits on the critical path **after** decide. A prior “skip re-fan-out” cut **stalled** because it had no ACK; with ACK, a missing peer simply does not match `id(set)`.

StartedRound later is **~235–266 ms** (height 5 **144–155**). Injected is **~172–187**. The unique gossip *BFT* tax is smaller than admit.

35k needs ~286 ms last-to-last. `started` + `aS` + a cheap ACK is in band **if `Fa` collapses**. Do not cite 35k until that is measured.

## After skip re-fan-out (same night)

`offer` already published the wave. `Finalized` ACKs first; fan-out only on ACK miss. Empty heights ACK the empty `id(set)` so a peer does not seal empty `I` while the offerer still holds the tape.

### Run 1 (port 50100)

| height | started | last | first | q | dF | Fa | aS | ev/s last |
|---|---|---|---|---|---|---|---|---|
| 2 | 155 | 327 | 169 | 172 | 0 | 143 | 93 | 30581 |
| 3 | 282 | 289 | 332 | 328 | 0 | 166 | 6 | 34602 |
| 4 | 149 | 315 | 299 | 302 | 0 | 148 | 93 | 31746 |
| 5 | 153 | 160 | 289 | 287 | 0 | 139 | 6 | 62500 |

later p50 (3–5): last **289** (~34.6k); first **299**; q **302**.

### Run 2 (port 50140)

| height | started | last | first | q | dF | Fa | aS | ev/s last |
|---|---|---|---|---|---|---|---|---|
| 2 | 142 | 314 | 167 | 165 | 0 | 141 | 93 | 31847 |
| 3 | 290 | 298 | 320 | 322 | 0 | 160 | 9 | 33557 |
| 4 | 137 | 324 | 306 | 306 | 0 | 166 | 90 | 30864 |
| 5 | 148 | 155 | 299 | 300 | 0 | 153 | 6 | 64516 |

later p50 (3–5): last **298** (~33.6k); first **306**; q **306**.

`Fa` fell **~213–244 → ~139–166**. It did **not** collapse to an ACK RTT; recovery fan-out still fires on the cluster-max node. Later last p50 **~289–298 ms (~33.5–34.6k)**. 35k needs ~286 ms. **Closest yet. Not 35k.** Do not cite height 5 last (straggler inversion).

## Why `Fa` is still ~150 ms (admit path)

Same cell, two runs, per-replica path at `Finalized` of the previous height (`Decision.admit` on height h).

`ready` = all n already matched. `grace` = ≥1 peer matched, 50 ms wait finished quorum. `recover` = re-fan pending. `acks` = matching `id(set)` after the first `SetAck` at `Finalized` (includes self). `fanout` = bytes of that re-fan (cluster max).

### Run 1 (port 50200)

| height | Fa | ready | grace | recover | late | acks min/max | fanout max kB | last ms |
|---|---|---|---|---|---|---|---|---|
| 2 | **12** | 0 | **4** | 0 | 0 | 2/2 | **0** | 300 |
| 3 | 152 | 0 | 0 | **4** | 0 | 1/1 | **944** | 292 |
| 4 | 132 | 1 | 0 | **3** | 0 | 1/4 | 30 | 304 |
| 5 | 146 | 1 | 0 | **3** | 0 | 1/4 | 433 | 153 |

later last p50 **292** (~34.2k).

### Run 2 (port 50240)

| height | Fa | ready | grace | recover | late | acks min/max | fanout max kB | last ms |
|---|---|---|---|---|---|---|---|---|
| 2 | **14** | 0 | **4** | 0 | 0 | 2/2 | **0** | 303 |
| 3 | 150 | 1 | 0 | **3** | 0 | 1/4 | 456 | 310 |
| 4 | 149 | 0 | 1 | **3** | 0 | 1/2 | 546 | 284 |
| 5 | 117 | 1 | 0 | **3** | 0 | 1/4 | 364 | 154 |

later last p50 **284** (~35.2k on this run’s p50 only).

| Claim | Status |
|---|---|
| `Fa` is a lying clock | **No.** When path is grace and fan-out is 0, `Fa` is **12–14 ms**. |
| Later `Fa` ~150 ms is last-voter / Malachite | **No.** It is **recover**. |
| Mid-height ACK already matches at later `Finalized` | **No.** Typical `acks_at_entry` is **1** (self only). Height 2 had **2** and used grace. |
| Recovery still sends the 10k | **Yes** on later heights (up to **~0.4–0.9 MB**). |

The first loaded height can admit on grace. Later waves do not: `id(set)` changes, old ACKs do not match, and a new matching ACK has not landed by `Finalized`. Then we re-write the tape. That is the remaining ~150 ms.

Do not cite run 2’s 284 ms p50 as 35k (need two runs; run 1 is 292). Height 5 last is still a straggler inversion.

## ACK the completed wave (same night)

Stop ACKing every growing ingest (that was ~10k partial `SetAck`s). ACK after a local offer batch, or when local `id(set)` matches a peer ACK.

### Run 1 (port 50300)

| height | started | last | Fa | ready | grace | recover | acks | fanout kB |
|---|---|---|---|---|---|---|---|---|
| 2 | 227 | 352 | 128 | 0 | 3 | 1 | 1/3 | 944 |
| 3 | 222 | 226 | 116 | 1 | 0 | 3 | 1/4 | 20 |
| 4 | 250 | 254 | 91 | 1 | 0 | 3 | 1/4 | 30 |
| 5 | 204 | 148 | 87 | 1 | 0 | 3 | 1/4 | 71 |

later last p50 **226 ms** (~44k). first **251**; q **252**.

### Run 2 (port 50340)

| height | started | last | Fa | ready | grace | recover | acks | fanout kB |
|---|---|---|---|---|---|---|---|---|
| 2 | 220 | 354 | 130 | 0 | 2 | 2 | 1/3 | 944 |
| 3 | 222 | 225 | 140 | 1 | 0 | 3 | 1/4 | 25 |
| 4 | 243 | 251 | 81 | 1 | 0 | 3 | 1/4 | 45 |
| 5 | 230 | 176 | 98 | 1 | 0 | 3 | 1/4 | 51 |

later last p50 **225 ms** (~44k). first **278**; q **278**.

Later recover is a **tail** (20–71 kB), not a second 10k (~0.9 MB). Height 2 still sometimes re-fans the first wave. Cluster-max `Fa` is still ~80–140 ms on a recover node; last-to-last p50 does not add that in full.

**10× peak (~35k, need ~286 ms) fits later last p50 (~225 ms / ~44k).** Two runs. Do not cite height 5 last. Do not cite 44k as injected (~55k). Cold height 2 is still ~0.35 s last.

## In-flight wait before large recover (same night)

Empty height 1 is too short for the first 10k. At `Finalized`, a **large** pending set (≥1024) waits ~180 ms for completed-wave ACKs before re-fan. A small tail still recovers immediately.

### Run 1 (port 50400)

| height | started | last | first | q | Fa | ready | grace | inflight | recover | fanout kB |
|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 211 | 223 | 200 | 202 | 14 | 1 | 0 | 3 | 0 | 0 |
| 3 | 212 | 215 | 160 | 161 | 21 | 1 | 0 | 3 | 0 | 0 |
| 4 | 166 | 174 | 228 | 227 | 88 | 1 | 0 | 2 | 1 | 93 |
| 5 | 152 | 202 | 224 | 224 | 76 | 0 | 0 | 4 | 0 | 0 |

later last p50 **202 ms** (~50k). first **224**; q **224**. Height 2 last **223 ms**.

### Run 2 (port 50440)

| height | started | last | first | q | Fa | ready | grace | inflight | recover | fanout kB |
|---|---|---|---|---|---|---|---|---|---|---|
| 2 | 219 | 236 | 204 | 210 | 15 | 0 | 0 | 4 | 0 | 0 |
| 3 | 189 | 192 | 162 | 159 | 21 | 1 | 0 | 3 | 0 | 0 |
| 4 | 217 | 220 | 193 | 197 | 53 | 1 | 0 | 3 | 0 | 0 |
| 5 | 180 | 148 | 231 | 231 | 53 | 1 | 0 | 2 | 1 | 69 |

later last p50 **192 ms** (~52k). first **193**; q **197**. Height 2 last **236 ms**.

First-wave recover is **gone** (0 bytes both runs; path is InFlight). Later recover is a **rare tail** (0–93 kB, one node). Height 2 last **~223–236 ms (~42–45k)**. Later last p50 **~192–202 ms (~50–52k)**.

**10× peak fits later last p50 and height 2 last.** Two runs. Do not cite height 5 last. Do not cite ~52k as injected (~55k).

## What this does not license

- Switching the product clock to first-to-first or quorum
- Skipping fan-out without ACK (already stalled)
- Citing ~52k as the injected grain
- WAN / FOCIL / Phase 7
