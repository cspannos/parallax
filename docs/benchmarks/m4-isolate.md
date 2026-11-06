# M4 isolate — harness vs Validate vs WAL

**Date:** 2026-09-30 (run 1 afternoon; **run 2** evening, same binary/host)  
**Binary:** `PLX_M4_ISOLATE=1 cargo run -p m4-scale --release`  
**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned. `ulimit -n 65536`.  
**Clock:** StartedRound → Decided (ms). Cluster = max node latency at the height.  
**Control:** same `EngineBuilder` as M4b. Dummy cell is **not** stock Malachite test-app (their 100-node / 1 MB experiment was not re-run here).

One variable at a time from the M4b cell (`broadcast+F+wal`). GossipSub uses mesh D=6 with **flood-publish off**. `stubV` skips `F`/BLAKE3 in Validate only. `stub+nowal` is a zero-root dummy `GetValue` and does not replica-apply. `nosync` is `SyncMode::Relaxed` (still writes the WAL, no `sync_all`).

Run 2 did not include n=100 (default isolate is 20, 50).

## Cluster p50 (ms)

| n | cell | heights | run 1 p50 | run 2 p50 | run 1 max | run 2 max |
|---|---|---|---|---|---|---|
| 20 | broadcast+F+wal | 4 | 271 | 253 | 438 | 431 |
| 20 | gossipsub+F+wal | 4 | 302 | 256 | 398 | 379 |
| 20 | broadcast+stubV+wal | 4 | 273 | 370 | 493 | 457 |
| 20 | broadcast+F+nosync | 4 | 298 | 284 | 335 | 299 |
| 20 | gossipsub+stub+nowal (floor) | 4 | 275 | 281 | 308 | 336 |
| 50 | broadcast+F+wal | 2 | 4654 | 4432 | 4654 | 4432 |
| 50 | gossipsub+F+wal | 2 | 1661 | 1975 | 1661 | 1975 |
| 50 | gossipsub+stub+nowal (floor) | 2 | 1672 | 1707 | 1672 | 1707 |
| 100 | broadcast+F+wal ([M4b](m4b-scale.md)) | 1 | 178006 | — | 178006 | — |
| 100 | gossipsub+F+wal | 1 | 159253 | — | 159253 | — |
| 100 | gossipsub+stub+nowal (floor) | 1 | 228352 | — | 228352 | — |

n=50/100 cluster sample count is 1–2; p95=max. n=100 dummy slower than F is noise under 100 processes on 14 cores, not “dummy is worse.” Run 2 `stubV` cluster p50 (370) is the noisiest n=20 cell; node p50 was still 228, in band with the others.

## What the 178 s was

| Hypothesis | n=20 (both runs) | n=50 (both runs) | n=100 (run 1) |
|---|---|---|---|
| Broadcast vs GossipSub | No (253–302 vs 253–271) | **Yes** (~1.7–2.0 s vs ~4.4–4.7 s) | No (~159 s vs 178 s) |
| `F` + BLAKE3 in Validate (Q-CRY-2) | No (dummy 275–281 ≈ full) | No (dummy 1.67–1.71 s ≈ GossipSub F) | No (dummy 228 s vs 159 s) |
| Replica `sync_all` | No (nosync 284–298) | — | — |
| 100 engines on 14 cores | — | likely (1.7–2.0 s floor) | **Yes** (floor still minutes) |

At n=20 every **full / dummy / nosync** cell is ~250–300 ms cluster p50. That is **BFT + 20 processes**, not matching, not `F`. Empty book: Q-CRY-2 is still load-bearing at 8k resting orders ([M1](m1-clob.md)); it is **not** why this harness looks slow.

At n=50, switching off broadcast is the only large win. The GossipSub floor is still ~1.7–2.0 s on this machine — above the &lt;500 ms target, below Malachite’s published 780 ms / 100 / 1 MB only in the sense that we are not in that experiment.

At n=100, GossipSub and dummy do not recover. Same-machine 100 `EngineBuilder` processes is not a 100-validator latency measurement.

## Pass / fail

Isolate is a measurement, not a product pick. Fail conditions unchanged: Engine API is not the value; Arc is not the app; decide is not `π`. `seven_gossipsub_mesh_decides` and `four_stub_dummy_skips_f_and_decides` in `cargo test -p consensus-adapter`.

## What this does not license

- Calling n=20 ~250 ms “matching latency”
- Shipping GossipSub as the M4a default at n=4 (mesh D=6 still a bad fit)
- Dropping `F` from Validate as a performance fix (it was not the cost)
- Starting Reth to make n=100 faster
- Claiming we reproduced or beat ~780 ms / 100 / 1 MB
