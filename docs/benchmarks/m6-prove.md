# M6 proofs — tiny `F` + settlement inert

**Date:** 2026-09-30  
**Machine:** Apple M4 Pro, 14 cores  
**ADR:** [0011](../adr/0011-missing-pi-settlement-inert.md)

**`C'` version:** every Plonky3 `C'` cell below (node_digest, upsert openings, EngineInsert, EngineTape, HeightStatement, HeightMatch) is **`C'` v1 (BLAKE3)**, pinned via `btree_engine_v1`. Production `C'` is SHA-256 since ADR [0024](../adr/0024-sha256-c-prime.md); the general `C'` proof is the RISC Zero section near the end.

Same instance: maker 10, taker 7, price 90 → fill 7, notional 630. Native spec `crates/tiny-f`; zkVM guests use `zkvm/spec` (lockstep test in `tiny-f`). **Not** the CLOB, **not** height `π`, **not** a Groth16 wrap.

## M6b — missing `π` (policy)

`cargo test -p proof-adapter`

Decide does not move money until `Unlock::Proof` verifies or `Unlock::FullViewCertificate`. Invalid / missing witness → `eth_get_balance` unchanged. Malachite is not rolled back.

## M6a — tiny transition (all three stacks)

### Plonky3 (`p3-uni-stark` 0.6.3)

`cargo test -p proof-plonky3 --release`

AIR: 15-bit range checks, `fill ∈ {maker,taker}`, `notional = fill × price`.

| | prove | verify | size | notes |
|---|---|---|---|---|
| release | 1 ms | <1 ms | 2090 B | FRI **queries = 2** (p3 test config, not production soundness) |

### RISC Zero 3.0.6 (`disable-dev-mode`, `RISC0_DEV_MODE` unset/0)

`RISC0_DEV_MODE=0 cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml`

STARK receipt (not Groth16 wrap). 1 segment, 4706 user cycles / 32768 total.

| | prove | verify | size |
|---|---|---|---|
| release | **1646 ms** | **8 ms** | **209 610 B** |

### SP1 6.8.1 (`SP1_PROVER=cpu`, **core** proof)

`SP1_PROVER=cpu cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml`

Needs `protoc` (Homebrew `protobuf`). `tempfile` pinned to **3.21.0** (`TempDir::keep()`). Core proofs grow with cycles; this is **not** the ~260 B Groth16 wrap.

| | prove | verify | size |
|---|---|---|---|
| release | **9198 ms** | **64 ms** | **2 777 231 B** |

## Match-step (Plonky3 only, 2026-10-03)

One sell rest + one buy take, still 15-bit. Native spec [`tiny_f::match_step`](../../crates/tiny-f/src/match_step.rs) locksteps the CLOB (cross at maker price, remainder stays). AIR adds the cross bit and min/remainder. Same FRI-2 / RNG Poseidon2 as tiny-`F`.

`cargo test -p proof-plonky3 --release`

| run | prove | verify | size |
|---|---|---|---|
| 1 | **1 ms** | <1 ms | **2500 B** |
| 2 | **0 ms** | <1 ms | **2500 B** |

Cite FRI-2 **~0–1 ms / 2500 B**. Tiny-`F` stays 1 ms / 2090 B. The extra columns did not move this FRI. RISC Zero and SP1 were **not** re-run — they were already seconds on the smaller fragment.

This is still **not** `F` of an 8k book and **not** height `π`.

## Production-shaped FRI (2026-10-03)

`FriClass::Prod`: 100 queries, 16 PoW bits, `default_babybear_poseidon2_16()`. Same AIRs. Two independent `--release` runs. This is SP1 Turbo-**shaped**, not a security proof.

| cell | run | prove | verify | size |
|---|---|---|---|---|
| tiny-`F` prod | 1 | **59 ms** | 2 ms | 84 214 B |
| tiny-`F` prod | 2 | **47 ms** | 1 ms | 84 214 B |
| match-step prod | 1 | **105 ms** | 2 ms | 92 650 B |
| match-step prod | 2 | **86 ms** | 2 ms | 92 650 B |

Cite match-step prod **~86–105 ms / ~93 KB**. Tiny-`F` prod **~47–59 ms / ~84 KB**. FRI-2 ~0–1 ms was the test cell. Do not cite 1 ms as the Plonky3 grain.

## Book-step (two asks, 2026-10-03)

One buy take walks two sell rests (cheaper first / FIFO at a tie). Native [`tiny_f::book_step`](../../crates/tiny-f/src/book_step.rs) locksteps the CLOB. Still 15-bit. **Not** an 8k book, **not** `C'`.

`cargo test -p proof-plonky3 --release -- book`

| cell | run | prove | verify | size |
|---|---|---|---|---|
| FRI-2 | 1 | **1 ms** | <1 ms | 3441 B |
| FRI-2 | 2 | **0 ms** | <1 ms | 3441 B |
| prod | 1 | **95 ms** | 3 ms | 111 120 B |
| prod | 2 | **79 ms** | 3 ms | 111 120 B |

Cite book-step prod **~79–95 ms / ~111 KB**. Two levels did not move the prod grain vs one match-step. Do not cite this as `F` of the loaded book.

## Book-step zkVM (2026-10-03)

Same two-ask instance as the Plonky3 book-step cell. Guests run [`tiny_f_guest_logic::book_step`](../../zkvm/spec/src/lib.rs). Lockstep with native `tiny-f`. Two independent `--release` runs. **Not** Groth16. **Not** an 8k book.

`RISC0_DEV_MODE=0 cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml`

| run | prove | verify | size | user cycles |
|---|---|---|---|---|
| 1 | **1647 ms** | 8 ms | 209 674 B | 6500 |
| 2 | **1612 ms** | 8 ms | 209 674 B | 6500 |

`SP1_PROVER=cpu cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml`

| run | prove | verify | size |
|---|---|---|---|
| 1 | **9242 ms** | 65 ms | 2 777 775 B |
| 2 | **9314 ms** | 63 ms | 2 777 775 B |

Cite RISC Zero **~1.61–1.65 s / ~210 KB**. Cite SP1 core **~9.2–9.3 s / ~2.8 MB**. Tiny-`F` zkVM was 1.65 s / 9.2 s — two asks did not move the zkVM grain. Plonky3 prod on the same fragment is **~80–95 ms**.

## k-ask walk (row-per-level, 2026-10-03)

One take walks k unit asks (prices 80, 81, …). Native [`tiny_f::book_walk`](../../crates/tiny-f/src/book_walk.rs) locksteps the CLOB at k=8. AIR is one row per ask. Prod FRI. **Not** `C'`. **Not** mixed 10k `I`.

`cargo test -p proof-plonky3 --release -- prove_walk`

| k | FRI-2 | prod prove | prod size |
|---|---|---|---|
| 8 | 0–1 ms | **45–67 ms** | 116 KB |
| 32 | 0–2 ms | **32–51 ms** | 181 KB |
| 128 | — | **55–79 ms** | 263 KB |
| 512 | — | **82–102 ms** | 359 KB |
| 8192 | — | **270 / 272 ms** | 596 KB |

Cite 8k-ask walk **~270–272 ms / ~596 KB**. FRI dominates through hundreds of rows; 8k is the first clear step up. This is a price-time walk of unit qty, not `F` of the loaded 8k+10k cell (~85 ms native).

## `C'` multiplicity (not a BLAKE3 AIR, 2026-10-03)

`C'` is the BLAKE3 treap (ADR 0013). BabyBear has no BLAKE3 gadget. Poseidon2-16 in the FRI sponge is **not** `C'`. The in-circuit cost is the hash count.

`cargo test -p clob --test c_prime_path -- --nocapture`

| cell | prio | node | BLAKE3 |
|---|---|---|---|
| one-path map upsert at 8k | 1 | 19 | **20** |
| engine insert at 8k (nonce + seen + resting) | 3 | 69 | **72** |
| mixed rest at 8k | 3 / 2 | 42 / 40 | **45 / 42** |
| mixed take at 8k | 2 | 38 | **40** |
| mixed cancel at 8k | 0 | 14 / 13 | **14 / 13** |

Cite **20 BLAKE3s** for one resting-map upsert at 8k (same as [hash-vs-tree](hash-vs-tree.md)). Cite engine `C'` at 8k as **~13–72 BLAKE3s per event**, not 20. A 10k mixed tape is on the order of **~10⁵ hashes**, not one permutation. A Poseidon2-16 STARK of the **count** (20 compressions) is below. That is not a BLAKE3 gadget.

## Mixed-`I` (rest / take / cancel, 2026-10-03)

Eight slots, empty start, unit events in the loaded-tape ratio (½ rest, ¼ take, ¼ cancel). Native [`tiny_f::mixed_f`](../../crates/tiny-f/src/mixed.rs) locksteps the CLOB at k=8 and k=32. AIR is one row per event. Unique-price best rest. Accrued notional is 24-bit (15-bit overflows at a few hundred events). **Not** `C'`. **Not** the loaded 8k+10k cell.

`cargo test -p proof-plonky3 --release -- prove_mixed`

| k | FRI-2 | prod prove | prod size |
|---|---|---|---|
| 8 | 0 ms / 8474 B | **27 / 27 ms** | 154 KB |
| 32 | — | **64 / 64 ms** | 220 KB |
| 128 | — | **82 / 108 ms** | 300 KB |
| 512 | — | **86 / 87 ms** | 396 KB |
| 8192 | — | **426 / 437 ms** | 637 KB |

Cite mixed-`I` 8k-event **~426–437 ms / ~637 KB**. FRI dominates through 512 rows; 8k is the step up (ask-walk 8k was ~0.27 s; this row is wider). Do not cite this as `F` of the loaded 8k+10k cell (~85 ms native).

## 8k-book scan (packed prefix, 2026-10-03)

Eight *columns* cannot hold an 8k book. Slots are **rows**: occupied asks in a price-sorted prefix, empties in the suffix. One event is one scan (`tiny_f::scan_event`). A take hits the head and compact-shifts. A rest appends. A cancel compact-shifts. Lockstep with the CLOB at n=8. **Not** `C'`. **Not** one proof of a 10k tape.

`cargo test -p proof-plonky3 --release -- prove_scan_k8192`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| one take, n=8192 | **366 ms** | **343 ms** | 602 KB |
| 8 sequential events, n=8192 | **2109 ms** | **2125 ms** | 4.81 MB |

Cite one 8k-book take **~343–366 ms / ~602 KB** (ask-walk 8k was ~0.27 s; this row carries rest/cancel). Cite an 8-event tape **~2.11–2.13 s / ~4.8 MB** — **eight proofs**, not one STARK of the tape. Next-row STARKs cannot jump `n` rows, so a multi-event 8k book in **one** proof is a `C'` opening, not more columns.

## Poseidon2-16 path of 20 (not `C'`, 2026-10-04)

`C'` upsert multiplicity at 8k is **20 hashes**. This cell is that count in the official BabyBear Poseidon2-16 (round-per-row, `x⁷` via `x²,x⁴,x⁶,x⁷`, lockstep with `default_babybear_poseidon2_16()`). **Not** BLAKE3. **Not** `C'`. **Not** one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_path`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| n=1 FRI-2 | **2 ms** | — | 10 KB |
| n=1 prod | **61 ms** | — | 223 KB |
| n=20 FRI-2 | **9 ms** | — | 14 KB |
| n=20 prod | **119 / 105 ms** | **118 / 106 ms** | 396 KB |

Cite 20 Poseidon2 compressions **~105–119 ms / ~396 KB**. Native `C'` at the same multiplicity is **20 BLAKE3s / ~9 µs**. A 10k mixed tape is ~10⁵ engine hashes, not 20. Do not stand in this path and call it `C'`.

## Poseidon2-16 path of 72 (engine insert, not `C'`, 2026-10-04)

Engine insert at 8k is **72** BLAKE3s (3 prio + 69 node). Same AIR, same official perm, **not** `C'`.

`cargo test -p proof-plonky3 --release -- prove_path_n72`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| n=72 FRI-2 | **45 ms** | — | 16 KB |
| n=72 prod | **178 ms** | **178 ms** | 506 KB |

Cite 72 Poseidon2 compressions **~178 ms / ~506 KB**. That is ~1.5–1.7× the 20-hash grain, not 72/20. FRI still dominates. One engine insert’s *hash count* in Poseidon2 is sub-second; one 10k tape is still ~10⁵ hashes. Not `F` of the loaded cell. Not BLAKE3.

## BLAKE3 G (gadget start, 2026-10-05)

One portable `g` (add / xor / `rotate_right` 16,12,8,7) on 16-bit BabyBear limbs. Native `blake3_hash64` locksteps `blake3::hash` on a 64-byte root chunk. **Not** one compression (56 `g`). **Not** `node_digest`. **Not** `C'`. **Not** one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_g`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| FRI-2 | **2 ms** | — | 8 KB |
| prod | **100 ms** | **101 ms** | 233 KB |

Cite one BLAKE3 `g` **~100–101 ms / ~233 KB**. A compression is 56 of these mixers in **one** STARK, not 56 proofs. Do not cite this as `C'` or as a path of 20.

## BLAKE3 compression (56 `g`, 2026-10-05)

56 mixers plus 8 output xors in **one** STARK (64 rows). 64-byte root chunk. Native `blake3_hash64` locksteps `blake3::hash`. **Not** `node_digest`. **Not** a path of 20. **Not** one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_compress`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| FRI-2 | **12 ms** | — | 43 KB |
| prod | **162 ms** | **163 ms** | 614 KB |

Cite one BLAKE3 compression **~162–163 ms / ~614 KB**. That is ~1.6× one `g`, not 56×. FRI still dominates. One `C'` hash *atom* is sub-second; a tape is still many hashes.

## BLAKE3 path of 20 (upsert count, 2026-10-05)

20 compressions in **one** STARK. Each step is `blake3_hash64(digest || sibling)` (64-byte root chunk). Lockstep with `blake3::hash`. This is the **upsert hash count**, not `node_digest` (domain + key + value) and not one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_blake3_path`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| FRI-2 | **181 ms** | — | 53 KB |
| prod | **293 ms** | **293 ms** | 899 KB |

Cite 20 BLAKE3 compressions **~293 ms / ~899 KB**. That is ~1.8× one compression, not 20×. Native `C'` at this count is **20 BLAKE3s / ~9 µs**. Do not cite this as `node_digest` or the 8k-book tape.

## Resting `node_digest` (C' string, 2026-10-05)

One treap node as BLAKE3 actually hashes it (ADR 0013): `TREAP_NODE_DOMAIN` (17 B) || `ENCODING_VERSION` u16 (2 B) || left 32 || key-len 8 || OrderId 16 || value-len 8 || `RestingOrder::leaf_bytes` 101 || right 32 = **216 B**. Four 64-byte blocks, CV-chained; last `block_len=24`, flags `CHUNK_END|ROOT`. Empty children are `treap_empty_digest`. Native lockstep: `blake3::hash`, `treap_node_digest`, `HashedMap` leaf upsert. **Not** `hash64(digest||sibling)`. **Not** a path of 20. **Not** one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_node_digest`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| FRI-2 | **20 ms** | — | 49 KB |
| prod | **93 ms** | **92 ms** | 734 KB |

Cite one resting `node_digest` **~92–93 ms / ~734 KB**. Native that hash is microseconds. A resting-map upsert at 8k is **19** of these in one STARK (18 node + 1 prio), not one. (8-byte-key isolate was 19+1.)

## 19 upsert openings (18 resting + 1 prio, chrono, 2026-10-11)

The `HashedMap` rehashes for one insert at 8k with OrderId keys and `RestingOrder::leaf_bytes`. Native and in-circuit **19** BLAKE3s = **18** resting `node_digest` (216 B / 4-block) + **1** OrderId prio (33 B / 1-block), **chronological** via `start_c_prime_trace`. Packed 4672 active rows in 8192. **Same count as HeightMatch (19), different tape** (no `I` / INC / settlement / match-step). **Not** 20 dummy compressions. **Not** engine insert (72). **Not** `F`.

`cargo test -p proof-plonky3 --release -- prove_node_path`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| prod | **902 ms** | **904 ms** | 1 066 076 B |

Cite upsert path **~902–904 ms / ~1.07 MB** (chrono 18+1). Prior node‖prio was **~981 ms / ~1.09 MB**. Native that path is **~9 µs**. Do not confuse with HeightMatch 19.

## Book-step + 19 upsert openings (chrono, 2026-10-11)

Two-ask `book_step` columns copied onto the same 8192-row trace as the 19 chronological upsert openings. Stacked gadgets, **not** `F` of one Place (engine insert is 72 BLAKE3s). **Not** HeightMatch. **Not** one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_book_node_path`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| prod | **1120 ms** | **1122 ms** | 1 101 000 B |

Cite book-step + 19 upsert openings **~1.12 s / ~1.10 MB** (chrono). Openings alone were **~902–904 ms**; the walk added ~0.22 s on this FRI. Prior node‖prio stack was **~1.18–1.19 s / ~1.07 MB**.

## Engine Place C' openings (72 = 69 node + 3 prio, chrono, 2026-10-11)

One Place at 8k after `load_places` (owner 1) then Place owner 2: nonce + seen + resting + prio. Native and in-circuit hash count is **72** BLAKE3s = **69 `node_digest` + 3 prio** (1×49 B OwnerId + 2×33 B OrderId, 1-block), **chronological** via `start_c_prime_trace` (prio interleaved; starts with owner prio). Lengths: **33** seen (115 B / 2-block), **3** nonce (139 B / 3-block), **33** resting (216 B / 4-block), **1** prio-owner, **2** prio-order. Packed 13440 active rows in 16384. **Not** HeightMatch (19). **Not** `F`. **Not** 18 resting-only (upsert path is now 19). **Not** 72 Poseidon2 compressions. **Not** one proof of an 8k-book tape.

`cargo test -p proof-plonky3 --release -- prove_engine_insert`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| prod | **9677 ms** | **9400 ms** | 2 939 990 B |

Cite engine Place `C'` openings **~9.40–9.68 s / ~2.94 MB**, verify **~75 ms** (2026-10-14; chrono 72 = 69 node + 3 prio + insert key latches path 12+12 oid/own + twin + empty leaf children + nonce **3←2** left + every insert-path sibling edge: right←out(6/40/12/46/20/54/24/58), left←out(8/42/10/44/14/48/16/50/18/52/22/56/26/60)). Each sibling pair added ~0.3–0.8 s (sib-20/54 was ~7.26–7.37 s / ~2.36 MB; sib-22/56 ~8.08–8.18 s / ~2.67 MB). The insert path (seen 5..27, rest 39..61) is now fully linked; the upper chain to the map roots (seen 28..37, rest 62..71) is **not** bound, so this still does not prove the path reaches `post_root`. The circuit is fixed to this one fixture (`EI_HIDX_*` constants), not a general insert. Native that Place is **~9 µs**. **Not** HeightMatch / not `F`.

## Engine 8-event C' tape (281 = 269 node + 12 prio, chrono, 2026-10-11)

`churn_tape(8000, 8)` after `load_places`: four rests, two takes, two cancels. Native and in-circuit **281** BLAKE3s = **269 `node_digest` + 12 prio**, **chronological** via `start_c_prime_trace`. Lengths: **123** seen / **18** nonce / **128** resting + **10** OrderId prio (33 B) / **2** OwnerId prio (49 B). Packed 52736 active rows in 65536. Opening index, not 281 one-hot columns. **Not** one Place (72). **Not** HeightMatch (19). **Not** 8 sequential packed-prefix scans (~2.11–2.13 s, eight proofs, not `C'`). **Not** loaded 10k `F` (~85 ms native).

`cargo test -p proof-plonky3 --release -- prove_engine_tape`

| cell | run 1 | run 2 | size |
|---|---|---|---|
| prod | **6781 ms** | **6631 ms** | 1 295 538 B |

Cite eight mixed events’ `C'` openings **~6.63–6.78 s / ~1.30 MB** (chrono 281 = 269 node + 12 prio). Prior node‖prio was **~7.84–7.85 s / ~1.27 MB**. One Place (72) is **~9.40–9.68 s**. **Not** HeightMatch / not `F`.

## Loaded 10k `F` C' openings (native, 2026-10-05)

`load_places(8000)` then `churn_tape(8000, 10000)` — the loaded cell whose native engine `F` is **~85 ms**. Trace starts after load (no `set_treap_hash` rebuild). **375999** BLAKE3s = **12502 prio + 363497 `node_digest`**. Lengths: **160851** seen (115 B), **17504** nonce (139 B), **185142** resting (216 B). **1114782** blocks → **71346048** active rows, next power of two **2²⁷**. The 8-event tape was 281 openings / 65536 rows / **~6.63–6.78 s** (chrono). This is ~1350× openings and ~2¹¹× padded rows. A trace that size is hundreds of GB. **No STARK.** Not 8 mixed events. Not one Place. Not 20 / 72 Poseidon2. Not height `π`.

`cargo test -p proof-plonky3 --release -- engine_loaded_10k`

Cite loaded 10k `C'` as **~3.76×10⁵ BLAKE3s** (363497 openings). Native `F` is **~85 ms**. One proof at the 8-event FRI grain is **not this**.

## Compressed receipts (recursive STARK, 2026-10-05)

Same two-ask book-step guests as the zkVM cell. Recursive STARK aggregation, **not** Groth16/PLONK (Q-PRF-4). `p3-uni-stark` 0.6 has no wrap; the 8-event `C'` tape stays **~1.29 MB**.

`RISC0_DEV_MODE=0 PLX_RECEIPT=succinct cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml`

| run | prove | verify | size | kind |
|---|---|---|---|---|
| 1 | **7558 ms** | 9 ms | 223 338 B | succinct |
| 2 | **6966 ms** | 9 ms | 223 338 B | succinct |

Composite was **~1.61–1.65 s / ~210 KB** (1 segment). Succinct is **~7.0–7.6 s / ~223 KB** — recursion tax, not a shrink, on a one-segment guest.

`SP1_PROVER=cpu PLX_RECEIPT=compressed cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml`

| run | prove | verify | size | kind |
|---|---|---|---|---|
| 1 | **32910 ms** | 28 ms | 1 272 625 B | compressed |
| 2 | **32257 ms** | 28 ms | 1 272 625 B | compressed |

Core was **~9.2–9.3 s / ~2.78 MB**. Compressed is **~32.3–32.9 s / ~1.27 MB** — ~2.2× smaller, ~3.5× slower prove, faster verify (28 ms vs ~64 ms). Not the ~260 B Groth16 wrap. Not `C'`. Not loaded 10k `F`. Not height `π`.

## Light-client verifier object (2026-10-05)

`Plonky3TinyVerifier` implements `VerifyFragment` with `FriClass::Prod` (100 queries, 16 PoW, official Poseidon2-16). Light clients call `verify(statement, bytes)` on the **fill fragment**. It does **not** implement `VerifyPi`. Garbage / Groth16-shaped bytes / wrong statement / Test-FRI under Prod all reject. RISC Zero succinct and SP1 compressed receipts are **not** this object. Not height `π`. Not a stack pick.

`cargo test -p proof-adapter --release --test light_client -- --nocapture light_client_prod`

| run | prove | verify | size |
|---|---|---|---|
| 1 | 70 ms | **2 ms** | 84 214 B |
| 2 | 47 ms | **1 ms** | 84 214 B |

Cite light-client verify **~1–2 ms / 84 KB**. Prove is still the tiny-`F` prod cell (**~47–70 ms** here; **~47–59 ms** in the earlier prod table). Do not cite FRI-2. Do not cite RISC Zero 9 ms or SP1 compressed 28 ms as this object. Do not treat 2 ms as CLOB settlement.

## Height `π` statement (2026-10-05)

`HeightStatement` is `C' = Commit(F(Open(C), I))` bound to `ConsensusValue`: `pre_root` is the treap `C` before `F` (not a `Value` field); `post_root` is voted `state_root`. Native `check_height_statement` locksteps `propose` / `validate`. Wrong `C'` or wrong `I` fails. `SettlementGate` takes this statement; a mismatch is inert even with a full-view certificate. `Plonky3TinyVerifier` is `VerifyFragment` and cannot enter the gate. Two-place height `C'` is **5 prio + 9 `node_digest`** (chrono map **14**). A STARK of those map hashes alone (`HeightOpeningsVerifier`) is not `F`. Public DA is n=4 replication of the **178 B** blob (`PublicStatementStore`); withhold is unavailability; `public_statement_id` ≠ `id(v)`. `NoHeightStark` rejects unlabeled proofs. Not the fill fragment. Not the 8-event tape (281). Not loaded 10k `F` (363497). Not Groth16. Not `π` of `F`. 178 B is full-download, not sampled.

`cargo test -p consensus-adapter --lib -- port::tests`
`cargo test -p proof-adapter --test m6_inert`
`cargo test -p proof-adapter --test public_da`

## Public DAS at n≫4 (2026-10-05)

178 B `HeightStatement` is **full-download** (≤ 16×256 B). A future `π` at tiny-`F` prod size or 8-event tape size is **not**. `StripedNet` stripes 256-byte chunks across n replicas, commits a BLAKE3 chunk Merkle (not `node_digest`, not Poseidon2), and a light client fetches **16** openings. Not 2D RS. Not reconstruct-from-samples. Not KZG. Not a DA chain. A withheld replica is detected when a sample hits it; a hole outside the sample set is **not** detected.

`cargo test -p proof-adapter --test das -- --nocapture`

| public size class | full | sample (16) | chunks | n |
|---|---|---|---|---|
| `HeightStatement` | **178 B** | (download) | — | 4 |
| tiny-`F` prod | 84 214 B | **8704 B** | 329 | 100 |
| 8-event C' tape size | 1 291 000 B | **10 752 B** | 5043 | 100 |

Cite n≫4 sample **~8.7 KB vs 84 KB** and **~10.8 KB vs 1.29 MB**. Do not cite 178 B as sampled. Do not treat 16 hits as availability of the unsampled stripe. Do not call this `π`.

## 2D RS reconstruct (2026-10-05)

`Rs2d` places data in a `k×k` square of 256-byte cells, then GF(256) RS-extends each row and each column to `n=2k` (`reed-solomon-erasure`). Merkle is over the coded `n×n` grid. A missing row reconstructs from columns. An erasure square of side `k+1` does not. **16 samples do not reconstruct** (need `k` shares on a line). 178 B still full-downloads. Not KZG. Not Groth16. Not a DA chain. Not a soundness proof of 16 random hits.

`cargo test -p proof-adapter --test rs2d -- --nocapture`

| | k | n | orig | coded | 16-sample |
|---|---|---|---|---|---|
| tiny-`F` prod size | 19 | 38 | 84 214 B | **369 664 B** | **9728 B** |
| 8-event tape size class | 72 | 144 | 1 291 000 B | **5 308 416 B** | **11 776 B** |

Cite 2D RS reconstruct of a missing row at the 8k-byte fixture and at tape `k=72`. Cite tiny-`F` **~370 KB coded / ~9.7 KB sampled, not reconstructed**. Cite tape **~5.3 MB coded / ~11.8 KB sampled, not reconstructed** (encode ~2.5 s debug). Do not cite 16 samples as availability. Do not call this `π`.

## Height-statement C' hashes (2026-10-05)

The 2-place crossing height is **5 prio + 9 mixed `node_digest`**. Mix is **3 order prio (33 B) + 2 owner prio (49 B) + 4 seen (115 B) + 4 nonce (139 B) + 1 resting (216 B)**; active rows for the 14 map openings padded to **2048**. Last-block lens 33/49/51/11/24. Trace order is **chronological apply order** (prio interleaved with nodes; via `start_c_prime_trace`). Public inputs are the **last map digest** (chrono ends on seen root), not `post_root` (they differ). Not 69 Place-at-8k. Not 281 tape. Not 363497 loaded 10k. Not matching. Not `F`.

`HeightOpeningsVerifier` implements `VerifyPi` with `UNLOCKS_SETTLEMENT = false`. Envelope is `public_statement_id` || preimages || STARK. Wrong statement / tiny-`F` bytes / garbage reject. A valid proof **does not** unlock `SettlementGate`. Not Groth16. Not a light-client proof of `C' = F(C, I)` (preimages travel with the envelope; openings are not matching).

`cargo test -p proof-plonky3 --release --lib -- prove_height_openings --nocapture`
`cargo test -p proof-adapter --release --test height_pi -- --nocapture`

| run | prove | verify | size | FRI |
|---|---|---|---|---|
| FRI-2 | 222 ms | 1 ms | 57 174 B | 2 |
| prod 1 | **323 ms** | **18 ms** | **948 028 B** | 100 / 16 PoW |
| prod 2 | **326 ms** | **18 ms** | **948 028 B** | 100 / 16 PoW |
| verifier object prod | 315 ms | **18 ms** | 949 430 B | 100 / 16 PoW |

Cite prod **~323–326 ms / ~948 KB**. Object verify **~18 ms**. Do not cite FRI-2 222 ms as the Plonky3 grain. Do not call this `π` of `F`. Do not treat 18 ms as CLOB apply.

## Height hashes + match-step (2026-10-05)

The same 2-place crossing’s fill locksteps `MatchStepStatement` (10@90 rest, 10@100 take → fill 10@90, remainder 0, notional 900). `HeightMatchAir` copies that match-step across a **4096**-row trace (**2816** active). Openings are **14 chrono map (9 node + 5 prio interleaved) + `I` (233 B) + genesis INC (`C`, 244 B) + mid INC + settlement (277 B / 5-block, `q21`) + post INC (`C'`, 244 B, last)**. Tape `NODE_DIGEST_BLOCKS` stays 4; the 5th block is height-only (`COL_NB4`). Public inputs are the **last digest = `post_root`**. Genesis INC hashes to **`pre_root`**. Parent is **`GENESIS_PARENT`**. Rest qty/price equal the 216 B leaf (`q24`). Take qty/price equal the take Place in `I` (`q41`). First Place id/instrument/side (`from_u128(1)`, instrument 1, Sell) equal the 216 B leaf (bytes 47/63/67 vs 91/107/111). Take Place id/instrument (`from_u128(5)` / instrument 1) at bytes 148/164. First Place expiry/nonce (`Height(1000)`, nonce 1) equal the rest leaf (bytes 116/124 vs 160/168). Take Place expiry/nonce at bytes 217/225 (I ends at nonce). Rest `TimeSeq` is `TimeSeq(0)` at byte 176, not post `next_time` (`TimeSeq(1)`). Rest left (byte 19) and right (byte 184) children are `treap_empty_digest()`. Domain / version / key_len / OrderId key / value_len / `RESTING` tag are the 216 B header. Seen 115 B (`q51`) and nonce 139 B (`q11`) share `TREAP_NODE_DOMAIN` / version / lens; nonce value is 1. Five prio share `TREAP_PRIO_DOMAIN`. First key byte is 1 or 2 by `hidx`. `I` is `INPUT_DOMAIN` / version / payload_len 206 / count 2 / two `INPLACE`+`ORDER` tags. Both 244 B INC openings are `INC_DOMAIN` / version / `height`. Two 244 B last-lens (`q52p` post / `q52g` genesis). Nonce/seen map roots equal openings 9/13; resting map is empty. INC height = `Height(1)`; post `next_time` = `TimeSeq(1)` (one rest); instruments = genesis hash. Settlement 277 B hashes to **`settlement_commitment`**. Base amounts equal fill (10); quote amounts equal notional (900). Maker account (`from_byte(1)`) equals the 216 B leaf owner and the first Place in `I` (byte 84); taker (`from_byte(2)`) equals the take Place. First Place qty/price (bytes 68/76) equal match rest. Both 244 B INC openings are `INC_DOMAIN` (`plx/clob/inc/v1`, 15 B) / version / `height` under `q52`. Settlement is `RECEIPT_DOMAIN` (`plx/clob/receipt/v1`, 19 B) / version / payload_len 248 / count 4 / four `DELTA` tags under `q21`. Post INC map tags are `nonces` / `seenid` / `books` with Digest len 32 under `q52p`. Tree edges: nonce root (hidx 9) left = opening 8 `out`; seen rotate root (hidx 13) left = demoted opening 12 `out` (≡ opening 3); heap + BST order on both; demote pins `out(12)=out(3)` / `out(1)=out(8)`; left-overwrite `7→9` / `11→13` by header composition. Assets are base/quote `1`/`2`. Not 69/269/363497. Not `F`. Prior cell (seen/nonce empty children; sibling `out` children) ~731–735 ms / 1.24 MB.

`HeightMatchVerifier` implements `VerifyPi` with `UNLOCKS_SETTLEMENT = false`. Envelope is `public_statement_id` || preimages || match-step || STARK. Last preimage hashes to `statement.post_root`; the other 244 B hashes to `statement.pre_root`; the 233 B preimage hashes to `statement.input_commitment`; the 277 B preimage hashes to `statement.settlement_commitment`; INC height bytes equal `statement.height`; `statement.parent` is `GENESIS_PARENT`. Wrong rest / take / height / parent / pre_root / settlement / tiny-`F` / garbage reject. A valid proof **does not** unlock `SettlementGate`. Not Groth16.

`cargo test -p proof-plonky3 --release --lib -- prove_height_match --nocapture`
`cargo test -p proof-adapter --release --test height_match -- --nocapture`

| run | prove | verify | size | FRI |
|---|---|---|---|---|
| FRI-2 | 1125 ms | 2 ms | 112 114 B | 2 |
| prod 1 | **1205 ms** | **39 ms** | **1 592 825 B** | 100 / 16 PoW |
| prod 2 | **1204 ms** | **39 ms** | **1 592 825 B** | 100 / 16 PoW |

Cite prod **~1.20–1.21 s / ~1.59 MB** (chrono map + Place1/2 insert key latches + resting prio/owner; prior Place1/2 ~1.16–1.17 s). Constructive: match-step treap hashes **0**; rotate crossing (take `OrderId` 5) apply is **5 prio + 9 node** (~500 µs native); HeightMatch openings **19** = 14 chrono map + I/genesis/mid/settlement/post. Fill lockstep ≠ apply proven. **19 ≠ 72 / 281 / 363497**. [`ApplyWitness`](../../crates/proof-adapter/src/apply_witness.rs) names that FULL_VIEW tape and checks it natively (`check_apply_witness`); wrong `I` / post / opening / match-step / mid INC / treap edge / insert key reject. Mid-apply: books = 216 B resting leaf; mid INC opening **16** (`q52m`). AIR binds seen rotate edge `13←12` (demoted left), demote pins `out(12)=out(3)` / `out(1)=out(8)`, nonce `9←8`, heap+BST; left-overwrite `11→13`/`7→9` by composition; insert latches Place1/2 order prios → seen/rest/`I` ids, owner prios → nonce/`I` owners, resting order prio (hidx 4) → sell id, rest leaf owner → sell owner; unique keys seen/order ∈ {1,5}. Not full rotate/insert algebra and not `F`. [`height_match_pi_from_apply`](../../crates/proof-adapter/src/height_match.rs) feeds that tape into `HeightMatchVerifier`. Still not `π` of `F`, still `UNLOCKS_SETTLEMENT = false`. Do not cite FRI-2 1125 ms as the Plonky3 grain. Do not call the bound HeightMatch STARK `F` of the height. Do not treat 36 ms as CLOB apply.

## Sample-soundness of 16 public hits (2026-10-05)

`sample_indices` is BLAKE3 of `blob_root`. The encoder knows the 16 cells before dispersal. Keeping only those cells, a light client **accepts** and 2D RS **does not reconstruct**. That is a constructive counterexample, not a probability. 178 B still full-downloads.

On this tiny-`F` grid (`k=19 n=38`, 1444 cells) the same 16 hits pierce every `(k+1)×(k+1)` square (0 avoiding placements). Complements still fool. `(k+1)` exceeds half of `n=2k`, so a square-hide is the wrong attack to lean on.

Integer hypergeometric (no floats), unique samples:

| withhold | present / total | 16-sample undetected | `≤ 2^{-40}` min unique | reconstruct |
|---|---|---|---|---|
| missing row | 1406 / 1444 | 3034010954072035750414443492995 / 4659181932328512286034416989074 | **739** (16 not even `≤ 1/2`) | **yes** |
| `(k+1)` square | 1044 / 1444 | 2472516097901315893362982862711 / 458092576977581008938548940275266 | **83** | no |
| 1-of-100 replica | 1429 / 1444 | 489224122567084590178301399012555 / 578693871229569851039861887315434 | **1211** (16 not even `≤ 1/2`) | (striping) |

`2^{-40}` is withhold-specific: **83** vs the square, **739** vs a missing row, **1211** vs 1-of-100 replica (integer limbs). 16 is none of those. 739 is not reconstructability (that withhold already reconstructs). Keeping the **83** public FS cells: light client **accepts**, reconstruct **fails**, fetched **50 464 B**. Do not cite ~86 from a float. Not KZG. Not `π`.

Tape size class (`k=72 n=144`, 20 736 cells, coded 5 308 416 B): encode measured; missing row reconstructs; 16-sample **11 776 B** does not reconstruct. `2^{-40}` is **94** vs `(k+1)` square, **3620** vs a missing row, **2575** vs 1-of-100 replica. Keeping those **94** public FS cells: light accepts, reconstruct fails, fetched **69 184 B**. Public FS reconstruct of this tape is **8621 cells / 6 345 056 B** (8620 do not); hidden coins `[1; 32]` reconstruct at **8421 / 6 197 856 B** (8420 do not). Both fetches **exceed** the coded grid (**5 308 416 B**). Recovery API `recover_public_payload` / `recover_hidden_payload` returns the payload on that path: tiny-`F` → **PublicSample 512 / 311 296 B** or **HiddenSample 495 / 300 960 B**; tape → **CodedGrid 5 308 416 B** (missing row still reconstructs). Uncoded orig (**84 214 B** / **1 291 000 B**) beats both when offered. Light 16 stays detection-only. 16 / 94 are none of those. Not `2^{-40}`. Not `π`.

`cargo test -p proof-adapter --test sample_soundness -- --nocapture`

## Hidden sample coins (2026-10-05)

`sample_indices_hidden(coins, root, n, 16)` mixes client-local 32-byte coins with the blob root under `plx/da/sample/hidden/v1`. The encoder who knows only `root` cannot precompute the set. Tests use a fixed coin `[1; 32]` (no OS RNG in protocol).

On the tiny-`F` 2D RS grid, public Fiat–Shamir is `[715, 285, …]`; hidden is `[101, 73, …]` — not the same set. Complement withhold of the public 16: public `light_sample` accepts; `light_sample_hidden` returns `MissingChunk`. Complement of the **hidden** 16: hidden sample accepts; reconstruct still fails. Fetched size is still **9728 B**. For coins `[1; 32]`, the smallest hidden-sample set that reconstructs this grid is **495 cells / 300 960 B** (16 still do not; 494 do not). Public Fiat–Shamir reconstruct of the same grid is **512 / 311 296 B** (511 do not). 178 B full-downloads. Coins that leak become public FS. 495 and 512 reconstruct this instance and are not `2^{-40}` (83 / 739 / 1211 are the other counts). Not KZG. Not `π`.

`cargo test -p proof-adapter --test hidden_coins -- --nocapture`

## General `C'` update on RISC Zero (any op tape, 2026-10-15)

ADR [0022](../adr/0022-treap-step-witness.md) / [0023](../adr/0023-general-c-prime-on-zkvm.md). The guest runs `IncTape::verify` (the `commitments` crate, unchanged) on a tape recorded from the engine (`clob::start_inc_step_trace`). It commits `pre_root ‖ post_root ‖ ops ‖ steps`. A height is chunk receipts plus a join guest that verifies them recursively and chains their roots. **CPU prover** (Metal needs full Xcode). 8k book. The journal pre/post roots equal the engine's `C` / `C'`.

`RISC0_DEV_MODE=0 PLX_TAPE=place cargo run --release -p host --bin tape --manifest-path zkvm/risc0/Cargo.toml`
`RISC0_DEV_MODE=0 PLX_TAMPER=1 PLX_CHUNKS=3 PLX_CHUNK_EVENTS=1 cargo run --release -p host --bin height --manifest-path zkvm/risc0/Cargo.toml`

| cell | steps | cycles | prove | size | verify |
|---|---|---|---|---|---|
| one Place, composite | 3 | 0.76 M (1 seg) | **59 903 ms** | 281 634 B | 12 ms |
| one Place, succinct | 3 | 0.76 M (1 seg) | **61 816 ms** | 223 426 B | 9 ms |
| 3 chunks × 4 events + join | 33 | 7.86 M + 0.13 M | 155 567 / 157 817 / 202 787 + **29 856 ms** | **223 514 B** | 10 ms |
| 3 chunks × 1 event + join | 9 | 3.15 M + 0.13 M | 60 674 / 59 192 / 59 289 + **27 575 ms** | **223 514 B** | 9 ms |

With the real chunk receipts attached, the join fails on swapped and dropped chunks (root chain) and on a forged journal (no receipt resolves it). Execute-only: 8 events 4.2 M cycles; 64 events 34.8 M cycles (4 148 node + 305 prio hashes, ~8.4 k cycles per node hash). Loaded 10k height: 27 500 steps, 674 389 node + 43 092 prio hashes, 50 MB witness → **~5.7×10⁹ cycles ≈ 93 CPU-hours (projection)**. Guest hash cycles, BLAKE3 vs accelerated SHA-256: 33 B 2 072 / 404; 115 B 3 678 / 536; 139 B 5 229 / 586; 216 B 6 815 / 658. Those cells are `C'` v1 (BLAKE3). **SHA-256 `C'` (production since ADR [0024](../adr/0024-sha256-c-prime.md)):** one Place **254K cycles**, succinct proof **~32 s** (31 593 ms, 223 426 B, 9 ms verify); 64 events **13.4M cycles** (15 segments); loaded 10k **~36 CPU-hours** (projection). Cite general `C'` per Place **~32 s CPU** (SHA-256) and join **~28–30 s / 224 KB / ~10 ms verify**. **Not** `F`: the ops are committed, not derived from `I`.

## `π` of `F` on RISC Zero (the matcher, 2026-10-15)

ADR [0025](../adr/0025-pi-of-f-on-zkvm.md). The guest decodes a canonical `EngineSnapshot`, rebuilds the engine (linear-time `C`), runs `clob::Engine` on `I`, and commits `mode ‖ pre_root ‖ post_root ‖ input_commitment ‖ settlement_commitment`. The host asserts the journal equals the natively computed statement fields. SHA-256 `C'`, **CPU prover**.

`RISC0_DEV_MODE=0 PLX_F_REST=1000 PLX_F_EVENTS=8 PLX_RECEIPT=succinct cargo run --release -p host --bin f --manifest-path zkvm/risc0/Cargo.toml`

| cell | cycles | segments | prove | size | verify |
|---|---|---|---|---|---|
| crossing (empty book, 2 Places) | 0.26 M | 1 | **18 998 ms** | 223 484 B | 9 ms |
| 200 resting + 32 events | 7.6 M | 8 | **496 005 ms** | 223 484 B | 9 ms |
| 1 000 resting + 8 events | 21.0 M | 20 | **1 311 183 ms** | 223 484 B | 10 ms |
| 8 000 resting + 0 / 8 / 64 / 512 events (execute) | 136.1 / 137.3 / 145.0 / 205.1 M | 162–247 | — | — | — |

Before the linear-time rebuild, 8 000 resting + 0 events was 918.7 M cycles. Cite `π` of `F` **~135 K cycles per event + ~8.5 K per committed entry**; loaded 10k at 8k **~24–26 CPU-hours (projection)**. `SettlementGate<Risc0FVerifier>` settles the crossing height with the real receipt (`cargo test -p proof-adapter --features risc0 --test risc0_gate`); another height's statement, a wrong image ID and flipped bytes stay inert. This **is** `π` of `F` for the prototype engine. It is not fast, not Groth16, and not DA.

**Re-measure with derived order ids (ADR [0026](../adr/0026-derived-order-ids.md), 2026-10-16):** 8 000 resting + 0 / 64 / 512 events = **106.1 / 111.9 / 154.1 M** cycles (137–197 segments); 1 000 + 0 = 12.9 M. Snapshot 808 KB (was 936 KB). Cite **~94 K cycles per event** plus the rebuild; no seen-set growth. The crossing fixture was regenerated (17.6 s, 223 484 B); the gate requires flag byte `0b11`.

**After guest trimming (2026-10-17, ADR 0025):** 8 000 resting + 0 / 64 / 512 events = **58.6 / 62.1 / 87.6 M** cycles (77–113 segments); 1 000 + 0 = 7.3 M. Real succinct proof of 1 000 resting + 8 events: **620 441 ms**, 10 segments, 223 484 B, 10 ms verify (was 1 311 183 ms / 20 segments). Cite **~57 K cycles per event** plus the rebuild.

## `π` of `F` on SP1 vs RISC Zero (2026-10-22)

ADR [0029](../adr/0029-prover-stack-risc-zero.md). SP1 guest `zkvm/sp1/f-program` (same `clob::run_f`, SP1-patched `sha2`); public values equal the native claim on every run.

`SP1_PROVER=cpu SHARD_SIZE=1048576 ELEMENT_THRESHOLD=67108864 MEMORY_LIMIT=12884901888 PLX_RECEIPT=compressed PLX_F_REST=1000 PLX_F_EVENTS=8 cargo run --release -p tiny-f-script --bin f --manifest-path zkvm/sp1/Cargo.toml`

| cell | RISC Zero 3.0.6 succinct | SP1 6.8.1 compressed |
|---|---|---|
| 1 000 + 8 events | 620 441 ms, 223 484 B, 10 ms verify | **463 304 ms**, 1 272 698 B, 30 ms verify |
| 100 + 8 events | 95 121–97 236 ms, 223 484 B, 9 ms | 91 666 ms, 1 272 698 B, 28 ms |
| SP1 core, 1 000 + 8 | — | 210 332 ms, 37 910 368 B |
| execute, 8 000 + 0 / + 512 | 58.6 / 87.6 M cycles | 218.4 / 392.9 M instructions |

With default settings SP1 was killed by the OS on this 24 GB host (peak RSS ~10 GB before the kill); the shard settings above fix it. Peak RSS: RISC Zero ~7.4 GB (100 + 8); SP1 ~9.8 GB (100 + 8, core), ~11 GB (1 000 + 8). Pipeline default stays RISC Zero.

## How to read this

Sizes are decimal (1 MB = 10⁶ B); cite lines before 2026-10-14 sometimes used MiB.

- **Stacks.** zkVM prove on tiny-`F` and two asks is seconds (RISC Zero ~1.6 s, SP1 ~9.3 s); Plonky3 on two asks is ~80–95 ms. Recursion on that book-step: RISC Zero succinct ~7.0–7.6 s / ~223 KB (no shrink on one segment), SP1 compressed ~32.3–32.9 s / ~1.27 MB. `p3-uni-stark` 0.6 does not wrap. Groth16 is not measured. No stack is picked.
- **Toward `C'` on Plonky3.** One resting `node_digest` ~92–93 ms; one upsert path (19 openings) ~902–904 ms; one engine Place (72 openings, insert path edges bound) ~9.40–9.68 s / ~2.94 MB; eight mixed events (281 openings, hashes only) ~6.63–6.78 s. Loaded 10k `F` is 363 497 openings and ~85 ms native — not one STARK at this FRI.
- **Height.** `HeightStatement` is the public instance (native `C'` of `F`; 2-place height 5 prio + 9 node). `HeightMatchVerifier` proves 14 chrono map hashes + `I` + genesis/mid INC + settlement + post INC stacked with match-step: ~1.20–1.21 s / ~1.59 MB, verify ~39 ms. What it binds is listed under [Height hashes + match-step](#height-hashes--match-step-2026-10-05). The fill-fragment light-client object is `Plonky3TinyVerifier`, ~1–2 ms / 84 KB.
- **Public DA.** 178 B full-download at n=4. n≫4 sampling ~8.7 KB vs 84 KB, ~10.8 KB vs 1.29 MB. 2D RS reconstructs a missing row but not from 16 samples; public sample indices let an encoder withhold the complement; hidden coins catch that but still do not reconstruct at 16. `2^{-40}` counts (83 / 739 / 1211; tape 94 / 3620 / 2575) are not reconstruct counts, and reconstruct counts (495 / 512) are not `2^{-40}`.
- **Not.** None of this is `π` of `F`. Match-step is not the CLOB apply. 19 ≠ 72 ≠ 281 ≠ 363 497. `HeightMatch` and EngineInsert are each fixed to one fixture. Settlement stays inert (`UNLOCKS_SETTLEMENT = false`); `NoHeightStark` rejects unlabeled proofs.

## Plonky3 defensibility (not a production `π`)

The **crate** is the one Polygon shipped and SP1 uses (BabyBear, Poseidon2 width 16, FRI). Two configs now exist.

| Piece | `FriClass::Test` | `FriClass::Prod` |
|---|---|---|
| Field | BabyBear | BabyBear |
| Sponge | Poseidon2 width 16 | Poseidon2 width 16 |
| Round constants | RNG seed 1 | `default_babybear_poseidon2_16()` |
| FRI queries | **2** | **100** |
| FRI PoW | 1 / 1 bits | **16 / 16** |
| AIR | fill / rest+take / two asks / k-ask walk / mixed-`I` / 8k-book scan / Poseidon2-16 path / BLAKE3 `g` / compress / path of 20 / resting `node_digest` / 19 upsert openings / openings+book-step / engine Place 72 openings / 8-event C' tape / 14 HeightStatement C' hashes / those hashes + `I` + genesis `C` + settlement + post `C'` + match-step | same |

Defensible: we measured both cells. Not defensible: “100 queries is a security proof,” or that this is height `π`.

## Pass / fail

| Claim | Status |
|---|---|
| We know what happens when proving fails | **M6b:** settlement inert |
| Decide is not world-computer validity | Restated |
| Two proving stacks on the same `F` | **Closed:** all three ran |
| One rest + one take is still milliseconds on FRI-2 | **Yes** (~0–1 ms / 2500 B) |
| That holds at 100 queries / official Poseidon2 | **No.** Match-step **~86–105 ms / ~93 KB** |
| Two asks walk at the same prod grain | **Yes** (~79–95 ms / ~111 KB) |
| zkVM on two asks is still seconds | **Yes** (RISC Zero ~1.6 s; SP1 ~9.3 s) |
| 8k-ask walk is still sub-second on this FRI | **Yes** (~270–272 ms / ~596 KB) |
| Mixed-`I` through 512 events is still the small-walk grain | **Yes** (~27–108 ms) |
| 8k mixed events stay sub-second on this FRI | **Yes** (~426–437 ms / ~637 KB) |
| One event on an 8k packed book is still the 8k-walk grain | **Yes** (~343–366 ms / ~602 KB) |
| Eight packed-prefix events on that book in one proof | **No.** Eight scans **~2.11–2.13 s / ~4.8 MB** |
| Engine `C'` is one hash | **No.** 20 / upsert; **~13–72** / event at 8k |
| 20 Poseidon2 compressions (`C'` count, not `C'`) | **Yes** (~105–119 ms / ~396 KB) |
| 72 Poseidon2 compressions (engine insert, not `C'`) | **Yes** (~178 ms / ~506 KB) |
| One BLAKE3 `g` (mixer) | **Yes** (~100–101 ms / ~233 KB) |
| One BLAKE3 compression (56 `g`s) | **Yes** (~162–163 ms / ~614 KB) |
| 20 BLAKE3 compressions (upsert count) | **Yes** (~293 ms / ~899 KB) |
| One resting `node_digest` (4-block `C'` string) | **Yes** (~92–93 ms / ~734 KB) |
| 19 upsert openings (18 resting + 1 prio, chrono) | **Yes** (~902–904 ms / ~1.07 MB); count=HeightMatch 19, different tape |
| That path plus a two-ask book-step | **Yes** (~1.12 s / ~1.10 MB) |
| Engine Place 72 mixed `C'` openings (69 node + 3 prio, chrono) | **Yes** (~9.40–9.68 s / ~2.94 MB); insert keys + empty leaves + nonce 3←2 + all 24 insert-path sibling edges (upper chain to roots unbound) |
| Eight mixed events’ 281 `C'` openings in one proof (269 node + 12 prio, chrono) | **Yes** (~6.63–6.78 s / ~1.30 MB) |
| One STARK of loaded 10k `F` `C'` openings | **No.** 363497 openings / 71M rows (~2²⁷ padded); native `F` ~85 ms |
| RISC Zero succinct shrinks 1-segment book-step | **No.** ~7.0–7.6 s / ~223 KB vs composite ~1.6 s / ~210 KB |
| SP1 compressed shrinks core | **Yes** (~1.27 MB vs ~2.78 MB; prove ~32 s vs ~9.3 s) |
| Groth16 / PLONK wrap | **Not this cell** |
| Light-client object (Plonky3 fragment verify) | **Yes** (~1–2 ms / 84 KB); not CLOB apply |
| Height `π` statement (`C'` of `F`) | **Named** (`HeightStatement`, native check); rotate 2-place **5 prio + 9 openings** |
| STARK of those 14 C' map hashes | **Yes** (~323–326 ms / ~948 KB); not `F`; not matching; `UNLOCKS_SETTLEMENT = false` |
| Those hashes + `I` + genesis `C` + settlement + post `C'` + this height's match-step | **Yes** (~1.20–1.21 s / ~1.59 MB); chrono map; Place1/2 insert key latches + resting prio/owner; last digest = `post_root`; genesis INC = `pre_root`; parent = `GENESIS_PARENT`; settlement hash = `settlement_commitment`; fill/notional = receipt amounts; maker = rest + first Place; taker = take Place; first Place qty/price = match rest; first Place id/instrument/side = rest leaf; take Place id/instrument = `from_u128(5)` / 1; first Place expiry/nonce = rest leaf; take Place expiry/nonce = same constants; rest `TimeSeq` = 0, not post `next_time`; rest empty children = `treap_empty_digest()`; rest `node_digest` header bound; seen/nonce/prio headers bound; unique keys by `hidx`; `I` header bound; `INC_DOMAIN` bound; `RECEIPT_DOMAIN` bound; INC map tags bound; seen/nonce empty children bound; sibling `out` children bound (9←8/1 and 13←12/3 among chrono map); prio heap + BST on chrono edges `9←8` / `13←12`; rotate demote AIR-bound; not `F`; `UNLOCKS_SETTLEMENT = false` |
| HeightMatch STARK is CLOB apply | **No.** Match-step treap hashes **0**; apply is **5 prio + 9 node** (~500 µs native); STARK openings **19** = 14 chrono map + I/genesis/mid/settlement/post; **19 ≠ 72 / 281 / 363497**; mid-books + mid INC AIR; post books empty (AIR); rotate 13←12 + demote pins 12≡3/8≡1 + left-overwrite + heap+BST + Place1/2 insert key latches + resting prio/owner (ApplyWitness too) |
| Public DA of that statement | **Yes** (178 B full-download at n=4) |
| n≫4 chunk-Merkle sample | **Yes** (~8.7 KB vs 84 KB; ~10.8 KB vs 1.29 MB); uncoded stripe is not reconstructable |
| 2D RS reconstruct | **Yes** (missing row); 16 samples **do not** (k=19, 9728 B vs 370 KB coded) |
| 16 public hits are sample-soundness | **No.** Encoder-known indices; complement withhold accepts, reconstruct fails |
| Hidden coins catch that public complement | **Yes** (`MissingChunk`); 16 hidden hits still do not reconstruct |
| `2^{-40}` unique samples vs `(k+1)` square | **83** (integer limbs; not 16; not reconstruct) |
| 83 public FS hits reconstruct tiny-`F` | **No** (accepts; fetched **50 464 B**) |
| `2^{-40}` unique samples vs missing row | **739** (withhold still reconstructs) |
| `2^{-40}` unique samples vs 1-of-100 replica | **1211** |
| Tape `k=72` encode / 16-sample | **Yes** (~5.3 MB coded / **11 776 B** sample; missing row reconstructs; 16 do not) |
| Tape `k=72` `2^{-40}` (square / row / 1-of-100) | **94 / 3620 / 2575** (integer; not 16) |
| 94 public FS hits reconstruct tape `k=72` | **No** (accepts; fetched **69 184 B**) |
| Public FS samples that reconstruct tape `k=72` | **8621 / 6 345 056 B** (> coded 5 308 416 B; not `2^{-40}`; not 94) |
| Hidden samples that reconstruct tape `k=72` | **8421 / 6 197 856 B** (coins `[1; 32]`; > coded; not `2^{-40}`; not 8621) |
| Recovery `cheaper_public_recovery` | tiny-`F` **PublicSample 512 / 311 296 B**; tape **CodedGrid 5 308 416 B** |
| Recovery `cheaper_hidden_recovery` | tiny-`F` **HiddenSample 495 / 300 960 B**; tape **CodedGrid 5 308 416 B** |
| Uncoded orig beats public recovery | **Yes** (84 214 B / 1 291 000 B) when offered; light 16 detection-only |
| `recover_public_payload` returns bytes | **Yes** (tiny-`F` PublicSample 512; tape CodedGrid; hidden tiny-`F` 495) |
| Hidden samples that reconstruct this tiny-`F` grid | **495 / 300 960 B** (coins `[1; 32]`; not `2^{-40}`; not `π`) |
| Public FS samples that reconstruct this tiny-`F` grid | **512 / 311 296 B** (not `2^{-40}`; not 83) |
| Plonky3 wrap of the `C'` tape | **No** (`p3-uni-stark` 0.6) |
| Packed-prefix 8-scan as one STARK | **No** |
| That is height `π` / a security proof | **No** |
| “The prover will just work” | Not claimed |
