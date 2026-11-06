# Batch size vs decided throughput (2026-10-26)

**Host:** Apple M4 Pro, 14 cores, 24 GB. All 4 validators run on this one machine.  
**Setup:** n=4, TCP, 8k resting orders preloaded; tiered finality k=1 and secured gossip in the gossip runs.  
**Question:** the engine matches ~1.5 M events/s on one core. Do bigger heights bring decided throughput closer to that?

**Answer: no, not on one machine.** Throughput plateaus around 60–100 k events/s unsigned. Bigger heights raise latency, not throughput. Matching is not the limit; per-input bookkeeping, repeated replays and four validators sharing 14 cores are.

## Injected `I` (consensus + execution, no gossip)

`PLX_M4_LOADED=1 PLX_M4_I=<n>`, one height, node p50:

| Orders per height | p50 | Events / s |
|---|---|---|
| 10 000 | 125 ms | ~80 k |
| 50 000 | 484 ms | ~103 k |
| 100 000 | 994 ms | ~101 k |

Isolate at 100k (`PLX_M4_ISOLATE=1`), node p50:

| Cell | p50 |
|---|---|
| F + WAL | 882 ms |
| F + no fsync | 780 ms |
| matching stubbed (`stub+nowal`) | 483 ms |

The stubbed cell, with no `F` and no apply, still takes ~0.5 s: the cost is outside the matcher.

## Per input, one replica, one thread

`cargo test -p consensus-adapter --release --test batch_cost -- --ignored --nocapture`:

| Step | 10k | 100k |
|---|---|---|
| Intent log intake (`offer`: id hash + three B-tree maps) | 0.88 µs | 1.69 µs |
| Seal (`tape`: id hash + sort) | 0.78 µs | 0.77 µs |
| `commit_list` (BLAKE3) | 0.05 µs | 0.06 µs |
| Canonical encode (91 B per input) | 0.17 µs | 0.14 µs |
| `F` + root (scratch, no per-receipt roots) | 7.4 µs* | 1.2 µs |

\* First run in the process (cold allocator); the clob bench measures ~0.65 µs.

That is about **4 µs per input per replica** before consensus messaging, WAL and gossip. Every validator pays it, plus replays (propose, speculate / validate, decide), and here four validators share the cores. Intake bookkeeping alone costs more than matching.

## Gossip (`PLX_M4_LOADED=1 PLX_M4_GOSSIP=1 PLX_M4_TIERED=1 PLX_M4_HEIGHTS=3`)

"Last" decide-to-decide per loaded height:

| Orders per height | Unsigned | Classical-signed (`PLX_M4_SIGNED=classical`) | Hybrid-signed |
|---|---|---|---|
| 1 000 | 72 ms (~14 k/s) | — | 83 ms (~12 k/s) |
| 10 000 | 108 ms (~93 k/s) | 153–313 ms (~32–65 k/s) | splits across heights |
| 50 000 | 780–925 ms (~54–64 k/s) | breaks: 6 s ACK waits, waves split | — |
| 100 000 | 1.0–2.5 s (~40–98 k/s) | — | — |

- A classical-signed intent adds 116 B on the wire (key + signature); the client signs in ~8 µs.
- At 50k and above, the last loaded height of each run sealed a partial set. The 180 ms admission grace (ADR 0020 / 0021) was tuned for ~10k unsigned waves.

## What it means

- **One host is the ceiling here, not the protocol.** Separate validator machines would each spend ~4 µs CPU per input, about 250 k inputs/s per core-thread before parallelizing intake. Not measured.
- **Engineering targets**, in order:
  1. Intake bookkeeping: hash each intent once, fewer maps, a bounded `consumed` set.
  2. Fewer `F` replays per height.
  3. Admission timing that scales with wave size.
  4. Parallel verification already exists for signed intents.
- **The bandwidth caps still hold** (1 Gbit/s per validator): ~1 M/s unsigned, ~700 k/s classical-signed, ~20–40 k/s hybrid-signed.
- A fair public figure stays "~12 k hybrid-signed (or ~30–60 k classical-signed) orders per second decided, 4 validators on one host".
