# ADR 0012 — Height-batch replica WAL (Q-STO-3)

**Status:** Accepted as the **consensus apply-path research default**. M2 crash tests stay `SyncMode::Full`.  
**Date:** 2026-10-01  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0007](0007-encrypted-wal.md) durability default **only** for Malachite decide / loaded apply. Does not rewrite M2.

## Context

ADR 0007 fsyncs every replica WAL record. M2 needs that to test “crash during `F` still replays.” Measured ([`q-sto-3-wal.md`](../benchmarks/q-sto-3-wal.md)): that path is **~270 ev/s**. A 10k-event height is **~35 s** of `sync_all`. Incremental `F` of the same tape is **~250 ms**. Per-input fsync is the TPS killer, not matching.

Group commit (one durability barrier per height) is **~32–36k ev/s** at `|I|=10k` on the same host. Crash *during* the tape can lose Relaxed records; those orders were not decided.

## Decision

### `SyncMode::Height`

Append **flushes** (same as `Relaxed`). The replica calls **`sync_all` once** after the height’s `I` is fully appended and **before** `apply` of that tape.

```text
encode I as one PLXTAPE blob → encrypt → append (flush)
sync_all once
install scratch / apply F
```

`SyncMode::Full`: unchanged (append + `sync_all` + apply per input). **M2 tests use Full.**  
`SyncMode::Relaxed`: flush only; benches / isolate `nosync`.  
**Malachite `ClusterSpec` / `start_four` default: `Height`.**

### Crash

- Truncated append before `sync_all`: incomplete height, not decided. Same as a lost mempool.
- After `sync_all`, crash during `F`: open replays the tape. Same as 0007, at height grain.
- Do not ack clients until decide (BFT) or until `sync_all` if running replica-only.

### Not in this ADR (see 0014)

Replica quorum instead of local fsync. Changing the file magic. **Done in [0014](0014-height-blob-wal.md):** one WAL blob per Height tape.

## Alternatives

| Option | Why not as default |
|---|---|
| Keep Full on the consensus path | ~270 ev/s; 300M/day is false |
| Relaxed in production | Silent loss of a decided height’s `I` |
| fsync every 5 ms regardless of height | Extra clock; Malachite already batches `I` |

## Consequences

M2 remains a correctness harness, not a speed claim. Consensus apply can sit next to treap `C'` (ADR 0013) without 10k fsyncs.

## Security implications

A crash mid-height loses undetermined orders. It must not fork a decided `id(v)`. Decide still WAL+applies the same `I` that `Validate` replayed.

## Performance implications

Height-batch WAL is in band with incremental `F` (~30k ev/s), not with Full. NVMe/`fdatasync` may move Full; they do not replace this default.

## Reversibility

High. `Full` remains. Switching Height → Full is a flag. Switching to a single blob record is a WAL version bump.
