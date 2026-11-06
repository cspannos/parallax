# ADR 0014 — One WAL record per height tape

**Status:** Accepted as the **Height-mode persist** research default  
**Date:** 2026-10-01  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0012](0012-height-batch-wal.md) “not in this ADR” blob. M2 `submit` / `SyncMode::Full` stay one `Input` per record.

## Context

ADR 0012 fsyncs once per height but still encrypts and appends **one WAL record per input**. Loaded isolate after scratch reuse: decide leftover **~210 ms** at `|I|=10k` is those appends, not `sync_all` ([m4-loaded-isolate.md](../benchmarks/m4-loaded-isolate.md)).

## Decision

`Replica::persist_batch` / Height `submit_batch` write **one plaintext**:

```text
tag "PLXTAPE\0"
u32 count
count × canonical Input
```

One encrypt, one append, one Height `sync_all`. Replay: tag → expand to `I`; otherwise decode a single `Input` (M2 records). File magic `PLXWAL01` / version 1 **unchanged**.

`SyncMode::Full` `submit` is still per-input. Crash tests keep that grain.

## Alternatives

| Option | Why not |
|---|---|
| Keep 10k records + Height fsync | Measured ~210 ms leftover |
| WAL version bump | Unnecessary; tag is disjoint from `INPLACE` / `INCNCL` / `INADVH` |
| Cap smaller than 16 MiB ciphertext | 10k places are ~1–2 MiB |

## Consequences

Preload + height are two blobs on disk, not 18k records. Truncating the last record drops the whole tape (correct for Height).

## Security implications

Same AEAD. A truncated blob is discarded as today. Binding of `I` to `id(v)` is still `input_commitment`, not WAL layout.

## Performance implications

Removes O(`|I|`) encrypt/append syscalls from decide. Expect decide WAL ≪ 210 ms; then GetValue/prevote `F` dominate (~530 ms `F+nowal`).

## Reversibility

High. Readers still accept single-`Input` records. Writing per-input again is a flag.
