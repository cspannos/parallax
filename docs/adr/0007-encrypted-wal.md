# ADR 0007 — Encrypted Append-Only WAL (Phase 2)

**Status:** Accepted for Phase 2 (M2 / M2b)  
**Date:** 2026-09-30  
**Deciders:** Protocol architecture (research prototype)

## Context

Phase 2 must show that four replicas, given the same ordered inputs, produce identical state roots, fills, and settlement deltas after crash, restart, WAL replay, and injected delay. RAM is not durable. Corruption must be detectable. RocksDB is not the default (Q-STO-1). Incremental Merkle (Q-CRY-2) is still unchosen; the WAL stores **inputs**, and the engine recomputes the root on replay.

This is **not** consensus. There is no voting. Delay must not reorder `I`.

## Decision

### Store (Q-STO-1)

**Append-only file**, not RocksDB, not redb, not MDBX.

Reasons: crash/truncate/corrupt tests map onto a file; Malachite already has its own consensus WAL; redb remains a candidate for later keyed private state. Measure before replacing this file.

Layout:

```text
magic "PLXWAL01"
u16 version = 1
u32 genesis_len
genesis bytes (canonical, unencrypted in M2 — instruments are public)
records:
  u64 seq
  [24] XChaCha nonce
  u32 ciphertext_len
  ciphertext (XChaCha20-Poly1305)
```

### Encryption (Q-STO-2)

**XChaCha20-Poly1305** (IETF / libsodium family). 32-byte node key. Nonce is unique per seq (seq encoded into 24-byte nonce). AAD = `PLXWAL01` || `seq` so a spliced record from another file or another seq fails.

This is confidentiality-at-rest plus tamper evidence. It is not a disclosure capability system.

### Durability (Q-STO-3)

M2 tests: **`sync_all` after every record** (`SyncMode::Full`). `Relaxed` exists for benches / isolate `nosync`.

**Consensus apply path (ADR 0012):** `SyncMode::Height` — flush each append, **one `sync_all` per height** before `F`. Measured ([`q-sto-3-wal.md`](../benchmarks/q-sto-3-wal.md)): Full ≈ **270 ev/s**; Height at `|I|=10k` ≈ **32–36k ev/s**.

### Apply order

```text
encode input → encrypt → append (+ fsync) → apply F
```

An input is **accepted** only after the WAL write succeeds. Crash during `F` leaves a complete record; restart replays it. Crash during the append leaves a truncated tail: detected, prefix replayed, incomplete tail **not** applied.

Decrypt/auth failure of a complete record: **refuse to open**. Do not skip.

Every `apply` input is logged, including rejects that still mutate nonce state.

### Replica shape

Four independent `Replica` instances (threads and/or OS processes), same genesis, same ordered `I`, **different** WAL keys/files. Compare `state_root`, fills, settlement.

Injected delay sleeps before `submit`; it does not reorder.

## Alternatives

| Option | Why not for M2 |
|---|---|
| RocksDB | Ops-heavy; not required; harder truncate tests |
| redb | Good later for keyed state; overkill for a log |
| WAL after apply | Crash can drop an accepted order |
| Unencrypted log | Fails “encrypted persistent” and easy silent bit-flips |
| Incremental Merkle in the same patch | Separate ADR (Q-CRY-2); replay does not need it |

## Consequences

Phase 2 can test recovery without BFT. Roots are treap `C'` (ADR 0013) on the replica; M2 still uses Full fsync. Four-node delay tests cannot be mistaken for networking research (Q-NET-1).

## Security implications

WAL keys are test/node secrets, not capability keys. Compromise of a replica key discloses that node’s input log. Header genesis is plaintext. Truncation of the *last* record is recoverable; punching a hole in the middle is detected as corrupt and halts.

## Performance implications

fsync per input will dominate matching. **Measured 2026-10-01** ([`q-sto-3-wal.md`](../benchmarks/q-sto-3-wal.md)): `SyncMode::Full` ≈ **270 ev/s**; one `sync_all` per 10k-event tape ≈ **32–36k ev/s**. M2 tests stay on Full. Consensus apply uses Height (ADR 0012).

## Reversibility

High. Swap the file WAL for redb/MMAP behind the same `Wal` trait. Changing AEAD requires a version bump.
