# ADR 0032 — Lazy `C'` hashing and SHA-256 order ids: `π` of `F` 3× cheaper

**Status:** Accepted (production `C'` / order-id default)  
**Date:** 2026-10-25  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0024](0024-sha256-c-prime.md) (`C'` is SHA-256), [0025](0025-pi-of-f-on-zkvm.md) (`π` of `F`, guest trimming), [0026](0026-derived-order-ids.md) (derived order ids).  
**Changes:** the order-id derivation (now `plx/clob/orderid/v2`, SHA-256). `C'` roots are unchanged.

## Context

After the guest trimming of ADR 0025, a loaded height (8k resting orders, 10k events) still cost ~634 M cycles, which projects to ~10–11 CPU-hours on this host. Events were ~90% of that, at ~57 K cycles each. A RISC Zero profile (`RISC0_PPROF_OUT`, `go tool pprof`) of the 10k height showed three hot spots:

- **Treap rehashing.** Every mutation rehashed its whole root path immediately. With 10k events, the upper levels were rehashed thousands of times per height, although only the final root is committed.
- **BLAKE3 in software.** ~75 M cycles: one `derive_order_id` per Place (~36 M), plus the bulk input and settlement commitments (~42 M). The guest accelerates SHA-256 but not BLAKE3.
- **SipHash.** The books' `OrderId` index used `RandomState` (~22 M cycles), on keys that are already hashes.

## Decision

1. **Lazy `C'` for production.** In `TreapHash::Sha256` mode with tracing off, a mutation only marks its path dirty. Hashing happens at most once per node per flush.
   - `HashedMap::flush` hashes dirty nodes children-first.
   - `root()` stays `&self`: it computes dirty subtrees on the fly without storing, so it is always correct.
   - `Engine::apply_all`, `from_snapshot` and the per-receipt root (`commit_on_apply`) flush.

   The digests are identical, because a node's hash depends only on the final tree. BLAKE3 v1, the isolate modes and tracing stay eager: the Plonky3 circuits and step witnesses depend on per-step openings.
2. **Order ids hash with SHA-256.** `derive_order_id = SHA-256(digest_preimage(owner ‖ nonce, "plx/clob/orderid/v2"))[..16]`, using the guest's accelerator when one is installed. Only production engines derive ids; `C'` v1 keeps client ids, so no v1 circuit or fixture depends on this.
3. **`IdHasher` for the books' `OrderId` index.** A multiply-xor fold replaces SipHash. It is not DoS-resistant against chosen client ids, and iteration order is never used.

## Measurements

RISC Zero executor, `PLX_EXECUTE_ONLY=1 PLX_F_REST=8000 PLX_F_EVENTS=…`. Each row is the same binary with only the change shown. "Eager" means the code before this ADR, measured by forcing `lazy() = false`.

| 8k resting | Eager (before) | + lazy `C'` | + SHA-256 ids, `IdHasher` |
|---|---|---|---|
| Rebuild only (0 events) | 58.9 M | 59.0 M | **54.9 M** |
| + 512 events | 88.2 M | 72.4 M | **66.2 M** |
| + 10 000 events | 634.2 M (810 segments) | 258.6 M (360) | **211.7 M (308)** |
| Per event | ~57.5 K | ~20.0 K | **~15.7 K** |

- A **loaded 10k height is 3.0× cheaper**: 308 segments instead of 810. It projects to **~3.5–4 CPU-hours** (was ~10–11), by the same per-segment scaling as ADR 0025.
- A real proof of 1 000 resting + 8 events took **603 s (9 segments)** against 620 s (10 segments). That height is rebuild-dominated, so the gain there is small. The win scales with events per height.
- Native consensus is unchanged: a loaded gossip height is 127 ms p50. Per-receipt roots flush, so their cost equals eager.

**Regression found and fixed.** Without the flush in `receipt_root`, every per-input root read re-hashed all dirty nodes without storing them, which is quadratic in the batch. The loaded height went 130 ms → 5 s. The flush restores it.

## Follow-ups (2026-10-25)

- **The native book index is keyed again.** An unkeyed fold on grindable ids (`H(owner, nonce)`) let an attacker pile orders into one bucket on every validator. `IdHashBuilder` is now `RandomState` (keyed SipHash) natively, and the multiply-xor fold only in the zkVM guest (`target_os = "zkvm"`), where `I` is already fixed. The guest stays at 212.2 M cycles for the 10k height.
- **No per-receipt roots in consensus.** Consensus replay (Validate / GetValue) and the replica's height-batch apply now skip per-input roots (`commit_on_apply = false` for the batch). Only the final root is voted. The standalone replica's per-input (`Full`) path keeps them.
  - Injected loaded height (8k + 10k): node p50 **~130 → 89–94 ms**.
  - Gossip loaded height: last p50 **127 → 108 ms** (~93k ev/s).

## What remains

The 10k profile after this ADR (cycles include paging):

| Item | Cycles |
|---|---|
| Paging (in + out) | ~102 M |
| memcpy | ~79 M (node key/value `Vec`s, the 808 KB snapshot) |
| BLAKE3 bulk input + settlement commitments | ~40 M |
| SHA-256 treap hashing | ~13 M accelerated, plus preimage assembly |

The next levers:

1. **Commitments in SHA-256 for production.** This saves ~35 M. It needs the hash family threaded into the settlement log (`evm-adapter` recomputes the settlement commitment) and the consensus `commit_list`, while v1 keeps BLAKE3 for the Plonky3 HeightMatch circuit, which proves BLAKE3 commitments.
2. **Fewer allocations in treap nodes** (inline keys, arena), to cut memcpy and paging.

## Consequences

- The guest image ID changed. The `risc0_gate` fixtures were regenerated (crossing height, succinct, 223 KB).
- Order ids changed for every `(owner, nonce)`. Tests derive them via `testutil::id_of`. Two hash-count tests asserted node counts that depended on where the old ids landed; they now assert what they meant: a new owner's Place touches two maps (two new priorities).

## Reversibility

Lazy hashing is reversible: one function, with no root changes. The order-id derivation is a protocol change; reverting it means `orderid/v1` again.
