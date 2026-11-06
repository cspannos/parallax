# ADR 0024 — `C'` hashes with SHA-256

**Status:** Accepted as the **consensus state root research default**  
**Date:** 2026-10-15  
**Deciders:** Protocol architecture (research prototype)  
**Amends:** [0013](0013-treap-is-c.md) (the treap stays `C'`; its hash changes). Closes Q-PRF-7.  
**Does not change:** the input, receipt, consensus-value, settlement or DA commitments (still BLAKE3); the treap shape rules; the witness format (ADR 0022).

## Context

ADR 0013 chose BLAKE3 for the treap because it was fast natively. ADR 0023 then put the general `C'` proof in a zkVM guest, where software BLAKE3 is ~⅔ of guest cycles. Q-PRF-7 measured a `TreapHash::Sha256` mode: the same treap, preimages and domains, with only the hash changed.

| Measure (8k book) | BLAKE3 | SHA-256 |
|---|---|---|
| Native insert (M4 Pro, ARMv8 SHA instructions) | 7.0 µs | **4.4 µs** |
| Native loaded 10k engine apply | 99 ms | **57 ms** |
| Native loaded 10k, **software** SHA-256 | — | 151 ms |
| RISC Zero guest, one Place | 759K cycles | **254K** |
| RISC Zero guest, 64 mixed events | 35.1M cycles | **13.4M** |
| Real succinct proof, one Place (CPU) | ~62 s | **~32 s** |
| Loaded 10k height (projection) | ~93 CPU-hours | **~36 CPU-hours** |

## Decision

- **`C'` uses SHA-256** for treap nodes, priorities, the empty digest and the INC root. Preimages and domain tags are unchanged. `TreapHash::Sha256` is the default for `HashedMap`, `IncrementalState` and `Engine`.
- **`C'` v1 = BLAKE3** stays as `TreapHash::Blake3`. The Plonky3 BLAKE3 circuits and HeightMatch / `ApplyWitness` are pinned to it (`clob::testutil::btree_engine_v1`). `check_apply_witness` rejects a non-v1 engine (`ApplyWitnessError::HashMode`). They remain valid measurements of `C'` v1, not of production `C'`.
- **Native SHA-256 uses hardware instructions** (`sha2` `asm` on aarch64). zkVM guests patch `sha2` to the prover's accelerated fork (RISC Zero `sha2-v0.10.9-risczero.0`).
- Only `C'` changes. Other commitments are not on the proving path, so moving them gains nothing.

This is a **versioned encoding change**, not an alias: every state root differs between v1 and production. There is no deployed state to migrate.

## Alternatives

| Option | Why not |
|---|---|
| Keep BLAKE3 | ~2.6× more guest cycles and ~1.7× slower native apply on hardware with SHA instructions |
| Poseidon2 | Native to Plonky3 AIRs, but slow natively and not accelerated in RISC Zero / SP1 guests. Revisit only if a hand-written AIR becomes the proof path |
| Port the Plonky3 circuits to SHA-256 | A rewrite of ~11k lines, and SHA-256 is no cheaper than BLAKE3 in an AIR. The general proof path is the zkVM (ADR 0023) |

## Consequences

- One stack-neutral hash: SHA-256 has precompiles in RISC Zero and SP1, and an EVM precompile (0x02), which matters if settlement ever checks state openings on-chain.
- **Hardware assumption:** native speed relies on SHA instructions (ARMv8 SHA2, x86 SHA-NI). Without them SHA-256 measured ~2× slower than BLAKE3 natively (151 vs 99 ms on the loaded tape). Validator hardware has to provide them.
- Plonky3 `C'` numbers in `m6-prove.md` are `C'` v1 numbers.
- Re-measured after the switch (same host): engine insert at 8k **~6.2 µs** p50 (v1 ~11 µs); loaded 10k engine work **~58 ms** (~172k ev/s; v1 ~85–102 ms); loaded Malachite height n=4 **~0.156–0.157 s** (~64k ev/s; v1 ~0.17–0.19 s). See [q-cry-2-incremental](../benchmarks/q-cry-2-incremental.md), [loaded-batch](../benchmarks/loaded-batch.md), [m4-loaded](../benchmarks/m4-loaded.md).

## Security implications

SHA-256 and BLAKE3 both give 256-bit outputs with 128-bit collision resistance (~85-bit against quantum collision search). Length extension does not apply: every preimage is domain-separated and fixed-format, and roots are never extended. A bug that mixes modes forks roots; the hash mode is carried explicitly in `IncTape`, and HeightMatch refuses non-v1 engines.

## Reversibility

High. It is a mode switch: `TreapHash::default()` and a re-measure.
