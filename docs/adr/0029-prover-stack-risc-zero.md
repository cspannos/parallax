# ADR 0029 — Prover stack for the `π` pipeline: RISC Zero (measured against SP1)

**Status:** Accepted as the **pipeline default**; revisit on GPU / Airbender numbers  
**Date:** 2026-10-22  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0025](0025-pi-of-f-on-zkvm.md) (`π` of `F`), [0028](0028-e2e-proof-pipeline.md) (pipeline). Updates Q-PRF-1 ("measure, do not pick by popularity").

## Context

`π` of `F` was proven on RISC Zero only. Before scaling the pipeline out (parallel provers), the same statement was measured on SP1, the other zkVM in the repo. SP1's guest (`zkvm/sp1/f-program`) runs the same `clob::run_f` and uses SP1's patched `sha2` (precompile). Its public values must equal the natively computed claim, as RISC Zero's journal must.

## Measurements

Apple M4 Pro (14 cores, 24 GB), CPU provers, SHA-256 `C'`, derived ids. Recursive / compressed artifacts on both (not Groth16).

| | RISC Zero 3.0.6 (succinct) | SP1 6.8.1 (compressed) |
|---|---|---|
| 1 000 resting + 8 events: prove | 620 s | **463 s** |
| 100 resting + 8 events: prove | 95–97 s | 92 s |
| Proof size | **224 KB** | 1.27 MB |
| Verify | **9–10 ms** | 28–30 ms |
| Peak memory (100 + 8) | **~7.4 GB** | ~9.8 GB (core) |
| Peak memory (1 000 + 8) | not measured | ~11 GB |
| Runs with default settings on 24 GB | **yes** | **no**: killed by the OS until `SHARD_SIZE=2^20`, `ELEMENT_THRESHOLD=2^26`, `MEMORY_LIMIT=12 GiB` |
| Counted work (1 000 + 8) | 9.7 M cycles | 29.7 M instructions |
| Counted work (8 000 + 512, execute) | 87.6 M cycles | 392.9 M instructions |

SP1 core (not compressed) on 1 000 + 8 was 210 s and 37.9 MB. Counted work is not comparable across VMs (RISC Zero reports padded cycles including paging; SP1 reports executed instructions); prove time is.

## Decision

**RISC Zero stays the pipeline prover.** On prove time the two are close: a tie on small heights, SP1 ~25% faster at 1 000 + 8. RISC Zero wins on everything else that the pipeline and settlement depend on:

- a 5.7× smaller proof
- 3× faster verification
- ~25% lower memory per prover, which bounds how many provers fit on one host
- running with default settings
- being already integrated (`Risc0FVerifier`, the gate, ADR 0028)

This is the first stack pick for `π`. It is a pipeline default, not a claim that RISC Zero is the best prover: the prover is a separate process behind a job directory, and the verifier sits behind `VerifyPi`.

## Revisit when

- A GPU benchmark (RISC Zero CUDA / Metal, SP1 CUDA, Airbender) is run. Prove time is then likely to dominate, and the ranking may change.
- Proof size stops mattering (for example, everything is wrapped for the EVM).
- SP1's SHA path is tuned: its per-event instruction count (~341 K) is ~6× RISC Zero's per-event cycles. That may be the patched `sha2` driving the precompile less efficiently than RISC Zero's one-call hash (see ADR 0025, guest trimming).

## Reversibility

High. Swap the `prover` process and the `VerifyPi` implementation; the job format and the pipeline are prover-neutral.
