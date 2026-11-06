# Matter Labs, 2026: “Introducing Airbender Prime”

**Source:** ZKsync blog, “Introducing Airbender Prime” (2026-10-13); code at [github.com/matter-labs/zksync-airbender](https://github.com/matter-labs/zksync-airbender)  
**Date read:** 2026-10-16  
**Purpose:** Work out what the announcement means for Parallax in practice. Every number below comes from the vendor and has not been reproduced here. Nothing in this note changes an ADR on its own.

---

## 1. What was announced

- **Airbender Prime** is a RISC-V zkVM from Matter Labs (ZKsync). It is the same category of tool as RISC Zero and SP1, which Parallax already uses (ADRs [0023](../adr/0023-general-c-prime-on-zkvm.md), [0025](../adr/0025-pi-of-f-on-zkvm.md)). It is open source.
- **Speed:** on one NVIDIA RTX PRO 6000 Blackwell, it proved 99% of 7,200 consecutive Ethereum mainnet blocks in under 10 s each, and every block in under 12 s. Both figures include witness preparation. Two- and four-GPU configurations are listed on the ETHproofs leaderboard, which it reportedly leads on average time, GPU-seconds per block and cost.
- **Proof system:** hash-based STARKs (GKR sumcheck, WHIR polynomial commitments, BLAKE2s). Proofs for Ethereum L1 use Keccak-256 commitments instead of BN254 pairings, so there is no pairing-based wrap. It ships a standalone verifier.
- **Pitch:** institutional finance. Requiring ZK proofs for ledger updates means even a compromised execution server cannot get an invalid update past verification.

That pitch is the same idea as Parallax's settlement rule: settlement stays inert until a validity proof verifies (ADR [0011](../adr/0011-missing-pi-settlement-inert.md), [0025](../adr/0025-pi-of-f-on-zkvm.md)).

## 2. What it means for Parallax

### 2.1 Proving time could drop from a day to seconds

The matcher proof `π` of `F` (ADR 0025) projects to **~1.5 × 10⁹ RISC-V cycles** and **~24–26 CPU-hours** for a loaded 10k-event height on an M4 Pro CPU with RISC Zero.

zkVM proofs of Ethereum mainnet blocks are commonly quoted in the range of a few hundred million to a few billion cycles. That range is our recollection, not a figure from the announcement. If it holds, a loaded Parallax height is the same order of work as what Airbender proves in ~10 s on one GPU.

At the average-load target (300M events/day ≈ 3.5k events/s), a 10k-event height arrives roughly every 3 s. At ~10 s per proof, about **3–4 GPUs** proving in parallel would keep up. That is a deployment cost, not a research blocker. Settlement would unlock seconds after decide instead of hours, which makes the Model III endgame (Q-PRF-6) practical rather than notional.

### 2.2 The matcher proof is already portable

The `F` statement is plain Rust compiled to RISC-V: [`clob::run_f`](../../crates/clob/src/snapshot.rs) takes bytes and returns a 129-byte claim. RISC Zero-specific code is confined to:

- the guest entry point and its input/output ([`zkvm/risc0/methods/f`](../../zkvm/risc0/methods/f/src/main.rs))
- the `sha2` patch for accelerated SHA-256
- the verifier ([`Risc0FVerifier`](../../crates/proof-adapter/src/risc0_f.rs))

The main unknown is **whether Airbender guests support Rust `std`**. `clob` and `commitments` rely on `HashMap`, thread-locals and `OnceLock`. If Airbender needs a `no_std` + `alloc` build, porting is real work.

### 2.3 The `C'` hash choice may need revisiting

ADR [0024](../adr/0024-sha256-c-prime.md) picked SHA-256 for `C'` because RISC Zero and SP1 accelerate it in guests. The announcement names BLAKE2s as the hash *inside the proof system*. It does not say which hashes Airbender accelerates for guest programs. If it accelerates BLAKE2s or Keccak but not SHA-256, our choice is the wrong one for the fastest prover. The hash is a mode switch (`TreapHash`), so changing it is cheap, but this should be checked before more depends on SHA-256.

### 2.4 A post-quantum route to on-chain verification

Parallax does not wrap proofs in Groth16, because BN254 pairings are not quantum-safe (Q-PRF-4). The cost is that our 224 KB RISC Zero succinct receipts are not cheap to verify in the EVM. A Keccak-committed STARK built for Ethereum L1 verification is a route to verifying Parallax heights on-chain without giving up post-quantum safety. This is relevant to Phase 7 (PQ) and to any future on-chain check of settlement on Reth.

### 2.5 One GPU makes self-hosted proving realistic

The prover sees the full private state: the snapshot is a FULL_VIEW witness (ADR 0025). Sending witnesses to a public prover market would leak order flow, so Parallax operators have to prove on hardware they control. A one-GPU prover, rather than a cluster, makes that realistic for institutions.

For this repo specifically: development is on Apple silicon, so CUDA provers cannot be measured locally. A rented GPU is needed.

### 2.6 It strengthens a direct competitor

ZKsync's Prividium targets private institutional ledgers backed by ZK proofs, the same market thesis as Parallax. A faster, cheaper prover strengthens that stack. It also suggests proving is becoming commodity infrastructure, so Parallax should not build its own prover. Its differentiation sits above the prover:

- the private state engine and native CLOB
- sub-second deterministic finality on Malachite
- selective-disclosure views

The prover should stay a swappable component behind `VerifyPi`, which is how the code is already shaped.

## 3. What it does not solve

- **State growth (Q-CLOB-8).** Every `π` of `F` rebuilds the full committed state, including every order id ever seen. A faster prover shrinks the constant, not the growth.
- **Witness privacy and data availability.** Fast proving does not change who must see the witness or what light clients can download (Q-DA-6).
- **Our own numbers.** The ~10 s figure is for Ethereum blocks using Airbender's own accelerated operations. Parallax's workload has not been measured on it, and leaderboard figures are self-reported.

## 4. Suggested roadmap changes

These are proposals, not decisions.

1. **Benchmark before optimizing.** Move “measure `π` of `F` on a GPU zkVM” ahead of guest trimming. Port the `F` guest to Airbender on a rented GPU, and measure the RISC Zero and SP1 GPU provers alongside it (“measure, don't pick”, Q-PRF-1). This tells us whether proving speed is still a research problem or just a deployment cost.
2. **Check Airbender's accelerated guest hashes** before more depends on SHA-256 `C'`. Revisit ADR 0024 if needed.
3. **Keep Q-CLOB-8 (seen-id growth) high on the list.** It matters whichever prover wins.
4. **Revisit three open questions:**
   - **Q-PRF-4:** add Keccak-committed L1 STARK proofs as the post-quantum on-chain option.
   - **Q-PRF-5:** if proofs take seconds, the asynchronous prover could become a bounded-lag pipeline (settle when `π` lands within N heights).
   - **Q-PRF-6:** the validity endgame stops being a distant research item.

## 5. Desk check of the repository (2026-10-16)

Read from a shallow clone of `matter-labs/zksync-airbender`. `main` was last committed 2026-04-23 and describes the earlier design. The GKR / WHIR work behind Prime is on development branches; `av_gkr_compiler` was last committed 2026-10-15.

| Question | Finding | Consequence for Parallax |
|---|---|---|
| Guest environment | **Bare-metal `no_std`, `no_main`, nightly Rust**, own startup, panic handler and I/O (`docs/writing_programs.md`) | Porting the `F` guest needs a `no_std + alloc` build of `clob` and `commitments`: the trace hooks (`thread_local!`), `OnceLock`, and the `HashMap` in `BTreeBook` must be gated or replaced. Moderate work; the matcher logic itself does not change. |
| Accelerated ops ("delegation circuits") | `main`: BLAKE2 and 256-bit bigint. `av_gkr_compiler`: BLAKE2 (G function, round), **Keccak** (four circuits), bigint. **No SHA-256 anywhere.** `reduced_keccak` is a software Keccak for the L1 recursion path, not a circuit. | Under Airbender, SHA-256 `C'` (ADR 0024) runs in software, which is the situation BLAKE3 was in on RISC Zero. ADR 0024 is right for RISC Zero / SP1 and wrong for Airbender. A Keccak `C'` mode would suit Airbender, and Keccak is also the EVM's native hash opcode. Possibly BLAKE3 too, since it uses the BLAKE2s G function, but that is unverified. Decide after the GPU benchmark (§4.1). |
| Security model | "Airbender currently proves only M-mode firmware that has been audited and compiled specifically for the circuit". The delegation circuits stay permissive and rely on trusted bytecode; untrusted / user-mode programs are future work (`docs/delegation_circuits.md`). | The `F` guest is network-pinned code, the same position as ZKsync OS, so it fits the model. It must be built with their toolchain and treated as audited firmware. |
| Maturity | Prime's design lives on moving development branches, not a release | Benchmarks should pin a commit. Treat the API as unstable. |

These sharpen §4: (1) the port costs a `no_std` pass first; (2) the hash question is now concrete. RISC Zero and SP1 accelerate SHA-256; Airbender accelerates Keccak and BLAKE2.
