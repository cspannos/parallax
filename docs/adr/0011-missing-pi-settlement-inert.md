# ADR 0011 — Missing `π`: commitment-final, settlement inert

**Status:** Accepted as the **M6 research default**, not a proving-system pick  
**Date:** 2026-09-30  
**Deciders:** Protocol architecture (research prototype)

## Context

Malachite decide is irreversible. Phases 1–5 can finalize `ConsensusValue` (commitments) and, on M5, apply `SettlementDelta` immediately. That makes **economic** finality as fast as BFT — and makes a missing or invalid validity proof a stolen-money problem, not a “prove later” problem.

Q-PRF-2: what happens if a finalized transition cannot be proven? Rollback contradicts instant finality. “Treat as valid anyway” fails verifiability. Slash-only does not un-fill a trade.

Q-PRF-3: is unproven state inert for external settlement?

Q-PRF-6: Model III (SNARK of a `PUBLIC_VIEW` statement + public DA) is the **validity** endgame if light clients must verify without honest-majority re-execution. A full-view committee (ADR 0009) is a product, not that endgame.

Q-PRF-1: measure SP1, RISC Zero, Plonky3 AIR on the **same** tiny `F`. Do not pick by popularity.

M5 (ADR 0010) proved crash atomicity of privileged apply. It did **not** wait for `π`. This ADR changes the **policy** in front of that apply, not the Engine API shape.

## Decision

### Decide ≠ validity (restate)

A Malachite decision on `ConsensusValue` is **ordering / preconfirmation** of those commitment bytes (ADR 0009). It is not world-computer validity. Light clients cannot skip re-execution or a proof.

### Settlement unlock (Q-PRF-2, Q-PRF-3)

External settlement (`AtomicApply` / `eth_get_balance` movement) is **inert** until one of:

| Unlock | Who can use it | What it is not |
|---|---|---|
| **`π`** verified against the **height’s** public statement | Anyone who has the proof and verifier key | A BFT vote, a commitment, native replay labeled as a SNARK |
| **Full-view certificate** | A replica that actually executed `F` (ADR 0008 `FULL_VIEW`) | A SNARK; not for `PUBLIC_VIEW` / light clients |

```text
on Decide(value, deltas):
  persist consensus artifacts as today
  if no unlock → do not call new_payload          // inert
  if Unlock::Proof and verify fails → inert       // do not apply
  if Unlock::Proof and verify ok → AtomicApply    // M5 path
  if Unlock::FullViewCertificate → AtomicApply    // committee path
```

**Missing or invalid `π` does not roll back the height.** The commitment stays decided. Money does not move. Sub-second finality is **ordering** finality, not “wallets see the fill.”

A later valid `π` may then unlock the same height (idempotent apply). A later invalid `π` stays inert.

### Model III is the validity endgame (Q-PRF-6)

The research default for **validity** is a proof of a public statement (eventually: `C' = Commit(F(Open(C), I))` under declared disclosure), plus an availability argument for the public bytes (Q-DA-6). [`HeightStatement`](../../crates/protocol-types/src/height_statement.rs) is that instance (`pre_root` is `C`, not a `ConsensusValue` field). Native equality is not `π`. A STARK of the fourteen chronological `C'` map hashes (9 node + 5 prio) plus `I` plus genesis/mid/post INC plus settlement, stacked with match-step, exists ([`HeightMatchVerifier`](../../crates/proof-adapter/src/height_match.rs)) for one fixed 2-place rotate fixture. It binds roots, parent, commitments, receipt amounts and owners, Place fields, headers and the fixture's treap edges ([`m6-prove.md`](../benchmarks/m6-prove.md#height-hashes--match-step-2026-10-05) lists them). It is not `F`, and it does not unlock settlement. [`NoHeightStark`](../../crates/proof-adapter/src/public_da.rs) rejects unlabeled proofs. Public DA is **validator replication** of those 178 B among the M4a set (full-download). At n≫4, public transcripts larger than 4096 B are chunk-Merkle sampled; reconstructability is 2D RS (not 16 samples, not a DA chain). Sample indices are a function of `blob_root`; a complement withhold of those 16 cells fools the light client. Client-local coins catch that complement and still do not reconstruct. A full-view voting set is sufficient for **this prototype’s safety among those replicas**. It is not a substitute for light-client validity.

Do not put `π` into M4a `id(v)` until `Validate` checks it. Same rule as `evm_state_root` (ADR 0010).

### Tiny `F` is not the CLOB (Q-PRF-1)

M6a proves a **fragment**: one crossing fill’s `min` quantity and `notional` (the integer identity already in ADR 0006). Instance class: quantities and price fit a **15-bit** range check so `fill × price` fits in BabyBear (≈ 2³¹) without a u64×u64→u128 circuit.

That proof is **not** `π` of a height. The height instance is [`HeightStatement`](../../crates/protocol-types/src/height_statement.rs): `C` (`pre_root`) → `C'` (`post_root` = voted `state_root`) under committed `I` and deltas. Native check is FULL_VIEW replay (`check_height_statement`). [`ApplyWitness`](../../crates/proof-adapter/src/apply_witness.rs) names the 2-place HeightMatch opening tape (18 openings, including Place1 mid INC) with that statement and checks it natively against traced apply; it is not `π` and does not unlock settlement (`UNLOCKS_SETTLEMENT = false`). A STARK of the thirteen `C'` hashes plus `I` plus genesis INC plus post INC stacked with this height's match-step (`HeightMatchVerifier`) is not `F` and does not unlock settlement (`UNLOCKS_SETTLEMENT = false`). `Plonky3TinyVerifier` is `VerifyFragment` only — `SettlementGate` takes `VerifyPi` on `HeightStatement` and cannot take the fill STARK. Policy tests use an abstract `VerifyPi` (`UNLOCKS_SETTLEMENT = true`) as a stand-in for height `π`. A mismatched statement is inert even with a full-view certificate.

### Who proves (Q-PRF-5)

Research default: an **async prover** (proposer, dedicated machines, or both). Decide does **not** wait. Liveness of money is prover liveness; liveness of ordering is BFT liveness. They are not the same.

### Wrap (Q-PRF-4)

M6 does **not** wrap to Groth16-BN254. The fill-fragment light-client object is inner STARK-family verify (`Plonky3TinyVerifier` / `VerifyFragment`). Height `π` would verify a [`HeightStatement`](../../crates/protocol-types/src/height_statement.rs); the 8-opening STARK is not that `F`. A pairing wrap would make the fragment object **not** PQ-ready. Wrap of a height proof is still open. RISC Zero succinct / SP1 compressed receipts are measured on book-step and are not height `π`.

### Proving stacks

Measure; do not pick. M6a ran Plonky3, RISC Zero (STARK receipt, `disable-dev-mode`), and SP1 (core, not Groth16). Numbers: [`docs/benchmarks/m6-prove.md`](../benchmarks/m6-prove.md). `RISC0_DEV_MODE` / execute-without-prove is not `π`.

## Alternatives

| Option | Why not as default |
|---|---|
| Apply on decide (M5 behavior, no gate) | Economic finality without validity |
| Roll back if `π` fails | Contradicts Malachite instant finality |
| Slash-only | Does not un-fill; bond may be < harm |
| Challenge period | Needs watchers who can re-execute; fights privacy |
| Refuse to decide without `π` | Kills the sub-second **ordering** target |
| Full-view committee = validity | Conflicts with Q-PRF-6 / Vitalik 2030 light clients |
| Plug tiny-`F` STARK into height settlement | Unsound; circuit is not `F` |
| Pick SP1 or RISC Zero by popularity | Q-PRF-1 |

## Consequences

`crates/proof-adapter` sits in front of `AtomicApply`. M5 tests still call apply directly (atomicity of the sidecar). M6 tests the gate.

Phase 7 still owns PQ on **consensus/auth**. STARK verify assumptions are hash/FRI, not “the chain is PQ.”

## Security implications

Counterfeit `FullViewCertificate` is the ADR 0009 trust model (whoever can execute `F`). Forged `π` is a verifier bug or a broken assumption. Inert-forever if the prover never appears is a **liveness** failure for money, not a safety failure for balances.

## Performance implications

Prove time is off the BFT path. It **does** gate wallet-visible settlement. Do not quote Malachite milliseconds as EVM-balance finality. Publish prove/verify/size separately ([`docs/benchmarks/m6-prove.md`](../benchmarks/m6-prove.md)).

## Reversibility

High until wallets depend on inert vs eager apply. Switching back to apply-on-decide is an explicit ADR, not a flag in production.
