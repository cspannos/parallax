# ADR 0035 — The CLOB as a private L2 over a commitment-only Malachite L1

**Status:** Proposed (design only; nothing implemented)  
**Date:** 2026-10-26  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0005](0005-data-availability-model.md) (DA is threat-model-first), [0008](0008-unequal-view-validity.md) (unequal views cannot share `valid(v)` without `π`), [0011](0011-missing-pi-settlement-inert.md) (settlement inert until unlocked), [0022](0022-treap-step-witness.md) / [0023](0023-general-c-prime-on-zkvm.md) (step witnesses, zkVM tapes), [0025](0025-pi-of-f-on-zkvm.md) (`π` of `F`), [0030](0030-pq-hybrid-suites.md) (hybrid KEM), [0031](0031-tiered-finality.md) (finality certificate), [0033](0033-signed-orders.md) (signed orders).  
**Generalized by:** [0036](0036-ledger-kernel-and-engines.md) (proposed): the L2 executes a ledger kernel with engines, the CLOB being one of them.  
**Would change:** what Malachite validators check in `valid(v)`, who executes `F`, how settlement unlocks, and what `disclosure` means.

## Context

Two goals pull against the current design.

1. **Selective disclosure at the CLOB and validator level.** Today every validator is `FULL_VIEW`: it receives `I`, runs `F` in Validate, and so sees the whole book. ADR 0008 showed why: without `π`, nodes with unequal views cannot agree on `valid(v)`. The `disclosure` crate projects views by label, and is explicitly not cryptographic isolation.
2. **No proving bottleneck.** Settlement waits for `π` of `F`. A loaded height (8k resting, 10k events) is ~212 M cycles, ~4 CPU-hours (ADR 0032). With a single prover, settlement queues behind decide (ADR 0028).

The Ethereum rollup split suggests a way out. An L2 executes; the L1 orders commitments and **verifies or adjudicates**, it does not prove. The proving question becomes *when* a proof is needed, not *whether* the L1 can afford it.

Most of the shape already exists. The Malachite value is already commitments only (`state_root`, `input_commitment`, `settlement_commitment`). The coupling is that validators re-run `F` to vote.

## Decision (proposed)

Split Parallax into two layers with one boundary: **commitments cross it, order flow does not.**

| | L1: Malachite validators | L2: CLOB operator committee |
|---|---|---|
| Members | The validator set (BFT, 2f+1) | A permissioned committee of N operators (first cut: N = 4–7) |
| Sees | Commitments, signatures, availability attestations | Full order flow and book (inside the disclosure perimeter) |
| Does | Orders batches, finalizes commitments, runs the dispute game, unlocks settlement | Admits signed orders, sequences, runs `F`, produces state roots, holds `I` |
| Proves | Nothing | Only on dispute (or on request, see mode B) |
| Trust for safety | ≤ f Byzantine validators | **At least one honest member watching each batch (1-of-N)** |

### 1. What a batch is

For L2 batch `b` (one CLOB height), the operators publish to L1 a **batch header**:

```text
BatchHeader {
  parent, batch_height,
  pre_root, post_root,            // C' (SHA-256 treap, ADR 0024)
  input_commitment,               // hiding: salted (see §5)
  settlement_commitment,
  trace_root,                     // Merkle root of checkpoint roots, every K events (§3)
  da_attestation,                 // ≥ t of N operators: "I hold I(b) and the pre-state"
  operator_sigs,                  // hybrid suite signatures (ADR 0030)
}
```

L1 `valid(v)` becomes a check every validator can do with **no view of the book**:
- The header is well-formed and extends the parent.
- At least t operator signatures and the DA attestation verify.
- Any forced-inclusion obligations are met (§6).

This resolves the tension in ADR 0008 by changing what is validated, not who sees what: validators no longer validate execution, so unequal views stop mattering.

### 2. Settlement modes

**Mode A, optimistic with ZK fraud proofs (default).** A batch's settlement deltas unlock after a challenge window `W` measured in L1 heights, unless a challenge is open. Nothing is proven in normal operation.

**Mode B, validity on demand.** Any batch can instead be settled early with `π` of `F` (ADR 0025): for large withdrawals, for a counterparty who will not wait `W`, or as a periodic audit. The proof is produced off L1 and only verified on L1 (~10 ms, 224 KB).

Today's "attest now, prove later" path (the full-view certificate plus ADR 0031's finality certificate) would be retired for the L1. Under it, the validators must see everything.

### 3. The dispute game: prove one step, not one height

Proving a whole loaded height takes hours on CPU, which would force `W` to be long. Instead the dispute narrows to a few events.

1. **Checkpoints.** The operator commits the `C'` root after every K events, as `trace_root`, a Merkle root over the checkpoint roots. Lazy hashing (ADR 0032) makes this a flush every K events rather than every event; the cost is a design parameter (§8).
2. **Locate.** A challenger is a committee member who recomputed the batch from `I(b)`. It already knows the first checkpoint `j` whose root differs from its own. It opens a challenge naming `j`, with a Merkle proof of checkpoint `j−1` (agreed) and checkpoint `j` (disputed). No interactive bisection is needed when checkpoints are committed. Bisection inside a chunk is optional if K is large.
3. **Prove the chunk.** Either side submits a zk proof that applying events `(j−1)K+1 … jK` to the state with root `r_{j−1}` gives `r_j`.
   - This needs a **stateless chunk guest**: the matcher reading and writing the book through treap openings against `r_{j−1}`, instead of rebuilding the whole book from a snapshot. It extends ADR 0022's `TreapStep` from `C'` maps to the matcher's reads (best levels, resting orders, nonces).
   - Cost is roughly K × 16 K cycles plus openings. K = 64 is about 1 M cycles, one segment, around a minute on this CPU and seconds on a GPU.
4. **Resolve.** If the chunk proof matches the challenger's root, the batch is fraudulent:
   - its settlement never unlocks
   - the operator bond is slashed
   - the L2 rolls back to `r_{j−1}` of that batch and re-executes

   If it matches the operator's root, the challenger's bond pays.

`W` then only has to cover detection, challenge, and one chunk proof: minutes, not the days of optimistic rollups that re-execute on L1.

### 4. Data availability

- `I(b)` and the pre-state live only with the committee. Each operator's DA attestation is a hybrid signature over `(batch_height, input_commitment)`. An operator attesting to data it does not serve is slashable through a DA challenge on L1: the challenger names a chunk; the operator must post it encrypted to the challenger within D heights, or lose its bond.
- This is a validium. If **every** operator withholds data, users cannot reconstruct state. §6 adds per-account exits to bound that risk.
- Public DA is still rejected for order flow (ADR 0005). The ADR 0005 DA-sampling research applies inside the committee, not to the public.

### 5. Selective disclosure becomes cryptographic

What each party gets:

| Party | Gets | How |
|---|---|---|
| Operators (committee) | Full plaintext of `I` and the book | Each order is encrypted to the committee with the hybrid KEM (X25519 + ML-KEM-768, ADR 0030) and an AEAD content key |
| The trader | Their own orders, fills and balances | The same envelope adds the trader's key, plus treap openings of their entries against `post_root` |
| Auditor / regulator | What a disclosure grant names (an account, an instrument, a time range) | Envelope recipients added per grant, or after the fact a re-encryption of the named items, with openings against committed roots |
| Counterparty | Facts about their own fills, not the book | Openings of the fill entries; a zk proof for computed facts (e.g. "executed at the best price at that time") |
| L1 validators and the public | Commitments, signatures, settlement deltas | Nothing else. `input_commitment` is salted so low-entropy orders cannot be guessed from it |

- Proofs of facts are checked against the same roots L1 finalized, so a disclosure cannot contradict the settled state.
- The operators still see everything: matching a CLOB needs the book. Hiding it from them as well needs MPC, FHE or TEEs, which are out of scope (see Alternatives).

### 6. Liveness and exits

- **Forced inclusion.** A trader can post an encrypted order (or cancel) directly to L1. Operators must include it within D L1 heights, or L1 halts the batch stream for those operators.
- **Escape hatch.** Each trader keeps the latest openings of their own balances against a settled `post_root`. If the committee stops producing batches for longer than a timeout, traders exit on L1 with those openings: a balance proof against the last settled root, no book needed.

### 7. What stays and what changes

| Today | Under this ADR |
|---|---|
| Validators gossip `I`, run `F` in Validate, replay it on decide | Validators check headers and signatures only. Batch-size tests showed the replays dominate per-order cost (`docs/benchmarks/batch-size.md`); this removes them from L1 |
| Intent gossip among validators (ADRs 0016–0021, 0027) | Moves to the L2 committee unchanged, plus encryption to the committee |
| Signed orders checked at admission (ADR 0033) | Checked by operators; the batch signature attests it. A fraud proof also covers authorization if the chunk guest checks signatures (§8) |
| `π` of `F` gates every settlement (ADR 0028) | `π` is mode B, and the basis of the chunk guest |
| Tiered finality certificate (ADR 0031) | Kept for L1 commitments. Operators sign batches with hybrid keys |
| `disclosure` labels (ADR 0008) | Replaced by encryption grants and openings (§5) |
| Treap `C'`, lazy hashing (ADRs 0024, 0032) | Unchanged; checkpoints every K events |

## Trust model, stated plainly

- **Safety of settled funds:** at least one honest, online committee member per batch within `W`, plus an honest L1 majority. A colluding committee of all N can steal only if nobody outside it can challenge. So N and member independence are the main parameters.
- **Privacy:** against L1 and the public, strong (commitments only). Against the committee, none: it sees order flow by design.
- **Liveness:** the committee can censor; forced inclusion bounds that. The committee can halt; the escape hatch bounds the damage.
- **Post-quantum:** batches and attestations use hybrid signatures. The envelopes use the hybrid KEM. The chunk and `π` proofs are STARK-based (not analysed for PQ).

## Alternatives considered

| Alternative | Why not the default |
|---|---|
| Keep validators full-view (today) | No selective disclosure from validators; settlement either trusts 2f+1 or waits for full `π` |
| Pure ZK validium (`π` before every settlement) | Strongest guarantees and the same privacy, but settlement throughput equals proving throughput (~0.7 events/s per CPU today). Kept as mode B |
| Optimistic with re-execution on L1 | L1 would need the data, which breaks disclosure |
| MPC / FHE matching | Hides the book from operators too, but orders of magnitude slower than 1.5 M events/s |
| TEE matching | Hardware trust and side channels; not this project's assumptions |

## Open questions

- **Committee:** size N, selection, bonds, rotation, and whether it overlaps the validator set (it should not, for independence).
- **Window `W` and checkpoint interval K.** Smaller K means faster chunk proofs but more checkpoint hashing. Lazy flush every K events still costs part of what ADR 0032 saved; measure K = 16 / 64 / 256.
- **The stateless chunk guest:** which book reads need openings (best price levels, FIFO position, nonce map), and whether signature checks belong inside it.
- **DA challenge protocol and timing** (D), and the encrypted-to-challenger delivery.
- **Forced inclusion** of encrypted orders: format, fee, and how L1 enforces it without seeing contents.
- **Disclosure grants:** who can issue them, whether they are revocable, and how they are logged.
- **L2 reorg on proven fraud:** what traders who saw soft-final fills are told.

## Consequences if accepted

- **Proving leaves the critical path.** In normal operation nothing is proven. A dispute needs one chunk proof (about a minute on CPU at K = 64). Mode B uses the existing prover.
- **L1 throughput rises** to header ordering speed, and L1 validators need no book, no `F`, and no private data.
- **The privacy story becomes cryptographic** (encryption plus openings), replacing view labels.
- **New trust assumption:** 1-of-N honest committee members with the data. That is weaker than ZK validity and stronger than "trust 2f+1 validators who see everything".
- **New engineering:** the stateless chunk guest, checkpoint commitments, the dispute and DA challenge game on L1, encryption envelopes, forced inclusion, and the escape hatch.

## Reversibility

The design is reversible until the L1 `valid(v)` stops running `F`. A staged path keeps both: validators keep replaying `F` (today), while L1 starts recording batch headers, checkpoints and the dispute game. Then the replay is switched off.
