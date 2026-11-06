# Initial Design

**Date:** 2026-09-25  
**Status:** Research hypothesis for review. Not an implementation license.  
**Depends on:** [reference architecture](../research/reference-architecture.md), [ADRs](../adr/), [threat model](../threat-model.md), [open questions](../open-questions.md)

This file is the Phase 0 close-out: the fifteen items requested at the end of the research brief.

---

## 1. Proposed architecture

Parallax is a **multi-engine L1 research prototype**, not “Malachite + Reth + encrypted txs.”

| Layer | Choice | Replaceable? |
|---|---|---|
| Consensus | Malachite 0.8.x via `app-channel` | Yes (port is `Propose/Validate/Finalize`) |
| Native execution | Private State Engine (Rust); first machine: CLOB | Yes (other machines later) |
| Public execution | Reth as settlement sidecar; revm for tests/guests | Yes |
| Hot state | Validator RAM | — |
| Durable private state | Encrypted append-only WAL (ADR 0007); redb still a candidate for keyed state | Yes |
| Canonical *chain* object | Malachite-decided public bundle (commitments) | — |
| Canonical *book* | PSE, among replicas that share inputs and view | See §7 |
| Canonical *public money* | EVM state | ADR 0004 |
| Networking | Malachite libp2p first; extra logical channels as needed | Yes at actor/core level |
| Privacy | Capability views; no enclave assumption | Construction open |
| Proofs | Asynchronous; stack unchosen | Yes |
| PQ | Versioned `CryptoSuite`; classical in Phase 0 | Yes |

**Not proposed:** forking Arc; putting the book in Reth; adding Celestia/EigenDA/Avail now; claiming the `C, C', Δ, π` pipeline is sound; claiming post-quantum security.

**Three matching models remain live** after this phase:

| Model | Description | When |
|---|---|---|
| **I** | Shared ordered inputs → identical books and roots | Phase 1–2 experiment |
| **II** | Proposer match tape; books may diverge (dYdX) | Fallback if I dies against privacy/MEV |
| **III** | Consensus on commitments + validity proofs | Phase 6 target |

Phase 3 is the experiment that tells us whether I is compatible with selective disclosure. Prediction: **it is not**, unless “validators” all have `FULL_VIEW` and privacy is only versus the public.

---

## 2. Architecture diagram

```text
                         CLIENTS
                            │
                   encrypted intents
                            │
                  PRIVATE P2P CHANNELS
                            │
                  PRIVATE STATE ENGINE
                            │
              ┌─────────────┼─────────────┐
              │             │             │
             CLOB          RFQ*        Auction*
              │             │             │
              └─────────────┼─────────────┘
                            │
                 deterministic transition
                            │
           ┌────────────────┴────────────────┐
           │                                 │
    C[t], C[t+1], π?                  SettlementDelta
           │                                 │
           │                            Reth / revm
           │                                 │
           └────────────────┬────────────────┘
                            │
                        MALACHITE
                            │
                       FINAL VALUE
```

Consensus-adjacent **M4a minimum** (ADR 0009; remainder still open):

```text
ConsensusValue {
    parent,                 // id(v) of previous; genesis = 32 zero bytes
    height,
    state_root,             // C'
    input_commitment,
    settlement_commitment,  // not the delta body
}
```

Not in M4a: `suite_id`, public EVM txs, `π`, DA commitment, vote extensions, the book.

`id(v)` is a domain-separated hash of that encoding (`plx/cons/value/v1`). The book is not gossiped as the value.

---

## 3. Trust model

**Stated honestly for the prototype:**

- Permissioned validator set, static in early phases.
- Tendermint assumption: &lt;⅓ voting power Byzantine ⇒ agreement on at most one value per height; decide is irreversible.
- **M4a (ADR 0009):** the voting set is four `FULL_VIEW` replicas so `Validate` may include `F`. That is a research default, not selective disclosure among validators.
- No enclave, no honest-prover assumption, no external DA majority, no PQ adversary in Phase 0–5.
- Proposer power: Malachite does not enforce fairness of `I`. A proposer can omit intents it saw. Model I among M4a voters uses a shared sequenced tape as the research default (ADR [0015](../adr/0015-sequenced-i.md)). First cut that produces the tape: a replicated intent set sealed at height start (ADR [0016](../adr/0016-intent-set.md)). First cut that **shares** the set: localhost TCP gossip of canonical `Input` (ADR [0017](../adr/0017-intent-gossip.md)). Living log: `offer` plus empty-wait then ACK of `id(set)` (ADR [0018](../adr/0018-per-height-offer.md)–[0021](../adr/0021-ack-id-set.md)), not Malachite `ready_delay`. Order is `(owner, nonce, kind, id)`, not arrival FIFO. WAN / encryption / FOCIL are not shipped.
- Users trust the protocol’s disclosure policy only as far as key holders and metadata leakage allow.

**If Phase 3 shows that only `FULL_VIEW` can validate matching:** the honest sentence is “safety of private execution is the full-view committee,” not “BFT of the whole set validates the book.” That must become an ADR, not a footnote.

**M3 result (ADR 0008):** that sentence is now the finding. Q-CONS-4 (committee vs `π`) is the remaining choice.

---

## 4. Data lifecycle

```text
intent (client)
  → authenticated, capability-labeled message
  → private channel (not consensus gossip)
  → optional local optimistic apply (not canonical)
  → inclusion in ordered input set I for a height
  → WAL (accepted inputs) before ack
  → F(S[t], I) in PSE RAM
  → C[t+1], receipts, SettlementDelta
  → validator DA fragments (encrypted to required views)
  → Malachite propose / vote / decide on public Value
  → persist decided public value + certificates (Malachite-style store)
  → apply SettlementDelta to EVM (Phase 5)
  → optional async π (Phase 6)
  → participant openings on request
  → archival encrypted history (later)
```

RAM is not authoritative durable storage. Durability is WAL + persist + (later) distributed recovery. A crash must not silently drop an **accepted** order. “Accepted” is a protocol definition we still owe (Q-CLOB-6): local ack ≠ consensus.

---

## 5. Transaction / order lifecycle

### Phase 1 order (fields to criticize, not freeze)

```text
Order {
    order_id,          // globally unique; encoding open
    instrument,        // integer id
    side,              // buy | sell
    quantity,          // fixed-point unsigned
    limit_price,       // fixed-point unsigned
    owner,             // identity under CryptoSuite
    expiry,            // height or consensus time — open
    nonce,             // replay — open
    jurisdiction?,     // disclosure-only candidate
    counterparty_constraints?,
    compliance_metadata?,
}
```

Every optional field is a candidate to drop until a predicate needs it. No floats. Canonical serialization versioned (codec unchosen).

### Lifecycle (Model I, Phase 1–2)

```text
place → validate (sig, nonce, bounds) → rest or match (price/time, FIFO)
      → partial fill → remainder rests
      → cancel removes remaining
      → receipt { fills, remaining, settlement_delta, new_root }
```

Phase 1 supports **limit, cancel, partial fill** only.

### What we will not silently copy from dYdX

Best-effort cancels as the product guarantee; N+1 activation; “the proposer’s tape is the book.”

---

## 6. Consensus lifecycle

Malachite round, as we intend to use it:

```text
Finalize(h-1) → StartHeight(h, HeightParams)
  StartedRound
  if proposer:
      GetValue → PSE already has S[t] + I
               → build Value (commitments)
               → reuse stored Value if (h, round) rebuilt after crash
               → stream public parts; stream private fragments on DA channel
  else:
      receive parts / fragments
  Validate:
      public checks always
      private F if view suffices
      else InsufficientView → prevote nil (ADR 0005)
  Prevote / Precommit
  Decide → persist; do not treat as “S is valid” without view or π
  Finalize → evidence; next HeightParams
```

Late joiners: public value-sync (Malachite). Private fragment sync is Q-DA-2.

**What must be consensus-critical (working list):** parent, height, suite, `C` previous/next, input commitment, settlement commitment or body, DA commitment, (later) proof commitment.

**What can be asynchronous:** ZK proofs; archival replication; participant openings; indexer streams.

**What validators must have before voting:** public `Value` + required fragments or `π` (ADR 0005).

**What can arrive after finality:** `π` (if we accept the security hole — §11, Q-PRF-2); user openings.

**Slashable/detectable (detectable first):** equivocation (Malachite evidence); signing two values; proposing a value without publishing required fragments (detectable if peers log the miss). Slashing policy is not designed.

**Invalid proposer + unavailable private state:** honest nodes do not prevote. Liveness depends on a later honest proposer. If they prevote anyway, we have finalized a hostage.

---

## 7. Disclosure model

See [`docs/privacy-model.md`](../privacy-model.md).

Capabilities: `FULL_VIEW`, `TRADING_VIEW`, `COMPLIANCE_VIEW`, `SETTLEMENT_VIEW`, `PUBLIC_VIEW`.

Different validators **may** have different plaintext. That is a consensus problem. We model it as `Validate → Valid | Invalid | InsufficientView`. We do not assume a crypto workaround.

Arc APS is a different model (shared plaintext in enclaves). We do not inherit it.

---

## 8. Recovery model

| Event | Intent |
|---|---|
| Process crash mid-match | WAL of accepted inputs; replay `F` → identical root |
| Crash after decide, before app persist | Malachite WAL + app must not ack decide until persist policy is defined (copy Arc persistence-backpressure idea) |
| Corrupted local store | Authenticated encryption / MAC; refuse to run on auth failure |
| Lost capability key | Cannot read old fragments; may still verify `C` + later `π` |
| Validator never had fragments | Cannot reconstruct plaintext; must not invent it |
| Late join | Public sync yes; private sync only if policy allows (open) |

Malachite WAL does **not** store the book. Application WAL does.

---

## 9. EVM integration model

[ADR 0004](../adr/0004-evm-settlement-model.md):

- Book is native.
- Public balances are EVM-canonical.
- A height applies `SettlementDelta` through a privileged system path, atomically with the decided value.
- Reservations (later) lock public balances before risky resting orders.
- Reth is a sidecar; Engine API is an adapter.
- revm is for tests and future proof guests.
- Not an ExEx CLOB.

M5 applies that delta through `evm-adapter` (privileged batch, separate apply log). Live Reth/MDBX is not shipped. `evm_state_root` is not yet in Malachite `id(v)`.

---

## 10. PQ migration model

[`docs/post-quantum.md`](../post-quantum.md).

Versioned `CryptoSuite`. Phase 0 classical. Later hybrid (ML-KEM on confidentiality; ML-DSA or SLH-DSA on long-lived auth). Consensus votes today would be Ed25519-class if we used Malachite defaults — linear in validator count; PQ makes that worse; no FIPS aggregate signatures.

Proof wraps (Groth16/BN254) stay classical unless we verify hash-based receipts on the consensus path.

We will not call the chain post-quantum secure while consensus, libp2p, and proof wraps remain classical.

---

## 11. Major unresolved research questions

Load-bearing (full list in [`open-questions.md`](../open-questions.md)):

1. **Q-CONS-3.** Can unequal-view validators implement identical `valid(v)` without `π`? **No** (ADR 0008).
2. **Q-PRF-2.** Finalized but unprovable transition. Malachite cannot roll back. Options: inert settlement until `π`; optimistic + challenge (needs public data watchers — conflicts with privacy); slash-only (bond may be &lt; harm); refuse to finalize without `π` (kills sub-second target). **Do not hand-wave.**
3. **Q-DA-2.** Historical private recovery without extra disclosure.
4. **Q-SET-1.** Double-spend across EVM mempool and native fills.
5. **Q-CLOB-1.** Model I vs II vs III. Model I holds among `FULL_VIEW` replicas only (ADR 0008).
6. **Q-DIS-1.** Capabilities as crypto vs labels on a replica.
7. **Q-CRY-2 / Q-CLOB-2.** Commitment cost and book data structures — measure.

### Asynchronous proof security (required analysis)

If we finalize `C'` in &lt;500 ms and prove later:

| If `π` never arrives or is invalid | Consequence |
|---|---|
| Treat state as final anyway | Verifiability invariant **fails** |
| Roll back the height | Contradicts Tendermint instant finality; every downstream consumer must handle reorgs we promised not to have |
| Slash proposer / prover | Does not un-fill a trade; may be economically inadequate |
| Freeze settlement (`Δ` inert) until `π` | Money safe; sub-second **economic** finality is false (only commitment-final) |
| Challenge period | Needs watchers who can re-execute — they need data. Privacy fights this |
| Prover quorum attestations without a proof | Not validity |
| Lightweight sync checks + async comprehensive `π` | Sync checks must be specified; if they need plaintext, we are back to Q-CONS-3 |

**Research default (M6b, ADR 0011):** fast path finalizes the **commitment**; **external settlement is inert until a proof or a full-view re-execution certificate**. That means “sub-second finality” is **ordering finality**, not “funds are movable on Ethereum tooling in 500 ms,” until proven otherwise. Implemented in `crates/proof-adapter`. M5 `AtomicApply` still exists for sidecar atomicity tests; the gate sits in front of it.

This default is also the alignment with Vitalik’s 2030 [cryptographic world computer](../research/vitalik-cryptographic-world-computer.md): L1-class **validity** is SNARK + public DA, not re-execution by an honest majority. A full-view committee (Q-CONS-4) is a product, not that endgame. Inclusion of `I` among M4a voters is shared-sequenced as a **research default** (ADR [0015](../adr/0015-sequenced-i.md)); the tape is a sealed replicated set (ADR [0016](../adr/0016-intent-set.md)) shared on localhost TCP (ADR [0017](../adr/0017-intent-gossip.md)). Not WAN. Not FOCIL. Malachite proposer rotation is not FOCIL.

---

## 12. Expected bottlenecks

| Bottleneck | Why |
|---|---|
| Incremental `C` over a large book | Naive Merkle rebuild per height will miss 100k/s |
| WAL fsync | Durability vs order/s |
| Gossip of votes at 100 validators, worse with PQ sigs | Bandwidth |
| Private fragment fanout | DA × disclosure |
| `TimeoutPropose` while building mixed payloads | Arc already budgets this |
| EVM trie updates if we accidentally settle per order | ADR 0004 exists to prevent this |
| Proof generation | Seconds-to-minutes class for non-trivial zkVM programs (vendor; unverified) |
| Disclosure crypto (if we encrypt per-capability) | CPU + key distribution |
| libp2p gossipsub under flood | Known backpressure limits |

---

## 13. Security risks

See [`docs/threat-model.md`](../threat-model.md). Highest design risks:

1. Treating `Decide(C')` as `Decide(S')`.
2. Voting without fragments (`E` in the DA alternatives).
3. Async `π` failure after users have spent `Δ`.
4. Metadata leakage presented as “private CLOB.”
5. Proposer omission/MEV if `I` is not shared.
6. System-contract minter if settlement apply is key-held rather than pure.
7. PQ downgrade if suite IDs are missing.
8. Host RAM inspection (out of scope, still real).
9. Inconsistent capability assignment (two “compliance” keys that open different fields).
10. Determinism bugs (iteration order, time, threads) — silent safety failure.

---

## 14. Benchmark plan

[`docs/performance.md`](../performance.md).

Phase 1: structure bake-off + match latency percentiles + root cost.  
Phase 2: four-node determinism under delay/crash (correctness) plus WAL p99.  
Phase 4: finality vs `n` and value size; transport bake-off.  
Phase 5: EVM apply isolated.  
Phase 6: two proving stacks, same circuit/program.  
Phase 7: signature/KEM sizes and verify/s.

No averages-only reports. No “we are faster than X” without workload and hardware.

---

## 15. Recommended first implementation milestone

**Do not start the blockchain.**

After this research package is reviewed, implement **Milestone M1** only:

> Standalone Rust crate: deterministic in-memory CLOB  
> limit orders, cancel, partial fills, price/time FIFO, fixed-point, canonical serialization, receipts, a state commitment, replay tests, microbenchmarks.

Out of scope for M1: networking, Malachite, Reth, encryption, ZK, PQ, RFQ, auctions, compliance engine.

Success criteria:

- identical `(S, I)` → byte-identical root, fills, delta
- no floats in consensus-critical paths
- p50/p95/p99/p99.9 published for insert/match/cancel on a documented machine
- at least two candidate book structures measured

Then M2 (four-node identical-input replica + WAL), then M3 (unequal views). Those are where the architecture can fail. That is the point.

---

## Workspace (refined, still mutable)

```text
/crates
    protocol-types      # orders, deltas, ids, suite ids
    crypto              # CryptoSuite traits; no invented primitives
    commitments         # Commit(S) abstraction
    private-state-engine
    clob                # may start as a module of PSE
    disclosure          # views; Phase 3
    settlement          # SettlementDelta types
    evm-adapter         # Phase 5
    tiny-f              # Phase 6 fragment of F
    proof-adapter       # Phase 6 settlement gate
    proof-plonky3       # Phase 6 Plonky3 AIR
    consensus-adapter   # Malachite AppMsg; Phase 4
    execution-port      # Propose/Validate/Finalize
    da                  # Phase 4
    storage             # WAL trait; Phase 2
    networking          # extra channels; Phase 4
    node                # late
    rpc                 # late; no plaintext logs
/benchmarks
/docs                   # this tree
/tests
    integration
    adversarial
    deterministic-replay
```

Do not create empty crate stubs until M1 starts. Docs-only is the correct Phase 0 tree.

---

## Invariants (how we will know we are lying)

| Invariant | How it can fail in this design |
|---|---|
| Safety | We vote on `C'` we cannot validate |
| Determinism | Hidden time / hashmap iteration / threads in `F` |
| Privacy | Metadata, logs, public `Δ` |
| Recoverability | Accepted order only in RAM; or recovery requires unauthorized plaintext |
| Verifiability | Async `π` never arrives |
| Crypto agility | Hard-coded Ed25519 in `Value` |
| EVM compatibility | We force orders through Solidity, or we ship a mirror that lies |
