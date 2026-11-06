# Vitalik, 2026: “The cryptographic world computer”

**Source:** [The cryptographic world computer](https://vitalik.eth.limo/general/2026/09/27/the_cryptographic_world_computer.html) (2026-09-27)  
**Date read:** 2026-09-30  
**Purpose:** Digest the argument, score Parallax against it, and list adaptations. This is not an instruction to become Ethereum, and it does not license treating unsolved Parallax problems as solved.

---

## 1. Digest

The post’s claim is that calling 2030 Ethereum “a blockchain” is mostly historical. Bitcoin-era systems are: user → public mempool → one miner → everyone downloads and re-executes. The thing Ethereum is moving toward is a **hybrid of Satoshian ideas and post-2009 cryptography**.

Three substitutions do most of the work:

| Then | 2030 |
|---|---|
| Verify by re-download + re-execute | Verify a **SNARK** + sample data with **PeerDAS** |
| PoW canonical chain | **PoS**, few-slot finality, an *available* chain |
| One miner builds the block | **Multi-party** block construction (builders, FOCIL inclusion) |

Authorization is no longer “an ECDSA signature on a tx.” It is sometimes a **quantum-safe signature** (or several), sometimes a **ZK proof**. Signatures and proofs are meant to be **stripped and aggregated in the mempool**, before the canonical block. Computation is **parallel where the algebra allows**; gas should punish inscrutable serial blobs.

The application-structure punchline (the sentence that maps onto Parallax most cleanly):

> perhaps in the long run, we will converge toward programming patterns where information directly related to describing **non-commutative state changes and ordering** is posted onchain, and **everything else is aggregated before it even gets included into a block**.

Light clients stop trusting an honest majority for *validity*. They check consensus **and** validity (compute + DA). Privacy of writes and of account policy moves to ZK (+ private account abstraction). Privacy of reads is either a light full node (SNARKs make that cheaper) or **PIR / TEE+ORAM**. Network privacy is onion routing / mixnets, not “hope the mempool is honest.”

User-visible Ethereum 2030 tradeoffs he is willing to own:

- Still: uptime, inclusion (stronger with FOCIL), rule-following execution, irreversibility
- Latency: **~4–8 s slots, ~8–32 s finality** — explicitly **not** server latency
- General-purpose compute stays expensive; **specialized** compute can be cheap
- Node requirements drop because verification is a proof, not a replay

Decentralization is recast as sometimes a *performance* feature: parallel storage, parallel mempool proving/verification, and **metadata hiding that only a decentralized network can do**. The 2010s “split the work” dream failed because **verification** was missing. Random committees were slow and had no recourse on failure. SNARKs are the recourse.

There is a second architectural sentence that matters as much as SNARKs:

> creating a stronger decentralized layer in the middle between users and a chain, **that is not itself a chain**, could make Ethereum very powerful without compromising any of the chain’s fundamental properties.

Ethereum L1 will not compete with servers on latency; **infrastructure around it could**. Indistinguishability obfuscation is named as a later holy grail (privacy × general computation). He says the rest of the essay holds **before** iO exists. Do not design Parallax around iO.

After Hegota, Ethereum’s primary story is recursive STARKs, formal verification, optimized consensus, quantum-safe primitives. PeerDAS is already the start of “not just a blockchain.”

---

## 2. Alignment scorecard

Legend: **aligned** = we already chose this direction; **partial** = same slogan, weaker or delayed mechanism; **divergent** = different product or a real tension; **gap** = he treats it as load-bearing and we barely specified it.

### 2.1 Strongly aligned

**Specialized vs general-purpose compute.**  
His table: general-purpose stays costly; specialized applications can have “very strong privacy” and lower overhead. Our split — native CLOB / PSE for non-commutative matching, Reth for general EVM settlement — is the same idea. Putting 100k order events through Solidity would be the 2015 “dump computation on the ledger” anti-pattern he is retiring.

**On-chain = ordering + non-commutative deltas; aggregate the rest first.**  
Matching *is* non-commutative (price-time). Settlement deltas *are* the on-chain commutative-ish money effect. Intent signatures, compliance proofs, and (later) validity proofs belong in the pre-block layer. [ADR 0001](../adr/0001-protocol-boundaries.md) and [ADR 0004](../adr/0004-evm-settlement-model.md) already say this. This is the deepest alignment. Do not “adapt” by moving the book into the EVM.

**Consensus object is not the full replay transcript.**  
We vote on `C, Δ, …`, not the book. He verifies a SNARK of the transition, not the transition’s witness. Same *shape*: the chain stores a compact claim.

**PQ-ready authorization is first-class.**  
He: “sometimes quantum-safe signature (or several).” We: versioned `CryptoSuite`, NIST FIPS 203/204/205 as the menu ([docs/post-quantum.md](../post-quantum.md)). We are at least as explicit; we still must not claim “PQ secure.”

**Privacy of writes is a protocol property, not an honest-mempool hope.**  
Both reject 2010 “the graph cannot be analyzed.” We go further in one respect (capability views among *validators*) and further behind in another (no mixnet, no PIR). See gaps.

**Light-client *intent*:** independent verification of validity, not just “the validators voted.”  
Our verifiability invariant is the same sentence. Our mechanism is not.

### 2.2 Partial — same words, different security object

**SNARK verification instead of re-execute.**  
Ethereum 2030: the canonical validity check *is* the proof (+ DAS). Honest majority is not required for validity.

Parallax: Model III (`C, C', Δ, π`) is Phase 6. Phases 1–4 still assume replicas **re-execute** `F` if they have the view. Async `π` after Malachite decide is closer to **2020 optimistic / delayed-validity** than to 2030 validity. We already documented that this breaks the verifiability invariant if `π` never arrives ([initial-design §11](../architecture/initial-design.md)).

Vitalik’s missing-ingredient paragraph is aimed at us: **committees without a proof have no recourse if they fail.** Our Phase 3 fallback “full-view committee is the safety set” (Q-CONS-4) is exactly the 2010s patch he says did not work — except we might accept it for a *permissioned* financial network. That is a product choice, not an alignment.

**Data availability.**  
He: PeerDAS — public sampling of public (or at least uniformly encoded) data.  
We: [ADR 0005](../adr/0005-data-availability-model.md) — no DA L1; capability-partitioned fragments; honest `InsufficientView`.  

Sampling public blobs is **not** selective disclosure. DAS of ciphertext proves “bytes exist,” not “the matching predicate holds,” and it **publishes metadata**. We were right not to bolt on Celestia. We were incomplete in not specifying a *sampling / encoding* argument even for the **public** tier (commitments, proofs, certificates).

**Privacy of reads.**  
He: cheap full node via SNARKs, or PIR / TEE+ORAM.  
We: participant openings (Q-DA-3). Query privacy (the fact that you asked for *this* order) is missing.

**Mempool aggregation.**  
He: strip signatures/proofs early; aggregate; parallelize in the mempool.  
We: private intent channels, unspecified aggregation. Malachite `GetValue` still assumes the proposer *builds a value* from whatever it has. That is still one-builder-shaped.

### 2.3 Divergent — different machine

**Latency and what “the chain” is.**  
His L1: 4–8 s / 8–32 s. He says L1 will **never** match servers; a **non-chain** middle layer might.

Our research target: **&lt;500 ms BFT** plus in-memory matching. That is not Ethereum 2030. It is closer to the **middle layer** he describes — except we currently plan to *be* an L1 with Malachite instant finality. Instant BFT finality of a commitment is not the same as his “economic + validity + DAS” finality.

This is useful, not embarrassing, if we say it: **Parallax is not a cryptographic world computer. It may be a specialized financial computer whose public settlement/proofs could one day plug into one.**

**Block construction authority.**  
He: multi-party, FOCIL for *guaranteed inclusion*.  
We: Tendermint **single proposer per round**. Q-CONS already notes proposer omission. For a CLOB, omission is not just censorship; it is **time-priority fraud**. dYdX Model II makes that explicit. We have no FOCIL analogue.

**Consensus family.**  
Public optimized PoS + available chain vs permissioned Malachite BFT. Fine for a prototype. Do not import Ethereum’s slot times in order to “align.”

**Validator disclosure.**  
Ethereum 2030 still assumes that *validity* is a **public** predicate (SNARK + DAS). Privacy is against the world, not “validator B must not learn price.” Our Phase 3 problem is **harder** than his privacy-of-writes row. APS-style “every validator decrypts” is closer to his model than ours. We should not pretend SNARK+DAS dissolves capability-partitioned *witnesses* unless the circuit’s public statement is exactly what `PUBLIC_VIEW` is allowed to learn.

**iO.**  
Ignore. He says so.

### 2.4 Gaps we under-specified

| Vitalik 2030 item | Parallax today |
|---|---|
| FOCIL / forced inclusion | Unspecified; proposer chooses `I` |
| Mixnets / onion routing | Q-DIS-5 “not Phase 1”; no design |
| PIR / private reads | Absent |
| PeerDAS-class *public* availability | Commitments only; no sampling story |
| Recursive STARK as the object light clients verify | Q-PRF-4; wrap-to-Groth16 temptation |
| Formal verification of `F` | Not in the roadmap |
| Parallel mempool proving | Proofs are Phase 6 and async |
| History/state sharding formats | Storage engine unchosen; no light-client store |

---

## 3. What to adapt (and what not to)

### Do not change

- **M1: standalone deterministic CLOB.** His “structure of computation” *endorses* keeping the serial matching core out of the general-purpose VM.
- **EVM as settlement, not the book.**
- **No public DA L1 just because PeerDAS exists.** PeerDAS is a *technique* for the public tier, not a reason to publish the book.
- **Sub-500 ms as a matching/preconfirmation target.** Do not slow down to 8–32 s to look like Ethereum. Do **name** that target correctly (below).
- **PQ agility and STARK-family preference for consensus-critical verify.** His 2030 stack is recursive STARKs + quantum-safe. That matches our existing warning: Groth16-BN254 wraps are not PQ-ready.

### Adapt the endgame wording (docs now, code later)

**A. Split “finality” into two properties we already suspected.**

| Property | Time | Mechanism |
|---|---|---|
| **Ordering / matching preconfirmation** | Sub-second (research) | PSE + (small-set) Malachite or even a non-BFT sequencer |
| **World-computer validity** | Proof latency | `π` + public DA of what `PUBLIC_VIEW` is allowed to have |

This is the honest reading of both his essay and our Q-PRF-2 / Q-PRF-3. Sub-second **economic** finality on EVM balances without `π` is the 2015 leftover. Our research default “settlement inert until proof or full-view certificate” is **more aligned with 2030 than “Malachite decide = money moved.”** Keep it. Say it in the architecture summary, not only in open questions.

**B. Treat Model III as the validity endgame, not an optional Phase 6 overlay.**

Phase 1–2 still re-execute (determinism harness). Phase 3 still *measures* unequal views. But we should stop describing “full-view committee” as a satisfactory long-term answer to Q-CONS-4. Vitalik’s review of sampled committees: complicated, latent, **no recourse on failure**. A permissioned full-view set is a *product* (APS-like, or a dark pool operator set). It is not a cryptographic world computer.

**C. Put multi-party inclusion on the research list.**

A CLOB whose `I` is “whatever this round’s proposer packed” is not FOCIL and is not price-time. Either:

- make `I` a shared sequenced intent log (Model I, hard under disclosure), or
- accept Model II and document MEV/censorship as dYdX did, or
- add an inclusion gadget (FOCIL-like, or threshold-sequenced intents) so time-priority cannot be silently dropped.

Do not implement this in M1. Do not pretend Malachite proposer rotation is FOCIL.

**D. Public-tier DA should become “commitments + proofs + a sampling story,” still not a DA chain.**

If light clients must verify validity without downloading private fragments, the *public* bytes (`C`, `Δ` commitment, `π`, certificates) need an availability argument stronger than “the four validators have a disk.” That can still be “validator-replicated public headers” at n=4. At n=100 it starts to look like DAS. Record as Q-DA-6.

**E. Network-layer privacy and private reads are in the 2030 privacy invariant.**

Payload encryption does not hide “who traded.” He is explicit that **only decentralized networks** help metadata. Upgrade Q-DIS-5 from a shrug. Add read privacy (PIR or equivalent) as Q-DIS-6. Neither blocks M1.

**F. Parallelize what is parallel; do not parallelize the book.**

Mempool: signature verify, proof verify, independent markets (if collateral is partitioned). Per-instrument price-time matching: serial. Gas/fee incentives for “one giant serial blob” are an EVM-side Phase 5 concern, not a CLOB concern.

**G. Formal verification of `F`.**

He lists it next to recursive STARKs. Our determinism tests are the cheap cousin. Add as a later companion to Phase 6, not a Phase 1 gate.

### Explicitly reject as adaptations

- Moving matching into Ethereum L1 or into revm “to be the world computer.”
- Waiting for iO.
- Replacing Malachite with Ethereum PoS to look current.
- Publishing the book to PeerDAS “for light clients.”
- Treating TEE+ORAM as our privacy answer (he offers it as a *read* option; we already refused enclaves as the *validator* model).

---

## 4. Mapping his 2010→2030 table onto Parallax

| Topic | His 2030 | Parallax research prototype | Fit |
|---|---|---|---|
| Authorization | PQ sig and/or ZK | Suite IDs; classical first; ZK later | Aligned direction |
| Canonical chain | PoS, few-slot, available | Malachite BFT, instant, availability open | Divergent family, similar “fast finality” *intent* |
| Verify blocks | SNARK + PeerDAS | Re-execute if view allows; `π` async | Partial / behind |
| Inclusion path | Private mempool → FOCIL/builder; aggregate | Private intents → single proposer | Gap |
| Computation | Parallel mempool; serial on-chain only for ordering | Serial matching; EVM settlement | Aligned structure |
| Client storage | Partial history, mixed formats | Unspecified | Gap |
| Light clients | Consensus **and** validity | Certificates; validity unsolved without `π` | Intent only |
| Privacy of writes | ZK | Capabilities + later ZK | Harder problem, weaker crypto so far |
| Account policy | ZK + private AA | Unspecified | Gap |
| Privacy of reads | Full node or PIR/ORAM | Openings, no PIR | Gap |
| Network privacy | Mixnets | Unspecified | Gap |

---

## 5. Guiding-question rewrite

Original:

> Can we build a Rust-native financial execution network in which Malachite provides deterministic BFT finality, a PSE processes high-frequency transitions, Reth provides EVM settlement, participants receive only authorized views, commitments allow agreement, and the crypto can migrate to PQ?

Vitalik’s essay suggests splitting that into two questions that we were conflating:

1. **Can the matching layer be fast, deterministic, and capability-partitioned?** (server-class latency; may look like his “not itself a chain” middle layer, even if we wrap it in Malachite for a small set.)
2. **Can the *public* settlement/commitment layer be verified like a 2030 world computer?** (SNARK of `F` on public statements + DA of public bytes + PQ-ready verify, without requiring every replica to hold TRADING_VIEW.)

If (1) requires (2) to be true in &lt;500 ms, we are fighting his latency table and our own proving-system survey at once. If (2) can trail (1) with inert `Δ`, we are aligned with both our Q-PRF-3 default and his “infrastructure around the chain.”

Do not optimize for making either answer yes. Phase 3 still has veto power over (1) under unequal views.

---

## 6. Doc / roadmap impact

| Action | Where |
|---|---|
| This note | `docs/research/vitalik-cryptographic-world-computer.md` |
| New questions | Q-CONS-10, Q-DA-6, Q-DIS-6, Q-PRF-6, Q-NET-5 |
| Endgame wording | `ARCHITECTURE.md`, initial-design §11 reminder |
| No ADR yet | No mechanism chosen (FOCIL, DAS, PIR, mixnet) |
| M1 unchanged | CLOB still first |

---

## 7. One-sentence verdict

Parallax is **aligned with the computational *structure* of the 2030 world computer** (specialized serial matching off the general VM; compact on-chain claims; PQ-ready *intent*) and **not yet aligned with its *verification* structure** (SNARK + public DAS as the validity predicate; multi-party inclusion; metadata-hiding networks). The useful adaptation is to **stop treating Malachite decide as world-computer validity**, and to **name the PSE as a low-latency middle layer** whose public `Δ` waits for a proof — not to abandon the CLOB or to become Ethereum.
