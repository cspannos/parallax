# ADR 0015 — Shared sequenced `I` (Q-CONS-10)

**Status:** Accepted as the **research default for inclusion of `I`**, not the product  
**Date:** 2026-10-02  
**Deciders:** Protocol architecture (research prototype)  
**Does not implement:** a mempool, FOCIL, or any inclusion gadget.

## Context

Malachite `GetValue` is one proposer per round. That proposer can omit, delay, or reorder intents it saw. For a CLOB, omission is **time-priority fraud**, not only censorship ([vitalik note](../research/vitalik-cryptographic-world-computer.md)). Q-CONS-10 asked: single proposer vs FOCIL-like forced inclusion vs shared sequenced `I`.

M4a (ADR 0009) is Model I among four `FULL_VIEW` voters: same `I`, same book, `Validate` replays `F`. The loaded bench already supplies the same tape to every replica **out of band**. When that tape is local at `StartedRound`, speculate overlaps GetValue and voter `F`. Cluster **~0.17–0.18 s** / ~55k ev/s at 8k+10k ([m4-loaded-isolate.md](../benchmarks/m4-loaded-isolate.md)). If `I` is unknown until the proposal, those `F`s are serial (~0.53 s before later `C'` cuts).

Malachite proposer **rotation is not FOCIL**. It does not guarantee inclusion. dYdX Model II (proposer match tape, divergent books) is a different machine (ADR 0003). This ADR does not pick Model II.

## Decision

**Research default:** among the M4a voting set, `I` is a **shared sequenced tape** available to every honest voter **before** `GetValue`. `GetValue` commits to that `I` (`input_commitment`). It does not choose a private subset as the protocol path.

StartedRound speculate (scratch-apply local `I`) is licensed only under this default. `Validate` remains an execution vote (ADR 0009 / Q-CONS-2): `id(v)` must match `F(S, I)`. Missing `I` is still `InsufficientView` → prevote nil (ADR 0005).

**Not in this ADR:**

- A mempool, gossip topic, or sequencer implementation.
- FOCIL, threshold inclusion, or any forced-inclusion gadget.
- Encryption / selective disclosure of `I` (Q-DIS, Q-CONS-8).
- Model II (proposer-authored match tape) or Model III (`π` of `F`). Those stay Q-CLOB-1 / Q-PRF-6.

**How the tape is produced (first cut):** ADR [0016](0016-intent-set.md) — replicated intent **set**, sealed at height start, canonical `(owner, nonce, kind, id)` order. Tests still inject the same set to every replica. Gossip / WAN / FOCIL remain remainder. The loaded cell is still a Model I bound, not a production mempool.

If a later ADR picks **proposer-packed `I`**, document time-priority fraud as dYdX did. Do not keep speculate-as-product. Expected height returns to serial `F`s.

## Alternatives

| Option | Why not as this default |
|---|---|
| Proposer-packed `I` (Malachite stock) | Time-priority fraud; serial `F`s; the 0.18 s cell is a lie |
| FOCIL-like gadget now | Unspecified protocol; not measured; not “rotation = inclusion” |
| Model II match tape | Divergent books; contradicts M4a Model I (ADR 0003 / 0009) |
| Close Q-CONS-10 as “we have a mempool” | We do not |

## Consequences

Docs and benches that cite ~0.18 s / ~55k ev/s must say **shared `I`**. Adapter `speculate` stays. Product inclusion work is a new protocol, not another `F` cut.

Q-CLOB-1 (Model I vs II vs III) is **not** closed. This ADR only says: if we stay Model I among `FULL_VIEW` voters, inclusion of `I` is shared-sequenced, not proposer-packed.

## Security implications

A Byzantine proposer cannot silently drop an intent that is already on the shared tape and still collect honest prevotes for a different `input_commitment`. It can still refuse to propose (liveness / timeout → next proposer). A Byzantine **majority of the inclusion path** (once one exists) can still censor. FOCIL-class guarantees are **not** claimed.

Withholding the shared tape from one voter is the same as withholding `I` today: that voter nils.

## Performance implications

Shared `I` is a TPS assumption, not a free lunch. Measured n=4 localhost: one `F` of wall time + floor + persist ≈ **0.17–0.18 s**. Proposer-packed `I` does not get that. Engine `F` of the same tape is ~85–102 ms ([loaded-batch.md](../benchmarks/loaded-batch.md)).

## Reversibility

High until a mempool or inclusion gadget ships. Switching the research default to proposer-packed `I` is a new ADR and invalidates the shared-`I` height numbers. Adding FOCIL later does not contradict this default (it is one way to *produce* a shared tape).
