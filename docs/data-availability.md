# Data Availability

**Status:** Living document  
**Date:** 2026-09-25  
**Normative decisions:** [ADR 0005](adr/0005-data-availability-model.md)

## Definition

A byte string `B` is **available to party P** if P can obtain `B` (or a reconstructable encoding of `B`) against the protocol’s failure model, without P being granted a disclosure capability P does not hold.

Availability is not:

- “a commitment to `B` was finalized”
- “someone encrypted `B`”
- “a proof exists that `B` was computed”

## Tiers (summary)

| Tier | Audience | Contents | Failure |
|---|---|---|---|
| Public | Anyone | Headers, commitments, public txs, certificates, proofs | Public audit fails |
| Validator | Consensus set (possibly partitioned by capability) | Fragments required to `Validate` or recover | Height not honestly votable |
| Participant | Entitled users | Own openings / receipts | User cannot self-verify |
| Archival | Designated stores | Encrypted history | Compliance / dispute, not tip safety |

## What we reuse

- **Malachite value-sync:** decided public values + certificates. Not private DA.
- **Arc follow mode / snapshots:** operational ideas for public state. Not adopted yet.
- **External DA L1s:** not used. Public, extra trust, extra latency. Reconsider only for the public tier.

## Prototype implementation intent

Phase 2 (done): every node stores the full plaintext locally (no real confidentiality). DA = “the other three processes have the same WAL.” That is replica agreement, not a DA protocol.

Phase 3 (done): nodes are **authorized** only for their view (labels on a projector). DA of withheld plaintext is not provided; they must not prevote execution validity (ADR 0008).

Phase 4: proposer must publish validator-required fragments on a non-consensus channel before honest prevote.

## Recovery without unauthorized disclosure

Q-DA-2 is open. Candidate directions (none selected):

- Re-encrypt historical fragments to the joining validator’s current capability (requires a party that already has the plaintext or a threshold of shares).
- Threshold secret sharing of a height key (VSS); recovery is a distributed protocol, not a file copy.
- Deny joiners historical private plaintext; they verify only `C` + later `π` (weak recoverability for private fields).

Each option attacks a different invariant. Write an ADR before implementing any of them.
