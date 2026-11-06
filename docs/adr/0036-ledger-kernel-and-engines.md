# ADR 0036 — A ledger kernel with pluggable engines

**Status:** Proposed (design only; nothing implemented)  
**Date:** 2026-10-26  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0001](0001-protocol-boundaries.md) (seven subsystems), [0004](0004-evm-settlement-model.md) / [0010](0010-m5-privileged-apply.md) (settlement ledger), [0006](0006-m1-clob-invariants.md) (CLOB), [0024](0024-sha256-c-prime.md) / [0032](0032-lazy-c-prime-and-guest-hashing.md) (`C'`), [0025](0025-pi-of-f-on-zkvm.md) (`π` of `F`), [0033](0033-signed-orders.md) (accounts are keys), [0035](0035-clob-as-l2-over-malachite.md) (private L2 over a commitment-only L1).  
**Would change:** what `F` is, where holdings live, what a transaction is, and what counts as protocol versus application.

## Context

The target is the internal ledger of an institution: sub-accounting, an on-chain fund, a transfer agent, an omnibus model. It needs high throughput, privacy, selective disclosure, and the usual blockchain properties: censorship resistance, no single trusted operator, and verifiable state.

The prototype grew around one application, a CLOB, so `F` *is* the matcher:

- `Input` has three variants: `Place`, `Cancel`, `AdvanceHeight` (`protocol-types`).
- `clob::Engine` owns everything committed: instruments, books, per-owner nonces, resting orders.
- **Holdings are not in `F`.** Fills emit `SettlementDelta`s, which a separate privileged ledger applies afterwards (`evm-adapter/src/ledger.rs`, ADRs 0004 / 0010). That ledger is outside `π`, and it can reject a batch with `InsufficientBalance` *after* matching. The matcher never checks that a trader can pay.
- ADR 0004 makes public EVM balances canonical for money, so holdings are not private.

An institutional ledger has many transaction types (transfers, issuance, subscriptions, redemptions, allocations, corporate actions, trades). They share one set of holdings and one set of rules about who may move what. Adding each as another `Input` variant inside the matcher would not scale, and would leave conservation and authorization to each feature's own code.

## Decision (proposed)

Split `F` into a **ledger kernel** and **engines**.

- **The kernel** owns accounts, assets, holdings, holds, nonces, transfer policy and the state commitment. It enforces the invariants that must hold whatever engine ran.
- **An engine** owns one business process: its transaction types, its validity rules and its private state. It changes holdings only by asking the kernel to apply postings.

Both compile into one deterministic `F`. It runs natively in every operator node and unchanged in the zkVM guest.

```text
           Tx (signed envelope)
                  │
        ┌─────────▼──────────┐
        │  kernel: admit     │  signature, nonce, account status
        └─────────┬──────────┘
                  │ route by engine id
   ┌──────────┬───┴──────┬───────────┬──────────┐
   │ transfer │ registry │ fund      │ clob     │  … engines
   └────┬─────┴────┬─────┴─────┬─────┴────┬─────┘
        │  postings, holds, engine-state writes
        ┌─────────▼──────────┐
        │  kernel: apply     │  balance, authorize, policy, commit
        └─────────┬──────────┘
                  ▼
        state root, receipt (→ batch header, ADR 0035)
```

### 1. Kernel state

| Object | Fields (first cut) | Notes |
|---|---|---|
| Account | `id`, `parent`, `controller`, `status` | Hierarchical: an omnibus account has sub-accounts. `controller` is a key set with a threshold. A "key account" with `id = owner_of(pk)` (ADR 0033) is the one-key special case. |
| Asset | `id`, `issuer`, `scale`, `policy` | The issuer account holds the issuance balance (§2). |
| Holding | `(account, asset) → u128` | Stored at leaf accounts only. A parent's position is the sum of its subtree (§6). |
| Hold | `id`, `account`, `asset`, `amount`, `owner_engine`, `expiry` | An encumbrance. `available = holding − Σ holds`. |
| Nonce | `account → u64` | Moves out of the CLOB into the kernel. |
| Policy | per-asset transfer rules, per-account attributes | Data, not code (§5). |

### 2. Invariants the kernel enforces

Each one holds no matter which engine produced the postings.

1. **Conservation.** A transaction's postings sum to zero per asset. Issuance is no exception: minting debits the asset's issuance account, which alone may go negative. Total supply is minus that balance.
2. **No overdraft.** Outside issuance accounts, a debit may not exceed `available`.
3. **Authorization.** Every debit from an account needs one of:
   - a signature by that account's controller on this transaction
   - a hold, created by a transaction the controller signed, being consumed (this is how a resting order settles when it is filled)
   - a role the asset policy grants (for example the issuer's registrar performing a forced transfer, or a corporate action)
4. **Policy.** Every posting passes the asset's transfer policy (§5).
5. **Atomicity.** A transaction applies all its postings, holds and engine-state writes, or none of them. The kernel journals writes and rolls back on reject.
6. **Replay.** Each signed transaction consumes the signer's next nonce.
7. **Determinism.** No clock, randomness, I/O or iteration-order dependence. Time is the `Tick` system input (§4).

### 3. Engine interface

```rust
pub trait Engine {
    const ID: EngineId;
    type Tx: CanonicalDecode;

    /// Apply one admitted transaction. All effects go through `ctx`.
    fn apply(&mut self, tx: &Self::Tx, ctx: &mut LedgerCtx) -> Result<Receipt, Reject>;

    /// System time advanced (expiries, accruals, scheduled actions).
    fn on_tick(&mut self, now: Tick, ctx: &mut LedgerCtx) -> Result<(), Reject>;

    /// This engine's state commitment (a `C'` treap root).
    fn root(&self) -> StateRoot;
}

// LedgerCtx gives an engine:
//   signer(), now()
//   available(account, asset), account(id), attributes(account)
//   hold(account, asset, amount, expiry) -> HoldId;  release(HoldId)
//   post(&[Posting]) -> Result<(), PostingError>   // checked against §2 immediately
//   (engines keep their own private state themselves and commit it in root())
```

An engine never writes holdings. It cannot see another engine's state; cross-engine effects go through postings and holds.

### 4. Transactions

```text
Tx { engine: EngineId, body: bytes, signer: AccountId, nonce: u64, auth: Auth }
```

- `auth` is the ADR 0033 suite signature, extended to threshold controllers.
- The kernel admits the transaction (signature, nonce, account status), then decodes `body` with the named engine's `Tx` type.
- **System inputs** are not client transactions:
  - `Tick { now }`, inserted by the sequencer once per batch. It replaces `AdvanceHeight` and closes the gap recorded in ADR 0033: order expiry under consensus.
  - Bridge deposits from L1, inserted when L1 finalizes them.

### 5. Policy

Transfer policy is data that the kernel interprets, not engine code. A first rule set:

- holder allowlists or required account attributes (an eligibility credential, a jurisdiction)
- lockups until a tick
- maximum holder count
- a frozen flag per account or per asset

Attributes are written by an attestation engine, signed by whoever the asset policy names. Expressive policies (rules that need computation) are an open question (§ Open questions).

### 6. Commitment

```text
state_root = H("plx/ledger/v1" ‖ kernel_root ‖ engines_root)
kernel_root  = H(accounts ‖ assets ‖ holdings ‖ holds ‖ nonces ‖ policy)   each a C' treap
engines_root = treap over EngineId → Engine::root()
```

- `holdings` is a **sum-annotated treap**: each node also commits the per-asset sum of its subtree, and the key order puts sub-accounts under their parent. One opening then proves:
  - a single holding
  - an omnibus total, without revealing the sub-accounts under it
  - total supply
  
  This is the main disclosure primitive for omnibus and fund reporting.
- Receipts (outcome, postings, events) fold into a per-batch receipt root, as today.

### 7. Protocol versus engine

| Protocol (this repository's core) | Engines (business logic) |
|---|---|
| Kernel state, invariants, policy interpreter, commitment | Transaction types and their validity |
| Execution harness: routing, journaling, `Tick`, native plus guest | Engine-private state and its root |
| Admission: accounts, signatures, nonces (ADR 0033) | Matching, NAV application, allocation, entitlement maths |
| Sequencing among operators (ADRs 0016–0027) | Which postings and holds to request |
| L1 settlement, dispute game, `π` (ADRs 0025, 0031, 0035) | |
| Disclosure: envelopes, openings, proofs of facts (ADR 0035 §5) | |
| Crypto suites (ADRs 0030, 0034); WAL, snapshots, DA | |

The kernel contains bugs in an engine: a faulty engine can reject or mis-price its own transactions, but it cannot create assets, overdraw, or move an account's holdings without that account's authorization.

### 8. Engine lifecycle

- The engine set is part of `F`, so **adding or changing an engine is a protocol upgrade**: a new `F` version, a new guest image ID, activation at an L1-agreed batch height, with a state migration where needed.
- The first cut is a fixed, reviewed engine set. User-deployed engines (WASM, or zkVM programs) are deferred (see Alternatives).

### 9. First engines

| Engine | Transactions | Uses |
|---|---|---|
| `transfer` | transfer, batch transfer | Postings |
| `registry` (transfer agent) | create asset, mint, burn, forced transfer, freeze | Issuance account, policy roles |
| `attest` | set and revoke account attributes | Policy inputs |
| `fund` | subscribe, redeem, strike NAV | Holds on cash at request; postings at the NAV strike |
| `clob` | place, cancel | A hold on the sell side at place; postings per fill, consuming the holds |

`clob` is ported, not rewritten. Its book, instruments and ids stay engine state. Nonces move to the kernel, and each fill becomes postings: four per fill (two assets times two sides), plus hold adjustments. That adds the pre-trade funds check the CLOB lacks today.

## Relation to existing decisions

- **ADR 0001.** The seven subsystems stand. The kernel and engines sit inside "execution validity".
- **ADR 0004 / 0010.** These are superseded for private holdings. Holdings become kernel state inside `F` and inside `π`, private by default. The EVM sidecar becomes a **bridge**: deposits and withdrawals are postings to and from a bridge account, and are the only point where balances become public.
- **ADR 0035.** The L2 executes the ledger, not just the CLOB. Batch headers, the dispute game, DA and disclosure apply unchanged. The stateless chunk guest has to cover kernel reads (holdings, holds, nonces, policy) as well as engine reads.
- **ADR 0033.** An account becomes an identity with a controller. Key-hash accounts remain the simple case. Key rotation and threshold control become possible.

## Alternatives considered

| Alternative | Why not the default |
|---|---|
| Keep `F` as the CLOB and add `Input` variants per feature | No shared invariants; every feature reimplements conservation and authorization |
| General smart-contract VM (EVM, WASM) as `F` | Flexible, but slower natively, far more expensive to prove, and conservation becomes a per-contract property. Possible later for user-defined engines |
| Module system without a kernel (Cosmos SDK style, each module owns its balances) | Cross-module conservation and authorization are not enforced in one place |
| Note/UTXO model (Zcash style) | Hides more, even from operators, but hierarchical accounts, omnibus reporting and corporate actions become very awkward. The account model keeps commitments and openings for privacy instead |
| Public EVM balances stay canonical (ADR 0004) | Holdings would be public, which contradicts the institutional privacy goal |

## Open questions

- **Account identity.** Assigned ids (creator plus nonce) or key-derived ids, rotation, recovery, threshold controllers.
- **Holds.** Partial consumption, expiry semantics, and whether engines may hold across engines (for example, a fund hold used as CLOB collateral).
- **Policy expressiveness.** Fixed rule set, or a small policy language. Expressive policies must stay cheap in the guest.
- **Sum-treap cost.** Extra hashing per holding update, natively and in the zkVM. Measure against the ~16 K cycles per event of ADR 0032.
- **Numeric model.** `u128` amounts with an asset `scale`; rounding rules for NAV, pro rata and entitlements, which must be deterministic and documented per engine.
- **One ledger per institution, or shared.** Separate L2s per institution make cross-institution delivery versus payment an L1 protocol (atomic across two batches). A shared ledger makes it a single transaction but enlarges the operator perimeter.
- **Fees.** Whether there is a fee asset, and who pays for system inputs.
- **Storage.** Fully in memory first, with disk-backed `C'` nodes once state outgrows memory.

## Consequences if accepted

- `F` becomes an institutional ledger, and the CLOB becomes one engine.
- Conservation, authorization, the funds check and policy are proven with everything else in `π` and covered by fraud proofs, instead of living in a separate unproven settlement ledger.
- Holdings become private, and become disclosable per account or per subtree.
- Expected cost: per-transaction kernel work (signature already exists; plus postings, holds and sum-treap updates). Target: native CLOB throughput within 2× of today. Guest cycles per fill to be measured.
- New engineering: the kernel crate, the engine trait and harness, the CLOB port, the sum-treap, the policy interpreter, the bridge, migrations, and the guest changes.

## Staged path

1. Kernel crate with accounts, assets, holdings, holds, nonces and the invariants; `transfer` and `registry` engines; native only.
2. Port the CLOB onto the kernel. Run the existing CLOB test suites through it; matching results must be unchanged apart from rejected unfunded orders.
3. Guest: compile the kernel plus engines; measure cycles per transfer and per fill.
4. Bridge replaces the privileged settlement apply.
5. `fund` and `attest` engines; sum-annotated holdings and disclosure openings.

## Reversibility

Reversible up to step 4. Until the bridge replaces the settlement ledger, the kernel can run beside today's path and be dropped.
