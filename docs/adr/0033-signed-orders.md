# ADR 0033 — Signed orders with suite-key accounts

**Status:** Accepted (research default for order authorization; opt-in via `ClusterSpec::with_signed_orders`)  
**Date:** 2026-10-25  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0030](0030-pq-hybrid-suites.md) (suites), [0031](0031-tiered-finality.md) (hybrid finality certificate), [0016](0016-intent-set.md) / [0021](0021-ack-id-set.md) (intent set and ACK admission).

## Context

Orders carried an `owner` but no signature: anyone who could reach a validator could place or cancel for any owner. Phase 7 listed account signatures as a remaining PQ gap.

## Decision

1. **An account is its key.** `OwnerId = SHA-256("plx/account/v1" ‖ encoded suite public key)` ([`order_auth.rs`](../../crates/consensus-adapter/src/order_auth.rs)).
   - No registry, and the id format is unchanged (32 bytes).
   - The encoding starts with the suite id, so a hybrid account and the classical key of the same Ed25519 secret are **different owners**. An account cannot be downgraded by relabelling its key.
2. **Place and Cancel carry `(public key, signature)`** over the input's canonical bytes (context `plx/order/v1`). The rules:
   - the key must hash to the order's owner
   - the signature must verify under the policy (e.g. hybrid only)
   - `AdvanceHeight` is a system input and needs none

   Replays are rejected by the engine's per-owner nonce (ADR 0026).
3. **Checked at admission, not in `π`.** Validators check signatures:
   - on local submit, in parallel off the app thread
   - on gossip ingest, where the per-connection verifier drains whatever has arrived (≤ 512 frames), verifies the batch on all cores, and forwards it **in arrival order**, so an ACK never overtakes the intents it covers

   Only valid intents enter the intent log. `I`, `F`, the snapshot and the guest are unchanged. Authorization is attested by the validators that admitted `I` and by the 2f+1 hybrid finality certificate (ADR 0031); it is not re-proven in the zkVM. Proving one ML-DSA verify per order would dwarf the ~16 K cycles per event of ADR 0032.
4. **Gossip** carries signed intents as `FRAME_SIGNED_INTENT` (`height ‖ input ‖ key ‖ signature`). The app keeps signatures by intent id so re-fans resend them, and drops them once the height decides.

## `AdvanceHeight` is never a client input (2026-10-25)

`AdvanceHeight` is a protocol input. Admission let it through unsigned, in every mode. A client could offer `AdvanceHeight { to: 10⁹ }`, which would expire every resting order with an expiry and make every later legitimate advance fail `HeightNotMonotonic`. Now:
- `check_order` returns `SystemInput` for it
- the app drops it from local submits and from gossip in **every** mode, signed or not

The operator-injected batch path is unchanged. Nothing in the consensus path inserts `AdvanceHeight` yet, so order expiry does not fire under consensus. That needs a proposer-inserted advance (recorded as a known gap).

**Update (2026-11-06): the protocol inserts the advance.** From height 2, every sealed `I(h)` starts with `AdvanceHeight { to: h }` (`IntentLog::tape`). Every full-view node seals the same tape, so it is part of `input_commitment`, of the replay in Validate, and of the `π` job. The engine's genesis height is 1, so height 1 has none, and engine height equals consensus height after each decide. Test: `m7_pq_gaps: orders_expire_under_consensus` (an order good until height 3 is expired by the advance to 4; a local replay of the decided `I` matches every decided root).

**Update (2026-11-06): signature table.** A signature is kept only when the intent log accepts its intent as newly pending. Previously a replayed, already-decided intent left its signature in the table for good.

Test: `m7_pq_gaps: client_cannot_inject_advance_height`. A client offers `AdvanceHeight` and an order; the decided `I` is exactly the order.

## Tests

`tests/m7_pq_gaps.rs: only_validly_signed_hybrid_orders_reach_i`. A tiered cluster with a hybrid order policy is offered:
- four hybrid-signed orders from two accounts, all decided
- one unsigned order
- one order signed by another account's key
- one classical-account order, under the hybrid policy

The decided `I` across heights 2–4 is **exactly** the four. Unit tests (`order_auth`) cover round trips, wrong owner, tampered nonce, downgrade, the owner-relabel check, and system inputs.

## Measurements

Loaded gossip height (n=4, 8k resting, tiered k=1, `PLX_M4_LOADED=1 PLX_M4_GOSSIP=1 PLX_M4_TIERED=1 [PLX_M4_SIGNED=1]`), later-heights "last" p50:

| Intents per height | Unsigned | Hybrid-signed |
|---|---|---|
| 1 000 | 72 ms | **83 ms** (full sets) |
| 2 000 – 10 000 | 75 – 127 ms | waves split across heights; ~0.5–0.6 s per height at 10k |

Per order:
- **+5 377 B on the wire per gossiped intent**: 1 990 B key + 3 379 B signature + framing. That is ~54 MB per peer for a 10k wave.
- **73 µs** to verify on one core, and **~240 µs** for the bench client to sign (key derivation included).

How the bottleneck moved:
1. Verifying on the listener task one frame at a time: 10k waves took 5–7 s.
2. Verifying on the app thread blocked consensus for ~0.75 s per 10k.
3. Batched, all-core verification (the current code): a 10k wave clears in ~0.5 s.

That is still beyond the admission grace window (180 ms, ADR 0020/0021, tuned for unsigned intents), so late intents roll into the next height. Nothing is lost, but heights no longer carry exactly one wave.

## Open

- **Send each account's key once per connection** (a per-peer key cache). The per-intent overhead drops from 5.4 KB to 3.4 KB.
- **Retune admission timing for signed intents.** The grace window could scale with the pending set, or an ACK could follow verification completion.
- Signature checks inside `π` (for light clients that do not trust the finality certificate's admission attestation): measure ML-DSA verify cycles in the guest first.
- Account recovery and key rotation (an account is its key).

## Reversibility

High. Opt-in. Unsigned clusters are unchanged.
