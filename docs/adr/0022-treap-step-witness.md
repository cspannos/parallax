# ADR 0022 — Treap step witness (general `C'` update)

**Status:** Accepted as the **research default for proving a `C'` change**, not a STARK  
**Date:** 2026-10-15  
**Deciders:** Protocol architecture (research prototype)  
**Builds on:** [0013](0013-treap-is-c.md) (treap is `C'`).  
**Does not implement:** an AIR, matching, `F`, recursion, a whole-height proof.

## Context

The Plonky3 `C'` cells so far (EngineInsert 72, HeightMatch 19) prove the BLAKE3 hashes of one **recorded** apply. Their parent/child links are hardcoded per fixture (`EI_HIDX_*`). They cannot prove a different order, a different book, or a remove. Binding every edge of the EngineInsert fixture took ~9.4 s and still does not link the path to the map root.

`HashedMap` hashes rotations as they happen. The rotate-time hash trace has no fixed shape, so a general circuit should not mirror it.

## Decision

A `C'` change is proven per map op from a **path witness** ([`TreapStep`](../../crates/commitments/src/treap_witness.rs)):

- **Upsert, key present:** the search path; rehash it with the new value.
- **Insert:** the search path plus `insert_at`. Above `insert_at` the nodes are unchanged except for one child. Below it, the path splits by key: smaller keys chain down via their right child, larger keys via their left child. Off-path children never change. Heap position takes **3 priority hashes**: the new key, `path[insert_at-1]` and `path[insert_at]`.
- **Remove:** the search path to the key, plus the right spine of its left subtree and the left spine of its right subtree. The new subtree is the priority-ordered merge of the two spines.
- **Remove, key absent:** a non-membership path; the root does not change.

`TreapStep::verify` recomputes the old root and the new root from the witness alone. `HashedMap::upsert_step` / `remove_step` extract it. Because the treap shape depends only on the key set, the split/merge result equals the rotate-based root. This is checked on 12 000 random ops (key lengths 1/3/8/16) against `HashedMap`.

Each witness row is "one node, its two child hashes, one direction bit". A general AIR is one row group per path level with selectors, not one column block per fixture edge.

## Cost (8k map, 16 B keys, 200 B values, 500 ops each)

| op | `node_digest` mean / max | prio mean / max |
|---|---|---|
| insert | 34.4 / 55 | 2.7 / 3 |
| update | 31.5 / 54 | 0 / 0 |
| remove | 33.4 / 54 | 1.9 / 13 |

The native trace records ~20 BLAKE3s per upsert because the node already trusts its memory. A proof also re-opens the old path, so it costs about 2× the trace.

## Alternatives

| Option | Why not |
|---|---|
| Keep binding fixture edges | Never general; ~0.3–0.8 s per edge pair; no link to the root |
| Prove the rotate trace | Variable shape; each rotation rehashes the same node twice |
| Switch `C'` to a sparse Merkle tree | Fixed depth (~256 hashes per update for 32 B keys, or a JMT); would reopen ADR 0013. Revisit if the treap AIR is not competitive |

## Consequences

- B2: a Plonky3 AIR for one `TreapStep` per map layout (seen / nonce / resting differ in key and value length). It is general over trees and ops, not over byte layouts.
- B3: one Place = three steps chained through the INC root. A tape = steps chained root to root.
- B4: a whole height is many such proofs or a recursion. That is still open (`p3-uni-stark` 0.6 does not wrap).

## Security implications

Soundness relies on the old root committing a valid treap (BST and heap order). That holds by induction only if **every** step from genesis is checked. A witness alone does not re-prove the invariant. Not a validity proof of `F`: matching is a separate statement.

## Reversibility

High. This is a witness format and a native checker. No wire or root change.
