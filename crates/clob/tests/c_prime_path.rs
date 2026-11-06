//! `C'` prove multiplicity. One-path upsert at 8k is 20 BLAKE3s (ADR 0013).
//! That is the in-circuit hash count, not a BLAKE3 AIR. Poseidon2 is not `C'`.

use clob::testutil::{churn_tape, limit, load_places, oid, owner};
use clob::{take_treap_hash_calls, Engine, HashedMap, TreapHash};
use protocol_types::{Input, Side};

fn map_key(i: usize) -> [u8; 8] {
    (i as u64).to_le_bytes()
}

fn counted_engine() -> Engine {
    let mut e = clob::testutil::btree_engine();
    e.set_treap_hash(TreapHash::Blake3Count);
    e
}

#[test]
fn upsert_at_8k_is_twenty_blake3s() {
    let mut m = HashedMap::with_hash(TreapHash::Blake3Count);
    let val = [0u8; 32];
    for i in 0..8_000 {
        m.upsert(&map_key(i), &val);
    }
    let _ = take_treap_hash_calls();
    m.upsert(&map_key(8_000), &val);
    let c = take_treap_hash_calls();
    assert_eq!(c.prio, 1, "one new key");
    assert_eq!(c.node, 19, "one-path node_digest at 8k");
    assert_eq!(c.blake3(), 20);
    assert_eq!(c.empty_compute, 0);
}

#[test]
fn engine_insert_at_8k_is_more_than_one_map() {
    let mut e = counted_engine();
    e.apply_all(load_places(8_000));
    let _ = take_treap_hash_calls();
    e.apply(Input::Place(limit(8_001, 2, Side::Buy, 1, 50, 1)));
    let c = take_treap_hash_calls();
    eprintln!(
        "C' engine insert at 8k: prio={} node={} blake3={}",
        c.prio,
        c.node,
        c.blake3()
    );
    // A new owner adds one key to the nonce map and one to the resting map:
    // two new priorities, two paths. Not one upsert. (Node counts depend on
    // where the derived id lands; ADR 0032 changed the derivation.)
    assert_eq!(c.prio, 2, "engine C' touches the nonce and resting maps");
    assert!(c.node > 2);
}

#[test]
fn engine_mixed_events_at_8k_hash_counts() {
    let mut e = counted_engine();
    e.apply_all(load_places(8_000));
    let tape = churn_tape(8_000, 4);
    assert_eq!(tape.len(), 4);
    let mut rest = 0;
    let mut rest_prio = 0;
    let mut take = 0;
    let mut cancel = 0;
    for (i, input) in tape.into_iter().enumerate() {
        let _ = take_treap_hash_calls();
        e.apply(input);
        let c = take_treap_hash_calls();
        match i % 4 {
            0 | 1 => {
                rest = c.blake3();
                rest_prio = c.prio;
            }
            2 => take = c.blake3(),
            _ => cancel = c.blake3(),
        }
        eprintln!(
            "C' mixed event {} at 8k: prio={} node={} blake3={}",
            i, c.prio, c.node, c.blake3()
        );
    }
    // A resting Place inserts a new resting key (and maybe a new nonce key).
    assert!(rest_prio >= 1 && rest > rest_prio);
    assert!(take > 0);
    assert!(cancel > 0);
}

#[test]
fn engine_cancel_at_8k_is_a_path() {
    let mut e = counted_engine();
    e.apply_all(load_places(8_000));
    let _ = take_treap_hash_calls();
    e.apply(Input::Cancel {
        order_id: oid(1),
        owner: owner(1),
        nonce: 8_001,
    });
    let c = take_treap_hash_calls();
    assert!(c.blake3() > 0);
    eprintln!(
        "C' engine cancel at 8k: prio={} node={} blake3={}",
        c.prio,
        c.node,
        c.blake3()
    );
}
