use clob::testutil::{id_of, btree_engine, limit, owner};
use clob::Engine;
use protocol_types::{Height, Input, Side};

fn script() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 10, 50, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 50, 1)),
        Input::Place(limit(3, 3, Side::Sell, 4, 40, 1)),
        Input::Place(limit(4, 2, Side::Buy, 20, 60, 2)),
        Input::Cancel {
            order_id: id_of(1, 1),
            owner: owner(1),
            nonce: 2,
        },
        Input::Place(limit(5, 4, Side::Buy, 1, 10, 1)),
        Input::AdvanceHeight { to: Height(2) },
        Input::Place(limit(6, 1, Side::Sell, 2, 10, 3)),
    ]
}

fn inc_engine() -> Engine {
    btree_engine()
}

#[test]
fn incremental_matches_rebuild_on_same_engine() {
    let mut live = inc_engine();
    live.apply_all(script());
    let tracked = live.incremental_root();
    let len = live.incremental_resting_len();
    live.enable_incremental();
    assert_eq!(len, live.incremental_resting_len());
    assert_eq!(tracked, live.incremental_root());
}

#[test]
fn consensus_state_root_is_treap() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Buy, 1, 10, 1)));
    assert_eq!(e.state_root(), e.incremental_root());
    assert_ne!(e.state_root(), e.full_walk_root());
}

#[test]
fn inc_root_preimage_hashes_to_root() {
    let mut e = btree_engine();
    e.set_treap_hash(clob::TreapHash::Blake3Count);
    e.apply_all(vec![
        Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)),
        Input::Place(limit(2, 2, Side::Buy, 10, 100, 1)),
    ]);
    let pre = e.incremental_root_preimage();
    assert_eq!(e.incremental_root().0, *blake3::hash(&pre).as_bytes());
    assert_eq!(e.state_root().0, *blake3::hash(&pre).as_bytes());
    assert_eq!(pre.len(), 244);
    eprintln!(
        "inc C' preimage {} B, blocks {}, last_blen {}",
        pre.len(),
        pre.len().div_ceil(64),
        if pre.len() % 64 == 0 {
            64
        } else {
            pre.len() % 64
        }
    );
}

#[test]
fn fills_match_when_incremental_off() {
    let inputs = script();
    let mut walk = btree_engine();
    walk.incremental_on_apply = false;
    let full = walk.apply_all(inputs.clone());
    let inc = inc_engine().apply_all(inputs.clone());
    for (a, b) in full.iter().zip(inc.iter()) {
        assert_eq!(a.fills, b.fills);
        assert_ne!(a.state_root, b.state_root);
    }
    let mut walk_e = btree_engine();
    walk_e.incremental_on_apply = false;
    walk_e.apply_all(inputs.clone());
    let mut inc_e = inc_engine();
    inc_e.apply_all(inputs);
    assert_eq!(walk_e.full_walk_root(), inc_e.full_walk_root());
}

#[test]
fn same_ops_same_incremental_root() {
    let mut a = inc_engine();
    a.apply(Input::Place(limit(1, 1, Side::Buy, 1, 10, 1)));
    a.apply(Input::Place(limit(2, 1, Side::Buy, 1, 11, 2)));
    let mut b = inc_engine();
    b.apply(Input::Place(limit(1, 1, Side::Buy, 1, 10, 1)));
    b.apply(Input::Place(limit(2, 1, Side::Buy, 1, 11, 2)));
    assert_eq!(a.incremental_root(), b.incremental_root());
    assert_eq!(a.state_root(), b.state_root());
}

#[test]
fn cancel_restores_resting_len() {
    let mut e = inc_engine();
    e.apply(Input::Place(limit(1, 1, Side::Buy, 1, 10, 1)));
    assert_eq!(e.incremental_resting_len(), 1);
    e.apply(Input::Cancel {
        order_id: id_of(1, 1),
        owner: owner(1),
        nonce: 2,
    });
    assert_eq!(e.incremental_resting_len(), 0);
    let mut rebuilt = btree_engine();
    rebuilt.apply(Input::Place(limit(1, 1, Side::Buy, 1, 10, 1)));
    rebuilt.apply(Input::Cancel {
        order_id: id_of(1, 1),
        owner: owner(1),
        nonce: 2,
    });
    rebuilt.enable_incremental();
    assert_eq!(e.incremental_root(), rebuilt.incremental_root());
}
