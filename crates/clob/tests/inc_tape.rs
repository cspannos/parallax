//! Engine `I` → [`IncTape`] of treap steps (ADR 0022). The tape's pre/post
//! roots equal the engine's `C` / `C'`. Not `F`: matching chose the ops.

use clob::testutil::{btree_engine, churn_tape, limit, load_places};
use clob::{start_inc_step_trace, take_inc_step_trace, Engine, TreapHash};
use commitments::{IncTape, TapeError};
use protocol_types::{Input, Side};

fn tape_of(e: &mut Engine, inputs: Vec<Input>) -> IncTape {
    let pre = e.incremental_inc_header();
    let (n, s, r) = e.incremental_map_roots();
    start_inc_step_trace();
    e.apply_all(inputs);
    let steps = take_inc_step_trace();
    IncTape { hash: e.treap_hash(), pre, pre_maps: [n, s, r], steps, post: e.incremental_inc_header() }
}

fn check(e: &mut Engine, inputs: Vec<Input>, label: &str) -> IncTape {
    let pre_root = e.state_root();
    let tape = tape_of(e, inputs);
    let claim = tape.verify().expect("valid tape");
    assert_eq!(claim.pre_root, pre_root, "{label}: pre");
    assert_eq!(claim.post_root, e.state_root(), "{label}: post");
    let bytes = tape.encode();
    assert_eq!(IncTape::decode(&bytes).as_ref(), Ok(&tape));
    eprintln!(
        "inc tape {label}: steps {}, node {}, prio {}, witness {} B",
        claim.steps,
        claim.node_hashes,
        claim.prio_hashes,
        bytes.len()
    );
    tape
}

fn book_8k() -> Engine {
    let mut e = btree_engine();
    e.apply_all(load_places(8_000));
    e
}

#[test]
fn one_place_at_8k() {
    let mut e = book_8k();
    let t = check(&mut e, vec![Input::Place(limit(8_001, 2, Side::Buy, 1, 50, 1))], "place@8k");
    // ADR 0026: derived ids keep the seen map empty, so no seen insert.
    assert_eq!(t.steps.len(), 2, "nonce + resting");
}

#[test]
fn eight_mixed_events_at_8k() {
    let mut e = book_8k();
    check(&mut e, churn_tape(8_000, 8), "churn8@8k");
}

#[test]
fn genesis_to_8k() {
    let mut e = btree_engine();
    check(&mut e, load_places(8_000), "genesis→8k");
}

#[test]
fn tampered_tape_rejected() {
    let mut e = book_8k();
    let tape = tape_of(&mut e, churn_tape(8_000, 8));
    let mut bad = tape.clone();
    bad.steps.remove(1);
    assert!(matches!(bad.verify(), Err(TapeError::Step { .. })));
    let mut bad = tape.clone();
    let (_, step) = &mut bad.steps[2];
    step.path[0].left.0[0] ^= 1;
    assert!(bad.verify().is_err() || bad.verify().unwrap().pre_root != tape.verify().unwrap().pre_root);
    let mut bad = tape;
    bad.pre_maps[2].0[0] ^= 1;
    assert!(matches!(bad.verify(), Err(TapeError::Step { .. })));
}

#[cfg(not(debug_assertions))]
#[test]
fn loaded_10k_at_8k() {
    let mut e = book_8k();
    let t = check(&mut e, churn_tape(8_000, 10_000), "loaded10k@8k");
    std::fs::create_dir_all(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("inc_tape_10k.bin");
    std::fs::write(&path, t.encode()).unwrap();
}

/// ADR 0024: production `C'` is SHA-256; `C'` v1 (BLAKE3) tapes still verify
/// in their own mode and open different roots.
#[test]
fn production_and_v1_tapes_match_engine() {
    let mut prod = book_8k();
    assert_eq!(prod.treap_hash(), TreapHash::Sha256);
    let mut v1 = clob::testutil::btree_engine_v1();
    v1.apply_all(load_places(8_000));
    assert_ne!(prod.state_root(), v1.state_root(), "different C' encoding");
    let place = || vec![Input::Place(limit(8_001, 2, Side::Buy, 1, 50, 1))];
    check(&mut prod, place(), "sha256 place@8k");
    check(&mut v1, place(), "blake3-v1 place@8k");
    check(&mut prod, churn_tape(8_000, 64), "sha256 churn64@8k");
    check(&mut v1, churn_tape(8_000, 64), "blake3-v1 churn64@8k");
}
