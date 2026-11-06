//! `F` from a snapshot (ADR 0025): the rebuilt engine commits the same `C`,
//! then matches identically; `run_f` reproduces the statement fields; a
//! non-canonical snapshot is rejected.

use clob::testutil::{btree_engine, churn_tape, churn_wave, load_places};
use clob::{run_f, Engine, EngineSnapshot, SnapshotError};
use commitments::{commit_list_payload, Digest, INPUT_DOMAIN, RECEIPT_DOMAIN};
use protocol_types::Input;

fn book(n: usize) -> Engine {
    let mut e = btree_engine();
    e.apply_all(load_places(n));
    e
}

#[test]
fn snapshot_round_trips_and_rebuilds_root() {
    let mut e = book(2_000);
    e.apply_all(churn_tape(2_000, 500));
    let snap = e.snapshot();
    assert_eq!(EngineSnapshot::decode(&snap.encode()), Ok(snap.clone()));
    let r = Engine::<clob::BTreeBook>::from_snapshot(&snap).expect("canonical");
    assert_eq!(r.state_root(), e.state_root());
}

/// Rebuilt and original engines stay in lockstep over many further waves.
#[test]
fn rebuilt_engine_matches_identically() {
    let mut a = book(1_000);
    a.apply_all(churn_tape(1_000, 300));
    let mut b = Engine::<clob::BTreeBook>::from_snapshot(&a.snapshot()).unwrap();
    for wave in 1..12u64 {
        let tape = churn_wave(1_000, 200, wave);
        let ra = a.apply_all(tape.clone());
        let rb = b.apply_all(tape);
        assert_eq!(ra, rb, "receipts, wave {wave}");
        assert_eq!(a.state_root(), b.state_root(), "root, wave {wave}");
        // Re-snapshot mid-stream too.
        b = Engine::<clob::BTreeBook>::from_snapshot(&b.snapshot()).unwrap();
        assert_eq!(a.state_root(), b.state_root());
    }
}

#[test]
fn run_f_reproduces_the_statement_fields() {
    let e = book(2_000);
    let inputs = churn_tape(2_000, 64);
    let mut scratch = e.clone();
    let receipts = scratch.apply_all(inputs.clone());
    let settlement: Vec<_> = receipts.into_iter().flat_map(|r| r.settlement).collect();
    let claim = run_f(&e.snapshot().encode(), &commit_list_payload(&inputs)).unwrap();
    assert_eq!(claim.pre_root, e.state_root());
    assert_eq!(claim.post_root, scratch.state_root());
    assert_eq!(claim.input_commitment, Digest::from_bytes(&commit_list_payload(&inputs), INPUT_DOMAIN));
    assert_eq!(
        claim.settlement_commitment,
        Digest::from_bytes(&commit_list_payload(&settlement), RECEIPT_DOMAIN)
    );
    assert_ne!(settlement.len(), 0, "the tape fills");
}

#[test]
fn run_f_rejects_trailing_or_garbage_bytes() {
    let e = book(10);
    let snap = e.snapshot().encode();
    let inputs = commit_list_payload::<Input>(&[]);
    assert!(run_f(&snap, &inputs).is_ok());
    let mut s = snap.clone();
    s.push(0);
    assert!(run_f(&s, &inputs).is_err());
    let mut i = inputs.clone();
    i.push(0);
    assert!(run_f(&snap, &i).is_err());
}

#[test]
fn non_canonical_snapshots_rejected() {
    let mut e = book(50);
    e.apply_all(churn_tape(50, 20));
    let good = e.snapshot();
    assert!(good.resting.len() > 3);

    // Derived ids (ADR 0026): the seen set must stay empty.
    assert!(good.seen.is_empty());
    let mut s = good.clone();
    s.seen.push(protocol_types::OrderId::from_u128(1));
    assert_eq!(
        Engine::<clob::BTreeBook>::from_snapshot(&s).err(),
        Some(SnapshotError::SeenUnderDerivedIds)
    );

    // v1 (client ids): a duplicate seen id is non-canonical.
    let mut v1 = clob::testutil::btree_engine_v1();
    v1.apply_all(clob::testutil::load_places_v1(50));
    let mut s = v1.snapshot();
    assert_eq!(Engine::<clob::BTreeBook>::from_snapshot(&s).unwrap().state_root(), v1.state_root());
    s.seen.push(s.seen[0]);
    assert_eq!(Engine::<clob::BTreeBook>::from_snapshot(&s).err(), Some(SnapshotError::NotCanonical));

    let mut s = good.clone();
    s.resting.swap(0, 1);
    assert_eq!(Engine::<clob::BTreeBook>::from_snapshot(&s).err(), Some(SnapshotError::NotCanonical));

    // Same id twice (different time): the treap would merge them, the book would not.
    let mut s = good.clone();
    let mut dup = s.resting[0].clone();
    dup.time = protocol_types::TimeSeq(s.next_time.0 + 100);
    s.resting.push(dup);
    assert_eq!(Engine::<clob::BTreeBook>::from_snapshot(&s).err(), Some(SnapshotError::NotCanonical));

    let mut s = good.clone();
    s.nonces.reverse();
    if s.nonces.len() > 1 {
        assert_eq!(Engine::<clob::BTreeBook>::from_snapshot(&s).err(), Some(SnapshotError::NotCanonical));
    }

    let mut s = good;
    s.resting[0].instrument = protocol_types::InstrumentId(999);
    assert_eq!(Engine::<clob::BTreeBook>::from_snapshot(&s).err(), Some(SnapshotError::UnknownInstrument));
}
