use clob::testutil::{btree_engine, btree_engine_v1, id_of, limit, limit_v1, oid, owner, vec_engine};
use clob::{Book, Engine, Outcome, RejectReason, VecBook};
use protocol_types::{Height, Input, Qty, Side};

/// v1 (client-chosen ids): a reused id is rejected via the seen set.
#[test]
fn v1_duplicate_order_id_rejected() {
    let mut e = btree_engine_v1();
    e.apply(Input::Place(limit_v1(1, 1, Side::Buy, 1, 1, 1)));
    let r = e.apply(Input::Place(limit_v1(1, 2, Side::Sell, 1, 1, 1)));
    assert_eq!(r.outcome, Outcome::Rejected(RejectReason::DuplicateOrderId));
}

/// ADR 0026: an id that is not `derive_order_id(owner, nonce)` is rejected,
/// without consuming the nonce.
#[test]
fn non_derived_id_rejected() {
    let mut e = btree_engine();
    let mut o = limit(0, 1, Side::Buy, 1, 1, 1);
    o.order_id = oid(1);
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::OrderIdMismatch)
    );
    let ok = e.apply(Input::Place(limit(0, 1, Side::Buy, 1, 1, 1)));
    assert_eq!(ok.outcome, Outcome::Accepted { remaining: Qty(1) });
}

/// Another owner cannot squat a pending order's id: the id binds the owner.
#[test]
fn derived_id_cannot_be_squatted() {
    let mut e = btree_engine();
    let victim = id_of(1, 7);
    let mut squat = limit(0, 2, Side::Sell, 1, 1, 1);
    squat.order_id = victim;
    assert_eq!(
        e.apply(Input::Place(squat)).outcome,
        Outcome::Rejected(RejectReason::OrderIdMismatch)
    );
    let r = e.apply(Input::Place(limit(0, 1, Side::Buy, 1, 1, 7)));
    assert_eq!(r.outcome, Outcome::Accepted { remaining: Qty(1) });
}

/// Replaying a Place (same owner, nonce, id) is a nonce replay; the seen set
/// stays empty under derived ids.
#[test]
fn replayed_place_rejected_without_seen_set() {
    let mut e = btree_engine();
    let o = limit(0, 1, Side::Buy, 1, 1, 3);
    e.apply(Input::Place(o.clone()));
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::NonceReplay)
    );
    assert!(e.snapshot().seen.is_empty());
}

#[test]
fn nonce_replay_rejected() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Buy, 1, 1, 5)));
    let r = e.apply(Input::Place(limit(2, 1, Side::Buy, 1, 1, 5)));
    assert_eq!(r.outcome, Outcome::Rejected(RejectReason::NonceReplay));
    let r = e.apply(Input::Place(limit(3, 1, Side::Buy, 1, 1, 4)));
    assert_eq!(r.outcome, Outcome::Rejected(RejectReason::NonceReplay));
}

#[test]
fn zero_qty_and_price_rejected() {
    let mut e = btree_engine();
    let mut o = limit(1, 1, Side::Buy, 0, 1, 1);
    assert_eq!(
        e.apply(Input::Place(o.clone())).outcome,
        Outcome::Rejected(RejectReason::ZeroQuantity)
    );
    o.order_id = oid(2);
    o.quantity = Qty(1);
    o.limit_price = protocol_types::Price(0);
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::ZeroPrice)
    );
}

#[test]
fn unknown_instrument_rejected() {
    let mut e = btree_engine();
    let mut o = limit(1, 1, Side::Buy, 1, 1, 1);
    o.instrument = protocol_types::InstrumentId(99);
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::UnknownInstrument)
    );
}

#[test]
fn zero_nonce_rejected() {
    let mut e = btree_engine();
    let o = limit(1, 1, Side::Buy, 1, 1, 0);
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::ZeroNonce)
    );
}

#[test]
fn lot_and_tick_enforced() {
    let mut genesis = clob::testutil::genesis();
    genesis.instruments[0].lot_size = Qty(10);
    genesis.instruments[0].tick_size = protocol_types::Price(5);
    let mut e = Engine::<clob::BTreeBook>::new(genesis);
    let mut o = limit(1, 1, Side::Buy, 5, 5, 1);
    assert_eq!(
        e.apply(Input::Place(o.clone())).outcome,
        Outcome::Rejected(RejectReason::QuantityNotMultipleOfLot)
    );
    o.quantity = Qty(10);
    o.limit_price = protocol_types::Price(6);
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::PriceNotMultipleOfTick)
    );
}

#[test]
fn expired_on_place_rejected() {
    let mut e = btree_engine();
    let mut o = limit(1, 1, Side::Buy, 1, 1, 1);
    o.expiry = Height(0);
    assert_eq!(
        e.apply(Input::Place(o)).outcome,
        Outcome::Rejected(RejectReason::Expired)
    );
}

#[test]
fn advance_height_expires_resting() {
    let mut e = btree_engine();
    let mut o = limit(1, 1, Side::Buy, 1, 1, 1);
    o.expiry = Height(5);
    e.apply(Input::Place(o));
    let r = e.apply(Input::AdvanceHeight { to: Height(6) });
    match r.outcome {
        Outcome::HeightAdvanced { expired } => assert_eq!(expired, vec![id_of(1, 1)]),
        other => panic!("{other:?}"),
    }
    assert_eq!(e.book(protocol_types::InstrumentId(1)).unwrap().len(), 0);
}

#[test]
fn cancel_unknown_rejected() {
    let mut e = btree_engine();
    let r = e.apply(Input::Cancel {
        order_id: oid(99),
        owner: owner(1),
        nonce: 1,
    });
    assert_eq!(r.outcome, Outcome::Rejected(RejectReason::UnknownOrder));
}

#[test]
fn height_must_increase() {
    let mut e = btree_engine();
    let r = e.apply(Input::AdvanceHeight { to: Height(1) });
    assert_eq!(
        r.outcome,
        Outcome::Rejected(RejectReason::HeightNotMonotonic)
    );
}

#[test]
fn malformed_inputs_do_not_panic_on_vec_book() {
    let mut e = vec_engine();
    e.apply(Input::Place(limit(1, 1, Side::Buy, 0, 0, 0)));
    e.apply(Input::Cancel {
        order_id: oid(0),
        owner: owner(0),
        nonce: 0,
    });
    e.apply(Input::AdvanceHeight { to: Height(0) });
    let _ = Engine::<VecBook>::new(clob::testutil::genesis()).state_root();
}
