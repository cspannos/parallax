use clob::testutil::{id_of, btree_engine, limit, owner};
use clob::{Book, Outcome, RejectReason};
use protocol_types::{Input, Qty, Side};

#[test]
fn buy_crosses_sell_at_maker_price() {
    let mut e = btree_engine();
    let r1 = e.apply(Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)));
    assert_eq!(r1.outcome, Outcome::Accepted { remaining: Qty(10) });
    assert!(r1.fills.is_empty());

    let r2 = e.apply(Input::Place(limit(2, 2, Side::Buy, 10, 100, 1)));
    assert_eq!(r2.outcome, Outcome::Accepted { remaining: Qty(0) });
    assert_eq!(r2.fills.len(), 1);
    assert_eq!(r2.fills[0].price.0, 90);
    assert_eq!(r2.fills[0].qty.0, 10);
    assert_eq!(r2.settlement.len(), 4);
    assert_eq!(e.book(protocol_types::InstrumentId(1)).unwrap().len(), 0);
}

#[test]
fn partial_fill_rests_remainder() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Sell, 10, 50, 1)));
    let r = e.apply(Input::Place(limit(2, 2, Side::Buy, 4, 50, 1)));
    assert_eq!(r.outcome, Outcome::Accepted { remaining: Qty(0) });
    assert_eq!(r.fills[0].qty.0, 4);
    let book = e.book(protocol_types::InstrumentId(1)).unwrap();
    assert_eq!(book.len(), 1);
    assert_eq!(book.get(id_of(1, 1)).unwrap().remaining, Qty(6));
}

#[test]
fn fifo_at_same_price() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)));
    e.apply(Input::Place(limit(2, 1, Side::Sell, 5, 10, 2)));
    let r = e.apply(Input::Place(limit(3, 2, Side::Buy, 6, 10, 1)));
    assert_eq!(r.fills.len(), 2);
    assert_eq!(r.fills[0].maker_order_id, id_of(1, 1));
    assert_eq!(r.fills[0].qty.0, 5);
    assert_eq!(r.fills[1].maker_order_id, id_of(1, 2));
    assert_eq!(r.fills[1].qty.0, 1);
}

#[test]
fn better_price_before_worse() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Sell, 5, 20, 1)));
    e.apply(Input::Place(limit(2, 1, Side::Sell, 5, 10, 2)));
    let r = e.apply(Input::Place(limit(3, 2, Side::Buy, 5, 20, 1)));
    assert_eq!(r.fills.len(), 1);
    assert_eq!(r.fills[0].maker_order_id, id_of(1, 2));
    assert_eq!(r.fills[0].price.0, 10);
}

#[test]
fn self_trade_skipped_book_may_self_cross() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)));
    let r = e.apply(Input::Place(limit(2, 1, Side::Buy, 5, 10, 2)));
    assert!(r.fills.is_empty());
    assert_eq!(r.outcome, Outcome::Accepted { remaining: Qty(5) });
    assert_eq!(e.book(protocol_types::InstrumentId(1)).unwrap().len(), 2);
}

#[test]
fn cancel_removes_resting() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Buy, 5, 10, 1)));
    let r = e.apply(Input::Cancel {
        order_id: id_of(1, 1),
        owner: owner(1),
        nonce: 2,
    });
    assert_eq!(r.outcome, Outcome::Cancelled { cancelled: Qty(5) });
    assert_eq!(e.book(protocol_types::InstrumentId(1)).unwrap().len(), 0);
}

#[test]
fn cancel_wrong_owner_does_not_remove() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Buy, 5, 10, 1)));
    let r = e.apply(Input::Cancel {
        order_id: id_of(1, 1),
        owner: owner(2),
        nonce: 1,
    });
    assert_eq!(r.outcome, Outcome::Rejected(RejectReason::OwnerMismatch));
    assert_eq!(e.book(protocol_types::InstrumentId(1)).unwrap().len(), 1);
}

#[test]
fn settlement_buy_credits_base_debits_quote() {
    let mut e = btree_engine();
    e.apply(Input::Place(limit(1, 1, Side::Sell, 2, 7, 1)));
    let r = e.apply(Input::Place(limit(2, 2, Side::Buy, 2, 7, 1)));
    let taker_base: u128 = r
        .settlement
        .iter()
        .filter(|d| d.account == owner(2) && d.asset.0 == 1 && !d.debit)
        .map(|d| d.amount)
        .sum();
    let taker_quote_debit: u128 = r
        .settlement
        .iter()
        .filter(|d| d.account == owner(2) && d.asset.0 == 2 && d.debit)
        .map(|d| d.amount)
        .sum();
    assert_eq!(taker_base, 2);
    assert_eq!(taker_quote_debit, 14);
}
