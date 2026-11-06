use private_state_engine::{Input, PrivateStateEngine};
use protocol_types::{
    AssetId, Height, Instrument, InstrumentId, Order, OwnerId, Price, Qty, Side,
};

#[test]
fn pse_apply_is_engine_apply() {
    let genesis = clob::Genesis {
        height: Height(1),
        instruments: vec![Instrument {
            id: InstrumentId(1),
            base: AssetId(1),
            quote: AssetId(2),
            lot_size: Qty(1),
            tick_size: Price(1),
        }],
    };
    let mut eng = PrivateStateEngine::<clob::BTreeBook>::new(genesis);
    let r = eng.apply(Input::Place(Order {
        order_id: clob::testutil::id_of(1, 1),
        instrument: InstrumentId(1),
        side: Side::Buy,
        quantity: Qty(1),
        limit_price: Price(1),
        owner: OwnerId::from_byte(1),
        expiry: Height(10),
        nonce: 1,
    }));
    assert!(matches!(
        r.outcome,
        clob::Outcome::Accepted { remaining } if remaining == Qty(1)
    ));
    let _ = eng.state_root();
}
