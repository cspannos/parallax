//! M3 corpus: a real fill plus a same-owner rest-cross (STP).

use clob::testutil::{limit, oid, owner};
use protocol_types::{Input, Side};

/// Ordered `I` for the unequal-view experiment.
///
/// Owner 1 rests both a sell and a buy at 10 (self-cross, no fill).
/// Owners 2 and 3 produce a real fill at 20. TRADING_VIEW sees a crossed
/// book at 10 and cannot tell STP from a matching bug.
pub fn m3_stream() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)),
        Input::Place(limit(2, 1, Side::Buy, 5, 10, 2)),
        Input::Place(limit(3, 2, Side::Sell, 5, 20, 1)),
        Input::Place(limit(4, 3, Side::Buy, 3, 20, 1)),
        Input::Cancel {
            order_id: oid(3),
            owner: owner(2),
            nonce: 2,
        },
    ]
}
