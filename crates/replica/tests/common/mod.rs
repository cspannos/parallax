//! Shared Phase 2 input stream used by in-process and OS-process harnesses.

use clob::testutil::{id_of, limit, owner};
use protocol_types::{Height, Input, Side};

/// Ordered `I` covering place, partial fill, cancel, height, and a reject.
pub fn demo_stream() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)),
        Input::Place(limit(2, 2, Side::Buy, 4, 100, 1)),
        Input::Place(limit(3, 3, Side::Buy, 6, 90, 1)),
        Input::Place(limit(4, 2, Side::Buy, 5, 50, 2)),
        Input::Cancel {
            order_id: id_of(2, 2),
            owner: owner(2),
            nonce: 3,
        },
        Input::Place(limit(5, 1, Side::Sell, 3, 50, 2)),
        Input::AdvanceHeight { to: Height(2) },
        // Replays owner 1's nonce 1 (the first Place): reject, still WAL'd.
        // Under derived ids (ADR 0026) this is how a duplicate shows up.
        Input::Place(limit(1, 1, Side::Sell, 1, 90, 1)),
        Input::Place(limit(6, 4, Side::Buy, 1, 40, 1)),
    ]
}
