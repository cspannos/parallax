use clob::testutil::{id_of, btree_engine, limit, vec_engine};
use protocol_types::{CanonicalEncode, Input, Side};

fn script() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 10, 50, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 50, 1)),
        Input::Place(limit(3, 3, Side::Sell, 4, 40, 1)),
        Input::Place(limit(4, 2, Side::Buy, 20, 60, 2)),
        Input::Cancel {
            order_id: id_of(1, 1),
            owner: clob::testutil::owner(1),
            nonce: 2,
        },
        Input::Place(limit(5, 4, Side::Buy, 1, 10, 1)),
        Input::AdvanceHeight {
            to: protocol_types::Height(2),
        },
        Input::Place(limit(6, 1, Side::Sell, 2, 10, 3)),
    ]
}

#[test]
fn replay_twice_byte_identical_root_fills_delta() {
    let inputs = script();
    let a = btree_engine().apply_all(inputs.clone());
    let b = btree_engine().apply_all(inputs);
    assert_eq!(a.len(), b.len());
    for (ra, rb) in a.iter().zip(b.iter()) {
        assert_eq!(ra.outcome, rb.outcome);
        assert_eq!(ra.fills, rb.fills);
        assert_eq!(ra.settlement, rb.settlement);
        assert_eq!(ra.state_root, rb.state_root);
        assert_eq!(ra.state_root.0.len(), 32);
    }
}

#[test]
fn btree_and_vec_produce_identical_receipts() {
    let inputs = script();
    let a = btree_engine().apply_all(inputs.clone());
    let b = vec_engine().apply_all(inputs);
    for (ra, rb) in a.iter().zip(b.iter()) {
        assert_eq!(ra.outcome, rb.outcome);
        assert_eq!(ra.fills, rb.fills);
        assert_eq!(ra.settlement, rb.settlement);
        assert_eq!(ra.state_root, rb.state_root);
    }
}

#[test]
fn input_encoding_is_stable() {
    let bytes = script()[0].encode_vec();
    assert_eq!(bytes, script()[0].encode_vec());
    assert_ne!(bytes, script()[1].encode_vec());
}
