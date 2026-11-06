use clob::testutil::{genesis, limit, oid, owner as owner_id};
use clob::{BTreeBook, Engine, VecBook};
use proptest::prelude::*;
use protocol_types::{Height, Input, Side};

#[derive(Clone, Debug)]
enum Op {
    Place {
        id: u16,
        owner: u8,
        side: bool,
        qty: u8,
        price: u8,
        nonce: u8,
    },
    Cancel {
        id: u16,
        owner: u8,
        nonce: u8,
    },
    Advance,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (1u16..40, 1u8..6, any::<bool>(), 1u8..20, 1u8..20, 1u8..=40).prop_map(
            |(id, owner, side, qty, price, nonce)| Op::Place {
                id,
                owner,
                side,
                qty,
                price,
                nonce,
            }
        ),
        (1u16..40, 1u8..6, 1u8..=40).prop_map(|(id, owner, nonce)| Op::Cancel { id, owner, nonce }),
        Just(Op::Advance),
    ]
}

fn to_input(op: &Op, height: &mut u64) -> Input {
    match op {
        Op::Place {
            id,
            owner,
            side,
            qty,
            price,
            nonce,
        } => {
            let mut o = limit(
                u128::from(*id),
                *owner,
                if *side { Side::Buy } else { Side::Sell },
                u64::from(*qty),
                u64::from(*price),
                u64::from(*nonce),
            );
            o.expiry = Height(10_000);
            Input::Place(o)
        }
        Op::Cancel { id, owner, nonce } => Input::Cancel {
            order_id: oid(u128::from(*id)),
            owner: owner_id(*owner),
            nonce: u64::from(*nonce),
        },
        Op::Advance => {
            *height += 1;
            Input::AdvanceHeight {
                to: Height(*height),
            }
        }
    }
}

proptest! {
    #[test]
    fn same_inputs_same_root_across_backends(ops in prop::collection::vec(op_strategy(), 1..80)) {
        let mut h1 = 1u64;
        let mut h2 = 1u64;
        let inputs_a: Vec<Input> = ops.iter().map(|op| to_input(op, &mut h1)).collect();
        let inputs_b: Vec<Input> = ops.iter().map(|op| to_input(op, &mut h2)).collect();
        prop_assert_eq!(&inputs_a, &inputs_b);
        let inputs = inputs_a;

        let mut btree = Engine::<BTreeBook>::new(genesis());
        let mut vecb = Engine::<VecBook>::new(genesis());
        let ra = btree.apply_all(inputs.clone());
        let rb = vecb.apply_all(inputs.clone());
        prop_assert_eq!(&ra, &rb);

        let mut btree2 = Engine::<BTreeBook>::new(genesis());
        let rc = btree2.apply_all(inputs);
        prop_assert_eq!(&ra, &rc);
    }
}
