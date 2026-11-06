//! Propose and validate `ConsensusValue` (ADR 0009).

use clob::{BTreeBook, Engine};
use commitments::{Digest, INPUT_DOMAIN, RECEIPT_DOMAIN};
use protocol_types::{
    Bytes32, CanonicalEncode, ConsensusValue, EncodeBuf, Height, HeightStatement, Input,
    SettlementDelta,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validity {
    Valid,
    Invalid,
    /// Public value present; book/`I` missing (ADR 0005 / 0009).
    InsufficientView,
}

pub fn commit_list<T: CanonicalEncode>(items: &[T], domain: &[u8]) -> Digest {
    let mut buf = EncodeBuf::new();
    buf.u32(items.len() as u32);
    for item in items {
        item.encode(&mut buf);
    }
    Digest::from_bytes(buf.as_slice(), domain)
}

/// Scratch-apply `I` without mutating the replica. Used by GetValue / Validate.
pub struct Replay {
    pub engine: Engine<BTreeBook>,
    pub value: ConsensusValue,
}

pub fn replay(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    consensus_height: Height,
    inputs: &[Input],
) -> Replay {
    let mut scratch = engine.clone();
    // Only the final root is voted; per-receipt roots would re-flush the lazy
    // treap after every input (ADR 0032).
    scratch.commit_on_apply = false;
    let receipts = scratch.apply_all(inputs.iter().cloned());
    scratch.commit_on_apply = engine.commit_on_apply;
    let settlement: Vec<SettlementDelta> = receipts
        .iter()
        .flat_map(|r| r.settlement.iter().cloned())
        .collect();
    Replay {
        value: ConsensusValue {
            parent,
            height: consensus_height,
            state_root: scratch.state_root().to_bytes32(),
            input_commitment: commit_list(inputs, INPUT_DOMAIN).to_bytes32(),
            settlement_commitment: commit_list(&settlement, RECEIPT_DOMAIN).to_bytes32(),
        },
        engine: scratch,
    }
}

/// `GetValue`: build the public bundle from current `S` and this height's `I`.
/// Does not mutate the replica.
pub fn propose(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    consensus_height: Height,
    inputs: &[Input],
) -> ConsensusValue {
    replay(engine, parent, consensus_height, inputs).value
}

/// Public `π` instance: `C` before `F`, `C'` / `I` / deltas after. Native
/// identity, not a STARK. `pre_root` is the current engine treap (ADR 0013).
pub fn height_statement(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    consensus_height: Height,
    inputs: &[Input],
) -> HeightStatement {
    let pre_root = engine.state_root().to_bytes32();
    HeightStatement::from_value(pre_root, &propose(engine, parent, consensus_height, inputs))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("native F does not produce this HeightStatement")]
pub struct HeightStatementError;

/// Replay `F` and require the statement. FULL_VIEW witness, not `π`.
pub fn check_height_statement(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    consensus_height: Height,
    inputs: &[Input],
    stmt: &HeightStatement,
) -> Result<(), HeightStatementError> {
    if &height_statement(engine, parent, consensus_height, inputs) == stmt {
        Ok(())
    } else {
        Err(HeightStatementError)
    }
}

/// Shape-1 `valid(v)`: public checks + replay `F`.
pub fn validate(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    expected_height: Height,
    value: &ConsensusValue,
    inputs: Option<&[Input]>,
) -> Validity {
    if value.parent != parent || value.height != expected_height {
        return Validity::Invalid;
    }
    let Some(inputs) = inputs else {
        return Validity::InsufficientView;
    };
    let got = replay(engine, parent, expected_height, inputs).value;
    if value.state_root != got.state_root
        || value.input_commitment != got.input_commitment
        || value.settlement_commitment != got.settlement_commitment
    {
        return Validity::Invalid;
    }
    Validity::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine, limit};
    use protocol_types::{ConsensusValue, Side};

    fn crossing_i() -> Vec<Input> {
        vec![
            Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit(2, 2, Side::Buy, 10, 100, 1)),
        ]
    }

    /// v1 ids (the documented `C'` v1 hash counts depend on key order).
    fn crossing_i_v1() -> Vec<Input> {
        use clob::testutil::limit_v1;
        vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(2, 2, Side::Buy, 10, 100, 1)),
        ]
    }

    #[test]
    fn height_statement_is_c_prime_of_f() {
        let engine = btree_engine();
        let inputs = crossing_i();
        let stmt = height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
        let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
        assert!(stmt.binds_value(&value));
        assert_eq!(stmt.pre_root, engine.state_root().to_bytes32());
        assert_eq!(stmt.post_root, value.state_root);
        assert_ne!(stmt.pre_root, stmt.post_root);
        check_height_statement(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            &stmt,
        )
        .unwrap();
        assert_eq!(
            validate(
                &engine,
                ConsensusValue::GENESIS_PARENT,
                Height(1),
                &value,
                Some(&inputs),
            ),
            Validity::Valid
        );
    }

    #[test]
    fn wrong_post_root_fails_native_check() {
        let engine = btree_engine();
        let inputs = crossing_i();
        let mut stmt =
            height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
        stmt.post_root = stmt.pre_root;
        assert!(check_height_statement(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            &stmt,
        )
        .is_err());
        let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
        assert!(!stmt.binds_value(&value));
    }

    #[test]
    fn wrong_i_fails_native_check() {
        let engine = btree_engine();
        let inputs = crossing_i();
        let stmt = height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
        let other = vec![Input::Place(limit(1, 1, Side::Sell, 10, 90, 1))];
        assert!(check_height_statement(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &other,
            &stmt,
        )
        .is_err());
    }

    #[test]
    fn height_statement_c_prime_openings_are_not_pi() {
        use clob::TreapHash;
        use commitments::{
            start_node_digest_trace, start_prio_trace, take_node_digest_trace, take_prio_trace,
            take_treap_hash_calls,
        };

        // `C'` v1 counts (BLAKE3, client ids, seen set): the documented 5 + 8.
        let mut engine = clob::testutil::btree_engine_v1();
        engine.set_treap_hash(TreapHash::Blake3Count);
        let inputs = crossing_i_v1();
        let stmt = height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
        let _ = take_treap_hash_calls();
        start_node_digest_trace();
        start_prio_trace();
        let _ = engine.apply_all(inputs.iter().cloned());
        let calls = take_treap_hash_calls();
        let openings = take_node_digest_trace();
        let prio = take_prio_trace();
        eprintln!(
            "height-statement C' hashes: prio={} node={} prio_pre={} node_pre={} blob={} B",
            calls.prio,
            calls.node,
            prio.len(),
            openings.len(),
            stmt.encode_vec().len()
        );
        assert_eq!(openings.len() as u64, calls.node);
        assert_eq!(prio.len() as u64, calls.prio);
        assert_eq!(stmt.encode_vec().len(), 178);
        assert_eq!(calls.prio, 5);
        assert_eq!(calls.node, 8);
        // Not F. Last digest is not post_root. Openings are not matching.
        // A STARK of these 13 hashes exists; it does not unlock settlement.
    }
}
