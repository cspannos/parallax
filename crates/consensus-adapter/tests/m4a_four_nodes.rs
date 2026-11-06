//! M4a: four FULL_VIEW replicas, Validate includes F (ADR 0009).

use clob::testutil::{churn_tape, genesis, limit, load_places, oid, owner};
use commitments::value_id;
use consensus_adapter::{run_height, Cluster, IntentLog, Validity};
use protocol_types::{Bytes32, Input, Side};

fn batch_a() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 10, 1)),
    ]
}

fn batch_b() -> Vec<Input> {
    vec![Input::Cancel {
        order_id: oid(1),
        owner: owner(1),
        nonce: 2,
    }]
}

#[test]
fn sealed_offer_order_does_not_change_id() {
    let fwd = batch_a();
    let rev: Vec<Input> = fwd.iter().rev().cloned().collect();
    let mut a = IntentLog::open();
    let mut b = IntentLog::open();
    for i in fwd {
        a.offer(i);
    }
    for i in rev {
        b.offer(i);
    }
    let ta = a.tape(1).unwrap().to_vec();
    let tb = b.tape(1).unwrap().to_vec();
    assert_eq!(ta, tb);
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    assert_eq!(
        cluster.nodes[0].get_value(&ta),
        cluster.nodes[1].get_value(&tb)
    );
}

#[test]
fn four_full_view_nodes_decide_the_same_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let id = run_height(&mut cluster, &batch_a(), [true; 4]).unwrap();
    for n in &cluster.nodes {
        assert_eq!(n.decided_id(1).unwrap(), id);
    }
}

#[test]
fn missing_i_is_insufficient_view_not_valid() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let value = cluster.nodes[0].get_value(&batch_a());
    let v = cluster.nodes[3].validate_proposal(&value, None);
    assert_eq!(v, Validity::InsufficientView);
    assert_ne!(v, Validity::Valid);
}

#[test]
fn three_of_four_with_i_still_quorum() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let id = run_height(&mut cluster, &batch_a(), [true, true, true, false]).unwrap();
    assert!(cluster.nodes[0].decided_id(1).is_some());
    assert!(cluster.nodes[3].decided_id(1).is_none());
    assert_eq!(cluster.nodes[0].decided_id(1).unwrap(), id);
}

#[test]
fn bogus_state_root_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let mut value = cluster.nodes[0].get_value(&batch_a());
    value.state_root = Bytes32([0xff; 32]);
    for n in &mut cluster.nodes {
        assert_eq!(
            n.validate_proposal(&value, Some(&batch_a())),
            Validity::Invalid
        );
    }
}

#[test]
fn cannot_decide_two_values_at_one_height() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = Cluster::open_four(dir.path(), genesis()).unwrap();
    let v = c.nodes[0].get_value(&batch_a());
    c.nodes[0].decide(&v, &batch_a()).unwrap();
    let mut v2 = v;
    v2.state_root = Bytes32([1; 32]);
    assert!(c.nodes[0].decide(&v2, &batch_a()).is_err());
}

#[test]
fn second_height_binds_parent() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let id1 = run_height(&mut cluster, &batch_a(), [true; 4]).unwrap();
    let v2 = cluster.nodes[0].get_value(&batch_b());
    assert_eq!(v2.parent, id1.to_bytes32());
    let id2 = run_height(&mut cluster, &batch_b(), [true; 4]).unwrap();
    assert_ne!(id1, id2);
    for n in &cluster.nodes {
        assert_eq!(n.decided_id(2).unwrap(), id2);
        assert_eq!(n.last_id(), id2.to_bytes32());
    }
}

#[test]
fn honest_values_match_across_proposers() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let a = cluster.nodes[0].get_value(&batch_a());
    let b = cluster.nodes[1].get_value(&batch_a());
    assert_eq!(a, b);
    assert_eq!(value_id(&a), value_id(&b));
}

#[test]
fn decide_wrong_input_commitment_does_not_apply() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let mut value = cluster.nodes[0].get_value(&batch_a());
    value.input_commitment = Bytes32([0x11; 32]);
    assert!(cluster.nodes[0].decide(&value, &batch_a()).is_err());
    assert!(cluster.nodes[0].decided_id(1).is_none());
    assert_eq!(cluster.nodes[0].replica().engine().metrics.places, 0);
}

#[test]
fn get_value_reuses_matching_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let a = cluster.nodes[0].get_value(&batch_a());
    let b = cluster.nodes[0].get_value(&batch_a());
    assert_eq!(a, b);
    cluster.nodes[0].decide(&a, &batch_a()).unwrap();
    assert_eq!(cluster.nodes[0].replica().engine().metrics.places, 2);
}

#[test]
fn voter_speculate_then_validate_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let value = cluster.nodes[0].get_value(&batch_a());
    cluster.nodes[1].speculate(&batch_a());
    assert_eq!(
        cluster.nodes[1].validate_proposal(&value, Some(&batch_a())),
        Validity::Valid
    );
    cluster.nodes[1].decide(&value, &batch_a()).unwrap();
    assert_eq!(cluster.nodes[1].replica().engine().metrics.places, 2);
}

#[test]
fn voter_speculate_still_rejects_tampered_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    cluster.nodes[1].speculate(&batch_a());
    let mut bad = cluster.nodes[0].get_value(&batch_a());
    bad.state_root = Bytes32([0xff; 32]);
    assert_eq!(
        cluster.nodes[1].validate_proposal(&bad, Some(&batch_a())),
        Validity::Invalid
    );
}

#[test]
fn proposer_validate_reuses_getvalue_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let value = cluster.nodes[0].get_value(&batch_a());
    assert_eq!(
        cluster.nodes[0].validate_proposal(&value, Some(&batch_a())),
        Validity::Valid
    );
    cluster.nodes[0].decide(&value, &batch_a()).unwrap();
    assert_eq!(cluster.nodes[0].replica().engine().metrics.places, 2);
}

#[test]
fn proposer_validate_still_rejects_tampered_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let value = cluster.nodes[0].get_value(&batch_a());
    let mut bad = value;
    bad.state_root = Bytes32([0xff; 32]);
    assert_eq!(
        cluster.nodes[0].validate_proposal(&bad, Some(&batch_a())),
        Validity::Invalid
    );
}

#[test]
fn decide_binds_c_after_one_apply() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let id = run_height(&mut cluster, &batch_a(), [true; 4]).unwrap();
    assert_eq!(cluster.nodes[0].decided_id(1).unwrap(), id);
    assert_eq!(cluster.nodes[0].replica().engine().metrics.places, 2);
}

#[test]
fn loaded_propose_state_root_is_treap() {
    let dir = tempfile::tempdir().unwrap();
    let mut cluster = Cluster::open_four(dir.path(), genesis()).unwrap();
    let preload = load_places(8);
    for n in &mut cluster.nodes {
        n.preload(&preload).unwrap();
    }
    let tape = churn_tape(8, 4);
    let value = cluster.nodes[0].get_value(&tape);
    let mut scratch = cluster.nodes[0].replica().engine().clone();
    scratch.apply_all(tape);
    assert_eq!(value.state_root, scratch.incremental_root().to_bytes32());
    assert_ne!(value.state_root, scratch.full_walk_root().to_bytes32());
}
