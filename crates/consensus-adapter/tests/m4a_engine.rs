//! M4a engine: four FULL_VIEW Malachite nodes decide `ConsensusValue` with `F` in Validate.

use std::time::Duration;

use clob::testutil::{genesis, limit};
use consensus_adapter::{start_four, Validity};
use protocol_types::{Input, Side};
use tokio::time::timeout;

fn batch_a() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 10, 1)),
    ]
}

fn all_have_i() -> [Option<Vec<Input>>; 4] {
    let b = batch_a();
    [Some(b.clone()), Some(b.clone()), Some(b.clone()), Some(b)]
}

fn mixed_offer_order() -> [Option<Vec<Input>>; 4] {
    let fwd = batch_a();
    let rev: Vec<Input> = fwd.iter().rev().cloned().collect();
    [Some(fwd.clone()), Some(rev.clone()), Some(fwd), Some(rev)]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_engine_nodes_decide_the_same_id() {
    let dir = tempfile::tempdir().unwrap();
    let port = 41000 + (std::process::id() % 2000) as usize;
    let mut nodes = start_four(dir.path(), genesis(), all_have_i(), port)
        .await
        .expect("start four");

    let mut ids = Vec::new();
    for n in &mut nodes {
        let d = timeout(Duration::from_secs(20), n.decisions.recv())
            .await
            .expect("timeout waiting for decide")
            .expect("decision channel closed");
        assert_eq!(d.height, 1);
        ids.push(d.id);
    }
    for id in &ids[1..] {
        assert_eq!(*id, ids[0]);
    }

    for n in nodes {
        let _ = n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn opposite_offer_order_still_decides_the_same_id() {
    let dir = tempfile::tempdir().unwrap();
    let port = 42000 + (std::process::id() % 2000) as usize;
    let mut nodes = start_four(dir.path(), genesis(), mixed_offer_order(), port)
        .await
        .expect("start four");

    let mut ids = Vec::new();
    for n in &mut nodes {
        let d = timeout(Duration::from_secs(20), n.decisions.recv())
            .await
            .expect("timeout waiting for decide")
            .expect("decision channel closed");
        assert_eq!(d.height, 1);
        ids.push(d.id);
    }
    for id in &ids[1..] {
        assert_eq!(*id, ids[0]);
    }

    for n in nodes {
        let _ = n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn missing_i_node_does_not_block_quorum() {
    let dir = tempfile::tempdir().unwrap();
    let port = 43000 + (std::process::id() % 2000) as usize;
    let b = batch_a();
    let mut nodes = start_four(
        dir.path(),
        genesis(),
        [Some(b.clone()), Some(b.clone()), Some(b), None],
        port,
    )
    .await
    .expect("start four");

    let mut got = 0usize;
    for n in nodes.iter_mut().take(3) {
        let d = timeout(Duration::from_secs(20), n.decisions.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(d.height, 1);
        got += 1;
    }
    assert_eq!(got, 3);

    let dir2 = tempfile::tempdir().unwrap();
    let mut cluster = consensus_adapter::Cluster::open_four(dir2.path(), genesis()).unwrap();
    let value = cluster.nodes[0].get_value(&batch_a());
    assert_eq!(
        cluster.nodes[3].validate_proposal(&value, None),
        Validity::InsufficientView
    );

    for n in nodes {
        let _ = n.shutdown().await;
    }
}
