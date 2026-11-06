//! ADR 0017–0019: localhost intent gossip; offer after decide; `gossip_spread`.

use std::time::Duration;

use clob::testutil::{genesis, limit};
use consensus_adapter::{start_cluster, ClusterSpec, Decision, RunningNode};
use protocol_types::{Input, Side};
use tokio::time::timeout;

fn batch_a() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 10, 1)),
    ]
}

fn port(band: usize) -> usize {
    44000 + band * 20 + (std::process::id() as usize % 20)
}

async fn await_height(nodes: &mut [RunningNode], height: u64) -> Decision {
    let mut got = Vec::new();
    for n in nodes {
        let d = timeout(Duration::from_secs(30), n.decisions.recv())
            .await
            .expect("timeout waiting for decide")
            .expect("decision channel closed");
        assert_eq!(d.height, height);
        got.push(d);
    }
    for d in &got[1..] {
        assert_eq!(d.id, got[0].id);
    }
    got.remove(0)
}

async fn decide_same_id(inputs: Vec<Option<Vec<Input>>>, band: usize) {
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(4, port(band)).with_intent_gossip();
    let mut nodes = start_cluster(dir.path(), genesis(), inputs, spec)
        .await
        .expect("start gossip cluster");
    let _ = await_height(&mut nodes, 1).await;
    for n in nodes {
        let _ = n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_seed_gossips_i_others_decide_the_same_id() {
    let b = batch_a();
    decide_same_id(vec![Some(b), Some(vec![]), Some(vec![]), Some(vec![])], 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn split_offers_union_at_seal() {
    let b = batch_a();
    decide_same_id(
        vec![
            Some(vec![b[0].clone()]),
            Some(vec![b[1].clone()]),
            Some(vec![]),
            Some(vec![]),
        ],
        2,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn offer_after_height1_is_height2() {
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(4, port(3)).with_intent_gossip();
    let empty = vec![Some(vec![]); 4];
    let mut nodes = start_cluster(dir.path(), genesis(), empty, spec)
        .await
        .expect("start");
    let h1 = await_height(&mut nodes, 1).await;
    let t = std::time::Instant::now();
    for input in batch_a() {
        nodes[0].offer(input).expect("offer");
    }
    let h2 = await_height(&mut nodes, 2).await;
    assert_ne!(h1.id, h2.id);
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "height 2 paid ready_delay: {:?}",
        t.elapsed()
    );
    for n in nodes {
        let _ = n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn split_offer_after_height1_unions_at_height2() {
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(4, port(4)).with_intent_gossip();
    let empty = vec![Some(vec![]); 4];
    let mut nodes = start_cluster(dir.path(), genesis(), empty, spec)
        .await
        .expect("start");
    let h1 = await_height(&mut nodes, 1).await;
    let b = batch_a();
    nodes[0].offer(b[0].clone()).expect("offer 0");
    nodes[1].offer(b[1].clone()).expect("offer 1");
    let h2 = await_height(&mut nodes, 2).await;
    assert_ne!(h1.id, h2.id);
    for n in nodes {
        let _ = n.shutdown().await;
    }
}
