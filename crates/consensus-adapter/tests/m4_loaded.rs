//! Loaded-book Malachite height: treap `C'` + height WAL (ADR 0012 / 0013).
//!
//! Small tape for CI. The 8k+10k cell is
//! `PLX_M4_LOADED=1 cargo run -p m4-scale --release`.

use std::time::Duration;

use clob::testutil::{churn_tape, churn_wave, genesis, load_places};
use consensus_adapter::{
    await_decisions, await_seal, run_heights, start_cluster, AppOpts, ClusterSpec,
};

fn base_port() -> usize {
    35000 + (std::process::id() as usize % 80)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_nodes_decide_loaded_height() {
    let n = 4;
    let resting = 32;
    let batch = 8;
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port()).with_preload(load_places(resting));
    let tape = churn_tape(resting, batch);
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(tape); n], spec)
        .await
        .expect("start");
    let samples = run_heights(&mut nodes, 1, Duration::from_secs(30))
        .await
        .expect("loaded height");
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].node_ms.len(), n);
    for node in nodes {
        let _ = node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_nodes_stubv_loaded_height() {
    let n = 4;
    let resting = 32;
    let batch = 8;
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port() + 40)
        .with_preload(load_places(resting))
        .with_app(AppOpts {
            stub_validate: true,
            stub_propose: false,
            skip_apply: false,
            emit_inputs: false,
        });
    let tape = churn_tape(resting, batch);
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(tape); n], spec)
        .await
        .expect("start stubV");
    let samples = run_heights(&mut nodes, 1, Duration::from_secs(30))
        .await
        .expect("stubV loaded height");
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].node_ms.len(), n);
    for node in nodes {
        let _ = node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_nodes_gossip_offer_loaded_height() {
    let n = 4;
    let resting = 32;
    let batch = 8;
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port() + 80)
        .with_preload(load_places(resting))
        .with_intent_gossip();
    let tape = churn_tape(resting, batch);
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec)
        .await
        .expect("start gossip loaded");
    let h1 = await_decisions(&mut nodes, 1, Duration::from_secs(30))
        .await
        .expect("height 1");
    nodes[0].offer_all(tape).expect("offer tape");
    let h2 = await_decisions(&mut nodes, 2, Duration::from_secs(30))
        .await
        .expect("height 2");
    assert_ne!(h1[0].id, h2[0].id);
    for node in nodes {
        let _ = node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_nodes_gossip_steady_heights() {
    let n = 4;
    let resting = 32;
    let batch = 8;
    let last = 3u64;
    let wait = Duration::from_secs(30);
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port() + 90)
        .with_preload(load_places(resting))
        .with_intent_gossip();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec)
        .await
        .expect("start gossip steady");
    let mut prev_id = None;
    for h in 1..=last {
        await_seal(&mut nodes[0], h, wait)
            .await
            .unwrap_or_else(|e| panic!("seal {h}: {e}"));
        if h < last {
            nodes[0]
                .offer_all(churn_wave(resting, batch, h - 1))
                .expect("offer wave");
        }
        let dec = await_decisions(&mut nodes, h, wait)
            .await
            .unwrap_or_else(|e| panic!("height {h}: {e}"));
        if h >= 2 {
            assert_ne!(dec[0].id, prev_id.take().expect("prev id"));
        }
        prev_id = Some(dec[0].id);
    }
    for node in nodes {
        let _ = node.shutdown().await;
    }
}
