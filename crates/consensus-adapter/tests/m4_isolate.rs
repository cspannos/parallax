//! Isolate knobs: stub Validate / dummy propose still decide; GossipSub mesh at n=7.

use std::time::Duration;

use clob::testutil::{genesis, limit};
use consensus_adapter::{run_heights, start_cluster, AppOpts, ClusterSpec};
use protocol_types::{Input, Side};

fn batch_a() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 10, 1)),
    ]
}

fn all_have_i(n: usize) -> Vec<Option<Vec<Input>>> {
    vec![Some(batch_a()); n]
}

fn base_port(band: usize) -> usize {
    33000 + band * 250 + (std::process::id() as usize % 40)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn four_stub_dummy_skips_f_and_decides() {
    let n = 4;
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port(1)).with_app(AppOpts {
        stub_validate: true,
        stub_propose: true,
        skip_apply: true,
        emit_inputs: false,
    });
    let mut nodes = start_cluster(dir.path(), genesis(), all_have_i(n), spec)
        .await
        .expect("start");
    let samples = run_heights(&mut nodes, 2, Duration::from_secs(20))
        .await
        .expect("decide");
    assert_eq!(samples.len(), 2);
    for s in &samples {
        assert_eq!(s.node_ms.len(), n);
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn seven_gossipsub_mesh_decides() {
    let n = 7;
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port(2)).gossipsub_mesh();
    let mut nodes = start_cluster(dir.path(), genesis(), all_have_i(n), spec)
        .await
        .expect("start gossipsub");
    let samples = run_heights(&mut nodes, 1, Duration::from_secs(30))
        .await
        .expect("gossipsub decide");
    assert_eq!(samples[0].node_ms.len(), n);
    for n in nodes {
        let _ = n.shutdown().await;
    }
}
