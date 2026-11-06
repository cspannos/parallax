//! M4c: QUIC vs TCP on the same broadcast mesh (n=10). Measure; do not assume.
//!
//! This is Malachite consensus gossip (votes + `ConsensusValue` parts), not a
//! 1 MB DA blob and not the private `I` channel (still out of band, ADR 0009).

use std::time::Duration;

use clob::testutil::{genesis, limit};
use consensus_adapter::{run_heights, start_cluster, ClusterSpec};
use protocol_types::{Input, Side};

fn batch_a() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 5, 10, 1)),
        Input::Place(limit(2, 2, Side::Buy, 3, 10, 1)),
    ]
}

fn all_have_i(n: usize) -> Vec<Option<Vec<Input>>> {
    let b = batch_a();
    vec![Some(b); n]
}

fn base_port(band: usize) -> usize {
    32000 + band * 250 + (std::process::id() as usize % 40)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_quic_nodes_decide() {
    let n = 10;
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::quic(n, base_port(1));
    let mut nodes = start_cluster(dir.path(), genesis(), all_have_i(n), spec)
        .await
        .expect("start quic n=10");
    let samples = run_heights(&mut nodes, 2, Duration::from_secs(45))
        .await
        .expect("quic decide");
    assert_eq!(samples.len(), 2);
    for s in &samples {
        assert_eq!(s.node_ms.len(), n);
        assert!(s.cluster_ms > 0);
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
}
