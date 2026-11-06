//! M4b: same FULL_VIEW decide test at 7 / 10 / 20 / 50 / 100 validators.
//!
//! 7 and 10 run in the default suite. 20 / 50 / 100 are `#[ignore]` (localhost
//! file-descriptor and CPU bound). Percentiles: `cargo run -p m4-scale --release`.

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
    30000 + band * 250 + (std::process::id() as usize % 40)
}

fn timeout_for(n: usize) -> Duration {
    Duration::from_secs(match n {
        0..=10 => 30,
        11..=20 => 60,
        21..=50 => 120,
        _ => 180,
    })
}

async fn scale_tcp(n: usize, band: usize, heights: u64) {
    let dir = tempfile::tempdir().unwrap();
    let spec = ClusterSpec::tcp(n, base_port(band));
    let mut nodes = start_cluster(dir.path(), genesis(), all_have_i(n), spec)
        .await
        .unwrap_or_else(|e| panic!("start n={n}: {e:#}"));
    let samples = run_heights(&mut nodes, heights, timeout_for(n))
        .await
        .unwrap_or_else(|e| panic!("decide n={n}: {e:#}"));
    assert_eq!(samples.len(), heights as usize);
    for s in &samples {
        assert_eq!(s.node_ms.len(), n);
        assert!(
            s.cluster_ms > 0,
            "zero cluster latency at height {}",
            s.height
        );
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn seven_tcp_nodes_decide() {
    scale_tcp(7, 1, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_tcp_nodes_decide() {
    scale_tcp(10, 2, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "localhost n=20: run with --ignored or cargo run -p m4-scale --release"]
async fn twenty_tcp_nodes_decide() {
    scale_tcp(20, 3, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "localhost n=50: file descriptors / CPU; cargo run -p m4-scale --release"]
async fn fifty_tcp_nodes_decide() {
    scale_tcp(50, 4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "localhost n=100: file descriptors / CPU; cargo run -p m4-scale --release"]
async fn hundred_tcp_nodes_decide() {
    scale_tcp(100, 5, 1).await;
}
