//! Phase 7 (ADR 0030): validator signatures under a crypto suite policy.
//! Hybrid = Ed25519 + ML-DSA-65, both must verify. A node rejects any vote or
//! proposal below its minimum suite, so a downgrade costs liveness, not safety.

use std::time::Duration;

use clob::testutil::genesis;
use consensus_adapter::engine::{await_decisions, start_cluster, ClusterSpec};
use consensus_adapter::order_auth::is_system_input;
use protocol_types::CryptoSuiteId::{ClassicalV0 as C, HybridV1 as H};

/// Slots are 16 ports apart: n=4 tiered uses consensus, gossip and cert ports.
fn base_port(slot: usize) -> usize {
    30_000 + (std::process::id() as usize % 100) * 160 + slot * 16
}

async fn decides(spec: ClusterSpec, heights: u64, wait: Duration) -> bool {
    if std::env::var("PLX_M7_LOG").is_ok() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();
    }
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); spec.n], spec)
        .await
        .expect("start");
    let mut ok = true;
    for h in 1..=heights {
        if await_decisions(&mut nodes, h, wait).await.is_err() {
            ok = false;
            break;
        }
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    ok
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hybrid_cluster_decides() {
    let spec = ClusterSpec::tcp(4, base_port(0)).hybrid();
    assert!(decides(spec, 3, Duration::from_secs(30)).await);
}

/// One classical key under a hybrid policy: its votes are rejected, but the
/// three hybrid validators are still a quorum.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hybrid_policy_tolerates_one_classical_key() {
    let spec = ClusterSpec::tcp(4, base_port(1))
        .hybrid()
        .with_key_suites(vec![H, H, H, C]);
    assert!(decides(spec, 2, Duration::from_secs(30)).await);
}

/// Two classical keys under a hybrid policy: only two valid voters, below
/// quorum. No height may decide.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hybrid_policy_rejects_downgraded_quorum() {
    let spec = ClusterSpec::tcp(4, base_port(2))
        .hybrid()
        .with_key_suites(vec![H, H, C, C]);
    assert!(!decides(spec, 1, Duration::from_secs(15)).await);
}

/// The classical path still works: classical policy accepts mixed suites.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn classical_policy_accepts_mixed_suites() {
    let spec = ClusterSpec::tcp(4, base_port(3)).with_key_suites(vec![H, H, C, C]);
    assert!(decides(spec, 2, Duration::from_secs(30)).await);
}

/// Intents reach every validator over the suite handshake and sealed frames,
/// and land in the decided input set. Hybrid and classical both work.
async fn secured_gossip_includes(spec: ClusterSpec) -> usize {
    use clob::testutil::{churn_wave, load_places};
    use consensus_adapter::engine::{await_seal, AppOpts};
    let dir = tempfile::tempdir().unwrap();
    let spec = spec
        .with_preload(load_places(20))
        .with_secure_gossip()
        .with_app(AppOpts {
            emit_inputs: true,
            ..AppOpts::default()
        });
    let n = spec.n;
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec)
        .await
        .expect("start");
    let wait = Duration::from_secs(30);
    await_seal(&mut nodes[1], 1, wait).await.expect("seal 1");
    nodes[1].offer_all(churn_wave(20, 8, 0)).unwrap();
    let mut included = 0;
    'outer: for h in 1..=4 {
        let d = loop {
            let d = tokio::time::timeout(wait, nodes[0].decisions.recv())
                .await
                .expect("decision")
                .expect("open");
            if d.height == h {
                break d;
            }
        };
        included += d.inputs.map_or(0, |i| i.iter().filter(|i| !is_system_input(i)).count());
        if included >= 8 {
            break 'outer;
        }
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    included
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hybrid_secured_gossip_delivers_intents() {
    let spec = ClusterSpec::tcp(4, base_port(4)).hybrid();
    assert_eq!(secured_gossip_includes(spec).await, 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn classical_secured_gossip_delivers_intents() {
    let spec = ClusterSpec::tcp(4, base_port(5));
    assert_eq!(secured_gossip_includes(spec).await, 8);
}

/// Tiered finality (ADR 0031): votes carry Ed25519 only; each decided height
/// gets a 2f+1 hybrid finality certificate at its collectors, and it verifies
/// under the hybrid policy against the full-key roster.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tiered_cluster_certifies_every_height() {
    use consensus_adapter::engine::make_validators_with;
    use consensus_adapter::finality::collectors;
    use crypto_suite::SuitePolicy;

    let n = 4;
    let spec = ClusterSpec::tcp(n, base_port(6)).tiered(2);
    let roster: Vec<_> = make_validators_with(&[H; 4], 42).iter().map(|k| k.private.public()).collect();
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec)
        .await
        .expect("start");
    let wait = Duration::from_secs(30);
    let mut ids = Vec::new();
    for h in 1..=3u64 {
        let d = loop {
            let d = tokio::time::timeout(wait, nodes[0].decisions.recv()).await.unwrap().unwrap();
            if d.height == h {
                break d;
            }
        };
        ids.push(d.id);
    }
    for (h, id) in (1..=3u64).zip(&ids) {
        for c in collectors(h, n, 2) {
            let cert = loop {
                let cert = tokio::time::timeout(wait, nodes[c].finality.recv()).await.unwrap().unwrap();
                if cert.height == h {
                    break cert;
                }
            };
            assert_eq!(&cert.value_id, id, "collector {c} height {h}");
            assert_eq!(cert.verify(SuitePolicy::HYBRID, &roster), Ok(()));
            assert!(cert.sigs.len() >= 3);
        }
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
}

/// Collector failover (ADR 0031). k=1: height 2's only collector is node 2.
/// Shut it down; validators get no `Certified` notice, re-send to the next
/// collector after `finality_failover`, and a consumer fetches a valid
/// certificate without asking for anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tiered_failover_when_collector_down() {
    let (cert, _) = tiered_scenario(base_port(7), None).await;
    assert_eq!(cert.recollects, 0, "timeout failover alone produced it");
}

/// A collector that announces a certificate but never serves it: the
/// consumer's fetch fails, it requests a recollect, the next collector forms
/// and serves the certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn tiered_recollect_routes_around_withholding_collector() {
    let (cert, _) = tiered_scenario(base_port(8), Some(2)).await;
    assert!(cert.recollects >= 1, "needed a recollect: {}", cert.recollects);
}

/// `withhold = None`: kill node 2 after height 1. `Some(2)`: node 2 withholds.
async fn tiered_scenario(
    port: usize,
    withhold: Option<usize>,
) -> (consensus_adapter::finality_net::Obtained, ()) {
    use consensus_adapter::engine::make_validators_with;
    use consensus_adapter::finality_net::{cert_addr, obtain_certificate};
    use crypto_suite::SuitePolicy;

    let n = 4;
    let mut spec = ClusterSpec::tcp(n, port).tiered(1);
    spec.finality_failover = Duration::from_millis(300);
    if let Some(w) = withhold {
        spec.withhold_certs = vec![w];
    }
    let roster: Vec<_> = make_validators_with(&[H; 4], 42).iter().map(|k| k.private.public()).collect();
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec)
        .await
        .expect("start");
    let wait = Duration::from_secs(30);
    next_decision(1, &mut nodes[0], wait).await;
    if withhold.is_none() {
        let dead = nodes.remove(2);
        let _ = dead.shutdown().await;
    }
    let d2 = next_decision(2, &mut nodes[0], wait).await;
    next_decision(3, &mut nodes[0], wait).await;
    let addrs: Vec<_> = (0..n).map(|i| cert_addr(port, n, i)).collect();
    let got = obtain_certificate(
        &addrs,
        2,
        d2.id,
        SuitePolicy::HYBRID,
        &roster,
        1,
        Duration::from_millis(800),
        Duration::from_secs(20),
    )
    .await
    .expect("certificate for height 2");
    assert_eq!(got.cert.verify(SuitePolicy::HYBRID, &roster), Ok(()));
    assert_eq!(got.cert.value_id, d2.id);
    for n in nodes {
        let _ = n.shutdown().await;
    }
    (got, ())
}

async fn next_decision(
    h: u64,
    node: &mut consensus_adapter::engine::RunningNode,
    wait: Duration,
) -> consensus_adapter::engine::Decision {
    loop {
        let d = tokio::time::timeout(wait, node.decisions.recv()).await.unwrap().unwrap();
        if d.height == h {
            return d;
        }
    }
}
