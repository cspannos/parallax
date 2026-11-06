//! Remaining PQ gaps (ADRs 0033 / 0034): owner-signed orders, and Malachite's
//! libp2p connections inside the hybrid tunnel.

use std::time::Duration;

use clob::testutil::{genesis, id_of, limit, load_places};
use consensus_adapter::engine::{start_cluster, AppOpts, ClusterSpec, RunningNode};
use consensus_adapter::order_auth::{is_system_input, owner_of, sign_order};
use consensus_adapter::pq_tunnel::tunnel_stats;
use crypto_suite::{SuitePolicy, SuiteSigningKey};
use protocol_types::CryptoSuiteId::{ClassicalV0 as C, HybridV1 as H};
use protocol_types::{Input, Order, Side};

fn base_port(slot: usize) -> usize {
    20_000 + (std::process::id() as usize % 50) * 200 + slot * 60
}

async fn decision(node: &mut RunningNode, h: u64) -> consensus_adapter::engine::Decision {
    loop {
        let d = tokio::time::timeout(Duration::from_secs(30), node.decisions.recv())
            .await
            .expect("decision in time")
            .expect("open");
        if d.height == h {
            return d;
        }
    }
}

fn place_by(key: &SuiteSigningKey, nonce: u64, price: u64) -> Input {
    let Input::Place(o) = Input::Place(limit(1, 1, Side::Buy, price, 10, nonce)) else { unreachable!() };
    Input::Place(Order { owner: owner_of(&key.public()), ..o })
}

/// Hybrid accounts' signed orders are admitted and decided; unsigned,
/// wrongly-signed and classical (downgraded) orders never reach `I`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn only_validly_signed_hybrid_orders_reach_i() {
    let spec = ClusterSpec::tcp(4, base_port(0))
        .tiered(1)
        .with_preload(load_places(20))
        .with_signed_orders(SuitePolicy::HYBRID)
        .with_app(AppOpts { emit_inputs: true, ..AppOpts::default() });
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); 4], spec).await.unwrap();
    decision(&mut nodes[0], 1).await;

    let alice = SuiteSigningKey::from_seed(H, [11; 32]);
    let bob = SuiteSigningKey::from_seed(H, [12; 32]);
    let carol = SuiteSigningKey::from_seed(C, [13; 32]);
    let good: Vec<Input> = (1..=3).map(|n| place_by(&alice, n, 3)).chain([place_by(&bob, 1, 2)]).collect();
    for i in &good {
        nodes[1].offer_signed(i.clone(), sign_order(if i == &good[3] { &bob } else { &alice }, i)).unwrap();
    }
    // Unsigned; signed by the wrong key; a classical account under a hybrid policy.
    nodes[1].offer(place_by(&alice, 4, 3)).unwrap();
    let stolen = place_by(&alice, 5, 3);
    nodes[1].offer_signed(stolen.clone(), sign_order(&bob, &stolen)).unwrap();
    let weak = place_by(&carol, 1, 3);
    nodes[1].offer_signed(weak.clone(), sign_order(&carol, &weak)).unwrap();

    let mut got = Vec::new();
    for h in 2..=4 {
        if let Some(i) = decision(&mut nodes[0], h).await.inputs {
            got.extend(i.into_iter().filter(|i| !is_system_input(i)));
        }
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    let mut want = good.clone();
    want.sort_by_key(|i| format!("{i:?}"));
    got.sort_by_key(|i| format!("{i:?}"));
    assert_eq!(got, want, "exactly the four signed hybrid orders");
}

/// Malachite traffic through the hybrid tunnel: the cluster decides, and the
/// tunnels (not direct libp2p dials) carried it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hybrid_tunnel_cluster_decides() {
    if std::env::var("PLX_M7_LOG").is_ok() {
        let _ = tracing_subscriber::fmt().with_env_filter("warn,consensus_adapter=debug").try_init();
    }
    let before = tunnel_stats();
    let spec = ClusterSpec::tcp(4, base_port(1)).tiered(1).with_pq_tunnel();
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); 4], spec).await.unwrap();
    for h in 1..=3 {
        decision(&mut nodes[0], h).await;
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    let (ok, _) = tunnel_stats();
    assert!(ok - before.0 >= 6, "tunnels carried the peer links: {}", ok - before.0);
}

/// A classical validator cannot open a tunnel to hybrid-policy peers. With one
/// of four classical, the three hybrid validators still decide; the classical
/// node's handshakes are rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn classical_validator_cannot_tunnel_under_hybrid_policy() {
    let before = tunnel_stats();
    let spec = ClusterSpec::tcp(4, base_port(2))
        .hybrid()
        .with_key_suites(vec![H, H, H, C])
        .with_pq_tunnel();
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); 4], spec).await.unwrap();
    for h in 1..=2 {
        decision(&mut nodes[0], h).await;
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    let (_, rejected) = tunnel_stats();
    assert!(rejected > before.1, "classical handshakes were rejected");
}

/// `AdvanceHeight` is a protocol input. Offered by a client (or gossiped) it
/// would expire every resting order with an expiry and wedge later advances;
/// it never reaches `I`, in any mode. The order offered with it does. The only
/// advances in `I` are the protocol's own, one per height, first.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn client_cannot_inject_advance_height() {
    let spec = ClusterSpec::tcp(4, base_port(3))
        .with_preload(load_places(20))
        .with_intent_gossip()
        .with_app(AppOpts { emit_inputs: true, ..AppOpts::default() });
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); 4], spec).await.unwrap();
    decision(&mut nodes[0], 1).await;
    let order = Input::Place(limit(1, 7, Side::Buy, 2, 10, 1));
    nodes[1].offer(Input::AdvanceHeight { to: protocol_types::Height(1_000_000_000) }).unwrap();
    nodes[1].offer(order.clone()).unwrap();
    let mut got = Vec::new();
    for h in 2..=3 {
        let i = decision(&mut nodes[0], h).await.inputs.unwrap_or_default();
        assert_eq!(i.first(), Some(&Input::AdvanceHeight { to: protocol_types::Height(h) }));
        got.extend(i.into_iter().skip(1));
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    assert_eq!(got, vec![order]);
}

/// Order expiry fires under consensus: each height's `I` starts with the
/// protocol's `AdvanceHeight`, so an order good until height 3 rests, then is
/// expired by the advance to 4. A local replay of the decided `I` reproduces
/// every decided state root.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn orders_expire_under_consensus() {
    let preload = load_places(20);
    let spec = ClusterSpec::tcp(4, base_port(4))
        .with_preload(preload.clone())
        .with_intent_gossip()
        .with_app(AppOpts { emit_inputs: true, ..AppOpts::default() });
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); 4], spec).await.unwrap();
    let d1 = decision(&mut nodes[0], 1).await;
    let Input::Place(o) = Input::Place(limit(1, 7, Side::Buy, 2, 10, 1)) else { unreachable!() };
    nodes[1].offer(Input::Place(Order { expiry: protocol_types::Height(3), ..o })).unwrap();

    let mut engine = clob::Engine::<clob::BTreeBook>::new(genesis());
    engine.apply_all(preload);
    engine.apply_all(d1.inputs.unwrap_or_default());
    assert_eq!(engine.state_root().to_bytes32(), d1.value.state_root);
    let mut expired_at = None;
    for h in 2..=5 {
        let d = decision(&mut nodes[0], h).await;
        for r in engine.apply_all(d.inputs.unwrap_or_default()) {
            if let clob::Outcome::HeightAdvanced { expired } = r.outcome {
                if expired.contains(&id_of(7, 1)) {
                    expired_at = Some(h);
                }
            }
        }
        assert_eq!(engine.state_root().to_bytes32(), d.value.state_root, "height {h}");
        assert_eq!(engine.height(), protocol_types::Height(h));
    }
    for n in nodes {
        let _ = n.shutdown().await;
    }
    assert_eq!(expired_at, Some(4), "expired by the advance to height 4");
}
