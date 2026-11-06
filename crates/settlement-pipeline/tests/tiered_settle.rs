//! Tiered finality on the settlement path (ADR 0031): a decided height
//! settles only with a 2f+1 hybrid finality certificate fetched from the
//! validators' cert servers. The unlock here is the follower's own
//! FULL_VIEW replay; the real-`π` version is `bin/e2e`.

use std::sync::Arc;
use std::time::Duration;

use clob::testutil::{btree_engine, churn_wave, genesis, load_places, owner};
use consensus_adapter::engine::{await_seal, make_validators_with, start_cluster, AppOpts, ClusterSpec};
use consensus_adapter::finality_net::{cert_addr, obtain_certificate};
use crypto_suite::SuitePolicy;
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{InertReason, NoHeightStark, OnDecided, SettlementGate, Unlock};
use protocol_types::{AssetId, CryptoSuiteId};
use settlement_pipeline::Follower;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn heights_settle_only_with_a_finality_certificate() {
    let (n, rest) = (4, 20);
    let port = 33_000 + (std::process::id() as usize % 100) * 20;
    let spec = ClusterSpec::tcp(n, port)
        .tiered(1)
        .with_preload(load_places(rest))
        .with_app(AppOpts {
            emit_inputs: true,
            ..AppOpts::default()
        });
    let roster = Arc::new(
        make_validators_with(&[CryptoSuiteId::HybridV1; 4], 42)
            .iter()
            .map(|k| k.private.public())
            .collect::<Vec<_>>(),
    );
    let addrs: Vec<_> = (0..n).map(|i| cert_addr(port, n, i)).collect();
    let dir = tempfile::tempdir().unwrap();
    let mut nodes = start_cluster(dir.path().join("nodes"), genesis(), vec![Some(vec![]); n], spec)
        .await
        .unwrap();

    let mut base = btree_engine();
    base.apply_all(load_places(rest));
    let mut follower = Follower::new(base, 1);
    let mut ledger = Ledger::new();
    for o in 1..=3u8 {
        for a in [AssetId(1), AssetId(2)] {
            ledger.genesis_fund(owner(o), a, 1_000_000_000);
        }
    }
    let mut gate = SettlementGate::new(AtomicApply::open(dir.path().join("settle.log"), ledger).unwrap(), NoHeightStark)
        .require_finality(SuitePolicy::HYBRID, roster.clone());
    let start = gate.eth_get_balance(owner(2), AssetId(1));

    let wait = Duration::from_secs(30);
    let mut prev_cert = None;
    for h in 1..=3u64 {
        await_seal(&mut nodes[0], h, wait).await.unwrap();
        if h < 3 {
            nodes[0].offer_all(churn_wave(rest, 8, h - 1)).unwrap();
        }
        let dec = loop {
            let d = tokio::time::timeout(wait, nodes[0].decisions.recv()).await.unwrap().unwrap();
            if d.height == h {
                break d;
            }
        };
        let d = follower.on_decided(&dec.value, dec.inputs.as_deref().unwrap()).unwrap();
        let full = Unlock::FullViewCertificate;

        // FULL_VIEW unlock without a certificate: inert.
        let out = gate.on_decided_final(&d.value, &d.deltas, &d.statement, Some(&full), None).unwrap();
        assert_eq!(out, OnDecided::Inert { reason: InertReason::MissingFinality });
        // The previous height's certificate: inert.
        if let Some(prev) = &prev_cert {
            let out = gate
                .on_decided_final(&d.value, &d.deltas, &d.statement, Some(&full), Some(prev))
                .unwrap();
            assert_eq!(out, OnDecided::Inert { reason: InertReason::FinalityInvalid });
        }
        let got = obtain_certificate(
            &addrs,
            h,
            dec.id,
            SuitePolicy::HYBRID,
            &roster,
            1,
            Duration::from_millis(800),
            Duration::from_secs(20),
        )
        .await
        .expect("certificate");
        let out = gate
            .on_decided_final(&d.value, &d.deltas, &d.statement, Some(&full), Some(&got.cert))
            .unwrap();
        assert!(matches!(out, OnDecided::Settled(_)), "height {h}: {out:?}");
        prev_cert = Some(got.cert);
    }
    assert_ne!(gate.eth_get_balance(owner(2), AssetId(1)), start, "trades settled");
    for node in nodes {
        let _ = node.shutdown().await;
    }
}
