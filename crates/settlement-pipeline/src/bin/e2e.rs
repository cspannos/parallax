//! End-to-end `π` pipeline on a local cluster (ADR 0028).
//!
//!   cargo run --release -p settlement-pipeline --features risc0 --bin e2e
//!
//! Four validators decide heights (intent gossip, small preloaded book). A
//! FULL_VIEW follower replays each decided height and writes a proof job; the
//! RISC Zero `prover` service (spawned from `zkvm/risc0`) answers with a
//! receipt; `SettlementGate<Risc0FVerifier>` settles the height only then.
//!
//! Env: `PLX_PIPE_REST` (resting orders, 20), `PLX_PIPE_EVENTS` (events per
//! loaded height, 8), `PLX_PIPE_HEIGHTS` (loaded heights, 3),
//! `PLX_PIPE_PROVERS` (prover processes sharing the job directory, 1),
//! `PLX_PIPE_THREADS` (cores per prover via `RAYON_NUM_THREADS`; emulates N
//! separate machines on one host),
//! `PLX_PIPE_NO_PROVER=1` (use already-running provers on `PLX_PIPE_DIR`),
//! `PLX_PIPE_TIERED` (finality collectors, 1; `0` = no finality certificate).
//! With tiered finality (ADR 0031) a height needs its receipt **and** a 2f+1
//! hybrid finality certificate fetched from the validators' cert servers.
//! Settlement is in height order whatever order receipts land in.
//! CPU prover; times are this host's.

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clob::testutil::{btree_engine, churn_wave, genesis, load_places, owner};
use consensus_adapter::engine::{await_seal, make_validators_with, start_cluster, AppOpts, ClusterSpec};
use consensus_adapter::finality_net::{cert_addr, obtain_certificate};
use crypto_suite::SuitePolicy;
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{InertReason, OnDecided, Risc0FVerifier, SettlementGate, Unlock};
use protocol_types::{AssetId, CryptoSuiteId};
use settlement_pipeline::{Follower, JobDir};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().map_or(default, |v| v.parse().expect(name))
}

struct ProverChildren(Vec<Child>, std::path::PathBuf);

impl Drop for ProverChildren {
    fn drop(&mut self) {
        let _ = std::fs::write(self.1.join("stop"), b"");
        for c in &mut self.0 {
            let _ = c.kill();
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> eyre::Result<()> {
    if std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1") {
        eyre::bail!("RISC0_DEV_MODE=1 is not π; refuse to run");
    }
    let rest = env_usize("PLX_PIPE_REST", 20);
    let events = env_usize("PLX_PIPE_EVENTS", 8);
    let loaded = env_usize("PLX_PIPE_HEIGHTS", 3) as u64;
    let tmp = tempfile::tempdir()?;
    let pipe_root = std::env::var("PLX_PIPE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| tmp.path().join("pipe"));
    let jobs = JobDir::create(&pipe_root)?;
    let _ = std::fs::remove_file(pipe_root.join("stop"));

    // Prover service (separate process, separate Cargo workspace).
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let provers = env_usize("PLX_PIPE_PROVERS", 1);
    let mut children = Vec::new();
    if std::env::var("PLX_PIPE_NO_PROVER").ok().as_deref() != Some("1") {
        // Build once, then start N processes of the binary (no concurrent cargo).
        let status = Command::new("cargo")
            .args(["build", "--release", "-q", "-p", "host", "--bin", "prover", "--manifest-path"])
            .arg(repo.join("zkvm/risc0/Cargo.toml"))
            .env("RISC0_DEV_MODE", "0")
            .status()?;
        eyre::ensure!(status.success(), "prover build failed");
        for w in 0..provers {
            children.push(
                Command::new(repo.join("zkvm/risc0/target/release/prover"))
                    .env("PLX_PROVER_DIR", &pipe_root)
                    .env("PLX_PROVER_WORKER", format!("w{w}"))
                    // Cores per prover (emulates N separate machines on one host).
                    .envs(std::env::var("PLX_PIPE_THREADS").ok().map(|t| ("RAYON_NUM_THREADS", t)))
                    .env("RISC0_DEV_MODE", "0")
                    .spawn()?,
            );
        }
    }
    let _guard = ProverChildren(children, pipe_root.clone());
    let t_wait = Instant::now();
    let image_id = loop {
        if let Some(id) = jobs.image_id() {
            break id;
        }
        if t_wait.elapsed() > Duration::from_secs(1800) {
            eyre::bail!("prover did not start");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    println!("prover ready (image id from prover; a deployment pins it in config)");

    // Validators.
    let tiered = env_usize("PLX_PIPE_TIERED", 1);
    let (n, port) = (4, 46_500);
    let mut spec = ClusterSpec::tcp(n, port)
        .with_preload(load_places(rest))
        .with_intent_gossip()
        .with_app(AppOpts {
            emit_inputs: true,
            ..AppOpts::default()
        });
    if tiered > 0 {
        spec = spec.tiered(tiered);
    }
    let roster = Arc::new(
        make_validators_with(&[CryptoSuiteId::HybridV1; 4], 42)
            .iter()
            .map(|k| k.private.public())
            .collect::<Vec<_>>(),
    );
    let cert_addrs: Vec<_> = (0..n).map(|i| cert_addr(port, n, i)).collect();
    let mut nodes = start_cluster(tmp.path().join("nodes"), genesis(), vec![Some(vec![]); 4], spec).await?;

    // FULL_VIEW follower and settlement gate.
    let mut base = btree_engine();
    base.apply_all(load_places(rest));
    let mut follower = Follower::new(base, 1);
    let mut ledger = Ledger::new();
    for o in 1..=3u8 {
        for a in [AssetId(1), AssetId(2)] {
            ledger.genesis_fund(owner(o), a, 1_000_000_000);
        }
    }
    let mut gate = SettlementGate::new(
        AtomicApply::open(tmp.path().join("settle.log"), ledger)?,
        Risc0FVerifier { image_id },
    );
    if tiered > 0 {
        gate = gate.require_finality(SuitePolicy::HYBRID, roster.clone());
    }
    let start_balance = gate.eth_get_balance(owner(2), AssetId(1));

    // Decide heights; height 1 is empty, waves land in 2..=loaded+1.
    let last = loaded + 1;
    let wait = Duration::from_secs(60);
    let mut decided = Vec::new();
    for h in 1..=last {
        await_seal(&mut nodes[0], h, wait)
            .await
            .map_err(|e| eyre::eyre!("seal {h}: {e}"))?;
        if h < last {
            nodes[0].offer_all(churn_wave(rest, events, h - 1))?;
        }
        let dec = loop {
            let d = tokio::time::timeout(wait, nodes[0].decisions.recv())
                .await?
                .ok_or_else(|| eyre::eyre!("decisions closed"))?;
            if d.height == h {
                break d;
            }
        };
        let at = Instant::now();
        let inputs = dec.inputs.clone().ok_or_else(|| eyre::eyre!("no inputs on decision"))?;
        let d = follower.on_decided(&dec.value, &inputs)?;
        jobs.write_job(&d.job)?;
        // Before the proof (and certificate): decided, but settlement stays inert.
        let before = gate.on_decided_final(&d.value, &d.deltas, &d.statement, None, None)?;
        let want = if tiered > 0 { InertReason::MissingFinality } else { InertReason::MissingWitness };
        assert_eq!(before, OnDecided::Inert { reason: want });
        // The finality certificate (tiered): fetched from the cert servers.
        let cert = if tiered > 0 {
            let got = obtain_certificate(
                &cert_addrs,
                h,
                dec.id,
                SuitePolicy::HYBRID,
                &roster,
                tiered,
                Duration::from_secs(1),
                Duration::from_secs(30),
            )
            .await
            .ok_or_else(|| eyre::eyre!("no finality certificate for height {h}"))?;
            println!(
                "height {h}: finality certificate {} sigs, {} B, {} ms after decide",
                got.cert.sigs.len(),
                got.cert.encoded_len(),
                at.elapsed().as_millis()
            );
            Some(got.cert)
        } else {
            None
        };
        println!(
            "height {h}: decided, |I| {}, deltas {}, job written {} ms after decide; settlement inert",
            inputs.len(),
            d.deltas.len(),
            at.elapsed().as_millis()
        );
        decided.push((h, inputs.len(), d, at, cert));
    }
    for node in nodes {
        let _ = node.shutdown().await;
    }

    // Settle each height as its receipt lands (the prover works in order).
    let t_first = decided.first().map(|d| d.3).unwrap_or_else(Instant::now);
    println!("finality: {}", if tiered > 0 { format!("tiered, {tiered} collector(s); settlement needs receipt + certificate") } else { "off".into() });
    println!(
        "\n{provers} prover(s), {} threads each",
        std::env::var("PLX_PIPE_THREADS").unwrap_or_else(|_| "all".into())
    );
    println!("| height | |I| | deltas | prove (worker) | decide → settled | outcome |");
    println!("|---|---|---|---|---|---|");
    for (h, n_inputs, d, at, cert) in &decided {
        let receipt = loop {
            if let Some(r) = jobs.receipt(*h) {
                break r;
            }
            if at.elapsed() > Duration::from_secs(3600) {
                eyre::bail!("no receipt for height {h}");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        let prove = std::fs::read_to_string(pipe_root.join(format!("receipts/{h:010}.ms")))
            .unwrap_or_default();
        let mut it = prove.split_whitespace();
        let (prove_ms, worker) = (it.next().unwrap_or("?"), it.next().unwrap_or("?"));
        let out = gate.on_decided_final(&d.value, &d.deltas, &d.statement, Some(&Unlock::Proof(receipt)), cert.as_ref())?;
        let settled = matches!(out, OnDecided::Settled(_));
        println!(
            "| {h} | {n_inputs} | {} | {} ms ({worker}) | {:.1} s | {} |",
            d.deltas.len(),
            prove_ms,
            at.elapsed().as_secs_f64(),
            match (settled, cert.is_some()) {
                (true, true) => "settled by π + finality cert",
                (true, false) => "settled by π",
                _ => "NOT settled",
            }
        );
        eyre::ensure!(settled, "height {h} did not settle: {out:?}");
    }
    println!(
        "first decide → last settled: {:.1} s",
        t_first.elapsed().as_secs_f64()
    );
    let end_balance = gate.eth_get_balance(owner(2), AssetId(1));
    eyre::ensure!(end_balance != start_balance, "taker balance did not move");
    println!(
        "\nall {} heights settled by RISC Zero π of F; owner 2 base balance {start_balance} → {end_balance}",
        decided.len()
    );
    Ok(())
}
