//! M4 isolate matrix: GossipSub vs broadcast, stub Validate, skip replica apply.
//!
//! ```text
//! PLX_M4_ISOLATE=1 cargo run -p m4-scale --release
//! PLX_M4_ISOLATE=1 PLX_M4_N=20,50 cargo run -p m4-scale --release
//! ```

use std::env;
use std::process::Command;
use std::time::{Duration, Instant};

use clob::testutil::{btree_engine, churn_tape, churn_wave, genesis, limit, load_places};
use consensus_adapter::{
    await_decisions, await_seal, commit_list, percentile_ms, run_heights, start_cluster, AdmitPath,
    AppOpts, ClusterSpec, Decision, IntentLog, ScaleRun, INPUT_DOMAIN,
};
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

fn timeout_for(n: usize) -> Duration {
    Duration::from_secs(match n {
        0..=10 => 45,
        11..=20 => 90,
        21..=50 => 180,
        _ => 300,
    })
}

fn default_heights(n: usize) -> u64 {
    match n {
        0..=10 => 8,
        11..=20 => 4,
        21..=50 => 2,
        _ => 1,
    }
}

fn parse_list(var: &str, default: &[usize]) -> Vec<usize> {
    match env::var(var) {
        Ok(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|p| p.trim().parse::<usize>().expect("integer in list"))
            .collect(),
        _ => default.to_vec(),
    }
}

/// `PLX_M4_SUITE=hybrid` signs votes/proposals with Ed25519 + ML-DSA-65 under
/// a hybrid-only policy; `PLX_M4_SECURE=1` runs intent gossip over the suite
/// handshake and sealed frames (ADR 0030).
fn suited(spec: ClusterSpec) -> ClusterSpec {
    let spec = match env::var("PLX_M4_SUITE").as_deref() {
        Ok("hybrid") => spec.hybrid(),
        Ok("classical") | Err(_) => spec,
        Ok(other) => panic!("unknown suite {other}"),
    };
    let spec = if env::var("PLX_M4_SECURE").ok().as_deref() == Some("1") && spec.intent_gossip {
        spec.with_secure_gossip()
    } else {
        spec
    };
    let spec = match env::var("PLX_M4_TIERED").ok().and_then(|k| k.parse().ok()) {
        Some(k) => spec.tiered(k),
        None => spec,
    };
    let spec = if env::var("PLX_M4_TUNNEL").ok().as_deref() == Some("1") {
        spec.with_pq_tunnel()
    } else {
        spec
    };
    match signed_suite() {
        Some(suite) => spec.with_signed_orders(crypto_suite::SuitePolicy { min: suite }),
        None => spec,
    }
}

/// `PLX_M4_SIGNED=1|hybrid|classical`: every account intent is signed by an
/// account key of that suite (ADR 0033); the bench re-owns each wave's
/// inputs to those accounts.
fn signed_suite() -> Option<protocol_types::CryptoSuiteId> {
    match env::var("PLX_M4_SIGNED").ok().as_deref() {
        Some("1") | Some("hybrid") => Some(protocol_types::CryptoSuiteId::HybridV1),
        Some("classical") => Some(protocol_types::CryptoSuiteId::ClassicalV0),
        _ => None,
    }
}

fn signed_orders() -> bool {
    signed_suite().is_some()
}

/// Re-own `wave` to hybrid accounts (one per original owner) and sign it.
fn sign_wave(wave: &[Input]) -> Vec<(Input, consensus_adapter::order_auth::OrderAuth)> {
    use consensus_adapter::order_auth::{owner_of, sign_order};
    use crypto_suite::SuiteSigningKey;
    use std::collections::HashMap;
    let mut keys: HashMap<protocol_types::OwnerId, SuiteSigningKey> = HashMap::new();
    let mut key_for = |o: protocol_types::OwnerId| {
        keys.entry(o)
            .or_insert_with(|| SuiteSigningKey::from_seed(signed_suite().expect("signed"), o.0))
            .clone()
    };
    wave.iter()
        .map(|i| {
            let (input, key) = match i.clone() {
                Input::Place(mut o) => {
                    let k = key_for(o.owner);
                    o.owner = owner_of(&k.public());
                    (Input::Place(o), k)
                }
                Input::Cancel { order_id, owner, nonce } => {
                    let k = key_for(owner);
                    (Input::Cancel { order_id, owner: owner_of(&k.public()), nonce }, k)
                }
                other => (other, key_for(protocol_types::OwnerId::ZERO)),
            };
            let auth = sign_order(&key, &input);
            (input, auth)
        })
        .collect()
}

fn transports() -> Vec<&'static str> {
    match env::var("PLX_M4_TRANSPORT") {
        Ok(s) => s
            .split(',')
            .map(|p| match p.trim() {
                "tcp" => "tcp",
                "quic" => "quic",
                other => panic!("unknown transport {other}"),
            })
            .collect(),
        Err(_) => vec!["tcp", "quic"],
    }
}

fn host_line() -> String {
    let cpu =
        cmd(&["sysctl", "-n", "machdep.cpu.brand_string"]).unwrap_or_else(|| "unknown".into());
    let ncpu = cmd(&["sysctl", "-n", "hw.ncpu"]).unwrap_or_else(|| "?".into());
    format!("{cpu}, {ncpu} cores, Darwin. Process not pinned.")
}

fn cmd(args: &[&str]) -> Option<String> {
    let out = Command::new(args[0]).args(&args[1..]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn print_row(run: &ScaleRun) {
    let node = run.node_ms();
    let cluster = run.cluster_ms();
    println!(
        "| {n} | {label} | {h} | {ns} | {cs} | {np50} | {np95} | {np99} | {nmax} | {cp50} | {cp95} | {cmax} |",
        n = run.n,
        label = run.label,
        h = run.heights.len(),
        ns = node.len(),
        cs = cluster.len(),
        np50 = percentile_ms(&node, 50.0),
        np95 = percentile_ms(&node, 95.0),
        np99 = percentile_ms(&node, 99.0),
        nmax = node.iter().copied().max().unwrap_or(0),
        cp50 = percentile_ms(&cluster, 50.0),
        cp95 = percentile_ms(&cluster, 95.0),
        cmax = cluster.iter().copied().max().unwrap_or(0),
    );
}

struct Cell {
    label: &'static str,
    gossipsub: bool,
    app: AppOpts,
    relaxed_wal: bool,
}

fn isolate_cells() -> Vec<Cell> {
    vec![
        Cell {
            label: "broadcast+F+wal",
            gossipsub: false,
            app: AppOpts::default(),
            relaxed_wal: false,
        },
        Cell {
            label: "gossipsub+F+wal",
            gossipsub: true,
            app: AppOpts::default(),
            relaxed_wal: false,
        },
        Cell {
            label: "broadcast+stubV+wal",
            gossipsub: false,
            app: AppOpts {
                stub_validate: true,
                stub_propose: false,
                skip_apply: false,
                emit_inputs: false,
            },
            relaxed_wal: false,
        },
        Cell {
            label: "broadcast+F+nosync",
            gossipsub: false,
            app: AppOpts::default(),
            relaxed_wal: true,
        },
        Cell {
            label: "gossipsub+stub+nowal",
            gossipsub: true,
            app: AppOpts {
                stub_validate: true,
                stub_propose: true,
                skip_apply: true,
                emit_inputs: false,
            },
            relaxed_wal: false,
        },
    ]
}

async fn run_spec(
    spec: ClusterSpec,
    label: String,
    heights: u64,
    inputs: Vec<Option<Vec<Input>>>,
    timeout: Duration,
) -> eyre::Result<ScaleRun> {
    let n = spec.n;
    let transport = spec.transport_name().to_string();
    let dir = tempfile::tempdir()?;
    eprintln!(
        "start n={n} {label} heights={heights} port={} delay={:?}",
        spec.base_port, spec.ready_delay
    );
    let mut nodes = start_cluster(dir.path(), genesis(), inputs, spec).await?;
    let samples = run_heights(&mut nodes, heights, timeout).await?;
    for node in nodes {
        let _ = node.shutdown().await;
    }
    Ok(ScaleRun {
        n,
        transport,
        label,
        heights: samples,
    })
}

async fn one_run(
    n: usize,
    transport: &str,
    heights: u64,
    base_port: usize,
) -> eyre::Result<ScaleRun> {
    let spec = suited(match transport {
        "tcp" => ClusterSpec::tcp(n, base_port),
        "quic" => ClusterSpec::quic(n, base_port),
        other => eyre::bail!("transport {other}"),
    });
    run_spec(
        spec,
        transport.to_string(),
        heights,
        all_have_i(n),
        timeout_for(n),
    )
    .await
}

async fn isolate_main() -> eyre::Result<()> {
    let ns = parse_list("PLX_M4_N", &[20, 50]);
    let height_override = env::var("PLX_M4_HEIGHTS")
        .ok()
        .map(|s| s.parse::<u64>().expect("PLX_M4_HEIGHTS integer"));
    let cells = isolate_cells();

    println!("# M4 isolate — harness vs Validate vs WAL");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `PLX_M4_ISOLATE=1 cargo run -p m4-scale --release`");
    println!("**Units:** milliseconds. StartedRound → Decided.");
    println!("**GossipSub:** mesh D=6, flood-publish off (not broadcast-in-disguise).");
    println!("**stubV:** Validate skips `F`/BLAKE3. **stub:** GetValue is a zero-root dummy.");
    println!("**nosync:** replica WAL `SyncMode::Relaxed` (no `sync_all`). **nowal:** skip replica apply.");
    println!();
    println!("| n | cell | heights | node samples | cluster samples | node p50 | node p95 | node p99 | node max | cluster p50 | cluster p95 | cluster max |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");

    let cell_filter: Option<Vec<String>> = env::var("PLX_M4_CELL").ok().map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    });

    let mut port = 41000usize;
    for n in ns {
        let heights = height_override.unwrap_or_else(|| default_heights(n));
        let run_cells: Vec<&Cell> = cells
            .iter()
            .filter(|c| {
                if let Some(ref f) = cell_filter {
                    return f.iter().any(|x| x == c.label);
                }
                if n >= 100 {
                    c.label == "gossipsub+F+wal" || c.label == "gossipsub+stub+nowal"
                } else if n >= 50 {
                    c.label == "broadcast+F+wal"
                        || c.label == "gossipsub+F+wal"
                        || c.label == "gossipsub+stub+nowal"
                } else {
                    true
                }
            })
            .collect();
        for cell in run_cells {
            let mut spec = ClusterSpec::tcp(n, port).with_app(cell.app);
            if cell.gossipsub {
                spec = spec.gossipsub_mesh();
            }
            if cell.relaxed_wal {
                spec = spec.relaxed_wal();
            }
            match run_spec(
                spec,
                cell.label.to_string(),
                heights,
                all_have_i(n),
                timeout_for(n),
            )
            .await
            {
                Ok(run) => print_row(&run),
                Err(e) => {
                    eprintln!("FAIL n={n} {}: {e:#}", cell.label);
                    println!(
                        "| {n} | {} | {heights} | — | — | fail | fail | fail | fail | fail | fail | fail |",
                        cell.label
                    );
                }
            }
            port += n + 16;
        }
    }

    println!();
    println!("Read across a row of n: mesh vs `F` vs WAL. Dummy cell is the EngineBuilder floor, not stock Malachite test-app.");
    Ok(())
}

async fn scale_main() -> eyre::Result<()> {
    let large = env::var("PLX_M4_LARGE").ok().as_deref() == Some("1");
    let mut ns = parse_list("PLX_M4_N", &[7, 10, 20]);
    if large {
        for extra in [50, 100] {
            if !ns.contains(&extra) {
                ns.push(extra);
            }
        }
    }
    let height_override = env::var("PLX_M4_HEIGHTS")
        .ok()
        .map(|s| s.parse::<u64>().expect("PLX_M4_HEIGHTS integer"));
    let txs = transports();

    println!("# M4b / M4c scale");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `cargo run -p m4-scale --release`");
    println!("**Units:** milliseconds. StartedRound → Decided.");
    println!("**Value:** M4a `ConsensusValue` (~178 B canonical), not 1 MB.");
    println!("**Pubsub:** broadcast (same as M4a). **I:** out of band.");
    println!();
    println!("| n | transport | heights | node samples | cluster samples | node p50 | node p95 | node p99 | node max | cluster p50 | cluster p95 | cluster max |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");

    let mut port = 40000usize;
    let mut runs = Vec::new();
    for n in ns {
        let heights = height_override.unwrap_or_else(|| default_heights(n));
        for t in &txs {
            if *t == "quic" && n > 20 && !large {
                continue;
            }
            match one_run(n, t, heights, port).await {
                Ok(run) => {
                    print_row(&run);
                    runs.push(run);
                }
                Err(e) => {
                    eprintln!("FAIL n={n} {t}: {e:#}");
                    println!("| {n} | {t} | {heights} | — | — | fail | fail | fail | fail | fail | fail | fail |");
                }
            }
            port += n * n + 4 * n + 16; // consensus, gossip, certs, tunnels
        }
    }

    println!();
    println!("Cluster latency is max(node latencies) at that height (last voter to decide).");
    println!(
        "Node samples within a height are the same decision; they are not independent trials."
    );
    println!(
        "Malachite README ~780 ms / 100 validators / 1 MB is a different value size and topology."
    );
    println!();
    if !runs.iter().any(|r| r.n == 100 && r.transport == "tcp") {
        println!("n=100 not in this run. `PLX_M4_LARGE=1` enables it.");
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    if let Ok(filter) = env::var("PLX_M4_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    }
    let loaded = env::var("PLX_M4_LOADED").ok().as_deref() == Some("1");
    let isolate = env::var("PLX_M4_ISOLATE").ok().as_deref() == Some("1");
    let gossip = env::var("PLX_M4_GOSSIP").ok().as_deref() == Some("1");
    let gap = env::var("PLX_M4_GAP").ok().as_deref() == Some("1");
    if env::var("PLX_M4_WIRE").ok().as_deref() == Some("1") {
        wire_main().await
    } else if loaded && gossip {
        loaded_gossip_main().await
    } else if loaded && gap {
        loaded_gap_main().await
    } else if loaded && isolate {
        loaded_isolate_main().await
    } else if loaded {
        loaded_main().await
    } else if isolate {
        isolate_main().await
    } else {
        scale_main().await
    }
}

/// Consensus bytes per height by suite mode (Q-CRY-5, ADR 0031). Measured at
/// decode, summed over nodes (= bytes sent). Every mode runs secured intent
/// gossip so the admit path is the same; heights are empty.
async fn wire_main() -> eyre::Result<()> {
    use consensus_adapter::engine::{wire_reset, wire_stats};
    let ns = parse_list("PLX_M4_N", &[4, 7, 10, 20]);
    let heights = env::var("PLX_M4_HEIGHTS").ok().and_then(|s| s.parse().ok()).unwrap_or(10u64);
    let mut port = env::var("PLX_M4_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(41_000usize);
    println!("# Q-CRY-5 consensus bytes per height (ADR 0031)");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `PLX_M4_WIRE=1 cargo run -p m4-scale --release`. Localhost TCP, broadcast, {heights} empty heights, secured intent gossip in every mode.");
    println!("Bytes are summed over receivers (= sent), per height. `signed` = votes, proposals, liveness; `finality` = hybrid finality signatures to collectors.");
    println!();
    println!("| n | mode | signed msgs/h | signed KB/h | finality KB/h | total KB/h | vs hybrid | node p50 ms | node p95 ms |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for n in ns {
        let f = (n - 1) / 3;
        let mut hybrid_total = None;
        let modes: Vec<(String, Box<dyn Fn(ClusterSpec) -> ClusterSpec>)> = vec![
            ("classical".into(), Box::new(|s: ClusterSpec| s.with_secure_gossip())),
            ("hybrid".into(), Box::new(|s: ClusterSpec| s.hybrid().with_secure_gossip())),
            (format!("tiered k={}", f + 1), Box::new(move |s: ClusterSpec| s.tiered(f + 1))),
            ("tiered k=1".into(), Box::new(|s: ClusterSpec| s.tiered(1))),
        ];
        for (label, make) in modes {
            let spec = make(ClusterSpec::tcp(n, port));
            port += 3 * n + 8;
            let dir = tempfile::tempdir()?;
            wire_reset();
            let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec).await?;
            let samples = run_heights(&mut nodes, heights, timeout_for(n)).await?;
            let w = wire_stats();
            for node in nodes {
                let _ = node.shutdown().await;
            }
            let per = |b: u64| b as f64 / heights as f64 / 1000.0;
            let total = per(w.signed_bytes + w.finality_bytes);
            if label == "hybrid" {
                hybrid_total = Some(total);
            }
            let vs = hybrid_total.map_or("—".into(), |h| format!("{:.1}×", h / total));
            let mut ms: Vec<u64> = samples.iter().flat_map(|s| s.node_ms.iter().copied()).collect();
            ms.sort_unstable();
            println!(
                "| {n} | {label} | {:.0} | {:.1} | {:.1} | {total:.1} | {vs} | {} | {} |",
                w.signed_msgs as f64 / heights as f64,
                per(w.signed_bytes),
                per(w.finality_bytes),
                percentile_ms(&ms, 50.0),
                percentile_ms(&ms, 95.0),
            );
        }
    }
    Ok(())
}

async fn loaded_main() -> eyre::Result<()> {
    let n = env::var("PLX_M4_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4usize);
    let resting = env::var("PLX_M4_RESTING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8_000usize);
    let batch = env::var("PLX_M4_I")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000usize);
    let port = env::var("PLX_M4_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45000usize);
    let timeout = Duration::from_secs(180);

    println!("# M4 loaded height — treap C' + height WAL");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `PLX_M4_LOADED=1 cargo run -p m4-scale --release`");
    println!("**Units:** milliseconds. StartedRound → Decided.");
    println!("**n={n}.** preload={resting} resting buys. |I|={batch} mixed. WAL=`SyncMode::Height`. `C'`=treap (ADR 0012/0013).");
    println!();
    println!("| n | cell | heights | node samples | cluster samples | node p50 | node p95 | node p99 | node max | cluster p50 | cluster p95 | cluster max |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");

    let spec = suited(ClusterSpec::tcp(n, port).with_preload(load_places(resting)));
    let tape = churn_tape(resting, batch);
    let dir = tempfile::tempdir()?;
    eprintln!(
        "start n={n} loaded rest={resting} |I|={batch} port={} delay={:?}",
        spec.base_port, spec.ready_delay
    );
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(tape); n], spec).await?;
    let samples = run_heights(&mut nodes, 1, timeout).await?;
    for node in nodes {
        let _ = node.shutdown().await;
    }
    let run = ScaleRun {
        n,
        transport: "tcp".into(),
        label: format!("loaded/{resting}+{batch}"),
        heights: samples,
    };
    print_row(&run);
    println!();
    println!(
        "This is one BFT height whose GetValue is a loaded mixed tape + treap C' + one fsync."
    );
    println!("It is not 1M validators, not sharded treaps, not π.");
    Ok(())
}

async fn loaded_gossip_main() -> eyre::Result<()> {
    let n = env::var("PLX_M4_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4usize);
    let resting = env::var("PLX_M4_RESTING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8_000usize);
    let batch = env::var("PLX_M4_I")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000usize);
    let port = env::var("PLX_M4_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(47000usize);
    let spread_ms = env::var("PLX_M4_SPREAD_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100u64);
    let quiet_ms = env::var("PLX_M4_QUIET_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20u64);
    let loaded = env::var("PLX_M4_HEIGHTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4u64);
    eyre::ensure!(loaded >= 1, "PLX_M4_HEIGHTS must be ≥ 1");
    let last = 1 + loaded;
    let wait = Duration::from_secs(180);

    println!("# M4 loaded gossip — steady-state offer after each seal (ADR 0017–0021)");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `PLX_M4_LOADED=1 PLX_M4_GOSSIP=1 cargo run -p m4-scale --release`");
    println!("**Units:** milliseconds. `started` is StartedRound → Decided. `last`/`first`/`q` are inter-decide from replica `decided_at` (last / first / 2f+1). `dF` Decided→Finalized, `Fa` Finalized→ACK, `aS` ACK→StartedRound (cluster max). `offer` is offer-for-h → last decide(h).");
    println!("**n={n}.** preload={resting}. |I|={batch} per loaded height. heights 1 empty + 2..{last} offered on node 0 at the previous seal. WAL=`Height`. `C'`=treap.");
    println!("**admit:** empty-wait {spread_ms} ms, ACK of `id(set)` (ADR 0021), fan-out only on ACK miss. quiet knob={quiet_ms} ms unused. **Not** injected `Vec`.");
    println!();

    let spec = suited(
        ClusterSpec::tcp(n, port)
            .with_preload(load_places(resting))
            .with_intent_gossip()
            .with_gossip_spread(Duration::from_millis(spread_ms))
            .with_gossip_quiet(Duration::from_millis(quiet_ms)),
    );
    let empty_c = commit_list(&[] as &[Input], INPUT_DOMAIN).to_bytes32();
    let tapes: Vec<Vec<Input>> = (0..loaded).map(|w| churn_wave(resting, batch, w)).collect();
    let t_sign = Instant::now();
    let signed: Vec<Vec<_>> = if signed_orders() { tapes.iter().map(|t| sign_wave(t)).collect() } else { Vec::new() };
    if signed_orders() {
        let per = t_sign.elapsed().as_secs_f64() * 1e6 / (loaded as f64 * batch as f64);
        let bytes: usize = signed[0].iter().map(|(_, a)| a.encode().len()).sum::<usize>() / batch.max(1);
        println!("**signed orders (ADR 0033):** {:?} accounts; client signing {per:.0} µs/order; +{bytes} B per gossiped intent (key + signature).", signed_suite().expect("signed"));
        println!();
    }
    let tapes: Vec<Vec<Input>> = if signed_orders() {
        signed.iter().map(|w| w.iter().map(|(i, _)| i.clone()).collect()).collect()
    } else {
        tapes
    };
    let expect_c: Vec<_> = tapes.iter().map(|t| sealed_input_c(t)).collect();

    let dir = tempfile::tempdir()?;
    eprintln!(
        "start n={n} gossip-steady rest={resting} |I|={batch} loaded={loaded} port={} empty={:?} quiet={:?}",
        spec.base_port, spec.gossip_spread, spec.gossip_quiet
    );
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec).await?;

    let mut offer_for_next: Option<Instant> = None;
    let mut prev_marks: Option<(Instant, Instant, Instant)> = None;
    let mut rows: Vec<GossipSplitRow> = Vec::new();
    let q_idx = (n * 2 / 3).min(n.saturating_sub(1));

    for h in 1..=last {
        await_seal(&mut nodes[0], h, wait).await?;
        let offer_for_this = offer_for_next;
        if h < last {
            let wave = (h - 1) as usize;
            offer_for_next = Some(Instant::now());
            if signed_orders() {
                nodes[0].offer_all_signed(signed[wave].clone())?;
            } else {
                nodes[0].offer_all(tapes[wave].clone())?;
            }
            eprintln!("offer wave {wave} at seal {h}");
        }
        let dec = await_decisions(&mut nodes, h, wait).await?;
        let marks = decide_marks(&dec, q_idx);
        if h == 1 {
            eyre::ensure!(
                dec.iter().all(|d| d.value.input_commitment == empty_c),
                "height 1 should be empty I"
            );
        } else {
            let want = expect_c[(h - 2) as usize];
            let included = dec.iter().all(|d| d.value.input_commitment == want);
            let (first, q, last_d) = marks;
            let (pf, pq, pl) = prev_marks.expect("height 1 marks");
            let offer_ms = offer_for_this
                .map(|t| last_d.duration_since(t).as_millis() as u64)
                .unwrap_or(0);
            rows.push(GossipSplitRow {
                height: h,
                started: max_dur(&dec, |d| d.latency),
                inter_last: last_d.duration_since(pl).as_millis() as u64,
                inter_first: first.duration_since(pf).as_millis() as u64,
                inter_q: q.duration_since(pq).as_millis() as u64,
                decide_to_fin: max_dur(&dec, |d| d.decide_to_finalized),
                fin_to_ack: max_dur(&dec, |d| d.finalized_to_ack),
                ack_to_start: max_dur(&dec, |d| d.ack_to_started),
                offer_ms,
                included,
                admit: admit_summary(&dec),
            });
            if !included {
                eprintln!("height {h} input_commitment miss");
            }
        }
        prev_marks = Some(marks);
    }

    for node in nodes {
        let _ = node.shutdown().await;
    }

    println!("| height | started | last | first | q | dF | Fa | aS | offer | ev/s last | tape |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|");
    let mut last_s = Vec::new();
    let mut first_s = Vec::new();
    let mut q_s = Vec::new();
    let mut miss = false;
    for r in &rows {
        let ev = if r.inter_last > 0 {
            batch as u64 * 1000 / r.inter_last
        } else {
            0
        };
        last_s.push(r.inter_last);
        first_s.push(r.inter_first);
        q_s.push(r.inter_q);
        if !r.included {
            miss = true;
        }
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {ev} | {} |",
            r.height,
            r.started,
            r.inter_last,
            r.inter_first,
            r.inter_q,
            r.decide_to_fin,
            r.fin_to_ack,
            r.ack_to_start,
            r.offer_ms,
            if r.included {
                "full |I|"
            } else {
                "NOT full set"
            }
        );
    }
    println!();
    if miss {
        println!("**Window miss or split set.** Do not cite a gossip TPS.");
        eyre::bail!("a loaded gossip height did not seal its offered set");
    }
    fn later_p50(v: &[u64]) -> u64 {
        percentile_ms(&v.iter().skip(1).copied().collect::<Vec<_>>(), 50.0)
    }
    let later_last = later_p50(&last_s);
    let later_first = later_p50(&first_s);
    let later_q = later_p50(&q_s);
    let ev = |ms: u64| if ms > 0 { batch as u64 * 1000 / ms } else { 0 };
    println!(
        "later p50 (heights 3..{last}): last **{later_last} ms** (~{} ev/s); first **{later_first} ms** (~{} ev/s); q **{later_q} ms** (~{} ev/s).",
        ev(later_last),
        ev(later_first),
        ev(later_q)
    );
    println!("`dF`/`Fa`/`aS` are cluster max on that height. This is not injected shared-I (~0.18 s). Not WAN. Not FOCIL.");
    println!();
    println!(
        "| height | Fa | ready | grace | inflight | recover | late | acks min/max | fanout max kB | pending |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for r in &rows {
        let a = &r.admit;
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {}/{} | {} | {} |",
            r.height,
            r.fin_to_ack,
            a.ready,
            a.grace,
            a.inflight,
            a.recover,
            a.late,
            a.acks_min,
            a.acks_max,
            a.fanout_max / 1024,
            a.pending_max
        );
    }
    Ok(())
}

struct GossipSplitRow {
    height: u64,
    started: u64,
    inter_last: u64,
    inter_first: u64,
    inter_q: u64,
    decide_to_fin: u64,
    fin_to_ack: u64,
    ack_to_start: u64,
    offer_ms: u64,
    included: bool,
    admit: AdmitSummary,
}

struct AdmitSummary {
    ready: usize,
    grace: usize,
    inflight: usize,
    recover: usize,
    late: usize,
    acks_min: u8,
    acks_max: u8,
    fanout_max: u64,
    pending_max: u32,
}

fn admit_summary(dec: &[Decision]) -> AdmitSummary {
    let mut ready = 0;
    let mut grace = 0;
    let mut inflight = 0;
    let mut recover = 0;
    let mut late = 0;
    let mut acks_min = u8::MAX;
    let mut acks_max = 0u8;
    let mut fanout_max = 0u64;
    let mut pending_max = 0u32;
    for d in dec {
        let Some(a) = d.admit else {
            continue;
        };
        match a.path {
            AdmitPath::Ready => ready += 1,
            AdmitPath::Grace => grace += 1,
            AdmitPath::InFlight => inflight += 1,
            AdmitPath::Recover => recover += 1,
            AdmitPath::Late => late += 1,
        }
        acks_min = acks_min.min(a.acks_at_entry);
        acks_max = acks_max.max(a.acks_at_entry);
        fanout_max = fanout_max.max(a.fanout_bytes);
        pending_max = pending_max.max(a.pending);
    }
    if acks_min == u8::MAX {
        acks_min = 0;
    }
    AdmitSummary {
        ready,
        grace,
        inflight,
        recover,
        late,
        acks_min,
        acks_max,
        fanout_max,
        pending_max,
    }
}

fn max_dur(dec: &[Decision], f: impl Fn(&Decision) -> Duration) -> u64 {
    dec.iter()
        .map(|d| f(d).as_millis() as u64)
        .max()
        .unwrap_or(0)
}

fn decide_marks(dec: &[Decision], q_idx: usize) -> (Instant, Instant, Instant) {
    let mut t: Vec<Instant> = dec.iter().map(|d| d.decided_at).collect();
    t.sort();
    let first = t[0];
    let q = t[q_idx.min(t.len() - 1)];
    let last = *t.last().unwrap();
    (first, q, last)
}

fn sealed_input_c(tape: &[Input]) -> protocol_types::Bytes32 {
    let mut expect = IntentLog::open();
    for input in tape.iter().cloned() {
        expect.offer(input);
    }
    let sealed = expect.tape(1).expect("sealed expect").to_vec();
    commit_list(&sealed, INPUT_DOMAIN).to_bytes32()
}

struct LoadedCell {
    label: &'static str,
    app: AppOpts,
    relaxed_wal: bool,
}

fn loaded_isolate_cells() -> Vec<LoadedCell> {
    vec![
        LoadedCell {
            label: "F+wal",
            app: AppOpts::default(),
            relaxed_wal: false,
        },
        LoadedCell {
            label: "stubV+wal",
            app: AppOpts {
                stub_validate: true,
                stub_propose: false,
                skip_apply: false,
                emit_inputs: false,
            },
            relaxed_wal: false,
        },
        LoadedCell {
            label: "F+nosync",
            app: AppOpts::default(),
            relaxed_wal: true,
        },
        LoadedCell {
            label: "F+nowal",
            app: AppOpts {
                stub_validate: false,
                stub_propose: false,
                skip_apply: true,
                emit_inputs: false,
            },
            relaxed_wal: false,
        },
        LoadedCell {
            label: "stubV+nowal",
            app: AppOpts {
                stub_validate: true,
                stub_propose: false,
                skip_apply: true,
                emit_inputs: false,
            },
            relaxed_wal: false,
        },
        LoadedCell {
            label: "stub+nowal",
            app: AppOpts {
                stub_validate: true,
                stub_propose: true,
                skip_apply: true,
                emit_inputs: false,
            },
            relaxed_wal: false,
        },
    ]
}

/// Same 8k+10k tape as `loaded_main`, one variable at a time.
async fn loaded_isolate_main() -> eyre::Result<()> {
    let n = env::var("PLX_M4_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4usize);
    let resting = env::var("PLX_M4_RESTING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8_000usize);
    let batch = env::var("PLX_M4_I")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000usize);
    let timeout = Duration::from_secs(180);
    let cells = loaded_isolate_cells();
    let cell_filter: Option<Vec<String>> = env::var("PLX_M4_CELL").ok().map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    });

    println!("# M4 loaded isolate — GetValue vs Validate vs decide WAL");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `PLX_M4_LOADED=1 PLX_M4_ISOLATE=1 cargo run -p m4-scale --release`");
    println!("**Units:** milliseconds. StartedRound → Decided. One height.");
    println!("**n={n}.** preload={resting} resting buys. |I|={batch} mixed. `C'`=treap. Default WAL=`Height`.");
    println!("**stubV:** prevote skips replay `F`. **stub:** GetValue is a zero-root dummy.");
    println!("**nosync:** `SyncMode::Relaxed`. **nowal:** skip replica apply on decide.");
    println!("Decide WALs `I` and installs the GetValue/Validate scratch (no third `F`).");
    println!("Shared-`I`: StartedRound speculates local `I`; Validate is an `id(v)` check.");
    println!();
    println!("| n | cell | heights | node samples | cluster samples | node p50 | node p95 | node p99 | node max | cluster p50 | cluster p95 | cluster max |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");

    let preload = load_places(resting);
    let tape = churn_tape(resting, batch);
    {
        let t0 = Instant::now();
        let _ = seal_sort(&tape);
        eprintln!(
            "one-process IntentLog::tape |I|={} {} ms",
            tape.len(),
            t0.elapsed().as_millis()
        );
    }
    let mut port = env::var("PLX_M4_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(46000usize);

    for cell in cells.iter().filter(|c| {
        cell_filter
            .as_ref()
            .map(|f| f.iter().any(|x| x == c.label))
            .unwrap_or(true)
    }) {
        let mut spec = ClusterSpec::tcp(n, port)
            .with_app(cell.app)
            .with_preload(preload.clone());
        if cell.relaxed_wal {
            spec = spec.relaxed_wal();
        }
        match run_spec(
            spec,
            cell.label.to_string(),
            1,
            vec![Some(tape.clone()); n],
            timeout,
        )
        .await
        {
            Ok(run) => print_row(&run),
            Err(e) => {
                eprintln!("FAIL n={n} {}: {e:#}", cell.label);
                println!(
                    "| {n} | {} | 1 | — | — | fail | fail | fail | fail | fail | fail | fail |",
                    cell.label
                );
            }
        }
        port += n + 16;
    }

    println!();
    println!("Read down the column: prevote `F` vs GetValue `F` vs decide WAL vs BFT floor.");
    println!("Empty-book isolate (`PLX_M4_ISOLATE=1` alone) is a different experiment.");
    Ok(())
}

/// Why gossip StartedRound (~256–309 ms) is slower than injected (~180 ms).
async fn loaded_gap_main() -> eyre::Result<()> {
    let n = 4usize;
    let resting = 8_000usize;
    let batch = 10_000usize;
    let wait = Duration::from_secs(180);
    let mut port = env::var("PLX_M4_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(48300usize);

    let gen = churn_tape(resting, batch);
    let sorted = seal_sort(&gen);
    let wave1 = churn_wave(resting, batch, 1);
    let wave1_sorted = seal_sort(&wave1);
    eyre::ensure!(
        gen != sorted,
        "generator interleave already matched seal order"
    );
    eyre::ensure!(
        sealed_input_c(&gen) == sealed_input_c(&sorted),
        "gen and sorted must be the same set"
    );

    println!("# M4 StartedRound gap — injected vs gossip order");
    println!();
    println!("**Host:** {}", host_line());
    println!("**Binary:** `PLX_M4_LOADED=1 PLX_M4_GAP=1 cargo run -p m4-scale --release`");
    println!(
        "**n={n}.** preload={resting}. |I|={batch}. Gossip **off** unless noted. WAL=`Height`."
    );
    println!("**Question:** gossip later-height StartedRound ~256–309 ms vs injected ~180 ms.");
    println!();

    println!("## Engine-only `F` (one process, 7 clones, p50 ms)");
    println!();
    println!("| tape | p50 ms |");
    println!("|---|---|");
    let f_gen = engine_f_p50(resting, &gen, 7);
    let f_sorted = engine_f_p50(resting, &sorted, 7);
    let f_w1 = engine_f_after(resting, &sorted, &wave1_sorted, 7);
    println!("| gen 10k on 8k | {f_gen} |");
    println!("| seal-sorted 10k on 8k | {f_sorted} |");
    println!("| sorted wave 1 after sorted wave 0 | {f_w1} |");
    println!();

    println!("## Injected BFT (StartedRound → Decided, cluster max ms)");
    println!();
    println!("| run | cell | ms |");
    println!("|---|---|---|");

    for run in 1..=2u32 {
        let spec = ClusterSpec::tcp(n, port).with_preload(load_places(resting));
        let ms = injected_started(spec, gen.clone(), wait).await?;
        println!("| r{run} | injected gen (height 1) | {ms} |");
        port += n + 16;
    }
    for run in 1..=2u32 {
        let spec = ClusterSpec::tcp(n, port).with_preload(load_places(resting));
        let ms = injected_started(spec, sorted.clone(), wait).await?;
        println!("| r{run} | injected seal-sorted (height 1) | {ms} |");
        port += n + 16;
    }
    for run in 1..=2u32 {
        let spec = ClusterSpec::tcp(n, port).with_preload(load_places(resting));
        let ms = offer_all_started(spec, sorted.clone(), wait).await?;
        println!("| r{run} | empty h1 + offer-all sorted (no mesh) | {ms} |");
        port += n + 16;
    }

    println!();
    println!("Gossip-on later StartedRound is ~256–309 ms (m4-loaded-gossip).");
    println!("This is not WAN. Not FOCIL.");
    Ok(())
}

fn seal_sort(tape: &[Input]) -> Vec<Input> {
    let mut log = IntentLog::open();
    for input in tape.iter().cloned() {
        log.offer(input);
    }
    log.tape(1).expect("seal").to_vec()
}

fn preloaded_engine(resting: usize) -> clob::Engine<clob::BTreeBook> {
    let mut e = btree_engine();
    for input in load_places(resting) {
        let _ = e.apply(input);
    }
    let _ = e.state_root();
    e
}

fn engine_f_p50(resting: usize, tape: &[Input], samples: usize) -> u64 {
    let base = preloaded_engine(resting);
    let mut ms = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut e = base.clone();
        let t0 = Instant::now();
        for input in tape.iter().cloned() {
            let _ = e.apply(input);
        }
        let _ = e.state_root();
        ms.push(t0.elapsed().as_millis() as u64);
    }
    percentile_ms(&ms, 50.0)
}

fn engine_f_after(resting: usize, first: &[Input], second: &[Input], samples: usize) -> u64 {
    let mut grown = preloaded_engine(resting);
    for input in first.iter().cloned() {
        let _ = grown.apply(input);
    }
    let _ = grown.state_root();
    let mut ms = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut e = grown.clone();
        let t0 = Instant::now();
        for input in second.iter().cloned() {
            let _ = e.apply(input);
        }
        let _ = e.state_root();
        ms.push(t0.elapsed().as_millis() as u64);
    }
    percentile_ms(&ms, 50.0)
}

async fn injected_started(
    spec: ClusterSpec,
    tape: Vec<Input>,
    wait: Duration,
) -> eyre::Result<u64> {
    let n = spec.n;
    let dir = tempfile::tempdir()?;
    eprintln!("start injected port={}", spec.base_port);
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(tape); n], spec).await?;
    let d = await_decisions(&mut nodes, 1, wait).await?;
    let ms = d
        .iter()
        .map(|x| x.latency.as_millis() as u64)
        .max()
        .unwrap_or(0);
    for node in nodes {
        let _ = node.shutdown().await;
    }
    Ok(ms)
}

async fn offer_all_started(
    spec: ClusterSpec,
    tape: Vec<Input>,
    wait: Duration,
) -> eyre::Result<u64> {
    let n = spec.n;
    let empty_c = commit_list(&[] as &[Input], INPUT_DOMAIN).to_bytes32();
    let dir = tempfile::tempdir()?;
    eprintln!("start offer-all port={}", spec.base_port);
    let mut nodes = start_cluster(dir.path(), genesis(), vec![Some(vec![]); n], spec).await?;
    for i in 0..n {
        await_seal(&mut nodes[i], 1, wait).await?;
    }
    for node in &nodes {
        node.offer_all(tape.clone())?;
    }
    let h1 = await_decisions(&mut nodes, 1, wait).await?;
    eyre::ensure!(
        h1.iter().all(|d| d.value.input_commitment == empty_c),
        "height 1 should stay empty"
    );
    let h2 = await_decisions(&mut nodes, 2, wait).await?;
    let ms = h2
        .iter()
        .map(|x| x.latency.as_millis() as u64)
        .max()
        .unwrap_or(0);
    for node in nodes {
        let _ = node.shutdown().await;
    }
    Ok(ms)
}
