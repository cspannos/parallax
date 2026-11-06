//! Proof service for the end-to-end pipeline (ADR 0028).
//!
//!   RISC0_DEV_MODE=0 PLX_PROVER_DIR=/path cargo run --release -p host --bin prover
//!
//! Watches `$PLX_PROVER_DIR/jobs/*.job` (`clob::FJob`), proves each with
//! `f_guest` (succinct), checks the journal against the job's statement, and
//! writes `receipts/<height>.receipt` (bincode) plus `receipts/<height>.ms`.
//! Writes `receipts/f_guest.id` at start. Stops when `$PLX_PROVER_DIR/stop`
//! exists.
//!
//! Any number of provers can share one directory (one host or many): a worker
//! claims the lowest pending job by atomically renaming `jobs/<h>.job` to
//! `jobs/claimed/<h>.<worker>`, so each job is proven once. `PLX_PROVER_WORKER`
//! names the worker (default: pid). A worker that dies mid-proof leaves its
//! claim behind; reclaiming is not implemented.

use std::path::Path;
use std::time::{Duration, Instant};

use clob::FJob;
use methods::{F_GUEST_ELF, F_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

/// tmp-then-rename. The tmp name is per process: several provers write the
/// same `f_guest.id` at start, and a shared tmp name made one rename fail.
fn write_atomic(path: &Path, bytes: &[u8]) {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes).expect("write tmp");
    std::fs::rename(&tmp, path).expect("rename");
}

fn main() {
    if std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1") {
        panic!("RISC0_DEV_MODE=1 is not π; refuse to run");
    }
    let root = std::path::PathBuf::from(std::env::var("PLX_PROVER_DIR").expect("PLX_PROVER_DIR"));
    let jobs = root.join("jobs");
    let claimed = jobs.join("claimed");
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&claimed).unwrap();
    std::fs::create_dir_all(&receipts).unwrap();
    let worker = std::env::var("PLX_PROVER_WORKER").unwrap_or_else(|_| std::process::id().to_string());
    let id: Vec<u8> = F_GUEST_ID.iter().flat_map(|w| w.to_le_bytes()).collect();
    write_atomic(&receipts.join("f_guest.id"), &id);
    eprintln!("prover {worker}: watching {}", jobs.display());
    let prover = default_prover();
    let opts = ProverOpts::succinct();
    loop {
        if root.join("stop").exists() {
            break;
        }
        let mut pending: Vec<_> = std::fs::read_dir(&jobs)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "job"))
            .collect();
        pending.sort();
        // Claim the lowest job by atomic rename; losing a race just moves on.
        let mut mine = None;
        for path in pending {
            let stem = path.file_stem().unwrap().to_string_lossy().to_string();
            let claim = claimed.join(format!("{stem}.{worker}"));
            if std::fs::rename(&path, &claim).is_ok() {
                mine = Some((stem, claim));
                break;
            }
        }
        let Some((stem, path)) = mine else {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        let job = FJob::decode(&std::fs::read(&path).unwrap()).expect("job");
        let env = ExecutorEnv::builder().write_slice(&job.guest_input()).build().unwrap();
        let t0 = Instant::now();
        let info = prover.prove_with_opts(env, F_GUEST_ELF, &opts).expect("prove");
        let ms = t0.elapsed().as_millis();
        assert!(
            job.journal_matches(&info.receipt.journal.bytes),
            "journal does not prove the job's statement"
        );
        let bytes = bincode::serialize(&info.receipt).expect("serialize");
        write_atomic(
            &receipts.join(format!("{stem}.ms")),
            format!("{ms} {worker}").as_bytes(),
        );
        write_atomic(&receipts.join(format!("{stem}.receipt")), &bytes);
        eprintln!(
            "prover {worker}: height {} proved in {ms} ms ({} cycles, {} segments)",
            job.statement.height.0, info.stats.total_cycles, info.stats.segments
        );
    }
}
