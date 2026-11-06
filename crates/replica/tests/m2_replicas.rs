//! Four in-process replicas: identical `I`, crash/replay, injected delay.

mod common;

use std::thread;
use std::time::Duration;

use clob::testutil::genesis;
use common::demo_stream;
use protocol_types::{Fill, Input, SettlementDelta};
use replica::{OpenInfo, Replica, ReplicaError, ReplicaOpts, SyncMode};
use storage::WalError;

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}

fn open_node(dir: &std::path::Path, n: u8) -> (Replica, OpenInfo) {
    let path = dir.join(format!("n{n}.wal"));
    Replica::open(ReplicaOpts::new(path, key(n), genesis())).expect("open replica")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Trace {
    roots: Vec<[u8; 32]>,
    fills: Vec<Fill>,
    settlement: Vec<SettlementDelta>,
    final_root: [u8; 32],
}

fn run_stream(replica: &mut Replica, inputs: &[Input], delay: Duration) -> Trace {
    let mut roots = Vec::new();
    let mut fills = Vec::new();
    let mut settlement = Vec::new();
    for input in inputs {
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let receipt = replica.submit(input.clone()).expect("submit");
        roots.push(receipt.state_root.0);
        fills.extend(receipt.fills);
        settlement.extend(receipt.settlement);
    }
    Trace {
        roots,
        fills,
        settlement,
        final_root: replica.state_root().0,
    }
}

#[test]
fn four_replicas_agree() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = demo_stream();
    let delays = [
        Duration::from_millis(0),
        Duration::from_millis(3),
        Duration::from_millis(1),
        Duration::from_millis(7),
    ];
    let mut traces = Vec::new();
    for n in 0..4u8 {
        let (mut replica, info) = open_node(dir.path(), n);
        assert_eq!(info.replayed, 0);
        traces.push(run_stream(&mut replica, &inputs, delays[n as usize]));
    }
    for t in &traces[1..] {
        assert_eq!(t, &traces[0], "delay must not change roots or fills");
    }
}

#[test]
fn crash_after_wal_replays_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("crash.wal");
    let inputs = demo_stream();
    let committed = {
        let (mut replica, _) = Replica::open(ReplicaOpts::new(&path, key(9), genesis())).unwrap();
        replica.submit(inputs[0].clone()).unwrap();
        replica.crash_after_wal = true;
        let err = replica.submit(inputs[1].clone()).unwrap_err();
        assert!(matches!(err, ReplicaError::SimulatedCrash));
        replica.state_root()
    };

    let (replica, info) = Replica::open(ReplicaOpts::new(&path, key(9), genesis())).unwrap();
    assert_eq!(info.replayed, 2);
    assert!(!info.truncated_tail);
    // First input applied before crash; second applied on replay.
    assert_ne!(replica.state_root(), committed);

    let (mut fresh, _) = Replica::open(ReplicaOpts::new(
        dir.path().join("fresh.wal"),
        key(8),
        genesis(),
    ))
    .unwrap();
    fresh.submit(inputs[0].clone()).unwrap();
    fresh.submit(inputs[1].clone()).unwrap();
    assert_eq!(replica.state_root(), fresh.state_root());
}

#[test]
fn restart_replays_full_stream() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full.wal");
    let inputs = demo_stream();
    let root = {
        let (mut replica, _) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
        run_stream(&mut replica, &inputs, Duration::ZERO).final_root
    };
    let (replica, info) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
    assert_eq!(info.replayed, inputs.len() as u64);
    assert_eq!(replica.state_root().0, root);
}

#[test]
fn truncated_wal_replays_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trunc.wal");
    let inputs = demo_stream();
    {
        let (mut replica, _) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
        for input in &inputs {
            replica.submit(input.clone()).unwrap();
        }
    }
    let meta = std::fs::metadata(&path).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(meta.len() - 5)
        .unwrap();

    let (replica, info) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
    assert!(info.truncated_tail);
    assert!(info.replayed < inputs.len() as u64);
    assert!(info.replayed > 0);

    let (mut prefix, _) = Replica::open(ReplicaOpts::new(
        dir.path().join("prefix.wal"),
        key(2),
        genesis(),
    ))
    .unwrap();
    for input in inputs.iter().take(info.replayed as usize) {
        prefix.submit(input.clone()).unwrap();
    }
    assert_eq!(replica.state_root(), prefix.state_root());
}

#[test]
fn corrupt_wal_refuses_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.wal");
    let inputs = demo_stream();
    {
        let (mut replica, _) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
        for input in &inputs {
            replica.submit(input.clone()).unwrap();
        }
    }
    let mut bytes = std::fs::read(&path).unwrap();
    let idx = bytes.len() / 2;
    bytes[idx] ^= 0xa5;
    std::fs::write(&path, bytes).unwrap();

    let err = match Replica::open(ReplicaOpts::new(&path, key(1), genesis())) {
        Err(e) => e,
        Ok(_) => panic!("corrupt WAL must refuse to open"),
    };
    match err {
        ReplicaError::Wal(WalError::Decrypt | WalError::Corrupt(_)) => {}
        other => panic!("expected decrypt/corrupt, got {other}"),
    }
}

#[test]
fn rejects_are_logged_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rej.wal");
    let dupe = demo_stream()[7].clone(); // replayed nonce
    assert!(matches!(&dupe, Input::Place(_)));
    let (root, n) = {
        let (mut replica, _) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
        replica.submit(demo_stream()[0].clone()).unwrap();
        replica.submit(dupe.clone()).unwrap();
        (replica.state_root(), replica.engine().metrics.rejects)
    };
    assert!(n >= 1);
    let (replica, info) = Replica::open(ReplicaOpts::new(&path, key(1), genesis())).unwrap();
    assert_eq!(info.replayed, 2);
    assert_eq!(replica.state_root(), root);
}

#[test]
fn height_batch_wal_replays() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("h.wal");
    let inputs = demo_stream();
    let mut opts = ReplicaOpts::new(&path, key(1), genesis());
    opts.sync = SyncMode::Height;
    let root = {
        let (mut replica, _) = Replica::open(opts.clone()).unwrap();
        let receipts = replica.submit_batch(inputs.clone()).unwrap();
        assert_eq!(receipts.len(), inputs.len());
        replica.state_root()
    };
    let (replica, info) = Replica::open(opts).unwrap();
    assert_eq!(info.replayed, inputs.len() as u64);
    assert_eq!(info.wal_records, 1);
    assert_eq!(replica.state_root(), root);
}
