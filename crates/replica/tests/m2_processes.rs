//! Four OS processes, same ordered `I`, injected delay, kill + restart.

mod common;

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::Duration;

use clob::testutil::genesis;
use common::demo_stream;
use protocol_types::{CanonicalEncode, GenesisBlob, Input};
use replica::encode_hex;

fn genesis_hex() -> String {
    let g = genesis();
    let blob = GenesisBlob {
        height: g.height,
        instruments: g.instruments,
    };
    encode_hex(&blob.encode_vec())
}

fn key_hex(n: u8) -> String {
    encode_hex(&[n; 32])
}

struct Node {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Node {
    fn spawn(wal: &Path, key_n: u8) -> Self {
        let exe = env!("CARGO_BIN_EXE_parallax-replica");
        let mut child = Command::new(exe)
            .arg("--wal")
            .arg(wal)
            .arg("--key-hex")
            .arg(key_hex(key_n))
            .arg("--genesis-hex")
            .arg(genesis_hex())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn parallax-replica");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn submit(&mut self, input: &Input) -> [u8; 32] {
        let bytes = input.encode_vec();
        self.stdin
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .unwrap();
        self.stdin.write_all(&bytes).unwrap();
        self.stdin.flush().unwrap();
        let mut root = [0u8; 32];
        self.stdout.read_exact(&mut root).unwrap();
        root
    }

    fn shutdown(mut self) {
        let _ = self.stdin.write_all(&0u32.to_le_bytes());
        let _ = self.stdin.flush();
        drop(self.stdin);
        drop(self.stdout);
        let _ = self.child.wait();
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn four_processes_agree_with_delay() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = demo_stream();
    let delays = [0u64, 4, 1, 9];
    let mut nodes: Vec<Node> = (0..4u8)
        .map(|n| Node::spawn(&dir.path().join(format!("n{n}.wal")), n + 1))
        .collect();

    let mut traces: Vec<Vec<[u8; 32]>> = vec![Vec::new(); 4];
    for input in &inputs {
        for (i, node) in nodes.iter_mut().enumerate() {
            if delays[i] > 0 {
                thread::sleep(Duration::from_millis(delays[i]));
            }
            traces[i].push(node.submit(input));
        }
    }
    for t in &traces[1..] {
        assert_eq!(t, &traces[0]);
    }
    for node in nodes {
        node.shutdown();
    }
}

#[test]
fn process_kill_and_restart_replays() {
    let dir = tempfile::tempdir().unwrap();
    let wal = dir.path().join("kill.wal");
    let inputs = demo_stream();
    let prefix = &inputs[..4];
    let rest = &inputs[4..];

    let mut live = Node::spawn(&wal, 7);
    let mut roots = Vec::new();
    for input in prefix {
        roots.push(live.submit(input));
    }
    live.kill();

    let mut restarted = Node::spawn(&wal, 7);
    for input in rest {
        roots.push(restarted.submit(input));
    }
    restarted.shutdown();

    let mut reference = Node::spawn(&dir.path().join("ref.wal"), 3);
    let mut ref_roots = Vec::new();
    for input in &inputs {
        ref_roots.push(reference.submit(input));
    }
    reference.shutdown();

    assert_eq!(roots, ref_roots);
}
