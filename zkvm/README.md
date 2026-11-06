# zkVM benches (not in the main Cargo workspace)

Same tiny `F` as `crates/tiny-f` / `zkvm/spec`. **Not** height `π`. Do not use `RISC0_DEV_MODE=1`. Default SP1 proofs are **core** (no Groth16 wrap). `PLX_RECEIPT=succinct` / `compressed` is recursive STARK aggregation, still not Groth16.

From the **repo root** (do not chain `cd` after the first; they are sibling directories):

```bash
# RISC Zero composite (default)
RISC0_DEV_MODE=0 cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml

# RISC Zero succinct (recursive STARK, not Groth16)
RISC0_DEV_MODE=0 PLX_RECEIPT=succinct cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml

# SP1 core (default)
SP1_PROVER=cpu cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml

# SP1 compressed (recursive STARK, not Groth16)
SP1_PROVER=cpu PLX_RECEIPT=compressed cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml
```

Needs `rzup` / `sp1up` installed. RISC Zero: `disable-dev-mode`, never `RISC0_DEV_MODE=1`. SP1: `SP1_PROVER=cpu`. SP1 also needs `protoc` (`brew install protobuf`) and `tempfile = 3.21.0` (see `script/Cargo.toml`).

## General `C'` (ADR 0023)

Any `IncTape` of treap steps (ADR 0022), recorded from the engine on an 8k book. `C'` is SHA-256 by default (ADR 0024; the tape guest patches `sha2` to RISC Zero's accelerated fork); `PLX_HASH=blake3` runs `C'` v1. The CPU prover is used; the Metal prover needs full Xcode.

```bash
# One Place (PLX_TAPE=place) or churn_tape(8000, N) (PLX_TAPE=churn:N); PLX_EXECUTE_ONLY=1 for cycles only
RISC0_DEV_MODE=0 PLX_TAPE=place cargo run --release -p host --bin tape --manifest-path zkvm/risc0/Cargo.toml

# Height as chunks + recursive join; PLX_TAMPER=1 also checks swapped/dropped/forged chunks fail
RISC0_DEV_MODE=0 PLX_TAMPER=1 PLX_CHUNKS=3 PLX_CHUNK_EVENTS=1 cargo run --release -p host --bin height --manifest-path zkvm/risc0/Cargo.toml

# Guest cycles per hash, BLAKE3 vs accelerated SHA-256 (executor only)
RISC0_DEV_MODE=0 cargo run --release -p host --bin hashbench --manifest-path zkvm/risc0/Cargo.toml
```

## `π` of `F` (ADR 0025)

The guest runs the real matcher on a canonical engine snapshot and commits the `HeightStatement` `F` fields.

```bash
# PLX_F_REST resting orders, PLX_F_EVENTS mixed events; PLX_EXECUTE_ONLY=1 for cycles only
RISC0_DEV_MODE=0 PLX_RECEIPT=succinct PLX_F_REST=1000 PLX_F_EVENTS=8 cargo run --release -p host --bin f --manifest-path zkvm/risc0/Cargo.toml

# Regenerate the settlement-gate fixture (crossing height), then run the gate test
RISC0_DEV_MODE=0 PLX_RECEIPT=succinct PLX_F_SCENARIO=crossing PLX_F_FIXTURE=crates/proof-adapter/tests/fixtures cargo run --release -p host --bin f --manifest-path zkvm/risc0/Cargo.toml
cargo test -p proof-adapter --features risc0 --test risc0_gate
```

The fixture pins the guest image ID. Changing `clob`, `commitments` or `protocol-types` changes the image, so regenerate it after such changes.

## End-to-end pipeline (ADR 0028)

Decided heights on a local cluster → follower proof jobs → this workspace's `prover` service → settlement through `SettlementGate`. The demo spawns the prover itself:

```bash
RISC0_DEV_MODE=0 cargo run --release -p settlement-pipeline --features risc0 --bin e2e
# N provers sharing the job directory (claims by atomic rename; settlement stays in order)
RISC0_DEV_MODE=0 PLX_PIPE_PROVERS=2 cargo run --release -p settlement-pipeline --features risc0 --bin e2e
# or run the prover on its own against a job directory
RISC0_DEV_MODE=0 PLX_PROVER_DIR=/tmp/pipe cargo run --release -p host --bin prover --manifest-path zkvm/risc0/Cargo.toml
```

## `π` of `F` on SP1 (ADR 0029 comparison)

```bash
# Smaller shards are required on a 24 GB host (defaults get the process killed)
SP1_PROVER=cpu SHARD_SIZE=1048576 ELEMENT_THRESHOLD=67108864 MEMORY_LIMIT=12884901888 \
  PLX_RECEIPT=compressed PLX_F_REST=1000 PLX_F_EVENTS=8 \
  cargo run --release -p tiny-f-script --bin f --manifest-path zkvm/sp1/Cargo.toml
```

