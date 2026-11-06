# RISC Zero tiny-`F` (M6a)

Not in the main workspace. STARK receipt only — no `RISC0_DEV_MODE=1`, no Groth16 wrap. Default is composite; `PLX_RECEIPT=succinct` is recursive STARK compression.

From repo root:

```bash
RISC0_DEV_MODE=0 cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml
RISC0_DEV_MODE=0 PLX_RECEIPT=succinct cargo run --release -p host --manifest-path zkvm/risc0/Cargo.toml
```

Guest logic: `zkvm/spec`. Numbers: [`docs/benchmarks/m6-prove.md`](../../docs/benchmarks/m6-prove.md).
