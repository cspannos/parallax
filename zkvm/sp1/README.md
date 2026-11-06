# SP1 tiny-`F` (M6a)

Not in the main workspace. Default is **core** proof (`SP1_PROVER=cpu`), not Groth16/PLONK. `PLX_RECEIPT=compressed` is recursive STARK aggregation. Needs `protoc` and `tempfile = 3.21.0`.

From repo root:

```bash
SP1_PROVER=cpu cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml
SP1_PROVER=cpu PLX_RECEIPT=compressed cargo run --release -p tiny-f-script --manifest-path zkvm/sp1/Cargo.toml
```

Guest logic: `zkvm/spec`. Numbers: [`docs/benchmarks/m6-prove.md`](../../docs/benchmarks/m6-prove.md).
