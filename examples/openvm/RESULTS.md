# Captured OpenVM v1.7.0 runs

Recorded 2026-11-24 from the shipping `scripts/benchmark.py`, after final source formatting.

All guest assertions passed. The script compared every public output byte with its frozen expected value and across every variant and mode. `meter` reports `instret` and estimated cells; `segment` reports `instret` and segment count. No proofs or proving-time measurements were performed.

Top-level commands (from this example directory):

```sh
python3 scripts/benchmark.py
python3 scripts/benchmark.py --bin payment --variants software accelerated
```

The runner sets `OPENVM_RUST_TOOLCHAIN=nightly-2026-03-17` and obtains `RUSTC` using `rustup which --toolchain nightly-2026-03-17 rustc`.

## Smoke

Machine-readable capture: [smoke.json](results/smoke.json).

CLI: `cargo-openvm v1.7.0 (425913bd)`. Compiler: `rustc 1.96.0-nightly (3645249d7 2026-03-16)`.

OpenVM source: `git+https://github.com/openvm-org/openvm.git?tag=v1.7.0#425913bdc743ef44236daf472ec53c2c05b75fa1`.

| Variant | `instret` | Estimated cells | Segments |
| --- | ---: | ---: | ---: |
| `software` | 68,553,310 | 5,964,411,703 | 8 |
| `accelerated` | 244,184 | 41,980,730 | 1 |
| `openvm-sha256` | 68,042,130 | 5,917,943,331 | 8 |
| `openvm-keccak256` | 68,400,718 | 5,951,215,385 | 8 |
| `openvm-k256` | 47,195,192 | 4,029,523,832 | 6 |
| `openvm-p256` | 22,266,074 | 2,036,533,291 | 3 |

Public bytes: `d0125c20e1feb62adbf3d98b84440beeeb03a1f51cec7aae0057374e98c4a375`.

Exact expanded commands executed by the runner:

```sh
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify --config openvm.toml --output-dir target/runs/planchet-openvm-verify/software
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/software/planchet-openvm-verify.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/software/planchet-openvm-verify.vmexe --config openvm.toml --mode segment
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify --config openvm.toml --output-dir target/runs/planchet-openvm-verify/accelerated --features accelerated
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/accelerated/planchet-openvm-verify.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/accelerated/planchet-openvm-verify.vmexe --config openvm.toml --mode segment
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify --config openvm.toml --output-dir target/runs/planchet-openvm-verify/openvm-sha256 --features openvm-sha256
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-sha256/planchet-openvm-verify.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-sha256/planchet-openvm-verify.vmexe --config openvm.toml --mode segment
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify --config openvm.toml --output-dir target/runs/planchet-openvm-verify/openvm-keccak256 --features openvm-keccak256
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-keccak256/planchet-openvm-verify.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-keccak256/planchet-openvm-verify.vmexe --config openvm.toml --mode segment
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify --config openvm.toml --output-dir target/runs/planchet-openvm-verify/openvm-k256 --features openvm-k256
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-k256/planchet-openvm-verify.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-k256/planchet-openvm-verify.vmexe --config openvm.toml --mode segment
cargo openvm build --locked --no-default-features --bin planchet-openvm-verify --config openvm.toml --output-dir target/runs/planchet-openvm-verify/openvm-p256 --features openvm-p256
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-p256/planchet-openvm-verify.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin planchet-openvm-verify --exe target/runs/planchet-openvm-verify/openvm-p256/planchet-openvm-verify.vmexe --config openvm.toml --mode segment
```

## Payment

Machine-readable capture: [payment.json](results/payment.json).

CLI: `cargo-openvm v1.7.0 (425913bd)`. Compiler: `rustc 1.96.0-nightly (3645249d7 2026-03-16)`.

OpenVM source: `git+https://github.com/openvm-org/openvm.git?tag=v1.7.0#425913bdc743ef44236daf472ec53c2c05b75fa1`.

| Variant | `instret` | Estimated cells | Segments |
| --- | ---: | ---: | ---: |
| `software` | 16,778,548 | 1,527,191,663 | 2 |
| `accelerated` | 118,529 | 17,385,619 | 1 |

Public bytes: `4a848e4b4529c481e5d39ac685ef4b9505615abd41f35624745a0108ff39d13c`.

Exact expanded commands executed by the runner:

```sh
cargo openvm build --locked --no-default-features --bin payment --config openvm.toml --output-dir target/runs/payment/software --features payment
cargo openvm run --locked --bin payment --exe target/runs/payment/software/payment.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin payment --exe target/runs/payment/software/payment.vmexe --config openvm.toml --mode segment
cargo openvm build --locked --no-default-features --bin payment --config openvm.toml --output-dir target/runs/payment/accelerated --features accelerated,payment
cargo openvm run --locked --bin payment --exe target/runs/payment/accelerated/payment.vmexe --config openvm.toml --mode meter
cargo openvm run --locked --bin payment --exe target/runs/payment/accelerated/payment.vmexe --config openvm.toml --mode segment
```

## Additional host checks

These checks passed with Rust 1.91.0; their results do not contribute VM metrics.

```sh
cargo +1.91.0 run --locked --bin planchet-openvm-verify
cargo +1.91.0 run --locked --bin planchet-openvm-verify --features accelerated
cargo +1.91.0 run --locked --bin payment --features payment
cargo +1.91.0 fmt -- --check
```
