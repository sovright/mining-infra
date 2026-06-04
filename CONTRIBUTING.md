# Contributing to Sovright

Thank you for your interest in contributing to the Sovright Zcash mining infrastructure.

## Getting Started

### Prerequisites

- **Rust** (stable) -- install via [rustup](https://rustup.rs/)
- **Git**
- A running [Zebra](https://github.com/ZcashFoundation/zebra) node is required for integration tests and examples, but not for unit tests

### Clone and Build

```bash
git clone https://github.com/sovright/mining-infra.git
cd mining-infra
cargo build
```

### Run Tests

```bash
cargo test --workspace
```

### Check Formatting and Lints

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes.
3. Ensure all CI checks pass locally:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
4. Write clear, descriptive commit messages.
5. Open a pull request against `main`.

## Code Style

- Run `cargo fmt` before committing. The CI enforces `rustfmt` formatting.
- All `clippy` warnings are treated as errors in CI (`-D warnings`).
- Write tests for new functionality.
- Keep pull requests focused -- one logical change per PR.

## Architecture Overview

See the [README](README.md) for the crate dependency graph and data flow. Key crates:

| Crate | What it does |
|-------|-------------|
| `zcash-pool-server` | Main pool server orchestration |
| `zcash-mining-protocol` | Binary message codec |
| `zcash-equihash-validator` | Solution validation and vardiff |
| `zcash-template-provider` | Zebra RPC integration |
| `zcash-jd-server` | Job Declaration Server |
| `sovright-noise` | Noise_NK encryption |
| `sovright-relay` | Compact block relay |
| `sovright-relay-sidecar` | Relay sidecar for V1 pools |
| `sovright-telemetry` | Prometheus metrics, tracing |

## Reporting Issues

- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) for bugs.
- Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) for proposals.

## License

By contributing, you agree that your contributions will be licensed under the project's dual MIT OR Apache-2.0 license.
