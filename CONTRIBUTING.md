# Contributing

# Contributing to Ferryman

Thank you for helping. The Bridge protects private project history, so changes
are reviewed more carefully than ordinary application changes.

## How to contribute

1. Open an issue first for a large change, security-sensitive change, or new provider.
2. Fork the repository (or use a branch if you are an invited private collaborator).
3. Make one focused change, with tests and documentation.
4. Open a pull request. Do not push directly to `main`.
5. Add a `Signed-off-by: Your Name <email>` line to every PR commit using `git commit -s`.

Use Rust stable, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. Keep provider/model logic outside core storage. Never commit secrets, private prompts, recovery keys, or artifacts.

## Review and releases

Maintainers review every pull request. CI checks formatting, linting, tests on Windows/macOS/Linux, dependency audit, secret scanning, and an SPDX SBOM. A merged commit is **not** a Bridge update: installations only update from a versioned release declared in `bridge-release.toml`. See [the release process](docs/RELEASE_PROCESS.md).
