# Contributing to Ferryman

Thank you for helping. Ferryman carries private project history between machines,
so changes are reviewed more carefully than ordinary application changes.

## What your contribution is licensed as

Ferryman is source-available, not open source, and it is sold above a free tier.
You are entitled to know what that means for a patch you send, before you send it:

- Your contribution is licensed under the [Ferryman Source-Available
  License](LICENSE), the same licence as the rest of the project.
- By opening a pull request you also grant the Licensor a perpetual, irrevocable,
  worldwide, royalty-free right to use, modify, sublicense and relicense your
  contribution, including under commercial terms. Without that, a contributed line
  could not be shipped to a paying customer, and the project could not accept
  patches at all.
- The `Signed-off-by` line required below is a [DCO](https://developercertificate.org/)
  sign-off: you are certifying you have the right to submit the code. It is separate
  from the grant above, and neither replaces the other.

If that is not a trade you want to make, say so in the issue rather than opening a
pull request — an idea, a bug report, or a failing test case costs you nothing and
is often worth more than the patch.

## How to contribute

1. Open an issue first for a large change, security-sensitive change, or new provider.
2. Fork the repository (or use a branch if you are an invited private collaborator).
3. Make one focused change, with tests and documentation.
4. Open a pull request. Do not push directly to `main`.
5. Add a `Signed-off-by: Your Name <email>` line to every PR commit using `git commit -s`.

Use Rust stable, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. Keep provider/model logic outside core storage. Never commit secrets, private prompts, recovery keys, or artifacts.

## Review and releases

Maintainers review every pull request. CI checks formatting, linting, tests on Windows/macOS/Linux, dependency audit, secret scanning, and an SPDX SBOM. A merged commit is **not** a Ferryman update: installations only update from a versioned release declared in `bridge-release.toml`. See [the release process](docs/RELEASE_PROCESS.md).
