# Release process

Third-party commits never update Bridge installations directly.

1. A contributor opens a signed-off pull request.
2. A maintainer reviews the exact diff and all CI checks pass.
3. A maintainer merges it and deliberately creates a versioned release with updated `bridge-release.toml`.
4. The release is tested, checksummed, and (for a production release) signed.
5. A Bridge operator runs the opt-in updater against that approved release.

Until a signing key is configured, releases are **preview** releases and must not be treated as production security attestations. The updater must refuse dirty installations and never adds a remote.

For this private repository, invite trusted collaborators in GitHub to submit PRs. If the repository becomes public, contributors can fork it and follow the same PR process.
