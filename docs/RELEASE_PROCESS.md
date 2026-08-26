# Release process

Third-party commits never update Ferryman installations directly.

1. A contributor opens a signed-off pull request.
2. A maintainer reviews the exact diff and all CI checks pass.
3. A maintainer merges it and deliberately creates a versioned release with updated `bridge-release.toml`.
4. The release is tested, checksummed, and (for a production release) signed.
5. A Ferryman operator runs the opt-in updater against that approved release.

Until a signing key is configured, releases are **preview** releases and must not be treated as production security attestations. The updater must refuse dirty installations and never adds a remote.

For this private repository, invite trusted collaborators in GitHub to submit PRs. If the repository becomes public, contributors can fork it and follow the same PR process.

## Verifying a release

Release tags are signed. The public half of the signing key is in this
repository at `keys/estejosh.asc`, with this fingerprint:

```
4432 6FD9 19BA A67D 9DEE  3B95 AC2E 0A22 B11B 207D
```

To check a tag:

```sh
gpg --import keys/estejosh.asc
git tag -v v0.5.1
```

### Why the key is in the repository

It was not, and the first signed release nobody could verify made the case.
`v0.5.0` was signed correctly, and the tag object was byte-identical on the
machine that made it and on GitHub - nothing had been tampered with. It was
still unverifiable everywhere: GitHub could not export the key it holds
(`the keys with the following IDs couldn't be parsed`), the public keyservers
had no copy, and every machine in the fleet answered `NO_PUBKEY`.

Signed and unverifiable is worse than unsigned, because from a distance it
looks checked. So verification does not depend on a third party being able to
serve the key: it is here, in the tree, and the fingerprint above is what a
reader compares against.

That is also the limit of what this buys. A key committed beside the thing it
signs proves the release and the repository came from the same place; it cannot
prove that place is the one you meant. For that, compare the fingerprint with
one you obtained some other way.

### Known gap

GitHub reports `"verified": false, "reason": "bad_email"` on these tags: the
tagger address is the `users.noreply.github.com` one used for commits, which is
not a UID on the signing key. `git tag -v` is unaffected and reports a good
signature. Adding that address as a UID on the key would close it.
