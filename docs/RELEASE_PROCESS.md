# Release process

Third-party commits never update Ferryman installations directly.

1. A contributor opens a signed-off pull request.
2. A maintainer reviews the exact diff and all CI checks pass.
3. A maintainer merges it and deliberately creates a versioned release with updated `bridge-release.toml`.
4. The release is tested, checksummed, and (for a production release) signed.
5. A Ferryman operator runs the opt-in updater against that approved release.

## The approval gate (ADR 0018)

The maintainer's judgement in step 3 is now exercised through a gate, not a
`git push`. A machine proposes a release; a person approves it; the signing
machine lands it. Telegram is not part of the authority — it only announces that
a release is waiting.

1. A machine writes a signed release request into the channel:
   `ferry release propose --version 0.5.4 --commit <full-sha> --ci green --changelog "…"`.
2. The bridge tells Telegram that a release is waiting, and links to the
   dashboard. Telegram cannot approve anything.
3. The operator opens the dashboard (loopback by default; a tunnel they already
   run puts the same page on their phone), signs in with their password, and
   approves or denies. Approving signs with the operator key that signing in
   unsealed — the fleet cannot sign as the operator, because it never has the
   password.
4. The signing machine applies the approval:
   `ferry release land`. This refuses — loudly — an approval that does not
   verify, names nobody on the roster, points at a different version or commit,
   is older than 24 hours, or whose CI is not green. It then tags, signs and
   pushes.

### The release key

Releases are signed with a key that is separate from any operator's personal GPG
identity. Generate it once per machine with:

```sh
ferry release key
```

It prints a public half. Publish that public half in this repository and in the
section below; keep the private half where it is (`.ferryman/keys/release.key`,
owner-only, never in the channel, never committed).

The release signing public key for this repository is:

```
__RELEASE_KEY_PLACEHOLDER__ — run `ferry release key` and paste the public half
```

Until a release key is generated, releases are **preview** releases and must not
be treated as production security attestations. The updater must refuse dirty
installations and never adds a remote.

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

### The tagger address has to be a UID on the key

GitHub reported `"verified": false, "reason": "bad_email"` on v0.5.0 through
v0.5.2 while `git tag -v` reported a good signature on all of them. Both were
right. GitHub matches the tagger address on the tag object against the UIDs of
the key registered on the account; the tagger address here is the
`users.noreply.github.com` one, and it was not a UID on the key, so there was
nothing to match.

The obvious fix is the wrong one. Setting the tagger address to the address the
key already carried made GitHub refuse the push outright:

```
! [remote rejected] v0.5.3 -> v0.5.3 (push declined due to email privacy restrictions)
```

That is the account's "block command line pushes that expose my email" setting
doing its job. The key is the thing to change, not the privacy setting:

```sh
gpg --quick-add-uid <KEYID> "Your Name <ID+user@users.noreply.github.com>"
gpg --batch --yes --armor --output keys/estejosh.asc --export <KEYID>
```

Export with `--output`, not by piping into a shell redirect: PowerShell's
pipeline flattens the armor onto one line and produces a key file that looks
present and parses as nothing.

**Then re-upload the public key in GitHub → Settings → SSH and GPG keys.**
Verification is computed against the copy GitHub holds, not the copy in this
repository, so a UID added locally changes nothing until that copy is replaced.
Adding a UID does not change the key or its fingerprint, and tags signed before
the change still verify.
