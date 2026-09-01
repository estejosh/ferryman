# Release process

Third-party commits never update Ferryman installations directly.

1. A contributor opens a signed-off pull request.
2. A maintainer reviews the exact diff and all CI checks pass.
3. A maintainer merges it.
4. A machine writes a signed **release request** into the channel:

   ```sh
   ferry release propose --version 0.5.4 --commit <full-sha> --ci green --changelog "…"
   ```

5. The bridge announces it on Telegram, showing what is being approved — version,
   commit, CI, changelog. The approver — the one operator whose Telegram id is
   configured — replies:

   ```
   /release approve 0.5.4
   /release deny 0.5.4 not ready yet
   ```

6. On approve, the bridge writes a signed decision, verifies it, tags, signs with
   the release key, and pushes. The same signing step runs from
   `ferry release land` for an approval already in the channel.
7. A Ferryman operator runs the opt-in updater against that approved release.

Until a release key is generated (`ferry release key`), releases are **preview**
releases and must not be treated as production security attestations. The
updater must refuse dirty installations and never adds a remote.

For this private repository, invite trusted collaborators in GitHub to submit
PRs. If the repository becomes public, contributors can fork it and follow the
same PR process.

## What the signature attests to

A signed Ferryman release means **the approver said yes from their phone**, not
"a human typed a passphrase at the machine". The approval decision is a signed
record carrying the approver's Telegram id; the bridge machine signs that
record, and the release itself is tagged and signed with a **release key**
separate from any operator's personal GPG identity. A compromise of the signing
machine forfeits releases and nothing else — never the operator's identity. The
tag message records who approved and how; read it with `git tag -v`.

## Verifying a release

Release tags are signed with the release key. Its public half is in this
repository at `keys/release.asc`, with this fingerprint:

```
<run `ferry release key` on the signing machine and paste the fingerprint here>
```

Until that key exists, tags are signed with the maintainer's personal key in
`keys/estejosh.asc` (fingerprint `4432 6FD9 19BA A67D 9DEE  3B95 AC2E 0A22 B11B 207D`),
and the arrangement above does not yet apply.

To check a tag:

```sh
gpg --import keys/release.asc
git tag -v v0.5.4
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
gpg --batch --yes --armor --output keys/release.asc --export <KEYID>
```

Export with `--output`, not by piping into a shell redirect: PowerShell's
pipeline flattens the armor onto one line and produces a key file that looks
present and parses as nothing.

**Then re-upload the public key in GitHub → Settings → SSH and GPG keys.**
Verification is computed against the copy GitHub holds, not the copy in this
repository, so a UID added locally changes nothing until that copy is replaced.
Adding a UID does not change the key or its fingerprint, and tags signed before
the change still verify.

`ferry release key` mints the release key with the UID
`Ferryman Release <release@ferryman.invalid>`. `git tag -v` works the moment
`keys/release.asc` is published; the GitHub "verified" badge additionally wants
the key registered on the account with the account's noreply UID, which is the
procedure above. The badge is cosmetic — the check that matters is `git tag -v`
against the key in this tree.
