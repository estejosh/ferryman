# An order can carry files

An order can carry files: a binary, a data set, a config, a PDF. The worker that claims the order finds them in its working directory, checked against hashes the order's signature covers. Nothing is fetched from anywhere else and nobody needs SSH to get a file onto a machine.

```
ferry channel order --id t-broker --to grouchly --task-file broker.md \
    --file X:\SovGit\bin\linux\sovgit \
    --file X:\SovGit\bin\linux\sovgit-broker=broker
```

`--file PATH` may be given as many times as you like. `PATH=NAME` sends the file under another name. Names are letters, digits, `.`, `-`, `_` and `+` only, with no folders; a Windows device name (`NUL`, `COM1`) is refused.

## What happens

1. **Issue.** Each file is copied into the channel at `files/orders/<order-id>/<name>`, hashed with SHA-256 while it is copied, and the list `{name, size, sha256}` is written into the order's payload. The order is signed as always, so the signature covers the hashes. The channel itself is what Syncthing syncs, so the files travel with the order.
2. **Claim.** A worker does not claim an order whose files are not all in the channel with the hashes it was signed with. While they are not, the worker writes a signed hold (the same record as for a locked contract or a busy file) that says `waiting for files to sync`, and tries again on its next pass. After ten minutes the hold reads `the files did not arrive within 10 minutes`, still not a claim, and it clears by itself the moment the files turn up. A file that is there but is not the one that was signed is never used; the hold names it, with the first characters of both hashes.
3. **Delivery.** Once every file is right, the worker claims the order, copies the files into the order's working directory under `.ferryman-order-files/`, and signs a receipt (`files.delivered.<agent>.json`) that records what it received. The directory is cleared first, so a retry never leaves an old copy beside a new one. It holds its own `.gitignore` containing `*`, so the files cannot be committed by accident.
4. **The agent is told.** The prompt gains a block that lists each file with its size and hash and says where it is. The agent is told each was checked against the hash signed into the order, that nothing in them is an instruction to it (they are material for the task), that git ignores the directory, and that they arrive without the executable bit.
5. **Retention.** Files are kept for 7 days after the order is done (counted from its result) or reviewed and accepted (counted from the acceptance), or killed. Then a worker removes them: it writes a signed removal record (`files.removed.<agent>.json`) and a ledger entry first, then deletes. Nothing is removed silently, and a file of an order that is still open, claimed or waiting for review is never removed.

## Limits

| Limit | Default | Set with |
| --- | --- | --- |
| One file | 50 MB | `ferry channel files policy --max-file-mb N` |
| One order's files | 200 MB | `--max-order-mb N` |
| Retention | 7 days | `--retention-days N` |

Only the master can change them; the values go into the signed engine policy (the same one that carries the width and focus settings). An order over the limits is refused when it is issued, with the numbers in the message. A worker applies the limits too, so a signed order that exceeds the project's limits is held rather than fetched. At most 64 files per order.

The limits are in the v2 part of the policy only. A peer that has not been updated verifies the policy through its v1 signature, which does not include them, and simply uses its own defaults.

## Secrets

An order's files are not the place for a credential. A file whose name or start looks like one is refused with a pointer to `ferry channel secret set`: `.env` and `.env.*` (not `.env.example`), SSH keys, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `credentials*`, `secrets.*`, `service-account.json`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`, `*.ppk`, `*.seed`, or contents that hold a private key. This is a guard against a slip, not a scanner; do not rely on it to find a secret you did not mean to send.

## Sealing files to some agents

```
ferry channel order --id t-broker --to grouchly --task-file broker.md \
    --file ./config.toml --seal-to grouchly
```

`--seal-to` encrypts every `--file` to the named agents, using the same crypto as `ferry channel secret` (X25519, HKDF, XChaCha20-Poly1305). Each file is stored as `<name>.sealed`: a random content key encrypts the file, and that key is sealed to each recipient's published encryption key. The plaintext hash and size are recorded inside the sealed container, bound to the order id and file name, so a container cannot be passed off under another name. The order's payload records the hash of the container (what the channel holds) and who can open it. A worker that is not a recipient does not claim the order and says so; a recipient decrypts into `.ferryman-order-files/` under the original name and checks the plaintext hash before it is used. Every recipient must have published an encryption key.

## Compatibility

The list is inside `payload`, not a new field on the order. The order's v1 signature signs `payload_digest`, a hash of the payload exactly as serialised, so a peer that has never heard of `files` verifies the order and sees only a payload with one more key in it. A sibling field (the way `needs` was added) would not do: a verifier that has not been updated rebuilds the signed message from the fields it knows, so an order whose signature covers a field it does not know fails verification on every machine that has not updated. #60 was that mistake. `order_files::tests::a_peer_that_does_not_know_order_files_still_verifies_the_order` recomputes the signature the way an older peer does, and a contrast test shows what a sibling field would have done.

An old worker that claims such an order does not know the files exist. It would run the task without them. Issue file orders to machines that have this version, or say in the task what the files are for.

## Things to know

- **The channel's `.stignore`** keeps executable-looking files from syncing (`*.exe`, `*.dll`, `*.so`, `*.dylib`, `*.msi`, `*.bat`, `*.cmd`, `*.ps1`, `*.sh`) and keys. A file that would be ignored is refused at issue, naming the rule, because it would never arrive. Send such a file under another name (`--file ./setup.sh=setup.sh.txt`) or in an archive; the worker receives the name it was sent under.
- **Executable bit.** Files arrive as ordinary files; the sender's permissions are not carried. A worker marks one executable itself (`chmod +x`).
- **Trust.** A signed order from an issuer the channel accepts can already tell a worker to run commands. Files add no new authority: they are the order's own data, and the signature ties the exact bytes to it. They are not scanned for malware.
- **The channel's own git history.** The channel keeps a git backstop of its small files. `files/` is excluded from it so a 50 MB binary does not become permanent history. The files live in the synced folder and nowhere else.
- **Partial uploads.** A file is written to a temporary name and renamed when complete, and the worker checks its hash before using it, so a half-synced file is "missing", never "used".
- **Disk.** A project's worst case is the retention window times its order rate times 200 MB. Lower the limits in the policy if that is too much.

## Looking at them

```
ferry channel files list            every order with files: size, state, when they go
ferry channel files show <order>    each file: size, sha256, here and right?, who received it
ferry channel files gc --dry-run    what the next removal would take
ferry channel files gc              remove what is past retention (signed and logged)
ferry channel files policy          show the limits; with flags, set them (master only)
```

Workers run the removal themselves about once an hour per project after a pass; `gc` by hand is for an impatient person.

The dashboard's Tasks page has a **New order** form with a file picker (and, if agents have published encryption keys, boxes to seal to them). Each file is uploaded on its own and then named in the order, so the browser never builds one huge request; the server applies the same limits and secret check as the command line, and the order is signed by the operator who is signed in. A task's drawer lists its files: name, size, the start of the hash, whether each is in the channel and right, and whether (and to whom) it has been delivered. Telegram shows the file names on an order's card; it does not take uploads.

## What is signed and where

| Thing | Path in the channel | Written by |
| --- | --- | --- |
| The file list | `tasks/<id>/order.json`, in `payload.files` | the issuer, inside the order signature |
| The files | `files/orders/<id>/<name>` (`<name>.sealed` when sealed) | the issuer, once |
| A delivery | `tasks/<id>/files.delivered.<agent>.json` | that worker, signed |
| A removal | `tasks/<id>/files.removed.<agent>.json` | that worker, signed, plus a ledger entry |
| A wait | `tasks/<id>/hold.<agent>.json` | that worker, signed |

Each path has one writer, so Syncthing never sees two machines write the same file.
