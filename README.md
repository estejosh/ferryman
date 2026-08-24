# ferry-deadman

**Timelocked succession for any git repository.**

```text
Your projects outlive you. Provably.
```

`ferry-deadman` seals an archive of your repo so that it becomes decryptable
only after a future point in time, enforced by the drand threshold beacon —
not by any server, company, or person. While you keep running `heartbeat`,
the deadline keeps moving away from you. The day you stop, the mathematics
opens the envelope.

Designed as a standalone CLI and as a [ferryman](https://github.com/estejosh/ferryman)
add-on: any ferryman file channel can carry the sealed artifact to your
successors' machines.

---

## How it works

1. **Archive** — `git bundle --all` (full history + all refs), plus any extra
   working-tree files you chose (globs and/or conventional secret locations),
   packed into one file. A custom archiver can replace this entirely.
2. **Encrypt** — a fresh 32-byte key encrypts the archive with AES-256-GCM.
3. **Timelock** — that key is itself encrypted with identity-based encryption
   ([tlock]) to *beacon round R = now + window*. The only decryption key for
   round R is drand's BLS signature of round R — which **does not exist**
   until time(R). Nobody can open it early. Not you, not us.
4. **Seal** — each successor gets their own independently sealed copy under
   `<repo>/.deadman/` alongside `<repo>/state.json`-described state in
   `.deadman/state.json`. Sync the copies anywhere; after round R anyone
   holding one can recover your work.
5. **Heartbeat** — re-sealing at a new future round atomically replaces the
   copies and prunes old ones. Living = pushing the deadline.

[tlock]: https://eprint.iacr.org/2023/189

## Quickstart

```sh
cargo install --git https://github.com/estejosh/ferry-deadman ferry-deadman
# or: cargo install ferry-deadman   (once published on crates.io)

cd ~/projects/my-repo

# 1. Scaffold a commented deadman.toml:
ferry-deadman init --repo .

# 2. Edit it (beacon, window, successors…), then drill offline first:
ferry-deadman arm --repo . --simulate --window 2s --successor ada=succ.pub
ferry-deadman test-trigger --repo .     # waits out the window, prints proof

# 3. Arm for real against the drand quicknet chain:
ferry-deadman arm --repo .              # everything comes from deadman.toml

ferry-deadman status    --repo .
ferry-deadman heartbeat --repo .        # any "I'm alive" event re-arms
ferry-deadman test-trigger --repo .     # rehearsal: verify recovery works
ferry-deadman disarm     --repo .       # remove config + local sealed artifacts
```

Every setting lives in the optional per-repo `deadman.toml`; CLI flags merely
override it value-by-value.

## `deadman.toml` reference

All keys optional; unknown keys warn but never error (forward compatible).
`init` writes this as a commented template.

| key | default | meaning |
|---|---|---|
| `window` | `"30d"` | silence window before unlock: `30d`, `12h`, `45m`, `90s`, `1w`, compound `1d12h` |
| `beacon` | public quicknet mirrors | `"simulate"` (offline fake chain, NO protection) or any drand HTTP endpoint URL |
| `include` | `[]` | gitignore-style globs archived beyond the bundle (`"docs/**"`, `"*.key"`); bare patterns match basenames at any depth |
| `include_secrets` | `false` | additionally sweep conventional secrets: `.env*`, `*.key`, `*.pem`, `secrets/**`, `.secrets/**` |
| `[[successors]]` `name` / `key` | required ≥1 | one entry per successor; EACH gets its own sealed copy at `.deadman/sealed-<name>.tlock`. `key` = file path or inline hex (identity commitment only) |
| `archive.command` | built-in bundle+tar.gz | replacement archiver: shell string or argv vector; must write ONE file to `$FERRY_DEADMAN_OUT` (cwd = repo, `$FERRY_DEADMAN_REPO` set). Recovery then verifies by hash instead of bundle verification |
| `heartbeat.sources` | `["manual"]` | which events re-arm the switch: `"manual"` (explicit command, always honoured) and/or `"any-cli"` (any invocation re-arms) |
| `notify.arm` / `notify.rearm` / `notify.trigger` | none | arbitrary shell commands run on arm / re-arm / trigger via `sh -c` (cwd = repo). Exposes `$FERRY_DEADMAN_EVENT`, `$FERRY_DEADMAN_REPO`, `$FERRY_DEADMAN_ROUND`, `$FERRY_DEADMAN_UNLOCK_AT`. Hook failures are warnings |

Example:

```toml
window = "30d"
beacon = "https://api.drand.sh"
include = ["docs/**", ".env*"]

[[successors]]
name = "ada"
key = "~/keys/ada.pub"

[[successors]]
name = "grace"
key = "aabbccddeeff00112233445566778899"

[notify]
trigger = "mail -s 'project handed over' ada@example.test < NOTICE"
```

## Commands

| command | what it does |
|---|---|
| `init [--repo <path>] [--force]` | write the commented `deadman.toml` template |
| `arm [--repo <path>] [...overrides]` | seal the repo at a future beacon round |
| `heartbeat [--repo <path>]` | rebuild the archive at a **new** future round; prune old copies |
| `status [--repo <path>]` | armed state, successors, next unlock round/time, last heartbeat |
| `disarm [--repo <path>]` | delete `deadman.toml` + `.deadman/` |
| `test-trigger [--repo <path>] [--max-wait 0s] [--keep]` | sandbox drill: wait out the round, decrypt every copy, verify integrity, print proof |

Arm overrides (each beats the config): `--config <file>`,
`--successor [name=]key` (repeatable), `--window`, `--beacon <url>`,
`--simulate`, `--include <glob>`, `--include-secrets/--no-include-secrets`,
`--archive-cmd <shell line>`.

Exit codes: `0` ok · `1` error · `2` bad input / not armed / not a git repo ·
`3` still time-locked (expected during drills).

## Using it with ferryman channels

The entire recovery payload is a single self-contained file per successor:

```
<repo>/.deadman/sealed-ada.tlock
```

Point any file-sync channel at the repo's `.deadman/` directory (it is kept
out of git via `.git/info/exclude`, so it never pollutes history). Whatever
channel you already trust to move files — ferryman channels, rsync, object
storage, a USB stick in a drawer — works. After round R the successor runs
`ferry-deadman test-trigger` (or follows the manual recovery steps printed in
the proof output).

## Threat model

**Guarantees**

- *Nobody opens early.* Decryption requires drand's signature of round R,
  produced by a distributed threshold network only after time(R). Breaking
  this means breaking BLS-12-381 or corrupting a majority of the League of
  Entropy — not stealing your laptop, not pressuring a vendor.
- *Owner cancels by living.* A heartbeat re-seals at a new round; the old
  ciphertext is deleted locally and its round never arrives for the new blob.
- *No infrastructure executes the switch.* There is no server to subpoena,
  hack, or shut down. The artifact is inert bytes until the beacon speaks.
- *We cannot block it.* Neither ferryman nor any third party can prevent a
  successor who holds the artifact from opening it after round R.
- *Tamper-evident.* The archive is authenticated twice (AES-GCM over the
  payload, sha256 records of bundle + archive in both state and artifact),
  and every successor copy must decrypt to identical bytes during drills.

**Explicitly out of scope**

- `--simulate` mode enforces the timelock **by policy, not cryptography**.
  Its signature is a public function of the round number. It exists so tests
  and rehearsals run offline and deterministically. Never rely on it for real
  succession.
- After round R passes, the archive is decryptable by *anyone* holding the
  artifact (that is the point). Delivery secrecy before R is your channel's
  job; the timelock protects the *contents*, not the *envelope's location*.
- Successor keys/fingerprints are audit commitments only; they grant no
  decryption power and prove no identity by themselves.
- drand quicknet is operated by the League of Entropy. A catastrophic,
  long-lived compromise of their threshold could forge early signatures;
  this is the same trust anchor every tlock deployment shares.
- Heartbeat counting is exactly what `heartbeat.sources` says it is — nothing
  watches logins behind your back. Wire explicit heartbeats to whatever
  liveness signal you like (cron on sign-in, a button, CI).

## Artifact format

```
b"FDM1" | u32 header_len | header(JSON) | keyblob | nonce(12) | AES-GCM(payload)

keyblob (drand): 0x01 || U(96) || V(16) || W(16)      # tlock IBE ciphertext
keyblob (sim):   0x00 || nonce(12) || ct(48)          # policy-gated wrap
```

The JSON header is plaintext on purpose: a successor can see the target
round, chain, and fingerprints without any keys.

## Development

```sh
cargo test                                    # full offline suite (simulation beacon)
cargo clippy --all-targets -- -D warnings
cargo test --test real_beacon -- --ignored    # live-network validation vs api.drand.sh
```

Requires Rust ≥ 1.90. `#![forbid(unsafe_code)]`.

## License

MIT © 2026 estejosh — see [LICENSE](LICENSE).
