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
successor's machine.

---

## How it works

1. **Archive** — `git bundle --all` (full history + all refs), plus optional
   conventional secret files (`.env*`, `*.key`, `*.pem`, `secrets/**`),
   packed into one `tar.gz`.
2. **Encrypt** — a fresh 32-byte key encrypts the archive with AES-256-GCM.
3. **Timelock** — that key is itself encrypted with identity-based encryption
   ([tlock]) to *beacon round R = now + window*. The only decryption key for
   round R is drand's BLS signature of round R — which **does not exist**
   until time(R). Nobody can open it early. Not you, not us.
4. **Seal** — everything lands in `<repo>/.deadman/sealed-archive.tlock`
   with `<repo>/.deadman/state.json` describing the armed state. Sync that
   one file anywhere; after round R anyone holding it can recover your work.
5. **Heartbeat** — re-running the seal at a new future round atomically
   replaces the artifact and prunes the old one. Living = pushing the deadline.

[tlock]: https://eprint.iacr.org/2023/189

## Quickstart

```sh
cargo install --git https://github.com/estejosh/ferry-deadman ferry-deadman
# or: cargo install ferry-deadman   (once published on crates.io)

cd ~/projects/my-repo

# Dry run first — offline fake beacon, no real protection:
ferry-deadman arm --repo . --successor-pub succ.pub --window 30d \
    --include-secrets --simulate
ferry-deadman test-trigger --repo .        # waits out the window, then proves decryption

# Arm for real against the drand quicknet chain:
ferry-deadman arm --repo . --successor-pub succ.pub --window 30d --include-secrets

ferry-deadman status    --repo .
ferry-deadman heartbeat --repo .          # any "I'm alive" event re-arms
ferry-deadman test-trigger --repo .       # drill: verify the recovery path works
ferry-deadman disarm     --repo .         # remove config + local sealed artifacts
```

### Commands

| command | what it does |
|---|---|
| `arm --repo <path> --successor-pub <file\|hex> --window 30d [--include-secrets] [--beacon <url>] [--simulate]` | seal the repo at a future beacon round |
| `heartbeat --repo <path>` | rebuild the archive at a **new** future round; prune old artifact |
| `status --repo <path>` | armed state, next unlock round/time, last heartbeat |
| `disarm --repo <path>` | delete `.deadman/` (config + sealed artifacts) |
| `test-trigger --repo <path> [--max-wait 0s] [--keep]` | sandbox drill: wait out the round, decrypt, verify bundle integrity, print proof |

Exit codes: `0` ok · `1` error · `2` bad input / not armed / not a git repo ·
`3` still time-locked (expected during drills).

## Using it with ferryman channels

The entire recovery payload is a single self-contained file:

```
<repo>/.deadman/sealed-archive.tlock
```

Point any file-sync channel at the repo's `.deadman/` directory (it is kept
out of git via `.git/info/exclude`, so it never pollutes history). Whatever
channel you already trust to move files — ferryman channels, rsync, object
storage, a USB stick in a drawer — works. The successor runs
`ferry-deadman test-trigger` (or simply follows the manual recovery steps in
the proof output) once the unlock round has passed.

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
  payload, sha256 records of bundle + archive in both state and artifact).

**Explicitly out of scope**

- `--simulate` mode enforces the timelock **by policy, not cryptography**.
  Its fake signature is a public constant. It exists so tests and rehearsals
  run offline and deterministically. Never rely on it for real succession.
- After round R passes, the archive is decryptable by *anyone* holding the
  artifact (that is the point). Delivery secrecy before R is your channel's
  job; the timelock protects the *contents*, not the *envelope's location*.
- The successor fingerprint (`sha256:` commitment) is audit metadata; it
  grants no decryption power.
- drand quicknet is operated by the League of Entropy. A catastrophic,
  long-lived compromise of their threshold could forge early signatures;
  this is the same trust anchor every tlock deployment shares.
- Heartbeats are explicit. This tool does not watch logins by itself — wire
  it to whatever liveness signal you like (cron on sign-in, a button, CI).

## Artifact format

```
b"FDM1" | u32 header_len | header(JSON) | keyblob | nonce(12) | AES-GCM(tar.gz)

keyblob (drand): 0x01 || U(96) || V(16) || W(16)      # tlock IBE ciphertext
keyblob (sim):   0x00 || nonce(12) || ct(48)          # policy-gated wrap
```

The JSON header is plaintext on purpose: a successor can see the target
round, chain, and fingerprints without any keys.

## Development

```sh
cargo test                       # full offline suite (simulation beacon)
cargo clippy --all-targets -- -D warnings
cargo test --test real_beacon -- --ignored   # live-network validation vs api.drand.sh
```

Requires Rust ≥ 1.90. `#![forbid(unsafe_code)]`.

## License

MIT © 2026 estejosh — see [LICENSE](LICENSE).
