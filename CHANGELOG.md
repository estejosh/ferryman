# Changelog

## 0.4.0

The release this project was reviewed for rather than written into. Most of what
follows is a fix, and the detail is deliberate: for a tool that asks you to let models
work unsupervised on your machines, *how the author looks for problems* is more useful
information than a feature list.

**If you are running 0.3.x, upgrade.** Several of these lose work or forge identities.

### Fixed — work and identity

- **A worker could kill its own running task, in a loop it could not leave.** The loop
  sampled free memory every five seconds and killed the agent CLI below
  `min_free_ram_mb` — the same threshold that had just allowed the claim, while the
  agent CLI is the thing consuming the memory. Then `bail!` became a retry, forever,
  with the claim never released and no other machine able to take it. It also read
  *system* memory, so a browser could kill your run. Removed. The pre-claim gate was
  always the correct place, and `governor`'s own tests assert the promise this broke:
  *"anything already running is unaffected."*
- **Any peer could permanently destroy a project's root of trust.** `ferry channel
  master transfer` resolved the *current* master's identity with `load_or_create`,
  minting a key under their name. Reproduced end to end: a peer holding only the synced
  folder took the master role, after which every machine failed `master status`,
  `lease` and `grants` with "signature does not verify", with no way back. Fourteen
  call sites took a name from argv and would forge a key for it; all now refuse through
  one helper. `ferry channel join` remains the only command that may create a key.
  `transfer_master` additionally verifies the offered *key*, not the name.
- **Interrupts were bound to nothing.** A signed `kill` copied into another task's
  directory — no key needed, just `cp` — made every worker abandon that task's claim.
  Now bound to its order id and its filename's issuer.
- **One malformed file stopped a worker permanently, with no signature required.** The
  interrupt reader parsed *above* the signature check and propagated, so a single
  non-JSON file — or a Syncthing conflict copy — failed every pass every ten seconds,
  forever. It now skips, as the signature check three lines below always did.
- **The audit ledger reported itself tampered after ordinary two-machine use.** One
  `ledger.jsonl` in the synced folder, appended by every machine, guarded by a
  machine-local lock. A sync conflict dropped records and broke the hash chain
  permanently, because the file is append-only. Now `ledger.<agent>.jsonl` — one writer
  per path, like every other artifact — verified per file and merged on read. Existing
  ledgers are still read, so no history is lost.

### Fixed — secrets and prompts

- **`--sandbox` put credentials on the process list.** The container runner passed
  `--env KEY=VALUE` into podman's argv, and `/proc/<pid>/cmdline` is world-readable.
  Now the name only, with the value in the child's environment.
- **Operator key files were world-readable.** Salt, nonce, iteration count and sealed
  seed at default umask. Now `0600`, and `0700` on the directory, via the same helper
  the signing key has always used.
- **The dashboard answered anonymous callers.** Authentication was per-handler and
  three of seventeen routes had it; the rest served order payloads, worker output, the
  memory bank, the ledger, and every device's registered email. Now one layer over the
  whole router with an explicit list of public paths.
- **Creating a dashboard operator required no credential at all** — anyone reaching the
  port could mint an identity the whole fleet trusts. The first operator now needs a
  single-use token printed to the terminal; every later one needs a session.
- **The dashboard's DNS-rebinding guard was a string prefix**, so `127.0.0.1.evil.com`
  passed it. Now parsed as an IP address.
- **Memory-bank profiles were unsigned prompt text from a synced folder**, injected at
  the front of every prompt framed as the agent's own trusted memory. Now signed and
  verified three ways — content hash, signer identity, roster membership — and reframed
  as a record rather than an instruction. Peer profiles are attributed, not asserted.
- **`/api/memory/suggest` invented its author** when unauthenticated, writing the byline
  `"operator"` into the synced memory bank every agent reads.

### Fixed — Windows

Every one of these was found by running the binary on a real Windows machine. All of
them passed CI and both test suites first.

- **`ferry` crashed instantly**: `thread 'main' has overflowed its stack`. `main` was
  one async fn holding every subcommand's locals, and Windows gives the main thread 1 MB
  where Linux gives 8. Even `--version` died. Now the CLI runs on a thread with a stack
  size we choose.
- **Shell task sources never worked**, because `sh` was hardcoded. And fixing that alone
  was not enough: Rust escapes `"` as `\"` on Windows, which `cmd.exe` does not
  understand, so quoted commands silently produced mangled output rather than an error.
- **`clippy -D warnings` failed**, which is a CI job on `windows-latest`.
- **The benchmark scorer recorded fabricated failures into the fleet's synced confidence
  data**, because a scorer that could not spawn was indistinguishable from one that
  failed. There are now three outcomes, and "could not run" abstains.

### Added

- **`ferry soak`** — a report you can paste into an issue: counts, category labels and
  the build string. Redaction is structural rather than filtered: every field is a type
  that cannot hold a path, a prompt or a secret, and run-log lines are reduced to a
  label from a fixed vocabulary before counting. Prints by default; sends only with
  `FERRYMAN_SOAK_URL` *and* `--send`, per invocation. Documented in `PRIVACY.md` and
  pinned by a test that fails if the payload changes without the page changing too.
- **`ferry --version` now reports the commit** — `0.4.0 (53d577aa)`, with `-dirty` when
  the tree was not clean. The previous release reported the same version before and
  after a day of changes, which meant a fleet operator could not answer "did that
  machine get the new build?" It came from an outside upgrade report, and it was the
  sharpest thing in it.
- **`preamble_file`** — standing context placed byte-identically at the front of every
  prompt, so provider prefix caching applies. A configured-but-unreadable preamble stops
  the agent starting rather than quietly degrading.
- **`claim_window`** — hours during which a machine picks work up, local time unless you
  append `UTC`. For cheaper overnight power, metered connections, or a desktop in a room
  where someone is asleep.

### Changed

- `--read-only` dashboards now permit sign-in. With reads requiring a session, refusing
  the only way to obtain one made the flag mean "unusable" rather than "cannot write".
- `PRIVACY.md` documented `checkin = "off"` in `agent.toml`; no code ever read that key.
  Corrected, and the OpenTelemetry exporter is now documented — including that its spans
  *do* carry agent names, project names and workspace paths, unlike anything else.
- The README gained a **Known issues** section. Ten of them.

### Known issues

Listed in the README rather than discovered by you. Notably: `ferry cost project`
reports `$0.00` because nothing records per-run token counts yet; engine prices and
quality priors are hand-typed constants; `ferry ask` attributes sources it has not
verified; an addressed order reports as `claimed` before anyone picks it up; the MCP
client has no timeouts; and the SBOM omits the tray binary.

## 0.3.1

- Syncthing wiring in the released binary.

## 0.1.0-preview

- Local single-node SQLite orchestration reference implementation.
- Project-local private Git workspaces, durable job state, worker leases, approval
  gates, artifacts, SSE, agents, and bridge-owned project memory.
