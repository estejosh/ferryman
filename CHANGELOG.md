# Changelog

## Unreleased

### Added - dashboard team model and invitation prototype (`codex/novice-dashboard-ux`)

- **Dashboard redesigned around human teams and agents.** A new home and
  install experience separates human teammates from AI agents throughout,
  backed by a real `GET /api/team` endpoint that reads the roster and master
  declaration and never invents ownership. Install and access controls are an
  honest policy preview: without enforcement behind them they save drafts and
  say so rather than claiming authority changed.
- **Teammate invitation onboarding, prototyped.** Owner-side invite composition
  and a recipient flow, both non-mutating pending signed invitation
  enforcement. The product model and remaining backend contract are in
  `docs/DASHBOARD_TEAM_ACCESS_MODEL.md` and
  `docs/TEAM_INVITATION_ONBOARDING_PROPOSAL.md`; design QA is filed under
  `docs/reviews/`.
- Demo state is client-side only (`?demo=team`) and never touches live APIs.

### Added - grants as leases: the lifetime primitive behind the team model

- **`ferry channel lease grant | renew | revoke | list`.** Access grants are
  now lease-shaped, per ADR 0013: a short-lived signed lease naming one
  subject, scopes, and optionally one resource (a secret id, a repository).
  Renewal extends from now by the original issuer only; a visible revocation
  ends authority immediately where seen; expiry ends it everywhere, including
  machines that never sync again. Every issue, renewal, and revocation lands
  in the audit ledger. Existing worker leases are untouched - tokens without
  grant fields sign under exactly their original payload bytes.
- **ADR 0013** records the semantics and what is deliberately left to policy:
  who may be trusted as an issuer is the enforcement layer's decision, not the
  primitive's.

### Added - the loop and the bill become observable

- **`ferry agent status`.** The one command for "why is nothing happening":
  whether the worker process is alive, which task it holds with heartbeat age,
  and the exact claim-gate decision the poll acts on - paused, outside working
  hours, someone typing, memory floor - naming the `agent.toml` setting that
  causes it. `--json` for callers.
- **Recorded engine usage makes cost real where engines report it.** Workers
  now parse the token counts an engine prints (Claude Code's JSON result, JSONL
  streams restating cumulative totals), record them in the trajectory and the
  signed result, and `ferry cost project` bills from recorded numbers instead
  of reading structurally zero. Engines that print nothing stay an honest zero.
- **ADR 0013: agent access grants are renewable leases.** The semantics behind
  the dashboard team-access and secret-transport proposals: authority is a
  short-lived signed lease renewed by its owner, so revocation means "stop
  renewing" and an offline machine expires out of authority at a known horizon
  instead of holding a durable capability until a revocation file arrives.
  THREAT_MODEL states the same rule.

### Added - the setup knows before the first task does

- **`ferry doctor`.** One read-only command that answers "will this machine
  actually run a task?" before one fails trying: channel discovered, `agent.toml`
  parses, the engine resolves on PATH, signing key and roster entry exist,
  Syncthing reachable, credentials file present (never its contents). Every
  failing check states its remedy. `--json` for a calling program; exit 1 when
  not ready.
- **Engine-aware worker args.** `ferry enable --command opencode` now writes
  OpenCode's real non-interactive contract (`run --auto {prompt}`) instead of
  Claude Code's `-p`, which failed on every task for every OpenCode operator;
  `codex` gets `exec --full-auto` as its config already documented. Claude and
  unknown engines keep the historical args, and Claude's permission grant is
  still yours to add — never written in uninvited.
- **Enable reports engine presence.** Human output warns when the configured
  engine is missing from PATH; `--json` gains `agent_args` and `command_found`,
  so an agent caller can react without parsing prose.

### Fixed

- `settle_worktree` tripped `clippy::too_many_arguments` under
  `-D warnings` with the pinned toolchain, failing `cargo clippy --workspace`
  locally on an unchanged tree. Allowed explicitly, with the reasoning inline.

## 0.4.1

A fleet is a mixed fleet. Everything here was found by running 0.4.0 across Windows,
WSL and Linux at the same time, and none of it is visible on any single one of them.

**If you run Ferryman on more than one machine, upgrade.** The identity faults below
are silent on a case-folding filesystem and split an agent in two on a case-sensitive
one, which is exactly the pair most people have.

### Fixed - one name, one identity

- **`Grouchly` and `grouchly` were two agents with two keys.** An agent name is a
  filename in three stores at once: the roster entry in the synced folder, the pinned
  key store, and the private key store. Whether two spellings are the same file
  therefore depended on the filesystem - NTFS and APFS fold case, ext4 does not. So the
  same two commands produced one agent on Windows and two on Linux, each with its own
  key; messages addressed to one were invisible to the other, and a message signed by
  one read as `UnknownSigner` to a machine that knew the other. Names are now folded
  where they are minted, published, and put into messages.

  Existing keys are **adopted, never rotated**. A machine holding `keys/Grouchly.key`
  and nothing else would otherwise find no key under the folded name and mint a fresh
  one - publishing a second key under a name the fleet already trusts, which every
  other machine would correctly read as an impostor.

  Rosters are folded on **read**, not rewritten: the synced folder is
  one-writer-per-path, and someone else's roster entry is not yours to delete.
  Signature checks match case-insensitively so a message already in flight, signed
  under the old spelling, still verifies - otherwise upgrading would itself raise a
  fleet-wide impersonation alarm.

- **A Syncthing conflict copy of a roster entry was read as a second agent.** Found by
  grouchly. `agents/beastly.sync-conflict-....json` carries the same `name`, so the
  roster held two `beastly` entries - and the conflict copy is usually the older,
  *keyless* one, so it could displace a real published key. This, not the
  capitalisation, is what produced "registered participant names must be unique" on a
  live channel.

### Fixed - signing

- **A message could be published unsigned in a person's name.** Every signing site was
  written `if let Ok(identity) = signing_identity(..)`, which computes the refusal and
  discards it. The reasoning was sound - a fleet that has not adopted signing must keep
  working - but it covers one case and was applied to two. Where nobody has a published
  key, unsigned is all there is and readers see it as unsigned. Where the roster
  *knows* this sender and carries a key for them, "unsigned from op" is a claim about
  who spoke, made to readers who could have checked it, with nothing behind it. That
  case now refuses. Five sites: send, order (twice), claim, review.

### Added - operators are people

- **`ferry operator create|export|import|list`.** A human operator's key is sealed
  under their password rather than kept in plaintext like a machine key, which is what
  makes it safe to carry: the sealed record can cross machines and is useless without
  the password. So one person is one identity everywhere they work, instead of a
  separate key per machine under the same name - which the roster's first-key-wins
  correctly rejects. `import` verifies the record against the roster **before**
  installing it, so a mismatch is caught at import rather than at the first rejected
  approval.

- **Operator identities are machine-wide, and a machine can hold several.** Being the
  operator of nineteen projects used to mean nineteen imports. Machine-wide because a
  person is not per-directory - the same reasoning that moved machine keys once per
  machine. Several per machine because these records are *sealed*: two people can keep
  an identity on one workstation without being able to sign as one another. A
  project-local record still wins for that name, so one project can have a different
  operator from the rest of the machine - use `--this-project-only`.

- **Operators can receive messages.** A created operator published an empty capability
  list. Nothing refused; every path that routes by capability simply skipped the human.

### Fixed - platforms and CI

- **A scorer that ignores its input was sometimes recorded as never having run.** A
  scorer that exits without reading stdin (`exit 0`, `test -f build/report.json`, a
  `grep -q` matching the first line) makes `write_all` return EPIPE. That was read as
  "could not run", which abstains from the fleet's synced learning record - so a real
  verdict was silently discarded whenever the race went the wrong way. It passed three
  runs in four.

- **`ferry enable` left the signing key one `git add -A` from being committed.**

- **macOS is built and tested on every push, not only on tags.** It was gated to tags,
  and the cost was paid in full at the first release: 101 commits had never been
  compiled on macOS, and the tag build was where we found out. Its failures now name
  the failing test in the job summary, readable without a token.

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
