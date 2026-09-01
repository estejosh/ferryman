# Changelog

## Unreleased

## v0.5.6 - 2026-09-01

One place to put things, an operator whose "stop" means stop, and a fleet
that keeps itself current without being asked.

### Added

- **One root called `ferry`.** `ferry/comms/`, `ferry/repos/`, `ferry/work/`
  and a `.ferry` manifest that tells an engine where everything is. Finding
  things used to be guesswork - the dashboard read the directory beside wherever
  it happened to be launched, which finds a fleet kept as siblings, finds nothing
  on another drive, and fails *silently* by showing one project as though one is
  all there is. Nothing of yours is moved into the root: repositories are linked
  and recorded, never relocated. See ADR 0019.
- **The manifest fills itself in by being used.** Every time a route is
  resolved, that project and its repository are filed. There is no command to
  run and nothing to keep in sync by hand; a fleet that has been running for
  weeks acquires a complete manifest by carrying on working. Nineteen channels
  filed themselves on the first pass here.
- **A project picker in the dashboard**, backed by discovery that reads the
  manifest first, then the learned index, then the directory scan - so the answer
  improves as the install is used rather than depending on where it was started.
- **Workers keep themselves current.** A long-running `ferry agent` checks for a
  newer release at most every six hours, installs it, and hands over at the next
  natural boundary. Ferryman is getting better daily and an install that needs a
  person to notice is an install that falls behind.

- **A person can say no to a release.** The channel could only hold approvals, so
  declining had nowhere to go and silence was indistinguishable from refusal - which
  meant "did anybody look at this" could not be answered. `Decline` writes a signed
  denial with a reason. It is a separate record rather than a field on the approval,
  because adding a field would have changed the bytes every existing approval was signed
  over and retroactively turned real consent into an unreadable signature. An unsigned
  denial is ignored: a forged refusal blocking every release is a denial of service any
  peer could mount, and refusing to ship is not the safe direction when the block itself
  is unattributable. Declining is never disabled by red tests or staleness - those refuse
  a release, and must not refuse a person's refusal.
- **Teammates can be invited, and what each may do is on the screen.** Inviting reserves
  the *name*, and says so: an operator key is sealed under that person's own password, so
  a key minted here would be a key this machine has seen, which is the thing operator
  identities exist to prevent. Access levels are `MasterGrant`, which has carried
  projects, roles and capabilities since ADR 0014 - authority that was in the channel and
  on no screen, so who could do what was answerable only by reading JSON.

### Fixed

- **The release page could offer to approve what the gate would refuse.** `may_sign` had
  one caller, `ferry release status`, at a terminal; the dashboard never consulted it. Two
  answers to one question, with the reassuring one in front of the person. The page now
  renders the verdict from the same function the signing path calls.
- **A killed order came back.** The worker acknowledged a signed `kill`, dropped
  its claim and returned - correct for the running process, never made true of the
  order. Next poll, the acknowledgement made the interrupt stop being pending, the
  order read as plainly `Open`, and the same worker claimed it and ran the work the
  operator had just stopped. Because `list_tasks` is a correct FIFO, a killed order
  sat permanently at the *head* of the queue and re-ran itself ahead of everything
  issued after it: one killed at 20:11 was acknowledged at 23:13, re-claimed at
  23:45, and held a worker for thirty-one minutes while live work sat last in a
  line it could never reach. Death now belongs to the order, is read from the
  order's own signed files by every machine, and needs a valid signature to
  declare. `Kill` and `Pause` also did byte-identical work; kill was only ever a
  pause that sounded final. See ADR 0020.
- **Two projects could share one worktree, and one committed to the other.**
  Moving worktrees into a shared `ferry/work/` keyed them on `(order id, agent)`,
  which was unambiguous only while they lived beside their own repository. Order
  ids are short human names nobody coordinates across projects, and a ferry root
  exists to hold many projects - so the second task found a valid checkout sitting
  there, reused it, and ran and committed in the wrong repository, reporting
  success. Worktrees are now keyed on the repository as well, and reuse verifies
  the directory is a checkout of *this* repo rather than merely a checkout.
- **The ledger recorded claims that never happened.** The entry was written the
  instant the claim file was, before the re-read that decides whether the claim
  held, so every lost race went into the tamper-evident chain as "claimed order X".
  A machine losing the same race every ten seconds - which had been happening for
  six hours - writes thousands of signed entries for claims it never had. The
  ledger's whole value is recording what happened.
- **`Restart=on-failure` would have permanently killed a self-updating worker**,
  because a worker that hands over cleanly after an update exits successfully.
- **The dashboard reported a valid approval as coming from an unknown signer**,
  having verified it against the roster as it was at boot rather than as it is.
- **CI's test job had been red on all three platforms since before v0.5.4**, and
  v0.5.4 and v0.5.5 were both tagged, signed and published over it. Four dashboard
  tests each asked for their own machine state directory through a first-call-wins
  `OnceLock`, so three of them silently got the first one's - already holding an
  operator - and the test that needs a virgin machine passed or failed depending on
  which test the scheduler started first. It won that race on the maintainer's
  machine and lost it on every runner, which is how local and CI disagreed for weeks
  with neither of them lying.

## v0.5.5 - 2026-08-31

The release that can see what people said, and the last one anybody has to
install by hand.

### Added

- **The dashboard can show the conversation.** It showed team, tasks, stats,
  ledger, learnings, roster, fleet, memory, secrets and cost - and not one word
  anyone had said, while `conversation.rs` had been storing signed turns in the
  channel all along with the Telegram bridge as their only writer. Conversations
  down the side, the thread in the middle, a box to type in. Typing here appends a
  signed turn into the same file the bridge appends to, so what is said in the
  browser and what is said in Telegram are indistinguishable afterwards and every
  agent reads both. The dashboard is a view over the synced channel, never a
  second channel: a message that existed only in the dashboard would be invisible
  to the fleet and would die with the process.
- **`ferry update`, and installs that keep themselves current.** Fetches the
  release for this platform, verifies it against the checksum published beside it,
  and installs it where ferry runs from; `--check` says what would change and
  installs nothing. `ferry agent` and `ferry dashboard` do it on the way in, at
  most once every six hours, because a notice somebody has to act on is how an
  install ends up four minor versions behind. It only ever replaces the binary on
  disk - the running process keeps the code it has and every worker in flight
  finishes its task, so the new version takes effect at the next start.
  `FERRYMAN_NO_AUTO_UPDATE=1` turns it off.

### Fixed

- **A worker that died before its first heartbeat held its task forever.** The
  staleness test read only the heartbeat, so a claim carrying none had nothing to
  compare against and stayed `Claimed` indefinitely - the one shape of death ADR
  0011's recovery story could not see. The claim time is the fallback now.
- **`el.hidden` did nothing to labels on the sign-in form**, because
  `#login label{display:block}` overrode the user agent's `[hidden]` rule: the
  create-identity form asked for a recovery phrase above a field that was not
  there, on the first screen a stranger sees.
- **`ferry channel review --notes-file`**, for the same reason `--task-file`
  exists: a shell splits a multi-line verdict on an apostrophe, and a review is a
  signed ledger record, so a mangled one is worse than a missing one.


## v0.5.4 - 2026-08-31

The release that makes a person someone before it makes them configure anything,
and gives the orchestrator a memory that outlives the machine holding it.


### Added

- **Marvin: the orchestrator is a memory, not a machine** (ADR 0017). What has to
  survive when an orchestrator stops is not a machine and not a model - it is what
  it knew. `ferry marvin brief` records the objective, what is in flight and why,
  the standing constraints, the decisions that never became ADRs, what was tried
  and rejected, and what is waiting on the human; `ferry marvin resume` prints it
  back in the order a successor needs it. Written continuously rather than at
  handoff, for the same reason `ferry-deadman` exists: running out of context is
  never a graceful event, so the handoff cannot be an event either, and `brief`
  therefore touches only the sections it is given. Exactly one machine holds Marvin
  at a time - `take` refuses while the current holder is still being heard from and
  says how long ago that was, `release` hands it straight over, and writing to the
  memory is itself the heartbeat. Each holder writes its own file, so
  one-writer-per-path holds; those files are pages of one memory and `resume` reads
  them as one. Work in flight is read from the channel rather than from the memory,
  so a stale page cannot hide a task.
- **`ferry channel order --task-file`.** An order worth issuing is worth writing in
  an editor. A shell splits a multi-line brief on an apostrophe and the order lands
  signed and mangled, which is worse than a missing one because it looks like it
  worked.
- **One seed, and every identity derives from it** (ADR 0016), in the channel
  crate. A machine may hold an `operator.seed` beside its other machine state -
  32 bytes, owner-only, never in a project directory and never in the channel -
  and an identity being created for the first time is derived from it rather than
  minted at random: `HKDF-SHA256(seed, "ferryman/v1/sign/" || name)` for signing
  and `"ferryman/v1/encrypt/" || name` for sealed secrets, over the case-folded
  name so `Fang` and `fang` cannot become two identities again. Distinct keys per
  agent, so "which agent did what" survives. The derived key is then written to
  the keystore and the keystore wins from that point on, which is what keeps
  rotation possible: an agent that must re-key writes a new key and the roster
  reports `KeyChanged` exactly as it does today. Nothing that already has a key
  is re-keyed, anywhere, and a machine with no seed behaves precisely as before.
  This also makes true the sentence ADR 0015 wrongly claimed was already true
  about the encryption key. The first-run flow and the recovery phrase are a
  separate change; this one is the crypto underneath them.
- **The first thirty seconds: an identity and a recovery phrase.** `ferry enable`
  at a terminal now creates the operator seed on first run, shows it once as a
  BIP-39 English recovery phrase (24 words), and prints one operator fingerprint
  to verify out of band - one value per person instead of one per agent per
  project. An existing seed is used silently and never re-displayed. `ferry
  identity show` prints that fingerprint and which agent identities on the
  machine derive from the seed; `ferry identity recover` restores the seed from
  the phrase onto a new machine, and with `--force` onto one that already holds a
  seed, moving the old seed aside rather than deleting it. The seed bytes and the
  phrase never reach a log line, a result payload, or the channel, and
  `*.seed`/`operator.seed` are excluded from the channel's `.stignore`.
- **The dashboard operator is the seed, and the password is the local unlock.**
  The dashboard's operator identity no longer mints a random key: its signing key
  is the third derivation from the machine seed, `HKDF-SHA256(seed,
  "ferryman/v1/operator/" || name)` - bound to the operator's name, exactly as an
  agent's key is bound to the agent's, so two operators on one machine are two
  keys and not one - and the recovery phrase genuinely restores the person, not
  just the agents. The bare `"ferryman/v1/operator"` remains what it always was:
  the one machine fingerprint per seed, which is not anybody's signing key. The password is demoted to the local unlock - it still
  seals the derived key at rest and is what a person types to sign in, but it is
  no longer the root of anything. Operators that predate the seed keep their keys
  forever. The first-run experience now lives in the browser: opening the
  dashboard with no operator creates the identity, shows the recovery phrase once
  (with a three-word confirmation before the page moves on), and drops the person
  into the product; recovery pastes the 24 words on a new machine; and a new
  Identity page shows the one fingerprint, readable aloud. The one-time setup
  token for the first operator is unchanged, for the reason given in the previous
  entry: the bootstrap endpoint had no authentication once, and the token is the
  proof of console access that no browser hand-off can reproduce without making
  the secret available over HTTP. Recovery in the browser carries the same gate as
  creation - an existing operator's session, or that one-time token - because a
  recovery phrase is not a credential when the machine has no seed to check it
  against: the caller simply supplies one.
- **`ferry-deadman`, a sub-product, at `crates/ferry-deadman`.** Timelocked
  succession for any git repository: seal an archive to a future drand beacon
  round, and it cannot be opened early by anyone, including whoever sealed it.
  Useful with no Ferryman anywhere - Ferryman's part is only transport, and a
  channel can carry the sealed artifact to a successor as ciphertext. In this
  workspace so it is compiled, linted and tested with everything else rather than
  living in a directory nothing builds, which found two Windows defects in the
  first hour. Its six commits came in with their history, and it was relicensed
  from MIT to the Ferryman Source-Available License on the way in.

## 0.5.3 - 2026-08-25

### Added

- **Secrets travel the channel, sealed** (ADR 0010). A credential is encrypted
  to each recipient with X25519 + XChaCha20-Poly1305, keyed through HKDF-SHA256
  salted with the ephemeral and recipient public keys, and only the ciphertext
  is ever written anywhere. The encryption identity is a separate keypair from
  the Ed25519 signing key, so sealing and signing cannot be confused for one
  another. A machine's access hangs off its owner's: revoking a person revokes
  their machines in the same act. Revocation is not retroactive, and the ADR
  says so rather than implying otherwise.
- **Telegram is a first-class order surface** (ADR 0008), with the conversation
  kept in the channel rather than beside the bridge, so an orchestrator reading
  an order can see what was already asked and answered instead of asking again.
- **Roles are conferred, not claimed** (ADR 0014).

### Fixed

- **A dead worker was only detectably dead on Linux.** `process_alive` read
  `/proc/{pid}` there and returned `true` everywhere else, so on macOS and
  Windows a lock left behind by a worker that died read as a live worker
  forever: the takeover in ADR 0011 never fired, and `retire` refused to release
  a worker that was already gone. A fleet that can recover on one platform and
  not the others is the failure ADR 0011 exists to remove. sysinfo answers for
  the one pid off Linux; no new dependency.
- **Windows OpenCode workers silently ran Claude Code's arguments.** The `.exe`
  suffix was stripped before the name was folded to lower case, so
  `OpenCode.EXE` missed the engine table and fell through to `-p {prompt}` -
  precisely the failure that table was added to prevent.

### Changed

- **The toolchain is pinned at 1.97** across the pin file, all five CI jobs and
  the container build stage. sysinfo 0.39 requires 1.95, and a dependency bump
  must never be the thing that moves the compiler under a project.
- **The crypto dependencies move a major version**: ed25519-dalek 2.2 to 3.0,
  chacha20poly1305 0.10 to 0.11, sha2 0.10 to 0.11, rand 0.9 to 0.10. Existing
  signatures verify unchanged - checked against a live channel, every record
  written by 2.2, all of them Valid under 3.0, none Unsigned, Invalid,
  UnknownSigner or KeyChanged.
- **CI builds the tray on every push.** It is excluded from the workspace,
  correctly - it needs GTK, and agent machines are headless - which left it
  compiled by nothing between releases. Its lockfile had already drifted behind
  the crypto bump it depends on by path, and would have broken on this tag.

## 0.5.2 - 2026-08-25

### Fixed

- A build from the v0.5.1 tag stamped itself `-dirty`, every time, forever. The
  manifest at that tag said 0.5.1 and the lockfile still said 0.5.0 for the six
  workspace crates, so cargo rewrote those lines before `build.rs` asked git
  whether the tree was clean - and `--locked` refused outright. The lockfile is
  part of the version bump now rather than a commit that follows it.

## 0.5.1 - 2026-08-24

### Fixed

- A task's worktree starts from the default branch rather than from wherever
  the checkout was left. 0.5.0 was tagged one commit before this landed, so the
  release assets carried the bug while a build from main did not - the two
  documented install paths disagreed about whether it existed.

### Changed

- The signing key's public half ships in `keys/estejosh.asc` with its
  fingerprint in the release process, so a tag can be verified without a third
  party being able to serve the key. 0.5.0 was signed and unverifiable
  everywhere, which reads as checked from a distance and is worse than
  unsigned.

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
## 0.5.0 - 2026-08-24

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
