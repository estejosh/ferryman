# Changelog

## v0.5.13 - 2026-09-23

This release exists for one thing: archiving now reaches the whole fleet. In 0.5.12
`ferry root archive` wrote a flag into this machine's `.ferry`, and `.ferry` never leaves
the machine it is on - so a project archived on beastly was still live on grouchly and
everywhere else. Every machine has to run 0.5.13 to honour a fleet-wide archive, which
is why this is a version and not a quiet patch.

### Changed

- **An archive is now a signed `ARCHIVED` file in the channel, not a line in the local
  index.** Syncthing carries it to every machine that syncs the channel, and carries its
  removal back, so `archive` and `--restore` both travel with the project. `.ferry` no
  longer has an `archived` field.

- **Only a project's master can archive it or bring it back.** The mark is signed, and a
  machine honours it only when the signature is the master's, by the key the channel
  knows the master by. A peer can write a file called `ARCHIVED` into the channel; it
  cannot make any machine believe it. A mark signed by a member, lifted from another
  project, or not signed at all is read as no mark. The master's `--restore` clears it.

- **A project with no master cannot be archived**, and says so, with the command that
  names one (`ferry root master`). Archiving also needs the channel on the
  machine doing it, since that is the only place the fleet would hear it.

### Added

- **`ferry root master`: one password, and you are master of every project that has
  none.** `enable` never makes a machine the master where a person is present, and it
  cannot sign as that person, so on a machine you use it left the role empty and
  pointed at the dashboard - and nothing came back for it. On the machine this was
  written for, 30 of 33 channels had no master and 30 had never seen the person's
  public key. This goes through every project in the ferry root, puts your key on each
  channel's roster, and declares you master where nobody is. A project with another
  master, or that knows your name by a different key, is left alone and named.
  `--dry-run` shows the plan without a password. `enable` now points here.

  **And in the browser, unasked.** Opening the dashboard's team page signed in as the
  master of the project on screen claims every unclaimed project in the ferry root for
  that person - the human, never the machine - and lists each one it took. A person
  who is not yet master anywhere gets a button for the same thing. Neither turns on
  required grants in bulk: switching thirty projects to grants-required at once would
  stop every agent working in them.

## v0.5.12 - 2026-09-23

Your machines are you, a git account is proof of whose projects these are, and a
finished project can be put away without being thrown away.

### Added

- **A master claims their git account, and every project that account owns gets it**
  (ADR 0022). `ferry team anchor claim` binds the master's Ferryman key to a GitHub
  account by signing with an SSH *signing* key published on that account - one that
  grants no access to anything, only proves the account is yours. Claim once and every
  project whose remote that account owns is anchored; nobody else can become master of
  them without controlling the account. One identity can hold several accounts.

  Required for projects on git, optional off it. The agent loop and the dashboard
  re-check at irregular 3-11 day intervals, jittered from the machine's own name so a
  fleet does not hit the provider in step. When an anchor stops verifying the master is
  **paused, never vacated**: after 72 hours of contradiction a paused master directs no
  new work, and the fleet finishes what it already holds. A sale of the account is a new
  owner, and a new owner claims for themselves.

  Verification reads `api.github.com/users/<login>/ssh_signing_keys`, not
  `github.com/<login>.keys` - the second lists *authentication* keys, which grant push,
  and a proof key must be one that grants nothing.

- **`ferry root archive`: finished is a state, not a deletion.** Between `adopt` and
  `forget` there was nothing for a project that is simply over. Archiving keeps the
  channel, its signed history, and its sync; it only stops the project being offered as
  somewhere work happens, and drops it from the anchor spread. `--restore` takes it back.
  `ferry root show` always says how many it is hiding; `--all` shows them.

- **`ferry root forget`, and `--gone`.** The index could be added to and never
  subtracted from, and the gap did not show: `show` hides an entry whose channel has
  gone, so a dead entry vanished from every listing while staying in the file forever.
  `forget` touches the manifest and nothing on disk. `--gone` clears every unreachable
  entry, and prints where each one pointed so a dead test run can be told from a project
  you are about to stop tracking.

- **`docs/FERRYMAN_IN_EVERY_PROJECT.md`**: the page a project reads to *stay* on
  Ferryman. The eight ways a project gets stranded, what each looks like, and the command
  that fixes it - every command run against the binary before being written down.

- **A second machine can join as you, rather than as a stranger.**
  `ferry team invite create --as-identity josh --machine beastly` invites one of your
  own machines onto a project you are already on. It joins as `josh-beastly` and
  inherits exactly what `josh` can do - no more, and nothing the master has to approve.
  Until now every invitation needed the master's signature and produced a separate
  member, so a person with two laptops was two people on the roster with two grants to
  keep in step, and revoking them was two jobs, one of which was easy to forget.

  The inheritance is a signed file of its own, `owners/<agent>.json`, sitting beside the
  grants: a statement by an established identity that a named key is one of their
  machines. It confers nothing by itself. `is_granted` resolves a machine to its owner
  and answers with the owner's grant, so revoking the person takes every machine of
  theirs dark in the same moment - the answer was never stored on the machine.

  The claim is signed by the owner, not by the master, because it is a claim about your
  own keys. That is worth exactly what your own access is worth: creating one of these
  invitations refuses anyone who does not already hold a live grant here, since every
  invitation lets a device into the synced folder and a name that was merely reserved is
  not a member. The claim binds the machine's public key, so a name that is ever re-keyed
  stops resolving to anybody. A machine cannot claim itself, an owner cannot be owned,
  and the file being writable by anyone with the folder buys nothing: only a signature by
  the identity being claimed *as* counts.

  The machine finishes joining with `ferry team pending --as josh` on the machine holding
  josh's key, or from the dashboard while signed in as josh. The agent loop reports the
  wait rather than signing it, because it holds a machine's key and not a person's.

  The `owner` field on an invitation is appended to the signed payload only when it is
  set, so every invitation written before this release still verifies over exactly the
  bytes it was signed over.

- **A machine or an agent can be killed from any machine you own.** `ferry team revoke
  --name josh-beastly` used to be the master's command and nobody else's. Now the master
  still ends anyone on the project, and everybody else ends their own machines and agents
  - signed by the owner, or by any *other* machine of the same owner. That last one is
  the case that matters: a kill switch you can only reach from the machine you are trying
  to kill is not a kill switch. The laptop still on your desk ends the one that left in a
  taxi, with no master involved and without your operator key having to be on the machine
  doing it.

  A sibling can end a sibling and nothing else - it cannot grant, cannot claim, cannot
  speak for its owner anywhere. The worst a stolen laptop does with this is switch your
  other laptops off, which you undo by claiming them again; the alternative was a stolen
  laptop that kept working because you were not sitting at the right desk. It cannot
  revoke itself, so it cannot cover its tracks. Re-claiming a machine clears a revocation
  a sibling or the owner signed, and never one the master signed.

  It is a signed tombstone at `owners/<agent>.revoked.json`, not a deleted file: on a
  synced folder a delete wins on one machine and then loses an argument with the next
  replica that still had the file. Entitlement is checked when the revocation is read,
  not when it is written, so writing one by hand into the folder achieves nothing.

### Fixed

- **`ferry doctor` told a stale machine the fleet was level.** The `versions` check
  listed machines behind *this* one and never said this one was behind, reasoning in its
  own comment that the stale machine "is never the one you are sitting at". It is, and
  the check reassured precisely the machine that needed telling: grouchly sat on 0.5.10
  beside 0.5.11 being told nothing was wrong. It now reports both directions and leads
  with *"this machine 0.5.10 is BEHIND the fleet's 0.5.11 - run 'ferry update' here"*,
  because that is the half you can act on without leaving the chair.

- **Pinned public keys no longer share a name with private ones.** The trust-on-first-use
  pin store wrote `agents-pinned/<name>.key`; the private key store next door is
  `keys/<name>.key`. Same extension, and both files exactly 64 bytes, because a
  hex-encoded 32-byte key is 64 characters whichever half it is. A careful reader with the
  source open still took the pins for private keys. Pins are `<name>.pub` now. The old
  name is read when the new one is absent and carried across, because a rename that
  stopped finding the old pins would re-run trust-on-first-use against whatever the
  channel says at that moment - the one moment a pin exists to distrust.

### Security

- **RUSTSEC-2026-0285 in `rustls`.** TLS 1.3 handshake messages were accepted across
  encryption-level boundaries. 0.23.42 to 0.23.45, with `rustls-webpki` 0.103.13 to
  0.103.15. A patch bump inside 0.23; nothing else in the lockfile moved.

## v0.5.11 - 2026-09-14

Beta. Sync that said it was healthy while nothing moved, and licences that verify
with nothing to phone home to.

### Fixed

- **`ferry enable` no longer breaks sync by moving a folder in silence.** Syncthing's
  config POST replaces a folder carrying the same id, its path included, so registering
  blind re-pointed a `<project>-ferryman` folder that already existed at another path
  and said nothing about it. Worse, Syncthing writes the `.stfolder` marker when it
  *creates* a folder root and never when it updates one, so the moved folder landed on a
  directory with no marker and Syncthing then refused to touch it in either direction -
  "folder marker missing" - forever, silently. Registration now reads the folder id
  first: unchanged path, it only widens the share list; different path, it moves the
  folder deliberately and reports where it came from (`moved_from`, printed as
  `moved from <path> - that path no longer syncs`). This is why `ferry channel syncthing
  off` then `on` was the only thing that fixed it: the delete made the next
  registration a genuine creation.
- **Ferryman writes the Syncthing folder marker itself.** `.stfolder` is created
  alongside the channel directory rather than left to Syncthing, so the missing-marker
  failure cannot happen whichever way Syncthing treats the registration.
- **`ferry doctor` stops reporting a dead folder as ready.** The `syncthing` check only
  asked whether the daemon answered and counted paired devices, which is why it said
  healthy while nothing had synced in either direction. A new `syncthing_folder` check
  reads `/rest/db/status` for this project's folder and fails on any state that is not
  `idle`, `scanning` or `syncing`, quoting Syncthing's own error.

- **`ferry channel syncthing on` no longer unshares the folder it is repairing.** It
  called `syncthing_register_folder(&route, &[])` - an empty share list - so the command
  people reach for to fix a folder silently dropped every device it was reaching. It now
  goes through `syncthing_share_folder`, which reads the current device list first and
  adds to it. Found by causing it: repairing two folders on a live machine took them
  from two devices to one, and nothing said so.
- **The test suite no longer rewrites the operator's real ferry manifest.** Tests run
  `ferry enable` in temporary workspaces; `enable` found the machine's real ferry root
  and filed the temporary project into it. Because filing merges by project id, a
  scratch project sharing a name with a real one overwrote the real one's channel path
  with a directory that was deleted seconds later - four live projects on one machine
  went that way in an afternoon. `Root::adopt` now refuses to file a channel under the
  machine's temporary directory into a root that is not itself temporary, and returns
  whether it filed rather than reporting success either way. A temporary root filing its
  own temporary channels is untouched, which is what every test fixture does, so no test
  had to opt in and none can forget to.
- **`ferry root gather`** moves scattered channels into the root's `comms/`, one place
  for every channel. `--dry-run` says what would move. Only the channel directory moves:
  keys and config stay in the project, because keys must never enter the directory
  Syncthing carries. Peers are unaffected - a Syncthing folder's path is local to each
  machine and devices match on the folder id - and the share list is preserved.
- **A channel may live outside its project.** `validate` required `communications` to be
  exactly `<attachment>/ferryman`, which made a shared comms root impossible. What that
  rule was really protecting is now what it says: the channel may be anywhere outside the
  workspace, and never anywhere inside it, because a channel inside the workspace would
  put the work itself into the synced folder.

### Security

- **CVE-2026-48504 in `opentelemetry_sdk`.** `BaggagePropagator::extract_with_context`
  parsed an inbound W3C baggage header before applying the size limits, so an oversized
  header bought more CPU and allocation than it should have. Moderate, availability only,
  and not reachable from anything Ferryman does - nothing here accepts inbound
  propagation headers, the OTLP integration only exports - but the fix is free. The whole
  OpenTelemetry set moves to 0.32 together, which `tracing-opentelemetry` 0.33 finally
  allows; the partial bump Dependabot proposed does not compile, and the manifest says so
  where the next person will look. Both lockfiles, the workspace's and the tray's.
- **`chacha20` 0.10.1 was yanked.** Moved to 0.10.2. It is the cipher under the sealed
  licensor key, so it is not a dependency to leave on a version the registry has
  withdrawn.
- **`reqwest` stays at 0.12 on purpose.** 0.13 builds, but its `rustls` feature swaps
  `ring` for `aws-lc-rs`, and `aws-lc-sys` wants cmake and a C toolchain - a hard stop on
  exactly the unattended machine an agent is asked to install this on. The OTLP exporter
  pulls a 0.13 of its own regardless; one duplicate crate is cheaper than a native build
  dependency.

### Added

- **Licences that verify with no server.** An entitlement is a small signed document:
  subject, seat and device allowances, an issue date, an optional build cutoff, and an
  ed25519 signature over the payload. The licensor's public key is compiled into the
  binary; `ferry license status` reads the installed entitlement and verifies it locally.
  Nothing phones home, and there is nothing to phone.
- **Expiry is measured against the build, not the clock.** `build.rs` stamps the git
  committer date into the binary, and an entitlement that covers builds before a date
  covers every binary built before it, forever. Setting the system clock back gains
  nothing, because the clock is never consulted; a licence that stops at a date simply
  stops covering newer builds, and the copy already installed keeps working.
- **`ferry license keygen` / `issue` / `install`.** The licensor key is sealed at rest
  with PBKDF2-SHA256 at 600,000 iterations and XChaCha20-Poly1305, and the passphrase is
  typed at the console - it is never an argument, never an environment variable, and
  never written anywhere. `issue` takes `--to`, `--seats`, `--computers`, `--mobile`,
  `--until`, `--note` and `--referred-by`; omitted allowances mean unlimited. Referrals
  are appended to the signed payload only when present, so entitlements issued before
  referrals existed still verify byte-for-byte.
- **A licence claim proves the machine holds the licence, not merely a copy of it.** The
  claim is signed by the seed-derived operator key whose public half is the entitlement's
  subject, so pasting someone else's licence into your channel proves nothing to anyone.
- **Seat counts read the licence.** `FleetCount::exceeded_under` uses the entitlement's
  allowances when one is installed and falls back to the free tier when none is.

### Changed

- **`ferry enable` starts the managed Syncthing instead of noting that it is down.**
  Enabling on a machine whose daemon was not running registered nothing and carried on,
  which is a bad first five minutes for someone who just pointed an agent at the repo.
- **Syncthing installs from the project's own releases on Linux.** Rather than guessing
  between apt, dnf, pacman and apk, the static binary for the machine's architecture is
  downloaded and unpacked per-user under the machine state directory. Nothing is
  elevated, and `find_binary` looks there.
- **Setup reads the git identity before it asks for one.** `git config --get user.email`
  is consulted first, so an agent working unattended does not stop on a question the
  machine can already answer.

## v0.5.10 - 2026-09-09

Beta. An invitation no longer names the person; the person names themselves.

### Changed

- **Generic invitations.** The name field on the Teammates tab is optional. An
  invitation made without one carries no name at all; the joiner's Claude asks them
  what name they want, checks it against the channel (`ferry team claim <name>` says
  free, taken, reserved, or not synced yet), and claims it. Until then the joiner is
  `USER` in the prompt and `guest-<invite id>` on the roster; on claim the placeholder
  is renamed `<name>-<host>` and the roster entry for the guest is removed. A named
  invitation still reserves that name for the person it was made for.
- **One invitation pairs one device.** When several devices knock with the same
  handshake, `settle_pending` takes the most recent knock and leaves the others
  pending, so a second machine cannot ride in on a code that was already used.
- **The master's key is on the channel.** Loading Teammates as the master publishes
  the operator's own `agents/<name>.json` to the channel if it is missing there, so
  teammates can verify the master's grants without a manual copy.
- **The joined device is named after the real hostname** (`hostname::get()`), not the
  `COMPUTERNAME` variable, which sandboxed and non-Windows profiles do not set.

### Prompt

- The invitation prompt now tells the joiner which Claude can run it (Claude Code, or
  Claude Desktop with a shell), that the project appears on their disk once the
  inviter is online, and to ask for a name first and claim it before anything else.

## v0.5.9 - 2026-09-09

v0.5.8 built for Windows only: the managed-Syncthing supervisor detached its child with a
raw `setsid`, and `ferryman-ops` forbids unsafe code, so every Linux and macOS target
failed at build. This release is v0.5.8 with that one block replaced by std's
`process_group`, and the same tests, clippy and fmt run on Linux as well as Windows.

## v0.5.8 - 2026-09-09

Beta. Bringing a person onto a channel is one code and one prompt; the doctor tells
the truth about Syncthing; the master is a person.

From bringing one non-developer onto a channel and finding out what the tool made
them do by hand. The findings and their order are in `_launch/ONBOARDING_ABC_REVIEW.md`
(scratch); this is the first batch.

### Fixed

- **`ferry doctor` told the truth about the wrong Syncthing.** Ferryman can run its own
  Syncthing (`%LOCALAPPDATA%\SyncthingFerry`), and nothing in the code knew that: the
  config lookup read the person's own `Syncthing\config.xml`, the API base was
  hard-coded to 8384, and "no key found" and "process not answering" both came back as
  an empty peer list. Doctor said `ok syncthing reachable; 0 device(s) paired` against
  a managed instance carrying four live devices, and said the same when it was not
  running at all. Now the managed instance is looked for first, address and key always
  come from the same `config.xml`, and each failure names itself.

### Added

- **`ferry syncthing start | stop | status`** supervises the managed instance: `start`
  creates its home on first use and waits for the API; `stop` goes through Syncthing's
  own shutdown and refuses to touch a Syncthing that is not Ferryman's; `status` shows
  which config is read and every device with its live connected state. `ferry doctor
  --fix` starts it when it is configured but down, and the worker loop does the same
  between passes. Doctor reports paired, connected, and how many devices this folder
  is shared with.
- **Secrets in one line on both ends.** `ferry channel secret get NAME --env` prints
  `NAME=value`, so `>> .env` writes a line tools can read (`--key` to rename).
  `ferry channel secret set NAME --from-env [KEY] [--env-file F]` reads the value out
  of a `.env` line without it touching argv, a pipe, or a temporary file. Sealing to a
  name that is reserved but has not joined yet says exactly that.
- **Invitations: one code from the master, one line for the newcomer.** `ferry team
  invite create --name david --agent david-agent` (or Teammates -> *Make the code*)
  reserves the names, writes a signed record, and prints a code plus the one line to
  send. On the new machine `ferry team invite accept <code>` - or the `join.ps1` /
  `join.sh` one-liner, which installs ferry first - starts the managed Syncthing
  (installing it with winget or brew when absent), names the device after the invite,
  trusts the inviter, enables the project under the right folder id shared with the
  inviter's device, creates the operator, and writes a signed acceptance. The inviter's
  ferry - the worker loop, or the dashboard while open - sees the device knocking under
  the invite's name, trusts it and shares the folder; when the keys and acceptance sync
  back, the dashboard signs the grant the invite promised. Nobody sees a device id.
- **The master is a person.** The dashboard offers *I am the master of this project*
  whenever no master exists, signed with the session's already-unlocked operator key -
  no password typed twice - and flips grants to required. When `ferry enable` creates
  an operator on a machine whose agent was just declared master implicitly, the role is
  transferred to the person, signed by the agent, so the chain reads "declared, then
  disclaimed".
- **A first machine is the master.** `ferry enable` declares the master implicitly when
  no declaration exists and either nobody else is on the roster or this machine is the
  only orchestrator. `--master` stays for every other case. Doctor now reports the
  master, or that there is none.
- **Inviting a second person makes grants required.** The dashboard's invite flips
  `grants = "required"` in `bridge.toml` and records it in the ledger. Doctor warns when
  grants are open and more than one operator is on the roster.
- **Version skew is visible.** Each machine's record in the channel carries the
  Ferryman version it last ran (stamped by `ferry enable`, `ferry license register`,
  and the worker loop on start). The Fleet page shows it with a *behind* badge, and
  doctor lists machines older than this one with the `ferry update` line.

## v0.5.7 - 2026-09-02

Setup you double-click, an API spec that cannot drift, and the first release
signed with SSH.

### Added

- **Setup is a file you double-click.** `Ferryman-Setup.cmd` and
  `Ferryman-Setup.command`, attached to every release. They install Ferryman, ask for
  an email and a folder, enable the project and open the dashboard — after which it is
  a web page. The install instructions were `curl … | sh` and `irm … | iex`, and both
  are command lines, which is the one thing this tool tells its users they will not
  need. A `.ps1` cannot even be double-clicked; Windows opens it in Notepad.
- **`ferry dashboard` opens the browser** rather than printing an address and hoping,
  and `ferry enable` now ends by pointing at it instead of asking for two more
  commands. `--no-open` for headless machines.
- **A person can decline a release**, signed, with a reason — and declining is never
  disabled by red tests or staleness, because those refuse a release and must not
  refuse a person's refusal.
- **Teammates can be invited, with per-project access levels.** Inviting reserves the
  *name*: an operator key is sealed under that person's own password, so a key minted
  here would be a key this machine has seen.
- **Engine cost is measured.** `Learning` now carries token counts read from the result
  in whatever shape the engine reported (OpenAI's, Anthropic's, or flat). Optional
  rather than zero — silence is not a free run.
- **`ferry channel submit --result-file`**, for the same reason `--task-file` exists.
  It carries the largest payload in the channel and was the one command without it.
- **`scripts/uninstall.sh` and `.ps1`.** They keep your operator identity unless you
  pass `--identity`, never touch channels, and support `--dry-run`.
- **The whole API is documented**, and a test fails if a route is added without a spec
  entry. It described 11 of 31 endpoints.

### Fixed

- **A lost identity no longer reads as a first run.** The dashboard answered "does an
  operator exist" from one machine's disk and offered a setup token — so an operator
  whose sealed key had been deleted was told they had never set one up, while their
  signatures were still verifying in the channel. It asks the channel now, names who is
  missing, and defaults to recovery.
- **Recovering a published name needs no console token.** The phrase must derive that
  exact published key, which only its owner can do — a stronger claim than a secret
  printed in a terminal window the person may never have seen.
- **An old approval hid the button for approving the new one.** The release page matched
  approvals by version alone, so an approval of one commit made it render as settled for
  a different commit the gate was refusing. Page and gate now both come from `may_sign`.
- **Your operator key is kept in two places.** It lived only in `%LOCALAPPDATA%` (or
  `~/.local/state`), where every disk cleaner points; one deleted the whole directory
  overnight. A second sealed copy lives in `~/.ferryman/operators`, and signing in puts
  the primary back if it has gone.
- **Two machines sharing a hostname got a frightening error.** The refusal named
  impersonation first; it now names the ordinary cause — two VMs from one image — and
  gives the fix.
- **Errors print a sentence, not a stack trace.** `FERRYMAN_BACKTRACE=1` brings it back
  for whoever is fixing ferry rather than using it.

### Notes

Releases are signed with SSH from this version on. v0.5.6 and earlier are GPG-signed.


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
