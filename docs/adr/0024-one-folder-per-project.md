# ADR 0024: One folder per project

Status: proposed, for the master (josh). Builds on 0014, 0017, 0019, 0021 and 0023. Replaces
the root layout in 0019 and the hand-in location in 0023 (section 1). Related to
docs/IROH_LANE.md and docs/LAYOUT.md.

## Context

Josh wants to hand any LLM one project folder and have it see that project and nothing else.
The root as it stood could not do that. It had `comms/`, `repos/` and `work/` at the top, with
every project's files spread across the three, so "the folder for quantly" did not exist. Three
more things were loose at the root of the drive: the worker's `service/`, `bin/` and `tmp/`.

Three other problems had the same root.

- **Access.** Every agent could write the channel and read every credential on the machine.
  A machine that only needs to do work and hand it in had no way to be less than a full member.
- **Transport.** The fleet is moving from Syncthing to iroh (docs/IROH_LANE.md). The layout
  must not be a Syncthing layout with iroh bolted on. Syncthing stays as the fallback.
- **Other people's folders.** A person who already organises a project their own way, with a
  channel on another drive or a repository they keep elsewhere, must not be forced into ours.

## Decision

### 1. The layout

```text
ferry/
  projects/<id>/
    repo/      Ferryman's own clone. Machine-local, never synced.
    comms/     the channel. Synced. Same channel and Syncthing folder id as before.
    handins/   hand-ins, and everything else a worker-level agent writes. Synced.
    work/      task worktrees. Machine-local.
    tmp/       scratch. Machine-local.
    .env       this project's keys only. Never synced.
  secrets/     write credentials and fleet-wide keys. Never synced. Orchestrator only.
  logs/
  .ferry       the manifest
```

No project's files sit at the root. Machine-level folders from before (`service/`, `bin/`,
`autoenable/`) belong to the machine, not to a project. They stay where they are and
`doctor` does not call them wrong; moving them is a separate change.

The manifest's `version` is the layout version: 2 for this, 0 or 1 for `comms/ repos/ work/`.
A version-1 root keeps working exactly as before. Nothing is converted behind anyone's back:
`ferry root migrate` does it, on request.

### 2. The layout is a default, never a rule

The layout is what Ferryman does when nobody decides. A user who decides is respected.

- Each manifest entry records where its channel, repository, hand-ins, `.env` and worktrees
  are, and `placement`: `managed` (the layout's places) or `custom` (a person's).
- `ferry enable --channel P --repo P --handins P --env P` records a custom project. Without
  them a project in a version-2 root goes to `projects/<id>/`.
- A project adopted from outside the root is custom. An existing manifest without a
  `placement` is read that way: custom if its paths are not the layout's.
- Nothing in the code builds a project path from `projects/<id>` when an entry records one.
  Every caller asks the entry. `migrate` never moves a custom project or a human checkout
  (ADR 0019 stands). `doctor` does not fail a custom project: it checks that the paths it
  recorded exist, and that is all.

The one rule that holds anywhere is the safety one. A secrets folder or an `.env` may not be
inside a folder that is synced, and a synced folder may not be the root, `projects/<id>`
itself, a `repo/`, `work/`, `tmp/`, `secrets/` or `service/`. That is checked by path against
the recorded places, so it holds for custom placements too.

### 3. Hand-ins get a folder of their own

ADR 0023 put hand-ins inside the channel (`comms/<id>-ferryman/handins/`), because `<id>-work`
had put worktrees in a shared folder. That fixed the leak and left a second problem: the only
place a worker could write was the place everyone reads, so a worker could never be kept out
of the channel.

In version 2 hand-ins live in `projects/<id>/handins/` (or the entry's recorded path), a
second synced folder with the channel's peers. Everything a worker-level agent writes goes
to `handins/<agent>/`: its hand-ins, its order claims and heartbeats, its status and replies,
and its iroh transports record. Only that agent writes its own subfolder. Only the head writes
`accepted.json` and `rejected.json` beside a hand-in. Channel readers (the worker loop, the
head, the dashboard, doctor) read the signed files in `handins/<agent>/` as if they were in
the channel for that agent. A project in a version-1 root, or one with its hand-ins recorded
inside the channel, behaves as before.

Under iroh the lane syncs `handins/` per project beside `comms/`, on the same trust rules
(roster-signed transports) and the same safety rules (`.stignore`, no deletes, no `..`, no
symlinks, size caps). Under Syncthing it is a folder `<id>-handins` shared with the
channel's devices.

### 4. Access levels are signed grants, enforced by the receiver

| Level | Reads the channel | Writes the channel | Clone and git | Credentials |
|---|---|---|---|---|
| Worker | yes | no; writes `handins/<agent>/` | read PAT from the project `.env` | the project `.env` |
| Member | yes | yes | read PAT from the project `.env` | the project `.env` |
| Orchestrator | yes | yes | as Member | the project `.env`, and `secrets/` |

- The level is a grant the project's master signs into `access/<agent>.json` in the channel.
  It is not a local setting: a machine that wants more access cannot give it to itself, and a
  forged or edited grant fails its signature. A grant has a sequence number, and a machine
  never accepts an older one than it has seen.
- With no Worker in the project an agent with no grant is a Member (existing fleets change
  nothing). The master and the named head are Orchestrators. The roster is unsigned and is
  trusted on first use, so being on it admits nobody: once the project has a Worker grant,
  a roster name the master has not admitted (a signed grant in `access/` or `grants/`) is a
  Worker too. A Worker that registers a fresh name and key therefore gains nothing. Setting
  the first Worker admits every agent already on the roster as a signed Member in the same
  step, so nobody is demoted by it. The master signs the admission; the head can read it,
  not issue it.
- A name that registers after the first Worker was set is **not** admitted automatically, on
  any later `access set` or otherwise: a Worker registering a fresh key is exactly the case
  this guards, and an automatic admission would hand it Member. It waits as a Worker until
  the master looks at the list and admits it: `ferry access admit <project>` lists who is
  waiting, `ferry access admit <project> NAME...` or `--all` signs them in as Members.
  `ferry access show` and `ferry doctor` (the `admission` line) say who is waiting.
- A Worker's writes to `agents/` and `devices/` (its own roster entry and device records) are
  refused by the receiver like its other channel files; a file in `grants/` or `access/`
  signed by a Worker is refused, and one signed by anyone else has to verify as the master's
  to count.
- A Worker's channel writes are refused by the machine that **receives** them: every peer's
  iroh lane and every reader of the channel refuses a channel file authored by a worker-level
  agent, whether the file is signed or not. Its writes are accepted only from
  `handins/<agent>/`. A compromised Worker machine can write whatever it likes to its own
  disk; nobody reads it.
- Defence in depth on the Worker's own machine: its iroh lane does not publish the channel,
  and under Syncthing its channel folder is set to `receiveonly` through Ferryman's Syncthing
  REST.
- Credential loading is by path. Worker and Member read the project's `.env` and nothing
  under `secrets/`. Only an Orchestrator reads `secrets/`. Paths are resolved first (symlinks
  followed, `..` applied), so a link or a custom placement cannot lead a lower level in.
- **This isolation is advisory.** Every agent subprocess on a machine runs as the same
  operating-system user as Ferryman and as every other agent there, so a Worker's process
  can read `secrets/` straight from disk, or the environment of its siblings. The levels
  decide what Ferryman loads for an agent and what other machines accept from it. They do
  not sandbox a process that chooses to go around Ferryman. Real isolation needs a separate
  OS user or container per level, which this ADR does not provide; keep a secret that must
  never reach a Worker off any machine a Worker runs on. Where both the scoped store (the
  project `.env`, and `secrets/` for an Orchestrator) and the older credential store name
  the same key, the scoped one wins.
- The levels are enforced only when hand-ins are kept apart from the channel. Where they are
  inside it (a version-1 project), a Worker has nowhere else to write, so the level is
  recorded and shown, and refuses nothing. `ferry access show` says which.

`ferry access set <project> <agent> worker|member|orchestrator` is the master's command.
`ferry access show [--project P]` lists the levels.

### 5. Git for a Worker

A Worker's default is a repository-scoped read token from the project `.env`. The other
option is no git at all, with the order carrying a git bundle. That option is described here
and not built; see Follow-ups.

### 6. Migration

`ferry root migrate` moves a version-1 root to version 2, a project at a time. It is a dry
run until `--apply`, and the dry run writes nothing. It refuses a project that has a running
worker, a live worker lock or a live worktree, and says what blocks it. It never deletes: what
a move supersedes goes to `<root>/_to_delete/`. It writes `<root>/logs/migrate-<UTC>.md`. It is
idempotent. The manifest becomes version 2 only when every managed project has moved.

A project is judged on its own, not by the root's version, which stays 1 until the last
project moves: the managed clone, worktrees and folders of a project that moved are found
where its manifest entry says, so `repos sync` and `doctor --fix` never re-clone it. A
worktree is *live* (and blocks the project) only when a running order's heartbeat on this
machine names it; any other registered worktree is stale, listed as "would prune", and moved
to `_to_delete` only with `--prune-stale-worktrees`.

With Syncthing the order of the steps matters. The channel's folder is paused before
anything moves and stays paused while `handins/` leaves it, `handins` is added to the
channel's `.stignore`, and `<id>-handins` is registered; only then is the folder pointed at its
new path and resumed. Resuming earlier would announce the hand-ins as deleted to a peer that
has not migrated. The channel's new place is written to the manifest and the bridges right
after it moves, Syncthing is resumed on every way out, and a rerun that finds the channel at
`comms/` with the manifest still naming the old place finishes the record. Hand-ins are read
from `handins/` in the project folder and, while any are left there, from the old
`<channel>/handins`. The iroh lane keeps `handins/` out of the channel share in a layout-2
project, so an unmigrated peer cannot re-create it there.

A marker, `projects/<id>/.migrating`, is written before the first step and removed after the
last, and records whether the person had the folder paused. A rerun after a failure at any
point finishes whatever it stands for (ignoring `handins`, registering `<id>-handins`,
re-pointing Syncthing) even when there were no hand-ins, and gives the folder back paused if
it was paused. If Syncthing cannot be pointed at the new place, the folder is resumed at its
old path only when the old path still holds the channel; otherwise it stays paused and the
report says what path to set. A failed step makes the project Failed and the manifest stays
at version 1.

`--prune-stale-worktrees` moves only worktrees under `work/` or `projects/<id>/work` that
nothing uses, have no uncommitted changes and no commit that is on no remote. It skips adopted
projects, lists in the plan exactly what it will move (and the reason for each it will not),
and also works on projects that moved earlier. A worktree somebody made elsewhere is never
touched; after the clone moves, `git worktree repair` from it reconnects it.

### 7. A mixed fleet

The channel of a migrated machine no longer carries `handins/`: it is in `.stignore` and kept
out of the iroh share. A peer that has not migrated writes its hand-ins to the old place, so
they never reach a migrated machine, and nothing else fails to tell anyone. There is no bridge
between the two layouts. The order is: **migrate every machine in the same window, with the
workers stopped.** To make a gap visible, each worker's presence record carries the layout it
keeps the channel in (`layout`, outside the signed fields so older machines still verify the
record). `ferry root migrate` names the peers that still report the old layout in the plan,
and `ferry doctor` (the `layout_peers` line) says, per peer, "peer X has not migrated; its
hand-ins are not received". A peer from before this field counts as not migrated.

## Consequences

- One folder per project can be handed to an LLM. A custom project can be handed over by its
  recorded paths instead.
- An agent can be given a role that cannot damage the channel. The cost is two synced folders
  per project, and readers that merge them. That merge is one function per kind of file
  (`access::overlay_dirs`), not a spread of special cases.
- Version-1 roots keep working, and mixed fleets work: an older peer refuses the
  `<id>+handins` share it does not know and the rest syncs as before.
- A migration moves a Syncthing folder's path on each machine separately. Peers match on the
  folder id, so nothing re-pairs. The folder is held paused and `handins` ignored before the
  hand-ins leave it (see Migration), so a machine that has not migrated does not see them
  deleted. Its own hand-ins are not carried to a migrated peer through the channel; they
  reach it once that machine migrates too, so migrate the fleet together.
- `accepted.json` and `rejected.json` are signed by the head or the master over the order,
  the patch digest and the verdict, and `ferry work list` does not count one that is
  unsigned, signed by someone without standing, or for another patch. Syncthing cannot filter
  by author, so the check is on read, not on the wire; over iroh they are also accepted only
  from the head or the master. A signer has standing if it is the master, the head now, or
  held the head appointment when it gave the verdict (`head/` keeps past appointments), so a
  verdict survives the head role being passed on. (A head who steps down, or whose
  appointment is revoked, has its appointment file removed; its earlier verdicts then read
  as unverified.)
- A verdict file that is there but cannot be verified is **unverified**, not waiting: the
  old unsigned `accepted.json` and `rejected.json` that v0.5.30 wrote, a forged one, or one
  from a signer without standing. `accept` and `reject` refuse such a hand-in without
  `--force` (an old accepted one applied again would apply twice, and an old rejected one
  would be applied by mistake), and `ferry work list` shows `unverified`. Once, after
  reading the list, the master or head runs `ferry work adopt-verdicts` (a listing) and
  `ferry work adopt-verdicts --yes` to sign the old ones as their own, keeping what they said
  and when.

## Follow-ups

- Worker git by bundle: an order that carries a signed git bundle so a Worker needs no
  repository credential at all.
- Anti-replay memory is keyed by project id plus the channel's identity (its master's
  declaration), so a project re-created under the same name starts fresh and a moved channel
  does not forget.
- Sign claims and heartbeats. Today a Worker-originated claim or heartbeat is accepted only
  from `handins/<agent>/`, bound to the folder it sits in and to the agent field inside it.
- An Orchestrator (not only the master) signing an admission.
- A non-head peer relaying the head's verdicts is not accepted over iroh. The mesh is full
  today, so nothing is lost.
- A master-only control for levels on the dashboard's Teammates page.
