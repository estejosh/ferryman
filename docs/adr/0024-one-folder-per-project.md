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
- With no grant an agent is a Member (existing fleets change nothing). The master and the
  named head are Orchestrators.
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

## Consequences

- One folder per project can be handed to an LLM. A custom project can be handed over by its
  recorded paths instead.
- An agent can be given a role that cannot damage the channel. The cost is two synced folders
  per project, and readers that merge them. That merge is one function per kind of file
  (`access::overlay_dirs`), not a spread of special cases.
- Version-1 roots keep working, and mixed fleets work: an older peer refuses the
  `<id>+handins` share it does not know and the rest syncs as before.
- A migration moves a Syncthing folder's path on each machine separately. Peers match on the
  folder id, so nothing re-pairs, but a machine that has not migrated yet will see
  `handins/` leave its channel folder when its neighbour moves it. Migrate the fleet together,
  or pause the folder first.
- `accepted.json` and `rejected.json` are accepted over iroh only from the head or the
  master. They are not yet signed, so under Syncthing the head's folder is trusted as before.

## Follow-ups

- Worker git by bundle: an order that carries a signed git bundle so a Worker needs no
  repository credential at all.
- Sign `accepted.json` and `rejected.json`.
- A non-head peer relaying the head's verdicts is not accepted over iroh. The mesh is full
  today, so nothing is lost.
- A master-only control for levels on the dashboard's Teammates page.
