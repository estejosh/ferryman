# ADR 0026: A home for the fleet

Status: proposed, for the master (josh). Builds on 0014, 0019, 0021, 0023 and 0024. Related to
docs/LAYOUT.md, docs/FLEET_SETUP.md and docs/IROH_LANE.md.

## Context

Everything Ferryman syncs belongs to a project, and some things do not. Where each machine keeps
each project. Which version each machine runs. That the root moved on one machine and a worker on
another is still looking at the old paths. That a release is out. Those are true of the fleet,
and today they live nowhere, or in the wrong place:

- Release requests and approvals sit in the `ferryman` project's channel, because that was the
  nearest channel. A release is not that project's business alone.
- Two files sit loose in `comms/` that are not any project's: `agents-pinned/` and `runtime/`.
- Paths are written into scripts, session notes and people's heads. The v0.6.0 move to one folder
  per project broke every one of them, and the next move will break them again.

What is wanted is one place, separate from every project, that holds the fleet's shared truth, so a
move or a migration is one update and nothing has to hardcode a path.

## Decision

### 1. One more channel, and it is not a project

`<root>/fleet/` is a synced channel with the Syncthing folder id `fleet-ferryman`. The iroh lane
carries it like any other channel. It is not filed in the manifest, so no worker serves it as a
project and `repos sync` never tries to clone it.

```text
fleet/
  master.json, agents/, grants/     the folder's own trust (section 2)
  directory/<project>/<machine>.json            where a machine keeps a project; the machine signs it
  directory/<project>/<machine>.override.json   the same, signed by the master; it wins
  machines/<machine>.json           version, layout, root, OS, engines, projects served, last seen
  notices/<id>.json                 fleet-wide announcements
  orders/<id>.json                  fleet-wide orders, in the ordinary order format
  releases/                         release requests, approvals and denials
  librarian/README.md               a placeholder
  local/                            this machine's own part; never synced
```

The name is close to an older channel, the licensing fleet channel (`ferryman-fleet`, in the
machine state directory, carrying device records). They are different folders with different ids
and different contents. This one is the root's, and it is about where things are.

### 2. What counts

Nothing in the folder counts because it is there. A file counts when it is signed, its signature
verifies against the key the folder's roster pins, and its signer has standing for what it says.

- **The master** (declared in `fleet/master.json`, as for any channel) has standing for anything.
- **A machine** has standing for its own entries only: the directory entries and machine record
  filed under its own machine name, and a `layout-change` or `migration` notice about itself. The
  master gives a machine that standing by signing a grant that names `machine:<name>`
  (`ferry fleet admit`). Being on the roster, which anyone can arrange, gives none.
- **A Worker-level agent** (ADR 0024) has none, whatever else it holds. It never writes the fleet
  folder. The writer refuses, the readers ignore anything it signed, and the iroh lane's existing
  refusal of Worker-authored channel files applies here as it does to a project.

Anything else is ignored by every reader. The readers say what they ignored, and `ferry doctor
--layout` reports it, so a forged or unsigned entry is a line in a report and not a silent hole.

The file's kind and name are inside the signature, so a valid file cannot be copied under another
machine's name.

### 3. The directory is many small files, not one map

A single `directory.json` mapping projects to machines to paths would have two writers per file,
which breaks the rule the whole channel follows (one writer per path). So each machine writes only
its own `directory/<project>/<machine>.json`, and the master can write a
`<machine>.override.json` beside it. A reader takes the master's override if there is one, else
the machine's own entry. An entry records the machine's root, `managed` or `custom` placement,
the layout version, whether the project is live or archived, and the paths: code, channel,
hand-ins, data, env, work, and the person's own checkouts (for information only).

A path in the directory is text another machine wrote. It is checked and handed back; nothing here
opens it, runs it or joins another path to it. A path with `..`, a control character, a UNC or
device prefix (`\\server`, `//x`, `\\?\`), a drive-relative form (`C:x`), an alternate data
stream, a character Windows forbids, or a reserved device name is refused, and the entry that
carried it is ignored and reported.

No secret is in the folder. A project's `.env` is recorded as a path, and nothing of its contents.

### 4. `ferry where`

`ferry where <project> [--machine M] [--json] [--kind code|channel|handins|data|env]` prints one
path and nothing else, from any folder, so a script can use it. `--all` lists every project on every
machine. `--json` gives every place, where the answer came from and who signed it.

For this machine the answer is read from the root's own manifest, then from the directory. That is
the reverse of "directory first", and deliberate: the manifest is what is actually on this
disk, and it is correct the instant a migrate finishes, before anything has been published and
before any peer has synced. The directory is the answer for every other machine, and for this one
when the project is not in the manifest. Rows from the manifest say `manifest`; rows from the
directory say `directory` or `override`.

### 5. Data

Each project gets a `data/` place, `projects/<id>/data` by default, for a database, a model or a
dataset. It is machine-local, and it is never synced:

- the Syncthing guard refuses it, and refuses any folder that holds it or lies inside it, wherever
  it is recorded;
- the iroh lane keeps it out of a share it sits in, and exchanges nothing at all if it is the share;
- `ferry enable --data PATH` and `ferry root data <project> PATH` record a different place, and
  refuse one inside or around a synced folder;
- `ferry doctor --layout` checks the same, and `--fix` makes the default folder.

Layout 2's own rule already kept `projects/<id>/data` out of Syncthing, because only `comms` and
`handins` may be shared there. The new guards are for places a person chose.

### 6. Publishing

Every worker publishes its own machine record and directory entries when it starts and on each
pass (a file that already says the same is left alone, and `last_seen` is refreshed every ten
minutes). `ferry enable`, `ferry root adopt`, `ferry root data` and `ferry root migrate --apply`
publish straight away. `ferry root migrate --apply` updates the directory first and then posts a
signed `layout-change` notice that lists every old and new path, so a reader who sees the notice
finds the entry already agreeing with it.

A machine that has not been admitted is told so, once, and carries on. The fleet folder is
additive: no project waits on it.

### 7. Notices and orders

A notice has a kind (`layout-change`, `deprecation`, `update-available`, `migration`, `general`), a
severity (`info`, `warning`, `high`), a title, a text, and an optional expiry. `ferry fleet
notices` and the dashboard's Fleet page show them. A worker says each unread high-severity notice
once. A worker that sees a newer release in an `update-available` notice says so, and says whether
this machine updates by itself. It does not install anything because a notice said to; it follows
the update policy that already exists (`FERRYMAN_NO_AUTO_UPDATE`).

A fleet order is an ordinary order (same format, same signature) in `fleet/orders/`, addressed to a
machine or to all. A worker acts on one only if it is signed by the master and issued in the
master's name. The actions are `update`, `migrate` and `restart-worker`. `restart-worker` makes
the worker stop between passes, as an update already does, so its supervisor starts it again.
`update` installs the newest release unless this machine has auto-update turned off, in which case
it says so and does nothing. `migrate` is not done by a worker: a migrate refuses a project with a
running worker, and a worker cannot stop itself and then run one. It says what the master ordered
and what to run.

### 8. Releases

Release requests, approvals and denials are written to `fleet/releases/` when the root has a fleet
folder, and read from there and from the project channel's `release/` folder. Where a file of the
same name is in both, the fleet folder's counts. While a fleet still has machines on an older
release, the old place is kept current too, so those machines see the request where they have
always looked. Nothing is deleted from the old place.

### 9. The session hint

`ferry where --session-hint <project>` prints a short, stable block for a CLAUDE.md or AGENTS.md:
where the project lives, where its channel and data are, and "if a path fails, ask `ferry where`;
never hardcode a path". `ferry fleet write-hints` shows what it would write into each clone, and
with `--apply` writes it between `<!-- ferry:where begin -->` and `<!-- ferry:where end -->`. It
adds the block at the end of a file that has no markers, replaces only the text between them in a
file that does, keeps the file's line endings, and refuses a file whose markers are damaged. It
makes CLAUDE.md if it is missing and never makes AGENTS.md. It stages, commits and pushes nothing.

### 10. Old binaries

The fleet folder is a new folder. A binary that does not know it never reads it. Nothing it needs
moved: the project channels, the manifest, the release records (kept in both places while needed)
and `runtime/` are where they were. `agents-pinned/` is mirrored into `fleet/local/` and never
moved: the old copy stays the authority while it holds a pin, and the mirror is only what is left
if it is lost.

## Consequences

- A move or a migration is one update to the directory and one notice. Scripts and agents ask
  `ferry where`.
- A machine that is not admitted can read the fleet folder and cannot write it. Admitting a machine
  is one signed line from the master, and `doctor` names the machines waiting for it.
- The master's key signs every notice and order. A person who loses it cannot post notices; the
  directory and machine records keep working, because machines sign those.
- `runtime/` is not moved. It holds live worker locks, and a lock only excludes a second worker if
  every binary looks in the same place; an old binary and a new one looking in different places
  would each think the other absent. It moves when no old binary is left to be fooled.
- A directory entry can be stale, because it is only as fresh as the machine's last publish. The
  machine record carries `last_seen`, and the dashboard marks a machine quiet after an hour.

## Not built

- The librarian. `fleet/librarian/` is a folder with a README, held for it.
- A worker running `migrate` on its own say-so.
- Moving `runtime/`, as above.
- The master's key held somewhere other than the master's machine. Posting a notice or an order
  needs it.
- An Orchestrator other than the master signing notices, as ADR 0024 also leaves open.
