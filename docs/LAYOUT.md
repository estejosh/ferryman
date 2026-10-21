# The layout

Every machine that runs Ferryman has the same layout under its ferry root. One command puts it there (`ferry fleet setup`), and `ferry doctor --layout` and the watchdog check it and repair what is safe. Nothing depends on a person or an agent remembering a path, because a path an agent has to remember is a path it will eventually get wrong.

**Layout 1 (older roots, still supported):**

```text
<root>/                       X:\ferry   or   /mnt/nvme-storage/ferry
  .ferry                      this machine's manifest (never leaves the machine)
  ferry.toml                  this machine's choices: where to clone from, what to keep out of the swarm
  comms/<project>-ferryman    the channel. The only thing Syncthing shares.
  repos/<project>             Ferryman's own clone of the project. Workers use this and nothing else.
  work/<project>/<order>      task worktrees, made from repos/<project>. Transient.
  service/                    the worker's environment file, wrapper and backups (see FLEET_SETUP.md)
```

## Layout 2: one folder per project (0.6.0)

A new root is layout 2 (ADR 0024). Each project has one folder, so you can hand an LLM `projects/<id>/` and it sees that project and nothing else.

```text
<root>/
  .ferry                      the manifest (version 2); never leaves the machine
  ferry.toml                  this machine's choices
  projects/<id>/
    repo/                     Ferryman's own clone. Machine-local.
    comms/                    the channel. Synced (Syncthing folder id <id>-ferryman, unchanged).
    handins/                  hand-ins and a worker-level agent's own signed writes. Synced (<id>-handins).
    work/                     task worktrees. Machine-local.
    tmp/                      scratch. Machine-local.
    .env                      this project's keys only. Never synced.
  secrets/                    write credentials and fleet-wide keys. Never synced. Orchestrator only.
  logs/                       including migrate-<UTC>.md
```

**The layout is the default, never a rule.** The manifest's recorded paths are the truth. `ferry enable --channel P --repo P --handins P --env P` puts a project where you say and records it as `placement: custom`; a project adopted from outside the root is custom too. Nothing Ferryman does assumes a project is under `projects/<id>`: it asks the entry. `ferry root migrate` never moves a custom project, and `doctor --layout` checks only that a custom project's recorded paths exist. A custom project is not a failure.

**Hand-ins have their own folder** so that a Worker-level agent can be kept out of the channel. Everything such an agent writes (hand-ins, claims, status, replies, its iroh transports record) goes to `handins/<agent>/`; readers treat the signed files there as if they were in the channel for that agent. See "Access levels" below.

**What may be synced.** Only `projects/<id>/comms` and `projects/<id>/handins`, or the paths a custom entry records. Ferryman refuses to share the root, `projects/`, `projects/<id>` itself, `repo/`, `work/`, `tmp/`, `secrets/`, `service/`, or any folder holding an `.env`, and `doctor --layout` reports one already configured.

**Access levels** are signed by the project's master (`ferry access set <project> <agent> worker|member|orchestrator`, `ferry access show`). A Worker reads the channel and never writes it: the machines that receive its files refuse a channel file it authored, and accept its writes only from `handins/<agent>/`. A Worker and a Member read the project's `.env` and nothing under `secrets/`; only an Orchestrator reads `secrets/`. With no grant an agent is a Member until the project has a Worker; from then on a roster name the master has not admitted (the roster is unsigned, so a Worker could register a fresh one) is a Worker too, and setting the first Worker signs everyone already there in as a Member. The master and the named head are Orchestrators. **This is not a sandbox:** every agent on a machine runs as the same operating-system user, so a process that goes around Ferryman can read `secrets/` straight from disk. The levels decide what Ferryman loads for an agent and what other machines accept from it; keep a secret that must never reach a Worker off any machine a Worker runs on. Levels are enforced when hand-ins are kept apart from the channel (layout 2 or a recorded path); in a layout-1 project they are recorded and shown, and refuse nothing.

**Moving a layout-1 root.** `ferry root migrate` is a dry run. `ferry root migrate --apply` moves each managed project (channel, hand-ins, Ferryman's own clone), repoints `bridge.toml` and Ferryman's Syncthing folder paths (ids kept, so nobody re-pairs), refuses a project with a running worker, lock or live worktree and says why, leaves stale worktrees under `work/` and lists them, deletes nothing (superseded files go to `_to_delete/`), logs to `logs/migrate-<UTC>.md`, and bumps the manifest to version 2 only when every managed project moved. It can be run again.

A layout-1 root keeps working unchanged. The rest of this page describes layout 1 and the checks both share.

## What each folder is for (layout 1)

**`comms/`** holds one channel per project: orders, claims, results, the roster, the master's signed settings. It is plain files, and Syncthing carries it between your machines.

**`repos/<project>`** is Ferryman's own clone. It is never a person's working copy. `ferry repos sync` makes it (a `git clone`, then a fetch), and attaches it to the channel the root already files: a `.ferryman/bridge.toml` and `/.ferryman/` in the clone's `.git/info/exclude`. It never touches a roster, a key, a device or a Syncthing folder, and it never signs.

**`work/<project>/<order>`** is where a worker does one order, in a git worktree of `repos/<project>`. It is safe to delete when the order is over. Hand-ins do not live here: they live in the channel, as `comms/<project>-ferryman/handins/`.

## A person's working copy is never the worker's checkout

`X:\ferryman` on beastly and `/mnt/nvme-storage/repos/ferryman` on grouchly are places a person works. Ferryman does not move them, clean them, fetch into them or write to them. When a project was attached to one, the managed clone becomes the worker's checkout and the manifest records:

- `repo`: the managed clone, `repos/<project>`. This is what workers use.
- `human_checkouts`: the working copies it replaced, for information only.

Nothing on disk is moved or deleted. A worktree made from the old checkout keeps working until its order ends; new orders use the managed clone.

## Where a clone comes from

In this order, per project:

1. `[git.remotes]` in `<root>/ferry.toml`: one project, one URL.
2. `[git] remote_template`, with `{project}` standing for the id:
   - beastly: `https://github.com/estejosh/{project}.git`, with the credential helper and a read-only token.
   - grouchly: `git@github-estejosh:estejosh/{project}.git`, through its ssh alias.
3. The `origin` of a checkout this machine already has, with any credentials stripped.

A password or token in a URL is refused. Ferryman never stores a token in a file it writes: the credential helper or the ssh alias is the machine's, not Ferryman's. Git is run with `GIT_TERMINAL_PROMPT=0` and `GCM_INTERACTIVE=never`, so a missing credential is a skipped project with a reason, not a hung worker.

## Syncthing shares channels and nothing else

Only channel folders under `<root>/comms/` are ever shared by Syncthing. `repos/` and `work/` are machine-local; git carries the code. Sharing a clone or a worktree between machines is how two machines end up writing into one `.git` directory, so this is enforced, not advised:

- **Ferryman refuses to create or share a Syncthing folder** whose path is the root itself, is above it (so it would carry `repos/` and `work/` too), or is under `repos/`, `work/` or `service/` (which holds the worker's environment file). The path is compared after `.` and `..` are resolved and after symlinks are followed, so a link inside `comms/` that leads into `repos/` is refused too. The check runs before anything is looked up or written, in the one function every folder registration goes through (channels, the fleet folder, anything added later), so there is no marker file, no half-registered folder and no way around it by a flag.
- **`ferry doctor --layout` flags a folder that is already configured outside `comms/`.** It reads the managed Syncthing's own configuration through its API. A folder is flagged when it is at the root, above it, or under `repos/` or `work/` (whoever created it), or when it has one of Ferryman's own ids (`<project>-ferryman`, `<project>-work`) and sits anywhere other than under `comms/`. A folder you set up yourself for something else (photos, say) is never flagged for being elsewhere. If Syncthing is not running, the check says it was not made; that is not a failure.
- **`ferry doctor --layout --fix` stops Syncthing sharing a stray that Ferryman registered itself** (an old `<project>-work`, for instance). Only the Syncthing registration is removed. No file is touched. A stray it cannot vouch for as its own stays reported.

Before this rule, hand-ins were shared as a second folder, `<project>-work`, which was `work/<project>`: the same folder the worktrees are made in. Hand-ins now live inside the channel (`comms/<project>-ferryman/handins/`), which already syncs, so a hand-in needs no folder of its own. A machine that registered `<project>-work` before shows it in `doctor --layout`; `--fix` clears it. An unreviewed hand-in left in the old `work/<project>` folder is still on disk; move its folders into the channel's `handins/` by hand.

## `ferry doctor --layout`

Six checks in layout 1, eight in layout 2. Each failing one prints the command that fixes it.

| Check | Passes when |
|---|---|
| folders | `comms/`, `repos/` and `work/` exist under the root |
| repos | every live project has `repos/<project>`, attached to its channel |
| one worker | exactly one worker runs or is enabled on this machine |
| service | that worker is a service, so a reboot or a closed terminal does not end it |
| locks | no `worker-<agent>.lock` names a process that is gone |
| syncthing | no configured Syncthing folder sits outside `comms/` (layout 2: outside `projects/<id>/comms` and `handins`) |
| projects (layout 2) | a managed project has `repo/`, `comms/`, `handins/` and `work/`; a custom one has the paths it recorded. Custom is not a failure |
| keys | no `secrets/` or `.env` is inside a synced folder, and no Worker-level agent on this machine has a write path into the channel (its hand-ins are separate, nothing of its is stray in `comms/`, its Syncthing folder is receive-only) |

`--json` prints the same. `--fix` makes missing folders, runs `repos sync`, renames the locks of dead processes to `<name>.stale-<pid>` (never deleting them, and only after looking at the pid again) and stops Syncthing sharing strays Ferryman registered. It does not sign, enrol, revoke or release anything: those are the master's lines, and `ferry fleet setup` prints them.

The watchdog runs the same checks. When the layout is incomplete it takes one fixed action, `repair_layout`, which is `repos sync` plus the stale-lock rename. A model cannot pick it when nothing needs repairing, and it never signs. Problems it cannot repair (a second worker, no service, a stray Syncthing folder) go to the alert.

## Keeping a project out of the swarm

Some projects must not be worked by the fleet: a secrets repository, someone else's code.

- The project's master signs `swarm = off` into the channel (`ferry root swarm off --project pc-secrets`, or the Teammates page of the dashboard). Every machine that syncs the channel hears it. Absent means on, so the one unsigned thing a peer can do (delete the file) only puts the project back; a file anyone but the master wrote is ignored.
- A machine can also exclude a project for itself (`ferry root swarm exclude pc-secrets`), written to `[swarm] exclude` in `<root>/ferry.toml`. Nobody else can reach it.

Either way: `repos sync` does not clone it, an all-projects worker does not serve it (and a running one stops at its next pass), and `team approve --all` does not enrol anyone in it. `ferry root swarm show` lists both.

## Where Josh's machines keep things
Added 2026-10-21. One root per machine, nothing outside it.
- beastly: root `X:\ferry`. Code in `repos\<project>`, channels in `comms\<project>-ferryman`, scratch in `tmp`, retired old checkouts in `_retired`, Hone's data folders in `hone-data`.
- grouchly: root `/mnt/nvme-storage/repos/ferry` with the same `repos`, `comms`, `tmp` and `_retired` folders. Some channels there still sit in `/mnt/nvme-storage/repos/ferryman-comms` until the services that use them move.
- Secrets stay in `X:\ferryman\.env` (copy at `X:\ferry\secrets\.env`) until Custodly replaces them. Never print or commit them.
- The `ferry root show` command lists every project with its repo and channel path.