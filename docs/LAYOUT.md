# The layout

Every machine that runs Ferryman has the same layout under its ferry root. One command puts it there (`ferry fleet setup`), and `ferry doctor --layout` and the watchdog check it and repair what is safe. Nothing depends on a person or an agent remembering a path, because a path an agent has to remember is a path it will eventually get wrong.

```text
<root>/                       X:\ferry   or   /mnt/nvme-storage/ferry
  .ferry                      this machine's manifest (never leaves the machine)
  ferry.toml                  this machine's choices: where to clone from, what to keep out of the swarm
  comms/<project>-ferryman    the channel. The only thing Syncthing shares.
  repos/<project>             Ferryman's own clone of the project. Workers use this and nothing else.
  work/<project>/<order>      task worktrees, made from repos/<project>. Transient.
  service/                    the worker's environment file, wrapper and backups (see FLEET_SETUP.md)
```

## What each folder is for

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

- **Ferryman refuses to create or share a Syncthing folder** whose path is the root itself, is above it (so it would carry `repos/` and `work/` too), or is under `repos/` or `work/`. The check runs before anything is looked up or written, in the one function every folder registration goes through (channels, the fleet folder, anything added later), so there is no marker file, no half-registered folder and no way around it by a flag.
- **`ferry doctor --layout` flags a folder that is already configured outside `comms/`.** It reads the managed Syncthing's own configuration through its API. A folder is flagged when it is at the root, above it, or under `repos/` or `work/` (whoever created it), or when it has one of Ferryman's own ids (`<project>-ferryman`, `<project>-work`) and sits anywhere other than under `comms/`. A folder you set up yourself for something else (photos, say) is never flagged for being elsewhere. If Syncthing is not running, the check says it was not made; that is not a failure.
- **`ferry doctor --layout --fix` stops Syncthing sharing a stray that Ferryman registered itself** (an old `<project>-work`, for instance). Only the Syncthing registration is removed. No file is touched. A stray it cannot vouch for as its own stays reported.

Before this rule, hand-ins were shared as a second folder, `<project>-work`, which was `work/<project>`: the same folder the worktrees are made in. Hand-ins now live inside the channel (`comms/<project>-ferryman/handins/`), which already syncs, so a hand-in needs no folder of its own. A machine that registered `<project>-work` before shows it in `doctor --layout`; `--fix` clears it. An unreviewed hand-in left in the old `work/<project>` folder is still on disk; move its folders into the channel's `handins/` by hand.

## `ferry doctor --layout`

Six checks. Each failing one prints the command that fixes it.

| Check | Passes when |
|---|---|
| folders | `comms/`, `repos/` and `work/` exist under the root |
| repos | every live project has `repos/<project>`, attached to its channel |
| one worker | exactly one worker runs or is enabled on this machine |
| service | that worker is a service, so a reboot or a closed terminal does not end it |
| locks | no `worker-<agent>.lock` names a process that is gone |
| syncthing | no configured Syncthing folder sits outside `comms/` |

`--json` prints the same. `--fix` makes missing folders, runs `repos sync`, renames the locks of dead processes to `<name>.stale-<pid>` (never deleting them, and only after looking at the pid again) and stops Syncthing sharing strays Ferryman registered. It does not sign, enrol, revoke or release anything: those are the master's lines, and `ferry fleet setup` prints them.

The watchdog runs the same checks. When the layout is incomplete it takes one fixed action, `repair_layout`, which is `repos sync` plus the stale-lock rename. A model cannot pick it when nothing needs repairing, and it never signs. Problems it cannot repair (a second worker, no service, a stray Syncthing folder) go to the alert.

## Keeping a project out of the swarm

Some projects must not be worked by the fleet: a secrets repository, someone else's code.

- The project's master signs `swarm = off` into the channel (`ferry root swarm off --project pc-secrets`, or the Teammates page of the dashboard). Every machine that syncs the channel hears it. Absent means on, so the one unsigned thing a peer can do (delete the file) only puts the project back; a file anyone but the master wrote is ignored.
- A machine can also exclude a project for itself (`ferry root swarm exclude pc-secrets`), written to `[swarm] exclude` in `<root>/ferry.toml`. Nobody else can reach it.

Either way: `repos sync` does not clone it, an all-projects worker does not serve it (and a running one stops at its next pass), and `team approve --all` does not enrol anyone in it. `ferry root swarm show` lists both.
