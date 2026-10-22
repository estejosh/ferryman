# Setting up a machine: `ferry fleet setup`

A fleet only works if every machine is the same shape and each one does one job. This is the page for putting a machine there, and for what to run when it is not. The layout it builds is in [LAYOUT.md](LAYOUT.md); the worker it starts is in [FLEET_WORKER.md](FLEET_WORKER.md).

The rule behind all of it: Ferryman works by fixed structure, not by agents remembering paths or steps. Every machine has the same layout, one command puts it there, and `doctor` and the watchdog check it and repair what is safe. Anything that needs the master's signature is printed for the master to run, never done for them.

## The short version

On each machine, once:

```sh
ferry fleet setup --dry-run                 # read what it would do; nothing is written
ferry fleet setup --service                 # do it
```

Then run the lines it prints under "run these as the project master", on the machine that holds the master's key.

## What `ferry fleet setup` does

1. **Layout.** Makes the root's folders (`projects/`, `secrets/`, `logs/` in layout 2; `comms/`, `repos/`, `work/` in layout 1) (`--root <folder>` makes the root first when there is none).
2. **Settings.** `--remote-template` writes where clones come from to `<root>/ferry.toml`; `--exclude <project>` keeps a project out of the swarm on this machine only. Both are optional, both are local.
3. **Clones.** Runs `ferry repos sync`: every live project gets `repos/<project>`, attached to its channel. A person's working copy is not touched, and is remembered in the manifest as a `human_checkouts` entry.
4. **Identity.** Picks the machine's one worker identity: `--identity` if given, else the identity a worker here already runs as, else the only `*-swarm` identity found, else `ichabod-<machine>-swarm`. Its `agent.toml` and key live in a managed clone (`--home <project>` chooses which). A key already on this machine is copied, never regenerated and never moved: a second key under a name the rosters know reads as an impostor everywhere.
5. **Service (only with `--service`).** Writes one service that runs `ferry agent run --all-projects --workspace <clone>` and turns the others off. See below.
6. **The master's lines.** Prints, exactly, the signed commands only the project master can run: enrolling the identity (`team approve`), revoking the ones it replaces (`team revoke --name`), releasing their stale claims (`order release`), taking projects out of the swarm (`root swarm off`) and re-offering orders addressed to a retired identity (`order reoffer`). It never signs.

Without `--service` nothing is installed or turned off: it is the layout, the clones, the identity and the printed lines. `--dry-run` shows all of it and writes nothing (it does not clone either; it says what it would clone).

Safe to run again. It reports "already" for what is there and changes nothing.

### Flags

| Flag | Meaning |
|---|---|
| `--identity NAME` | The worker identity for this machine |
| `--home PROJECT` | The project whose managed clone holds the worker's `agent.toml` and key |
| `--retire NAME` | An identity this machine used to run as; prints the master's revoke and release lines for it. Repeatable |
| `--exclude PROJECT` | Keep this project out of the swarm on this machine. Repeatable |
| `--remote-template URL` | Where clones come from, with `{project}` for the id |
| `--root FOLDER` | Make the ferry root here when there is none |
| `--dry-run` | Say everything, write nothing |
| `--service` | Write and enable the one service, and turn the others off |
| `--no-syncthing` | Do not run Syncthing as a service of its own |
| `--no-fetch` | No network. Clones and attaches still happen |

## Where clones come from (GitHub, SovGit)

A project's remote is a per-machine setting in `<root>/ferry.toml`, not something in a channel: the channel is shared by every machine, and a machine without `git-remote-sov` must not be told to use `sov://`. (A master-signed `repo_remote` would put one machine's transport in every machine's face, and a forged or stale one is a way to point every clone at someone else's server; the local file has neither problem.)

```toml
[git]
remote_template   = "https://github.com/estejosh/{project}.git"   # the default; GitHub
# fallback_template = "https://github.com/estejosh/{project}.git" # tried when the first cannot be used

[git.remotes]
# One project that is on SovGit. git speaks sov:// through the helper `git-remote-sov`, which must be on PATH.
quantly = "sov://my-bucket/quantly"
```

`ferry repos sync` tries, in order: the project's `[git.remotes]` entry, `remote_template`, `fallback_template`, then the `origin` of a checkout already on the machine (credentials stripped). A `sov://` remote whose helper is not installed is skipped with the reason in the row (`skipped sov://bucket/repo: git needs the program git-remote-sov for sov:// remotes and it is not installed`) and the next candidate is tried; if nothing else is usable the project is a failed row that says why, and nothing is written. The same check runs before every fetch: a clone whose `origin` needs a missing helper is reported as `not fetched - ...`, never as an error. A remote that runs a command (`ext::`, `fd::`) is always refused. Ferryman has no SovGit code; it calls `git`, and git calls the helper.

`ferry repos sync` also moves Ferryman's own clone forward: after a fetch it fast-forwards `repos/<project>` when, and only when, the clone was made by `repos sync`, has no changes to tracked files, and is strictly behind its upstream. A diverged or edited clone is fetched and left alone. A person's checkout is never moved.

## Layout 2 and moving to it

A new root is layout 2: `projects/<id>/{repo,comms,handins,work,tmp,.env}`, `secrets/` and `logs/` (docs/LAYOUT.md, ADR 0024). `ferry fleet setup` makes the folders of whichever layout the root is in and clones into `projects/<id>/repo` in layout 2. `ferry enable` files a new project's channel at `projects/<id>/comms`; pass `--channel`, `--repo`, `--handins` or `--env` to place any of them yourself, and Ferryman records the project as custom and leaves it where you put it.

An existing machine moves with one command, once per machine, with the worker stopped:

```sh
ferry root migrate            # dry run: says what would move and what blocks it; writes nothing
ferry root migrate --apply    # does it, logs to <root>/logs/migrate-<UTC>.md
ferry agent run --all-projects   # start the worker again; the iroh lane re-reads bridge.toml
```

A project with a running worker, a worker lock or a live worktree is refused, and the line names what blocks it. Custom projects and your own checkouts are listed as left in place. Nothing is deleted: superseded copies go to `<root>/_to_delete/`. Where Ferryman's Syncthing has a project's folder, its path is changed and the folder id kept, so no other machine re-pairs; migrate the fleet together, or pause the folder on the machines that have not moved yet. Run it on grouchly the same way (root `/mnt/nvme-storage/repos/ferry`). Then `ferry access show` lists each agent's level and `ferry access set <project> <agent> worker|member|orchestrator` (the master's command) changes one.
## The fleet folder (0.6.1)

The fleet has one folder of its own, `<root>/fleet/`, a synced channel (Syncthing folder id `fleet-ferryman`, carried by the iroh lane too) that holds what is true of the whole fleet: where each machine keeps each project, what each machine runs, notices, fleet orders and release approvals (ADR 0026, docs/LAYOUT.md). Setting it up is the master's, once:

```sh
ferry fleet init                       # on the master's machine; makes <root>/fleet, registers it, admits this machine
ferry fleet admit <name> --machine <m> # for each other machine, once it has started a worker
ferry fleet machines                   # who is publishing: version, layout, projects, last seen
ferry fleet notices                    # layout changes, deprecations, new releases
ferry fleet notice update-available "0.6.2 is out" --version 0.6.2 --severity warning
ferry fleet order restart-worker --machine grouchly   # a worker acts only on the master's signature
```

A worker on another machine puts itself on the fleet roster when it starts and says so if the master has not admitted it yet (`fleet folder: not publishing yet - ...`). Until it is admitted it can read the folder and write nothing. Once it is, it publishes its machine record and its directory entries each pass; `ferry enable`, `ferry root adopt`, `ferry root data` and `ferry root migrate --apply` publish at once. After a migrate the directory is updated first, then a signed `layout-change` notice lists every old and new path.

`ferry where <project>` answers where a project is, on this machine or another, and nothing in a script needs to hardcode a path. `ferry fleet write-hints` puts a "ask `ferry where`" block into each clone's CLAUDE.md and AGENTS.md; it shows what it would do unless you pass `--apply`, and it never commits.

The folder is additive. A machine on an older release never reads it and loses nothing. Release requests are written there when it exists and also, while older machines are about, to the `ferryman` project's channel, and both places are read. A worker does not update itself because a notice says a release is out: it says so, and follows the update policy it has (`FERRYMAN_NO_AUTO_UPDATE`). A fleet `update` order from the master does update it, unless that variable is set; a `migrate` order is reported and left to a person, because a migrate refuses to run while a worker does.

## One worker per machine

Two workers on one machine claim the same orders, burn the same engines and race each other's worktrees. `ferry fleet setup --service` leaves exactly one:

- **Linux:** a systemd user unit, `ferryman-worker.service`, with `Restart=on-failure`, `MemoryHigh=70%`, `MemoryMax=85%`, `CPUQuota=400%`, a task limit, and `EnvironmentFile=-` pointing at `service/worker.env`.
- **Windows:** a Scheduled Task, `Ferryman Worker`, that runs at logon with restart on failure and no time limit, and runs a PowerShell wrapper (`service/ferryman-worker.ps1`). The wrapper loads `service/worker.env` (`KEY=VALUE` per line) and runs `ferry agent run --all-projects --workspace <clone>`.
- **Environment.** Keys the worker needs go in `service/worker.env`, never inline in a unit, a task or a wrapper. The file is made once and never overwritten.
- **The others are turned off, not deleted.** Every other ferry worker unit or task is disabled, and a copy is saved first in `service/backup/<time>/`. A worker running in a terminal is never killed: setup prints the command to stop it, and holds the service back until it is stopped.
- **Elevation is printed, not attempted.** Anything that needs administrator or root rights is a line for a person to run.
- **Syncthing outlives the worker.** It runs as a service of its own (`ferryman-syncthing.service`, or the task `Ferryman Syncthing` on Windows), so stopping, restarting or replacing the worker never stops syncing. `ferry syncthing run` is the foreground form both use; started detached it is placed outside the worker's process tree (`systemd-run --user` on Linux, a job breakaway on Windows). `--no-syncthing` leaves it alone.

`ferry agent run` and `ferry doctor` both look for another live worker or service. `agent run --all-projects` refuses to start as a second all-projects worker, and says which one is running and how to stop it; `--allow-second-worker` overrides that for a test. Other cases are a warning. `ferry doctor --layout` makes it a check.

## Coming back after an update (0.6.2)

A long-running worker checks for a release between passes (at most every six hours). When it installs one, the process still running is the old code, so it has to stop and start again. It used to stop with exit status 0, which a supervisor that restarts only on failure reads as "done", and a worker with no supervisor simply stayed stopped. Now it asks to be restarted and comes back by itself, whatever supervises it:

- **Linux and macOS:** the worker `exec`s the new binary in place, with the same arguments and environment, after its locks and its lane are released. Same process id, so systemd (or launchd, or nothing) sees one unbroken process. If the `exec` fails it exits 75, which any restart-on-failure supervisor treats as a failure.
- **Windows, run by the scheduled task from `ferry fleet setup`:** the wrapper sets `FERRYMAN_SUPERVISED`, and the worker exits **75** (`EX_TEMPFAIL`). The wrapper passes the exit code on, the task's restart-on-failure policy sees a failure, and the worker is back within a minute. A wrapper written before 0.6.2 does not set the variable, so the worker also recognises the task by the wrapper script (ferryman-worker.ps1) being among its parent processes and exits 75 all the same. It also adds $env:FERRYMAN_SUPERVISED = 'task' to an old wrapper itself, once, when it starts and before it restarts (the old file is kept as ferryman-worker.ps1.before-supervised), so the first auto-update on a machine set up before 0.6.2 does not leave the worker stopped. A wrapper edited by hand, without the $env:GIT_TERMINAL_PROMPT line, is left alone.
- **Windows, with no supervisor:** the worker starts a detached copy of itself that waits five seconds for the old process to let go of its locks, then exits 0.
- **A fleet `restart-worker` order** (ADR 0026) goes the same way, so it works without a supervisor too.

**Restart loops are capped.** Every restart request is recorded in `reexec.json` in the machine state directory. A fourth request in one hour is refused: the worker says so in its log and carries on with the version it is running until its next start. Delete `reexec.json` to reset the count.

**Belt and braces: recommended supervisor settings.** None of this is needed for the restart to happen, but a supervisor that restarts on any exit also covers a crash during the exec or a binary that fails to start:

- systemd (`~/.config/systemd/user/ferryman-worker.service`, then `systemctl --user daemon-reload`):

  ```ini
  [Service]
  Restart=always
  RestartSec=30
  StartLimitIntervalSec=600
  StartLimitBurst=10
  ```

  `ferry fleet setup --service` writes `Restart=on-failure`, which is enough now that the worker exits 75 when it cannot `exec`; `Restart=always` also restarts a worker that exits 0. Keep `RestartSec` so a crash loop is slow.
- Windows scheduled task (`Ferryman Worker`): *Settings* tab, "If the task fails, restart every" **1 minute**, "Attempt to restart up to" **999** times (what setup writes), "Stop the task if it runs longer than" **unchecked**, and "If the task is already running, then the following rule applies" **Do not start a new instance**. Exit 75 counts as a failure to the task, which is what makes it restart.
- No supervisor at all: nothing to set. Unix re-executes in place and Windows starts the detached copy.

## Keeping projects out of the swarm

```sh
ferry root swarm show                             # signed state and this machine's exclusions
ferry root swarm off --project pc-secrets         # the master signs it; every machine hears it
ferry root swarm on  --project pc-secrets         # the master puts it back
ferry root swarm exclude pc-secrets               # this machine only, no signature
ferry root swarm include pc-secrets
```

The signed `SWARM` file carries a number that only goes up, and every machine remembers the highest it has accepted for each project. Putting an old signed file back (to switch a project on again) is therefore not obeyed, and neither is deleting the file: the remembered setting stands until the master signs a higher one. (Old peers, 0.5.26 and 0.5.27, do not read `SWARM` at all; they keep serving a project the master has taken out until they are updated.)

The dashboard's Teammates page has the same switch for each project (master only). A project that is out is not cloned by `repos sync`, not served by `agent run --all-projects` (a running worker stops at its next pass), and not enrolled by `team approve --all`. Josh's two: `pc-secrets` and `phonehome`.

## Per-project policy in fleet mode

A fleet worker runs as one identity with one `agent.toml`, so one preamble covers every project. A project with binding rules of its own (Quantly: paper trading only, Rust only) declares them where the worker will read them:

1. `ferryman.toml` at the repository root, so the policy travels with the code and is reviewed like it:

   ```toml
   [policy]
   files = ["quantly-rust-complete-handoff/RUST_ONLY_POLICY.md", "docs/PAPER_EXECUTION.md"]
   ```

2. `.ferryman/POLICY.md` in the managed clone: this machine's own addition, last, with the last word. It is not in git.

The files are injected after the global preamble, into that project's prompts and no other project's. Each file is cut at 12 KiB and the whole policy at 32 KiB, with a marker where it was cut; `ferryman.toml` itself is read to 64 KiB, must be a file inside the repository, and names at most 8 files. The block says it can only narrow what the worker does and is not an instruction to run anything, and a line in a policy file that looks like the block's own frame (`--- ... ---`) is indented so a file cannot close the block early. A path must be relative, must not climb out with `..`, and must resolve to a regular file inside the repository; a link to `~/.ssh/id_ed25519` is a skipped note, not a prompt. A missing or refused file is a note, never a reason the worker does not start. Nothing is guessed: an `AGENTS.md` is not injected unless the project names it.

`ferry agent run --all-projects --dry-run` and `ferry route explain` print a `policy: <files>` line per project, with what was left out and why.

## Adding a project

`ferry enable` in a project is safe in a fleet:

- It refuses when this checkout would join a different channel than the one the root already files for the project, or when Syncthing already syncs that folder id somewhere else. `--force-new-channel` overrides, on purpose.
- It enrols the checkout's new identity on the project's roster as before, and then makes the project's managed clone (`repos/<project>`), so a newly enabled project arrives in the layout. `--no-enrol` makes the key and tells nobody. A clone that cannot be made yet (no remote known, no network) is a note; `ferry repos sync --project P` does it later.
- Use `ferry root attach <folder> [--project P | --all]` to attach an existing clone to the channel the root already files for it.

## Retiring an identity

When a machine's old identity is replaced, from the master's machine:

```sh
ferry team revoke --name OLD --all [--as master]     # revoke it in every project the master owns
ferry order release --held-by OLD --all [--as master] [--dry-run]
ferry order reoffer <order> --to NEW [--project P] [--as master]
```

- `team revoke --all` reaches every project the signing master owns, including those with no checkout here; projects someone else masters are left alone, and it refuses to revoke the signing master.
- `order release` writes a signed release for each unfinished claim OLD holds, putting the order back in the queue. It refuses a name whose worker is alive on this machine.
- `order reoffer` is for an order addressed to an identity that is gone. It does not edit the signed order: it writes a signed offer beside it (`offer.<signer>.<time>.json`) and a history line. The newest valid offer decides who may claim it. Only the order's issuer or the project's master can offer, and a forged offer file is ignored. An offer is signed together with its project and order, so a copy dropped into another project's folder is ignored, and one dated in the future is ignored too (it could not be outranked by a later real one). The reason is cut at 500 characters. `--queue` offers it to whoever is first.

Nothing is deleted: the order, the claim and every earlier record stay.

## Checking and repairing

```sh
ferry doctor --layout            # six checks, each with the command that fixes it
ferry doctor --layout --fix      # makes folders, runs repos sync, sets dead locks aside, unshares strays
ferry doctor                     # includes the workers line
```

The watchdog does the same on a timer and takes the one fixed action `repair_layout`. Neither signs. See LAYOUT.md.
