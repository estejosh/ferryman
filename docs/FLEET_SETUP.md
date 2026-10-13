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

1. **Layout.** Makes `comms/`, `repos/` and `work/` under the ferry root (`--root <folder>` makes the root first when there is none).
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

## One worker per machine

Two workers on one machine claim the same orders, burn the same engines and race each other's worktrees. `ferry fleet setup --service` leaves exactly one:

- **Linux:** a systemd user unit, `ferryman-worker.service`, with `Restart=on-failure`, `MemoryHigh=70%`, `MemoryMax=85%`, `CPUQuota=400%`, a task limit, and `EnvironmentFile=-` pointing at `service/worker.env`.
- **Windows:** a Scheduled Task, `Ferryman Worker`, that runs at logon with restart on failure and no time limit, and runs a PowerShell wrapper (`service/ferryman-worker.ps1`). The wrapper loads `service/worker.env` (`KEY=VALUE` per line) and runs `ferry agent run --all-projects --workspace <clone>`.
- **Environment.** Keys the worker needs go in `service/worker.env`, never inline in a unit, a task or a wrapper. The file is made once and never overwritten.
- **The others are turned off, not deleted.** Every other ferry worker unit or task is disabled, and a copy is saved first in `service/backup/<time>/`. A worker running in a terminal is never killed: setup prints the command to stop it, and holds the service back until it is stopped.
- **Elevation is printed, not attempted.** Anything that needs administrator or root rights is a line for a person to run.
- **Syncthing outlives the worker.** It runs as a service of its own (`ferryman-syncthing.service`, or the task `Ferryman Syncthing` on Windows), so stopping, restarting or replacing the worker never stops syncing. `ferry syncthing run` is the foreground form both use; started detached it is placed outside the worker's process tree (`systemd-run --user` on Linux, a job breakaway on Windows). `--no-syncthing` leaves it alone.

`ferry agent run` and `ferry doctor` both look for another live worker or service. `agent run --all-projects` refuses to start as a second all-projects worker, and says which one is running and how to stop it; `--allow-second-worker` overrides that for a test. Other cases are a warning. `ferry doctor --layout` makes it a check.

## Keeping projects out of the swarm

```sh
ferry root swarm show                             # signed state and this machine's exclusions
ferry root swarm off --project pc-secrets         # the master signs it; every machine hears it
ferry root swarm on  --project pc-secrets         # the master puts it back
ferry root swarm exclude pc-secrets               # this machine only, no signature
ferry root swarm include pc-secrets
```

The dashboard's Teammates page has the same switch for each project (master only). A project that is out is not cloned by `repos sync`, not served by `agent run --all-projects` (a running worker stops at its next pass), and not enrolled by `team approve --all`. Josh's two: `pc-secrets` and `phonehome`.

## Per-project policy in fleet mode

A fleet worker runs as one identity with one `agent.toml`, so one preamble covers every project. A project with binding rules of its own (Quantly: paper trading only, Rust only) declares them where the worker will read them:

1. `ferryman.toml` at the repository root, so the policy travels with the code and is reviewed like it:

   ```toml
   [policy]
   files = ["quantly-rust-complete-handoff/RUST_ONLY_POLICY.md", "docs/PAPER_EXECUTION.md"]
   ```

2. `.ferryman/POLICY.md` in the managed clone: this machine's own addition, last, with the last word. It is not in git.

The files are injected after the global preamble, into that project's prompts and no other project's. Each file is cut at 12 KiB and the whole policy at 32 KiB, with a marker where it was cut. A path must be relative, must not climb out with `..`, and must resolve to a regular file inside the repository; a link to `~/.ssh/id_ed25519` is a skipped note, not a prompt. A missing or refused file is a note, never a reason the worker does not start. Nothing is guessed: an `AGENTS.md` is not injected unless the project names it.

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
- `order reoffer` is for an order addressed to an identity that is gone. It does not edit the signed order: it writes a signed offer beside it (`offer.<signer>.<time>.json`) and a history line. The newest valid offer decides who may claim it. Only the order's issuer or the project's master can offer, and a forged offer file is ignored. `--queue` offers it to whoever is first.

Nothing is deleted: the order, the claim and every earlier record stay.

## Checking and repairing

```sh
ferry doctor --layout            # six checks, each with the command that fixes it
ferry doctor --layout --fix      # makes folders, runs repos sync, sets dead locks aside, unshares strays
ferry doctor                     # includes the workers line
```

The watchdog does the same on a timer and takes the one fixed action `repair_layout`. Neither signs. See LAYOUT.md.
