# Nested bridge layout

Some agents are sandboxed to the project directory they are working in. They
cannot reach a Ferryman checkout that lives in a *sibling* folder (for example
`X:\orchestrator-bridge` next to `X:\myproject`), so they cannot find or talk to
the bridge. The fix is to put a full, self-contained bridge **inside** the
project — without polluting the project's git history.

## The model

```
myproject/                <- the main project repo (its own git)
├─ .gitignore             <- contains "/.ferryman/"
├─ src/ ...
└─ .ferryman/             <- a FULL Ferryman bridge, and its OWN git repo
   ├─ .git/               <- independent history; push it to its own remote if you like
   ├─ .gitignore          <- ignores .data/ (runtime state)
   ├─ bridge.toml         <- endpoint + project slug
   ├─ start.ps1 / start.sh
   ├─ README.md
   └─ .data/              <- SQLite db, artifacts, workspaces, memory, recovery
```

Two independent git repositories share one folder tree:

- The **parent** project gitignores `/.ferryman/`, so the bridge never shows up
  in the project's `git status`, diffs, or commits.
- The **bridge** is its own repo (`.ferryman/.git`). Git treats a nested `.git`
  as a boundary and never descends into it, so the two histories stay fully
  separate. You can give the bridge its own remote and version it as a
  sub-project, exactly like any other repo.

Runtime state (`.data/`) is gitignored inside the bridge repo too — only the
config, helper scripts, and README are tracked there.

## Set it up

From the Ferryman repo, run the helper against your project:

```powershell
# Windows
powershell -File scripts\nest-bridge.ps1 -Project C:\code\myproject -Port 8795
```

```sh
# Linux / macOS
scripts/nest-bridge.sh /code/myproject 8795 demo
```

Arguments: project directory (default: current dir), port (default: 8787),
project slug (default: `demo`). The script is idempotent — safe to re-run.

It will:

1. add `/.ferryman/` to the project's `.gitignore` (if the project is a git repo),
2. create `.ferryman/` and `git init` it as its own repo,
3. write the bridge's own `.gitignore`, `bridge.toml`, a `start` helper, and a README.

## Run it

The bridge needs the `ferryman-server` binary. Put it on `PATH`, or point the
start helper at it with `FERRYMAN_BIN`:

```powershell
$env:FERRYMAN_BIN = "X:\orchestrator-bridge\target\release\ferryman-server.exe"
cd C:\code\myproject\.ferryman
powershell -File start.ps1
```

```sh
export FERRYMAN_BIN=/path/to/ferryman-server
cd /code/myproject/.ferryman && ./start.sh
```

No recovery key is required for local/dev use — the server mints an ephemeral
one and warns (see the README quickstart). The API comes up on
`http://127.0.0.1:<port>` and every file it writes stays under `.ferryman/.data/`.

## One bridge per project

In this full-bridge layout each project runs its **own** server, so give each
project a **distinct port** (8795, 8796, …). Agents working in a project point at
that project's `http://127.0.0.1:<port>` and use its scoped project token — the
same Ferryman HTTP API as always, just reachable from inside the sandbox.

## Running the bridge in WSL / Ubuntu (Linux-side data)

On Windows, running the bridge as a Linux process (WSL/Ubuntu) is often more
robust: real daemonization via systemd, and agent CLIs launch as plain
executables (no `.cmd`/`.ps1` shim handling). **One caveat matters:** SQLite on a
Windows drive mounted into WSL (`/mnt/*`, DrvFs) has file-locking bugs that cause
intermittent "database is locked/busy" failures. Keep the database on the Linux
filesystem.

`scripts/wsl-bridge.sh` does exactly that: it keeps a discoverable, gitignored
`.ferryman/bridge.toml` inside the Windows project (so sandboxed agents find the
endpoint), but puts the SQLite `.data/` on Linux (`~/ferryman/<slug>/.data`) and
runs the server as a durable systemd service.

```sh
# inside WSL; build ferryman-server first: cargo build --release -p ferryman-server
export FERRYMAN_BIN=$HOME/ferryman/ferryman-server
export FERRYMAN_SUDO_PW=...        # omit if sudo is passwordless
scripts/wsl-bridge.sh /mnt/x/myproject 8796 myproject
```

The API comes up on `http://127.0.0.1:8796`, reachable from **both** WSL and
Windows-native processes via WSL2 localhost forwarding. Manage it with
`systemctl status|restart ferryman-<slug>`. Give each project its own port.

Rule of thumb: **the SQLite database lives on the same OS that runs the server.**
A Windows-native server keeps data on the Windows drive; a WSL server keeps data
on the Linux filesystem.
## Many repos, one instance (shared hub + attach)

When a machine hosts a lot of repos, do not run a bridge per project — run **one**
shared hub and attach each repo to it. Each repo still keeps a full, own-git
`.ferryman/` directory (gitignored by the parent); it just holds the repo''s
config + scoped token instead of a server. The `ferryman-server` software runs
once; the directories are per-repo.

```sh
# once per machine: bring up the single hub (durable systemd, Linux-side data)
export FERRYMAN_BIN=$HOME/ferryman/ferryman-server
export FERRYMAN_SUDO_PW=...            # omit if passwordless sudo
scripts/hub-up.sh 8796

# per repo: attach it as a scoped project in the one hub
scripts/attach-bridge.sh /mnt/x/myproject myproject
```

`attach-bridge.sh` ensures the one hub is up (idempotent — it never starts a
second instance), creates the repo''s own-git `.ferryman/`, registers the repo as
a project, and stores a scoped token in `.ferryman/token` (gitignored, local-only,
never committed). Agents read `.ferryman/bridge.toml`, connect to the hub with
that token, and are isolated to their project by the API.

Trade-off: one instance means one process + one database for all projects
(isolation is by token + workspace, not by separate processes). If a specific
repo needs hard process/DB isolation, give it a dedicated bridge on its own port
(`wsl-bridge.sh` / `nest-bridge.ps1`) instead — a hybrid is fine.
## Updates — approve/deny gate

A nested bridge does not track `main` on its own, and nothing updates
automatically. The flow is an explicit gate (`ferryman-updater`):

- **Check (read-only):** `ferryman-updater check-remote --checkout <bridge> --branch main`
  fetches the canonical origin and lists the commits you would be pulling. It
  changes nothing and exits 10 when an update is pending — so an agent can
  surface "update available" to you without ever applying it.
- **Approve:** `ferryman-updater update-bridge --checkout <bridge> --branch main --confirm`
  fast-forwards the install (clean checkout + already-configured origin only).
  Without `--confirm` it prints the pending diff and refuses, so it can never
  apply blind.
- **Deny:** do nothing. The bridge stays pinned where it is.

Per-project opt-in is unchanged: a project only accepts a recorded release when
its `bridge-project.toml` has `opt_in = true` (`ferryman-updater check` / `apply`).

Agents should run **check-remote** and report; a human runs **update-bridge
--confirm** to approve. Never wire auto-apply.

**Auto-updateable, with permission.** `scripts/update-check.sh` runs on a daily
`systemd` timer (`ferryman-update-check.timer`): it is read-only, and when the
canonical repo is ahead it records `~/ferryman/UPDATE_AVAILABLE` with the pending
commits — it never applies. Approving is one explicit command,
`scripts/apply-update.sh --confirm`, which fast-forwards the source, rebuilds,
swaps the binaries, and restarts the hub. Without `--confirm` it just shows what
would change. So the machine notices updates on its own but only a human ever
applies one.
## Migrating from a sibling bridge

If a project was using a bridge in a sibling folder, you do not lose anything:

- Stand up the nested bridge with the script above (new `.data/`).
- Point the project's workers/agents at the nested endpoint + token instead of
  the sibling one.
- The old sibling checkout can keep running in parallel until you have proven the
  nested one; nothing is deleted or moved for you.

The bridge's git repo (`.ferryman/.git`) can be pushed to its own remote so the
sub-project's config/history is backed up independently of the main project.
