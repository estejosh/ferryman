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

## Migrating from a sibling bridge

If a project was using a bridge in a sibling folder, you do not lose anything:

- Stand up the nested bridge with the script above (new `.data/`).
- Point the project's workers/agents at the nested endpoint + token instead of
  the sibling one.
- The old sibling checkout can keep running in parallel until you have proven the
  nested one; nothing is deleted or moved for you.

The bridge's git repo (`.ferryman/.git`) can be pushed to its own remote so the
sub-project's config/history is backed up independently of the main project.
