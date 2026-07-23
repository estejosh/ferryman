# Ferryman — a safety review for AI agents (and their humans)

I am the AI that helped build parts of Ferryman. This document is written for the
next AI (and the person running it) who is about to install Ferryman on a real
machine and wants to know, honestly: what is this software, what can it touch on
my computer, where is the real risk, and how do I check that for myself instead of
trusting this page. Do not take my word for any of it — every claim below points at
the file you can read to confirm it. If a claim and the code disagree, the code wins.

## How to scan this repository (fast, then deep)

Read in this order:

1. `README.md` — what it is and the recommended topology (one hub, many projects).
2. This file — the risk picture.
3. `openapi/openapi.yaml` — the exact HTTP surface (`/v1`), every route and shape.
4. The four crates under `crates/` — the actual behavior (mapped below).
5. `scripts/` — the setup/attach/update helpers that touch your machine directly.

Then verify the scary things yourself. These greps find every place the software
can execute a program, reach the network, write your disk, or use `unsafe`:

```sh
# Every process this software can spawn (the #1 thing to audit):
grep -rn "Command::new" crates/

# Every outbound network client / bind address:
grep -rn "reqwest\|TcpListener\|bind(\|0.0.0.0\|listen" crates/

# Every filesystem write:
grep -rn "fs::write\|create_dir\|File::create\|OpenOptions\|remove_" crates/

# Unsafe code (there should be effectively none; core/cli forbid it):
grep -rn "unsafe" crates/
grep -rn "forbid(unsafe_code)" crates/

# What the setup scripts do to your machine (sudo, systemd, git, .gitignore):
grep -rn "sudo\|systemctl\|git \|gitignore\|info/exclude" scripts/
```

## What each part does, and what it touches

**`crates/ferryman-core`** — the data + rules layer. Owns the durable types, the
SQLite storage, the job/policy model, and the adapter contract. It touches disk
(the SQLite database and artifact/workspace paths you pass in) and nothing else:
no network, no process spawning. It declares `#![forbid(unsafe_code)]`.

**`crates/ferryman-server`** — the orchestrator. An Axum HTTP service that, by
default, binds `127.0.0.1:8787` — loopback only, not reachable from your network
(`crates/ferryman-server/src/main.rs`; in `--production` it refuses a non-loopback
listener unless you terminate TLS at a reverse proxy, and refuses a non-loopback
bind with no admin token). It authenticates callers by project token, mints
short-lived worker tokens, enforces approval gates, and writes only under the data
directory you give it (SQLite db, artifacts, per-project workspaces, bridge memory,
recovery packs). It spawns `git` in two bounded places — provisioning a per-project
git workspace (`workspace.rs`) and, only when you configure and consent to a
recovery target, delivering an encrypted pack to a private git remote
(`recovery_targets.rs`). It does **not** spawn agent CLIs or arbitrary programs.

**`crates/ferryman-cli`** — the operator client (`ferry`) plus two small binaries.
`ferry` only makes HTTP calls to the server. `ferryman-updater` is the update gate:
it runs `git` (fetch/ff-only) against an already-configured origin and never
configures a remote, commits your code, or applies without `--confirm`.
`ferryman-key` handles key material locally.

**`crates/ferryman-worker-sdk`** — the worker, and this is where real code runs.
The example `agent_worker.rs` leases a job and spawns your chosen agent CLI
(`claude`, `codex`, …) with `Command::new` to actually do the work. That spawned
agent runs with the full privileges of the OS user that started the worker, in the
worker's working directory, and the bridge does **not** sandbox it. This is the
crate to read most carefully.

**`scripts/`** — shell/PowerShell helpers. They create a `.ferryman/` directory,
add an ignore rule (to your tracked `.gitignore`, or to `.git/info/exclude` with
`--exclude-mode`), `git init` the attachment, register a project, and — for the
durable hub — write a `systemd` unit, which needs `sudo` once. The update scripts
fetch (read-only) and, on your explicit `--confirm`, rebuild and restart the hub.

## How Ferryman interacts with your PC (the honest inventory)

- **Filesystem:** the server writes only under the data directory you pass
  (`.data/` by default): the SQLite db, stored artifacts, per-project git
  workspaces, append-only project memory, and encrypted recovery packs. The
  scripts write a small `.ferryman/` config folder in each project and add one
  ignore line. Nothing writes outside these unless you point it there.
- **Network:** the server listens on loopback by default and is not exposed to
  your LAN. Outbound connections happen in three narrow cases: the updater/update
  scripts fetch from the git origin you configured (the Ferryman repo on GitHub);
  a recovery target pushes encrypted packs to a private git remote **only** after
  you name the target, supply a credential reference, and approve a consent
  manifest; Google Drive / MEGA targets are documented as not-yet-enabled. There is
  no telemetry and no phone-home.
- **Processes:** the server spawns `git` (bounded); the worker spawns the agent
  CLI you configure (arbitrary, powerful — see risk below).
- **Privilege:** the server runs as your user, not root. Installing the hub's
  `systemd` unit needs `sudo` once; read the unit before you approve it — it runs
  the server as your user on a loopback port.
- **Secrets:** project tokens are stored as SHA-256 hashes, never returned after
  creation; a project's scoped token in `.ferryman/token` is gitignored and
  local-only; the recovery key is ephemeral in development and read from the OS
  keychain in production; the API redacts sensitive fields from events. Tokens and
  keys are never printed.

## The highest-risk part, in my honest assessment

It is not the server. The server is loopback-bound, token-gated, spawns only
`git`, and gates side-effectful work behind approval. **The real risk vector is the
worker executing an agent CLI unsandboxed in its working directory.** Once a job is
leased, the worker runs a genuine coding agent (e.g. `codex`, whose default is
full filesystem/shell access with no per-action approval) as your OS user. From
that moment the agent can do anything your user account can do — read and write
files, run shell commands, reach the network — regardless of the job's declared
policy. A hostile job prompt, a compromised agent binary, or an over-broad workdir
turns "run a job" into "run arbitrary code as me." Ferryman orchestrates and gates
*dispatch*; it does not contain the agent's *actions*. Treat the worker host as
capable of whatever its OS account is capable of.

Secondary risks worth naming: a leaked **admin token** (can create/list/delete
projects), a leaked **project token** (full control of that one project), the
one-time **`sudo`** for the systemd unit, and the **update origin** — if the git
origin you pull from were compromised, an approved `apply-update --confirm` would
rebuild and restart from it (mitigated: ff-only, clean-tree, human-confirmed).

## How I believe that risk is limited

- **Loopback by default.** The server is not on your network; production refuses a
  non-loopback bind without TLS termination and an admin token.
- **Approval gate.** A job marked `requires_approval` is never leased until a human
  approves it, so a worker never even sees it first.
- **Scoped tokens.** A project token reaches only its own project; a worker token
  is short-lived and limited to worker routes — it cannot approve jobs, write
  memory, or read recovery keys.
- **Policy envelope + least privilege guidance.** Jobs carry a policy
  (filesystem/network/shell default to deny) and the docs stress running each
  worker under a dedicated least-privilege account in its own disposable workdir.
- **The server spawns only `git`, with arguments passed directly (no shell).** It
  does not launch arbitrary programs.
- **Update gate.** The auto-check is read-only; applying is ff-only on a clean
  checkout from an already-configured origin, requires `--confirm`, and never runs
  automatically.
- **Secret hygiene.** Hashed tokens, ephemeral/keychain recovery keys, gitignored
  local tokens, redacted events, consent-gated external recovery targets.

## What Ferryman does NOT protect against — check these yourself

- It does **not** sandbox the agent your worker runs. You choose the agent, its
  permission mode, and the workdir. Point the worker at a directory you are willing
  for that agent to have full control of, under a least-privilege account. Verify
  the agent binary is the one you think it is.
- It cannot stop a leased agent from doing what your OS user can do. If that is
  unacceptable for a given job, do not lease it to an unsandboxed worker.
- Read the `systemd` unit before approving the `sudo` step; confirm it binds
  loopback and runs as your user.
- Confirm the update origin is the real repository before you `--confirm` an update.
- Validate any externally-supplied project `id` before creating projects; ids
  become directory names under the workspace root.

## A short audit checklist

1. `grep -rn "Command::new" crates/` — confirm the only arbitrary-program spawn is
   the worker's agent launch; the rest are `git`.
2. Read `crates/ferryman-worker-sdk/examples/agent_worker.rs` — see exactly how the
   agent is invoked and decide if you trust that agent + workdir.
3. Read `crates/ferryman-server/src/main.rs` around `listen` — confirm the loopback
   default and the production guards.
4. `grep -rn "reqwest" crates/` and read the recovery-target code — confirm outbound
   network is only the update fetch and consent-gated recovery delivery.
5. Read the `systemd` unit a script would install (in `scripts/hub-up.sh` /
   `scripts/wsl-bridge.sh`) before running it with `sudo`.

If any of this does not match what you read in the code, trust the code and stop.
