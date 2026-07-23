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
- **Approval gate.** A job marked `requires_approval` is never *leased by a worker*
  until it is approved. Caveat (independent review #5): approval and submission
  currently use the same project token, so the gate stops the worker but not the
  token holder — an automation holding the project token can self-approve. For a
  real human-in-the-loop, keep the project token as an automation identity
  distinct from the human, or gate approvals behind the admin token.
- **Scoped tokens.** A project token reaches only its own project; a worker token
  is short-lived and limited to worker routes — it cannot approve jobs, write
  memory, or read recovery keys.
- **Least-privilege worker guidance.** The docs stress running each worker under a
  dedicated least-privilege account in its own disposable workdir. NOTE (independent
  review #6): the per-job **policy envelope** (filesystem/network/shell = deny) is
  **advisory metadata only** — it is stored and can be simulated but is NOT enforced
  against the agent at runtime. Do not treat it as a control; the least-privilege
  account and the agent's own sandbox are the real boundary.
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

## Independent review & remediation (2026-07-23)

An independent AI security reviewer audited a fresh clone with no project context.
Its verdict: **the code you download and read is not malware** (no telemetry, no
`unsafe`, no SQL injection, no path traversal, loopback default, sound recovery
crypto); **running the worker is exactly as safe as letting your chosen agent run
code as you** — the inherent risk this doc names. It found 3 High, 3 Medium, 4 Low,
2 Info. Full report: `docs/reviews/2026-07-23-independent-review.md`. Every finding
and its remediation:

| # | Sev | Finding | Status |
|---|-----|---------|--------|
| 1 | High | Windows `cmd /c` argument injection from a job prompt | **Fixed** — the worker resolves the shim via PATH/PATHEXT and spawns it directly; Rust std batch-file escaping neutralizes cmd metacharacters. |
| 2 | High | Worker runs the agent unsandboxed as the OS user; prompt attacker-influenced | **Inherent / documented** — the design and the top risk here. Bound it with a least-privilege account + disposable workdir + the agent's own sandbox; the bridge cannot remove it. |
| 3 | High | Shipped hub ran dev-mode: open admin routes + public `demo-local-token` | **Fixed** — `hub-up.sh` generates an admin token (0600 EnvironmentFile) and ships `--no-demo-project`; the live hub was redeployed and the demo project removed. |
| 4 | Med | No DNS-rebinding / Host protection on the loopback service | **Fixed** — a loopback bind rejects non-loopback `Host` headers (403); verified. |
| 5 | Med | Approval gate shares the submission credential | **Mitigated / documented** — see the approval-gate caveat above; credential-separated approve route is tracked. |
| 6 | Med | Policy envelope advisory-only but listed as a mitigation | **Fixed (doc)** — no longer credited as a runtime control (see above); enforcement is tracked. |
| 7 | Low | Non-constant-time admin/memory-token compare | **Fixed** — constant-time comparison. |
| 8 | Low | A worker could post events onto jobs it doesn't lease | **Fixed** — event posting now requires the active lease. |
| 9 | Low | `start-local.ps1` defaulted to a third-party recovery remote | **Fixed** — recovery git target is opt-in; no default remote. |
| 10 | Low | Agent stdout/transcripts not secret-scrubbed | **Documented** — redaction is key-name based; agent stdout and the transcript artifact are stored/streamed verbatim to project-token holders. Don't print secrets from agents; treat transcripts as sensitive. Pattern-scrubbing tracked. |
| 11 | Info | Update-apply TOCTOU; ff-only still builds origin code on `--confirm` | **Documented** — mitigated by human confirm + ff-only + clean-tree; confirm the origin and reviewed commit before approving. Commit-hash pinning tracked. |
| 12 | Info | `FERRYMAN_SUDO_PW` visible in the script environment | **Documented** — convenience only; prefer interactive sudo. Piped via `printf`, never on a command line. |

Code fixes for #1/#3/#4/#7/#8/#9 shipped together and were verified (builds incl.
the Windows worker path, server tests green, functional checks: admin gate 401,
Host guard 403/200, no demo project). "Tracked" items are honest future work, not
silent gaps.

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
