# Production readiness plan

**Written:** 2026-08-13 (Friday) — for orchestrator review Monday.
**Last updated:** 2026-08-14 (end of session).
**Branches (dependency order):** `feat/portable-auth-v2` → `feat/groundcrew-borrows` → `feat/always-on-fleet` → `feat/learn-and-observe` → `feat/skills` → `feat/ready-hardening`.

This is the single source of truth for what it takes to reach production/live
status. When an item changes, update this file — not the chat.

---

## 0. Correct the framing (do this first)

`docs/PUBLIC_RELEASE_PLAN.md` and the July review call this a
**"local single-node preview."** That is wrong and it has been wrong for a
while. Ferryman is a **multi-machine, multi-agent team coordination system**:

- Syncthing-carried shared channel + private-Git backstop,
- signed portable messages with replay protection and a trust store,
- an append-only attribution ledger,
- a master operator with signed grants and delegation,
- shared project memory.

Correct label: **"self-hosted, local-first team coordination — reference
implementation."** Fix it in `PUBLIC_RELEASE_PLAN.md`, `THREAT_MODEL.md`, the
repository banner, and the README.

---

## 1. Done this cycle

- **Signed v2 portable messages** — Ed25519 over RFC 8785 canonical JSON, domain
  separation, trust store, `key_version` + revocation, replay ledger (with
  atomic save + per-project lock).
- **Attribution ledger** — append-only, hash-chained, signed; git-backstopped.
- **Full-channel git backstop** — every portable file (tasks, ledger) snapshots
  to private Git on each ledger append, so a Syncthing deletion is recoverable.
- **Team memory** — project memory bank (Syncthing-synced, gitignored, with a
  `README.md` review order) + the agent-memory tier defined.
- **Master model** — explicit `ferry enable --master`, signed declaration in the
  shared channel, disclaim/transfer, master-signed member grants.
- **Team-awareness + enforcement** — `integration_mode` read; `grants =
  "required"` gates the agent loop on master grants; `grants = "open"` (default)
  is full permissions.

---

## 1.5 Session-2 status (2026-08-14)

One session added five feature branches and three production blockers:

- **Built:** pluggable runner (`none`/`podman`/`docker` + `net=` egress policy),
  task sources, worktree-per-task, interrupt mode, always-on triggers, result
  contracts, learning DB + `ferry bench`/`ferry channel stats`, OTLP export,
  `SKILL.md` skills, repo roadmap.
- **Ready blockers done this session:** B1's sandbox half (runner) and
  independent approval (`requires_approval`, no self-approval), B5 (git
  subprocess secret sweep), B7 (label fix).
- **Still open:** B3 (worker credential separation), B4 (distributed message
  claims), B6 (release checklist).

### B4 — distributed message claims: deferred with a design note

`claim_message_v2` writes its processed-marker to the machine-local
`attachment/runtime/processed`. Fixing the double-claim needs the marker moved
into the synced channel, keyed per recipient. This is subtle because a message
to `all` must be processed once *per machine*, whereas a message to a named
agent must be processed once *total* — the claim model differs by recipient
class. This needs an orchestrator decision on broadcast semantics before the
change; documented rather than rushed, because the adjacent code is
replay-protection-critical.

### Next build sequence ("better", agreed 2026-08-14)

1. Plan/spec artifact + dependency DAG.
2. Session trajectory capture/replay (kept in channel memory).
3. Credential injection (runner).
4. Native event adapters (GitHub/Linear/webhook).
5. Eval scorer command.
6. Web dashboard.
7. Cost/token accounting + reduction suggestions.
8. BYO-key manager (easy key insertion, no `.env` hand-editing).
9. At-rest/payload encryption.
10. Cross-project master console + memory.
11. hone integration (marketplace/orchestration) — see `docs/HONE_INTEGRATION.md`.

---

## 2. Remaining blockers, prioritized

### B1 — Worker sandboxing + independent approval (CRITICAL)

**Status (2026-08-13):** the container-sandbox layer is implemented — set
`sandbox = "<image>"` in `agent.toml` (or `ferry enable --sandbox <image>`) and
the agent CLI runs inside it: `podman run --rm -v <workspace>:/workspace:Z -w
/workspace <image> <command>`. Empty `sandbox` (default) runs bare. Image
curation/maintenance is requested from the community in
[issue #8](https://github.com/estejosh/ferryman/issues/8), reviewed before any
merge. Remaining: the per-platform bind-mount wrinkles (SELinux/macOS/WSL),
independent approval, and credential separation (B3).

**Problem.** The reference worker runs a coding agent (`claude`/etc.) with the
full privileges of its OS user. One bad or malicious prompt is machine-wide
damage. This is the last thing standing between "works" and "safe to run on
real work."

**Proposed fix (four layers, not one):**

1. **Dedicated unprivileged account.** Run the worker under its own OS user (or
   a container/VM) that can reach only the project workspace and a scoped
   credential set — never the operator, memory-write, recovery, or repository
   credentials.
2. **Sandbox the agent CLI.** Wrap the spawned coding agent in a sandbox with a
   filesystem allowlist (the workspace only) and a network policy:
   Linux → containers / `firejail` / `bubblewrap`; macOS → `sandbox-exec`;
   Windows → Job Objects / AppContainer.
3. **Independent approval authority.** For `requires_approval` work, the approve
   decision comes from a *separate* principal — the master/human via the channel
   — never the agent that did the work. The agent can propose, not self-approve.
4. **Credential separation** (B3 below) so the worker holds only short-lived,
   scoped leases.

This is the hardest item because it is OS-level and platform-specific, not just
Rust. It needs an operator decision (container vs. dedicated user vs.
sandbox-exec) per platform.

### B2 — Merge `feat/portable-auth-v2` → `main`

The orchestrator decides this Monday. Everything above is on the branch and
green; nothing in `main` carries the signed-message/ledger/master work until
the merge.

### B3 — Worker credential separation, with a full-permissions opt-in

Default: workers get short-lived, scoped lease tokens (not operator/project
tokens). **Explicit requirement:** a user must be able to opt into full
permissions for their own projects — that is already the shape of the model
(`grants = "open"` = full permissions; `grants = "required"` = master-gated).
The lease-token mechanism itself (short-lived, scoped, minted by the master)
is still to be built on top.

### B4 — Distributed *message* claims

Order/work claims already use the optimistic-claim + deterministic-winner model.
The portable *message* claims (`claim_message_v2`) are still machine-local, so
two machines can double-claim a message. Fix: apply the same model — write the
claim into the synced channel, oldest-claim-wins with a name tiebreak, and the
loser backs off. (This is the "merge is being requested" item: no, it is not
about the branch merge — it is about making message claims distributed, same as
order claims already are.)

### B5 — Finish git subprocess secret isolation

Already scrubs known sensitive env vars; finish the *strict allowlist* so a
project-local git hook cannot inherit anything it was not given.

### B6 — Public-surface release checklist

From `PUBLIC_RELEASE_PLAN.md`, still open: a real security-reporting path,
startup production-config validation, black-box HTTP integration tests, OpenAPI
completion, dependency/secret/license scans + SBOM in CI.

### B7 — Label + docs

Carried from section 0: fix the "single-node" framing everywhere.

---

## 3. Decisions the orchestrator needs to make Monday

1. **Merge timing** — approve `feat/portable-auth-v2` → `main` (B2).
2. **Sandbox mechanism per platform** — container vs. dedicated user vs.
   `sandbox-exec`/Job Object (B1).
3. **Token model** — confirm: default BYO (each member's own key) + optional
   master-provisioned pool; jobs shared, secrets not (this is the "share tokens
   vs jobs" question).
4. **Full-permissions default** — confirm `grants = "open"` is the default and
   `required` is opt-in (already implemented).

---

## 4. Recommended sequence (Monday onward)

1. Orchestrator reviews + merges `feat/portable-auth-v2` (B2).
2. Worker sandboxing + independent approval (B1) — the real safety gate.
3. Distributed message claims (B4).
4. Worker credential separation with full-permissions opt-in (B3).
5. Git subprocess allowlist (B5).
6. Release checklist + label fix (B6, B7).

---

## Product roadmap (agreed 2026-08-13)

Decisions from the "what would make it compelling" review, in build order.

1. **Signed audit report** — BUILT (`ferry channel report`, commit `61989be`).
   Signed, standalone, per-entry verification; JSON or human-readable.
2. **Web dashboard** — build. Users are uncomfortable with a CLI; this is the
   biggest usability unlock. Ledger, tasks, memory in one pane.
3. **Cost/token accounting + reduction suggestions** — analysis of token usage
   with suggestions to reduce (route selection to cheaper models). Reference
   tools mentioned: omniroute/caveman, ponytail.
4. **Multi-provider BYO-key manager** — per-agent keys, vendor independence.
5. **At-rest / app-level payload encryption** — Syncthing already encrypts in
   transit; the gap is at-rest. Use Syncthing "Receive Encrypted" for offsite
   backup devices, plus per-project payload encryption (master mints the key,
   shares it encrypted to members' device keys — ADR 0009 applied to content).
6. **Cross-project master console + master memory** — one view over every
   project the master runs, with persistent cross-project memory so the master
   does not restart context per project.
7. **Multi-messenger approval + 2FA** — keep Telegram; plan for other
   messengers (Signal, etc.); a "confirm on a second channel" 2FA mode
   (issue on Telegram, confirm on Signal).
8. **Agent/memory marketplace via hone** — hone hosts the marketplace;
   consider a "memory marketplace" (expert context from other work).
9. **Autonomous orchestrator** — the long-term goal; build towards full
   integration into hone. Must remain human-gated for destructive work.

---

## Competitor learnings → build plan (groundcrew/ClipboardHealth)

Reviewed `ClipboardHealth/groundcrew` and `prolego-team/groundcrew`
(`memory-bank/competitors.md`). Four borrows, planned:

1. **Pluggable runner abstraction.** Generalize the current `sandbox=<image>`
   into `local.runner` with `none` (bare) / `podman:<image>` / `docker:<image>`
   and per-platform auto-resolution (Linux→podman, macOS/Windows→docker or a
   native sandbox). Keep the "none" escape hatch + a network-egress allowlist.
   First step: rename/extend `AgentConfig.sandbox` into a `runner` enum.
2. **Task-source adapters.** Add pluggable task sources (Linear, Jira, custom
   shell) that map external tickets into signed orders. Reuses the adapter
   definition pattern from groundcrew; Ferryman's value-add is that the imported
   ticket becomes a signed order with a ledger entry.
3. **Worktree-per-task, made better.** Borrow groundcrew's `git worktree` per
   task, but tie it to our trust model: the worktree branch derives from the
   signed order id + agent (deterministic, idempotent re-dispatch), the worktree
   is recorded in the attribution ledger, and the signed result carries the
   worktree HEAD so a reviewer can verify the work matches the commit. Cleanup
   (teardown of worktree + branch) is a ledger-recorded, idempotent operation.
4. **Interrupt mode.** Today the Telegram gate approves/denies *parked* work;
   groundcrew lets you take over a *running* agent. Add an interrupt path — a
   signed "interrupt/pause/steer/kill" order that the worker honors between its
   poll ticks, surfaced through Telegram and `ferry`. This is the missing
   analogue of groundcrew's live terminals.

### Status (2026-08-14): all four built on `feat/groundcrew-borrows`

1. Runner abstraction — `agent::Runner` (`Bare`/`Podman`/`Docker`), `sandbox`
   config now accepts `none`/`podman:IMG`/`docker:IMG`/`IMG` (legacy podman).
2. Task sources — `channel::source` (`TaskSource::Shell` → signed orders),
   `ferry channel source`.
3. Worktree-per-task — `channel::worktree` + `AgentConfig.worktree`; branch
   derives from signed order + agent; head signed into the result.
4. Interrupt mode — `channel::interrupt` (kill/pause/steer, signed, acked),
   honored in `do_work`, `ferry channel interrupt`.

## Broader competitive research → analysis and outcome

A parallel agent reviewed 11 adjacent projects (`memory-bank/competitive-research.md`).
Seven upgrades were assessed; two were built, five deferred.

### Built (materially better, and self-contained)

1. **Always-on triggers** (research #2) — the gap between Ferryman and an
   "always-on fleet." `sources.toml` lists sources; `ferry agent` now re-polls
   them on their interval and imports new tickets as signed orders, and
   `ferry channel watch`/`sources` give a standalone path. Intervals survive
   restarts via a last-import marker; imports are race-tolerant and idempotent.
2. **Result contracts** (research #4) — an order can `--require` top-level keys
   in its result. The contract is signed into the order (backward-compatible:
   no contract → identical signature bytes), `ferry channel tasks` flags
   missing keys, and `ferry channel review --accept` refuses malformed
   deliverables mechanically.

### Deferred (assessed, not built this cycle)

3. **MCP providers** — real leverage, but needs an external MCP crate (none in
   the dependency tree) and a trust decision on arbitrary MCP servers. Blocked
   on a dependency/architecture decision, not effort.
4. **Approval-mode ladder** — Ferryman already has `review = auto|confirm|off`
   and, with the runner, `none|podman|docker`. The finer edit-permission ladder
   belongs in the runner; no separate build this cycle.
5. **Worker eval harness** — a separate project (dataset curation + scoring),
   not a feature to bolt on. Roadmap, not this branch.
6. **OTLP trace/metrics** — needs an OTLP dependency + a collector. The ledger
   already answers *attribution*; trace observability is a later, larger piece.
7. **Repo-map pre-context** — most agent CLIs build this themselves; marginal
   for a provider-neutral shell wrapper. Lowest priority.

---



## 5. Quick answers to the questions asked Friday

- **"Assuming all changes pass muster, are we ready?"** — The coordination and
  identity layer is ready (signed messages, replay, attribution, master/grants,
  memory). The *execution-safety* layer is not: B1 (sandboxing), B3 (credential
  separation), and B4 (distributed message claims) are the remaining gaps. So:
  ready as a team-coordination product; not yet safe to run untrusted work on
  machines you care about.
- **"You still have not fixed sandboxing?"** — Correct, and it is deliberate
  scope: it is OS-level and platform-specific, and it needs an operator decision
  (container vs. dedicated user). The fix is fully specified in B1 above.
- **"Single node? That is not what we built."** — Agreed; the label was
  inherited and wrong. See section 0.
- **"Merge is being requested?"** — B2 (the branch merge) is the orchestrator's
  call; B4 (distributed message claims) is a code change, not a merge request.
