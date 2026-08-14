# Production readiness plan

**Written:** 2026-08-13 (Friday) — for orchestrator review Monday.
**Branch:** `feat/portable-auth-v2` (all work below is committed there).

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
