# Novice experience after integration: status and backlog

Date: 2026-08-22
Author: programmer/Ox Alpha (independent whole-repository review, branch
`oxalpha/novice-onboarding`)
Scope: the state of the novice journey assuming both open branches land in
full - `oxalpha/novice-onboarding` (CLI onboarding) and
`codex/novice-dashboard-ux` (dashboard team model and invitations), including
every proposal each branch makes for follow-up work.

This complements [ROADMAP.md](../ROADMAP.md) and
[REPO_ROADMAP.md](../internal/REPO_ROADMAP.md); it is narrower - what a person or agent
new to Ferryman experiences from install to first accepted task - and dated,
because backlog priorities rot faster than architecture.

## What is already true once the two branches merge

Verified by building the merged tree (`oxalpha/integration-dashboard`,
merge of both branches plus reconciliation) and running its full test suite.

| Journey stage | Mechanism | State |
|---|---|---|
| Install `ferry` | curl/PowerShell scripts, checksum-verified, no toolchain | Shipped |
| Enable a project | `ferry enable`: non-interactive, idempotent, JSON, engine-aware args | This branch |
| Know it will work | `ferry doctor`: config, engine on PATH, key, roster, Syncthing | This branch |
| Point at an engine | `command`/`args` contracts; OpenCode/Codex written automatically; credentials via `credentials.json` | This branch |
| First task | `ferry channel order` → `agent run` → signed result | Shipped |
| Watch and approve | Channel CLI plus the redesigned dashboard (tasks, ledger, learnings, approve/send-back) | Dashboard branch |
| Human/agent distinction | Roster-backed `/api/team`; never calls an agent a teammate | Dashboard branch |
| Join a teammate | Invitation prototype (owner compose → recipient join) | Dashboard branch, **UI only** |
| Review lifecycle | `auto`/`confirm`/`off`, `ferry agent pending`, `ferry channel review` | Shipped |
| Second machine | Pair once in Syncthing (deliberately manual); `enable` shares folders | Shipped |
| Recovery | Continuity packs, two-machine drill, keys never synced | Shipped |
| Governance | Master declaration, grants, lease tokens, audit ledger | Shipped |

## What the project becomes if every open proposal also lands

If the invitation MVP sequence and the team-access backend contract are
implemented (signed invitation records, atomic acceptance, expiry/revocation,
preflight wired to the shipped `ferry doctor --json`, platform installers with
consent-gated command previews), then:

- **Two humans can onboard each other without a terminal tutorial.** An owner
  sends an invitation; the recipient installs, runs doctor, joins verified, and
  appears on the dashboard. Today that path requires manual Syncthing pairing
  plus hand-carried trust; invitations make it a guided flow.
- **Agents become first-class team members with scoped access** - personal
  agents owned by a teammate, business agents owned by the organization, each
  grant permission-scoped, duration-bounded, revocable, and audited.
- **The dashboard stops being a viewer** and becomes the control plane for
  team membership and agent access, with every action landing in the ledger.

That is a materially different product: a fleet coordinator that a non-expert
can grow from one machine to a small team unaided.

## Honest residual gaps (after everything above)

1. **Grant enforcement in a sync-based system is unsolved until specified.**
   Revocation propagates at sync speed; a machine that is offline keeps working
   under a revoked grant until it sees the revocation. Durable capability files
   are the wrong shape. The existing lease-token machinery - short-lived,
   renewable, expiring on its own - is the right primitive: a grant should be a
   lease the owner keeps renewing, so revocation is "stop renewing", not
   "chase copies".
2. **Money is still invisible.** Per-run token counts are recorded by nothing;
   `ferry cost project` and the spend tile read structurally zero. The moment
   business agents exist, spending authority exists, and usage attribution
   stops being cosmetic.
3. **Runtime state is the last blind spot.** Doctor proves the setup; nothing
   answers "why is the idle worker not claiming?" (paused? outside claim
   window? memory gate?) without reading local logs.
4. **The known-issues list ships with the project**: Claude `-p` aborts on
   substantial tasks, MCP client has no timeouts, addressed orders read as
   claimed before anyone starts, macOS CI is red.
5. **The dashboard redesign is dark-only and carries almost no ARIA** (one
   attribute in the file). Keyboard reachability and responsiveness were QA'd;
   screen-reader semantics and light-theme were not.
6. **Terminology drift persists**: bridge/channel/attachment/communications,
   and server-mode docs beside channel-mode docs. Labeled now, not unified.

## Backlog

### P0 - do before inviting real teams

- **Specify grants as renewable leases**, reusing master/lease machinery;
  define offline-revocation semantics in THREAT_MODEL.md before writing the
  enforcement code. (Blocks the entire invitation value proposition.)
- **Record per-run token usage** on the signed result; feed `ferry cost
  project`, the dashboard, and any business-agent spending limit from it.
- **`ferry agent status`**: heartbeat age, current claim, governor decline
  reasons (paused, window closed, memory), next poll - one command, JSON flag,
  and a deep-link target for the dashboard machine rows.

### P1 - quality of the same journey

- Accessibility pass on the redesigned dashboard: light theme via
  `prefers-color-scheme`, ARIA roles/labels for tabs, tables, icon buttons,
  text labels beside every color-coded state.
- `ferry doctor --live`: opt-in smoke task with an explicit cost disclosure,
  proving engine auth works, not just that the binary exists.
- WSL trap made explicit: when `command` resolves into `/mnt/c/...`, warn that
  a Linux worker cannot use the Windows install.
- Invitation end-to-end tests including expired/revoked-offline scenarios.
- MCP client timeouts (small fix, listed risk today).
- Distinguish "assigned, nobody started" from "running" for addressed orders.

### P2 - polish and reach

- Platform installers (winget/brew) with checksums and consent previews, per
  the invitation proposal.
- One glossary page fixing vocabulary; sweep new code of "bridge" for the
  channel sense.
- A worked multi-machine example project (the report-project example is
  single-machine).
- macOS test-suite triage - blocked on someone with a Mac.
- Dashboard: local-only live tail of `ferry log` for the selected machine.
