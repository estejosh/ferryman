# Ferryman A+++++ implementation plan

Status: implementation proposal. This document sequences accepted product
proposals into enforceable, testable release work. It does not claim that the
described controls are live.

## Outcome

Ferryman should let a novice owner invite people, install and share agents,
transport recipient-bound secrets, coordinate work across machines, and recover
from failures without needing to understand its internal transport. Advanced
operators should be able to inspect the evidence behind every green status.

The quality bar is **proof-complete**, not feature-complete:

- a dashboard badge never substitutes for runtime authorization;
- a directory on disk never substitutes for an end-to-end delivery proof;
- an estimate never appears as measured usage;
- a delivery receipt never substitutes for recipient acceptance;
- a successful upgrade never substitutes for a tested rollback;
- revoking a durable file is never presented as revoking an offline copy.

## Accepted inputs and dependencies

This plan assumes the following work lands before production enforcement:

1. the novice onboarding and engine-aware `ferry doctor --json` work;
2. the human teammate, agent ownership, invitation, and Vault proposals;
3. ADR 0013's shared renewable-lease primitive;
4. signed per-run usage recording and live agent status;
5. the recipient-bound secret transport security contract.

ADR 0013 and the threat-model update are hard dependencies. Agent and secret
grants must use the same renewable lifetime shape so an offline recipient loses
authority by failing to renew rather than by pretending a copied capability was
deleted remotely.

## Architecture

```text
dashboard / CLI
       |
       v
signed intent + read-only evidence APIs
       |
       v
channel schemas: leases, receipts, revocations, usage, health evidence
       |
       v
runtime enforcement: agent runner, delivery engine, use-only broker
       |
       v
local filesystem -> Syncthing/shared -> private-Git fallback
```

The portable channel carries signed policy, evidence, receipts, and ciphertext.
Private keys, decrypted secrets, dashboard session tokens, provider credentials,
and runtime state remain outside the portable channel.

## Build sequence

### Phase 0 — freeze the truth model

- Land ADR 0013 and update `docs/THREAT_MODEL.md` before wiring grants into a
  production path.
- Define canonical meanings for `assigned`, `claimed`, `running`, `blocked`,
  `waiting_for_approval`, `awaiting_review`, and terminal states.
- Mark every dashboard datum as `measured`, `verified`, `estimated`, `unknown`,
  or `proposal`.
- Add schema versions and signature fixtures before implementing consumers.

Exit gate: two independent implementations verify the same golden signatures,
expiry decisions, replay decisions, and state transitions.

### Phase 1 — signed evidence layer

Add versioned portable records in `ferryman-channel`:

- `CapabilityLease`: issuer, subject human, optional agent, project, operations,
  issued time, renewal deadline, maximum lifetime, version, and policy digest;
- `LeaseRenewal` and `LeaseRevocation`;
- `RunUsageReceipt`: task, revision, run, engine, provider, prompt/completion/
  reasoning tokens, price-table version, measured or estimated source, signer;
- `AgentHeartbeat` and derived `AgentStatus` with last progress, current task,
  run id, governor decision, and reason;
- `HealthEvidence`: check id, scope, observed time, source, status, evidence
  digest, expiry, and repair id;
- `OffboardingPlan`: enumerated revocations with preconditions and dry-run hash.

Do not put secret values, environment snapshots, authorization headers, prompt
transcripts, or raw third-party tool responses into these records.

Exit gate: round-trip, invalid-signature, wrong-recipient, expiry, replay,
clock-skew, downgrade, and unknown-schema tests pass on every supported OS.

### Phase 2 — enforce least privilege

- Add one authorization decision function used by task addressing, agent
  messaging, handoff, repository operations, and the use-only broker.
- Require a current lease at the point of use, not only when the dashboard
  creates a grant.
- Fail closed on unknown issuer, wrong subject, wrong project, wrong agent,
  disallowed operation, expiry, missing renewal, revocation, replay, or policy
  digest mismatch.
- Keep human signing and encryption keys separate.
- Default secret grants to use-only. Reveal requires an explicit, separately
  audited exception and explains that upstream rotation is then required.
- Default workers to the strongest supported sandbox. Bare execution shows an
  explicit policy exception, scope, owner, and expiry.

Exit gate: adversarial tests cannot turn a dashboard draft, stale capability,
copied envelope, agent grant, or unrelated repository grant into authority.

### Phase 3 — prove the fleet

- Keep `ferry doctor --json` as the setup/readiness check.
- Add `ferry agent status --json` for live work and governor reasons.
- Add `ferry fleet prove --json` for an end-to-end signed test covering identity,
  seat, engine, task, result, review, and transport recovery.
- Add the dashboard Health Center proposed in
  `docs/FLEET_TRUST_AND_READINESS_PROPOSAL.md`.
- Every failed check returns a stable repair id, explanation, safe command
  preview, whether the repair mutates state, and whether human confirmation is
  required.

Exit gate: a novice can start from an invitation and reach a verified signed
result, then offboard the identity, using only the guided journey.

### Phase 4 — measure reliability

- Publish service-level objectives for delivery, acknowledgement, duplicates,
  lost accepted artifacts, stale-run recovery, and restore time.
- Add chaos scenarios for an offline peer, stopped Syncthing, slow or failed Git
  helper, conflict files, clock skew, duplicate delivery, revoked keys, process
  death, power loss, disk full, and interrupted upgrade.
- Add bounded retention and compaction for messages, replay ledgers,
  trajectories, transcripts, heartbeats, usage receipts, and Git checkpoints.
- Make migrations resumable and idempotent, with a preflight, dry-run, backup,
  compatibility window, and rollback rehearsal.

Exit gate: the release candidate meets the SLOs in a two-machine soak and loses
zero accepted artifacts in the fault matrix.

### Phase 5 — release and lifecycle trust

- Test Windows, WSL, Linux, and macOS on real machines, not only path-unit tests.
- Produce signed, reproducible artifacts, complete SBOMs including optional tray
  components, dependency/license/secret scan results, and provenance metadata.
- Stage upgrades through canary machines and prove rollback plus backup restore.
- Implement one dry-run-first offboarding plan that covers the human identity,
  devices, agent grants, secret grants, leases, Syncthing folder access, Git
  access, and outstanding work.
- Require a public quickstart proof from a clean machine as a release gate.

Exit gate: an operator can verify the artifact, upgrade one canary, roll it back,
restore a backup, and remove a teammate without orphaned authority.

## Work packages

| ID | Deliverable | Primary area | Required acceptance evidence |
|---|---|---|---|
| T1 | Lease and revocation schemas | `ferryman-channel` | Golden vectors, expiry/replay/downgrade tests |
| T2 | Unified authorization decision | `ferryman-ops` | Denial matrix at every point of use |
| T3 | Per-run usage receipts | agent runner + channel | Provider fixtures; measured/estimated separation |
| T4 | Live agent status | agent runner + CLI | Heartbeat, stale, blocked, approval, recovery tests |
| T5 | Local encrypted vault | CLI/OS integration | Key rotation, locked-vault, permissions, recovery tests |
| T6 | Use-only broker and Git helper | `ferryman-ops` | Repo/agent/purpose isolation and redaction tests |
| T7 | Fleet evidence API and Health Center | server/dashboard | Contract tests and novice end-to-end journey |
| T8 | Chaos, SLO, and retention harness | channel/ops | Two-machine fault report and bounded-store proof |
| T9 | Offboarding planner | CLI/server/channel | Dry-run hash, partial-failure resume, complete revocation |
| T10 | Release evidence bundle | release tooling | Reproducibility, SBOM, provenance, rollback, restore |

T1, the threat-model update, and ADR 0013 precede T2, T5, and T6. T3 and T4
can proceed in parallel. T7 consumes T1, T3, and T4 but must label unavailable
evidence honestly while those packages are incomplete. T8 gates T9 and T10.

## Product contracts

### Dashboard

- **Health** answers “Can my team safely work right now?” before showing
  implementation detail.
- Each status includes scope, freshness, evidence source, and a repair action.
- Red means work is denied or unsafe; amber means degraded or incomplete; gray
  means unmeasured; green requires fresh evidence.
- Repair actions preview commands and side effects. Mutations require explicit
  confirmation and produce signed audit events.
- Offboarding starts with a dry-run plan and never silently deletes local data.

### CLI

Every dashboard operation has a machine-readable CLI contract. JSON is a
versioned API, not formatted prose. Commands never accept secret values as
positional arguments and never print secret contents.

### API

Read endpoints return evidence plus freshness. Write endpoints require an
authenticated human identity, an idempotency key, scope-specific authority,
and a signed result or refusal. Unknown and stale authority fails closed.

## Explicit non-goals until the gates pass

- PostgreSQL migration;
- a public marketplace;
- general workflow graphs;
- wildcard human or secret grants;
- automatic publishing, deployment, spending, or legal acceptance;
- claiming protection from a malicious process outside the enforced sandbox.

These may become valuable later, but they add breadth before Ferryman has proved
its core trust claims.

## Definition of A+++++

Ferryman earns this label only when all five release gates—runtime enforcement,
fleet proof, measured reliability, truthful telemetry, and release/lifecycle
trust—have reproducible evidence attached to a release. Proposal screens and
unit tests alone are insufficient.

