# Fleet trust and readiness proposal

Status: product, CLI, API, and evidence contract for the dashboard Health Center
prototype. The current prototype uses synthetic metadata and does not run,
repair, revoke, or offboard anything.

## User outcome

A novice owner opens **Health** and gets a plain answer to four questions:

1. Can my team work safely right now?
2. What is degraded or unproved?
3. What exact repair should I perform, and what will it change?
4. Can I revoke a person or device without leaving authority behind?

An experienced operator can expand every check to inspect its signed evidence,
freshness, scope, source, and command-line equivalent.

## Trust levels

- `verified`: fresh measured evidence satisfies the check.
- `degraded`: work can continue with a stated limitation.
- `blocked`: the runtime must deny the affected operation.
- `unknown`: no sufficiently fresh evidence exists.
- `proposal`: the control is designed but not implemented.

Only `verified` renders green. Folder presence, configuration text, an estimate,
or a dashboard draft cannot produce `verified`.

## Health Center journey

The first screen shows an overall readiness decision and five grouped gates:

- **Identity and access** — signing/encryption identities, ownership, leases,
  revocation, approval independence;
- **Communications** — local delivery, Syncthing/shared path, private-Git
  fallback, acknowledgements, and return to the preferred path;
- **Agents and usage** — engine availability, current run, heartbeat freshness,
  governor decision, signed token and cost usage;
- **Recovery** — stale-run recovery, duplicate suppression, backup/restore,
  retention, and offboarding coverage;
- **Release trust** — platform matrix, artifact signature, SBOM, provenance,
  migration compatibility, canary, and rollback.

Selecting a failed gate opens an ordered repair plan. A repair entry shows:

- what Ferryman observed and when;
- what is affected;
- the exact command or dashboard action;
- whether the action is read-only, local mutation, remote mutation, or
  destructive;
- required authority and confirmation;
- success evidence and rollback instructions.

## Proposed CLI

```text
ferry doctor --workspace <path> --json
ferry agent status --comms <path> --json
ferry fleet prove --comms <path> --project <id> --json
ferry fleet prove --comms <path> --project <id> --exercise-failover --json
ferry health explain <check-id> --json
ferry health repair-plan <check-id> --json
ferry team offboard plan --human <name> --comms <path> --json
ferry team offboard apply --plan <file> --confirm <plan-digest> --json
ferry release verify <artifact-or-manifest> --json
```

`doctor`, `status`, `prove` without failover exercise, `explain`, repair-plan,
offboard-plan, and release-verify are read-only. A failover exercise may write a
clearly named synthetic message and signed receipt, but may not alter a real
task. Applying repairs or offboarding is separate, idempotent, and requires a
human confirmation tied to the exact plan digest.

## Proposed dashboard API

- `GET /api/health` — latest report and grouped gate summaries.
- `POST /api/health/runs` — start a bounded read-only evidence refresh.
- `GET /api/health/runs/{id}` — progress and per-check results.
- `GET /api/health/checks/{id}` — evidence, freshness, scope, and explanation.
- `POST /api/health/checks/{id}/repair-plan` — create a non-mutating plan.
- `POST /api/offboarding/plans` — enumerate all authority tied to one human.
- `POST /api/offboarding/plans/{id}/apply` — apply an unchanged confirmed plan.
- `GET /api/releases/{version}/evidence` — release verification bundle.

Starting a health run requires a signed-in operator. Repair plans require the
relevant scope. Applying a repair or offboarding plan requires an owner or a
separately authorized approver and an idempotency key. The server rejects a
plan if its digest, preconditions, roster, grant versions, or outstanding work
changed since review.

## Health report contract

Conceptual response:

```json
{
  "schema": "ferryman.health-report.v1",
  "report_id": "uuid",
  "project": "ferryman",
  "generated_at": "timestamp",
  "overall": "degraded",
  "source": "measured",
  "expires_at": "timestamp",
  "summary": {"verified": 14, "degraded": 2, "blocked": 1, "unknown": 3},
  "checks": [{
    "id": "communications.syncthing.peer",
    "group": "communications",
    "status": "degraded",
    "scope": {"machine": "devbox-01", "project": "ferryman"},
    "observed_at": "timestamp",
    "fresh_for_secs": 30,
    "evidence_source": "syncthing-bounded-probe",
    "evidence_digest": "sha256",
    "impact": "shared delivery unavailable; local queue remains active",
    "repair_id": "syncthing.peer.reconnect",
    "mutation": "external",
    "requires_confirmation": true
  }],
  "signature": "operator-or-machine-attestation"
}
```

Evidence digests let an operator correlate the report with local logs or signed
portable evidence without copying sensitive log contents into the dashboard.
Health reports contain no secret values, tokens, environment dumps, private
paths outside the selected workspace, or third-party response bodies.

## End-to-end fleet proof

The standard proof uses an isolated synthetic project task:

1. verify the human signing identity and published roster key;
2. verify the agent identity, owner policy, current lease, and engine command;
3. issue a clearly marked synthetic order with an idempotency key;
4. observe assignment, real claim, heartbeat, and governor decision;
5. receive a signed synthetic result plus measured usage receipt;
6. record a signed human review;
7. confirm acknowledgement and duplicate suppression;
8. verify the preferred transport and configured fallback without exposing
   credentials;
9. clean up only the synthetic proof artifacts under the normal retention rule.

The optional failover exercise deliberately disables only a test transport
adapter, never Syncthing or Git globally. It proves fallback and return using
the same synthetic idempotency key.

## Repair safety

Repairs are classified before execution:

| Class | Example | Default behavior |
|---|---|---|
| Read-only | recheck roster, engine, signature | run immediately |
| Local reversible | rewrite generated config from reviewed values | preview, confirm, backup |
| External reversible | reconnect Syncthing peer | preview, confirm, verify |
| Authority-changing | renew or revoke a lease | second review and signed audit |
| Destructive | delete data or remove a device | never bundled; separate explicit confirmation |

Ferryman must not convert a diagnostic into a mutation. A repair plan is safe to
share because it contains references and commands, not credential values.

## Offboarding contract

Offboarding discovers, but does not initially change:

- human signing and encryption keys, devices, and active sessions;
- personal agents owned by the human and business-agent grants held by them;
- repository, agent, secret, publishing, deployment, and spending leases;
- pending invitations, access requests, reviews, claims, and handoffs;
- Syncthing device/folder relationships and private-Git access references;
- secrets ever revealed, which require upstream rotation rather than a false
  claim of remote erasure.

The owner chooses transfer, suspend, revoke, rotate, or leave unchanged for each
item. The signed plan records those choices. Apply is resumable; partial failure
leaves a report that can be safely applied again.

## Proposed reliability objectives

These are initial targets to validate in soak tests, not current guarantees:

- zero lost accepted orders, results, reviews, grants, or revocations;
- zero duplicate externally visible side effects for one idempotency key;
- local delivery and acknowledgement p95 under 2 seconds;
- shared transport delivery p95 under 20 seconds at the default poll interval;
- private-Git fallback visible p95 under 120 seconds when configured;
- a dead run classified within two heartbeat windows plus one poll interval;
- restore point objective of the last acknowledged portable artifact;
- documented recovery time objective measured by the two-machine drill.

## Test and release matrix

Every release candidate runs:

1. schema/signature fixtures on Windows, WSL, Linux, and macOS;
2. invite-to-first-result and revoke-to-denial journeys;
3. two-machine local/shared/private-Git delivery and return;
4. offline, clock-skew, conflict, replay, process-death, disk-full, and
   interrupted-upgrade chaos scenarios;
5. backup restore, canary upgrade, rollback, and offboarding drills;
6. accessibility checks for keyboard navigation, names/roles, focus, contrast,
   status text independent of color, and narrow-screen layout;
7. secret scanning of portable artifacts, logs, browser payloads, and release
   bundles using synthetic canary credentials only.

The release evidence bundle records tool versions, platform, commit, fixture
digests, results, failures, waivers, SBOM, provenance, and artifact signatures.
No gate is green because a test was skipped.

## Prototype boundary

The dashboard prototype renders realistic gate, evidence, and repair metadata.
In demo mode, refresh and repair-plan actions update only in-memory presentation
state. In production mode they explain that the backend contract is not yet
connected. The prototype never changes system services, Syncthing, Git access,
leases, secrets, or files.

