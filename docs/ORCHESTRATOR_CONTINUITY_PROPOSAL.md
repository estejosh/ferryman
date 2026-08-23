# Orchestrator continuity and safe failover

**Status:** Proposed for owner and primary-orchestrator decision  
**Prepared:** 2026-08-23  
**Decision target:** Monday, 2026-08-24  
**Scope:** Native Ferryman channel, worker, Telegram, policy, and dashboard behavior

## Decision requested

Make continuity a Ferryman protocol guarantee:

> When the primary orchestrator cannot run, Ferryman keeps the request moving with one
> eligible agent. It executes only when that agent already has every required permission.
> Otherwise it produces a signed proposal for an authorized agent or human. Ferryman never
> solves availability by impersonating the primary, copying its credentials, spending outside
> an existing budget, or duplicating a side effect.

This is deliberately broader than a configured backup CLI. The eligible pool can contain any
currently available agent seated in the project, including human-owned agents that opted in and
permanent business agents. Proposal-only continuity is the safe common denominator.

## Why the current behavior stops

Ferryman already fails over communications transport, but not the actor that interprets or works
on a request.

- `AgentConfig` names one command and one model.
- The Telegram map names one orchestrator. When it exists, new operator messages are addressed to
  that identity rather than the general worker pool.
- An addressed order is visible only to its assignee.
- Engine failures have text detail but no structured failure class or retry time.
- After five failed attempts the worker intentionally keeps the task claimed. This prevents a bad
  order from thrashing through every machine, but it also holds a good task when the local model
  subscription or token allowance is exhausted.
- A signed pause or kill can release work, but only after a deliberate operator action.

The missing primitive is not another retry. It is a safe, auditable distinction between **this
agent cannot run now** and **this task cannot run anywhere**.

## Product invariant

For every accepted user request, the dashboard and channel must eventually show exactly one of:

1. **Executing** — one execution-eligible agent owns a fenced task lease.
2. **Proposal in progress** — one proposal-eligible agent is preparing a non-terminal handoff.
3. **Waiting for primary** — retry time is known and policy says not to fail over.
4. **Blocked** — there is no eligible agent, budget, permission, or safe handoff point, with an
   exact remedy shown.

“Claimed forever with no next action” is not an allowed continuity state.

## Permission model

Failover changes who may be selected; it does not broaden what that identity may do.

### Execution eligible

An agent may execute a failed-over task only when all of these are true:

- it is seated in the same project channel with a valid signing identity;
- its owner has opted the agent into continuity for this project;
- any cross-human use has an active owner-approved lease;
- it has active grants for the task role, repository, tools, and each required secret;
- its engine readiness heartbeat is current;
- its existing spend policy permits the run; and
- the task is at a safe handoff point with no unresolved non-idempotent side effect.

Credentials remain recipient-bound. A substitute uses its own credentials and grants. Ferryman
must never copy, reveal, mount, or inject the primary's credentials into a substitute.

### Proposal eligible

A seated agent may opt into proposal-only continuity without receiving execution authority. It
gets the task brief and channel context it was already permitted to read, but no new repository,
tool, or secret grant. Its output is a signed `ContinuityProposal`, not a task result:

- it does not mark the task done;
- it does not satisfy dependencies;
- it cannot approve itself;
- it records the agent, owner, engine/model, evidence used, assumptions, and unresolved approvals;
- an authorized human or agent may later adopt it as the plan for execution.

This lets Ferryman preserve momentum even when every available agent is proposal-only, without
turning a suggestion into an authorization bypass.

## Native protocol design

### 1. Signed continuity policy

Add a versioned, owner-signed policy to the channel rather than relying on local convention:

```json
{
  "schema": "ferryman.continuity-policy/v1",
  "primary": "beastly",
  "candidate_pool": "project",
  "mode": "execute-when-authorized-else-propose",
  "quota_grace_secs": 0,
  "offline_grace_secs": 60,
  "unknown_failure_grace_secs": 300,
  "parallel_proposals": 1,
  "failback_healthy_checks": 2,
  "signed_by": "owner"
}
```

The policy contains no credentials. A fleet-wide template may supply defaults, but each project
receives its own signed effective policy so one project cannot disclose work to agents in another.

### 2. Structured availability and failure evidence

The worker writes a signed, secret-free availability record for its own identity:

```json
{
  "schema": "ferryman.agent-availability/v1",
  "agent": "beastly",
  "state": "quota_exhausted",
  "scope": "engine",
  "failure_class": "provider_capacity",
  "retry_after": "2026-08-24T07:00:00Z",
  "task_phase": "before_execution",
  "safe_to_handoff": true,
  "observed_at": "2026-08-23T18:00:00Z",
  "expires_at": "2026-08-23T18:02:00Z"
}
```

Agent adapters should receive a `FERRYMAN_STATUS_FILE` path and write a machine-readable failure
envelope. Ferryman may ship conservative adapters for known CLIs, but output-string matching must
not be the authority for a destructive handoff. Missing or unrecognized evidence is `unknown`.

Failure classes:

| Class | Default action |
|---|---|
| Confirmed quota exhaustion or long provider rate limit | Immediate continuity election |
| Engine process unavailable before execution | Elect another execution-eligible agent |
| Host offline after heartbeat grace | Elect under a new fenced lease epoch |
| Unknown engine failure | Proposal-only after grace; do not execute elsewhere automatically |
| Task/test failure | Keep with task; do not walk it through the fleet |
| Policy denial, missing approval, or revoked grant | Block and show the required approval |
| Possible side effect with no checkpoint | Block execution; proposal-only is allowed |

### 3. Deterministic election and fenced leases

The owner-signed policy pre-authorizes an election; no unavailable orchestrator needs to sign the
handoff. Eligible candidates are ordered deterministically by:

1. permanent business agent explicitly preferred for this project;
2. execution eligibility;
3. proposal eligibility;
4. task capability match;
5. lower allowed cost;
6. stable agent-name tie-break.

Only the first candidate attempts a renewable continuity lease. The lease has an epoch/fencing
term, expiry, selected mode, task ID, and evidence digest. Every result or proposal records that
term. A stale primary or loser in a race cannot submit under an old term.

This should reuse the renewable grant/lease primitive rather than invent a second clock and
signature model. Existing permanent claim files become historical evidence; active ownership is
the unexpired fenced lease.

### 4. Handoff rules

- **New or merely offered work:** elect immediately when a qualifying primary failure exists.
- **Claimed but engine failed before execution:** the live worker records evidence and releases its
  own claim; the elected agent receives the next lease.
- **In progress with a safe checkpoint:** persist branch/commit, proposal/context digest, and phase;
  then hand off under a new term.
- **In progress with an unknown side effect:** do not run a second executor. A substitute may draft
  a recovery proposal while a human resolves the side effect.
- **Primary returns:** it takes only new work after healthy-check hysteresis. The substitute finishes
  work already leased to it.

### 5. Telegram and request routing

Replace the single effective `[orchestrator]` destination with a continuity service resolved from
the signed policy. Telegram still files one immutable request, but the current lease holder receives
it. The sender sees an immediate status update such as:

> Primary is quota-limited until 07:00 UTC. `openrouter-ox-alpha` is preparing a proposal. No
> repository or secret access was added.

The request origin remains attached so the final result returns to the correct topic.

### 6. Dashboard

Add a **Continuity** panel to Team/Health:

- primary status, failure class, reset time, and last healthy evidence;
- policy mode: Off / Proposal only / Execute when already authorized;
- eligible agents grouped as execution, proposal-only, awaiting permission, unavailable;
- human owner, business/shared status, engine/model, cost policy, and lease expiry per agent;
- active failover term, selected agent, work phase, and why it was selected;
- immediate failover/failback notifications and an immutable event timeline;
- controls to opt an agent in, prefer a business agent, pause continuity, or require approval for a
  work class;
- honest task labels: `Primary`, `Failed over`, `Proposal only`, `Waiting for permission`, `Blocked`.

The invite/install flow should ask whether a human-owned agent may be used for proposal, execution,
or both, and for temporary, renewable long-term, or permanent-business scope. No dashboard toggle
is effective until its signed grant or lease is present in the channel.

## Code changes

The design must land in protocol and runtime code, with the dashboard as a view/control surface:

1. `ferryman-channel`
   - add signed `ContinuityPolicy`, `AgentAvailability`, `AttemptFailure`,
     `ContinuityLease`, and `ContinuityProposal` records;
   - calculate effective availability, eligibility, election, lease term, and task state;
   - make proposal records non-terminal and dependency-neutral;
   - validate signatures, expiry, owner consent, grants, and fencing terms.
2. `ferryman-ops`
   - replace the in-memory, untyped terminal retry outcome with persisted attempt evidence;
   - let a worker release its own claim only for a failover-eligible, pre-execution failure;
   - run elected proposal mode in a restricted prompt/tool envelope;
   - check grants, secrets, cost, lease term, and task phase again at point of use.
3. `ferryman-cli`
   - add `ferry continuity status`, `policy`, `opt-in`, `pause`, and `test` commands;
   - extend `ferry agent status --json` with readiness and retry evidence;
   - teach Telegram routing to target the active continuity lease rather than one static identity.
4. `ferryman-server` dashboard/API
   - expose evidence and policy without secret material;
   - stage policy changes, then require the correct owner/master signature;
   - show execution versus proposal authority explicitly.
5. Agent adapter contract
   - document stable failure codes and the status-file envelope;
   - provide conformance fixtures for quota, rate limit, auth, timeout, task failure, and unknown.

## Verification gates

The feature is not complete until automated tests prove:

- a primary quota failure before execution releases once and one eligible substitute continues;
- an addressed orchestrator request becomes visible only to the elected substitute;
- a malformed task does not circulate through the fleet;
- unknown failure produces at most one proposal and no second executor;
- proposal-only work cannot finish a task, satisfy a dependency, use an ungranted secret, or mutate
  a repository;
- a cross-human agent is ineligible without its owner's active consent lease;
- permanent business agents work only within their published project/tool/secret scope;
- engine, repository, tool, secret, and spend checks fail closed at point of use;
- a clock-skewed or stale agent cannot act under an old fencing term;
- primary recovery does not preempt or duplicate the substitute's in-flight work;
- zero eligible agents produces a visible blocked state and exact remedy;
- Windows, WSL, Linux, Syncthing delay, process crash, and restart preserve the decision record.

A release drill should exhaust a test primary's quota, observe failover, receive a signed proposal or
result, restore the primary, and verify clean failback end to end.

## Owner questions for Monday

Recommended defaults are included so the implementation can proceed with short answers.

1. **Trigger:** Fail over immediately on signed quota exhaustion; after 60 seconds for missed
   heartbeats; after five minutes in proposal-only mode for unknown engine failures. Accept?
2. **Candidate pool:** Consider every available agent seated in that project, but require an agent
   owner opt-in for cross-human use; prefer a permanent business agent when one exists. Accept?
3. **Execution boundary:** Execute automatically only before side effects and only with every active
   repo/tool/secret/spend grant; otherwise create a proposal. Accept?
4. **Proposal boundary:** A proposal may use only already-readable context, cannot mutate or mark the
   task done, and needs later adoption by an authorized actor. Accept?
5. **Concurrency:** Select one proposal agent at a time; ask a second only if the first declines,
   times out, or returns blocked. Or should Ferryman ask several agents in parallel?
6. **Spend:** Failover never increases an agent's existing budget. Should projects also have a hard
   continuity ceiling per incident and per day; if yes, what amounts?
7. **Failback:** Require two healthy readiness checks; give the primary new work only and let the
   substitute finish its current lease. Accept?
8. **Notifications:** Notify immediately on failover, permission blockage, and failback, but do not
   wait for approval when the signed policy already permits the safe action. Accept?
9. **Scope:** Use a fleet-wide default with a separately signed effective policy per repo/channel;
   never expose one repo's raw task to an agent that is not seated there. Accept?

## Recommended delivery order

1. Approve the failure taxonomy, permission boundary, and answers above.
2. Land renewable/fenced lease semantics and point-of-use authorization prerequisites.
3. Add persisted availability/failure evidence and proposal records.
4. Implement proposal-only election first; it is useful and has the smallest authority surface.
5. Add execution failover for confirmed pre-execution failures.
6. Move Telegram to the continuity service and add dashboard controls/status.
7. Run the cross-platform and outage drill before enabling execution failover by default.

Proposal-only continuity can default on for opted-in project agents after its safety tests pass.
Automatic execution failover should remain opt-in until fenced leases and point-of-use grant checks
are proven end to end.

