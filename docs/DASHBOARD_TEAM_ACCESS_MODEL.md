# Dashboard team and agent access model

Status: approved product direction for the dashboard UX branch.

## Vocabulary

- A **teammate** is a human operator.
- An **agent** is an AI or automated worker.
- A **personal agent** is owned by one teammate. Other teammates must receive an
  explicit grant before they can view, message, assign work to, or delegate
  through it.
- A **business agent** is owned by the business rather than by an employee. A
  business owner installs it and chooses whether it is available to everyone or
  only selected teams and roles.

The interface must never call an agent a teammate. Human and agent identities
must remain visually and semantically distinct throughout the dashboard.

## Personal-agent grants

Every grant is scoped, revocable, attributable, and recorded in the audit trail.
The owner may approve fewer permissions than were requested.

Supported durations:

- **One task**: expires when the named task reaches a terminal state.
- **Temporary**: expires after a short duration, such as 24 hours.
- **Long-term**: expires after an explicit longer duration, such as 7 or 30 days.
- **Permanent**: has no automatic expiry but remains revocable by the owner.

Supported permissions are independent:

- view status and outputs;
- message the agent;
- assign project tasks;
- allow agent-to-agent handoffs.

Repository access, credentials, secrets, publishing, deployment, and spending
are not implied by an agent grant. They require their own explicit controls.

## Business agents

The Agents > Install flow offers two ownership modes:

1. **Personal agent** — owned by one teammate; other people request access.
2. **Business agent** — owned by the organization; access follows a business
   policy.

A business agent may be temporary, long-term, or permanent. A permanent business
agent remains installed until a business owner suspends or retires it. Its
audience is one of:

- everyone in the business;
- selected teams or roles;
- approval required for each use.

The default least-privilege business policy allows viewing status, messaging,
and assigning project tasks. Agent handoffs are off by default. Repository and
secret access are always configured separately. Every use and policy change is
auditable.

## Required dashboard surfaces

- **Home**: human teammates, AI agents, shared work, mentions, reviews, and a
  concise activity feed.
- **Teammates**: human membership, role, presence, invitations, and project
  responsibilities.
- **Agents**: agents grouped by human or business owner, with explicit access
  state and request/approval controls.
- **Install agent**: ownership, lifecycle, audience, permissions, placement, and
  review summary before installation.
- **Inbox**: human mentions, access requests, reviews, and agent blockers.
- **Audit**: requester, approver, scopes, duration, expiry, revocation, and agent
  use.

## Enforcement boundary

The dashboard may explain and initiate these operations, but it must not imply
that a visual badge is enforcement. The channel/runtime must verify an active
grant before accepting a message, task assignment, or handoff to an agent owned
by another human. Business-wide access must resolve from a signed business
policy. Unknown, expired, revoked, or unverifiable grants fail closed.
