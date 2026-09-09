# Scoped access: one permission model for people and agents

Status: proposal. Builds on ADR 0013 (grants are renewable leases), ADR 0014
(a role is conferred, not claimed), ADR 0016 (one seed, every identity
derives), and `DASHBOARD_TEAM_ACCESS_MODEL.md`. Nothing here replaces those;
this document names the vocabulary they left open and says where it is
enforced.

## The two situations this has to serve

1. **A software team.** Redaktly wants a salesperson who can see task status,
   read the conversation about a customer's request and message the
   orchestrator, and nothing else. It wants a contract developer who can take
   and submit work on one feature, review nothing, and never see the vault.
2. **A law office.** A firm runs its own Ferryman server. Attorneys,
   paralegals and staff each get an identity. Access is per matter, read or
   write. An attorney's agent drafts inside the matters that attorney can see;
   a paralegal's agent can read a matter but never approve anything. The
   partner who runs the server can answer, from the ledger, who could see what
   on any given day.

These are the same problem. The second one is only the first one with a
compliance officer reading the audit trail.

## What the repository already has

- Every principal is an ed25519 key. A human operator (`operators.rs`) and an
  agent (`AgentIdentity`) derive from the same seed and sign the same way. The
  channel does not care which one is holding the pen. **This is the whole
  foundation and it is already built.** Do not add a second identity type.
- `MasterGrant` carries `projects`, `roles`, `capabilities`, master-signed.
- `LeaseToken` carries `scope`, `resource`, `grant_id`, an expiry, renewal,
  revocation, and a ledger entry for each - ADR 0013.
- `is_granted(route, grantee, role)` gates whether a worker may take work when
  `grants = "required"`.
- A hash-chained ledger.

## What is missing

Three things, and the third is the one that matters.

1. **No vocabulary.** `capabilities` is `Vec<String>` and the values in use are
   `messages.receive`, `issue`, `build`, `mock`. Nothing can be checked
   consistently because nothing agrees on what the words are.
2. **No binding between a person and their agents.** A grant to the sales
   agent and a grant to the salesperson are unrelated files. Nothing stops the
   agent from holding more than its human.
3. **No enforcement at the dashboard.** `require_session` is yes/no. Any
   operator who can log in can call every one of the thirty `/api/*` routes:
   read and set vault secrets, approve a release, issue grants to others,
   invite teammates. The sales guy is an admin the moment his password works.

## Decision

### 1. A scope is `resource:action[:selector]`

Scopes are strings so they keep fitting in the existing `capabilities` and
`scope` fields, sign under the existing payloads, and stay readable in a
ledger years later. The grammar is fixed:

```
<resource>:<action>            applies to every instance of the resource
<resource>:<action>:<selector> applies to one named instance
<resource>:*                   every action on the resource
```

Resources and actions (the initial set; additions are a one-line change to
`SCOPES` and nothing else):

| resource        | actions                             | selector          |
|-----------------|-------------------------------------|-------------------|
| `tasks`         | `read`, `create`, `take`, `submit`, `review` | task id or label |
| `conversations` | `read`, `write`                     | topic             |
| `memory`        | `read`, `propose`, `approve`        | -                 |
| `ledger`        | `read`                              | -                 |
| `agents`        | `view`, `message`, `assign`, `handoff` | agent name     |
| `secrets`       | `list`, `use`, `set`, `remove`      | secret id         |
| `release`       | `read`, `approve`                   | -                 |
| `team`          | `read`, `invite`, `grant`, `revoke` | -                 |
| `fleet`         | `read`                              | -                 |
| `cost`          | `read`, `plan`                      | -                 |

A scope always sits inside a project. `projects` on the grant already says
which; `*` there means business-wide. So "read the redaktly tasks" is the pair
(`projects: [redaktly]`, `tasks:read`) and it cannot be misread as anything
broader.

Matching is exact on resource and action, and a selector on the *required*
side must equal the selector on the *held* side or the held side must have
none. `secrets:use:stripe-live` satisfies `secrets:use:stripe-live`;
`secrets:use` satisfies it too; `secrets:use:stripe-test` does not. No regex,
no hierarchy, no inheritance. If a check needs cleverness the vocabulary is
wrong.

### 2. A role is a named bundle of scopes, expanded when the grant is written

Operators will not type scopes. They pick a role in the dashboard, and the
role expands to scopes **before signing**, so the stored grant and the ledger
carry the scopes, never the role name. Two consequences: a role's definition
can change tomorrow without silently changing what was granted yesterday,
and an auditor reads the grant file and needs no other document.

Built-in roles, deliberately few:

| role        | scopes                                                                 |
|-------------|------------------------------------------------------------------------|
| `owner`     | `*:*` in `projects: ["*"]`                                             |
| `admin`     | everything except `secrets:set`, `secrets:remove`, `team:grant`, `team:revoke` |
| `developer` | `tasks:*`, `conversations:*`, `memory:read`, `memory:propose`, `ledger:read`, `agents:view`, `agents:message`, `fleet:read` |
| `reviewer`  | `developer` minus `tasks:take`, `tasks:submit`; plus `tasks:review`   |
| `viewer`    | `tasks:read`, `conversations:read`, `memory:read`, `ledger:read`, `agents:view`, `fleet:read` |
| `worker`    | `tasks:read`, `tasks:take`, `tasks:submit`, `conversations:read`, `conversations:write`, `memory:read`, `memory:propose` (this is ADR 0014's floor, unchanged) |

`viewer` plus `agents:message` is the Redaktly salesperson. A law office adds
`attorney` = `reviewer` + `memory:approve`, `paralegal` = `developer` minus
`tasks:review`, `staff` = `viewer`, in a `roles.toml` in the master folder.
Custom roles are the firm's business; Ferryman ships the six above and reads
the file.

`temp` / `contractor` / `employee` from ADR 0014 stay exactly what they are:
the *engagement* picks the lease horizon and project breadth; the *role*
picks the scopes. Two axes, two words.

### 3. An agent's authority is attenuated from its owner's

This is the rule that makes "extends to the agents" true instead of hopeful.

- Every agent has an **owner**: the principal that issued its lease.
- **Who owns a business agent is the business's decision, not Ferryman's.**
  The master is the *default* owner of a business agent because on day one
  it is the only principal that exists, but the master may assign ownership
  to any operator (a managing partner, an IT lead, a practice-group head) by
  a signed record in the master folder, and may reassign it the same way.
  Ferryman defines what an owner *can do* (issue attenuated leases, renew,
  revoke) and records who it is; it never decides who it *should* be. The
  dashboard shows the owner on every business agent and refuses to install
  one without naming one.
- A principal may issue a lease to an agent only for scopes it currently
  holds itself, in projects it currently holds. `issue_grant` enforces this by
  reading the issuer's own effective scopes and refusing any excess. **No
  agent can hold a scope its owner lacks.**
- When the owner's grant shrinks or expires, the agent's leases are not
  reissued past the owner's horizon. The dashboard renews an agent's lease
  only while the owner's own lease is live, so the attenuation holds over
  time, not only at issuance.
- The master keeps the existing power to grant directly; that is the one
  place authority enters the system from outside.

This is capability attenuation in the sense of macaroons or Biscuit, without
importing either: the "proof" is the chain of signed lease files already in
the channel, and the attenuation check is a set comparison at issue time.

For the law office this reads: the paralegal's drafting agent can read the
Smith matter because the paralegal can, cannot approve a memory entry because
the paralegal cannot, and loses the Smith matter the day the paralegal is
taken off it. Nobody has to remember the agent.

### 3b. Master is a person; primary agent is a designation

Two roles that were one word in the code, and should not be.

**The master is a person.** The root of trust is an operator key, held by a
human, carried between machines, sealed under their password. A machine
agent can be declared master implicitly on a first machine so setup does
not stall (`ferry enable`), but the moment a person exists on that machine
the role is transferred to them, signed by the agent, so the chain reads
"declared, then disclaimed" and never "seized". The dashboard offers *I am
the master of this project* whenever no master exists, signed with the
session's already-unlocked key - no password typed twice.

**The primary agent is a designation the master signs and can move.** It
names which agent currently orchestrates: issues work, reviews, holds the
fleet's attention. It is exactly Marvin's *holder* (ADR 0017) with one
addition: the master can move it **on the fly**, from the dashboard, without
waiting for the old holder to go quiet. The trigger is usually tokens - the
primary is out, and the fleet must not stall for the quiet-timeout - so the
switch is one click: *Make grouchly primary now*.

The designation is a lease (`role: primary`, scope `agents:assign`,
`tasks:review`, `tasks:create`, `memory:approve` across the project, short
horizon, renewed while the holder's brief keeps moving). Moving it:

1. writes a `primary.json` naming the new holder, signed by the master;
2. the outgoing holder, if alive, sees it and calls `marvin release` with a
   note; if it is not alive, the brief it was writing continuously *is* the
   handoff (ADR 0017's whole point);
3. the incoming holder calls `marvin take`, runs `marvin resume`, and opens
   its context with the outgoing brief;
4. the ledger records the switch with both names and the reason.

**The primary's memory is its own, on top of project memory.** Project
memory (`memory/`, approved by proposal) is what the fleet agrees is true.
The primary's brief is what *this orchestrator* is doing about it: the
objective, what is in flight and why, decisions not worth an ADR, what is
waiting on the human, what was tried and rejected. It is per-holder
(`marvin/brief.<holder>.json`), written continuously, and read by the
successor. Switching the designation never merges the two: the successor
reads the predecessor's brief and starts its own.

**The master switches it from anywhere.** The designation is a signed file
in the channel, and the channel is everywhere the master is. Nothing is
done *on* the new primary's machine: the master writes `primary.json` from
whichever device holds the master key - the beastly dashboard, a laptop
with the seed restored (ADR 0016), or the phone through Telegram (ADR 0008:
the order is a signed file too, bound to a hash of exactly what was said) -
Syncthing carries it, and grouchly's own agent loop sees it on its next
poll and takes the brief. The old primary sees the same file and releases.
A master who is away from every keyboard but the phone can still say
*make grouchly primary* and have it happen.

**The primary reports; silence is the signal.** Rather than every machine
polling faster to notice a switch, the primary writes a short signed
**report** on a fixed cadence (`marvin/report.<holder>.json`, one writer,
like everything here): when, what it is doing, the brief's age, and the
engine's token or quota state where the engine exposes one. That is the
deadman pattern (`ferry-deadman`): liveness is something the holder proves,
never something a peer probes. Three consequences:

- *Missed reports mean gone.* Marvin already treats a holding that has gone
  quiet as abandoned; the report gives "quiet" a clock. Two missed reports
  (the cadence is the holder's to declare in the report, default five
  minutes) and the designation is open.
- *Failover is ordered, not a race.* The master's `primary.json` names the
  primary **and a standby list**. When the primary's reports stop, the
  first standby that is itself reporting takes the brief, signs its own
  holding, and the ledger records "took over from X after N minutes of
  silence". Nobody else moves. If the standby is also silent, the next one.
  Every agent on the roster with the `primary` scope is reporting anyway,
  because reporting is how it stays eligible.
- *The master sees it coming.* A report carrying "12% of context left" or
  "quota resets 14:00" is on Home before the silence starts, next to *Make
  … primary now*. Most switches should be the master's choice, made early,
  from the phone; the automatic one is the floor under that, not the plan.

The manual switch and the automatic one write the same file shape and
leave the same ledger line, so a reader never has to know which happened.

The dashboard shows the primary on Home with its last report, brief age and
token state, and a *Make … primary* control next to every reporting agent.
The Telegram topic for the project accepts the same instruction in words
and posts a line when a failover happens. A firm that wants two primaries
(one per project) has two designations, one per project.

### 4. Three enforcement points, no more

| where                     | today                           | after                                                   |
|---------------------------|---------------------------------|---------------------------------------------------------|
| dashboard `/api/*`        | logged in or not                | a route table: each route names the scope it requires; middleware resolves the session's effective scopes and fails closed |
| channel `permits` / `is_granted` | recipient + role string  | `permits(principal, scope)`; `is_granted` becomes a call into the same resolver |
| secrets broker            | proposed, unwired                | `secrets:use:<id>` at use time, with the recipient-bound transport rules unchanged |

One function answers all three: `effective_scopes(route, principal, at) ->
ScopeSet`, which reads the principal's valid master grant, every unexpired
unrevoked lease naming it, and (for agents) intersects with the owner's set.
It is pure, it takes a timestamp, and it is unit-tested against a table of
grant files. Every enforcement point calls it and nothing else does its own
reading of grant files.

The dashboard route table is the highest-value piece and the smallest: thirty
routes, one scope each, in the file that defines the router. A route missing
from the table does not fall through to "allowed"; the middleware refuses it
and CI has a test that every registered route is in the table.

### 5. Read and write are what they say

`read` scopes never mutate. The dashboard's read-only mode (a router built
without signing state) already exists; a session holding only `*:read` scopes
gets the same router. This is how a law-office viewer is guaranteed harmless
without auditing every handler.

## What this deliberately does not do

- No permission hierarchy, no role inheritance, no groups-of-groups. Groups
  are a dashboard convenience that expands to individual grants at write
  time, the same way roles do.
- No central authority at use time. Every check reads local files, per ADR
  0013. Stale copies self-extinguish at their horizon.
- No change to signatures. Scopes are strings in fields that already exist and
  already sign. Existing leases verify unchanged; `messages.receive` is mapped
  to `conversations:read` by the migration below and nothing else is touched.
- No opinion on organisational structure. Ownership, custom roles and
  groups are all data the business writes; Ferryman ships defaults so the
  first day works and reads the business's choices from then on.
- No multi-server federation. A firm is one master, one server, one channel
  set. Two firms sharing a matter is a later problem and this design does not
  preclude it.

## Migration

- On first run with a `SCOPES` table present, every existing grant and lease
  is read as-is; legacy capability strings map through a fixed table
  (`messages.receive` -> `conversations:read`, `issue` -> `tasks:create`,
  `build` -> `worker`), and unknown strings are kept and ignored by the
  matcher, never rejected. Nothing stops working.
- Every operator on the roster is auto-granted `owner` by the master, once,
  signed, in the ledger - the same shape as ADR 0014's migration, because the
  alternative is locking out the people who already run the place. The
  operator then narrows from the Teammates page.
- The dashboard's route table ships with every route mapped; a first release
  can log denials without enforcing (`scopes = "audit"` in `bridge.toml`) so
  an operator sees what would break for a week before `scopes = "required"`.

## Order of work

1. `scopes.rs` in `ferryman-channel`: the grammar, the matcher, `SCOPES`,
   built-in roles, `effective_scopes`. Pure, tested, no I/O beyond reading
   grant files through the existing lease/master functions.
2. Attenuation in `issue_grant` and in the dashboard's renewal path.
3. The dashboard route table and middleware, `audit` mode first.
4. `roles.toml` in the master folder for custom roles (catalogue and profiles in `SCOPE_PROFILES.md`, `examples/roles/`).
5. Teammates page: pick a role, pick projects, pick an engagement; the page
   shows the expanded scopes before the operator signs. Agents page: the same
   for an agent, with the owner's scopes shown greyed as the ceiling.
6. Flip the default to `required` one release later, migration included.

Steps 1-3 are the product. Steps 4-6 are the law office.
