# 0014 — A role is conferred, not claimed

Status: Proposed
Date: 2026-08-24
Builds on: [0013](0013-agent-access-grants-are-renewable-leases.md)

## The state this describes

An agent's role lives in its own `agent.toml`. It writes `role = "orchestrator"`
there and the roster publishes that claim. Nothing confers it and, in the common
configuration, nothing checks it.

The gate exists. `ProjectRoute::requires_grants()` is true when `bridge.toml`
says `grants = "required"`, and then a worker will not take work unless
`master::is_granted(route, agent, role)` says the master granted it that role,
per role, signed. It is good machinery.

It is also off by default: absent *or* `"open"` means no gate. Every channel in
the fleet this was found in reads `grants = "open"`.

The result is not hypothetical. Eighteen of nineteen channels on one machine had
declared themselves `role = "orchestrator"` — not by anyone's decision, but
because nothing stopped a config file from saying so. Fifteen of them signed as
one name and three as another, on the same machine, which is the thing
one-key-per-machine exists to prevent.

## Decision

**A role is conferred by the master, not declared by the holder.**

1. `worker` is the floor and needs no grant. An agent that takes assigned work
   and returns results is the least an agent can be, and requiring ceremony for
   it would only teach operators to turn the ceremony off.

2. `orchestrator` and `master` require a signed grant. These are the roles that
   issue work into other projects and settle what lands. They are authority over
   other agents, and authority should be given rather than taken.

3. `grants` absent defaults to **required**. Today absence means "trust anything
   that names itself", which is the wrong default for a folder every peer can
   write to. An operator who wants the old behaviour writes `grants = "open"` and
   means it.

## Why not name the default role `agent`

It was proposed, and it is the wrong word. Workers, orchestrators, bridges,
operators and observers are all agents; a role called `agent` distinguishes
nothing and would read, in a roster, as "we did not decide". `worker` already
carries the meaning the floor needs.

`employee`, `contractor` and `temp` were proposed for the same slot and moved to
a different one, below. They describe how an agent is engaged rather than what
it does - a roster line reading `alice - contractor` still leaves open whether
she issues orders or executes them, which is the distinction `worker` and
`orchestrator` exist to make. Both axes are worth having; neither replaces the
other.

## How an engagement is named

`role` says what an agent does. It does not say how long it is trusted or how
broadly, and those are the questions an operator actually asks when handing
someone access.

ADR 0013 already carries the second axis, unnamed: every grant is scoped "one
task / 24 hours / 7-30 days / permanent". Durations are precise and unreadable.
Three words carry the same thing and need no manual:

| engagement   | means                                                    | expires |
|--------------|----------------------------------------------------------|---------|
| `temp`       | one task, or one day                                     | by itself |
| `contractor` | scoped to one project; returns work, sees nothing else   | on its term |
| `employee`   | standing, across projects                                | not until revoked |

**`temp` is the default.** Not for tidiness: the vocabulary has to push the same
way the policy does. `employee` carries an assumption of loyalty and continuity
that this system deliberately does not make - people grant employees broad
standing access because the relationship is mutual and ongoing, and nothing
about an agent earns that. If the default were `employee`, the naming would
argue against the rule this document exists to establish. `contractor` is the
normal case. `employee` should be rare and deliberate.

### Short forms are for typing, not for storage

`emp`, `cont` and `temp` are accepted wherever an engagement is named, and
normalized on write. The stored grant, the roster and the ledger always carry
the full word.

This is the rule already settled for headless agent names, where the full form
is canonical and the short form exists for speech. It applies for the same
reason: the operator types the same flag forty times, and a stranger reads the
record once, years later, with no idea what was obvious to whoever typed it.

`cont` rather than `con` deliberately. A stored trust level should not read as
*against*, and in a public repository the shorter form invites exactly one
joke at the expense of the thing it names.

### What the words do not import

A contractor in the world is accountable for their work and carries their own
liability. An agent is not and never will be; the operator is. Ferryman borrows
these words for their shape - how long, how broad, does it lapse - and models
none of the obligations that surround them. Nothing here is a statement about
employment, and no part of the system changes behaviour based on which word was
chosen beyond scope and expiry.

## Migration, which is the hard part

Flipping the default stops every existing fleet on its next poll — politely,
each agent reporting "not granted", and nobody noticing for a day. That failure
is quiet, fleet-wide, and looks exactly like the agents being broken.

So the change is not a flag flip:

- On first run under the new default, every name already on the roster is
  granted the role it currently holds, by the master, signed and recorded. The
  gate then starts closed for names that arrive afterwards and open for names
  already trusted.
- The grant is written once and is visible in the ledger. An operator can read
  what was auto-granted and revoke it.
- A fleet with no master declared cannot auto-grant. It reports that it needs a
  master and keeps working ungated until one exists, because breaking a working
  fleet to enforce a rule nobody can yet satisfy helps no one.

## What this does not do

It does not stop a machine that already holds a granted name from misusing it —
a signature proves who acted, never that the act was wise. And it does not
address the second half of what was found: that a role can be structurally
impossible to perform, as when an orchestrator is sandboxed away from the
channels it must write into. A grant says an agent *may*. It says nothing about
whether it *can*.
