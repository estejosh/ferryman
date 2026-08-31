# ADR 0017: The orchestrator writes down what only it knows

## Status

Accepted.

## Context

Ferryman coordinates workers well. A worker that dies is recovered by ADR 0011: its
claim is released, another machine picks the task up, and nothing is lost because
everything a worker needs is in the order.

The orchestrator has none of that. It is the agent that decides *what the orders should
be*, and when it stops — context exhausted, session ended, subscription spent — the
project does not continue with a different orchestrator. It restarts, badly. The owner's
words: *"when the main orchestrator runs out of tokens, no other orchestrator can take
over in a meaningful way, it kills me 3 days a week."*

Three days a week is not an edge case. It is the normal operating condition of the
product, and it is unaddressed.

`ferry loadmem` was built for this and does not solve it. It prints the memory bank, the
durable log and the agent profiles — everything the *project* knows. What it cannot
print is what the orchestrator knows and nothing else does:

- the current objective, and what it is being traded against
- what is in flight, and why each thing sits where it does
- decisions that were load-bearing but never ADR-worthy, and the reason behind each
- the human's standing constraints, which are learned by being corrected
- what is waiting on the human rather than on a machine
- what was tried and rejected, so the next orchestrator does not spend its first hour
  rediscovering it

None of that is in the channel. It is in a context window, and a context window is the
one component of this system with no durability story at all.

## Decision

### The orchestrator keeps a brief, in the channel, signed, one per orchestrator

`<communications>/orchestrator/<agent>.json`, named after its only writer, like every
other record here — so two orchestrators can never produce a conflicting edit and a
successor can read the outgoing one's brief while writing its own.

It holds an objective, a deadline if there is one, and six free-text sections:
constraints, in flight, decided, rejected, waiting on the human, and next. Free text on
purpose: the value is in the reasoning, and a schema that forced the reasoning into
fields would keep the fields and lose the reasons.

It is signed and verified exactly as every other channel artifact is, against the
roster, and for the same reason `memory` gives for signing a profile: a brief is not a
document, it is **prompt text**. It is written to be pasted into a fresh orchestrator as
its opening context, which makes an unsigned one an injection vector any peer with write
access to the synced folder could plant.

### It is written continuously, not at handoff

This is the part that matters, and it is the same insight as `ferry-deadman`: **running
out of context is never a graceful event, so the handoff cannot be an event.** There is
no moment at which a dying orchestrator reliably gets to write a summary. It may simply
stop mid-sentence.

So the brief is updated as work happens — after a decision, after a dispatch, after the
human says something that changes the standing constraints. `ferry orchestrator brief`
therefore touches only the sections it is given: an orchestrator recording one decision
must not have to restate the other five, because the version that costs six paragraphs
is the version that stops being written.

When updates stop, the last one is already current. The staleness of the brief is itself
the signal: an orchestrator whose brief has not moved while its fleet has is an
orchestrator that is gone.

### `ferry orchestrator resume` produces the handoff, not the raw record

A successor should not have to read JSON and assemble a picture. One command prints, in
the order a new orchestrator needs them: the brief and how old it is, who wrote it and
whether that signature verifies, the roster, work in flight taken from the channel
rather than from the brief, and what is waiting on the human.

Work in flight is read from the channel on purpose, so a stale brief cannot hide a task —
and the two disagreeing is itself information.

## Consequences

**The orchestrator becomes recoverable, which is what the rest of the product already
assumes.** ADR 0011 recovers a dead worker; nothing recovered the thing that issues the
orders. This closes the gap at the top.

**It is honest about what a successor inherits.** A brief carries a signature and an
age, and the age is never buried: past four hours `resume` says so in words, because a
successor reasoning about a four-hour-old brief must behave differently from one
trusting it as current.

**It costs the orchestrator discipline.** A brief that is not updated is worse than none,
because it will be trusted. The mitigation is that updating it is cheap and the age is
always shown — a stale brief announces itself rather than lying quietly.

**It is not a transcript, and must not become one.** The temptation will be to dump
everything. A successor that has to read four hours of history has not been helped. The
brief is the state of the world now, plus the reasons that are not reconstructable from
it.

## What this is not

Not a second orchestrator running in parallel — that is
[the continuity proposal](../ORCHESTRATOR_CONTINUITY_PROPOSAL.md), which is about
failover of *execution* and is a separate and larger decision. This ADR is only about
making sure that whatever takes over, human or machine, knows what was in the head of
the thing that stopped.
