# ADR 0011: Recovering a task whose worker is gone

## Status

Accepted.

## Context

A claim is permanent.

```rust
pub struct Claim {
    pub order_id: String,
    pub agent: String,
    pub claimed_at: DateTime<Utc>,   // written, never read
}
```

`claimed_at` is recorded and nothing ever compares it to anything. `work_for` offers a
`Claimed` task **only to its holder**, which is right — it is what stops two machines
doing one task — but it means that when the holder is gone, the task is offered to nobody,
for ever. The only exit is `ferry channel interrupt --action kill`, which is a human
typing.

This was not theoretical. `ichabod-1650` was claimed by `fang`, which was then stopped
mid-task during its own switchover: it was told to submit before stopping its parent, did
it the other way round, and killed the process that was writing the report. The work
completed. The report was lost. The claim will outlive the machine.

## Why the obvious fix is wrong

"Expire a claim after N minutes" fails in this system specifically.

Clocks disagree. Timestamps written by `fang` and by `wisp` have been hours
apart all along; neither is authoritative, and there is no server to ask. Delivery is
eventual: a claim written on one machine reaches the others when Syncthing gets to it, so
a claim can be simultaneously fresh where it was written and absent where it is read.

So "`claimed_at` is old" conflates three states that need opposite responses: *the worker
is dead*, *that machine's clock is wrong*, and *the file has not arrived yet*. Guess wrong
and two engines run one order in two worktrees and both submit — which is worse than a
stuck task, and is the exact outcome one-writer-per-path exists to prevent.

The rule that follows: **no comparison of clocks between machines may release a claim.**
Only local certainty, or a deliberate act, may.

## Decision

Five parts, ordered by how much trust each needs. The first needs none.

### 1. A heartbeat carrying a run id

While a task runs, the worker rewrites `<task>/heartbeat.<agent>.json`:

```json
{ "order_id": "...", "agent": "...", "run": "1a", "pid": 12345, "at": "..." }
```

One writer per path, as everywhere else. `run` names *this* execution, so a second attempt
after a failure is distinguishable from the first. `pid` is local truth on the machine
that wrote it and meaningless anywhere else, which is precisely the point: it is only ever
read by the machine that wrote it.

### 2. `TaskState::Stale { by, since }`

When a claim's heartbeat has lapsed past a generous multiple of the interval, `state()`
reports `Stale` rather than `Claimed`.

This is display, and only display. It makes the task claimable by nobody. It exists
because "nobody is doing this" currently looks identical to "someone is doing this", which
is the same defect as an addressed order reading as `Claimed` before anyone had touched
it — the status told the reassuring story in both cases. A stale claim should read as
stale from any machine, whatever its clock, and then a human or a policy decides.

### 3. A worker kills and releases its own dead runs

A worker knows the pids of its own children. A heartbeat under its own name whose pid is
gone is *certainly* dead: no skew, no sync, no trust required. It kills anything still
lingering and writes a signed release.

This is the only place a machine may decide a task is abandoned, and it may decide it
only about itself.

### 4. A worker reclaims its own orphans at startup

A claim under its own name, with no result and no live run, on a machine that has just
started: it either resumes the work or releases it.

This covers what (3) cannot. When the parent dies, parent and child die together and
nobody is left to adjudicate — which is exactly what happened to `ichabod-1650`. A worker
starting up is the moment to ask "what do I already hold, and am I running it?"

### 5. Retiring an identity releases what it holds

`ferry channel retire --agent <name> --comms <dir>`: signed, recorded, deliberate.

For the case nothing time-based can catch, because the holder is not late — it is gone.
`ichabod-1650` is held by `fang`, and `fang` will never run again: that machine's
unattended worker is `ichabod-fang-deepseek` now. No heartbeat will ever lapse,
because none was ever written.

### The release record

`<task>/release.<releaser>.json`, signed like everything else:

```json
{ "order_id": "...", "released": "fang", "releaser": "...",
  "reason": "retired", "at": "...", "signed_by": "...", "signature": "..." }
```

`state()` treats a released claim as no longer held, so the task returns to `Open` or
`Offered` and the fleet can pick it up. The ledger keeps both the claim and the release,
so the history says who held it, who let it go, and why.

## Constraints

- **No cross-machine clock comparison releases a claim.** Only a same-machine pid check
  (3, 4) or a deliberate act (5).
- **`Stale` is advisory.** It never by itself makes work claimable by another machine.
- **Every release is signed and recorded.** A stuck fleet must not be fixed by tasks
  quietly changing hands: "who was working on this" is what the ledger is for.
- **A worker may only release its own.** Nothing decides on another machine's behalf.
- **The heartbeat is one writer per path**, like every other artifact.
- **A release is not a result.** Releasing says the work was abandoned, never that it was
  done; anything already committed on the task's branch stays where it is.

## Consequences

Positive: a crashed engine frees its task on the next pass, a restarted worker recovers
what it dropped, a retired name stops holding things hostage, and a claim nobody is
serving finally *reads* as one. Negative: five mechanisms where there were none, and the
heartbeat is one more small write per task per interval into a synced folder. Deliberately
not solved: a machine that is powered off indefinitely still holds its claims until
someone retires it, because the alternative is guessing across clocks, and guessing wrong
costs more than waiting.
