# ADR 0020: A killed order stays killed, and one repo's scratch is not another's

## Status

Accepted.

## Context

Two defects, found within minutes of each other, both of the same shape: a name that
identified something to one machine, taken as identifying it to everyone.

### A killed order came back

An operator kills a task with a signed `kill` interrupt. The worker did the obvious
thing — acknowledged the interrupt, dropped its claim, returned — and that is correct
for the *running process*. It was never made true of the *order*.

On the next poll, `pending_interrupts` skipped the interrupt because the acknowledgement
file was sitting beside it. With no pending interrupt and no claim, the order read as
plainly `Open`. The same worker claimed it and ran the work the operator had just
stopped. Then again. Then again.

`list_tasks` sorts by `created_at`, oldest first, which is a correct FIFO and made this
much worse than a wasted run: **a killed order sits permanently at the head of the queue
and re-runs itself ahead of everything issued after it.** Live work queued behind it is
never reached at all.

Observed here on 31 August 2026. An order killed at 20:11 was acknowledged at 23:13 and
re-claimed at 23:45, taking a worker for thirty-one minutes while the order that would
have brought a fleet machine up to date sat untouched, thirteen minutes old and last in
a line it could never reach.

`Kill` and `Pause` also did byte-identical work. The enum distinguished them; nothing
else did. Kill was only ever a pause that sounded final.

### Two projects wanted the same scratch directory

ADR 0019 moved task worktrees into one shared `ferry/work/`. The directory name is the
branch, which is `(order id, agent)` — and that was unambiguous only for as long as
worktrees lived beside their own repository, because the repository's own path did the
disambiguating.

Order ids are short human names: `update-0828`, `seat-2245`. Nobody coordinates them
across projects, and a ferry root exists precisely to hold many projects. Two of them
resolve to one directory. The second task finds a valid git checkout sitting there,
reuses it, and runs — and commits — in the wrong repository, reporting success. The
same collision exists in the legacy location for two repos that share a parent.

Centralising `work/` is what introduced this, so centralising `work/` is what pays for it.

## Decision

### Death belongs to the order

`TaskState::Killed { by, at }`, computed from the order's own signed files by every
machine, checked before the holder is even resolved. A kill that lands on an unclaimed
order is as final as one that interrupts a run.

An acknowledgement records that a worker *saw* a kill. It is not, and never was, a
statement that the order may run again — so `state()` does not consult acks at all.

A kill needs a valid signature. Any peer can write into the synced folder, and ending an
order is destructive and irreversible in a way a `steer` is not.

`work_for` returns a killed order to exactly one machine: the one still holding a claim,
and only so that it can let go. Otherwise a claim sits on the order forever, and the
channel shows someone working on something nobody will ever finish.

Pause keeps its old behaviour, which is now the thing that distinguishes it: a paused
order is meant to be picked up again.

### Scratch is keyed on the repository, not just the task

Worktrees live at `ferry/work/<repo-name>-<digest>/<branch>`. The readable half so a
person can see whose scratch this is; the digest of the repository's own path so two
repos with the same folder name in different places never share it.

Before reusing an existing worktree directory, verify it is a checkout of *this*
repository, by comparing the common git directory. `is_git_repo` answers "is there a
worktree here", which is not the question.

The legacy location beside the repo is stepped around in one case only: a **live**
worktree of another repository is occupying it. That neighbour is neither reused nor
deleted; this repo takes a qualified name instead. A *broken* leftover is a different
thing and is still reclaimed, because reclaiming it is what stops an agent working in a
directory whose changes cannot be committed.

## Consequences

An operator's kill is now worth what it appears to be worth. The cost is that a killed
order cannot be revived — reviving one means issuing a new order, which is honest, since
the old one's history says it was stopped.

Worktree paths change for anyone with a ferry root. Work already in progress at an old
path is still found there, so nothing in flight is abandoned.

## Notes

The test named `acknowledging_a_kill_does_not_bring_the_order_back_to_life` is this
incident written down. It is worth keeping under that name.
