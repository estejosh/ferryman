# ADR 0012: Landing a finished branch — merge or deny

## Status

Accepted.

## Context

A worker that changes files commits them and pushes its own branch:

```rust
let branch = ferryman_channel::worktree::branch_name(id, &config.agent);
// ...
payload["worktree_branch"] = json!(branch);
payload["committed"]       = json!(made);
payload["pushed"]          = json!(remote);
```

Then it stops, and nothing else happens. The result is written, the ledger records a
finished task, `state()` says `Done`, and the change sits on a branch that no one has
read.

Four of them are sitting on `origin` as this is written:

```
ferryman-e2e-fang-122420-e2e-fang
ferryman-proof-112843-wisp
ferryman-secrets-build-145457-fang
ferryman-tg-topics-155625-fang
```

One of those four — `secrets-build` — shipped a real cryptographic defect: raw X25519
output used directly as a cipher key, no KDF. It was caught by reading the branch, by
hand, days later. Nothing in the system was ever going to catch it, because nothing in the
system was ever going to look.

So `Done` today means *the engine stopped and wrote a result*. It does not mean *the
change is good*, and it does not mean *the change is in `main`*. Those three are being
reported as one thing.

## Why the obvious fix is wrong

"Merge when the tests pass" fails here for the same reason a claim cannot expire on a
clock: the thing you would trust was produced by the thing you are checking. The engine
that wrote the change also wrote the tests, also chose which cases to write, and is the
same engine that produced the defect. Green tests are evidence, not a verdict.

Nor can review live on GitHub. The channel is plain files carried by Syncthing and works
with no network at all; a pull request is a thing on a host, reachable only sometimes, by
only some of the machines. A verdict that exists only on github.com is a verdict half the
fleet cannot read.

The rule that follows: **the seat that decides the work may not be the seat that lands
it.** Deciding and reviewing are different seats, and the verdict lives in the channel.

## Decision

### 1. A worker never merges

It commits, pushes `ferryman-<id>-<agent>`, and stops. This is already what the code does;
this ADR makes it a rule rather than an accident, and narrows `push_branch` so it can only
ever write a ref under `refs/heads/ferryman-`. A worker cannot push the default branch
even by mistake, and cannot push someone else's task branch at all.

### 2. Landing is a separate, signed act

```
ferry channel land --task <id> --comms <dir> [--into main]
ferry channel deny --task <id> --comms <dir> --reason "<why>"
```

Both are issued by the orchestrator seat, both are signed, and both refuse to run under
the same agent name that produced the result. A machine may hold both seats; it may not
use one to rubber-stamp the other.

### 3. Both outcomes leave a record; neither deletes anything

`<task>/verdict.<reviewer>.json`:

```json
{
  "order_id": "secrets-build-145457",
  "decision": "landed",
  "branch": "ferryman-secrets-build-145457-fang",
  "head": "1e5be57...",
  "base": "8fcc3ef...",
  "into": "main",
  "merge_commit": "...",
  "reason": "KDF defect fixed on the branch; dashboard endpoint still unread",
  "at": "...",
  "signed_by": "wisp",
  "signature": "..."
}
```

`deny` writes the same record with `"decision": "denied"` and no `merge_commit`. The
branch stays. A denied branch is evidence — of what was attempted, and of what was wrong
with it — and the next attempt is a new task that may start from it.

### 4. A task with no verdict is not finished

`state()` gains `Submitted { by }`, sitting between `Claimed` and `Done`: work is in,
nobody has ruled on it. `Done` now means landed or denied.

As with `Stale` in ADR 0011, this is **display only**. It must not make the task claimable
by anyone, and `work_for` must treat `Submitted` exactly as it treats `Done`. The point is
to stop the status telling a reassuring story — the same defect as an addressed order
reading as `Claimed` before anyone touched it, and a dead claim reading as work in
progress.

### 5. What the reviewer is required to check

The diff is against the result's `base`, not against whatever `main` happens to be now.
If `base` is no longer an ancestor of the target branch, the task is rebased or denied —
never force-merged, and never merged with `-X ours`.

Before landing: the diff carries no key-shaped material. `.gitleaks.toml` is already in
the repo and this is where it earns its place. Secrets do not traverse the channel, and
they do not traverse a branch either.

## Consequences

The orchestrator is a bottleneck, deliberately. Nothing reaches `main` that a second seat
did not read and sign for. Work does not stop while it waits — a denied or unlanded branch
blocks only itself.

Every finished task now ends in a signed sentence about whether it was any good, written
by someone other than its author, stored where the machine with no network can still read
it.

## Rejected

- **Auto-merge on green tests.** The tests came from the same engine as the change.
- **Pull requests as the source of truth.** The channel must work offline; GitHub may
  mirror a verdict, it may not hold it.
- **Deleting denied branches.** A denial with nothing to point at is a rumour.
