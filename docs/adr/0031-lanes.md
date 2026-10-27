# ADR 0031: Lanes

Status: proposed, approved by the master (josh) as a spec, 2026-10-23. Builds on 0019, 0024.
Related to the per-order worktrees of `ferry channel worktree`.

## Context

Two agent sessions (game, art) shared one checkout of `idle-ish`. Git has one index and one
HEAD per working tree, and three things went wrong that no discipline can fix:

- one session's `git add -A` committed the other's files (art PNGs in a code commit);
- both took the next decision number (D30 and D31 were used twice);
- one session's `pull` / `checkout` moved files under the other mid-task.

Ferryman already gives each *order* its own worktree. That is transient and anonymous. N agents
working on N things in one repo for days need something longer-lived, named, owned and
landed.

## Decision

1. **A lane is a worktree** at `<repo>/.lanes/<lane>` on branch `lane/<lane>`, excluded through
   `.git/info/exclude`. Inside the repo, not a sibling folder and not under `work/` (see
   docs/LANES.md for why). CLI: `ferry lanes ...`; `ferry lane iroh` is the transport lane.
2. **Ownership is declared and signed.** One record per lane in the channel
   (`lanes/<lane>.json`, single writer, signed by the owner, verified against the roster). A
   per-worktree pre-commit hook (`extensions.worktreeConfig`, `git config --worktree
   core.hooksPath`) refuses staged paths another lane owns; unowned paths and shared files are
   allowed and reported; the override is an environment variable and is logged in the channel.
   Landing re-checks the whole diff, because hooks can be skipped.
3. **Landing is a serialized rebase and fast-forward.** A machine-local OS lock plus a signed
   channel claim (earliest unexpired claim wins) allow one landing at a time. The rebase runs
   in a scratch worktree; a conflict aborts, leaves lane and base untouched, lists the files and
   posts a notice to the lane's owner. Shared files: append-only, edited only in a lane and
   merged by landing; `DECISIONS.md` uses `merge=union`.
4. **Sequential ids come from the channel.** Signed claim files
   `counters/<name>/<n>.<agent>.json`; lowest `(time, agent, machine)` wins; loser retries.
   Strictly safe on one machine; across machines final only after a settle window and after
   peers' files arrive (`ferry counter check` finds late losers). A master-signed policy can
   name a single allocator and/or give disjoint ranges, which cannot collide.
5. **The push token stays sealed.** It is opened in memory and given to one git child as
   `GIT_CONFIG_*` environment scoped to the remote host. Never on disk, in a git config, or in
   an argument list.
6. **`ferry doctor`** warns about two live sessions in one tree, stale lanes and lanes far behind
   their base.

## Consequences

- An agent's `git add -A` can only ever stage that agent's lane. Two commits at once cannot mix.
- A lane that touches another's paths is stopped at commit time and again at landing.
- Landing needs the base's checkout to be clean (it fast-forwards it). A person editing `main`
  directly while lanes land will be told to commit or stash first.
- Counters across machines are eventually, not instantly, consistent; the ADR says so and gives
  the master two switches (allocator, ranges) that remove the race where it matters.
- The channel claim for landing is advisory between machines; git's fast-forward-only base and
  the remote's rejection of a stale push are the backstop.
- More git state to explain: `.lanes/`, `lane/*` branches, `refs/ferry/landed/*` (the tip a
  lane had before it was rebased, kept so nothing is lost).

## Alternatives considered

- *A sibling `<project>.lanes/` folder.* Shows up in `repos/` as another repository; has to be
  excluded from sync and scans by name. Rejected.
- *Worktrees under `work/`.* That folder is for transient order worktrees and migration may
  prune it. Rejected.
- *A single allocator service for ids.* Needs a daemon and a reachable master; the claim files
  work offline and degrade honestly. Kept as policy, not as the only path.
- *Merge commits for landing.* Rejected for history shape and because the rebase gives a clean
  place to stop on conflict.
