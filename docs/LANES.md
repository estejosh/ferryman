# Lanes: several agents, one repository

Two agents in one checkout share one git index and one HEAD. So one agent's `git add -A`
commits the other's files, one agent's `pull` moves files under the other mid-task, and both
pick "the next decision number". Lanes remove all three. Decision record: ADR 0028.

A **lane** is one agent's (or one task's) own git worktree and branch of the same repository,
the paths it owns, and one serialized way onto `main`.

```
ferry lanes new idle-ish game --owns "game/**" --owns "docs/game-*.md"
ferry lanes new idle-ish art  --owns "art/**"  --owns "assets/**"
```

## Where a lane lives

`<repo>/.lanes/<lane>`, on branch `lane/<lane>`, inside the project's own folder.

Why inside the repo and not a sibling `<project>.lanes/`:

- the repo folder is already the project's housing; a sibling would show up in `repos/` as a
  second "repository" to every scan and to `ferry root show`;
- it is not under `work/`, which holds transient per-order worktrees that
  `ferry root migrate --prune-stale-worktrees` is allowed to move. A lane is long-lived;
- it is **excluded** by `.git/info/exclude` (`/.lanes/`), so `git status` in the main checkout
  never mentions it and `git add -A` there cannot stage it. `repos/` and `work/` are
  machine-local and never synced (`syncscope`), so a lane is not synced either.

`ferry channel worktree` (per-order, transient, `ferryman-<order>-<agent>`) is unchanged and
uses the same git primitives; lanes are the long-lived, human-named sibling of it.

The CLI is `ferry lanes ...` (plural). `ferry lane iroh ...` is the iroh transport lane and
is unrelated.

## Commands

| command | what it does |
| --- | --- |
| `ferry lanes new <project> <lane> --owns <glob>... [--shared <glob>] [--base main]` | worktree + branch + hook + signed record. Safe to repeat. |
| `ferry lanes list [--project p] [--all] [--json]` | owner, owned globs, ahead/behind, dirty, live sessions |
| `ferry lanes enter [--session id]` | register this session in the current tree; prints the rules; warns if another live session shares the tree |
| `ferry lanes leave` | end the session |
| `ferry lanes land <lane> [--push] [--no-fetch] [--allow-foreign why] [--wait s]` | rebase + fast-forward, one at a time |
| `ferry lanes retire <lane> [--force]` | remove worktree and branch, free the globs |
| `ferry counter next <name> [--project p] [--start N]` | print the next number |
| `ferry counter list / check / policy <name>` | who holds what; contested numbers; master-signed policy |
| `ferry root show` | lists each project's lanes |
| `ferry doctor` | warns about shared trees and stale or far-behind lanes |

## Ownership

Each lane declares globs it owns (`*` stays in a directory, `**` crosses directories, a bare
directory name covers everything under it). The declarations are one **signed record per lane**
in the project's channel (`lanes/<lane>.json`, written only by the lane's owner, so sync never
sees two writers). A record that does not verify is ignored and reported; it grants nothing.

A **pre-commit hook**, installed per worktree (`extensions.worktreeConfig` +
`git config --worktree core.hooksPath`, so no other worktree and no existing repo hook is
touched; the repo's own `pre-commit`, if any, still runs after ours), classifies every staged
path:

- owned by this lane: fine;
- owned by **another** lane: the commit is **refused**, naming the path and the lane;
- owned by nobody: allowed, reported;
- a shared file (below): allowed, reported.

The one way around it is explicit and logged:
`FERRY_LANE_OVERRIDE="why" git commit ...` appends a signed line to
`lanes/overrides/<lane>.jsonl` in the channel. Landing checks the same rule again over the
whole lane diff, so `--no-verify` does not get around it; `ferry lanes land --allow-foreign why`
is the logged escape there.

## Shared files

`DECISIONS.md`, `docs/DECISIONS.md`, `README.md`, `CHANGELOG.md` (plus anything passed with
`--shared`) belong to no lane. The rule:

1. **append only** to a log-like file (decisions, changelog); do not reflow or renumber;
2. edit it in your lane; it reaches `main` only through a landing, which rebases it;
3. `DECISIONS.md` is set to git's `merge=union` driver, so two lanes that each appended an
   entry both survive the rebase; and the numbers come from `ferry counter next decision`, so
   the entries do not clash (D30/D31 twice cannot happen);
4. a real conflict (both rewrote the same line) is a landing conflict: nothing changes, the
   second lane rebases and resolves.

## Landing

`ferry lanes land <lane>`, run by the agent or by a person:

1. the lane must be committed (its working tree clean);
2. take the **landing lock**: a machine-local OS lock in the repo's git dir, plus a signed claim
   at `lanes/landing/<agent>.json` in the channel (15 minute expiry, earliest claim wins).
   Only one landing runs at a time; others wait (`--wait`);
3. optionally fetch and fast-forward the base from the remote;
4. check ownership over the whole lane diff;
5. **rebase in a scratch worktree** onto the base, so the lane's own files never pass through
   a half-rebased state;
6. conflict: `git rebase --abort`, remove the scratch worktree, list the files, post a signed
   notice to the lane's owner, exit non-zero. **The lane and the base are untouched**;
7. success: fast-forward the base (in the checkout that has it, which must be clean; else
   `update-ref`), keep the old tip at `refs/ferry/landed/<lane>/<time>`, move the lane onto the
   new base, optionally push.

The base moving under a landing (someone committed straight to main) makes the fast-forward
fail; run it again.

Across machines the channel claim is advisory (it travels at sync speed). The backstop is git:
the base only moves by fast-forward, and a push of a stale base is rejected by the remote, so
two machines cannot both land the same history.

## Counters

`ferry counter next decision --start 30` prints `30`, then `31`, ... The claim is a signed file
`counters/<name>/<n>.<agent>.json`. For one number, the claim with the lowest
`(claimed_at, agent, machine)` among validly signed claims wins; a loser takes the next number.
Unsigned or forged claims count for nothing.

The guarantee, plainly:

- **Agents on one machine never collide**: allocation holds an OS lock and reads every earlier
  claim off the same disk.
- **Agents on different machines can claim the same number before either sees the other.** The
  rule still picks one winner everywhere, but a number is **final only after the settle
  window** (`--settle`, default 8 s once another machine has used the counter) **and once peers'
  files have arrived**. `ferry counter check <name>` lists any number claimed twice and who
  won, so a late loser is found, not silent.
- **Make the safe thing the default where it matters.** The project's master can sign a policy:
  `ferry counter policy decision --allocator josh` (only that agent allocates; others are
  refused unless they pass `--provisional`), and/or disjoint ranges
  `--range ash=1000-1999 --range rf=2000-2999`, which cannot collide at all, at the price of
  non-contiguous numbers.

## Credentials

The push token stays a sealed secret (`ferry channel secret set GH_TOKEN ...`). `ferry lanes
land --push` opens it in memory for this agent and hands it to the one `git` child process as
`GIT_CONFIG_COUNT/KEY/VALUE` environment (`http.https://<host>/.extraheader`). It is never in
the argument list, never in `.git/config`, never on disk, and it is scoped to the remote's own
host. Needs git 2.31 or later. A non-https remote gets no header.

## Doctor

`ferry doctor` warns when

- two live sessions are registered in one working tree (a session is live for 15 minutes after
  its last `lanes enter` or commit; set `FERRY_SESSION` or `CLAUDE_SESSION_ID` and commits
  refresh it);
- a lane has had no commit or session activity for 7 days (`FERRY_LANE_STALE_DAYS`);
- a lane is 100 or more commits behind its base;
- a lane record does not verify, or a lane of this machine lost its worktree.

## Paste this into each project session

```
This repo uses Ferryman lanes. You work in your own lane: never in the main checkout, never in
another lane's folder.
1. Start: cd into your lane (`ferry lanes list`; if you have none, `ferry lanes new <project>
   <lane> --owns <glob>`), then run `ferry lanes enter`.
2. Commit only inside your lane. The hook refuses paths another lane owns; hand those changes
   to that lane. Never use --no-verify.
3. Numbers (decision ids, asset ids): `ferry counter next <name>`. Never pick "the next one".
4. Shared files (DECISIONS.md, README, CHANGELOG): append only, in your lane.
5. To ship: commit everything, then `ferry lanes land <lane>`. On a conflict nothing is
   changed: rebase in your lane, resolve, land again.
6. Never git pull / checkout / switch / rebase / add -A in the main checkout.
```
