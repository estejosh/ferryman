# Lanes: several agents, one repository

Two agents in one checkout share one git index and one HEAD. So one agent's `git add -A`
commits the other's files, one agent's `pull` moves files under the other mid-task, and both
pick "the next decision number". Lanes remove all three. Decision record: ADR 0031.

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
| `ferry lanes new <project> <lane> --owns <glob>... [--shared <glob>] [--append-only <file>] [--base main]` | worktree + branch + hooks + signed record. Safe to repeat. Needs git 2.20+. |
| `ferry lanes list [--project p] [--all] [--json]` | owner, owned globs, ahead/behind, dirty, live sessions |
| `ferry lanes enter [--session id]` | register this session in the current tree; prints the rules; warns if another live session shares the tree |
| `ferry lanes leave` | end the session |
| `ferry lanes land <lane> [--push] [--no-fetch] [--allow-foreign why] [--wait s]` | rebase + fast-forward, one at a time |
| `ferry lanes retire <lane> [--force]` | remove worktree and branch, free the globs; refuses to lose work (see Retiring) |
| `ferry counter next <name> [--project p] [--start N]` | print the next number |
| `ferry counter list / check / policy <name>` | who holds what; contested numbers; master-signed policy |
| `ferry root show` | lists each project's lanes |
| `ferry doctor` | warns about shared trees and stale or far-behind lanes |

## Ownership

Each lane declares globs it owns (`*` stays in a directory, `**` crosses directories, a bare
directory name covers everything under it). The declarations are one **signed record per lane**
in the project's channel (`lanes/<lane>.json`, written only by the lane's owner, so sync never
sees two writers). A record that does not verify is ignored and reported; it grants nothing.

A **hook set**, installed per worktree (`extensions.worktreeConfig` +
`git config --worktree core.hooksPath`, so no other worktree is touched; needs **git 2.20 or
later**, checked up front), covers every standard client hook. Each is a small wrapper that
reaches the repository's own hook of the same name: the folder its `core.hooksPath` names
(husky's `.husky/_`, say) or else `<common git dir>/hooks`. Ours adds one thing, in
`pre-commit`: the ownership check, which runs first. Nothing the repo already runs is dropped.
The check classifies every staged path (read with `git diff --cached -z --no-renames`):

- owned by this lane: fine;
- owned by **another** lane: the commit is **refused**, naming the path and the lane;
- owned by nobody: allowed, reported;
- a shared file (below): allowed, reported.

**When the channel cannot be reached** the check does not guess. Each successful check caches
the manifest in the worktree's git dir; offline, the cached manifest decides, so paths known to
be owned stay protected (fail closed for those). With no cache at all there is nothing to check
against: the commit is allowed, a warning is printed, and the gap is appended to
`ferry-lanes-warnings.jsonl` in the worktree's git dir.

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
3. git's `merge=union` driver (both sides' added lines kept) is used **only for files the lane
   declared append-only** (`--append-only DECISIONS.md`), recorded in the signed lane manifest
   and applied through a per-worktree attributes file and to the landing rebase. Nothing is
   written to the shared `info/attributes`. Union is wrong for a file edited in place (it
   would keep both versions of a changed line), so: `CHANGELOG.md` and `DECISIONS.md` are
   logs, declare them; `README.md` and `docs/*.md` are prose, do **not**: two lanes editing the
   same paragraph conflict, and the second rebases and resolves. Numbers come from
   `ferry counter next decision`, so entries do not clash (D30/D31 twice cannot happen);
4. a real conflict (both rewrote the same line) is a landing conflict: nothing changes, the
   second lane rebases and resolves.

## Landing

`ferry lanes land <lane>`, run by the agent or by a person:

1. the lane must be committed (its working tree clean);
2. take the **landing lock**: a machine-local OS lock in the repo's git dir, plus a signed claim
   at `lanes/landing/<agent>.<machine>.json` in the channel (15 minute expiry, earliest claim
   wins; the same agent on two machines has two claims, and a loser deletes only its own).
   A Syncthing conflict copy is never read as a claim;
   Only one landing runs at a time; others wait (`--wait`);
3. optionally fetch and fast-forward the base from the remote;
4. check ownership over the whole lane diff (`git diff -z --no-renames --name-only`, as the
   hook does, so non-ASCII names and a rename out of another lane's folder count);
5. **rebase in a scratch worktree** onto the base, so the lane's own files never pass through
   a half-rebased state;
6. conflict: `git rebase --abort`, remove the scratch worktree, list the files, post a signed
   notice to the lane's owner, exit non-zero. **The lane and the base are untouched**;
7. success: **re-check the lane under the lock** (same tip, no uncommitted change, no untracked
   file where a landed file arrives); if anything changed, nothing is touched and the landing
   is refused. Then keep the old tip at `refs/ferry/landed/<lane>/<time>` (always), fast-forward
   the base (in the checkout that has it, which must be clean; else `update-ref`), move the
   lane onto the new base with `reset --keep` (it cannot overwrite a local change), optionally
   push.

The settle wait after claiming the lock defaults to 1 s alone and 8 s as soon as the project
has lanes or claims from another machine.

The base moving under a landing (someone committed straight to main) makes the fast-forward
fail; run it again.

Across machines the channel claim is advisory (it travels at sync speed). The backstop is git:
the base only moves by fast-forward, and a push of a stale base is rejected by the remote, so
two machines cannot both land the same history.

## Retiring

`ferry lanes retire <lane>` refuses when the worktree has any uncommitted or **untracked**
file, when a live session is registered in it, when it has commits not on the base, or when it
cannot count them (including when the folder is already gone: the branch's commits are still
counted). `--force` overrides all of those, and even then the branch tip is first saved under
`refs/ferry/retired/<lane>/<time>`. `git worktree remove --force` is used only with `--force`.

## Counters

`ferry counter next decision --start 30` prints `30`, then `31`, ... The claim is a signed file
`counters/<name>/<n>.<agent>.<machine>.json` (a Syncthing conflict copy is ignored). For one number, the claim with the lowest
`(claimed_at, agent, machine)` among validly signed claims wins; a loser takes the next number.
Unsigned or forged claims count for nothing.

The guarantee, plainly:

- **Agents on one machine never collide**: allocation holds an OS lock and reads every earlier
  claim off the same disk.
- **Agents on different machines can claim the same number before either sees the other.** The
  rule still picks one winner everywhere, but a number is **final only after the settle
  window** (`--settle`, default 8 s whenever another machine appears in the project's lanes or
  claims, otherwise none) **and once peers' files have arrived**. `ferry counter check <name>` lists any number claimed twice and who
  won, so a late loser is found, not silent.
- **Make the safe thing the default where it matters.** The project's master can sign a policy:
  `ferry counter policy decision --allocator josh` (only that agent allocates; others are
  refused unless they pass `--provisional`), and/or disjoint ranges
  `--range ash=1000-1999 --range rf=2000-2999`, which cannot collide at all, at the price of
  non-contiguous numbers. When ranges are set, an agent with no range is **refused**, never
  given an open-ended one that could overlap.

## Credentials

The push token stays a sealed secret (`ferry channel secret set GH_TOKEN ...`). `ferry lanes
land --push` opens it in memory for this agent and hands it to the one `git` child process as
`GIT_CONFIG_COUNT/KEY/VALUE` environment (`http.https://<host>/.extraheader`), appended after
any `GIT_CONFIG_*` entries already in the environment. Only the fetch and push children get it,
with hooks switched off for those calls. It is never in the argument list, never in
`.git/config`, never on disk, and it is scoped to the remote's own host. Needs git 2.31 or
later (checked). A non-https remote gets no header.

## Doctor

`ferry doctor` warns when

- two live sessions are registered in one working tree (a session is live for 15 minutes after
  its last `lanes enter` or commit, and, when a pid was recorded with `--pid`, only while that
  process runs; without `FERRY_SESSION`/`CLAUDE_SESSION_ID` the id is derived from agent,
  machine and path, so one agent is one session, not many);
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
