# ADR 0019: One root called `ferry`, described by a `.ferry` manifest

## Status

Accepted.

## Context

The dashboard showed one project when the machine held nineteen. Discovery read the
directory *beside wherever it was launched*: a fleet kept as siblings was found, a
checkout on another drive was not, and the miss was silent — a picker that simply shows
fewer projects than exist looks like a working feature, not a bug.

The operator proposed a fix. Most of it is right and is what this ADR builds. One part
must not be built, and that refusal is more important than the construction.

## Decision

### One machine-local root called `ferry`

```
ferry/
  comms/     every channel: <project>-ferryman/
  repos/     repositories Ferryman itself cloned
  work/      task worktrees, which are transient
  .ferry     the manifest an engine reads first
```

The root is machine-local, so it is found deterministically — `FERRYMAN_ROOT` when set,
otherwise `$HOME/ferry` (`%USERPROFILE%\ferry` on Windows) — never by asking "what
directory am I standing in". That is the whole point: discovery must not depend on where
it was launched.

### The `.ferry` manifest is an index, not authority

`.ferry` is a machine-local JSON file at the root. It describes the layout and, for every
project this machine has adopted, the channel path and the repository path wherever that
repository actually is. Paths in it are machine-specific, which is exactly why Windows and
WSL disagree on this machine today and why the file must never travel in a channel.

Its shape:

```json
{
  "version": 1,
  "comms": "comms",
  "repos": "repos",
  "work": "work",
  "projects": {
    "ferryman": {
      "channel": "/home/user/ferry/comms/ferryman-ferryman",
      "repository": "/mnt/repos/ferryman"
    }
  }
}
```

It is an index, not a source of truth:

- A project present on disk but absent from `.ferry` still works; the directory scan
  notices it and it can be adopted.
- Deleting `.ferry` costs nothing but convenience: discovery falls back to the scan and
  everything keeps working.
- A recorded path that no longer exists is dropped on read, not reported — a picker
  offering a project it cannot open looks like the switch did nothing.

### Discovery reads the manifest, then the scan

Discovery reads `.ferry` (the known projects) and the scan is demoted to the thing that
notices a channel nobody has recorded yet. The scan is kept because a fresh checkout that
predates this change must still appear the moment its channel is on disk.

### Anything Ferryman creates goes in the root

A channel it opens, a repository it clones, a worktree it makes — all under the root, with
no prompt and no configuration. Task worktrees move from `repo.parent()` to `work/`, where
they are namespaced by repository so two projects that happen to issue the same order id
cannot collide.

## The refusal

The proposal included: when Ferryman meets a repository outside the root, **move it in**.
That must not be built, and the reason is already in this codebase.

`create_worktree` put worktrees beside the repository. A worktree's `.git` is a *file*
holding an absolute path back to its repo, so moving a repository breaks every existing
worktree. `worktree.rs` already documents that exact failure: a directory "whose repo has
moved, looks identical from out here and is not a checkout at all: git refuses to operate
in it". The comment exists because it happened.

Beyond git, a repository's absolute path lives in an IDE's project list, a shell history,
another tool's config, a running process's working directory. Moving it breaks those
quietly, one at a time, over days.

The reason underneath: this project's thesis is that the files are the truth and Ferryman
carries the channel, not the work. A tool that relocates a person's repositories to suit
its own filing has become a different kind of tool. Coordinating work does not entitle it
to the filesystem.

So: **adopt in place**. The repository stays where it is; `.ferry` records where. A tidy
view may put a *link* to an adopted repo under `repos/` — a link that costs nothing to
break — but nothing moves a directory the user made.

## Migration

Writing down where things already are is safe, reversible, and runs without asking.
Adoption records a repository into `.ferry` without touching it: `ferry enable` appends an
entry carrying the channel and repository paths it already knows. A migration that moves
anything is exactly what this ADR refuses. Existing installs keep working untouched and
are adopted where they stand — including worktrees already sitting beside their
repositories, which are reused in place and never relocated.

## Consequences

**Discovery finally finds the whole fleet**, on any drive, without depending on the launch
directory.

**The root becomes the place a machine can be reasoned about.** One directory contains
everything Ferryman made, which makes "what did this machine create" answerable, and makes
backup a single path rather than a scavenger hunt.

**Nothing moves, ever.** This ADR closes the door on the one part of the proposal that
would have quietly corrupted worktrees and tooling. A future design that wants to move a
user's directory must stop and say so, not ship.

**Deleting `.ferry` is safe by construction.** The file is convenience, not state. Losing
it costs the machine its index; it costs no project anything.
