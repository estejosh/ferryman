# ADR 0019: One place called ferry, and nothing of the user's is moved into it

## Status

Proposed.

## Context

Finding things is guesswork today. `discover_projects` reads the directory beside
wherever the dashboard happened to be launched; `find_project_route` does the same. That
finds a fleet kept as siblings, finds nothing from a checkout on another drive, and
cannot see two locations at once — and it fails *silently*, showing one project as though
one is all there is. The operator asked why his dashboard could only see one project, and
he was right to.

ADR 0018's work added an index learned from use, which helps. It does not answer the
question underneath: **where do things go.** A person who has never used Ferryman has
nowhere obvious to put a channel, and an agent has nowhere obvious to look.

## Decision

### One root, described by a file

```
ferry/
  comms/                     every channel:  <project>-ferryman/
  repos/                     repositories Ferryman itself cloned
  work/                      task worktrees, which are transient
  .ferry                     what is here, and where anything outside here lives
```

`.ferry` is the manifest an engine reads first: the layout, and for every project its
channel path and its repository path — wherever that repository actually is. It is
machine-local, because every path in it is, and for that reason it never travels in the
channel.

This replaces guessing with reading. It is also the thing a person can be told in one
sentence: *your Ferryman lives in `ferry/`.*

### Anything Ferryman creates is created there

A channel it opens, a repository it clones, a worktree it makes: all default into the
root. No prompt, no configuration, no decision for a person who does not want one.

### Nothing of the user's is ever moved into it

The proposal that prompted this went one step further: when Ferryman meets a repository
outside the root, move it in. That step is refused, for a reason this codebase already
documents against itself.

**Worktrees are created beside the repository.** `create_worktree` uses `repo.parent()`.
So moving a repository does two things at once:

- Every existing worktree breaks. A worktree's `.git` is a file holding an *absolute*
  path to its repository. `worktree.rs` already knows this failure and describes it: a
  directory "whose repo has moved, looks identical from out here and is not a checkout at
  all: git refuses to operate in it". The comment exists because it happened.
- `repos/` becomes a mixture of repositories and transient task worktrees, since the
  worktrees would now be created as siblings inside it — and the next thing that scans
  that folder cannot tell them apart.

Beyond git, a repository has an absolute path in an IDE's project list, a shell's
history, another tool's config, a running process's working directory. Moving it breaks
those quietly, one at a time, over days.

And the deeper reason: this project's thesis is that **the files are the truth and
Ferryman carries the channel, not the work**. A tool that relocates a person's
repositories to suit its own filing has changed what it is. Coordinating work does not
entitle it to the filesystem.

So: **adopt in place.** The repository stays where it is and `.ferry` records where that
is. Discovery gets everything it wanted; nothing of the user's moves. If the tidy view is
wanted, `repos/` may hold a link to an adopted repository — a link that breaking costs
nothing.

### Worktrees move out of the repository's parent

This is the improvement the proposal surfaces, and it is worth doing on its own. Task
worktrees are transient and Ferryman-owned, and putting them next to the user's
repository litters a directory that is not ours — which is also why a scan of that
directory finds things that are not projects. They belong in `ferry/work/`.

## Consequences

**"Where is my stuff" gets one answer**, for a person and for an agent, which is worth
more to a non-technical operator than any amount of cleverness in discovery.

**Discovery stops being a scan.** `.ferry` plus the usage index answers directly; the
scan stays only as the thing that notices a channel nobody has told us about.

**Two roots have to stay in step on a split machine.** Windows and WSL are different
machines by this reasoning, and today they genuinely disagree: 19 of these channels have
a route in WSL and 2 on Windows. `.ferry` makes that visible instead of mysterious. It
does not merge them, and it should not pretend to.

**Existing installs keep working, and are adopted where they stand.** A migration that
moves things is exactly what this ADR refuses; a migration that writes down where things
already are is safe, reversible, and can run without asking.

## What this is not

Not a package manager, and not a workspace tool. It files what Ferryman makes and
remembers where everything else is. The moment it starts moving a person's work around to
suit its own layout, it has stopped being a thing that carries messages.
