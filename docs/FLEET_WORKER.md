# One worker, every project

A worker is one identity (`agent` in its `agent.toml`) with one set of engines. The work it
can do is the work of every project whose roster it is on, so it should not take one
process, one `agent.toml` and one hand-made setup per project. Two commands do that.

```text
ferry team approve <name> --all        # once: put the identity on every project you master
ferry agent run --all-projects         # then: one worker serves all of them
```

Setting a machine up for this is one command, `ferry fleet setup` (see [FLEET_SETUP.md](FLEET_SETUP.md)): it makes the fixed layout ([LAYOUT.md](LAYOUT.md)), gives every project its own clone in `repos/<project>`, picks the machine's one worker identity and, with `--service`, installs the one service that runs it. The rest of this page is what that worker does.
## Serving every project: `ferry agent run --all-projects`

Run it next to the worker's own `agent.toml` (or pass `--workspace <dir>`):

```text
cd X:\ferryman
ferry agent run --all-projects --dry-run     # what it would do, per project
ferry agent run --all-projects               # do it
```

It runs as the identity and engine config of that one `agent.toml`, for every project in
the ferry root (`ferry root show`), or in the root that `--comms <folder>` points into. The
engines, the router and `max_parallel` are the config's and are shared: a pass works one
project at a time and each claims at most `max_parallel` orders, so `max_parallel = "4"` is
four orders at once across all projects, not four per project. A project's own `agent.toml`
is not read.

Each pass visits the projects in the fleet's focus order (focus first, then normal, then background, then paused; see FOCUS.md), and an improvement order in a background or paused project is held as usual.

A project is served when all of these hold, and otherwise skipped with one line that says
which and what to do:

- its channel folder is here and it is not archived;
- its master has not signed `swarm = off` for it, and this machine does not exclude it (see below);
- it has a checkout on this machine (a repository with `.ferryman` in it; `ferry repos sync` makes the managed clone, `repos/<project>`, which is the checkout a fleet worker uses, never a person's working copy). A project that
  is only a channel here has nowhere to do work. Clone it and run `ferry enable` in it;
- the checkout's `bridge.toml` reads its channel from the folder the ferry root files the
  project under;
- the channel's own roster lists the identity under the same key this machine signs with;
- the master has not revoked it (or its owner), and `may_work` allows the configured `role`.

Where the checkout does not hold the identity's key yet, this machine's own copy is put
there before the first pass, as `ferry channel seat` would. It only copies a key between two
directories of one machine, only for a project whose roster already lists exactly that key,
and it never replaces a different key. It also never puts the key in a checkout whose git
would commit it: if `.ferryman` is not git-ignored there, the project is skipped and says
to run `ferry enable` in it, which adds `/.ferryman/`.

The answers above are asked again before each project's turn, every pass. A revocation of
the identity or its owner, or the master archiving the project, stops the next pass rather
than waiting for a restart. A project another worker already holds the lock for, or whose
lock cannot be written, is named and left out; the rest are served.

`--dry-run` prints, per project, `would serve as <identity> with engines ...` or
`not serving: <why>`, then the orders it would act on. It notes any worker already running as
the same identity for that project. Stop that one first: two workers under one name resume
each other's claims and run the same order twice, so the new one refuses to start while the
old one holds its lock.

`--comms <folder>` without `--all-projects` is unchanged. It watches a folder of checkouts,
each under its own `agent.toml`. A ferry root's `comms/` holds channels, not checkouts, so it
finds none of them and prints a line pointing here.

## Enrolling an identity: `ferry team approve <name> --all`

```text
ferry team approve ichabod-beastly-swarm --all
ferry team approve ichabod-beastly-swarm --all --as josh --role worker
```

For every project in the ferry root whose master is you, it writes the roster entry (the
same public key, role worker) and your signed grant, and reports each project as one of:

```text
  alpha: added (roster entry and grant, signed by josh)
  beta: already there
  gamma: skipped - its master is bob, not josh
  delta: skipped - 'ichabod-beastly-swarm' was revoked there. Enrolling would lift that; ...
```

- It needs your master identity exactly as `team delegate` does: your operator password,
  asked for once, and only when something is about to be written. A project that is already
  enrolled, or that someone else masters, never asks for it.
- `--as <master>` says whose identity signs. Without it, it is whoever masters the most
  projects in the root. Projects mastered by anyone else are skipped.
- The key is this machine's own copy of the identity (beside the directory you run it in, or
  in any checkout of the root). A worker that lives on another machine is named by its public
  key: `--key <64 hex characters>`. A roster is never the source, because any member of a
  project can write one, and a key taken from it would be enrolled in every project at once.
  Two different keys for the name on this machine, or a `--key` that is not the held one,
  stop it before anything is written.
- In each project the identity you sign with must be the key that project's roster knows the
  master by, not only a name that matches. A name that is revoked there, or whose owner was,
  is left alone.
- Safe to run again. A roster that already knows the name under a different key is left
  alone (first key wins). A name you revoked in a project stays revoked; lifting that is
  `ferry team approve <name>` in that project, on purpose.
- It does not edit manifests or bypass any signature check. It uses the same roster and grant
  writes as `team approve`, one project at a time.

A worker needs no grant to work (ADR 0014), so `may_work` passes for a worker once it is on
the roster and not revoked. The grant is there for machines still on an older version and so
the enrolment is visible in the channel's signed record.

## One worker per machine

Two workers on one machine claim the same orders and race each other. `ferry agent run --all-projects` looks for another live all-projects worker, and for a worker service or scheduled task that is enabled, before it starts. It refuses to be the second all-projects worker and names the other one (what is running, how it was started, how to stop it); `--allow-second-worker` overrides that, for a test. Any other worker is a warning. `ferry doctor` prints the same as a `workers` line, and `ferry doctor --layout` makes it a check. `ferry fleet setup --service` installs the one service and turns the others off without deleting them.

## Keeping a project out of the swarm

A project's master can sign `swarm = off` into its channel (`ferry root swarm off --project pc-secrets`, or the dashboard's Teammates page), and a machine can exclude a project for itself (`ferry root swarm exclude pc-secrets`). Either way the project is skipped here with the reason, a worker already running drops it at its next pass, `ferry repos sync` does not clone it and `ferry team approve --all` does not enrol anyone in it.

## A project's own policy

A project with binding rules of its own declares them in its repository, and the worker injects them into that project's prompts and no other project's: `[policy] files = [...]` in a `ferryman.toml` at the repository root, plus an optional `.ferryman/POLICY.md` in the clone that is this machine's own addition and comes last. Each file is cut at 12 KiB and the whole policy at 32 KiB; paths must stay inside the repository. `--dry-run` and `ferry route explain` print `policy: <files>` for each project. See [FLEET_SETUP.md](FLEET_SETUP.md#per-project-policy-in-fleet-mode).