# ADR 0023: Agents hand in, heads push

Status: accepted by the master (josh), 2026-10-08. Builds on 0014, 0017, 0019. Related to
docs/SCOPED_ACCESS_PROPOSAL.md.

## Context

Today every developer's agent works on that developer's git credentials. It can write
wherever its person can, it works blind to every other agent, and it pushes branches straight
into the repository for a human to untangle one pull request at a time. Nothing coordinates
one person's agents with another's, and nothing records what each agent was told.

Ferryman already keeps agents' *talk* out of the repository. This ADR keeps their *work* out
of it too, until it has been reviewed by someone with authority over that part of the code.

Three practical pains led here:

- Every worker machine held a token that could write to the repository, so a lost or
  compromised worker could damage `main`.
- Work done on one machine stayed on that machine's disk until someone pushed it.
- When the orchestrator ran out of tokens, nobody else could take over cleanly, because the
  right to push lived on one machine.

## Decision

### 1. Two folders under the ferry root

- `<root>/comms/<project>-ferryman` carries communication: orders, messages, presence,
  secrets. Unchanged.
- `<root>/work/<project>/<order-id>/` carries **handed-in work**. It is synced like comms.

Git checkouts are never synced. Each machine keeps its own clone and pulls. Syncthing and git
never manage the same files, because a `.git` directory under Syncthing corrupts.

### 2. Workers hand in; they do not push

When a worker finishes an order it writes a hand-in to `work/<project>/<order-id>/`:

- `handin.patch` - `git format-patch` output against a named base commit, so authorship and
  messages survive.
- `handin.json` - order id, project, agent, base commit, branch, file list, created time,
  and the agent's signature over the manifest and the patch's sha256.
- `files/` - optional large outputs (renders, models, datasets) that do not belong in git.

Only the assigned worker writes into its order folder, so there is never a second writer on
the same file. A worker never needs a write token.

### 3. Only the head pushes

The current head of a project (`head::current`, ADR 0017) reviews hand-ins:

- `ferry work list` shows hand-ins waiting.
- `ferry work accept <order>` verifies the signature, applies the patch in the head's own
  checkout with `git am` (the worker stays the author, the head becomes the committer), and
  pushes. No trailers are added; attribution is carried by git's own author field.
- `ferry work reject <order> --reason "..."` writes `rejected.json`, and the order goes back
  for revision.

Ferryman refuses `accept` from an agent that is not the current head. The head is a role,
not a machine: when the master appoints another head (by signed words, from anywhere,
including Telegram), the new head inherits the queue. Nothing waits on the old machine.

Workers that already push (`push = "<remote>"` in `agent.toml`) keep pushing **only if they
are the current head**. Otherwise their finished branch becomes a hand-in automatically.

### 4. Areas, for teams

A project may be split into areas. A signed `areas.json` in the channel maps paths to an area
and each area to its head and standby list - CODEOWNERS, but enforced by Ferryman.

- An area head accepts hand-ins for its area and pushes to its area branch, or its own area
  repository.
- A hand-in that touches another area's paths is split by path; the foreign part becomes a
  hand-in to that area's head. Nobody edits another area's code directly.
- One integrator (the master or a top head) merges area branches into `main` on a cadence.
- Changes that cut across every area go to the integrator as one coordinated order.
- If two areas wait on each other past a deadline, the integrator decides.

A solo project is one area covering everything. Areas are a later build; this ADR fixes the
shape so the hand-in format does not change when they arrive.

### 5. Hard boundaries use separate repositories

GitHub tokens cannot be limited to a branch or a folder inside one repository. So:

- **Division of labour among your own agents**: one repository plus Ferryman's area map.
  Enforced by Ferryman, a policy check.
- **A real security boundary** (a client, a contractor, a business unit): its own repository
  seeded from `main`, with the main repository as an upstream remote. Its head holds a write
  token for that repository only. The integrator merges it into `main`. Enforced by GitHub.
- **Later, Custodly**: one GitHub App per area or unit, minting short-lived write tokens only
  to whoever is head right now. Nothing else in this design changes when it arrives.

### 6. Credentials baseline

A machine holds at most two GitHub tokens for a project:

- **One read-only token per machine**, covering every repository of the owner
  (fine-grained PAT, "All repositories", Contents: read, Metadata: read). Named
  `GH_RO_<MACHINE>`, e.g. `GH_RO_GROUCHLY`, sealed to that machine's agents. Revoking a
  machine kills only its token.
- **One narrow write token per area**, held only by that area's head and standbys. Named
  `GH_RW_<PROJECT>` or `GH_RW_<PROJECT>_<AREA>`.

The type is declared by the name at sealing time, because GitHub does not report a
fine-grained token's permissions. Other people (contractors, teammates) get tokens scoped to
their grants, never the owner's all-repositories token. Organisation repositories need a
token from that organisation.

### 7. The librarian watches tokens

Advice, never action. `ferry doctor` (and the dashboard and Telegram, which read it) reports:

- **missing**: this machine has no `GH_RO_*` token, so its workers cannot pull;
- **orphaned**: a token sealed only to identities that are retired or not on the roster;
- **over-scoped**: a `GH_RW_*` token sealed to an agent that is neither head nor standby, or
  a bare `GITHUB_TOKEN` whose type cannot be told from its name;
- **expiring**: when this machine can open the token, GitHub's
  `github-authentication-token-expiration` header, warned at 14 and 3 days.

It never revokes or rotates. Until Custodly mints tokens, the person mints the new one.

### 8. Which machine does which work

Decided by what the work needs, never by which machine happens to be up:

- **Heavy** (GPU, large builds and test suites, media, orders the router sizes "large") goes
  to the machine that publishes a GPU and high power - beastly.
- **Light** (always-on services, polling, triage, docs, small fixes, reviews, waiting on
  remote APIs) goes to the cheapest always-on machine - grouchly.
- Each machine publishes its profile once; the router applies the rule. Heavy work for a
  machine that is off waits for it, and the master is told if it waits over a day.

### 9. Migration

Nothing for a person to run. On the first worker pass after `ferry update`, the machine
creates `<root>/work/<project>/` for every project it serves and switches to hand-in mode
unless it is the current head. `ferry doctor` shows `work_folder` and `handin_mode`.

## Consequences

- Git contains only reviewed work. Review stops being a convention and becomes the only path
  into the repository.
- Worker machines need only a read token; losing one exposes no write access.
- The head is a bottleneck. At small scale that is fine; areas spread it at larger scale.
- Prompts that told agents to "commit and push your work" change to "hand in your work".
