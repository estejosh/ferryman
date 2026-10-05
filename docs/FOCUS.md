# Focus: which projects the swarm spends itself on

One person runs many projects. The weekly self-improve loop and the fleet's workers used
to treat every one of them the same. The focus is the master's own, signed word about which
projects matter this month, so the swarm can give them most of the improve time and the
first claim on a worker, and leave the rest a trickle.

Nothing here is automatic. The signals ([`ferry focus suggest`](#suggestions)) only
propose; the master signs the tiers they choose, from the CLI, the dashboard or Telegram.
With no focus signed, every project is `normal` and the swarm behaves exactly as it did
before this existed.

## Tiers

| Tier | Weight | What it gets |
| --- | --- | --- |
| `focus` | 12 | most of the weekly improve budget, the policy's full width, first claim on a worker |
| `normal` | 3 | a fair share; half the policy's width, rounded up. A project with no entry is normal |
| `background` | 1 | a trickle: at least one improvement order a week, one at a time |
| `paused` | 0 | nothing of the swarm's own initiative |

An entry may carry an expiry (`--days N`, one to 366). When it passes, the project is
`normal` again on its own, and the next signing drops the entry.

A tier decides what the swarm does *on its own initiative*: the improve loop's planning,
the width of improvement orders, and the order a worker looks at projects in. It never
holds back a person's own orders - an order you send runs whatever tier its project is in.
It does not touch the per-project self-improve switch either: self-improve stays an
on/off choice per repo, and a tier only shares out the budget among the projects that have
it on. An archived project gets nothing, in every tier, and is left out of every view.

## Where it lives

In the channel of one *home* project, `ferryman` unless `FERRYMAN_FOCUS_HOME` names
another, as a file called `FOCUS`.

- Not in the ferry root: its manifest (`.ferry`) is machine-local and never syncs.
- Not a file in every project's channel: thirty copies is thirty places to roll back and
  thirty sequence numbers to keep in step.
- The home channel is already carried to every machine in the fleet by Syncthing, has the
  master the fleet already trusts, and every machine that runs a worker has it. A machine
  without the home channel has no focus, which reads as every project being `normal`.

## Trust

The same shape as the engine policy (`ENGINE_POLICY`), and nothing on disk is trusted.

- The record is honoured only when it is signed by the home channel's master, or by a
  delegate holding the master's `improve` delegation (the Telegram bridge signs this way),
  over exactly what it says. The home project id is inside the signed payload, so a record
  cannot be lifted from another channel.
- It carries a sequence number. Each machine remembers, outside the synced folder, the
  highest it has accepted and the last good record. An older signed copy put back, a
  doctored file, or a deleted file leaves the last good record in force and raises a
  notice; the master signing again repairs it.
- Clearing the focus is therefore a newer, *empty* record, never deleting the file.

## Commands

```text
ferry focus show                       the tiers in force, what each comes to this week
ferry focus set <project[,project]> <focus|normal|background|paused> [--days N]
ferry focus suggest [--json]           signals and the seed list, one reason per project
ferry focus clear [<project[,project]>]
```

`set`, and `clear`, sign as the home project's master on this machine. They fail for
anyone else. A project that is archived is refused; one that is not in this machine's ferry
root is recorded anyway (with a note) and takes effect where the project is.

## Dashboard

The **Focus** page lists every project with its tier, when it expires, whether self-improve
is on, how many improvement orders it gets this week and its widths. The master changes a
tier or clears the focus there; the change is signed as the master, as dashboard policy
edits are. Anyone else sees it read-only, and a signed-out request is refused
(`GET`, `POST /api/focus`, `POST /api/focus/clear`; `GET /api/focus?suggest=1` adds the
suggestions).

## Telegram

**Menu, Focus** lists the projects with their tier. Press a project and choose a tier
(focus for 30 days, focus until changed, normal, background or paused for 30 days), or
clear the whole focus. The bridge signs as the master's delegate, so it needs the `improve`
delegation it already has for self-improve; without it the screen says so.

## Suggestions

`ferry focus suggest` combines four signals read without running anything, and shows one
reason per project:

| Signal | Points |
| --- | --- |
| commits in the last 30 days (when the checkout is on this machine) | 0, 1 (1-4), 2 (5-19), 3 (20+) |
| open orders | 1 (1-2), 2 (3+) |
| orders sent back, refuted or stale | 1 each, up to 3 |
| evidence items in the last `improve gather` | 1 (1-4), 2 (5+) |
| quiet for over 90 days / over 30 days / active this week | -3 / -2 / +1 |

A score of 6 or more suggests `focus`, 2 to 5 `normal`, below that `background`. A project
with a signed entry keeps it. Where the master has named a focus (a signed record with a
focus entry, or a seed list) the signals never promote another project to `focus`: they say
`normal` at best, and can only suggest `background` for one that has gone quiet. They fill
in what you have not said; they do not second-guess what you have. A project whose checkout
is not here has no git signal, which is not the same as no activity, and says so.

### The seed

With no signed record, `suggest` starts from your own list: the projects named in
`FERRYMAN_FOCUS_SEED` (comma separated) or, one per line, in a file called `focus-seed`
in the ferry root (`#` starts a comment). The list is yours and stays on your machine;
none is built in. It proposes those projects as `focus`, names any that are not on this
machine, and signs nothing. To accept it, run the `ferry focus set ... focus --days 30`
line it prints.

## What the allocation does

**Budget.** `ferry improve run` plans `per_project` improvement orders (`--max`, five by
default) for each project that has self-improve on and is not paused. The focus does not
change that total; it moves it. Each project's share is its weight over the sum of weights,
rounded by largest remainder, at least one and at most three times `per_project`. With
everyone in one tier each project gets exactly `per_project`, as before. Five each over a
focus, a normal and a background project is 11, 3 and 1; a paused project gets none, and
`improve run` skips it and says why. Projects are visited in claim order, focus first.

**Width.** The policy's per-role width (how many improvement orders of a role may be claimed
at once) is scaled by tier: `focus` keeps it, `normal` gets half rounded up, `background`
gets one, `paused` none. It applies only to improvement orders, and only when a focus is
signed, so with no focus nothing is capped. Once one is signed, a focus or normal project whose policy sets no width stays uncapped, while background and paused are still limited.

**Claim order.** `ferryman_channel::focus::Focus::claim_order(&ids, now)` is a pure function:
a stable sort of project ids by tier, focus then normal then background then paused. The
fleet loop (`ferry agent run --comms`) uses it to visit the channels it serves, with an
archived project last. A worker also asks `focus::hold_for(route, order)` before claiming,
so a paused project's improvement orders wait and a background one is held to one at a time.

## For a loop that serves many projects

A loop that serves several projects, such as `--all-projects` on the fleet worker, needs
three lines to follow the focus:

```rust
let focus = ferryman_channel::focus::current();
let ids: Vec<String> = routes.iter().map(|r| r.project_id.clone()).collect();
for id in focus.claim_order(&ids, chrono::Utc::now()) { /* work_once for that project */ }
```

`ferryman_channel::focus::claim_order(&ids)` does the same with this machine's focus. The
hold on improvement orders is already in the worker's claim path and needs nothing more.