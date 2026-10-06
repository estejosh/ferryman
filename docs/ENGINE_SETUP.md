# Engine setup: pointing a worker at your agent CLI

`.ferryman/agent.toml` decides what actually does the work. Ferryman runs no
models itself and has no preferred vendor: it starts one command per task, with
the task text substituted where you put `{prompt}`, and reads back whatever the
engine prints.

```toml
command = "claude"
args = ["-p", "{prompt}"]
```

This page covers the three contracts Ferryman knows out of the box, how to wire
any other engine, and how credentials reach an engine that authenticates from
the environment. It is provider-neutral throughout; the OpenCode + OpenRouter
walkthrough below is a worked example, not a requirement.

## The one rule: there is nobody to approve anything

Interactive engines ask before touching files. A worker has no terminal for
that question — the engine sits waiting until Ferryman's stall watchdog kills
it, and the failure reads as something useless like "printed nothing for 600s".
So a headless worker needs its engine's *non-interactive* form **and** its
auto-approve flag. That is a real grant: the engine then reads, writes and runs
commands in this workspace with your account's privileges and nothing in the
way. Prefer `sandbox` in the same file over trusting the flag alone, and read
the isolation note at the top of `.ferryman/agent.toml`.

## Known engines

`ferry enable --command <name>` writes these automatically:

| Engine | Written contract | Notes |
|---|---|---|
| `claude` | `["-p","{prompt}"]` | The permission grant (`--dangerously-skip-permissions`) is deliberately **not** added for you; add it yourself if you accept what it grants |
| `opencode` | `["run","--auto","{prompt}"]` | `opencode run` is the non-interactive mode; `--auto` approves permissions not explicitly denied |
| `codex` | `["exec","--full-auto","{prompt}"]` | |
| *(anything else)* | `["-p","{prompt}"]` | Almost certainly wrong; edit `args`, and enable warns at setup time |

Matching is on the command's file name, so `/usr/local/bin/opencode` resolves
like `opencode`. Give the engine an absolute path when it must be exact — on
WSL, `claude` on your PATH is often the **Windows** install, which a Linux
worker cannot use; point `command` at the Linux binary inside the WSL
filesystem.

## Worked example: OpenCode with OpenRouter

Verified against OpenCode's published CLI reference. OpenRouter is used here as
a concrete provider because it fronts many engines, including models reached
through a gateway slug such as `stealth/ox-alpha`; the same shape works for any
provider OpenCode knows (list them with `opencode models openrouter` — model
ids change often enough that you should check rather than copy).

1. Install [OpenCode](https://opencode.ai) so `opencode --version` works on
   this machine, and authenticate once interactively:

   ```sh
   opencode auth login      # choose OpenRouter; stored in ~/.local/share/opencode/auth.json
   ```

   ...or skip auth storage entirely and hand the key through Ferryman as shown
   in step 3.

2. Enable with OpenCode as the engine:

   ```sh
   ferry enable --email you@example.com --command opencode
   ```

   `.ferryman/agent.toml` comes out already correct:

   ```toml
   command = "opencode"
   args = ["run", "--auto", "{prompt}"]
   ```

   To pin the model, either record it for the fleet's cost/quality attribution
   without changing behaviour:

   ```toml
   model = "openrouter/stealth/ox-alpha"
   ```

   or force it into every run by adding `-m` and the id to `args`:

   ```toml
   args = ["run", "--auto", "-m", "openrouter/stealth/ox-alpha", "{prompt}"]
   ```

3. Get the key past the environment scrub. A worker process is deliberately
   stripped of secret-looking variables — `OPENROUTER_API_KEY` is removed by
   name, and anything containing `API_KEY`, `TOKEN`, `SECRET`, `PASSWORD`,
   `PASSPHRASE`, `CREDENTIAL` or `PRIVATE_KEY` goes with it. The only way one
   reaches the engine is the operator-listed allowlist
   `.ferryman/credentials.json`:

   ```json
   { "OPENROUTER_API_KEY": "sk-or-..." }
   ```

   That file lives under `.ferryman/`, which `enable` excludes from git and
   which sits outside the synced channel folder, so the key neither commits nor
   syncs. Never move it elsewhere "to be safe" — that is how keys reach public
   repositories. `ferry doctor` reports whether the file exists and never what
   is inside it.

4. Prove it end to end before trusting it:

   ```sh
   ferry doctor
   ferry agent run &
   ferry channel order --agent <your-name> --id t-first \
     --task "print the first three lines of README.md"
   ferry channel tasks
   ```

## Claude Code specifics

- Add the permission grant yourself if you want unattended work:
  `args = ["-p","--dangerously-skip-permissions","{prompt}"]`.
- Sandboxed? Claude authenticates from a credential directory in your home;
  mount the least that works:
  `mounts = "/home/you/.claude:/root/.claude"`. Reaching instead for an API key
  quietly moves work off a subscription onto metered billing — a pricing
  decision nobody made on purpose.
- Large tasks can abort mid-stream in `-p` mode (see Known issues in the
  README). Scope orders small until that is understood.

## Several engines, and falling back between them

One agent can list several engines in order of preference. When one runs out of
credit - HTTP 402, "insufficient balance", "usage limit", a 429 asking for ten
minutes or more - it is marked exhausted until the reset the message gives (six
hours when it gives none), the failure is **not** counted against the order, and
the same order goes straight to the next engine at the same tier or above. An
ordinary failure is handled exactly as before.

```toml
agent = "ichabod-grouchly-cline"
# command, args and model stay as they are: they are what an old config runs, and
# what a CLI engine without a command of its own runs.
command = "ferryman-cline"
engines = ["nvidia", "deepseek"]

# NVIDIA's free tier, through the same cline runner, so it can edit and commit.
# `env` points the runner at NVIDIA's OpenAI-compatible endpoint: use the names your
# runner reads (the common OPENAI_* ones shown). Values are secret:NAME or env:NAME,
# never a key. base_url and key are for the probe; probe = "chat" asks for one token
# instead of listing models, because some listed models answer 404.
engine.nvidia.kind = "cli"
engine.nvidia.model = "nvidia/nemotron-3-super-120b-a12b"
engine.nvidia.env = {"OPENAI_BASE_URL":"https://integrate.api.nvidia.com/v1","OPENAI_API_KEY":"secret:NVIDIA_API_KEY","OPENAI_MODEL":"nvidia/nemotron-3-super-120b-a12b"}
engine.nvidia.base_url = "https://integrate.api.nvidia.com/v1"
engine.nvidia.key = "secret:NVIDIA_API_KEY"
engine.nvidia.tier = "build"
engine.nvidia.paid = "free-tier"
engine.nvidia.probe = "chat"
engine.nvidia.weekly_requests = "400"

# The runner as it is set up today (DeepSeek). With base_url and key the probe also
# reads DeepSeek's balance, so an empty wallet is known before an order is tried.
engine.deepseek.kind = "cli"
engine.deepseek.model = "deepseek-v4-pro"
engine.deepseek.base_url = "https://api.deepseek.com"
engine.deepseek.key = "secret:DEEPSEEK_API_KEY"
engine.deepseek.tier = "build"
engine.deepseek.paid = "prepaid"
engine.deepseek.weekly_usd = "5"
```

An engine can also be `kind = "http"`: an OpenAI-compatible endpoint asked once per
order (`base_url`, `model`, `key`). It answers in text and cannot edit files, so it
suits judging, planning and chores, not building.

- **Tiers**: `judge` plans and reviews, `build` builds, `chore` does orders marked
  `"tier": "chore"`. An order goes to its own tier first and only climbs: a chore
  engine never builds, and a judge builds only when every builder is out.
- **A CLI pointed at an endpoint** is how an HTTP-only model edits code: give the
  CLI engine its own `command`, `args` (`{model}` and `{base_url}` are filled in)
  and `env` - a JSON object whose values may be `secret:NAME` or `env:NAME`, e.g.
  `engine.nim-code.env = {"OPENAI_BASE_URL":"https://integrate.api.nvidia.com/v1","OPENAI_API_KEY":"secret:NVIDIA_API_KEY"}`.
  `base_url` and `key` on a CLI engine are used only by the probe.
- **Local models**: `engine.local.base_url = "http://localhost:1234/v1"` (LM Studio)
  or `http://localhost:11434/v1` (Ollama) is `paid = "local"` automatically.
- **Probes**: every ten minutes the worker lists each endpoint's models (or asks
  for one token), reads DeepSeek's and OpenRouter's balance endpoints when it has
  their key, and checks a CLI is on PATH. A CLI is never run just to probe it.
- **Budgets**: `weekly_requests` and `weekly_usd` (list prices, from the usage the
  engine reports) make an engine exhausted until Monday 00:00 UTC once reached.
- **Where it shows**: each worker publishes a signed `engines/<agent>.json` beside
  its presence file, with no credentials in it. `ferry engines` shows the whole
  fleet; `ferry mcp serve` has a read-only `list_engines` tool.

## The weekly improvement loop

Off for every project until its master switches it on: `ferry improve on [project]`
(or `--workspace <dir>`), or the Self-improve button on the dashboard's Teammates
page. The setting is signed by the master and lives in the channel, so every machine
honours it; one anyone else signed is ignored. `ferry improve off` switches it back,
and `ferry improve status` lists every project with its switch and last run. Only
projects switched on take part in anything below.

`ferry improve run` does whichever steps are due for every project (all of them in
the ferry root, or `--comms <dir>`, or `--workspace <dir>`), and is safe to call from
n8n or cron as often as you like:

- `gather` - the last seven days (send-backs, failed runs, late orders, doctor,
  TODO/FIXME, the learning database) into `improve/<week>/evidence.md`;
- `plan` - the engine the engine policy (below) puts first, a judge when it allows one, turns it into at most `--max` (5) ranked
  improvements with acceptance checks, each a signed order tagged `improvement`,
  open to any worker, on its own branch. With no judge up a builder plans and the
  plan is marked unreviewed. Once a week; a second run issues nothing new;
- `review` - with a judge up, reviews improvement results through the ordinary
  review mechanism and reads any unreviewed plan. Never merges;
- `report` - `improve/<week>/report.md`: done, success and send-back rates, median
  time to claim and cost, this week against last, and what is ready to merge.

`improve = "true"` in `agent.toml` lets the worker run it itself, at most hourly.
`ferry pause` stops all of it.

Projects are visited, and the weekly budget of `--max` orders each is shared out, by the
master's signed focus (`ferry focus`, the dashboard's Focus page, or Telegram's Focus
button): focus projects first and most, paused projects skipped. With no focus signed,
every project is treated alike. See [FOCUS.md](FOCUS.md).

## Which engines do background work: the engine policy

Self-improve runs with nobody watching, so it must never quietly spend the Claude or
Codex limits you need on Thursday. Each project has an **engine policy** that decides
which engines do its background work - the loop's planning and review, and the
improvement orders it issues - in what order, which never, and on which machines.
Orders you give yourself are yours to spend on: the policy does not touch them unless
it says `never_applies_to = "all"`.

With no policy signed the fleet runs on **auto**: local engines first, then free
tiers, then prepaid engines with a weekly cap, then unknown, then uncapped prepaid,
and a subscription never. Ties go to the engine whose results have held up best
(verified against refuted), then the cheaper per verified result, then your order in
`agent.toml`. A `claude` or `codex` CLI with no `paid` set is taken for the
subscription it almost always is; set `paid` to say otherwise. A free tier that
returns a payment or quota error, or reports a cost, is flagged, ranked down for a
week, and you are told once.

```sh
ferry engines                        # the fleet, then each project's policy and who it blocks
ferry engines policy recommend       # what auto would choose, one reason per choice
ferry engines policy accept [--all]  # sign it
ferry engines policy show [--json]
ferry engines policy set --role build --prefer <selector>... --never <selector>... --where <agent>...
ferry engines policy clear           # back to auto
```

A selector is an engine name (`nemotron`), a model glob (`nvidia/nemotron*`), a paid
class (`paid:free-tier`, `paid:subscription`) or an endpoint host
(`host:deepseek.com`). A bare word also matches a model or host containing it, so
`claude` blocks the `claude` engine and every `claude-*` model. Without `--role`,
`--prefer` sets the order for all four roles: `plan`, `build`, `review`, `chore`.
`--where` lists the agents or machines allowed to run the project's self-improve; a
worker anywhere else leaves its improvement orders unclaimed. `--cap-usd` with
`--role` caps what the fleet spends on that role in a week.

The simple way is two choices: what **improves** (plans and builds) and what
**reviews**. The dashboard's Engine policy panel has a dropdown for each, with each
engine's paid class and the recommended one marked, and a "Use recommended" button;
Telegram's Engines menu has an "Improvement engine" and a "Review engine" button. From
the CLI:

```sh
ferry engines policy set --improve nemotron --review deepseek --never claude --where grouchly --all
```

Example - free model first, never my subscription, only on the always-on machine,
for every project I am master of, with the full lists:

```sh
ferry engines policy set --prefer nemotron --prefer deepseek --never claude --where grouchly --all
```

Planning and review want a `judge`-tier engine: a builder may plan (the plan is
marked unreviewed), but only a judge reviews. If nothing you allow is a judge, give
one `engine.<name>.tier = "judge"` in `agent.toml`, or review waits.

When nothing the policy allows can do the work it **waits** - it never falls back to
a blocked engine - and you are asked once a week per role, with buttons on the phone
(Accept recommended, or keep holding). Setting the policy takes the master's
signature, like `ferry improve on`, and the signed `ENGINE_POLICY` file travels with
the channel; one anybody else signed or edited is ignored. The dashboard's Teammates
page and the Telegram Engines menu show the same thing and can accept, block or move
an engine to the top. `ferry improve status` and `ferry improve report` say which
engine and model, on which machine, did each step, and what each engine spent.

## Mixed fleets and what a fresh machine trusts

The signed files that decide what the fleet may do - `ENGINE_POLICY`, `ADVERSARY_POLICY`
and the engine inventories - are only as protected as the oldest machine that reads them
and the newest thing a machine has already seen. Know the edges.

- **A fresh machine trusts the first valid file it sees.** Rollback protection lives in
  each machine's own state directory, not in the channel: the highest sequence number it
  has seen and the last good policy. A machine that has never read the channel has none,
  so whatever genuine signed file is there when it first syncs is what it runs - including
  an older one somebody put back, or no `ADVERSARY_POLICY` at all (the defaults: advisory).
  Before a new machine takes work, let it finish syncing and read `ferry engines policy
  show`; keep the channel's Syncthing folder shared with devices you trust to write it.
- **A v0.5.17 machine reads the v1 view and has no memory.** It verifies the engine policy's
  v1 signature and obeys what it knows (`prefer` for the four building roles, `never`,
  `where`, caps, subscription protection, auto-merge); it ignores effort, width,
  subscription roles, `class:` selectors and the whole adversary, and it has no sequence
  number, so it cannot tell an older signed policy put back from the current one. It never
  runs the adversary and does not wait for it, so `blocking` binds only the machines on
  this release - a v0.5.17 worker can still hand over the review key for work an adversary
  blocked. Upgrade every machine before relying on `blocking`.
- **A policy signed by v0.5.17 has only the v1 signature.** A machine on this release
  accepts it (sequence 0) but it has no rollback protection beyond what that machine saw
  first, and it cannot carry the newer parts - effort, width, subscription roles and
  **routing** (`ordered`, thresholds, bias): a project that chose `routing = ordered` and is
  then signed again by a v0.5.17 master reads as smart routing with the defaults, and
  the file itself cannot say otherwise. When the fleet has members that sign v2
  (their inventories carry a v2 signature) and the policy in force is still a v1-only file,
  `ferry engines policy show` and the dashboard say so, routing included. Signing the policy again from a
  current `ferry` (`ferry engines policy set ...`, or the dashboard) replaces it with one
  that has a sequence number and a v2 signature. Do that once the fleet is upgraded.
- **The adversary's policy is master-only on every machine that knows it.** A delegate
  cannot sign it, and a machine remembers the last one it saw; but a machine that does not
  know the file (v0.5.17) ignores it, and a fresh machine has nothing to remember.

## Team preset and swarms: plan on high, build on medium, swarm the cheap work

A strong model should plan and review, a few mid-size models should build in
parallel, and the smallest models should do the chores. Three things in the engine
policy make that a setting rather than a habit.

**Effort per role.** The policy says how hard each role thinks: `plan`, `review` and
`adversary` default to `high`, `build` to `medium`, `chore` to `low`. Set it with
`ferry engines policy set --effort build=medium --effort chore=low`. An engine acts on
it only where you say how:

- `{effort}` in an engine's `args` is filled with `low`, `medium` or `high`, the way
  `{model}` is.
- `engine.<name>.effort_args` lists extra arguments per level, spliced in before the
  prompt: `{"low":[...],"medium":[...],"high":[...]}`.
- An HTTP engine is sent a `reasoning_effort` field only with
  `engine.<name>.supports_effort = "true"` (the default is off, because a server that
  does not know the field may refuse the request).

An engine with none of these ignores effort, and its step record leaves effort out
rather than claiming one. The flags below are **examples**: check your own CLI's
documentation before using one.

```toml
# Example only: codex takes a reasoning effort as a config override.
engine.codex.args = ["exec","--full-auto","-c","model_reasoning_effort={effort}","{prompt}"]
# Example only: "--reasoning" stands for whatever flag your CLI has.
engine.mycli.effort_args = {"low":["--reasoning","low"],"medium":["--reasoning","medium"],"high":["--reasoning","high"]}
# Example only: an OpenAI-compatible endpoint that accepts reasoning_effort.
engine.gateway.supports_effort = "true"
```

The effort each step used is recorded beside its engine, model and machine in
`ferry improve status` and `ferry improve report`.

**Model size class.** Each engine has a class, `small`, `medium` or `large`, shown by
`ferry engines`, published in the signed inventory and usable as a selector
(`class:small`). Declare it with `engine.<name>.class = "medium"`; your word wins.
Without one fm guesses from the model name: `haiku`, `mini`, `nano`, `small`,
`flash-lite` and a size under 10B are small; `opus`, `pro`, `ultra`, `large`,
`reasoner`, `r1` and 70B or more are large; everything else (`sonnet`, `flash`,
`deepseek-chat`, a mid-size nemotron) is medium. A model with an active-parameter
count (`a12b`) is sized by that. The guess is a default, not a measurement: declare
the class of anything it gets wrong.

**Swarm width.** `max_parallel` in `agent.toml` is how many orders one work pass
claims and runs at once; `1`, the default, is one after another, exactly as before.
With more, each order runs in its own git worktree (turn `worktree` on, or they would
share one checkout). Orders whose `touches` overlap are never run together, on this
machine or across the fleet. The policy's `width` caps how many improvement orders of a
role the whole fleet may have claimed at once, counted from the current claims (a stale
claim does not count): `ferry engines policy set --width build=3 --width chore=4`, and
`--width build=none` removes the cap. Both caps are soft: two machines claiming in the
same instant can each get in, and a weekly request cap can be overshot by up to the
number of orders in flight. An engine that runs out of credit mid-swarm lets the orders
already in flight finish or fail as usual, and new claims skip it.

### The team preset

```sh
ferry engines policy team [PROJECT | --all]                 # the proposal, one reason per choice
ferry engines policy team --accept                         # sign it as the master
ferry engines policy team --allow-subscriptions-for build,chore --width build=4 --effort build=high
```

From the engines the fleet published it proposes:

| Role | Engine | Effort | Width |
|---|---|---|---|
| plan | a large, judge-tier engine | high | 1 |
| build | medium-class engines | medium | 3 |
| chore | the smallest engines | low | 4 |
| review | a large judge | high | |
| adversary | a large judge of a different model family than the top builder, advisory | high | |

Within a size class the order is auto's: local, free tier, capped prepaid, then the
rest. An engine of the wrong size stays in the list after the right ones as a
fallback, so a fleet without the ideal engine still has someone to ask. `--accept`
signs the proposal with the master's signature, like every other policy change. The
dashboard's Engine policy panel has a Team preset button that shows the proposal with
its reasons and an Accept button, selectors for effort and width per role and a
checkbox per role for subscriptions; Telegram's Engines menu has a "Use team preset"
button under the improvement and review pickers, with the same proposal and an Accept
button. `ferry engines` and `ferry improve status` show each role's effort, width and
the class of the engine first in line.

**Subscriptions are still off by default.** A swarm is exactly what drains a Claude or
Codex limit, so the proposal never uses a subscription unless you name the role:
`--allow-subscriptions-for build,chore` (the policy's `subscription_roles`). Even then
it uses only an engine with a `weekly_requests` cap, so the swarm stops at a number you
chose. A subscription engine with no cap stays blocked for the role, and the proposal,
the CLI and the dashboard say so.

Example (a), the free default: nemotron's free tier and DeepSeek build, a local model
does chores, and nothing touches a subscription. Add the `env`, `base_url` and `key`
lines from the example above for the nemotron and deepseek engines.

```toml
agent = "grouchly-team"
command = "ferryman-cline"
max_parallel = "3"
worktree = "true"
engines = ["nemotron", "deepseek", "reasoner", "local"]

engine.nemotron.kind = "cli"
engine.nemotron.model = "nvidia/nemotron-3-super-120b-a12b"
engine.nemotron.tier = "build"
engine.nemotron.paid = "free-tier"
engine.nemotron.weekly_requests = "400"

engine.deepseek.kind = "cli"
engine.deepseek.model = "deepseek-chat"
engine.deepseek.tier = "build"
engine.deepseek.paid = "prepaid"
engine.deepseek.weekly_usd = "5"

# The judge: plans, reviews and challenges. Class large from its name (reasoner).
engine.reasoner.kind = "http"
engine.reasoner.base_url = "https://api.deepseek.com"
engine.reasoner.model = "deepseek-reasoner"
engine.reasoner.key = "secret:DEEPSEEK_API_KEY"
engine.reasoner.tier = "judge"
engine.reasoner.paid = "prepaid"
engine.reasoner.supports_effort = "true"

# Chores on a small local model.
engine.local.kind = "http"
engine.local.base_url = "http://localhost:11434/v1"
engine.local.model = "qwen2.5-coder:7b"
engine.local.tier = "chore"
```

```sh
ferry engines policy team --all            # read the proposal and its reasons
ferry engines policy team --all --accept
```

Example (b), opting in: Claude Sonnet builds and Claude Haiku does chores, both on a
subscription, both with a weekly cap, and only for those two roles. The planner,
reviewer and adversary stay on engines that are not a subscription. Use the model names
your CLI accepts; the selectors below are globs, so no version is hard-coded.

```toml
agent = "grouchly-claude"
command = "claude"
max_parallel = "3"
worktree = "true"
engines = ["claude-sonnet", "claude-haiku"]

engine.claude-sonnet.kind = "cli"
engine.claude-sonnet.args = ["-p","--model","{model}","{prompt}"]
engine.claude-sonnet.model = "sonnet"
engine.claude-sonnet.class = "medium"
engine.claude-sonnet.tier = "build"
engine.claude-sonnet.paid = "subscription"
engine.claude-sonnet.weekly_requests = "200"

engine.claude-haiku.kind = "cli"
engine.claude-haiku.args = ["-p","--model","{model}","{prompt}"]
engine.claude-haiku.model = "haiku"
engine.claude-haiku.class = "small"
engine.claude-haiku.tier = "chore"
engine.claude-haiku.paid = "subscription"
engine.claude-haiku.weekly_requests = "500"
```

```sh
ferry engines policy team --allow-subscriptions-for build,chore
ferry engines policy team --allow-subscriptions-for build,chore --accept
# or by hand, from the same selectors:
ferry engines policy set --role build --prefer "claude-sonnet*"
ferry engines policy set --role chore --prefer "claude-haiku*"
ferry engines policy set --allow-subscriptions-for build,chore
```

The caps are yours to choose: set `weekly_requests` to what you can spare, not to what
the plan allows. Once reached, the engine is exhausted until Monday 00:00 UTC and the
swarm moves to the next engine in the list or waits.

## Two keys before an improvement goes live

Every improvement the loop builds needs **two** keys before it may go live - merge,
deploy or release:

1. **The review engine's.** The engine the policy picks for review (a judge-tier engine
   it does not block, on a machine it names) reads the result and records a signed
   verdict. It never accepts on its own: a "keep" becomes a recommendation. The result's
   own evidence must pass verification, and no verifier may have refuted it.
2. **Yours.** The master approves - or a delegate with the `review` scope acting on the
   master's button press on the phone.

Neither alone is enough: an agent's accept is refused, and so is yours until the
review engine has given its key. If the review engine is blocked or out of credit the
loop holds and asks you once; it never skips the review and never approves by itself.
With both keys the improvement becomes "approved, ready to merge", and merging is yours -
unless you turn on auto-merge for low-risk work, below.

```sh
ferry improve pending                        # what waits, with diff stat, evidence and the review engine's verdict
ferry improve approve improve-2026-w40-1     # your key
ferry improve send-back improve-2026-w40-1 --notes "cover the error path"
```

The dashboard's Teammates page lists them under "Waiting for your approval" with
Approve and Send back; Telegram sends each one with the same buttons once the review
engine has given its key.

### Auto-merge: docs, tests and dependency bumps, after both keys

Off by default. Turn it on per project (or `--all`) and fm merges an improvement on its
own - but only once it holds **both** keys, and only when every file it changes is low
risk:

- **docs**: `*.md`, `docs/**`, LICENSE / COPYING / NOTICE / AUTHORS, and Rust changes to
  comments only;
- **tests**: `tests/**` (not under `src/`), `*_test.*`, `test_*.*`, `*.spec.*`, `*.test.*`,
  and Rust changes inside a `#[cfg(test)]` module that runs to the end of its file;
- **dependencies**: a lockfile changed in place (`Cargo.lock`, `package-lock.json`,
  `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, `poetry.lock`, `uv.lock`), or a manifest whose only
  change is dependency versions (`Cargo.toml`, `package.json`, `pyproject.toml`,
  `requirements*.txt`, `go.mod`).

Anything else - code, config, a new dependency, a feature flag, a git source, the
package's own version, an executable bit - still stops at "approved, ready to merge"
for you. So does fm's own repository: self-improve on the ferryman project gets no
exemption.

```sh
ferry engines policy set --auto-merge low-risk --all     # or: --auto-merge none
```

On the dashboard it is the "Auto-merge docs/tests/deps after both approvals" checkbox in
the policy panel; on the phone, the button of the same name in the Engines menu.

How it happens: the improve loop records a signed `merge-authorized` for each
improvement with both keys. The worker that built the branch then checks everything
again itself - the policy, both keys, that the branch is still at the commit that was
reviewed, and every changed file as git has it - and merges into the default branch in
its own checkout: a fast-forward when it can, a merge commit otherwise. If the default
branch is checked out with uncommitted changes, or the merge conflicts, nothing is
merged. It pushes the default branch only if that worker already pushes for the project
(`push = "origin"` in `agent.toml`), after checking the remote is not ahead, and never
with force; a refused push puts the branch back. The merge commit goes into the ledger
and Telegram says so. Whatever goes wrong, the improvement falls back to you,
"approved, ready to merge", with the reason. fm cannot see CI, so it does not wait on
it: the checks the worker ran are in the evidence the review engine judged.

## The adversary: a second model that argues with the builders

Builders (cheap or medium models) build. The **adversary** is a separate model that
challenges their work, and only at three moments, so it costs a few calls, not a second
copy of every step:

1. **Before an interface contract locks.** Once the provider has produced a result (or at
   once, when there is none yet) it reads the shapes, the provider's result and the
   consumer's order, after a deterministic check that the result fits the shape. Its
   verdict is shown next to Lock and Reject - in `ferry contract show`, the dashboard's
   Contracts page and the Telegram contract card.
2. **When the same order fails twice.** Before the third attempt a deterministic scan of
   the order branch's diff looks for test tampering (tests deleted or disabled, assertions
   removed or made trivial, forced passes like `|| true`, loosened tolerances, tests moved
   out of the checked paths, edits to the check itself); then the adversary gets both
   failures' check output, the diff and the scan, and asks whether the builder is fixing
   the bug or hiding the symptom. A Block - or any High
   tamper hit, even in `advisory` mode - sends the task back as ChangesRequested with the
   finding text, which the next attempt's prompt carries. The master is asked once.
3. **Before an improvement is called done.** It runs before the review engine's key is
   produced. The finding is shown beside the two keys: `ferry improve pending`, the
   dashboard's review card, the Telegram review card.

It answers with a verdict - `pass`, `concern` or `block` - and findings, each with a
severity. Only a reply that ends with one fenced `json` block holding a `verdict` and a
`findings` list is read; anything else records nothing (it is not a finding, so it cannot
satisfy `blocking`) and the next allowed engine is asked. Each finding is a signed file,
`<channel>/adversary/<subject>-r<revision>-<moment>/<signer>.finding.json` (one per signer, subject,
revision and moment, so asking again changes nothing; a master's override sits beside it as
`<signer>.override.json` and a waiver as `waiver.json`, and a signer's name has no `.` so none
of them can be mistaken for another), and the engine, model, machine and
cost go into the ledger like any improvement step.

**Modes**, set with `--adversary`:

- `advisory` (the default): findings are shown; nothing waits on them. (The one exception
  is a High tamper hit at moment 2, which always sends the task back.)
- `blocking`: a Block binds, and it fails closed. A contract cannot be locked, the review
  engine's key cannot be granted for that revision, and auto-merge never happens for it,
  until the master signs an **override** (with a reason) - or, when no eligible adversary
  has read exactly that revision at all (see below), a signed **waiver** (the same
  command, with `--finding none`). Contracts need the `improve` delegation to override
  from the phone; the other two need `review`.
- `off`: it is never asked, and nothing about it is shown.

**The adversary's policy is the master's alone.** Everything about the adversary -
its mode, which engines it prefers (`--role adversary --prefer`), the engines it never
uses (`--adversary-never`), the agents allowed to judge (`--adversary-agents`) and its
weekly cap (`--role adversary --cap-usd`) - is its own signed file,
`<channel>/ADVERSARY_POLICY`, and not part of `ENGINE_POLICY`. It is honoured only when the
master signed it with their own key: there is no delegation for it, so the phone, a
dashboard session acting under a delegation, or anyone else who holds `improve` can
neither loosen it nor take its judges or its budget away. Like the engine policy it
carries a sequence number and every machine remembers the highest it has seen and the last
good one, so putting an older copy back, or deleting the file, changes nothing and asks
the master once. The engine policy's `never`, `where` and caps do not apply to the
adversary, and anything an `ENGINE_POLICY` file says about it is ignored. The dashboard
shows the adversary's terms to everyone and changes them only for the master; Telegram
shows them and never changes them (accepting a preset there leaves them as they are).
Putting the engine policy back to auto leaves the adversary's policy as signed. A machine
still on v0.5.17 does not know the file and never runs the adversary.

**Whose finding counts.** A finding is only heard when its signer did not build the work
it judges, published a valid signed engine inventory that lists the engine the finding
names, and is an adversary the master allows (`ADVERSARY_POLICY`). If the master named
`adversary_agents` (`--adversary-agents`), only those agents count. If the list is empty,
the trust is **any member running an allowed adversary engine**: a member counts when its
signed inventory lists an engine that matches the adversary's preference selectors (any
engine, when there are none) and that the adversary's own `never` does not name. Anyone
else's finding is ignored - and so is a Pass from a member you did not mean to give a vote
to, so name the agents when the roster holds people or machines you do not fully trust.
(The deterministic tamper scan is the one floor anybody on the roster may record, and it
can only block.) Every eligible adversary runs its own pass - one adversary's Pass does
not stand in for another's look - and a Block from any of them dominates. A finding is
one signed file per signer, so nobody can pre-empt or overwrite another adversary's word.
It also names the result it judged (a hash of that result's order, revision and
signature): at a contract lock and before an improvement is called done it counts only
for that exact result, so deleting an older provider result, which renumbers a contract's
rounds, cannot let an old Pass cover a newer result. Several adversaries add up. A finding
that does not count is ignored and shown as `ignored: <reason>` in `ferry adversary show`
and under `ignored` in the dashboard's `/api/adversary`. Findings count only on a
revision that exists, and every gate decides on the revision under decision, never on the
newest finding.

**Overrides name what you read.** Locking and overriding are bound to what the master was
looking at, so a proposal or a finding that changed in between is not acted on: the CLI
shows the contract's digest and asks you to confirm at a terminal (or take
`--digest <prefix of at least 8>` from `ferry contract show`, plus `--finding <digest|none>`
with `--override`); the dashboard sends the digests `/api/contracts` gave; Telegram's
buttons carry them. A mismatch is refused with "the contract changed since you looked".

**Who challenges.** The adversary ranks engines by the same rules as background work -
subscriptions protected, paid engines need a cap - but under its own `never` and its own
cap, and with no `where` list. It is never the engine that built the work unless that is the only one allowed -
then it runs and the finding says `same engine`. Among the rest, a different model family
(deepseek, qwen, llama, gemma, claude, gpt...) is preferred over the builder's own.
`recommend()` picks one for you with a one-line reason.

```sh
# adversary = deepseek, blocking
ferry engines policy set --role adversary --prefer deepseek --adversary blocking

ferry adversary list                      # every finding, newest first
ferry adversary show improve-2026-w40-1   # one order (or: user-api@1)
ferry adversary override user-api@1 --reason "the consumer ships a fix first"  # shows the finding, asks to confirm
ferry adversary override user-api@1 --finding 0123456789abcdef --reason "..."   # or name the finding you read
ferry contract lock user-api@1 --override "the consumer ships a fix first"      # shows the digest, asks to confirm
ferry contract lock user-api@1 --digest 89abcdef --override "..." --finding none # no prompt: name what you read
```

`ferry adversary check` asks about everything waiting now; the improve loop does it on
its own schedule. On the dashboard the policy panel has the adversary engine and mode,
and a Block carries an Override button for the master; on the phone it is an "Override
the Block" button, shown only for a Block.

## What an engine can do, and what an order needs: capabilities and the work profile

The smart router sends each piece of work to the cheapest engine that will most likely
do it well. To do that it has to know two things: what each engine can do, and what
each order needs. This section is the first half of that - the profiles. (Choosing
between engines from them comes next; nothing here changes which engine runs an order.)

### The engine's capability profile

Every engine has a profile, published in the signed engine inventory and shown by
`ferry engines` (the modalities column, and a `can:` line under each engine) and on the
dashboard's Engines page:

| Field | Meaning |
| --- | --- |
| `modalities` | What it takes in or makes: `text`; `code` (edits files in a worktree - only a `cli` engine can have it, so a declared `code` on an `http` engine is dropped); `vision` (reads images); `image`, `video` (generates or edits); `audio_in` (speech to text); `audio_out` (text to speech); `embed`. |
| `strengths` | Free tags: `code`, `reasoning`, `docs`, `tests`, `review`, `translation`, `long-context`, `math`. |
| `context_k` | The context window in thousands of tokens. |
| `cost` | `per_call_usd`, `per_mtok_in_usd`, `per_mtok_out_usd`. Local, free-tier and subscription engines are zero (a subscription is zero marginal cost; its scarcity is the weekly cap's job). A prepaid engine nobody priced is **unknown**, not zero. |
| `local` | Nothing leaves the machine or the private network. |

**Your word wins, field by field.** Say any of it in `agent.toml` and that field is
used as written - a declared `modalities` replaces the guessed list, it does not add to
it. Whatever you leave out is guessed:

```toml
engine.vision.base_url = "http://localhost:1234/v1"
engine.vision.model = "qwen2.5-vl-72b-instruct"
engine.vision.modalities = ["text","vision"]        # or: text, vision
engine.vision.strengths = ["docs","review"]
engine.vision.context_k = "32"
engine.vision.cost_per_call_usd = "0"
engine.vision.cost_per_mtok_in_usd = "0"
engine.vision.cost_per_mtok_out_usd = "0"
engine.vision.local = "true"
```

**What is guessed**, from the engine's name, model and command, its kind, its endpoint
and how it is paid for. Every rule below is a unit test:

- A `cli` engine gets `text` and `code`; an `http` engine gets `text`.
- `vl`, `vision` or `llava` in the name means `vision`. A `claude`, `gemini` or
  `gpt-4o`/`gpt-4.1`/`gpt-5` CLI sees images too; an HTTP endpoint is not assumed to
  from a family name alone.
- `whisper` means `audio_in`; `tts`, `kokoro` or `piper` means `audio_out`.
- `flux`, `sdxl`, `stable-diffusion` or `comfyui` means `image`; `wan`, `hunyuan-video`
  or `ltx` means `video`; `embed` means `embed`. An engine named like one of these does
  *only* that until you say otherwise: it is not also assumed to chat or edit code.
- `coder`, `codestral`, `devstral`, `codellama` or `codex` is a `code` strength;
  `reasoner`, `r1`, `o1`, `o3`, `qwq` or `thinking` is `reasoning`; `math` and
  `translation`/`nllb` likewise. A context of 200k or more adds `long-context`.
- Only a window written in the name (`-128k`, `-1m`) is guessed for `context_k`; a wrong
  guess would shut an engine out of work it could do, so unknown stays unknown.
- `local` is true when the endpoint's host is `localhost`, a `.local`/`.lan` name, a
  loopback, private (10/8, 172.16/12, 192.168/16), link-local or Tailscale-range
  (100.64/10) address, when it is `paid = "local"`, or when it is a media CLI with no
  endpoint that nobody marked as paid. An agent CLI such as `claude` or `codex` is not
  local: it calls out.

The profile rides in the signed inventory as a v2-only field, like `class`: a v0.5.17
peer still verifies the rest of the inventory, and a forged or stripped profile does not
verify on a new one. A worker older than profiles publishes none, and `ferry engines`
shows a guess for it marked `?`.

### Media engines are ordinary cli engines

Nothing special is needed for pictures, sound or video: an engine is a command that
takes a prompt, and its modalities say what it makes. **The three below are examples
only** - the command lines, flags, file names and model names are placeholders for
whatever you have installed; check each tool's own documentation, and use `{prompt}`
where your runner takes the work. None of them ships with Ferryman.

```toml
engines = ["claude", "comfy", "whisper", "speak"]

# EXAMPLE ONLY: a ComfyUI workflow runner. "run-comfy-workflow" stands for a script of
# yours that submits a workflow to a ComfyUI server and writes the image into the order's
# worktree. The names say image, so it is guessed `image` only; declared here anyway.
engine.comfy.command = "run-comfy-workflow"
engine.comfy.args = ["--workflow","flux-dev.json","--prompt","{prompt}"]
engine.comfy.model = "flux-dev"
engine.comfy.modalities = ["image"]
engine.comfy.paid = "local"

# EXAMPLE ONLY: speech to text with a whisper CLI that prints a transcript. The model
# name says whisper, so `audio_in` is guessed.
engine.whisper.command = "whisper-cli"
engine.whisper.args = ["--model","large-v3","--output-txt","{prompt}"]
engine.whisper.model = "whisper-large-v3"
engine.whisper.paid = "local"

# EXAMPLE ONLY: text to speech with a piper-style CLI. `kokoro` or `tts` in the name
# would be guessed `audio_out` as well.
engine.speak.command = "piper-say"
engine.speak.args = ["--voice","en_US-lessac","--text","{prompt}"]
engine.speak.model = "piper-en-us"
engine.speak.paid = "local"
```

`ferry engines` then lists them as `image`, `audio_in` and `audio_out`, and the router
will never offer them text work or a chat engine an image job.

### What an order needs

`ferry route classify <order>` shows what an order needs and where that read came from.
The profile has four parts: the **modalities** an engine must have, the **kind** of work
(`code-change`, `docs`, `tests`, `review`, `plan`, `chore`, `research`, `translate`,
`transcribe`, `image`, `video`, `audio` or `other`), its **size** (`small`, `medium`,
`large`) and the **context** it wants (`min_context_k`). It is decided in this order,
and the source is always recorded - `explicit`, `rules` or `model`:

1. **Explicit.** Say it when you issue the order; it is signed into the order, so it
   cannot be changed afterwards, and it wins over everything below:

   ```sh
   ferry channel order --id t-9 --task-file brief.md --kind docs --size small
   ferry channel order --id t-10 --task "what is wrong in this screenshot?" \
       --needs vision --kind review   # (--needs takes modalities)
   ```

   `--kind`, `--needs` (modalities, comma-separated or repeated), `--size` and
   `--min-context-k` are all optional and independent: leave one out and the rules fill
   it in. Orders issued without any of them are byte-for-byte what they always were and
   verify as before.

2. **Rules** - deterministic, no model. They read:
   - *attachments and file types*: an order payload may carry `attachments` (or `files`,
     `images`), each a path or URL or `{"path":..., "mime":...}`. Images need `vision`,
     audio `audio_in`, video `video`. **Only an attachment (or an explicit `--needs`)
     makes an engine need one of these**: a media file merely *named* in the task text
     (`update docs/logo.png in the README`) is noted in the reasons and asks for nothing,
     and a media word in code work (`fix the transcription retry in src/lib.rs`) is a name
     in the code, not the job: an order that names a source file or directory, or touches
     code, is code work unless the audio, video or image is attached. Only when the winning
     kind is itself media (`Transcribe the standup recording`) does the text make the
     engine need the media modality;
   - *the `touches` globs*: only docs (`docs/**`, `*.md`, `README*`) is `docs`, only
     tests (`tests/**`, `*_test.rs`, `*.spec.ts`) is `tests`, any code leans
     `code-change`;
   - *verbs in the task text*: transcribe, translate, summarize, review, plan,
     research, "generate an image", "render a video", "text to speech", "add unit
     tests", "update the README", fix/implement/refactor, bump/tidy, and so on - the
     table is `RULES` in `ferryman_channel::work`, one tested example each;
   - *the order's tier*: `"tier": "chore"` is `chore`;
   - *size*: about four characters a token over the task text plus attached text files
     (measured by file size, never read), and how many files it means to touch; the
     context wanted is that plus room to answer.

   Evidence combines per kind; two kinds that both fire (`fix the typo in the README`)
   lower the confidence. Code and tests need `code`, so only a `cli` engine can take
   them; transcribe needs `audio_in`; image, video and audio jobs need only their media
   modality; everything else needs `text`.

   **Work that edits files needs `code` whatever it reads as.** A docs, chore, translate
   or `other` order is often a change to files, and an `http` engine answers in text and
   changes nothing, so the result is refuted ("no commit and no diff") and the engine is
   blamed and demoted for work it could never do. So an improvement order (build or chore
   work), an order that declares `touches`, one that requires changes, and one whose kind
   the rules cannot tell, are routed as needing `code`; the routing line says why. A plan,
   a review or research that only produces text stays text, and a fleet with no `cli`
   engine still takes the order on an `http` one, as it always has.

3. **A model, only when the rules are unsure** (confidence under 0.55). A worker makes
   this call itself, once per order, before it routes an improvement order under
   `routing = "smart"` (a person's own order is routed on the rules' read). It goes to the
   cheapest **`http`** text engine - never a `cli` engine, because that is an agent with
   tools and the order's text is not to be trusted - asking for a small JSON label, with a
   45 second timeout. Which engine obeys the same
   rules as any background work: the engine policy's `never` list, its `where`, weekly
   caps, `protect_subscriptions` and `subscription_roles`; local engines go first, then
   free tier, then by price. **A subscription engine is never used for this unless the
   policy's `subscription_roles` includes `chore` and the engine has a weekly request
   cap.** The reply can only choose among the known kinds and sizes (an invented kind
   is refused), the order text is sent fenced as data with an instruction not to follow
   it, and a model's stated confidence is capped. The modalities a model names are
   ignored (it never saw the attachments); only the kind and size are taken. If nothing
   may be asked or the answer is no use, the rules' best read is used and the reason is
   recorded.

   The answer is cached per order id on the machine that asked, in
   `<project attachment>/routing/classify/<order id>.json`. It is **local and not
   signed**: it is advice derived from an order that is already signed, it is cheap to
   redo, and keeping it off the synced channel means no second writer and nothing for a
   peer to forge. Two machines may each pay for one call; an explicit `--kind` on the
   order is how you make every machine agree. An unusable answer is remembered for an
   hour so a model that cannot follow the format is not asked on every pass.

`ferry route classify <order>` never calls an engine by itself: it prints the rules'
read, or the cached model answer, with the reasons. `--model` asks now, as a worker
would. `--json` prints the classification. The dashboard shows the same on each order
card (kind, size, any modality beyond text; unsure ones are marked) and, with the
reasons, in the order's detail.

## Smart routing: the cheapest engine that will do it well

Every piece of background work goes to the engine best suited to it, by one rule: **use
the cheapest engine that will most likely do it well, and move up only when a cheaper
one has failed at that kind of work.** It applies to text, code, vision, image, video
and audio work, and to local, free, prepaid and subscription engines alike. Smart is
the default; `routing = "ordered"` keeps the strict prefer lists exactly as they were
before the router.

### What runs before any scoring

The router chooses only among the engines the engine policy already lets through, so
none of these can be bypassed: the `never` list, `protect_subscriptions` and
`subscription_roles` with their weekly caps, `caps_usd`, `where`, an engine that is out of
credit, and the tiers (a chore engine never builds, a demoted engine only does chore
work, review is a judge's). **The adversary is never routed**: it keeps its own
master-only `ADVERSARY_POLICY` and its own order. After that the router also leaves out an
engine that lacks a modality the work needs (code-change needs `code`, which only a `cli`
engine has; vision work needs `vision`), or whose context window is smaller than the work
wants. An `http` engine is sent text only, so it is never given vision, audio, image or
video work, whatever its profile says: point a `cli` engine at the model and declare the
modality on it. A fleet with no `cli` engine at all still takes build orders on `http`
engines, as it always has, and the reason says so.

### How the choice is made

1. **Estimate.** For each engine and kind of work, the chance it does the work well is a
   Beta estimate. The prior comes from the engine's **model profile** when the router knows
   the model (see "What each model is good at" below), and from its size class when it does
   not: large 0.80, medium 0.70, small 0.55, plus 0.05 for each strength tag that matches
   the kind (at most 0.10), minus 0.10 for each class the engine is below the size of the
   work. Either way it is worth four results. The evidence is the worker's own ledger of
   results for this engine and kind, verified or refuted by its checks, each counting for
   half as much after 14 days. So `p = (prior x 4 + verified) / (4 + verified + refuted)`.
2. **Price.** One call is estimated at 3k/1k, 12k/3k or 48k/10k tokens in/out for small,
   medium and large work, times the engine's price. Local and free-tier engines cost 0 -
   but how an engine is paid for decides before where it runs: an endpoint on this machine
   or network counts as local only when nothing says it is somebody's paid API behind a
   proxy. An OmniRoute or LiteLLM style gateway (OmniRoute's provider or port 20128, or a
   known route) is never guessed local, and an engine marked `paid = "prepaid"`,
   `"subscription"` or `"free-tier"` is priced as that even at `localhost`; declare
   `local = "true"` or `paid = "local"` to say it really is. An
   engine with **no declared price is not free**: it is assumed to cost a frontier model's
   list price ($5 in, $25 out per million tokens), so a declared price always beats a
   guess. A free tier that asked for money is priced like an unpriced one until its flag
   lapses. A subscription costs nothing per call, but its **scarcity** is priced: about two
   cents a call on a cap of 300 a week with the cap full, rising to ten times that as the
   cap runs down, and in proportion to the cap - a request on a 2000 a week cap is about
   6.7 times cheaper. So when two subscriptions both clear the bar, the one with the bigger
   cap (Haiku at 2000) takes the work, and the smaller (Sonnet at 300) gets what the bigger
   one does not clear. The line says so: `subscription, cap 2000/wk, ...; preferred over a
   smaller cap (claude-sonnet 300/wk)`.
3. **Choose.** The *sufficient set* is every engine whose estimate reaches the threshold
   for the kind. Unless the policy says otherwise that is **0.80 for review and plan**
   (only an engine that is actually good at judging and planning gets that work),
   **0.70 for docs, chore, tests and research** - a free engine that writes well takes
   that work from the start and loses it as soon as its results are refuted - and **0.75
   for everything else** (code changes, translation and media). **Large work adds 0.05** to
   the default of any kind. A threshold you set with `--threshold` is used exactly as you
   set it, large work or not. The winner is the cheapest of the sufficient set. If none is
   sufficient, the winner is the one most likely to succeed. Costs within 10% count as
   tied, and ties go to **bias**, then to **how the engine is paid for - free (local or a
   free tier) before a subscription before paid** - then the nearer tier, then the
   **higher estimate**, then the faster engine, then the order the policy and `agent.toml`
   already gave.
4. **Escalate.** After a result *of this worker's own* is refuted by its own evidence, or
   sent back with changes requested, the next attempt leaves that engine out and prefers
   an estimate **higher than the failed engine's**. A retry therefore climbs: cheap first,
   then up. That is a bar for the sufficient set, not a rule: when no remaining engine
   clears it, the likeliest remaining engine still takes the order, even at or below the
   failed one's estimate. And when the failed engine is the only one that can do the work
   (a single-engine fleet), nothing waits for another that is never coming: the likeliest
   of the failed engines tries again, and the routing line says so. An engine here is
   *this agent's engine on this machine*, so another machine's `claude` failing says
   nothing about yours. The failures are read only from results this worker signed, and
   the estimate to beat is worked out from this worker's own ledger, never from the
   numbers a result's payload carries: anyone who can write a result could otherwise name
   your cheap engine "failed" or set the bar to 1.0.
5. **Learn.** Each verified or refuted result is counted for that (engine, kind) in the
   worker's engine ledger, under the same lock as the rest of it, and published in the
   signed inventory (a v2-only field). A cheap engine that keeps getting docs right becomes
   sufficient for docs; one that gets refuted stops being picked for it, while what it is
   good at is untouched. `ferry engines` shows each engine's best kinds with its success rate.

### What each model is good at

The size class alone cannot tell Claude Haiku (a fine chore engine) from a model that is
merely small, or NVIDIA's Nemotron (a good writer) from a good reviewer. So the router
carries a built-in table of **model profiles**: for each known family, a conservative prior
`p` for each kind of work. It covers Claude (opus, sonnet, haiku, including the bare
`opus`, `sonnet` and `haiku` the claude CLI takes), GPT-5 (and mini, nano, codex), Gemini
(pro, flash, flash-lite), DeepSeek (v3, v4, v4-pro, r1), NVIDIA Nemotron (super, ultra,
nano), Qwen (2.5 and 3, scaled by the parameter count in the name; `-coder` is stronger on
code, `vl` is a vision model and a little weaker on text), GLM-4.x (air, flash), Llama,
Mistral (with Codestral and Devstral) and Kimi. A few of its rows, for medium-sized work:

| Model | code | review | plan | docs | tests | chore |
|---|---|---|---|---|---|---|
| claude-opus | 0.92 | 0.92 | 0.93 | 0.90 | 0.90 | 0.88 |
| claude-sonnet | 0.88 | 0.87 | 0.86 | 0.86 | 0.86 | 0.84 |
| claude-haiku | 0.72 | 0.70 | 0.66 | 0.78 | 0.76 | 0.82 |
| deepseek-v4-pro | 0.86 | 0.84 | 0.86 | 0.82 | 0.84 | 0.80 |
| nemotron-super | 0.72 | 0.72 | 0.70 | 0.78 | 0.72 | 0.80 |
| glm-flash | 0.72 | 0.66 | 0.64 | 0.72 | 0.70 | 0.74 |
| qwen ~14b | 0.66 | 0.63 | 0.62 | 0.70 | 0.64 | 0.70 |
| qwen-vl ~7b | 0.52 | 0.54 | 0.53 | 0.56 | 0.54 | 0.58 |

These are starting guesses, not benchmarks. The ledger still moves them: a few verified or
refuted results change `p` as before, so a model that does better or worse than its family
is found out. The rules:

- The engine's `model` is matched (case does not matter; Bedrock-style ids such as
  `us.deepseek.r1-v1:0` work). Only an engine with no `model` is matched by its name: an
  engine called `sonnet-fast` serving `my-finetune` is not Sonnet. A model that matches
  nothing has no profile, and it is scored by its size class exactly as before.
- **A profile wins over the size class**, including a `class` you declared: the class is a
  size guess, and the profile is a better one. Your declared `strengths` still count for
  the kinds they help (0.05 each, at most 0.10), except a strength the profile already
  includes, such as `code` on a `-coder` model. For a model the router does not know,
  `class` and `strengths` count in full.
- **Opus is never picked for background work by the router on its own.** It has a profile,
  but an engine whose model is Claude Opus is left out of smart background routing unless
  the role's prefer list names it (`name:claude-opus`, `model:opus`, or its bare name; a
  `paid:` or `class:` selector does not count). Work you ask for directly is not held back.
- Large work takes 0.05 off a medium model and 0.10 off a small one; a large model loses
  nothing.
- `ferry route simulate` and `ferry route explain` say where each `p` came from, for
  example `p 0.87 (model profile: claude-sonnet)` or `p 0.70 (class medium)`, and add the
  ledger's counts once there are any.

### The policy fields

```sh
ferry engines policy set --routing smart            # the default; `ordered` is today's strict order
ferry engines policy set --threshold docs=0.6 --threshold code-change=0.85
ferry engines policy set --bias 'nemotron*=3' --bias 'claude-sonnet*=2'
ferry engines policy set --threshold none --bias none   # clear them
```

- `routing`: `smart` or `ordered`. With `ordered` nothing is scored and the first engine the
  lists allow does the work, byte for byte as before.
- `thresholds`: per kind (`code-change`, `docs`, `tests`, `review`, `plan`, `chore`,
  `research`, `translate`, `transcribe`, `image`, `video`, `audio`, `other`), the
  probability that counts as sufficient. Higher means "only the engines I trust with this";
  lower lets a cheap engine try.
- `bias`: per selector, a tie-break weight. Higher goes first **among engines that cost the
  same**. It never lets a dearer engine beat a cheaper sufficient one; to force an order use
  `ordered`. Your prefer lists already give their first entries a small bias of their own.

All three are signed in the policy's v2 view only, like `effort` and `width`: a v0.5.17
machine still verifies the file and keeps ordering. In the dashboard, the Engine policy
panel has a Routing section with the same three settings.

### Seeing why

```sh
ferry route simulate --kind docs --size small                 # who would get it now, and why
ferry route simulate --kind docs --size small --needs vision  # ... if it needs to read images
ferry route explain <order>     # what it needs, what each worker recorded, and what would happen now
ferry engines                   # each engine's top kinds with their success rates
```

Every routing decision is recorded beside the step and in the result: each candidate with its
estimate and price, why each excluded engine was left out, and a one-line reason such as
`nvidia: free, p 0.80 for docs >= 0.70, cheapest sufficient`. Each candidate's line says
where its estimate came from: `> nvidia  beastly  p 0.78 (model profile: nemotron-super), free`. The dashboard shows the reason
on each order card, every candidate in the order's drawer, and a Routing panel that runs the
simulation without running anything. Telegram's review card carries the one-line reason.

### Example: NVIDIA first while it is free, then Sonnet, then Haiku, local models too

"If one model is better suited, or can do it well cheaply, it should be used." That is the
rule above; what you add is only a bias for ties. Declare what each engine is, then sign the
policy. This is an example: use the names and models of your own `agent.toml`.

```toml
engines = ["nemotron", "claude-sonnet", "claude-haiku", "ollama"]

# Free while it lasts, and large. Prices of 0 make it the cheapest; the router also learns
# whether it is good at each kind of work.
engine.nemotron.kind = "cli"
engine.nemotron.model = "nvidia/nemotron-3-super-120b-a12b"
engine.nemotron.env = {"OPENAI_BASE_URL":"https://integrate.api.nvidia.com/v1","OPENAI_API_KEY":"secret:NVIDIA_API_KEY","OPENAI_MODEL":"nvidia/nemotron-3-super-120b-a12b"}
engine.nemotron.base_url = "https://integrate.api.nvidia.com/v1"
engine.nemotron.key = "secret:NVIDIA_API_KEY"
engine.nemotron.paid = "free-tier"
engine.nemotron.class = "large"

# Subscriptions: no price per call, but the weekly cap makes them scarce as it runs down.
engine.claude-sonnet.kind = "cli"
engine.claude-sonnet.command = "claude"
engine.claude-sonnet.args = ["-p", "--model", "{model}", "{prompt}"]
engine.claude-sonnet.model = "claude-sonnet-4-6"
engine.claude-sonnet.paid = "subscription"
engine.claude-sonnet.weekly_requests = "300"
engine.claude-sonnet.strengths = ["code", "docs", "reasoning"]
engine.claude-haiku.kind = "cli"
engine.claude-haiku.command = "claude"
engine.claude-haiku.args = ["-p", "--model", "{model}", "{prompt}"]
engine.claude-haiku.model = "claude-haiku-4-5"
engine.claude-haiku.paid = "subscription"
engine.claude-haiku.weekly_requests = "600"

# Local models count: free, and eligible for the work they prove they can do.
engine.ollama.kind = "http"
engine.ollama.base_url = "http://localhost:11434/v1"
engine.ollama.model = "qwen2.5-coder"
engine.ollama.paid = "local"
```

```sh
ferry engines policy set --routing smart \
  --prefer nemotron --prefer claude-sonnet --prefer claude-haiku \
  --bias 'nemotron*=3' --bias 'claude-sonnet*=2' --bias 'claude-haiku*=1' \
  --threshold chore=0.55 \
  --allow-subscriptions-for plan,build,chore
```

What that does: NVIDIA is free and large, so it takes the work while it is up and keeps taking
it for as long as it keeps getting it right. When it is out of credit, down, or has failed
at that kind of work, the next cheapest engine that is likely to do it well takes over: a
local model that has proven itself at it, then Sonnet, then Haiku (Sonnet before Haiku
when their price is tied, because of the bias). Docs, research, tests and chores need only
0.70 by default, which a model whose profile says it writes well (Nemotron super does)
meets from the start, so a free one wins them cheaply until its results are refuted.
Review and plan need 0.80, so they go to a model that is actually good at them (Sonnet),
and large work needs 0.05 more. Haiku is a good chore model by its profile; a small model
the router does not know becomes sufficient for a kind of work by proving itself at it, or
because you lowered that kind's threshold (`--threshold chore=0.55` above): that is "can do
it well cheaply". A
subscription is used for a role only because `--allow-subscriptions-for` says so, and only an engine with a weekly cap; `never` and the
dollar caps still apply first. Drop `--allow-subscriptions-for` and the two Claude engines
are never used for background work, as before. `ferry route simulate --kind docs --size small`
shows the ranking before you trust it.

## OmniRoute: a free gateway as an engine

[OmniRoute](https://github.com/diegosouzapw/OmniRoute) (MIT) is a self-hosted AI
gateway: one OpenAI-compatible endpoint, `http://localhost:20128/v1` by default, in front
of hundreds of providers - many free - with quota-aware fallback and **combos**, named
routes over several models. Install and start it as its README says (`npm i -g
omniroute`, then `omniroute`), then add it to `agent.toml`:

```toml
engines = ["omniroute", "deepseek"]
engine.omniroute.provider = "omniroute"
engine.omniroute.kind = "http"
engine.omniroute.base_url = "http://localhost:20128/v1"
engine.omniroute.model = "free-stack"            # a combo, or a model id such as "nvidia/nemotron-70b:free"
engine.omniroute.key = "secret:OMNIROUTE_API_KEY" # an OmniRoute API key, sealed; leave out if yours needs none
engine.omniroute.tier = "build"
```

`provider = "omniroute"` (or a base URL on port 20128) makes it a first-class engine:

- The probe lists its models and combos (`/v1/models`) and, when the key may read it,
  each combo's steps (`/api/combos`).
- **Each route is paid for the way it ends.** A `:free` model is free tier. A route that
  ends at somebody's plan - Claude Code or Codex signed in through OmniRoute, Cursor,
  Copilot - is a subscription, so `protect_subscriptions` and `never claude` block it
  **through** the gateway: the policy matches the provider/model names on the route, not
  just the combo's name. A combo is a subscription if any step is one, free if every
  step is free. A combo whose steps cannot be read counts as a subscription when that
  OmniRoute has any subscription provider connected, because it may route there.
- Its combos and free models are offered as engines of their own - `omniroute.free-stack`,
  shown as "OmniRoute: free-stack" - so the dashboard dropdowns and Telegram can pick one.
  Auto ranks a free combo as free tier: a strong improvement engine.
- OmniRoute reports what each request cost (`X-OmniRoute-Response-Cost`), so a free
  route's spend stays at $0 and a paid one is counted.

When OmniRoute answers on the machine and no engine uses it yet, `ferry enable` points it
out and `ferry engines policy recommend` prints the lines above.

## Diagnosing

```sh
ferry doctor    # readiness: config parses, engine on PATH, key + roster, Syncthing
ferry log       # this machine's local attempts and why claims were declined
```

| Symptom | Cause → remedy |
|---|---|
| `'…' printed nothing for Ns and was killed` | Engine waiting on an approval nobody can answer → use the non-interactive/auto-approve contract above |
| `start '…'; is it installed and on PATH?` | Engine missing or wrong binary (WSL trap above) → install, fix `command`, `ferry doctor` |
| Task answers but never touches files | Engine ran without its auto-approve flag → see "The one rule" |
| Result shows authentication errors | Key did not survive the scrub → step 3; expired credentials also retry-fail forever by design until fixed |
| Wrong model billed | `model =` unset while `args` names several → set `model`, or pin with `-m` in `args` |
