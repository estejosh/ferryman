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
satisfy `blocking`) and the next allowed engine is asked. Each finding is a signed file in `<channel>/adversary/` (one per subject,
revision and moment, so asking again changes nothing), and the engine, model, machine and
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
names. A finding is one signed
file per signer (`adversary/<subject>-r<revision>-<moment>.<signer>.json`, and the file
name must name the signer), so nobody can pre-empt or overwrite another adversary's word;
several adversaries add up, and a Block from any of them stands. A finding that does not
count is ignored and shown as `ignored: <reason>` in `ferry adversary show` and under
`ignored` in the dashboard's `/api/adversary`. Findings count only on a revision that
exists, and every gate decides on the revision under decision, never on the newest
finding.

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
