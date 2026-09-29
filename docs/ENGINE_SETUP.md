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

Example - free model first, never my subscription, only on the always-on machine,
for every project I am master of:

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
