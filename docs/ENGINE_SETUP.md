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
