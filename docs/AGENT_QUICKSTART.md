# Ferryman for agents

**You are the intended reader.** This page is written for an AI agent that has been
told to put a project on Ferryman, with no human available to answer questions. Every
step below is non-interactive, idempotent, and safe to retry.

If you are a human: this works for you too, but [the README](../README.md) is friendlier.

---

## What you are setting up, in one paragraph

Ferryman lets agents on different machines hand each other work without a server. An
order is a file, a result is a file, a review is a file; Syncthing copies the folder
between machines. You will install a binary, run one command in the project directory,
and end up with a signed identity on a channel. Nothing you do touches the project's own
code or git history.

## Step 1 — install

```sh
cargo install --git https://github.com/estejosh/ferryman ferryman-cli
```

Needs a Rust toolchain and, on Linux, D-Bus headers for the OS credential store
(`libdbus-1-dev pkg-config` on Debian/Ubuntu, `dbus-devel pkgconf` on Fedora). If you
would rather not build, the container carries everything:

```sh
podman run -d --name ferryman -v ~/ferryman-channels:/channels:U \
  -p 22000:22000/tcp -p 22000:22000/udp ghcr.io/estejosh/ferryman:latest
```

Check it:

```sh
ferry --version
```

## Step 2 — enable the project

From inside the project directory:

```sh
ferry enable --email you@example.com --json
```

The email is required. Free production use is conditioned on registering one
(LICENSE section 3), and it is how the Licensor counts Seats and can tell you when a
deployment goes over. **If you do not have an address to give, ask your human for one
— do not invent one.** `FERRYMAN_EMAIL` works instead of the flag.

Nothing about your code, your channel, or your agents' work is ever transmitted. See
[PRIVACY.md](../PRIVACY.md) for the exact payload, and run
`ferry license checkin --dry-run` to see it before anything is sent.

That is the whole setup. It prints one JSON object:

```json
{
  "enabled": true,
  "project": "myproject",
  "agent": "beastly",
  "channel": "/path/to/myproject/.ferryman/ferryman",
  "syncthing_folder_id": "myproject-ferryman",
  "review": "confirm",
  "public_key": "710836e3...",
  "already_configured": false,
  "files": [{ "what": "channel config", "path": "...", "created": true }]
}
```

Read `already_configured` to tell "I just set this up" from "it was already done". If
you cannot remember whether you ran this, **run it again** — it will not overwrite an
edited config and will not rotate your signing key.

Useful flags, all optional:

| Flag | Default | Why you would change it |
|---|---|---|
| `--project` | the directory name | The directory is named something unhelpful |
| `--agent` | this machine's name | Several agents on one machine |
| `--role` | `worker` | This one hands out and reviews work: use `orchestrator` |
| `--command` | `claude` | You run a different agent CLI |
| `--email` | *(required)* | No default is possible; ask your human |
| `--review` | `confirm` | See the risk section below |

Exit code is 0 on success, non-zero with a message on stderr otherwise. It never
prompts, never opens an editor, and never waits on a terminal.

## Step 3 — join the other machines

The channel folder printed above is what Syncthing shares. On each machine, add that
folder with the printed folder id. Ferryman does not do this for you: adding a Syncthing
folder is a change to a program you own, and doing it behind your back would be wrong.

One machine alone is still useful — you can issue and do work — but nothing crosses
machines until the folder is shared.

## Step 4 — run the loops

```sh
ferry agent run       # picks work up, runs your agent CLI, submits a signed result
ferry agent review    # judges results that are waiting
```

Both loop until stopped. Add `--once` to do a single pass and exit, which is what you
want from cron, a systemd timer, or a test.

**An agent will not review its own work.** If one machine runs both loops under the same
agent name, `review` will tell you it is skipping and why. Give the reviewer its own
name (`ferry enable --agent orchestrator --role orchestrator`).

---

## How much authority the reviewer has — your call, not Ferryman's

Set with `--review`, changeable any time in `.ferryman/agent.toml`.

| Mode | What happens | Use when |
|---|---|---|
| `auto` | The reviewing agent's verdict stands. Work flows with nobody watching. | The work is recoverable and you want throughput |
| `confirm` | The agent judges and writes its reasoning; a human settles it. **Default.** | Mistakes cost something |
| `off` | No agent judgement. Results wait for a person. | You do not want a model's opinion on record |

The default is `confirm` because that is the cautious end, not because it is
recommended. Ferryman has no view on how much you trust a model to approve work
unsupervised — that depends on the work and the team, and only you know both.

In `confirm` mode:

```sh
ferry agent pending --json
```

returns each waiting recommendation with its reasoning and its signature check. Settle
one with:

```sh
ferry channel review --accept t-4f2a
ferry channel review --notes "the totals do not add up" t-4f2a
```

A recommendation changes nothing on its own. Until a human writes the review, the task
sits exactly where it was.

## Where the deployment stands under the licence

```sh
ferry license status --json
```

Free tier is 2 Seats, 2 Computers and 2 phones/tablets, checked separately rather than
pooled — three computers is over even with no phone. **Agents are unlimited and never
counted**, so adding agents to a machine never changes any of this.

Going over prints a notice and changes nothing else. Ferryman does not stop, degrade,
or withhold anything. Do not treat an over-limit notice as a reason to halt work; treat
it as something to tell your human.

## Handing out work

```sh
ferry channel order --agent orchestrator --id t-4f2a \
  --task "write the Q3 report" --requires-review

ferry channel order --agent orchestrator --id t-4f2b --to grouchly --task "..."
```

Pass `--agent` with the name you enabled under. Omit it and the order is signed by the
machine name, which the roster will not recognise, and every reader will report
`UnknownSigner`.

Addressed orders (`--to`) have nothing to race over. Open ones are settled by oldest
claim, computed identically on every machine, so nobody has to be the authority.

## Checking your work

```sh
ferry channel status     # where the channel is and whether it is healthy
ferry channel agents     # who is on it
ferry channel tasks      # every task, its state, and every signature check
```

`ferry channel tasks` is the one to check after setup. Every line should read `Valid`.
`UnknownSigner` means something was signed by a name the roster does not carry —
usually a missing `--agent`.

## What this does not do

- **It does not sandbox the agent CLI it runs.** That process gets the full privileges
  of the account running the loop, in its working directory. Give each worker its own
  least-privilege account and its own disposable directory, and prefer your agent's own
  sandbox flags.
- **It does not touch the project's code or git history.** Everything lives under
  `.ferryman/`.
- **It does not carry your private key.** Keys live in `.ferryman/keys`, which is
  excluded from the synced folder before any key exists.
- **It does not decide anything for you** about review authority. See above.

## If something fails

| Symptom | Cause | Fix |
|---|---|---|
| `no Ferryman channel found` | Not enabled here, or you are above the project directory | `ferry enable` in the project root |
| `run 'ferry enable' in this project first` | Channel exists, agent config does not | `ferry enable` again; it is idempotent |
| `order UnknownSigner` | Signed by a name not in the roster | Pass `--agent <your enabled name>` |
| reviewer does nothing | It is the same agent that did the work | Run the reviewer under a different name |
| `'claude' ... is it installed and on PATH?` | The configured agent CLI is missing | Install it, or change `command` in `.ferryman/agent.toml` |
| work sits in `AwaitingReview` forever | `review = "confirm"` and nobody settled it | `ferry agent pending`, then `ferry channel review` |
