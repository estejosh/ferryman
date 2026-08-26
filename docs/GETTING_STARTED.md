# Getting Started

Ferryman lets AI agents on different machines hand each other work with no server
in the middle. Orders, results and reviews are signed files in a folder that
[Syncthing](https://syncthing.net) carries between machines you own. This guide
is the short human version; [AGENT_QUICKSTART.md](AGENT_QUICKSTART.md) is the
same journey written for an unattended agent, and
[ENGINE_SETUP.md](ENGINE_SETUP.md) covers pointing the worker at your agent CLI.

## 1. Install

macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh
```

Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | iex
```

Both verify the release checksum and install for the current user — no Rust
toolchain needed. Prebuilt binaries cover x86-64 and ARM64 Linux, both Macs, and
x86-64 Windows. Or build it yourself, which needs **Rust 1.97 or newer** —
`rust-toolchain.toml` is not honoured for a `cargo install --git` checkout, so an
older toolchain fails on language features rather than telling you the version:
`cargo install --git https://github.com/estejosh/ferryman ferryman-cli`.
Check it with `ferry --version`.

Ferryman also needs Syncthing installed and running to reach other machines
([downloads](https://syncthing.net/downloads/)). Everything works locally
without it; nothing crosses machines until it runs.

## 2. Enable the project

From inside the project directory:

```sh
ferry enable --email you@example.com --json
```

The email registers this deployment for the free licence tier; nothing about
your code or work is ever transmitted ([PRIVACY.md](PRIVACY.md) lists exactly
what check-ins carry). One command does all of it: writes `.ferryman/`
configuration, creates the channel folder, generates a signing key, keeps the
key out of git and out of the synced folder, registers the machine, and shares
the channel folder through your local Syncthing.

It never overwrites a config you edited and is safe to re-run — if you are unsure
whether you already ran it, run it again. Under `--json`, or anywhere that is not a
terminal, it never prompts either. Run at a terminal it asks one question: whether
to set up the web dashboard, which then wants an operator name and a password.
Answer `n`, or pass `--json`, and it will not ask.

Then confirm the machine can actually run a task:

```sh
ferry doctor
```

Every required check should pass. The one people fail most: the configured
engine (`claude` by default) is not installed on this machine, which `doctor`
reports with its fix instead of letting the first task discover it.

## 3. Point the worker at your agent CLI

`.ferryman/agent.toml` says what does the work. `--command claude` writes
Claude Code's non-interactive contract; `--command opencode` and
`--command codex` get theirs automatically. Other engines: edit `command` and
`args`, replacing `{prompt}` where the task text goes. See
[ENGINE_SETUP.md](ENGINE_SETUP.md) — including how an API key reaches the
engine (`.ferryman/credentials.json`) and why headless workers need their
engine's auto-approve flag.

## 4. Start the loops

```sh
ferry agent run       # picks up orders, runs your engine, submits a signed result
ferry agent review    # judges submitted results (respects review = "confirm")
```

Both loop until stopped; add `--once` for a single pass (cron/systemd). Give
the reviewer a different name than the worker — an agent never reviews its own
work (`ferry enable --agent orchestrator --role orchestrator`).

## 5. Issue the first task

From any machine on the channel:

```sh
ferry channel order --agent <your-name> --id t-demo --task "summarize README.md"
ferry channel tasks     # every task, its state, every signature check
```

States you will see: **open** (waiting to be claimed), **claimed/running**,
**awaiting-review** (in `review = "confirm"` a person settles these),
**revising** (sent back with notes), **done**. Settle reviews yourself with:

```sh
ferry agent pending --json                 # what is waiting, with reasoning
ferry channel review --accept t-demo       # ...or send back with --notes "..."
```

`UnknownSigner` anywhere means something was signed by a name the roster does
not know — usually an order issued without `--agent <your enabled name>`.

## 6. Add another machine

Pair the two machines in Syncthing once — exchanging device IDs is a trust
decision Ferryman will not make for you — then run steps 1–2 on the other
machine. `enable` shares the new channel folder with devices Syncthing already
trusts, and the two channels merge file by file.

## Recovery

Keys live per machine under `.ferryman/keys` and are never synced, so a wiped
machine needs `ferry enable` again (same agent name restores the identity's
roster entry; a fresh key signs under it from then on).
[TWO_MACHINE_RECOVERY.md](TWO_MACHINE_RECOVERY.md) and
[BACKUP_AND_RECOVERY.md](BACKUP_AND_RECOVERY.md) cover the full drill,
including encrypted continuity packs (`ferry continuity`).

## If something fails

Start here:

| Symptom | First move |
|---|---|
| Nothing claims work | `ferry doctor`; check `pause_while_active` and `claim_window` |
| Task fails to start | The engine line in `ferry log`; usually engine missing or args wrong |
| Engine frozen / killed | It is waiting for a permission prompt nobody can answer — see ENGINE_SETUP.md |
| Work waits forever | `review = "confirm"` and nobody settled: `ferry agent pending` |

[AGENT_QUICKSTART.md](AGENT_QUICKSTART.md) ends with the full table.

---

### A note on server mode

Ferryman also ships an optional HTTP server (`ferryman-server`) with tokens,
jobs and a worker SDK — an older integration path kept for embedders who want
a reachable endpoint, described in [ARCHITECTURE.md](ARCHITECTURE.md) and
[openapi/openapi.yaml](../openapi/openapi.yaml). You do not need it: `ferry
enable` and the commands above talk to the synced folder directly, which is
the intended setup and the one everything else assumes.
