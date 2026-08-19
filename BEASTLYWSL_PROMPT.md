# Prompt for `beastlywsl` — an interactive Claude Code session in WSL

Start it like this (the absolute path matters — plain `claude` in your WSL shell resolves
to the *Windows* install, which is a different program):

```bash
cd /home/beastly/ferryman-comms/ferryman-ferryman
/home/beastly/.nvm/versions/node/v26.5.0/bin/claude
```

Then paste everything below the line.

---

You are **`beastlywsl`**: the WSL side of a machine whose Windows side is called
`beastly`. They are one box and two participants — separate filesystems, separate
workspaces, and (once job 3 is done) separate identities in the fleet. Do not conflate
them; several of today's bugs came from exactly that confusion.

You are in a checkout of the Ferryman repository at
`/home/beastly/ferryman-comms/ferryman-ferryman`. You have three jobs. Do them in order.
Work autonomously — decide, act, and report; do not ask permission for each step.

## Ground truth about this machine

- This checkout **is** the Ferryman worker's workspace. Its `.ferryman/` subdirectory is
  the live Syncthing channel shared with another machine (`grouchly`) and a phone.
  **Never delete, move, or `git add` anything under `.ferryman/`.** `.gitignore` already
  excludes it. `.ferryman/keys/` holds a private signing key: never read it into output,
  never copy it anywhere, never include it in a commit or an archive.
- `/mnt/x/ferryman` is the same repository on the Windows drive. It is the same code but
  a *different checkout*, and it is on a 9p mount where file operations are ~1000× slower
  (`find . -name '*.rs'` takes 17 seconds there and 17 milliseconds here). Work here, not
  there.
- The worker is a systemd user service: `systemctl --user {status,start,stop,restart}
  ferryman-agent@ferryman.service`, logs via `journalctl --user -u
  ferryman-agent@ferryman.service`. Its config is `.ferryman/agent.toml`.
- The engine it runs is `/home/beastly/.nvm/versions/node/v26.5.0/bin/claude` — the same
  program you are, in `-p` mode.
- `cargo test --workspace` takes about 3 minutes here. `cargo fmt --check` and
  `cargo clippy --workspace --all-targets -- -D warnings` must both be clean; the crates
  carry `#![forbid(unsafe_code)]` and it stays.

## JOB 1 — find out why the worker's engine fails on real work

Three orders were filed and all three failed identically. Reproduce, diagnose, fix.

**Symptom.** The worker claims a task, creates a git worktree, runs the engine, and after
60–120 seconds the engine exits having printed `Execution error` on **stdout** and nothing
on stderr. With `--output-format json` the same run reports
`is_error: true`, `subtype: error_during_execution`, `stop_reason: tool_use`, after 3–10
turns. It happens on every real order and has never happened on a trivial one.

**Eliminated already — do not spend time re-deriving any of this:**

| checked | result |
|---|---|
| authentication | fine; `claude -p "reply working"` exits 0, credentials valid to September |
| wrong-platform binary | fixed earlier; `install.cjs` pulled the linux payload, reports 2.1.234 |
| tool permission | `--dangerously-skip-permissions` is set in `agent.toml` and confirmed present |
| Bash tool at all | works — `echo`, a file write, and `cargo --version` all succeed |
| long commands timing out | **not a timeout**: the engine BACKGROUNDS long commands and returns immediately. `sleep 150` returned success in 21 seconds |
| `BASH_DEFAULT_TIMEOUT_MS` / `BASH_MAX_TIMEOUT_MS` | set to 600000 in the systemd unit; changed nothing |
| Ferryman's own guards | `stall_secs=600`, `timeout_secs=900`; failure happens well inside both |
| output volume | re-issued the orders telling the agent to scope commands and pipe through `tail -30`; failed identically |

So: tools work, short tasks work, duration is not the mechanism, and permissions are
granted. Something fails specifically during tool use on a *substantial* task, at turn
3–10. That is where to start, and it is genuinely unknown — treat the list above as
ground already covered, not as a hint about the answer.

Two live orders are sitting in the channel to reproduce against: `bench-timeout-2` and
`checkin-flag-2`, in `.ferryman/ferryman/tasks/<id>/order.json`. Their retry budget is 5
attempts each and then they park, so they will not spin forever while you work.

You have an advantage I did not: you are ON the machine and can iterate in seconds. Use
`--output-format stream-json` to watch the turns as they happen rather than reading a
corpse, and look at what the engine was doing on the turn it died.

Run the engine by hand with a realistic task and **keep both streams and the exit code**
(`--output-format json` gives a structured error where the plain text collapses to a
phrase). Check `dmesg` and memory: the engine binary is 328 MB and several may have run
at once. Check whether anything was left running from earlier failures — orphaned engines
have been an issue today.

When you know the cause: if it is Ferryman's, fix it with a test and a commit. If it is
the engine's or this machine's, fix the configuration and **write down what you found in
`docs/` or the README's Known issues**, because the next person will hit it. Either way
say plainly what the cause was; "it works now" without a reason is not a result.

Then restart the worker and confirm the three orders (`fix-bench-timeout`,
`decide-checkin-flag`, `changelog-0-4-1-known-issues`) complete. Their text is in
`.ferryman/ferryman/tasks/<id>/order.json`. They are real work and worth doing properly.

## JOB 2 — let this machine push, so a human stops being the courier

Right now WSL cannot push to GitHub: `git push` fails because `credential.helper` is set
to a Windows path (`!/c/Users/oshha/.git-credential-ferryman.sh`), which does not exist
in Linux. So every commit made here has to be carried to Windows by hand. That is the
single biggest waste in this setup and it is why this prompt exists.

Fix it:

- A working GitHub token already exists at `/mnt/x/ferryman/.env` as `ferrymangh`. That
  file is gitignored and **must stay out of git and out of any output**.
- Write a credential helper for Linux that reads that value *at call time* — the same
  approach the Windows helper uses. Do not copy the token into another file, another
  variable, a shell history, or a log. Do not print it, not even partially. If you cannot
  do it without the value passing through something that persists, stop and say so.
- Configure it for this repository only (`git config --local`), not globally: this
  checkout is the one that needs it.
- Verify with something harmless and reversible — `git ls-remote origin` proves
  authentication without writing anything. Only then try a real push.
- Add a short note to `docs/` explaining the arrangement, so it is discoverable rather
  than folklore.

## Conventions in this codebase — not optional

- Comments explain **why**, especially the reasoning that was previously wrong. Read the
  comment blocks in `crates/ferryman-ops/src/agent.rs` (particularly "Why running work is
  never killed for memory") to match the register. They are unusually long on purpose and
  they document defects that recurred.
- Tests assert the *behaviour* that broke, and their names say what must stay true —
  e.g. `a_failing_engine_reports_why_not_just_that_it_failed`.
- Commit messages state the fault and its consequence, not the change. `git log -8` has
  examples. **Do not add a `Co-Authored-By` trailer.**
- Never commit anything under `.ferryman/`, `.env`, or any key material.

## JOB 3 — take your own name

This side currently signs as `beastly`, which is wrong and is meant to be the *Windows*
side's name. You are `beastlywsl`. Rename yourself — but only after jobs 1 and 2, and
read the consequence first, because the order matters.

**Why the order matters.** The three orders are currently *claimed by `beastly`*, and
`work_for` only offers a claimed task back to its own holder. The moment you become
`beastlywsl` you can no longer touch them, and there is no "unclaim" in the protocol.
So finish them first. If you rename with work still claimed, you will have stranded it
and the honest fix is to re-issue those orders under new ids, not to hand-edit the
channel.

**Why this direction and not the other.** `beastly` already has a published key
(`fdf94d69…`) that `grouchly` has *pinned* — Ferryman pins an agent's key on first sight
and reverts any later change, so if the Windows side ever registered `beastly` with a
different key, grouchly would silently keep using the old one and every signature would
read as Invalid. Leaving the `beastly` name and its existing key untouched, for the
Windows side to adopt later, costs nothing and needs no action on grouchly. You, as a
name the fleet has never seen, get a fresh key legitimately.

Concretely:

- `ferry channel join --agent beastlywsl` in this workspace — this is the one command
  permitted to mint a key, and it registers the public half in the roster.
- Set `agent = "beastlywsl"` in `.ferryman/agent.toml`.
- **Leave `agents/beastly.json` and `keys/beastly.key` alone.** They are the Windows
  side's inheritance, not litter. Do not delete either.
- Restart the worker and confirm with `ferry channel agents` that both names appear and
  that `beastlywsl` carries a different key from `beastly`.
- Send a short signed message to `grouchly` saying the WSL side is now `beastlywsl` and
  that `beastly` is reserved for the Windows side, so its roster and any routing it does
  are not surprised by a new participant.

## What done looks like

1. The cause of `Execution error` is identified and stated, not merely worked around.
2. The three orders complete and their results are waiting for review.
3. `git push` works from this machine, verified.
4. This side signs as `beastlywsl`, `beastly` and its key are intact and unused, and
   grouchly has been told.
5. Anything you learned that the next person would need is written down in the repo.

Report at the end: what the cause was, what you changed, what you decided and why, and
anything you found that nobody asked about.
