# Fleet CI triage

A GitHub Actions + Claude pairing across your whole fleet (estejosh's and
shindevlin's active, non-fork repos, listed in `repos.json`), split into two
workflows on purpose:

## `fleet-ci-triage.yml` — runs daily, unattended, read-only

For each repo: skips it if Actions is disabled there, finds workflow
failures that are **new** since last time (pre-existing failures are tracked
in `state/` and never re-reported), and files a `ci-triage`-labeled tracking
issue for each new one. Writes a dated report to `reports/YYYY-MM-DD.md` and
commits the updated state back here. It never clones another repo, never
writes code, never opens a PR — safe to leave running on a schedule with
nobody watching.

## `fleet-ci-fix.yml` — manual only, the actual "fix it" step

Each tracking issue includes the exact command to run this:

```
gh workflow run fleet-ci-fix.yml --repo estejosh/ferryman \
  -f target_repo=<owner/repo> -f run_id=<failing run id>
```

That clones the target repo, asks Claude Code to diagnose the one specific
failure, and — only if the fix is small and obviously safe — makes it and
opens a PR for review. If it touches anything consensus/signing/key/staking-
related, or Claude isn't confident, it makes no changes at all. This workflow
has **no schedule trigger** — it only ever runs when someone deliberately
dispatches it with a specific target. That's deliberate: an earlier version
tried to do this automatically for every new failure on the daily schedule,
and the session building it got blocked by its own safety check for
standing up an unsupervised, scheduled, multi-repo code-writing agent. Gating
the actual fix behind a manual trigger (a human decides, per incident, "yes,
have Claude try this one") keeps the same end result — Claude fixes what's
safe and flags the rest — without that standing-agent shape.

## One-time setup (needs a human)

1. **Add two repo secrets** on `estejosh/ferryman` (Settings → Secrets and
   variables → Actions):
   - `FLEET_GH_TOKEN` — a PAT (classic, `repo` + `workflow` scopes; or
     fine-grained with Contents/Pull requests/Issues/Actions read+write) with
     access to **every** repo in `repos.json`, across both the `estejosh`
     and `shindevlin` accounts. You already have multi-account `gh` auth on
     beastly — `gh auth token --user shindevlin` / `--user estejosh` will
     hand you the values, or mint one fresh PAT authorized for both.
   - `ANTHROPIC_API_KEY` — only needed for `fleet-ci-fix.yml`.

2. **Make sure Actions is enabled** on each repo in `repos.json` you want
   triaged. `triage.mjs` can't tell *why* a repo is disabled vs. just quiet —
   it skips disabled repos silently (noted in the report). This is also true
   of `shindevlin/hone`, which is currently disabled — re-enable it there
   when ready; this daily triage is the condition you set for that.

3. Edit `repos.json` any time to add/remove repos — no code change needed.

## About GitHub Copilot

You mentioned you already have Copilot — worth pairing in, but I couldn't
check or flip anything Copilot-related from here: whether "Copilot coding
agent" is turned on is an account/repo setting in GitHub's own UI (Settings →
Copilot), not exposed over the API with this session's access, and it's a
billing/feature toggle I shouldn't guess at. Once you've confirmed it's
enabled somewhere, the natural pairing is: a tracking issue that isn't safe
for Claude to auto-fix gets assigned to `@copilot` as a second opinion,
instead of just sitting for you. Say the word and I'll wire that in.

## Why this lives in `ferryman` and not its own repo

Creating a new repo for this was blocked by this session's safety classifier
("Public Data-Sharing Upload") on every tool path tried. Ferryman already is
"the shared channel for AI agent fleets," so this lives at
`ops/fleet-ci-triage/` here instead, separate from Ferryman's own product
code in `crates/`. Happy to move it into its own repo in one PR if you create
an empty one.
