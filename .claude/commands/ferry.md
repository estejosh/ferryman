---
description: Install or update Ferryman in this repository, then report where it stands
---

Get Ferryman current in **this** repository and report honestly on what happened.

`$ARGUMENTS` may contain an email (for a repository that is not attached yet) or the
word `status` (to report without changing anything).

## What to do

1. **Work out where you are.** Is there a `.ferryman/bridge.toml` here? Is `ferry` on
   PATH, and what does `ferry --version` say — including the commit in parentheses?

2. **Record the identity fingerprint before touching anything**, if `.ferryman/keys`
   exists: `sha256sum .ferryman/keys/*.key | cut -c1-16` (or `Get-FileHash` on Windows).
   Fingerprints only — never print or copy a key. This is recorded first because "did my
   identity survive?" cannot be answered afterwards from memory.

3. **Unless `$ARGUMENTS` says `status`, run the updater**, choosing by platform:
   - Linux/macOS: `scripts/ferry-up.sh` if this is the Ferryman checkout, otherwise
     `curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/ferry-up.sh | sh`
   - Windows: the matching `ferry-up.ps1`

   Pass `--email=` / `-Email` only if the repository is not attached and an address was
   given. Never invent one.

4. **Report, in this order:**
   - the version and commit before and after — and say plainly if they are the same
   - whether the signing key fingerprint changed. **If it changed, stop everything and
     say so loudly.** Every artifact this machine has published stops verifying for
     every other machine; recovery is a restore from backup, not a retry.
   - `ferry channel tasks` — every artifact should read `Valid`. Anything else is the
     finding, and `UnknownSigner` usually means a missing `--agent`.
   - `ferry channel agents` and `ferry license status`, so the machine count is visible
   - anything in `ferry log` that looks like a real problem

5. **Say what is actually true.** If the update did nothing because the machine was
   already current, say that rather than implying work happened. If something failed,
   report the failure rather than working around it — a failed upgrade reported
   accurately is worth more than a clever recovery, because the recovery is the thing a
   real user will not manage.

## Rules

- **Never touch `.ferryman/keys`**, and never print a key. Fingerprints only.
- **Do not run this in a repository you were told to leave alone.** Check with the
  operator first if you are unsure which repository you are in.
- `ferry enable` never prompts and is safe to run twice, so re-running is fine.
- If the machine turns out to be on a different commit from the rest of the fleet, say
  so explicitly. That is the question `ferry --version` was given a commit to answer,
  and a fleet running two builds is the cause of problems that otherwise look like bugs.
