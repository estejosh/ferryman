# ALWAYS READ THIS FIRST

This is the mandatory entrypoint for AI agents and operators working on
Ferryman or updating an attached project.

## Current standard

- Ferryman project standard revision: **2**
- Updated: **2026-07-24**
- Portable marker: `<project>/.ferryman/ferryman/STANDARD.toml`
- Outer marker: `<project>/.ferryman/standard.toml`

Revision 2 adds crash-safe live communications, inbound private-Git
synchronization, acknowledgement delivery/retry, actor-scoped inbox/claim/ack
tokens, queue/quarantine status, safe unregister, and framework-neutral
unmanaged/single-agent/multi-agent adoption.

If either marker is missing or its `revision` is lower than 2, the attached
project needs a standard update. A higher revision means this checkout is older:
stop and update Ferryman before touching the project.

## Before any update: scan, then ask the user to review

Never begin with `git pull`, attachment apply, Syncthing registration, or a remote
change. First run the read-only directory safety scan and show the result to the
user:

```powershell
& X:\ferryman\scripts\scan-project-safety.ps1 -Workspace X:\example
```

```bash
scripts/scan-project-safety.sh --workspace /path/to/example
```

The scan reads paths, Git metadata, ignore state, and Ferryman-owned standard
markers. It checks for reparse points/symlinks, dirty portable files, suspicious
portable filenames, a misplaced token/runtime directory, and unexpected
remotes. It never reads `.ferryman/token` or other secret contents.

Stop if the scan reports `FAIL`. Do not update through an unexplained symlink,
dirty managed file, unexpected inner remote, or possible secret in the portable
repository.

## Determine whether Ferryman itself changed

From `X:\ferryman`, preserve the working tree and inspect:

```powershell
git status --short --branch
git log -1 --oneline --decorate
git fetch --prune origin
git rev-list --left-right --count HEAD...origin/main
git log --oneline HEAD..origin/main
```

`git fetch` updates remote-tracking metadata only. Do not merge or pull over a
dirty tree. The final two commands state whether local Ferryman is ahead/behind
and list exactly which upstream commits are new. Review `README.md`,
`docs/COMMUNICATIONS_READINESS.md`, and this file after an update.

## Update an attached local project

Keep the project's existing integration model. Supply the same project ID,
paths, private repository, and participant mappings used during attachment.
Always dry-run first.

PowerShell:

```powershell
& X:\ferryman\scripts\attach-project.ps1 `
  -Workspace X:\example `
  -Project example `
  -SharedRemote /wisp-bridges/example `
  -GitRemote https://github.com/estejosh/example-bridge.git `
  -IntegrationMode unmanaged `
  -UpdateStandard `
  -DryRun
```

WSL/Linux:

```bash
scripts/attach-project.sh \
  --workspace /path/to/example \
  --project example \
  --shared-remote /wisp-bridges/example \
  --git-remote https://github.com/estejosh/example-bridge.git \
  --integration-mode unmanaged \
  --update-standard \
  --dry-run
```

Review every reported action, remove only the dry-run flag, then scan again.
The update refuses dirty Ferryman-managed portable files, validates and
enriches a compatible legacy outer `bridge.toml`, updates revision markers and
portable instructions, and commits only managed portable metadata. It never
stages the outer token/runtime or changes the main project remote.

For a single- or multi-agent project, retain its existing `-Participant` or
`--participant` entries. Do not convert a project to multiple agents merely to
adopt the standard; `project-inbox` supports humans, scripts, CI, and unmanaged
projects.

## What must never be automatic

- Never inspect, print, copy, rewrite, or commit token/credential contents.
  Only the attachment helper may load an existing token directly into an
  authorization header; it must not display or persist the value elsewhere.
- Never change the main project Git remote.
- Never weaken the channel's `.stignore`; it is what stops Syncthing replicating `.git`.
- Never make a GitHub repository public.
- Never delete an old communications checkout during attachment/update.
- Never unregister communications while either outbox is non-empty.
- Never migrate a real project solely because its name appears in this file.

NATV is the first designated real migration target. Its apply step still
requires review of the current read-only scan and dry run before any filesystem,
Syncthing, hub, or GitHub mutation.
