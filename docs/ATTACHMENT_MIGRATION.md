# Attachment and migration

Read [`ALWAYS_READ_THIS_FIRST.md`](../ALWAYS_READ_THIS_FIRST.md) before using
these commands. Run the read-only safety scanner first and show its result to
the user:

```powershell
& X:\ferryman\scripts\scan-project-safety.ps1 -Workspace X:\example
```

Use `scripts/attach-project.ps1` on Windows or `scripts/attach-project.sh` on
WSL/Linux. Both are idempotent, support a no-write dry run, refuse to overwrite
different existing configuration, check the exact GitHub owner/name and private
visibility before cloning, and compare the main project remote before and after
setup.

The portable `PROTOCOL.md`, `ADOPTION.md`, `STANDARD.toml`, and ignore rules are committed with
a fixed Ferryman identity and pushed to the current named branch. This makes
the same framework-neutral handoff available to another trusted machine. The
outer token, runtime, and `bridge.toml` are never included in that commit.

Choose `unmanaged`, `single-agent`, or `multi-agent`. `unmanaged` is the default
and always provides `project-inbox`, so a project without agents can adopt
Ferryman without changing its build architecture. Repeat
`-Participant 'name|role|capability1,capability2'` on PowerShell or
`--participant 'name|role|capability1,capability2'` on Bash for existing
automation identities. See the [framework-neutral project adoption
standard](PROJECT_ADOPTION_STANDARD.md).

The command creates the outer/inner layout and routing metadata. It never
creates, changes, copies, or prints a project token. If an existing outer
`.ferryman/token` is present, the command reads it only into memory to authorize
registration of the communications mapping with the hub, then releases the
value. If no token exists, setup continues and reports that hub registration is
deferred. Use `-SkipHubRegistration` or `--skip-hub-registration` to suppress
registration explicitly.

For an existing bridge checkout, `-AdoptFrom` or `--adopt-from` performs a
non-hardlinked local clone, verifies the source and clone `HEAD`, and then sets
only the inner clone's origin. The source checkout is left unchanged and
recoverable.

MEGAcmd registers only the inner directory. Use `-SkipMegaRegistration` or
`--skip-mega-registration` only for a fixture or when an operator intentionally
plans to register the dedicated sync separately.

Generic Windows dry run:

```powershell
& X:\ferryman\scripts\attach-project.ps1 `
  -Workspace X:\example `
  -Project example `
  -SharedRemote example-bridge `
  -GitRemote https://github.com/OWNER/example-bridge.git `
  -IntegrationMode unmanaged `
  -DryRun
```

Generic WSL/Linux dry run:

```bash
scripts/attach-project.sh \
  --workspace /path/to/example \
  --project example \
  --shared-remote example-bridge \
  --git-remote https://github.com/OWNER/example-bridge.git \
  --integration-mode unmanaged \
  --dry-run
```

After review, remove only the dry-run flag. When adopting an old communications
checkout, do not retire it as part of attachment. Retirement is a distinct,
explicitly approved operation after history, remote, MEGA status, hub status,
and message round-trip verification.

For an existing attachment below revision 2, retain all original parameters and
add `-UpdateStandard` (PowerShell) or `--update-standard` (Bash), still with the
dry-run flag first. The update refuses dirty managed portable files and
validates and enriches a compatible legacy outer `bridge.toml`. Scan again
after apply.
