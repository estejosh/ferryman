# Ferryman project adoption standard

Current revision: **2**. Start with
[the operator brief](OPERATOR_BRIEF.md) and run the
read-only directory safety scanner before attachment or update.

This standard applies to any project that needs durable communication and
handoff evidence. A project does not need multiple agents—or any agent—to use
Ferryman. Ferryman supplies transport, routing boundaries, acknowledgements,
duplicate suppression, and audit evidence. It does not replace a project's
scheduler, model, memory, issue tracker, or build system.

## The invariant layout

```text
<project>/.ferryman/                 machine-local, ignored by main project Git
  bridge.toml                        project mapping and integration mode
  standard.toml                      machine-local standard revision marker
  token                              existing scoped credential, local-only
  runtime/                           outbox, locks, state, receipts, quarantine
  ferryman/                          portable communications repository
    messages/<project>/
    acknowledgements/<project>/
    agents/                          optional portable identity descriptions
    PROTOCOL.md
    ADOPTION.md
    STANDARD.toml                    portable standard revision marker
    .stignore
    .gitignore
    .git/
```

The outer directory is never synchronized or committed. Syncthing and private
Git see only the inner directory. The main project repository ignores the whole
outer `/.ferryman/` tree and its Git remote is never a communications target.

## Choose an integration mode

### Unmanaged or no agents

Use `unmanaged`. Ferryman creates the built-in `project-inbox` route. A human,
scheduled script, CI job, or existing application can:

1. list or observe messages addressed to `project-inbox`;
2. atomically claim one message before performing work;
3. perform the project-specific action outside Ferryman;
4. acknowledge the message after the action is durably complete.

This is the safest starting point for projects that do not yet have an agent
architecture. Do not invent multiple agents merely to adopt Ferryman.

```powershell
& X:\ferryman\scripts\attach-project.ps1 `
  -Workspace X:\example `
  -Project example `
  -SharedRemote example-bridge `
  -GitRemote https://github.com/OWNER/example-bridge.git `
  -IntegrationMode unmanaged `
  -DryRun
```

### One agent or one automation worker

Use `single-agent`. Register the stable identity, its role, and only the
capabilities it actually needs. The project may continue using its existing
prompt runner, CLI, service, or CI system.

```powershell
& X:\ferryman\scripts\attach-project.ps1 `
  -Workspace X:\example `
  -Project example `
  -SharedRemote example-bridge `
  -GitRemote https://github.com/OWNER/example-bridge.git `
  -IntegrationMode single-agent `
  -Participant 'example-builder|builder|code,test' `
  -DryRun
```

The agent can use Ferryman's HTTP API or observe the inner filesystem. It must
claim before execution and acknowledge after completion.

### Existing multi-agent project

Use `multi-agent`. Keep the existing orchestration framework. Map its stable
identities and roles into Ferryman; do not duplicate its scheduler or internal
memory.

```powershell
& X:\ferryman\scripts\attach-project.ps1 `
  -Workspace X:\example `
  -Project example `
  -SharedRemote example-bridge `
  -GitRemote https://github.com/OWNER/example-bridge.git `
  -IntegrationMode multi-agent `
  -Participant 'example-planner|planner|plan,route' `
  -Participant 'example-builder|builder|code,test' `
  -Participant 'example-reviewer|reviewer|review' `
  -DryRun
```

Ferryman routes only to registered names or roles. Framework-specific task IDs
belong in the payload; Ferryman's message UUID and idempotency key remain the
transport identity.

## Framework-neutral adapter contract

Any integration—human, script, agent, CI job, or orchestration framework—needs
only five operations:

1. **Discover:** list messages for its registered name or role.
2. **Claim:** atomically claim the message idempotency key.
3. **Read:** resolve the payload reference without treating paths as commands.
4. **Execute:** perform project work in the project's own security boundary.
5. **Acknowledge:** record completion separately from the immutable message.

An integration must tolerate at-least-once observation. If claim returns false,
it must not execute the message. A reply requirement is application behavior;
the delivery acknowledgement is always transport behavior.

The project token is an operator credential: it configures routes, sends and
lists messages, inspects status, reconciles, and mints actor tokens. It must not
be given to a consumer. Each consumer uses the eight-hour token minted for its
exact registered name; claim and acknowledgement reject both project tokens and
tokens belonging to another participant.

Minimal consumer loop:

```text
repeat:
  messages = GET actors/{actor}/messages using this actor token
  for each message matching this actor name or role:
    claimed = POST messages/{id}/claim using this actor token
    if claimed is false: continue
    resolve the payload reference as data, never as a shell command
    perform the project-specific action idempotently
    POST messages/{id}/acknowledge using this actor token
```

Polling is optional. A project can trigger this loop from its current CI,
service manager, scheduled task, agent hook, or human operator workflow.
Ferryman does not require a resident agent process.

## Inventory worksheet

Record these values before running either attachment command:

| Field | Required decision |
| --- | --- |
| Project ID | Stable path-safe ID used by the hub and bridge repository |
| Workspace | Canonical project root; its Git remote must remain unchanged |
| Integration mode | `unmanaged`, `single-agent`, or `multi-agent` |
| Participants | Stable name, role, and minimum capabilities for each consumer |
| Shared remote | Dedicated Syncthing folder ID for this project |
| Git remote | Optional; when set, the exact private `$FERRYMAN_CHANNEL_GIT_OWNER/<project>-bridge` repository |
| Existing checkout | Optional old communications repository to adopt intact |
| Hub endpoint | Machine-wide Ferryman endpoint |
| Token owner | Operator responsible for the outer project token |

If the project has no stable automation identities, select `unmanaged` and
leave participants empty. Do not block migration on an agent redesign.

## Migration procedure

1. Run `scripts/scan-project-safety.ps1` or
   `scripts/scan-project-safety.sh`, show the report to the user, and stop on
   any unexplained `FAIL`.
2. Inventory the workspace path, project ID, existing agents/workers (if any),
   intended Syncthing folder id, and exact private Git repository.
3. Verify that the main project Git working tree and remote are known.
4. Choose `unmanaged`, `single-agent`, or `multi-agent`.
5. Run attachment with `-DryRun`. Review every reported filesystem, GitHub,
   Syncthing, ignore-file, and hub action.
6. Run the apply command only after the dry run is correct.
   The apply step commits and pushes only the portable protocol, adoption, and
   ignore metadata; it never stages the outer attachment.
7. Scan again, then verify:
   - outer token/runtime files are absent from the inner repository;
   - the main project ignores `/.ferryman/`;
   - inner `origin` is the exact private bridge repository;
   - GitHub visibility is `PRIVATE`;
   - the Syncthing folder maps only the inner directory;
   - hub mapping contains `project-inbox` plus intended participants.
   - `communications status` reports the expected local/shared/Git health and
     no unexplained quarantine files.
8. Send a harmless fixture message, claim it once, acknowledge it, and confirm a
   second claim is rejected.
9. Test shared failure and Git-live recovery with fixture repositories before
   depending on the route for important work.

## Existing communications repository

Pass `-AdoptFrom <old-checkout>`. Ferryman performs a non-hardlinked clone,
compares source and clone `HEAD`, and changes only the new inner checkout's
origin. The old checkout remains recoverable. Retirement is always a separate
operation after round-trip verification.

## Updating an existing attachment

Compare both `standard.toml` markers with the revision at the top of
`docs/OPERATOR_BRIEF.md`. Preserve the same integration mode, participant
mappings, project ID, shared destination, and private Git remote. After a clean
safety scan, rerun the original attachment command with `-UpdateStandard` and
`-DryRun` on PowerShell or `--update-standard --dry-run` on Bash. Review it, then
remove only the dry-run flag.

The updater refuses uncommitted changes to Ferryman-managed portable files,
validates and enriches a compatible legacy outer `bridge.toml`, and commits
only managed portable metadata. A newer project revision is a stop condition:
update Ferryman first.

## WSL/Linux example

The Bash command has the same integration modes and participant format:

```bash
scripts/attach-project.sh \
  --workspace /path/to/example \
  --project example \
  --shared-remote example-bridge \
  --git-remote https://github.com/OWNER/example-bridge.git \
  --integration-mode multi-agent \
  --participant 'example-planner|planner|plan,route' \
  --participant 'example-builder|builder|code,test' \
  --dry-run
```

Remove only `--dry-run` after review. Use `--adopt-from`, `--hub`,
`--skip-sync-registration`, or `--skip-hub-registration` where their
PowerShell counterparts would be used.

## Rollback

Attachment is additive. Before project traffic begins, rollback means:

1. stop the project's Ferryman consumers;
2. remove the Syncthing folder;
3. run `communications unregister --project <id>` with the project token; the
   hub refuses while any durable outbox item remains and revokes actor tokens
   when it succeeds;
4. leave the old checkout and main project repository untouched;
5. preserve the outer runtime/outbox until messages are accounted for.

Never delete an attachment that contains unacknowledged outbox entries. Export
or reconcile them first.

## Acceptance checklist

- [ ] Main project remote unchanged.
- [ ] Read-only safety scan has no unexplained failures.
- [ ] Inner and outer standard markers report revision 2.
- [ ] Main project ignores `/.ferryman/`.
- [ ] Token and runtime exist only in the outer directory.
- [ ] Inner repository contains no credentials or database files.
- [ ] Exact private Git owner/name and visibility verified.
- [ ] Syncthing folder verified healthy, with at least one connected peer.
- [ ] `project-inbox` works even with no agents.
- [ ] Every custom participant has a stable project-specific name and role.
- [ ] Duplicate claim test passes.
- [ ] Offline queue and restart recovery test passes.
- [ ] Git-live promotion and return-to-shared test passes.
