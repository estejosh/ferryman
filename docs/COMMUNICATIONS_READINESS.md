# Communications readiness

## Validation evidence — 2026-07-26

- `cargo fmt --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed: 30 tests, 0 failures.
- The real Git test used a temporary bare repository and two independent
  checkouts. It proved per-message push, stale-checkout rebase, same-message
  duplicate suppression at the shared-folder/Git boundary, inbound pull, private-Git
  acknowledgement return, sender outbox retirement, and fresh-clone evidence.
- The local HTTP fixture proved configure, actor-token isolation, idempotent
  send, local-only inbox, claim, acknowledgement, zero-depth local-only status,
  guarded unregister, and actor-token revocation.
- The Windows apply fixture proved preserved adopted history, idempotent rerun,
  compatible legacy `bridge.toml` enrichment, an unchanged main-project remote,
  outer-only runtime/token boundaries, a passing read-only safety scan, and a
  portable adoption contract pushed to a temporary bare repository.
- The WSL/Linux fixtures proved a non-mutating dry run and an idempotent apply
  with the same no-agent/single-agent/multi-agent standard and safety scan.
- `openapi/openapi.yaml` parsed successfully as YAML 3.1 contract data.

The automated evidence suite uses only disposable local fixtures. It does not
read or modify a real project, token, Syncthing folder, GitHub repository, or
old communications checkout.

## Functional

- One machine-wide hub stores a project-scoped mapping for each attachment.
- The outer `.ferryman` directory contains only local configuration, token, and
  runtime state; the inner `ferryman` directory contains portable messages,
  acknowledgements, participant profiles, protocol metadata, and its own Git
  history.
- Messages receive stable UUIDs and idempotency keys, are atomically persisted
  to the outer outbox before delivery, and keep immutable per-attempt receipts.
- Delivery is local first. Ferryman verifies the exact Syncthing folder rather than
  treating directory existence as shared health.
- A missing acknowledgement by its bounded deadline promotes the project to
  private-Git live mode. Every message is committed and pushed in that mode.
- Receivers synchronize the named private-Git branch when shared delivery is
  unavailable or inbound Git mode remains active. Acknowledgements have their
  own durable outbox and return through shared storage or private Git, allowing
  the sender to retire its original outbox after a full two-checkout round trip.
- Failed or rate-limited Git delivery remains queued with bounded backoff. A
  background reconciler retries every ten seconds and probes preferred routes.
- Failover and backoff state survives process restarts. Corrupt outbox entries
  are quarantined without blocking healthy entries, and external subprocesses
  have hard deadlines.
- Inbound acknowledgement retirement reloads the exact stored message and
  compares its recipient and idempotency key before removing the sender
  outbox. Forged-field regression tests preserve the queued message.
- Atomic, hashed execution claims suppress duplicate execution when the same
  message arrives through local, the synced folder, and Git.
- Claim and acknowledgement require an eight-hour token scoped to the exact
  registered actor. Project operator tokens cannot consume work, and one actor
  cannot acknowledge another actor's message.
- Inline payloads are capped at 256 KiB and recursively reject credential-like
  fields before portable persistence.
- The live Git transport verifies exact owner/name, private visibility, and the
  inner `origin`; attachment setup compares the main project remote before and
  after and refuses any change.
- Git live writers serialize locally, fetch/rebase before commit, and retry one
  rejected push without creating duplicate message commits.
- Automated Git disables repository hooks. Git, `gh`, and Syncthing API
  transport probes remove Ferryman control/recovery tokens and common model
  credentials from their child environments.
- Windows drive paths and WSL `/mnt/<drive>` paths are translated at the server
  boundary. Automated Windows adoption coverage proves idempotence, preserved
  source history, and an unchanged main-project remote.
- Windows PowerShell and WSL/Linux Bash attachment commands implement the same
  framework-neutral modes. Every mapping includes `project-inbox`, including
  projects with no agent framework.
- Revision-2 inner/outer markers, explicit standard-update flags, a mandatory
  first-read guide, and read-only safety scanners give older projects a
  reviewable migration path without changing their agent architecture.

## Deliberate v0.1 boundaries

- Healthy-operation Git checkpoints are not scheduled. Git is used per message
  in live failover; operators may checkpoint portable metadata separately.
- Attachment does not create or rotate project tokens. If the existing outer
  token is absent, hub registration remains a separate authenticated step.
- Ferryman provides transport and evidence, not a worker sandbox or a
  framework-specific scheduler.

## Security limitations

- Portable v1 messages and acknowledgements are not yet cryptographically
  authenticated. A process or peer with write access to the inner directory,
  Syncthing folder, or private Git repository can forge a structurally valid
  message. Treat transport write access as work-authoring authority and do not
  use portable messages for irreversible actions. Signed v2 enforcement is
  specified in [portable authentication](PORTABLE_AUTHENTICATION.md).
- Portable message payloads are not encrypted by Ferryman. The inner directory,
  Syncthing folder, and private Git repository must therefore be readable only
  by trusted participants. Payload validation blocks common secret-bearing
  fields but cannot infer whether an arbitrary string is sensitive; use local
  references.
- GitHub privacy verification relies on the authenticated `gh` CLI and is cached
  for ten minutes. A visibility-verification failure closes Git delivery and
  retains the local queue.
- Workers and message consumers remain trusted execution environments. The
  claim protocol prevents duplicate Ferryman execution but does not sandbox the
  action itself.

## Generic migration commands

Windows dry run:

```powershell
& C:\ferryman\scripts\attach-project.ps1 `
  -Workspace C:\example `
  -Project example `
  -SharedRemote example-bridge `
  -GitRemote https://github.com/OWNER/example-bridge.git `
  -IntegrationMode unmanaged `
  -DryRun
```

WSL/Linux equivalent:

```bash
scripts/attach-project.sh \
  --workspace /path/to/example \
  --project example \
  --shared-remote example-bridge \
  --git-remote https://github.com/OWNER/example-bridge.git \
  --integration-mode unmanaged \
  --dry-run
```

See `PROJECT_ADOPTION_STANDARD.md` for unmanaged, single-agent, and multi-agent
mapping examples and the acceptance checklist.
