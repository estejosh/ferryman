# Live project communications

Ferryman has one machine-wide hub and one private communications repository per
attached project. Live communications are separate from encrypted continuity
packs: continuity packs are recovery archives; messages are small durable,
idempotent work envelopes.

## Boundary and layout

```text
<workspace>/.ferryman/             machine-local; ignored by the project repo
  bridge.toml                      project routing
  token                            existing scoped secret; never portable
  runtime/                         outbox, delivery attempts, dedupe claims
    transport-state.json           crash-safe failover/backoff state
    acknowledgement-outbox/        receipts awaiting remote delivery
    quarantine/outbox/             malformed entries isolated for inspection
    locks/git-live.lock             cross-process Git writer lock
  ferryman/                        portable communications Git + MEGA root
    messages/<project>/*.json
    acknowledgements/<project>/*.json
    agents/
    PROTOCOL.md
    STANDARD.toml
    .megaignore
    .gitignore
    .git/
```

The main project Git remote is never inspected as a communications target and
is never changed. MEGAcmd registers only the inner directory as a separate sync
root, so a project-level rule excluding hidden paths remains intact.

## Message delivery state

1. Ferryman assigns a UUID and idempotency key and atomically writes the
   envelope to the outer `runtime/outbox`.
2. If the local communications root is healthy, the message is atomically written to
   the inner `messages/<project>/` directory.
3. If local peer delivery is unavailable but the configured MEGAcmd sync reports
   healthy, the inner write is allowed to propagate through MEGA.
4. Every envelope has an acknowledgement deadline. If the preferred routes are
   unavailable, or that deadline passes without an acknowledgement, the private
   inner repository enters Git live mode: every message is committed and pushed.
5. Git/network failure retains the outbox item. Retry uses exponential backoff
   capped at five minutes.
6. A receiver pulls the named private-Git branch when shared delivery is
   unavailable or Git inbound mode is active. Acknowledgements use the same
   shared/Git fallback in reverse, so the sender can retire its outbox.
7. The hub reconciles every project's message and acknowledgement outboxes
   every ten seconds. Preferred
   transports are probed during reconciliation; two consecutive healthy
   shared-transport deliveries are required before Git live mode is left.
8. Each attempt is immutable under `runtime/delivery-attempts/<message>/`; the
   latest receipt is also stored under `runtime/deliveries/`.
9. Failover mode, inbound-Git mode, recovery streak, Git backoff, and
   privacy-verification cache
   are atomically persisted. A server restart resumes that state rather than
   incorrectly returning the project to local-only delivery.

Malformed or cross-project outbox entries are moved to
`runtime/quarantine/outbox` with an error sidecar. One corrupt file therefore
does not stop reconciliation of the rest of the project. MEGAcmd probes have a
15-second hard deadline; Git and GitHub subprocesses have a 45-second hard
deadline and are killed on expiry.

Quarantine is evidence, not an automatic retry queue. Inspect the error sidecar
and original file locally. For a legitimate malformed request, submit a new
validated message through the API with an intentional idempotency key; do not
move raw quarantined JSON back into the outbox. Preserve or archive quarantine
evidence according to the project's retention policy.

Acknowledgements live separately. Before executing a message, a consumer claims
the SHA-256 digest of its idempotency key under outer `runtime/processed`; an
existing atomic claim means the message was already observed through another
transport and must not execute again. Recording an acknowledgement removes a
locally originated outer outbox copy. For a Git-delivered message, it first
enters the receiver's durable `acknowledgement-outbox`, then is committed and
pushed; the sender pulls it and retires its original outbox. The immutable
portable message and acknowledgement remain available as evidence.

## Hub API

Operator routes use the project token:

- `POST|GET /v1/projects/{project}/communications` — configure/read the project map.
- `POST|GET /v1/projects/{project}/communications/messages` — send/list envelopes.
- `POST .../actors/{actor}/token` — mint an eight-hour actor-scoped token once.
- `POST .../reconcile` — request an immediate outbox reconciliation.
- `GET .../status` — transport health, failover/backoff, both queue depths, and
  quarantine. Use `?probe_external=false` for a strictly local snapshot.
- `DELETE /v1/projects/{project}/communications` — unregister the mapping and
  revoke its actor tokens without deleting attachment files; refused while the
  outbox is non-empty.

Consumer routes require the actor token for the exact registered actor named in
the request:

- `GET .../actors/{actor}/messages` — synchronize inbound state, then list only
  that actor's name/role inbox. Use `?synchronize=false` for a local-only read.
- `POST .../messages/{id}/claim` — atomically claim before execution.
- `POST .../messages/{id}/acknowledge` — record a separate acknowledgement.

A project token cannot claim or acknowledge work. An actor cannot claim or
acknowledge a message unless its registered name or role matches the message
recipient. This keeps an existing multi-agent framework's identities separate;
an unmanaged project uses the built-in `project-inbox` actor.

`acknowledgement_timeout_seconds` defaults to 30 and is bounded to 5–3600
seconds. Inline payloads are capped at 256 KiB. Portable JSON is rejected when
it contains credential-bearing keys such as `token`, `secret`, `password`,
`credential`, `api_key`, or `private_key`; use a local secret reference instead.
The server translates Windows drive paths to `/mnt/<drive>/...` when running in
WSL, and the reverse when running as a Windows process.

## Health and Git safety

MEGA health comes from `mega-sync --show-handles` inside the configured Ubuntu
distribution, matching both the translated `/mnt/<drive>/...` path and the
expected MEGA destination. On a WSL/Linux hub, Ferryman invokes `mega-sync`
directly; on Windows it invokes it through `wsl.exe`. Directory existence alone
is not shared-transport health. The acknowledgement deadline also detects a
remote peer that is not consuming messages even when MEGAcmd itself reports a
healthy sync.

When a Git remote is configured, GitHub visibility must be verified as `PRIVATE`
for the exact `$FERRYMAN_CHANNEL_GIT_OWNER/<project>-bridge` name before
clone/configuration. A channel with no Git remote is Syncthing-only: the Git rung
is simply unavailable and no visibility check applies. Visibility is
cached for ten minutes by the live Git transport; the attachment command also
verifies it once per run and refuses any public or mismatched repository. Before
each Git delivery, Ferryman verifies that the inner repository's `origin`
matches the registered project remote. It never runs a remote-changing command
against the main project checkout.

Git live retries are message-idempotent: an already committed file is pushed
again without creating a duplicate commit. Writers take an exclusive
project-local lock, fetch, rebase with autostash, commit only new portable
files with a fixed non-secret Ferryman commit identity, and push. A rejected
push triggers one fetch/rebase/retry in the same bounded operation; any
remaining error retains the outbox item for the next reconciliation. A
same-message delivery from a stale second checkout rebases without creating a
second message commit. Pull and acknowledgement pushes use the same named-branch
verification, clean-worktree requirement, exclusive lock, bounded subprocess,
and exact-origin checks.

## Operator commands

```powershell
# Project token
cargo run -p ferryman-cli -- communications status --project example
cargo run -p ferryman-cli -- communications status --project example --local-only
cargo run -p ferryman-cli -- communications reconcile --project example
cargo run -p ferryman-cli -- communications mint-actor-token `
  --project example --actor project-inbox

# Replace FERRYMAN_TOKEN with the returned actor token for consumer actions.
cargo run -p ferryman-cli -- communications inbox `
  --project example --actor project-inbox
cargo run -p ferryman-cli -- communications inbox `
  --project example --actor project-inbox --local-only
cargo run -p ferryman-cli -- communications claim `
  --project example --recipient project-inbox <message-id>
cargo run -p ferryman-cli -- communications acknowledge `
  --project example --recipient project-inbox <message-id>

# Project token; safe rollback only after the outbox reaches zero.
cargo run -p ferryman-cli -- communications unregister --project example
```

Actor tokens are returned once and expire after eight hours. They are runtime
credentials and must never be written inside the portable inner repository.
