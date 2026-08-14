# Ferryman Repository Roadmap

## 1. Orientation

Ferryman is **private coordination for a fleet of AI agents, across machines you own**
(`README.md`). The workspace is version `0.3.1`, edition `2024`, source-available
(`LicenseRef-Ferryman-Source-Available`), and forbids `unsafe` code workspace-wide
(`Cargo.toml` `[workspace.lints.rust]`). Its heart is **`ferryman-channel`**: a durable,
project-scoped coordination layer where agents leave signed files in a Syncthing-carried
folder and read each other's files back — no server, no database, no listener. Around it
sit a CLI (`ferryman-cli`), the agent loop library (`ferryman-ops`), and an older
**server mode** (`ferryman-core` + `ferryman-server` + `ferryman-worker-sdk`) that runs
the same kind of coordination as an HTTP control plane over SQLite. The two modes share
the channel's identity, signing, and trust primitives. `ferryman-tray` is deliberately
excluded from the workspace because it needs desktop libraries; the repo root also carries
a `memory-bank` symlink into this project's own live `.ferryman` memory, which is context
for humans/agents working on Ferryman, not part of the build.

## 2. Workspace layout

Members (from `Cargo.toml`):

- `crates/ferryman-channel`
- `crates/ferryman-core`
- `crates/ferryman-server`
- `crates/ferryman-cli`
- `crates/ferryman-ops`
- `crates/ferryman-worker-sdk`
- `crates/ferryman-tray` — **excluded** (`exclude = [...]`) because it needs GTK on Linux.

Other notable roots: `docs/` (architecture, threat model, operator brief, ADRs, reviews),
`scripts/` (attach/scan helpers), `openapi/`, `deploy/`, `config/`, `Containerfile`,
`compose.yaml`, `bridge-release.toml`.

## 3. Crate-by-crate purpose and public surface

### 3.1 `ferryman-channel`

`crates/ferryman-channel/Cargo.toml` describes it as: *"The Ferryman channel: portable
agent messages and shared memory on a synced folder. No server, no database, no network
listener."* Dependencies are intentionally small: `ed25519-dalek`, `serde`, `serde_jcs`
(RFC 8785 canonical JSON), `sha2`, `fs2`, `uuid`, `toml`, `chrono`, `rand`, `wait-timeout`,
`anyhow`.

Modules declared in `crates/ferryman-channel/src/lib.rs`:

- `contract` — result contracts
- `interrupt` — operator interrupts
- `learning` — durable record of what worked
- `ledger` — append-only signed attribution ledger
- `licensing` — device counting / licensing
- `master` — master declaration and master-signed grants
- `migration` — v1 → v2 portable message migration
- `portable_auth` — signed v2 envelopes and the trusted-signers store
- `source` — task sources (external work → signed orders)
- `worktree` — one git worktree per (order, agent)

`lib.rs` itself is the biggest file (~7,000 lines) and exposes four overlapping surfaces:

1. **Routing and roster.** `ChannelNamespace`, `AgentRoute`, `ProjectRoute` (fields:
   `project_id`, `workspace`, `attachment`, `communications`, `shared_remote`,
   `git_remote`, `git_visibility`, `agents`); `ProjectRoute::master_dir()`,
   `ProjectRoute::is_team()`, `ProjectRoute::requires_grants()`. Discovery/registration:
   `route_for`, `discover_attachment`, `load_route`, `register_agent`, `register_agent_key`,
   `read_agent_roster`.

2. **The task protocol** (see §4). `Order`, `Claim`, `TaskResult`, `Review`,
   `Recommendation`, `TaskState`, `Task`; `issue_order`, `claim_order`, `submit_result`,
   `submit_review`, `submit_recommendation`, `read_task`, `list_tasks`, `work_for`;
   `Task::holder()`, `Task::latest_revision()`, `Task::contract_violations()`,
   `Task::pending_recommendation()`, `Task::state()`.

3. **Signing and trust** (see §5). `AgentIdentity`, `SignatureCheck`, `check_signature`,
   `verify_order`, `verify_result`, `verify_review`, `verify_recommendation`,
   `verify_message`, plus v2 wrappers `trust_store`, `replay_ledger`, `verify_v2_message`,
   `verify_v2_acknowledgement`, `add_trusted_signer`, `revoke_trusted_signer`.

4. **Message transport.** v1 `Message`/`Acknowledgement`, `MessageTransport` trait,
   `LocalFilesystemTransport`, `SharedFolderTransport`, `PrivateGitTransport`,
   `DeliveryEngine`, `system_delivery_engine`, `snapshot_channel_to_git`, Syncthing
   helpers (`syncthing_peers`, `syncthing_register_folder`, `syncthing_register_fleet`,
   `SyncthingProbe`), and message APIs (`claim_message`, `read_message`, `list_messages`,
   `find_message_by_idempotency_key`, `record_acknowledgement`, `claim_message_v2`,
   `acknowledge_v2`, `list_messages_v2`, `read_message_v2`).

Small helpers worth knowing: `is_safe_component` (path-safe id validation), `atomic_json`,
`write_task_file` (temp-then-rename), `filesystem_metrics`, `real_path`.

### 3.2 `ferryman-core`

`crates/ferryman-core/src/lib.rs` is the durable store and job state machine for **server
mode**. It depends on `ferryman-channel` and `rusqlite`. Public types: `JobStatus`
(`PendingApproval | Queued | Leased | Succeeded | Accepted | Failed | Cancelled`),
`PolicyEnvelope`/`Access`, `Project`, `ProjectCommunicationMapping`,
`CommunicationActorRegistration`, `AgentPersistence`, `Agent`, `ProjectMemoryEntry`,
`ConsentRequest`, `MemoryCandidate`, `Job`, `Event`, `Lease`, `Artifact`, `Worker`,
`WorkerRegistration`, `NewJob`, and the `Adapter` trait.

The workhorse is `SqliteStore` (`open` + one short-lived connection per operation), with
methods: `create_project`, `authenticate`, `get_project`, `list_projects`,
`set/get/list/delete_project_communications`, `mint_communication_actor_token`,
`authenticate_communication_actor`, `delete_project`, `submit_job`, `get_job`,
`list_jobs`, `approve`, `cancel`, `get_job_any_project`,
`jobs_pending_telegram_notification`, `telegram_approve`, `telegram_deny`,
`mark_telegram_notified`, `jobs_awaiting_review`, `accept_result`, `request_changes`,
`register_worker`, `list_workers`, `authenticate_worker`, `ensure_agent`, `list_agents`,
`record_memory`, `project_memory`, `heartbeat`, `lease`, `complete`,
`worker_holds_active_lease`, `append_worker_event`, `append_project_event`, `events`,
`timeline`, `create_artifact`, `list_artifacts`, `get_artifact`, `project_artifacts`,
`metrics`, `approve_artifact_bypass`, `artifact_bypass_limit`, `create_consent`,
`list_consents`, `resolve_consent`, `propose_memory`, `list_memory_candidates`,
`approve_memory_candidate`.

### 3.3 `ferryman-server`

`crates/ferryman-server/src/lib.rs` is an **axum 0.8 HTTP API** over `SqliteStore`.
`AppState` holds the store, artifact root, admin/memory-write tokens, workspace/memory/
recovery roots, the recovery key, and a per-project map of `SystemDeliveryEngine`s, plus
the resolved `ChannelNamespace`; it is assembled with `with_*` builders. `app(state)` is
the single router, with routes grouped as:

- health/metrics: `/healthz`, `/v1/metrics`
- projects & communications: `/v1/projects`, `/v1/projects/{project_id}`,
  `/v1/projects/{project_id}/communications[/...]`, `/communications/messages`,
  `/communications/messages/{message_id}/claim|acknowledge`,
  `/communications/actors/{actor}/token|messages`, `/communications/reconcile`,
  `/communications/status`
- agents/memory/consents: `/agents`, `/memory`, `/memory/candidates[/...]`,
  `/consents[/...]`, `/outbound-submissions`, `/improvement-proposals`
- continuity: `/continuity-pack`, `/continuity-packs`, `.../recover`,
  `.../delivery-consents`, `.../deliver`, `/recovery-drill`
- jobs/workers/artifacts: `/jobs` (POST/GET), `/jobs/{job_id}`,
  `/jobs/{job_id}/approve|cancel`, `/jobs/awaiting-review`,
  `/jobs/{job_id}/accept|request-changes|events|artifacts|events/log|complete`,
  `/jobs/{job_id}/artifact-bypass/approve`, `/artifacts/{artifact_id}[/content]`,
  `/workers`, `/workers/{worker_id}/heartbeat|lease`.

Auth helpers are `checked`, `checked_admin`, `checked_memory_write`, `checked_worker`,
`checked_communication_actor` (constant-time comparison in `ct_eq`).
`start_communications_reconciler` runs the background reconciler.

Submodules: `continuity.rs` (encrypted continuity packs: `PackManifest`, `PackPayload`,
`PackArtifact`, `SafeJob`, `PackResult`, `RecoveryBriefing`, `encrypt`/`decrypt`,
`manifest_hmac`), `recovery_targets.rs` (`RecoveryTarget` trait, `FilesystemTarget`,
`GitRecoveryTarget`, `DisabledExternalTarget`, `Receipt`), `telegram.rs` (`TelegramGate`),
`workspace.rs` (`project_directory`, `provision_private_repository`,
`write_agent_profile`, `select_artifact_root`).

`crates/ferryman-server/src/main.rs` is the binary entrypoint: clap `Args` (database,
artifacts, workspace/memory/recovery roots, listener, `--production`, `--tls-terminated`,
etc.), boot-time guards, recovery-key loading (`load_recovery_key`), Telegram token
loading (`load_telegram_bot_token`), and gate wiring.

### 3.4 `ferryman-cli`

`crates/ferryman-cli/src/main.rs` builds the `ferry` binary (`default-run = "ferry"`).
The `Command` enum splits into **channel-first** commands and **server-mode** commands:

- `Enable` → `ferryman_ops::enable::perform`
- `Pause` / `Resume` → `ferryman_ops::governor::pause_marker()`
- `Log` → `ferryman_ops::runlog::tail`
- `Agent { Run | Review | Pending }` → `agent_command`
- `Channel { ... }` → `channel()` (see below)
- Server mode: `Init`, `Projects`, `Jobs`, `Workers`, `Agents`, `Memory`, `Artifacts`,
  `Consents`, `Continuity`, `Communications` — these call `call` / `call_memory` /
  `call_approver` against a running server.

`Channel` subcommands (dispatch in `fn channel(...)`, ~line 1854): `Status`, `Send`,
`Inbox`, `Join`, `Agents`, `Order`, `Source`, `Sources`, `Watch`, `Worktree`
(`Branch`/`Create`/`Cleanup`), `Interrupt`, `Work`, `Claim`, `Submit`, `Review`, `Tasks`,
`Log`, `Trust` (`List`/`Revoke`/`Add`), `Master` (`Init`/`Status`/`Transfer`/`Grant`/
`Grants`), `Report`.

Two extra bins are auto-discovered in `src/bin/`:

- `ferryman-key.rs` — operator utility that writes the recovery secret to the OS keychain
  and never prints key material.
- `ferryman-updater.rs` — explicit approve/deny update helper (`check-remote` read-only,
  `update-bridge --confirm`).

`src/license.rs` implements `ferry license` (`status`; check-in only when
`FERRYMAN_CHECKIN_URL` is set; failures never block work).

### 3.5 `ferryman-ops`

`crates/ferryman-ops/src/lib.rs` documents the split: *the things Ferryman does,
separated from the program that types them*. Nothing prints; progress flows through the
tiny `Progress` trait with `Silent` and `Stdout` implementations. Modules:

- `agent.rs` — the agentic half. `ReviewMode` (`Auto`/`Confirm`/`Off`), `Runner`
  (`Bare`/`Podman`/`Docker`), `AgentConfig` (agent name, command, args, runner, worktree
  flag, timeout, review mode, memory/claim-window/poll settings, preamble). Key functions:
  `plan`, `work_once`, `review_once`, `pending`, private `do_work`/`run_agent`,
  `work_prompt`/`review_prompt`, `parse_verdict`, `Verdict`.
- `enable.rs` — `ferry enable`: `Request`, `Step`, `Outcome`, `perform`.
- `governor.rs` — whether this machine may claim: `Window`, `Presence`, `pause_marker`,
  `paused`, `presence`, `available_memory_mb`, `Decision` (`Go`/`Wait`), `may_claim`,
  and the pure `judge_*` helpers.
- `identity.rs` — `machine_name`, `resolve`, `slug`.
- `priority.rs` — `lower(pid)` (nice the child, Unix; no-op elsewhere).
- `runlog.rs` — machine-local diagnostic log: `path`, `append`, `tail`, `Logged`.

### 3.6 `ferryman-worker-sdk`

`crates/ferryman-worker-sdk/src/lib.rs` is a minimal HTTP worker client for **server
mode**. `WorkerClient` exposes `register`, `lease`, `event`, `complete`, `artifact`
(wrapping the `/v1/...` worker routes). Examples: `mock_worker.rs`, `agent_worker.rs`,
`dryrun_worker.rs`.

### 3.7 `ferryman-tray` (excluded)

`crates/ferryman-tray/src/main.rs` is a system-tray status/switch using `tray-icon` +
`winit`. It owns nothing: it reads the same `governor` the worker reads and writes the
same pause file `ferry pause` writes.

## 4. Core loop data flow: order → claim → result → review → ledger

There are two loops. The **channel loop** (files on a Syncthing folder) is the heart; the
**server loop** (SQLite jobs over HTTP) is the older mode. Both exist in the same repo.

### 4.1 Channel loop (serverless)

Artifacts for a task live under `tasks_root(route) = route.communications.join("tasks")`
(`lib.rs:828`), one directory per order id: `task_dir(route, order_id) =
tasks/<order_id>/` (`lib.rs:832`). Files are written atomically by
`write_task_file` (temp file, then rename — `lib.rs:840`).

**1. Order.** `ferry channel order` builds an `Order`
(`id`, `project_id`, `issued_by`, `assigned_to?`, `created_at`, `payload`,
`requires_review`, `result_contract?`, `signed_by?`, `signature?`), signs it with
`AgentIdentity::sign_order`, then calls `ferryman_channel::issue_order`
(`lib.rs:851`). `issue_order` refuses if the file already exists and writes
`tasks/<order_id>/order.json`. The CLI then appends a ledger entry of kind `"order"`.

**2. Claim.** `ferry channel claim` calls `ferryman_channel::claim_order`
(`lib.rs:869`), which writes `tasks/<order_id>/claim.<agent>.json` (each agent writes
only its own file, so claims never collide). In the running loop,
`ferryman_ops::agent::work_once` (`agent.rs:755`) first finds eligible work with
`ferryman_channel::work_for`, gates on `governor::may_claim` and (in team mode)
`master::is_granted`, then claims, writes ledger entry `"claim"`, re-reads via
`read_task`, and backs off if `task.holder() != agent` (oldest claim wins, deterministic
tie-break by agent name — `Task::holder`, `lib.rs:753`).

**3. Result.** `ferryman_ops::agent::do_work` (`agent.rs:831`) handles interrupts,
optionally creates a worktree, runs the agent CLI, and builds a `TaskResult`
(`order_id`, `agent`, `revision`, `submitted_at`, `payload`, `signed_by?`, `signature?`)
with `revision = task.latest_revision().unwrap_or(0) + 1` and payload keys
`output`, `produced_by`, `worktree_branch`, and `worktree_head` when a worktree was used.
It signs via `AgentIdentity::sign_result` and calls `ferryman_channel::submit_result`
(`lib.rs:889`), which writes `tasks/<order_id>/result.<agent>.<revision:03>.json`.
Ledger entry kind `"result"`.

**4. Review.** Two paths:

- Human: `ferry channel review` builds a `Review`
  (`order_id`, `revision`, `reviewer`, `reviewed_at`, `accepted`, `notes?`,
  `signed_by?`, `signature?`), signs it, and calls `ferryman_channel::submit_review`
  (`lib.rs:902`). Rejecting without notes is refused. `submit_review` writes
  `tasks/<order_id>/review.<revision:03>.json`, then calls
  `learning::record_outcome` so the fleet records which engine's work was kept.
- Agent: `ferryman_ops::agent::review_once` (`agent.rs:959`) finds tasks in
  `TaskState::AwaitingReview` where `by != config.agent`, runs the reviewer CLI, and
  parses a `Verdict`. `ReviewMode::Auto` writes a signed `Review`;
  `ReviewMode::Confirm` writes a signed `Recommendation` via
  `ferryman_channel::submit_recommendation` (`lib.rs:932`), which writes
  `tasks/<order_id>/recommendation.<reviewer>.<revision:03>.json`; `ReviewMode::Off`
  leaves results for a human. Ledger entry kind `"review"`.

**5. State and ledger.** `ferryman_channel::read_task` (`lib.rs:951`) reconstructs a
`Task` by scanning the directory for `claim.*`, `result.*`, `review.*`, and
`recommendation.*` files. `Task::state()` (`lib.rs:804`) derives `TaskState`:

- no holder → `Open`
- holder, no result → `Claimed { by }`
- result, no review, `requires_review` → `AwaitingReview { by, revision }`
- rejected review → `ChangesRequested { revision + 1 }`
- accepted review → `Accepted`
- result, no review, review not required → `Done`

Every significant act is appended to the ledger by
`ferryman_channel::ledger::append_ledger_entry` (`ledger.rs:101`), which writes one
signed, hash-chained JSON line to `communications/ledger.jsonl` (previous-line SHA-256 in
`prev`), takes the exclusive lock at `attachment/runtime/locks/ledger.lock`, and
best-effort backstops to private Git via `snapshot_channel_to_git`.
`ledger::read_ledger` (`ledger.rs:149`) verifies the chain and signatures;
`ledger::build_report` (`ledger.rs:243`) exports a signed `AuditReport` with per-entry
verification status.

### 4.2 Server loop (HTTP/SQLite)

The same conceptual cycle, implemented as a job state machine in `ferryman-core`
(see `docs/ARCHITECTURE.md`):

1. `SqliteStore::submit_job` (`lib.rs:595`) inserts a `Job` in `PendingApproval` (if
   `requires_approval`) or `Queued`, emitting event `job.submitted`.
2. `approve` transitions `PendingApproval → Queued` (`job.approved`).
3. A worker calls `lease` (`lib.rs:1105`), which first reaps expired leases, then
   atomically claims the oldest eligible `Queued` job (`Queued → Leased`,
   `job.leased`), returning a `Lease` with an opaque `lease_id`.
4. `complete` (`lib.rs:1177`) uses `lease_id` as the idempotency key and moves the job to
   `Succeeded` (`job.succeeded`), or back to `Queued` with backoff (`job.retry_scheduled`),
   or `Failed` (`job.failed`).
5. For `requires_review` jobs, `accept_result` (`lib.rs:835`) moves `Succeeded →
   Accepted` (`job.result_accepted`); `request_changes` (`lib.rs:886`) increments
   `revision`, attaches `review_notes`, and moves the job back to `Queued`
   (`job.changes_requested`). Jobs and events commit in one SQLite transaction.

## 5. Signing, identity, trust, master, grants

**Identity — `crates/ferryman-channel/src/lib.rs`.** `AgentIdentity`
(`lib.rs:1041`) is one Ed25519 key **per agent** (not per machine), loaded/created by
`AgentIdentity::load_or_create` / `load_or_create_in`. The private key stays outside the
synced folder (OS secret store, else the machine state dir / attachment `keys/`), while
`public_key_hex` publishes only the public half. Signing methods: `sign_order`,
`sign_result`, `sign_review`, `sign_recommendation`, `sign_interrupt`,
`sign_message_v2`, `sign_acknowledgement_v2`.

**Payload construction and verification.** Each artifact defines the exact bytes its
signature covers: `order_payload`, `result_payload`, `review_payload`,
`recommendation_payload` (all in `lib.rs`), `ledger::ledger_payload`,
`master::master_payload`, `master::grant_payload`, `interrupt::payload`, and
`portable_auth::canonical_bytes` (RFC 8785 JCS). `check_signature` compares against the
roster; `SignatureCheck` is `Valid | Invalid | UnknownSigner | Unsigned`. Public
verifiers: `verify_order`, `verify_result`, `verify_review`, `verify_recommendation`,
`verify_message`; the ledger verifies through `read_ledger`; master declarations/grants
through `read_master`/`member_grants`.

**Portable auth v2 — `crates/ferryman-channel/src/portable_auth.rs`.** Implements gates 1
and 2 of `docs/PORTABLE_AUTHENTICATION.md`: `SignerId` (`sha256:<hex>` of the public key),
`Authentication` block, signed `MessageV2`/`AcknowledgementV2` envelopes
(`MESSAGE_FORMAT_V2` / `ACKNOWLEDGEMENT_FORMAT_V2`), `SignerGrant`, `TrustedSigners`
(parses the outer, unsynchronized `trusted-signers.toml`), and `ReplayLedger` for nonce
replay protection. `lib.rs` wraps these as `trust_store`, `replay_ledger`,
`verify_v2_message`, `verify_v2_acknowledgement`, `add_trusted_signer`,
`revoke_trusted_signer`, and `quarantine_invalid_inbound`.

**Master — `crates/ferryman-channel/src/master.rs`.** `MasterDeclaration` is a signed,
public file (`communications/master.json`) naming the project master; the master's own
folder is `<project>-master-ferryman` (`master_folder_name`). `initialize_master`,
`read_master`, `transfer_master` (disclaim, signed by the outgoing master).

**Grants — `crates/ferryman-channel/src/master.rs`.** `MasterGrant` is a master-signed
statement of one member's `projects`/`roles`/`capabilities`. `grant_member`,
`member_grants`, `is_granted` (the team-mode gate used by `agent::work_once`).

## 6. The newer modules and what each adds

- **`source`** (`crates/ferryman-channel/src/source.rs`) — pluggable adapters that map
  external work (issue tracker export, script stdout) into signed orders. `TaskSource`
  (today only `Shell`), `SourceTicket`, `TaskSource::fetch`, pure `to_order`,
  deterministic `order_id(source_name, ticket_id)`, `import`, and always-on
  `SourceTrigger`/`SourceConfig`/`load_triggers`/`poll_if_due`. An imported ticket becomes
  a signed order with a ledger entry, so its provenance is as checkable as a hand-issued
  one.
- **`worktree`** (`crates/ferryman-channel/src/worktree.rs`) — one git worktree per
  (order, agent). `branch_name` is deterministic (`ferryman-<order>-<agent>`, slugged and
  git-safe), so a re-dispatched task lands in the same worktree (idempotent);
  `create_worktree`, `is_git_repo`, `worktree_head`, `remove_worktree`. The head commit is
  signed into the result (`worktree_head` in `do_work`).
- **`interrupt`** (`crates/ferryman-channel/src/interrupt.rs`) — a signed way for an
  operator to pause, steer, or kill a running agent between poll ticks.
  `InterruptAction::{Kill, Pause, Steer}`, `Interrupt`, `payload`,
  `write_interrupt`, `pending_interrupts`, `acknowledge`, `abandon_claim`. Honored in
  `do_work`, and recorded in the ledger.
- **`contract`** (`crates/ferryman-channel/src/contract.rs`) — `ResultContract`
  (required top-level result keys) and `violations(payload)`. It travels inside the signed
  order, so the requirement cannot be tampered with after issue; `Task::contract_violations`
  and `ferry channel review` reject malformed deliverables mechanically.
- **`learning`** (`crates/ferryman-channel/src/learning.rs`) — a durable, synced record of
  *what worked*, as opposed to the ledger's *what happened*. `Learning`, `EngineStats`,
  `record_learning`, `read_learnings`, `engine_stats` (per-engine acceptance rate), and
  `record_outcome` (hooked into `submit_review`). Appends to
  `communications/learnings.jsonl`; deliberately unsigned/unchained because it is derived
  data, and torn lines are skipped rather than fatal.
- **`licensing`** (`crates/ferryman-channel/src/licensing.rs`) — device/fleet counting:
  `DeviceKind`, `DeviceRecord`, `FleetCount`, `device_id`, `register_device`,
  `read_devices`, `count`, `registered_emails`, `deployment_id`, `check_in`,
  `machine_state_dir`, `over_limit_notice`.
- **`migration`** (`crates/ferryman-channel/src/migration.rs`) — v1 (unsigned) → v2
  (signed) portable message migration: `MigrationEntry`, `ConvertOutcome`,
  `inventory_v1`, `convert_v1_to_v2`, `convert_v1_to_v2_with_identity`.
- **`portable_auth`** — see §5 (v2 signed envelopes + trust store).

A memory-bank exists at the repo root as a symlink
(`memory-bank -> /mnt/nvme-storage/repos/ferryman-ferryman/.ferryman/ferryman/memory-bank`).
It is this project's own shared agent memory (read order documented in
`memory-bank/README.md`: `projectbrief.md`, `productContext.md`, `systemPatterns.md`,
`techContext.md`, `activeContext.md`, `progress.md`), not a compiled crate.

## 7. Where to start reading

1. `README.md` (what it is) and `docs/ARCHITECTURE.md` (design constraints and the server
   job state machine).
2. `docs/OPERATOR_BRIEF.md` — mandatory before touching code (safety scan, update
   procedure, secret handling).
3. `crates/ferryman-channel/src/lib.rs` — the task protocol types and functions: read
   `Order`/`Claim`/`TaskResult`/`Review`/`Recommendation` (~line 618), `issue_order`/
   `claim_order`/`submit_result`/`submit_review` (~line 850), `read_task`/`Task::state`
   (~line 950), and `AgentIdentity` (~line 1041).
4. `crates/ferryman-channel/src/ledger.rs` — append-only signed ledger.
5. `crates/ferryman-ops/src/agent.rs` — the worker/reviewer loops (`work_once`,
   `do_work`, `review_once`).
6. `crates/ferryman-cli/src/main.rs` — how `ferry channel ...` maps onto the channel
   API (`fn channel`, ~line 1854).
7. `crates/ferryman-channel/src/portable_auth.rs` and `master.rs` — trust, grants, and
   the master model.
8. `crates/ferryman-core/src/lib.rs` then `crates/ferryman-server/src/lib.rs` — server
   mode (SQLite state machine and HTTP surface).

## 8. How to add a feature

1. **Safety first.** Read `docs/OPERATOR_BRIEF.md`; run the read-only project safety scan
   before touching anything. Treat every token/credential/key as read-only. The workspace
   forbids `unsafe` code.
2. **Pick the layer.** Channel-first features belong in `ferryman-channel` (and are exposed
   through `ferry channel ...` in `ferryman-cli` and the loops in `ferryman-ops`). Server
   features belong in `ferryman-core` (state) + `ferryman-server` (routes) + `ferryman-cli`
   (server subcommands) + possibly `ferryman-worker-sdk`.
3. **For a new channel artifact**, follow the existing pattern: define the struct and the
   exact `*_payload` bytes its signature covers; add a `sign_*` method on `AgentIdentity`
   and a `verify_*` function (or a module-local payload verifier like `master.rs`/
   `ledger.rs`); add the write function using `write_task_file`/`atomic_json`; if it
   participates in task state, teach `read_task`/`Task::state` about it; add a
   `ledger::append_ledger_entry` call for attribution; and add the CLI subcommand in
   `ferryman-cli/src/main.rs::channel`.
4. **For loop behavior**, add it in `ferryman-ops/src/agent.rs` (`work_once`/`do_work`/
   `review_once`) behind an `AgentConfig` flag, and keep `plan()` in sync so a dry-run
   shows what would happen.
5. **For server-mode state**, add a `SqliteStore` method using the
   transaction + `append_event` pattern, then a route in `ferryman-server/src/lib.rs::app`
   with the matching `checked_*` auth, then a CLI subcommand.
6. **Tests.** Channel modules carry inline `#[cfg(test)]` tests using `tempfile` and a
   hand-built `ProjectRoute`; mirror them. Run `cargo build --workspace` and
   `cargo test --workspace` (the tray is excluded on purpose and will not be built).
7. **Docs and version.** Update the relevant `docs/` file (and, for cross-machine or
   security-sensitive changes, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, or the ADR
   directory), bump `workspace.package.version`/`bridge-release.toml`, and note the change
   in `CHANGELOG.md`.
