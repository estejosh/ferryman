# Adversarial review: what could make Ferryman suck or become dangerous

**Review date:** 2026-07-24  
**Reviewed revision:** `b92c10df9f99aea77463be484781205c043db8fb`  
**Scope:** Ferryman only: server, worker example, live communications, attachment
scripts, service setup, safety scanner, recovery behavior, and current claims.

## Executive verdict

Ferryman is a useful local-first preview, but it is not yet a trustworthy
security boundary or a safe multi-machine execution authority.

The most dangerous failure is not a conventional remote exploit. It is a trust
collapse between Ferryman's control plane and its portable files:

1. portable messages and acknowledgements are not signed;
2. any Git or MEGA peer that can write the portable repository can forge work;
3. a forged inbound acknowledgement can retire an outbox item without passing
   the stronger acknowledgement-to-message checks used by the API;
4. claims are local to one machine, so two machines can execute the same work;
5. the reference worker then runs a coding agent with the full privileges of
   its OS user.

That chain can turn a compromised sync peer, private-repository collaborator,
or overpowered local agent into forged work, duplicated irreversible effects,
false completion, or machine-wide credential theft.

**Release recommendation:** keep the project labeled as an internal,
single-node preview. Do not describe it as production-safe, exactly-once,
provider-neutral, or a sandbox. Do not use portable messages for irreversible
actions until findings F-01 through F-05 are fixed.

## Priority summary

| ID | Severity | Finding | Consequence |
|---|---|---|---|
| F-01 | Critical | Portable messages and acknowledgements are unsigned | A transport writer can forge work or completion |
| F-02 | Critical | Inbound acknowledgement retirement bypasses message matching | A forged UUID can silently delete queued work |
| F-03 | Critical | The reference worker is unsandboxed; approval is not an independent authority | Self-approved prompts can act as the OS user |
| F-04 | Critical | Git subprocesses inherit machine-wide hub secrets | A project-local Git hook can escalate to hub admin |
| F-05 | High | Claims are machine-local, not distributed | Two machines can perform the same irreversible action |
| F-06 | High | One global lock covers blocking transport operations | One slow project can freeze every project's communications |
| F-07 | High | The durable hub defaults to an ephemeral recovery key | Restart can make continuity packs unrecoverable |
| F-08 | High | Safe unregister ignores unread inbound work | A clean sender outbox can still abandon receiver work |
| F-09 | High | “Crash-safe” writes are not power-loss durable | A power loss can lose supposedly durable state |
| F-10 | High | Storage and scans are unbounded | Normal growth or hostile files can exhaust disk, memory, and latency |
| F-11 | Medium | Attachment is a non-transactional multi-system migration | Failures leave partial Git, MEGA, hub, and local state |
| F-12 | Medium | Provider neutrality and safety-scan confidence are overstated | Non-default users fail; a PASS can be misread as content-safe |

## Detailed findings

### F-01 — Unsigned portable work makes transport access execution authority

**Severity: Critical**

The portable `Message` envelope contains routing fields and payload, but no
signature, MAC, signer identity, or key version. Validation checks syntax,
sizes, and suspicious JSON key names; it does not authenticate the sender or
verify that the sender is registered. The acknowledgement format has the same
problem.

Evidence:

- [`Message` has no authentication field](../../crates/ferryman-server/src/communications.rs#L123)
- [`Message::validate` performs structural checks only](../../crates/ferryman-server/src/communications.rs#L188)
- [`Acknowledgement` is also unsigned](../../crates/ferryman-server/src/communications.rs#L240)
- [`list_messages` accepts every structurally valid project message](../../crates/ferryman-server/src/communications.rs#L1695)
- [`claim_message` checks project and recipient, not message origin](../../crates/ferryman-server/src/communications.rs#L1649)

**Failure scenario:** a compromised Git collaborator, MEGA sync peer, or local
process writes a valid JSON message addressed to a privileged actor. The actor
authenticates to Ferryman correctly, but Ferryman has no way to distinguish the
forged message from one created through the project API.

**Required fix:**

1. Give each hub/machine a signing identity.
2. Sign the canonical message and acknowledgement envelope.
3. Bind signer identities to project roles and capabilities.
4. Include protocol/key versions and replay protection.
5. Quarantine unsigned or unauthorized portable files.
6. Encrypt portable payloads when transport readers are not all trusted.

Until then, repository or MEGA write access must be documented as equivalent to
permission to author work.

### F-02 — Inbound acknowledgements can retire outbox work without matching it

**Severity: Critical**

The explicit acknowledgement path is reasonably strict: it loads the stored
message and compares the acknowledgement's idempotency key and recipient.
However, inbound synchronization calls a different helper that validates only
the acknowledgement's shape and project, derives an outbox filename from the
untrusted message UUID, and deletes that file.

Evidence:

- [The strict acknowledgement-to-message comparison](../../crates/ferryman-server/src/communications.rs#L1768)
- [Inbound synchronization calls `retire_acknowledged_outbox`](../../crates/ferryman-server/src/communications.rs#L1209)
- [The retirement helper deletes by UUID without loading and matching the message](../../crates/ferryman-server/src/communications.rs#L1838)

**Failure scenario:** a transport writer learns or guesses a queued message UUID
and places an acknowledgement JSON file with that UUID and the correct project
ID. On the next synchronization, Ferryman deletes the durable outbox item even
if the intended recipient never processed it.

**Required fix:** eliminate the weaker retirement path. Every inbound
acknowledgement must go through one canonical verification function that:

- verifies its signature;
- loads the exact stored/outbox message;
- compares project, message ID, recipient, idempotency key, and signer role;
- records the validated acknowledgement first;
- removes the outbox item only after durable recording succeeds.

Add a regression test proving that a forged recipient or idempotency key cannot
retire an outbox item during Git or shared-folder synchronization.

### F-03 — An approved job is not a contained job

**Severity: Critical**

The reference worker explicitly starts an external coding-agent CLI with full
OS-user privileges and no Ferryman sandbox. Its default example is Claude with
automatic permission mode. Ferryman's policy envelope is simulated and stored,
but it does not enforce filesystem, shell, or network restrictions on the child
agent.

Worker tokens cannot approve jobs, which is good. The broader project token can
both submit and approve a job. Consent approval also uses the project token and
accepts the approver identity from a caller-supplied header. An automation that
holds the project token can therefore submit and self-approve.

Evidence:

- [Worker isolation warning and default agent arguments](../../crates/ferryman-worker-sdk/examples/agent_worker.rs#L3)
- [The agent process is spawned directly](../../crates/ferryman-worker-sdk/examples/agent_worker.rs#L217)
- [Policy simulation reports decisions but does not constrain a process](../../crates/ferryman-server/src/lib.rs#L1537)
- [Job approval uses the same project bearer check](../../crates/ferryman-server/src/lib.rs#L1668)
- [Consent approval trusts a caller-provided approver string](../../crates/ferryman-server/src/lib.rs#L1243)

**Required fix:**

- Run workers under a dedicated, least-privilege account or isolated container.
- Give every run a disposable worktree and explicit filesystem/network policy.
- Require a separate approval credential and authenticated approver identity.
- Prevent the submitter identity from approving its own dangerous action.
- Make enforced policy distinct from advisory metadata in the API and UI.

Ferryman must continue saying plainly: it orchestrates agents; it does not
contain them.

### F-04 — Project-local Git execution can inherit machine-wide hub secrets

**Severity: Critical**

The recommended systemd service loads the hub admin token into the server's
environment. Ferryman then launches `git`, `gh`, and MEGA commands without
clearing the inherited environment. Git operations run inside the project's
inner repository and include pull/rebase/commit/push.

A process that can modify project-local Git configuration or hooks may execute
code under the hub account during a later Git operation and read the inherited
`FERRYMAN_ADMIN_TOKEN`. That turns control of one attachment into machine-wide
hub authority. The installed service also has no systemd sandbox directives.

Evidence:

- [The service loads `hub.env`](../../scripts/hub-up.sh#L31)
- [Git inherits the server environment](../../crates/ferryman-server/src/communications.rs#L552)
- [Git operations run in the project repository](../../crates/ferryman-server/src/communications.rs#L677)

**Required fix:**

- Clear child environments and allowlist only required variables.
- Set a trusted empty `core.hooksPath` for all automated Git invocations.
- Use absolute, administrator-controlled executable paths.
- Run the hub as a dedicated account that cannot read unrelated projects.
- Harden the service with `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`,
  `PrivateTmp`, a restrictive `UMask`, and appropriate syscall/address-family
  restrictions.
- Do not keep a machine-wide admin secret in the environment of a process that
  launches project-scoped tools.

### F-05 — Idempotency claims do not cross machines

**Severity: High**

Ferryman creates a claim directory under the outer machine-local
`.ferryman/runtime/processed` tree. Portable messages are synchronized, but
claims are intentionally not. Two machines can therefore each atomically win
their own local claim for the same idempotency key and both perform the action.

Evidence:

- [Claims are stored in the outer local runtime](../../crates/ferryman-server/src/communications.rs#L1649)
- [The completion contract excludes distributed consensus](../V0_1_COMPLETION.md#L63)

This is not exactly-once execution. It is at-least-once transport plus a local
duplicate guard. Project-level idempotency helps only if every external action
actually supplies and enforces the same key.

**Required fix:** add a single-active-consumer fence or a signed distributed
lease/claim protocol with expiry and takeover rules. Until that exists, block
multiple active consumers by default and expose an unmistakable
`multi_machine_execution_unsafe` readiness state.

### F-06 — One slow transport can block every project

**Severity: High**

All delivery engines live behind one Tokio mutex. Handlers take that global
lock and then perform synchronous filesystem and subprocess work. Git and MEGA
commands can block for 45 and 15 seconds. The background reconciler holds the
same lock while walking every project sequentially.

Evidence:

- [One mutex contains all project engines](../../crates/ferryman-server/src/lib.rs#L35)
- [Send holds it through delivery](../../crates/ferryman-server/src/lib.rs#L757)
- [Status holds it through external probes](../../crates/ferryman-server/src/lib.rs#L998)
- [The reconciler holds it across every mapping](../../crates/ferryman-server/src/lib.rs#L1022)
- [Blocking subprocess timeouts](../../crates/ferryman-server/src/communications.rs#L23)

**Failure scenario:** one repository has a hung credential helper or slow
network. Its request holds the shared lock. Communications requests for every
other project queue behind it, and synchronous work also occupies a Tokio
runtime thread.

**Required fix:** use per-project locks, move blocking operations to
`spawn_blocking` or a bounded worker pool, batch reconciliation, bound
concurrency, make operations cancellable, and supervise the reconciler so a
panic cannot silently stop retries.

### F-07 — The persistent hub creates disposable recovery

**Severity: High**

`hub-up.sh` installs an always-restarting service but supplies only the admin
token. It does not enable production mode or configure a stable recovery key.
In non-production mode the server generates a new ephemeral recovery key and
warns that packs created during that run cannot be recovered after restart.

Evidence:

- [The persistent service command](../../scripts/hub-up.sh#L23)
- [Development creates an ephemeral recovery key](../../crates/ferryman-server/src/main.rs#L171)

**Required fix:** the durable hub setup must provision a stable key reference,
or disable continuity-pack creation. Health/readiness must report whether
existing packs remain decryptable after restart. Existing env-file permissions
must be verified and corrected, not only applied when the file is first made.

### F-08 — “Safe unregister” can abandon inbound work

**Severity: High**

Unregister refuses only when the local message outbox or acknowledgement outbox
is non-empty. It does not consider unread inbound messages, unacknowledged
claims, quarantine, Git-live state, or unresolved portable acknowledgements.
It then deletes the mapping and actor tokens.

Evidence:

- [The unregister guard checks only two counts](../../crates/ferryman-server/src/lib.rs#L708)
- [Mapping deletion also removes actor tokens](../../crates/ferryman-core/src/lib.rs#L437)

**Required fix:** refuse unregister while any unresolved inbound, claim,
quarantine, failover, or acknowledgement state exists. Add an explicit
force-unregister operation that first exports a manifest and explains exactly
what will be stranded.

### F-09 — Atomic rename is not full crash durability

**Severity: High**

`atomic_json` writes a temporary file and renames it, which prevents readers
from seeing a partial process write. It does not call `sync_all` on the file or
fsync the parent directory. Sudden power loss can therefore lose a supposedly
durable outbox, acknowledgement, claim record, receipt, or transport-state
update.

Evidence:

- [The complete atomic-write implementation](../../crates/ferryman-server/src/communications.rs#L352)

**Required fix:** write, flush, fsync the temporary file, atomically replace the
destination, then fsync the parent directory. Document filesystem assumptions
and add process-kill and power-loss fault-injection tests. Until then use
“atomic against process interruption,” not “crash-safe.”

### F-10 — Unbounded files and linear scans will become a denial of service

**Severity: High**

Message listing reads, sorts, parses, and returns every message. Each idempotent
send scans every message plus the entire outbox. Reconciliation walks complete
outboxes. Delivery receipts and quarantine files accumulate. The unauthenticated
metrics route scans every registered attachment.

Evidence:

- [Unpaginated full inbox scan](../../crates/ferryman-server/src/communications.rs#L1695)
- [Linear idempotency lookup](../../crates/ferryman-server/src/communications.rs#L1726)
- [Full outbox reconciliation](../../crates/ferryman-server/src/communications.rs#L1393)
- [Public filesystem-scanning metrics](../../crates/ferryman-server/src/lib.rs#L441)
- [Retention and deletion remain a release-plan item](../PUBLIC_RELEASE_PLAN.md#L19)

**Required fix:** use an indexed manifest or SQLite index, paginate all list
routes, cap queue and quarantine sizes, reconcile bounded batches, authenticate
and cache metrics, and define retention/compaction behavior.

### F-11 — Attachment can leave a half-migrated project

**Severity: Medium**

Attachment is an ordered series of local writes, a Git commit/pull/push, root
ignore modification, MEGA registration, and hub registration. There is no
transaction journal or automatic rollback. A failure late in the sequence can
leave a pushed standard but no MEGA sync, a MEGA sync but no hub mapping, or a
modified root with an incomplete inner checkout.

Evidence:

- [Portable files are committed and pushed before later registrations](../../scripts/attach-project.ps1#L305)
- [Root ignore, MEGA, and hub operations happen afterward](../../scripts/attach-project.ps1#L418)

**Required fix:** complete all possible preflight checks before mutation, write
a resumable transaction journal, define phase markers, defer irreversible
operations until ready, and implement tested rollback/resume instructions.

### F-12 — Non-default installations fail, and a safety PASS can mislead

**Severity: Medium**

The README calls Ferryman provider-neutral, but live route validation hardcodes
the GitHub owner `estejosh` and `/beastly-bridges/<project>`. Windows conversion
assumes drive-letter paths map to `/mnt/<drive>`, and attachment defaults to an
Ubuntu WSL distribution.

The safety scanner correctly avoids reading secrets, but its portable-content
check is filename-based. A secret value inside `payload.json`, an encoded blob,
or an innocently named artifact passes. The runtime payload filter likewise
checks JSON key names and never examines string values.

Evidence:

- [Provider-neutral claim](../../README.md#L8)
- [Hardcoded GitHub owner and MEGA root](../../crates/ferryman-server/src/communications.rs#L80)
- [Drive-letter WSL conversion](../../crates/ferryman-server/src/communications.rs#L1864)
- [Filename-only safety scan](../../scripts/scan-project-safety.ps1#L120)
- [Key-name-only payload filter](../../crates/ferryman-server/src/communications.rs#L219)

**Required fix:** make provider, owner, remote root, WSL distribution, and path
adapter explicit configuration. Rename scanner output so PASS means
“structure passed without inspecting contents,” never “no secrets present.”
Add an optional user-authorized secret scanner that reports only filenames and
rule IDs, not secret values.

## What would make the product suck even without an attacker

- One degraded project freezes unrelated projects.
- Message and receipt history grows until common operations become visibly
  slower.
- A restart invalidates recovery packs created by the recommended hub setup.
- A migration failure leaves four systems disagreeing about attachment state.
- Custom GitHub owners, MEGA roots, WSL layouts, UNC paths, and other providers
  are rejected despite a provider-neutral claim.
- Operators cannot safely infer the running binary's commit from `/healthz`;
  it reports only `api_version: v1`.
- Several safety controls are advisory or local while their names sound global:
  policy, approval identity, idempotency claim, crash safety, and scan PASS.

## Required remediation order

### P0 — before irreversible multi-machine work

1. Sign and authorize portable messages and acknowledgements.
2. Remove the weak inbound acknowledgement retirement path.
3. Add distributed fencing or enforce one active consumer.
4. Scrub subprocess environments and harden the hub service.
5. Separate approval authority and run workers inside an enforced sandbox.

### P1 — before production claims

6. Replace the global blocking transport lock with isolated asynchronous work.
7. Provision stable recovery in the recommended service.
8. Implement power-loss durability, quotas, retention, and pagination.
9. Make unregister and attachment transactional/recoverable.

### P2 — before broad adoption

10. Generalize provider and platform configuration.
11. Add build/version identity to health/readiness.
12. Test forged envelopes, forged acknowledgements, multi-machine races,
    process kills, power loss, slow providers, storage growth, and partial
    migration against compiled binaries.

## Scope and fairness

This review did not inspect secret contents, modify external projects, exercise
real credentials, or attempt exploitation. It combined an independent agent
review with a separate source-level adversarial pass.

Ferryman already has useful protections: loopback binding and Host checking,
hashed stored tokens, scoped worker and actor tokens, private-remote checks,
path validation, dry-run attachment, outbox persistence, quarantining, and
honest preview language in the public release plan. Those protections reduce
risk, but they do not close the trust, execution, durability, or scaling gaps
above.

“100% complete” can remain true only for the explicitly bounded internal v0.1
contract. It must not be interpreted as production-safe, adversary-resistant,
distributed-execution-safe, or finished for public adoption.
