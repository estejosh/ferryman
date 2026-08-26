# Threat model

**Applies to:** Ferryman as it actually ships — a signed channel carried between
machines by Syncthing, and a worker that runs an agent CLI locally. The HTTP server
that older parts of this document describe is a second, optional mode; it is covered
further down, under [Server mode](#server-mode-optional).

## The shape of the thing

There is no service in the middle. A project's channel is a folder — orders,
results, reviews, heartbeats, the roster, the ledger — replicated between your own
machines by Syncthing. Every file is named after its only writer, so two machines
cannot produce a conflicting edit of one file. Nothing listens on a port for this to
work, and nothing outside your machines holds any of it.

## Who can write into the channel

**Any Syncthing peer you have shared the folder with.** That is the boundary, and it
is worth being blunt about: Syncthing authenticates devices, so nobody who is not an
approved device can put a file in the channel at all — but every approved device can
write anything, including a file claiming to be from another agent.

That is why writing is not what is trusted. **Consumption is.**

## What is enforced when a record is read

- **Signatures are checked, and an unsigned or invalid order is not worked.** The
  worker verifies before it claims (`crates/ferryman-ops/src/agent.rs:2044`) and
  again before it acts on a claimed task (`agent.rs:2609`). `SignatureCheck` has
  five outcomes — `Valid`, `Unsigned`, `Invalid`, `UnknownSigner`, `KeyChanged` —
  and only `Valid` proceeds. Nothing anywhere softens the other four into "probably
  fine".
- **Keys are pinned on first sight (trust on first use).** An agent's key is pinned
  into the operator-local `attachment/agents-pinned/`, and a key later overwritten
  in the shared folder is reverted to the pin and reported as `KeyChanged`. The
  limit is the first sight itself: a machine that has never met an agent pins
  whatever the channel shows it first. **So signatures prove continuity, not
  identity, until a fingerprint is checked out of band.** Out-of-band key
  distribution is the real fix and is not built.
- **Authority is a renewable lease, not a durable capability.** Any authority a
  human or agent holds over another principal's agents, secrets or membership is
  short-lived, signed by its owner, expires on its own, and is renewed by
  publication into the channel — see
  [ADR 0013](adr/0013-agent-access-grants-are-renewable-leases.md). Revocation means
  "stop renewing", so a machine that has not synced still expires out of authority
  at a known, deliberately small horizon.
- **Secrets are sealed to a recipient and never appear as plaintext in the
  channel.** X25519 + XChaCha20-Poly1305, keyed through HKDF-SHA256 salted with the
  ephemeral and recipient public keys, with the encryption identity a separate
  keypair from the signing key — see
  [ADR 0010](adr/0010-secrets-through-the-channel.md). Secret-use grants fail closed
  at every use. Revealing a secret once always requires rotating the upstream
  credential; no Ferryman control can undo that.
- **No cross-machine clock comparison may release a claim.** Only a machine may
  judge its own runs abandoned, and only about itself — see
  [ADR 0011](adr/0011-recovering-a-dead-worker.md).

## What is not defended

- **A worker runs the agent CLI with the full privileges of the account that
  started it.** This is the central risk in the product and it is not mitigated by
  default. `sandbox` in `agent.toml` (or `ferry enable --sandbox IMAGE`) runs each
  task in a fresh podman or docker container with a network-egress policy instead,
  and that is the mode to use for anything you would not run yourself. The default
  is `Bare` because the default has to work on a machine with no container runtime.
- **The agent CLI is a third party.** Ferryman scrubs secret-named variables out of
  the child environment and passes arguments as vectors rather than through a shell,
  but what the engine does with a prompt is between you and its vendor.
- **Anything an approved Syncthing device does with the folder outside Ferryman.**
  Deleting files, filling the disk, or replicating the folder onward are device-level
  concerns, and the answer is which devices you approve.
- **A stolen machine.** The signing key lives on disk under `.ferryman/keys` at
  0600. Full-disk encryption is yours to have.

## Server mode (optional)

Everything below concerns `ferryman-server`, the HTTP mode described in
[GETTING_STARTED](GETTING_STARTED.md) as "an older integration path". If you are
using the channel — which is the default and what the README documents — none of it
applies to you.

## Assets

Project inputs/results, artifact metadata and contents, project bearer tokens, secret references, policy decisions, and audit history.

## Trust boundaries and controls

- **Client to API:** project bearer token is required; tokens are compared by SHA-256 hash. Run only behind TLS in production.
- **API to worker:** registration requires an operator project token once; it returns an 8-hour, worker-specific token exactly once. That token is stored only as a hash and can access worker protocol routes for its own worker ID—not operator, memory-write, recovery, consent, or outbound-submission routes. Job completion also requires its opaque lease ID.
- **Communications consumers:** a project operator token can configure routes,
  send work, inspect status, and mint an eight-hour actor token. Claim and
  acknowledgement reject project tokens and require the token for the exact
  registered recipient. Actor tokens are stored only as hashes.
- **Portable messages:** inline JSON is limited to 256 KiB and recursively
  rejects common credential-bearing keys. The outer token, runtime state,
  claims, locks, and quarantine never enter the synced folder or the portable Git repository.
- **Transport subprocesses:** Git and GitHub checks have hard timeouts; the Syncthing API probe is loopback-only with a 5-second deadline.
  GitHub privacy and exact inner-origin checks fail closed; failed delivery
  stays in the durable local outbox.
- **Artifacts:** content is hashed, written under the bridge-owned artifact root, and metadata is associated with one project. Paths from requests are never used as filesystem paths.
- **Recovery providers:** raw artifacts are never mirrored. Local-first continuity packs are encrypted before any configured network, Drive, MEGA, or private-Git recovery target receives them. External adapters fail closed until a target policy, credential reference, consent manifest, and remote hash verification are available.
- **Sensitive data:** logs/events redact top-level keys containing `secret`; this is defense-in-depth, not a replacement for application-level data minimization.
- **Destructive/external work:** project submits it with `requires_approval`; v0.1 requires a separate approve transition before dispatch.
- **Agent access grants and invitations:** any authority a human or agent holds
  over another principal's agents, secrets, or membership is a **renewable
  lease**, not a durable capability - short-lived, signed by its owner,
  expiring on its own, renewed by publication into the channel (see
  [ADR 0013](adr/0013-agent-access-grants-are-renewable-leases.md)). This is
  the offline story: revocation means "stop renewing", so a machine that has
  not synced still expires out of authority at a known, deliberately small
  horizon. Secret-use grants additionally fail closed at every use and never
  place plaintext in any channel artifact; revealing a secret once always
  requires rotating the upstream credential, which no Ferryman control can
  undo.

## Non-goals and residual risks

Workers and communications consumers remain trusted execution environments:
Ferryman does not sandbox their local execution or prove external effects are
idempotent. A claim prevents duplicate Ferryman execution, but integrations
must use their own idempotency protection for irreversible external effects. Do
not place production secrets in job or message input or run untrusted workers.
SQLite at-rest encryption and a real identity provider remain deployment
choices. Deploy with TLS, restrictive filesystem permissions, token rotation,
backups, and a recovery drill before handling sensitive project data.
