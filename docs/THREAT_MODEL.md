# Threat model (v0.1)

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
the Bridge does not sandbox their local execution or prove external effects are
idempotent. A claim prevents duplicate Ferryman execution, but integrations
must use their own idempotency protection for irreversible external effects. Do
not place production secrets in job or message input or run untrusted workers.
SQLite at-rest encryption and a real identity provider remain deployment
choices. Deploy with TLS, restrictive filesystem permissions, token rotation,
backups, and a recovery drill before handling sensitive project data.
