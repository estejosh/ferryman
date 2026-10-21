# Threat model (v0.1)

## Assets

Project inputs/results, artifact metadata and contents, project bearer tokens, secret references, policy decisions, and audit history.

## Trust boundaries and controls

- **Client to API:** project bearer token is required; tokens are compared by SHA-256 hash. Run only behind TLS in production.
- **API to worker:** registration requires an operator project token once; it returns an 8-hour, worker-specific token exactly once. That token is stored only as a hash and can access worker protocol routes for its own worker ID—not operator, memory-write, recovery, consent, or outbound-submission routes. Job completion also requires its opaque lease ID.
- **Artifacts:** content is hashed, written under the bridge-owned artifact root, and metadata is associated with one project. Paths from requests are never used as filesystem paths.
- **Recovery providers:** raw artifacts are never mirrored. Local-first continuity packs are encrypted before any configured network, Drive, MEGA, or private-Git recovery target receives them. External adapters fail closed until a target policy, credential reference, consent manifest, and remote hash verification are available.
- **Sensitive data:** logs/events redact top-level keys containing `secret`; this is defense-in-depth, not a replacement for application-level data minimization.
- **Destructive/external work:** project submits it with `requires_approval`; v0.1 requires a separate approve transition before dispatch.

## Non-goals and residual risks

Workers remain trusted execution environments: the Bridge does not sandbox their local execution or prove external effects are idempotent. Do not place production secrets in job input or run untrusted workers. SQLite at-rest encryption and a real identity provider remain deployment choices. Deploy with TLS, restrictive filesystem permissions, token rotation, backups, and a recovery drill before handling sensitive project data.
