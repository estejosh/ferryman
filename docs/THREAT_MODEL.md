# Threat model (v0.1)

## Assets

Project inputs/results, artifact metadata and contents, project bearer tokens, secret references, policy decisions, and audit history.

## Trust boundaries and controls

- **Client to API:** project bearer token is required; tokens are compared by SHA-256 hash. Run only behind TLS in production.
- **API to worker:** a worker receives only a leased job and its policy envelope. Job completion requires its opaque lease ID.
- **Artifacts:** content is hashed, written under the bridge-owned artifact root, and metadata is associated with one project. Paths from requests are never used as filesystem paths.
- **Optional Google Drive mirror:** credentials come from environment variables, never the database or job inputs. The adapter writes only into a configured folder and never grants permissions. Local storage remains authoritative if Drive is unavailable.
- **Sensitive data:** logs/events redact top-level keys containing `secret`; this is defense-in-depth, not a replacement for application-level data minimization.
- **Destructive/external work:** project submits it with `requires_approval`; v0.1 requires a separate approve transition before dispatch.

## Non-goals and residual risks

Workers are trusted execution environments. **Deferred:** workers currently use a project bearer token; short-lived worker/job tokens are a later security milestone. This bridge does not confine a malicious worker, prevent a valid bearer token from being copied, encrypt SQLite data, or prove that an external side effect is idempotent. Do not place production secrets in job input or run untrusted workers. Deploy with TLS, restricted database/artifact filesystem permissions, rotation, backups, and a real identity provider when v0.1 is extended for production use.
