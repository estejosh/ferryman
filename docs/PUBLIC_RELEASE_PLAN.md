# Public release plan

## Goal

Publish this repository as a transparent, self-hostable **reference implementation and blueprint** for Ferryman—not as a hosted service, complete agent framework, or production-security guarantee. The first public tag should be `v0.1.0-alpha` or `v0.1.0-preview` until the acceptance criteria below are met.

## 1. Freeze and document the public v0.1 contract

**Why:** A public repository must make it obvious what works now, not just where it is heading.

1. Inventory every HTTP route and CLI command from the source.
2. Complete `openapi/openapi.yaml` for every supported v0.1 endpoint, including schemas, authentication, error responses, idempotency, pagination, SSE, agents, recovery memory, artifacts, and worker actions.
3. Either implement or remove/mark experimental any advertised behavior that does not work end-to-end. In particular, make `tail logs` consume SSE instead of only printing its URL, and define artifact download/listing behavior.
4. Add an API compatibility policy: `/v1` is additive-only; breaking changes require `/v2` or a major version.
5. Add a concise `docs/OPERATING_MODEL.md` explaining that the Bridge is a control plane and recovery source—not an agent or autonomous orchestrator.

**Done when:** a fresh user can follow README examples and every command/route is either verified or explicitly marked unavailable.

## 2. Security and privacy baseline

**Why:** The project handles job inputs, artifacts, private local repositories, and external credentials.

1. Replace the generic security contact with a real private reporting address or GitHub Security Advisories configuration before public release.
2. Add configuration validation at startup: production mode requires TLS termination guidance, admin token, memory-write token, non-demo project setup, restrictive filesystem permissions, and an explicit artifact root.
3. **Deferred by product decision:** separate worker credentials from project tokens with short-lived, signed lease/job tokens. Workers must not receive operator, memory-write, or repository-management credentials. Until this is implemented, deployments must treat workers as fully trusted project principals.
4. Add audit identities for memory writes, approvals, and worker transitions; preserve append-only recovery history.
5. Define data retention/deletion behavior for SQLite, artifacts, memory mirrors, and Drive mirrors. Implement it or clearly exclude it from v0.1.
6. Move Drive mirroring behind a tested OAuth flow using least-privilege scopes, resumable upload, retry, and a documented failure/reconciliation path. Keep it disabled by default.
7. Run dependency audit, secret scan, and license scan in CI. Add SBOM generation for release artifacts.

**Done when:** no documented production path relies on a shared project token, secret values cannot enter logs by normal API use, and the security policy gives users a real reporting path.

## 3. Test the behavior users will rely on

**Why:** Current coverage proves key state transitions, but not enough of the public surface.

1. Add black-box integration tests that launch the compiled server on an ephemeral port and use the CLI/worker SDK over HTTP.
2. Cover: server restart recovery, expired lease reaping, idempotency collision, cancellation race, pagination/cursors, SSE replay, authorization isolation between two projects, memory-write-token denial, and artifact content hashing.
3. Add filesystem tests for private workspace creation, remote refusal, naming stability across device roots, and network-artifact fallback.
4. Add mocked HTTP tests for Google Drive create/upload failures and event emission; do not require real account credentials in CI.
5. Add OpenAPI validation and generated-client smoke tests against the running server.
6. Run the test matrix on Linux, macOS, and Windows, plus MSRV and latest stable Rust.

**Done when:** CI exercises the binary over real HTTP on all supported platforms, and public contract/authorization regressions fail CI.

## 4. Make self-hosting reproducible

**Why:** A public user must be able to run the advertised local path without understanding the codebase.

1. Add a minimal `compose.yaml` smoke test and a production-oriented compose profile with named volumes, a reverse-proxy/TLS example, and no demo token.
2. Add `docs/DEPLOYMENT.md`, `docs/BACKUP_AND_RECOVERY.md`, and `docs/UPGRADING.md`.
3. Provide a one-command quick-start script for PowerShell and POSIX shells that initializes a demo project, starts a mock worker, submits a job, and displays its artifact/memory path.
4. Publish example configuration for local-only, network-HDD, and optional Drive-mirror deployments. Do not put credential values in examples.
5. Add database migration/version checks and documented backup/restore commands before schema changes are released.

**Done when:** a clean machine can complete the quick start in under 10 minutes, and backup/restore is tested.

## 5. Public GitHub and release hygiene

**Why:** This repository teaches users how to build and run a bridge, so its own maintenance signals matter.

1. Replace the placeholder `repository` URL in `Cargo.toml` with the final public URL.
2. Add `CHANGELOG.md`, release notes template, versioning policy, and a `0.1.0-preview` milestone.
3. Add GitHub labels, issue forms for bugs/security-sensitive reports/feature proposals, Discussions guidance, and maintainers/ownership information.
4. Configure branch protection: required formatting, Clippy, tests, audit, OpenAPI validation, and code review.
5. Produce signed release binaries/checksums and a container image only after the security/test gates pass.
6. Add a repository banner: “Reference implementation; local single-node preview” until the production milestones are complete.

**Done when:** a visitor can understand scope in under a minute, reproduce the demo, report a vulnerability safely, and verify a release artifact.

## Recommended sequence

1. Complete sections 1 and 5 enough to publish a clearly labeled public `preview` repository.
2. Complete sections 2 and 3 before encouraging real private project data.
3. Complete section 4, then cut `v0.1.0` as a self-hosted local-node release.
4. Treat PostgreSQL/HA, workflow DAGs, hosted adapters, dashboards, and MEGA as later milestones—not public-release blockers for the local-node reference.
