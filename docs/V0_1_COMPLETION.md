# Ferryman v0.1 internal completion contract

“100%” means every required gate below is implemented and validated for the
Ferryman repository itself. It does not mean every future roadmap feature is
implemented, and it does not depend on migrating or testing an external
project.

## Required gates

1. **Durable core:** SQLite jobs, approvals, leases, artifacts, memory, recovery
   packs, and communications survive process restarts.
2. **Crash-safe communications:** stable message identity, atomic outbox first,
   persisted failover/backoff state, acknowledgement deadlines, bounded
   retries, corrupt-entry quarantine, duplicate-safe claims, inbound Git
   synchronization, and durable acknowledgement return.
3. **Transport safety:** exact Syncthing folder health, hard subprocess deadlines,
   exact private-Git owner/name/visibility, exact inner origin, serialized Git
   writers, fetch/rebase/push retry, disabled repository hooks, scrubbed child
   process secrets, and no mutation of a main project remote.
4. **Authorization and limits:** project-scoped operator routes, short-lived
   actor-scoped inbox and consume routes, recipient enforcement, field limits,
   256 KiB payload cap, portable secret-field rejection, authenticated v2
   portable messages and acknowledgements, signer-to-project/role grants,
   replay rejection, and fail-closed quarantine of unsigned input.
5. **Observability:** per-project communications status, aggregate queue and
   quarantine metrics, immutable delivery attempts, and actionable errors.
6. **Framework-neutral adoption:** documented and scripted Windows and
   WSL/Linux migration for unmanaged/no-agent, single-agent, and multi-agent
   projects, always including `project-inbox`, with a non-destructive,
   outbox-guarded unregister path, revision markers, explicit standard update,
   and read-only safety scan.
7. **Versioned contract:** CLI coverage, OpenAPI coverage, threat-model and
   operator documentation, migration/rollback instructions, and explicit
   v0.1 boundaries.
8. **Release evidence:** formatting, warnings-as-errors lint, all workspace
   tests, real local Git failover, Windows attachment fixture, and WSL/Linux
   attachment dry-run all pass without contacting or modifying an external
   project.

## Required validation

Run from the Ferryman repository root:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash -n scripts/attach-project.sh
bash -n scripts/scan-project-safety.sh

# Read-only dry-run against this checkout; skips all external registration.
bash scripts/attach-project.sh `
  --workspace /mnt/x/ferryman `
  --project ferryman `
  --shared-remote /beastly-bridges/ferryman `
  --git-remote https://github.com/estejosh/ferryman-bridge.git `
  --integration-mode unmanaged `
  --dry-run --skip-sync-registration --skip-hub-registration
```

The real Git integration test creates only temporary local repositories. The
Windows apply fixture uses a temporary bare repository and fake `gh`; the
WSL/Linux dry-run fixture is non-mutating. Neither exercises an external
project or GitHub repository.

## Deliberate non-gates

PostgreSQL, a dashboard, distributed consensus, worker sandboxing, hosted
identity, scheduled healthy-state Git checkpoints, and framework-specific
adapters remain roadmap work. They are not required for the bounded single-node
v0.1 contract. Portable authentication is a required gate even for that
single-node contract because synced and Git files cross the local trust boundary.
