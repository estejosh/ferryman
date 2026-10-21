# Deployment

## Local preview

Run the server with default local files:

```powershell
cargo run -p orchestrator-server
```

This starts a demo-only development mode. Do not expose it to a network.

## Production mode

Terminate TLS at a reverse proxy and bind the Bridge only on a trusted private network. Set these environment variables before starting with `--production`:

- `ORCHESTRATOR_ADMIN_TOKEN`: protects project creation.
- `ORCHESTRATOR_MEMORY_WRITE_TOKEN`: protects recovery-memory writes from workers.

Use a unique, randomly generated value for each. The server intentionally does not provide TLS itself; it must sit behind a correctly configured TLS terminator. Keep database, artifacts, project workspace, and bridge-memory paths on volumes accessible only to the bridge service account.

```powershell
$env:ORCHESTRATOR_ADMIN_TOKEN = '<random-value>'
$env:ORCHESTRATOR_MEMORY_WRITE_TOKEN = '<different-random-value>'
cargo run -p orchestrator-server -- --production --no-demo-project
```

This remains a single-node deployment. Do not use it with untrusted workers or high-sensitivity secrets.
# Production preflight

Production mode is intentionally strict:

- bind to loopback, or use `--tls-terminated` behind a trusted TLS proxy;
- set distinct `ORCHESTRATOR_ADMIN_TOKEN` and `ORCHESTRATOR_MEMORY_WRITE_TOKEN` values;
- set `ORCHESTRATOR_RECOVERY_KEY_REFERENCE=keychain:service:account` and store a 32-byte hex recovery key in that OS-keychain entry;
- use explicit database, artifact, project-workspace, memory, and recovery roots with access limited to the Bridge service identity;
- start with `--production --no-demo-project`, run a recovery drill, and keep workers on their short-lived registration tokens.

Do not use `ORCHESTRATOR_RECOVERY_KEY_HEX` outside explicit local development.
