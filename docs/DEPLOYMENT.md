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
