# Deployment

## Local preview

Run the server with default local files:

```powershell
cargo run -p ferryman-server
```

This starts a demo-only development mode. Do not expose it to a network.

## Production mode

Terminate TLS at a reverse proxy and bind the Bridge only on a trusted private network. Set these environment variables before starting with `--production`:

- `FERRYMAN_ADMIN_TOKEN`: protects project creation.
- `FERRYMAN_MEMORY_WRITE_TOKEN`: protects recovery-memory writes from workers.

Use a unique, randomly generated value for each. The server intentionally does not provide TLS itself; it must sit behind a correctly configured TLS terminator. Keep database, artifacts, project workspace, and bridge-memory paths on volumes accessible only to the bridge service account.

```powershell
$env:FERRYMAN_ADMIN_TOKEN = '<random-value>'
$env:FERRYMAN_MEMORY_WRITE_TOKEN = '<different-random-value>'
cargo run -p ferryman-server -- --production --no-demo-project
```

This remains a single-node deployment. Do not use it with untrusted workers or high-sensitivity secrets.
## Worker isolation

The Bridge gates orchestration - leases, approvals, memory, recovery - but it does
**not** sandbox the model itself. A leased worker runs its agent CLI (`claude`,
`codex`, ...) with the full privileges of the OS user that started the worker, in that
worker's working directory, regardless of any project policy. `codex` in particular
runs shell commands and edits files on the host by default. Treat every worker host as
capable of doing anything its OS account can do.

- Run each worker under a dedicated, least-privilege OS account - never the Bridge's
  service account and never an administrator.
- Give each worker its **own disposable working directory** (one per worker/project).
  Never point two workers at the same tree, and never launch a worker from a directory
  that holds secrets or unrelated repositories.
- Prefer the agent's own sandbox/approval flags (set through `AGENT_ARGS_JSON`) over
  trusting the Bridge to contain the model. `AGENT_ARGS_JSON` is forwarded verbatim;
  choose a permission mode that matches your trust level for the job prompts.


# Production preflight

Production mode is intentionally strict:

- bind to loopback, or use `--tls-terminated` behind a trusted TLS proxy;
- set distinct `FERRYMAN_ADMIN_TOKEN` and `FERRYMAN_MEMORY_WRITE_TOKEN` values;
- set `FERRYMAN_RECOVERY_KEY_REFERENCE=keychain:service:account` and store a 32-byte hex recovery key in that OS-keychain entry;
- use explicit database, artifact, project-workspace, memory, and recovery roots with access limited to the Bridge service identity;
- start with `--production --no-demo-project`, run a recovery drill, and keep workers on their short-lived registration tokens.

Do not use `FERRYMAN_RECOVERY_KEY_HEX` outside explicit local development.
