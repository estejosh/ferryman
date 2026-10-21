# Upgrading

1. Read the release notes and back up the database, artifacts, project workspaces, and bridge memory.
2. Stop the server and workers.
3. Install the new binary/container image.
4. Start the server; it applies additive SQLite schema migrations at startup.
5. Verify `/healthz`, job listing, artifact listing, and project-memory reads before restarting workers.

Do not downgrade after a schema migration without restoring the backup.
