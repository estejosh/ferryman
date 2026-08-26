# Upgrading

## The channel — what almost everyone runs

There is no database, no server and no `/healthz` to check. Upgrading is replacing
one binary:

1. Read the release notes for anything about the channel format.
2. Stop the worker on the machine you are upgrading (`ferry pause`, then let the
   task it holds finish, or `ferry agent retire` once it is idle).
3. Install the new `ferry` — re-run `scripts/install.sh` or `install.ps1`, which
   verify the checksum, or replace the binary yourself.
4. `ferry --version`, then `ferry doctor`.
5. `ferry resume`.

Upgrade one machine at a time and let it take a task before you move to the next.
The channel is files, so a fleet part-way through an upgrade is a fleet running two
versions against the same channel — which is normal and supported, and still the
moment to notice if a release disagrees with its predecessor about a record.

Nothing is migrated in place and nothing is rewritten, so downgrading is replacing
the binary again. Keep the copy you replaced until the new one has taken a task.

## Server mode

Only if you run `ferryman-server`, the older integration path.

1. Read the release notes and back up the database, artifacts, project workspaces, and memory.
2. Stop the server and workers.
3. Install the new binary/container image.
4. Start the server; it applies additive SQLite schema migrations at startup.
5. Verify `/healthz`, job listing, artifact listing, and project-memory reads before restarting workers.

Do not downgrade after a schema migration without restoring the backup.
