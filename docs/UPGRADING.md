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

## Known issue: a machine set up with an older Ferryman never sees new work

Older versions kept each channel inside its work repo, at
`<repo>/.ferryman/ferryman`, and Syncthing was pointed there. Newer versions run one
worker over a ferry root with `ferry agent run --comms <root>/comms`, which reads
`<root>/comms/<project>-ferryman`. Upgrading the binary moves neither: Syncthing keeps
syncing the old folder, and the worker reads the new one, which never fills.

What it looks like:

- The issuing machine's `ferry channel status` says the order was not delivered
  ("has not seen it"), while Syncthing reports the folder 100% synced to that machine.
- The worker is healthy, says it is watching the channel, and claims nothing.
- The order's files are on the machine, just not where the worker looks.
- `ferry channel join` in the comms folder fails with "no Ferryman channel found",
  because the folder the worker reads holds no channel.

Check on the affected machine: compare each Syncthing folder's path with
`<root>/comms/<folder id>`. Any `-ferryman` folder whose path is elsewhere is one the
worker cannot see.

Fix each mismatched folder, one at a time:

1. Pause the folder in Syncthing and back up both copies.
2. Copy the Syncthing copy into the comms path, keeping everything, including
   `.stfolder` and `.stignore`, and without deleting what is only in the comms path
   (`agent.toml`, keys): `rsync -a <old path>/ <root>/comms/<folder id>/`.
3. Only then change the Syncthing folder path to `<root>/comms/<folder id>` and unpause.
4. Watch it settle. It must not report deleting anything.
5. Restart the worker.

The order matters. Pointing Syncthing at a folder before the files are in it makes
the missing files read as deletions, and Syncthing sends those deletions to every
other machine on the channel. Leave the old folder in place until the worker has
taken a task from the new one.

Found on a two-machine fleet on 6 Oct 2026, where orders to the upgraded machine sat
undelivered for weeks. Upgrades should detect and move these folders themselves;
until they do, this is a manual step.

## Server mode

Only if you run `ferryman-server`, the older integration path.

1. Read the release notes and back up the database, artifacts, project workspaces, and memory.
2. Stop the server and workers.
3. Install the new binary/container image.
4. Start the server; it applies additive SQLite schema migrations at startup.
5. Verify `/healthz`, job listing, artifact listing, and project-memory reads before restarting workers.

Do not downgrade after a schema migration without restoring the backup.
