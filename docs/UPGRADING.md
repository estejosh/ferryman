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

Every workspace says where its channel lives, in `.ferryman/bridge.toml`:

```toml
communications = "/path/to/the/channel"
```

When that line is absent, the channel is `<workspace>/.ferryman/ferryman`. That path is
the only place a worker looks. Syncthing has to sync that exact folder.

A machine first set up with an older Ferryman can end up with Syncthing pointed at a
different copy. A common case: the channel used to be synced into the work repo, at
`<repo>/.ferryman/ferryman`, and the machine now runs one worker over a ferry root
with `ferry agent run --comms <root>/comms`, where each `comms/<project>-ferryman` is
its own workspace with its own `.ferryman`. Upgrading the binary moves nothing.
Syncthing keeps filling the old copy, and the worker reads one that never fills.

What it looks like:

- The issuing machine's `ferry channel status` says the order was not delivered
  ("has not seen it"), while Syncthing reports the folder 100% synced to that machine.
- The worker is healthy, says it is watching the channel, and claims nothing.
- The order's files are on the machine, just not where the worker looks.

Check on the affected machine, for each `-ferryman` Syncthing folder: find the
workspace the worker uses for it, read `communications` from its
`.ferryman/bridge.toml` (or take `<workspace>/.ferryman/ferryman`), and compare that
with the Syncthing folder path. They must be the same folder.

Do not point Syncthing at the workspace itself. The workspace holds `.ferryman`, with
the machine's `agent.toml`, its config and its worker locks, and Syncthing would carry
those to every other machine on the channel.

Fix each mismatched folder, one at a time:

1. Pause the folder in Syncthing and back up both copies.
2. Copy the Syncthing copy into the channel path, keeping `.stfolder` and `.stignore`
   and without deleting anything: `rsync -a <syncthing path>/ <channel path>/`.
3. Check that what the issuer sent is now in the channel path.
4. Only then change the Syncthing folder path to the channel path, and unpause.
5. Watch it settle, then restart the worker.

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
