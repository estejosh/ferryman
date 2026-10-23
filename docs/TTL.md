# Expiring hand-ins and the outbox (opt-in)

By default nothing in a channel is ever removed. A project's master can switch on expiry
for two folders only, for small short-lived files such as a phone's deposits and the
receipts written back (ADR 0027, section d).

```
ferry channel ttl set <project> --days 14 --paths handins/,outbox/   # master only
ferry channel ttl show <project>
ferry channel ttl clear <project>                                    # master only
ferry channel expire --dry-run                                        # what would go, here
```

## What can expire

- Only files under `handins/` and `outbox/` (a rule path may also be a folder below one,
  such as `handins/phone-1`). `set` refuses any other path, `..`, `.`, empty parts,
  absolute paths, backslashes and drive letters. A signed `ttl.json` that holds one is
  ignored whole.
- `handins/` is the project's hand-ins folder (`projects/<id>/handins` in layout 2);
  `outbox/` is `outbox/` in the channel. Tasks, messages, orders, results, grants and the
  roster are not reachable by any rule.
- Symlinks are never followed, at any level, and never removed. A link inside `handins/`
  cannot lead the pass out of it, and a final check requires the real path of every file to
  be inside the folder the rule named.
- At least 14 days. `set` refuses less, and a signed file asking for less is ignored.

## The rule file

`ttl.json` sits in the channel (`seq`, `days`, `paths`, `at`, signed). It is honoured only
if it names this project, is signed by the project's master, has a `seq` no lower than the
highest this machine has accepted, and every path passes the checks above. Otherwise
nothing expires. A project with no `ttl.json` never expires anything. `clear` writes a
signed rule that says "off", because a deleted file would not travel.

## How a file expires

No deletion is ever sent: the lane carries none and this adds none. Each machine, in its
worker (every ten minutes) or by `ferry channel expire`, works alone by its own clock:

1. A file is due when its modification time AND the time this machine first saw it are both
   at least `days` old. The lane keeps modification times, which says how old a file is, but
   a phone with a wrong clock can claim any age, so a file that arrives "old" waits `days`
   from arrival. A modification time in the future never expires anything. First-seen times
   are kept in `ttl-state.json`.
2. A due file is moved into `<attachment>/ttl/expired/<UTC stamp>/<path>`, a folder that is
   machine-local and outside every folder the lane or Syncthing carries. Put a file back
   from there to recover it.
3. A quarantine batch older than seven days is deleted for good.
4. A slow peer that has not expired a file yet may send it back. The state remembers what was
   expired (path and modification time), so the returned copy goes again on the next pass
   instead of staying another `days`.

The receiver must consume a deposit before it expires; its own record of what it handled is
the audit trail, and expiry removes only the transport copy.

## Syncthing: refused

Syncthing would turn a local removal into a delete on every peer at once, by one machine's
clock, which breaks the rule that each machine decides alone. The safe choice is to refuse:
a folder with a `.stfolder` marker (the channel, the hand-ins folder or the outbox) is
treated as carried by Syncthing, `set` will not write a rule, and the pass removes nothing
even if a rule exists. `ferry doctor` shows the `ttl` line as a warning when that is so. The
quarantine is outside those folders, so no `.stignore` entry is needed. This means expiry
turns on once Syncthing is off for the project (ADR 0027's cutover criteria).

## `ferry doctor`

One `ttl` line per project: no expiry; switched off by the master; a rule is there and
ignored (and why); or the paths and days, the rule number and how many quarantine batches
wait.
