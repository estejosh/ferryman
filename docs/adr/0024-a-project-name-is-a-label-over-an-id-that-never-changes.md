# ADR 0024: A project's name is a label over an id that never changes

## Status

Accepted.

## Context

A project's id did three jobs at once:

- it was the Syncthing folder id (`<id>-ferryman`), which is what devices pair on;
- it was inside every signed record (grants, offers, `SWARM`, `ARCHIVED`, iroh transports),
  which is how a record copied from another project is refused;
- it was the folder names on every machine (`comms/<id>-ferryman`, `repos/<id>`).

So a project could not be renamed. Changing the id would invalidate every signature it ever
carried and make every device share the folder again; leaving it meant living with a name
that no longer fit (fructly, which is becoming part of Ferryman's communications).

## Decision

The id is permanent. A project keeps the id it was created with, everywhere a machine or a
signature looks.

The name is a signed label. The project's master signs a `NAME` record into the channel: the
id, the new name, every earlier name (kept as aliases) and a sequence number covered by the
signature that only goes up. Each machine remembers the highest it accepted, as for `SWARM`,
so putting an older signed file back, or deleting it, renames nothing back. A file anyone
but the master signed is ignored.

`ferry root rename <project> <name>` signs it and moves this machine's folders. Every other
machine moves its own folders when it next reads the channel: an all-projects worker does it
when it starts, the watchdog's `repair_layout` does it, and `ferry root follow` does it by
hand. Moving means `comms/<id>-ferryman` becomes `comms/<name>-ferryman` and `repos/<id>`
becomes `repos/<name>`, `bridge.toml` and the manifest are rewritten, task worktrees are
repaired, and the local Syncthing is pointed at the new path with the same folder id and the
same devices. Peers match on the folder id, so nothing re-pairs, nothing is re-approved and
no signature changes.

Only Ferryman's own folders move: a channel in `comms/` and a clone in `repos/`. A person's
checkout, or a channel in an older layout, stays where it is. Nothing is moved onto a folder
that holds something, a folder in use is tried again next time, and nothing is deleted. A
worker's home (the clone holding its `agent.toml`) is named in its service unit or scheduled
task, so it keeps its folder until `ferry fleet setup --service` runs again.

Every command that asks for a project accepts its id, its name or an old name. An id wins
over a name and a name over an old name; two projects can never be given one name.
Renaming to the id undoes a rename.

## Consequences

- Renaming is one signed file and no fleet work. A machine that was off catches up when it
  starts.
- Signed records, ledgers and the Syncthing folder id keep the id forever, which is what
  someone reading them later must be told: the id is the project, the name is what it is
  called now.
- A machine running an older version ignores `NAME`: it keeps the old folder names and
  still syncs, because nothing it pairs on changed.
- Not yet: the dashboard and Telegram still show ids, and `[git.remotes]` in a root's
  `ferry.toml` stays keyed by id.
