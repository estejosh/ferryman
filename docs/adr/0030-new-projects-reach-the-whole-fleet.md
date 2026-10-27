# ADR 0030: New projects reach the whole fleet

Status: proposed, for the master (josh). Builds on 0014, 0026 and the iroh lane
(docs/IROH_LANE.md). Related to docs/LAYOUT.md.

## Context

A project enabled on one machine of a fleet stayed on that machine. On the real fleet (beastly,
Windows; grouchly, Linux; the iroh lane; the fleet home channel) three things went wrong at once:

1. Nothing filed the project on another machine. The iroh lane exchanges only projects both
   sides already serve, and its first-contact exchange needs the peer's worker on the channel's
   roster on BOTH sides. So each new project meant a hand-made channel, a hand-made clone and a
   hand-made roster entry per machine.
2. The connector identity an app uses (`claude-ai-josh`, one key per machine) is "seated" in a
   project only where `<attachment>/keys/<name>.key` exists. Nothing put it there for a project
   that arrived later, so the connector could not use any project made after it was set up.
3. After the channel was filed and cloned by hand, the running all-projects worker still did not
   serve it until it was restarted. `judge` skips a channel with no checkout ("no checkout of X
   on this machine"); nothing in the worker ran `repos sync`; the worker said nothing the first
   time it met such a project after it had started; and the fleet-home route was added to the
   lane only when the lane started.

## Decision

The owner's rules: a project made on one machine reaches every other machine of the fleet with
nobody typing anything, unless that machine excludes it (`[swarm] exclude`), it is archived, or
its master set `swarm = off`. Only inside one fleet: between machines the fleet master admitted
(`ferry fleet admit`), and only for projects the fleet master masters. Connector identities a
machine lists are seated in every project it serves. A running worker serves a new project within
a pass or two, with no restart.

### 1. Advertise (every worker pass)

The fleet-home records grow optional fields. Each is inside the signed body, so it is covered by
the signature, and each is skipped when absent, so a record written before this change is the same
bytes and still verifies.

- Directory entry (`DirBody`): `git_remote`, the origin of the managed clone with credentials
  taken off, and `master`, the project's master as read from its verified `master.json`. A remote
  that carries a credential is never published (`propagate::publishable_remote` refuses it, and
  `fleethome::remote_is_clean` refuses it again at publish and at read). A local path or a
  `file://` URL is not published either: it means nothing on another machine. A project its
  master took out of the swarm advertises nothing.
- Machine record (`MachineBody`): `worker`, the machine's all-projects worker as a name and a
  PUBLIC key, and `excludes`, the projects this machine keeps out (`[swarm] exclude`). A machine
  record is signed by the admitted machine, so the chain is master, admitted machine, worker key.
  The worker's public identity is written once to `fleet/local/worker.json` when the worker
  starts, so any publisher (`ferry enable` as well as the worker) keeps the field filled.

### 2. Make room (`propagate::make_room`)

For each project this machine serves (live, not swarm-off, master equals the fleet master) and
each OTHER admitted machine whose record names a worker and does not exclude the project, the
channel's roster gets that worker, with its public key, through `register_peer_key`. First key
wins: a different key already listed under the name is logged and left alone. The role is
"worker", which needs no grant; access levels are unchanged. Only the public half is known, so
the machine-wide licensing roster that `register_agent_key` also writes is not touched.

### 3. Receive (`propagate::receive`)

For each project advertised by an admitted machine whose master equals the fleet master, that is
live, not filed here, not excluded here, and has a safe id: create the channel home
(`Root::comms_home`, layout-aware), put this machine's worker on the roster (its own key, from
`load_existing`, never made), put the advertiser's worker there too (the lane's bootstrap needs
both entries on both sides), `Root::adopt` it channel-only, and keep the advertised remote as a
machine-local `repos sync` candidate in `fleet/local/arrived.json` (never in the user's
`ferry.toml`). One line is logged: "<id> arrived from <machine>: filed, cloning".

Then `propagate::sync_arrivals` runs `repos::sync` for filed projects with a channel and no
checkout. It does at most two clones per pass (`CLONES_PER_PASS`), every git command runs under a
clock (`repos::Options::git_timeout`, 120 s in the worker), and a project that failed is tried
again after five minutes, so one unreachable remote cannot use up every pass or stall the loop.
A project that a person has attached a checkout to is never taken over.

### 4. Seat connectors (`[seat] agents`)

The root's `ferry.toml` takes `[seat] agents = ["claude-ai-josh", ...]`. For each name, in every
project this machine serves, the worker seats the key THIS machine already holds (in another
project's attachment or in the machine key store) with `seat_in`, and lists it on the roster with
the role it already has on a roster here, else "member". It runs when the worker starts serving a
project and right after `repos sync` attaches a fresh clone. Never a new key: a name with no key
here is left alone. Never into a checkout git would commit (`keeps_keys_out_of_git`). When the
machine holds two different keys under one name, or a roster or a checkout holds a different one,
it refuses and says so. `ferry root seat <name>` and `ferry fleet setup --seat <name>` add a name
and seat it everywhere at once. Seating gives a key file and a roster line, not authority: the
grant still comes from the master (`ferry team approve <name> --all`).

### 5. Live pickup

`run_fleet`, before `take_newly_approved`, runs receive and the bounded sync (off the async
executor, in `spawn_blocking`), and make-room. `take_newly_approved` says why a project is not
served the first time it appears, not only a change of reason afterwards, and the fleet-home route
is added to the running lane on the pass after the folder appears (`follow_fleet_home`), the way
projects already were.

The question whether a project that was filed, attached and roster-listed while the worker ran
was ignored had no further bug behind it: a test (`a_project_filed_attached_and_listed_while_the_worker_runs_is_served_at_whichever_step_completes_it`)
completes the three steps in each order between passes, and the next pass serves it every time.
What the owner saw is explained by the three causes in Context.

## Consequences

- A project made on any admitted machine is filed, cloned, rostered and served on the others
  within a few passes, and the lane finds the peer on the first round after that.
- Trust never widens. Every step acts only on records signed by the master or a machine the master
  admitted; a record from anyone else is ignored. A key is never copied between machines, never
  put in a channel, never made for a name the roster knows, and never replaces a different one.
- A fleet's machines can all clone a project, which only works where the advertised remote is
  reachable with that machine's own git credentials. A remote that needs a credential is not
  advertised at all; the owner sets `[remote] template` on such a machine, which is tried first.
- Old binaries ignore the new fields. A machine on an old binary neither advertises nor makes
  room, so projects reach it only through a newer machine.
- The new fields are added by every publisher, so a directory entry grows by two short strings.

## Not covered

- A project whose master is not the fleet's master. It does not propagate. Such a project is a
  different trust domain and needs its own invitation.
- The MCP all-projects server (on the unmerged `mcp-http` branch) may compute its project list at
  startup. This change makes the keys and channels be there; that server still has to look again
  when a project appears.
- Revoking or removing a project on other machines. Archiving stops new arrivals; it does not
  delete what arrived.
- Granting the connector authority in a project. `ferry team approve <name> --all` is still the
  master's.
- A machine that cannot reach the advertised remote and has no template. It stays channel-only,
  and says why each time the reason changes.
