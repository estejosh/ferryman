# The iroh lane: channels over QUIC, through a relay of your choice

Syncthing carries a channel well between machines on one network. Away from home it is
only as good as its discovery and its public relays. The iroh lane carries the same
channel folders a second way: over [iroh](https://www.iroh.computer) (QUIC, peers
identified by ed25519 endpoint ids), through a relay (a small one of your own, iroh's
public ones, or none), and directly between two machines whenever they can see each other.

It runs **beside** Syncthing, not instead of it. Both write channel files the same way
(temporary file, then rename) and both keep modification times, so a file that arrived by
one lane is simply already there when the other looks.

## Turning it on, per machine

1. Add to the ferry root's `ferry.toml` (machine-local, never synced). The smallest working
   setup, and the right one for a new user, is:

   ```toml
   [iroh]
   enabled = true
   ```

   With no relay named, the lane uses iroh's public relays: no server to run, no
   certificate to pin, no token. To use a relay of your own instead, see
   [Relays](#relays-ours-irohs-public-ones-or-none) below. Our own fleet's relay is:

   ```toml
   [iroh]
   enabled = true
   relay_url = "https://162.35.10.46"
   # The relay's self-signed certificate: this exact certificate and no other.
   relay_cert_sha256 = "49:32:08:E4:6F:B8:E3:9B:FD:F2:8D:B8:0F:8C:33:F9:9F:2A:57:A0:A1:71:B3:52:4A:9D:11:67:AD:BD:C0:D1"
   ```

2. Only if the relay asks for an access token: put it, and nothing else, in
   `iroh-relay.token` in the machine state directory (`%LOCALAPPDATA%\Ferryman` on Windows,
   `~/.local/state/ferryman` on Linux, or `$FERRYMAN_STATE_DIR`). `relay_token_file =
   "<path>"` points elsewhere. **The token is optional**: with no file the lane connects
   without one, which is all the public relays ask for. It is read, never printed, and never
   belongs in a channel or in `ferry.toml`.

3. From the worker's home checkout (where its `agent.toml` is):

   ```
   ferry lane iroh init
   ```

   This makes the machine's iroh key once (`iroh.key`, beside the operator seed) and
   writes `transports/<agent>.json` into every channel the all-projects worker serves.

4. Restart the worker (`ferry agent run --all-projects`). Its startup line says
   `iroh lane on as <endpoint id> over N channel(s), relay ...`.

5. `ferry lane iroh status` shows the endpoint id, the version, which relays may be used,
   whether the relay lets us in (it dials with a throwaway key, so it does not disturb the
   worker), any standing alerts, and for each peer the worker has synced with: the last
   success, the last error (and since when it has been failing), whether the exchange went
   direct or through a relay (and which), the version it runs, and how many files went each
   way. `--json` gives the same.

Do this on every machine. A pair starts syncing once each has the other's record, and the
records travel like any channel file: over Syncthing at first, over iroh after that.

## Relays: ours, iroh's public ones, or none

The lane works in any of these ways, chosen by what `[iroh]` says about relays:

| `ferry.toml` | The lane uses |
| --- | --- |
| nothing about relays | **iroh's public relays** (n0's defaults). The default for a new user. |
| `relay_url` and/or `relays` | **Our relays only**, primary first. Public relays are not used. |
| the above plus `fallback_public_relays = true` | Ours, and iroh's public relays **only while none of ours can be reached**. |
| `direct_only = true` | **No relay.** Machines must be able to reach each other. |

```toml
[iroh]
enabled = true
relay_url = "https://relay-one.example"        # the primary
relays = ["https://relay-two.example"]          # more of ours, after the primary
relay_cert_sha256 = "49:32:...:C0:D1"           # pins OUR relays (self-signed certificate)
fallback_public_relays = true                   # off unless you say so
alert_after_minutes = 15                        # see "Is the lane healthy?"
```

- **Our relays** (those in `ferry.toml`) are pinned: each must present the one certificate in `relay_cert_sha256`
  and nothing a public CA signed stands in for it. With no pin they must present a certificate
  a public CA signed. All must be `https://`.
- **Public relays** are checked against the public CA roots in the ordinary way and need no
  pin and no token. When the fallback is on, one verifier serves both: a relay at one of our
  hosts needs the pin, any other relay needs a public certificate.
- **The fallback is a fallback**, not a second choice made by latency. The lane starts with our
  relays only. If none has been connected for two minutes, the public relays are added to the
  relay map the endpoint was bound with, and `status` says so. The map is shared with the
  endpoint, so iroh sees the new entries the next time it checks the network; restarting the
  worker applies them at once. They stay for the life of the worker. A peer is dialed through
  the relay its own TRANSPORTS record names: the worker republishes its record when the relay it
  is on changes (a public-relay setup publishes its home relay once connected), so a peer on a
  public relay can still be found.
- **The token is optional in all of these.** It is put on our relays when `iroh-relay.token`
  exists and nowhere else, and never on a public relay. A relay that wants no token needs no
  file; a lane with no token and public relays works as it is. A machine can move off the shared
  token without the lane noticing: delete the file once the relay no longer asks.
- **Direct only** is for a flat network. With no relay, two machines behind different NATs
  will often not reach each other, and `status` will say so.
- iroh picks its home relay among the relays it knows by latency, so the order of `relays`
  is the order they are listed and published, not a guarantee of which one carries a given
  connection.

A config that says `enabled = true` and names no relay used to mean "direct only". It now means
"iroh's public relays". Add `direct_only = true` to keep the old behaviour.

### The fleet's relay list (0.6.2)

A fleet that runs its own relays does not have to put them in every machine's `ferry.toml`.
The master signs an ordered list into the fleet folder, and every machine reads it:

```
ferry fleet relays                                      # show it
ferry fleet relays set https://162.35.10.46/=<sha256> https://relay2.example.org/
ferry fleet relays add https://relay3.example.org/ --note "Frankfurt"
ferry fleet relays add https://relay0.example.org/ --first
ferry fleet relays remove https://relay3.example.org/
ferry fleet order restart-worker                        # have the fleet pick the change up
```

- **Order.** A machine tries the relays in its own `ferry.toml` first, then the list in the
  master's order. The first is the primary; our VPS goes first. A relay named in both places
  is used once, as `ferry.toml` has it.
- **Failover.** All of them are in the map the endpoint is bound with. iroh homes on the
  one that answers best and moves to the next when it stops answering; the worker republishes
  the relay it is homed on in its TRANSPORTS record, so peers find it there. The alerts above
  fire when none connects.
- **Trust.** `fleet/relays.json` is signed like every other fleet file and only the master's
  signature counts. A copy signed by a machine the master admitted, or edited afterwards, is
  ignored (`ferry doctor` lists it). An entry that is not an `https://` address, has odd
  characters, or has a pin that is not 64 hex digits is dropped, the rest kept.
- **Certificates.** `=<sha256>` is the master's word for that relay's certificate, and applies
  to that host alone: a second relay with its own self-signed certificate needs no change on
  any machine. An entry without a pin must present a certificate a public CA signed (a relay
  with a domain and a Let's Encrypt certificate, say). A pin cannot be loosened by the list:
  the relays in `ferry.toml` still need `relay_cert_sha256`.
- **When it takes effect.** The relays and the certificates to trust are fixed when the worker
  binds, so a changed list applies when the worker restarts. A running worker notices the
  change, says so once, and keeps what it has.
- **No relay in `ferry.toml`** and a list in the fleet folder: the list is the plan, not iroh's
  public relays. Without both, a new user is on the public relays. `direct_only` ignores the list.
- **Public relays** stay what they were: an opt-in fallback, off for a setup that pins a relay.
- **Tokens.** The list carries no secret. The shared token (if any) goes on every relay in the
  list; a lane with none works. A relay that wants a per-device credential, such as a hosted
  one, is another entry in the list; the entry is a record with room for more fields.

Running a relay on a fleet machine (`ferry relay serve`) is not built; see ADR 0027.

## Is the lane healthy? Alerts

Once per worker pass the lane works out what is wrong with itself, from what it last did:

- **a peer failing**: every exchange with it has ended in an error for two minutes or more;
- **a peer gone quiet**: no successful sync with it for `alert_after_minutes` (default 15),
  counted from the lane's start for a peer it has never reached;
- **no relay**: a relay is meant to be in use and none has been connected for two minutes.

A peer that is both failing and quiet is one alert. Each alert is raised **once**, when it
starts to hold, and cleared **once**, when it stops. It is shown:

- in the worker's log (`iroh lane alert: ...`, then `iroh lane recovered: ...`);
- in `ferry doctor` (a `lane` line) and `ferry lane iroh status` (an `ALERT` line);
- in the dashboard's `/api/fleet` as `lane_alerts` (checked, threshold, and each alert with
  its key, text, since and severity `warning`);
- to the rest of the fleet as a `lane-health` notice in the fleet folder (ADR 0026), severity
  `warning`, signed by the machine's own identity and about its own machine only. The notice id
  is fixed per machine and alert, so raising it again replaces the file, and recovery overwrites
  the same file, marked `info` and expired, which every reader treats as gone. Nothing is
  deleted (the lane never deletes). A machine the master has not admitted (`ferry fleet admit`)
  cannot post one and says so; it still has the first three. There is no Telegram push for these
  today: the Telegram bridge only relays orders and results.

The alert state is in `lane-alerts.json` in the machine state directory (machine-local).
Machines still on 0.6.1 do not know the `lane-health` kind and list those notices as ignored in
`ferry doctor` until they update.

## Who may connect

A peer is accepted only if its endpoint id is in a `transports/<agent>.json` that is
signed by that agent, whose key the channel's roster pins, who has an entry in that
channel's own `agents/`, and whom the master has not revoked. The project id is signed
into the record, so it cannot be copied into another channel. Every connection from any
other endpoint is closed as soon as it is accepted, before any channel is read. A peer is
offered a channel only if it is trusted in that channel; being in one project does not
open another (beyond the first-contact exchange below), and a project only one side serves is
skipped. Records are re-read on every
connection and every round, so a revocation takes effect on the next one.

## First contact in a new channel

Trust in a channel needs each side to hold the other's `transports/<agent>.json` for that
channel, and those are channel files, so two machines that already share one project used
to need a hand-copied file (or Syncthing) for every further project. They no longer do.

A peer that is trusted in at least one channel served here (its endpoint id is in an
honoured record of that channel: signed by a roster agent, on the roster pin, not revoked) is
offered, for every OTHER channel served here that it is not yet trusted in, the `transports/`
records of that channel and nothing else, in both directions. Nothing else is opened:

- only `transports/<agent>.json` is listed, asked for, sent or received. Not tasks, not
  messages, not `agents/`, not the hand-ins folder (which is not offered at all);
- a received record is kept only if this machine would honour it as it stands: the file is
  named for the agent it holds, that agent signed it for THIS project, its key is the one this
  channel's roster pins, it has its own `agents/<agent>.json` here, it is not revoked, it is
  not dated in the future, and it is under 8 KiB. Anything else is read and dropped;
- once a kept record names the peer's endpoint, ordinary trust applies from the next round
  (a round is every 30 seconds): the same rules as any trusted peer, and the same revocation.

One limit remains, deliberately: the agent's roster entry, `agents/<agent>.json`, must already
be in the new channel on the receiving machine (from the invite, a git checkout or Syncthing).
The lane will not carry a roster entry before trust, because a roster entry is what trust is
made of. Without it the record is dropped and first contact simply does not happen yet.
## What moves, and what never does

Every 30 seconds the worker sends each trusted peer, per shared project, a manifest
(path, size, BLAKE3, modification time); the peer replies with what it lacks or has
older, and the files go across and are written atomically.

- The channel's `.stignore` exclusions apply both ways, on top of the built-in list
  (`keys`, `*.key`, `*.seed`, executables, scripts, `local`, `*.tmp`).
- Syncthing conflict copies, temporary files and Syncthing's own folders are never sent.
- Nothing over 64 MiB.
- Nothing is ever deleted. (erry root migrate moves a channel on disk; the lane then sees new paths under the root, and a peer that has not moved its own copy yet receives nothing deleted.)
- Nothing is written outside the channel folder: `..`, absolute paths, drive letters,
  backslashes and Windows device names are refused, and no folder on the path or file at
  the end may be a symlink. Symlinks are never sent.
- For a path whose contents differ, the newer modification time wins. Equal times keep
  the local copy on both sides.

## Hand-ins, and who may write the channel (layout 2)

In a layout-2 project (docs/LAYOUT.md) the lane exchanges two folders per project with each trusted peer: the channel (`projects/<id>/comms`) and the hand-ins folder (`projects/<id>/handins`, or the path the manifest records). The second is a separate share under the key `<id>+handins`, on the same trust rules (the peer's endpoint id must be in a roster-signed `transports` record) and the same safety rules: the `.stignore` exclusions, no deletes, no `..`, absolute paths or symlinks, the 64 MiB cap. A peer that predates this refuses the share it does not know, and the channel syncs as before.

Access levels (ADR 0024) are enforced by the machine that **receives** a file. A channel file authored by a Worker-level agent, by its name or by the `signed_by`, `sender` or `from` inside it, is dropped on arrival, signed or not; a Worker's files are accepted only from `handins/<agent>/`. `accepted.json` and `rejected.json` in the hand-ins folder are accepted only from the project's head or master. On a Worker's own machine the lane listens to the channel and publishes none of it (`Lane::set_local_agents`); under Syncthing the same machine's channel folder is made receive-only by `ferry access set`. A Worker's `transports` record is written to its hand-ins folder and honoured from there only.
## The fleet folder, and data (0.6.1)

The fleet's own folder (`<root>/fleet/`, ADR 0026) is one more channel to the lane, under the project id `fleet`. A worker serves it when the root has it, after putting itself on the folder's roster so its `transports` record can be written there; `ferry lane iroh init` does the same. Everything above applies unchanged: the same trust (a peer's endpoint id in a roster-signed `transports` record), the same safety rules, the same `.stignore`. Two things are particular to it:

- `fleet/local/` is this machine's own part (its keys for the folder, the pins it mirrors, which notices it has shown). The lane's built-in `local` exclusion keeps it out both ways, and so does the folder's own `.stignore` under Syncthing.
- A file authored by a Worker-level agent is dropped on arrival, as in any channel, and a Worker never writes the folder. What counts in it is decided by signatures when it is read (`fleethome`), not by who sent it: a peer cannot make a forged entry count by being trusted to sync.

A project's `data/` folder is machine-local and is never exchanged. By default it is `projects/<id>/data`, which is not a share. If a manifest records it somewhere that is inside a share (a hand edit, or an older record), the lane adds it to that share's exclusions; if it is the share itself, or the share is inside it, the lane exchanges nothing from that folder. `ferry doctor --layout` reports the same case.
## Not done yet

- Channel compaction (`ferry channel compact`) is Syncthing-only for now. The lane never
  deletes, so a peer would send back every message compaction removed and the space would
  never be freed; and an archive file over 64 MiB would not be carried at all. `compact`
  therefore refuses a channel the lane carries, or that has a `transports` record, with a
  message saying so. Its archive files are split at 32 MiB (`<thread>.part2.jsonl`, ...)
  so that they stay under the cap once the lane can propagate a removal.
- Files are checked by hash in transit, but not every file type's own signature is
  audited on arrival. The readers that already verify signatures (orders, results,
  policies, records) still do so when they read, exactly as for Syncthing.
- Syncthing still runs. The lane is a second path, not the only one.
- Newer-wins can lose an edit when two machines change the same file between rounds;
  Syncthing would have kept a conflict copy. Channel writers are mostly one-writer,
  write-once files, which is why this is acceptable for now.
- No LAN discovery: peers are dialed by endpoint id and the relay URL in their record,
  and iroh finds the direct path between them through that relay. With `direct_only` and
  no address a peer can reach, the lane has no way to reach anyone.
- The public-relay fallback is exercised by tests of the configuration, the relay map and the
  certificate check, not against n0's servers; try it on a machine before relying on it.
- The relay certificate is pinned by hash: rotating it means changing
  `relay_cert_sha256` on every machine.
