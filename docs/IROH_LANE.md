# The iroh lane: channels over QUIC, through our own relay

Syncthing carries a channel well between machines on one network. Away from home it is
only as good as its discovery and its public relays. The iroh lane carries the same
channel folders a second way: over [iroh](https://www.iroh.computer) (QUIC, peers
identified by ed25519 endpoint ids), through a relay we run ourselves, and directly
between two machines whenever they can see each other.

It runs **beside** Syncthing, not instead of it. Both write channel files the same way
(temporary file, then rename) and both keep modification times, so a file that arrived by
one lane is simply already there when the other looks.

## Turning it on, per machine

1. Add to the ferry root's `ferry.toml` (machine-local, never synced):

   ```toml
   [iroh]
   enabled = true
   relay_url = "https://162.35.10.46"
   # The relay's self-signed certificate: this exact certificate and no other.
   relay_cert_sha256 = "49:32:08:E4:6F:B8:E3:9B:FD:F2:8D:B8:0F:8C:33:F9:9F:2A:57:A0:A1:71:B3:52:4A:9D:11:67:AD:BD:C0:D1"
   ```

2. Put the relay's access token, and nothing else, in `iroh-relay.token` in the machine
   state directory (`%LOCALAPPDATA%\Ferryman` on Windows, `~/.local/state/ferryman` on
   Linux, or `$FERRYMAN_STATE_DIR`). `relay_token_file = "<path>"` points elsewhere.
   The token is read, never printed, and never belongs in a channel or in `ferry.toml`.

3. From the worker's home checkout (where its `agent.toml` is):

   ```
   ferry lane iroh init
   ```

   This makes the machine's iroh key once (`iroh.key`, beside the operator seed) and
   writes `transports/<agent>.json` into every channel the all-projects worker serves.

4. Restart the worker (`ferry agent run --all-projects`). Its startup line says
   `iroh lane on as <endpoint id> over N channel(s), relay ...`.

5. `ferry lane iroh status` shows the endpoint id, whether the relay lets us in (it dials
   with a throwaway key, so it does not disturb the worker), and each peer the worker has
   synced with: when, which projects, how many files each way, and the last error.

Do this on every machine. A pair starts syncing once each has the other's record, and the
records travel like any channel file: over Syncthing at first, over iroh after that.

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
## Not done yet

- Files are checked by hash in transit, but not every file type's own signature is
  audited on arrival. The readers that already verify signatures (orders, results,
  policies, records) still do so when they read, exactly as for Syncthing.
- Syncthing still runs. The lane is a second path, not the only one.
- Newer-wins can lose an edit when two machines change the same file between rounds;
  Syncthing would have kept a conflict copy. Channel writers are mostly one-writer,
  write-once files, which is why this is acceptable for now.
- No LAN discovery: peers are dialed by endpoint id and the relay URL in their record,
  and iroh finds the direct path between them through that relay. With no relay
  configured, the lane has no way to reach anyone.
- The relay certificate is pinned by hash: rotating it means changing
  `relay_cert_sha256` on every machine.
