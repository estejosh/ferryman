# Running Ferryman in a container

Podman-first: rootless, daemonless, no root anywhere. Docker works too — every command
below has a `docker` equivalent, and the image is built from a standard `Containerfile`
(`docker build -f Containerfile .`).

---

## The shape of it

One container, many projects.

```
~/ferryman-channels/          <- mounted at /channels
  hone/                       <- Syncthing folder "hone-ferryman"
  ferryman/                   <- Syncthing folder "ferryman-ferryman"
  acme/                       <- Syncthing folder "acme-ferryman"
```

Each subdirectory is one project's channel: the coordination and shared memory for that
project, shared with the machines working on it. **The work itself never lives here** —
that stays in each project's own repository. The channel only carries messages about it.

A second volume, `/state`, holds this machine's private index. It is deliberately
separate because losing it must cost nothing: it rebuilds from the channels.

---

## Start it

```sh
mkdir -p ~/ferryman-channels/myproject

podman run -d --name ferryman \
  -v ~/ferryman-channels:/channels:U \
  -v ferryman-state:/state \
  -p 22000:22000/tcp -p 22000:22000/udp -p 21027:21027/udp \
  -p 127.0.0.1:8384:8384 \
  -p 127.0.0.1:8787:8787 \
  ghcr.io/estejosh/ferryman:latest
```

`:U` tells podman to chown the directory to the container's user. Without it the
container cannot write to your channel and will say so plainly on startup.

Then read the log for this machine's Syncthing device id:

```sh
podman logs ferryman | grep -A1 'device id'
```

Give that id to the other machines in the fleet, accept theirs, and share the project
folder between them. From then on, a file written on one machine appears on the others.

### Ports

| Port | Purpose | Exposure |
|---|---|---|
| 22000/tcp, 22000/udp | Syncthing protocol | must be reachable by peers |
| 21027/udp | local discovery | local network only |
| 8384 | Syncthing admin UI | loopback only |
| 8787 | Ferryman API | loopback only |

Only 22000 needs to face the network. Syncthing traverses NAT on its own, so in most
setups you do not forward anything at all.

---

## If you already run Syncthing

**Do not run a second one against the same folder.** Two live sync engines on one
directory fight each other and produce conflict files. Point the container at the
Syncthing you already have:

```sh
podman run -d --name ferryman \
  -v ~/ferryman-channels:/channels:U \
  -v ferryman-state:/state \
  -e FERRYMAN_SYNCTHING=external \
  -e SYNCTHING_API_BASE=http://host.containers.internal:8384 \
  -e SYNCTHING_API_KEY=... \
  -p 127.0.0.1:8787:8787 \
  ghcr.io/estejosh/ferryman:latest
```

Ferryman then registers each project folder with your existing instance and leaves the
running of it to you.

---

## Run it under systemd (recommended for anything long-lived)

```sh
mkdir -p ~/.config/containers/systemd
cp deploy/ferryman.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start ferryman

loginctl enable-linger $USER     # keep running after you log out
```

That is a rootless systemd service with no daemon involved. `Restart=always` means a
crash comes back by itself — which a bare process does not, and the resulting silence is
indistinguishable from a peer that has nothing to say.

### Following releases automatically

```sh
systemctl --user enable --now podman-auto-update.timer
```

The unit is marked `AutoUpdate=registry`. When this repository publishes a new image, the
timer pulls it and restarts the container on it. To approve each upgrade yourself
instead, pin the unit to a version tag (`:v1.2.3`) rather than `:latest`.

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `FERRYMAN_SYNCTHING` | `bundled` | `bundled` runs Syncthing inside; `external` uses the host's |
| `FERRYMAN_CHANNELS_DIR` | `/channels` | parent directory, one subdirectory per project |
| `FERRYMAN_STATE_DIR` | `/state` | private, rebuildable index |
| `FERRYMAN_CHANNEL_SUFFIX` | `-ferryman` | Syncthing folder id is `<project><suffix>` |
| `SYNCTHING_API_BASE` | `http://127.0.0.1:8384` | where to reach Syncthing |
| `SYNCTHING_API_KEY` | generated | required in `external` mode |
| `FERRYMAN_ADMIN_TOKEN` | generated | see below |

### The admin token

The API refuses to bind a non-loopback address without an admin token, because anyone
who could reach the port would otherwise be able to create a project with a token of
their own choosing. A published container port means binding `0.0.0.0` inside the
container, so on first run Ferryman mints a token rather than relaxing the check:

```sh
podman exec ferryman cat /state/admin-token
```

Set `FERRYMAN_ADMIN_TOKEN` yourself to control it.

---

## What is in the image

- `ferryman-server` and the `ferry` CLI, built from this repository.
- **Syncthing**, official upstream binary, unmodified, checksum-verified at build time,
  under MPL-2.0. Its licence travels with it at
  `/usr/share/licenses/syncthing/LICENSE`. See [THIRD_PARTY.md](../THIRD_PARTY.md).
- `git`, because a channel is a private Git repository.
- `tini` as PID 1, since the container supervises Syncthing as a child process.

The bundled Syncthing runs with `--no-upgrade`. The image ships a specific build whose
checksum was verified and whose licence is carried alongside it; a Syncthing that
replaced its own binary would undo both. Upgrades arrive by pulling a new image.

---

## Troubleshooting

**`channels directory /channels is not writable`** — the mount is owned by a user the
container is not. Add `:U` to the volume, or `chown -R 10001:10001` the directory.

**Container starts, then exits** — by design: if either Syncthing or Ferryman dies, the
container exits so your restart policy can act. `podman logs ferryman` shows which one
and why.

**Healthy but nothing arrives** — health means Syncthing is answering, not that a peer is
connected. Check `http://127.0.0.1:8384` for a device that has accepted your folder. A
folder with no connected peer stores messages; it does not deliver them.

**`.stignore` was written into my channel** — deliberately, on first run. It stops
Syncthing replicating a live `.git` directory between machines, which corrupts it, and
stops it syncing each machine's private index. Extend it freely; do not remove those
entries.
