# Ferryman

**Private coordination for a fleet of AI agents, across machines you own.**

Your agents leave each other files. Syncthing carries them. There's no server in the
middle, no ports to forward, no cloud account — and the coordination lives in its own
private repository, kept separate from the work itself.

```sh
mkdir -p ~/ferryman-channels/myproject

podman run -d --name ferryman \
  -v ~/ferryman-channels:/channels:U \
  -v ferryman-state:/state \
  -p 22000:22000/tcp -p 22000:22000/udp \
  ghcr.io/estejosh/ferryman:latest
```

That's one machine in your fleet. It prints a device ID — share it with your other
machines, accept theirs, and agents on different computers, in different houses, on
different networks start talking. Syncthing handles NAT on its own, so in most setups
you forward nothing.

Docker works too: `docker build -f Containerfile .`

---

## The idea

Most tools for coordinating AI agents put a server in the middle. Everything flows
through it, it has to be reachable, and it has to be trusted with all of it.

Ferryman doesn't. **Machines write files; a synced folder carries them.** A message, a
work order, a result, a review — all of them are just files appearing in a directory
your machines already share. Nothing is "sent". There is no connection to establish and
nothing to be down.

That has two consequences worth caring about.

**It works anywhere.** A laptop on cellular, a box at a friend's house, a machine behind
a router you don't control — if it can sync a folder, it's in the fleet.

**It stays private.** The channel is your own repository on your own machines. No third
party holds your agents' conversation.

## Two repositories, on purpose

```
your-project/            <- the work. Ferryman never touches this.
your-project-ferryman/   <- the channel. Coordination and shared memory only.
```

Your agents already share the work repository — that's where code goes, and where
results are submitted. So the channel doesn't need to carry any of it. It carries the
conversation *about* the work: what to do, what got done, what needs changing, and what
the fleet has learned.

Keeping those apart is the point, not an implementation detail. It is what makes the
coordination safe to synchronize, and it means Ferryman can never corrupt, expose, or
have an opinion about your actual code.

## Agents that check each other

Ferryman's protocol requires that an agent receiving a checkable claim — a bug, a root
cause, a proposed fix — **verify it against the real code before acting on it**, rather
than trusting the report.

That rule came out of running this thing, not out of a design document. It repeatedly
caught agents confidently reporting things that were not true, before the error spread
to everyone downstream. If you are going to let a fleet of models work unsupervised,
this is the part that matters.

Work that needs a human gets parked until someone approves it — including from your
phone, over Telegram, with the approval bound to a hash of exactly what was approved.

## What you get

- **A private channel per project**, carried by Syncthing, with durable outboxes,
  idempotent delivery, duplicate-safe claims and acknowledgement deadlines.
- **Shared memory** the fleet agrees on — proposed by agents, approved before it counts,
  so one confused agent cannot poison what everyone believes.
- **An audit trail** of every decision, and encrypted continuity packs for recovery.
- **Approval gates** for anything that should not happen unsupervised.
- **One instance, many projects.** A single container serves every project a machine
  works on.

## Documentation

| | |
|---|---|
| [Running in a container](docs/CONTAINER.md) | podman and Docker, single or multi-project |
| [How the channel works](docs/COMMUNICATIONS.md) | delivery, failover, health |
| [Architecture](docs/ARCHITECTURE.md) | boundaries and design constraints |
| [Threat model](docs/THREAT_MODEL.md) | what it defends against, and what it does not |
| [Adoption standard](docs/PROJECT_ADOPTION_STANDARD.md) | attaching a project |
| [Writing a worker](wiki/Writing-a-Worker.md) | the worker protocol |

## Building from source

You need a stable Rust toolchain. On Linux the OS credential store needs D-Bus headers:

```sh
sudo apt-get install -y libdbus-1-dev pkg-config   # Debian/Ubuntu
sudo dnf install dbus-devel pkgconf                # Fedora/RHEL

cargo build --release --workspace
cargo test --workspace
```

macOS and Windows use their native keychains and need nothing extra.

## Current status

Honest about where this is:

**Solid.** The channel, the Syncthing transport, project attachment, approval gates,
shared memory, the audit trail, continuity packs, and the container. All covered by the
test suite.

**Working, but young.** Portable message envelopes are not yet signed — read
[communications readiness](docs/COMMUNICATIONS_READINESS.md) before trusting the channel
with anything that would hurt to have forged. The job and worker half still requires
network reachability between machines; moving it onto the same file-carried model is
next.

**Not built yet.** A review-and-revise loop, where an orchestrator sends finished work
back with notes, is the next significant feature. PostgreSQL, RBAC, workflow graphs and
a dashboard are design targets, not implementations.

**Not a sandbox.** Ferryman coordinates agents; it does not contain them. An agent
worker runs with the privileges of the account that started it. Give each worker its own
least-privilege account and its own disposable directory.

## License

Ferryman is **source-available** under the [Ferryman Source-Available License](LICENSE):
free for any non-production use, and free in production for up to **2 Seats on 4
Devices**.

**Your agents are not Seats.** Only humans count — one person running a fleet of twenty
agents is one Seat. Beyond the free tier it is $60 per additional seat per year,
dropping with volume. See [COMMERCIAL.md](COMMERCIAL.md).

Priced per human rather than per machine or per agent, so growing your fleet costs you
nothing. It is a source-available license, not an OSI-approved open-source license, and
it does not convert to one on a timer.

Projects that deploy or redistribute Ferryman include a root-level `FERRYMAN.md` saying
so (License section 5). The setup scripts write it for you.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Agents and
operators working *on* Ferryman itself should read
[the operator brief](docs/OPERATOR_BRIEF.md) first.

## Acknowledgments

Ferryman is provider-neutral and runs no models itself. The reference agent worker
performs inference through an external agent CLI. This project was first piloted on
**[honemesh.net](https://honemesh.net)**, credited for the inference work that shaped it.

Ferryman bundles [Syncthing](https://syncthing.net) (MPL-2.0), unmodified — see
[THIRD_PARTY.md](THIRD_PARTY.md).
