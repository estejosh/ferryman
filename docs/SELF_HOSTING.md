# Run your own relay

Ferryman's iroh lane moves channel files machine to machine over QUIC. When two
machines cannot reach each other directly (one is behind a home router, say), a
relay finds them for each other and carries the traffic between them. This is a
guide to running that relay yourself, on a VPS or a home server, so you do not
have to use iroh's public relays or anyone else's.

The relay never sees your work. It only ever carries encrypted QUIC, so it can
see that two machines talked and roughly how much, but never what they said.

## When you need one

You do not need a relay if every machine can already reach every other one
directly (same network, or with working port forwarding on both ends). You want
one when machines move networks (laptops), sit behind home routers or NAT, or
cannot be dialed directly — which is most real setups.

## Option A: a small Debian/Ubuntu VPS (recommended)

The cheapest VPS is enough: a relay is a tiny proxy, not a fileserver.

### Install iroh-relay

Install the same generation Ferryman uses (iroh 1.3.x):

```
cargo install iroh-relay --version 1.3.0
```

This needs a Rust toolchain. If you would rather not build on the VPS, build it
on your own machine and copy the binary, or use a binary release of iroh-relay
1.3.x.

### The config file

Put this in `/etc/iroh-relay/relay.toml`. HTTPS on TCP 443, and QUIC address
discovery on UDP 443, so one firewall rule covers both:

```toml
# /etc/iroh-relay/relay.toml
enable_quic_addr_discovery = true

[tls]
https_bind_addr = "[::]:443"
quic_bind_addr = "[::]:443"
```

Add the certificate section below, depending on whether you have a domain.

### The certificate

**With a domain (ACME).** A public CA signs it, so nothing is pinned:

```toml
[tls]
https_bind_addr = "[::]:443"
quic_bind_addr = "[::]:443"
cert_mode = "LetsEncrypt"
hostname = ["relay.example.com"]
contact = "you@example.com"
cert_dir = "/var/lib/iroh-relay/certs"
```

**No domain (self-signed, pinned).** Generate a certificate and pin its
fingerprint in Ferryman. No public CA will sign for a bare IP, so instead of
turning verification off you pin the one certificate the relay serves:

```
mkdir -p /etc/iroh-relay
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /etc/iroh-relay/default.key -out /etc/iroh-relay/default.crt \
  -days 3650 -nodes -subj "/CN=relay"
```

```toml
[tls]
https_bind_addr = "[::]:443"
quic_bind_addr = "[::]:443"
cert_mode = "Manual"
manual_cert_path = "/etc/iroh-relay/default.crt"
manual_key_path = "/etc/iroh-relay/default.key"
```

Print the fingerprint you will pin:

```
openssl x509 -in /etc/iroh-relay/default.crt -noout -fingerprint -sha256
```

It prints `SHA256 Fingerprint=49:32:08:E4:...`. The part after the `=` is what
goes in `relay_cert_sha256` (and in `ferry fleet relays add` below).

### The systemd unit

`/etc/systemd/system/iroh-relay.service`, hardened so the relay drops every
capability except the one it needs to bind port 443:

```ini
[Unit]
Description=iroh-relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/iroh-relay --config /etc/iroh-relay/relay.toml
Restart=always
RestartSec=5
User=iroh-relay
Group=iroh-relay
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/iroh-relay

[Install]
WantedBy=multi-user.target
```

Then:

```
sudo useradd --system --home /var/lib/iroh-relay --shell /usr/sbin/nologin iroh-relay
sudo systemctl daemon-reload
sudo systemctl enable --now iroh-relay
sudo systemctl status iroh-relay
```

Open TCP 443 and UDP 443 in the VPS firewall (and in the provider's console, if
it has one in front).

### Optional: an access token

You can require a token so only your machines use the relay. Add to the config:

```toml
[access]
shared_token = ["put-a-long-random-token-here"]
```

Then put that same token in a file named `iroh-relay.token` in the machine
state directory on each machine (see "Where the token lives" below). The token
is read, never printed, and never belongs in `ferry.toml` or in a channel.

## Option B: a home server behind a router

The same install works at home. Forward TCP 443 and UDP 443 to the server in
your router, and use the no-domain (self-signed, pinned) certificate path above.

What breaks with CGNAT: if your internet provider puts you behind
carrier-grade NAT (a shared public address you cannot forward ports on), a home
relay is not reachable from outside. In that case use a cheap VPS instead.

## Point Ferryman at it

### One machine

In the ferry root's `ferry.toml` (machine-local, never synced):

```toml
[iroh]
enabled = true
relay_url = "https://relay.example.com"
# No domain, self-signed certificate: pin it. With an ACME cert, omit this.
relay_cert_sha256 = "49:32:08:E4:6F:B8:E3:9B:FD:F2:8D:B8:0F:8C:33:F9:9F:2A:57:A0:A1:71:B3:52:4A:9D:11:67:AD:BD:C0:D1"
# Optional: also use iroh's public relays while yours cannot be reached.
fallback_public_relays = true
```

`relay_cert_sha256` only applies to a relay you run with a self-signed
certificate. With an ACME certificate there is no pin. With `relay_url` set and
no `fallback_public_relays`, iroh's public relays are not used.

### The whole fleet

A fleet with several machines puts the relay in one master-signed list instead
of every `ferry.toml` (0.6.2). `=<sha256>` only when the certificate is
self-signed:

```
ferry fleet relays add https://relay.example.com/=49:32:08:E4:...:C0:D1
```

Machines try their own `ferry.toml` relays first, then this list.

### Check it works

```
ferry lane iroh status
```

It shows which relays may be used and whether the relay lets this machine in.
See [docs/IROH_LANE.md](IROH_LANE.md) for everything the lane reports.

## Where the token lives

The access token goes in a file named `iroh-relay.token` in the machine state
directory — `%LOCALAPPDATA%\Ferryman` on Windows, `~/.local/state/ferryman` on
Linux, or whatever `FERRYMAN_STATE_DIR` points at. Ferryman reads that file by
default; set `relay_token_file = "<path>"` in `ferry.toml` to point elsewhere.
The token is never written into `ferry.toml`, a channel, or a fleet list, and it
is never printed.

