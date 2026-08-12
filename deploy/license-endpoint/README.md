# Standing up the check-in receiver

This is the endpoint installs report to. It records who is running Ferryman and how
large their deployment is, and emails you when one goes beyond the free tier.

Until it exists, `ferry license checkin` has nowhere to send anything — the client is
built, but you learn nothing. That is the only thing this fixes.

## What it is

One Python file, standard library only, no database. Check-ins are appended to a JSONL
file; that is the store. It has to run for years without attention, and every
dependency is something that breaks while you are not watching.

## Run it

```sh
cd deploy/license-endpoint
podman build -t ferryman-licensing .

cp ferryman-licensing.container ~/.config/containers/systemd/
$EDITOR ~/.config/containers/systemd/ferryman-licensing.container   # set FERRYMAN_ALERT_TO

printf 'FERRYMAN_SMTP_USER=...\nFERRYMAN_SMTP_PASS=...\n' > ~/.config/ferryman-licensing.env
chmod 600 ~/.config/ferryman-licensing.env

systemctl --user daemon-reload
systemctl --user start ferryman-licensing
curl -s localhost:8799/health
```

Without systemd:

```sh
podman run -d --name ferryman-licensing \
  -p 127.0.0.1:8799:8799 \
  -v ferryman-licensing-data:/data \
  -e FERRYMAN_ALERT_TO=you@example.com \
  -e FERRYMAN_SMTP_HOST=smtp.example.com \
  ferryman-licensing
```

## Put TLS in front of it

It binds to loopback and speaks plain HTTP deliberately — doing TLS inside a script
meant to be auditable at a glance would mean certificate handling nobody reviews. Any
reverse proxy will do:

```
# Caddy
licensing.example.com {
    reverse_proxy 127.0.0.1:8799
}
```

**This matters.** Check-ins carry email addresses. Sending them unencrypted across the
internet would contradict PRIVACY.md, which is part of the licence terms.

## Point installs at it

```sh
export FERRYMAN_CHECKIN_URL=https://licensing.example.com/checkin
```

Unset, an install reports nothing at all. There is no baked-in default URL — a binary
that phones somewhere by default, with the destination compiled in, is the thing this
audience checks for first.

## Reading it

```sh
podman exec ferryman-licensing cat /data/checkins.jsonl | tail -20

# every deployment currently over the free tier
podman exec ferryman-licensing cat /data/checkins.jsonl \
  | python3 -c 'import json,sys
seen={}
for line in sys.stdin:
    row=json.loads(line); seen[row["deployment_id"]]=row
for row in seen.values():
    if row.get("over_limit"):
        print(row["deployment_id"], row.get("emails"), row.get("seats"), row.get("computers"))'
```

You are emailed **once per deployment**, not once per check-in. Clients report daily,
and a daily alert is one that ends up in a folder you stop opening.

## What it will not do

- **It does not enforce anything.** Nothing here can disable an install; over-limit is
  a notice on their side and a line in your log. Deliberate — see LICENSE section 4.
- **It does not receive anything about their work.** Only the fields in PRIVACY.md are
  stored, and anything else a client posts is dropped rather than recorded.
- **It does not authenticate callers.** Anyone can post a made-up check-in. Adding
  auth would mean shipping a shared secret in a source-available binary, which
  authenticates nobody. Treat the data as a signal, not as evidence.

## Back it up

The JSONL file is the only record of who your users are. It lives on the
`ferryman-licensing-data` volume; include it in whatever you already back up.
