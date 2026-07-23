#!/usr/bin/env bash
# Bring up THE single shared Ferryman hub (one instance serves every project) as
# a durable systemd service in WSL, with its SQLite database on the Linux
# filesystem. Idempotent: safe to re-run.
#
# Security: the hub is created with a generated admin token and WITHOUT a demo
# project, so admin routes (project create/list/delete) require that token and
# there is no public demo credential. The token lives in a 0600 env file read by
# systemd; attach-bridge.sh reads it from the same file.
#
# Usage: scripts/hub-up.sh [port]
# Env:   FERRYMAN_BIN (default $HOME/ferryman/ferryman-server), FERRYMAN_SUDO_PW
set -eu
PORT="${1:-8796}"
BIN="${FERRYMAN_BIN:-$HOME/ferryman/ferryman-server}"
HUBDIR="$HOME/ferryman/hub"
DATA="$HUBDIR/.data"
ENVFILE="$HUBDIR/hub.env"
[ -x "$BIN" ] || { echo "ferryman-server not found/executable at $BIN (set FERRYMAN_BIN)"; exit 1; }
mkdir -p "$DATA"
s() { if [ -n "${FERRYMAN_SUDO_PW:-}" ]; then printf '%s\n' "$FERRYMAN_SUDO_PW" | sudo -S -p '' "$@"; else sudo "$@"; fi; }

# generate a hub admin token once (0600 env file; not in the world-readable unit)
if ! grep -q '^FERRYMAN_ADMIN_TOKEN=' "$ENVFILE" 2>/dev/null; then
  TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
  umask 177
  printf 'FERRYMAN_ADMIN_TOKEN=%s\n' "$TOKEN" > "$ENVFILE"
  echo "generated hub admin token -> $ENVFILE (0600)"
fi

UNIT=/tmp/ferryman-hub.service
cat > "$UNIT" <<EOF
[Unit]
Description=Ferryman hub - single shared instance (Linux-side data)
After=network.target
[Service]
User=$USER
EnvironmentFile=$ENVFILE
ExecStart=$BIN --database $DATA/bridge.db --artifacts $DATA/artifacts --workspace-root $DATA/projects --memory-root $DATA/bridge-memory --recovery-root $DATA/recovery --listen 127.0.0.1:$PORT --no-demo-project
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
s cp "$UNIT" /etc/systemd/system/ferryman-hub.service
s systemctl daemon-reload
s systemctl enable --now ferryman-hub.service
s systemctl restart ferryman-hub.service
sleep 3
curl -s "http://127.0.0.1:$PORT/healthz" && echo "  <- hub up on 127.0.0.1:$PORT (admin routes require the token in $ENVFILE; no demo project)" || { echo "HEALTHZ FAILED"; exit 1; }
