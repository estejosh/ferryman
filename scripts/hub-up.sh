#!/usr/bin/env bash
# Bring up THE single shared Ferryman hub (one instance serves every project) as
# a durable systemd service in WSL, with its SQLite database on the Linux
# filesystem. Idempotent: safe to re-run; if the hub is already up it just
# reports healthz. There is only ever one hub instance (one systemd unit).
#
# Usage: scripts/hub-up.sh [port]
# Env:   FERRYMAN_BIN (default $HOME/ferryman/ferryman-server), FERRYMAN_SUDO_PW
set -eu
PORT="${1:-8796}"
BIN="${FERRYMAN_BIN:-$HOME/ferryman/ferryman-server}"
DATA="$HOME/ferryman/hub/.data"
[ -x "$BIN" ] || { echo "ferryman-server not found/executable at $BIN (set FERRYMAN_BIN)"; exit 1; }
mkdir -p "$DATA"
s() { if [ -n "${FERRYMAN_SUDO_PW:-}" ]; then printf '%s\n' "$FERRYMAN_SUDO_PW" | sudo -S -p '' "$@"; else sudo "$@"; fi; }

UNIT=/tmp/ferryman-hub.service
cat > "$UNIT" <<EOF
[Unit]
Description=Ferryman hub - single shared instance (Linux-side data)
After=network.target
[Service]
User=$USER
ExecStart=$BIN --database $DATA/bridge.db --artifacts $DATA/artifacts --workspace-root $DATA/projects --memory-root $DATA/bridge-memory --recovery-root $DATA/recovery --listen 127.0.0.1:$PORT
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
s cp "$UNIT" /etc/systemd/system/ferryman-hub.service
s systemctl daemon-reload
s systemctl enable --now ferryman-hub.service
sleep 3
curl -s "http://127.0.0.1:$PORT/healthz" && echo "  <- hub up on 127.0.0.1:$PORT (data: $DATA)" || { echo "HEALTHZ FAILED"; exit 1; }
