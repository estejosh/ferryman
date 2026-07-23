#!/usr/bin/env bash
# Run a Ferryman bridge in WSL/Ubuntu with its SQLite database on the LINUX
# filesystem (ext4), avoiding the DrvFs file-locking problems that hit a SQLite
# db living on a Windows drive (/mnt/*). A small, discoverable config is nested
# inside the Windows project so sandboxed agents find the endpoint; the actual
# data stays Linux-side. The bridge runs as a durable systemd service.
#
# Usage:
#   scripts/wsl-bridge.sh <project-mount-path> [port] [slug]
#   e.g. scripts/wsl-bridge.sh /mnt/x/hone 8796 hone
#
# Env:
#   FERRYMAN_BIN     path to ferryman-server (default: $HOME/ferryman/ferryman-server)
#   FERRYMAN_SUDO_PW sudo password for installing the systemd unit (omit if passwordless sudo)
set -eu
PROJ="${1:?project mount path, e.g. /mnt/x/hone}"
PORT="${2:-8796}"
SLUG="${3:-demo}"
BIN="${FERRYMAN_BIN:-$HOME/ferryman/ferryman-server}"
DATA="$HOME/ferryman/$SLUG/.data"
CFG="$PROJ/.ferryman"

[ -x "$BIN" ] || { echo "ferryman-server not found/executable at $BIN (set FERRYMAN_BIN)"; exit 1; }
mkdir -p "$DATA" "$CFG"

# 1) discoverable, gitignored config in the Windows project (data stays Linux-side)
if git -C "$PROJ" rev-parse --git-dir >/dev/null 2>&1; then
  GI="$PROJ/.gitignore"; E="/.ferryman/"
  grep -qxF "$E" "$GI" 2>/dev/null || printf '\n# Ferryman nested bridge config (server in WSL; data Linux-side)\n%s\n' "$E" >> "$GI"
fi
cat > "$CFG/bridge.toml" <<EOF
# Server runs in WSL as systemd unit ferryman-$SLUG.service; data is Linux-side.
endpoint = "http://127.0.0.1:$PORT"
project  = "$SLUG"
runtime  = "wsl-systemd:ferryman-$SLUG.service"
EOF

# 2) durable systemd system unit
s() { if [ -n "${FERRYMAN_SUDO_PW:-}" ]; then printf '%s\n' "$FERRYMAN_SUDO_PW" | sudo -S -p '' "$@"; else sudo "$@"; fi; }
UNIT="/tmp/ferryman-$SLUG.service"
cat > "$UNIT" <<EOF
[Unit]
Description=Ferryman bridge ($SLUG) - Linux-side data on WSL
After=network.target
[Service]
User=$USER
ExecStart=$BIN --database $DATA/bridge.db --artifacts $DATA/artifacts --workspace-root $DATA/projects --memory-root $DATA/bridge-memory --recovery-root $DATA/recovery --listen 127.0.0.1:$PORT --no-demo-project
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
s cp "$UNIT" "/etc/systemd/system/ferryman-$SLUG.service"
s systemctl daemon-reload
s systemctl enable --now "ferryman-$SLUG.service"
sleep 3

echo "=== healthz ==="
curl -s "http://127.0.0.1:$PORT/healthz" && echo "  <- $SLUG bridge up on 127.0.0.1:$PORT (data: $DATA)" || { echo "HEALTHZ FAILED"; exit 1; }
