#!/usr/bin/env bash
# Permissioned update of the shared Ferryman hub. NEVER runs automatically.
#   - no flag:   read-only. Shows what would change, then stops (deny = do nothing).
#   - --confirm: APPROVE. Fast-forwards the bridge source, rebuilds, swaps the
#                binaries, and restarts the hub service.
#
# Usage: scripts/apply-update.sh [--confirm]
# Env: SRC (default ~/ferryman/src), BIN_DIR (default ~/ferryman),
#      SERVICE (default ferryman-hub.service), PORT (default 8796), FERRYMAN_SUDO_PW
set -eu
CONFIRM=0; [ "${1:-}" = "--confirm" ] && CONFIRM=1
SRC="${SRC:-$HOME/ferryman/src}"
BIN_DIR="${BIN_DIR:-$HOME/ferryman}"
SERVICE="${SERVICE:-ferryman-hub.service}"
PORT="${PORT:-8796}"
UPDATER="$SRC/target/release/ferryman-updater"
s(){ if [ -n "${FERRYMAN_SUDO_PW:-}" ]; then printf '%s\n' "$FERRYMAN_SUDO_PW" | sudo -S -p '' "$@"; else sudo "$@"; fi; }

# 1) read-only gate
set +e
"$UPDATER" check-remote --checkout "$SRC" --branch main
code=$?
set -e
if [ "$code" -eq 0 ]; then echo "nothing to apply."; exit 0; fi   # up to date
# code 10 => update pending
if [ "$CONFIRM" -ne 1 ]; then
  echo ""
  echo "Update pending (above). To APPROVE: scripts/apply-update.sh --confirm"
  echo "To DENY: do nothing; the hub stays where it is."
  exit 10
fi

# 2) approved -> apply
echo "=== APPROVED: fast-forwarding source ==="
"$UPDATER" update-bridge --checkout "$SRC" --branch main --confirm
echo "=== rebuilding ==="
( cd "$SRC" && cargo build --release -p ferryman-server -p ferryman-cli )
cp -f "$SRC/target/release/ferryman-server" "$BIN_DIR/ferryman-server"
cp -f "$SRC/target/release/ferry"           "$BIN_DIR/ferry"
echo "=== restarting $SERVICE ==="
s systemctl restart "$SERVICE"
sleep 3
curl -s "http://127.0.0.1:$PORT/healthz" && echo "  <- hub updated + restarted" || { echo "HEALTHZ FAILED after update"; exit 1; }
rm -f "$BIN_DIR/UPDATE_AVAILABLE"
echo "done."
