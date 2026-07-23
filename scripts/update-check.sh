#!/usr/bin/env bash
# Auto-check for a pending Ferryman hub update. Read-only: it NEVER applies.
# Meant to run on a systemd timer. When an update is pending it records
# ~/ferryman/UPDATE_AVAILABLE (with the pending commit list) so the operator/an
# agent can see it and choose to approve via scripts/apply-update.sh --confirm.
# Always exits 0 so the timer stays healthy.
set -u
SRC="${SRC:-$HOME/ferryman/src}"
BIN_DIR="${BIN_DIR:-$HOME/ferryman}"
UPDATER="$SRC/target/release/ferryman-updater"
OUT="$BIN_DIR/UPDATE_AVAILABLE"

[ -x "$UPDATER" ] || { echo "updater not built at $UPDATER"; exit 0; }
MSG="$("$UPDATER" check-remote --checkout "$SRC" --branch main 2>&1)"; code=$?
if [ "$code" -eq 10 ]; then
  {
    printf '%s\n' "$MSG"
    echo ""
    echo "To apply (requires approval): scripts/apply-update.sh --confirm"
  } > "$OUT"
  echo "update available -> wrote $OUT (apply is permissioned; never automatic)"
else
  rm -f "$OUT"
  echo "up to date"
fi
exit 0
