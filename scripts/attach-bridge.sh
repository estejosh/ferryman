#!/usr/bin/env bash
# Attach a project to THE single shared Ferryman hub. The project keeps a full,
# own-git .ferryman/ directory holding only its config + scoped token; the server
# and database are the shared hub's. This is the default for many repos on one
# machine — one running instance, N projects.
#
# Usage: scripts/attach-bridge.sh [--exclude-mode] <project-mount-path> <slug> [hub-endpoint]
#   e.g. scripts/attach-bridge.sh /mnt/x/hone hone
#
#   --exclude-mode  keep the parent repo's tracked .gitignore untouched; add the
#                   ignore rule to .git/info/exclude (local-only) instead.
#
# Env: FERRYMAN_FERRY (default $HOME/ferryman/ferry), FERRYMAN_SUDO_PW,
#      HUB_ADMIN_TOKEN (only if the hub runs with --production)
set -eu

EXCLUDE_MODE=0
POS=()
for a in "$@"; do
  case "$a" in
    --exclude-mode) EXCLUDE_MODE=1 ;;
    *) POS+=("$a") ;;
  esac
done
PROJ="${POS[0]:?project mount path, e.g. /mnt/x/hone}"
SLUG="${POS[1]:?project slug, e.g. hone}"
HUB="${POS[2]:-http://127.0.0.1:8796}"
FERRY="${FERRYMAN_FERRY:-$HOME/ferryman/ferry}"
CFG="$PROJ/.ferryman"

# 1) ensure the ONE hub is up (idempotent; never starts a second instance)
if ! curl -sf "$HUB/healthz" >/dev/null 2>&1; then
  echo "hub not responding at $HUB; starting ferryman-hub.service ..."
  if [ -n "${FERRYMAN_SUDO_PW:-}" ]; then printf '%s\n' "$FERRYMAN_SUDO_PW" | sudo -S -p '' systemctl start ferryman-hub.service; else sudo systemctl start ferryman-hub.service; fi
  sleep 3
  curl -sf "$HUB/healthz" >/dev/null || { echo "hub still down at $HUB"; exit 1; }
fi

# 2) full own-git .ferryman/ directory, ignored by the parent project
mkdir -p "$CFG"
if git -C "$PROJ" rev-parse --git-dir >/dev/null 2>&1; then
  E="/.ferryman/"
  if [ "$EXCLUDE_MODE" -eq 1 ]; then
    GITDIR="$(git -C "$PROJ" rev-parse --absolute-git-dir)"
    EX="$GITDIR/info/exclude"
    mkdir -p "$(dirname "$EX")"
    grep -qxF "$E" "$EX" 2>/dev/null || printf '\n# Ferryman bridge attachment (local-only; not committed)\n%s\n' "$E" >> "$EX"
    echo "NOTICE: added $E to $EX (local-only; your tracked .gitignore was NOT modified)"
  else
    GI="$PROJ/.gitignore"
    grep -qxF "$E" "$GI" 2>/dev/null || printf '\n# Ferryman bridge attachment (own git repo; token is local-only)\n%s\n' "$E" >> "$GI"
    echo "NOTICE: added $E to the tracked $GI (pass --exclude-mode to keep .gitignore untouched)"
  fi
fi
[ -d "$CFG/.git" ] || git -C "$CFG" init -q
cat > "$CFG/.gitignore" <<'EOF'
# the scoped token is local-only; never commit it to the attachment sub-repo
token
*.log
EOF

# 3) register the project in the hub (idempotent) and store its scoped token locally
if [ -s "$CFG/token" ]; then
  echo "reusing existing token for '$SLUG'"
else
  TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)"
  ADMIN="${HUB_ADMIN_TOKEN:-adminplaceholder}"
  if "$FERRY" --endpoint "$HUB" --token "$ADMIN" projects create --id "$SLUG" --name "$SLUG" --token "$TOKEN" >/dev/null 2>&1; then
    printf '%s' "$TOKEN" > "$CFG/token"; chmod 600 "$CFG/token"
    echo "registered project '$SLUG' in the hub"
  else
    echo "project '$SLUG' already exists in the hub but no local token file was found."
    echo "  -> recreate the project with a fresh token, or restore $CFG/token, then re-run."
    exit 2
  fi
fi

# 4) config (endpoint = the one hub; token in ./token, gitignored)
cat > "$CFG/bridge.toml" <<EOF
# Attached to the shared Ferryman hub (one instance serves all projects).
endpoint = "$HUB"
project  = "$SLUG"
# scoped token is in ./token (local-only, gitignored). Server + database are the hub's.
EOF

echo "attached '$SLUG' -> hub $HUB"
echo "  config: $CFG/bridge.toml"
echo "  token:  $CFG/token (local-only)"
