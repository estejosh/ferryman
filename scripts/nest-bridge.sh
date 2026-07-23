#!/usr/bin/env sh
# Set up a full, self-contained Ferryman bridge nested inside a project repo.
#
# Creates <project>/.ferryman/ which runs its own server + SQLite data, is its
# OWN git repo (versioned independently), and is gitignored by the parent so it
# never pollutes the main project. Unblocks agents sandboxed to their project dir.
#
# Usage: scripts/nest-bridge.sh [project-dir] [port] [project-slug]
set -eu
PROJECT="${1:-$(pwd)}"
PORT="${2:-8787}"
SLUG="${3:-demo}"
DIRNAME=".ferryman"
BRIDGE="$PROJECT/$DIRNAME"

# 1) parent repo ignores the nested bridge
if git -C "$PROJECT" rev-parse --git-dir >/dev/null 2>&1; then
  GI="$PROJECT/.gitignore"
  ENTRY="/$DIRNAME/"
  if ! { [ -f "$GI" ] && grep -qxF "$ENTRY" "$GI"; }; then
    printf '\n# Ferryman nested bridge (its own git repo; not part of this project)\n%s\n' "$ENTRY" >> "$GI"
    echo "gitignore: added $ENTRY to $GI"
  fi
else
  echo "note: $PROJECT is not a git repo; skipped parent .gitignore step"
fi

# 2) bridge folder + data + own git
mkdir -p "$BRIDGE/.data"
# attribution notice at the project root (Ferryman Source-Available License, section 5)
[ -f "$PROJECT/FERRYMAN.md" ] || printf '%s\n' '# Ferryman' '' 'This project uses Ferryman (https://github.com/estejosh/ferryman),' 'licensed under the Ferryman Source-Available License.' > "$PROJECT/FERRYMAN.md"
if [ ! -d "$BRIDGE/.git" ]; then
  git -C "$BRIDGE" init -q
  echo "git: initialized bridge sub-repo at $BRIDGE"
fi

# 3) bridge's own .gitignore (runtime state stays out of the sub-repo)
cat > "$BRIDGE/.gitignore" <<'EOF'
# Runtime state - never committed to the bridge sub-repo
.data/
*.log
bin/
target/
EOF

# 4) config
cat > "$BRIDGE/bridge.toml" <<EOF
# Ferryman nested bridge
endpoint = "http://127.0.0.1:$PORT"
project  = "$SLUG"
# All state lives under .data/ in this folder.
EOF

# 5) start helper (port baked in; override the binary with \$FERRYMAN_BIN)
cat > "$BRIDGE/start.sh" <<EOF
#!/usr/bin/env sh
set -eu
HERE="\$(CDPATH= cd "\$(dirname "\$0")" && pwd)"
BIN="\${FERRYMAN_BIN:-ferryman-server}"
exec "\$BIN" \\
  --database       "\$HERE/.data/bridge.db" \\
  --artifacts      "\$HERE/.data/artifacts" \\
  --workspace-root "\$HERE/.data/projects" \\
  --memory-root    "\$HERE/.data/bridge-memory" \\
  --recovery-root  "\$HERE/.data/recovery" \\
  --listen "127.0.0.1:$PORT"
EOF
chmod +x "$BRIDGE/start.sh"

# 6) readme
cat > "$BRIDGE/README.md" <<EOF
# Nested Ferryman bridge

Self-contained Ferryman bridge for the parent project. Its own git repo,
gitignored by the parent. Start: ./start.sh (needs ferryman-server on PATH
or \$FERRYMAN_BIN). API: http://127.0.0.1:$PORT. State under .data/.

See the Ferryman repo docs/NESTED_BRIDGE.md for the full model.
EOF

echo ""
echo "Nested bridge ready: $BRIDGE  (API http://127.0.0.1:$PORT)"
echo "Next: (cd \"$BRIDGE\" && ./start.sh)"
