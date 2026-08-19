#!/usr/bin/env bash
# Second attempt. `--allow-scripts` is npm 11+; node:22-slim ships npm 10, so the flag
# itself killed the build. It was only ever needed to work around the HOST's npm config
# (which blocks postinstall scripts and is why the host install pulled a stub) - a clean
# image has no such config, so a plain install runs the postinstall correctly.
set -uo pipefail
MODE=${1:-dry}
IMG=ferryman-claude:local

echo "=== build ==="
if [ "$MODE" != apply ]; then echo "  dry run; pass 'apply'"; exit 0; fi

BUILD=$(mktemp -d)
cat > "$BUILD/Containerfile" <<'DOCKER'
FROM docker.io/library/node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# The postinstall downloads a ~330 MB platform-native binary. It must run, or the package
# installs a stub that reports "native binary not installed" - the exact failure that cost
# a day on the host, where npm was configured to skip scripts.
RUN npm install -g --no-audit --no-fund @anthropic-ai/claude-code
RUN claude --version
WORKDIR /workspace
DOCKER
podman build -t "$IMG" -f "$BUILD/Containerfile" "$BUILD" 2>&1 | tail -8 | sed 's/^/  /'
rm -rf "$BUILD"

echo
echo "  image: $(podman images --format '{{.Repository}}:{{.Tag}}  {{.Size}}' 2>/dev/null | grep ferryman-claude || echo 'NOT BUILT')"

if podman image exists "$IMG" 2>/dev/null; then
  echo
  echo "=== does the engine authenticate inside it, with the credential mounted? ==="
  podman run --rm -v /home/beastly/.claude:/root/.claude "$IMG" \
    claude -p --dangerously-skip-permissions "Reply with one word: sandboxed" \
    < /dev/null 2>&1 | head -4 | sed 's/^/  /'
fi
