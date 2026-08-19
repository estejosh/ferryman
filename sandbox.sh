#!/usr/bin/env bash
# Sandbox the engine on the WSL side, at Linux prices.
#
# WSL2 is already a Linux VM, so podman inside it does not create a second one - the cost
# is the ordinary container cost, not the 1-2 GB a Windows-native container runtime pays
# to stand up a VM of its own.
#
# The image needs the agent CLI in it, because Ferryman runs `command` INSIDE the
# container. And the container needs the operator's credential directory mounted, or the
# CLI cannot authenticate - which is what the `mounts` setting added in b34b867 is for.
set -uo pipefail
MODE=${1:-dry}
H=/home/beastly/ferryman-comms/ferryman-ferryman
IMG=ferryman-claude:local

echo "=== tooling ==="
echo "  podman: $(podman --version 2>&1 | head -1)"
echo "  rootless ok: $(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo unknown)"
echo "  credential to mount: $(ls -d /home/beastly/.claude 2>/dev/null || echo MISSING)"

if [ "$MODE" != apply ]; then echo; echo "dry run; pass 'apply'"; exit 0; fi

echo
echo "=== build an image with the engine in it ==="
BUILD=$(mktemp -d)
cat > "$BUILD/Containerfile" <<'DOCKER'
FROM docker.io/library/node:22-slim
# git, because the agent works in a git worktree and will want to read its state.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# --allow-scripts matters: without the postinstall the package installs a stub that
# reports "native binary not installed", which is the exact failure that cost a day on
# the host install.
RUN npm install -g --allow-scripts=@anthropic-ai/claude-code @anthropic-ai/claude-code \
    && claude --version
WORKDIR /workspace
DOCKER
podman build -t "$IMG" -f "$BUILD/Containerfile" "$BUILD" 2>&1 | tail -6 | sed 's/^/  /'
rm -rf "$BUILD"
echo "  image: $(podman images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep ferryman-claude || echo 'NOT BUILT')"

echo
echo "=== does the engine authenticate inside it? ==="
podman run --rm \
  -v /home/beastly/.claude:/root/.claude \
  "$IMG" claude -p --dangerously-skip-permissions "Reply with one word: sandboxed" \
  < /dev/null 2>&1 | head -4 | sed 's/^/  /'
