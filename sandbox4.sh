#!/usr/bin/env bash
# Claude Code refuses --dangerously-skip-permissions when running as root, which is a
# sensible refusal and means the container must not run as root. The node images already
# ship a non-root `node` user (uid 1000), which also happens to match the host user's uid,
# so a bind-mounted credential is readable without any ownership juggling.
#
# Running the engine as non-root inside the container is a better posture anyway: the
# whole point of the sandbox is that the model-driven process is not privileged.
set -uo pipefail
MODE=${1:-dry}
IMG=ferryman-claude:local
H=/home/beastly/ferryman-comms/ferryman-ferryman
MOUNTS="/home/beastly/.claude:/home/node/.claude, /home/beastly/.claude.json:/home/node/.claude.json"

echo "=== host uid, which must match the container user for the mount to be readable ==="
id -u | sed 's/^/  host uid: /'

echo
echo "=== rebuild as non-root ==="
BUILD=$(mktemp -d)
cat > "$BUILD/Containerfile" <<'DOCKER'
FROM docker.io/library/node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g --no-audit --no-fund @anthropic-ai/claude-code && claude --version
# The engine refuses to skip permission prompts as root, and a sandbox that runs the
# model as root is not much of a sandbox. `node` is uid 1000, matching the host user, so
# the bind-mounted credential is readable without chown.
USER node
WORKDIR /workspace
DOCKER
podman build -t "$IMG" -f "$BUILD/Containerfile" "$BUILD" 2>&1 | tail -4 | sed 's/^/  /'
rm -rf "$BUILD"

echo
echo "=== does the engine run, authenticated, as a non-root user? ==="
podman run --rm \
  -v /home/beastly/.claude:/home/node/.claude \
  -v /home/beastly/.claude.json:/home/node/.claude.json \
  "$IMG" claude -p --dangerously-skip-permissions "Reply with one word: sandboxed" \
  < /dev/null 2>&1 | head -5 | sed 's/^/  /'

if [ "$MODE" != apply ]; then echo; echo "dry run; pass 'apply' to switch the worker over"; exit 0; fi

echo
echo "=== switch the ferryman worker to the sandbox ==="
systemctl --user stop ferryman-agent@ferryman.service
python3 - "$H/.ferryman/agent.toml" "$MOUNTS" <<'PY'
import pathlib, sys
p, mounts = pathlib.Path(sys.argv[1]), sys.argv[2]
lines, saw = [], False
for line in p.read_text().splitlines():
    if line.startswith('sandbox ='):
        line = 'sandbox = "podman:ferryman-claude:local"'
    elif line.startswith('command ='):
        line = 'command = "claude"'   # on PATH inside the image
    elif line.startswith('mounts =') or line.startswith('# mounts ='):
        line, saw = f'mounts = "{mounts}"', True
    lines.append(line)
if not saw:
    lines.append(f'mounts = "{mounts}"')
p.write_text('\n'.join(lines) + '\n')
PY
grep -E '^(command|args|sandbox|mounts) ' "$H/.ferryman/agent.toml" | sed 's/^/  /'

systemctl --user start ferryman-agent@ferryman.service
sleep 2
/home/beastly/.local/bin/ferry channel order --workspace "$H" --agent beastlywsl \
  --id "sandboxed-$(date +%H%M%S)" \
  --task "Reply with one short line: the user you run as (whoami), whether /workspace exists, and how many files are in it. Under 30 words." 2>&1 | head -1 | sed 's/^/  /'
echo "  worker: $(systemctl --user is-active ferryman-agent@ferryman.service)"
