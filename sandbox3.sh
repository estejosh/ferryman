#!/usr/bin/env bash
# Claude Code keeps its state in two places, not one: the directory ~/.claude (which holds
# the OAuth credential) and the FILE ~/.claude.json beside it. Mounting only the directory
# gets you an engine that finds its credential and then refuses to start for want of its
# config. Both, or neither.
set -uo pipefail
MODE=${1:-dry}
IMG=ferryman-claude:local
H=/home/beastly/ferryman-comms/ferryman-ferryman
MOUNTS="/home/beastly/.claude:/root/.claude, /home/beastly/.claude.json:/root/.claude.json"

echo "=== does it work with both mounted ==="
podman run --rm \
  -v /home/beastly/.claude:/root/.claude \
  -v /home/beastly/.claude.json:/root/.claude.json \
  "$IMG" claude -p --dangerously-skip-permissions "Reply with one word: sandboxed" \
  < /dev/null 2>&1 | head -5 | sed 's/^/  /'

if [ "$MODE" != apply ]; then echo; echo "dry run; pass 'apply' to switch the ferryman worker over"; exit 0; fi

echo
echo "=== switch the ferryman project to the sandbox ==="
systemctl --user stop ferryman-agent@ferryman.service
python3 - "$H/.ferryman/agent.toml" "$MOUNTS" <<'PY'
import pathlib, sys
p, mounts = pathlib.Path(sys.argv[1]), sys.argv[2]
lines, saw_mounts = [], False
for line in p.read_text().splitlines():
    if line.startswith('sandbox ='):
        line = 'sandbox = "podman:ferryman-claude:local"'
    elif line.startswith('command ='):
        # Inside the container the CLI is on PATH; the host's absolute path is wrong there.
        line = 'command = "claude"'
    elif line.startswith('mounts =') or line.startswith('# mounts ='):
        line = f'mounts = "{mounts}"'
        saw_mounts = True
    lines.append(line)
if not saw_mounts:
    lines.append(f'mounts = "{mounts}"')
p.write_text('\n'.join(lines) + '\n')
PY
grep -E '^(command|args|sandbox|mounts|net) ' "$H/.ferryman/agent.toml" | sed 's/^/  /'

echo
echo "=== a task, through the sandbox ==="
systemctl --user start ferryman-agent@ferryman.service
sleep 2
/home/beastly/.local/bin/ferry channel order --workspace "$H" --agent beastlywsl \
  --id "sandboxed-$(date +%H%M%S)" \
  --task "Reply with one short line: which user you are running as (run: whoami), whether /workspace exists, and the ferry version if ferry is on PATH. Under 30 words." 2>&1 | head -1 | sed 's/^/  /'
echo "  worker: $(systemctl --user is-active ferryman-agent@ferryman.service)"
