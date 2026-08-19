#!/usr/bin/env bash
# "Not logged in" with the credential plainly mounted is the rootless-podman uid mapping:
# by default your host uid maps to a SUBUID inside the container, so the in-container
# `node` user (uid 1000) is not you, and cannot read a file owned by you.
#
# `--userns=keep-id` maps your uid to the same uid inside. Ferryman has no way to pass an
# extra runtime flag, and it should not need one for this - so it goes in podman's own
# configuration, where it belongs and where it applies to every container this user runs.
set -uo pipefail
MODE=${1:-dry}
IMG=ferryman-claude:local
H=/home/beastly/ferryman-comms/ferryman-ferryman
MOUNTS="/home/beastly/.claude:/home/node/.claude, /home/beastly/.claude.json:/home/node/.claude.json"

echo "=== prove keep-id is the missing piece ==="
podman run --rm --userns=keep-id \
  -v /home/beastly/.claude:/home/node/.claude \
  -v /home/beastly/.claude.json:/home/node/.claude.json \
  "$IMG" claude -p --dangerously-skip-permissions "Reply with one word: sandboxed" \
  < /dev/null 2>&1 | head -4 | sed 's/^/  /'

if [ "$MODE" != apply ]; then echo; echo "dry run; pass 'apply'"; exit 0; fi

echo
echo "=== make it podman's default for this user ==="
mkdir -p /home/beastly/.config/containers
CONF=/home/beastly/.config/containers/containers.conf
if ! grep -q 'userns *= *"keep-id"' "$CONF" 2>/dev/null; then
  cat >> "$CONF" <<'CONFEOF'

[containers]
# Rootless podman maps this user to a subuid inside the container by default, so a
# bind-mounted file owned by this user is unreadable to the process that needs it - which
# presents as "Not logged in" from an engine whose credential is plainly mounted.
# keep-id maps this uid to the same uid inside, which is what a bind mount assumes.
userns = "keep-id"
CONFEOF
fi
grep -A2 '\[containers\]' "$CONF" | sed 's/^/  /'

echo
echo "=== the same run, now without the explicit flag ==="
podman run --rm \
  -v /home/beastly/.claude:/home/node/.claude \
  -v /home/beastly/.claude.json:/home/node/.claude.json \
  "$IMG" claude -p --dangerously-skip-permissions "Reply with one word: sandboxed" \
  < /dev/null 2>&1 | head -4 | sed 's/^/  /'

echo
echo "=== switch the worker over ==="
systemctl --user stop ferryman-agent@ferryman.service
python3 - "$H/.ferryman/agent.toml" "$MOUNTS" <<'PY'
import pathlib, sys
p, mounts = pathlib.Path(sys.argv[1]), sys.argv[2]
lines, saw = [], False
for line in p.read_text().splitlines():
    if line.startswith('sandbox ='):
        line = 'sandbox = "podman:ferryman-claude:local"'
    elif line.startswith('command ='):
        line = 'command = "claude"'
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
  --id "sbx-$(date +%H%M%S)" \
  --task "Reply with one short line: the user you run as (whoami), whether /workspace exists, and how many entries are in it. Under 30 words." 2>&1 | head -1 | sed 's/^/  /'
echo "  worker: $(systemctl --user is-active ferryman-agent@ferryman.service)"
