#!/usr/bin/env bash
set -uo pipefail
H=/home/beastly/ferryman-comms/ferryman-ferryman
echo "=== log ==="
journalctl --user -u ferryman-agent@ferryman.service --since '5 minutes ago' --no-pager 2>/dev/null \
  | grep -E 'submitted|attempt|giving up' | tail -4 | sed 's/^/  /'
echo
echo "=== result ==="
r=$(find "$H/.ferryman/ferryman/tasks" -path '*sbx-*' -name 'result*.json' 2>/dev/null | head -1)
if [ -n "$r" ]; then
  python3 - "$r" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
p = d.get('payload') or {}
print("  signed by", d.get('signed_by'))
print(" ", str(p.get('output') or p)[:300])
PY
else
  echo "  none yet"
fi
