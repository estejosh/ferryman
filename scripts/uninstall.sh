#!/bin/sh
# Remove Ferryman from this machine.
#
# Deliberately conservative about three things, because getting any of them wrong
# is worse than leaving a file behind:
#
#   - Your OPERATOR IDENTITY is never deleted without --identity. It is sealed under a
#     password nothing else holds a copy of, and if you uninstall to reinstall you want
#     it to still be there afterwards. A disk cleaner deleting one is what taught us this.
#   - Your CHANNELS are never deleted. They are the coordination history for real work,
#     they live in your projects, and Syncthing would carry the deletion to every other
#     machine in the fleet.
#   - Nothing outside Ferryman's own directories is touched. Syncthing is not ours.
set -eu

say() { printf 'ferryman: %s\n' "$1"; }

WITH_IDENTITY=0
DRY=0
for arg in "$@"; do
  case "$arg" in
    --identity) WITH_IDENTITY=1 ;;
    --dry-run)  DRY=1 ;;
    -h|--help)
      cat <<'USAGE'
usage: uninstall.sh [--identity] [--dry-run]

  --identity   also remove your operator identity and its spare copy.
               There is no undo except your 24-word recovery phrase.
  --dry-run    list what would be removed, remove nothing.
USAGE
      exit 0 ;;
    *) say "unknown option: $arg (try --help)"; exit 2 ;;
  esac
done

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/ferryman"
REFUGE="$HOME/.ferryman"

targets=""
for bin in /usr/local/bin/ferry "$HOME/.local/bin/ferry" "${FERRYMAN_BINDIR:-}/ferry"; do
  [ -f "$bin" ] && targets="$targets $bin"
done
[ -d "$STATE" ] && targets="$targets $STATE"
if [ "$WITH_IDENTITY" -eq 1 ]; then
  [ -d "$REFUGE" ] && targets="$targets $REFUGE"
fi

if [ -z "$targets" ]; then
  say "nothing to remove - Ferryman is not installed here"
  exit 0
fi

for t in $targets; do
  if [ "$DRY" -eq 1 ]; then
    say "would remove $t"
  else
    rm -rf "$t"
    say "removed $t"
  fi
done

if [ "$WITH_IDENTITY" -eq 0 ] && [ -d "$REFUGE" ]; then
  say "kept your operator identity in $REFUGE - re-run with --identity to remove it too"
fi
say "your project channels (.ferryman inside each project) were not touched"
