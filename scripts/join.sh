#!/bin/sh
# Ferryman: join a project from an invite code, on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/join.sh | sh -s -- <code>
#
# Installs ferry if it is not here (the same install.sh every release uses), then hands
# the code to `ferry team invite accept`, which does the rest: Syncthing, the channel,
# your identity. Everything it asks for, it asks on this screen.
set -eu
CODE="${1:-}"
if [ -z "$CODE" ]; then
  echo "usage: join.sh <invite code>" >&2
  exit 2
fi
FERRY="$(command -v ferry 2>/dev/null || true)"
if [ -z "$FERRY" ]; then
  for candidate in "$HOME/.local/bin/ferry" /usr/local/bin/ferry; do
    [ -x "$candidate" ] && FERRY="$candidate" && break
  done
fi
if [ -z "$FERRY" ]; then
  echo "Installing Ferryman..."
  curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh
  for candidate in "$HOME/.local/bin/ferry" /usr/local/bin/ferry; do
    [ -x "$candidate" ] && FERRY="$candidate" && break
  done
fi
if [ -z "$FERRY" ]; then
  echo "ferry was not installed; see the messages above" >&2
  exit 1
fi
# The accept step asks questions (email, password); it needs the terminal, not the pipe
# this script arrived through.
exec "$FERRY" team invite accept "$CODE" < /dev/tty
