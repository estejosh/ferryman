#!/bin/sh
# Ferryman one-click setup for macOS and Linux.
#
# A `.command` file is double-clickable in Finder, which is the point: the documented
# alternative was pasting `curl ... | sh` into a terminal, and a terminal is the thing
# this product promises its users they will not need.
#
# It does the whole job: installs ferry, points a folder at Ferryman, and opens the
# dashboard. After this the person is in a browser.
#
# On Linux, `chmod +x` it and run it from the file manager, or from a shell if you
# would rather.
set -eu

# Finder starts a .command in the user's home directory, not beside the file.
cd "$(dirname "$0")"

printf '\n  Ferryman setup\n  --------------\n\n'

printf '  Installing Ferryman...\n'
curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh

FERRY="$(command -v ferry || true)"
[ -n "$FERRY" ] || FERRY="$HOME/.local/bin/ferry"
if [ ! -x "$FERRY" ]; then
  printf '\n  Ferryman did not install. The message above says why.\n'
  printf '  If you are stuck: https://github.com/estejosh/ferryman/issues\n\n'
  exit 1
fi

# `ferry enable` refuses without a contact address (LICENSE section 3), so ask for it
# here rather than letting setup die on it. Found by running this file end to end: the
# double-click flow cannot pass a flag, so anything enable requires, this must collect.
printf '\n  Your email address. Ferryman registers it and sends nothing else -\n'
printf '  PRIVACY.md lists the entire payload.\n\n'
printf 'Email: '
read -r EMAIL || EMAIL=""
if [ -z "$EMAIL" ]; then
  printf '\n  An address is needed to enable a project. Nothing else is collected.\n\n'
  exit 1
fi

printf '\n  Which folder holds the project you want Ferryman to coordinate?\n'
printf '  Drag the folder onto this window and press Enter, or press Enter to use\n'
printf '  the folder this file is in.\n\n'
printf 'Folder: '
read -r PROJECT || PROJECT=""
[ -n "$PROJECT" ] || PROJECT="$(pwd)"
# Finder wraps a dragged path in quotes and escapes spaces; undo both.
PROJECT=$(printf '%s' "$PROJECT" | sed "s/^['\"]//; s/['\"]$//; s/\\\\ / /g")

if [ ! -d "$PROJECT" ]; then
  printf '\n  That folder does not exist: %s\n\n' "$PROJECT"
  exit 1
fi

printf '\n  Setting up %s\n' "$PROJECT"
cd "$PROJECT"
"$FERRY" enable --email "$EMAIL"

printf '\n  Opening the dashboard. Leave this window open while you use it -\n'
printf '  closing it stops Ferryman.\n\n'
exec "$FERRY" dashboard
