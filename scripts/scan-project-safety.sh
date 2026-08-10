#!/usr/bin/env bash
# Read-only Ferryman attachment safety scan. Never reads token contents.
set -euo pipefail

WORKSPACE=
while (($#)); do
  case "$1" in
    --workspace) WORKSPACE=${2:?}; shift 2 ;;
    -h|--help)
      echo "Usage: scan-project-safety.sh --workspace /path/to/project"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
: "${WORKSPACE:?--workspace is required}"
WORKSPACE=$(cd "$WORKSPACE" && pwd -P)
ATTACHMENT="$WORKSPACE/.ferryman"
COMMUNICATIONS="$ATTACHMENT/ferryman"
FAILURES=0

result() {
  local level=$1 check=$2 detail=$3
  printf '%-4s  %-22s  %s\n' "$level" "$check" "$detail"
  [[ "$level" != FAIL ]] || FAILURES=$((FAILURES + 1))
}

result PASS workspace "$WORKSPACE"
if [[ -d "$WORKSPACE/.git" ]]; then
  main_remote=$(git -C "$WORKSPACE" config --get remote.origin.url || true)
  result PASS main_remote "${main_remote:-"(none)"}"
  if git -C "$WORKSPACE" check-ignore -q .ferryman; then
    result PASS main_ignore "/.ferryman/ is ignored"
  else
    result FAIL main_ignore "/.ferryman/ is not ignored"
  fi
else
  result WARN main_git "workspace is not a Git checkout"
fi

if [[ -d "$ATTACHMENT" ]]; then
  result PASS attachment "$ATTACHMENT"
  reparse=$(find "$ATTACHMENT" -path "$COMMUNICATIONS/.git" -prune -o -type l -print)
  if [[ -z "$reparse" ]]; then
    result PASS symlinks "no symlinks under .ferryman"
  else
    result FAIL symlinks "$reparse"
  fi
else
  result WARN attachment "no .ferryman attachment exists"
fi

if [[ -f "$ATTACHMENT/token" ]]; then
  result PASS outer_token "exists; contents were not read"
else
  result WARN outer_token "absent; hub registration may be deferred"
fi

if [[ -d "$COMMUNICATIONS/.git" ]]; then
  inner_remote=$(git -C "$COMMUNICATIONS" config --get remote.origin.url || true)
  scan_suffix="${FERRYMAN_CHANNEL_GIT_SUFFIX:--ferryman}"
  if [[ -z "$inner_remote" ]]; then
    # No upstream at all is the Syncthing-only channel, not a failure.
    result PASS inner_remote "(none; Syncthing-only)"
  elif [[ -z "${FERRYMAN_CHANNEL_GIT_OWNER:-}" ]]; then
    result FAIL inner_remote "$inner_remote (set FERRYMAN_CHANNEL_GIT_OWNER to pin the expected owner)"
  elif [[ "$inner_remote" =~ ^https://github\.com/"$FERRYMAN_CHANNEL_GIT_OWNER"/[A-Za-z0-9._-]+"$scan_suffix"(\.git)?$ ]]; then
    result PASS inner_remote "$inner_remote"
  else
    result FAIL inner_remote "$inner_remote"
  fi
  inner_status=$(git -C "$COMMUNICATIONS" status --porcelain --untracked-files=all)
  if [[ -z "$inner_status" ]]; then
    result PASS inner_status "portable repository is clean"
  else
    result WARN inner_status "$inner_status"
  fi
else
  result WARN inner_git "portable communications Git checkout is absent"
fi

for forbidden in token runtime; do
  if [[ -e "$COMMUNICATIONS/$forbidden" ]]; then
    result FAIL "inner_$forbidden" "forbidden portable path exists"
  else
    result PASS "inner_$forbidden" "absent"
  fi
done

if [[ -d "$COMMUNICATIONS" ]]; then
  suspicious=$(find "$COMMUNICATIONS" -path "$COMMUNICATIONS/.git" -prune -o -type f \
    \( -iname '.env' -o -iname '.env.*' -o -iname '*token*' -o -iname '*secret*' \
       -o -iname '*credential*' -o -iname '*password*' -o -iname '*.db' \
       -o -iname '*.sqlite' -o -iname '*.sqlite3' -o -iname '*.lock' \) -print)
  if [[ -z "$suspicious" ]]; then
    result PASS portable_names "no suspicious portable filenames"
  else
    result FAIL portable_names "$suspicious"
  fi
fi

STANDARD="$COMMUNICATIONS/STANDARD.toml"
if [[ -f "$STANDARD" ]]; then
  revision=$(sed -nE 's/^revision[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*$/\1/p' "$STANDARD" | head -n1)
  revision=${revision:-0}
  if ((revision == 2)); then
    result PASS standard_revision "revision 2"
  elif ((revision > 2)); then
    result FAIL standard_revision "project revision $revision is newer than this checkout"
  else
    result WARN standard_revision "revision $revision needs update to 2"
  fi
else
  result WARN standard_revision "STANDARD.toml is missing"
fi

((FAILURES == 0)) || exit 2
