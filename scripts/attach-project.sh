#!/usr/bin/env bash
# Framework-neutral Ferryman attachment for Linux/WSL.
# Tokens are read only for hub authentication and are never created or changed.
set -euo pipefail

WORKSPACE=
PROJECT=
SHARED_REMOTE=
GIT_REMOTE=
ADOPT_FROM=
HUB=http://127.0.0.1:8796
INTEGRATION_MODE=unmanaged
DRY_RUN=0
UPDATE_STANDARD=0
SKIP_SYNC=0
SKIP_HUB=0
PARTICIPANTS=()

usage() {
  cat <<'EOF'
Usage:
  attach-project.sh --workspace PATH --project ID --shared-remote FOLDER_ID \
    [--git-remote https://github.com/OWNER/ID-ferryman.git] [options]

The Git rung is optional; omit --git-remote for a Syncthing-only channel. When a Git
remote is supplied, FERRYMAN_CHANNEL_GIT_OWNER must name the account that owns the
channel repositories (FERRYMAN_CHANNEL_GIT_SUFFIX overrides the "-ferryman" suffix).

Options:
  --adopt-from PATH
  --hub URL
  --integration-mode unmanaged|single-agent|multi-agent
  --participant 'name|role|capability1,capability2'   repeatable
  --update-standard
  --dry-run
  --skip-sync-registration     (--skip-mega-registration is accepted as an alias)
  --skip-hub-registration
EOF
}

while (($#)); do
  case "$1" in
    --workspace) WORKSPACE=${2:?}; shift 2 ;;
    --project) PROJECT=${2:?}; shift 2 ;;
    --shared-remote) SHARED_REMOTE=${2:?}; shift 2 ;;
    --git-remote) GIT_REMOTE=${2:?}; shift 2 ;;
    --adopt-from) ADOPT_FROM=${2:?}; shift 2 ;;
    --hub) HUB=${2:?}; shift 2 ;;
    --integration-mode) INTEGRATION_MODE=${2:?}; shift 2 ;;
    --participant) PARTICIPANTS+=("${2:?}"); shift 2 ;;
    --update-standard) UPDATE_STANDARD=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-sync-registration|--skip-mega-registration) SKIP_SYNC=1; shift ;;
    --skip-hub-registration) SKIP_HUB=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

: "${WORKSPACE:?--workspace is required}"
: "${PROJECT:?--project is required}"
: "${SHARED_REMOTE:?--shared-remote is required}"
# --git-remote is optional: a Syncthing-only channel has no Git rung at all.
case "$INTEGRATION_MODE" in
  unmanaged|single-agent|multi-agent) ;;
  *) echo "invalid integration mode: $INTEGRATION_MODE" >&2; exit 2 ;;
esac
[[ "$PROJECT" != . && "$PROJECT" != .. && "$PROJECT" =~ ^[A-Za-z0-9._-]+$ ]] ||
  { echo "project ID is not path-safe" >&2; exit 2; }
# The shared remote is a Syncthing folder ID since the transport swap, not the MEGA
# path it used to be: require a path-safe identifier rather than a pinned path.
[[ -z "$SHARED_REMOTE" || ( "$SHARED_REMOTE" != . && "$SHARED_REMOTE" != .. &&
   "$SHARED_REMOTE" =~ ^[A-Za-z0-9._-]+$ ) ]] ||
  { echo "shared remote must be a path-safe Syncthing folder ID" >&2; exit 2; }

WORKSPACE=$(cd "$WORKSPACE" && pwd -P)
ATTACHMENT="$WORKSPACE/.ferryman"
COMMUNICATIONS="$ATTACHMENT/ferryman"
GIT_SUFFIX="${FERRYMAN_CHANNEL_GIT_SUFFIX:--ferryman}"
EXPECTED_NAME="$PROJECT$GIT_SUFFIX"
normalize_remote() { printf '%s' "${1%.git}" | tr '[:upper:]' '[:lower:]'; }
# Pinning the channel to a canonical location stops a tampered or mistaken mapping
# from redirecting a private channel somewhere else. Fail closed: a remote that cannot
# be pinned is refused rather than accepted unpinned.
if [[ -n "$GIT_REMOTE" ]]; then
  [[ -n "${FERRYMAN_CHANNEL_GIT_OWNER:-}" ]] ||
    { echo "a Git remote was supplied but FERRYMAN_CHANNEL_GIT_OWNER is not set; set it to the account that owns the channel repositories, or pass an empty --git-remote to run Syncthing-only" >&2; exit 2; }
  EXPECTED_REMOTE="https://github.com/$FERRYMAN_CHANNEL_GIT_OWNER/$EXPECTED_NAME"
  [[ "$(normalize_remote "$GIT_REMOTE")" == "$(normalize_remote "$EXPECTED_REMOTE")" ]] ||
    { echo "Git remote must be $EXPECTED_REMOTE.git" >&2; exit 2; }
fi

# bash 3.2 (still the system bash on macOS) has no associative arrays, so a
# newline-delimited list stands in for the set of names already seen.
SEEN_PARTICIPANTS=$'\nproject-inbox\n' 
for participant in "${PARTICIPANTS[@]}"; do
  IFS='|' read -r name role capabilities extra <<<"$participant"
  [[ -n "$name" && -n "$role" && -z "${extra:-}" ]] ||
    { echo "participant must use name|role|capability1,capability2" >&2; exit 2; }
  [[ "$name" != . && "$name" != .. && "$role" != . && "$role" != .. &&
     "$name" =~ ^[A-Za-z0-9._-]+$ && "$role" =~ ^[A-Za-z0-9._-]+$ ]] ||
    { echo "participant name and role must be path-safe" >&2; exit 2; }
  [[ "$SEEN_PARTICIPANTS" != *$'\n'"$name"$'\n'* ]] ||
    { echo "participant names must be unique and cannot replace project-inbox" >&2; exit 2; }
  SEEN_PARTICIPANTS+="$name"$'\n' 
done

ROUTE_SUMMARY='- project-inbox (role project; capabilities: messages.receive)'
for participant in "${PARTICIPANTS[@]}"; do
  IFS='|' read -r name role capabilities <<<"$participant"
  ROUTE_SUMMARY+=$'\n'"- $name (role $role; capabilities: ${capabilities:-none})"
done

run() {
  if ((DRY_RUN)); then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

write_new() {
  local path=$1 content=$2
  if [[ -e "$path" ]]; then
    [[ "$(cat "$path")" == "$content" ]] ||
      { echo "refusing to overwrite existing file: $path" >&2; exit 2; }
    echo "OK existing: $path"
  elif ((DRY_RUN)); then
    echo "DRY-RUN: create $path"
  else
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$content" >"$path"
  fi
}

write_managed() {
  local path=$1 content=$2
  if [[ -e "$path" ]] && ((UPDATE_STANDARD)); then
    if [[ "$(cat "$path")" == "$content" ]]; then
      echo "OK current standard: $path"
    elif ((DRY_RUN)); then
      echo "DRY-RUN: update Ferryman-managed standard file $path"
    else
      printf '%s\n' "$content" >"$path"
      echo "UPDATED standard file: $path"
    fi
  else
    write_new "$path" "$content"
  fi
}

MAIN_REMOTE_BEFORE=
if [[ -d "$WORKSPACE/.git" ]]; then
  MAIN_REMOTE_BEFORE=$(git -C "$WORKSPACE" remote -v || true)
fi

echo "Project:        $PROJECT"
echo "Workspace:      $WORKSPACE"
echo "Attachment:     $ATTACHMENT"
echo "Communications: $COMMUNICATIONS"
echo "Shared folder:  ${SHARED_REMOTE:-(none)}"
echo "Git:            ${GIT_REMOTE:-(none; Syncthing-only)}${GIT_REMOTE:+ (PRIVATE required)}"
echo "Integration:    $INTEGRATION_MODE"

if [[ -z "$GIT_REMOTE" ]]; then
  echo "No Git remote configured; the Git rung is unavailable for this project."
elif ((DRY_RUN)); then
  echo "DRY-RUN: verify GitHub name $FERRYMAN_CHANNEL_GIT_OWNER/$EXPECTED_NAME and visibility PRIVATE"
else
  command -v gh >/dev/null || { echo "gh is required" >&2; exit 2; }
  visibility=$(gh repo view "$FERRYMAN_CHANNEL_GIT_OWNER/$EXPECTED_NAME" \
    --json nameWithOwner,visibility \
    --jq '.nameWithOwner + "|" + .visibility')
  [[ "$visibility" == "$FERRYMAN_CHANNEL_GIT_OWNER/$EXPECTED_NAME|PRIVATE" ]] ||
    { echo "refusing mismatched or non-private GitHub repository" >&2; exit 2; }
fi

run mkdir -p "$ATTACHMENT"
if [[ ! -e "$COMMUNICATIONS" ]]; then
  if [[ -n "$ADOPT_FROM" ]]; then
    ADOPT_FROM=$(cd "$ADOPT_FROM" && pwd -P)
    [[ -d "$ADOPT_FROM/.git" ]] ||
      { echo "adoption source is not a Git checkout" >&2; exit 2; }
    adopt_remote=$(git -C "$ADOPT_FROM" config --get remote.origin.url)
    normalized_adopt_remote=$(normalize_remote "$adopt_remote")
    normalized_git_remote=$(normalize_remote "$GIT_REMOTE")
    [[ "$normalized_adopt_remote" == "$normalized_git_remote" ]] ||
      { echo "adoption source origin is unexpected" >&2; exit 2; }
    run git clone --no-hardlinks "$ADOPT_FROM" "$COMMUNICATIONS"
    if ((!DRY_RUN)); then
      adopt_head=$(git -C "$ADOPT_FROM" rev-parse HEAD)
      communications_head=$(git -C "$COMMUNICATIONS" rev-parse HEAD)
      [[ "$adopt_head" == "$communications_head" ]] ||
        { echo "adopted history verification failed" >&2; exit 2; }
      git -C "$COMMUNICATIONS" remote set-url origin "$GIT_REMOTE"
    fi
  elif [[ -n "$GIT_REMOTE" ]]; then
    run git clone "$GIT_REMOTE" "$COMMUNICATIONS"
  else
    # Syncthing-only: the channel is still its own repository (git remains the
    # archive of record), it just has no upstream to clone from or push to.
    run git init -q "$COMMUNICATIONS"
  fi
elif [[ -d "$COMMUNICATIONS/.git" ]]; then
  if ((!DRY_RUN)) && [[ -n "$GIT_REMOTE" ]]; then
    communications_remote=$(git -C "$COMMUNICATIONS" config --get remote.origin.url)
    normalized_communications_remote=$(normalize_remote "$communications_remote")
    normalized_git_remote=$(normalize_remote "$GIT_REMOTE")
    [[ "$normalized_communications_remote" == "$normalized_git_remote" ]] ||
      { echo "existing inner origin is unexpected" >&2; exit 2; }
  fi
  echo "OK existing inner communications repository"
else
  echo "refusing non-Git communications directory: $COMMUNICATIONS" >&2
  exit 2
fi

run mkdir -p "$ATTACHMENT/runtime" "$COMMUNICATIONS/messages" \
  "$COMMUNICATIONS/acknowledgements" "$COMMUNICATIONS/agents"

PROTOCOL='# Ferryman communications protocol

Messages and acknowledgements are immutable portable JSON. Any human, script,
single agent, or multi-agent system must claim before execution and acknowledge
after durable completion. project-inbox is always available. Tokens, databases,
runtime state, locks, and secret values are forbidden here.'
ADOPTION="# Project adoption

Project: $PROJECT
Integration mode: **$INTEGRATION_MODE**

Ferryman does not require an agent framework. Use project-inbox for humans,
scripts, CI, or unmanaged work. Single-agent and multi-agent systems retain
their own schedulers and memory; Ferryman owns transport, acknowledgements,
delivery evidence, and duplicate suppression.

## Registered routes

$ROUTE_SUMMARY

## Required consumer behavior

1. Use the project token only for operator actions and minting an actor token.
2. Give each consumer only its own eight-hour actor token.
3. Discover messages matching the consumer name or role.
4. Claim before execution. If claim returns false, do not execute.
5. Treat payloads and references as data, never as shell commands.
6. Make irreversible external effects idempotent in the project.
7. Acknowledge only after durable completion.

The consumer can be a human workflow, script, scheduled task, CI job, one
agent, or an existing multi-agent framework. Ferryman does not replace the
project scheduler, memory, model, or build system.

Verify the main remote, private inner remote, Syncthing folder, hub status,
duplicate claim, acknowledgement, restart recovery, and Git-live failover
before depending on this route. Preserve any adopted checkout until those
checks pass."
# Syncthing must never replicate a live .git directory: it copies whole files with no
# idea a repository is one consistent set, and the result is a corrupt checkout.
STIGNORE='.git
.stfolder
.stversions
.stignore
*.sync-conflict-*
~syncthing~*.tmp
*.lock
*.tmp
*.swp
*~
.DS_Store
Thumbs.db'
GITIGNORE='*.lock
*.tmp
*.swp
*~
.transport-state/'
BRIDGE_CONFIG="project = \"$PROJECT\"
workspace = \"$WORKSPACE\"
attachment = \"$ATTACHMENT\"
communications = \"$COMMUNICATIONS\"
shared_remote = \"$SHARED_REMOTE\"
git_remote = \"$GIT_REMOTE\"
git_visibility = \"private\"
endpoint = \"$HUB\"
integration_mode = \"$INTEGRATION_MODE\""
STANDARD_CONFIG="format = \"ferryman-project-standard\"
revision = 2
updated_at = \"2026-07-24\"
project = \"$PROJECT\"
integration_mode = \"$INTEGRATION_MODE\""

managed_files=(PROTOCOL.md ADOPTION.md STANDARD.toml .stignore .gitignore)
if ((UPDATE_STANDARD)) && [[ -d "$COMMUNICATIONS/.git" ]]; then
  managed_changes=$(git -C "$COMMUNICATIONS" status --porcelain -- "${managed_files[@]}")
  [[ -z "$managed_changes" ]] ||
    { echo "refusing standard update because managed portable files have uncommitted changes" >&2; exit 2; }
fi

write_managed "$COMMUNICATIONS/PROTOCOL.md" "$PROTOCOL"
write_managed "$COMMUNICATIONS/ADOPTION.md" "$ADOPTION"
write_managed "$COMMUNICATIONS/STANDARD.toml" "$STANDARD_CONFIG"
write_managed "$COMMUNICATIONS/.stignore" "$STIGNORE"
write_managed "$COMMUNICATIONS/.gitignore" "$GITIGNORE"
write_managed "$ATTACHMENT/standard.toml" "$STANDARD_CONFIG"
if ((UPDATE_STANDARD)) && [[ -f "$ATTACHMENT/bridge.toml" ]]; then
  # Same bash 3.2 constraint: no associative arrays. `expected_value` is the lookup
  # that `expected_bridge[$key]` used to be, and the existing file is compared a line
  # at a time as it is read - so no map is needed on either side.
  expected_value() {
    case "$1" in
      project)          printf '%s' "$PROJECT" ;;
      workspace)        printf '%s' "$WORKSPACE" ;;
      attachment)       printf '%s' "$ATTACHMENT" ;;
      communications)   printf '%s' "$COMMUNICATIONS" ;;
      shared_remote)    printf '%s' "$SHARED_REMOTE" ;;
      git_remote)       printf '%s' "$GIT_REMOTE" ;;
      git_visibility)   printf '%s' "private" ;;
      endpoint)         printf '%s' "$HUB" ;;
      integration_mode) printf '%s' "$INTEGRATION_MODE" ;;
      *)                return 1 ;;
    esac
  }
  saw_project=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*\"(.*)\"[[:space:]]*$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      [[ "$key" == project ]] && saw_project=1
      expected=$(expected_value "$key") ||
        { echo "existing bridge.toml does not match this update request: $key" >&2; exit 2; }
      [[ "$value" == "$expected" ]] ||
        { echo "existing bridge.toml does not match this update request: $key" >&2; exit 2; }
    else
      echo "existing bridge.toml contains an unsupported line: $line" >&2
      exit 2
    fi
  done <"$ATTACHMENT/bridge.toml"
  ((saw_project)) ||
    { echo "existing bridge.toml does not identify a project" >&2; exit 2; }
  write_managed "$ATTACHMENT/bridge.toml" "$BRIDGE_CONFIG"
else
  write_new "$ATTACHMENT/bridge.toml" "$BRIDGE_CONFIG"
fi

if ((DRY_RUN)); then
  echo "DRY-RUN: commit portable protocol/adoption/ignore metadata and push the current named branch"
else
  portable_files=("${managed_files[@]}")
  git -C "$COMMUNICATIONS" add -- "${portable_files[@]}"
  if [[ -n "$(git -C "$COMMUNICATIONS" status --porcelain -- "${portable_files[@]}")" ]]; then
    commit_message="Initialize Ferryman communications standard"
    if ((UPDATE_STANDARD)); then
      commit_message="Update Ferryman communications standard to revision 2"
    fi
    git -C "$COMMUNICATIONS" \
      -c user.name=Ferryman \
      -c user.email=ferryman@localhost \
      commit -m "$commit_message"
  fi
  if [[ -n "$GIT_REMOTE" ]]; then
    branch=$(git -C "$COMMUNICATIONS" symbolic-ref --quiet --short HEAD)
    [[ -n "$branch" ]] ||
      { echo "inner communications repository must use a named branch" >&2; exit 2; }
    remote_branch=$(git -C "$COMMUNICATIONS" ls-remote --heads origin "refs/heads/$branch")
    if [[ -n "$remote_branch" ]]; then
      git -C "$COMMUNICATIONS" pull --rebase --autostash origin "$branch"
    fi
    git -C "$COMMUNICATIONS" push -u origin "HEAD:$branch"
    echo "OK portable adoption standard committed and pushed"
  else
    echo "OK portable adoption standard committed (Syncthing-only channel; no remote to push)"
  fi
fi

if ! grep -qxF '/.ferryman/' "$WORKSPACE/.gitignore" 2>/dev/null; then
  if ((DRY_RUN)); then
    echo "DRY-RUN: append /.ferryman/ to $WORKSPACE/.gitignore"
  else
    printf '\n# Ferryman machine-local attachment\n/.ferryman/\n' >>"$WORKSPACE/.gitignore"
  fi
fi

# Register the channel with Syncthing, which is what carries it between machines.
# The folder id is $SHARED_REMOTE. fsWatcher is off with a 20s rescan on purpose:
# file watching is unreliable on network paths and on Windows drives seen through
# WSL, and a missed event is indistinguishable from a peer with nothing to say.
if ((!SKIP_SYNC)); then
  st_api="${SYNCTHING_API_BASE:-http://127.0.0.1:8384}"
  st_key="${SYNCTHING_API_KEY:-}"
  if [[ -z "$st_key" ]]; then
    for candidate in "${SYNCTHING_CONFIG_DIR:-}/config.xml" \
                     "$HOME/.local/state/syncthing/config.xml" \
                     "$HOME/.config/syncthing/config.xml"; do
      [[ -f "$candidate" ]] || continue
      st_key=$(sed -n 's:.*<apikey>\(.*\)</apikey>.*:\1:p' "$candidate" | head -1)
      [[ -n "$st_key" ]] && break
    done
  fi
  if ((DRY_RUN)); then
    echo "DRY-RUN: register Syncthing folder '$SHARED_REMOTE' -> $COMMUNICATIONS"
  elif [[ -z "$st_key" ]]; then
    echo "WARN  no Syncthing API key found; add folder '$SHARED_REMOTE' -> $COMMUNICATIONS by hand" >&2
    echo "      (set SYNCTHING_API_KEY, or SYNCTHING_CONFIG_DIR to where config.xml lives)" >&2
  elif curl -fsS -H "X-API-Key: $st_key" "$st_api/rest/config/folders/$SHARED_REMOTE" >/dev/null 2>&1; then
    echo "OK    Syncthing folder '$SHARED_REMOTE' already registered"
  else
    if curl -fsS -X POST -H "X-API-Key: $st_key" -H 'Content-Type: application/json' \
         -d "{\"id\":\"$SHARED_REMOTE\",\"label\":\"$SHARED_REMOTE\",\"path\":\"$COMMUNICATIONS\",\"type\":\"sendreceive\",\"fsWatcherEnabled\":false,\"rescanIntervalS\":20}" \
         "$st_api/rest/config/folders" >/dev/null; then
      echo "OK    registered Syncthing folder '$SHARED_REMOTE'"
      echo "      share it with the other machines in the fleet from the Syncthing UI"
    else
      echo "WARN  could not register '$SHARED_REMOTE' with Syncthing; add it by hand" >&2
    fi
  fi
fi

if ((!SKIP_HUB)); then
  TOKEN_PATH="$ATTACHMENT/token"
  if ((DRY_RUN)); then
    echo "DRY-RUN: register hub mapping using existing read-only token at $TOKEN_PATH"
  elif [[ -s "$TOKEN_PATH" ]]; then
    command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }
    routes='[{"name":"project-inbox","role":"project","capabilities":["messages.receive"]}]'
    for participant in "${PARTICIPANTS[@]}"; do
      IFS='|' read -r name role capabilities <<<"$participant"
      capabilities_json=$(jq -Rn --arg value "${capabilities:-}" \
        '$value | split(",") | map(select(length > 0))')
      routes=$(jq -c --arg name "$name" --arg role "$role" \
        --argjson capabilities "$capabilities_json" \
        '. + [{name:$name,role:$role,capabilities:$capabilities}]' <<<"$routes")
    done
    mapping=$(jq -n --arg workspace "$WORKSPACE" --arg attachment "$ATTACHMENT" \
      --arg communications "$COMMUNICATIONS" --arg shared "$SHARED_REMOTE" \
      --arg git "$GIT_REMOTE" --argjson agents "$routes" \
      '{workspace:$workspace,attachment:$attachment,communications:$communications,
        shared_remote:$shared,git_remote:$git,git_visibility:"private",agents:$agents}')
    token=$(<"$TOKEN_PATH")
    printf 'header = "Authorization: Bearer %s"\n' "$token" |
      curl --silent --show-error --fail --config - --request POST \
        --header 'Content-Type: application/json' --data-binary "$mapping" \
        "${HUB%/}/v1/projects/$PROJECT/communications" >/dev/null
    unset token
    echo "OK registered project communications mapping"
  else
    echo "WARNING: no existing token; hub mapping registration deferred" >&2
  fi
fi

if ((!DRY_RUN)) && [[ -d "$WORKSPACE/.git" ]]; then
  MAIN_REMOTE_AFTER=$(git -C "$WORKSPACE" remote -v || true)
  [[ "$MAIN_REMOTE_AFTER" == "$MAIN_REMOTE_BEFORE" ]] ||
    { echo "main project remote changed; stop and inspect" >&2; exit 2; }
fi
echo "Attachment setup complete. No token was created, changed, copied, or printed."
