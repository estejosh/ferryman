#!/bin/sh
# Ferryman container entrypoint.
#
# One instance, many projects. /channels is a parent directory; each subdirectory is one
# project's channel - its own Syncthing folder, shared with its own set of devices. A
# project's channel carries coordination and shared memory about that project, never the
# work itself.
#
#   /channels/hone/       -> Syncthing folder id "hone-ferryman"
#   /channels/ferryman/   -> Syncthing folder id "ferryman-ferryman"
#
# Two shapes, chosen by FERRYMAN_SYNCTHING:
#   bundled  (default) run Syncthing in here and register every project folder with it.
#   external           use the host's Syncthing. Required when the host already syncs
#                      these folders - two live sync engines on one folder conflict.
set -eu

CHANNELS_DIR="${FERRYMAN_CHANNELS_DIR:-/channels}"
STATE_DIR="${FERRYMAN_STATE_DIR:-/state}"
ST_HOME="${SYNCTHING_HOME:-/syncthing}"
ST_API="${SYNCTHING_API_BASE:-http://127.0.0.1:8384}"
MODE="${FERRYMAN_SYNCTHING:-bundled}"
SUFFIX="${FERRYMAN_CHANNEL_SUFFIX:--ferryman}"

log() { printf '%s ferryman: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

api() { # api <method> <path> [body]
    if [ -n "${3:-}" ]; then
        curl -fsS -X "$1" -H "X-API-Key: $SYNCTHING_API_KEY" \
             -H 'Content-Type: application/json' -d "$3" "$ST_API$2"
    else
        curl -fsS -X "$1" -H "X-API-Key: $SYNCTHING_API_KEY" "$ST_API$2"
    fi
}

# Syncthing must never replicate a live .git directory or a machine's private index.
# Copying a .git tree between machines mid-write corrupts it; that has already cost this
# project a week of confusing conflicts. Written once so an operator can extend it.
write_stignore() { # write_stignore <channel-dir>
    [ -f "$1/.stignore" ] && return 0
    cat > "$1/.stignore" <<'IGN'
// Written by Ferryman on first run. Safe to extend; do not remove these lines.
// A replicated .git directory corrupts: Syncthing copies whole files with no idea
// that a repository is one consistent set.
.git
.stfolder
.stversions
.stignore
*.sync-conflict-*
~syncthing~*.tmp
// Each machine's index is private and rebuildable from the channel. Never sync it.
index.db
index.db-wal
index.db-shm
IGN
    log "wrote $1/.stignore"
}

discover_projects() {
    [ -d "$CHANNELS_DIR" ] || die "channels directory $CHANNELS_DIR is not mounted"
    find "$CHANNELS_DIR" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%f\n' 2>/dev/null | sort
}

register_folder() { # register_folder <project>
    project="$1"
    dir="$CHANNELS_DIR/$project"
    folder_id="${project}${SUFFIX}"
    if api GET "/rest/config/folders/$folder_id" >/dev/null 2>&1; then
        log "project '$project' already registered as folder '$folder_id'"
        return 0
    fi
    log "registering project '$project' as Syncthing folder '$folder_id'"
    # fsWatcher off + a 20s rescan: file watching is unreliable on bind mounts and on
    # Windows drives seen through WSL, and a missed event looks exactly like a dead peer.
    api POST /rest/config/folders "$(cat <<JSON
{"id":"$folder_id","label":"$folder_id","path":"$dir","type":"sendreceive",
 "fsWatcherEnabled":false,"rescanIntervalS":20,
 "versioning":{"type":"simple","params":{"keep":"5"}}}
JSON
)" >/dev/null || log "WARNING: could not register '$folder_id'; add it in the Syncthing UI"
}

start_syncthing() {
    # Decide the API key ourselves rather than scraping it back out of config.xml.
    # Syncthing 2.x accepts --gui-apikey, so the key is known before it starts.
    if [ -z "${SYNCTHING_API_KEY:-}" ]; then
        if [ -f "$ST_HOME/.ferryman-apikey" ]; then
            SYNCTHING_API_KEY=$(cat "$ST_HOME/.ferryman-apikey")
        else
            SYNCTHING_API_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
            ( umask 077; printf '%s' "$SYNCTHING_API_KEY" > "$ST_HOME/.ferryman-apikey" )
        fi
        export SYNCTHING_API_KEY
    fi

    log "starting bundled Syncthing (home=$ST_HOME)"
    # --no-upgrade matters: this image ships a specific Syncthing build whose checksum
    # was verified at build time and whose licence is carried alongside it. A Syncthing
    # that silently replaced its own binary would undo both.
    # --no-restart so a crash kills the container and the restart policy handles it,
    # rather than Syncthing quietly respawning inside a container that looks healthy.
    STNODEFAULTFOLDER=1 syncthing serve \
        --home="$ST_HOME" \
        --no-browser \
        --no-restart \
        --no-upgrade \
        --no-port-probing \
        --gui-apikey="$SYNCTHING_API_KEY" \
        --gui-address="${SYNCTHING_GUI_ADDRESS:-0.0.0.0:8384}" &
    ST_PID=$!
    i=0
    while [ "$i" -lt 90 ]; do
        api GET /rest/system/ping >/dev/null 2>&1 && { log "Syncthing API up"; return 0; }
        kill -0 "$ST_PID" 2>/dev/null || die "Syncthing exited during startup"
        i=$((i + 1)); sleep 1
    done
    die "Syncthing did not become ready within 90s"
}

# Syncthing creates a "default" folder on a fresh config. In here that points at a
# path we never mounted, so it only ever reports errors. Remove it if it appears.
drop_default_folder() {
    api GET /rest/config/folders/default >/dev/null 2>&1 || return 0
    log "removing Syncthing's auto-created 'default' folder"
    api DELETE /rest/config/folders/default >/dev/null 2>&1 || true
}

resolve_api_key() {
    [ -n "${SYNCTHING_API_KEY:-}" ] && return 0
    if [ -f "$ST_HOME/.ferryman-apikey" ]; then
        SYNCTHING_API_KEY=$(cat "$ST_HOME/.ferryman-apikey")
        export SYNCTHING_API_KEY
        [ -n "$SYNCTHING_API_KEY" ] && return 0
    fi
    if [ -f "$ST_HOME/config.xml" ]; then
        SYNCTHING_API_KEY=$(sed -n 's:.*<apikey>\(.*\)</apikey>.*:\1:p' "$ST_HOME/config.xml" | head -1)
        export SYNCTHING_API_KEY
        [ -n "$SYNCTHING_API_KEY" ] && return 0
    fi
    [ "$MODE" = "external" ] && die "external mode needs SYNCTHING_API_KEY, or mount the host's $ST_HOME/config.xml read-only"
    die "could not resolve a Syncthing API key"
}

wait_for_api() {
    i=0
    while [ "$i" -lt 60 ]; do
        api GET /rest/system/ping >/dev/null 2>&1 && return 0
        i=$((i + 1)); sleep 1
    done
    die "Syncthing API at $ST_API did not answer within 60s"
}

case "${1:-run}" in
healthcheck)
    # Up but not syncing is not healthy: messages written then are stored, not delivered.
    [ -d "$CHANNELS_DIR" ] || exit 1
    resolve_api_key 2>/dev/null || exit 1
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $SYNCTHING_API_KEY" \
           "$ST_API/rest/system/ping" 2>/dev/null || echo 000)
    [ "$code" = "200" ] || exit 1
    exit 0
    ;;
shell) exec /bin/sh ;;
run)
    [ -d "$CHANNELS_DIR" ] || die "channels directory $CHANNELS_DIR is not mounted"
    [ -w "$CHANNELS_DIR" ] || die "$CHANNELS_DIR is not writable by uid $(id -u); chown it to 10001 on the host"
    mkdir -p "$STATE_DIR"

    projects=$(discover_projects)
    if [ -z "$projects" ]; then
        log "no projects found under $CHANNELS_DIR yet"
        log "create a directory per project, e.g. $CHANNELS_DIR/myproject, and restart"
    else
        log "projects: $(echo "$projects" | tr '\n' ' ')"
    fi

    case "$MODE" in
    bundled)
        for p in $projects; do write_stignore "$CHANNELS_DIR/$p"; done
        start_syncthing
        drop_default_folder
        for p in $projects; do register_folder "$p"; done
        device_id=$(api GET /rest/system/status 2>/dev/null | tr -d '\n ' \
                    | sed -n 's/.*"myID":"\([^"]*\)".*/\1/p')
        if [ -n "$device_id" ]; then
            log "this machine's Syncthing device id:"
            log "  $device_id"
            log "share it with the other machines in the fleet, and accept theirs"
        else
            log "WARNING: could not read this machine's device id from Syncthing"
        fi
        ;;
    external)
        log "using the Syncthing already running at $ST_API (not starting our own)"
        log "one live sync engine per folder: a second one here would fight the host's"
        resolve_api_key
        wait_for_api
        for p in $projects; do register_folder "$p"; done
        ;;
    *) die "FERRYMAN_SYNCTHING must be 'bundled' or 'external', got '$MODE'" ;;
    esac

    # The API refuses a non-loopback bind without an admin token, because anyone who
    # could reach the port would otherwise create a project with a token of their own
    # choosing. A published container port means binding 0.0.0.0, so mint a token on
    # first run rather than relaxing the check.
    if [ -z "${FERRYMAN_ADMIN_TOKEN:-}" ]; then
        token_file="$STATE_DIR/admin-token"
        if [ ! -s "$token_file" ]; then
            ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$token_file" )
            log "generated an admin token (first run); it is at $token_file inside the container"
            log "read it with: podman exec <container> cat /state/admin-token"
        fi
        FERRYMAN_ADMIN_TOKEN=$(cat "$token_file")
        export FERRYMAN_ADMIN_TOKEN
    fi

    shift 2>/dev/null || true
    log "starting ferryman-server (hub for $(echo "$projects" | grep -c . || echo 0) project(s))"
    ferryman-server \
        --database "$STATE_DIR/index.db" \
        --artifacts "$STATE_DIR/artifacts" \
        --workspace-root "$STATE_DIR/projects" \
        --memory-root "$STATE_DIR/memory" \
        --listen "${FERRYMAN_LISTEN:-0.0.0.0:8787}" "$@" &
    FM_PID=$!

    # If either half dies the container exits so the restart policy can act. Syncthing on
    # this project's own hub has been running as a bare process with no restart path; the
    # outage that caused is in its history. A container fixes that for free.
    wait -n 2>/dev/null || wait "$FM_PID"
    code=$?
    log "a supervised process exited (status $code); shutting down"
    kill "$FM_PID" 2>/dev/null || true
    [ -n "${ST_PID:-}" ] && kill "$ST_PID" 2>/dev/null || true
    exit "$code"
    ;;
*) exec "$@" ;;
esac
