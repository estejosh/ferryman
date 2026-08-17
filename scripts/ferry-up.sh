#!/usr/bin/env sh
# Get Ferryman current and this repository attached, in one command.
#
#   curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/ferry-up.sh | sh
#   ferry-up.sh                     # from a checkout
#
# # What this is for
#
# The first outside upgrade report said it plainly: there is no documented upgrade path
# for a channel-mode worker. `docs/UPGRADING.md` describes a SQLite server with a
# `/healthz` endpoint that does not exist in this mode, and `docs/UPDATES.md` describes
# an updater that does not apply. The agent had to read the source of
# `ferryman-channel` to convince itself its signing key would survive before it dared
# upgrade. A real user will not do that.
#
# So: one command, safe to run repeatedly, in any repository. It installs or updates
# `ferry`, attaches the repository if it is not attached, and then tells you where you
# stand - including the one fact a fleet actually needs, which is whether this machine
# is on the same build as the others.
#
# # What it will not do
#
# It does not touch your signing keys, your channel, or your work. Upgrading has never
# rotated a key - that is deliberate, and the reason is in `ferryman-channel`: rotating
# on upgrade would invalidate every signature that machine has already published. This
# script prints the key fingerprint before and after so you can see that for yourself
# rather than take it on faith.
set -eu

say()  { printf 'ferry-up: %s\n' "$1"; }
warn() { printf 'ferry-up: %s\n' "$1" >&2; }
die()  { printf 'ferry-up: %s\n' "$1" >&2; exit 1; }

EMAIL="${FERRYMAN_EMAIL:-}"
ENABLE=1
for arg in "$@"; do
  case "$arg" in
    --email=*) EMAIL="${arg#--email=}" ;;
    --no-enable) ENABLE=0 ;;
    --help|-h)
      cat <<'USAGE'
ferry-up: install or update ferry, attach this repository, and report status.

  --email=you@example.com   contact email for `ferry enable` (or set FERRYMAN_EMAIL)
  --no-enable               update the binary only; do not attach this repository

Safe to run twice. Never rotates a signing key.
USAGE
      exit 0 ;;
    *) die "unknown option: $arg (try --help)" ;;
  esac
done

# ---------------------------------------------------------------- before

# Recorded BEFORE anything changes, because "did my identity survive?" is the question
# an upgrade has to be able to answer, and it cannot be answered afterwards from memory.
BEFORE_VERSION="$(ferry --version 2>/dev/null || echo 'not installed')"
BEFORE_KEYS=""
if [ -d .ferryman/keys ]; then
  # Fingerprints only. The key never leaves the machine and must not appear in a log.
  if command -v sha256sum >/dev/null 2>&1; then
    BEFORE_KEYS="$(sha256sum .ferryman/keys/*.key 2>/dev/null | cut -c1-16 || true)"
  elif command -v shasum >/dev/null 2>&1; then
    BEFORE_KEYS="$(shasum -a 256 .ferryman/keys/*.key 2>/dev/null | cut -c1-16 || true)"
  fi
fi

say "before: $BEFORE_VERSION"

# ---------------------------------------------------------------- install

say 'installing or updating ferry...'
if command -v curl >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh
elif command -v wget >/dev/null 2>&1; then
  wget -qO- https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh
else
  die 'need curl or wget'
fi

command -v ferry >/dev/null 2>&1 || die 'ferry is still not on PATH; add the install directory to PATH and re-run'

AFTER_VERSION="$(ferry --version 2>&1)"
say "after:  $AFTER_VERSION"
if [ "$BEFORE_VERSION" = "$AFTER_VERSION" ] && [ "$BEFORE_VERSION" != 'not installed' ]; then
  # Not an error. Worth saying out loud, because the previous release reported an
  # identical version string before and after a day of changes, and "nothing appears to
  # have happened" was indistinguishable from "nothing happened".
  say 'the version and commit are unchanged, so this machine was already current'
fi

# ---------------------------------------------------------------- attach

if [ "$ENABLE" -eq 1 ]; then
  if [ -f .ferryman/bridge.toml ]; then
    say 'this repository is already attached; leaving its configuration alone'
  elif [ -z "$EMAIL" ]; then
    warn 'this repository is not attached, and no email was given'
    warn 'run:  ferry-up.sh --email=you@example.com   (or FERRYMAN_EMAIL=...)'
  else
    say "attaching this repository as $(basename "$(pwd)")..."
    # `enable` never prompts and is safe to run twice; it is built to be run by an agent
    # with nobody watching.
    ferry enable --email "$EMAIL"
  fi
fi

# ---------------------------------------------------------------- after

printf '\n'
if [ -f .ferryman/bridge.toml ]; then
  say 'where this repository stands:'
  ferry channel status 2>&1 || true
  printf '\n'
  ferry channel agents 2>&1 || true
  printf '\n'
  # The one that matters after an upgrade: every artifact should still read `Valid`. A
  # new binary that cannot verify signatures written by the old one is the failure this
  # whole check exists to catch.
  say 'signature check on every artifact (all should read Valid):'
  ferry channel tasks 2>&1 || true
  printf '\n'
fi

AFTER_KEYS=""
if [ -d .ferryman/keys ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    AFTER_KEYS="$(sha256sum .ferryman/keys/*.key 2>/dev/null | cut -c1-16 || true)"
  elif command -v shasum >/dev/null 2>&1; then
    AFTER_KEYS="$(shasum -a 256 .ferryman/keys/*.key 2>/dev/null | cut -c1-16 || true)"
  fi
fi
if [ -n "$BEFORE_KEYS" ]; then
  if [ "$BEFORE_KEYS" = "$AFTER_KEYS" ]; then
    say 'signing key unchanged (upgrading never rotates one)'
  else
    # Loud, and stop. A changed key means every artifact this machine has published
    # stops verifying for every other machine, and the roster will treat its next
    # registration as an impostor. Recovering is a restore, not a retry.
    warn ''
    warn '*** THE SIGNING KEY CHANGED. STOP. ***'
    warn 'Every artifact this machine published will now fail to verify elsewhere.'
    warn 'Restore .ferryman/keys from a backup before running anything else, and'
    warn 'please report this: https://github.com/estejosh/ferryman/issues'
    exit 1
  fi
fi

cat <<'NEXT'
next:
  ferry agent run        # this machine does work
  ferry agent review     # this machine judges results
  ferry soak             # a report to paste into an issue while we soak-test

Run this same command on every machine in the fleet, then compare the commit in
`ferry --version`. If they differ, they are not running the same Ferryman.
NEXT
