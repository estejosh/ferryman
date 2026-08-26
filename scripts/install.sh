#!/usr/bin/env sh
# Ferryman installer, for people who do not want node.
#
#   curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh
#
# POSIX sh, not bash: this is piped into whatever /bin/sh happens to be, and a bashism
# here fails on exactly the minimal systems most likely to be running an agent.
#
# It verifies the checksum before installing. Piping a script from the internet into a
# shell already asks for trust; silently running an unverified binary afterwards would
# be asking twice.
set -eu

REPO="estejosh/ferryman"
VERSION="${FERRYMAN_VERSION:-latest}"
# Falls back to a user-writable directory rather than demanding sudo, because an agent
# running as an unprivileged account cannot answer a password prompt.
BINDIR="${FERRYMAN_BINDIR:-}"

say()  { printf 'ferryman: %s\n' "$1"; }
die()  { printf 'ferryman: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

need uname
need tar
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "curl or wget is required"
fi

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64)              target="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64|Linux-arm64) target="aarch64-unknown-linux-gnu" ;;
  Darwin-arm64)              target="aarch64-apple-darwin" ;;
  Darwin-x86_64)             target="x86_64-apple-darwin" ;;
  *)
    die "no prebuilt binary for $os-$arch. Build it instead, with Rust 1.97 or newer
(the codebase uses language features older toolchains do not have):
  cargo install --git https://github.com/$REPO ferryman-cli" ;;
esac

if [ "$VERSION" = "latest" ]; then
  url_base="https://github.com/$REPO/releases/latest/download"
else
  url_base="https://github.com/$REPO/releases/download/$VERSION"
fi
archive="ferry-$target.tar.gz"

tmp="$(mktemp -d)"
# Cleans up on failure too, so a half-downloaded archive is never left behind.
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $archive"
fetch "$url_base/$archive" "$tmp/$archive" || die "download failed - is there a release yet?"
fetch "$url_base/$archive.sha256" "$tmp/$archive.sha256" || die "could not fetch the checksum"

expected="$(cut -d' ' -f1 <"$tmp/$archive.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$archive" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)"
else
  die "sha256sum or shasum is required to verify the download"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch - refusing to install.
  expected $expected
  got      $actual
Do not work around this. Report it: https://github.com/$REPO/issues"

tar -xzf "$tmp/$archive" -C "$tmp"

if [ -z "$BINDIR" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    BINDIR=/usr/local/bin
  else
    BINDIR="$HOME/.local/bin"
  fi
fi
mkdir -p "$BINDIR"
install -m 0755 "$tmp/ferry-$target/ferry" "$BINDIR/ferry"

say "installed $("$BINDIR/ferry" --version) to $BINDIR/ferry"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) say "note: $BINDIR is not on your PATH - add it, or run $BINDIR/ferry directly" ;;
esac
say "next: cd your-project && ferry enable --email you@example.com"
