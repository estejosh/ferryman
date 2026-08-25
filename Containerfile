# Ferryman — OCI image. Podman-first (rootless, daemonless); also `docker build -f Containerfile .`
#
# One instance, many projects. /channels holds one subdirectory per project, each its own
# Syncthing folder shared with its own devices. A channel carries coordination and shared
# memory about a project - never the work itself, which lives in the project's own repo.
#
# FERRYMAN_SYNCTHING=bundled (default) runs Syncthing in here.
# FERRYMAN_SYNCTHING=external uses the host's, which is required when the host already
# syncs these folders: two live sync engines on one folder produce conflict loops.

# ---------------------------------------------------------------- build
# --platform=$BUILDPLATFORM pins this stage to the machine doing the building, then we
# CROSS-COMPILE to $TARGETARCH. The alternative - letting the builder emulate the target
# - once took six and a half hours for arm64 and published nothing, because emulated
# Rust compilation is roughly 10-20x slower. Cross-compiling takes minutes.
FROM --platform=$BUILDPLATFORM docker.io/library/rust:1.97-bookworm AS build
ARG TARGETARCH
ARG BUILDARCH

# The keyring crate reads secrets from the OS credential store; on Linux that is the
# D-Bus Secret Service, so libdbus headers are needed - and when cross-compiling they
# are needed for the TARGET architecture, not the builder's. dpkg's foreign-architecture
# support provides exactly that.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) rust_target=x86_64-unknown-linux-gnu;  deb_arch=amd64; cross_pkgs="" ;; \
      arm64) rust_target=aarch64-unknown-linux-gnu; deb_arch=arm64; cross_pkgs="gcc-aarch64-linux-gnu g++-aarch64-linux-gnu" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "$rust_target" > /rust-target; \
    dpkg --add-architecture "$deb_arch"; \
    apt-get update; \
    apt-get install -y --no-install-recommends pkg-config $cross_pkgs "libdbus-1-dev:$deb_arch"; \
    rm -rf /var/lib/apt/lists/*; \
    rustup target add "$rust_target"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# rusqlite bundles SQLite, so the C compiler must target the same architecture as Rust.
RUN set -eux; \
    rust_target="$(cat /rust-target)"; \
    if [ "$TARGETARCH" = "arm64" ]; then \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
      export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc; \
      export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++; \
      export PKG_CONFIG_ALLOW_CROSS=1; \
      export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig; \
      export PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig; \
    fi; \
    cargo build --release --target "$rust_target" -p ferryman-server -p ferryman-cli; \
    mkdir -p /out; \
    cp "target/$rust_target/release/ferryman-server" /out/; \
    cp "target/$rust_target/release/ferry" /out/

# ------------------------------------------------- vendor Syncthing (MPL-2.0)
# The stock upstream binary, unmodified, run as a subprocess and configured over its REST
# API. Ferryman never patches Syncthing source: modifying an MPL-2.0 file would oblige us
# to publish that file's changes. Wrap, don't fork.
# Runs on the builder and fetches the TARGET architecture's Syncthing release, so no
# emulation is needed here either.
FROM --platform=$BUILDPLATFORM docker.io/library/debian:bookworm-slim AS syncthing
ARG SYNCTHING_VERSION=2.1.2
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    base="https://github.com/syncthing/syncthing/releases/download/v${SYNCTHING_VERSION}"; \
    name="syncthing-linux-${TARGETARCH}-v${SYNCTHING_VERSION}"; \
    cd /tmp; \
    # Keep upstream's filename: the published checksum list refers to it by name.
    curl -fsSL "${base}/${name}.tar.gz" -o "${name}.tar.gz"; \
    if curl -fsSL "${base}/sha256sum.txt.asc" -o sums.asc; then \
      grep " ${name}.tar.gz\$" sums.asc | sed 's/^ *//' > sum.txt; \
      test -s sum.txt; \
      sha256sum -c sum.txt; \
    else \
      echo "WARNING: upstream checksum list unavailable; archive NOT verified" >&2; \
    fi; \
    mkdir -p /tmp/st && tar -xzf "${name}.tar.gz" -C /tmp/st --strip-components=1; \
    install -m0755 /tmp/st/syncthing /usr/local/bin/syncthing; \
    mkdir -p /usr/share/licenses/syncthing; \
    # MPL-2.0 obliges us to carry the licence text with the binary. Locate it rather
    # than assuming a path (1.x shipped LICENSE, 2.x ships LICENSE.txt) and FAIL the
    # build if it is missing - shipping the binary without it is not an option.
    lic=$(find /tmp/st -maxdepth 2 -iname 'LICENSE*' -type f | head -1); \
    test -n "$lic" || { echo "FATAL: no LICENSE in the Syncthing archive" >&2; exit 1; }; \
    cp "$lic" /usr/share/licenses/syncthing/LICENSE; \
    aut=$(find /tmp/st -maxdepth 2 -iname 'AUTHORS*' -type f | head -1); \
    [ -n "$aut" ] && cp "$aut" /usr/share/licenses/syncthing/AUTHORS || true

# ---------------------------------------------------------------- runtime
FROM docker.io/library/debian:bookworm-slim
LABEL org.opencontainers.image.title="Ferryman" \
      org.opencontainers.image.description="Private communication and shared memory for a fleet of AI agents, carried over Syncthing." \
      org.opencontainers.image.source="https://github.com/estejosh/ferryman" \
      org.opencontainers.image.licenses="LicenseRef-Ferryman-Source-Available"

# libdbus-1-3 is the runtime half of the keyring dependency above. A headless container
# usually has no Secret Service running, in which case Ferryman falls back to reading
# secrets from the environment - but the binary still has to link.
# git is a hard runtime dependency, not an optional extra: a channel is a private Git
# repository and the server runs `git init` when a project is attached.
# libdbus-1-3 is the runtime half of the keyring dependency in the build stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl tini git libdbus-1-3 \
 && rm -rf /var/lib/apt/lists/*

# Fixed non-root uid so the host can chown the channel directory to match.
RUN useradd --uid 10001 --system --create-home --shell /usr/sbin/nologin ferryman

COPY --from=build      /out/ferryman-server /usr/local/bin/
COPY --from=build      /out/ferry           /usr/local/bin/
COPY --from=syncthing  /usr/local/bin/syncthing            /usr/local/bin/
COPY --from=syncthing  /usr/share/licenses/syncthing/      /usr/share/licenses/syncthing/
COPY THIRD_PARTY.md    /usr/share/licenses/THIRD_PARTY.md
COPY LICENSE           /usr/share/licenses/ferryman/LICENSE
COPY scripts/container-entrypoint.sh /usr/local/bin/ferryman-entrypoint
RUN chmod +x /usr/local/bin/ferryman-entrypoint

# /channels is the synced parent: one subdirectory per project.
# /state is this machine's private index - a separate volume on purpose, because losing
# it must cost nothing. It rebuilds from the channels.
RUN mkdir -p /channels /state /syncthing \
 && chown -R ferryman:ferryman /channels /state /syncthing
VOLUME ["/channels", "/state"]

USER ferryman
# Without this the process runs from "/", which a non-root user cannot write to, and
# anything touching a relative path fails with a bare "Permission denied".
WORKDIR /home/ferryman
ENV FERRYMAN_SYNCTHING=bundled \
    FERRYMAN_CHANNELS_DIR=/channels \
    FERRYMAN_STATE_DIR=/state \
    FERRYMAN_CHANNEL_SUFFIX=-ferryman \
    SYNCTHING_HOME=/syncthing \
    SYNCTHING_API_BASE=http://127.0.0.1:8384 \
    GIT_TERMINAL_PROMPT=0

# 22000 sync (tcp+udp), 21027/udp discovery, 8384 Syncthing UI, 8787 Ferryman API.
EXPOSE 22000/tcp 22000/udp 21027/udp 8384/tcp 8787/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/ferryman-entrypoint", "healthcheck"]

# tini as PID 1: this image supervises Syncthing as a child, so zombies need reaping.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ferryman-entrypoint"]
CMD ["run"]
