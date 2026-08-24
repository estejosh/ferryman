# Changelog

All notable changes to **ferry-deadman** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-24

### Added
- `arm` — seal a git repo (`git bundle --all` + optional secret files → tar.gz
  → AES-256-GCM) to a future drand beacon round via tlock identity-based
  encryption.
- `heartbeat` — prove liveness: re-seal at a new future round, atomically
  replace the artifact, prune the old one.
- `status` — armed state, next unlock round/time, last heartbeat, artifact
  health.
- `disarm` — remove `.deadman/` config and all local sealed artifacts.
- `test-trigger` — sandbox drill that waits out the unlock round, decrypts,
  runs `git bundle verify`, clones the bundle and prints a PROOF block with
  matching sha256 records.
- Real timelock backend: drand quicknet (`bls-unchained-g1-rfc9380`,
  chain `52db9ba7…c84e971`) through the `tlock` crate; mirrors api.drand.sh +
  drand.cloudflare.com with automatic failover; custom endpoint via `--beacon`.
- Simulation backend: deterministic offline fake beacon (1 round/second) for
  tests and rehearsals; enforced by policy only, loudly labelled everywhere.
- Exit-code contract: 0 ok · 1 error · 2 bad input/not armed · 3 still locked.
- `#![forbid(unsafe_code)]`, clippy `-D warnings` clean, 25+ offline tests,
  plus ignored-by-default live-network validation tests.
