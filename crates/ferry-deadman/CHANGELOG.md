# Changelog

All notable changes to **ferry-deadman** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-24

### Added
- `deadman.toml` config file — every setting is user-configurable per repo;
  CLI flags override individual values. Unknown keys warn instead of error.
- `init` — writes a fully commented `deadman.toml` template (`--force` to
  overwrite).
- Multiple successors — each `[[successors]]` entry gets its own
  independently sealed copy at `.deadman/sealed-<name>.tlock`; drills verify
  every copy decrypts to identical bytes; re-arming prunes copies of removed
  successors.
- Include globs — gitignore-style extra files archived beyond the bundle
  (`include = ["docs/**", "*.key"]`), on top of the conventional-secrets
  sweep (`include_secrets`, `.env*`, `*.key`, `*.pem`, `secrets/**`).
- Custom archive command — `archive.command` (shell line or argv vector)
  replaces the built-in bundle+tar.gz archiver; must write one file to
  `$FERRY_DEADMAN_OUT`. Recovery then proves integrity by hash.
- Heartbeat sources — `heartbeat.sources = ["manual", "any-cli"]`: opt into
  any ferry-deadman invocation counting as a heartbeat.
- Notify hooks — arbitrary shell commands on arm / re-arm / trigger with
  lifecycle env vars; failures are non-fatal warnings.
- `arm` — seal a git repo (`git bundle --all` + extra files → tar.gz →
  AES-256-GCM) to a future drand beacon round via tlock identity-based
  encryption.
- `heartbeat` — prove liveness: re-seal at a new future round, atomically
  replace the artifacts, prune the old ones.
- `status` — armed state, successors, next unlock round/time, last heartbeat,
  artifact health.
- `disarm` — remove `deadman.toml` and all local sealed artifacts.
- `test-trigger` — sandbox drill that waits out the unlock round, opens every
  successor copy, runs `git bundle verify`, clones the bundle and prints a
  PROOF block with matching sha256 records.
- Real timelock backend: drand quicknet (`bls-unchained-g1-rfc9380`,
  chain `52db9ba7…c84e971`) through the `tlock` crate; mirrors api.drand.sh +
  drand.cloudflare.com with automatic failover; any endpoint via `beacon`.
- Simulation backend: deterministic offline fake beacon (1 round/second) for
  tests and rehearsals; enforced by policy only, loudly labelled everywhere.
- Exit-code contract: 0 ok · 1 error · 2 bad input/not armed · 3 still locked.
- Broken-pipe-safe output (piping into `head` exits quietly).
- `#![forbid(unsafe_code)]`, clippy `-D warnings` clean, 48 offline tests,
  plus ignored-by-default live-network validation tests.
