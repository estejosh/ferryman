# Ferryman roadmap

Local-first, provider-neutral, fail-closed. No mandatory central server; every
machine keeps its own authority, and portable files never grant it.

Cross-cutting decisions (2026-08-13):

- **Protect credentials, don't scrub them.** Secrets live in an OS keychain or a
  sealed credential store; agents request them *by reference*, and a worker child
  receives only the specific secrets its task is granted. (Replaces the
  scrub-on-subprocess approach; see Phase 0, item 4.)
- **Capability-model sandboxing.** A worker is not confined to "one folder" — it
  is granted exactly the folders, keys, and network/actions its task needs.
- **Per-agent memory.** Every agent has its own working memory; projects have
  shared memory. Both are first-class, not out-of-band.
- **Messenger-agnostic operator channel.** Telegram first, but behind an adapter
  so Signal / WhatsApp / Slack can plug in.
- **Channel folder convention:** `<project>-ferryman` (e.g. `hone-ferryman`,
  `brutus11-ferryman`). Create it if absent, reuse it if present, and quarantine
  anything unexpected into a `deprecated/` subfolder rather than refusing.

## Phase 0 — trust boundary (blocking production use)

1. **Signed v2 portable envelopes** (`F-01`). Implement `PORTABLE_AUTHENTICATION.md`
   as specified: Ed25519 canonical-JSON signatures, `trusted-signers.toml` grants,
   replay nonce ledger, fail-closed quarantine, and a dry-run v1→v2 migration.
   Until this ships, write access to the transport equals work-authoring authority.
2. **Distributed fencing / exactly-one consumer** (`F-05`). Lease-based: a signed
   claim carries a short-lived lease validated against the shared ledger, so two
   machines cannot both execute irreversible work. No full consensus.
3. **Worker sandbox (capability model)** (`F-03`). Grant folders/keys/actions
   per task; separate approval authority from execution. Multi-grant, not
   single-mount.
4. **Credential store.** OS-keychain-backed, reference-by-name, scoped grants to
   workers. Agents can access the keys their files need; nothing is scrubbed.

## Phase 1 — reliability

5. **Per-project transport isolation** (`F-06`): replace the single global
   blocking lock so one slow project can't freeze the fleet.
6. **Stable recovery key** in the default service (`F-07`): a restart must not
   make continuity packs unrecoverable.
7. **Power-loss durability + quotas/retention/pagination** (`F-09`): crash-safe
   writes and bounded history so the store never degrades unboundedly.
8. **Transactional unregister** (`F-08`): refuse unregister while the receiver
   has unclaimed inbound work; make attach/unregister recoverable.

## Phase 2 — operator and agent experience

9. **Telegram order surface (messenger-agnostic).** The operator can issue signed
   orders from the phone, not just approve/deny. See ADR 0008; generalise to a
   `ChannelAdapter` trait for other messengers.
10. **First-class memory tier.** Per-agent working memory + per-project shared
    memory (durable facts + a queryable knowledge graph + notes), recoverable by
    a replacement agent through one API.
11. **Build/version identity.** Embed the commit hash in `--version` and
    `/healthz`; bump the version on release. Stop shipping a stale `ferry` binary
    inside the synced channel folder (or `.stignore` it).
12. **Channel-mode upgrade path.** Document "how a worker moves to a newer build
    without losing its key" (currently only server mode is documented).
13. *(Done upstream — not this branch.)* `--agent` now resolves the OS hostname
    and fails instead of defaulting to the literal string `agent`.
14. **Attach script push guard.** Only `git push` the inner channel when an
    origin is configured; a Syncthing-only channel has none.
15. **Channel folder convention + quarantine.** Implement `<project>-ferryman`
    create-or-reuse with a `deprecated/` quarantine subfolder.
16. **CLI help text.** Fill in the blank descriptions (`consents`, `continuity`,
    `seats`, and friends).

## Non-goals

- No mandatory central server or hosted identity.
- No "distributed/exactly-once" claims until fencing (Phase 0.2) is real.
- No secrets or private prompts in portable files or memory — reference locations,
  never values.
