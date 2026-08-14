# Adversarial review: portable-authentication v2 (feat/portable-auth-v2)

**Review date:** 2026-08-13
**Reviewed revision:** `2be0ad4` (and the preceding `feat/portable-auth-v2` commits)
**Scope:** The v2 signed-envelope path only: `crates/ferryman-channel/src/portable_auth.rs`,
the v2 read/claim/ack/list/quarantine functions in `crates/ferryman-channel/src/lib.rs`,
`migration.rs`, the server v2 handlers in `crates/ferryman-server/src/lib.rs`, and the CLI
`migrate` subcommand. This is a line-by-line review, not a status/tests-only pass.

## Executive verdict

The v2 signing core is sound: canonical (RFC 8785) bytes, a kind-domain separator,
strict Ed25519 verification, grant lookup that binds `signer_id` to a key, and now
key-version and revocation enforcement. The migration tooling is careful about proof
of origin and identity preservation.

The one critical defect was in how the replay ledger was **applied**, not how it was
recorded. The ledger is populated by `claim_message_v2`, but the same check was also
wired into the boundary scanner, the reader, and the lister. A claimed message keeps
its nonce in the ledger *and* its file in the inbound directory, so every later
boundary scan misclassified the legitimate canonical copy as a replay and quarantined
it. That broke the server's claim→acknowledge sequence (the ack handler scans, then
fails to find the file it must bind to). Fixed in `2be0ad4` with a regression test.

**Recommendation:** proceed with the v2 rollout, but do not enable it fleet-wide until
F-02 (replay atomicity) is addressed and the v1/v2 acknowledgement identity
inconsistency (F-04) is settled.

## Priority summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-01 | Critical | Replay ledger applied at boundary/read/list as well as claim, so a claimed message was quarantined and the claim→ack sequence failed | Fixed (`2be0ad4`) |
| F-02 | Medium | Replay check-vs-record in `claim_message_v2` is not atomic (TOCTOU) | Open |
| F-03 | Low | `ReplayLedger::save` writes non-atomically; a crash can corrupt the ledger and fail all reads closed | Open |
| F-04 | Low | v2 acknowledgement `recipient` records the message target, not the acknowledging actor (inconsistent with v1) | Open |
| F-05 | Info | `message_digest` covers the signed envelope including its signature (matches the spec wording) | Accepted |
| F-06 | Info | Replay ledger is unbounded | Accepted (tracked) |

## F-01 (Critical) — Replay check over-applied, breaking claim→acknowledge

**Where:** `inspect_inbound_message_file`, `read_message_v2`, `list_messages_v2`,
and `claim_message_v2` in `crates/ferryman-channel/src/lib.rs`.

`claim_message_v2` records the message nonce in the replay ledger and then leaves the
message file at `communications/messages/<project>/<id>.json` (the canonical copy that
acknowledgements bind to). Three other code paths each independently interpreted
"nonce already in the ledger" as "replay" and reacted:

- `inspect_inbound_message_file` quarantined it,
- `read_message_v2` rejected it,
- `list_messages_v2` skipped it.

The server's handlers run `quarantine_invalid_inbound` at the top of every claim,
acknowledge, list, and read. So: claim succeeds (nonce recorded) → the next
`quarantine_invalid_inbound` quarantines the claimed file → the acknowledge handler,
which reads the file *after* the scan, fails to find it → HTTP 500. The claim→ack
lifecycle was broken for every v2 message.

**Fix:** replay enforcement now lives only at the consumption points — `claim_message_v2`
(and `acknowledge_v2` for acknowledgement nonces), where it is correctly ordered after
the idempotency-key claim-dir check. The boundary scanner, reader, and lister verify
signature/format/project only. Regression test:
`portable_auth_route_tests::claim_then_acknowledge_survives_a_boundary_scan`.

## F-02 (Medium) — Replay check-vs-record is not atomic

`claim_message_v2` loads the ledger, checks it, records the nonce, saves, then creates
the claim directory — with no lock. Two concurrent claims of two *different* messages
that reuse the same nonce can both pass the check before either records. The
idempotency-key claim directory still prevents double-execution of the *same* message,
but the cross-message replay window is real.

Exploitation requires a trusted signer to reuse a nonce (or an attacker with a captured
envelope and a new idempotency key to hit the window), so severity is bounded. Options:
serialize claim with a project lock, or store the accepted message digest in the ledger
so the boundary can distinguish "same message" from "reused nonce".

## F-03 (Low) — Replay ledger persistence is not crash-safe

`ReplayLedger::save` uses `std::fs::write`. A crash mid-write leaves a truncated JSON
ledger; the next load fails, and every read/claim fails closed. Use the existing
`atomic_json` (tmp + rename) helper.

## F-04 (Low) — v2 acknowledgement identity semantics differ from v1

v1 sets `acknowledgement.recipient = input.recipient` (the actor). v2 builds the
acknowledgement with `AcknowledgementV2::new(&message)`, which sets
`recipient = message.recipient` (the role/target). For a role-based acknowledger the v2
`recipient` field names the role, not the actor. The actor is still cryptographically
identified by the acknowledgement's `signer_id`, so this is not a forgery risk, but it
is a behavioral inconsistency that will confuse audit tooling. Decide and make both
formats consistent.

## F-05 (Info) — `message_digest` includes the signature

`AcknowledgementV2::new` digests `canonical_bytes(message)` without clearing the
`authentication.signature`, so the digest covers the signed envelope *including* its
signature. This matches the spec wording ("canonical signed message envelope") and is
self-consistent (the acknowledgement's own signature then binds that digest), so no
change is required — but it is easy to misread as "the bytes that were signed".

## F-06 (Info) — Unbounded replay ledger

The ledger only grows; retention/compaction is already tracked as follow-up work and is
acceptable for the short-lived-grant, rotation-as-revocation model in ADR 0009.

## What checked out clean

- Strict Ed25519 (`verify_strict`) — no signature malleability.
- Domain separator binds message vs acknowledgement kinds — no cross-type confusion.
- RFC 8785 canonicalization makes signatures deterministic across machines.
- `signer_id` is bound to the verifying key via the trust-store grant lookup.
- `key_version != 1` and `revoked` signers are now rejected in both verifiers.
- Claim idempotency (claim-dir check) is ordered *before* the replay check.
- Migration requires a delivery-attempt record as proof of origin, preserves
  id/idempotency key, and honors dry-run without touching disk.
