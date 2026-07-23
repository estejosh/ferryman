# Continuity, portability, and improvement

## Continuity pack

`POST /v1/projects/{project_id}/continuity-packs` writes a local content-addressed pack directory containing `manifest.json` and a compressed, XChaCha20-Poly1305 encrypted `bundle.obpack`. The payload contains the project manifest, agent profiles, approved and pending memory, consent history, policy snapshots, a decision timeline, safe job metadata, and all retained artifact blobs. Raw job inputs/results remain excluded unless a future retention policy explicitly includes them.

Every pack has a fresh data-encryption key wrapped by the configured recovery key, a bundle hash, per-artifact hashes/byte counts, provenance, and an authenticated manifest HMAC. Key material is never stored in the pack, workspace, SQLite database, or logs. Local development uses `FERRYMAN_RECOVERY_KEY_HEX`; production uses an operating-system keychain reference.

`POST /v1/projects/{project_id}/continuity-packs/{pack_hash}/recover` authenticates the manifest and ciphertext, validates all hashes, and creates a read-only recovery workspace plus a resume briefing. It never leases, resumes, or dispatches work. `POST /v1/projects/{project_id}/recovery-drill` performs that full loop and records a pass/fail event.

A recovery drill should create a fresh orchestrator/agent context, load the pack, inspect pending consents and candidates, and resume only after the orchestrator decides the next action.

## Storage order

1. Local disk is always preferred.
2. A configured network HDD is the next local-network recovery target.
3. Google Drive then MEGA may be used only when the local targets are unavailable and an approved policy/consent names that encrypted target.
4. A private Git repository is the final portability record for manifests, profiles, and recovery metadata—not an automatic destination for private artifacts.

The Bridge must never silently publish, share, or push a recovery record. Any outbound submission is a pending consent with an exact manifest hash, expiry, approver identity, target, files/content hashes, reason, redactions, and proposed Git branch/Drive folder. The orchestrator approves or rejects that immutable manifest before an adapter transmits anything.

## Improvement engine

The improvement engine is a proposal generator, not a self-modifying agent. It can compare project outcomes, failed jobs, policy friction, and recovery drills to create a proposed change manifest. The manifest includes:

- source project and evidence links;
- exact files or configuration paths affected;
- proposed diff/patch or artifact hashes;
- expected benefit and risk;
- destination repository/branch or recovery drive folder;
- required consent.

After approval, a future GitHub/Drive adapter may submit the exact manifest. The Bridge records the result and never expands the submission beyond the approved manifest.

`POST /v1/projects/{project_id}/outbound-submissions` now creates the immutable proposal/consent manifest for GitHub, Google Drive, MEGA, or private Git. It performs no delivery. GitHub delivery is constrained to a future draft-PR adapter; Drive/MEGA/private-Git delivery is constrained to opaque encrypted bundles. `POST /v1/projects/{project_id}/improvement-proposals` similarly produces only a reviewable proposal and its pending consent record—never a source-tree edit or external upload.
