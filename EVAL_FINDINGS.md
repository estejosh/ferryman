# Orchestrator Bridge — Evaluation Findings (HONE pilot)

Maintained by Claw (Beastly) + Grouchly (peer PC) per orchestrator order `b8e0f6a2`.
Honest evaluation for Shin — not a thumbs-up. Updated as we go.

Environment: Beastly = Windows 11, native `cargo` (rustls, no openssl issue).
Grouchly = Linux, `/mnt/btcpc-storage/repos/orchestrator-bridge`.
Repo: `estejosh/orchestrator-bridge` (private, created 2026-07-17T21:20Z).

---

## WORKS
- **Builds clean, both platforms.** Grouchly: `cargo build --workspace` 0 errors ~31s (Linux).
  Beastly: native Windows build of `orchestrator-cli`/`orchestrator-key` compiled and ran (rustls
  stack, no openssl-sys perl problem that bites the HONE node build).
- **Approval gate is real (Grouchly, local, verified end-to-end).** Submitted a job
  `--requires-approval` → `pending_approval`; a running `mock_worker` polled but did **not** lease it;
  after `jobs approve`, it went `queued` → leased within ~1s → `succeeded`. The core safety property
  the pivot depends on holds when tested directly.
- **Worker SDK surface is small and clean** (`crates/orchestrator-worker-sdk/src/lib.rs`):
  `register` → `lease` → `event` → `complete`. Mock worker is ~35 lines. Good adapter starting point.

## DOESN'T WORK
- **`orchestrator-key bootstrap` then `verify` disagree — recovery key does NOT persist (Beastly, Windows).**
  `bootstrap` prints "Recovery key created securely" and exits 0; an immediately-following `verify` (same
  service/account defaults `OrchestratorBridge`/`recovery`) errors `No matching entry found in secure
  storage`. `cmdkey /list` shows no such credential.
  **Root cause (confirmed in `Cargo.lock`):** `keyring = "3.6"` is declared with **no backend feature**.
  Its locked deps are only `log` + `zeroize` — no `windows-native`/`apple-native`/`sync-secret-service`.
  keyring v3 with no store feature compiles the **mock (in-memory) keystore**: `set_password` succeeds
  into a per-process store that vanishes on exit, so a separate `verify` process finds nothing. This is
  almost certainly why Grouchly on Linux also fell back to `ORCHESTRATOR_RECOVERY_KEY_HEX` instead of the
  keychain path.
  **Fix:** in root `Cargo.toml`, `keyring = { version = "3.6", features = ["windows-native",
  "apple-native", "sync-secret-service"] }` (or per-platform), so the real OS keychain backend is linked.
  Until then the documented `keychain:...` reference path is non-functional; only the
  `ORCHESTRATOR_RECOVERY_KEY_HEX` dev fallback works. **This blocks `start-local.ps1`'s advertised
  "creates the recovery key in Windows Credential Manager" step.**

## COULD BE IMPROVED
- **`ORCHESTRATOR_RECOVERY_KEY_HEX` is an undocumented hard requirement for a bare server start**
  (Grouchly hit this on Linux): the server errors if neither the keychain ref nor the hex key is set,
  but the README quickstart (`cargo run -p orchestrator-server -- --database ... --artifacts ...`) doesn't
  mention it. New operators hit an opaque error on the very first command.
- **`cargo run -p orchestrator-cli -- ...` is ambiguous** — that crate ships 3 bins (`orchestrator-cli`,
  `orchestrator-key`, `orchestrator-updater`); cargo refuses without `--bin orchestrator-cli`. README
  shows the ambiguous form.
- **`jobs` has no `list` subcommand** (only `submit/get/approve/reject/tail`) — you must capture the job
  id from `submit`'s output; there's no way to enumerate jobs for a project afterward.
- **No `projects create` in the CLI.** The CLI top-level commands are
  `Init/Jobs/Workers/Agents/Memory/Artifacts/Consents/Continuity` — there is no `projects` command at
  all. Creating a project (step 2 of the pivot: "Create the HONE project") must be done by POSTing
  `/v1/projects` `{id,name,token}` by hand (curl/HTTP). An operator setting up the canonical HONE
  project has no first-class command for the single most important setup step.
- **`POST /v1/projects` has NO auth in non-production mode** (no `security:` in the OpenAPI for that
  route; README confirms admin token is required only under `--production`). So in the default local
  mode anyone who can reach `127.0.0.1:8787` can create a project and set its token. That's the reason
  binding to a non-loopback (Tailscale) address for the cross-machine test needs care — see the
  reachability note below. For the real HONE project, project creation + its operator/approval token is
  Shin's to perform; workers only ever get the short-lived worker-scoped token from `register`.

## WOULD MAKE IT MORE USEFUL (for running Claude/Codex agents + HONE go-live)
- **RECOMMENDATION (SDK, not applied): add `heartbeat()` and `artifact()` wrappers to `WorkerClient`.**
  The SDK wraps only `register`/`lease`/`event`/`complete`, but two more worker routes EXIST server-side:
  `POST /v1/projects/{p}/workers/{worker_id}/heartbeat` (server `lib.rs:221`) and
  `POST /v1/projects/{p}/jobs/{job_id}/artifacts` (octet-stream, `lib.rs:205`). `WorkerClient` never
  wrapped them, and `worker_id`/token are private, so an integrator must reimplement the protocol from
  the OpenAPI spec by hand. Per the read-only-base rule I did **not** patch the SDK — a proposed
  `artifact()` wrapper (and a matching `heartbeat()`) is preserved as a patch on Beastly
  (`~/orchestrator-bridge-base-edits-preserved/sdk-and-cargo.patch`, also `~/hone-bridge-agent-base-edits.patch`)
  for Shin/CODEOWNERS to apply if wanted. The HONE adapter instead implements all six worker calls
  directly against the HTTP API. **Gotcha the wrappers should hide:** the artifact route reads the worker
  id from an `x-orchestrator-worker-id` **header**, while `event`/`complete` read it from the JSON
  **body** (`worker_id`) — same identity, two transport conventions across sibling worker routes, easy
  to get wrong.
- **Artifacts are digest-named only.** Upload takes raw bytes and identifies the artifact by sha256;
  there's no filename/name field on the route. Fine, but means the caller must track which digest is
  which transcript out-of-band (e.g. in the completion result). The HONE adapter records the returned
  artifact id in the job result.
- **RECOMMENDATION (base, not applied): ship a real agent adapter as an in-tree example**, not just
  `mock_worker`. The whole pivot hinges on a worker that shells `claude -p ... --permission-mode auto`,
  streams its output as `worker.log`/`progress` events, captures its file changes as artifacts, and
  completes idempotently. Per the read-only-base rule the HONE adapter lives **outside** this repo (see
  below) rather than as an in-tree example; a reference `hone_agent_worker.rs` is preserved on Beastly
  (`~/orchestrator-bridge-base-edits-preserved/hone_agent_worker.rs`) if CODEOWNERS want to adopt a
  shipped primitive. What we built (spawn, timeout, capture, artifact-package) is exactly that shape.
