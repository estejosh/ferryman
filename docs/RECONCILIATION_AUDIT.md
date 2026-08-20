# Ferryman — Reconciliation Audit

**Date:** 2026-08-10 · **Repo:** `github.com/estejosh/ferryman` · **Local:** `X:\ferryman`
**Audited against:** the kickoff brief, the live channel at `X:\hone-ferryman`, and the code.

---

## 0. Headline

The kickoff's central premise — *"GitHub is stale, significant unpushed local work exists including Syncthing"* — **is not what's on disk.**

| | Finding |
|---|---|
| Local `main` | `a7b4bf8`, dated 2026-07-26 |
| `origin/main` | `a7b4bf8` — **identical** |
| Ahead / behind | `0 / 0`, clean tree |
| Syncthing in `X:\ferryman` | **zero references** |

There is nothing to reconcile *between* local and git in this repo. They are the same commit.

The real divergence is between **two different implementations of Ferryman**:

- **`X:\ferryman`** — the polished Rust product. Well engineered, well documented, transport built on **MEGA**. Never run at scale.
- **`X:\hone-ferryman`** — the channel that has actually been running your fleet for a month. Bash and Python, transport on **Syncthing**, and carrying a month of hard-won operational lessons the Rust product does not encode.

The Rust product is the better substrate. The bash channel is the better teacher. Reconciliation means porting the lessons, not merging the code.

---

## 1. Branch audit

Four branches on `origin`. Two are already dead weight; two hold real work stranded behind a rename.

| Branch | Unique commits | Verdict |
|---|---|---|
| `feat/public-release-prep` | **0** | Fully merged. Safe to delete. |
| `fix/lease-renewal-and-hardening` | **0** | Fully merged. Safe to delete. |
| `feat/claude-agent-worker` | 1 (+270 lines) | Salvage — small. |
| `feat/telegram-approval-gate` | 5 (+1,214 lines) | **Salvage — valuable.** |

**Both salvageable branches predate the `orchestrator-*` → `ferryman-*` crate rename.** They touch `crates/orchestrator-core`, `crates/orchestrator-server`, `crates/orchestrator-worker-sdk` — paths that no longer exist on `main`. A plain rebase will conflict on every file. They need **porting**, not merging.

**`feat/telegram-approval-gate`** is the one worth the effort: an 831-line `telegram.rs` implementing an approval gate with inline Approve/Deny buttons, plus approval-gate TTL and store methods. That is human-in-the-loop approval from your phone — which is directly the AI-safety trust story the storefront is supposed to lead with. It should not be left to rot on a stale branch.

**`feat/claude-agent-worker`** adds `artifact()` upload to the worker SDK plus a working agent-worker example. Small, cheap to port, and an example is worth a lot on a public repo.

*No branches deleted or merged. Awaiting your go-ahead per instruction.*

---

## 2. The extraction seam — better than expected

The concern was that the message channel is welded to the HTTP server. **It isn't.**

`communications.rs` is 2,990 lines — the largest file in the project — and it currently lives inside the `ferryman-server` crate. But its actual coupling to that crate is:

| Coupling checked | Count |
|---|---|
| `crate::` references to server internals | **0** |
| `axum` (the web framework) | **0** |
| `rusqlite` / SQLite | **0** |
| `ferryman_core` (the job engine) | **0** |
| `reqwest` (HTTP client) | **0** |

Its entire dependency set is `std`, `anyhow`, `chrono`, `fs2`, `serde`, `serde_json`, `sha2`, `uuid`, `wait_timeout`. Nine ordinary crates, none of them a server.

The dependency runs **one way only**: `lib.rs` (the HTTP layer) calls into `communications::`. Never the reverse.

**So the extraction is a move, not a rewrite.** New `ferryman-channel` crate, move the file, rewire `communications::` → `ferryman_channel::` in `lib.rs`, add the dependency to the CLI. The server keeps its entire HTTP API. The CLI gains the ability to send and read messages with no daemon, no port and no tokens.

It also carries its own tests: **20 of the project's 30 tests live in `communications.rs`.** The channel is the best-tested part of the codebase, and extraction moves that coverage with it.

---

## 3. The MEGA removal is smaller *and* bigger than it looks

**Smaller,** because the transport layer is already trait-based and correctly abstracted:

```
trait MessageTransport          ← the transport contract
trait SharedHealthProbe         ← "is the shared folder actually syncing?"
SharedFolderTransport<P>        ← generic over the probe — transport-agnostic
MegaCmdProbe                    ← the only MEGA-specific piece
```

`SharedFolderTransport` doesn't know or care what syncs the folder — it just writes files into it. That is *exactly* the shape Syncthing needs. Swapping transports means writing a `SyncthingProbe` that implements `SharedHealthProbe` and changing which probe gets constructed. MEGA-specific code is confined to roughly 50 lines plus two error strings and some test fixtures.

**Bigger,** because MEGA is what drags Windows and WSL into the product. `MegaCmdProbe` shells out to `wsl.exe` to run `mega-sync`. That requirement propagates outward:

- `windows_to_wsl()` — a path-translation helper with **no other callers**. Dies with MEGA.
- `wsl_distribution` — threaded through `AppState`, a builder method, a **CLI flag**, and 12 call sites, existing solely to feed the MEGA probe.

Removing MEGA as a transport therefore deletes the entire WSL dependency from the product. For something meant for public consumption, that matters more than the transport swap itself — right now a stranger on Linux or macOS inherits a code path built around a Windows Subsystem for Linux distribution named "Ubuntu."

**MEGA is retained as backup.** This removal is strictly about MEGA as a *mail carrier*. As a once-daily one-way snapshot so a git wipeout can't kill a project, it stays, and gets documented as the recommended backup posture. The rule being enforced is the one your own `SYNCTHING.md` already states: **one live sync engine per folder.** Two carriers on one folder is what produced the conflict mess.

---

## 4. What the live channel knows that the product doesn't

Three lessons, each paid for with a real incident.

### 4.1 Reply expectation must be declared, not inferred

`hone-ferryman/PROTOCOL.md` records the failure: on **2026-07-15** a watcher decided from a message's *type label* that no reply was needed. It was wrong. It went silent. The other side waited. The silence lasted long enough that you had to relay messages by hand.

The fix your own fleet adopted: the sender states it outright — `reply_expected: true|false`. `true` means the receiver must answer. `false` means the thread ends cleanly: act if useful, do not reply. The type label stays as a human-readable decoration and never drives routing.

The Rust product has acknowledgement deadlines, which detect *"nobody consumed this."* That is a different state from *"consumed, and deliberately concluded."* It currently cannot distinguish them — which is precisely the ambiguity that caused the stall.

### 4.2 Verify before trusting a peer

The watcher contract in the live channel requires that an agent receiving a checkable claim — a bug, a root cause, a fix — verify it against the actual code before acting on it. Your logs show this catching real errors repeatedly:

> *"your diagnosis is real but incomplete"* · *"my first pass checked the wrong branch"* · *"CORRECTION: my empty-validators claim was WRONG"*

This is a protocol norm, not something code can enforce. But it is the single most differentiated thing about the project: **a fleet whose agents cross-check each other by design**, with a month of receipts. It belongs in `PROTOCOL.md` and on the front page.

### 4.3 Shared mutable files cannot survive sync — and this is the scaling wall

`FMN_LOG.md` is one file, rebuilt from all messages, by every machine. Two machines rebuild it independently; Syncthing sees two versions of one path and preserves both as `FMN_LOG.sync-conflict-<timestamp>-<device>.md`. **There are five of these on disk.** It is structural: it happens every time two machines are awake at once.

At two machines this is untidy. At the hundreds of machines Ferryman is meant to reach, it is fatal — and not merely as file clutter. **If an agent cannot reconstruct what happened and what it has been ordered to do, it stalls or acts on a stale order.** The log is not a nicety; it is how a fleet stays coherent.

The same defect applies to `SCOREBOARD.md`, `DECISIONS.md`, and every other shared mutable aggregate.

**Design requirement (see §5).** Related and already half-fixed: `.git` was added to `.stignore` around 2026-08-04, but for the preceding week Syncthing replicated a live `.git` directory between machines. The wreckage is still on disk — ten `index.sync-conflict-*`, ten `FETCH_HEAD.sync-conflict-*`, plus `COMMIT_EDITMSG` conflicts. Ferryman should generate a correct `.stignore` at join time so no adopter rediscovers this the way you did.

---

## 5. Log design for a fleet, not a pair

The requirement is that at hundreds of machines an agent can still answer *"what happened"* and *"what am I supposed to be doing"* — cheaply, and without trusting that some central file is current.

Principles:

1. **No two writers ever touch the same path.** Each machine appends only to its own shard (`log/<device>/<date>.jsonl`). A conflict becomes structurally impossible rather than merely unlikely — nothing to merge, so nothing to lose.
2. **Order is derived on read, not stored.** The canonical view is computed from the shards. Nobody has to win a write race to produce it.
3. **Causality survives clock skew.** Wall-clock timestamps across hundreds of machines will disagree. Threading (`in_reply_to`) and per-writer sequence numbers give a partial order that stays correct when the clocks don't.
4. **Cheap partial reads.** An agent joining or waking must be able to answer "what are my open orders?" without ingesting fleet-wide history. Per-reader watermarks plus per-recipient indexing.
5. **Append-only is the audit trail.** Immutable shards are evidence. This is also what makes the self-auditing safety story verifiable rather than merely claimed.

Detailed design to follow as `docs/LOG_DESIGN.md` before implementation.

---

## 6. Loose ends found along the way

- **`X:\ferryman` git writes fail from the device bridge**: `unable to unlink .git/index.lock: Operation not permitted`. Reads are fine. Commits and pushes will run through Desktop Commander's native shell instead.
- **CLI still defaults to `orchestrator.toml`** (`ferryman-cli/src/main.rs:22`) — a leftover from the crate rename. Rough edge for a public repo.
- **Stray order `0de822dafdfc`** confirmed at `X:\hone-ferryman\wisp\20260810-1613-order-ferryman-phase0-extract-and-podman.md`, created today 16:13Z. It orders an "extract from HONE and scaffold a new repo" that is obsolete — the repo exists, has four crates and a `v0.1.0-preview` tag. Left cancelled.
- **Test coverage is thin outside the channel**: 30 tests total, 20 of them in `communications.rs`. `ferryman-core` — the job and lease engine — has **one**.

---

## 7. Recommended order of work

1. Port `feat/telegram-approval-gate` and `feat/claude-agent-worker` onto the renamed crates; delete the two empty branches.
2. Extract `ferryman-channel`; wire the CLI for serverless send/watch/log.
3. Write `SyncthingProbe`; delete `MegaCmdProbe`, `windows_to_wsl`, and the `wsl_distribution` plumbing. Document MEGA as backup.
4. Implement the sharded log and the `reply_expected` field; generate `.stignore` at join.
5. `cargo build --release --workspace`; tests green.
6. Push as `estejosh`, per-repo PAT pin, report the delta from 2026-07-26.
7. Podman-first packaging plan.
8. Storefront polish — Shin approves public copy.

**Open question for you:** step 1 (branch porting) is a chunk of work on top of everything else. If the Telegram approval gate isn't something you want in the public v1, say so and I'll drop both branches and go straight to step 2.
