# ADR 0028: A native MCP server for the channel

Status: proposed (beta), for the master (josh). Builds on 0014, 0017, 0021, 0023, 0024. Design only; no code in this PR.

## Context

Agents that join a fleet must be taught the file layout and the `ferry` CLI. MCP gives tools plus server instructions, so the teaching ships with the connection. Three needs:

1. **Join.** An agent in Claude Code, Claude Desktop or Codex learns who it is here and what to do, in one call.
2. **Continuity.** When the primary agent runs out of tokens, any agent on any machine learns in one call who is primary, what was decided, what is open and what it was told to do (ADR 0017, Marvin).
3. **Machine load.** Many agents doing heavy work make a machine crawl. Heavy work goes to the local snifrig queue when it exists.

### What exists today (audit, origin/main at v0.6.2 plus open PRs)

- `ferry mcp serve|list|call|add|remove|servers` already exists: `crates/ferryman-cli/src/mcp.rs` (631 lines) and `mcp_client.rs`. JSON-RPC over stdio, protocol 2024-11-05, 8 **read-only** tools (`channel_status`, `discover`, `list_tasks`, `get_task`, `read_memory`, `list_ledger`, `list_learnings`, `list_engines`) and a gateway that proxies external servers from `.ferryman/mcp.toml` under a `name_` prefix. Its header says write tools are deliberately absent ("an MCP connection is a stranger, not the operator"). The client has no timeouts (README known issue).
- `crates/ferryman-channel/src/discovery.rs`: an agent can carry capability `mcp` (`ferry channel join --mcp`) and `ferry channel agents --json` names the "MCP agent". A designation, not a server.
- The same mcp.rs is present unchanged on `feat/librarian` (#72), `desktop-app` (#91), `adr-desktop-control`, `hive-rescue`, `fleet-hardening`, `codex/orchestrator-soft-failover`. No branch holds a second or half-built MCP server.
- Not present: no ferryman MCP binary in `%LOCALAPPDATA%\Ferryman\bin` or `X:\ferry\bin`. Claude Desktop config on beastly lists `github` and `snifrig` (`snifrig-mcp.exe`) servers and nothing for Ferryman.

This ADR therefore **extends** `ferry mcp serve` instead of adding a crate or binary.

## Decision

`ferry mcp serve --as <agent> --project <id>` gains a small write-capable "agent surface" next to the old read tools. It is a stdio server launched by the AI app. It reads and writes channel files exactly as `ferry channel ...` does. No daemon, no network; messages work with nothing running.

The MCP is a thin facade. The CLI and the `ferryman-channel` library stay canonical: each tool calls the same library function as the matching CLI subcommand, so permission checks, signing and ledger entries are identical.

### Hard token requirements (enforced in CI)

| # | Requirement | Cap |
|---|---|---|
| T1 | Core `tools/list` JSON, serialised, estimated at chars/4 | <= 1,500 tokens (target 1,350) |
| T2 | Rare and admin tools are not in the default list. Opt-in groups `--tools admin` and `--tools legacy`, mentioned in one line of the instructions | 0 tokens by default |
| T3 | Server instructions | <= 250 tokens |
| T4 | Every read returns a compact summary by default; `detail:true` expands. Hard caps per response: 20 items and 4,000 chars, with `truncated:true` and a `next` cursor | per response |
| T5 | `since` cursors: repeat calls return only what is new. Opaque string (ledger seq + message marker) | - |
| T6 | `ferry_catchup` digest bounded; built from decisions, open orders, my assignments; never history | <= 800 tokens |
| T7 | Bodies (long messages, task files, results, decisions) come back as `resource_link` (`ferry://<project>/order/<id>`), fetched on demand with `resources/read`, never inlined | - |
| T8 | Byte-stable tool list for prompt caching: sorted, static description strings, no version, time or agent name inside definitions. Dynamic facts go in results | - |
| T9 | `structuredContent` plus `outputSchema`; the text `content` is a one-line summary, not a second copy of the JSON | - |
| T10 | CI token-budget test fails the build if T1, T3, T6 or any typical-response fixture exceeds its cap | see Testing |

### Per-tool token estimate (chars/4, to be re-measured by the CI test)

| Tool | Definition | Typical response | Cap |
|---|---|---|---|
| `ferry_join` | ~230 | ~350 | 600 |
| `ferry_catchup` | ~260 | ~500 | 800 |
| `ferry_orders` | ~340 | ~250 | 600 |
| `ferry_talk` | ~240 | ~300 | 600 |
| `ferry_primary` | ~200 | ~150 | 300 |
| `ferry_ask_human` | ~230 | ~120 | 300 |
| Core total | ~1,500 with envelope; target 1,350 | | |
| Instructions | ~170 | | 250 |
| Admin group (opt-in): `ferry_search`, `ferry_get`, `ferry_status` | ~600 | | not loaded by default |

Six core tools use an `action` enum rather than one tool per verb: fewer definitions cost fewer tokens.

## Tools

All tools are scoped to one project (from config, see Identity). Writes are signed with the caller's agent key by the same library calls the CLI uses.

### `ferry_join`
In: `{}`. Out: `{agent, project, machine, level: worker|member|orchestrator, granted: bool, primary: {name, age_s, alive}, alive: [{name, doing, age_s}] (max 10), mine_open: n, queue: {snifrig: bool}, next: "ferry_catchup"}`.
Wraps: `ferry channel join` (announce, idempotent), `channel agents --json`, `ferry access show`, `ferry agent status --json`, `ferry marvin list`. `granted:false` means the key is not seated yet; the reply says to ask the owner (dashboard, Agents).

### `ferry_catchup`
In: `{since?: cursor, detail?: bool}`. Out (<= 800 tokens): `{primary, brief: {objective, constraints (<=5 lines)}, decisions: [{id, line, at}] (<=8 newest), open: [{id, title, state, assignee}] (<=10), mine: [{id, title, state}], asks: [{id, state}], waiting_on_you: [...], links: [resource_link], next: cursor}`.
Wraps: `ferry marvin resume` (sections, truncated per section), `channel tasks`, ledger tail since cursor, `ferry agent pending`.

### `ferry_orders`
In: `{action: list|show|claim|progress|submit|review, id?, note?, ref?, verdict?: accept|changes, notes?}`. Out: compact order rows; `show` returns hints and a `resource_link` to the body.
Wraps: `channel work`, `channel tasks`, `channel claim`, `channel submit`, `channel review`. `progress` appends a signed progress line to the order's ledger entry (new small record, <= 2 KB per call). `submit` takes a reference to a hand-in (`ferry work hand-in`) plus a short summary, never work content. `review` is refused unless the caller may review under existing rules (not the author).

### `ferry_talk`
In: `{action: read|post, to?: name|"all", text?, since?: cursor, peek?: bool}`. Out: `read` gives unread messages for me since my marker, 300 chars each, `resource_link` for longer bodies, plus `next`. `post` gives `{id}`.
Wraps: `channel send`, `channel inbox --agent`. The marker is the existing acknowledge state (`communications acknowledge`); `read` acknowledges what it returned unless `peek`. `post` runs the secret-shape guard already used for order files and refuses key-, token- or `.env`-looking text, pointing to `ferry channel secret`. Telegram is never a target.

### `ferry_primary`
In: `{action: status|standby|takeover|release}`. Out: `{primary, age_s, state: alive|quiet|silent, rule}`.
Wraps: `ferry marvin list|take|release`, the orchestrator pointer (`tgmap.rs`), `pause`/`resume` state.

### `ferry_ask_human`
In: `{action: raise|status, title, recommendation, reasoning, id?}`. Out: `{id, state: pending|approved|rejected|sent_back, note?}`.
Wraps the existing approval gate: signed pending items (`ferry agent pending`), the dashboard approve or send back, `jobs approve|reject`. `raise` writes a signed request; the human's signed answer is read by `status`. The MCP can ask, never approve. Reasoning capped at 1,200 chars; secrets refused.

### Opt-in groups (not in the default list)
- `--tools admin`: `ferry_search` (paged text search over ledger, memory, learnings), `ferry_get` (by `ferry://` URI), `ferry_status`.
- `--tools legacy`: the 8 existing read tools, unchanged.
Neither group can mint grants, change access levels, sign releases, touch the vault or unpause. Those stay CLI and dashboard only.

## Identity

- One MCP process = one agent identity = one project, passed as `--as <agent> --project <id>` in the per-app config the dashboard writes.
- Key: the agent's own keystore entry (ADR 0015/0016) through the same unlock path the worker uses on that machine. The MCP never sees a passphrase. If locked it returns `locked` with a dashboard pointer and does nothing.
- Default name `<app>-<machine>` (for example `claude-desktop-beastly`) so two apps on one machine do not collide. The name is bound to a key by the roster (ADR 0021); the MCP cannot speak as another agent.
- Git: the MCP never runs `gh auth switch` and never handles a PAT. Repo pushes keep the estejosh identity with the per-repo PAT pin, done by the agent's normal git, not by the MCP.

## Permissions

Same checks as the CLI, because they are the same library calls:
- Level (ADR 0024) from the master-signed grant. Worker: reads the channel, writes only its hand-ins folder, so channel-writing tools return `denied: level worker`. Member: reads and writes the channel. Orchestrator: Member plus takeover.
- An agent never exceeds its owner's permissions per project (scoped grants, attenuation); the denial names the missing scope.
- No tool reads root `secrets/` or any secret. Secrets go through `ferry channel secret` only.
- Release signing is not exposed. Passphrases are never read, accepted or echoed.
- Work stays in the work repo. Tools accept references (hand-in id, commit sha) never work content. Channel writes are limited to messages, progress lines, asks, verdicts.

## Primary and takeover (existing rules only)

`status`: primary is the Marvin holder or named orchestrator; freshness is the age of its last page or presence. States: alive, quiet, silent (past the quiet period that `marvin take` already uses).
- Not silent: `standby`. Work assignments; poll `ferry_catchup`.
- Silent: `takeover` calls `marvin take`, which already refuses while the holder is heard from. Requires level Orchestrator (or soft-failover eligibility from docs/ORCHESTRATOR_CONTINUITY_PROPOSAL.md) on a machine that is not paused (the master switch, `ferry pause`/`resume`). A paused machine cannot take over.
- After takeover: one message "taking over from X", then `ferry_catchup`. The new primary writes its brief continuously via `ferry marvin brief` (CLI, not a tool, to save tokens; the instructions say so).
- Unchanged: no impersonation of the old primary, no credential copy, no spend outside existing budgets. Missing a permission means `ferry_ask_human` with a recommendation.
- The `ferry-deadman` crate is a sealed-archive release mechanism, not agent liveness; liveness here is Marvin's quiet period plus presence (open question 2).

## Approvals flow

Agent calls `ferry_ask_human raise` with title, recommendation, reasoning. The existing gate stores a signed pending item; dashboard and Telegram render it; the human approves, rejects or sends back with their signed key. The agent sees only verdict and note, via `status` or `ferry_catchup.asks`.

## Snifrig integration (proposal, pending agreement on the channel)

Additive order fields, covered by the order signature and ignored by older workers:

```json
{ "heavy": true,
  "hints": { "cores": 8, "ram_gb": 16, "gpu_mem_gb": 8, "expected_minutes": 45 } }
```

`heavy` defaults false; every hint is optional. When a claimed order is heavy and snifrig is present (`ferry_join.queue.snifrig`), the command runs as `snifrig run --name <order-id> -- <command>` after `snifrig_can_i_start` with the hints; progress via `snifrig_queue_status` and `snifrig_queue_wait`. Otherwise it runs directly as today. `ferry_orders show` reports `run_via: snifrig|direct`. Snifrig only wraps process start; no work content moves. Nothing is built until the snifrig side confirms field names and `can_i_start` semantics.

## Server instructions (draft, ~170 tokens)

```
Ferryman channel. Files are the channel; nothing needs to be running.
1. Call ferry_join first, then ferry_catchup. Do not read full history or the comms folder.
2. ferry_orders: claim, report progress, submit, review. ferry_talk: read only what is new.
3. Heavy orders: run through this machine's queue (snifrig) when present.
4. Do work in the work repo; commit and push it there. Never put work, code or files in the channel.
5. Never send secrets in messages. Use the vault flow (ferry channel secret).
6. If the primary is silent, ferry_primary status and follow its rule. Need a human: ferry_ask_human with a recommendation.
```

## Beta label

`serverInfo.version` carries `-beta`; `ferry_join` output starts "Ferryman MCP (beta)"; docs and the dashboard card say Beta. `--read-only` restores the old read-only behaviour.

## Dashboard install (non-technical)

Dashboard, Settings, "Connect an AI app". One button or one copy-paste per app; no token or passphrase ever goes in the config. The dashboard also registers the agent (`channel expect`) and sets its level (default Member; "work only" sets Worker).
- Claude Desktop: "Add to Claude Desktop" merges this into `claude_desktop_config.json` (or shows it to copy):
  `{"mcpServers":{"ferryman":{"command":"<ferry path>","args":["mcp","serve","--as","claude-desktop-<machine>","--project","<id>"]}}}`
- Claude Code: `claude mcp add ferryman -- <ferry path> mcp serve --as claude-code-<machine> --project <id>`
- Codex, `~/.codex/config.toml`: `[mcp_servers.ferryman]` with the same `command` and `args`.

## Testing plan

1. Unit per tool against a temp channel fixture (mcp.rs test style): schemas, errors, caps, cursors, truncation.
2. Permission matrix: Worker, Member, Orchestrator across every write tool; attenuation; paused machine cannot take over; locked keystore.
3. Safety: secret-shape refusal in talk and ask; no tool reads `secrets/`; no tool accepts work content.
4. Continuity: primary silent, takeover, catch-up digest matches `marvin resume` within caps; second agent cannot take while the first is alive.
5. Heavy path with a fake `snifrig` shim: heavy runs via it, absent runs direct, hints validated.
6. Token-budget test in CI (`mcp_budget`): fails if core `tools/list` > 1,500 estimated tokens, instructions > 250, catch-up on a busy fixture (200 ledger entries, 40 open orders) > 800, any typical response over its cap, or `tools/list` bytes differ between two runs with different time and agent. A committed `mcp_budget.json` snapshot makes growth visible in review.
7. E2E: scripted JSON-RPC session between two temp agents (initialize, join, catchup, claim, submit, talk), then a real Claude Code session on beastly.
8. Client smoke: Claude Desktop, Claude Code, Codex (initialize, tools/list, one call).

## Consequences

- One connection teaches layout and CLI; no per-project prompt.
- `ferry mcp serve` stops being read-only by design; the rule becomes "the agent's own key, capped by its grant"; `--read-only` keeps the old stance.
- New small records (progress lines, ask files) and optional `heavy`/`hints` order fields.
- Push notifications for new messages are skipped: polling with `since` costs fewer tokens.
