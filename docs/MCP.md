# MCP server (beta)

`ferry mcp serve` lets an AI app (Claude Desktop, Claude Code, Codex) join a Ferryman
project as an agent: catch up, take orders, talk to the fleet, ask you for approvals. It
runs on your machine over stdio. There is no network service, and it never serves files.

Design and decisions: [ADR 0028](adr/0028-mcp-server.md).

## Connect an app

Open the dashboard, choose **Connect an AI app (beta)**, pick the agent name and project,
and copy the config. It holds no secrets. By hand:

```
claude mcp add ferryman -- ferry mcp serve --as my-app --project my-project
```

Claude Desktop (`claude_desktop_config.json`):

```json
{ "mcpServers": { "ferryman": { "command": "ferry",
  "args": ["mcp", "serve", "--as", "my-app", "--project", "my-project"] } } }
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.ferryman]
command = "ferry"
args = ["mcp", "serve", "--as", "my-app", "--project", "my-project"]
```

A new app starts at the Worker level. Raise it with `ferry access set <agent> member`
(or `orchestrator`) like any other agent.

## Tools

Six tools, about 630 tokens in all:

| Tool | What it does |
| --- | --- |
| `ferry_join` | who you are, your level, who is primary, whether an update exists |
| `ferry_catchup` | a short digest; pass the returned cursor to get only what changed |
| `ferry_orders` | list, show, claim, progress, submit, review |
| `ferry_talk` | read new messages, post to an agent |
| `ferry_primary` | status, standby, takeover, release |
| `ferry_ask_human` | raise a question for you, check the answer |

Optional groups: `--tools admin` adds `ferry_get`, `ferry_search`, `ferry_status` and
`ferry_update`; `--tools legacy` keeps the older read-only tools. `--read-only` serves
only those, and with no `--as` the server is read-only as before.

## What an agent may do

The same levels as the CLI (Worker, Member, Orchestrator).

- Workers read, and hand work in. They cannot post to the channel.
- Members claim, progress, submit and post. They cannot take over as primary.
- Orchestrators also review, take over as primary, and apply updates.
- Takeover works only when the primary has been silent past the quiet period, and not
  on a paused machine.
- An agent can ask you for an approval. It can never give one.
- Posts are refused if they look like a secret, code or a diff. Results are a git ref and
  a short note; the work stays in the repo.

## Updates

`ferry_join` and the catch-up header carry a short `update` field when a newer release
is available, and only if it is signed and approved (by the master on the channel, or a
verified public release). `ferry_update check` says the same; `apply` (admin group,
Orchestrator only) runs the existing verified self-update. Agents are told to mention
an update to you and not to update in the middle of an order. Set
`FERRYMAN_MCP_NO_UPDATE_CHECK=1` to skip the public lookup.

## Heavy orders (pending snifrig agreement)

Orders may carry `heavy` and `hints` (`cores`, `ram_gb`, `gpu_mem_gb`,
`expected_minutes`); they are shown, nothing more. A worker runs a heavy order through
`snifrig run` only when `snifrig_heavy = true` is set in `agent.toml`, snifrig is on
PATH, and it supports `can-i-start`. Off by default.

## Limits

Responses are capped (20 items, 4,000 characters, per-tool token caps) and long items
come back as `ferry://` resource links. A CI test (`mcp_budget`) holds the numbers in
`crates/ferryman-cli/tests/mcp_budget.json`. The server times out hung external MCP
servers after 30 seconds (120 for a call); set `FERRYMAN_MCP_TIMEOUT_SECS` to change it.
