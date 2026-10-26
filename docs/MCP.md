# MCP server (beta)

`ferry mcp serve` lets an AI app (Claude Desktop, Claude Code, Codex) join a Ferryman
project as an agent: catch up, take orders, talk to the fleet, ask you for approvals. It
runs on your machine over stdio. By default there is no network service, and it never
serves files. `--all-projects` serves every live project through one connection, and
`--http` is the opt-in network mode for cloud apps (see "Connect claude.ai").

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

The name after `--as` is only a name. The app can read and write nothing until that agent
is seated: its key must already be on this machine and listed on the project roster (the
dashboard, Agents, or `ferry channel join --as my-app` on this machine). Until then
`ferry_join` says so, every other tool refuses, and joining creates no key and no roster
entry. A seated agent starts at the Worker level; raise it with
`ferry access set <agent> member` (or `orchestrator`) like any other agent.

## All projects in one connection

```
ferry mcp serve --as my-app --all-projects
```

Serves every live, non-archived project in the ferry root, as `ferry agent run
--all-projects` counts them. Every tool takes a `project` argument. `ferry_join` with no
project lists the projects `my-app` is seated in and its level in each; the checks per
project are the same as in single-project mode (the level comes from that project's
master-signed grants). A project where the identity is not seated is not offered. With
only one seat the `project` argument may be left out. `--project` and `--all-projects`
do not combine.

## How Ferryman works, as the AI is told

The server instructions and `ferry_join` say it in a few lines: messages travel peer to
peer over iroh; the VPS relay is only a fallback; the AI never handles transport; and
folder layout changes are applied only from a master-signed fleet order (`ferry fleet
order migrate`), never on anyone else's say-so. No MCP tool changes the layout: a tool or
action that tries is refused with that explanation.

## Connect claude.ai

`ferry mcp serve --http` serves MCP over Streamable HTTP (protocol 2025-06-18, one `/mcp`
endpoint) with its own sign-in, so a cloud app can connect to this machine.

1. Start the server, behind TLS (see below), naming the public address. It serves every
   live project and takes no `--as`: each app gets an identity of its own.

   ```
   ferry mcp serve --http 127.0.0.1:8787 --public-url https://mcp.example.com
   ```

   It prints the connector URL, `https://mcp.example.com/mcp`.
2. Run `ferry mcp pair`. It prints a code that works once, for ten minutes.
3. In claude.ai, Settings, Connectors, add a custom connector and paste the connector URL.
4. The sign-in page opens on your server. It shows which host the app will return to and
   which projects it can be seated in. Enter the code. The page then says it is waiting for
   you.
5. Approve it on the machine that runs Ferryman: `ferry mcp apps approve <id>` (the page
   prints the id), or the dashboard, Teammates, Connected apps. The page continues by
   itself; if you do nothing it gives up after ten minutes.

### Each app is its own agent

An approved app gets a name (`claude-ai-<owner>`, `chatgpt-<owner>`, where the owner is the
master), a key of its own, a roster entry and a level the project's master signs. The key
lives in the server's state directory (`mcp-http/keys/`), not in the machine's keystore and
not in any project, so deleting it ends the identity. The level is **Worker** (read the
channel, ask you, write nothing into it) unless you choose **Member**
(`ferry mcp apps approve <id> --level member`). It is never Orchestrator, and never the
master. `--project a,b` seats it only in those projects; otherwise it is seated in every
live project whose master key is on this machine.

An app is approved only when a master-signed grant for its key exists. If the master key is
not on this machine, nothing is signed: the command prints the path of the app's signed
request. Copy that file to the machine that holds the master key and run
`ferry mcp apps approve --request <file>`. When the grant syncs back, the waiting login
continues without anyone touching this machine.

```
ferry mcp apps list                 # id, identity, level, state, projects, last used, calls
ferry mcp apps approve <id>         # Worker; --level member, --project a,b, --request <file>
ferry mcp apps deny <id>            # refuse a waiting app
ferry mcp apps revoke <id>          # end it
```

**Revoking** ends every token of the app at the server's next request (no restart), signs
its grant down to Worker with a master-signed revocation record beside it, and deletes its
key. Where the master key is not on this machine the command says which projects still need
signing; the app is dead here regardless. The dashboard's Connected apps card does the same in a
click. The app can also end its own session with the standard revocation endpoint
(`POST /revoke`, RFC 7009, advertised in the metadata); when that was its last session the
app is revoked as above, so a disconnect leaves no identity behind. Logging in again makes a
new identity.

**TLS.** `--http` speaks plain HTTP and must sit behind TLS. claude.ai only reaches an
https URL on a public name. Until the edge with automatic certificates exists, put a
reverse proxy or tunnel you control in front, forwarding the `Host` header unchanged. Do
not bind `--http` to a public address without it.

Apps register themselves (dynamic client registration) and only `https://claude.ai/api/mcp/auth_callback`
and loopback redirect addresses are accepted. Client ID metadata documents are not
supported yet.

## Tools

Six tools, about 760 tokens in all (the `project` argument adds a little in all-projects mode):

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
- Writes are refused while the machine is paused. Anything you send is refused if it looks
  like a secret; anything that comes back is redacted if it does (marked `redacted: true`).
- Posts are also refused if they look like code or a diff. Results are a git ref and
  a short note; the work stays in the repo.

## Updates

`ferry_join` and the catch-up header carry a short `update` field when the master has
signed an approval for a release newer than the one running. A public tag or release page
is never enough. `ferry_update check` says the same. `apply` (admin group, Orchestrator
only, refused while paused; a deliberate exception in ADR 0028) installs it through the existing self-update, but checks the
download against the SHA-256 for this platform that the master signed into the approval,
not a checksum file published beside the release; an approval that pins none is refused.
Agents are told to mention an update to you and not to update in the middle of an order.
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
