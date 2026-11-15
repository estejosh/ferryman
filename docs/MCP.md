# MCP server (beta)

`ferry mcp serve` lets an AI app (Claude Desktop, Claude Code, Codex) join a Ferryman
project as an agent: catch up, take orders, talk to the fleet, ask you for approvals. It
runs on your machine over stdio. By default there is no network service, and it never
serves files. `--all-projects` serves every live project through one connection, and
`--http` is the opt-in network mode for cloud apps (see "Connect claude.ai").

Design and decisions: [ADR 0028](adr/0028-mcp-server.md).

## Connect an app

One command per client, then restart it. Nothing to read, nothing to seat first:

```
ferry mcp setup --client codex            # or claude-code, claude-desktop, cursor
ferry mcp setup --client codex --print    # show what it would write, and where
```

It adds Ferryman to the client's own config (merged: other servers and settings stay, a
backup of the old file is kept the first time), with this program's absolute path and
`FERRYMAN_ROOT`, and prints the one line to restart. Written by hand it is just:

```toml
# ~/.codex/config.toml
[mcp_servers.ferryman]
command = "/path/to/ferry"
args = ["mcp", "serve"]
[mcp_servers.ferryman.env]
FERRYMAN_ROOT = "/path/to/ferry-root"
```

With no flags, `ferry mcp serve` makes the app an identity of its own, `<client>-<machine>`
(for example `codex-grouchly`; the client says its name when it connects), keeps its key
in the machine keystore, and seats it as a **Worker** in every live project this machine
serves. A Worker needs no approval from the master. It is never the master identity, and
Member or Orchestrator only ever come from the master (`ferry access set <agent> member`).
`--project` or `--workspace` limits it to one project; `--as <name>` speaks as a named
agent instead, and an `--as` name nobody has seated is seated as a Worker rather than refused.

The dashboard, **Connect an AI app (beta)**, shows the same config.

## All projects in one connection

```
ferry mcp serve --all-projects
```

This is the default whenever no `--project` or `--workspace` is given. It serves every live, non-archived project in the ferry root, as `ferry agent run
--all-projects` counts them. Every tool takes a `project` argument. `ferry_join` with no
project lists the projects `my-app` is seated in and its level in each; the checks per
project are the same as in single-project mode (the level comes from that project's
master-signed grants). A project where the identity is not seated is not offered. With
only one seat the `project` argument may be left out. `--project` and `--all-projects`
do not combine.

## The guide the AI is given

One short guide (under 650 tokens) is the server instructions, the `ferry_help` tool, and
the first `ferry_join` reply. It says what Ferryman is, what each level may do, the loop
(join, catch up, list, claim, work in the work repo `ferry_orders show` names, commit,
submit with the commit as `ref`, wait for review), how to give work, ask the human and
message an agent, and the words: primary, seat, worker/member/orchestrator, swarm, order,
hand-in. Nothing in it needs a command line except what it tells the human to do. It
also says that messages travel peer to peer over iroh with a relay as fallback, and that
folder layout changes are applied only from a master-signed fleet order (`ferry fleet
order migrate`), never on anyone else's say-so. No MCP tool changes the layout: a tool or
action that tries is refused with that explanation.

## Connect claude.ai

`ferry mcp serve --http` serves MCP over Streamable HTTP (protocol 2025-06-18, one `/mcp`
endpoint) with its own sign-in, so a cloud app can connect to this machine.

1. Start the server, behind TLS (see below), naming the public address:

   ```
   ferry mcp serve --http 127.0.0.1:8787 --public-url https://mcp.example.com
   ```

   It prints the connector URL, `https://mcp.example.com/mcp`.
2. Run `ferry mcp pair`. It prints a code that works once, for ten minutes.
3. In claude.ai, Settings, Connectors, add a custom connector and paste the connector URL.
4. The sign-in page opens on your server. It shows which host the app will return to, the
   identity it will get and which projects it will see. Enter the code. The app is then
   given an identity of its own (`<app>-<machine>`, for example `claude-grouchly`), seated as
   a **Worker** in every live project here: nothing to seat by hand. Each app that pairs gets
   its own, and sees only its own seats. Raise one with `ferry access set` like any agent.
   Orchestrators and the master identity are refused over HTTP.

To bind every app to one identity you seat yourself, add `--as <name>` (and `--all-projects`);
that identity keeps the level it already has in each project.

The server answers only to the host in `--public-url`, refuses request bodies over 1 MiB
(16 KiB on the login endpoints), and locks the login for ten minutes after five wrong codes.
Access tokens last 15 minutes; refresh tokens rotate, and replaying an old one revokes the
grant; a grant ends after 90 days. Tokens are stored only as hashes in the machine state
directory (`mcp-http/`), never synced. To revoke every connected app, stop the server and
delete that folder's `oauth.json`.

**TLS.** `--http` speaks plain HTTP and must sit behind TLS. claude.ai only reaches an
https URL on a public name. Until the edge with automatic certificates exists, put a
reverse proxy or tunnel you control in front, forwarding the `Host` header unchanged. Do
not bind `--http` to a public address without it.

Apps register themselves (dynamic client registration) and only `https://claude.ai/api/mcp/auth_callback`
and loopback redirect addresses are accepted. Client ID metadata documents are not
supported yet.

## Tools

Seven tools; every argument is explained in its schema (the `project` argument adds a
little in all-projects mode):

| Tool | What it does |
| --- | --- |
| `ferry_join` | who you are, your level, your seats (every one, paged with `since` = `next`, each with what the project is about), who is primary, whether an update exists; the guide on the first call |
| `ferry_help` | the guide, whenever it is wanted |
| `ferry_catchup` | a short digest with the brief inline; pass the returned cursor to get only what changed |
| `ferry_orders` | `list` (`scope` mine, claimable, open or all; default open), `show`, `claim`, `progress`, `submit`, `review`, `create` |
| `ferry_talk` | read new messages, post to an agent |
| `ferry_primary` | status, standby, takeover, release |
| `ferry_ask_human` | raise a question for you, check the answer |

Every list says its `scope`, its `total`, how many are `hidden` (not on this page), and a
`next` cursor: call again with `since` set to it for the following page. Nothing is cut
without a cursor to the rest.

`ferry_orders create` takes `title`, `task`, `to` (an agent or machine name; leave it out
for an order open to anyone), `kind`, `size`, `priority` and `depends_on`. The order is
signed by the caller, goes through the same path as `ferry channel order`, and comes back
reviewed.

Optional groups: `--tools admin` adds `ferry_get`, `ferry_search`, `ferry_status` and
`ferry_update`; `--tools legacy` keeps the older read-only tools. `--read-only` serves
only those.

## What an agent may do

The same levels as the CLI (Worker, Member, Orchestrator).

- Workers read, claim an order, report progress, submit work and message agents. What
  they write lands in their own hand-ins folder, which readers honour. They cannot create
  orders, review, ask the human or take over; the refusal says whom to ask (the master, or a
  member agent, with `ferry_talk`).
- Members also create orders, review changes and raise questions for you.
- Orchestrators also take over as primary and apply updates.
- Takeover works only when the primary has been silent past the quiet period, and not
  on a paused machine.
- An agent can ask you for an approval. It can never give one: an order that needs the
  master is refused to an agent with "agents never approve, use ferry_ask_human".
- A primary that is silent and has no live worker behind its name (a retired machine name)
  is called stale by `ferry_catchup` and `ferry_primary`, with what the master should do,
  and one question is raised to you, once.
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
