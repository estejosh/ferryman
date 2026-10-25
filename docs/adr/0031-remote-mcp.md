# ADR 0031: Remote MCP with login, served from home, reached through the VPS

Status: proposed, for the master (josh). Revised 2026-10-25: login and MCP on home machines, VPS as relay and blind edge only (see "Decision"). Design only; no code in this PR. Builds on 0014, 0021, 0023,
0024, 0028 (local MCP; on `mcp-design`, PR #108 for the beta), 0030 (deployment profiles; on
`deployment-profiles`) and docs/IROH_LANE.md. Amends 0030 (see "Amendments").

## Context

Cloud chat apps (ChatGPT developer-mode connectors, claude.ai custom connectors, and others) cannot
spawn a local process. They call a remote MCP server over HTTPS from the vendor's cloud. 0030 left this
out because a public endpoint either holds an agent key or forwards plaintext through a third party.

The master's direction: "the VPS is the remote, and it should have a login", and, since it is his own
VPS (profile A), an fm **hub** installed on it, fully in the middle: a real lane peer that serves the
channel files and the remote MCP, and keeps working when the home machines are off. The earlier
passthrough shape (TLS ends on the home machine, the VPS forwards ciphertext) stays, for profile C
(hosted) and as an option in A for a user who does not want plaintext on the VPS.

Files remain the communication. The hub and the remote bridge are optional; with nothing running, the
files-only path works exactly as before. Nothing in this ADR changes the local stdio MCP of 0028.

### What the clients require (verified 2026-10-23)

- **MCP spec, revision 2025-11-25** (current): HTTP transports use OAuth 2.1 with PKCE (S256; clients
  refuse if `code_challenge_methods_supported` is absent). The MCP server is a resource server and MUST
  serve Protected Resource Metadata (RFC 9728), via `WWW-Authenticate: Bearer resource_metadata=...` on
  a 401 and/or the well-known URI. Authorization server metadata is RFC 8414 or OpenID discovery.
  Registration order: pre-registered, then Client ID Metadata Documents (CIMD, SHOULD), then Dynamic
  Client Registration (RFC 7591, MAY, "backwards compatibility"). Clients MUST send `resource` (RFC
  8707); servers MUST check the token audience and MUST NOT accept or pass on other tokens. Tokens go in
  the `Authorization` header on every request, never the query string. Redirect URIs are exact-match
  and the consent screen MUST show the redirect hostname. Public-client refresh tokens MUST rotate.
  https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- **claude.ai** (also Desktop, mobile, Cowork): supports DCR and CIMD by default. It starts sign-in only
  on a real `401`, uses only the first `authorization_servers` entry, and requires the metadata
  `resource` to equal the URL the user typed. It picks CIMD only if the server advertises both
  `client_id_metadata_document_supported: true` and `none` in `token_endpoint_auth_methods_supported`;
  else DCR. Hosted-app redirect URI: `https://claude.ai/api/mcp/auth_callback`; Claude Code uses a
  loopback redirect on any port. S256 PKCE always. Refresh on a 401 and five minutes before expiry;
  `/token` must accept `application/x-www-form-urlencoded`, return `invalid_grant` for a dead refresh
  token and rotate refresh tokens; `offline_access` is requested if listed in `scopes_supported`.
  Discovery, registration and token endpoints get 10 seconds (refresh 30). Outbound traffic comes from
  `160.79.104.0/21`.
  https://claude.com/docs/connectors/building/authentication
- **ChatGPT developer mode**: remote servers over SSE or streaming HTTP; OAuth, none, or mixed; client
  registration by static credentials, CIMD (server advertises it and the connector creator picks it) or
  DCR; tools without `readOnlyHint` are write actions and ask for confirmation. Available on the web
  for Pro, Plus, Business, Enterprise and Education accounts.
  https://developers.openai.com/api/docs/guides/developer-mode . A third-party note
  (https://zuplo.com/learn/mcp/compatibility/clients/chatgpt-connectors.md) adds: no custom headers, no
  client-credentials grant, `resource` on both requests, `client_id` is a URL on `chatgpt.com`, tool
  metadata frozen at admin approval, full write support beta for Business, Enterprise and Edu. OpenAI
  does not publish the exact redirect URI or spec revision; the Zuplo points are unverified (open
  questions 2 and 3).

So the server needs Streamable HTTP, PRM, AS metadata, PKCE S256, DCR **and** CIMD, `resource` audience
binding, rotating refresh tokens, and a public-CA certificate on a stable hostname. All plain OAuth; no
third-party identity provider is needed.

## Decision (revised 2026-10-25, the master)

The master's direction, in his words: "i type in the mcp as connector on claude... and then all of my
folders magically work ... the communications happen on iroh, and vps is coordinator in case
communications are for some reason not working." And: "if we make it so they use the vps, that means
all communications depend on centralized server. that is not the intent."

So the remote MCP is **not centralized on the VPS**. It replaces the hub-first decision below.

1. **The MCP and the login live on the user's own machines.** `ferry mcp serve --http` runs on a home
   machine (grouchly first, beastly as the second). That process is a full lane peer: it signs with
   its own keys, syncs over iroh like any worker, terminates TLS, runs the authorization server
   (OAuth 2.1, PKCE, DCR and CIMD, as specified under "Authorization server"), and shows the approval
   card on that machine's dashboard. No round trip through a server is needed to approve an app.
2. **One connector URL covers every live project.** The user pastes one URL into claude.ai (or
   ChatGPT), logs in once and approves. Tools take a `project` argument; `ferry_join` lists the
   projects the app may see, which is every live, non-archived project unless the master narrows it at
   approval. This answers open question 12: one connection, all projects, not one URL per project.
3. **Communication stays peer-to-peer on iroh.** The MCP process reads and writes the local channel
   files; the lane carries them between machines directly. The MCP's server instructions and
   `ferry_join` tell every AI how this works, so the AI never needs transport details of its own.
4. **The VPS is only a coordinator of last resort.** It runs the iroh relay (already live) for when
   direct paths fail, and a blind edge (shape 2, "passthrough") so cloud apps, which can only reach a
   public HTTPS URL, can reach a home machine. The edge reads only SNI and pipes ciphertext. It holds no
   keys, no channel copy and no login. A compromised VPS learns hostnames, IPs, timing and volume, and
   nothing else.
5. **No single door.** The edge forwards to any home endpoint named in the master-signed `edge.json`,
   in order (grouchly, then beastly), so the connector keeps working while either is on. A second
   ingress (another VPS, or a user's own tunnel) can be listed the same way. If the VPS is down, only
   cloud connectors using that URL wait; machine-to-machine traffic and every local AI (stdio MCP) are
   untouched. This answers open question 11: failover between home machines is in, not deferred.
6. **Folder layout changes come only from the master.** An AI connected through the MCP can see fleet
   notices and orders, but a layout change (moving repos, comms or work folders) is applied only when
   it is a fleet order signed by the master (`ferry fleet order migrate`). An MCP tool that is asked to
   change the layout without that signature refuses and says why.
7. **The hub (shape 1) is an opt-in, not the default.** A user who wants the connector to answer while
   every home machine is off can still enable a hub on their own VPS for chosen projects, accepting that
   the VPS can then read those projects. It is built last, if at all.

What this costs, plainly: the connector needs a home machine to be on (any one of the listed ones),
and cloud apps still need a public way in, which the VPS edge provides. The cloud vendor still receives
whatever its model reads through the connector (see "Privacy disclosure").

Build order under this decision: (a) all-projects mode for the MCP; (b) `--http` transport with the
authorization server, on a home machine, tested locally; (c) the blind edge on the VPS with failover by
`edge.json`; (d) a real claude.ai connector on the master's fleet, Worker first, then Member;
(e) ChatGPT. Hub, blobs and agentic setup follow only on request.

The sections below were written for the hub-first decision. Where they conflict with this revision,
this revision wins; the authorization, identity, tools and security sections apply unchanged to the
home-machine endpoint.

## Original decision (hub-first, superseded 2026-10-25)

Profile A gets a **hub**: `ferry hub`, installed on the master's VPS, is a headless lane peer with its
own machine identity, enrolled by a master-signed grant for the projects the master enables there. It
runs the remote MCP endpoint over HTTPS with the login (OAuth 2.1 with PKCE, a pairing code, optional
passkey or TOTP, dashboard approval per app, one agent identity per app) and it holds a copy of the
enabled channels, so it keeps serving when every home machine is off. **In this shape the VPS can read
the channels it is enrolled in.** That is acceptable because the user owns the VPS; projects not enabled
on the hub are never synced there. For bulk data the hub does not carry bytes: large files go to
S3-compatible object storage (MEGA S4) as client-side-encrypted blobs, and the channel carries small
references. Passthrough (TLS on the home machine, VPS forwards ciphertext) is the shape for profile C and
an opt-in for A.

## Shapes compared

| | 1. Hub on the VPS (A, default) | 2. Passthrough to home (C; opt-in in A) | 3. User's own tunnel (B) |
| --- | --- | --- | --- |
| Public endpoint and login | hub, on the VPS address | VPS forwards to home | user's choice |
| TLS ends | on the VPS, inside the hub | on the home machine | tunnel vendor or home |
| VPS can read channels | yes, enabled projects only (owner's VPS) | no: SNI, IPs, timing, bytes | n/a |
| Agent keys | hub's own key and the app keys, on the VPS; never the master | home machine | home |
| Home machines off | still served | down | down |
| Effort | medium | higher (edge + ACME at home) | none from us |

Rejected: terminating TLS on the VPS and forwarding plaintext to home over the lane. It has the
disadvantages of both: the VPS reads everything and the service still dies with the home machine.

## Shape 1: the hub (profile A)

### Role and enrolment

- `ferry hub` is the existing worker (`ferry agent run`, lane, channel library) packaged for a server,
  plus the HTTP endpoint below. It is a separate systemd unit and unix user from the iroh relay and gate;
  the relay stays a blind forwarder and the master's existing relay setup (0030 decision 9) is not touched.
- Identity: its own machine key and endpoint id, named `hub-<name>`. It appears on the roster of each
  project the master enables for it, with a `transports` record, like any machine. Level **Member** by
  default; Orchestrator only if the master chooses it for a project (dashboard toggle with a warning).
  It is a peer by explicit signed enrolment, so 0030 invariant 2 stands for relays and for C.
- Enrolment from the dashboard: "Add a hub" shows the install command (below); the VPS prints a hub
  invite (its endpoint id and public key); the master pastes it into the dashboard, which signs the
  roster entry and grant for the chosen projects and orders the fleet to expect it (`channel expect`).
  The hub holds the master's **public** key only. The master key never leaves the master's devices.
- Which projects: a per-project toggle, default off. The lane's trust is per channel (docs/IROH_LANE.md,
  "Who may connect"), so a project that is not enabled is not offered to the hub and never syncs there.
  The fleet folder is not synced to the hub by default. Disabling a project revokes the hub's roster
  entry (signed by the master); the dashboard then orders the hub to purge its copy and shows when it did.
- What the VPS reads: the full contents of enabled channels (tasks, messages, decisions, ledger,
  hand-in references), and the plaintext MCP traffic. Disk encryption on the VPS is recommended. It does
  not see secrets, which never enter channels (`ferry channel secret`), or work content, which stays in
  work repos.
- Hub key at rest: a file owned by the service user, sealed by the systemd credential store where the
  host supports it. A stolen disk gives that Member-level hub identity for the enabled projects until the
  master revokes it; it gives no master key, no operator seed, no release signing.

### Availability

The hub holds a synced copy, so with every home machine off it still answers reads and accepts signed
writes from app identities (messages, progress lines, asks); the lane carries them home when a machine
returns. What waits for a master-key holder: approving a new app, appointing roles, revoking in the
roster. Revoking tokens is local to the hub and immediate; the signed roster revocation follows when the
master is next online. If the VPS is down, the clients show their generic failure; the lane, direct
paths and Hive rescue are unaffected (0030).

### Remote MCP endpoint (`ferry hub`, same process)

- Streamable HTTP; protocol 2025-06-18 or 2025-11-25 negotiated (0028's stdio server speaks 2024-11-05
  today). Serves only `/mcp`, `/.well-known/*`, `/authorize`, `/token`, `/register`, `/revoke`; refuses
  unknown `Host`. No dashboard route. The dashboard stays loopback on each home machine (0030).
- TLS: public-CA certificate obtained automatically (ACME) for the master's hostname, renewed by the
  hub. The hub shares 443 with the live iroh relay by SNI (open question 1): the MCP hostname goes to
  the hub, every other handshake, including bare-IP relay clients, to the relay unchanged. Step 1 of the
  build runs the hub on a separate port so the relay is not touched until the mux is tested.
- Tools: **the same tools and token caps as 0028** (six core tools, T1 to T10, `resource_link` for
  bodies, byte-stable definitions, `ferry_join` first). Differences are all stricter for remote use:
  see "Tools and guards".

### Authorization server (same process)

- Metadata (RFC 8414) and PRM (`resource` equals the canonical MCP URL, one `authorization_servers`
  entry). Advertises `code_challenge_methods_supported: ["S256"]`, `authorization_code` and
  `refresh_token` grants only, `registration_endpoint`, `client_id_metadata_document_supported: true`,
  `token_endpoint_auth_methods_supported: ["none"]`, scopes `ferry:read`, `ferry:write`,
  `offline_access`. No client-credentials, implicit or password grant.
- Clients: CIMD preferred, DCR accepted. DCR is public by nature, so it is fenced: redirect URIs must be
  on an allow-list (`https://claude.ai/api/mcp/auth_callback`, the ChatGPT callback once confirmed,
  loopback for Claude Code); anything else is refused unless the owner enables "custom client".
  Registration alone grants nothing; registrations are capped (default 50) and unused ones expire in an
  hour. CIMD fetches use an SSRF guard (https only, no private ranges, size and time limits).
- Tokens: opaque 256-bit values stored as hashes in machine-local state (not synced). Hub is both AS and
  RS, so no JWT and no introspection. Access 15 minutes; rotating refresh with reuse detection (a replay
  revokes the grant); 90-day absolute life, then re-approval. Audience (the canonical MCP URL) checked on
  every request. Numbers are placeholders.
- **Login**, two layers, because the master wants a login and approval needs the master key:
  1. *Pairing code (always).* Dashboard, "Connect ChatGPT / claude.ai", mints a single-use code valid 10
     minutes and sends the hub a master-signed record holding only its hash and expiry (over the lane).
     `/authorize` asks for the code; without it nothing is queued, so strangers cannot flood the dashboard.
  2. *Owner sign-in (optional).* The owner enrolls a passkey (WebAuthn, relying party = the MCP
     hostname) or TOTP, locally on the dashboard, and the hub keeps only the public credential. After
     that `/authorize` asks for it instead of a code, so an existing app can be re-approved without a
     new code. There is no password field and no shared password anywhere.
- **Approval per app.** After the code or sign-in the page says "waiting for approval on your home
  machine". The hub writes a signed pending request (client name, redirect hostname, project, requested
  level) that reaches the home dashboard over the lane. The master approves; the dashboard signs the new
  agent's roster entry and grant and the lane carries them back; only then does the hub issue the
  authorization code. If no home machine is online the page waits, then times out; existing apps keep working.

### Identity, permissions, revocation

- Each approved app gets its own agent identity (`chatgpt-<owner>`, `claude-ai-<owner>`): a new key in
  the hub's keystore, a roster entry, a master-signed grant. Level is **Worker or Member, never
  Orchestrator**; the approval card defaults to Worker ("read the channel, ask the human, write nothing
  into it"); Member is an explicit choice. `ferry_primary takeover` is denied to every remote identity.
- Scopes map to levels: `ferry:read` = Worker, `ferry:write` = Member. A missing scope is
  `insufficient_scope` (403 with `WWW-Authenticate`), never silently dropped. An app is bound to one
  project, chosen at approval. Same library calls and checks as the CLI; an app never exceeds its owner's
  permissions per project (0028, 0024).
- **Revoke in one click:** dashboard, "Connected apps" (app, identity, level, project, last used, call
  counts). Revoke kills all tokens on the hub at once, master-signs the roster and grant revocation, and
  deletes the identity's key. Writes are signed by the app's own identity, so the ledger shows who; reads
  add a local audit line (time, app, tool, bytes; no content).

### Tools and guards (remote)

- The secret-shape guard runs on inbound text (`ferry_talk post`, `ferry_ask_human`, as in 0028) and on
  **outbound results**, because a result is about to leave for a vendor; a match is withheld with a
  pointer to the dashboard.
- No secrets, passphrases, vault flow or release signing is exposed, ever; those stay CLI and dashboard.
  `resources/read` honours `.stignore` and the built-in exclusions (`keys`, `*.key`, `*.seed`, `local`).
- Work never moves into the channel: tools take references (hand-in id, commit sha), not content.
- `readOnlyHint` is per tool, but 0028's `action` enums mix reads and writes, so ChatGPT would confirm
  even a list. Open question 4 weighs a read-only split for the remote list. ChatGPT freezes tool
  metadata at approval (third-party report), so byte-stable lists (T8) matter; a tool change bumps the
  connector version.

### Update awareness

Per 0030 ("Updates, in every profile") agents ask the MCP what is newest. The hub fetches the
master-signed release record from the release source, verifies it, and `ferry_join` (remote and local)
reports running version, latest signed release, and how to update. The hub serves **no binaries**.
Machines still pull and verify Josh-signed releases themselves (ADR 0026, section 7), and a hub that is
compromised cannot push code to anyone. A stale or unverifiable record is reported as such.

### Privacy disclosure

Whatever a cloud model reads leaves the user's control and goes to that vendor. The dashboard says so
before the connect step and again on the approval card:

> "ChatGPT / Claude will receive everything it reads through this connection (task titles, messages,
> decisions, file excerpts you let it open) and the vendor may keep it under its own policy. Your server
> (the hub) holds a copy of this project and can read it; nobody else on the path can, but the vendor
> can. Connect only projects you are willing to share with that vendor."

## Bulk data: blobs in MEGA S4

The hub is a small VPS with a bandwidth meter. The lane carries small files well (manifests every 30
seconds, files under 64 MiB). Large hand-ins, artifacts and attachments should not pass through the VPS
at all.

### Shape

- Above a threshold (default 256 KiB, a placeholder), a hand-in, artifact or attachment is stored as a
  **blob** in S3-compatible object storage, and the channel carries only a small signed reference file
  (`blobs/<id>.ref.json`: id, size, name, plaintext size, chunk size, key epoch, hash of the ciphertext,
  author signature). The lane syncs the reference like any channel file; peers fetch the blob **from the
  store directly**, not through the hub or the relay. Messages, orders, ledger and metadata stay on the lane.
- **Encrypted before upload.** Blobs use chunked AEAD (XChaCha20-Poly1305, STREAM construction) with a
  per-blob key derived from a per-project `blob key`. The object name is a keyed hash of the plaintext
  (BLAKE3 keyed with the blob key), so it is content-addressed within a project (dedupe, resume) without
  letting the store test whether it holds a known file, and a project prefix derived the same way hides
  project names. The store sees ciphertext, random-looking names, sizes, timing and client IPs; never
  plaintext, names or keys.
- **Keys never in S4.** The blob key is made by the master and distributed sealed to each enrolled
  machine's public key as a channel file, so only roster members can unseal it; a revoked member gets no
  later epoch (a new epoch is minted on revocation; old blobs stay readable by old holders, which is
  stated, not hidden). S4 access credentials are machine-local secrets (the machine-local secret file,
  never a channel, never `ferry.toml`); the hub gets only what it needs.
- Cloud apps never receive blobs. Tool results obey the T4 caps; a blob appears as a `resource_link`, and
  at most a capped text excerpt is decrypted by the hub for a Member or Worker that holds `ferry:read`.
- Lane rules stay: nothing is ever deleted by the lane. Blobs are removed only by a master-signed sweep of
  unreferenced blobs, because the store offers no lifecycle rules (below).

### MEGA S4 terms (secondary source; confirm before relying)

I could not read MEGA's own pages from this environment (blocked). A summary dated 2026-08-01,
https://zenn.dev/sashimi3433/articles/569ae2eff2b892?locale=en , reports: S4 is included from the MEGA
Pro I plan up and shares that plan's storage quota (Pro I: 3 TB at EUR 9.99 a month, about EUR 3.33 per
TB); ingress is free; monthly egress is free up to 5 times the storage capacity (15 TB on Pro I), with no
price given beyond it; no per-request fees; possible rate limits on very large request bursts; objects
use server-side encryption, not MEGA's end-to-end encryption; no lifecycle policies, cold storage or
compliance mode. If true, the egress that matters is the VPS's own (the hub fetches almost nothing) and
MEGA's per-TB allowance, which a small fleet will not approach. The server-side-only encryption is why the
client-side layer above is mandatory. Open question 8 lists what to confirm.

### Relation to SovGit

SovGit (git on S3-compatible storage, planned) wants the same pieces: an S3 client, content-addressed
objects, client-side encryption, a keyed-hash naming scheme and a sweep. They should be one crate shared by
Ferryman blobs and `git-remote-sov` rather than two implementations. Ferryman owns the blob layout
above; SovGit can reuse it for pack objects. Whether it lives in this repo or its own crate is open
question 9. Nothing here depends on SovGit shipping.

## Shape 2: passthrough (profile C; option in A)

For C, and for an A user who does not want plaintext on the VPS: the VPS runs a small edge (`ferry edge
serve`) that listens on the public HTTPS port, reads only the SNI from the ClientHello, and pipes the raw
bytes over an iroh stream (ALPN `ferryman/edge/1`) to `ferry mcp serve --http` on a home machine. That
machine terminates TLS (certificate obtained at home by ACME TLS-ALPN-01, which works through the
passthrough), runs the same authorization server and MCP, and holds the app keys. The edge is not a channel
peer, holds no keys and no content, and accepts only the home endpoint named in a master-signed `edge.json`.
The VPS learns the hostname, vendor IPs, timing and volume. If the home machine is off the edge closes the
socket (TLS is not terminated, so it cannot send an HTTP error) and clients show their generic failure; an
optional status hostname that the edge terminates itself can show "home last seen N minutes ago" with no
channel data. In C the tenant hostname is `<slug>.mcp.<our-domain>`, routed by SNI to the tenant's
endpoint; per-tenant limits and a suspend flag live in the edge, which is stateless.

**Honest limit.** A cloud app validates through the public web PKI and cannot pin our certificate.
Whoever controls the DNS name or IP can obtain a valid certificate and actively terminate TLS. Passthrough
removes passive and accidental reading; it is not a cryptographic bar to a hostile operator. In A the
operator is the user. In C it is us, so C offers the user's own name (a CNAME to us) with a `CAA` record
limiting issuance to the ACME account their home machine created, a Certificate Transparency watch that
alerts on any certificate the home machine did not request, and a privacy policy that says this in the
same words. C is gated on the LLC (0030 decision 6); until then design and private testing only.

## Profiles

| Profile | Recommendation |
| --- | --- |
| **A. Own VPS** (the master's fleet) | **Passthrough** (shape 2) is the default since 2026-10-25, with failover across home machines; **Hub** (shape 1) is opt-in, on the existing relay VPS (162.35.10.46) as a separate unit; the relay is untouched. Passthrough (shape 2) is an opt-in for a user who wants no plaintext on the VPS, at the price of "down when home is off". |
| **B. Home only** | Remote MCP not available natively: there is no public ingress without a server, and iroh public relays are not an HTTP ingress. The dashboard offers "get a relay" (A or C) or the user's own tunnel (outside this design). Local stdio MCP is unaffected. |
| **C. Hosted** | Strictly passthrough, never a hub and never terminating TLS for a tenant. Hosting a hub for others would make us a reader of their channels, which 0030 forbids. |

## Install UX (profile A)

- Dashboard, Settings, "Add a hub": shows one command to paste on the VPS (or a generated script for the
  provider's web console): it downloads the master-signed release, verifies the signature, creates the
  service user, installs the systemd unit (`ferry-hub.service`, restart on failure, hardened sandbox
  options), and prints the invite. No other step on the VPS.
- Hostname: the master chooses a name pointing at the VPS (the dashboard checks DNS); the hub then gets
  its certificate automatically and renews it. Paste the invite into the dashboard, choose projects
  (default none), choose the level (default Member), click Enrol. The grant is master-signed on the
  dashboard and reaches the hub over the lane.
- "Connect ChatGPT / claude.ai" then shows the URL to paste, the exact clicks for each app (checked
  against the vendors' current screens before release), the privacy paragraph and a pairing code, and
  walks the login and approval; "Connected apps" lists and revokes.
- Updating the hub is the same signed-release pull as every machine.

## Agentic setup

Once the master's own hub works, setup must not need him. Anyone with their own VPS and storage account
should be able to tell their own AI agent (Claude Code, Codex, or claude.ai through the MCP) "set up
Ferryman with my VPS and storage", and have it done end to end. Two parts: a published **setup skill**
(a prompt and playbook the agent loads) and `ferry setup` subcommands the skill drives. The skill holds
judgement; the subcommands hold all effects, so an agent cannot improvise a step that is not there.

### Contract of `ferry setup`

- **Non-interactive and idempotent.** Every subcommand takes flags or a plan file, prints JSON, and exits
  with a distinct code for ok, needs-human, and failed. Running it twice changes nothing the second time.
- **check, plan, apply, verify.** `ferry setup check` reports the current state (what exists, what is
  missing, versions). `ferry setup plan` writes a plan file: an ordered list of steps, each with what it
  changes, whether it is reversible, and whether it needs the human. `ferry setup apply <plan>` runs
  steps and records each in a local setup log; a step that is already satisfied is skipped. `ferry setup
  verify` re-checks every step. Every subcommand has `--dry-run`, which shows the exact commands and file
  changes without making them.
- **Steps**, in order: (1) pick the profile (below); (2) provision the hub over SSH: install the signed
  release, service user, systemd unit, firewall rules (allow SSH, 443 and the relay port; deny the rest),
  hostname check, TLS; (3) create and enrol identities through master-signed grants (hub, then the
  machines the user names); (4) configure object storage, MEGA S4 or any S3-compatible service, with
  client-side encryption and a bucket round-trip test; (5) write and sign the relay list; (6) connect AI
  apps (mint the pairing code, show the URL, wait for approval); (7) run the self-test drill and write its
  report.
- **Profile choice.** The skill asks three questions (do you have or want a VPS; do you leave home; do you
  add phones) and `ferry setup plan --profile auto` proposes A, B or C per 0030: no server means B with the
  upgrade offer, a server the user owns means A with the hub, "host it for me" means C once it exists. The
  user confirms the profile; the agent does not choose it silently.
- **Provider-agnostic.** Any VPS with SSH, root or sudo, and Ubuntu or Debian (a current LTS and the
  previous one). Nothing calls a provider API; the user buys the server and gives the agent a host name.
  Tested providers are listed in the repo docs only after a real run on each, and the list says which
  version was tested. Anything else is "expected to work, untested".
- **Self-test drill** (`ferry setup drill`): sends a signed message through the hub and back, claims and
  submits a dummy order, uploads and fetches a small encrypted blob through the store, restarts the hub,
  fails over to the second relay, and runs an OAuth login against the local test client. It reads only its
  own dummy project, which it creates and removes. A failed step names the fix.

### What the human keeps, and how the agent never sees credentials

The agent drives; the human decides and holds every secret. The lines that never move:

- **Credentials.** SSH keys or passwords for the VPS, storage access keys, the master passphrase and any
  API token are entered by the user into the local vault or a dashboard prompt on their own machine. The
  agent receives **handles** (for example `vault:vps-main`, `vault:s4-main`) and passes them to `ferry setup`,
  which resolves them locally. Secrets never appear in chat, in a plan file, in the setup log, in a command
  line or in an environment dump; the output scrubber that guards 0028 tools also scrubs `ferry setup` output.
  If an agent asks for a secret in chat, the skill tells it to stop and send the user to the prompt.
- **Signing.** Master-signed grants, the relay list and release trust are approved by the human in the
  dashboard. The agent can request a signature (a pending item, as `ferry_ask_human` does) and wait; it
  cannot sign. `ferry setup` never holds the master key.
- **Spending money.** Buying a server, a domain, a storage plan or a hosted relay is the user's action. A
  plan step that would incur cost is marked `needs-human: spend` and is never run by the agent.
- **Destructive steps.** Anything that deletes data, replaces a running service, changes DNS, opens or
  closes a firewall port on an existing server, or removes a project from the hub is `needs-human:
  destructive` and runs only after the human approves that step by its id, with the dry-run output shown.
- The agent is a Worker-level actor by default for setup: it can run `check`, `plan` and `--dry-run`
  freely; `apply` of anything marked above waits for approval, and an unapproved step ends the run with the
  needs-human exit code and a plain-language message for the user.

### Rollback and uninstall

- Every `apply` step records an inverse in the setup log. `ferry setup rollback [--to <step>]` undoes steps
  in reverse order, each dry-runnable and each destructive one human-approved.
- `ferry setup uninstall --hub` stops and removes the unit and service user on the VPS, removes the
  firewall rules this tool added, deletes the hub's keys and its synced copies (the purge of 0031), asks
  the dashboard to revoke the hub's roster entry and the app identities, and leaves the relay, the user's
  other services and the object store untouched. Deleting stored blobs is a separate, explicit, destructive
  step. Home machines keep working on direct paths and Hive rescue (0030).
- A failed `apply` stops at the failing step with the log; re-running `apply` resumes. Nothing is left
  half-configured without `verify` saying so.

### Where it sits

It is built after the master's own hub works (steps 1 to 7 above), because it automates a flow that must
first be done by hand once and found stable. Its pieces map to the earlier steps, so each `ferry setup`
subcommand is a thin wrapper over a function that already exists by then; the new work is the plan and log
format, SSH provisioning, scrubbing and the drill. The skill is written last, against the real commands.

## Amendments

- 0030, "Dashboard and MCP are never on the server" and "Does any profile need remote MCP?": a **hub**
  may run on the user's own VPS in profile A as an enrolled peer (0030 invariant 2 still holds for relays,
  gates, the edge and all of C). Remote MCP is supported in A (hub or passthrough) and C (passthrough),
  not natively in B. The dashboard stays loopback on home machines; the hub has none.
- 0030 decision 3 (the gate takes a signed allow-list push) is unchanged; the hub is not the gate.
- 0028, "no daemon, no network": true by default; `--http` and `ferry hub` are explicit opt-ins.
- 0023/0030: large hand-ins may be a blob reference instead of a file in the hand-ins folder.

## Security notes

- New public surface: the hub's HTTPS endpoint. Auth before any MCP parsing, request size caps,
  per-source rate limits, login lockout, generic errors, constant-time comparison, fixed `Host`, TLS 1.3
  only. The browser leg of the login comes from the user's own IP, so a vendor-IP allow-list cannot cover
  `/authorize`; it is left out.
- A compromised hub gives the attacker the enabled projects' plaintext, the app identities' keys (capped at
  Worker/Member, revocable), and the hub's own Member key. It gives no master key, no operator seed, no
  secrets, no release signing, and cannot push code to machines. This is the cost of shape 1 and the
  reason projects are enabled one by one.
- Prompt injection: a cloud model reading channel text can be steered by it. Remote identities cannot
  approve, sign releases, mint grants, take over or read secrets, and default to Worker.
- Redirect hostname is shown on every consent; the DCR allow-list removes the common phishing path.

## Effort and build order

Focused days for one engineer, after the local MCP beta (PR #108) lands. Rough.

| # | Step | Days |
| --- | --- | --- |
| 1 | `ferry hub`: headless peer packaging, enrolment grant and invite, per-project enable and purge, systemd unit and install script, dashboard "Add a hub" | 8 |
| 2 | HTTP mode of the MCP: Streamable HTTP, protocol upgrade, sessions; stdio unchanged | 4 |
| 3 | Authorization server and PRM: DCR and CIMD, PKCE, authorize page, token, rotating refresh, audience check, revoke | 8 |
| 4 | Per-app identity and approvals over the lane: pending request and pairing-code records, key, roster, grant, scopes, "Connected apps", approval card | 8 |
| 5 | Automatic TLS (ACME) on the VPS and SNI mux with the relay | 4 |
| 6 | Update awareness in `ferry_join` (signed release record on the hub) | 2 |
| 7 | Tests: OAuth conformance, permission matrix, secret guard on results, token-budget CI, real ChatGPT and claude.ai smoke runs, security review | 6 |
| | **Subtotal, profile A hub** | **40** |
| 8 | Blobs in S4: S3 client, chunked AEAD, keyed naming, reference files, blob key sealing and epochs, fetch/store in hand-ins, sweep (shared with SovGit if agreed) | 10 |
| 9 | Passkey / TOTP owner sign-in | 4 |
| 10 | Passthrough edge and ACME at home (C and the A option) | 10 |
| 11 | Profile C routing, wildcard names, CT watch, per-tenant limits (after the C control plane, 0030) | 6 |
| 12 | Agentic setup: erry setup check/plan/apply/verify/rollback/uninstall/drill, SSH provisioning, secret handles and output scrubbing, setup skill, one real run on each tested provider | 14 |

Order: 1, then 2 and 3 in parallel, then 4, then 5 (first on a separate port), 6, 7. Milestone for the
master: a read-only Worker connection from claude.ai to his fleet through the hub with the home machines
off, then ChatGPT. Step 8 is an independent track that can start once the S4 client question (open
question 9) is settled. 9 after the beta; 10 and 11 only with C. 12 (agentic setup) comes after the master's own hub and steps 1 to 7 work, and ideally after 8, so storage setup is covered.

## Open questions

1. Hostname: which domain for the hub, and may the hub take 443 by SNI beside the live relay, or start on
   another port?
2. ChatGPT's exact redirect URIs and spec revision are unpublished; verify with a real developer-mode
   connector before fixing the DCR allow-list.
3. Plan limits: OpenAI's guide lists Pro, Plus, Business, Enterprise and Edu; a third-party note says full
   write support is Business, Enterprise and Edu beta. Which plan does the master have? claude.ai plan
   limits for custom connectors were not checked.
4. Split the remote tool list into read-only tools (`readOnlyHint`) and write tools to avoid a prompt on
   every read, at the cost of definition tokens (0028 T1)?
5. Hub as Orchestrator: allowed per project on request, but should a hub ever hold the pointer, given a
   server is easier to reach than a home machine?
6. Is a Worker app allowed `ferry_ask_human raise` (a signed request file) when 0028 denies channel writes
   to Worker? Proposed: yes, as a hand-in.
7. Disabling a project on the hub: purge is ordered and reported, but a copy that was already read is read.
   Is that wording enough in the dashboard?
8. MEGA S4: confirm on MEGA's own pages the plan requirement, the egress allowance (5x storage), request
   limits, maximum object size, whether sub-users or scoped keys exist (one key per machine, read-only for
   the hub), and the terms for programmatic use.
9. Blob and S4 code: one crate shared with SovGit, or Ferryman first and extract later? Who owns the
   blob layout?
10. Blob sweep and key epochs: how long to keep unreferenced blobs, and is "old holders keep old blobs"
    acceptable after a revocation?
11. Passthrough in A and C: needs the home machine on. Failover to a second home certificate holder:
    defer?
12. One project per connection, or one connector URL per project (`/p/<project>/mcp`)?
13. Agentic setup: which providers get a tested run first, where the setup log lives (machine-local, never synced), and whether the skill ships in this repo or in a separate published skills repo?
14. Token lifetimes (15 minutes, 90 days), the DCR cap and the 256 KiB blob threshold are placeholders.
