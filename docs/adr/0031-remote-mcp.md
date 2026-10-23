# ADR 0031: Remote MCP through the VPS, with login

Status: proposed, for the master (josh). Design only; no code in this PR. Builds on 0014, 0021, 0023,
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

## Decision in one paragraph

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
| **A. Own VPS** (the master's fleet) | **Hub** (shape 1), default, on the existing relay VPS (162.35.10.46) as a separate unit; the relay is untouched. Passthrough (shape 2) is an opt-in for a user who wants no plaintext on the VPS, at the price of "down when home is off". |
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

Order: 1, then 2 and 3 in parallel, then 4, then 5 (first on a separate port), 6, 7. Milestone for the
master: a read-only Worker connection from claude.ai to his fleet through the hub with the home machines
off, then ChatGPT. Step 8 is an independent track that can start once the S4 client question (open
question 9) is settled. 9 after the beta; 10 and 11 only with C.

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
13. Token lifetimes (15 minutes, 90 days), the DCR cap and the 256 KiB blob threshold are placeholders.
