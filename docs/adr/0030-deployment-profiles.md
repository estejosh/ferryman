# ADR 0030: Deployment profiles (own VPS, home only, hosted)

Status: proposed, for the master (josh). Design only; no code in this PR. Builds on 0014, 0021,
0024, 0026, 0027 (phones, relay gate, Hive rescue; on `adr-0027-phones`) and 0028 (MCP server;
on `mcp-design`). Related to docs/IROH_LANE.md (relay list, fail-closed relays, public-relay
opt-in; v0.6.2). Numbers 0028 (MCP) and 0029 (lanes) are taken.

## Context

Ferryman's fleet today is one shape: an own relay on a VPS (pinned self-signed certificate), two
home machines, phones planned. Other people will not have that shape. Three do exist:

- **A. Own VPS.** The user rents a small server and runs a relay on it.
- **B. Home only.** No server at all. Home machines (and phones) find each other directly, through
  iroh's public relays if the user opts in, and through the Hive rescue channel when cut off.
- **C. Hosted.** We run the relay for them as a paid service ("relay connection as a hosted VPS service").

The requirement in all three: **end-to-end encryption, and any server we or the user run sees only
ciphertext and minimal metadata.** C must be a zero-knowledge host.

## Decision in one paragraph

A profile is **data, not a code fork**. The lane is the same in all three. What differs is (1) which
relay entries are in the master-signed `fleet/relays.json` (or none), (2) where the optional
admission gate runs, and (3) who pays for and operates the relay. Device identity (endpoint ids,
roster, phone grants) never mentions a relay, so changing profile is editing one signed list and
restarting workers: **no re-pairing**. Ferryman default for new users is **B**, with a dashboard path
to **C** the moment they add a phone or leave home (see Recommendation).

## What every profile shares (the invariants)

1. **The relay is a blind forwarder.** iroh peers run QUIC/TLS 1.3 authenticated by ed25519 endpoint
   ids, inside whatever the relay carries. A relay (ours, theirs, n0's) forwards ciphertext. It
   learns: endpoint ids, source IPs, timing, byte volume. It never learns channel names, file names,
   content, roster, or who the master is. The relay's own TLS certificate (and the pin) protects
   availability and impersonation, not confidentiality: a relay operator who terminates relay TLS
   still sees only the inner encrypted QUIC.
2. **A relay is never a channel peer.** No host ever joins a roster, holds an agent key, or syncs a
   channel. Channel files are signed, not encrypted at rest between peers, so a machine that
   synced them would read them. Hosts see transit, not channels.
3. **Admission is decided by the receiver** (roster-honoured `transports` record, or a phone grant),
   exactly as in docs/IROH_LANE.md "Who may connect". The relay's gate (0027 c) only protects the
   relay's bandwidth. So a relay with no gate (public) is not a confidentiality or integrity risk,
   only an availability and metadata one. This corrects a loose reading of 0027 ("a phone cannot use
   a public relay"): a phone can, functionally; what it lacks is a gate and a service guarantee.
4. **No shared tokens in apps.** The goal state is: no token anywhere, relay admission by endpoint id
   (allow-list), receiver admission by signed grant. The shared `iroh-relay.token` stays legacy and
   optional (0027, decision 4).
5. **Nothing here stores for later.** iroh is not store-and-forward; both ends must be online, or
   the sender retries. Section "Optional: blind mailbox" covers the one case that needs buffering.
6. **Keys never leave the user.** The master key, agent keys, phone keys and Hive posting keys stay
   on the user's devices. No profile asks for a copy.

## Components and where they run

| Piece | Exists? | A: own VPS | B: home only | C: hosted |
| --- | --- | --- | --- | --- |
| iroh relay | stock `iroh-relay` 1.3 (our VPS runs it); `ferry relay serve` not built | user's VPS | none, or n0 public relays (opt-in) | our host, one relay process per tenant |
| Relay gate (admission by endpoint id) | designed in 0027 c, not built | user's VPS, beside the relay | not needed (no relay of ours) | our host, per tenant |
| Phone/1 server (deposits, receipts) | designed 0027 a, not built | on a home machine (the receiver) | same | same (home machine; hosted mailbox optional) |
| Hive rescue poster | built on `hive-rescue`, off by default | master (+ optional backup) | master, strongly recommended | master; also covers "our relay is down" |
| Hive rescue reader | same branch | every machine and phone, only while cut off | same | same |
| Dashboard | exists, loopback only forever (dashboard.rs) | on each home machine | same | same; never hosted by us |
| MCP | local stdio (0028), read-only today | on each machine, spawned by the AI app | same | same; we host no MCP |
| Syncthing | exists, being retired | irrelevant | same | same |

### Dashboard and MCP are never on the server

The dashboard binds loopback and refuses unknown `Host` headers; that is non-negotiable (dashboard.rs)
and is not changed here. Remote operator access, where wanted, is a tunnel the user owns
(`tailscale serve`, an SSH forward), as already documented in the code. A hosted service must not
become a plaintext web UI for a user's fleet.

### Does any profile need remote MCP?

Default MCP is local stdio, spawned by the AI app on the machine that holds the agent key
(0028: "no daemon, no network"). Needs, and answers:

- **Claude Desktop, Claude Code, Codex on a fleet machine:** local stdio. No profile needs more.
- **A phone or the web (claude.ai) wanting Ferryman tools:** a cloud AI app connects to a public
  HTTPS MCP endpoint. Any such endpoint either holds an agent key (breaks zero-knowledge) or
  forwards plaintext through a third party. So: **not supported in A, B or C v1, and C never hosts
  an MCP.**
- **If wanted later, the E2E way:** a new lane protocol `ferryman/mcp/1` that tunnels one MCP
  session over iroh from a phone app (own endpoint id, `worker`-level phone grant, 0027 b) to
  `ferry mcp serve` on a home machine. Same relay rules, same grant, no new listener, no token,
  tools still limited by the grant. Effort 6 to 8 days after phone/1 exists. Deferred.
- The user's own tunnel (Tailscale) to a loopback-bound MCP over HTTP stays the user's choice and
  outside this design.

## Profile A: own VPS

**Runs where.** A stock `iroh-relay` and the gate on the user's VPS. Everything else on home
machines. This is the master's fleet today (relay at 162.35.10.46, pinned self-signed certificate,
beastly and grouchly at home).

**Finding each other.** Direct when both can see each other; otherwise the relay list
(`fleet/relays.json`, VPS first); `fallback_public_relays` optional; Hive rescue when cut off.
Phones: relay URL and pin come from the signed grant (see "Relay list for phones" below), not
baked into the app.

**Credentials.** Endpoint-id allow-list on the relay. The master signs a small
`relay-allow.json` (endpoint ids only: machines and unexpired phone grants, `seq`, `written_at`) and
pushes it to the gate over HTTPS, authenticated by a signature from the master key. The gate holds
only the master's **public** key. This refines 0027 (c), which had the gate read grants through
the lane as a read-only peer: that makes the VPS a channel peer and so a reader of the grants
channel, which invariant 2 forbids. The push keeps the VPS to ids. Revocation: master re-signs a
list without the id; the gate drops it within one poll or immediately on push.

**What the host sees.** Endpoint ids, IPs, timing, volume. Not names, content or channels. The user
is the host, so only the user sees even that. **Cannot:** read, forge a peer (ids are authenticated
end to end), or add a peer to a channel (receivers check the roster).

**Failure and recovery.** VPS down: established direct paths keep working; others retry; the
second relay in the list (user adds another VPS, or public fallback) takes over; Hive rescue
tells cut-off machines a new relay. VPS lost: stand up a new one, `relays set`, restart workers
(or the rescue record applies it). Certificate rotation with a bare-IP pin means every machine
learns a new pin: with the list that is one signed edit, not a per-machine edit (needs live reload
or a restart). Gate compromise: it can admit extra ids to the relay (bandwidth, metadata of the
user's own traffic) but cannot get into a channel. Fail closed: a gate that cannot verify its list
keeps the last good one.

**Setup UX (no CLI).** Dashboard, "Where does your fleet meet?", card A: "I have a server".
Step 1 shows one copy-paste block (a cloud-init / "user data" script, or one line for a provider's
web console) that installs the relay and gate and prints an **invite string** (URL, pin, gate
public endpoint). Step 2: paste the invite into the dashboard. The dashboard signs
`relays.json`, pushes `relay-allow.json`, and orders `restart-worker` across the fleet (existing
fleet order). The user never opens a terminal on their own machines; the only "server" step is
pasting into their provider's console.

**Cost.** VPS $4 to $6 a month (relay is light, bandwidth is the real meter). Optional domain
$10 a year (a public-CA certificate removes the pin from the picture).

## Profile B: home servers only

**Runs where.** No relay of ours. Machines at home (and anywhere they roam); phones.

**Finding each other.** In order: direct (same LAN, or a mesh the user already has);
`public_relays = true`, an explicit dashboard choice (n0's relays, no pin, no token); Hive rescue
as the independent last resort. With none of these selected the lane runs **without a relay and
says so** (existing fail-closed behaviour). `direct_only` for a flat home network.

**Credentials.** None for the relay. Receiver-side only: roster-honoured records, phone grants.
The phone's per-device grant (0027 b) is the whole credential; its key is the Keystore-wrapped
`phone.key`. Nothing shared, nothing in the app but the public parts.

**What the host sees.** n0 (if opted in) sees endpoint ids, IPs, timing, volume for every
connection that uses their relay, and can see who talks to whom by id. Not content. The dashboard
states this in one sentence at the opt-in. Without public relays no third party sees anything.

**Failure and recovery.** Honest weak points: (1) two machines behind different NATs without a
relay often cannot connect; (2) public relays are a third party's service with no promise to us
(rate limits, outages, policy changes); (3) the receiver for phone deposits is a home machine
that sleeps, so a phone and the receiver must be online together, and deposits retry until then
(see mailbox below). Mitigation: Hive rescue is what makes B survivable (a changed address or
relay can be announced with no server), and the dashboard's lane alerts say "cannot reach a
peer directly, no relay configured" in plain words with the fix being one click to C or A.
Recovery from a lost home machine: re-enrol via roster/invite as today; nothing on a server to clean up.

**Setup UX.** Zero steps beyond installing. First run asks one question: "Will you use your
devices away from home or add a phone?" No: stay direct. Yes: choose "free public relays (they can
see which of your devices talk, and when, never what)" or "get a relay" (C or A).

**Cost.** $0. Plus a Hive account with some staked HP for rescue posting (resource credits, not
spend); optional and one-time.

## Profile C: hosted by us (zero-knowledge relay service)

**Runs where.** Our host runs, **per tenant**: one `iroh-relay` process and one gate. Home
machines, dashboard, MCP, phone/1 receiver stay with the user. Optional blind mailbox below.

**Finding each other.** The fleet relay list gets one entry: `https://<random-slug>.relay.<our-domain>/`
with a public-CA certificate (no pin; phones and machines validate normally). Same direct-first,
list, fallback and Hive rescue behaviour as A. Add a second relay (the user's own, or public
fallback) and C stops being a single point of failure.

**Credentials.** Endpoint-id allow-list, as in A. At signup the user's dashboard registers the
**master public key** and nothing else, and later pushes signed `relay-allow.json`. The account
is that public key (plus a billing contact when billing exists). Per-device grants for the relay are
membership in the allow-list; no token is issued, none sits in any app. We never ask for, derive or
store a user key, seed, passphrase, grant or Hive key.

**What the host sees (zero-knowledge host).** Master public key, endpoint ids, IPs, connect times,
bytes per day, billing identity. **Cannot:** content, file or channel names, roster, project
names, device labels (the allow-list has ids only), who is the master of what, or anything signed
or sealed. Operationally: no application logs beyond counters; connection logs kept for the shortest
window abuse handling needs (open question 2). **Cannot forge:** a relay operator impersonating a
peer fails the end-to-end handshake. **Can:** drop, delay or refuse traffic (availability), and
see traffic timing and volume. These limits are what the privacy policy says, in the same words.

**Multi-tenancy isolation.**
- One relay process per tenant, systemd/container unit with cgroup memory and CPU caps, its own
  unix user, its own port behind a shared TLS-terminating front end by SNI, own allow-list file. A
  bug or flood in one tenant's relay does not touch another. Cost is small: the relay is a few tens of MB.
- No shared state between tenants: separate gate instance, separate counters, separate
  directories. The control plane (provisioning, metering, billing) is a separate service that
  can write a tenant's limits and suspend flag and can read counters; it cannot read allow-lists
  it does not need to (it stores a hash for audit) and has no code path to user keys because none exist.
- Why not one shared relay: endpoint ids are the addresses, so tenants on one relay could address
  each other's ids and share fate. Receivers would still refuse them; isolation is for blast radius and per-tenant limits.
- Tenant slug is random and unlisted; no tenant enumeration endpoint.

**Quotas and abuse.** A relay we host is a bandwidth pipe and could be abused as one, so it is
never open: only allow-listed ids connect. Per tenant, defaults to settle in the spike: 25
devices, 5 concurrent connections per id, per-client rate limit (iroh-relay has rate limiting; the
spike confirms the knobs), monthly byte cap (suggest 200 GB) with soft warning at 80%, then throttle, never
silent drop. We cannot inspect content, so abuse handling is by volume, id count and behaviour,
and the terms say so. Suspend means refuse new connections and keep the allow-list; the
user's direct paths and Hive rescue still work. A lawful-process answer is limited to the
metadata above, written into the privacy policy before launch.

**Billing hooks (LLC and merchant later).** Build the seams, not the shop:
- Metering: per tenant per day, `{bytes, peak_devices, connected_minutes}` appended to an
  internal log. No ids in billing records.
- A plan table (`free_beta`, `standard`) with limits, read by the quota layer.
- An interface `BillingProvider { create_customer, subscription_status, portal_url }` with a
  manual implementation first (the operator flips a tenant active/suspended by hand). A real merchant
  plugs in later with webhooks `active | past_due | canceled`.
- Lifecycle: `active` -> `grace` (7 days, banner only) -> `suspended` (new connections refused,
  relay answers with a distinct "billing" code so `ferry lane iroh status` and the dashboard say so) ->
  `deleted` after 30 days (we hold nothing but the master public key, ids and counters). Everything
  dormant is reactivated by paying; devices need no re-pairing.
- Entity, merchant account, terms and privacy policy are the master's to set up
  (software-business plan). Until then C runs as invite-only free beta.

**Setup UX.** Dashboard card C: "Get a relay from Ferryman". One click: the dashboard registers the
master public key, receives the relay entry, signs `relays.json`, signs and pushes the allow-list,
orders `restart-worker` (fleet order). Adding a phone is the existing QR enrol (0027 b); the
allow-list update is automatic. Nothing to copy, no CLI.

**Cost to the user.** Suggest $3 to $5 a month with quotas above (to be set once cost per tenant is measured).
Cost to us: a shared VPS handles hundreds of idle tenants; bandwidth dominates.

**Failure and recovery.** Host down: as A (second relay, direct paths, Hive rescue). We lose the
tenant database: tenants re-register the same public key and push the allow-list again; no
re-pairing. We go away: the user takes the same stock relay to profile A by changing one list
entry. We are compromised: attacker gets metadata and can disrupt, not read or impersonate.
Our domain/cert expiry: automated renewal plus alert; clients fall back to the next relay.

## Upgrade paths: no re-pairing

Pairing is endpoint ids + roster + grants, none of which name a relay. A move is: add the new
relay entry (first) -> restart workers (fleet order) -> confirm `ferry lane iroh status` shows the
new relay on every peer -> remove the old entry. Order matters so there is never a moment with no relay.

| From -> to | What changes | Re-pair? |
| --- | --- | --- |
| B -> A | Stand up the relay (invite paste), `relays set`, allow-list push | No |
| B -> C | One click; entry + allow-list | No |
| A <-> C | Swap or add one list entry; allow-list pushed to the new gate; a relay with a public-CA certificate needs no pin | No |
| A or C -> B | Remove entries, optionally `public_relays = true`; stop paying | No |

Three things must exist for "no re-pairing" to be true for **phones**, which today (0027) bake in the relay URL and pin:

1. **Relay list for phones.** The grant (and every `RENEW` reply) carries the current signed relay
   entries (`relays: [{url, pin?}]`), master-signed, so a grant renewal moves a phone to a new
   relay. The app ships no relay constant except a first-contact value from the QR.
2. **Hive rescue record** carries the same list, so a phone that missed renewals can still
   be told (0027, "Phones").
3. **Live reload** of the relay list on a running worker (today it needs a restart; docs/IROH_LANE.md).
   Not required, but without it a move needs a restart on every machine.

## Optional: blind mailbox (for offline buffering)

The lane has no store-and-forward, so a phone deposit needs the receiver awake. For A and C an
optional **mailbox** can run beside the relay: it accepts a phone/1 `PUT` of an already-sealed
deposit (sealed to the receiver's key by the app, 0027) into a per-phone-id folder, caps 1 MiB a
file and 100 MiB a phone, expires after 14 days, and hands files to the receiver when it comes
online. It sees ciphertext with random names. It is not a channel peer (invariant 2): it speaks
only phone/1 and a receiver pull. Only sealed deposits go in; channels and orders never do.
Effort 8 to 10 days after phone/1. Not needed to ship the profiles.

## Comparison

| | A: own VPS | B: home only | C: hosted |
| --- | --- | --- | --- |
| Needs a server | yes, user's | no | no (ours) |
| Cost | ~$5 a month | $0 | ~$3 to $5 a month (to set) |
| Works away from home / behind NAT | yes | partly (public relays or luck) | yes |
| Phones | yes, gated | works, no gate or SLA | yes, gated |
| Third party sees metadata | none (user only) | n0, if opted in | us (disclosed, minimal) |
| Sees content | no | no | no |
| Setup | paste one block in provider console | none | one click |
| Single point of failure | the VPS (add a second relay) | the public relays | our host (add a second relay) |
| Hive rescue | recommended | essential | recommended |
| Operator burden | user | none | us |
| Re-pair when switching | no | no | no |

## Recommendation: the default for new users

**B is the default at first run**: it works today, costs nothing, asks no one to run a server, and
is honest about what public relays can see. It is not the destination for anyone who adds a phone
or works away from home, because public relays have no gate and no promise. So the dashboard
moves them on at the first of: a phone is being enrolled, a peer is unreachable for 15 minutes
with no relay, or the user says "away from home". The suggested path then is **C once it exists**
(one click, nothing to run), **A** for people who already have a server or want no third party at
all. Until C ships, A is the only paid-for-by-you option, B the only zero-setup one.

## Exists, and what must be built

Effort in focused days for one engineer, rough.

| Item | Status | Effort |
| --- | --- | --- |
| Lane, relay list, fail-closed relays, public-relay opt-in, pins, alerts | exists (v0.6.2) | 0 |
| Hive rescue crate, CLI, drill | built, branch `hive-rescue`, off by default | 2 to merge and review |
| Phone grants, phone/1 server, `ferryman-phone` | designed (0027), not built | per 0027 (~15 to 20) |
| MCP local stdio server | read-only exists; write surface designed (0028) | per 0028 |
| Relay gate + signed allow-list push (replaces gate-reads-lane) | designed in 0027, reworked here | 4 |
| Relay bootstrap for A (cloud-init script, `ferry relay init`, invite string) | not built | 4 |
| Dashboard "Where does your fleet meet?" (cards, invite paste, status wording) | not built | 5 |
| Relay entries in grants / RENEW, and in the rescue record | not built | 2 |
| Live relay-list reload | not built | 2 to 3 |
| Hosted control plane for C (tenant provisioning, per-tenant relay units, multi-tenant gate, metering, quotas, suspend, admin view, monitoring) | not built | 15 to 20 |
| Billing provider interface + manual implementation (hooks only) | not built | 3 (real merchant later: +5) |
| Terms, privacy policy, abuse process, entity and merchant | not engineering | master |
| `ferry relay serve` embedded relay (a volunteer home machine) | not built | 3 |
| Blind mailbox (optional) | not built | 8 to 10 |
| `ferryman/mcp/1` remote MCP over the lane (optional, later) | not built | 6 to 8 |

A and B need about 15 days beyond 0027. C adds about 20 on top, plus the non-engineering items,
so a free invite-only beta is about 5 weeks after A.

## Security notes

- The new trust anchor is the allow-list push. It is authenticated by a master signature, replay-
  protected by `seq` and `written_at`, and fails closed (last good list kept). It admits ids to a
  relay only; it cannot admit anyone to a channel.
- Metadata is the cost of any relay. Mitigations: random slugs, random file names (0027), no
  application logs, no content to log, short retention, and Hive records sealed per member.
- C is only as private as our promises plus the architecture. The architecture removes the
  ability to read; the policy covers the metadata. State both.
- A hosted tenant that suspends must never strand a user: direct paths, a second relay and Hive
  rescue all continue, and the user can walk to A with one entry.

## Open questions for the master

1. Default: ship B as first-run default now, and switch the dashboard's recommendation to C when it exists?
2. Retention of connection logs on C (suggest none beyond counters and a 7-day abuse window)?
3. Replace 0027's "gate reads grants through the lane" with the signed allow-list push? (This ADR assumes yes.)
4. Public-relay disclosure wording, and whether n0 relays are acceptable for phones at all.
5. Price and quota for C; free tier or invite-only beta first?
6. Entity, terms and privacy policy owner and timing; which jurisdictions we may host in.
7. Is the blind mailbox wanted for Custodly deposits before C?
8. Domain for hosted relays (`relay.<domain>`).

## Consequences

- One lane, three configurations; every profile is reachable from every other without re-pairing.
- 0027's gate, and its phone relay constant, change as described above; that ADR is amended when this lands.
- C is a service with an operator's obligations; the design keeps those to metadata.

