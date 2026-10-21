# ADR 0027: Phones on the lane

Status: proposed, for the master (josh); his decisions on the open questions are recorded at the
end (2026-10-21). Builds on 0014, 0021, 0023, 0024 and 0026. Related to
docs/IROH_LANE.md. Written for Custodly (an Android app that drops sealed key files into a
folder that a receiver on beastly reads and answers with receipts), which needs the iroh lane
as its transport because Syncthing is being retired about a week after iroh runs clean.

## Context

Today the Custodly deposit folder is a Syncthing folder (`custodly-deposit`) carried by
Ferryman's own Syncthing. The lane (docs/IROH_LANE.md) carries channels between machines that
run a full worker. A phone is not one:

- It cannot run `ferry agent run`, and must not sync a whole channel. It needs to put files in
  one place and read a few files back.
- The only credential the lane knows is one shared relay token. A phone that holds it can reach
  the relay as anyone, and losing the phone means rotating the token on every machine.
- Every file the lane carries is kept forever (docs/IROH_LANE.md, "Nothing is ever deleted").
  Deposits, receipts and enrollment files are small, numerous and worthless after a few weeks.
- Deposits are private to one receiver. They have no business in the `custodly` agent channel,
  which swarm workers on other machines serve.

The deposit content is already sealed by the app to the receiver's public key (`intake_pub` in
`pairing.json`) before it reaches any folder. Nothing in this ADR changes that.

## Decision

### a. A phone client: a Rust core, hand-written JNI, a small protocol

A new crate `ferryman-phone` (cdylib + rlib) reuses the endpoint and relay-pin code of
`ferryman-iroh` (split into a small shared module if needed: the phone must not link
`ferryman-channel`). It speaks a new ALPN, `ferryman/phone/1`, not the channel-sync protocol.
A phone never exchanges manifests and never sees a channel. It makes four requests of one
server over one QUIC connection:

| Request | Meaning |
|---|---|
| `PUT name bytes` | Write `handins/<phone>/<name>`. At most 1 MiB, hash checked. |
| `LIST` | The names, sizes and BLAKE3 of `comms/outbox/<phone>/`. |
| `GET name` | One file of its own outbox. |
| `RENEW` | Swap a grant near expiry for the next one (see b). |

The server, not the phone, builds every path: from the endpoint id the QUIC handshake
authenticated, never from a field in the message. `name` is one path segment, validated by the
lane's existing rules (no `..`, separators, drive letters, device names, symlinks).

Android surface, hand-written JNI (about eight `native` methods, no generated bindings):
`init(stateDir, relayCertSha256)`, `endpointId()`, `status()`, `put(name, bytes)`, `list()`,
`get(name)`, `renew()`, `identityCode()`. The key (`phone.key`) lives in app-private storage,
wrapped by an Android Keystore key.

Why not uniffi: its Kotlin bindings need JNA (a jar and per-ABI `.so`) and in practice Gradle to
resolve them. Custodly builds its APK with `android/build.ps1` (aapt2, d8, zipalign, apksigner)
and has no Gradle. A cdylib built with `cargo ndk -t arm64-v8a`, copied into the APK as
`lib/arm64-v8a/libferryman_phone.so` before alignment and signing, plus `System.loadLibrary` and
`native` declarations in the existing Java, fits that build with one new step. Ship arm64 first
(x86_64 only for the emulator build).

Size: expected 5 to 8 MB for arm64 with `opt-level = "z"`, `lto = "fat"`, `panic = "abort"`,
stripped, iroh default features off (as the crate does today). This is an estimate, not a
measurement; the first task measures it, and the choice is revisited above 12 MB.

Alternative, documented and not chosen: the phone/1 frames are length-prefixed JSON plus bytes,
so another-language client is possible in principle, but it needs QUIC and the iroh relay
handshake, which no Android library gives without a native build anyway. The realistic fallback
is an HTTPS door on beastly, which adds a public listener and its own auth. Recommendation: JNI
over the Rust core.

### b. A restricted phone identity

A phone is not an agent. It has no roster entry, no `agents/<name>.json` and no `transports`
record. It has a **phone grant**: a file `phones/<phone-id>.json` in the project's channel,
signed by the project's master:

```json
{ "kind": "phone-grant", "project": "custodly-deposit", "phone": "<endpoint id hex>",
  "label": "josh-pixel", "level": "worker", "may_write": "handins/<phone-id>/",
  "may_read": "comms/outbox/<phone-id>/", "seq": 3, "issued": "...", "expires": "...",
  "revoked": false, "signature": "..." }
```

It maps to ADR 0024's **Worker**, narrowed: a Worker writes only `handins/<agent>/`, and a
phone may also read only its own outbox, where a Worker normally reads the channel. The rules
that make a Worker safe are reused: the receiver enforces them (the server derives the path from
the authenticated endpoint id; a grant that is unsigned, not the master's, older than the
sequence number already seen, expired or revoked admits nothing), and a phone can never write a
roster entry, grant, access file or verdict. `phone-grant` has no level above `worker`, and
`level` is not a field the phone can influence.

Revocation: the master sets `revoked` (higher `seq`) or removes the grant. The server rereads
grants on every connection. Grants also expire (default 30 days, renewed by `RENEW` while the
phone still holds a live one), so a phone that is lost and never revoked stops working alone.
Renewal is silent: the phone swaps a grant near expiry for the next one in the background and the
master is not asked again. Revocation is immediate and does not wait for expiry (see the decisions
at the end).

Onboarding, in order:

1. The app makes its key and shows a QR code and the same text as a short code: its endpoint id,
   the relay URL, the relay certificate pin, and a 6-word verification phrase derived from the id.
2. On beastly the master runs `ferry phone enroll custodly-deposit` and scans or types the code.
   It prints the same 6 words; the master confirms they match the phone's screen.
3. The master's machine signs the grant. The server now accepts the phone and (c) lets it reach
   the relay.

The phone has no relay access before step 3, and needs none: the QR carries its identity to
beastly out of band. A second flow (the master shows a one-time code, the phone presents it
through a relay slot that admits one unknown endpoint for 15 minutes) is possible later. It is
not needed for Custodly and is left out so the relay has no unauthenticated door.

### c. No shared relay token on the phone

The relay accepts anyone who presents the shared token. For phones it must accept an endpoint
id, not a secret:

- A phone presents no token. The relay learns its endpoint id from the authenticated handshake
  and asks a small **gate** whether that id may connect. The gate says yes for the ids of
  unexpired, unrevoked phone grants (and for machines, until they too move off the token).
- The gate is a few dozen lines: `ferry relay-gate serve`, run **on the relay VPS
  (162.35.10.46)**, not on beastly (decided; see the end). It
  reads the signed grants, verifies them against the master's key, and serves an allow list. The
  relay's access hook calls it (an HTTP check, or a file the gate rewrites). The relay host was
  not inspected for this ADR. What iroh's relay offers for per-endpoint access control, and
  whether the 1.3 `with_auth_token` path can be satisfied without a shared token, is the first
  thing the spike confirms. If it cannot, the fallback is a per-device token minted by the gate,
  master-signed with the expiry inside it: more parts, same properties.
- Revoking a phone removes it from the gate within one poll (30 seconds), with no change on any
  machine and no rotation of the shared token.
- The relay forwards encrypted QUIC. It sees endpoint ids, IP addresses and volume, never file
  names or content.
- Unchanged: the certificate pin (the phone ships the hash). Machines move off the shared token
  in the same release (decided; see the end), but a per-device credential is optional, never
  required: the lane keeps working with no token at all and with iroh's public relays, for
  anyone running Ferryman without our relay. A lost phone no longer endangers the machines' token.

### d. Expiring small files, opt-in

A project's master may sign `ttl.json` into the channel:

```json
{ "kind": "ttl", "project": "custodly-deposit", "seq": 1,
  "rules": [ {"glob": "handins/*/**", "days": 14}, {"glob": "comms/outbox/**", "days": 14} ] }
```

- Only a path a rule matches expires. A project without `ttl.json` behaves exactly as today.
  Ordinary channels cannot be matched: a rule file is refused if a glob reaches anything but
  `handins/` and `comms/outbox/` (or paths the project lists as `ttl_paths` in its manifest),
  never `tasks`, `messages`, `orders`, results, grants or the roster. `ferry doctor` says what
  a project expires.
- Expiry is a function of modification time, which the lane already carries. So nobody sends a
  deletion. Every machine decides alone: the manifest builder omits an expired file, the
  receiver refuses an expired entry, and a local pass removes expired files. A peer that still
  holds one cannot bring it back, because the others will not accept it. The lane still sends
  no delete, and "nothing is ever deleted" stays true for every channel without a signed rule.
- A one-day grace on each side covers clock skew. A file is never removed less than 14 days
  after its mtime, and an mtime in the future is not trusted.
- Under Syncthing the same local pass runs and the deletion propagates as an ordinary delete,
  so the cutover can run both.
- The receiver must have consumed a deposit before it expires. The receiver's own record of what
  it handled, not the folder, is the audit trail; expiry removes only the transport copy.

### e. A dedicated `custodly-deposit` project

A layout-2 project, separate from `custodly` (the agent channel that swarm workers serve):

```text
projects/custodly-deposit/
  comms/
    master.json, agents/, grants/, access/    the channel's trust (beastly is master)
    phones/<phone-id>.json                    phone grants (b)
    ttl.json                                  expiry rules (d)
    outbox/<phone-id>/                        receipts, written by the receiver only
  handins/<phone-id>/                         deposits, written by a phone through PUT
  data/                                       the receiver's own state, never synced
```

- Roster: one agent, the receiver on beastly. Phones are grants, not roster members. Grouchly
  and every other machine are not enrolled, so the lane never offers them the project (a project
  only one side serves is skipped). To keep it that way, `custodly-deposit` goes in `[swarm]
  exclude` in `ferry.toml` on every machine and `ferry focus` marks it `paused`, so no improve or
  planning order is ever made for it.
- Exclusion: `.stignore` carries `*.tmp`, `.stfolder` and `local`; the lane's built-ins already
  keep keys, seeds, executables and scripts out. The phone/1 server serves only the two paths
  above. Phones never get the `<id>+handins` share, which only roster machines can open.
- `custodly` keeps its channel and is unchanged.

### f. Cut-over from the Syncthing folder to the lane

1. Create `custodly-deposit` on beastly. Point the receiver at `handins/*` and `outbox/*`, and
   keep it reading the old Syncthing folder too. A file seen in both counts once.
2. Enrol the phone (b). Ship an app build that speaks phone/1 and still writes the Syncthing
   folder (dual write: the same sealed file by both routes under the same name).
3. Run both for a week. Compare every deposit and receipt by hash on both routes.
4. Stop the phone's Syncthing folder, unshare `custodly-deposit` in Ferryman's Syncthing on
   beastly, and keep its files 30 days under `_to_delete/`.

Criteria to turn Syncthing off for this folder: seven consecutive days with every deposit and
receipt arriving by the lane inside one round; `relay reached yes` and no `last_error` in any
status sample; one revoke drill (phone blocked within a minute, then restored); one TTL drill (a
test file gone at 15 days on every machine and not resurrected); the app proven on mobile data
and on Wi-Fi.

Criteria to turn Syncthing off fleet-wide (the "about a week after iroh runs clean" Josh set):

- seven days of status samples on every machine pair with no `last_error` and no peer more than
  two rounds behind, with an alert on it (status is only read by hand today);
- all machines on the same release, and a worker that comes back after an update without a
  person (see Findings);
- a lane-only drill: Syncthing stopped on one machine for a day, a task and a hand-in round trip,
  nothing lost;
- compaction answered: the lane has no `compact` (docs/IROH_LANE.md), so channels only grow.
  Either TTL (d) covers the growth or a signed removal is added first;
- a drill away from home, relay path only;
- a decision on the single relay (a second one, or accepted risk), and the certificate rotation
  steps written down.

## Findings that shaped this ADR (2026-10-21)

The grouchly peer's `no answer: deadline has elapsed` was not the relay, the pin, holepunching or
the version gap. Grouchly's worker updated itself to 0.6.1 at 21:15 UTC and exited 0, as
designed ("a supervised worker restarts by itself"). Its unit had `Restart=on-failure`, which
does not restart a clean exit, so the worker, and with it grouchly's lane endpoint, stayed down
for 32 minutes while beastly kept dialing a peer that was not there. Starting the unit made the
lane sync on the next round with both ends on the relay, and a 0.5.30 to 0.6.1 pair syncs. A
drop-in with `Restart=always` was added on grouchly. Beastly still runs 0.5.30, and its
scheduled task restarts only on failure, so the same update will probably stop it the same way.
That is a precondition for any "no Syncthing fallback" claim; this ADR does not depend on it.

## Security

- The lane never needs plaintext. Deposits are sealed to the receiver's key before the app
  writes them, and receipts are signed or sealed by the receiver. The phone core treats a file as
  bytes and a name. Nothing in phone/1 may parse, index or log content.
- A stolen phone can fill its own folder and read its own receipts until revoked or expired.
  Mitigations: Keystore-wrapped key, short grant lifetime, one-command revoke, per-phone quotas
  (1 MiB a file, 500 files, 100 MiB) enforced by the server.
- A rogue phone cannot write another phone's folder or any channel file: the path comes from the
  authenticated id. It can try to flood: rate limit per id, and the gate can drop an id.
- The gate is a new trust anchor: whoever controls it can admit endpoints to the relay (not to a
  channel; the server still checks the grant). Run it where the master key is, have it verify
  grants itself, and fail closed.
- Metadata is visible to the relay (ids, IPs, timing) and to the receiver (names). Use random
  128-bit names unrelated to content.
- Expiry deletes by local clock and mtime. Keep the grace day, refuse future mtimes, never
  expire below 14 days.
- Replay: an old receipt resent is harmless if the app checks the deposit hash it carries. Only
  the receiver writes an outbox.
- Mixed versions: phone/1 is versioned in its ALPN; an old server refuses it and the app says so.

## Consequences

- A phone joins the fleet's transport without becoming a fleet member or holding a shared secret.
- Ferryman grows a second protocol, a gate and a TTL feature, each small and opt-in.
- Custodly's Android build gains one step and a native library.
- The lane stays additive; Syncthing keeps working until the criteria in (f) are met.

## Build order and effort (one engineer, focused days)

0. Fleet hardening that gates any Syncthing retirement: restart after update on both OSes, alert
   on `last_error` and stale peers. 1 to 2 days.
1. Spike: measure the arm64 `.so`, confirm the relay's access hook and the no-shared-token
   path. 1 day.
2. `ttl.json`, the lane filter and local prune, a `doctor` line, tests. 3 days.
3. Phone grants (`ferry phone enroll|list|revoke`), master signing, receiver rules. 3 to 4 days.
4. phone/1 server in `ferryman-iroh`, quotas, two-endpoint tests. 4 days.
5. The gate and the relay configuration. 3 days, plus half a day on the relay host.
6. `ferryman-phone`, JNI, the `build.ps1` step, an emulator test. 6 to 8 days, plus 3 days on
   Custodly's side for the QR screen and phrase confirm.
7. The `custodly-deposit` project and receiver wiring, dual run, drills, cutover. 2 days of work
   and seven calendar days of observation.
8. Rescue channel over Hive (proposal, see below). 8 to 10 days; a condition for removing Syncthing,
   not for the dual run.

About 25 to 30 working days, around six weeks elapsed with the observation week. Steps 2, 3 and
4 can run beside 6 once the frame format in (a) is fixed.

## Decisions of the master (2026-10-21)

These answer the questions this ADR was proposed with.

1. **Grant renewal: silent renewal.** A grant lasts 30 days and renews itself in the background
   while the phone holds a live one; the master is not asked again after 90 days or at any other
   point. **Revocation is immediate**: the master sets `revoked` (higher `seq`) and the gate drops
   the endpoint within one poll (30 seconds), whatever time the grant had left. Expiry stays as
   the backstop for a lost phone nobody revoked.
2. **arm64-only for the first build: yes.** `lib/arm64-v8a/libferryman_phone.so` only. Other ABIs
   are a later decision, taken if a device in use needs one.
3. **The relay gate runs on the relay VPS (162.35.10.46), not on beastly.** The master key stays
   where it is and the gate holds only what it needs to verify: the master's public key and the
   signed grants it reads. How the grants reach the VPS (the lane itself, as a read-only peer of
   the channel that holds them, is the obvious way) is for the spike to settle. This also means
   the relay's access decision does not depend on beastly being up.
4. **Machines move off the shared relay token in the same release**, with one condition: a
   per-device credential stays **optional**. The lane must keep working with no token and with
   iroh's public relays, because Ferryman is used by people who run no relay of ours (see
   docs/IROH_LANE.md, "Relays: ours, iroh's public ones, or none", shipped in v0.6.2). The gate
   is an extra door in front of our own relay, not a new requirement of the lane. A machine
   whose config names no relay, or only public ones, is unaffected by anything in this ADR.
5. **Our fleet uses our own relay, on the VPS (162.35.10.46); iroh's public relays stay an
   option for other users and are off for our fleet.** `fallback_public_relays` exists
   (v0.6.2) and stays unset in our `ferry.toml`; a setup that pins a relay never gets public
   relays unless it asks. This is the posture the phones need anyway (a phone cannot use a
   public relay, which has no gate).
6. **A hosted relay may be sold later; the design must make it one more entry.** A paying user's
   relay is a relay URL, a certificate (or a public-CA one) and, possibly, a credential that is
   theirs alone. That is what a fleet relay entry is (item 7); the per-device credential is the
   optional token of item 4 issued per device instead of shared, so nothing about the lane
   changes when the relay is somebody's service rather than ours.
7. **A second relay, decentrally: a master-signed fleet relay list (built in v0.6.2).**
   `fleet/relays.json` in the fleet folder (ADR 0026) holds an ordered list of relays, signed by
   the master and verified like every other fleet file: only the master's signature counts, and an
   edited or foreign copy is ignored and shown by `ferry doctor`. An entry is a URL and, for a
   relay no public CA signs for, the SHA-256 of its certificate, which the master vouches for and
   which applies to that host only. Machines try the relays in their own `ferry.toml` first and
   then the list in order; iroh homes on the best one and moves on when it stops answering, and the
   worker republishes the relay it is on. Our VPS is first. Adding a second relay is therefore one
   command on the master (`ferry fleet relays add ...`) and a worker restart on each machine, with
   no edit to any `ferry.toml`. A change to the list is picked up when the worker restarts, because
   the certificates to trust are fixed when the endpoint binds; making that live is a later step.

   **Next step, not built: a fleet machine volunteers a relay.** The `iroh-relay` crate at the
   version we use (1.3.0) has a `server` feature, so a relay can be embedded in `ferry` (a
   `ferry relay serve`) or run as the stock `iroh-relay` binary, and its access-control hook is the
   same one the gate in (c) uses. A machine with a publicly reachable port and a certificate would
   run it and the master would add it to the list. This is small to build on top of the list
   (about 3 days, most of it the certificate: a bare-IP self-signed certificate whose pin the
   master writes into the entry, or a domain and an ordinary certificate) but it puts a relay on a
   home or office machine, so it waits until a machine that should carry one exists.

## Rescue channel over Hive (proposal, not built)

Status: proposal. Nothing in this section is in v0.6.2 and none of it is decided.

**The problem.** Once Syncthing is gone, the lane depends on a relay for any pair of machines that
cannot reach each other directly. The relay list (decision 7) and the public-relay fallback cover a
relay going down. They do not cover everything: the list itself arrives over the lane, so a machine
that is cut off cannot learn that the master moved the fleet to a new relay; and all the relays in
the list can be unreachable from one network at once. The machine then has nothing to find its peers
with. The rescue channel is a way to say "here is where I am, and here is where to find us" that
does not use the lane, a relay, a server of ours or Syncthing.

**The idea.** When no relay and no peer path works, a machine posts a small sealed record to the
Hive blockchain as a `custom_json` operation under a fleet-specific id (for example
`ferryman-rescue-v1`), from a Hive account the fleet controls. A Hive block takes about 3 seconds,
posting costs no money (it spends the account's resource credits), and a `custom_json` payload is
limited to about 8 KB. The record carries:

- the machine's current iroh endpoint addresses (its endpoint id, its relay URL, and, only if the
  fleet turns it on, direct-address candidates for hole punching);
- the relay-list version and, when the master has moved the fleet, the new relay URL or the whole
  list (these records are signed by the master, not by the machine);
- a sequence number, a validity time and the machine's name.

Peers read Hive (any public API node, several configured, none trusted for content because the
content is signed) for operations with that id, but only when their normal paths have failed
(see Cadence). A record that verifies is handed to iroh as an
address-lookup source, so the next dial uses the addresses in it, and a master-signed relay change
is applied like a change to `fleet/relays.json`. **It is rendezvous and signalling only.** No file,
manifest, order or message ever goes over Hive, and the lane's own trust rules are unchanged: a
peer reached through a rescue record is still let in only if its endpoint id is in a roster-honoured
transports record.

**Cadence: posting is rare, not continuous.** Hive's roughly 3 second block time is only how
fast a posted operation is confirmed; it is not a posting rate and nothing here posts that
often. A machine posts in three cases:

1. *A baseline record every N hours*, so the latest known addresses are never stale. N is
   configurable from 1 to 6 hours, default 6 (four operations a day per machine).
2. *At once when its addresses or its relay change*, so the record a reader finds is the
   current one.
3. *At once when it finds it has lost every path*: the relay and every peer unreachable for
   longer than the lane's alert threshold (`alert_after_minutes`, default 15).

Readers do not watch the chain. A machine reads Hive only when its normal paths have failed,
and then polls every few minutes while it stays disconnected (reads are free). From what it
reads it takes the newest valid signed record for each machine and ignores the rest. When the
lane is healthy nothing reads Hive at all.

The benefits of this cadence: the on-chain footprint is small and so is the metadata an
observer can collect (a regular baseline, plus a burst when something changes or breaks),
and the resource-credit cost is negligible. It also means the baseline is the usual way a
reader finds an address, so an outage costs a poll interval, not a block time, to recover from.

**Sealing and verification.**

- *Signed:* a machine's record is signed with its roster key, and a relay change with the master's
  key. A reader checks the signature against the fleet roster before using anything in it, exactly
  as it does for fleet files, so what is on the chain is not trusted for what it says, only for being
  there. A record from a name not on the roster, a revoked key, or a bad signature is dropped.
- *Sealed:* the payload is encrypted so the chain's readers learn nothing from its content.
  Recommended: a fresh ephemeral key per record, with the content key wrapped separately to each
  roster member (an X25519 sealed box derived from the roster's keys), at about 80 bytes per
  recipient, which fits a fleet of tens of machines in 8 KB. Revoking a machine means not wrapping
  to it from then on. The alternative is one fleet rescue key held by every machine, which is smaller
  but cannot be rotated while a machine is cut off, which is the case this exists for. Josh's
  Obscura protocol is a candidate encoding for the sealed payload; it has not been evaluated here and
  the choice is open.
- *Replay:* each record has a per-signer sequence number (a reader keeps the highest it has seen and
  drops anything lower or equal), an expiry (an hour is plenty: an address that is older is stale
  anyway) and the signer's name inside what is signed, so a record cannot be replayed under another
  name or after it has expired. The Hive block and its timestamp are only used to order and discard;
  they are not trusted for time.

**Risks.**

- *Public metadata.* The content is sealed; the fact of it is not. Anyone can see that an account
  posted under that id at those times, how often, and the size. The baseline
  record is regular, so it shows little, but the extra records at a change and at a loss of all
  paths tell an observer when something happened to a machine. The chain is permanent, so a
  sealed record is stored for good: if the fleet's keys ever leak, old records become readable. That
  is why direct IP addresses are off by default and why every record is sealed to a fresh key.
- *Hive API node availability.* Public nodes come and go and rate-limit. Several are configured,
  and a reader tries them in turn. If all are unreachable the rescue channel is simply unavailable,
  as a relay would be; it is a fallback to a fallback.
- *Account key custody.* The account's posting key lives on the machines that post (a posting key
  cannot move funds, only post). A leaked key lets a stranger spend the account's resource credits
  and spam the id, which costs the fleet its rescue channel until the key is rotated, and cannot
  forge a record. Custody of the owner and active keys is Custodly's job. A per-machine account
  instead of one shared account removes the shared key at the price of a roster entry per account.
- *Cost.* Posting is free to the poster but not free: the account needs enough staked Hive Power
  for the resource credits to post one small operation when a machine is in trouble. At the default cadence
  (four baseline records a day per machine, plus the occasional change) that is far inside what a
  small stake gives; the stake has to exist and be kept.
- *A censoring or lagging node* can hide a record from one reader. Reading more than one node, and
  accepting a record from whichever has it, is the answer.

**Phones.** It works for phones with no change in kind. A phone has no relay but ours, and a phone
can read Hive over HTTPS from any API node whatever network it is on. If our relay is down, a
phone that cannot be told is stuck, and a signed relay-change record is how it would be told. A
phone is a recipient only of the relay-list and relay-change records, never of other machines'
addresses (the same restriction as its grant in (b)).

**Effort and place in the order.** About 8 to 10 working days for one engineer: the record format,
sealing and replay rules with tests (3), a Hive client that streams the id from several nodes and
posts the operation (2), the iroh address-lookup source and the trigger that decides "no path
works" (2 to 3, after a spike to confirm the extension point at iroh 1.3), the doctor and status
lines (1), and an end-to-end test against a Hive test network or a recorded node (1 to 2). It is
step 8 in the order above. It does not gate the cutover's dual run, but it is a condition for
removing Syncthing, since that is the moment the lane becomes the only way a stranded machine
could be reached.
