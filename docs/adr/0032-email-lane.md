# ADR 0032: The email lane, a store-and-forward fallback

Status: accepted by the master (josh), 2026-11-02. Builds on the iroh lane (docs/IROH_LANE.md),
sealed secrets (`ferryman_channel::secrets`) and the Hive rescue channel (#104).

## Context

A channel moves between machines over Syncthing and the iroh lane, with the fleet's VPS relay as
iroh's fallback and a master-signed Hive post as the break-glass way to find each other again.
All of them need the two machines, or the relay, to be up at the same moment. When the relay is
down, or a machine sits behind a network that refuses QUIC, orders stop until a person notices.

Some agents can never join iroh at all: a cloud AI or an outside agent that can send and read
email but cannot hold a QUIC connection.

The fleet owns an AgentMail inbox for this, `ferryman@agentmail.to`, separate from
`helpmeagent@agentmail.to` (the public contact inbox for the repos). Email is store-and-forward:
the sender and the receiver need not be up together, and nothing of ours has to run in between.

## Decision

### 1. A fallback lane, not a second copy

Email carries channel files only when the live lanes cannot:

- a peer the iroh lane has not reached for `[email] after_minutes` (15 by default) gets what it
  is missing by email, until the lane reaches it again;
- an agent whose TRANSPORTS record says `email_only` (it will never be on iroh) always gets its
  files by email.

Everything else stays on the live lanes. Every order is NOT mailed: the inbox would fill with
copies, and AgentMail's limits would be spent on nothing.

### 2. What travels, and how

The unit is the same as the iroh lane's: channel files, under the same manifest rules (the
channel's `.stignore`, nothing over the size limit, never a deletion, never a path outside the
channel, the newer modification time wins, Worker-level agents' files only from their hand-ins).

A mail is one bundle for one recipient agent and one project:

- the files, as manifest entries plus bytes, compressed;
- **sealed to the recipient**: X25519 ECDH with the recipient's roster `encryption_key`, HKDF,
  XChaCha20-Poly1305, with the project id, sender, recipient and bundle id bound in as associated
  data (the construction `secrets` already uses);
- **signed by the sending agent** with the ed25519 key the roster pins for it;
- sent as the mail's body: the bundle as JSON, zstd-compressed, hex, in lines of 76 between
  `FERRYMAN-MAIL v1` and `END` (anything between them that is not hex - a line break or an
  indent a mail system added - is ignored), with a subject that names nothing but
  `fm/<bundle id>`. AgentMail, and anyone else between, sees only ciphertext. The body, not an
  attachment, because AgentMail takes inline content up to 6 MB a request and the body comes
  back whole from one API call.

The receiver checks, before writing anything: the signature against the roster of THAT channel,
the sender not revoked, the recipient being itself, the project id, and every file against the
manifest rules exactly as a file arriving over iroh. A bundle id is taken once (kept in machine
state), so a mail that arrives twice, or is replayed, changes nothing. Orders keep their own
signatures inside, so a file that arrives by email is the same file it would have been over iroh.

### 3. An email is never an order by itself

A plain email - including a reply from a person - is never filed as an order, a review or an
answer. Mail that is not a sealed, signed bundle from a roster member is left alone, or handed to
the suggestions inbox as an outsider's suggestion where the project has one open. Anything that
needs the master's authority still goes through the dashboard, Telegram or the APK.

### 4. One reader per machine; agents never touch the inbox

The email lane runs in the machine's worker, like the iroh lane: one per machine, not one per
agent. Agents (Claude, codex, Cline, Hermes) never hold the AgentMail key and never read the
inbox; what the lane brings in is in the channel, where they already look.

### 5. Narrow keys

The key the master made is kept on the master's machine only (`X:\ferry\secrets\.env`,
`AGENTMAIL_FERRYMAN_API_KEY`) and is used for one thing: minting the machines' keys. Each machine
gets its own key, scoped to the `ferryman` inbox:

| machine role | permissions |
|---|---|
| sends and receives (a worker that publishes) | `inbox_read`, `message_read`, `message_send` |
| receives only (a machine where every agent is a Worker, or a listener) | `inbox_read`, `message_read` |

No key below the master's can delete or label messages, create inboxes, keys or webhooks, or see
messages AgentMail marks spam, blocked or unauthenticated. A restricted key cannot mint a more
privileged one, so a leaked machine key is worth only what it allows, and it is revoked alone.
What each machine has already read is kept in its own state, which is why no machine needs
`message_update`.

A leaked key still cannot forge anything: every bundle is signed by a roster key and sealed to
one. The worst it does is read ciphertext or send mail the lane will refuse.

One inbox serves every role. A second address for readers and a first for senders was
considered and not taken: who may say something is decided by the bundle's signature, and who
may do something with the inbox by the key's permissions, so a second address would add an
address to watch and no protection.

First keys, 2026-11-02: grouchly's worker holds a read+send key (`AGENTMAIL_FERRYMAN_MACHINE_KEY`
in its secrets file; key id `f124d84b-…`). The master's key exists on beastly only.

### 6. Notices by email, optional

The master can ask for notices by email as well as on the dashboard and Telegram (the daily
digest, merge notices, renewal cards), each kind switched on separately, sent from the inbox to
the master's address. Their buttons still answer only on a signed surface: an email reply answers
nothing.

## Consequences

- A fleet keeps moving with the relay down and the VPS gone: two machines that can both reach
  AgentMail reach each other, a few minutes slower.
- AgentMail becomes a dependency of the fallback only. With the inbox gone the live lanes are
  unchanged.
- Bundles are capped at AgentMail's attachment size; a bigger backlog goes in several mails, and a
  file over the cap waits for a live lane.
- New config: `[email]` in `ferry.toml` (`inbox`, `after_minutes`, `key` - the name of the
  variable holding the machine's key, `AGENTMAIL_FERRYMAN_MACHINE_KEY` by default - and
  `enabled`), the machine's key in the environment or `<root>/secrets/.env`, and the lane's own
  state in `<machine state>/mail-state.json`.

## Built (2026-11-02)

The first build carries channel files, sealed and signed, to iroh peers the lane has not
reached for `after_minutes`, and lets them in under the iroh lane's own rules
(`ferryman_iroh::lane::channel_share`, the one place both lanes take them from). Bundles are at
most about 1.5 MB of files; a single file bigger than that waits for a live lane. Still to come:
`email_only` agents (an agent that is never on iroh), hand-ins folders by email, and notices by
email (section 6).
