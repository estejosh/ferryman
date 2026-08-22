# ADR 0013: Agent access grants are renewable leases

## Status

Proposed. This ADR specifies semantics only; no enforcement is wired by it. It
exists so that the dashboard team-access work (`docs/DASHBOARD_TEAM_ACCESS_MODEL.md`)
and the secret-transport work
(`docs/RECIPIENT_BOUND_SECRET_TRANSPORT_PROPOSAL.md`) build their authority on
one lifetime primitive instead of three ad-hoc ones.

## Context

The dashboard branches introduce a second kind of authority beside the work
order: **grants** - permission for one principal to view, message, drive, or
hand off to an agent owned by someone else; or to use a secret held in an
owner's vault. The access-model doc scopes every grant with permissions and a
duration (one task / 24 hours / 7-30 days / permanent); the transport proposal
checks revocation before each use.

Both documents leave the same question open, and it is the hard one:

> **What does "revoked" mean on a machine that has not synced yet?**

Ferryman's channel is files carried by Syncthing. There is no online authority
to consult at the moment of use. Any design where authority is a *durable file*
("here is your capability, valid until June") has this shape:

1. The owner revokes the grant.
2. The revocation is a file that must sync to every machine that might act.
3. A machine that is offline, asleep, or behind a slow link keeps exercising
   the durable capability until the file arrives.

Durable capability + distributed revocation is the combination to avoid. It
turns every expiry into a fleet-wide consistency problem, and consistency is
the one thing a sync layer does not promise.

## Why the obvious fix is wrong

**"Just check a revocation list before acting"** - that is the vault broker's
plan, and locally it works, because the list is on the same disk. Across a
fleet it silently assumes the list is current, which is exactly what Syncthing
never guarantees. The check becomes a ritual that passes whether or not the
revocation has landed: fail-closed theatre.

**"Expire grants quickly so staleness is bounded"** - right instinct, wrong
mechanism. A short static expiry still ships authority as a fact ("valid until
14:00"), and facts do not shrink when you change your mind early. It also makes
long-lived collaboration noisy: someone must reissue constantly.

**"Permanent grants for convenience"** - permanent authority held as a synced
file is a credential with no rotation story, which THREAT_MODEL already refuses
for tokens.

## Decision

**A grant is a lease: short-lived, renewed by the owner, expiring on its own.**

1. **Authority is expressed as a signed lease** carrying grant id, subject,
   scope (the permissions of the access model, or the secret-use policy), an
   `expires_at` measured in minutes-to-hours, and the owner's signature. This
   reuses the existing master/grants/lease-token machinery rather than minting
   a fourth authority system.
2. **Renewal is the owner writing the next lease**, signed, into the channel -
   the same one-writer-per-path discipline as everything else. No renewal step
   means the grant dies quietly at its horizon.
3. **Revocation is stopping renewal** - plus, optionally, a signed revocation
   record for auditability and for holders that are watching. Neither replaces
   expiry; both are advisory next to it.
4. **Actors honour the lease they can see, never longer.** A machine acts only
   while its copy of the lease is unexpired. Stale copies self-extinguish; the
   worst case exposure window is the lease horizon, known in advance and
   chosen small.
5. **"One task" durations are leases bounded by task state**, expiring when the
   named order reaches a terminal state or at the lease horizon, whichever is
   first.
6. **Use-time checks remain**, exactly as the transport proposal states: the
   broker verifies signature, scope, and expiry before each operation. What
   changes is what the check reads - a fresh-enough lease, not an eternal
   entitlement.

### Why this shape

Expiry converts a distributed-consistency problem (is every replica informed?)
into a local one (is *this* copy past its horizon?), which every machine can
answer alone, offline, without clocks compared across machines. It is the same
reasoning as ADR 0011's refusal to compare clocks across machines for claims:
only local truth decides local action. And it matches what the codebase
already trusts for worker credentials - "a leaked worker credential stops
working on its own".

## Constraints

- **Lease horizons bound exposure; choose them deliberately.** Minutes for
  secret use, hours for routine agent access. The access model's "permanent"
  tier becomes "renewed indefinitely", which keeps the operator's intent while
  keeping the mechanics revocable.
- **Renewal must not require the holder to be online.** The owner publishes;
  holders pick up whenever they sync.
- **Every issuance, renewal, and revocation is a ledger entry**, so "who could
  do what, when" stays answerable from the audit trail.
- **No plaintext anywhere new.** For vault-backed grants the lease authorises
  use; the ciphertext handling remains governed by the transport proposal's
  boundaries (separate encryption keys, HPKE envelope, use-only broker).

## Consequences

Positive: revocation has a definite meaning everywhere, including offline;
expiry is chosen per grant rather than discovered per incident; the existing
lease/master/ledger primitives carry the whole design; and the two dashboard
proposals gain a shared lifetime vocabulary instead of inventing divergent
ones.

Negative: owners who want long-lived access must run something that renews
(the dashboard, or a cron'd `ferry` command) - permanence now has a process,
not just a flag. Renewals add small periodic writes to the channel. And during
its final validity window a lease still confers real authority; the horizon is
the bound, not zero.

Deliberately not solved here: key rotation of the underlying identities, and
compensation for secrets already revealed outside Ferryman - the transport
proposal's rule stands: rotate the upstream credential.
