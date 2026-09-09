# ADR 0021: A Ferryman ID is a claim on a shared log

Status: proposed, 2026-09-09. Builds on 0013, 0014, 0016.

## Context

Every principal in Ferryman is a key (ADR 0016), and a name is a label pinned to a key
inside one channel: first key wins, per roster. That is right inside a project and wrong
across them. Nothing today says that the `david` invited to one project is the `david`
who joined another, and nothing stops two people claiming the name in two places.

The person joining should be able to prove, on any project, that they are the holder of
a name - and a project should be able to check that without asking anyone.

## Decision

**A Ferryman ID is a signed claim on an append-only, hash-chained log that anyone can
read and verify. The name is global to Ferryman, not to any project.**

- A claim is `{name, operator public key, created_at, signature}` signed by the key it
  names. The first valid claim for a name, in log order, owns it.
- The log is the format the channel ledger already uses: each entry hashes the one
  before it, so a reader can verify the whole history from any copy.
- An invitation to a name carries the claimed key. The acceptance must be signed by
  that key. Wrong key, wrong person, whatever they typed.
- Sign-up becomes "claim a Ferryman ID, or recover yours from your 24 words". Projects
  come after, and every invite is a proof against the ID.
- Rotation and recovery are later entries signed by the previous key; the seed stays
  the root. Revocation of access stays per project (a grant), never touches the name.

### Backends, behind one `IdentityLog` trait

1. **Hosted object** - first. The log is one object hosted somewhere reachable (MEGA to
   start). A Ferryman node is the writer: it receives signed claims at a small submit
   endpoint, appends them in the order received, and re-publishes the object. Readers
   verify locally and cache, so a fleet keeps working offline. The host cannot forge or
   reorder (every reader would see it); it can only refuse to append, which is visible.
2. **Anchor** - the log's head hash is posted daily as a `custom_json` from the Hive
   account that belongs to *Ferryman itself* (`ferrymanapp`), so the hosted object cannot
   be quietly rewritten. The posting key lives in the ferryman project's vault, sealed to
   the writer node's agent; nothing else holds it.
3. **Private log** - for a firm that will not publish staff names. Same record format,
   appended to the firm's own ledger; the name is unique within the firm. Required for
   the law-office and clinic profiles.
4. **No log** - a fleet that opts out behaves exactly as today: names as labels.
5. **Later** - more than one writer with an ordering rule, once adoption warrants it.
   Nothing already claimed changes hands; the record format does not change.

### Who pays for what

The person claiming a name needs nothing but their key. Broadcasting costs are the
writer node's - Ferryman's account - never the claimant's and never a project's.
Sponsored claims are what make sign-up one step.

## Consequences

- `david` means one key everywhere Ferryman runs, and a project proves it at join time.
- Two people cannot hold one name; the second sees "taken" at claim time, not a
  confusing collision later.
- A public name is a choice. The private mode exists so the model does not force
  anyone to publish.
- The hosted stage has one writer, and that is stated plainly rather than dressed up as
  decentralisation. The anchor is what keeps the writer honest until there are more.

## Not decided here

The submit endpoint's shape, rate limits and abuse handling; the exact anchor cadence;
the migration of names already pinned in existing channels (they become claims on the
day the log starts, oldest roster entry first).
