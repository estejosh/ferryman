# ADR 0018: Releases are approved from afar, not signed by hand

## Status

Proposed.

## Context

Every release so far has been signed by the operator, at the machine, typing a
passphrase. That is a good property — a compromise of the fleet cannot produce a signed
release, because the one thing the fleet does not have is the passphrase — and it is
the reason the arrangement has held: Claude prepares and tags, Claude issues a "gpg
request", Josh signs.

It is also the reason releases only happen when he is at that machine. The request that
prompted this: *"I would like to be able to automate, from afar, with no need to sign
locally."*

The obvious implementation is forbidden and should stay forbidden. **The passphrase must
never travel over Telegram.** That is a standing rule in this project, the bridge's own
help text says "Do not send credentials here", and a passphrase pasted into a chat is a
passphrase in a message history, on a phone, on a server, and in a backup.

So the passphrase cannot move. Something else has to.

## Decision

**Telegram carries the authorisation, never the secret.** The key is usable on one
machine without a human present; what gates its use is a structured approval from the
operator's Telegram identity.

### Why this is a smaller change than it sounds

The trust boundary already includes Telegram. ADR 0008 made the approver a first-class
order surface: `from.id == approver_id` can issue signed orders to the entire fleet,
which is a strictly broader power than "cut a release from a commit that is already on
main and already passed CI". Anyone able to speak as the approver can already command
every machine. Letting them authorise a tag does not hand them anything they could not
already take a longer road to.

What *does* change is what a compromise of the signing machine alone yields. Today: a
box with an unusable encrypted key. Under this: a box that can sign a release, if it can
also produce an approval. That is the cost, and it is stated plainly rather than
discovered later.

### A release identity, not a personal one

The key that signs releases is **not** the operator's personal GPG identity. A separate
release key lives on the signing machine, and its public half is published in the repo
and in `docs/RELEASE_PROCESS.md` exactly as the current one is.

This is the part that makes the trade acceptable. A personal key sitting passphrase-less
on a machine that runs autonomous agents puts the operator's whole identity — every
commit, every other project, every place that key means "him" — behind the weakest
process on that box. A release key forfeits releases and nothing else, and it can be
rotated without touching who he is.

### The flow

1. The fleet prepares the release: version bumped, changelog written, CI green, commit
   pushed. Nothing is tagged.
2. It raises a **release request** — a signed record in the channel, like everything
   else — and the bridge puts it on Telegram: the version, the commit, the CI result,
   and the changelog summary. Not "approve?" but *what is being approved*: the same rule
   the approval gate already follows, which is that a gate offering only yes and no is a
   gate nobody can exercise judgement at.
3. The operator replies with a structured command — `/release approve <version>` — never
   free text. ADR 0008's rule: free text must never be silently promoted to a signed
   action.
4. The signing machine verifies the approval, tags, signs, and pushes. The tag message
   records that it was approved remotely and by whom.
5. The result comes back on Telegram: the tag, its fingerprint, and the release URL.

### What refuses

- An approval that does not verify, or comes from anyone but the approver.
- An approval for a version that does not match the request, or for a commit that moved
  after the request was raised. Approving *this* release must not authorise a different
  one.
- A request older than a short horizon. An approval sitting unread for a day is not
  consent to ship whatever main has become since.
- CI that is not green. The gate is for judgement, not for overriding the machine.

## Consequences

**Releases stop depending on where he is standing.** Which is the point, and it is worth
something beyond convenience: a release that has to wait for someone to be at a
particular desk is a release that gets delayed, batched, and eventually cut in a hurry.

**The security property changes, in a way that is stated rather than implied.** It moves
from "only a person with the passphrase can sign" to "only a person with the approver's
Telegram identity can cause a signature". Weaker in one direction, and honest about it.
`docs/RELEASE_PROCESS.md` must say so, because a reader deciding whether to trust a
Ferryman release deserves to know what the signature actually attests to.

**Two keys to keep track of instead of one.** The personal key keeps signing commits and
keeps its passphrase; the release key signs releases and does not. Confusing them is the
failure mode to design against — hence a different key with a different name in a
different place, rather than the same key with a flag.

**It is not a launch blocker and should not be treated as one.** An unattended pipeline
that can produce signed artefacts is exactly the kind of thing to get wrong when rushed.

## What this is not

Not a way to release without a human. Every release still needs a person to look at what
is being shipped and say yes — this changes where they are standing, not whether they
are there.
