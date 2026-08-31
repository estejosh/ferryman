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

**Telegram carries the doorbell. The channel carries the authorisation. Neither carries
the secret.**

### The mistake this avoids

The obvious design is: leave the key usable on the signing machine, and let a Telegram
`/release approve` trigger it. It is wrong, and the reason is a fact about this fleet
rather than a hypothetical.

`phone.key` is not on a phone. The `phone` identity signs on whichever machine runs the
bridge — beastly holds no such key, and ADR 0008 says so outright: the bot "shells out to
the local CLI that already owns the key". So a Telegram approval signed as `phone` proves
**the bridge machine acted**. It does not prove the operator did.

An approval gate whose key lives on the machine being gated is not a gate. It would look
like two parties and be one, and the bot token would be the whole of the security. That is
worse than having no gate at all, because it reads as safe.

So the authorisation has to be signed by a key on a device the operator actually holds.

### The design

The release key stays **encrypted at rest** on the signing machine. What unlocks it does
not live there.

1. The fleet prepares the release — version bumped, changelog written, CI green, commit
   pushed — and raises a signed **release request** in the channel naming the version, the
   exact commit, the CI conclusion, and the changelog summary.
2. Telegram shows the operator what is being approved. This is a notification and a human
   decision surface, nothing more. It holds no authority.
3. The operator approves **from a device that holds a key** — anything that can run
   `ferry`: a phone with Termux, a tablet, whichever laptop they are near. That device
   writes a signed approval naming the version and the commit, and **seals the unlock for
   the release key to the signing machine's X25519 key**.
4. The signing machine opens the seal — which only it can — verifies the approval against
   the roster, tags, signs, and pushes. The unlock exists in its memory for one operation
   and is never written down.

### Why this is the product's own thesis

Every primitive here already exists and is already the documented rule. Secrets are set up
once on one device and travel encrypted through the channel. Plaintext credentials never go
into Telegram; **sealed ciphertext travels the channel freely**. One writer per path.
Records signed and verified against the roster.

This is that machinery pointed at Ferryman's own release process — which is also the
honest test of whether the machinery is any good. A secrets layer nobody trusts with their
own signing key is a secrets layer that has not been used for anything yet.

### What it buys

**The fleet alone can never produce a release.** Not the orchestrator, not a worker, not a
compromised bridge, not the bot token. The signing machine holds a key it cannot open; the
operator's device holds what opens it; a release needs both. That is the property the
current passphrase arrangement has, kept — and the operator stops having to be at a
particular desk to exercise it.

### A release identity, not a personal one

The key that signs releases is **not** the operator's personal GPG identity, and its public
half is published in the repo and in `docs/RELEASE_PROCESS.md` exactly as the current one
is.

Even sealed at rest, a personal key on a machine that runs autonomous agents puts every
commit that key has ever meant behind the weakest process on that box. A release key
forfeits releases and nothing else, and it rotates without touching who he is.

### The weaker tier, named so it is chosen and not drifted into

If the operator has only Telegram and no device running `ferry`, a Telegram-only approval
can still trigger a release — but then the gate really is "bot token plus bridge machine",
and that must be stated in `docs/RELEASE_PROCESS.md` rather than implied away. It is a
reasonable trade for a preview build and a poor one for anything a stranger installs.
Whichever tier produced a release is recorded in the tag message, because a person reading
`git tag -v` a year from now should be able to tell which arrangement they are trusting.

### What refuses

- An approval that does not verify, or from a name the roster does not know.
- An approval whose version or **commit** does not match the request. Approving *this*
  release must never authorise a different one; this is the attack the design turns on.
- A request older than a short horizon. An approval sitting unread overnight is not consent
  to ship whatever main became.
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
