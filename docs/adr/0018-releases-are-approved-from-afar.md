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

**Approving a release is a dashboard action, authenticated by the operator's password.
Telegram is the doorbell. No new key, no new device, no command line.**

### Two mistakes this avoids

The first draft said: leave the release key usable on the signing machine and let a
Telegram `/release approve` trigger it. Wrong, for a reason about this fleet rather than a
hypothetical. `phone.key` is not on a phone — the `phone` identity signs on whichever
machine runs the bridge, and ADR 0008 says so outright: the bot "shells out to the local
CLI that already owns the key". An approval signed as `phone` proves the *bridge machine*
acted, not that the operator did. A gate whose key lives on the machine being gated is not
a gate; it looks like two parties and is one.

The second draft fixed the cryptography and broke the product: it had the operator run
`ferry` on a phone to sign the approval. Ferryman is for people who are not going to
install a terminal emulator on their phone, and a design that assumes otherwise has
quietly changed who the product is for. Correct and unusable is not correct.

### What was already here

The operator identity is **already** the right primitive, and it was built two ADRs ago
without anyone noticing it solved this.

An operator's signing key derives from the machine seed (ADR 0016) and is **sealed at rest
with their password** — PBKDF2-SHA256 at 600k iterations and XChaCha20-Poly1305. The
dashboard process does not hold that key until the person signs in, and holds it only in
memory for the life of the session.

Which means the property this ADR needs already exists: **the fleet cannot sign as the
operator, because the fleet does not have the password.** No new key, no second device, no
new secret to lose. The thing that authorises is a password in the operator's head, and the
thing being authorised is a key on the machine that is useless without it.

### The flow

1. The fleet prepares the release — version bumped, changelog written, CI green, commit
   pushed — and raises a signed **release request** in the channel naming the version, the
   exact commit, the CI conclusion, and the changelog summary. Nothing is tagged.
2. Telegram says a release is waiting and links to it. That is all Telegram does: it holds
   no authority and must not be able to cause a signature.
3. The operator opens the dashboard — on a phone, on a laptop, on whatever is to hand —
   and signs in. Signing in unseals their operator key with their password.
4. They see what is being approved: version, commit, CI, changelog. Then they approve, and
   the dashboard signs the approval with the operator key that is now in memory.
5. The signing machine verifies the approval against the roster, tags, signs, and pushes.

Step 3 is the entire security model and it is also just "log in". That is the point.

### Reaching it from afar

The dashboard binds to loopback, which is right and should stay right. Reaching it from
outside is a **transport** problem, not a trust problem: a tunnel the operator already runs
(cloudflared, Tailscale) puts the same loopback page on their phone without weakening
anything. Whatever fronts it must not be allowed to become an authority — it carries bytes
to a page that still demands a password.

The Host guard must therefore be relaxed deliberately and narrowly, if at all, and the
default stays loopback-only. An operator who has not set up a tunnel is not locked out;
they approve the next time they are on the network, exactly as today they approve the next
time they are at the machine.

### A release identity, not a personal one

The key that finally signs the tag is **not** the operator's personal GPG identity. Its
public half is published in the repo and in `docs/RELEASE_PROCESS.md` exactly as the
current one is. Even sealed, a personal key on a box running autonomous agents puts every
commit that key has ever meant behind the weakest process on that machine. A release key
forfeits releases and nothing else, and rotates without touching who he is.

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
