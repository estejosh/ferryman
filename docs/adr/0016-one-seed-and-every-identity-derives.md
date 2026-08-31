# ADR 0016: One seed, and every identity derives from it

## Status

Accepted.

> **Implementation note, 2026-08-31.** The derivation is implemented in
> `crates/ferryman-channel/src/seed.rs`: `OperatorSeed`, the HKDF-SHA256 derivations
> (signing, encryption, and the operator's own key below), and the derive-then-persist
> branch in `AgentIdentity::load_or_create` and `EncryptionIdentity::load_or_create`. A
> machine with no seed is unchanged, and no identity that already holds a key is re-keyed.
>
> The recovery phrase (BIP-39, 24 words) round-trips the seed through `seed_to_phrase`
> and `phrase_to_seed`. `ferry identity show` and `ferry identity recover` expose it at a
> terminal, which is the fallback for a headless box. The primary path is the web
> dashboard: the first time it is opened with no operator on the machine, it creates the
> identity (seed and operator together) in the browser, shows the phrase once, and offers
> recovery from a phrase on a new machine. The dashboard operator's signing key now
> derives from the seed — see "The operator identity" below — and its password is demoted
> to the local unlock.

## Context

A person installing Ferryman today gets no identity. They get a binary. An identity
appears later, per agent, minted at random the first time `ferry enable` runs in a
project — and again for the encryption key, and again for the next agent name on the
same machine. One attachment on the author's machine holds five signing keys:
`beastly`, `beastlywsl`, `opencoder`, `programmer`, `telegram`.

Two rounds of work have already pulled at this thread. Keys became **machine-wide**
rather than per-project, so `Fang` in one project and `fang` in another stopped being
two identities. `ferry channel seat` exists to "put one identity's key into every
channel under a folder, so it can sign in all of them". Both are the same complaint:
identity is scattered, and the product keeps adding machinery to gather it up.

The comparison that prompted this is [Buzz](https://github.com/block/buzz), which
generates a keypair on first run and scopes everything a person ever does by it. Their
model is inherited from Nostr, and the part worth taking is not the cryptography — it
is that **the first thing that happens to a new user is that they become someone.**

Three concrete costs of not having that:

1. **There is nothing to back up.** Every private key on a machine exists only on that
   machine. The machine that wrote this paragraph had its filesystem go read-only with
   I/O errors the same week. Nothing was lost because everything was pushed; the keys
   would not have been.
2. **Verification is O(agents).** `docs/THREAT_MODEL.md` is honest that key pinning is
   trust-on-first-use and that the real fix is out-of-band verification. Out-of-band
   verification of *eleven* fingerprints is a thing nobody does. One fingerprint per
   person, once, is a thing somebody might.
3. **ADR 0010 says "a machine's access to a secret hangs off its owner's".** That is
   currently a sentence in a document, enforced by care. It could be arithmetic.

## Decision

### One seed, created when a person first installs Ferryman

`ferry enable` on a machine with no operator seed creates one: 32 random bytes, stored
at `0600` beside the other machine state, and shown to the operator **once** as a
recovery phrase. It is the only secret that has to survive.

### Every identity derives from it

```
signing key   for agent A    = HKDF-SHA256(seed, info = "ferryman/v1/sign/"    || A)
encryption key for agent A   = HKDF-SHA256(seed, info = "ferryman/v1/encrypt/" || A)
operator signing identity    = HKDF-SHA256(seed, info = "ferryman/v1/operator")
```

Distinct keys per agent, so the property the whole design rests on survives: when
something breaks at 3am you can still tell *which agent* did it, not merely which
machine. HKDF is one-way, so an agent holding its own derived key learns nothing about
the seed or about its siblings.

### The operator identity

The dashboard operator is **not** a second, unrelated identity; it is the seed, wearing
a name. Its signing key is the third derivation above, `"ferryman/v1/operator"` — a
purpose string with no agent name after it, so it can never collide with an agent's key
even on a machine that happens to run an agent named `operator`. Its public key is the
single fingerprint a person reads aloud to verify a machine out of band.

This closes the hole where a new user ended up with two unrelated identities — a
dashboard password and a separate recovery phrase covering different keys, with no
stated relationship. Now there is one: **phrase recovers, password unlocks.** The
password no longer mints or is the root of anything; it is the *local unlock* that seals
the derived operator key at rest (PBKDF2-SHA256 + XChaCha20-Poly1305, unchanged), and it
is what a person types to sign in. Nobody types 24 words to log in, and nobody recovers
the fleet with a guessed password.

An operator whose key already exists keeps it forever. Derivation is a bootstrap for new
operators, exactly as for agents: a key minted before the seed existed is never replaced
by the seed's derivation, and `ferry identity show` (and the dashboard's Identity page)
say plainly which identities derive and which predate the seed.

### Derivation is a bootstrap, not a permanent binding

The derived key is **written to the keystore on first use, and the keystore wins from
then on.** This is the part Nostr cannot do and the reason to prefer this shape over
copying theirs.

- **Recovery** re-derives every key from the seed, so one phrase restores a machine.
- **Rotation stays possible.** An agent whose key must change writes a new one to its
  keystore and the roster reports `KeyChanged` exactly as it does now. The seed does
  not have to change, and the other agents are untouched. In a pure-derivation model —
  Nostr's — rotating anything means abandoning the identity.

### Nothing that has already signed is re-keyed

The existing rule holds without amendment: *"An identity that has already signed things
must never change. Swapping it would make this agent sign as a key the roster has not
seen, and the roster - rightly - reports that as impersonation."* Derivation applies to
identities being minted, never to established ones, in the same way machine-wide
unification was applied only to new attachments.

## Consequences

**`ferry channel seat` becomes unnecessary for anyone starting after this.** A machine
holding the seed can sign in any channel by construction. The command stays for fleets
that predate this.

**The install story changes shape.** "Run this, then run enable, then share a folder"
becomes "run this — you are `<name>`, here is your recovery phrase, write it down".
That is a first thirty seconds worth having, and it is the point of the change.

**ADR 0015 is wrong and is superseded on this point.** It states that an agent's X25519
encryption key "is derived from the same seed". It is not: `EncryptionIdentity::
load_or_create` fills 32 bytes from the RNG. ADR 0010 describes the truth — a separate
keypair — and the code follows ADR 0010. After this ADR, ADR 0015's sentence becomes
true for the first time, by a different route than it meant.

## The costs, stated plainly

**One seed is one blast radius.** Today, a leaked agent key forges that agent. After
this, a leaked seed forges every identity that has not since rotated. This is a real
loss and it buys recoverability; it is the same trade every hardware wallet makes, and
it is only worth it because the seed never travels — it is not in the channel, not in
any project directory, and not on any machine but the operator's.

**A recovery phrase is a thing a person can lose.** Ferryman's answer to losing a key
today is "you cannot; there is no recovery". Its answer after this is "restore from the
phrase", which is better only for people who kept it. The dashboard must make writing it
down the hard-to-skip step, and it must never offer to store it anywhere.

**It does not remove trust-on-first-use.** A stranger still learns your key by seeing
it. What changes is that there is now exactly one fingerprint per person to check out of
band instead of one per agent per project, which moves out-of-band verification from
theoretically-correct to actually-done.
