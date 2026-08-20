# ADR 0010: Secrets through the channel

## Status

Accepted, implemented.

## Context

A secret set up today has to be carried to every machine by hand. The GitHub PAT is
`ferrymangh` on one machine and `GHEstejoshFerrymanFMPATFull` on another; the Telegram
token had to be placed separately again. The operator wants to set a secret ONCE, on one
device, and have every machine that should have it receive it, without touching those
machines.

Ferryman already has the hard part: every agent has an ed25519 signing keypair published
in the roster, and Syncthing already delivers the roster and every other channel artifact
everywhere. That is a working PKI whose bootstrap problem `ferry channel join` already
solves, so the channel can carry ciphertext while private keys stay where they have always
been. This uses "no keys in the channel" rather than weakening it: the channel has always
carried *public* keys and signed plaintext; it can equally carry *ciphertext*.

## Decision

### The interface is the dashboard, not the CLI

The operator does not want a command line ("no command line bullshit"). Setting a secret
is something he does in the dashboard, in a browser, with a form. `ferry dashboard`
already serves this project's channel, authenticates an operator against a
password-protected identity, binds loopback only, and already lets him approve or send
back work. Secrets belong there, next to the things he already goes there to do.

So the inversion: **the dashboard form is the interface; the CLI is the thing the form
calls**, and exists for scripts and for machines with no browser - not as the way a human
does this. Both paths call the same `channel::secrets` module, so the form is not a second
implementation of the sealing, it is a second caller of the same one.

### Sealing happens under the OPERATOR's identity

This inversion has a real consequence. Sealing from the dashboard happens under the
**operator's** identity, not a machine key. Concretely:

- **Who signs the envelope: the operator.** The dashboard session already holds the
  operator's unlocked ed25519 identity (`role: operator` in the roster). That identity
  signs the envelope, and readers verify it against the roster exactly like any other
  signature. The machine's own agent is not involved in sealing at all.
- **The operator does NOT need an encryption key of their own.** Sealing only requires
  each *recipient's* published X25519 public key plus an ephemeral keypair; the setter
  never decrypts, so the setter needs no X25519 keypair. Encryption keys are for
  recipients (agents), not for sealers. Operators therefore keep only their existing
  signing identity.
- **A dashboard running on a machine whose agent is not a recipient** can still set and
  list secrets: setting only needs the operator's signing key and the recipients' public
  keys, and listing only reads summaries, never values. What it cannot do is *reveal* a
  value: `secret:<name>` resolution and `get` run against the local agent's encryption
  key, so a non-recipient machine fails loudly - "this machine's agent is not a
  recipient of secret X" - never returning an empty or partial value. The operator who
  just typed the value into the form already has it, so this does not block setting.

### A separate X25519 keypair per agent (for recipients)

Each agent gets a second keypair, X25519 (RFC 7748), used only for decryption. It is
generated at `enable`/`join`, stored beside the signing key
(`<attachment>/keys/<name>.enc.key`, owner-0600), never synced, and its public half is
published as a new roster field `encryption_key`. It is machine-wide like the signing
key, so an agent is the same recipient in every project. It is separate from the ed25519
signing key on purpose: a signing-key compromise must not by itself expose ciphertext,
and a key-format change on one primitive must not drag the other along. The field is
additive (`#[serde(default, skip_serializing_if = "Option::is_none")]`), so old readers
ignore it; pre-existing agents simply have no `encryption_key` until they re-join and are
not valid recipients until then.

### Sealed per recipient

For each recipient the setter generates an *ephemeral* X25519 keypair and does ECDH
against the recipient's published X25519 public key. The shared secret is **not** used as
a key directly: it goes through HKDF-SHA256, salted with the ephemeral and recipient
public keys, exactly as `age` does. An X25519 output is a curve point's x-coordinate, not
thirty-two uniformly random bytes, and RFC 7748 says to hash it before use; NaCl's
`crypto_box` runs it through HSalsa20 for the same reason. Using it raw was the one place
this design contradicted its own rule below about not hand-writing constructions - the
practical risk was small, since the envelope is signed and no attacker can inject an
ephemeral key, but "probably fine" is worth less than not having to say it. Salting with
both public keys binds the key to that exact pair rather than to the shared secret alone.
The derived key encrypts the value with XChaCha20-Poly1305 (24-byte nonce). The secret NAME, the PROJECT ID, and the RECIPIENT
name are bound in as AEAD associated data, so a ciphertext cannot be replayed under a
different name, moved into another project, or swapped between recipient slots and still
decrypt - independent of the signature.

### Signed envelope (the thing that beats agenix)

The whole envelope - name, project, every recipient slot, timestamp - is signed by the
setter's roster identity and verified against the roster before any decryption. This is
the property agenix documents itself as NOT having: agenix's encrypted files are
unauthenticated, so anyone with write access to the repository can replace them. The
signed envelope is what Ferryman adds over that; a tampered envelope fails signature
verification before it is ever opened, and tampering with any field (including a
ciphertext) invalidates the signature first.

### Wrapping an audited implementation versus hand-rolling

**Recommendation: hand-roll the sealing on the audited primitive crates, not wrap the
`age` file-format crate.** The `age` crate, linked in rather than shelled out to, is
audited - but it is a *file/armor format*, not a string-sealing primitive, and it cannot
express this design's requirement to bind name + project + recipient as AEAD associated
data per recipient slot. The audited pieces `age` uses internally are the very crates we
link directly: `curve25519-dalek` (X25519 ECDH) and `chacha20poly1305`
(XChaCha20-Poly1305), the latter already in-tree for operator sealing. So no new curve
math or AEAD construction is hand-written, the single-static-binary property is
preserved, and the one thing agenix lacks - authentication - is supplied by our signed
envelope on top either way; wrapping `age` would not have bought that property. This is
the thing the implementation must beat, and its tests prove it: flipping a byte in a
ciphertext, or re-signing as a different identity, both fail open.

### Storage, scope, and resolution

The envelope lives at `<communications>/secrets/<name>.json` - one project's channel,
reaching only devices sharing that project. Explicitly NOT the fleet folder
(`ferryman-fleet`): that syncs to everything, the opposite of what this needs. Recipient
scope sits on top of channel scope (`--to grouchly,beastlywsl`): two independent limits,
neither relying on the other.

A `credentials.json` value of `secret:<name>` is a reference only when `<name>` names an
envelope this agent can decrypt, and then resolves to the decrypted value. If `<name>`
names an envelope this agent cannot decrypt (not a recipient, no local key, bad
signature), the command fails loudly - never an empty string, never the literal
`secret:<name>`. A value that happens to begin with `secret:` but names no envelope is a
literal and passes through untouched, so no escaping is needed. Literal values keep
working, so nothing existing breaks. Values are never placed on argv; the CLI reads them
from the terminal (hidden) or stdin, and the dashboard's form posts them to a loopback
endpoint that seals them in memory.

## Constraints

- **Separate encryption keys from signing keys.** X25519 for decryption, ed25519 for
  attribution.
- **The shared secret is put through a KDF**, never used as a key directly.
- **Name and project bound as associated data**, and the recipient name too.
- **Envelope signed and verified against the roster.** An unsigned envelope is a forged
  one.
- **Stored in one project's channel, never the fleet folder.**
- **Recipient scope on top of channel scope.**
- **Values never on argv** (or in shell history, the process list, or the bridge).
- **Literals in `credentials.json` keep working.**
- **A reader that cannot decrypt fails loudly**, never handing the engine an empty string.
- **Secrets never travel through the Telegram bridge.** A cloud chat is not end-to-end
  encrypted, so a token typed there lives on someone else's servers and syncs to every
  device signed into that account. Orders are fine to leak; a credential is not. This is
  documented in the bridge module and the README, and it is *why the dashboard is the
  path*: the dashboard is loopback-only and operator-authenticated.
- **Usable by someone who has never heard of age or sops.** The measure: can a person
  with no prior knowledge set a secret correctly on the first try, without reading
  anything? The form asks for three things in plain words - a name, a value, and which
  machines - and shows existing secrets as a list. If this needed a paragraph of
  explanation, the design would be wrong.

## Consequences

Positive: a secret is set once and reaches exactly the machines that should have it,
attributable and tamper-evident, through the same loopback dashboard the operator already
uses. Negative: no revocation short of rotation (once ciphertext has synced it is on those
disks and in Syncthing's history), and a leaked recipient encryption key exposes
everything ever sealed to it. The fleet folder is deliberately not used.

