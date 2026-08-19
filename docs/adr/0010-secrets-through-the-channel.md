# ADR 0010: Secrets through the channel

## Status

Proposed. Design only; implementation is a separate order.

## Context

A secret set up today has to be carried to every machine by hand. The GitHub PAT is
`ferrymangh` on beastly and `GHEstejoshFerrymanFMPATFull` on this box; the Telegram
token had to be placed separately again. The operator wants to set a secret ONCE, on one
device, and have every machine that should have it receive it, without touching those
machines.

Ferryman already has the hard part:

- Every agent has an ed25519 signing keypair, generated at join
  (`AgentIdentity::load_or_create`, `enable.rs:283`). The private half is written beside
  the existing key in the non-synced state directory (`<attachment>/keys/<name>.key`,
  `lib.rs:1287`, owner-0600 via `restrict_to_owner`); the public half is published in the
  roster (`<communications>/agents/<name>.json`).
- Syncthing already delivers the roster and every other channel artifact everywhere.
- Orders are signed (`AgentIdentity::sign_order`, `lib.rs:1414`) and verified against the
  roster on read (`verify_order` -> `check_signature`, `lib.rs:1537`).

That is a working PKI whose bootstrap problem `ferry channel join` already solves. So the
channel can carry ciphertext while private keys stay where they have always been. This
does not weaken "no keys in the channel" - it uses it: the channel has always carried
*public* keys and signed plaintext; it can equally carry *ciphertext*.

## Decision

### A separate X25519 keypair per agent

Each agent gets a second keypair, X25519 (RFC 7748), used only for encryption. It is
generated at `join`, stored beside the signing key (`<attachment>/keys/<name>.enc.key`,
owner-0600), never synced, and its public half is published as a new roster field.

It is separate from the ed25519 signing key on purpose. ed25519 (RFC 8032) and X25519
(RFC 7748) are different curves used for different primitives; reusing one key across
signing and DH is a shortcut that is fine until it is not. The signing key's job is
attributable statements; the encryption key's is confidential decryption. Keeping them
apart means a signing-key compromise does not by itself expose ciphertext, and a key-format
change on one primitive does not drag the other along.

**Agents that joined before this existed:** their roster entry has a signing `public_key`
but no encryption key. On the next `ferry channel join` (or lazily, on the first
`ferry secret` command), the agent generates its X25519 pair and publishes the public half
into its *own* `agents/<name>.json`. This is safe under the one-writer-per-path rule: an
agent only ever writes the file named after itself. The signing key is untouched. Until it
does so it is simply not a valid `--to` target (see "no key yet" below).

The field is additive: `#[serde(default, skip_serializing_if = "Option::is_none")]
pub encryption_key: Option<String>`. Old readers ignore it. (Implementer note: the
existing `register_agent_key` rebuilds `AgentRoute { name, role, capabilities, public_key }`
from scratch - `lib.rs:2745` - and would silently drop the new field; the join path must
carry `encryption_key` through, and pre-existing agents need a small publish-encryption-key
path that does not trip the signing-key first-key-wins guard.)

### Sealed per recipient

For each recipient the setter generates an *ephemeral* X25519 keypair, does ECDH against
the recipient's published X25519 public key, and encrypts the value with
XChaCha20-Poly1305 (24-byte nonce - note this differs from the 12-byte nonce in
`encrypt.rs`). The secret NAME and the PROJECT ID are bound in as AEAD associated data, so
a ciphertext cannot be replayed under a different name or moved into another project. The
recipient name is also bound, so an entry cannot be swapped between recipients' slots and
still decrypt.

The 32-byte X25519 shared secret is the AEAD key directly; no HKDF is required, and domain
separation is already provided by the AAD.
### Signed envelope, verified like an order

`secrets/<name>.json` is an envelope signed by whoever set it, exactly like an order: a
canonical payload string (name, project_id, sealed_by, sealed_at, and a digest of each
recipient entry), an ed25519 signature, and `signed_by`. On read the signature is checked
against the roster with `check_signature`.

One difference from the order path, and it is load-bearing: `check_signature` returns
`SignatureCheck::Unsigned` as "normal for a fleet that has not adopted signing"
(`lib.rs:1702`). For a secret that is NOT acceptable. An unsigned, invalid, or unknown-signer
envelope is rejected outright. A peer who can write to the synced folder can overwrite the
file, but it cannot forge the signature, so every reader refuses the tampered copy.

### Storage and scope

Stored at `<communications>/secrets/<name>.json`, so it lives in ONE project's channel and
reaches only devices sharing that project. Explicitly NOT the fleet folder
(`ferryman-fleet`, `licensing.rs:158`) - that syncs to everything, the opposite of what
this needs.

Recipient scope sits on top of channel scope: `--to grouchly,beastlywsl`. These are two
independent limits, neither relying on the other. A phone in the channel carries the
channel copy but no ciphertext addressed to it.

### CLI

- `ferry secret set <name> [--to ...]` reads the value from a prompt (`rpassword`, already
  a dependency) or stdin, NEVER from argv, because `/proc/<pid>/cmdline` is world-readable.
  It refuses to seal to a recipient with no published encryption key, naming the recipient.
- `ferry secret list` shows names, recipients, who sealed it, and when - never values.
- `ferry secret get <name>` decrypts locally (for debugging) and refuses if this agent is
  not a recipient.
- `ferry secret rm <name>` removes the envelope.

### Resolution

A `credentials.json` value of `secret:<name>` resolves through this store at the point
credentials are injected into the agent CLI (`agent.rs:1808`). Literal values keep working,
so nothing existing breaks.

Resolution rule: `secret:<name>` is recognized only when `<name>` names a secret envelope
this agent can decrypt, and then resolves to the decrypted value. If `<name>` does not
resolve (unknown name, not a recipient, bad signature), the command fails loudly - it never
silently falls back to treating `secret:<name>` as a literal, because that would quietly
inject the literal string `secret:<name>` into the agent's environment. A literal value
that itself begins with `secret:` therefore needs no escape: `secret:` is only special when
it names a resolvable secret.

## What this does NOT give

- **Rotation is the only real revocation.** Once ciphertext has synced it is on those
  disks and in Syncthing's history. Removing an agent from the roster, or deleting the
  envelope, does not unsend it: the copies already made remain. The only way to invalidate
  a value is to change the value itself (rotate the PAT/token) and re-seal.
- **No forward secrecy.** The ephemeral X25519 keypair keeps the setter's long-term key out
  of the path and gives each seal fresh key material, but the recipient's *static* X25519
  key is still what decrypts. A machine whose private encryption key is compromised exposes
  everything ever sealed to it. True forward secrecy would need per-secret recipient key
  rotation, which a synced, offline channel cannot do.
- **A recipient with no encryption key yet** (a pre-existing agent that has not re-joined)
  is simply not sealable-to: `set --to x` refuses and names x. A reader that cannot decrypt
  - not a recipient, no local key, or a key that does not match - fails loudly and
  specifically; it never falls back to an empty value or silently skips the entry.

## What needs adding

- `x25519-dalek` is the one genuinely new dependency (ECDH). Everything else is already in
  the workspace: `chacha20poly1305 = "0.10"` provides XChaCha20-Poly1305 (already used in
  `ferryman-key.rs`), `ed25519-dalek` for the envelope signature, and `hex` / `serde` /
  `serde_json` / `rand` / `rpassword` for everything else. The existing `encrypt.rs` is
  master-secret at-rest encryption, not a reusable sealed-store API; the reusable pieces
  are the AEAD usage, `atomic_json` (`lib.rs:587`), and `restrict_to_owner` (`lib.rs:1658`).
- A new `secrets` module in `ferryman-channel` (keypair generation/storage, seal/open,
  envelope sign/verify), plus the CLI subcommand and the `credentials.json` resolution
  step. `credentials.rs` is not modified.

## Consequences

Positive: a secret is set once and reaches exactly the machines that should have it,
attributable and tamper-evident. Negative: no revocation short of rotation, and a leaked
recipient key exposes all ciphertext ever addressed to it. The fleet folder is deliberately
not used.


