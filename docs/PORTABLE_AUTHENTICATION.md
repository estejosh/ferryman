# Portable message authentication

Status: implementation design; unsigned v1 transport remains
unsafe until this document's enforcement gate is complete.

## Security objective

Possession of write access to the MEGA folder or private Git repository must
not grant authority to create work or report it complete. Ferryman must
authenticate the origin and authorization of every portable message,
acknowledgement, and future claim before it can affect local state.

Transport encryption and transport authentication are different controls.
Private Git and MEGA limit who can read or write the transport, but Ferryman
still verifies every envelope independently.

## Identity and key storage

Each Ferryman hub has an Ed25519 signing identity:

- the private key is generated locally and stored in the operating-system
  keychain; it is never written below a project or portable communications
  root;
- the signer ID is `sha256:<hex SHA-256 of the public key>`;
- trusted public keys and their project-specific grants live in the outer,
  unsynchronized `<project>/.ferryman/trusted-signers.toml`;
- adding, rotating, or revoking a signer is an explicit operator action;
- the continuity recovery key is not reused for transport signing.

A trust grant binds one signer to a project, allowed sender identities or
roles, and allowed message capabilities. An acknowledgement signer must also
be authorized for the stored message's recipient identity or role.

## Version 2 envelope

Messages use `ferryman-message/v2`. Acknowledgements use
`ferryman-acknowledgement/v2`. Both add:

```json
{
  "authentication": {
    "algorithm": "ed25519",
    "signer_id": "sha256:<public-key-digest>",
    "key_version": 1,
    "nonce": "<128-bit random value encoded as lowercase hex>",
    "signature": "<Ed25519 signature encoded as lowercase hex>"
  }
}
```

The signature covers the RFC 8785 canonical JSON representation of the full
envelope with `authentication.signature` omitted. The domain separator is:

```text
ferryman-portable-envelope/v2\0<envelope-kind>\0
```

The acknowledgement body also includes `message_digest`, the SHA-256 digest of
the exact canonical signed message envelope. It therefore cannot be replayed
against a different serialization or a replaced message that reused an ID.

## Verification order

Inbound processing must:

1. bound the file size before parsing;
2. parse a supported version and reject duplicate JSON keys;
3. validate project and path identity;
4. resolve the signer from the outer trust store;
5. verify key version, validity interval, and revocation state;
6. verify the Ed25519 signature over the canonical envelope;
7. authorize the signed sender and requested capability;
8. reject a previously consumed `(signer_id, nonce)` pair;
9. apply the existing structural, payload, recipient, and idempotency checks;
10. durably record acceptance before making the message claimable or retiring
    an outbox item.

An acknowledgement additionally loads the exact stored message and compares
project ID, message ID, recipient, idempotency key, and message digest before
the outbox may be removed.

Invalid, unsigned, unknown-signer, revoked, unauthorized, replayed, or
over-sized files are moved to the machine-local quarantine with a reason
record. They are never returned by inbox APIs and never block later valid
files from being processed.

## Replay and clock rules

Message UUID and idempotency checks remain required. The signed nonce provides
a signer-scoped replay key. Accepted nonces and message digests are retained
in the outer machine-local ledger for at least the maximum message lifetime
plus the operator's recovery window.

Clock time is advisory for ordering and expiry, not the sole replay defense.
A clock moving backward must not make an accepted nonce valid again.

## Migration from v1

There is no permissive mixed-mode receiver.

- New sends switch to v2 only after a signing identity and trust grants exist.
- Unsigned inbound v1 files are quarantined once enforcement is enabled.
- A local v1 outbox entry may be converted only when Ferryman can prove it was
  created locally from its immutable delivery-attempt record. Conversion
  creates a new signed v2 envelope while preserving the original message ID
  and idempotency key and records the old and new digests.
- Other v1 files require operator review; transport location alone is not
  proof of origin.
- The migration command must support `--dry-run`, report every classification,
  and never print payloads or key material.

Enforcement is fail-closed. A hub that lacks its private key or trust store
reports communications as unavailable rather than accepting unsigned input.

## Implementation gates

1. Add signing identity generation/loading and public trust-store parsing.
2. Add canonical v2 message and acknowledgement types and signature tests.
3. Sign at the authenticated API boundary and verify before listing, reading,
   claiming, acknowledging, or retiring.
4. Add bounded quarantine processing and replay ledger persistence.
5. Add dry-run v1 inventory/conversion tooling.
6. Test tampering of every signed field, unknown/revoked/wrong-role signers,
   nonce replay, cross-project replay, acknowledgement substitution, key
   rotation, and restart persistence.
7. Exercise the signed flow through temporary local Git before declaring the
   portable transport safe.
