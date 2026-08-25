# Recipient-bound secret transport proposal

Status: product and security contract for the dashboard prototype. Cryptographic
storage, delivery, and use-only enforcement are not implemented on this branch.

## User outcome

A repository owner can place an existing API key, Git credential, or other
secret in their local Ferryman vault, then assign that specific key to exactly
one named human for one repository and one approved purpose. Ferryman transports
the encrypted grant. Only the recipient's device can open it, and approved
agents use it through a local broker without learning the plaintext value.

The novice path is: **Vault → Assign key → choose one teammate → choose one
repository → choose purpose and duration → review → send → recipient accepts**.
Every screen states what changes, what stays local, and who remains in control.

## Non-negotiable boundaries

- A grant has one human recipient. Groups, wildcard recipients, and recipient
  delegation are invalid.
- A secret may additionally be sealed to a *machine*, so unattended work can
  open a credential with nobody present. That is not a second, independent
  grant: every machine recipient is recorded against the person who owns it,
  and revoking the person revokes their machines in the same act. See
  ADR 0010, "Who a secret may be sealed to". Two independent lists would leave
  a revoked teammate's laptop working, which is the failure this rule exists to
  prevent.
- Human signing keys and human encryption keys are separate key pairs. Existing
  Ed25519 identity material must not be reused as an encryption key.
- The key value is accepted only by the owner's encrypted local vault. It is
  never written to a channel directory, Git object, task, result, log, audit
  record, browser storage, or dashboard HTML.
- Ferryman delivery paths carry ciphertext and signed metadata only.
- Reveal and copy are off by default. The preferred mode is **use-only**: a
  local broker performs an approved API or Git credential operation without
  returning plaintext to the user or agent.
- Revocation is checked before every broker use. Expired, revoked, replayed,
  unverifiable, or scope-mismatched grants fail closed.
- If plaintext was ever revealed or copied, revoking the Ferryman grant cannot
  erase that copy; the upstream credential must also be rotated.

## Identity and envelope

Each human operator publishes two independently generated public keys:

1. a signing key for authorship, approvals, receipts, and revocations;
2. an encryption key for recipient-bound envelopes.

The owner's vault generates a fresh random content-encryption key, encrypts the
secret plus use policy, then wraps that content key to the recipient's public
encryption key using an audited recipient encryption construction such as HPKE.
The owner signs the grant metadata and ciphertext digest.

Conceptual envelope:

```json
{
  "schema": "ferryman.secret-grant.v1",
  "grant_id": "grant-uuid",
  "version": 1,
  "secret_id": "owner-local-stable-id",
  "owner": "bob",
  "recipient": "maya",
  "recipient_encryption_key_id": "maya-enc-2026-08",
  "repository": "ferryman",
  "approved_agents": ["programmer"],
  "purpose": "Use OpenRouter ox-alpha for Ferryman coding tasks",
  "permissions": {"use": true, "reveal": false, "delegate": false},
  "not_before": "timestamp",
  "expires_at": "timestamp-or-null",
  "nonce": "unique-random-value",
  "wrapped_content_key": "ciphertext",
  "ciphertext": "ciphertext",
  "owner_signature": "signature"
}
```

The recipient verifies the schema, owner signature, recipient identity, key id,
repository, time window, grant version, and unused nonce before decrypting. HPKE
does not by itself provide replay protection, so Ferryman must maintain explicit
accepted/spent nonce and grant-version state.

## Ferryman transport

The existing delivery order remains unchanged:

1. local filesystem delivery when sender and recipient share a machine;
2. shared/synced Ferryman delivery when available;
3. per-message private-Git fallback.

Only the envelope enters those paths. The decrypted credential is stored in the
recipient's encrypted outer Ferryman vault, outside the synced project/channel
folder. Delivery produces signed sent, delivered, declined, and accepted
receipts. A delivery receipt does not activate the grant; recipient acceptance
and local policy installation do.

## Use-only broker

The recipient's local broker is the enforcement point. A request includes the
human identity, agent identity, grant id/version, repository, operation, and
purpose. The broker verifies current grant status before each use and returns
only the operation result or a short-lived provider-specific credential handle.

- For Git HTTPS, Ferryman can expose a custom Git credential helper and bind
  permission to the complete repository URL/path. It must not use Git's
  plaintext credential store.
- For APIs, Ferryman can spawn the approved process with an isolated credential
  channel or proxy the request locally. Environment inheritance into unrelated
  processes is not an acceptable default.
- Logs redact authorization headers, query-string secrets, request bodies that
  may contain secrets, subprocess environments, and provider responses that echo
  credentials.

Use-only reduces casual disclosure but is not a promise that an untrusted
process can never misuse an authorized operation. Provider-side least privilege,
repository-limited tokens, rate limits, expiry, rotation, and owner monitoring
remain required.

## Grant lifecycle

```text
draft → prepared → sent → delivered → accepted → active
                                           ↘ declined
active → expired
active → revoked
```

- `prepared`: recipient key and all policy fields are frozen and owner-signed.
- `sent`: immutable ciphertext has entered Ferryman transport.
- `accepted`: recipient signature confirms local decryption and policy review.
- `active`: local broker installed the policy and can confirm revocation state.
- `revoked`: owner published a signed revocation for grant id and version.
- `expired`: the signed expiry passed; no network round trip is needed to deny.

Changing recipient, repository, approved agents, purpose, permissions, or
duration creates a new version and envelope. A grant is never reassigned.

## Audit record

Audit records contain metadata, not values: actor, recipient, secret id/name,
provider/type, repository, approved agents, purpose, permissions, duration,
grant id/version, timestamps, delivery route, receipt status, use decision,
revocation, and rotation requirement. Secret values, authorization headers,
wrapped keys, raw ciphertext, and decrypted provider responses are excluded from
normal dashboard audit views.

## Proposed interfaces

Names are provisional and should be finalized with the CLI contract:

```sh
ferry vault add --name "OpenRouter ox-alpha" --type api-key
ferry vault grant prepare --secret <id> --to maya --repo ferryman \
  --agent programmer --purpose "Ferryman coding" --expires 30d --use-only
ferry vault grant send <grant-id>
ferry vault grant accept <grant-id>
ferry vault grant revoke <grant-id>
ferry vault grants --incoming
ferry vault audit
```

`vault add` must read the value from a protected prompt or OS credential API,
never a positional argument. JSON equivalents should power the dashboard and
return metadata/status only.

## Implementation sequence

1. Add separate human encryption identities, rotation, roster publication, and
   recovery rules.
2. Implement an encrypted local outer vault using an OS-backed key when
   available, with explicit unlock behavior and secure file permissions.
3. Define canonical grant, receipt, revocation, replay, and audit schemas with
   signature test vectors.
4. Add recipient encryption and ciphertext-only delivery through Ferryman's
   existing local/shared/private-Git engine.
5. Implement acceptance, revocation synchronization, expiry, and replay state.
6. Build the use-only API broker and Git credential helper; test process,
   repository, agent, and purpose isolation.
7. Connect the dashboard controls only after adversarial, recovery, rotation,
   and end-to-end tests pass.

## Prototype truthfulness

The current dashboard is an interactive proposal. Demo mode simulates prepare,
send, accept, audit, and revoke states using synthetic metadata. Production mode
does not request a secret, transmit an envelope, or claim that authority changed.
