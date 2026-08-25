# Human teammate invitation and guided installation proposal

Status: dashboard proposal; no invitation authority or machine installer is live.

## Outcome

An existing Ferryman owner should be able to invite one named human from the
dashboard. The recipient should understand what will be installed, consent to
every machine-changing action, create their own human operator identity, and
finish only after Ferryman verifies channel and dashboard access end to end.

This is a human onboarding flow. It does not create an AI agent and does not
grant access to another person's agents.

## Dashboard journey

### Owner

1. Open **Teammates > Invite teammate**.
2. Enter the recipient's name and work email.
3. Choose Reviewer, Maintainer, or Owner.
4. Choose one project or an explicit business-wide scope.
5. Review starting human permissions and invitation expiry.
6. Preview the exact setup the recipient will see.
7. Create a signed, one-use invitation and send the resulting link.

### Recipient

1. Inspect the inviter, business, project, role, expiry, and excluded access.
2. Run a read-only readiness check for the operating system, Ferry CLI,
   Syncthing, and the expected communications folder.
3. Review and approve the platform-specific Ferry installation command.
4. Choose the local path for the already-shared Syncthing channel folder.
5. Create a password-sealed human operator identity locally.
6. Accept the invitation by publishing the public key plus the one-time proof.
7. Open the dashboard and verify roster membership, synchronization, project
   scope, and a signed test message.

## What Ferryman helps install

- the `ferry` CLI, after showing the exact platform command;
- local Ferryman configuration for the selected project;
- connection to the existing Syncthing communications folder;
- a local password-sealed human operator identity;
- a dashboard launch and end-to-end readiness check.

Ferryman must not silently install software, select a sync path, accept legal
terms, or make a new identity for the recipient without confirmation.

## Security contract

The invitation envelope contains only:

- invitation id and nonce hash;
- issuer identity and signature;
- intended recipient;
- business, project, and human role;
- starting human permissions;
- issued time, expiry, and maximum use count of one.

The raw invitation secret appears only in the recipient's link. Ferryman stores
its hash, spends it atomically on acceptance, and rejects replay, expiry,
revocation, issuer mismatch, or changed scope.

Acceptance creates the private signing key on the recipient's machine. Only the
public key and signed invitation proof enter the shared channel. The invitation
never contains API keys, GitHub tokens, repository credentials, passwords,
agent private keys, personal-agent grants, publishing rights, or spending
authority.

## Proposed lifecycle

`draft -> sent -> opened -> preflight -> accepted -> verified`

Terminal alternatives are `revoked`, `expired`, and `failed_verification`.
Acceptance is not success: the dashboard reports the teammate as active only
after verification completes.

## Proposed CLI

```text
ferry team invite create --email alex@example.com --role reviewer --project ferryman --expires 7d
ferry team invite inspect <code-or-url> --json
ferry team invite accept <code-or-url>
ferry setup doctor --project ferryman --json
ferry team invite revoke <invitation-id>
```

Every command should support structured JSON output so the dashboard can show
progress without parsing prose.

## Proposed dashboard API

- `POST /api/team/invitations` — create a signed one-use invitation.
- `GET /join/{secret}` — return public invitation metadata only.
- `POST /api/team/invitations/{id}/preflight` — record non-mutating readiness.
- `POST /api/team/invitations/{id}/accept` — bind the recipient public key.
- `GET /api/team/invitations/{id}` — report lifecycle and verification.
- `DELETE /api/team/invitations/{id}` — revoke an unspent invitation.

Creation and revocation require an authenticated owner with invite authority.
The public join route is rate limited and exposes no roster, project paths,
email directory, tokens, or secrets.

## MVP sequence

1. Persist signed invitation records and implement create, inspect, revoke, and
   atomic acceptance.
2. Add `ferry setup doctor --json` with OS, CLI, Syncthing, folder, roster, and
   dashboard checks.
3. Connect the existing dashboard proposal to the invitation endpoints.
4. Add platform installers that always preview commands and require consent.
5. Add verification, audit events, expiry cleanup, resend, and recovery states.

Agent sharing remains a separate project. Once the human is verified, they may
request scoped access to personal agents or use business agents permitted by
business policy.
