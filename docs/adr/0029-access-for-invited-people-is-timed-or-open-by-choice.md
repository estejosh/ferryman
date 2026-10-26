# ADR 0029: Access for invited people is timed or open, by choice

## Status

Accepted.

## Context

An invitation had one clock, and it was the wrong one. The code stopped working for joining
after seven days (`expires_days`), but what the code led to, a master-signed grant, lasted
until someone remembered to revoke it. A contractor invited for a month kept access for
as long as nobody noticed, and "nobody noticed" is the default state of an access list.

The master wanted three things:

1. The code still times out, and says so on the dashboard form.
2. The access an invitation gives is either timed (N days) or open, and the master chooses
   on every invitation. A default would be a decision made for them, in the one place
   where the safe choice and the convenient choice differ.
3. A few days before timed access ends, the master is asked, with two buttons, whether to
   renew it. Nobody answering means it ends on the date.

Three things already existed and shaped the answer. A revocation is checked by every gate
(`master::is_revoked`, `is_revoked_in`): the channel's gate, a worker taking work, the iroh
lane's admission, a delegate's standing, the doctor. The master's signed answers to
questions (`questions.rs`) already travel the channel and reach Telegram as buttons. And a
machine that joins under a person inherits that person's standing through an owner
attestation.

## Decision

**The access has an end that is signed.** `MasterGrant` gains `expires_at`, and the grant
signature covers it. It is appended to the signed payload only when present
(`\nexpires:<rfc3339>`), so every grant written before this signs exactly the bytes it
always did and still verifies. An `Invite` gains `access_days`, signed the same way
(`\naccess_days=<n>`), so an invitation cannot be edited to promise more time. A legacy
invitation has none, which means no expiry. `invite::create` takes `access_days`
(`Some(0)` and more than 3650 are refused; `None` is "no expiry"). `grant_member` is
unchanged and calls `grant_member_until(.., None)`.

**The length is chosen every time.** `ferry team invite create` requires
`--access <DAYS|forever>`; the dashboard's invitation form has an "Access lasts" select
that starts on "Choose..." and the endpoint answers 400 unless exactly one of `access_days`
or `access_forever` is sent. The code's own lifetime stays `--expires-days` and gets its own
select. Adding a machine under your own identity (`--as-identity`) takes no term: it
inherits its owner's, so it lapses with them.

**The term starts when the master signs, not when the code is made.** The dashboard's grant
step gives the person and their agent the same `expires_at`, `access_days` from now. A person
who took a week to join still gets what was offered.

**Lapsed means revoked, everywhere.** `is_revoked` and `is_revoked_in` also return true when
the grantee's access has lapsed, and `admitted_at` follows because it asks the same
question. One change covers every gate listed above, and an owner who lapses takes the
machines that inherit from them. `is_explicitly_revoked` is the old question, for a screen
that must tell "the master ended it" from "it ran out". Grants with no `expires_at` cost one
file read and behave exactly as before; nothing under `questions/` is scanned for them.

**Renewal is the master's signed answer.** `master::ask_renewals` (called each pass by the
worker loop, best effort) asks, once, when a timed access is inside its notice window: three
days, or a third of the term when the term is under nine days. The question's kind is
`access`, its options are `Renew` and `Let it end`, and its id is
`access-{grantee}-{granted_at}-{until}`, where `until` is one term past the current end.
Nothing needs the master's key on the machine that asks. `master::access_ends` is the
current end: the grant's `expires_at`, extended by every verified `access` question whose
answer is exactly `Renew`. "Verified" means what `questions.rs` already means: the question
signed by a roster member, the answer signed by the master or their `improve` delegate.
Three more conditions stop forgery of a thing the master only saw as a button:

- the id names this grantee and this grant's `granted_at`, so a renewal of an earlier grant
  never extends a fresh one;
- `until` may be at most one term past the end reached so far (the id is chosen by whoever
  asked, and without the bound a member could ask for "renew until 2099");
- when the end is being worked out for someone and the same person turns up again (a
  delegate whose standing is being checked), they count only up to their own date, so a
  person whose time ran out cannot renew themselves by answering as the master's delegate.

Renewing after the end still works, since the master's word is the master's word, but it
extends from the date the access would have ended, not from the day of the answer.

**Syncthing is cut by the agent loop.** Iroh stops at the revocation check, so a lapsed
person's transports record is no longer honoured. Syncthing does not look: the device stays
trusted and the folder shared. `invite::lapsed_devices` names the accepted devices of people
whose own signed grant says their time is up (a machine that joined under an owner goes with
its owner), and the CLI's agent loop unshares the folder from those still sharing it. It
needs no key, writes only when a device is still shared, and logs
`access for X ended on DATE: folder unshared from N device(s)`.

**Surfaces.** The dashboard's `/api/team` rows carry `access_ends` and `access_lapsed`,
and `pending_access` lists the renewal questions; the Team page shows "access ends DATE",
"ended DATE" or "no expiry" per person and Renew / Let it end buttons for the master, which
post to `POST /api/questions/{id}/answer` (master only, `access` questions only, one of the
question's own options). Telegram posts the same question with the same two buttons under
the heading "access ending, waiting for you"; the answer goes through the generic
`questions::answer` path.

Editing a timed person's roles on the dashboard keeps their end (the grant is rewritten
with it), so changing what they may do does not quietly change how long. If their access
has already ended it is refused; renewal or a new invitation is the way back.

## Consequences

- No timed grant exists until someone asks for one. Every existing grant, invitation and test
  behaves as before.
- Forgetting is now safe in the direction that matters. An access nobody renews ends, and
  the master finds out three days before, in the place they already answer questions.
- The person's agent gets its own renewal question next to theirs, because the master may
  reasonably keep one and not the other. Two questions per person is the price.
- A clock matters. Access ends when the machine checking it believes it has ended; a
  machine with a wrong clock is wrong in both directions. This is the same trust the
  delegation and lease expiries already place in the clock.
- **What it does not cover.** Everything in the channel that synced before the end is on
  their disk and stays there. Secrets sealed to them or their agent are still theirs: rotate
  them when access ends (the revoke endpoint lists which; a lapse does not yet). A fork of
  the work repository, a clone, or a copy of the files is outside the channel entirely.
  Ending access is not the same as ending trust.
- The device id on an invitation is not covered by its signature (it never was). The only use
  made of it here is to stop sharing with it, and only for a person whose own signed grant has
  run out.
