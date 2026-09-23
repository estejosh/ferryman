# ADR 0022: A master claims their git account

Status: proposed, 2026-09-17. Builds on 0014, 0016. Related to 0021.

## Context

The master is the root of trust for a project (ADR 0014): they declare grants, and every
member verifies those grants against the master's published key. Who the master *is* is
`master.json`, and `master.json` lives in the shared channel - the synced folder every
member can write.

`transfer_master` is hardened: it compares the offered key against the key that signed the
standing declaration, so a forged key wearing the master's name cannot take the role. That
guards the transfer path. It does not guard the *absence* path. `initialize_master` returns
early only `if path.is_file()`. Delete `master.json` from the synced folder and the next
`ferry enable` takes the role - `implicit_master`, "this machine is the first, so it is the
master" - or somebody clicks "I am the master" in the dashboard. Their declaration then
verifies for everyone, because they are on the roster and they signed it themselves.
Deleting a file is a takeover.

A purely local fix - each machine pins the master's key privately in its attachment the
first time it sees a valid declaration - closes that for machines that already saw the
truth. It does nothing for a machine that has never touched the channel, which is exactly
when a person is most exposed: a newcomer accepting an invitation has nothing to compare
against and trusts whatever the folder says.

What is missing is evidence that lives somewhere else.

And takeover is the rarer half of the problem. The common one is ordinary commerce: a
company is sold, a new CTO arrives, the repository moves to their org and every token is
rotated on the first day. Nothing has been stolen and nobody has done anything wrong. But
the outgoing master still holds the Ferryman key, their channel still syncs, the grants they
issued still verify, and their agent fleet is still working - against a codebase that is no
longer theirs, under authority nobody at the new company can withdraw, because the key that
would withdraw it left with the founder.

That is the case to design for, because it needs no adversary. It only needs somebody to
forget, and unattended agents are very good at not being switched off. The two problems have
the same shape - authority that has come loose from the thing it was authority over - and
one mechanism answers both.

## Decision

**A master may bind their Ferryman key to one or more git provider accounts. The binding
is proven once, at claim time, against the provider. Nothing after the claim ever consults
the provider again.**

This is the whole shape of it, and the second sentence is as important as the first.
Ferryman verifies licences offline against a compiled-in key rather than phoning home; a
channel that had to reach github.com to answer "who is in charge" would be a worse tool
than one that cannot. `is_granted`, `grant_member` and `revoke_member` do not touch the
network, before this change or after it.

### The claim binds in both directions

A claim is a record naming a provider account and a Ferryman key, signed twice:

- the account's **published SSH key** signs a payload naming the Ferryman key, and
- the **Ferryman key** signs the whole record, naming the account.

Each signature names the other side, so neither can be lifted off and replayed against a
different key. This is the pairing the invitation nonce already uses, applied to identity.
A one-way assertion - "I claim estejosh" written into a file - proves nothing, because
anyone can write a file.

### ssh-ed25519, not GPG

GitHub publishes a user's SSH public keys, unauthenticated, at `github.com/<login>.keys`.
An `ssh-ed25519` key *is* an ed25519 key: the same primitive `ferryman-channel` signs
everything with. The signature comes from `ssh-keygen -Y sign`, and Ferryman verifies it
with `ed25519-dalek` plus a blob parser.

GPG would mean pulling an entire OpenPGP stack into the tree. There is no GPG anywhere in
Ferryman today and this is not the reason to start; the dependency budget already turned
away `reqwest` 0.13 for dragging in a C toolchain, and an OpenPGP implementation is a
larger version of the same bill. Accounts with no published ed25519 key cannot claim. That
is a real limit and an acceptable one - a key can be added in a minute.

Signing does not have to happen at a command line. Where the key is held by ssh-agent,
Ferryman drives the agent from the dashboard and no passphrase is ever typed into Ferryman
- the same arrangement as release signing.

### The account is a number

`login` is recorded for humans to read and is never what gets checked. GitHub handles are
reassignable: an account released today can belong to somebody else tomorrow, and a claim
pinned to the string would follow it. The numeric account id is immutable and never reused.

### A master may claim several accounts

The claim is a list, not a field, from the first version - one record per account, each
proven independently, all bound to the same Ferryman key. This is not hypothetical
generality: the same person is `estejosh` on Ferryman and Redaktly and a different git
identity on Hone. A project names which claim its master holds.

### What the network does at claim time

Ferryman fetches the account id and the published key list, verifies the SSH signature
against a key in that list, and embeds that key in the record along with what was fetched
and when. From then on the claim verifies by arithmetic, offline, forever. A key removed
from an account in 2027 was still on it in 2026, and the claim does not stop being true
because the evidence moved.

### And afterwards: an irregular re-check, which can pause the role

The claim is settled, but the account behind it is a live thing, and a project should
notice if it changes underneath them. So any member re-checks the anchor on a loose
schedule and writes what they found into the channel.

**Any member, not just the master.** The claim is public and so is the evidence, so the
whole team watches the master's anchor rather than the master watching themselves. That is
the correct direction for the check to run in.

**Irregular, literally.** A jittered interval - days, not hours, and never the same gap
twice. A fixed schedule is a window an attacker can work around, and a fleet on a fixed
schedule hits the provider's rate limit all at once.

**Two questions get asked, and the second is the one that matters most:**

- *Is the claimed key still published on the account?* Catches an account that has been
  taken or abandoned.
- *Does the claimed account still own the repository this project points at?* Catches the
  sale, the transfer to an org, the new CTO. **This is the common case and the first
  question is blind to it** - after an acquisition the outgoing master's key is still on
  the outgoing master's account, perfectly valid, answering a question nobody asked.

**Three states for each, and only one is an alarm:**

- *verified* - the fetch succeeded and the answer is what the claim says.
- *not checked* - offline, rate-limited, provider down, DNS, a laptop shut for a fortnight.
  The normal state most of the time. It means nothing.
- *contradicted* - the fetch succeeded and the answer disagrees: the key is gone, or the
  repository's owner id is not the claimed account. This is the loud one.

**Not checked raises a finding and nothing more.** An outage, a rate limit or a shut laptop
is not evidence of anything and must never move the role, or anyone able to make the check
fail could move it on purpose.

**Contradicted pauses the master.** Positively contradicted - the fetch succeeded, the
claimed key is genuinely gone, and several checks across days agree - freezes the role: no
new grants, no invitations, no new machines claimed. Existing grants keep working, so a
project is not bricked by an afternoon.

**Paused is not vacant, and this distinction is the whole design.** The role is frozen, not
released. There is still a named master, `initialize_master` still refuses, and nobody can
walk in. Releasing the role on a failed check would create exactly the vacancy this ADR
exists to close, and would hand the trigger to whoever can interrupt a network connection:
a remote decapitation switch operated with a cable. Freeze stops the master doing anything
new. It does not invite a successor.

**A paused master may still transfer, and only transfer.** That is the recovery path and it
must stay open, or an account genuinely lost leaves a project frozen for good. It is safe
because a transfer is signed by the Ferryman key and can only land on a master who has
claimed an account of their own - and the Ferryman key is a different secret from the git
account, so losing the account does not cost the key that signs the handover. The rule is
that a frozen master may give the role away and may give nothing else away.

Recovery without a transfer is just as ordinary: re-publish the key to the account and the
next check clears the pause.

### An ownership change is one event, not two

When a repository genuinely changes hands, the new owner rotates the tokens. Automation
signed in as the old owner stops working on its own, without anybody remembering to switch
it off. Pausing the Ferryman role on the same signal, and requiring the incoming master to
claim before they can act, puts the two halves on the same clock: git access and Ferryman
authority end together instead of drifting apart and leaving an outgoing master with a live
channel and dead credentials, or the reverse.

That requirement is already the rule above - declaring or transferring on a git-backed
project requires a claim - so a successor cannot inherit the role and sort the paperwork
out later. They claim, or they do not hold it.

Ferryman does not *depend* on the token rotation for any of this; the pause is driven by the
unauthenticated anchor check, which every member can run. A token that stops working is
corroboration, and belongs in the ownership check below rather than in the trust path.

### One claim, every project

**The claim binds an account to a key, and a key is not project-shaped.** It is proven once
on the machine that holds the key, kept in that machine's own state beside the seed, and
copied into each project's channel when the role is declared there. No re-proof per project:
both signatures travel with the record and verify anywhere, offline.

That is what makes it self-populating. Claim `estejosh` once and every Ferryman project you
are master of carries it - existing ones on the next run, new ones from the moment they are
created. The master's roster entry shows the account alongside the key, so every member sees
who they are trusting without asking anyone, and a newcomer sees it before they join.

This gets the useful half of ADR 0021 - an identity that means the same thing across
projects - without the hosted log, the writer node or the anchor account that ADR proposed.
The provider is already the shared namespace. For a master, this may be enough that 0021 is
only needed for members who have no git account to anchor to.

**Self-population needs no token.** The projects to populate are Ferryman's own, and
Ferryman already knows them: `ferry::Root::projects()` reads them out of the `.ferry`
manifest (ADR 0019). Walking that list and writing the claim into each channel where this
key is master reaches every project on the machine without asking a provider anything.

### Two checks, both able to pause, neither able to move the role

**The anchor check** reads `github.com/<login>.keys` and the account id. Unauthenticated, so
every member runs it and a contradiction is corroborated by the whole project.

**The ownership check** reads the project's own repository - `repos/{owner}/{name}` - and
compares `owner.id` against the claimed account id. This is the acquisition check, and it
cannot be advisory, because it is the only one that fires when a company changes hands. An
advisory finding that a project now belongs to somebody else, sitting in a dashboard while
the old master's agents carry on, is the whole failure this ADR was written to stop.

For public repositories it needs no token and every member can run it, the same as the
anchor check. For private ones it needs a token, and that runs on one designated machine.
Git is the authority there and the `.ferry` manifest is a stale local cache: the provider is
asked first and the manifest reconciled against the answer, not the reverse. The token is
fine-grained, metadata read on selected repositories - never classic `repo`, never contents,
never write - one machine, stored like any other credential (ADR 0010).

Concentrating the private-repository check on one machine is a real concentration of power
and is bounded deliberately: a contradiction there can pause the role and can never move it,
so the worst a captured or lying master-master machine achieves is freezing a project until
a person looks. That is recoverable. Handing one machine the ability to install a successor
would not be.

**Git authentication failures are not a signal.** Tokens expire, get rotated, get scoped
wrong. A 401 or a 403 means somebody's credential needs attention and nothing about who owns
anything. Only the owner id answers the ownership question, and only that is allowed to
pause. The full stack failing after a sale is a true and useful thing - it is just not
evidence, and evidence is what may pause a role.

**Nor is a 404.** On a private repository GitHub returns 404 rather than 403 for anything
the caller cannot see, so "moved", "deleted", "made private" and "your token no longer
reaches it" arrive as the same status. Verified against this account: `repos/estejosh/
redaktly` answers 404 to the read-only token in use, while `repos/estejosh/ferryman` answers
in full - the difference is the token's scope, not the repositories' ownership. A 404 is
therefore *not checked*, never *contradicted*. Only a successful fetch returning a different
`owner.id` may pause. Reading a 404 as ownership moving would pause every private project
the day a token expired, which is the same mistake as pausing on an auth failure wearing a
different status code.

### The successor is already decided

Tying the claim to repository ownership settles the one thing that made a vacancy dangerous.
Once a project's master must hold the account that owns the repository, only one account can
take the role after a transfer: the one GitHub says owns it now. A stranger cannot walk into
a paused project, because a stranger does not own the repository.

So the handover protocol falls out of the two rules already here. The repository moves; the
ownership check contradicts; the role pauses, issuing nothing new; the outgoing master's one
remaining power is to transfer, and the only party who can receive it is the new owner, who
claims their own account to do so. Nobody has to remember to switch anything off, and the
project is never for a moment unowned.

### A repository is owned by a person or by an organisation, and person is the default

`owner` on a repository carries an `id` and a `type` - `User` or `Organization` - in one
numeric space. The ownership check is the same either way: does this repository's `owner.id`
match any claim this master holds. Which kind it matched is a property of the claim, not a
second mechanism.

What differs is the proof, and they are not equally strong:

**A personal account proves itself.** `github.com/<login>.keys` is published by the account
holder and by nobody else, which is what makes the claim unforgeable and lets every member
verify it without a token. This is the primary case and it is most repositories - certainly
every repository this project currently has.

**An organisation has no `.keys` endpoint** and cannot prove itself the same way. It also
does not need to, because an org claim is a different sentence: not *I am this org*, which
several people could truthfully say, but **I am person P, and P administers org O, and this
repository belongs to O.** The first clause is proven exactly as before, by `.keys`. Only
the middle clause is new.

That middle clause is why the repository check cannot cover the org case on its own. **A
repository's owner id does not change when the organisation's people do.** Sell the company
and the usual thing is not that repositories move - it is that control of the org moves. The
org keeps its name and its id, the founder is removed as an owner, and a per-repository
check goes on answering *verified* indefinitely. The organisation is a container, and the
container did not move; what changed was who holds the keys to it.

So an org-owned project needs both, and they catch different events:

- **`repos/{owner}/{name}`** - the repository left the org. One call per project.
- **`orgs/{org}/memberships/{username}`** - the master is no longer an admin of the org.
  **One call covers every repository that org owns**, which is cheaper than per-project and
  is the sense in which an org change does pass down to all its repositories.

What can be seen without a token is uneven, and the pause follows it:

- `orgs/{org}/public_members` is readable unauthenticated. It shows *membership*, never
  role. So a master removed from the org outright is publicly visible and every member can
  corroborate it - that may pause.
- `orgs/{org}/memberships/{username}` carries the `role` field that distinguishes admin
  from member, and needs a token with members-read. Demotion from admin to ordinary member
  is therefore invisible to the project unless the master-master machine is looking. That
  signal may pause too, with the same bound as every other one-machine signal: it can freeze
  and it can never move the role.
- Membership kept private means the token is the only route, and an org-owned project whose
  master is a private member is checkable only from the one machine.

An acquisition usually produces both events, demotion first and removal later, so a project
with no token still finds out - later than one with a token, and well before never.

**Order of work**, scoped to what each case can actually prove:

1. **Personally owned repositories** - works with no token and no new proof at all. Claim,
   verify, check, pause. Every repository this project has today is here.
2. **Organisation-owned repositories** - the same claim record with an org clause, the
   membership check beside the repository check, and pausing enabled once that exists.
   Until then the check reports and does not pause, because otherwise the first thing it
   would do is freeze a project for being moved into an org deliberately.

Being unable to pause an org-owned project is the state everything is in today, so the
personal case shipping first costs nothing and covers what exists. The org path follows
immediately, not eventually: Ferryman's own repository needs it the day it moves.

### On git, required. Off git, optional

The project's own git remote decides, and `ProjectRoute` already carries it.

**A project with a git remote requires a claimed master.** It costs nothing to require:
a project that is already on GitHub already has an account behind it. Declaring the role on
a git-backed project without a claim is refused.

**A project with no git remote does not.** Local-only projects have no account to claim
against and must keep working exactly as they do now.

Once claimed, a project refuses a master declaration signed by a key with no claim, whether
or not `master.json` is still there. That is what closes the deletion hole, and it is why a
project cannot go back to unclaimed: "the master may drop the claim" is the takeover path
wearing a different hat. Transfer to another claimed master stays available and remains the
only way the role moves.

### What "required" means for projects that already exist

It cannot mean that every git-backed project stops working on upgrade. The rule bites at
declaration time:

- Declaring or transferring the master role on a git-backed project requires a claim, from
  the first release that ships this. New projects are therefore never in the unclaimed
  state, and the hole is closed for everything created from here on.
- A git-backed project whose master was declared before this exists keeps working, and
  `doctor` reports it as an open finding until the master claims. Loudly: this is not a
  style note.

That grace window is a real exposure and should be written down as one. A git-backed
project with an unclaimed master is takeoverable exactly as it is today, and requiring a
claim of the *attacker* does not prevent it - anyone can register a GitHub account. What it
buys during the window is attribution: a seizure now carries an immutable account id, which
is worth having and is not worth mistaking for prevention. The window closes per project,
the moment its master claims.

## Consequences

- Nobody but the holder of the account can claim it. That is the property asked for, and
  it holds without the network after the moment of claiming.
- A newcomer can check who the master is before joining, against something outside the
  folder they are about to trust.
- A project that adopts a claim can no longer be taken over by deleting a file. Every
  git-backed project created from here on has one from the moment its master is declared.
- Ferryman's own repository, Redaktly and every other git-backed project already standing
  carry the finding until their master claims. That work is a one-off per project.
- Ferryman gains no runtime dependency on GitHub, and no new cryptographic dependency at
  all.
- Publishing a key to an account requires being signed in to that account, so the claim is
  exactly as strong as the account is, and that is the point rather than a caveat. Every
  trust system has a root that ends the argument if taken; what matters is whether the root
  is well defended and whether taking it is noisy. A GitHub account behind a password and
  2FA, which logs its own security events and notifies on a new key, is both - and it is a
  considerably better root than a JSON file in a folder every member can write, which is
  what the role rests on today. The irregular re-check above exists so that a key appearing
  or vanishing is seen by the whole project within days.
- The seed (ADR 0016) remains the root of the Ferryman identity itself; the claim anchors
  that identity to a name in the world, and does not replace it. Revocation and the grant
  model are unaffected.
- A project whose master's anchor is contradicted keeps running on the grants it already
  has, cannot issue new ones, and cannot be claimed by anybody. It comes back when the key
  is republished, or when the role is handed to a master who has claimed. There is no state
  in which a git-backed project has no master.
- A master is now pauseable by evidence rather than only by another person's decision. That
  is new authority in the system and it is deliberately narrow: it can stop the role acting
  and can never move it.
- Selling a company no longer leaves the founder's agent fleet running under authority the
  buyer cannot withdraw. The event is the repository moving, or the founder losing the org
  that holds it; nobody has to remember to act on either; and the only account that can take
  the role afterwards is the one that owns the repository now.
- An organisation is checked once for every repository it holds, so an org changing hands
  reaches all of its projects from a single call rather than one per project.
- The cost of that is real and should be stated: for a git-backed project, GitHub's record
  of who owns the repository becomes able to pause who governs it. That is a dependency on
  a third party for a governance decision. It is bounded to *pausing* and to git-backed
  projects, existing grants keep working offline regardless, and the justification is that
  a project which is a repository has little claim to be governed by somebody who does not
  hold the repository. It is still a trade and not a free win.
- Providers other than GitHub fit the same record. Nothing here is GitHub-shaped except
  the two URLs.
