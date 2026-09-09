# Bringing on a non-developer: the Redaktly sales case

A worked example. David joins Redaktly in sales. He should see and work the
business side, read the code but never change it, and run an agent that
reads the repository, analyses it, and makes suggestions that Josh decides
on. Nothing David or his agent does lands without Josh's say.

Two halves: what works today with no new code, and what the scoped-access
work adds on top.

## The three levers that exist today

Ferryman's dashboard is loopback-only and reads a synced folder, so a
teammate runs Ferryman on their own machine against their own copy of the
channel. That fixes what "permission" can mean right now:

| lever | what it controls | enforced by |
|---|---|---|
| **Which folders sync to him** | what he can read at all | Syncthing sharing - a folder he is not shared on does not exist for him |
| **What the master accepts from his key** | what he can *do* | signature + grant checks on Josh's side; `grants = "required"` in `bridge.toml` |
| **Recipient-bound secrets** | which credentials his agent can open | HPKE envelopes sealed to a named key; nobody else can open them |

Roles on a grant are honoured by the orchestrator today; the dashboard does
not yet refuse a route per role (that is step 3 of `SCOPED_ACCESS_PROPOSAL`).
So a grant is attribution and acceptance, not a wall on his own screen.
Design around the levers, not the grant.

## Setup today

**1. Two projects, two channels.**

- `redaktly` - the dev channel. Josh, the dev agents, the work repository.
  David is not shared on this folder.
- `redaktly-business` - sales, pricing, positioning, customer questions,
  and the place suggestions land. Josh, David, David's agent.

One master (Josh) over both. David's dashboard shows one project because
only one syncs to him. Josh's shows both.

**2. Invite.** Teammates → *Add someone* → reserve `david` on
`redaktly-business`. Today this reserves the name; David creates his own
identity on his own machine. Send him the `Ferryman-Setup` file and the
Syncthing folder invitation for `redaktly-business` only. That pair is the
"link and login" - his login is a password he sets on his own machine, and
his machine never sees Josh's.

**3. Grant.** Once his key appears on the roster: Access for david → *Work*,
project `redaktly-business`. With `grants = "required"` on the business
channel, his agent is accepted as a worker there and nowhere else. On the
dev channel he has no grant and no folder.

**4. Read-only code.** Create a fine-grained GitHub PAT on `estejosh/redaktly`
with Contents: read and nothing else, expiring. Vault → add secret
`github-redaktly-ro`, recipient `david-agent` only. Ferryman carries the
sealed envelope; only that agent's key opens it. GitHub enforces read-only;
Ferryman enforces who holds the token. David the human never needs it.

**5. His agent.** On David's machine, `ferry agent` as `david-agent`, role
`worker`, on `redaktly-business`. To pull the token into his own `.env`:

    ferry channel secret get GITHUB_DAVID_READONLY --env >> .env

On the sealing side, the value never leaves `.env`:

    ferry channel secret set GITHUB_DAVID_READONLY --from-env Github_David_READONLY --to david-agent --as josh

`--from-env KEY` reads `KEY=` out of the project's `.env` (or `--env-file`);
with no key it reads the line named like the secret. Its standing brief: read the repository
through the token, analyse, and write suggestions into the channel - as a
conversation on the `suggestions` topic, or as memory proposals. It never
opens a task on the dev channel because it cannot see one.

**6. Josh decides.** Suggestions appear on Josh's dashboard under Needs
review (memory proposals) and Conversation. Accepting one is Josh opening a
task in `redaktly` for a dev agent - a deliberate act, with the ledger
showing where the idea came from.

That is the whole thing. Nothing in it requires code that does not exist.

## What the scoped-access work adds

With `SCOPE_PROFILES` in place the same arrangement becomes one project and
a sentence:

- Office type: *Software or dev house*. Role card **Sales**.
- **David** can read tasks and conversations, write in `sales` and
  `suggestions`, propose to memory, message the fleet, own agents; cannot
  take or submit work, review, or see the vault.
- **Labels**: `customer:*` and `business:*` are David's; `code:*` is
  read-only to him through `redacted_view` = none, `artifacts:read` only.
- **His agent** is attenuated to him, holds `secrets:use:github-redaktly-ro`
  because Josh sealed it to that key, `tools:network` for GitHub and nothing
  else, `handoff_depth = 0`, and a budget.
- **Invitation carries the role.** *Add someone* asks the four questions up
  front and stores a pending grant that binds the moment David's key
  arrives, so the grant is signed before he ever opens a dashboard. This is
  what "give David a link and a login" means once built.
- **Dashboard enforcement** means David's own screen refuses what his
  grant does not cover, so the two-channel split becomes a choice rather
  than the only wall.

Until then, two channels and a sealed token do the job.

## The message a teammate receives now

Teammates -> *Make the code* on the inviter's dashboard produces a prompt the newcomer
pastes into their Claude; see `JOIN_PROMPT.md`. No terminal on their side.

## The three-line target

The target, once the invitation protocol lands (item 1 of the onboarding
findings). Until then the two-channel setup above is the honest version.

    1. Run this installer: <link>
    2. When it asks your name, type: david
    3. Paste this code: <invite>
    Done. Your agent can read Redaktly and picks up its GitHub key by itself.

If the flow needs more than that, the flow is not finished.
