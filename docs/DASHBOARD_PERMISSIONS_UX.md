# Permissions on the dashboard

Status: proposal. The mechanism is `SCOPED_ACCESS_PROPOSAL.md`; the content
is `SCOPE_PROFILES.md`. This document is the rule that makes both usable:
**nobody types a scope, ever.** The dashboard asks four plain questions,
shows one plain sentence, and signs. Scopes, labels, leases, engagements,
attenuation and label policy are what that sentence compiles to.

## The one rule

Every permission screen has the same shape:

1. A handful of questions in the words the business uses (*What does priya
   do here? On which matters? For how long?*), each answered by clicking
   one of a few cards or chips. Never a free-text field for anything a
   role file already knows.
2. A **sentence** at the bottom, generated from the answers, that says in
   English exactly what will be true after signing - including what the
   person *cannot* do and what happens to their agents.
3. One button: **Sign this**. A fold underneath - *Show the 11 scopes this
   writes* - for the person who wants to see the grant file. Closed by
   default. Never required.

If a screen needs a paragraph of explanation, the screen is wrong.

## Screen 1 - Teammates

The existing page, with two changes.

- The **Can** column is the plain sentence, not a scope list. It is
  generated from the grant by the same function that generates the
  sentence on the editor, so the list and the editor never disagree.
- **Access for <name>** becomes the four-question editor:

| question | control | writes |
|---|---|---|
| What does she do here? | role cards from `roles.toml`, each with its one-line `note` | the role's expanded `scopes` |
| On which matters? | chips from the project's labels of the role's `label` kind; required when the role has one | `projects` + selector on every content scope |
| For how long? | three buttons: *One task* / *Until each matter closes* / *Standing* | engagement `temp` / `contractor` / `employee`, which sets lease horizon and lifecycle binding |
| Her agents | two checkboxes: *same access, no more* (always on, shown so it is understood) and *may lend her agents* | attenuation (implicit) and `agents:own` |

The sentence names: the person, the matters, what they can do, what they
cannot (the notable subtractions from the nearest broader role), the agent
rule, and when it ends.

## Screen 2 - Lend my agent

Reached from an agent the viewer owns: **Let someone use this**. A drawer.

| question | control | writes |
|---|---|---|
| Who | a person on the same matters, picked from a list | `issued_to` |
| What she sees back | two radios: *Only what she could already see* (default) / *Everything I would see* | `reveal = borrower-scopes` / `owner-context` |
| For how long | *Today* / *This week* / *While I'm out* | horizon; the last binds to the owner's presence |
| Spend limit | one number, prefilled from `[lending]` | `cost:spend:<budget>` |
| I can read every exchange | checkbox, on | `transcript = owner` |
| She may pass it on | checkbox, off and disabled | never; shown so the rule is visible |

The sentence ends with the label reminder: *Matter policy still applies* -
because that is the question people ask next.

## Screen 3 - Matter policy

Reached from a matter (a label). Five rows, each a question with three
answers or a switch, and the answers are in the business's words, not the
policy's:

| row | answers | writes |
|---|---|---|
| AI may learn from this matter | Never / Only with the client's consent / Yes | `train` |
| Where it may be worked on | Our machines only / Cloud with an agreement / Anywhere | `infer` |
| Can leave Ferryman | Never / Two people agree / Anyone on it | `export` |
| A person reads every AI draft first | switch | `review_before_release` |
| When it closes | *Keep N years* | `lifecycle` + `retention` |

Under *learn*, when consent is the answer, one line shows the consent's
state and source (*Client consented 14 Aug, from their portal*) and whether
names are removed first (`redacted_label`). Below the rows: **Walled off
from** (exclusions, with the reason and who signed, and *and his 2 agents*
so the inheritance is visible) and **Who is on it** (every principal with a
scope on the label, agents marked as agents).

## What is deliberately not on any screen

- The words *scope*, *lease*, *grant*, *attenuation*, *engagement*, *label*.
  The sentence uses *can*, *cannot*, *until*, *matter*, *agent*.
- A free-text scope editor. Custom roles are edited in `roles.toml` by
  whoever the firm trusts with `policy:write`; the dashboard shows them as
  cards like the built-in ones.
- Anything that needs the CLI to finish. If a step ends in "run this", the
  step is not done.

## The sentence generator

One function, used by the Can column, the editor, the lend drawer and the
ledger's human-readable line: `describe(grant | lease) -> String`. It reads
the role file for names, the scope list for facts, and writes: subject,
labels, positive verbs, notable negatives, the agent rule, the end
condition. It is tested against the profiles so that every role in every
shipped `roles.toml` renders as a sentence a stranger can read.
