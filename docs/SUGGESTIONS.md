# Suggestions: let outsiders and their agents improve your project, under your terms

A Ferryman owner can open any project to suggestions. Anyone, and anyone's AI agent, can then
send an idea, a bug report or a piece of content, after agreeing to the owner's terms. Triage
reads each one with a model that has no tools; the owner decides; an accepted suggestion
becomes an ordinary signed order for the workers, and a shipped one earns the contributor a
credit.

Strangers never join your private channel and never touch Syncthing. Suggestions travel
through a **public inbox** you name: in this version, a public GitHub repository, one issue
per suggestion. The inbox is untrusted by construction. What makes a suggestion believable is
what is signed on it, not where it was found.

Ferryman is source-available (Usufruct License v2.2). The terms a contributor agrees to are
yours, not Ferryman's.

## For the owner

You need to be the project's master (`ferry root master` claims projects that have none), a
public GitHub repository for the inbox, and a GitHub token that can write to it
(`GITHUB_TOKEN`, or `gh auth login`).

```
ferry suggestions terms template > TERMS.md      # a DRAFT starting point, not legal advice
# edit TERMS.md until it says what you stand behind
ferry suggestions open --inbox github:you/your-ideas --terms TERMS.md --publish
```

`open` signs a `SUGGESTIONS` record into your project's channel (master-signed, with a
sequence number and a machine-local high-water mark, exactly like `ENGINE_POLICY` and
`FOCUS`), and with `--publish` commits the join page to the inbox repository with your own
credentials. Without `--publish` the same files are written to `./ferryman-suggest-page` for
you to commit yourself. `open` refuses the untouched draft template (or any text that still
has `{{placeholders}}`) unless you pass `--accept-draft-terms`: Ferryman does not write your
terms.

Options of `open`: `--name`, `--types idea,bug:steps=500!+expected=300,content:where=200`,
`--limits open=3,per-day=1,rounds=2,days=14,title=80,pitch=1000,why=500`, `--canon` and
`--rubric` (files in your repository that tell triage what the product is and what a good
suggestion is), `--out DIR`.

| command | what it does |
| --- | --- |
| `ferry suggestions show [--json]` | what is in force, and where the suggestions stand |
| `ferry suggestions pending [--all] [--json]` | the suggestions waiting for you ("needs me"), with what triage made of each |
| `ferry suggestions accept <issue>` | accept: it becomes a normal signed order |
| `ferry suggestions decline <issue> [--reason ".."]` | decline; the reason is shown to the contributor |
| `ferry suggestions ask <issue> ["question"]` | ask the contributor more |
| `ferry suggestions terms set FILE [--publish]` | new terms: a new version |
| `ferry suggestions invite` | print the one-line invite |
| `ferry suggestions publish [--out DIR]` | (re)publish the join page |
| `ferry suggestions sync` | look at the inbox now instead of on the next worker pass |
| `ferry suggestions close` | stop taking new suggestions; what is in flight is still decided |

The same decision is available from the dashboard (Suggestions page, with a count of what
waits for you) and from Telegram (Accept, Decline and Ask more buttons). All three are the
same signed answer to the same signed question.

Workers do the rest. On each `improve run` pass (and in the worker loop), a machine of your
fleet reads the inbox, checks each new issue, labels invalid ones with a comment saying what
to fix (a model is never shown an invalid one), asks the triage model about each valid one,
and puts the ones that need you in the queue. Projects whose focus is `paused` are skipped.

### What triage may and may not do

* It is a text model chosen the way the router chooses a labeller: an `http` engine only
  (never an agent with tools), cheapest allowed, local first, under the engine policy's chore
  budget and its `never` and subscription rules. If no engine is allowed or up, the
  suggestion waits, and after 48 hours it is put to you unread by a model.
* It sees the contributor's words as quoted data between random boundary markers, with your
  canon and rubric. It returns strict JSON (decision, scores, questions, reason, a spec
  draft); anything else is treated as "escalate to the owner". It cannot accept anything:
  accepting is your signed answer.
* Whatever the model's output says in public (a clarifying question, a decline reason) has
  links, `@` mentions, angle brackets and backticks removed and is length-limited before it is
  posted.

### What a suggestion becomes

Accept becomes a normal signed order (`sugg-<inbox>-<issue>`, tag `suggestion`, build tier,
review and approval required) that links the issue and quotes the contributor's words as
untrusted data. It goes through the usual build, review and merge path; nothing here merges.
When the order is done, the issue is labelled `shipped` and a second order
(`suggestion-credit`) adds the contributor to your credits. Every step is a line in a signed,
append-only ledger of kind `suggestion`: that ledger, with the contributor's signed agreement
kept in it, is the legal record.

If you change the terms, suggestions in flight keep the terms they were sent under, but a
suggestion you accept is held until its sender agrees to the new terms (the client posts a
fresh signed agreement on their open suggestions the next time they run `ferry suggest
join`).

## For a contributor (or their agent)

Everything is on the project's README. In short:

```
ferry suggest join ferry-suggest:...    # read the terms, type: I agree
ferry suggest types                     # what the project takes
ferry suggest new                       # asks each field, shows a preview, sends
ferry suggest status                    # where yours stand; answers a question with:
ferry suggest reply 12 "my answer"
ferry suggest withdraw 12
```

You only need the `ferry` program and a GitHub token. Your suggestion is signed with a key
this program makes on your machine (kept in `suggest/` under Ferryman's machine state directory, or in `FERRYMAN_SUGGEST_DIR`)
and posted as you with your own token, which is used and never stored or shown.

**Consent.** `join` shows the full terms, their sha256 and the owner's key fingerprint, and
asks you to type exactly `I agree`. A person's own script may pass `--agree <sha256 of the terms>`
instead; that is recorded as `flag` rather than `typed`. The flag is evidence that the person agreed,
not a way round them: an agent must show the terms to its human and wait, and the published
`AGENTS.md` says so. (Nothing in a program can tell a person from an agent holding the flag; the
signed record says how consent was given, and the owner sees it with every suggestion.)

**For agents.** `ferry suggest new --file suggestion.json --json` (or `--file -` for stdin)
validates, signs and posts, and prints `{"ok":true,"issue":N,"url":"..."}` or
`{"ok":false,"errors":[...]}` with a nonzero exit code. `ferry suggest status --json` lists
the states; a suggestion with `needs_reply: true` has a `question` for the human.

Defaults the owner can change: 3 open suggestions per contributor, 1 new a day, 2 rounds of
questions, 14 days to answer one, title 80 characters, pitch 1000, why 500.

## How the terms are enforced, end to end

1. The owner's offer (project, inbox, terms version and sha256, kinds, fields, limits, status)
   is signed by the master and carried in the private channel, in the invite and in
   `ferryman-suggest.json` in the inbox. A contributor's client checks the signature against
   the owner key the invite names and pins that key on first contact; a different owner key
   for the same project is refused.
2. `TERMS.md` is fetched from the inbox and must hash to the value the owner signed. A changed
   file is refused, not shown.
3. Agreeing writes an acceptance signed with the contributor's key over the project, the
   owner's key, the terms version and hash, their GitHub login, how it was given and the time.
4. A suggestion is signed by the same key and carries the digest of that acceptance. Both are
   in the issue as a signed block.
5. The owner's side reads only that block. A suggestion is taken in only if the signatures
   verify, the acceptance names the current terms hash (or is a held older one, see above),
   the key matches, the login matches the issue's author and the fields fit the offer. Issues
   that fail are labelled `invalid` with a comment saying what to fix and are never shown to a
   model.
6. The taken-in record, with the whole signed envelope, goes into the signed ledger before
   anything else happens.

## Triage isolation, in one place

A contributor can write anything. It reaches a model only after intake has verified it, as
quoted data with a per-call random boundary, to an engine that cannot run anything. The reply
is parsed strictly; the model cannot accept, close, label or write a file. A forged ledger
line, a copied signed block, a stranger using someone else's agreement and a reply to a
different round are each tested to change nothing.

## Limits of this design, stated plainly

* **Identity is a GitHub login plus a key, not a person.** A fresh key does not reset a
  contributor's limits (they are counted by login as well as by key), but a person with several
  GitHub accounts has several allowances. Raise or lower the limits in the offer.
* **Triage is a model's reading, and is shown as one.** It cannot accept, close or label, and
  everything in the owner's question that came from the contributor or the model is shown quoted
  (each line starting with `| `), links defanged, with the first thing shown being what Accept
  would hand a builder. The owner decides from that, not from the model's score.
* **What a builder gets is the owner-approved spec, as quoted data.** An accepted order lists its
  rules first, then the quoted spec, title and pitch, and says the quoted lines are untrusted.
  A builder can still be talked into things by clever text; the guard is the same as for any
  order: it works on a branch, a reviewer reads the result and the master approves it.
* **The inbox is not trusted either.** A comment counts as the owner's side's only if GitHub says
  its author has a say in the repository; the owner's side reads at most 40 new issues a pass,
  answers an edited invalid issue at most 3 times, reads at most 10 pages of comments, and
  refuses an issue it cannot read whole. Text with hidden or direction-changing characters is
  refused in suggestions, replies and terms, so what a person is asked to agree to is what they see.
* **An accepted suggestion cannot be withdrawn by its sender.** Once the owner has accepted,
  the work is the owner's commitment; a withdrawal or a closed issue is reported to the owner
  and does not cancel it (decline it, or cancel its order, if you want that).
* **The signed ledger is the legal record, but the contributor's agreement is only as good as
  the key's secrecy.** Whoever holds the contributor key can agree as that contributor.

## The inbox
The join page is `README.md` (a marked section, so the rest of your README is kept),
`AGENTS.md`, `TERMS.md`, `ferryman-suggest.json` (the machine-readable offer and the invite),
`schemas/suggestion/<kind>.json` and an issue template config that points people to `ferry`.
Status is the label on the issue: `received`, `needs-clarification`, `accepted`, `building`,
`shipped`, `declined`, `duplicate`, `invalid`. Issues opened by hand are not reviewed.

GitHub App tokens cannot ask who they are: set `FERRYMAN_SUGGEST_LOGIN` to the login that owns
the token. `FERRYMAN_SUGGEST_API` points at another API address (GitHub Enterprise).

## Not in this version

* Only GitHub inboxes. The transport is a small trait (`Inbox`), so another can be added.
* Triage does not read attachments or links; a suggestion is words.
* Credits are an order for the owner's workers to act on; Ferryman does not publish a credits
  page of its own.
