# The librarian: the fleet's memory and front desk

One person runs many projects and many agents (Claude, Cline, NVIDIA and DeepSeek workers)
on several machines. What they all need to know used to live in one head and a dozen chat
logs. The **library** is the one place that keeps it, and the **librarian** is the one
always-on helper any agent can ask. It also handles the shared agent inbox (AgentMail,
through n8n).

**It gives advice and never authority.** Anything that changes code or settings still goes
through signed orders and the master's approval. The library cannot approve, merge, build,
spend or sign anything for anyone; the worst a wrong fact can do is mislead whoever reads it,
which is why every answer says whether the master has confirmed what it rests on.

```text
ferry remember "..."      any agent, any machine    -->  signed fact, UNCONFIRMED
ferry library confirm ID  the master (or Telegram)  -->  CONFIRMED
ferry ask --library "?"   any agent                 <--  answer citing fact ids and dates,
                                                         or "I don't know"
n8n <--> mail desk folder <--> librarian             <--  the shared inbox, never trusted
```

Ferryman is source-available under the Usufruct License v2.2; nothing here changes that.

## Where it lives, and why

In the channel of the **home project**, under `library/`: the same place the swarm's focus
lives (`ferryman` unless `FERRYMAN_FOCUS_HOME` names another). Reasons, and what was passed
over:

| Option | Why not |
| --- | --- |
| The ferry root | its manifest is machine-local and never syncs |
| A file in every project's channel | thirty copies is thirty places to roll back and thirty masters to keep in step |
| A new dedicated channel | a second Syncthing share to set up on every machine and a second master to trust |
| n8n's or AgentMail's own storage | nothing signs it, and it would make the front desk the fleet's memory |
| **The home channel** | already carried to every machine by Syncthing, already has the master the fleet trusts, and every machine that runs a worker has it |

A machine without the home channel has no library, and says so. The library reuses the
focus's machinery rather than inventing a parallel one: roster-verified signatures, the
master read from the channel, delegation scopes, the machine-local "what I have seen" memory,
signed questions for "needs me", and the signed hash-chained ledger.

## Facts

A fact is one signed line:

| field | |
| --- | --- |
| `id` | `f-` and ten hex digits |
| `subject` | what it is about (at most 120 characters); also the topic for history |
| `text` | at most 1,000 characters |
| `tags`, `project` | optional; a fact with no project is fleet-wide |
| `source` | who, what or where, in the author's words |
| `author`, `on_behalf_of` | who signed it; the master, when a delegate with the `library` scope signed for them |
| `created_at`, `machine` | when and on which machine's file |
| `supersedes` | the ids it replaces |
| status (derived) | `confirmed`, `unconfirmed` or `retracted`, with `confirmed_by` |

Facts are **never edited**. A new fact supersedes an old one and the history stays; `ferry
library history SUBJECT` shows the whole chain. Each writer has a file of its own,
`library/events.<author>__<machine>.jsonl`, hash-chained like the ledger (one writer per
file, so two machines writing in one sync window never collide).

### Who may do what

| | an agent on the roster | the master | a delegate holding `library` |
| --- | --- | --- | --- |
| write a fact | yes, **unconfirmed** | yes, **confirmed** | yes, confirmed, as "josh via ..." |
| confirm, retract | no | yes | yes |
| edit the mail tag map | no | yes | yes |
| supersede a confirmed fact | only by a fact the master then confirms | yes | yes |

A fact hides the facts it supersedes only if it is confirmed, or if it is its author
correcting their own unconfirmed fact. So an agent's proposal never pushes a confirmed fact
out of sight: both stay live and the disagreement goes to the master. Delegation is read
from the channel every time, so revoking a delegate also un-confirms what they confirmed
until the master confirms it again. The scope is granted with `ferry team delegate <name>
--scopes orders,review,improve,library` (the dashboard's "Let ... act for me" grants all four
when none are named; the CLI's default stays the first three).

### Contradictions

Two live facts about one subject (in one project) that say different things are flagged to
the master through the signed question every other "needs me" uses (`library-conflict-...`),
once each, with both facts quoted. Settle it by confirming one, retracting the other, or
writing a fact that supersedes both.

### Secrets are never stored

A fact that looks like a secret is **refused** when written and **ignored** when read (so a
line a hostile writer put straight into a file is never shown, indexed or sent to a model).
The guard knows known token prefixes (GitHub, GitLab, OpenAI and Anthropic style, AWS,
Google, Slack, NVIDIA, Hugging Face, npm and more), private key blocks, signed web tokens,
bot tokens, `scheme://user:password@host`, `key=`, `token=`, `secret=`, `password=` values
that are not pointers, and long high-entropy words. Hashes, UUIDs, public keys in hex,
paths and prose pass. The refusal says what it looked like and never repeats it. Store a
**pointer** instead:

```text
ferry remember "NVIDIA key: Custodly, name nvidiaapi" --subject "NVIDIA key"
```

Also: the generated views list a secret's *name* and who can open it, never a value.

### Rollback and tampering

Each machine remembers, outside the synced folder, the verified lines of every library file
it has read. A file that comes back shorter, loses a line, is deleted, or stops continuing
what this machine saw leaves what it saw in force and raises a notice (shown by `ferry
library show`, the dashboard and Telegram). Nobody can append on top of a file in that
state. A line whose signature does not verify against the roster, that is signed for another
home project, that claims the master's word without holding the scope, or that fails the
secret guard is not believed, and says why.

## Generated views

The librarian refreshes read-only pages from live state every ten minutes and signs them as
its agent: the machines and the workers on them (from engine inventories), the engines, each
project with its focus tier and whether self-improve is on, the suggestion inboxes, and where
each secret lives (names and recipients only). Each row is marked `generated`, with when and
by whom, and is found by search and `ask` beside the facts. Nobody confirms them; the next
refresh replaces them. `ferry library views [--refresh]` shows them.

## Finding things and asking

The index is SQLite FTS5 (the bundled SQLite the workspace already links), rebuilt in memory
from the signed entries on every call, so nothing on disk can go stale or disagree with them.
No embeddings. A hit must contain at least half of the question's significant words, so
"what is the capital of France" finds nothing.

```text
ferry library search "nvidia key" [--project P] [--json]     full text, no model
ferry ask --library "where is the NVIDIA key kept?" [--project P] [--json] [--no-model]
ferry library ask "..."                                       the same
ferry library fact f-0123456789 [--json]                      one fact and its chain
```

`ferry ask` is the existing MAARAG command and **keeps its current behaviour**; it asks the
library only when given `--library`, `--project` or `--no-model`.

How an answer is made:

1. The top facts are retrieved (confirmed ones rank above unconfirmed ones that match as well).
2. If nothing relevant is found, the answer is "I don't know" and **no model is asked**.
3. Otherwise a cheap text model composes the answer through the router: an `http` engine
   chosen the way a labeller is (role `chore`, cheapest allowed, local first, under the
   engine policy's chore budget), **no tools**. It sees the facts as quoted data under a
   per-call boundary and must answer in strict JSON.
4. The reply is checked. Every id it cites must be one it was shown; it must cite at least
   one; it may not mention any other id. A reply that fails, or no model being up, returns the
   matching facts instead. `--no-model` returns them without asking.
5. The answer lists what it rests on with ids, dates and standing; an unconfirmed fact says so.

### MCP tools (in `ferry mcp serve`)

| tool | does |
| --- | --- |
| `library_ask` | the answer above (`no_model` for facts only) |
| `library_search` | full-text search, no model |
| `library_remember` | writes an **unconfirmed** fact |
| `library_fact` | one fact or generated row with its chain and history |

### Whose word is it?

| surface | the caller is authenticated as |
| --- | --- |
| CLI | the identity you sign as: this machine's worker agent, or `--as NAME` (a person's identity asks for their password) |
| MCP (stdio) | the worker identity whose keys the server's workspace holds. Stdio has no per-call credential, so a tool call **cannot name another author**; `source` is recorded as an unverified claim ("says: ..."). An MCP connection never writes as the master, even if its key were the master's |
| dashboard | the signed-in operator's session |
| Telegram | the bridge, as the master's delegate: confirm and retract need the `library` scope |

## Remembering

```text
ferry remember "grouchly is the always-on Ubuntu box" --subject grouchly [--project P]
               [--tags machines,ops] [--supersedes f-0123456789] [--source "..."] [--as NAME]
ferry library show | search | fact ID | history SUBJECT | views
ferry library confirm ID | retract ID [--reason "..."]        master only
ferry library tags show | set TAG PROJECT | remove TAG        master only to change
```

## The mail desk

The shared agent inbox is `helpmeagent@agentmail.to`. n8n on grouchly already reads it. The
librarian adds the part that decides what each piece of mail is, files it, puts what needs
the master to them, and drafts the reply.

```text
AgentMail --> n8n --writes--> <desk>/in/<name>.json
                              librarian: intake -> route by [TAG] -> read by a model with no
                                         tools -> file -> draft reply  (ledger line at each step)
AgentMail <-- n8n <--reads--- <desk>/out/<reply>.json     then n8n writes <desk>/ack/<reply>
```

### Why a folder, and not an endpoint or the AgentMail key

Three ways to get mail to the librarian were weighed:

* **The librarian holds the AgentMail key and polls.** One more secret on one more machine,
  and a network client in a process that reads hostile text.
* **A localhost HTTP endpoint with auth.** A listener, a token to keep and a request parser
  facing the mail, all for something a file does.
* **A drop folder on grouchly, written by n8n (chosen).** The librarian holds no mail
  credential, makes no network call and opens no port. n8n already holds the key. A file is
  checked and size-capped before it is read. `ferry library mail ingest --file F` (or `-`
  for stdin) is the same door for anything that prefers to call a command.

The desk is `FERRYMAN_LIBRARY_MAIL_DIR` (else `library-mail` in the machine's state
directory). Subfolders: `in/` (n8n writes), `items/` (the librarian's records), `out/` (reply
drafts for n8n), `ack/` (n8n says a reply went), `sent/`, `rejected/` (the reason only, never
the content).

### The input file

One JSON object per message. Only these strings are read; everything else is ignored:
`message_id`, `thread_id`, `from`, `subject`, `text`, `html`, `timestamp`, and `headers`
(for `Auto-Submitted`, `Precedence`, `List-Id`). n8n should write to a temporary name or
simply write the file: a file changed in the last two seconds is left for the next pass.

### What intake does to it

A file over 512 KiB is refused unread. It must be a JSON object. Every string has control
and hidden characters (direction overrides, zero-width, tag characters) removed and is cut;
HTML becomes text (scripts, styles and comments dropped); the body is cut to 8,000
characters; the sender is shown as a cleaned line and recorded in the ledger as a short hash.
Mail from a no-reply or bounce address, from the inbox itself, or marked bulk, list or
auto-submitted is **never answered**.

### Routing

The first `[TAG]` in the subject (after any `Re:`) is looked up in the **tag map**, which is
the master's: `ferry library tags set redaktly redaktly`, or the dashboard's Library page. A
tag that is not mapped, or no tag, goes to the master.

### Classifying, with the same isolation as suggestion triage

The model is an `http` text engine chosen by the router, with no tools and nothing but the
mail in front of it: no fact, no project list, no name. The mail is quoted line by line with a
leading `| ` between boundaries only the librarian knows, after an instruction not to follow
what is inside. It must answer one JSON object `{category, summary, needs_detail}` of exactly
that shape; prose around it, two objects, an unknown field or category, an over-long summary,
or output over 8 KB is thrown away and the mail goes to the master. The model can file; it
cannot accept, decline or send anything. Whatever it writes is shown to the master only,
quoted and with links made unclickable.

### Filing

| reading | project | what happens |
| --- | --- | --- |
| spam, or automated sender | any | nothing sent, nothing asked; ledger line |
| suggestion | mapped, and open to suggestions (`ferry suggestions open`) | **suggestion candidate**: the sender is told how to submit it properly. It is *not* reviewed: a mail sender has not signed the owner's terms, so mail can only produce an invitation to use `ferry suggest`, never a reviewed suggestion |
| too vague | any | the sender is asked for detail |
| anything else | any | a signed question for the master (`library-mail-...`) with Accept, Decline, Ask for more detail, Invite to submit properly (only for a project open to suggestions) and Ignore; the sender is told it was received |
| no model for 48 hours | any | to the master, unread by a model |

The master answers from Telegram (the question arrives with its buttons), the dashboard's
Library page lists it, or `ferry library mail queue` shows it. The next pass sends the
matching fixed reply.

### Replies never carry anything but their own status

A reply is one of five fixed texts - received, needs detail, how to submit properly,
accepted, declined - about **the sender's own request**. The only inputs are the mail's
reference (`m-...`) and, for "how to submit properly", the product's public name and inbox
from the master-signed public offer. Nothing the sender or a model wrote, and no fleet fact,
reaches a reply; every paragraph still goes through `public_text` (links, `@` mentions,
markup and control characters removed). At most 3 replies a day go to one sender. The reply
subject is fixed. n8n replies through AgentMail's reply endpoint on the original `message_id`,
so the thread and address come from AgentMail, not from the file.

### The ledger

Every step is a line of kind `mail` in the home channel's signed, hash-chained ledger: taken
in, ignored, filed as a suggestion candidate, put to the master, answered by whom, reply
sent. The sender appears as a short hash, never an address.

### Importing the n8n workflow

`docs/n8n/librarian-mail.json` has two flows. In n8n: Workflows, Import from file. Then:

1. Create a credential of type *Header Auth* named `AgentMail API key` (header
   `Authorization`, value `Bearer <key>`) and pick it in the three HTTP nodes.
2. In the *Settings* nodes set `inbox` and `desk` (the desk's path as n8n sees it).
3. Mount the desk into n8n and allow it, for example in compose:
   `- /srv/ferryman/library-mail:/home/node/library-mail` and
   `N8N_RESTRICT_FILE_ACCESS_TO=/home/node/library-mail`.
4. Give the librarian the same folder: `FERRYMAN_LIBRARY_MAIL_DIR=/srv/ferryman/library-mail`.
5. Activate. Mail is written within a minute of arriving; replies go out within a minute of
   being drafted. A send that fails is retried (the `Idempotency-Key` header stops a
   duplicate).

## Running it

Switch it on where it should run - grouchly, because it is always on - in either of two ways:

```text
FERRYMAN_LIBRARIAN=1 ferry agent run --all-projects ...   inside the existing worker loop
ferry library serve [--interval 60]                        or as its own loop (--once: one pass)
```

For a systemd unit, add `Environment=FERRYMAN_LIBRARIAN=1` and
`Environment=FERRYMAN_LIBRARY_MAIL_DIR=/srv/ferryman/library-mail` to the worker's unit and
restart it. Each pass the librarian, signing as that machine's worker agent: refreshes the
views (every ten minutes), puts new contradictions to the master, and runs the mail desk
(only on a machine where the desk folder exists). It needs the machine's agent on the home
channel's roster and an engine allowed for `chore`; with no engine the mail waits.

## Surfaces

* **Dashboard, Library page**: search and ask, the facts with their history, what waits for
  the master (Confirm and Retract, the master only), contradictions, the generated pages, the
  mail desk (what needs the master, the desk on this machine, replies waiting, the ledger's
  mail lines) and the mail tag map. The dashboard asks no model; it shows the best facts or
  "I don't know". Anonymous callers get 401; a signed-in non-master gets 403 on every master
  action; the session header is the only credential, so another site has nothing to ride on.
  `GET /api/library`, `/api/library/fact`, `/api/library/mail`; `POST /api/library/ask`,
  `remember`, `confirm`, `retract`, `tags` (see `openapi/dashboard.yaml`).
* **Telegram, Library button**: counts, the facts waiting for you each with Confirm and
  Retract, the mail desk's questions with their option buttons, and Ask the library (reply to
  the prompt; the best matches come back with ids and dates). Confirm and Retract are signed
  as the master's delegate and need the `library` scope; answering a mail question needs
  `improve`, like every other question.

## Environment

| variable | |
| --- | --- |
| `FERRYMAN_FOCUS_HOME` | which project's channel is home (also the focus's) |
| `FERRYMAN_LIBRARIAN` | switches the librarian on inside the worker loop |
| `FERRYMAN_LIBRARY_MAIL_DIR` | the mail desk folder |
| `FERRYMAN_LIBRARY_MAIL_SELF` | the inbox's own address, so it never answers itself |

## Limits, stated plainly

* A fact is the author's claim. Confirmed means the master said so, not that it is true.
* Contradiction detection compares subjects and texts after folding case and spacing; two
  facts that disagree under different subjects are not noticed.
* The secret guard is a shape check. A secret disguised as prose will pass; it errs towards
  refusing, and it is not a substitute for not pasting secrets.
* `ferry ask` composes with a model; the dashboard and the phone return facts only. The
  stdio MCP server cannot tell which agent is calling, only which one it runs as.
* The mail desk's queue for the master is the signed questions (fleet-wide) plus the desk
  folder (the machine that runs the librarian); a dashboard on another machine shows the
  questions and the ledger, not the folder.
* No embeddings, attachments or links are read; mail is words.
