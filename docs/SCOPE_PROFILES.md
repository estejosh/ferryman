# User scopes and how permissions resolve

Status: proposal. Companion to `SCOPED_ACCESS_PROPOSAL.md`, which gives the
mechanism (grants, leases, attenuation, enforcement points). This document
gives the *content*: the full scope catalogue, the resolution rules, and
ready-to-use role profiles for three kinds of business. The profiles live in
`examples/roles/*.roles.toml` and are meant to be copied into the master
folder and edited; Ferryman ships them as starting points and never as
policy.

## 1. Vocabulary

| word | means |
|---|---|
| **principal** | anything holding a key: a human operator or an agent |
| **project** | Ferryman's unit of isolation. A dev firm's project is a repo; a law office's is a practice group or a single large matter; a clinic's is a department or site |
| **label** | a tag on a task or conversation, `kind:value`. This is how a matter or a patient is scoped *inside* a project without making every matter its own project. `matter:2026-0142`, `patient:p7f3a9`, `feature:billing` |
| **scope** | `resource:action[:selector]`, the unit of permission |
| **role** | a named bundle of scopes, expanded to scopes when a grant is signed |
| **engagement** | `temp` / `contractor` / `employee` — how long and how broadly (ADR 0014) |
| **owner** | the principal that leased an agent; the agent can never exceed it |
| **exclusion** | a master-signed subtraction applied last — the ethical wall |

Labels that identify a person (a client, a patient) are **opaque ids**, never
names. The mapping from id to person lives in the firm's own system of
record, not in the channel. A leaked channel folder must not be a client
list.

## 2. Scope catalogue

`read` never mutates. `*` as action means every action on that resource.
Selector is optional; when present on the *required* side it must match the
held side exactly, or the held side must have no selector.

| resource | action | what it permits | selector |
|---|---|---|---|
| `tasks` | `read` | see task status, notes, results | task id or label |
| | `create` | issue a new work order | label |
| | `take` | claim an assigned task | label |
| | `submit` | return a result | label |
| | `review` | accept or send back a result | label |
| | `cancel` | kill an order (ADR 0020) | label |
| `artifacts` | `read` | open files attached to tasks | label |
| | `write` | attach files | label |
| `conversations` | `read` | read a topic | topic or label |
| | `write` | post to a topic | topic or label |
| `memory` | `read` | read approved shared memory | — |
| | `propose` | suggest an entry | — |
| | `approve` | make an entry count | — |
| `ledger` | `read` | read the audit chain | — |
| `agents` | `view` | see an agent's status and outputs | agent name |
| | `message` | talk to an agent | agent name |
| | `use` | prompt the agent as the owner would: the owner's context, memory, skills and engine answer, the prompter's question asked | agent name |
| | `assign` | give an agent work | agent name |
| | `handoff` | let an agent delegate to another; the lease carries a hop count | agent name |
| | `install` | add an agent to the business | — |
| | `own` | be assignable as an agent's owner | — |
| `secrets` | `list` | see secret names, never values | — |
| | `use` | have the broker use a secret on your behalf | secret id |
| | `set` | store or rotate a secret | secret id |
| | `remove` | delete a secret | secret id |
| `release` | `read` | see release candidates | — |
| | `approve` | sign off a release (ADR 0018) | — |
| `team` | `read` | see members and their roles | — |
| | `invite` | issue an invitation | — |
| | `grant` | sign grants and leases for others | — |
| | `revoke` | revoke grants and leases | — |
| | `exclude` | write exclusions | — |
| `fleet` | `read` | see machines, health, presence | — |
| `cost` | `read` | see spend and rates | — |
| | `plan` | set budgets and rates | — |
| `policy` | `read` | read `roles.toml` and project policy | — |
| | `write` | change them | — |
| `tools` | `shell`, `network`, `browser`, `filesystem` | what an agent may reach on its machine; conferred only by an owner who holds it | — |
| `cost` | `spend` | draw down a named budget | budget id |
| `consent` | `give`, `revoke` | speak for a data subject about `train`/`export` on their label | label |

Fourteen resources. Adding one is a row here and a line in `SCOPES`.

## 3. Four axes, not one

A role answers "who is this person". That is one axis, and on its own it is
the wrong shape for a law office or a clinic, where the question that
actually gets asked is "may *this* data be used for *that*, *here*". Access
is the intersection of four independent things:

```
allowed  =  principal scopes
         ∩  what the DATA permits          (label policy)
         ∩  what the MACHINE may process   (machine tier)
         ∩  what the SUBJECT has consented (client / patient record)
         −  exclusions
```

Each axis is a signed file the business writes; Ferryman only intersects.

### 3.1 The data carries its own policy

A label is not a tag. It is a **classification** with a policy attached, in
`[labels.<kind>]` of `roles.toml`. The policy answers questions no role can:

| key | question it answers | values |
|---|---|---|
| `train` | may content under this label enter shared memory, learnings, a RAG index, a fine-tune, or any model's training corpus? | `never` / `with-consent` / `always` |
| `infer` | which engines may *read* this content into a prompt at all? | `local` / `cloud-with-agreement` / `any` |
| `export` | may it leave the channel: download, email, Telegram, a push to a remote git? | `never` / `two-person` / `owner` / `any` |
| `residency` | which machine regions may hold a copy? | list, or `any` |
| `review_before_release` | must a human with `tasks:review` on this label accept every agent output before it is visible outside the label? | bool |
| `two_person_read` | do reads need a second principal's live approval? (a partner's own matter, a VIP patient) | bool |
| `redacted_view` | is there a redacted rendering, and who gets it instead of the original? | role list |
| `retention` | how long after the label closes before content is purged and only the ledger remains | duration |
| `lifecycle` | which task or matter state closes the label - after which every scope on it drops to `read` | state name |

**"AI-trainable" is a label property, not a role property.** `train = never`
on `privileged` means no principal - not the managing partner, not an agent
owned by the managing partner - can `memory:propose` from it, and the
learnings module refuses to record an outcome whose inputs carried it. Shared
memory is the fleet's training set; this is the switch that keeps a matter
out of it.

**Derived content inherits the strictest label of its inputs.** A summary of
a `privileged` artifact is `privileged`. An agent that reads two matters and
writes one memo produces a memo labelled with both. The orchestrator stamps
labels on outputs from the labels on the task's inputs; a worker cannot
launder a classification by rewriting it. This is what makes `train` and
`export` mean anything.

**Redaction is an access tier.** `redacted_view = ["legal-assistant",
"intake-agent"]` means those principals receive the Redaktly rendering of an
artifact where others receive the original, under the *same* `artifacts:read`
scope. The redacted copy carries a weaker label the policy names, so it can
be trainable where the original is not. A firm gets to say "the model may
learn from our work, minus the names" as one line of policy.

### 3.2 The machine is a principal too

Every machine already holds a key. `[machines.<name>]` gives it a **tier**
(`onprem`, `private-cloud`, `public-cloud`), a **region**, and the engines it
runs with whether each is `local`. The orchestrator will not assign a task
carrying a label to a worker whose machine or engine the label's `infer` or
`residency` policy refuses, and a worker that somehow receives one refuses it
itself - the same check, run on both ends, from local files.

For a clinic this is the whole difference between "we have a policy about
PHI and cloud models" and "the fleet cannot physically route PHI to a cloud
model". For Ferryman it is the sovereignty thesis made enforceable: the
engine split that today saves tokens becomes the thing that keeps a matter
in the building.

### 3.3 The subject holds a key

A client or patient with a portal identity is a principal, and some scopes
exist only because they said so. `train = with-consent` means the label is
trainable only while a lease **signed by the subject's own key** says it is.
The subject issues it from the portal, sets its horizon, and revokes it by
not renewing - ADR 0013's mechanism, with the data's subject as the issuer.
The firm records nothing about consent that the subject did not sign.

Where a subject has no key (most clinics, today), the firm's compliance role
records the consent as a signed lease on the subject's behalf, and the ledger
shows it was the firm speaking, not the patient. The two are not the same
thing and the audit trail should not let them look the same.

### 3.4 Governing is not reading

The first draft gave `managing-partner` and `medical-director` `*:*`. That
is how software thinks about owners and it is wrong for these businesses. A
managing partner administers the firm; they do not, by virtue of the title,
read every matter - not the partner who is a client of the firm in her own
divorce, not the walled-off matter, not the matter another partner's client
insisted be seen by three people.

So the model splits authority in two, for every business:

- **administrative** scopes: `team:*`, `policy:*`, `agents:install`,
  `secrets:set`, `cost:plan`, `fleet:read`, `ledger:read`. These are what an
  owner has business-wide.
- **content** scopes: `tasks`, `artifacts`, `conversations`, `memory`,
  `secrets:use`. These are **always per label**, for everyone. There is no
  role in any profile with unlabelled content scopes except `viewer` in the
  dev-firm profile, where the business chose that and it is one line to
  change.

The master key can grant, revoke, wall, install and audit, and holds no
content it was not given like anyone else. Where the recipient-bound secret
transport lands, this stops being policy and becomes cryptography: content
under a label is encrypted to that label's key, and the master simply does
not have it.

### 3.5 Lending an agent: `agents:use`

`agents:message` talks *to* an agent as a peer: the agent answers from the
prompter's standpoint, with the prompter's scopes. `agents:use` is different
and there are real reasons to want it: a senior attorney lets an associate
draft through the agent that knows her style and her matters; a physician on
leave lets the covering physician use the scribe that knows his panel; a lead
lets a contractor use the agent that carries the team's conventions without
handing over the conventions doc.

Only the owner can grant it, because only the owner holds it - `agents:own`
confers `agents:use` on one's own agents and nothing else does. The owner
issues a lease to the borrower, scoped to the agent, with a horizon, and
optionally a label set and a budget. The borrower then prompts the agent and
the agent runs **as the owner**: owner's memory, owner's skills, owner's
engine, owner's scopes.

What keeps this from being a hole:

1. **The answer is filtered through the borrower's scopes before it is
   shown.** The agent may read what the owner may read; the borrower sees
   only what the borrower may read. Derived-label inheritance (3.1) is what
   makes this checkable: an answer that drew on `matter:0142` carries that
   label, and if the borrower lacks `artifacts:read:matter:0142` the answer
   is withheld and the ledger says so. The owner can lift this with
   `reveal = "owner-context"` on the lease, which is the deliberate case -
   "answer her as you would answer me" - and the ledger records that choice.
2. **Spend is the owner's**, so the lease carries `cost:spend:<budget>` or
   inherits the owner's cap. A borrowed agent runs out of the lender's money,
   not the firm's.
3. **Every prompt is a ledger entry with two principals**: prompter and
   owner. Neither can later claim the other did it.
4. **No re-lending.** `agents:use` is never conferrable by the borrower;
   attenuation forbids it because the borrower does not hold `agents:own`
   on that agent.
5. **Label policy still wins.** A borrowed scribe on a `patient:*` label
   still needs a purpose, still cannot leave the onprem tier, still cannot
   feed shared memory without consent. Lending changes who asks, never what
   the data permits.
6. **The owner can watch.** The lease may set `transcript = "owner"` so the
   owner sees every exchange, or `"summary"` for the ledger line only.
   Default is `"owner"`; a firm that wants borrowed use private to the
   borrower says so in policy.

### 3.6 Smaller things the axes make easy

- **Delegation depth.** `handoff` carries a hop count. An attorney's agent
  may delegate once; a contractor's not at all. Attenuation already shrinks
  scope per hop; this bounds the chain.
- **Budget as a scope.** `cost:spend:<budget-id>` on an agent's or a borrower's lease.
  Spend is authority; a leaked agent should run out of money before it runs
  out of time.
- **Tool scopes on agents.** `tools:shell`, `tools:network`, `tools:browser`
  as scopes the owner may or may not hold and therefore may or may not
  confer. An agent working `phi` gets no `tools:network`; the policy on the
  label can require it.
- **Label lifecycle instead of calendar expiry.** A matter closing narrows
  every scope on it to `read`, then retention purges it. Nobody has to
  remember to revoke the paralegal from a case that settled.

## 4. Resolution rules

Applied in this order, by one pure function, everywhere:

1. **Default deny.** No grant, no lease, no scope.
2. **Collect.** The principal's valid master grant, plus every unexpired and
   unrevoked lease naming it. Union the scopes. Each scope is bound to the
   projects on the grant or lease that carried it.
3. **Attenuate.** If the principal is an agent, intersect with its owner's
   set as of the same instant. The result can only shrink.
4. **Intersect the other axes.** Drop any scope the label policy refuses
   for this action (`train`, `export`, `infer`), that the acting machine's
   tier or region cannot satisfy, or that needs a subject consent lease that
   is not live.
5. **Exclude.** Subtract every exclusion naming this principal, its owner, or
   any of its labels. An exclusion is a master-signed record and beats
   everything above it, including `owner`.
6. **Match.** Required scope matches a held scope on resource and action,
   then on selector as in section 2, then on project.
7. **Gate.** If the matched scope is marked `two_person` in `roles.toml`, or the label has `two_person_read` and the action is a read, the action becomes an approval request to a second principal who also
   holds it. The requester cannot approve their own request.
8. **Record.** Every denial and every gated approval is a ledger entry. A
   plain allowed read is not, or the ledger drowns.

Consequences worth spelling out:

- A person with `owner` in project A and nothing in project B sees nothing in
  B. There is no business-wide access except `projects: ["*"]`, which is
  visible in the grant.
- An agent whose owner loses a matter loses it at the same instant, because
  rule 3 reads the owner's set live.
- An exclusion outranks a role. "Partner, except the Acme matter" is one
  record, and it holds for the partner's agents too.
- Engagement does not change scopes. `temp` and `employee` with the same role
  have identical scopes and different horizons.

### Break-glass

Clinics and, less often, law offices need access nobody granted in advance:
the covering physician at 3 a.m., the attorney who must see the walled matter
because opposing counsel just moved to disqualify. Break-glass is:

- a lease the principal issues **to itself**, with `reason` filled in,
  horizon capped at what `roles.toml` allows (default 4 hours),
- limited to scopes named in `[break_glass]` (typically reads),
- a ledger entry of kind `break-glass` that the owner and anyone holding
  `ledger:read` sees at once, and that the dashboard surfaces on Home until a
  second principal marks it reviewed.

It is an audit event with authority attached, not a permission. A business
that does not want it sets `break_glass.enabled = false`.

### Purpose of use

A lease may carry `purpose`. It is free text in a dev firm and an enum in a
clinic (`treatment`, `payment`, `operations`, `patient-request`). Ferryman
records it and shows it; it does not reason about it. The clinic's privacy
officer does, from the ledger.

## 5. Office types

The first question setup asks, before anyone is invited, is **what kind of
office is this**. The answer picks a profile: its roles, its label kinds,
its data policy defaults, and its *everyone* baseline. Nothing else about
Ferryman changes. A business can change the answer later; grants already
signed keep their scopes.

What separates the types is not the org chart. It is **who the data is
about** and **who is answerable for it**:

| office type | the data is about | answerable person | what a grant is usually *for* | profile |
|---|---|---|---|---|
| Dev house | customers, and the firm's own code | the lead | a repo, a feature, a customer's tickets | `dev-firm` |
| Law office | clients (matters) | the responsible attorney | a matter | `law-office` |
| Medical practice | patients | the treating clinician | a patient, with a purpose | `medical-clinic` |
| Accounting / tax / bookkeeping | clients' finances | the engagement partner | a client, a tax year | `accounting-firm` |
| Agency / consultancy / studio | clients' brands, plans, unreleased work under NDA | the account lead | a client, a campaign | `agency` |
| Staffing / HR / recruiting | candidates and employees | the recruiter or HR lead | a requisition, an employee file | `general-business` with `person:*` |
| Financial advisor / family office | households' money | the advisor | a household | `accounting-firm` renamed |
| Real estate / property management | buyers, tenants, owners | the agent or manager | a transaction, a property | `general-business` |
| School / tutoring / training | students | the instructor | a student, a class | `medical-clinic` shape without the clinical roles |
| Nonprofit | donors and beneficiaries | the program lead | a program, a donor | `general-business` |
| Any other business | customers and employees | the manager | a customer, a project | `general-business` |

`general-business` is the floor every other profile is a specialisation of:
three label kinds (`customer`, `employee`, `project`), five roles (owner,
manager, staff, contractor, viewer), sensible defaults. A business that
does not see itself in the table starts there and renames.

**Mixed.** A firm with a legal department, an engineering team and a
finance team is one master and three projects, each with its own profile.
The profile is per project, not per server. The Teammates page shows one
list; each row's *Can* sentence is written in that project's words.

### 5.0 Everyone: the office library

Every profile has an **everyone** baseline: what a person gets on day one
by being on the roster, before any grant is signed, and what every agent in
the building gets too. In every shipped profile it is the same shape:

- read the **library** - a label (`library`) whose policy is `train =
  always`, `infer = any`, `export = owner`; the place for the firm's own
  playbooks, templates, style guides, and precedent that has been through
  redaction;
- read shared memory and the fleet's learnings that were derived from the
  library;
- see who is in the office and what the fleet is doing (status, not
  content);
- message business agents whose audience is *everyone*.

The library is what makes AI useful in an office that cannot let AI near
its real work. A law firm's library holds its motion templates and the
redacted versions of its best briefs; the redaction pipeline is how a
matter's document becomes a library document, and a `redacted_view` on the
matter label is how that happens without anyone re-uploading. A clinic's
library holds protocols and de-identified case summaries. A dev house's
holds the conventions doc and scrubbed postmortems. Every agent in the
building may learn from it, so the fleet gets smarter on the firm's own
knowledge without touching a live matter, chart, or customer.

The baseline is a role like any other (`everyone` in each profile) and is
auto-granted to every roster name by the master, once, at setup. A firm
that wants no baseline empties the role.

## 6. Profiles

Each profile is a `roles.toml`. The shape:

```toml
format = "ferryman-roles/v1"

[roles.<name>]
scopes   = ["tasks:read", "conversations:read", ...]   # explicit list
extends  = "<other role>"                              # optional, expanded at write time
minus    = ["tasks:review"]                            # optional, removed after extends
label    = "kind"        # optional: this role is always granted per-label of this kind
note     = "one line for the person reading the ledger"

[two_person]
scopes = ["secrets:set", "release:approve"]

[break_glass]
enabled = true
max_hours = 4
scopes = ["tasks:read", "artifacts:read", "conversations:read"]

[purposes]              # empty means free text
allowed = []

[labels.matter]         # the data's own policy; see section 3.1
train = "never"
infer = "local"
export = "two-person"
review_before_release = true
lifecycle = "closed"
retention = "7y"

[machines.grouchly]     # see section 3.2
tier = "onprem"
region = "us"
engines = { deepseek = { local = true } }
```

`extends` and `minus` are conveniences for the file's author. They are
resolved when the grant is signed; the grant carries the flat list.

### 6.1 Dev firm — `examples/roles/dev-firm.roles.toml`

| role | who | in one line |
|---|---|---|
| `owner` | founder | administrative everywhere; content everywhere too, because a dev firm chose that |
| `admin` | ops / IT | everything but secrets values and granting |
| `lead` | eng lead | developer + review + assign + cost, per project |
| `developer` | staff eng | take, submit, converse, propose memory, use project secrets |
| `contractor` | outside dev | developer minus secrets, per feature label |
| `reviewer` | senior / QA | read + review, no take/submit |
| `sales` | the Redaktly case | read tasks and conversations, message agents, read cost |
| `support` | CS | viewer + create tasks + write conversations |
| `viewer` | stakeholder | read only |
| `ci` | agent | worker + `release:read`; owned by lead |
| `release-agent` | agent | `release:approve` is two-person, so it prepares and a human signs |
| `everyone` | all | conventions, scrubbed postmortems, status; auto-granted to all |

### 6.2 Law office — `examples/roles/law-office.roles.toml`

Projects are practice groups; matters are labels `matter:<id>`. Every role
below `partner` is granted **per matter label**, which is what `label =
"matter"` on the role enforces: the dashboard will not sign an `associate`
grant without at least one matter.

| role | in one line |
|---|---|
| `managing-partner` | administrative authority firm-wide; matter content only where granted, like everyone |
| `partner` | administrative within the practice group; grants attorney and below; content per matter |
| `attorney` | full work on assigned matters, review, approve memory, own agents |
| `associate` | attorney minus review and memory approve |
| `paralegal` | associate minus create; artifacts read/write |
| `legal-assistant` | create tasks, write conversations, read; no artifacts on `privileged:*` |
| `of-counsel` | attorney, engagement forced to `contractor` |
| `billing` | cost, ledger, task status; **no** conversations or artifacts |
| `it` | team, fleet, secrets set/rotate, policy; **no** matter content |
| `client` | read their own matter label; conversations on `client:<id>` only |
| `drafting-agent` | owned by an attorney or associate; take/submit/artifacts on the owner's matters |
| `intake-agent` | business agent; create tasks, write `intake` topic; reads nothing privileged |
| `everyone` | the library, shared memory from it, who is in, status; auto-granted to all |

Exclusions are the ethical wall: `[[exclusions]] principal = "jdoe" labels =
["matter:2026-0142"]`, master-signed. Applies to jdoe's agents by rule 3.

`privileged:*` is a second label kind on artifacts and conversations for
work product; `legal-assistant`, `billing`, `it`, `client` and every
business agent lack `artifacts:read:privileged`.

### 6.3 Medical clinic — `examples/roles/medical-clinic.roles.toml`

Projects are departments or sites; patients are labels `patient:<opaque>`.
Same per-label rule as matters. Additional constraints on top of the law
profile:

- `purposes.allowed` is the enum, and a lease without one is refused for any
  role that touches `patient:*`.
- `break_glass` is on, 4 hours, reads only, and reviewed by `privacy-officer`.
- Ledger retention is set to the clinic's documentation retention period;
  the profile ships a `retention_years = 6` comment pointing at the
  clinic's own policy rather than asserting what the law requires of them.
- Nothing in the profile grants `secrets:use` on the EHR credential to a
  human. Only the business agents that talk to the EHR hold it, and their
  owner is the clinic administrator, who can see the use log but not the
  value.

| role | in one line |
|---|---|
| `medical-director` | administrative authority; patient content per label, like everyone |
| `clinic-admin` | admin, owns business agents, no clinical writes |
| `physician` | full work on their patients, review, approve memory, own agents |
| `np-pa` | physician minus memory approve |
| `nurse` | take/submit/artifacts on assigned patients; no review |
| `ma` | nurse minus artifacts write |
| `front-desk` | create tasks and write `scheduling` topic; reads no clinical labels |
| `billing-coding` | cost, ledger, `tasks:read:billing`, `artifacts:read:billing` |
| `privacy-officer` | ledger, team, policy read; reviews break-glass; no clinical content except via break-glass |
| `it` | as law office |
| `patient` | read own label; write `patient-portal:<id>` topic |
| `scribe-agent` | owned by physician; writes drafts on owner's patients |
| `triage-agent` | business agent; reads `intake` topic, creates tasks, no `patient:*` artifacts |
| `ehr-agent` | business agent; the only holder of `secrets:use:ehr`; owned by clinic-admin |
| `everyone` | protocols and de-identified summaries in the library; status; auto-granted to all |

### 6.4 Accounting firm — `examples/roles/accounting-firm.roles.toml`

Labels `client:<id>` and `period:<client>-<year>`. Roles: `managing-partner`
(administrative), `partner`, `cpa`, `senior`, `staff-accountant`,
`bookkeeper`, `admin`, `client`, `prep-agent`, `everyone`. `period` labels
close on filing and drop to read; `retention` follows the firm's policy for
workpapers. `train = with-consent` on clients, `never` on `period`.

### 6.5 Agency — `examples/roles/agency.roles.toml`

Labels `client:<id>` and `campaign:<id>`, plus `unreleased` for anything
under embargo. Roles: `owner`, `account-lead`, `strategist`, `creative`,
`freelancer` (contractor, per campaign, no `unreleased` until the lead
says), `client`, `brief-agent`, `everyone`. `export = never` on
`unreleased` until the campaign's lifecycle flips to `launched`.

### 6.6 General business — `examples/roles/general-business.roles.toml`

Labels `customer`, `employee`, `project`. Roles: `owner`, `manager`,
`staff`, `contractor`, `viewer`, `assistant-agent`, `everyone`. `employee`
is the one label with `two_person_read` on by default, because the person
most likely to be curious about an employee file is a manager.

## 7. What the dashboard shows

- Setup, first run: *What kind of office is this?* - one card per type from section 5, with a one-line description of who gets access and for what. Picks the profile for the project. *Mixed* means choose per project.
- Teammates: pick a role, pick projects, pick labels (required when the role
  has `label`), pick an engagement, pick a purpose if the profile has an
  enum. The expanded scope list is displayed before the operator signs.
- Agents: the same, with the owner's scopes drawn as the ceiling and
  anything above it greyed out and unselectable.
- Exclusions: a separate page, master only, that lists walls by principal
  and by label and shows which agents inherit each one.
- Audit: filter by principal, label, purpose, and `break-glass`.

## 8. Open items the business decides, not Ferryman

- Who owns business agents (settled: the business, by signed record).
- Whether `partner` may grant `attorney` or only `associate` and below —
  the profile ships the former; `team:grant` can be selector-scoped to role
  names if a firm wants the latter.
- Whether clients and patients get accounts at all. The profiles include
  the roles; nothing in Ferryman requires using them.
