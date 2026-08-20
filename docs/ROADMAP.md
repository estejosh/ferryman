# Roadmap

Direction, not a schedule. `REPO_ROADMAP.md` is the map of the code as it is; this is what
is deliberately not built yet, and why.

Each entry says what it is, what it is **not**, and what would have to be true before it
ships. An item with no honest failure mode written down is an item nobody has thought about
hard enough.

---

## Secrets through the channel

**Now.** A fleet's real friction is not coordination, it is credentials. Today a token has
to be carried to every machine by hand, and it is usually spelled differently on each one,
so instructions cannot be written once. That is the same courier problem Ferryman was built
to remove from work, still present for the things work depends on.

Every agent already publishes a public key in the roster, and Syncthing already delivers the
roster everywhere. So the channel can carry ciphertext while private keys stay where they
have always been. Set a secret once, from the dashboard, tick the machines that should have
it; every worker resolves it locally. A machine that has joined needs no further visit.

Two limits, deliberately independent:

- **Channel scope.** A secret lives in one project's folder and reaches only devices sharing
  that project. Never the fleet folder.
- **Recipient scope.** Sealed per agent, so a phone in the channel is not carrying a
  repository token it has no use for.

### Distribution modes

Sealing everything to everyone up front is the simple model, not the right one for every
secret. Three modes, per secret:

- **`open`** — sealed to its recipients when it is set. No latency, no approval, the machine
  has it before it needs it. Right for a token the fleet uses constantly.
- **`on-request`** — nothing is sealed to a machine until it asks. The agent states *why*,
  citing the order it is working, and an operator approves. Right for anything whose misuse
  would be expensive.
- **`policy`** — auto-approve named combinations of secret, agent and scope; ask for the
  rest. Keeps unattended work flowing overnight without making every credential ambient.

`on-request` is the one that fits this codebase best, because the machinery already exists:
`requires_approval` on orders, master-signed short-lived leases, consent records, and an
approval gate that already reaches a phone. A secret request is the same shape as work that
needs a human — and the *reason* belongs in the ledger beside everything else, so "why did
fang have the deploy key on Tuesday" is a question with a signed answer rather than a
shrug.

Approving over Telegram is fine, incidentally, and worth distinguishing: approving a request
leaks nothing, because the secret never travels that path. Only the decision does.

**The honest limit.** Just-in-time narrows the window, not the fact. Once a machine has been
handed a value it has that value, and no protocol takes it back. The real answer to that is
short-lived credentials — tokens minted per task and expiring on their own — which is what
the lease machinery already anticipates and where this should end up. Until then, `on-request`
buys a smaller exposure window and a real audit trail, and it should be described as exactly
that rather than as containment.

**What it is not.** Not a password manager. No autofill, no mobile client, no recovery. If a
machine's disk dies, everything sealed to it is gone and the answer is rotation. That is a
reasonable answer for a repository token on a box you control and an unacceptable one for a
person's bank login — see the next entry for why that distinction matters.

**Before it ships:**

- Wrap an audited implementation rather than hand-rolling. Less novel cryptography is less
  to review and less to get subtly wrong.
- Say plainly, in the docs, that rotation is the only real revocation. Once ciphertext has
  synced it is on those disks and in Syncthing's history; removing an agent from the roster
  does not unsend it.
- A reader that cannot decrypt fails loudly and specifically. Handing an engine an empty
  string instead of a credential produces a failure three steps away from its cause.
- Never through the Telegram bridge. A cloud chat is not end-to-end encrypted; orders are
  fine to leak, credentials are not.

**Competitors here** are agenix, sops, Vault Agent, and the machine half of Doppler and
Infisical — not password managers. The edge is that the recipient list is a roster you
already maintain, the bootstrap was done when the machine joined, and the envelope is signed:
agenix documents that its encrypted files are *not* authenticated, so anyone with write
access to the repository can replace them. That is the specific thing to beat.

---

## The bridge should answer like a person, not a form

**Next, after secrets.** Message the fleet from a phone today and you get a receipt:
`issued tg-4821 to fang`. Ask the same thing at a desk, of something that can think, and
you get an answer — it works out what you meant, says who should do it and why, tells you
what it found, and asks when the request is ambiguous rather than guessing.

The gap is not politeness. A receipt makes the operator do the reasoning: which machine
should have this, is this the same as the thing I asked yesterday, did that other task ever
finish, is this even worth doing. All of that is knowable from the channel, and none of it
is in the reply.

Two capabilities, and they are the same feature approached from opposite ends:

**Routing.** `--default-to` fixes the worst of it — before it, an unaddressed message went
to whichever machine polled fastest, which in a mixed fleet reliably means the most
expensive one. But a fixed default is still not a decision. Who *should* do this depends on
what it is, what each machine is good at, what they cost to run, what they are already
doing, and whether one of them has done something similar before. The channel knows all of
that: roles and specialisations in the roster, cost per engine, live task states, and a
learning database of which engine wins on this project.

**Conversation.** The bridge is a channel client with no engine behind it, which is why it
is free and why it cannot think. Putting an orchestrator between the phone and the fleet —
an agent whose task is "handle this request" and which can read the channel, dispatch work,
and reply — closes the gap. It is the same shape as any other Ferryman task, with the
operator's chat as its input and its output.

**What it costs, honestly:**

- **An engine run per message.** Today a bridge costs nothing. This makes every "so?" a
  billable thought. It belongs on the cheap machine, and obvious commands — `/status`,
  `/agents` — should keep answering directly without waking a model.
- **Latency.** A chat reply that takes ninety seconds is a bad chat. Acknowledge
  immediately, answer properly when it lands. That is what a person does.
- **Memory.** This is the real work. A desk conversation carries context; each chat message
  arrives alone. Loading the memory bank and recent channel state gets most of the way, but
  genuine continuity across messages needs a thread the orchestrator can read and append to,
  and that does not exist yet.
- **A new trust boundary, and the sharpest one here.** An agent that turns chat into orders
  is a confused deputy waiting to happen. Checking `from.id` proves *who sent the message*
  and nothing about what it says. If the orchestrator then reads a document, an issue
  tracker, or another agent's result, instructions embedded in that content must never be
  able to dispatch work — the operator's message is the instruction, everything else is
  data. Ferryman already refuses to act on orders whose signatures do not verify; the same
  discipline has to extend to text that merely *looks* like an instruction.

**The measure:** the operator should be able to ask "so?" and get something worth reading.
If the reply is a receipt, this is not done.

---

## A sovereign password manager

**Later, and only after the above has been audited.** The interesting version of the idea:
a password manager with no company in the middle. Your devices, your keys, sync over a
folder you control, no account to close and no vendor to trust or outlive.

The technical core is largely the same as the entry above. That is exactly why it is
tempting, and exactly why it is dangerous to treat as a small step: the hard parts of a
password manager are not cryptographic.

**What actually makes that product**, none of which exists here:

- **Recovery.** The single biggest reason people pay for one. Lose a device today and the
  secrets sealed to it are gone. A person's password vault cannot work that way, and every
  recovery scheme is a deliberate weakening of the thing being recovered. This is the design
  problem, and everything else is downstream of how it is answered.
- **Clients.** Browser extension, iOS, Android, desktop. Autofill is table stakes and is
  most of the engineering.
- **The trust business.** Third-party audit, a published threat model, a bug bounty,
  disclosure process, and somebody to answer when it goes wrong. A sovereign tool does not
  escape this by having no company — it inherits the obligation personally.
- **The failure mode is different in kind.** A leaked repository token is expensive. A
  leaked password vault is somebody's life. That difference should govern the pace.

**Gate:** do not begin until the fleet secrets feature has been through an external audit
and has been in real use long enough to have been wrong at least once. The sequencing is not
timidity; it is that the second product is only credible if the first one has survived
contact with reality.
