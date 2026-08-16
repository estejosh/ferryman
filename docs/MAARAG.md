# MAARAG — why multi-agent auditable retrieval is necessary

**MAARAG** = Multi-Agent Auditable Retrieval-Augmented Generation. This is the
rationale paper for the feature surfaced as `ferry ask`, whose output is an
*auditable answer*: a natural-language answer in which every claim carries its
signed source.

## The problem

Ferryman is a fleet, not an assistant. Many agents — each with its own signing
identity — write to the shared memory bank, the attribution ledger, task
history, and learnings. Over time the fleet accumulates the answer to most
questions about the project: why a decision was made, who did what, what
worked, what was sent back.

Today that knowledge is *stored* but not *retrievable as an answer*. Ask "why
did we choose Syncthing over a central server?" and there is no command that
returns the answer with its source. An agent or operator must read the files and
reconstruct the answer by hand — or ask a model that will *guess*.

## Why plain RAG does not fit

Retrieval-augmented generation is the industry's answer to "ground a model in my
documents." But the standard RAG shape assumes three things, all wrong for
Ferryman:

1. **One user, one assistant** over a personal or company corpus.
2. **A static, read-only corpus** — documents someone uploaded.
3. **Embedding search** — a vector store and an embedding model in the
   retrieval path.

First, the corpus is **multi-writer**: many agents and operators, each with a
signing key. The important fact about a memory is not just *what* it says but
*who said it, under what identity, and whether it was accepted or sent back*.
Plain RAG has no concept of that.

Second, the corpus is **a living, contested, signed log**, not static documents.
Entries are added, reviewed, and sometimes rejected. Retrieval must respect that.

Third, embeddings violate Ferryman's core constraint: **offline, deterministic,
single-binary, no model in the loop for routing**. The existing retrieval — the
skills router and `routing_hint` — is deliberately keyword-overlap, with the
stated requirement "no embeddings and no network." A vector store would
reintroduce a model dependency and a layer of nondeterminism exactly where the
fleet most needs reproducibility.

Most importantly, plain RAG returns *relevant passages*, not *trustworthy
claims*. It answers "here is some text that looks related." It does not answer
the question a fleet actually has: **"who said this, and can I check?"**

## What MAARAG is

MAARAG is retrieval-augmented generation scoped to a multi-agent, auditable
channel:

- **Multi-agent** — every retrieved source is a signed claim by an agent or
  operator identity, not an anonymous document.
- **Auditable** — the answer carries each claim's provenance: the source file or
  entry, the signer, and its acceptance status. Every statement can be traced
  and verified.
- **Retrieval without embeddings** — deterministic keyword overlap over the
  memory bank, ledger, task history, and learnings, consistent with the
  existing router. Offline, reproducible, no model dependency.
- **Generation grounded in signed claims** — the model composes the answer from
  what was actually retrieved, and the citations travel with the text.

The product form is one command and one output:

```sh
ferry ask "why did we choose Syncthing over a central server?"
```

returns an auditable answer: a natural-language answer in which every claim
carries its signed source — file, signer, acceptance status — so an operator or
another agent can verify it rather than trust it.

## Why it is necessary

Ferryman is built on an audit culture. Orders, results, and reviews are signed;
the ledger is a signed audit trail; unverifiable work is reported as
`UnknownSigner` and treated as suspect. Confidence is *measured* from
accepted-vs-sent-back outcomes, never self-reported.

An answer that cannot be audited breaks that culture at its most important
point — the moment a human or agent makes a decision. A hallucinated or
unattributed answer is not merely wrong; it is *unauditable*, and in a system
whose whole value is verifiability, that is worse than no answer at all. It
cannot be trusted, it cannot be attributed, and it cannot be improved, because
there is no record of where it came from.

MAARAG is necessary because the fleet's knowledge has a property plain retrieval
does not: **provenance**. Capturing that provenance in the answer — making every
claim auditable — is not a nice-to-have. It is the difference between an
assistant that "looks related" and a fleet that can be held accountable for what
it knows.

## Scope

MAARAG is read-only. It retrieves and cites; it does not write. An auditable
answer is a *view* over the channel's signed knowledge, not a new source of
truth — the same derived-view principle that keeps the roster and the discovery
manifest race-free.
