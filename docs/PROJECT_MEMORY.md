# Bridge-owned project memory

Project memory is the bridge's recovery record, not an agent's scratchpad. The Bridge is infrastructure: it does not become an agent or orchestrator when an actor loses context. Instead, it supplies the durable record a recovered or replacement actor loads before continuing work. It is stored in two independently maintained forms:

1. An append-only SQLite record, available through `GET /v1/projects/{project_id}/memory`.
2. A Markdown mirror at `<memory-root>/<project-slug>/MEMORY.md`, outside the project Git workspace.

The default memory root is `./.data/bridge-memory`. It is never included in a worker's project workspace or policy envelope. A corrupt, deleted, or reset agent/orchestrator can therefore reload this memory before resuming work.

## What belongs here

- durable decisions and constraints;
- project naming, ownership, and integration conventions;
- approved operational facts and recovery handoffs;
- references to artifacts or job IDs, rather than raw private prompts or secrets.

Entries are append-only. Correct a bad entry with a new entry that identifies the correction; never rewrite history. The caller supplies a category and provenance `source` such as `operator`, `release-manager`, or `saturday-80s-visual-qa`.

For a true recovery boundary, set `ORCHESTRATOR_MEMORY_WRITE_TOKEN` on the bridge and keep the matching `ORCHESTRATOR_MEMORY_TOKEN` only with the human/operator or trusted memory service. The bridge then requires that separate token for new memory entries; workers with only project tokens can read history but cannot add or alter it. Without this configuration, local development permits project-token memory writes for convenience.

## CLI

```powershell
orchestrator-cli --token $env:ORCHESTRATOR_TOKEN memory add --project saturday-80s --category decision --content "Morning block remains family-safe." --source operator
orchestrator-cli --token $env:ORCHESTRATOR_TOKEN memory list --project saturday-80s
```
