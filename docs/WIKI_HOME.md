# Ferryman Wiki

A self-hostable, provider-neutral control plane for durable AI-assisted work. Independent
workers lease and complete jobs through a small HTTP protocol; the bridge persists state,
artifacts, audit events, and approval decisions without owning model execution.

> v0.1 is a local, single-node reference implementation. Treat it as a preview/blueprint,
> not production infrastructure. See [Public Release Plan](../docs/PUBLIC_RELEASE_PLAN.md).

## Start here
- [Getting Started](Getting-Started) — run the demo in a few minutes.
- [Writing a Worker](Writing-a-Worker) — connect a real agent (Claude, Codex, anything).

## Concepts & design
- [Architecture](../docs/ARCHITECTURE.md)
- [Operating model](../docs/OPERATING_MODEL.md) — control plane, not an orchestrator/agent.
- [Agent model](../docs/AGENT_MODEL.md)
- [Project memory](../docs/PROJECT_MEMORY.md)
- [Threat model](../docs/THREAT_MODEL.md) — trust boundaries; you choose your trust level.

## Operate
- [Deployment](../docs/DEPLOYMENT.md)
- [Backup & recovery](../docs/BACKUP_AND_RECOVERY.md) · [Two-machine recovery](../docs/TWO_MACHINE_RECOVERY.md)
- [Upgrading](../docs/UPGRADING.md)

## Contribute
- [CONTRIBUTING](../CONTRIBUTING.md) · [SECURITY](../SECURITY.md) · [CHANGELOG](../CHANGELOG.md)

The HTTP contract is versioned in [`openapi/openapi.yaml`](../openapi/openapi.yaml) (`/v1`).