# Operating model

Orchestrator Bridge is a self-hosted control plane and evidence store. It is not an AI agent, autonomous planner, or model provider.

- **Orchestrators** decide what work to request and which agents/workers to involve.
- **Agents** supply project-specific reasoning and domain behavior.
- **Workers** execute a leased capability and return progress, results, and artifacts.
- **The Bridge** persists job state, policy/approval decisions, recovery memory, artifacts, and audit events.

When an agent or orchestrator loses context, a new or recovered actor loads the Bridge's project memory and job/event history. The Bridge does not decide what to do with that information.
