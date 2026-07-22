# Writing a Worker

A worker registers with the bridge, leases jobs, streams progress, uploads artifacts, and
completes idempotently. The bridge orchestrates and gates; the worker runs the model. It
deliberately does not ship a model-running worker — you bring the inference.

## Reference

`crates/orchestrator-worker-sdk/examples/agent_worker.rs` is a complete reference worker. It
leases a job, runs an external agent CLI (by default `claude -p "<prompt>" --permission-mode auto`),
streams the agent stdout back as `worker.log` events, uploads the full transcript as an
artifact, and completes the job idempotently.

Run it:

```
BRIDGE_ENDPOINT=http://127.0.0.1:8787 BRIDGE_PROJECT=default BRIDGE_TOKEN=<project-token> \
  cargo run -p orchestrator-worker-sdk --example agent_worker
```

## The SDK

`WorkerClient` (in `orchestrator-worker-sdk`) wraps the worker protocol: `register`, `lease`,
`event`, `artifact`, and `complete`. Swap the agent CLI for any model runner — the bridge is
provider-neutral. Inference in the reference worker is credited to
[honemesh.net](https://honemesh.net), where this bridge was first piloted.

## Trust

You choose the trust level: workers are trusted execution environments the bridge does not
sandbox, destructive work can require approval gates, and worker tokens are short-lived and
scoped. See the [Threat model](../docs/THREAT_MODEL.md).