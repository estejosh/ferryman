# Getting Started

## Run the bridge (local)

```
cargo run -p orchestrator-server -- --database ./.data/bridge.db --artifacts ./.data/artifacts
```

It listens on `127.0.0.1:8787` and seeds a demo project with token `demo-local-token`.

## Submit and approve a job

```
cargo run -p orchestrator-cli -- --token demo-local-token jobs submit --project demo \
  --input '{"prompt":"make a report"}' --requires-approval
cargo run -p orchestrator-cli -- --token demo-local-token jobs approve --project demo <job-id>
cargo run -p orchestrator-cli -- --token demo-local-token jobs tail    --project demo <job-id>
```

## Run a worker

A harmless mock worker:

```
cargo run -p orchestrator-worker-sdk --example mock_worker
```

A real agent worker (runs an external model CLI):

```
cargo run -p orchestrator-worker-sdk --example agent_worker
```

See [Writing a Worker](Writing-a-Worker) to point it at your own agent. Every project gets a
private local Git workspace under `./.data/projects/<slug>`; nothing is published to a remote.