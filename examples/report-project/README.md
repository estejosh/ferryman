# Report project integration

This intentionally provider-neutral project submits structured input and lets its own worker decide how to create a report.

```bash
curl -X POST http://127.0.0.1:8787/v1/projects/demo/jobs \
  -H 'Authorization: Bearer demo-local-token' -H 'content-type: application/json' \
  -d '{"input":{"task":"weekly report","sources":["local://notes"]},"policy":{"network":"deny","shell":"deny"}}'
```

The project should consume only returned job IDs, events, and artifact metadata. Its domain credentials remain in its worker environment, never in the bridge.
