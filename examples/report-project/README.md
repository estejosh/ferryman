# Report project integration

This intentionally provider-neutral project submits structured input and lets its own worker decide how to create a report.

```http
POST /v1/projects/demo/jobs
Authorization: Bearer <project-token-from-your-local-secret-store>
Content-Type: application/json

{"input":{"task":"weekly report","sources":["local://notes"]},"policy":{"network":"deny","shell":"deny"}}
```

The project should consume only returned job IDs, events, and artifact metadata. Its domain credentials remain in its worker environment, never in the bridge.
