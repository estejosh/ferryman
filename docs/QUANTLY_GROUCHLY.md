# Quantly on Ferryman

Quantly is a first-class **paper-research service** on a Ferryman channel. It
uses Ferryman's normal signed, durable messages and its existing transport order:
local filesystem, shared device-to-device folder, then a private Git fallback.
There is no cloud relay, HTTP listener, broker adapter, or Python component in
this integration.

## Safety boundary

The `quantly.ferryman/v1` schema accepts research requests/results, market
snapshots, replay events, and paper order/fill records only. Every record has
`paper_only: true`; a false value is rejected before delivery. The protocol has
no live-order or account-operation event type. Ferryman also rejects portable
payloads with credential-like keys, so API keys and broker credentials cannot
be placed in channel messages.

Paper orders are simulation intent, not instructions to submit an order. The
Quantly Rust consumer must keep any broker integrations absent or disabled and
must treat schema validation failure as a no-op with an acknowledgement/error
record rather than a fallback to live behavior.

## Install on Grouchly

1. Install or update the Rust Ferryman CLI from this repository. The Quantly
   integration is in `ferryman-channel`, so no Python runtime is required.
2. Ensure the Quantly channel is already present in the canonical shared
   communications root on both machines. Use the existing device-to-device
   folder pairing; do not create a cloud sync or public Git remote.
3. On Grouchly, register its existing machine identity in the Quantly channel:

   ```sh
   ferry channel join --workspace /path/to/quantly \
     --name grouchly --role research-peer \
     --capabilities quantly.research.receive,quantly.research.publish,quantly.paper.replay
   ```

   If Grouchly already holds the `grouchly` identity in another Ferryman
   channel, use `ferry channel seat` with the canonical communications root
   instead of minting a second identity.

4. On the Quantly machine, register the Quantly service identity:

   ```sh
   ferry channel join --workspace /path/to/quantly \
     --name quantly --role research-service \
     --capabilities quantly.research.receive,quantly.research.publish,quantly.paper.replay,quantly.paper.ledger,quantly.paper.market
   ```

5. Copy `examples/quantly-grouchly-peer.toml` into Quantly's local config and
   keep its three safety flags `false`. It contains no credential fields.
6. Run `ferry channel agents --workspace /path/to/quantly` on both machines;
   verify that both `quantly` and `grouchly` appear with their paper-only
   capabilities. Then run `ferry channel status --workspace /path/to/quantly`
   to confirm the shared transport and the private Git fallback configuration.

## Rust consumer contract

The Quantly monorepo can depend on `ferryman-channel` and use
`quantly::QuantlyEnvelope` to serialize and validate its domain event before
calling the existing Ferryman `DeliveryEngine`/channel send path. On receive,
call `QuantlyEnvelope::from_message` before a replay or paper ledger action.

```rust
use ferryman_channel::quantly::{QuantlyEnvelope, QuantlyMessageKind};
use serde_json::json;

let event = QuantlyEnvelope::new(
    QuantlyMessageKind::ResearchRequest,
    "research-20260920-001",
    json!({"question": "compare current paper strategies"}),
);
let message = event.into_message(
    "quantly", "quantly", "grouchly", true, Some("research-20260920-001".into()),
)?;
// Send `message` with Ferryman's normal local/shared/private-Git transport.
```

Use a stable run ID as the idempotency key for replay/paper events. Claim and
acknowledge messages using the normal Ferryman consumer flow before executing a
simulation action; this prevents duplicate work when a shared folder and the
private Git fallback both deliver the same envelope.
