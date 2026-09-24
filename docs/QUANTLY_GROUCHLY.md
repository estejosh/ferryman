# Quantly on Ferryman

Quantly is a first-class paper-research service on a Ferryman channel. Ferryman
coordinates Quantly, Beastly, and Grouchly through signed local files carried by
the existing device-to-device Syncthing folder. This integration adds no cloud
relay, HTTP broker, or Python runtime.

The current research and implementation brief is
[Beastly: Quantly research direction](BEASTLY_QUANTLY_DIRECTION.md). The
machine-readable companion is
[`examples/quantly-research-policy.toml`](../examples/quantly-research-policy.toml).

## Safety boundary

The `quantly.ferryman/v1` schema accepts research requests/results, market
snapshots, replay events, and paper order/fill records only. Every record has
`paper_only: true`; a false value is rejected before delivery. The protocol has
no live-order or account-operation event type. Ferryman also rejects portable
payloads with credential-like keys.

Paper orders are simulation intent, not instructions to submit an order. The
Quantly Rust consumer must keep broker execution absent or disabled and treat a
schema validation failure as a no-op plus an acknowledgement/error record. It
must never fall back to live behavior.

Quantly-owned code remains Rust-only and UFL 1.1. This does not change
Ferryman's license or the licenses of upstream dependencies.

## Peer setup

1. Install or update the Rust Ferryman CLI from this repository. No Python
   runtime is required.
2. Use the existing Quantly channel in the canonical communications root. Let
   Ferryman manage its Syncthing folder; do not create a cloud relay or expose
   the channel through a public Git repository.
3. Register the existing Grouchly identity in the Quantly channel. If that
   identity is already seated in the canonical root, use `ferry channel seat`
   rather than minting a duplicate identity.
4. Register the Quantly service with these paper-only capabilities:
   `quantly.research.receive`, `quantly.research.publish`,
   `quantly.paper.replay`, `quantly.paper.ledger`, and
   `quantly.paper.market`.
5. Keep `examples/quantly-grouchly-peer.toml` and
   `examples/quantly-research-policy.toml` as the reviewed coordination policy.
   Neither file accepts credentials.
6. Verify peers with `ferry channel agents --workspace /path/to/quantly` and
   transport with `ferry channel syncthing status --workspace /path/to/quantly`.

## Rust consumer contract

The Quantly monorepo can depend on `ferryman-channel` and use
`quantly::QuantlyEnvelope` to validate a domain event before calling Ferryman's
normal channel delivery path. On receipt, call
`QuantlyEnvelope::from_message` before any replay or paper-ledger action.

```rust
use ferryman_channel::quantly::{QuantlyEnvelope, QuantlyMessageKind};
use serde_json::json;

let event = QuantlyEnvelope::new(
    QuantlyMessageKind::ResearchRequest,
    "experiment-20260924-001",
    json!({
        "action": "run_walk_forward_challenge",
        "experiment_id": "experiment-20260924-001",
        "seed": 20260924,
        "paper_only": true
    }),
);
let message = event.into_message(
    "quantly",
    "quantly",
    "beastly",
    true,
    Some("experiment-20260924-001".into()),
)?;
```

Use a stable experiment/run ID as the idempotency key. Claim and acknowledge
messages through the normal Ferryman consumer flow before running a simulation;
this prevents duplicate work when the same envelope is observed more than once.
Channel payloads should contain concise experiment metadata, hashes, and local
references, not datasets, private corpora, or secrets.
