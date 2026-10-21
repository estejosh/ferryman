# ADR 0004: HTTP worker protocol

Workers poll and lease work over JSON HTTP. Polling is easy to self-host and traverse restrictive networks; at-least-once semantics are made explicit by a lease ID and idempotent completion. Streaming transport can be an adapter later.
