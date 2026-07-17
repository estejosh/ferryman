# ADR 0002: Persisted job state machine

Store each transition and append an event in the same database transaction. In-memory queues are not authoritative. This makes restart recovery, retries, auditability, and SSE replay possible in local mode.
