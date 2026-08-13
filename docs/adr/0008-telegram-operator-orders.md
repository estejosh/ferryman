# ADR 0008: Telegram as a first-class order surface

Today the Telegram integration is a one-way approval gate. In server mode
`crates/ferryman-server/src/telegram.rs` only approves or denies jobs parked
as `pending_approval`; in channel mode the headless fleet routes free-text
Telegram messages into a file inbox that is not the signed order system. A
human operator can therefore react to work but never originate it: the
orchestrator issues signed orders (`ferry channel order`, or the jobs API),
but the operator's phone cannot.

Make Telegram a first-class order surface. The authorized operator (the
already-configured `approver_id`) issues a structured order from Telegram that
is signed and published through the same channel/communications path the
orchestrator uses, inheriting the claim → execute → submit → review lifecycle
and returning an acknowledgement receipt (order id, claimant, result) on
Telegram.

One contract, two modes. Channel mode (no server): the fleet bot translates a
structured `/order` command into a `ferry channel order` invocation using the
machine's existing `.ferryman` identity — the order is signed exactly as an
orchestrator's would be, and the bot holds no new secret because it shells out
to the local CLI that already owns the key. Server mode: `telegram.rs` gains an
order command path beside `/approve` and `/deny`, creating the job through the
authority the server already holds, keeping the bot token the only new secret
and failing closed (no order path) when the operator is not configured.

Both reuse one authorization model — `from.id == approver_id` for text and
buttons alike — and structured commands only, because free text must never be
silently promoted to a signed order. Orders are idempotent and auditable like
every other envelope.
