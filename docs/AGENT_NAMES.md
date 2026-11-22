# Agent names, aliases and charters

Source of truth: `fleet/names.toml` in the ferry root (human copy `AGENTS.md`). A missing file
changes nothing.

- **System name** `role.place`, the role from the file's role list (`worker.beastly`).
- **Alias**: one word whose story is the job (Ichabod). Never reused, retired ones included.
  People read `Alias (system.name)`; JSON output keeps the identity.
- **Charter**: what the agent does and `never` does. `ferry agent charter [--as <identity>]`
  prints it; the worker puts it at the top of every prompt with the refusal rule.
- **Refusal** is deterministic, no model: a worker will not claim an order titled `ask:` or
  `vps:`, or of kind `plan`. `ferry agent refuse <order> --why "..."` (the worker does this
  itself) records the refusal on the order and issues `refused: <order id>` (kind chore) to the
  `ferryman` project for Charon. The order stays in the queue.
- **Retirement**: `[retired]` identities take no orders (`claim_order` fails with
  "retired on <date> (AGENTS.md)"), are hidden from `ferry access show` and the MCP `to` check
  (`--all` shows them, greyed), and `read_agent_roster_visible` omits them. Their keys stay on
  `read_agent_roster`, so old signatures still verify. Nothing is deleted.
- **Enrolment**: `ferry agent enroll --identity --system --alias --charter [--level --limits]`
  checks the role list and alias uniqueness, then leaves the agent unable to claim until
  `ferry agent approve <identity>` (Josh) appends it to `names.toml`.

## Status

Done and tested: the names file loader; retirement (claim refusal with the date, roster
`retired` filter, `access show --all`, the MCP alive list and `to` check); names in
`ferry access show` and `ferry work list`; the charter block at the top of
every worker prompt; `ferry agent charter`; the deterministic worker refusal (`ask:`, `vps:`,
kind `plan`) before any claim, with `refused: <id>` issued to the `ferryman` project; enrolment
with alias and role checks; and `ferry agent approve`.

Not yet wired:
- Names in the Telegram notices, the dashboard (`ferry dashboard`, ferryman-server), the MCP
  output (the join list still shows identities) and `ferry engines`.
- Approving an enrolment from Telegram (Approve/Deny buttons) or the dashboard. Today only
  `ferry agent approve <identity>` does it, from the command line.
- A test of the `refused: <id>` order end to end: it needs a ferry root with a `ferryman`
  project, so it is checked by hand, not by `cargo test`.
