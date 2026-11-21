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
