# Self-improve: the review queue, the second key, and the notice

Three rules for the self-improve loop, from Josh's order of 21 Nov 2026 (items 32 and 33). The
review queue reached 143 because the loop kept adding work nobody had read, and improvements
needed his key with no way to see them but the command line.

## 1. No new suggestions while the queue is long

`ferry improve plan` and `ferry improve run` count the project's hand-ins that are waiting for
review (results in the awaiting-review state). Above the limit, the week's plan issues nothing,
and `improve/<week>/report.md` records why:

    held: 7 hand-ins waiting for review (the limit is 5)

Once the queue is back at or under the limit, the next run plans normally. Verification orders
for audit claims still go out while held; only new improvements wait.

The limit is `improve.max_waiting` in the project's signed policy. It defaults to 5 and is left
out of the signed JSON when unset, so a policy signed before this existed still verifies.

## 2. Docs, tests and dependency bumps: the head may give the second key

An improvement needs two keys before it is approved for live: the review engine's, and the
master's. The head (MO) may give the master's key alone, under a delegation, when the approved
revision changes only:

- docs: `*.md` and anything under `docs/`;
- tests: anything under `tests/`, or a file whose name contains `_test`;
- lock files: `Cargo.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`;
- dependency versions: `Cargo.toml` and `package.json`, where every changed line is a version
  (the line says `version`, or is a bare `name = "1.2.3"` / `"name": "^1.2.3"` pair).

Anything else still needs Josh. In particular a source file is refused for the head, and so is a
`#[cfg(test)]` block inside one: the path is `src/`, so it is not a test by path. A diff whose
changed-file list is empty or was cut short (over 200 paths) is refused too.

The delegation is the scope `improve:minor`. Josh grants it once from the dashboard (Settings >
Delegations > "the head may approve docs, tests and dependency bumps"). A delegate that also holds
the full `review` scope may approve anything, as before; `improve:minor` alone is limited to the
rules above.

Approve as the head from the command line:

    ferry improve approve <order-id> --project <project> --as <head>

Without `--as`, the master signs, as before. A refused approval says why: `src/x.rs is not docs,
tests, a lock file or a dependency version - only the master approves that`.

## 3. Real code changes reach Josh in Telegram, with buttons

When an improvement needs Josh's key, the Telegram bridge posts one notice to the operator chat:

- the order and revision, the worker, and the title;
- **Change:** what the worker's result says it changed, in its own words (500 characters);
- the diff size and the evidence;
- the review engine's verdict, and the adversary's finding when there is one;
- **Approve** and **Send back** buttons, the same tap flow as the steward's requests. Approve
  records his key (the master's delegate signs it). Send back asks for one line of reason.

When the gate moves on, the notice edits itself to the outcome, with its buttons removed:

- `approved, ready to merge`;
- `sent back: <reason>`;
- `no longer waiting` (for example, the result was refuted or superseded).

Six hours after that edit, the bridge deletes the message.

## Ceilings

- The path check is by path and by changed line. It does not parse Rust or manifests: a
  `#[cfg(test)]` block inside a source file is refused, and a dependency-version line must say
  `version` or be a bare semver value with a dot.
- A head's approval that fails the diff check is still read as a review by the task reader, but
  it never counts: `gate::master_key` refuses it, so the improvement is not approved for live.
- The hold writes one step to the week's report each hourly run it stays held.
- The end-to-end path (a recorded result with evidence, then a head's approval) is not covered by
  a test; the path and version rules are.

Code: `crates/ferryman-channel/src/gate.rs` (`is_minor_path`, `minor_check`, `order_is_gated`),
`crates/ferryman-channel/src/lib.rs` (`review_authority`), `crates/ferryman-channel/src/policy.rs`
(`max_waiting`, `waiting_cap`), `crates/ferryman-ops/src/improve.rs` (`plan`, `held_for_review`),
`crates/ferryman-cli/src/tgv2.rs` (the notice, `settle_notices`).
