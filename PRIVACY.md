# What Ferryman sends, and what it never sends

This page is part of the terms of Section 3 of the [license](LICENSE). It is
deliberately specific, because vague privacy pages are how software loses the trust
of exactly the people Ferryman is built for.

## The short version

Free production use requires registering a contact email. Ferryman records that
address plus a count of how many people, computers and phones are in your deployment,
and reports those counts to the Licensor.

**It never sends your code, your channel, your prompts, your results, your file names,
or anything your agents produce or say.** Those never leave your machines. That is the
entire point of the product and it is not compromised for licensing.

## Exactly what is sent

One JSON object, at most once a day, to the check-in URL configured in your install:

```json
{
  "deployment_id": "a41f...",
  "emails": ["you@example.com"],
  "seats": 1,
  "computers": 2,
  "mobile_devices": 0,
  "over_limit": false,
  "version": "0.3.0",
  "sent_at": "2026-08-12T09:00:00Z"
}
```

That is the whole payload. There is no other field, and you can confirm that by
reading `crates/ferryman-channel/src/licensing.rs` — the struct that is serialised is
the struct above, and nothing constructs it from your project data.

| Field | Why it exists |
|---|---|
| `deployment_id` | A random number generated on your machine, so two check-ins can be recognised as the same fleet without identifying you further. Not derived from your hardware, hostname, or network. |
| `emails` | The addresses registered with `ferry enable`. Distinct addresses are how Seats are counted, and the only way the Licensor can contact you about licensing. |
| `seats`, `computers`, `mobile_devices` | The counts the free tier is defined in. |
| `over_limit` | Whether those counts exceed the free allowance. |
| `version` | Which Ferryman is running, so you are not told to do something that does not apply to your version. |

## What is never sent

- Your code, in whole or in part
- Anything in the channel: orders, results, reviews, messages, shared memory
- Prompts sent to your agent CLI, or anything it returns
- File names, directory names, repository names, or project names
- IP-derived location, hardware identifiers, MAC addresses, or serial numbers
- Your hostnames or your agents' names
- Any content of any kind

The list above describes the licence check-in, which is the only thing Ferryman will
ever send to the Licensor. Two other outbound paths exist, both off unless you turn
them on, and neither goes to us by default:

### Soak reports — `ferry soak`

While Ferryman is in soak testing we would very much like to know how it behaves on
your machines. `ferry soak` builds a report and **prints it**; it is sent only if you
set `FERRYMAN_SOAK_URL` *and* pass `--send`, per invocation. There is no setting that
makes it happen on its own.

The report is counts, category labels and the build string:

| Field | What it is |
|---|---|
| `format`, `version`, `platform` | The report format, the build (including its git commit), and `linux`/`macos`/`windows`. Not your hostname or OS release. |
| `sandboxed`, `preamble_bytes` | Whether a container runner is configured, and the *size* of your preamble file. Never the image name or the preamble's contents. |
| `agents` | How many agents are on the project roster. A number, not names. |
| `tasks_by_state`, `max_revision` | Counts of tasks per state, and the highest revision reached. |
| `signature_checks` | Counts per outcome: `valid`, `unsigned`, `invalid`, `unknown_signer`, `key_changed`. The most useful number in the report. |
| `ledger_intact`, `ledger_entries` | Whether the ledger verifies, and how many entries it has. |
| `run_log_categories`, `run_log_lines` | Your local run log matched against a fixed list of failure *labels* (`agent_stalled`, `governor_declined`, …) and counted. Lines that match nothing count as `other`. |

No file paths, task text, prompts, results, agent output, credentials, agent names or
project names. That is structural rather than filtered: the report type has no field
that can hold them, and log lines are reduced to a label from a fixed vocabulary
before they are counted. `ferry soak --dry-run` prints exactly what `--send` would
transmit, from the same value, so the two cannot disagree.

### Tracing — `FERRYMAN_OTLP_ENDPOINT`

If you set `FERRYMAN_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_ENDPOINT`), Ferryman
exports OpenTelemetry spans to **your** collector. This is a debugging tool you point
at your own infrastructure; it never goes to the Licensor and there is no default
endpoint. Unlike the two above, these spans **do** carry agent names, project names
and absolute workspace paths, because that is what makes a trace useful. Do not set it
unless you are happy for that data to reach wherever you are pointing it.

## What you can do about it

- **Nothing is sent automatically.** There is no timer and no background sender. The
  check-in happens only when you run `ferry license checkin` yourself, and only if a
  check-in URL is configured in your install. If no URL is set — which is the state
  every downloaded release is in — that command sends nothing and says so.
  (An earlier version of this page suggested `checkin = "off"` in
  `.ferryman/agent.toml`. No code ever read that key, so it did nothing; leaving the
  URL unset is the control that works, and it is the default.)
  Note that free *production* use is conditioned on registration under Section 3 of the
  license — not reporting does not change what you owe, it only changes whether the
  Licensor can see it. Non-production use has no registration requirement at all.
- **See it before it goes.** `ferry license checkin --dry-run` and
  `ferry soak --dry-run` each print the exact payload and send nothing. In both cases
  the dry run and the real send format the *same value*, so a payload cannot drift away
  from what the dry run shows.
- **Read the code.** It is source-available. This is a claim you can check rather than
  trust, which is the only kind of privacy claim worth making.

## Handling

The Licensor stores the email addresses and counts to administer the license and to
contact you about licensing. They are not sold, and not shared with third parties
except where required by law or to a processor acting for the Licensor. To have your
address removed, or to ask what is held, email the address in
[COMMERCIAL.md](COMMERCIAL.md); removal ends free production use under Section 3 until
you register again.

If a check-in cannot be delivered — no network, endpoint down, DNS failure — Ferryman
carries on without complaint. Licensing never blocks work.
