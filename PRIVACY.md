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

## What you can do about it

- **Turn it off.** Set `checkin = "off"` in `.ferryman/agent.toml`, or leave the
  check-in URL unset. The software keeps working. Note that free *production* use is
  conditioned on registration under Section 3 of the license — turning it off does not
  change what you owe, it only changes whether the Licensor can see it. Non-production
  use has no registration requirement at all.
- **See it before it goes.** `ferry license checkin --dry-run` prints the exact payload
  and sends nothing.
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
