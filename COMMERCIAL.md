# Commercial Licensing

Ferryman is source-available under the [Ferryman Source-Available License](LICENSE).
This page explains when it's free, when it isn't, and how to pay.

## Free

- **Any non-production use** — evaluation, development, testing, personal projects,
  home labs. No limits, no seat count, no time limit.
- **Production use up to 2 Seats on 4 Devices.**

A **Seat** is a distinct human who operates, administers, deploys, or accesses
Ferryman or its outputs. Your agents and workers are *not* Seats — they roll up to
the human they act for. A fleet of twenty agents run by one person is one Seat.

A **Device** is a machine that runs Ferryman. A machine that only holds a synced
channel directory, without running Ferryman, doesn't count.

That means a solo operator, or two people running a handful of machines, never pays.

## Paid

Production use beyond 2 Seats or 4 Devices needs a per-Seat commercial license.
Commercial licenses have **no Device limit** — run Ferryman on as many machines as
you like.

| Total production Seats | Per billable Seat / year | ≈ per month |
|---|---|---|
| 1 – 2 | **Free** | — |
| 3 – 25 | **$60** | $5 |
| 26 – 100 | **$42** | $3.50 |
| 101+ | **$30** | $2.50 |

*Billable Seats* = your total production Seats minus the 2 free ones. Your rate is
set by the band your **total** Seat count falls in.

**Example.** A team of 10 pays for 8 billable Seats at the 3–25 rate:
8 × $60 = **$480/year**. That is roughly what one engineer costs per hour.

- **Multi-year, or 250+ Seats:** discounted — ask.
- **Nonprofit, education, and open-source projects:** free or discounted — ask.

## Why priced this way

Deliberately cheap enough that nobody has to build a business case to adopt it, and
priced per human rather than per machine or per agent — so scaling your fleet costs
you nothing. The money exists to keep the project maintained, not to meter your
usage.

## Getting a license

Open an issue titled `Commercial license` on
[github.com/estejosh/ferryman](https://github.com/estejosh/ferryman/issues), or
contact the maintainer through the address in the repository profile. Tell us your
total production Seat count and we'll send terms.

## Attribution

Projects that deploy or redistribute Ferryman must include a root-level
`FERRYMAN.md` stating that the project uses Ferryman (License section 5). The setup
scripts write that file for you.

## Questions people actually ask

**Do my AI agents count as Seats?** No. Only humans count. One person running fifty
agents is one Seat.

**Does a machine that only syncs the folder count as a Device?** No. Only machines
that actually run Ferryman.

**Is this open source?** No, and we don't claim it is. It's source-available: you can
read, modify and redistribute it, but production use above the free tier is paid.
The license does not convert to open source on a timer.

**Can I evaluate it in production before deciding?** Evaluation is non-production use
and free. If you're genuinely trialing it, you're free. When it becomes something you
depend on with more than 2 people, it's production.
