---
name: Soak report
about: You ran Ferryman for a while. Tell us what happened, even if nothing did.
title: "soak: "
labels: soak
---

<!--
Ferryman is in soak testing: it works, and it has not yet been run for weeks by
strangers, which is the only thing that finds the last set of problems. You running
it and saying what happened is the single most useful thing anyone can do for it
right now.

"Nothing broke" is a real report and we want it. It tells us which platforms and
shapes of fleet are actually holding up, and that is not knowable any other way.
-->

## The report

Run this and paste the output:

```sh
ferry soak
```

It prints counts, category labels and the build string. **No file paths, task text,
prompts, results, agent output or credentials** — it is assembled out of values whose
type cannot carry them, rather than filtered afterwards. Nothing is sent anywhere;
it prints, and you decide. If you want to check that claim rather than trust it, the
whole thing is in `crates/ferryman-ops/src/soak.rs`.

<details>
<summary>ferry soak output</summary>

```
paste here
```

</details>

## How you are running it

- **Machines in the fleet, and their platforms:** <!-- e.g. 1 Windows desktop, 1 Linux box -->
- **How long it has been running:**
- **Agent CLI:** <!-- claude, codex, aider, something of your own -->
- **Sandboxed?** <!-- `sandbox` set in agent.toml, or bare -->
- **Roughly how much work has gone through it:** <!-- a handful of tasks, hundreds -->

## What happened

<!--
Anything at all. Some prompts, in case they help:

- Did work get stuck, or silently not happen?
- Did `ferry channel tasks` ever show something other than `Valid`?
- Did the ledger ever report itself not intact?
- Did a machine stop taking work and not explain why?
- Was anything harder to set up than it should have been? Wrong error message,
  missing step in the docs, instruction that sent you the wrong way?
- Did anything surprise you — good or bad?

Blunt is better. The most useful report this project has had so far was a list of
seven things that were wrong.
-->

## If something broke

- **What you expected:**
- **What happened instead:**
- **`ferry log` around the time it happened** — this one *does* carry local paths and
  whatever your agent CLI printed, so read it before pasting and redact anything you
  would not put in public:

<details>
<summary>ferry log (optional, check it first)</summary>

```
paste here
```

</details>

---

Prefer email? `lafamiliahale@gmail.com` works just as well. Security issues should go through this repository's
**Private Vulnerability Reporting** flow rather than a public issue — see
[SECURITY.md](../../SECURITY.md).
