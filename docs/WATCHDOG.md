# Watchdog

`ferry watchdog` notices when a machine stops doing its job, fixes the few things that
are safe to fix, and reports what it saw where every machine can read it.

```
ferry watchdog                 # every 5 minutes
ferry watchdog --once          # one check
ferry watchdog --dry-run       # report what it would do, do nothing
ferry watchdog --show          # every machine's latest report
```

## What it checks

Plain code gathers the facts:

- whether this machine's Syncthing is running
- whether every channel's worker reads the folder Syncthing actually syncs
- whether the Ferryman worker services are up (Linux, systemd user units)
- every engine, read the way `ferry engines` reads it (see ENGINE_SETUP.md, "An engine
  is up only when it answers"). An endpoint gets a real one-token request - not a model
  listing, which can name models an account cannot run - and must return a completion
  within 20 s. A CLI that wraps an API is proven by the worker's own tiny-prompt run
  through that CLI, not by its endpoint answering. The report says:
  - `ok (850ms)`: something returned a real completion.
  - `reachable only: ...`: an address answered but no completion was seen. This counts
    as a fault.
  - `unprobed`: it cannot be tried without spending a real request (a CLI with no
    endpoint). Not a fault.
  - `says up, but recent runs failed: ...`: the engine proved itself, yet runs on it
    timed out, stalled, returned nothing or errored since it last worked, per the
    worker's engine ledger and within 24 hours. This is reported as a fact of its own,
    because it is exactly the shape a hung model has: it answers a ping all day and
    sits on every order.

## What it may do

Exactly one of: nothing, start Syncthing, repair channels (copy then repoint, nothing
deleted), restart failed workers, or alert. Nothing else is reachable.

A local decision model picks the action - Ollama 0.35 or later, `--decide nimble` by
default, or `tev1:4b` for half the download. Every pick is checked against the facts
before it runs: a model cannot ask for a fix the facts do not call for. With no model, or
when the model does not answer, simple rules decide the same way. `--explain qwen3:30b`
adds a plain-English paragraph when something is wrong.

## Where reports go

`<fleet>/watchdog/<machine>.json`, in the fleet folder Syncthing already carries, so
every machine sees every machine's state, and `ferry watchdog --show` reads them all.