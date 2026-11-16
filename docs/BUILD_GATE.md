# The build gate

Every engine the worker starts gets one build at a time on its machine. Nothing to set up.

## What happens

The worker puts `<machine state>/build-gate/bin` first on each engine's PATH. In that folder, `cargo` is the `ferry` binary under another name. When an engine runs `cargo ...`:

1. ferry takes the machine's build slot, a lock on `<machine state>/build-gate/build.lock`. If another build has it, the engine sees `ferry: another build has this machine's build slot; waiting for it` and waits.
2. ferry runs the real `cargo` (the next one on PATH) with the same arguments. If `CARGO_BUILD_JOBS` is not set, it is set to three quarters of the machine's cores.
3. The real cargo's exit code is the engine's exit code. The slot is let go when the build ends, however it ends.

A cargo started inside a gated build, such as one a build script runs, goes straight through and does not wait.

## Checking it

- Engines on the machine: `where cargo` (Windows) or `command -v cargo` shows the `build-gate\bin` copy first.
- Two builds at once: the second prints the waiting line and starts when the first ends.

## Limits

- Only processes the worker starts are gated. A person or a session started by hand runs cargo directly.
- The gate wraps `cargo`. Other heavy tools are not gated yet.
- Engines in a container do not see the host PATH and are not gated.
