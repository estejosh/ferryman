# The GPU lane

Ferryman decides who uses the GPU. Every use goes through one line, the `gpu` lane of the
machine scheduler ([ADR 0033](adr/0033-ferryman-schedules-the-machine.md)). Nothing is
killed to make room, servers are started and stopped on demand, and the line is always
visible.

`ferry gpu ...` is a way to type that lane, not a second scheduler.

## What it guarantees

- **One line.** Requests are ordered by priority, then by who asked first. Grants are
  given one at a time up to the lane's width (1 on a single card) and its memory budget.
- **Aging.** A waiting request gains one point of priority per `age_secs` (60 by default),
  so one that keeps losing eventually leads the line.
- **The head blocks.** If the first request in line does not fit the memory budget yet,
  nothing behind it is granted. A large request is never skipped forever by a stream of
  small ones. Some memory idles while it waits.
- **Nothing is killed.** A grant ends when its holder gives it back or its process is
  gone. A lease that lapsed while its process is still running keeps the grant, so the
  card is never given to another job underneath a running one.
- **Servers on demand.** A tenant server is started with the first grant that needs it and
  stopped after the lane has had no work for it for `idle_secs`. It is never left resident
  without a job.
- **Orders.** An order whose needs carry a `gpu_mem_gb` hint waits in the line and holds
  its grant while the worker runs it. Order priority maps to 0 (low), 10 (normal), 20 (high).

## Config

In `<root>/ferry.toml`. Every value shown is the default unless noted.

```toml
[gpu]
width = 1          # grants at once
vram_mb = 0        # memory Ferryman may hand out at once; 0 means only the width limits
lease_secs = 120   # a grant not renewed for this long is taken back if nothing holds it
idle_secs = 300    # a tenant server with no work this long is stopped
age_secs = 60      # seconds waited per point of priority gained; 0 turns aging off
keep = ["shell"]   # process names (a part is enough) never reported as unmanaged

[gpu.tenants.model-server]
start = "start-model-server"   # launches the server and returns; safe to run when it is up
stop = "stop-model-server"     # stops it
process = "model-server"       # part of its process name, so its memory is not reported
```

A `[gpu]` table that cannot be read is an error, not a guess. `width = 0` is refused.

## Commands

- `ferry gpu run --tenant <name> [--vram <mb>] [--priority <n>] [--wait <secs>] -- <command>`
  Waits in the line, runs the command with the grant, gives it back when it ends, however it
  ends. Exits with the command's exit code. The command sees `FERRYMAN_GPU_GRANT` and
  `FERRYMAN_GPU_VRAM_MB`. If `<name>` is a configured tenant, its server is started with
  the grant.
- `ferry gpu acquire --tenant <name> [--vram <mb>] [--priority <n>] [--pid <pid>] [--wait <secs>]`
  and `ferry gpu release <id>`
  For a script that starts its own server. `acquire` waits for the card and prints the
  grant id; `release` gives it back. The grant is held while `--pid` (default: the process
  that ran `acquire`) is running, and is taken back if that process ends without releasing.
- `ferry gpu status [--json]`
  The line: holders, then waiting requests in the order they will be served, each with
  its position, wait time, priority and the priority it counts with now. Also the tenant
  servers that are up, and processes holding video memory with no grant behind them
  (from `nvidia-smi` where there is one).
- `ferry gpu bump <id> [--priority <n>]`
  The master's lever: put a waiting request first, or give it a priority. Nothing else
  jumps the line.

## Where state lives

The lane is a small file in machine state (`<machine state>/gpu/lane.json`) behind a file
lock, so the worker and any number of `ferry gpu` commands see one line. There is no
daemon. Whoever touches the lane turns it; the all-projects worker also turns it once per
pass, which is what stops an idle tenant when nobody is asking.

## Not in this slice

The dashboard panel, `ferry doctor` rows, stopping unmanaged holders after a grace period
(`enforce`), and a bridge to an external queue come as separate orders. The engine is
[`sched.rs`](../crates/ferryman-ops/src/sched.rs); the card-shaped part is
[`gpu.rs`](../crates/ferryman-ops/src/gpu.rs).
