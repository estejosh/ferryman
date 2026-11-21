# ADR 0033: Ferryman schedules the machine

Status: proposed, 2026-11-15. Design note only. Builds on 0028 (heavy orders), 0031 (lanes), 0032 (email lane).
Order: `fm-scheduler-1115`. GPU slice: `gpu-scheduler-1115b` must fit this design.

## Context

Scheduling on a machine is split across tools that sit outside Ferryman:

- a GPU arbiter that hands out the card;
- resource rules for memory and CPU kept in a separate helper;
- per-engine weekly caps;
- each agent's own retry loop.

Ferryman today decides only which order a worker claims. It does not decide when heavy work
may start, or who gets the machine. The `max_parallel` setting in `agent.toml` (ops/src/agent.rs)
and the policy `width` (channel/src/policy.rs) cap concurrency, but nothing looks at the machine's
actual load, and nothing covers work that is not an order.

Outside helpers cannot be the scheduler. Ferryman ships to other engineers whose machines have
none of them, so the scheduler must work with only Ferryman installed.

## Decision

1. **One scheduler per machine, in the worker, for every lane.** Lanes: `review`, `subscription`,
   `api`, `local-text`, `gpu`, `cpu-heavy` (the directive's list; the names are config, not code).
   Each lane has a width. Widths come from config. Defaults are derived from the machine: CPU
   count, total RAM, GPU count and VRAM. `max_parallel` and policy `width` become inputs to the
   lane width (the smaller wins), not a second cap.

2. **Admission reads the OS, with no helper required.** Before a heavy grant starts, the worker
   samples free RAM, commit, CPU load, process start rate and GPU/VRAM, and answers
   `go`, `wait` or `no`:

   | Metric | Linux | Windows | macOS |
   |---|---|---|---|
   | RAM / commit | `/proc/meminfo` | performance counters | `vm_stat` (stub ok) |
   | CPU load | `/proc/loadavg` | performance counters | `sysctl` (stub ok) |
   | GPU / VRAM | `nvidia-smi` | `nvidia-smi` | none (answer `wait` for GPU lane) |

   Thresholds are config. A missing metric makes the admission answer `wait` for heavy lanes,
   never `go`. Outside helpers (snifrig, a GPU arbiter) may register extra rules as plug-ins.
   They are optional and never a second scheduler. `snifrig_heavy` in ADR 0028 becomes one such
   plug-in; it is no longer the design.

3. **Anything that needs the machine asks Ferryman.**
   - `ferry run --lane <lane> [--vram MB] [--mem MB] -- <command>` queues any command as if it
     were an order. Renders, training runs and batch jobs use it too.
   - Long-lived servers are *tenants*: Ferryman starts them when a grant needs them and stops
     them when idle past a timeout.
   - `ferry sched status` prints each lane's grants, queue and current pressure.
   - **Outside scripts ask first.** A script that starts its own server or job runs it through
     `ferry run --lane gpu --vram MB -- <cmd>`. Where the script must keep control, the sugar
     `ferry gpu acquire --vram MB` blocks until granted and `ferry gpu release` hands the grant
     back. Both are thin wrappers over the same lane queue, not a second path.
   - **No-kill rule.** A running job is never killed or preempted by the scheduler. A tenant
     (long-lived server) is stopped only when it is idle. The card is never granted to a second
     job while the first job's process is alive, whatever its grant says: release is judged by
     the process, not by the paperwork.

4. **One priority order.** The dispatcher score orders the queue on every machine: focus,
   unblocks, review first, age, sent-back penalty, pressure. The score is settled here, so the
   GPU lane builds on it unchanged:
   - **Aging.** An item's score rises with its wait time, without a ceiling below the top of the
     queue, so a waiting item always reaches the front eventually. No item starves, including a
     big-VRAM job behind many small ones. While such a job is first in line, a smaller job in the
     same lane starts ahead of it only if it fits in what is free now and does not delay the
     head job past the aging bound; otherwise the lane holds the resources for the head job.
   - **Bump.** Only the master may reorder, with `ferry sched bump <id>` (master key required;
     any other signer is refused). A bump moves one item to the front of its lane and is recorded
     as a signed entry in the channel (who, item, time, reason). Nothing else jumps the queue.
   - Open question: `focus_suggest.rs` has a `score`, but it ranks suggestions, not the queue.
     The shared function is written new or pulled out of there in slice 1; the rules above hold
     either way.

5. **Generic by construction.** No machine, project, tool or provider name in code, defaults or
   tests. Every new command gets a doc page and tests on Linux and Windows. macOS tests may be
   stubbed.

## Slices (proposed; split into orders after review)

1. Lane model and config: lane names, widths, defaults from machine facts. Pure functions, tests.
2. Admission: metric sampling per OS behind a trait; `go`/`wait`/`no` decision; fake metrics in tests.
3. Queue and grants inside the worker: a `ferry run` command enters a lane queue; the score orders it;
   a lane never runs more than its width at once.
4. Tenants: start on grant, stop when idle.
5. `ferry sched status` and docs.

## Done when (from the order)

On a test machine with fake metrics, the scheduler:

- admits heavy grants only while the thresholds hold;
- queues a `ferry run` command behind a higher-scoring order in the same lane;
- stops an idle tenant;
- never starts more than a lane's width at once;
- runs with no snifrig or arbiter installed.

`ferry sched status` prints the lanes, and the docs explain it for a new user.

## Consequences

- Heavy work waits instead of crashing a machine. Costs: more queue time on busy machines.
- The OS sampling is the only part that differs per platform, so it sits behind one trait.
- ADR 0028's `snifrig_heavy` path stays as-is until slice 2 replaces it with a plug-in.

## Alternatives considered

- *Keep the external arbiter and snifrig rules.* Needs helpers other engineers do not have. Rejected.
- *A separate scheduler daemon.* A second scheduler, the thing this ADR removes. Rejected.
- *Cap by per-engine weekly counts only.* Says nothing about RAM, VRAM or CPU pressure. Rejected.
