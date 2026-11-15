# GPU lane: every GPU job goes through Ferryman's scheduler

Status: design note and first slice (order `gpu-scheduler-1115`, Josh, 2026-11-15).

## Problem

The card was handed out by a Python arbiter outside Ferryman. Servers (an LLM server, an
image server, a TTS) started on the GPU by themselves, and held VRAM with no job. Ferryman
orders that need the GPU had no way to ask for it.

## Shape

- **Lane `gpu`.** The worker's scheduler gives a GPU job the lane only when it is granted.
  Width comes from config and is 1 on a single-card machine. A job declares `vram_mb` and an
  expected duration.
- **Grants are ordered by score** (focus, unblocks, age, priority). The caller computes the
  score; the lane picks the highest score that fits the free width and VRAM budget, with the
  earlier queue time as the tie-break.
- **Leases.** A grant is renewed by the running job. A lease that is not renewed in time is
  taken back.
- **Tenants.** Long-lived servers (LLM, image) are tenants. A tenant starts when a grant needs
  it and stops after the lane has been idle for `idle_secs`. It is never resident without a job.
- **Unmanaged VRAM.** A process holding VRAM with no grant is reported with its size. Processes
  the master marks `keep` (desktop, games) are never touched.

## Slices

1. **Done here:** `ferryman-ops::gpu`, a pure lane (queue, grants, leases, tenant idle stop,
   unmanaged-holder report). It takes the clock as seconds, so it has no I/O and its tests are
   deterministic.
2. **Next:** `ferry gpu run|status|acquire|release` in the CLI, the config (`[gpu]` width,
   VRAM budget, tenants with start and stop commands), and the dashboard and `ferry doctor`
   rows. Each new command gets a doc page and a test.
3. **Then:** the existing arbiter becomes an adapter: its tenant-keyed callers ask Ferryman
   for the grant, so old callers keep working.
4. **Optional:** `[gpu] enforce = true` stops an unmanaged holder after a grace period.

## Product rule

Nothing fleet-specific in code. Tenants, their commands and the VRAM budget come from config.
