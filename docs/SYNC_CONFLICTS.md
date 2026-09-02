# Syncthing conflict copies, and why they are not extra agents

## The shape of the problem

Syncthing does not merge. When two machines write the same path before they have heard
from each other, one copy keeps the name and the other is renamed:

```
agents/beastly.json
agents/beastly.sync-conflict-20260818-173636-D4LGQYW.json
```

The channel is a directory of files whose *names* carry meaning — `agents/<name>.json`,
`claim.<agent>.json`, `result.<agent>.<n>.json`. A conflict copy has a name that still
matches the pattern loosely, and content that is a valid record. Read naively, one
machine's hiccup becomes a second agent, a second claim, or a second signature.

One-writer-per-path makes conflicts rare, because two machines are not supposed to write
the same file. It does not make them impossible: a restored backup, a clock skew, a
folder shared twice, or a file rewritten during a partition will all do it.

## What Ferryman does

Every reader that walks a directory filters `.sync-conflict-` before parsing:

| Reader | Where |
|---|---|
| Agent roster | `read_roster_in` — `lib.rs` |
| Ledger | `ledger.rs` |
| Secrets | `secrets.rs` |
| Interrupts | `interrupt.rs` |

Each has a test. The roster's uses a fixture literally named
`wisp.sync-conflict-20260817-144138-O4SHF2J.json`.

## The false alarm, recorded on purpose

For several days a note was carried in this project's working memory saying **"two keys
claim `beastly` in the machine-wide roster"**, and it was repeated into more than one
readiness review as an open defect.

It was never true. All three `beastly` entries — the channel roster, the machine-wide
fleet roster, and the conflict copy — carry the same key, `fdf94d69…`. The conflict copy
is byte-identical to the file it was copied from, and `read_roster_in` was already
filtering it, with a test, before the note was ever written.

Two things went wrong, and neither was in the code:

1. **A worry was recorded as a finding.** "Two files exist with this name" was written
   down as "two keys claim this name" without the keys being compared.
2. **It was re-reported without being re-checked.** Once in a list, it survived several
   reviews because each one copied the previous list.

The check costs one command:

```sh
for f in agents/beastly*.json; do
  printf '%s ' "$f"; grep -o '"public_key": "[0-9a-f]\{8\}' "$f"
done
```

## The rule

A conflict copy is a **symptom of a write race, not a second principal.** If one appears:

- Compare the keys before concluding anything. Identical content is Syncthing being
  Syncthing, and can be deleted.
- Different content is worth understanding — it means two machines genuinely wrote the
  same path, which one-writer-per-path says should not happen. Find the second writer.
- Either way the readers already ignore it, so nothing is acting on it in the meantime.

And, for anything that lands on a defect list: state the evidence next to the claim, or
it will be repeated by someone who no longer remembers there wasn't any.
