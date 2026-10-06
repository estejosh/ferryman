# Rescue: break-glass access to your own machine

When the channel itself is what broke, there is nothing left to fix it with. `ferry rescue`
is the way back in: a live terminal on one of your own machines, from anywhere, for as long
as a person on that machine keeps it open.

It does not exist until it is needed. Nothing is installed, nothing runs and nothing
listens until someone runs `ferry rescue open`.

## Once, on each machine you might connect from

```
ferry rescue key
```

This makes the machine's rescue key and shares the public half with your other machines
through the fleet folder Syncthing already syncs. Each machine saves its own copy of those
keys (the worker refreshes it every time it starts), so a rescue still works on the day
Syncthing does not. Do this ahead of time, while sync works: `ferry rescue status` on the
other machine shows who it would let in.

## When a machine needs help

On the machine that needs help (a person must be there):

```
ferry rescue open
```

It prints a join line. Read or text it to the person helping you. On their machine,
anywhere in the world:

```
ferry rescue join "<the join line>"
```

If sync happens to be working, `ferry rescue join grouchly` finds the line by itself. Rescue
never depends on it.

The person on the machine being helped sees the join request and says yes or no. Type
`exit` there to end it. It also ends by itself after 30 minutes (`--minutes` to change).

`ferry rescue status` shows which machines have a key and which have a session open.

## Why it is safe

- **A person on both sides.** Every join is approved on the machine being rescued.
- **Only your machines may ask.** Only keys published by your own machines with
  `ferry rescue key` are accepted; anyone else is refused before asking.
- **No open ports.** Both sides connect outward through upterm's relay
  (`uptermd.upterm.dev`), so it works behind any router or hotel wifi and exposes nothing.
  The relay carries an encrypted SSH session; it cannot read it.
- **Temporary.** The session, and the join line, disappear when it closes or times out.
- **Fetched only when needed.** `ferry rescue open` downloads upterm the first time it is
  used and checks it against upterm's published checksums before running it.

## What it is not

Not the normal way machines talk. Orders, results, messages and keys go through the
channel. Rescue is for the day the channel cannot carry them.
