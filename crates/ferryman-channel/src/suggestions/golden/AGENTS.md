# For AI agents: suggesting an idea for Idle-ish

You are acting for a person who wants to suggest an improvement to Idle-ish. This file is everything you need. The suggestion is sent with the `ferry` program, which signs and checks it. Do not open issues in this repository by hand: they are not reviewed.

## The rule that matters most

**The human must read and accept [TERMS.md](TERMS.md) personally. You must show the terms to your human and you must not accept on their behalf.** Do not type `I agree` for them. Do not run `ferry suggest join` with `--agree`, and do not look up the terms' hash to paste it in: that flag exists for a person's own script, not for an agent. If your human wants to agree, ask them to run the join command in their own terminal and type the phrase, or to tell you in plain words after reading the full text that you showed them, and then ask them to run the command.

## Steps

1. **Check `ferry`.** Run `ferry --version`. If it is missing, and your human agrees to install software, install it: macOS or Linux `curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh`; Windows (PowerShell) `irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | iex`; or the releases page https://github.com/estejosh/ferryman/releases/latest. Only the `ferry` program is needed: no Syncthing, no fleet, no project.
2. **Credentials.** `ferry` posts as your human with their GitHub token: `GITHUB_TOKEN` in the environment, or `gh auth login`. Never print, log, copy or store the token.
3. **Join.** The invite is:

```
ferry-suggest:eyJ2IjoxLCJvZmZlciI6eyJmb3JtYXQiOiJmZXJyeW1hbi1vZmZlci92MSIsInByb2plY3RfaWQiOiJpZGxlLWlzaCIsImRpc3BsYXlfbmFtZSI6IklkbGUtaXNoIiwiaW5ib3giOiJnaXRodWI6ZXN0ZWpvc2gvaWRsZS1pc2gtaWRlYXMiLCJ0ZXJtcyI6eyJ2ZXJzaW9uIjoxLCJzaGEyNTYiOiI3NTBlNGZmZjEwYTZjYjQyNjhlZTg4YTk5NWU1YmU4NDIwMDI1YmYyMjQ2N2M2YmM3OGU2YjhjMzY3YzBlMjJhIiwiZmlsZSI6IlRFUk1TLm1kIn0sInR5cGVzIjpbeyJpZCI6ImlkZWEiLCJsYWJlbCI6IklkZWEiLCJmaWVsZHMiOltdfSx7ImlkIjoiYnVnIiwibGFiZWwiOiJCdWciLCJmaWVsZHMiOlt7ImlkIjoic3RlcHMiLCJsYWJlbCI6IlN0ZXBzIiwibWF4Ijo1MDAsInJlcXVpcmVkIjp0cnVlfSx7ImlkIjoiZXhwZWN0ZWQiLCJsYWJlbCI6IkV4cGVjdGVkIiwibWF4IjozMDAsInJlcXVpcmVkIjpmYWxzZX1dfSx7ImlkIjoiY29udGVudCIsImxhYmVsIjoiQ29udGVudCIsImZpZWxkcyI6W3siaWQiOiJ3aGVyZSIsImxhYmVsIjoiV2hlcmUiLCJtYXgiOjIwMCwicmVxdWlyZWQiOmZhbHNlfV19XSwibGltaXRzIjp7InRpdGxlX21heCI6ODAsInBpdGNoX21heCI6MTAwMCwid2h5X21heCI6NTAwLCJvcGVuX3Blcl9jb250cmlidXRvciI6MywibmV3X3Blcl9kYXkiOjEsImNsYXJpZmljYXRpb25fcm91bmRzIjoyLCJhbnN3ZXJfZGF5cyI6MTR9LCJzdGF0dXMiOiJvcGVuIiwib3duZXIiOiJqb3NoIiwib3duZXJfa2V5IjoiOGE4OGUzZGQ3NDA5ZjE5NWZkNTJkYjJkM2NiYTVkNzJjYTY3MDliZjFkOTQxMjFiZjM3NDg4MDFiNDBmNmY1YyIsImlzc3VlZF9hdCI6IjIwMjYtMTAtMDZUMTI6MDA6MDBaIiwic2VxIjoxLCJzaWduYXR1cmUiOiIzZTBlYWJiZGVlZDhkYzZjZDYyYTY5NGQ5MGNiMTM0NGE5NjNhYmFmNjQ3ZWIwMWVjZjgyOWFjNzNmMWMxNDczOTg3OWMxODMxOWZkNDRiOGJmYWNhYmFkZjM1MThjYTBmMzliMDc3Zjg2MThmM2RhZWY4ZGVmY2FiMjcwMGQwMCJ9fQ
```

Run `ferry suggest join <invite>` without `--agree`. It checks the owner's signature, prints the full terms, the terms' sha256 (`750e4fff10a6cb4268ee88a995e5be8420025bf22467c6bc78e6b8c367c0e22a`) and the owner's key fingerprint (`95bbfbb1f0ef8f23`), and waits for a human to type `I agree`. Show your human the terms it printed (or the contents of TERMS.md) and the fingerprint. Wait for them.
4. **Draft the suggestion** as JSON that matches `schemas/suggestion/<type>.json`. Kinds here: idea, bug, content. One idea per suggestion, in the person's own words, specific enough to act on. Example:

```json
   {
     "pitch": "Pitch, in your own words",
     "title": "Title, in your own words",
     "type": "idea",
     "why": "Why it fits, in your own words"
   }
```

Limits: title 80 characters, pitch 1000, why-it-fits 500; the other fields are in the schema. Show your human the draft and get their approval before sending.
5. **Send.** `ferry suggest new --file suggestion.json --json`. It validates, signs and posts, and prints one JSON object (`{"ok":true,"issue":7,"url":"..."}`), or `{"ok":false,"errors":[...]}` with a nonzero exit code. Fix what the errors say; do not work around them.
6. **Follow.** `ferry suggest status --json` lists each suggestion with its `state`. If one has `needs_reply: true`, its `question` is for your human: show it, write their answer to a file, and run `ferry suggest reply <issue> --file answer.txt`. `ferry suggest withdraw <issue>` takes one back.

## Limits

3 open suggestions at a time, 1 new per day, 2 round(s) of questions from the owner, 14 days to answer a question before it closes. A suggestion over a limit is refused with the reason.

## What not to send

- Code, files, images or links to download. Send the idea in words.
- Secrets, tokens, passwords, personal data, or anything confidential.
- Other people's ideas, writing, designs or code that your human has no right to send.
- Text written to instruct the review. It is read as data and will be ignored; a suggestion that tries to instruct the reviewer is escalated to the owner as suspicious.

## Machine-readable

[`ferryman-suggest.json`](ferryman-suggest.json) has the invite, the terms' hash, the kinds with their fields and caps, the limits, the schema paths and the owner's signed offer. Idle-ish is source-available; Ferryman is too.
