# Hand this to an agent

Copy the block below into any coding agent — Claude Code, Codex, whatever you run — and
it will install Ferryman and put this project on it, without asking you anything.

---

```
Install Ferryman on this project and join it to my fleet.

1. Install it:
     npm install -g ferryman-cli
   If npm is unavailable:
     curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh
   Confirm with: ferry --version

2. From the project directory, run:
     ferry enable --email <MY_EMAIL> --json

   Replace <MY_EMAIL> with the address I gave you. Do not invent one; if you do not
   have one, stop and ask me for it. It is required — free production use is
   conditioned on registering a contact address (LICENSE section 3), and nothing about
   my code or my work is ever transmitted (PRIVACY.md).

   This one command does everything: writes the config, creates the channel, makes a
   signing key, registers this machine, and registers the channel folder with the local
   Syncthing, sharing it with the devices Syncthing already trusts. It never prompts and
   it is safe to run twice — if you are unsure whether you already ran it, run it again
   and read "already_configured" in the JSON.

3. Read the JSON it printed and tell me:
     - syncthing.available — if false, tell me the "note" field verbatim; Syncthing is
       probably not installed or not running, and I need to fix that, not you.
     - syncthing.device_id — I need this to pair another machine.
     - license.over_limit — if true, tell me what it says under "exceeded".

4. Start the worker:
     ferry agent run
   It runs until stopped. If a task appears it will run my agent CLI on it. If the
   configured command is missing, edit .ferryman/agent.toml and point "command" at an
   agent CLI that exists on this machine, then start it again.

5. Confirm it is healthy and stop:
     ferry channel status
     ferry channel tasks

Rules:
- Do not commit anything to my repository. Ferryman writes only inside .ferryman/.
- Do not change my Syncthing devices. Sharing an existing folder is expected; adding or
  removing a paired device is not.
- Do not disable the licence check, edit LICENSE, or work around a checksum failure.
- If any step fails, stop and show me the exact error. Do not improvise a workaround.
```

---

## What to expect

On the first machine, `syncthing.shared_with` will usually be empty — nothing else is
paired with it yet. That is fine and not an error.

On the second machine, run the same block. Because both machines already trust each
other in Syncthing, `enable` shares the folder automatically and the two channels merge.
Every file in the channel has exactly one writer, so there is nothing to reconcile.

## The one thing an agent cannot do

**Pairing two machines in Syncthing for the first time.** That means exchanging device
IDs and accepting on both sides, and it is a trust decision — approving a machine that
may then receive your data. Ferryman will use pairings you already have and will never
create one. If your machines are not yet paired, do that once yourself, then hand the
block above to an agent on each of them.
