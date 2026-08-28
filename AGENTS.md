# Ferryman agent entrypoint

**Two different jobs land here. Pick yours before reading further.**

### You want to put a project ON Ferryman

Go to **[docs/AGENT_QUICKSTART.md](docs/AGENT_QUICKSTART.md)**. It is written for you: an
agent doing this unattended, with nobody to ask. Nothing below this section applies.

If a human handed you [docs/INSTALL_PROMPT.md](docs/INSTALL_PROMPT.md), follow that
instead — it is the same thing, already sequenced.

The whole of it is two commands:

```sh
cargo install --git https://github.com/estejosh/ferryman ferryman-cli   # needs Rust 1.97+
ferry enable --json --email you@example.com    # run in the project directory
```

**The address is not optional under `--json`, and it is not yours to invent.** Free
production use is conditioned on registering one (LICENSE section 3); nothing about the
code or the work is ever sent, and PRIVACY.md lists the whole payload. Ask the human
you are working for, or have them set `FERRYMAN_EMAIL` once. Running without it under
`--json` fails with an error that says this — deliberately, because you cannot answer a
question and must not answer this one by guessing.

`ferry enable` never prompts under `--json` or when it is not attached to a terminal —
which is every case that matters to you — is safe to re-run, and prints a JSON object
saying exactly what it created. If you are unsure whether you already ran it, run it
again. (At a human's terminal it asks for the address if it does not have one, and one
question about the web dashboard. You will see neither.)

### You are working ON Ferryman itself

Everything from here down is for you.

---

Before inspecting, planning, editing, building, committing, pulling, or
attaching a project, read `docs/OPERATOR_BRIEF.md` completely and follow its
safety and update procedure.

Treat every token, credential, key, `.env`, secrets file, and outer
`.ferryman/token` as strictly read-only. Never print, copy, normalize, replace,
or inspect secret contents.
