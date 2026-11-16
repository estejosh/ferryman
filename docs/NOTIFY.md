# Notices: telling the operator something

Tools do not message the operator themselves. They hand Ferryman a notice, and Ferryman decides what reaches the operator's chat.

```
ferry notify send --source gpu-queue --subject card --state stuck --level act \
  --text "2 jobs queued but the card has been idle 20 min"
ferry notify status
```

- `--source` names the tool. `--subject` names what the notice is about and stays the same every time. `--state` says where it stands now.
- `--level info` goes into the day's digest only. `act` and `urgent` go to the operator's chat.
- The same source, subject and state is not sent again for 24 hours. A new state for the same subject updates the message already sent instead of adding a new one.
- A source the operator mutes goes to the digest whatever its level, except `urgent`.

The all-projects worker delivers notices about every 30 seconds. Tools hand them in through `<machine state>/notices/inbox`, so a tool that cannot run a command can drop a JSON file there with the same fields: `source`, `subject`, `state`, `level`, `text` and `at`.

The chat is the bot named by `TELEGRAM_BOT_TOKEN`, and the chat named by `TELEGRAM_CHAT_ID` (otherwise the first id in `TELEGRAM_APPROVERS`). Both are read from the worker's environment or from the root's `secrets/.env`. If neither is set up, everything goes to the digest.

Rules live in the root's `ferry.toml`:

```toml
[notices]
resend_after_hours = 24     # the same news again only after this long
update_within_hours = 24    # a new state edits the earlier message within this long
muted = ["renders"]         # digest only, except urgent
```

`ferry notify status` shows what each source handed in and what became of it (sent, updated, digest or dropped as a repeat), plus today's digest.

Not built yet: questions with buttons through this path, and `ferry doctor` flagging scripts that still message the operator directly.
