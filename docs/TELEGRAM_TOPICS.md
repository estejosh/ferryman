# One group, a topic per project

A Telegram forum group is the right shape for a fleet: one place on your phone, one topic
per project, each topic a conversation with the machines working on it. Ferryman builds
that group for you and keeps a register of it in a file called `.tgferryman`.

## Why the file has to exist

Telegram has no method that lists a group's topics.

`createForumTopic` returns a `message_thread_id`; after that, the id exists only where
someone wrote it down. There is no call to get it back. A bridge that forgets a thread id
cannot ask Telegram what it was - it can only create a second topic with the same name
beside the first.

So `.tgferryman` is not configuration that happens to be saved. It is the only record.
Back it up like one.

## Getting started

Make a bot with [@BotFather](https://t.me/botfather), create a group, turn on Topics in the
group's settings, and add the bot as an administrator with **Manage topics**.

Then point the bridge at a map that does not exist yet:

```
ferry channel telegram --map ~/ferryman-comms/.tgferryman
```

It writes one for you, listing every Ferryman channel it finds beside it, and stops:

```
# Which Telegram topic is which Ferryman project.
#
# Ferryman writes this file. Telegram has no way to list a group's topics, so
# the thread ids below are the only record there is - keep a copy.
#
# To add a project: add a [[topic]] with a name and a workspace, leave `thread`
# out, and restart the bridge. It creates the topic and writes the id in here.

# The forum group's chat id - negative, starts with -100. Add the bot to the
# group as an admin with "Manage topics", then put its id here.
# group = -1001234567890

[[topic]]
name = "Bullship"
workspace = "bullship-ferryman"
# thread: not created yet

[[topic]]
name = "Ferryman"
workspace = "ferryman-ferryman"
# thread: not created yet
```

Start it again and it says it does not know which group to use yet. Say anything in your
group. That message is how it learns the id - Telegram does not show chat ids anywhere in
the app, and it can see the number for itself the moment someone types. It writes the id
into the map, creates a topic per project, writes each thread id back, and starts serving.

That is the whole setup: add the bot, run it, say hello.

## The fields

| Field | Where | Means |
| --- | --- | --- |
| `group` | top | The forum group's chat id. Negative, begins `-100`. Ferryman fills this in the first time you speak to it in the group. |
| `default_to` | top | The machine an unaddressed order goes to, fleet-wide. |
| `name` | `[[topic]]` | What the topic is called in Telegram. |
| `workspace` | `[[topic]]` | The project. Relative paths resolve against the map's own folder, so the same file works on two machines that lay their channels out the same way. |
| `thread` | `[[topic]]` | Telegram's id. Leave it out and Ferryman creates the topic and fills it in. |
| `default_to` | `[[topic]]` | Overrides the fleet-wide default for this project. |
| `general` | `[[topic]]` | This project takes messages that arrive with no topic - a private chat, or the group's General. At most one topic may say this. |

## What it does with it

- A message in a topic becomes a signed order in **that project's** channel.
- A result is announced back into **its own project's** topic, not into whichever chat the
  bridge was started from.
- A message in a topic that is not in the map is answered with what to add to fix it. It is
  never guessed into another project's channel: an order is signed, and signing work into a
  project nobody asked about is worse than not answering.

## Without a map

There does not have to be one. With no `--map` and no `.tgferryman` found from the working
directory upwards, the bridge is what it was before: one chat, one project. Nothing to
change on an existing install.

## Still not a path for secrets

Everything in the bridge's own warning applies per
topic. A Telegram cloud chat is not end-to-end encrypted, and a group is a chat with more
people in it. Orders, yes. Credentials, never.
