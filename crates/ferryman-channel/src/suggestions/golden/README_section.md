<!-- ferryman-suggest:begin -->
## Suggest an idea for Idle-ish

Idle-ish takes suggestions from anyone, and from your AI agent, through [Ferryman](https://github.com/estejosh/ferryman). A suggestion is one issue in this repository, sent with the `ferry` program so that it is signed and checked. You send an idea in words: no code, no files.

**Before anything you send can be reviewed you must agree to the [terms](TERMS.md).** They say that you send it under the owner's license, that nothing is promised or paid, and that credit is the reward. You agree by typing `I agree` yourself; an agent cannot agree for you.

### What you can suggest

- **Idea** (`idea`): `title` (up to 80), `pitch` (up to 1000), `why` (up to 500)
- **Bug** (`bug`): `title` (up to 80), `pitch` (up to 1000), `why` (up to 500), `steps` (up to 500), `expected` (up to 300, optional)
- **Content** (`content`): `title` (up to 80), `pitch` (up to 1000), `why` (up to 500), `where` (up to 200, optional)

Limits: 3 open at a time, 1 new per day, up to 2 round(s) of questions from us, and 14 days to answer one.

### Join in four steps

1. **Install Ferryman.** You need only the `ferry` program, no Syncthing and no project of your own: [download it](https://github.com/estejosh/ferryman/releases/latest), or run `curl -fsSL https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.sh | sh` (Windows: `irm https://raw.githubusercontent.com/estejosh/ferryman/main/scripts/install.ps1 | iex`), and ignore whatever it offers about setting up a fleet. Check with `ferry --version`. Ferryman is source-available.
2. **Join.** `ferry suggest join <invite>` with the invite below. It checks the owner's signature, shows you the full terms and the owner's key fingerprint, and asks you to type `I agree`. You need a GitHub token (`GITHUB_TOKEN`, or `gh auth login`); it is used to post as you and never stored or shown.
3. **Send.** `ferry suggest new` asks for each field with a live character count, shows a preview, and sends it when you confirm.
4. **Follow.** `ferry suggest status` shows where each of yours stands. If we have a question, answer it with `ferry suggest reply <number>`.

The invite, one line:

```
ferry-suggest:eyJ2IjoxLCJvZmZlciI6eyJmb3JtYXQiOiJmZXJyeW1hbi1vZmZlci92MSIsInByb2plY3RfaWQiOiJpZGxlLWlzaCIsImRpc3BsYXlfbmFtZSI6IklkbGUtaXNoIiwiaW5ib3giOiJnaXRodWI6ZXN0ZWpvc2gvaWRsZS1pc2gtaWRlYXMiLCJ0ZXJtcyI6eyJ2ZXJzaW9uIjoxLCJzaGEyNTYiOiI3NTBlNGZmZjEwYTZjYjQyNjhlZTg4YTk5NWU1YmU4NDIwMDI1YmYyMjQ2N2M2YmM3OGU2YjhjMzY3YzBlMjJhIiwiZmlsZSI6IlRFUk1TLm1kIn0sInR5cGVzIjpbeyJpZCI6ImlkZWEiLCJsYWJlbCI6IklkZWEiLCJmaWVsZHMiOltdfSx7ImlkIjoiYnVnIiwibGFiZWwiOiJCdWciLCJmaWVsZHMiOlt7ImlkIjoic3RlcHMiLCJsYWJlbCI6IlN0ZXBzIiwibWF4Ijo1MDAsInJlcXVpcmVkIjp0cnVlfSx7ImlkIjoiZXhwZWN0ZWQiLCJsYWJlbCI6IkV4cGVjdGVkIiwibWF4IjozMDAsInJlcXVpcmVkIjpmYWxzZX1dfSx7ImlkIjoiY29udGVudCIsImxhYmVsIjoiQ29udGVudCIsImZpZWxkcyI6W3siaWQiOiJ3aGVyZSIsImxhYmVsIjoiV2hlcmUiLCJtYXgiOjIwMCwicmVxdWlyZWQiOmZhbHNlfV19XSwibGltaXRzIjp7InRpdGxlX21heCI6ODAsInBpdGNoX21heCI6MTAwMCwid2h5X21heCI6NTAwLCJvcGVuX3Blcl9jb250cmlidXRvciI6MywibmV3X3Blcl9kYXkiOjEsImNsYXJpZmljYXRpb25fcm91bmRzIjoyLCJhbnN3ZXJfZGF5cyI6MTR9LCJzdGF0dXMiOiJvcGVuIiwib3duZXIiOiJqb3NoIiwib3duZXJfa2V5IjoiOGE4OGUzZGQ3NDA5ZjE5NWZkNTJkYjJkM2NiYTVkNzJjYTY3MDliZjFkOTQxMjFiZjM3NDg4MDFiNDBmNmY1YyIsImlzc3VlZF9hdCI6IjIwMjYtMTAtMDZUMTI6MDA6MDBaIiwic2VxIjoxLCJzaWduYXR1cmUiOiIzZTBlYWJiZGVlZDhkYzZjZDYyYTY5NGQ5MGNiMTM0NGE5NjNhYmFmNjQ3ZWIwMWVjZjgyOWFjNzNmMWMxNDczOTg3OWMxODMxOWZkNDRiOGJmYWNhYmFkZjM1MThjYTBmMzliMDc3Zjg2MThmM2RhZWY4ZGVmY2FiMjcwMGQwMCJ9fQ
```

Owner key fingerprint: `95bbfbb1f0ef8f23`. Terms: version 1, sha256 `750e4fff10a6cb4268ee88a995e5be8420025bf22467c6bc78e6b8c367c0e22a`.

### Using an AI agent

Give your agent [AGENTS.md](AGENTS.md). It can draft and send suggestions for you, but you must read and accept the terms yourself.

### What happens next

Each suggestion is checked, read by a model that can do nothing but read, and then decided by Idle-ish's owner, not by the model. Its status is the label on the issue:

| label | meaning |
| --- | --- |
| `received` | it passed the checks and is waiting to be read |
| `needs-clarification` | we asked you a question |
| `accepted` | the owner said yes and it is queued to be built |
| `building` | work has started |
| `shipped` | it is built, and you are credited |
| `declined` | not going forward, with a reason |
| `duplicate` | the same as another suggestion |
| `invalid` | it could not be checked; the comment says what to fix |

Nothing is promised and nothing is paid; credit is the reward. Issues opened by hand are not reviewed.
<!-- ferryman-suggest:end -->
