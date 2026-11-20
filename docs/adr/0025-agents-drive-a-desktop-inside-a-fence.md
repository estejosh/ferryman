# ADR 0025: Agents drive a desktop, inside a fence

Status: proposed, for the master (josh), 2026-10-18. Builds on 0010, 0013, 0014, 0020, 0023 and 0024. Related to docs/IROH_LANE.md, docs/LAYOUT.md, docs/TELEGRAM_TOPICS.md and docs/THREAT_MODEL.md.

## Context

Agents can read and write files, run commands and hand in patches. They cannot see a screen. Two things follow.

- An agent that builds something with a user interface cannot test it. Graea, the Telegram bot tester, is the first case: the bot is only real once something sends it a message and looks at the answer.
- Some work has no API. Operating an application means looking at it and clicking.

Letting an agent drive a desktop is a large grant. It can click anything the logged-in user can click. On a person's own machine that includes their browser sessions, their files and their other accounts. ADR 0024 already says plainly that its access levels are advisory because every agent on a machine runs as the same operating-system user. A desktop makes that worse, because the agent no longer needs to go around Ferryman to reach things. It only needs to look.

So this ADR does two things. It says that desktop control is its own signed grant, off until the master turns it on. And it says where the desktop lives: on a machine that nobody else uses, or inside a virtual machine that holds nothing of the master's.

### What was checked in the repository

Read on `origin/main` (v0.6.0, d73a23a) before writing. Where something this ADR relies on does not exist yet, it is listed here so nobody assumes it does.

- **Access levels (0024)** are Worker, Member and Orchestrator: who may write the channel and which credentials load. Nothing in them mentions a display or input. A desktop grant therefore has no home in the levels, which is what we want.
- **Hand-ins (0023, 0024)** already carry `files/` for large outputs and keep a Worker's writes in `handins/<agent>/`. Evidence for a desktop session fits there.
- **Interrupts** exist: `ferry channel interrupt` writes a signed `kill`, `pause` or `steer`, and a killed order stays killed (0020). The worker honours one between poll ticks. A desktop session needs it honoured between actions.
- **Evidence** exists for code work (`ferryman-channel/src/evidence.rs`): the worker, not the model, records what changed, and `judge` marks a result verified, unverified or refuted. There is no desktop evidence yet.
- **Secrets** are sealed per recipient and per name (0010). Secrets never travel through Telegram.
- **Telegram** accepts `/help`, `/agents`, `/status`, `/order` and `/to` (`crates/ferryman-cli/src/telegram.rs`). There is no stop, roll back, watch or approval command in channel mode. ADR 0018 also records that the `phone` identity signs on whichever machine runs the bridge, so a Telegram approval proves the bridge machine acted, not that the master did.
- **The Android APK** is not in the repository. There are no documents for it and no code. `docs/ROADMAP.md` mentions Android only as a possible future client. Everything below that depends on the APK depends on something that does not exist yet.
- **There is no notion of an order capability.** Orders are routed by the machine's published profile (0023, section 8), and routing is advisory (0009). This ADR adds the first capability that is enforced by the receiver.
- **Sandboxing** is opt-in and container-based (`sandbox` in `agent.toml`). Containers do not give a desktop to drive on Windows, which is why this ADR uses a virtual machine.

## Decision

These are the master's decisions of 2026-10-18, recorded as given.

1. Agents may drive a desktop (click, type, screenshot) to test what they build and to operate applications that have no API.
2. **grouchly** (Ubuntu, AI-only) needs no VM. Agents drive its desktop directly.
3. **beastly** (Windows 11, RTX 3090, the master's personal machine) runs all AI work inside a VM: the Ferryman worker, the agents, desktop driving, and NATV (the GPU animation pipeline, currently on WSL2 with CUDA). Nothing AI touches the master's Windows session, files or browser.
4. Internet is on by default in the VM. Keys and PATs stay out unless a task needs them. When one does, it arrives sealed for that task, using the existing `ferry channel secret` sealing (0010).
5. The VM talks to the fleet only through Ferryman's iroh lane (docs/IROH_LANE.md), plus Telegram and the Android APK for the master.
6. Approvals. Telegram is for watching (live screenshots), Stop, Roll back and routine approvals. The Android APK is for anything risky. Only the master holds the APK.
7. Desktop control is its own master-signed grant, per machine and per project, and off by default. No access level implies it (ADR 0024 levels).
8. Every session leaves evidence: a signed action log, plus screenshots or a recording attached to the order result. The judge reviews it the way it reviews a diff.
9. Kill is available at any time from the dashboard, Telegram and the APK.

The rest of this ADR is how to build that, what it costs, and the order to do it in. Anything that goes beyond the nine decisions is marked **proposed** so the master can strike it without touching the decisions.

## Design

### 1. The grant

A desktop grant is a signed file in the project's channel, written by the project's master only:

```text
comms/desktop/<agent>.json
  project, agent, machine
  targets        the displays or VMs the agent may drive, by name
  apps           optional allowlist of applications (empty means any inside the fence)
  net            "open" (default, decision 4) or "allowlist" with hosts
  max_session    longest single session, in minutes
  seq            a sequence number; a receiver never accepts an older one (as 0024)
  expires        a lease, renewed by publication (0013)
  signed_by, signature
```

- **Off by default.** No file means no desktop. There is no environment variable, no `agent.toml` key and no flag that turns it on.
- **Per machine and per project.** The grant names an agent. Each machine has its own, and so does the VM on beastly, which is its own agent identity. It lives in one project's channel, so it means nothing in another. Granting `graea` a desktop on grouchly gives nobody a desktop anywhere else.
- **Independent of the levels.** An Orchestrator, a Member and the master's own machine get nothing from their level. A Worker can hold a desktop grant. A desktop grant does not change a level, does not unlock `secrets/`, does not open the network and does not let the agent push. The VM's worker stays a Worker (0024), holds no write token (0023), and hands in.
- **A renewable lease (0013).** Short expiry, renewed by the master. Revocation is "stop renewing", and a machine that has not synced still runs out at a known horizon. Proposed default: seven days.
- **Enforced by the receiver of the order and by the driver.** The worker checks the grant before it starts a session and again before every action batch. The driver (below) refuses to start without a valid grant on disk. A forged or edited grant fails its signature.
- **Where the master sets it** (proposed): `ferry desktop grant|revoke|show`, and a switch on the Teammates page of the dashboard, behind the operator password as in 0018.

As 0024 says of its levels, the limit is advisory on a machine without a fence. On grouchly, a process that wants a desktop it was not granted can take one, because it shares an OS user with the worker. That is accepted for grouchly because nothing else lives there. It is the reason beastly gets a VM.

### 2. The driver

One small program, `ferry-desktop`, runs beside the worker on the machine that owns the display. It is a separate process with a narrow job.

Verbs: `screenshot`, `move`, `click`, `double_click`, `drag`, `scroll`, `type`, `key`, `wait`, `windows` (list titles), `record start|stop`. Clipboard read and write are **not** in the default set. `type_secret NAME` types a sealed secret from the task's envelope, logs the name and not the value, and exists only when the order carries a sealed secret.

Backends, chosen per target:

| Backend | Where | Input | Screenshot |
|---|---|---|---|
| `x11` | grouchly, a Linux VM | `xdotool` | `import`, `scrot` or `maim` |
| `uinput` | a Wayland session | `ydotool` (needs `/dev/uinput`, so a group or root) | the compositor's portal, which prompts for consent, or `grim` on wlroots |
| `windows` | a Windows VM | `SendInput` from an in-guest helper | `Windows.Graphics.Capture` or GDI |
| `rfb` | any VM or session that runs a VNC server | RFB key and pointer events | RFB framebuffer |

Notes on the choice, from what was read:

- `xdotool` does what it says on X11 and, as its author puts it, little on Wayland: GNOME 48 and KDE prompt for permission when input is sent through Xwayland, and GNOME will not remember the answer. `ydotool` works on both through the kernel's `uinput`, which needs root or a group, and it sends key codes, so it needs the keyboard map. The author's own summary is that every compositor needs its own approach. For an AI-only machine the answer is to run an **X11 session** (or a dedicated virtual X display) and use `xdotool`. That is an existing, boring path.
- Anthropic's reference implementation for computer use is a Docker container with Xvfb, the Mutter window manager, Tint2 and a few applications. It is a good model for a virtual display on grouchly when a second session must run beside the real one.
- A VNC (RFB) backend is the portable one. It works against any VM whose guest runs a VNC server, and it doubles as the way to watch. Its cost is a listening port, which is why it binds to loopback or the VM's private switch and never to a LAN.
- The master's existing remote-control tooling on beastly drives his real Windows session. It is not part of Ferryman and agents do not use it. This ADR is partly why.

**How a worker exposes it.** The worker publishes `desktop = ["grouchly:display", "beastly-vm:windows"]` in its machine profile (0023, section 8), only while a valid grant exists. An order asks for it with `needs = ["desktop"]` and may narrow it: `desktop = { target, apps, minutes, record = "log|screens|video" }`. Routing is advisory (0009), so the router uses the profile to send desktop orders to a machine that has the grant. The receiver is what refuses: a worker with no grant fails the order, it does not run it blind. Inside the order, the engine reaches the driver through an MCP server the worker starts for that session and stops at its end. Every call goes through the worker's policy layer first (grant, budgets, kill check) and is logged before it runs.

### 3. A session

1. The worker verifies the grant and the order.
2. Beastly VM: a Hyper-V checkpoint is taken first. A session is the unit of rollback.
3. If the order carries a sealed secret, it is opened here and nowhere earlier. It never goes into the checkpoint or the base image.
4. The driver starts recording. Every action is appended to the log.
5. At the end, or on kill, or at `max_session`, the driver stops, the secret is wiped, and the evidence is written to `handins/<agent>/<order>/`.

Budgets, all enforced by the worker and not by the model (**proposed** numbers): `max_session` 60 minutes, 600 actions, a screenshot with every action, a recording size cap, and one session per grant at a time.

### 4. Evidence

Each session writes, under `handins/<agent>/<order>/desktop/`:

- `actions.jsonl`: one line per action, in order. Verb, arguments (typed secrets replaced by the secret's name), time, the active window title, the sha256 of the screenshot taken just before and just after, and the sha256 of the previous line. The worker signs the head of the chain, so a line cannot be removed or reordered without breaking it. This is the signed action log.
- `screens/`: the screenshots, named by hash.
- `session.mp4` (or `session.webm`), when `record = video`. The iroh lane refuses anything over 64 MiB, so the recorder writes segments under that cap.
- `net.log`: the hosts the session connected to, taken from the VM's firewall or proxy on the host side, not from the guest.
- `desktop.json`: the manifest. Grant seq, checkpoint id, start and end, the budgets used, and how it ended (finished, killed, budget, timed out).

The result refers to the folder. `judge` (evidence.rs) learns four rules, in the same style as its existing ones (**proposed**):

- a desktop order with no signed log, or a log whose chain does not verify, is `refuted`;
- an answer that claims a UI behaviour with no screenshot after the last action that could have produced it is `unverified`;
- a log that shows an action outside the grant (an application or host off the allowlist) is `refuted`;
- a session that ended on a budget or a kill cannot be accepted without `--force`.

`ferry work show <order>` prints the log with a contact sheet of screenshots, so a reviewer reads a session the way they read a diff. `ferry work accept` refuses a desktop hand-in that fails these checks, as it refuses an unverified verdict today (0024).

### 5. Watching, approving, stopping

Three surfaces, different authority.

| Surface | Watch | Stop | Roll back | Routine approval | Risky approval |
|---|---|---|---|---|---|
| Dashboard | yes | yes | yes | yes | yes, with the operator password (0018), until the APK exists |
| Telegram | yes (screenshots) | yes | yes | yes | no |
| Android APK | yes | yes | yes | yes | yes, and only here once it exists |

- **Stop is always allowed from every surface.** It writes the existing signed `kill` interrupt (0020), so a stopped order stays stopped. A stop that fails to arrive is as bad as no stop, so the driver also stops on its own if it has not seen a fresh heartbeat from the worker host in 15 seconds (**proposed**). A VM cut off from the fleet therefore stops acting.
- **Roll back** reverts the VM to the session's checkpoint. It undoes what happened inside the VM. It cannot undo what left it: a message sent, a form submitted, a push. That is why those are risky and gated, not rolled back. On grouchly there is no checkpoint; Roll back there means discarding the hand-in and restoring the application profile directories that were copied before the session.
- **Routine** means actions that stay inside the grant and the fence and touch nothing outside it: starting a session within the grant, continuing past a budget the master has agreed in advance, and acting on the thing the agent built.
- **Risky** is decided by what the environment can see, not by what the model says about itself. A model driving a screen cannot be trusted to flag its own dangerous click. The triggers are: a host outside the order's allowlist when one is set, installing software, any use of a sealed secret, any action in an application not on the allowlist, and any send, post or payment the policy layer recognises by window title or destination host. A trigger pauses the session and asks the APK. If the APK is unreachable the session stays paused. It does not fall back to Telegram.
- **The Telegram bridge has the weakness 0018 found.** It signs as `phone` on whichever machine runs it. For Stop and Roll back this does not matter, because they only reduce risk. For routine approvals it is accepted. For anything risky it is not, which is the reason risky goes to a key that actually lives on a phone. The APK is the first such key. Until it exists, risky approvals use the dashboard flow of 0018, and no desktop grant should be signed for work that could reach a risky trigger.
- **Live is not live yet.** The iroh lane exchanges manifests every 30 seconds. A screenshot written to `handins/` reaches the bridge about that late. "Live screenshots" in decision 6 needs a session stream on the lane (same trust rules, same safety rules, one stream per session, roughly one downscaled frame every two seconds) or an equivalent. Until it is built, Telegram gets a still about every 30 seconds. This is a build item, not a reason to hold the design.
- **Where the Telegram token lives.** Not in the VM. The VM writes its stills to the hand-ins folder, and the bridge, on a machine that already runs it, posts them. This keeps the bot token out of the one place decision 4 says keys stay out of. (**proposed**)
- **Telegram is not end-to-end encrypted,** and 0010 keeps secrets out of it. Screenshots can show a secret if one is on screen. (**proposed**) While a session holds a sealed secret, Telegram receives no screenshots, only a text line per action, and full-screen watching moves to the APK.

### 6. Where the desktop lives

| Machine | Desktop | Fence |
|---|---|---|
| grouchly | its own X11 session, or a second virtual display beside it | none beyond the grant. AI-only, so there is no personal data to protect |
| beastly | a Hyper-V VM | the VM, described below |

The beastly VM in detail (**proposed** where marked, otherwise it follows from decisions 3 to 5):

- A Generation 2 Hyper-V VM with Secure Boot on.
- **Nothing shared with the host:** no shared folders, no drive or clipboard redirection, no enhanced session, and integration services off except what is needed to run (heartbeat, time sync). No host file copy service. (**proposed**)
- **Network:** a private switch with NAT to the internet. Outbound rules block the host, the master's LAN (RFC 1918 ranges) and every other fleet machine. The VM reaches the iroh relay, which is on the public internet, and nothing local. Rules are applied from the host side (the Hyper-V firewall and extended port ACLs), so a guest cannot edit them. (**proposed**)
- **Identity:** its own agent identity in the roster, enrolled as a Worker by the master (0024), with its own iroh endpoint key (IROH_LANE). It holds `GH_RO_*` at most, never a write token (0023).
- **Checkpoint per session**, as above.
- **Resources:** capped CPU and memory so a runaway job cannot starve the master's own work. (**proposed**)

## Where NATV runs: GPU inside a VM on Windows 11

NATV needs CUDA. Beastly is Windows 11 Pro (see Findings). The question is how a VM gets the 3090.

### Findings on beastly (read-only, 2026-10-18)

- `Get-ComputerInfo` reports `WindowsProductName` as "Windows 10 Pro" with HAL version 10.0.26100.1. That string is a known leftover on Windows 11. `Win32_OperatingSystem` reports "Microsoft Windows 11 Pro", build 26200 (version 25H2). The edition is Pro, which can have the Hyper-V role and is not Windows Server.
- `Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All` failed with "The requested operation requires elevation". Whether the Hyper-V feature is enabled is **unknown**. `HypervisorPresent` is True, which is what WSL2's Virtual Machine Platform produces, so a hypervisor is already running.
- `nvidia-smi` reports an RTX 3090, 24576 MiB, host driver 617.14.
- Nothing was changed.

### The options

| | Supported by the vendor | CUDA and ComfyUI | Isolation | Verdict |
|---|---|---|---|---|
| (a) Hardened WSL2 | Yes. NVIDIA documents CUDA on WSL 2 on Windows 11 with GeForce (Pascal or later), driver on the host only | Works today. NATV already runs this way | Weak (see below) | Interim, and the fallback |
| (b) Hyper-V GPU-P on Windows 11 Pro | **No.** Microsoft supports GPU-P on Windows Server 2025 with datacenter GPUs and says it is not supported on Windows 10 or 11 Pro | Unproven for a Linux guest. For a Windows guest, not verified here | Good (a real VM), with one extra attack surface | The path to try |
| (c) Full passthrough (DDA) | Server only. Microsoft: not supported on desktop-class hardware or client Windows | Would work if it could be set up | Strong | Not available on this machine |
| (d) VMware Workstation or VirtualBox | No GPU passthrough on a Windows host | No CUDA in the guest | Good, but pointless without a GPU | Rejected |

**(a) A hardened WSL2.** `wsl.conf` is per distribution, at `/etc/wsl.conf`. A new distribution (`wsl --import`, not the existing NATV one) with:

```ini
[automount]
enabled=false
mountFsTab=false

[interop]
enabled=false
appendWindowsPath=false

[user]
default=agent
```

and in `%UserProfile%\.wslconfig`: `networkingMode=nat` and `firewall=true`, plus memory and CPU caps. A separate unprivileged user, with sudo left off.

What this does not do, from the documents:

- Microsoft's own description of `automount enabled=false` is "drives won't be mounted automatically, but you could still mount them manually". The DrvFS internals document shows `mount -t drvfs C: /somewhere` as the manual route. Root in the distribution can undo the setting's purpose, and which Windows namespace it reaches depends on how the distribution was started, which the document does not settle.
- Interop and automount are settings in a file the guest can edit. They take effect after `wsl --shutdown`. They are guard rails, not a boundary.
- All WSL2 distributions share one utility VM and one kernel. A "separate distro" separates files and users, not the VM.
- The plan9 file server that serves Windows drives runs on the Windows side for the logged-in user. The boundary is the user's own session, which is exactly what decision 3 says AI must not touch.
- Firewall: `firewall=true` lets Windows Firewall and Hyper-V firewall rules filter WSL traffic. That can block the LAN. It is real, but it is filtering on the host's terms.
- Known CUDA-on-WSL limits (NVIDIA): unified memory is limited, pinned memory is limited, NVML (so `nvidia-smi`) reports a subset, and OpenGL-CUDA interop is not supported. Nothing here has stopped NATV so far.
- Windows 11 25H2 moves the WSL2 kernel to 6.6 LTS (press report of 9 October 2026, borncity). Read it as a convenience, not a security change.

So (a) is a good place to keep NATV for now and a poor answer to "nothing AI touches my session". It is the interim and the fallback, not the destination.

**(b) Hyper-V GPU partitioning.** Status as of October 2026, as far as the sources go:

- Microsoft's troubleshooting page for GPU-P and DDA says: "DDA and GPU-P aren't supported on desktop-class hardware or client operating systems such as Windows 10 or 11 Pro." GPU-P needs Windows Server 2025 and a Generation 2 guest, and the page lists A2, A10, A16, A40, L2, L4, L40 and L40S. It lists Windows 10 or later and Ubuntu 18.04, 20.04 and 22.04 as GPU-P guests. A 3090 is not on that list.
- The feature exists on Windows 11 Pro anyway. Community tooling (Easy-GPU-P) uses it: Windows 10 20H1 or 11, Pro or Enterprise, a desktop NVIDIA, AMD or Intel GPU that can hardware-encode video. The pattern is: enable Hyper-V and reboot; create a Gen 2 VM; enlarge its MMIO space and turn on guest-controlled cache types; add a GPU partition adapter; copy the host's NVIDIA driver files from `DriverStore\FileRepository` into the guest's `HostDriverStore`. Running NVIDIA's installer in the guest does not work (per the guide linked from the Level1Techs thread). After each host driver update the guest copy must be refreshed and the host rebooted.
- Known limits from that tool: a display or HDMI dummy plug is needed for screen capture; the screen can black out for seconds on UAC prompts; Vulkan is unavailable; OpenGL "may or may not work". Its README says nothing about CUDA and nothing about Linux guests.
- Linux guests: the 2023 forum thread that tried it with the WSL `dxgkrnl` module got `/dev/dxg` but no working `nvidia-smi` or CUDA, and closed with no answer. A newer working path was **not found**. Treat a Linux guest as unproven.
- A Windows guest therefore carries the weight of this option. ComfyUI on Windows with PyTorch CUDA should follow if CUDA runs in the guest. That is an expectation, not a verified result.
- Servicing risk: a Windows Server 2025 update in June 2025 was reported to break GPU-P to a Windows 11 VM (Microsoft Tech Community thread; the title was read, the thread was not). On client Windows an update or a driver change can break the guest copy. Expect to retest after both.
- Attack surface: GPU paravirtualization has the guest send commands over VMBus to Windows host components (`dxgkrnl.sys`, `dxgmms*.sys`). A 2022 Black Hat talk found four host-side bugs by fuzzing, including an arbitrary read and an arbitrary write. WSL2 uses the same path today, so this is not new exposure on beastly. It is the reason the VM has no GPU until the plain VM is proven.

**(c) DDA.** Microsoft's page rules it out on client Windows, and it needs server-class hardware. It also gives the whole card to the guest; on a single-GPU personal machine that would include the host's display (general DDA behaviour, not tested here). If NATV ever moves to a machine that runs only AI, DDA or ordinary KVM passthrough is available there, and that is a better answer than anything on beastly. Whether a GeForce card works under DDA at all is **unverified** here.

**(d) VMware or VirtualBox.** A community answer in the Broadcom forum says Workstation does not do PCI passthrough. Oracle's VirtualBox 6.0 manual limits its experimental PCI passthrough to Linux hosts. Whether later VirtualBox versions removed it is **unverified**. On a Windows host with Hyper-V on, both run on the Windows hypervisor anyway. Neither gives the guest CUDA on a 3090.

### Recommendation

1. **Now, interim:** keep NATV on WSL2 but in a new, hardened distribution (config above, NAT, firewall, no token). This is a step short of decision 3 and is only for the weeks before the VM exists. It needs the master's agreement and is not a substitute.
2. **Next:** enable Hyper-V and build the plain VM with no GPU. Run the Ferryman worker, the agents and the desktop driver in it. That meets decision 3 for everything except NATV.
3. **Then try GPU-P, on a throwaway Windows 11 guest:** `nvidia-smi` and `torch.cuda.is_available()` in the guest, a ComfyUI workflow, and a LoRA training run compared with the WSL2 baseline. (**Proposed** bar: within 15 percent of WSL2 throughput, survives a host driver update and a Windows cumulative update with a documented refresh step, and does not disturb the master's own display or games.)
4. **If it passes,** move NATV into the VM and retire the WSL2 distribution (export it first). **If it fails,** the master chooses: keep NATV on hardened WSL2 as a written exception, or move NATV to a machine that only runs AI.

The guest is a Windows 11 guest for NATV because that is the only variant with any evidence. It needs a Windows licence, which the master has to supply (open question 1).

## Threat model

Assume the agent is honest and the screen is not. The things that can go wrong, in order of how likely they are.

### Prompt injection through on-screen content

A web page, an email, a window title or a test fixture shows text that tells the agent to do something else. The agent reads it with its eyes and has no way to tell it from an instruction. Anthropic's documentation says instructions on webpages or in images might override the user's instructions, that classifiers reduce this and do not remove it, and that the precautions stay important regardless: a dedicated VM or container with minimal privileges, no sensitive data such as logins, an allowlist of domains, and a human confirming real-world consequences.

Mitigations:

- **Nothing to steal.** The VM holds no secret by default (decision 4), no personal browser profile and no host files. An injected agent in an empty room can still waste time and do harm outside, which the next points handle.
- **No write path.** The VM's worker is a Worker that holds no write token (0023). It cannot push, merge or publish. Whatever it makes is a hand-in that a human or the head reviews. The log shows what it did.
- **Scope is one project.** The grant is per project. An injection met while testing project A cannot give the agent project B's orders or channel (0024, 0010).
- **Risky actions are caught by the environment, not by the model** (section 5), and they go to the APK.
- **Tool output is marked untrusted** in the prompt the worker builds, and screenshots are never fed back as instructions. This lowers the odds. It is not a guarantee, so the points above carry the weight. (**proposed**)
- **Dedicated accounts.** Graea's Telegram client runs as a throwaway account made for testing, never the master's own. (**proposed**)
- **Allowlist when it matters.** With a sealed secret in the session, `net` narrows to the hosts the order names. With no secret, the internet is open (decision 4), and `net.log` records where the session went. (**proposed**)

### Credential exposure

Routes: a secret in the base image or a checkpoint; a secret typed on screen and captured in a screenshot or recording that then syncs to every peer; a secret on Telegram; a token in the VM that outlives the task; the VM reading host files.

- Secrets are sealed per task and per recipient (0010), opened at session start, wiped at the end, and never before the checkpoint is taken. The base image is built with none.
- The driver types a secret with `type_secret`; the log holds the name only. Password fields mask on screen. A secret shown in clear on screen **will** appear in the evidence. That is a residual risk, so the policy layer pauses a session whose screenshots OCR to the secret value (**proposed**), and Telegram stops receiving screenshots while a secret is present (section 5).
- There is no host clipboard, no shared folder and no host file service, so the VM has no route to the master's files (decision 3).
- Revealing a secret is irreversible: once it has been in a session, the upstream credential has to be rotated if the session is suspect. 0010 says so already.
- The VM holds at most a read-only GitHub token per machine (0023, section 6) and never the Telegram bot token.

### VM escape

A guest that breaks out of Hyper-V reaches the host and the master's session. This is rare and expensive, and it is the one threat the VM does not defeat by design.

- Keep Windows and Hyper-V patched. Fewer guest-facing devices: Gen 2, no enhanced session, no integration services beyond the basics.
- No GPU in the guest until the plain VM has run for a while. When GPU-P goes on, it adds the VMBus graphics path described above. WSL2 already exposes the same path, so the master is not worse off than today, but it is a real surface and is stated as one.
- A Hyper-V guest runs in its own per-VM worker process. That is a better position than WSL2, where the file server that serves Windows drives acts for the logged-in user. (This is inferred from the two designs, not from a document.)
- Rollback and checkpoints restore the VM but do not reach the host. A compromised host is a rebuild.
- Residual risk is accepted by the master with this ADR: a hypervisor flaw, or a GPU-PV flaw once GPU-P is on.

### A runaway agent

Loops, floods, runs forever, fills the disk, or does something expensive.

- Budgets in the worker: minutes, actions, one session per grant, a cap on recording size and on the folder.
- Loop detection (**proposed**): the same screenshot hash after N identical actions pauses the session and asks.
- Kill always wins and sticks (0020). The heartbeat dead-man rule stops the driver when the worker host stops answering.
- The grant is a short lease. If the master stops renewing, new sessions stop.
- The VM has CPU and memory caps, and its network has rate limits at the host (**proposed**), so a flood hits a cap and not the master's connection.
- The VM disk is a fixed-size virtual disk on a volume with space reserved for the host. (**proposed**)

## Rollout

Each phase has an exit test. Nothing moves to the next phase until the previous one passes.

### Phase 0: build, on no machine

- The grant type and `ferry desktop grant|revoke|show`, receiver checks, and the driver (`x11` backend first).
- Evidence: log chain, `judge` rules, `ferry work show`.
- Kill between actions and the heartbeat rule.
- The session stream on the iroh lane (or the 30-second still as the stopgap).
- Telegram commands for stop, roll back and watch.
- Remote: all of it.

### Phase 1: grouchly, Graea testing a Telegram bot

- A throwaway bot and a throwaway Telegram account. Graea sends a message to the bot through the Telegram client on grouchly's desktop and reads the answer.
- Exit test: Graea's session leaves a log that verifies, a hand-in the head can review, Stop and Roll back both work from Telegram within seconds of being pressed, and the dashboard shows the grant and its expiry. A deliberate injection (a bot reply that tells the agent to open another app) does not succeed.
- To check first: whether grouchly runs an X11 or a Wayland session. This was not checked, because the device tool reaches beastly only. If it is Wayland, switch the session to X11 or use a virtual display.
- Risky approvals use the dashboard until the APK exists, so this phase signs a grant only for work that cannot reach a risky trigger.
- Remote: all of it, if grouchly has a logged-in graphical session and the master approves installing `xdotool`, a screenshot tool and `ffmpeg`. At the desk: nothing.

### Phase 2: the beastly VM, for agents

- A Windows 11 Pro VM (Gen 2, no GPU), the fence in section 6, the worker as a Worker, the driver's `windows` backend, the checkpoint per session.
- Move the Ferryman worker and the agents' AI work from the host into the VM.
- Exit test: from inside the VM, the host, the LAN and every other fleet machine are unreachable; the internet and the iroh relay are reachable; a session ends with a verifying log; a deliberate attempt to read the host's files fails; Roll back restores the guest.
- At the desk (master): enabling the Hyper-V feature (it needs an elevated session and a reboot; the remote tool on beastly was not elevated), supplying the Windows ISO and licence, confirming virtualisation is on in firmware (a hypervisor is present now, so it very likely is), the first boot and install through the VM console, and approving the VM's network rules.
- Remote, afterwards: everything else, including the master signing the grant and the Worker enrolment from the dashboard.
- The APK needs to exist before any grant that can reach a risky trigger.

### Phase 3: NATV inside the VM, once GPU-P is proven

- Trial on a throwaway guest first (see Recommendation), then the real VM.
- At the desk: any host driver change and reboot, the first GPU-P attach and driver copy, and a dummy display plug if capture needs one. Updating the NVIDIA driver on the host after this needs the guest copy refreshed and a reboot.
- Remote: the tests, the workflow runs, the LoRA comparison, and moving NATV's data in.
- Exit test: the bar in the Recommendation. The WSL2 NATV distribution is exported and kept until then.

## Consequences

- Agents can test what they build and operate programs with no API, which they could not before.
- The master's personal Windows session stops being a place AI works. It costs a Windows licence, disk, RAM and a refresh step after host driver updates.
- A desktop grant is the first capability that is enforced by the receiver and signed by the master per machine. It sets the pattern for the next one.
- Session evidence is large. The hand-ins folder will grow, so retention and a cap need a decision (open question 4).
- Grouchly has no fence. If someone puts personal data on it, this ADR stops being true for grouchly.
- The Android APK becomes a dependency for risky approvals. Until it exists, the design degrades to the dashboard, not to Telegram.
- NATV may end up outside the VM if GPU-P does not work. The ADR says so now so that it is a choice the master makes and not one that happens to him.

## Open questions

1. Guest OS and licence for the beastly VM. Windows 11 is the only guest with any GPU-P evidence. A Linux guest would be cheaper and has better driver tooling but has no verified GPU path.
2. Which applications "with no API" are the first targets? That decides whether the Windows backend or the X11 one is built first.
3. How does the APK reach the fleet? Through the iroh lane, a relay or Telegram? Nothing in the repository says. The design assumes it can both receive a pause and send a signed approval, and that its key is enrolled in the roster by the master.
4. Retention for session evidence: how long recordings stay, and whether they leave the synced folder.
5. Should a desktop session ever run above Worker level? This ADR says Worker only, and the question is whether anyone needs more.
6. Is it acceptable that new network hosts are only logged, not paused on, with the internet on by default? This ADR logs.

## Unverified

- Whether Hyper-V is enabled on beastly (the check needs elevation).
- Whether CUDA runs in a Windows 11 Pro GPU-P guest with an RTX 3090 on driver 617.14, and whether ComfyUI and LoRA training match WSL2. No source found measures it.
- Whether any Linux guest has working CUDA through GPU-P in 2026. The only evidence found is from 2023 and negative.
- Whether VirtualBox removed PCI passthrough after 6.0, and whether a GeForce card works under DDA.
- Whether nested GPU-P (WSL2 inside the GPU-P guest) works. The design avoids it.
- Whether a session stream over the iroh lane can reach the frame rate proposed.
- The session type on grouchly.
- Whether the Telegram stop, roll back and watch commands, the APK and the `ferry desktop` commands exist anywhere. This ADR says they do not, from reading `origin/main`, not from a running system.

## Sources

Read on 2026-10-18.

- Microsoft Learn, [Troubleshoot GPU assignment, partitioning and passthrough issues in Hyper-V](https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/troubleshoot-hyper-v-gpu-assignment-partitioning-passthrough-issues): GPU-P and DDA not supported on client Windows; GPU-P needs Windows Server 2025; supported GPU and guest list.
- Microsoft Tech Community, [GPU Partitioning in Windows Server 2025 Hyper-V](https://techcommunity.microsoft.com/blog/itopstalkblog/-/4429593): only the page metadata was readable; last modified July 2025.
- Microsoft Tech Community discussion, [Windows Server 2025 host KB5062553 and June's update breaks GPU-P to a Windows 11 VM](https://techcommunity.microsoft.com/discussions/windows11/windows-server-2025-host-kb5062553-and-june%E2%80%99s-breaks-gpu-p-to-windows-11-vm/4431542/replies/4542472): title read from search results; thread body not read.
- Easy-GPU-P, [github.com/vadash/Easy-GPU-P](https://github.com/vadash/Easy-GPU-P): community GPU-PV on Windows 10/11 Pro and Enterprise; limits listed above.
- Level1Techs, [GPU paravirtualization, Hyper-V with Linux guest](https://forum.level1techs.com/t/gpu-paravirtualization-hyper-v-with-linux-guest/198336): 2023 attempt, no working CUDA, closed 2024.
- Black Hat USA 2022, [DirectX: The New Hyper-V Attack Surface](https://i.blackhat.com/USA-22/Thursday/US-22-Hong-DirectX-The-New-Hyper-V-Attack-Surface.pdf): GPU-PV host attack surface and four fuzzing finds.
- Microsoft Learn, [Advanced settings configuration in WSL](https://learn.microsoft.com/en-us/windows/wsl/wsl-config): `wsl.conf` per distribution, `automount`, `interop`, `.wslconfig` networking and `firewall`.
- wsl.dev, [DrvFS technical documentation](https://wsl.dev/technical-documentation/drvfs/): plan9 server, manual `mount -t drvfs`, elevated and non-elevated namespaces.
- DEV Community, [Improve WSL security with read-only filesystem](https://dev.to/tonymet/improve-wsl-security-with-read-only-filesystem-23e5): automount and interop settings as a way to reduce risk to host files.
- NVIDIA, [CUDA on WSL User Guide](https://docs.nvidia.com/cuda/wsl-user-guide/index.html): supported configurations and limits.
- borncity, [Windows 11 25H2: WSL2 gets kernel 6.6 LTS and NVIDIA CUDA support](https://borncity.com/news/windows-11-25h2-wsl2-erhaelt-kernel-6-6-lts-und-nvidia-cuda-support/), 9 October 2026.
- Broadcom community, [How to enable NVIDIA GPU in VMware Workstation Pro](https://community.broadcom.com/vmware-cloud-foundation/discussion/how-to-enable-nvidia-gpu-in-vmware-workstation-pro-1762): Workstation has no PCI passthrough (community answer).
- Oracle, [VirtualBox 6.0 PCI passthrough](https://docs.oracle.com/en/virtualization/virtualbox/6.0/admin/pcipassthrough.html): experimental, Linux hosts only.
- Anthropic, [Computer use tool](https://platform.claude.com/docs/en/agents-and-tools/tool-use/computer-use-tool): security guidance, prompt injection, reference implementation stack.
- Semicomplete, [Exploring the fragmentation of Wayland, an xdotool adventure](https://semicomplete.com/blog/xdotool-and-exploring-wayland-fragmentation/), 15 November 2025: xdotool on Wayland, uinput needs root, per-compositor workarounds.
