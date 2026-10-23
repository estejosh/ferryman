# Rescue drill: beastly and grouchly

How to prove, on two real machines, that the Hive rescue channel (ADR 0027, "Rescue channel over
Hive") brings a cut-off pair back together. The harness is `crates/ferryman-hive-rescue/examples/rescue_drill.rs`.
It is its own executable with its own iroh key, roster and throwaway channel, so it touches nothing of
the live fleet and a firewall rule can be scoped to it alone.

## What the drill proves

1. Two machines on a healthy lane (relay up, direct path) lose each other and the fleet relay.
2. Each notices it is cut off (peer failing and relay down) and starts the clock.
3. After the cut-off time the master posts one sealed, master-signed record to Hive.
4. The cut-off peer, which reads Hive only while cut off, finds it, accepts it, and learns the master's
   endpoint and the rescue relay URL.
5. Both machines connect through the rescue relay and the channel files catch up.
6. When the cut is lifted the lane returns to its own path by itself.

## Network options

Network facts, read-only: beastly is `<beastly-lan-ip>/22` (Ethernet, plus Tailscale `<beastly-tailscale-ip>` and a
Hyper-V switch `<hyperv-switch-ip>`). grouchly (alias `grouchly` in `C:\Users\<user>\.ssh\config`, `<user>@<grouchly-lan-ip>`)
is on the same LAN, same router (`<router-lan-ip>`), so both share one public address. The fleet relay is the
VPS at `162.35.10.46`. ssh from beastly to grouchly runs over the LAN address, so a rule that drops
beastly's LAN address system-wide would cut the ssh path. Every rule below is therefore scoped to the
drill process only.

| Option | What it does | What it proves | Limits |
|---|---|---|---|
| 1. grouchly drops beastly's LAN IPs | Drill-only rules on grouchly (and mirrored on beastly) drop the peer's LAN address, the CGNAT range (Tailscale), private 172.16/12 and IPv6 | No direct path: the lane cannot fall back to the LAN | Same-NAT hairpin: through the router's public address the two could still meet, so the public address `<beastly-public-ip>` is dropped too. Without that the "cut" is not a cut |
| 2. Both block the relay VPS | Same rules also drop `162.35.10.46` | The fleet relay is gone for both, so only the Hive record can say where to meet | Proves nothing about a relay that is up but refusing us (that is a 403, a separate lane alert) |
| 3. Phone hotspot | Put one machine on a phone's network | A genuinely different NAT: direct paths need hole punching, and the rescue relay is the only sure meeting point | Needs a person and a phone; cannot be scripted from here |
| 4. Cloud instance | Run the second end on a VPS | A real internet path both ways, no shared NAT | Needs an account and a box; the instance needs the relay token and an outbound path to Hive |

Options 1 and 2 together are the scripted drill below. Options 3 and 4 are for the live-Hive leg, where
the same-NAT shortcut matters least.

## Setup used

- Rescue relay: n0's public relay `https://use1-1.relay.n0.iroh.link./` (no pin, no token).
- Fleet relay: the VPS, pinned certificate, access token copied into each drill directory as
  `iroh-relay.token` (mode 600, shredded afterwards; never printed).
- Hive: no accounts exist yet, so the harness serves the mock Hive RPC node (`--serve-hive`) from beastly on
  `127.0.0.1:8091`. grouchly reaches it through `ssh -R 127.0.0.1:8091:127.0.0.1:8091 grouchly`, so it is
  "reachable by both" with nothing opened on the LAN and the VPS untouched. The master signs with the
  reference test key, which the mock never checks.
- Timers: `--cut-minutes 2 --poll-minutes 1 --expires-minutes 15` (production defaults are 15 and longer).
- The Windows Firewall needs an elevated shell, which the automation session does not have. beastly's end
  therefore ran in WSL2 (mirrored networking: same LAN address and Tailscale as Windows) as a throwaway
  user `drillu`, with nftables rules matching that uid. The same commit was built in the worktree
  (`target/release/examples/rescue_drill.exe`, used for the tests and for `init`) and for Linux on grouchly;
  both ends of the drill ran the Linux build. On a machine with an elevated shell, scope Windows Firewall
  rules to the example executable instead.

## Runbook

```text
# each machine: make an identity and a channel of its own (throwaway dir)
rescue_drill init --dir D --name <beastly|grouchly> --primary-relay https://162.35.10.46
# copy each machine's D/export/ to the other's D/peer/ ; put the relay token at D/iroh-relay.token

# beastly (master)
rescue_drill run --dir D --name beastly --master beastly --role master \
  --primary-relay https://162.35.10.46 --primary-pin <relay cert sha256> \
  --rescue-relay https://use1-1.relay.n0.iroh.link./ --hive http://127.0.0.1:8091 \
  --serve-hive 127.0.0.1:8091 --cut-minutes 2 --poll-minutes 1 --expires-minutes 15
# grouchly (peer): same with --name grouchly --role peer and no --serve-hive,
#   run as systemd unit ferry-drill so the firewall can match its cgroup

# the cut (both machines, same minute), auto-expiring after 12 minutes
drill-fw.sh add 12 <peer lan ip>           # SELECT=cgroup on grouchly, SELECT=uid:drillu on beastly
# lift early, or let it expire
drill-fw.sh remove
```

`docs/testing/rescue-drill/drill-fw.sh` holds the rules. They drop only for the drill's unit or uid, are
removed by a timer set at the moment they are added (`systemd-run --on-active` on grouchly, a `sleep`
and `nft delete table` on beastly, standing in for the scheduled task Windows would use), and never match
ssh, the live ferry processes, Syncthing, the Ferryman Worker or NATV.

## Result (2026-10-22, UTC)

Healthy start at 00:03:43 (`path=direct`, files syncing). Rules added on both machines 00:04:11.

| Step | beastly | grouchly | Since the cut |
|---|---|---|---|
| First sync failure | 00:04:33 | 00:04:40 | 22 s / 29 s |
| Cut off (peer failing and relay down) | 00:05:03 | 00:04:40 | 52 s / 29 s |
| Master posts the record (cut-off + 2 min, next 5 s tick) | 00:07:08 | | 2 min 57 s |
| Peer reads and accepts the record | | 00:07:45 | 37 s after the post |
| Rescue relay connected (home relay switched) | 00:07:33 | 00:08:11 | |
| Peer reachable again, `path=relay use1-1...` | 00:08:30 | 00:08:30 | 4 min 19 s |
| Rules removed | 00:09:00 | 00:09:00 | |
| Back on `path=direct` | 00:09:04 | 00:09:01 | 4 s |

During the cut the master kept writing a message file every 20 s; the peer's count reached 14 by the first
reconnect and 17 by the end, with no loss. grouchly's live lane (`ferry lane iroh status`) showed the
relay reached and the worker running after the drill; Syncthing and the Ferryman Worker on beastly were
not touched and kept their state. No firewall rule or timer was left on either machine.

Notes: beastly's relay connection lingered 30 s after the cut before the keepalive gave up, so its cut-off
clock started later than grouchly's. With production timers the post comes 15 minutes after cut-off.

## The live-Hive leg

Needs, from Josh:

- a Hive account for the fleet (`HIVE_RESCUE_ACCOUNT`) with enough staked HP for resource credits,
- its posting key for the master (`HIVE_RESCUE_POSTING_KEY`, posting authority only, in the secrets file),
- optionally a delegated poster account and key for the backup machine (authority granted by the fleet account),
- two or three public API nodes to list under `[hive_rescue] nodes`.

Then run `rescue_drill probe-hive --node <url> --account <name>` (read-only) and repeat the drill without
`--serve-hive`, pointing `--hive` at the public nodes. Use option 3 or 4 above for the second end.
