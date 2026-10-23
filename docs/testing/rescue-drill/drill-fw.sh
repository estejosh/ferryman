#!/bin/bash
# Rescue drill firewall for ONE process owner (nothing else on the machine is touched).
#   drill-fw.sh add <minutes> <peer_ip>   add rules, auto-remove after <minutes>
#   drill-fw.sh remove                    remove now
#   drill-fw.sh show
# Who the rules match, chosen by SELECT:
#   cgroup (default)  the systemd unit ferry-drill.service. ssh, the live ferry processes and every
#                     other socket are in other cgroups and never match. Used on grouchly.
#   uid:<user>        sockets owned by that user. Used on beastly, where the drill runs in WSL2 (mirrored
#                     networking, so it has the same LAN address) as the throwaway user "drillu", because
#                     Windows Firewall needs an elevated shell this session does not have.
# Drops, for that selector only: IPv6, the fleet relay, the NAT's public address (hairpin), the peer's
# LAN address, and the CGNAT/Tailscale and private ranges the peer also advertises. Loopback is not
# matched (the mock Hive node is reached over an ssh tunnel on 127.0.0.1). The rescue relay and
# everything else stay open. Removal is scheduled when the rules are added, so nothing outlives it.
set -eu
RELAY="${RELAY:-162.35.10.46}"
NAT_PUBLIC="${NAT_PUBLIC:?set NAT_PUBLIC to the shared public address}"
case "${SELECT:-cgroup}" in
  cgroup) SEL='socket cgroupv2 level 2 "system.slice/ferry-drill.service"' ;;
  uid:*)  SEL="meta skuid ${SELECT#uid:}" ;;
  *) echo "bad SELECT"; exit 2 ;;
esac
case "${1:-}" in
  add)
    MIN="$2"; PEER="$3"
    nft delete table inet ferry_drill 2>/dev/null || true
    nft -f - <<EOF
table inet ferry_drill {
  chain out {
    type filter hook output priority 0; policy accept;
    $SEL meta nfproto ipv6 drop
    $SEL ip daddr { $RELAY, $NAT_PUBLIC } drop
    $SEL ip daddr $PEER drop
    $SEL ip daddr { 100.64.0.0/10, 172.16.0.0/12 } drop
  }
}
EOF
    if systemctl is-system-running >/dev/null 2>&1; then
      systemctl stop ferry-drill-fw-expire.timer ferry-drill-fw-expire.service 2>/dev/null || true
      systemd-run --quiet --unit=ferry-drill-fw-expire --on-active="${MIN}m" /usr/sbin/nft delete table inet ferry_drill
    else
      setsid nohup sh -c "sleep $((MIN * 60)); nft delete table inet ferry_drill" >/dev/null 2>&1 &
    fi
    echo "$(date -u +%FT%T.%3NZ) rules added; auto-removal in ${MIN}m"
    nft list table inet ferry_drill
    ;;
  remove)
    nft delete table inet ferry_drill 2>/dev/null || true
    systemctl stop ferry-drill-fw-expire.timer 2>/dev/null || true
    echo "$(date -u +%FT%T.%3NZ) rules removed; table present: $(nft list tables | grep -c ferry_drill || true)"
    ;;
  show) nft list table inet ferry_drill 2>&1 || true ;;
  *) echo "usage: $0 add <min> <peer_ip> | remove | show"; exit 2;;
esac